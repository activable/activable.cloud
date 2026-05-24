//! Permissions enricher: materializes HasEffectivePermission edges from inline IAM policies.
//!
//! This enricher runs AFTER Principal nodes have been created with inline_policies properties.
//! It parses each Principal's inline_policies array and creates:
//! 1. Permission nodes (one per unique action+resource pair) with id=sha256(action|resource)
//! 2. HasEffectivePermission edges from Principal to Permission with action and resource properties
//!
//! This allows the risk scoring engine to efficiently query effective permissions via graph edges.

use crate::error::IngestError;
use crate::native::{EnrichmentStats, NativeEnricher};
use activable_graph::loader::{load_nodes, load_edges_with_props};
use async_trait::async_trait;
use deadpool_postgres::Pool;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};

/// Struct representing a Principal's policies (inline, managed, and permissions boundary).
pub struct PrincipalPolicies {
    pub principal_id: String,
    pub inline_policies: serde_json::Value,
    pub managed_policies: serde_json::Value,
    pub permissions_boundary: Option<serde_json::Value>,
}

/// Permissions enricher that materializes HasEffectivePermission edges
/// by computing effective permissions via UNION of inline+managed policies,
/// then AND-masked by permission boundary (if present).
pub struct PermissionsEnricher {
    /// If true, skip Deny statements (out of scope for this phase)
    skip_deny: bool,
    /// If true, warn about Conditions but include the permission anyway
    warn_on_conditions: bool,
}

impl PermissionsEnricher {
    /// Create a new permissions enricher with default settings.
    pub fn new() -> Self {
        Self {
            skip_deny: true,
            warn_on_conditions: true,
        }
    }
}

impl Default for PermissionsEnricher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NativeEnricher for PermissionsEnricher {
    fn service(&self) -> &str {
        "permissions"
    }

    async fn enrich(
        &self,
        pool: &Arc<Pool>,
        graph_name: &str,
    ) -> Result<EnrichmentStats, IngestError> {
        debug!("Starting Permissions enrichment (materializing HasEffectivePermission edges)");

        // Fetch all Principal nodes with their inline_policies, managed_policies, and permissions_boundary
        let principals = fetch_principals_with_policies(pool, graph_name).await?;

        if principals.is_empty() {
            debug!("No principals with policies found");
            return Ok(EnrichmentStats {
                service: self.service().to_string(),
                edges_created: 0,
            });
        }

        // Parse policies and collect unique permissions and edges
        let mut permission_nodes: HashMap<String, serde_json::Value> = HashMap::new();
        let mut edges: Vec<(String, String, serde_json::Value)> = Vec::new();
        let mut skipped_deny = 0u32;
        let mut skipped_conditions = 0u32;

        for principal in principals {
            let principal_id = principal.principal_id.clone();

            // Step 1: Collect Allow tuples from inline and managed policies (UNION).
            // Track the source (inline vs managed) for each permission.
            let mut effective_permissions: std::collections::HashMap<(String, String), &'static str> =
                std::collections::HashMap::new();

            // Process inline policies
            if let Some(inline_tuple) = parse_and_extract_permissions(&principal.inline_policies, &principal_id, "inline", &mut skipped_deny, &mut skipped_conditions, self.skip_deny, self.warn_on_conditions) {
                for (action, resource) in inline_tuple {
                    effective_permissions.insert((action, resource), "inline");
                }
            }

            // Process managed policies
            if let Some(managed_tuple) = parse_and_extract_permissions(&principal.managed_policies, &principal_id, "managed", &mut skipped_deny, &mut skipped_conditions, self.skip_deny, self.warn_on_conditions) {
                for (action, resource) in managed_tuple {
                    // If action+resource exists from inline, keep it; otherwise add from managed.
                    // Union semantics: if it's in either, it's in the result.
                    effective_permissions.insert((action, resource), "managed");
                }
            }

            // Step 2: AND-mask with permission boundary if present.
            let after_boundary = if let Some(boundary_value) = &principal.permissions_boundary {
                // Extract permissions allowed by the boundary
                let boundary_permissions = parse_and_extract_permissions_only_allow(boundary_value, &principal_id);
                if boundary_permissions.is_empty() {
                    debug!(principal = %principal_id, "Permission boundary has no Allow statements; all permissions filtered");
                    std::collections::HashMap::new()
                } else {
                    // Intersect: keep only permissions that are in both effective_permissions AND boundary
                    effective_permissions
                        .into_iter()
                        .filter(|(perm_key, _)| boundary_permissions.contains(perm_key))
                        .map(|(perm_key, _)| (perm_key, "boundary-survived"))
                        .collect()
                }
            } else {
                // No boundary: keep all effective permissions with their original source
                effective_permissions
            };

            // Step 3: Materialize Permission nodes and HasEffectivePermission edges.
            for ((action, resource), source) in after_boundary {
                let perm_id = sha256_perm_id(&action, &resource);
                let perm_key = format!("{}|{}", action, resource);

                permission_nodes
                    .entry(perm_key)
                    .or_insert_with(|| {
                        json!({
                            "id": perm_id,
                            "action": action,
                            "resource": resource,
                        })
                    });

                edges.push((
                    principal_id.clone(),
                    perm_id,
                    json!({
                        "action": action,
                        "resource": resource,
                        "source": source,
                    }),
                ));
            }
        }

        debug!(
            permission_nodes = permission_nodes.len(),
            edges_count = edges.len(),
            skipped_deny,
            skipped_conditions,
            "Parsed permissions from inline policies"
        );

        // Insert Permission nodes (MERGE semantics — idempotent)
        if !permission_nodes.is_empty() {
            let perm_values: Vec<serde_json::Value> = permission_nodes.into_values().collect();
            let written = load_nodes(pool.clone(), graph_name, "Permission", &perm_values, 100).await?;
            debug!(permissions_created = written, "Permission nodes inserted");
        }

        // Insert HasEffectivePermission edges with properties
        let mut edge_count = 0u32;
        if !edges.is_empty() {
            debug!(edge_count = edges.len(), "Writing HasEffectivePermission edges with properties");
            let written =
                load_edges_with_props(pool.clone(), graph_name, "HasEffectivePermission", &edges, 100)
                    .await?;
            edge_count = written as u32;
        }

        debug!(
            service = self.service(),
            edges_created = edge_count,
            "Permissions enrichment complete"
        );

        Ok(EnrichmentStats {
            service: self.service().to_string(),
            edges_created: edge_count,
        })
    }
}

/// Fetch all Principal nodes with their inline_policies, managed_policies, and permissions_boundary.
async fn fetch_principals_with_policies(
    pool: &Arc<Pool>,
    graph_name: &str,
) -> Result<Vec<PrincipalPolicies>, IngestError> {
    let conn = pool
        .get()
        .await
        .map_err(|e| IngestError::Graph(format!("Failed to get connection: {}", e)))?;

    // Initialize AGE on this connection
    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .map_err(|e| IngestError::Graph(format!("Failed to initialize AGE: {}", e)))?;

    let cypher = r#"
        MATCH (n:Principal)
        WHERE n.inline_policies IS NOT NULL OR n.managed_policies IS NOT NULL
        RETURN n.id, n.inline_policies, n.managed_policies, n.permissions_boundary
    "#;

    // Cast agtype columns to ::text so tokio-postgres can deserialize them as String.
    // Without the cast, try_get::<_, String> fails with "error deserializing column N".
    let sql = format!(
        "SELECT id::text, inline::text, managed::text, boundary::text FROM ag_catalog.cypher('{}', $${}$$) AS (id agtype, inline agtype, managed agtype, boundary agtype)",
        graph_name, cypher
    );

    let rows = conn
        .query(&sql, &[])
        .await
        .map_err(|e| IngestError::Graph(format!("Failed to query principals with policies: {}", e)))?;

    let mut results = Vec::new();

    for row in rows {
        // Use Option<String> for every column — agtype null becomes SQL null on
        // ::text cast, and tokio-postgres can't deserialize SQL null into String.
        // This is the same null-handling bug pattern seen in earlier slices.
        let id_opt: Option<String> = row
            .try_get(0)
            .map_err(|e| IngestError::Graph(format!("Failed to read principal ID column: {}", e)))?;
        let inline_opt: Option<String> = row
            .try_get(1)
            .map_err(|e| IngestError::Graph(format!("Failed to read inline_policies column: {}", e)))?;
        let managed_opt: Option<String> = row
            .try_get(2)
            .map_err(|e| IngestError::Graph(format!("Failed to read managed_policies column: {}", e)))?;
        let boundary_opt: Option<String> = row
            .try_get(3)
            .map_err(|e| IngestError::Graph(format!("Failed to read permissions_boundary column: {}", e)))?;

        // ::text casts strip agtype's outer JSON quoting:
        //   agtype string `"arn:..."` -> text `arn:...`
        //   agtype string `"[{...}]"` -> text `[{...}]` (literal JSON content)
        //   agtype null -> SQL NULL (no row text)
        let principal_id = match id_opt {
            Some(s) => s.trim().to_string(),
            None => continue, // skip principals with null id (shouldn't happen but be defensive)
        };

        // inline_policies / managed_policies: treat missing or "null" as empty array.
        let inline_policies = match inline_opt {
            Some(s) if s.trim() != "null" => serde_json::Value::String(s),
            _ => serde_json::Value::Array(Vec::new()),
        };
        let managed_policies = match managed_opt {
            Some(s) if s.trim() != "null" => serde_json::Value::String(s),
            _ => serde_json::Value::Array(Vec::new()),
        };

        // Boundary: SQL NULL OR literal "null" -> None; otherwise wrap.
        let permissions_boundary = match boundary_opt {
            Some(s) if s.trim() != "null" => Some(serde_json::Value::String(s)),
            _ => None,
        };

        results.push(PrincipalPolicies {
            principal_id,
            inline_policies,
            managed_policies,
            permissions_boundary,
        });
    }

    Ok(results)
}

/// Parse policy JSON (either String-wrapped or raw) and extract Allow permissions.
/// Returns a Vec of (action, resource) tuples, excluding Deny statements.
/// Also updates skipped_deny and skipped_conditions counters.
fn parse_and_extract_permissions(
    policies_value: &serde_json::Value,
    principal_id: &str,
    source_name: &str,
    skipped_deny: &mut u32,
    skipped_conditions: &mut u32,
    skip_deny: bool,
    warn_on_conditions: bool,
) -> Option<Vec<(String, String)>> {
    // Parse the JSON (may be String-wrapped)
    let policies = match policies_value {
        serde_json::Value::String(json_str) => {
            match serde_json::from_str::<serde_json::Value>(json_str) {
                Ok(parsed) => parsed,
                Err(e) => {
                    warn!(principal = %principal_id, source = %source_name, error = %e, "Failed to parse policies JSON string");
                    return None;
                }
            }
        }
        serde_json::Value::Null => return None,
        other => other.clone(),
    };

    let mut results = Vec::new();

    if let serde_json::Value::Array(policies_arr) = policies {
        for policy in policies_arr {
            if let serde_json::Value::Object(policy_obj) = policy {
                // Get the policy document
                if let Some(serde_json::Value::String(doc_str)) = policy_obj.get("document") {
                    if let Ok(doc) = serde_json::from_str::<serde_json::Value>(doc_str) {
                        // Extract permissions from Statement array
                        if let Some(statements) = doc.get("Statement").and_then(|s| s.as_array()) {
                            for statement in statements {
                                // Skip Deny statements (out of scope this phase)
                                if let Some(effect) = statement.get("Effect").and_then(|e| e.as_str()) {
                                    if effect == "Deny" {
                                        *skipped_deny += 1;
                                        if skip_deny {
                                            continue;
                                        }
                                    }
                                }

                                // Warn if statement has Conditions (not processed this phase)
                                if statement.get("Condition").is_some() {
                                    *skipped_conditions += 1;
                                    if warn_on_conditions {
                                        warn!(principal = %principal_id, "IAM statement has Conditions (not expanded this phase)");
                                    }
                                }

                                // Extract actions and resources
                                let actions = extract_string_or_array(statement.get("Action"));
                                let resources = extract_string_or_array(statement.get("Resource"));

                                // Add to results
                                for action in &actions {
                                    for resource in &resources {
                                        results.push((action.clone(), resource.clone()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// Parse policy JSON and extract ONLY Allow permissions (used for boundary masking).
/// Returns a HashSet of (action, resource) tuples that are allowed by this policy.
fn parse_and_extract_permissions_only_allow(
    policies_value: &serde_json::Value,
    principal_id: &str,
) -> std::collections::HashSet<(String, String)> {
    // Parse the JSON (may be String-wrapped)
    let policies = match policies_value {
        serde_json::Value::String(json_str) => {
            match serde_json::from_str::<serde_json::Value>(json_str) {
                Ok(parsed) => parsed,
                Err(e) => {
                    warn!(principal = %principal_id, error = %e, "Failed to parse permission boundary JSON string");
                    return std::collections::HashSet::new();
                }
            }
        }
        serde_json::Value::Null => return std::collections::HashSet::new(),
        other => other.clone(),
    };

    let mut results = std::collections::HashSet::new();

    if let serde_json::Value::Object(boundary_obj) = policies {
        // Permission boundary is a single policy document, not an array
        if let Some(serde_json::Value::String(doc_str)) = boundary_obj.get("document") {
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(doc_str) {
                if let Some(statements) = doc.get("Statement").and_then(|s| s.as_array()) {
                    for statement in statements {
                        // Only process Allow statements for boundary
                        if let Some(effect) = statement.get("Effect").and_then(|e| e.as_str()) {
                            if effect != "Allow" {
                                continue;
                            }
                        }

                        let actions = extract_string_or_array(statement.get("Action"));
                        let resources = extract_string_or_array(statement.get("Resource"));

                        for action in &actions {
                            for resource in &resources {
                                results.insert((action.clone(), resource.clone()));
                            }
                        }
                    }
                }
            }
        }
    } else if let serde_json::Value::Array(policies_arr) = policies {
        // Fallback: if it's an array, process as array of policy docs
        for policy in policies_arr {
            if let serde_json::Value::Object(policy_obj) = policy {
                if let Some(serde_json::Value::String(doc_str)) = policy_obj.get("document") {
                    if let Ok(doc) = serde_json::from_str::<serde_json::Value>(doc_str) {
                        if let Some(statements) = doc.get("Statement").and_then(|s| s.as_array()) {
                            for statement in statements {
                                if let Some(effect) = statement.get("Effect").and_then(|e| e.as_str()) {
                                    if effect != "Allow" {
                                        continue;
                                    }
                                }

                                let actions = extract_string_or_array(statement.get("Action"));
                                let resources = extract_string_or_array(statement.get("Resource"));

                                for action in &actions {
                                    for resource in &resources {
                                        results.insert((action.clone(), resource.clone()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    results
}

/// Extract a string or array of strings from a JSON value.
fn extract_string_or_array(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => vec![],
    }
}

/// Generate a stable ID for a permission (action, resource) pair.
/// Using SHA256 hash of "action|resource" for deterministic IDs.
fn sha256_perm_id(action: &str, resource: &str) -> String {
    use sha2::{Sha256, Digest};

    let input = format!("{}|{}", action, resource);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();
    format!("perm:{:x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_string() {
        let value = serde_json::json!("s3:GetObject");
        let result = extract_string_or_array(Some(&value));
        assert_eq!(result, vec!["s3:GetObject"]);
    }

    #[test]
    fn test_extract_array() {
        let value = serde_json::json!(["s3:GetObject", "s3:PutObject"]);
        let result = extract_string_or_array(Some(&value));
        assert_eq!(result, vec!["s3:GetObject", "s3:PutObject"]);
    }

    #[test]
    fn test_extract_none() {
        let result = extract_string_or_array(None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_sha256_perm_id() {
        let id1 = sha256_perm_id("s3:GetObject", "arn:aws:s3:::mybucket/*");
        let id2 = sha256_perm_id("s3:GetObject", "arn:aws:s3:::mybucket/*");
        assert_eq!(id1, id2, "Same action+resource should produce same ID");
        assert!(id1.starts_with("perm:"), "ID should have perm: prefix");
    }

    #[test]
    fn and_mask_boundary_restricts_permissions() {
        // Scenario: principal with inline {s3:GetObject, s3:PutObject}, boundary {s3:GetObject only}
        // Expected: effective = {s3:GetObject} only (boundary masks out s3:PutObject)
        // This demonstrates the AND-mask: intersection of inline and boundary

        let inline_policies = serde_json::json!([
            {
                "name": "s3-readwrite",
                "document": serde_json::json!({
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject", "s3:PutObject"],
                            "Resource": "*"
                        }
                    ]
                }).to_string()
            }
        ]);

        let boundary_policy = serde_json::json!({
            "arn": "arn:aws:iam::123456789012:policy/boundary",
            "document": serde_json::json!({
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*"
                    }
                ]
            }).to_string()
        });

        let mut skipped_deny = 0u32;
        let mut skipped_conditions = 0u32;

        // Extract inline permissions
        let inline_perms = parse_and_extract_permissions(
            &inline_policies,
            "test-principal",
            "inline",
            &mut skipped_deny,
            &mut skipped_conditions,
            true,
            true,
        );

        assert!(inline_perms.is_some());
        let inline_set: std::collections::HashSet<_> = inline_perms
            .unwrap()
            .into_iter()
            .collect();
        assert!(inline_set.contains(&("s3:GetObject".to_string(), "*".to_string())));
        assert!(inline_set.contains(&("s3:PutObject".to_string(), "*".to_string())));

        // Extract boundary permissions
        let boundary_perms = parse_and_extract_permissions_only_allow(&boundary_policy, "test-principal");
        assert!(boundary_perms.contains(&("s3:GetObject".to_string(), "*".to_string())));
        assert!(!boundary_perms.contains(&("s3:PutObject".to_string(), "*".to_string())));

        // Apply AND-mask: intersect inline_set with boundary
        let masked: std::collections::HashSet<_> = inline_set
            .into_iter()
            .filter(|perm| boundary_perms.contains(perm))
            .collect();

        // Result should have s3:GetObject (in both) but not s3:PutObject (only in inline)
        assert_eq!(masked.len(), 1);
        assert!(masked.contains(&("s3:GetObject".to_string(), "*".to_string())));
        assert!(!masked.contains(&("s3:PutObject".to_string(), "*".to_string())));
    }

    #[test]
    fn no_boundary_preserves_union_of_inline_and_managed() {
        // Scenario: principal with inline {s3:GetObject}, managed {ec2:DescribeInstances}, no boundary
        // Expected: both permissions in effective set

        let inline_policies = serde_json::json!([
            {
                "name": "s3-read",
                "document": serde_json::json!({
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "*"
                        }
                    ]
                }).to_string()
            }
        ]);

        let managed_policies = serde_json::json!([
            {
                "arn": "arn:aws:iam::123456789012:policy/ec2-describe",
                "name": "ec2-describe",
                "document": serde_json::json!({
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "ec2:DescribeInstances",
                            "Resource": "*"
                        }
                    ]
                }).to_string()
            }
        ]);

        let mut skipped_deny = 0u32;
        let mut skipped_conditions = 0u32;

        let inline_perms = parse_and_extract_permissions(
            &inline_policies,
            "test-principal",
            "inline",
            &mut skipped_deny,
            &mut skipped_conditions,
            true,
            true,
        )
        .unwrap_or_default();

        let managed_perms = parse_and_extract_permissions(
            &managed_policies,
            "test-principal",
            "managed",
            &mut skipped_deny,
            &mut skipped_conditions,
            true,
            true,
        )
        .unwrap_or_default();

        // Union: both should be present
        let mut union: std::collections::HashSet<_> =
            inline_perms.iter().cloned().collect();
        for perm in managed_perms {
            union.insert(perm);
        }

        assert_eq!(union.len(), 2);
        assert!(union.contains(&("s3:GetObject".to_string(), "*".to_string())));
        assert!(union.contains(&("ec2:DescribeInstances".to_string(), "*".to_string())));
    }

    #[test]
    fn deny_statements_skipped_with_log() {
        // Scenario: principal with one Allow and one Deny statement
        // Expected: only the Allow tuple in output; Deny skipped

        let policies = serde_json::json!([
            {
                "name": "mixed",
                "document": serde_json::json!({
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "*"
                        },
                        {
                            "Effect": "Deny",
                            "Action": "s3:DeleteBucket",
                            "Resource": "*"
                        }
                    ]
                }).to_string()
            }
        ]);

        let mut skipped_deny = 0u32;
        let mut skipped_conditions = 0u32;

        let results = parse_and_extract_permissions(
            &policies,
            "test-principal",
            "inline",
            &mut skipped_deny,
            &mut skipped_conditions,
            true,  // skip_deny = true
            true,
        )
        .unwrap_or_default();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], ("s3:GetObject".to_string(), "*".to_string()));
        assert_eq!(skipped_deny, 1);
    }
}
