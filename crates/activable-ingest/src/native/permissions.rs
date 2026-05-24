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

/// Permissions enricher that materializes HasEffectivePermission edges from inline policies.
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

        // Fetch all Principal nodes with their inline_policies property
        let principals = fetch_principals_with_policies(pool, graph_name).await?;

        if principals.is_empty() {
            debug!("No principals with inline policies found");
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

        for (principal_id, inline_policies_value) in principals {
            // inline_policies is now stored as a JSON string (serialized from Vec<{name, document}>)
            // Parse the string back to an array
            let inline_policies = match inline_policies_value {
                serde_json::Value::String(json_str) => {
                    match serde_json::from_str::<serde_json::Value>(&json_str) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            warn!(principal = %principal_id, error = %e, "Failed to parse inline_policies JSON string; skipping principal");
                            continue;
                        }
                    }
                }
                other => {
                    warn!(principal = %principal_id, value_type = ?other, "Expected inline_policies to be a JSON string; skipping principal");
                    continue;
                }
            };

            if let serde_json::Value::Array(policies) = inline_policies {
                for policy in policies {
                    if let serde_json::Value::Object(policy_obj) = policy {
                        // Get the policy document (URL-encoded by AWS, but already decoded in ingester)
                        if let Some(serde_json::Value::String(doc_str)) = policy_obj.get("document") {
                            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(doc_str) {
                                // Extract permissions from Statement array
                                if let Some(statements) = doc.get("Statement").and_then(|s| s.as_array()) {
                                    for statement in statements {
                                        // Skip Deny statements (out of scope this phase)
                                        if let Some(effect) = statement.get("Effect").and_then(|e| e.as_str()) {
                                            if effect == "Deny" {
                                                skipped_deny += 1;
                                                if self.skip_deny {
                                                    continue;
                                                }
                                            }
                                        }

                                        // Warn if statement has Conditions (not processed this phase)
                                        if statement.get("Condition").is_some() {
                                            skipped_conditions += 1;
                                            if self.warn_on_conditions {
                                                warn!(principal = %principal_id, "IAM statement has Conditions (not expanded this phase)");
                                            }
                                        }

                                        // Extract actions and resources
                                        let actions = extract_string_or_array(statement.get("Action"));
                                        let resources = extract_string_or_array(statement.get("Resource"));

                                        // Create one permission pair per (action, resource) combo
                                        for action in &actions {
                                            for resource in &resources {
                                                let perm_id = sha256_perm_id(action, resource);
                                                let perm_key = format!("{}|{}", action, resource);

                                                // Create Permission node if not exists
                                                permission_nodes
                                                    .entry(perm_key)
                                                    .or_insert_with(|| {
                                                        json!({
                                                            "id": perm_id,
                                                            "action": action,
                                                            "resource": resource,
                                                        })
                                                    });

                                                // Create edge with action and resource properties
                                                edges.push((
                                                    principal_id.clone(),
                                                    perm_id,
                                                    json!({
                                                        "action": action,
                                                        "resource": resource,
                                                    }),
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
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

/// Fetch all Principal nodes with their inline_policies property.
/// Returns a Vec<(principal_id, inline_policies_json_array)>.
async fn fetch_principals_with_policies(
    pool: &Arc<Pool>,
    graph_name: &str,
) -> Result<Vec<(String, serde_json::Value)>, IngestError> {
    let conn = pool
        .get()
        .await
        .map_err(|e| IngestError::Graph(format!("Failed to get connection: {}", e)))?;

    // Initialize AGE on this connection
    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .map_err(|e| IngestError::Graph(format!("Failed to initialize AGE: {}", e)))?;

    let cypher = "MATCH (n:Principal) WHERE n.inline_policies IS NOT NULL RETURN n.id, n.inline_policies";

    // Cast agtype columns to ::text so tokio-postgres can deserialize them as String.
    // Without the cast, try_get::<_, String> fails with "error deserializing column N".
    let sql = format!(
        "SELECT id::text, policies::text FROM ag_catalog.cypher('{}', $${}$$) AS (id agtype, policies agtype)",
        graph_name, cypher
    );

    let rows = conn
        .query(&sql, &[])
        .await
        .map_err(|e| IngestError::Graph(format!("Failed to query principals with policies: {}", e)))?;

    let mut results = Vec::new();

    for row in rows {
        let id_str: String = row
            .try_get(0)
            .map_err(|e| IngestError::Graph(format!("Failed to read principal ID column: {}", e)))?;
        let policies_str: String = row
            .try_get(1)
            .map_err(|e| IngestError::Graph(format!("Failed to read policies column: {}", e)))?;

        // ::text casts strip agtype's outer JSON quoting:
        //   agtype string `"arn:..."` -> text `arn:...`
        //   agtype string `"[{...}]"` -> text `[{...}]` (literal JSON content)
        // So id_str is the raw ARN; policies_str is the inline JSON array.
        // Wrap policies_str as Value::String to match the consumer's expected shape.
        let principal_id = id_str.trim().to_string();
        let policies_value = serde_json::Value::String(policies_str);
        results.push((principal_id, policies_value));
    }

    Ok(results)
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
}
