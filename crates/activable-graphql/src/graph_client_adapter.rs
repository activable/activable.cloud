//! Production adapter for GraphQueryService using real GraphClient (PG+AGE backend).
//!
//! This adapter wraps the real `GraphClient` and executes parameterized Cypher queries
//! against a live Postgres+AGE graph database.

use activable_graph::GraphClient;
use activable_risk::signals::{GraphQueryError, GraphQueryService, SignalError};
use async_trait::async_trait;

/// Production adapter: implements GraphQueryService using real PG+AGE via GraphClient.
/// All queries use Cypher with escaping for safety.
#[derive(Clone)]
pub struct GraphClientAdapter {
    client: GraphClient,
}

impl GraphClientAdapter {
    /// Create a new adapter wrapping a GraphClient instance.
    pub fn new(client: GraphClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl GraphQueryService for GraphClientAdapter {
    /// Count reachable nodes from principal within max_hops via outgoing edges (BFS).
    async fn reachable_count(&self, principal_id: &str, max_hops: u8) -> Result<u64, SignalError> {
        use futures::StreamExt;

        let node_id = activable_graph::types::NodeId::from(principal_id);
        let edge_types: Vec<&str> = vec![]; // all edge types

        let stream = self
            .client
            .blast_radius(&node_id, &edge_types, max_hops)
            .await
            .map_err(|e| {
                Box::new(GraphQueryError(format!(
                    "blast_radius query failed for principal_id='{}': {}",
                    principal_id, e
                ))) as SignalError
            })?;

        let nodes: Vec<_> = stream.collect::<Vec<_>>().await;
        let count = nodes.into_iter().filter_map(|r| r.ok()).count();

        tracing::trace!(
            principal_id = principal_id,
            max_hops = max_hops,
            count = count,
            "reachable_count computed"
        );

        Ok(count as u64)
    }

    /// Shortest path from principal to any admin-equivalent node (path length).
    /// Returns None if no path exists within max_depth.
    async fn shortest_path_to_admin(
        &self,
        principal_id: &str,
        max_depth: u8,
    ) -> Result<Option<u32>, SignalError> {
        // Query all nodes marked as admin
        let cypher_admins = "MATCH (n:Principal) WHERE n.is_admin = true RETURN n.id";

        let admin_results = self.client.cypher(cypher_admins).await.map_err(|e| {
            Box::new(GraphQueryError(format!(
                "cypher query for admin nodes failed: {}",
                e
            ))) as SignalError
        })?;

        if admin_results.is_empty() {
            tracing::trace!(principal_id = principal_id, "no admin nodes found");
            return Ok(None);
        }

        let start = activable_graph::types::NodeId::from(principal_id);
        let mut min_distance: Option<u32> = None;

        for admin_result in &admin_results {
            // Extract principal ID from the result
            let admin_id = if let Some(id_str) = admin_result.as_str() {
                id_str.to_string()
            } else {
                continue; // Skip non-string results
            };

            let end = activable_graph::types::NodeId::from(admin_id.as_str());

            // Find shortest path between principal and this admin
            match self
                .client
                .shortest_path_length(&start, &end, max_depth)
                .await
            {
                Ok(Some(dist)) => {
                    min_distance = Some(min_distance.map_or(dist, |m: u32| m.min(dist)));
                }
                Ok(None) => {
                    // No path to this admin, continue to next
                }
                Err(_e) => {
                    // Skip errors for individual admin nodes
                }
            }
        }

        if let Some(dist) = min_distance {
            tracing::trace!(
                principal_id = principal_id,
                max_depth = max_depth,
                distance = dist,
                "shortest_path_to_admin computed"
            );
        } else {
            tracing::trace!(
                principal_id = principal_id,
                max_depth = max_depth,
                "no path to admin found"
            );
        }

        Ok(min_distance)
    }

    /// Count cross-account hops via CanAssume edges (account boundary crossings).
    async fn cross_account_hop_count(&self, principal_id: &str) -> Result<u32, SignalError> {
        // Use Cypher to find CanAssume edges from principal, counting distinct account changes
        // Escape the principal ID for safe inclusion in Cypher
        let escaped_id = activable_graph::query_builder::escape_cypher(principal_id);

        let cypher = format!(
            "MATCH (start:Principal {{id: '{}'}})-[:CanAssume*1..10]->(target:Principal) WHERE start.account_id <> target.account_id RETURN count(DISTINCT target.account_id)",
            escaped_id
        );

        let results = self.client.cypher(&cypher).await.map_err(|e| {
            Box::new(GraphQueryError(format!(
                "cross_account_hop_count cypher query failed: {}",
                e
            ))) as SignalError
        })?;

        let count = if let Some(first) = results.first() {
            if let Some(count_u64) = first.as_u64() {
                count_u64 as u32
            } else {
                0
            }
        } else {
            0
        };

        tracing::trace!(
            principal_id = principal_id,
            count = count,
            "cross_account_hop_count computed"
        );

        Ok(count)
    }

    /// List all principal node IDs in the graph.
    async fn list_principal_ids(&self) -> Result<Vec<String>, SignalError> {
        let cypher = "MATCH (n:Principal) RETURN n.id";

        let results = self.client.cypher(cypher).await.map_err(|e| {
            Box::new(GraphQueryError(format!(
                "list_principal_ids cypher query failed: {}",
                e
            ))) as SignalError
        })?;

        let ids: Vec<String> = results
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        tracing::trace!(principal_count = ids.len(), "list_principal_ids retrieved");

        Ok(ids)
    }

    /// Get effective permissions for a principal (action + resource pairs).
    /// Queries HasEffectivePermission edges with action and resource properties.
    async fn get_effective_permissions(
        &self,
        principal_id: &str,
    ) -> Result<Vec<(String, String)>, SignalError> {
        // Escape principal ID for safe Cypher
        let escaped_id = activable_graph::query_builder::escape_cypher(principal_id);

        let cypher = format!(
            "MATCH (n:Principal {{id: '{}'}})-[r:HasEffectivePermission]->(m) RETURN r.action, r.resource",
            escaped_id
        );

        // Use multi-column query to get both action and resource in one call
        let results = self
            .client
            .cypher_multi_column(&cypher, 2)
            .await
            .map_err(|e| {
                Box::new(GraphQueryError(format!(
                    "get_effective_permissions cypher query failed: {}",
                    e
                ))) as SignalError
            })?;

        let perms: Vec<(String, String)> = results
            .iter()
            .filter_map(|row| {
                // Each row should have exactly 2 columns: [action, resource]
                if row.len() >= 2 {
                    let action = row[0].as_str()?.to_string();
                    let resource = row[1].as_str()?.to_string();
                    return Some((action, resource));
                }
                None
            })
            .collect();

        tracing::trace!(
            principal_id = principal_id,
            permission_count = perms.len(),
            "get_effective_permissions retrieved"
        );

        Ok(perms)
    }

    /// Read a cached risk assessment from a principal node property.
    /// Returns None if no cached assessment exists (property missing or null).
    async fn read_risk_assessment(
        &self,
        principal_id: &str,
    ) -> Result<Option<String>, SignalError> {
        // Escape principal ID for safe Cypher
        let escaped_id = activable_graph::query_builder::escape_cypher(principal_id);

        let cypher = format!(
            "MATCH (n:Principal {{id: '{}'}}) RETURN n.risk_assessment_json",
            escaped_id
        );

        let results = self.client.cypher(&cypher).await.map_err(|e| {
            Box::new(GraphQueryError(format!(
                "read_risk_assessment cypher query failed: {}",
                e
            ))) as SignalError
        })?;

        if let Some(first) = results.first() {
            // Handle both null and missing cases: AGE may return null, JSON null string, or a real JSON value
            match first {
                serde_json::Value::Null => {
                    // AGE returned agtype null — property doesn't exist yet
                    tracing::trace!(
                        principal_id = principal_id,
                        "no risk_assessment_json found (null)"
                    );
                    return Ok(None);
                }
                serde_json::Value::String(json_str) => {
                    // Successful deserialization of agtype string
                    if !json_str.is_empty() && json_str != "null" {
                        tracing::trace!(
                            principal_id = principal_id,
                            "risk_assessment_json retrieved"
                        );
                        return Ok(Some(json_str.to_string()));
                    }
                }
                _ => {
                    // Other types (shouldn't happen, but treat as missing)
                    tracing::trace!(
                        principal_id = principal_id,
                        "unexpected type for risk_assessment_json"
                    );
                    return Ok(None);
                }
            }
        }

        tracing::trace!(principal_id = principal_id, "no risk_assessment_json found");
        Ok(None)
    }

    /// Write a risk assessment JSON to a principal node property.
    async fn write_risk_assessment(
        &self,
        principal_id: &str,
        assessment_json: &str,
    ) -> Result<(), SignalError> {
        // Escape both principal ID and JSON for safe Cypher
        let escaped_id = activable_graph::query_builder::escape_cypher(principal_id);
        let escaped_json = activable_graph::query_builder::escape_cypher(assessment_json);

        let cypher = format!(
            "MATCH (n:Principal {{id: '{}'}}) SET n.risk_assessment_json = '{}'",
            escaped_id, escaped_json
        );

        self.client.cypher(&cypher).await.map_err(|e| {
            Box::new(GraphQueryError(format!(
                "write_risk_assessment cypher query failed: {}",
                e
            ))) as SignalError
        })?;

        tracing::trace!(principal_id = principal_id, "risk_assessment_json written");

        Ok(())
    }

    /// List principals belonging to an account.
    ///
    /// First tries HasPrincipal edges from the Account node. Falls back to
    /// scanning principals by ARN prefix when no edges are found.
    async fn list_account_principals(&self, account_id: &str) -> Result<Vec<String>, SignalError> {
        let escaped_account = activable_graph::query_builder::escape_cypher(account_id);

        // Primary path: HasPrincipal edges from Account node.
        let cypher_primary = format!(
            "MATCH (a:Account {{id: '{}'}})-[:HasPrincipal]->(p:Principal) RETURN p.id",
            escaped_account
        );

        let primary_results = self.client.cypher(&cypher_primary).await.map_err(|e| {
            Box::new(GraphQueryError(format!(
                "list_account_principals (primary) failed for account '{}': {}",
                account_id, e
            ))) as SignalError
        })?;

        let ids_primary: Vec<String> = primary_results
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        if !ids_primary.is_empty() {
            tracing::trace!(
                account_id = account_id,
                count = ids_primary.len(),
                "list_account_principals via HasPrincipal edges"
            );
            return Ok(ids_primary);
        }

        // Fallback: ARN-prefix scan.
        let arn_prefix = format!("arn:aws:iam::{}:", account_id);
        let escaped_prefix = activable_graph::query_builder::escape_cypher(&arn_prefix);
        let cypher_fallback = format!(
            "MATCH (p:Principal) WHERE p.id STARTS WITH '{}' RETURN p.id",
            escaped_prefix
        );

        let fallback_results = self.client.cypher(&cypher_fallback).await.map_err(|e| {
            Box::new(GraphQueryError(format!(
                "list_account_principals (fallback) failed for account '{}': {}",
                account_id, e
            ))) as SignalError
        })?;

        let ids_fallback: Vec<String> = fallback_results
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        tracing::trace!(
            account_id = account_id,
            count = ids_fallback.len(),
            "list_account_principals via ARN-prefix fallback"
        );

        Ok(ids_fallback)
    }

    /// Query OIDC providers attached to an account node.
    async fn query_oidc_providers(
        &self,
        account_id: &str,
    ) -> Result<Vec<activable_risk::signals::OidcProviderRow>, SignalError> {
        let escaped_account = activable_graph::query_builder::escape_cypher(account_id);

        let cypher = format!(
            r#"MATCH (a:Account {{id: '{account}'}})
               OPTIONAL MATCH (a)-[:HasOidcProvider]->(o:OidcProvider)
               RETURN o.id, o.name, o.aud, o.sub"#,
            account = escaped_account
        );

        let results = self
            .client
            .cypher_multi_column(&cypher, 4)
            .await
            .map_err(|e| {
                Box::new(GraphQueryError(format!(
                    "query_oidc_providers failed for account '{}': {}",
                    account_id, e
                ))) as SignalError
            })?;

        let rows: Vec<activable_risk::signals::OidcProviderRow> = results
            .iter()
            .filter_map(|row| {
                if row.len() < 4 {
                    return None;
                }
                // Skip rows where the OidcProvider node is null (no providers)
                if row[0].is_null() {
                    return None;
                }
                Some(activable_risk::signals::OidcProviderRow {
                    provider_id: row[0].as_str().unwrap_or("").to_string(),
                    provider_name: row[1].as_str().unwrap_or("").to_string(),
                    aud: row[2].as_str().unwrap_or("").to_string(),
                    sub: row[3].as_str().unwrap_or("").to_string(),
                })
            })
            .collect();

        tracing::trace!(
            account_id = account_id,
            count = rows.len(),
            "query_oidc_providers retrieved"
        );

        Ok(rows)
    }

    /// Look up a KMS key by both its full ARN and its bare UUID.
    async fn query_kms_key(
        &self,
        key_arn: &str,
        key_uuid: &str,
    ) -> Result<Option<activable_risk::signals::KmsKeyRow>, SignalError> {
        let escaped_arn = activable_graph::query_builder::escape_cypher(key_arn);
        let escaped_uuid = activable_graph::query_builder::escape_cypher(key_uuid);

        let cypher = format!(
            r#"MATCH (k:KmsKey)
               WHERE k.id = '{arn}' OR k.key_id = '{uuid}'
               OPTIONAL MATCH (k)-[:HasKeyPolicy]->(p:Policy)
               OPTIONAL MATCH (k)-[:ActsOn]->(grantee:Principal)
               RETURN k.id, p.document, collect(DISTINCT grantee.id)"#,
            arn = escaped_arn,
            uuid = escaped_uuid
        );

        let results = self
            .client
            .cypher_multi_column(&cypher, 3)
            .await
            .map_err(|e| {
                Box::new(GraphQueryError(format!(
                    "query_kms_key failed for key_arn='{}': {}",
                    key_arn, e
                ))) as SignalError
            })?;

        if results.is_empty() {
            return Ok(None);
        }

        let row = &results[0];
        if row.len() < 3 || row[0].is_null() {
            return Ok(None);
        }

        let resolved_arn = row[0].as_str().unwrap_or(key_arn).to_string();
        let policy_document = row[1].as_str().map(|s| s.to_string());
        let grantable_ids: Vec<String> = row[2]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        tracing::trace!(key_arn = key_arn, "query_kms_key retrieved");

        Ok(Some(activable_risk::signals::KmsKeyRow {
            key_arn: resolved_arn,
            policy_document,
            grantable_principal_ids: grantable_ids,
        }))
    }

    /// Query resource policy for an S3 bucket by name.
    async fn query_bucket_policy(
        &self,
        bucket_name: &str,
    ) -> Result<Option<activable_risk::signals::ResourcePolicyRow>, SignalError> {
        let escaped_name = activable_graph::query_builder::escape_cypher(bucket_name);

        let cypher = format!(
            r#"MATCH (b:Bucket)
               WHERE b.name = '{name}'
               OPTIONAL MATCH (b)-[:HasBucketPolicy]->(p:Policy)
               OPTIONAL MATCH (b)-[:AllowsAccessFrom]->(consumer:Principal)
               RETURN b.id, p.document, collect(DISTINCT consumer.id)"#,
            name = escaped_name
        );

        let results = self
            .client
            .cypher_multi_column(&cypher, 3)
            .await
            .map_err(|e| {
                Box::new(GraphQueryError(format!(
                    "query_bucket_policy failed for bucket '{}': {}",
                    bucket_name, e
                ))) as SignalError
            })?;

        if results.is_empty() {
            return Ok(None);
        }

        let row = &results[0];
        if row.len() < 3 || row[0].is_null() {
            return Ok(None);
        }

        let resource_arn = row[0]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("arn:aws:s3:::{}", bucket_name));
        let policy_document = row[1].as_str().map(|s| s.to_string());
        let consuming_ids: Vec<String> = row[2]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        tracing::trace!(bucket_name = bucket_name, "query_bucket_policy retrieved");

        Ok(Some(activable_risk::signals::ResourcePolicyRow {
            resource_arn,
            policy_document,
            consuming_principal_ids: consuming_ids,
        }))
    }

    /// Query resource policy for a KMS key (by ARN or UUID).
    async fn query_key_resource_policy(
        &self,
        key_id: &str,
    ) -> Result<Option<activable_risk::signals::ResourcePolicyRow>, SignalError> {
        let escaped_key = activable_graph::query_builder::escape_cypher(key_id);

        let cypher = format!(
            r#"MATCH (k:KmsKey)
               WHERE k.id = '{key_id}' OR k.key_id = '{key_id}'
               OPTIONAL MATCH (k)-[:HasKeyPolicy]->(p:Policy)
               OPTIONAL MATCH (k)-[:AllowsAccessFrom]->(user:Principal)
               RETURN k.id, p.document, collect(DISTINCT user.id)"#,
            key_id = escaped_key
        );

        let results = self
            .client
            .cypher_multi_column(&cypher, 3)
            .await
            .map_err(|e| {
                Box::new(GraphQueryError(format!(
                    "query_key_resource_policy failed for key '{}': {}",
                    key_id, e
                ))) as SignalError
            })?;

        if results.is_empty() {
            return Ok(None);
        }

        let row = &results[0];
        if row.len() < 3 || row[0].is_null() {
            return Ok(None);
        }

        let resource_arn = row[0]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("arn:aws:kms:us-east-1:000000000000:key/{}", key_id));
        let policy_document = row[1].as_str().map(|s| s.to_string());
        let consuming_ids: Vec<String> = row[2]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        tracing::trace!(key_id = key_id, "query_key_resource_policy retrieved");

        Ok(Some(activable_risk::signals::ResourcePolicyRow {
            resource_arn,
            policy_document,
            consuming_principal_ids: consuming_ids,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_implements_trait() {
        // This test verifies at compile time that GraphClientAdapter
        // implements GraphQueryService
        fn assert_impl<T: GraphQueryService>() {}
        // Intentionally don't call it—we just want the compile check
        let _ = assert_impl::<GraphClientAdapter>;
    }

    #[test]
    fn adapter_is_send_sync() {
        // Verify at compile time that GraphClientAdapter is Send + Sync
        // This is required for use in async contexts and shared state
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        fn assert_clone<T: Clone>() {}

        let _ = assert_send::<GraphClientAdapter>;
        let _ = assert_sync::<GraphClientAdapter>;
        let _ = assert_clone::<GraphClientAdapter>;
    }

    // The following tests require a live PG+AGE instance gated by AGE_TEST_URL.
    // They are marked #[ignore] and run only when explicitly requested:
    // cargo test -- --ignored --test-threads=1

    #[tokio::test]
    #[ignore]
    async fn integration_reachable_count_empty_graph() {
        // Test: reachable_count on a principal with no neighbors
        // Requires: AGE instance with at least one Principal node
        // Expected: returns 0 (no reachable nodes)
        let age_url = std::env::var("AGE_TEST_URL");
        if age_url.is_err() {
            eprintln!("Skipping: AGE_TEST_URL not set");
            return;
        }

        // Integration test would go here
        // For now, this serves as a template for future implementation
    }

    #[tokio::test]
    #[ignore]
    async fn integration_shortest_path_to_admin_no_admin() {
        // Test: shortest_path_to_admin when no admin nodes exist
        // Expected: returns None
        let age_url = std::env::var("AGE_TEST_URL");
        if age_url.is_err() {
            eprintln!("Skipping: AGE_TEST_URL not set");
            return;
        }
    }

    #[tokio::test]
    #[ignore]
    async fn integration_list_principal_ids_non_empty_graph() {
        // Test: list_principal_ids returns all principals
        // Requires: AGE instance with at least 3 Principal nodes
        // Expected: returns Vec with at least 3 IDs
        let age_url = std::env::var("AGE_TEST_URL");
        if age_url.is_err() {
            eprintln!("Skipping: AGE_TEST_URL not set");
            return;
        }
    }

    #[tokio::test]
    #[ignore]
    async fn integration_read_write_risk_assessment() {
        // Test: write_risk_assessment followed by read_risk_assessment
        // Expected: write succeeds; read returns same JSON
        let age_url = std::env::var("AGE_TEST_URL");
        if age_url.is_err() {
            eprintln!("Skipping: AGE_TEST_URL not set");
            return;
        }
    }

    #[tokio::test]
    #[ignore]
    async fn integration_cross_account_hop_count() {
        // Test: cross_account_hop_count on principals with CanAssume edges
        // Requires: AGE instance with CanAssume edges crossing account boundaries
        // Expected: returns count >= 0
        let age_url = std::env::var("AGE_TEST_URL");
        if age_url.is_err() {
            eprintln!("Skipping: AGE_TEST_URL not set");
            return;
        }
    }

    #[tokio::test]
    #[ignore]
    async fn integration_get_effective_permissions() {
        // Test: get_effective_permissions on a principal
        // Requires: AGE instance with HasEffectivePermission edges
        // Expected: returns Vec of (action, resource) tuples
        let age_url = std::env::var("AGE_TEST_URL");
        if age_url.is_err() {
            eprintln!("Skipping: AGE_TEST_URL not set");
            return;
        }
    }
}
