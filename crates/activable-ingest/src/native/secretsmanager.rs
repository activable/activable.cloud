//! Secrets Manager enricher: extracts Secret nodes, EncryptedBy edges, and AllowsAccessFrom edges.

use crate::error::IngestError;
use crate::native::access_edges::build_access_edges;
use crate::native::resource_policy::parse_resource_policy;
use crate::native::sentinel::{
    ensure_aws_managed_key, ensure_wildcard_principal, AWS_MANAGED_KEY_ID,
};
use crate::native::{EnrichmentStats, NativeEnricher};
use activable_graph::loader::{load_edges, load_edges_with_props, load_nodes};
use async_trait::async_trait;
use aws_config::SdkConfig;
use deadpool_postgres::Pool;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, warn};

/// Classify the KMS key target for a secret's encryption.
/// Returns the KMS key ID to use as the EncryptedBy edge target.
fn classify_secret_kms(kms_key_id: Option<&str>) -> String {
    match kms_key_id {
        None | Some("") => AWS_MANAGED_KEY_ID.to_string(),
        Some(id) => {
            if id == "aws/secretsmanager" || id.starts_with("alias/aws/") {
                AWS_MANAGED_KEY_ID.to_string()
            } else if id.starts_with("arn:aws:kms:") {
                // Customer KMS key ARN — use as-is (loader will drop edge if node missing)
                id.to_string()
            } else {
                // Bare key ID or alias — use as-is (best-effort)
                id.to_string()
            }
        }
    }
}

/// Secrets Manager enricher that extracts Secret nodes and emits EncryptedBy + AllowsAccessFrom edges.
pub struct SecretsManagerEnricher {
    config: SdkConfig,
}

impl SecretsManagerEnricher {
    /// Create a new Secrets Manager enricher with the given AWS config.
    pub fn new(config: SdkConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NativeEnricher for SecretsManagerEnricher {
    fn service(&self) -> &str {
        "secretsmanager"
    }

    async fn enrich(
        &self,
        pool: &Arc<Pool>,
        graph_name: &str,
    ) -> Result<EnrichmentStats, IngestError> {
        let client = aws_sdk_secretsmanager::Client::new(&self.config);

        debug!("Starting Secrets Manager enrichment");

        // Ensure sentinel nodes exist
        ensure_wildcard_principal(pool, graph_name).await?;
        ensure_aws_managed_key(pool, graph_name).await?;

        // Get caller account ID from STS
        let sts_client = aws_sdk_sts::Client::new(&self.config);
        let identity =
            sts_client.get_caller_identity().send().await.map_err(|e| {
                IngestError::AwsSdk(format!("Failed to get caller identity: {}", e))
            })?;
        let account_id = identity
            .account()
            .ok_or_else(|| IngestError::AwsSdk("No account ID in identity".to_string()))?
            .to_string();

        // Get caller region (best-effort from config)
        let region = self
            .config
            .region()
            .map(|r| r.as_ref().to_string())
            .unwrap_or_else(|| "us-east-1".to_string());

        // List all secrets (paginated)
        let mut secret_nodes = Vec::new();
        let mut encrypted_by_edges: Vec<(String, String)> = Vec::new();
        let mut principal_nodes_map: std::collections::HashMap<String, Value> =
            std::collections::HashMap::new();
        let mut allows_access_edges: Vec<(String, String, Value)> = Vec::new();

        let mut paginator = client.list_secrets().into_paginator().send();
        while let Some(page) = paginator.next().await {
            match page {
                Ok(resp) => {
                    for secret in resp.secret_list() {
                        let secret_arn = match secret.arn() {
                            Some(arn) => arn.to_string(),
                            None => {
                                warn!("Secret missing ARN");
                                continue;
                            }
                        };

                        let secret_name = secret.name().unwrap_or("").to_string();
                        let kms_key_id = secret.kms_key_id();
                        let rotation_enabled = secret.rotation_enabled().unwrap_or(false);

                        // Create Secret node
                        secret_nodes.push(json!({
                            "id": secret_arn.clone(),
                            "name": secret_name,
                            "account_id": account_id,
                            "region": region,
                            "kms_key_id": kms_key_id,
                            "rotation_enabled": rotation_enabled,
                        }));

                        // Build EncryptedBy edge if KMS key is resolvable
                        let kms_target = classify_secret_kms(kms_key_id);
                        encrypted_by_edges.push((secret_arn.clone(), kms_target));

                        // Try to get resource policy for AllowsAccessFrom edges
                        match client
                            .get_resource_policy()
                            .secret_id(&secret_arn)
                            .send()
                            .await
                        {
                            Ok(policy_resp) => {
                                if let Some(policy_doc_str) = policy_resp.resource_policy() {
                                    // Parse the resource policy
                                    match parse_resource_policy(policy_doc_str) {
                                        Ok(statements) => {
                                            let (edges, p_nodes) = build_access_edges(
                                                &secret_arn,
                                                &statements,
                                                &account_id,
                                            );

                                            // Dedup principal nodes by ID, keeping already-built nodes
                                            for p_node in p_nodes {
                                                let node_id =
                                                    p_node["id"].as_str().unwrap_or("").to_string();
                                                principal_nodes_map.insert(node_id, p_node);
                                            }

                                            allows_access_edges.extend(edges);
                                        }
                                        Err(e) => {
                                            warn!(
                                                secret_arn = %secret_arn,
                                                error = %e,
                                                "Failed to parse Secrets Manager resource policy"
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                // No resource policy is normal (debug, not warn)
                                debug!(
                                    secret_arn = %secret_arn,
                                    error = %e,
                                    "No resource policy (expected for most secrets)"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to list secrets (paginator error)");
                    break;
                }
            }
        }

        // Collect already-built Principal nodes from the dedup map
        let principal_nodes: Vec<Value> = principal_nodes_map.into_values().collect();

        // Write nodes and edges
        let mut total_edges = 0u32;

        if !secret_nodes.is_empty() {
            debug!(count = secret_nodes.len(), "Writing Secret nodes");
            load_nodes(pool.clone(), graph_name, "Secret", &secret_nodes, 100).await?;
        }

        if !principal_nodes.is_empty() {
            debug!(
                count = principal_nodes.len(),
                "Writing Principal nodes for Secrets Manager access policies"
            );
            load_nodes(pool.clone(), graph_name, "Principal", &principal_nodes, 100).await?;
        }

        if !encrypted_by_edges.is_empty() {
            debug!(
                count = encrypted_by_edges.len(),
                "Writing EncryptedBy edges (Secrets Manager)"
            );
            let outcome = load_edges(
                pool.clone(),
                graph_name,
                "EncryptedBy",
                &encrypted_by_edges,
                100,
                false,
            )
            .await?;
            debug!(
                created = outcome.created,
                dropped = outcome.dropped,
                "EncryptedBy edges outcome"
            );
            total_edges += outcome.created as u32;
        }

        if !allows_access_edges.is_empty() {
            debug!(
                count = allows_access_edges.len(),
                "Writing AllowsAccessFrom edges (Secrets Manager)"
            );
            let outcome = load_edges_with_props(
                pool.clone(),
                graph_name,
                "AllowsAccessFrom",
                &allows_access_edges,
                100,
                false,
            )
            .await?;
            debug!(
                created = outcome.created,
                dropped = outcome.dropped,
                "AllowsAccessFrom edges outcome"
            );
            total_edges += outcome.created as u32;
        }

        Ok(EnrichmentStats {
            service: self.service().to_string(),
            edges_created: total_edges,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_secret_kms_none() {
        let target = classify_secret_kms(None);
        assert_eq!(target, AWS_MANAGED_KEY_ID);
    }

    #[test]
    fn test_classify_secret_kms_empty() {
        let target = classify_secret_kms(Some(""));
        assert_eq!(target, AWS_MANAGED_KEY_ID);
    }

    #[test]
    fn test_classify_secret_kms_aws_managed_slash() {
        let target = classify_secret_kms(Some("aws/secretsmanager"));
        assert_eq!(target, AWS_MANAGED_KEY_ID);
    }

    #[test]
    fn test_classify_secret_kms_aws_managed_alias() {
        let target = classify_secret_kms(Some("alias/aws/secretsmanager"));
        assert_eq!(target, AWS_MANAGED_KEY_ID);
    }

    #[test]
    fn test_classify_secret_kms_customer_arn() {
        let kms_arn = "arn:aws:kms:us-east-1:999999999999:key/12345678-1234-1234-1234-123456789012";
        let target = classify_secret_kms(Some(kms_arn));
        assert_eq!(target, kms_arn);
    }

    #[test]
    fn test_classify_secret_kms_bare_key_id() {
        let key_id = "12345678-1234-1234-1234-123456789012";
        let target = classify_secret_kms(Some(key_id));
        assert_eq!(target, key_id);
    }

    #[test]
    fn test_classify_secret_kms_customer_alias_substring() {
        // Regression: customer alias like "alias/my-aws/secretsmanager" must NOT be
        // misclassified as AWS-managed. AWS reserves "alias/aws/" namespace;
        // customers cannot create aliases starting with "alias/aws/".
        let customer_alias = "alias/my-aws/secretsmanager";
        let target = classify_secret_kms(Some(customer_alias));
        assert_eq!(
            target, customer_alias,
            "Customer alias should not be misclassified as AWS-managed key"
        );
    }
}
