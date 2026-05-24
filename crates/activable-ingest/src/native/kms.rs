//! KMS key-policy ingester: KMS keys, key policies, AllowsAccessFrom + KmsGrantable edges.

use crate::error::IngestError;
use crate::native::{EnrichmentStats, NativeEnricher};
use crate::native::resource_policy::parse_resource_policy;
use crate::native::sentinel::{ensure_wildcard_principal, WILDCARD_PRINCIPAL_ID};
use activable_graph::loader::{load_nodes, load_edges, load_edges_with_props};
use async_trait::async_trait;
use aws_config::SdkConfig;
use deadpool_postgres::Pool;
use serde_json::json;
use sha2::Digest;
use std::sync::Arc;
use tracing::{debug, warn};

/// KMS enricher that extracts key policies and creates access edges.
pub struct KmsEnricher {
    config: SdkConfig,
}

impl KmsEnricher {
    /// Create a new KMS enricher with the given AWS config.
    pub fn new(config: SdkConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NativeEnricher for KmsEnricher {
    fn service(&self) -> &str {
        "kms"
    }

    async fn enrich(
        &self,
        pool: &Arc<Pool>,
        graph_name: &str,
    ) -> Result<EnrichmentStats, IngestError> {
        let client = aws_sdk_kms::Client::new(&self.config);

        debug!("Starting KMS enrichment");

        // Ensure sentinel WildcardPrincipal node exists
        ensure_wildcard_principal(pool, graph_name).await?;

        // Get caller account ID from STS
        let sts_client = aws_sdk_sts::Client::new(&self.config);
        let identity = sts_client
            .get_caller_identity()
            .send()
            .await
            .map_err(|e| IngestError::AwsSdk(format!("Failed to get caller identity: {}", e)))?;
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

        // List all KMS keys
        let mut key_ids = Vec::new();
        let mut paginator = client.list_keys().into_paginator().send();
        while let Some(page) = paginator.next().await {
            match page {
                Ok(resp) => {
                    for key_list_entry in resp.keys() {
                        if let Some(key_id) = key_list_entry.key_id() {
                            key_ids.push(key_id.to_string());
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to list KMS keys");
                    break;
                }
            }
        }

        let mut key_nodes = Vec::new();
        let mut policy_nodes = Vec::new();
        let mut has_key_policy_edges: Vec<(String, String)> = Vec::new();
        let mut allows_access_edges: Vec<(String, String, serde_json::Value)> = Vec::new();
        let mut kms_grantable_edges: Vec<(String, String, serde_json::Value)> = Vec::new();

        for key_id in key_ids {
            // Describe the key
            match client.describe_key().key_id(&key_id).send().await {
                Ok(describe_resp) => {
                    if let Some(metadata) = describe_resp.key_metadata() {
                        let key_arn = metadata.arn().unwrap_or("").to_string();
                        let key_state = metadata
                            .key_state()
                            .map(|ks| format!("{:?}", ks))
                            .unwrap_or_else(|| "Unknown".to_string());
                        let key_usage = metadata
                            .key_usage()
                            .map(|ku| format!("{:?}", ku))
                            .unwrap_or_else(|| "ENCRYPT_DECRYPT".to_string());

                    // Create KmsKey node
                    key_nodes.push(json!({
                        "id": key_arn.clone(),
                        "key_id": key_id.clone(),
                        "region": region,
                        "account_id": account_id,
                        "key_usage": key_usage,
                        "key_state": key_state,
                    }));

                    // Get key policy
                    match client.get_key_policy().key_id(&key_id).policy_name("default").send().await {
                        Ok(policy_resp) => {
                            if let Some(policy_doc) = policy_resp.policy() {
                                let policy_id = format!(
                                    "sha256:{:x}:key-policy",
                                    sha2::Sha256::digest(key_arn.as_bytes())
                                );

                                // Create Policy node
                                policy_nodes.push(json!({
                                    "id": policy_id.clone(),
                                    "name": format!("{}/key-policy", key_id),
                                    "source": "kms",
                                    "document": policy_doc,
                                }));

                                // Create HasKeyPolicy edge
                                has_key_policy_edges.push((key_arn.clone(), policy_id.clone()));

                                // Parse policy and extract principals + actions
                                match parse_resource_policy(policy_doc) {
                                    Ok(statements) => {
                                        for stmt in statements {
                                            let condition_keys_json = json!(stmt.condition_keys);

                                            // Create AllowsAccessFrom edges
                                            if stmt.wildcard_principal {
                                                allows_access_edges.push((
                                                    key_arn.clone(),
                                                    WILDCARD_PRINCIPAL_ID.to_string(),
                                                    json!({
                                                        "wildcard_principal": true,
                                                        "condition_keys": condition_keys_json,
                                                    }),
                                                ));
                                            } else {
                                                if stmt.principals.len() > 50 {
                                                    // Emit 49 explicit + 1 sentinel
                                                    for principal in stmt.principals.iter().take(49) {
                                                        allows_access_edges.push((
                                                            key_arn.clone(),
                                                            principal.clone(),
                                                            json!({
                                                                "condition_keys": condition_keys_json,
                                                            }),
                                                        ));
                                                    }
                                                    allows_access_edges.push((
                                                        key_arn.clone(),
                                                        WILDCARD_PRINCIPAL_ID.to_string(),
                                                        json!({
                                                            "cap_exceeded": true,
                                                            "condition_keys": condition_keys_json,
                                                        }),
                                                    ));
                                                } else {
                                                    for principal in &stmt.principals {
                                                        allows_access_edges.push((
                                                            key_arn.clone(),
                                                            principal.clone(),
                                                            json!({
                                                                "condition_keys": condition_keys_json,
                                                            }),
                                                        ));
                                                    }
                                                }
                                            }

                                            // Check if statement allows kms:CreateGrant
                                            let allows_create_grant = stmt.actions.iter().any(|a| {
                                                a == "kms:CreateGrant" || a == "kms:*" || a == "*"
                                            });

                                            if allows_create_grant {
                                                // Create KmsGrantable edges for each principal
                                                if stmt.wildcard_principal {
                                                    kms_grantable_edges.push((
                                                        WILDCARD_PRINCIPAL_ID.to_string(),
                                                        key_arn.clone(),
                                                        json!({
                                                            "wildcard_principal": true,
                                                            "condition_keys": condition_keys_json,
                                                        }),
                                                    ));
                                                } else {
                                                    if stmt.principals.len() > 50 {
                                                        // Emit 49 explicit + 1 sentinel
                                                        for principal in stmt.principals.iter().take(49) {
                                                            kms_grantable_edges.push((
                                                                principal.clone(),
                                                                key_arn.clone(),
                                                                json!({
                                                                    "condition_keys": condition_keys_json,
                                                                }),
                                                            ));
                                                        }
                                                        kms_grantable_edges.push((
                                                            WILDCARD_PRINCIPAL_ID.to_string(),
                                                            key_arn.clone(),
                                                            json!({
                                                                "cap_exceeded": true,
                                                                "condition_keys": condition_keys_json,
                                                            }),
                                                        ));
                                                    } else {
                                                        for principal in &stmt.principals {
                                                            kms_grantable_edges.push((
                                                                principal.clone(),
                                                                key_arn.clone(),
                                                                json!({
                                                                    "condition_keys": condition_keys_json,
                                                                }),
                                                            ));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            key_id = %key_id,
                                            error = %e,
                                            "Failed to parse KMS key policy"
                                        );
                                    }
                                }
                            }
                        }
                            Err(e) => {
                                warn!(key_id = %key_id, error = %e, "Failed to fetch key policy");
                            }
                        }
                    } else {
                        warn!(key_id = %key_id, "No metadata in describe_key response");
                    }
                }
                Err(e) => {
                    warn!(key_id = %key_id, error = %e, "Failed to describe key");
                }
            }
        }

        // Write nodes and edges
        let mut total_edges = 0u32;

        if !key_nodes.is_empty() {
            debug!(count = key_nodes.len(), "Writing KmsKey nodes");
            load_nodes(pool.clone(), graph_name, "KmsKey", &key_nodes, 100).await?;
        }

        if !policy_nodes.is_empty() {
            debug!(count = policy_nodes.len(), "Writing Policy nodes");
            load_nodes(pool.clone(), graph_name, "Policy", &policy_nodes, 100).await?;
        }

        if !has_key_policy_edges.is_empty() {
            debug!(count = has_key_policy_edges.len(), "Writing HasKeyPolicy edges");
            let written = load_edges(
                pool.clone(),
                graph_name,
                "HasKeyPolicy",
                &has_key_policy_edges,
                100,
            )
            .await?;
            total_edges += written as u32;
        }

        if !allows_access_edges.is_empty() {
            debug!(count = allows_access_edges.len(), "Writing AllowsAccessFrom edges (KMS)");
            let written = load_edges_with_props(
                pool.clone(),
                graph_name,
                "AllowsAccessFrom",
                &allows_access_edges,
                100,
            )
            .await?;
            total_edges += written as u32;
        }

        if !kms_grantable_edges.is_empty() {
            debug!(count = kms_grantable_edges.len(), "Writing KmsGrantable edges");
            let written = load_edges_with_props(
                pool.clone(),
                graph_name,
                "KmsGrantable",
                &kms_grantable_edges,
                100,
            )
            .await?;
            total_edges += written as u32;
        }

        Ok(EnrichmentStats {
            service: self.service().to_string(),
            edges_created: total_edges,
        })
    }
}
