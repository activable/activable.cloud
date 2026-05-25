//! S3 enricher: extracts bucket nodes, bucket policies, and access edges.

use crate::error::IngestError;
use crate::native::{EnrichmentStats, NativeEnricher};
use crate::native::resource_policy::parse_resource_policy;
use crate::native::sentinel::{ensure_wildcard_principal, WILDCARD_PRINCIPAL_ID};
use activable_graph::loader::{load_nodes, load_edges, load_edges_with_props};
use async_trait::async_trait;
use aws_config::SdkConfig;
use deadpool_postgres::Pool;
use serde_json::{json, Value};
use sha2::Digest;
use std::sync::Arc;
use tracing::{debug, warn};

/// S3 enricher that extracts bucket nodes, bucket policies, and creates access edges.
pub struct S3Enricher {
    config: SdkConfig,
}

impl S3Enricher {
    /// Create a new S3 enricher with the given AWS config.
    pub fn new(config: SdkConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NativeEnricher for S3Enricher {
    fn service(&self) -> &str {
        "s3"
    }

    async fn enrich(
        &self,
        pool: &Arc<Pool>,
        graph_name: &str,
    ) -> Result<EnrichmentStats, IngestError> {
        // LocalStack does not serve the virtual-hosted/s3express endpoint the SDK resolves by default;
        // force path-style addressing when using a custom endpoint to ensure compatibility.
        let client = if std::env::var("AWS_ENDPOINT_URL").is_ok() {
            let s3_conf = aws_sdk_s3::config::Builder::from(&self.config)
                .force_path_style(true)
                .build();
            aws_sdk_s3::Client::from_conf(s3_conf)
        } else {
            aws_sdk_s3::Client::new(&self.config)
        };

        debug!("Starting S3 enrichment");

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

        // List all buckets
        let bucket_list = client
            .list_buckets()
            .send()
            .await
            .map_err(|e| IngestError::AwsSdk(format!("Failed to list S3 buckets: {}", e)))?;

        let mut bucket_nodes: Vec<Value> = Vec::new();
        let mut policy_nodes: Vec<Value> = Vec::new();
        let mut has_bucket_policy_edges: Vec<(String, String)> = Vec::new();
        let mut allows_access_edges: Vec<(String, String, Value)> = Vec::new();

        for bucket in bucket_list.buckets() {
            let Some(bucket_name) = bucket.name() else {
                continue;
            };
            let bucket_name_str = bucket_name.to_string();
            let bucket_arn = format!("arn:aws:s3:::{}", bucket_name_str);

            // Get bucket location to extract region (best-effort)
            let region = match client
                .get_bucket_location()
                .bucket(&bucket_name_str)
                .send()
                .await
            {
                Ok(loc_resp) => loc_resp
                    .location_constraint()
                    .map(|lc| lc.as_str().to_string())
                    .unwrap_or_else(|| "us-east-1".to_string()),
                Err(_) => "us-east-1".to_string(),
            };

            // Create Bucket node
            bucket_nodes.push(json!({
                "id": bucket_arn,
                "name": bucket_name_str,
                "region": region,
                "account_id": account_id,
            }));

            // Try to get the bucket policy
            match client
                .get_bucket_policy()
                .bucket(&bucket_name_str)
                .send()
                .await
            {
                Ok(policy_resp) => {
                    if let Some(policy_doc_str) = policy_resp.policy() {
                        // Create Policy node
                        let policy_id = format!(
                            "sha256:{:x}:bucket-policy",
                            sha2::Sha256::digest(bucket_arn.as_bytes())
                        );
                        policy_nodes.push(json!({
                            "id": policy_id.clone(),
                            "name": format!("{}/bucket-policy", bucket_name_str),
                            "source": "bucket",
                            "document": policy_doc_str,
                        }));

                        // Create HasBucketPolicy edge
                        has_bucket_policy_edges.push((bucket_arn.clone(), policy_id.clone()));

                        // Parse the policy document
                        match parse_resource_policy(policy_doc_str) {
                            Ok(statements) => {
                                for stmt in statements {
                                    let condition_keys_json = json!(stmt.condition_keys);

                                    if stmt.wildcard_principal {
                                        // Single edge to WildcardPrincipal sentinel
                                        allows_access_edges.push((
                                            bucket_arn.clone(),
                                            WILDCARD_PRINCIPAL_ID.to_string(),
                                            json!({
                                                "wildcard_principal": true,
                                                "condition_keys": condition_keys_json,
                                            }),
                                        ));
                                    } else {
                                        // Cap at 50 explicit principal edges; if > 50, emit 49 + 1 sentinel
                                        if stmt.principals.len() > 50 {
                                            // Emit 49 explicit edges
                                            for principal in stmt.principals.iter().take(49) {
                                                allows_access_edges.push((
                                                    bucket_arn.clone(),
                                                    principal.clone(),
                                                    json!({
                                                        "condition_keys": condition_keys_json,
                                                    }),
                                                ));
                                            }
                                            // Emit sentinel edge
                                            allows_access_edges.push((
                                                bucket_arn.clone(),
                                                WILDCARD_PRINCIPAL_ID.to_string(),
                                                json!({
                                                    "cap_exceeded": true,
                                                    "condition_keys": condition_keys_json,
                                                }),
                                            ));
                                        } else {
                                            // Emit all explicit edges
                                            for principal in &stmt.principals {
                                                allows_access_edges.push((
                                                    bucket_arn.clone(),
                                                    principal.clone(),
                                                    json!({
                                                        "condition_keys": condition_keys_json,
                                                    }),
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    bucket = %bucket_name_str,
                                    error = %e,
                                    "Failed to parse S3 bucket policy"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    let error_message = e.to_string();
                    if error_message.contains("NoSuchBucketPolicy")
                        || error_message.contains("The bucket policy does not exist")
                    {
                        debug!(bucket = %bucket_name_str, "No bucket policy configured (expected)");
                    } else {
                        warn!(
                            bucket = %bucket_name_str,
                            error = %e,
                            "get_bucket_policy failed"
                        );
                    }
                }
            }
        }

        // Write nodes and edges
        let mut total_edges = 0u32;

        if !bucket_nodes.is_empty() {
            debug!(count = bucket_nodes.len(), "Writing Bucket nodes");
            load_nodes(pool.clone(), graph_name, "Bucket", &bucket_nodes, 100).await?;
        }

        if !policy_nodes.is_empty() {
            debug!(count = policy_nodes.len(), "Writing Policy nodes");
            load_nodes(pool.clone(), graph_name, "Policy", &policy_nodes, 100).await?;
        }

        if !has_bucket_policy_edges.is_empty() {
            debug!(count = has_bucket_policy_edges.len(), "Writing HasBucketPolicy edges");
            let written = load_edges(
                pool.clone(),
                graph_name,
                "HasBucketPolicy",
                &has_bucket_policy_edges,
                100,
            )
            .await?;
            total_edges += written as u32;
        }

        if !allows_access_edges.is_empty() {
            debug!(count = allows_access_edges.len(), "Writing AllowsAccessFrom edges");
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

        Ok(EnrichmentStats {
            service: self.service().to_string(),
            edges_created: total_edges,
        })
    }
}
