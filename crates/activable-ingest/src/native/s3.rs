//! S3 enricher: extracts bucket policies and creates access edges.

use crate::error::IngestError;
use crate::native::{EnrichmentStats, NativeEnricher};
use activable_graph::loader::load_edges;
use async_trait::async_trait;
use aws_config::SdkConfig;
use deadpool_postgres::Pool;
use std::sync::Arc;
use tracing::{debug, warn};

/// S3 enricher that extracts principals from bucket policies and creates access edges.
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
        let client = aws_sdk_s3::Client::new(&self.config);
        let mut edges: Vec<(String, String)> = Vec::new();

        debug!("Starting S3 enrichment");

        // List all buckets
        let bucket_list = client
            .list_buckets()
            .send()
            .await
            .map_err(|e| IngestError::AwsSdk(format!("Failed to list S3 buckets: {}", e)))?;

        for bucket in bucket_list.buckets() {
            let Some(bucket_name) = bucket.name() else {
                continue;
            };
            let bucket_name_str = bucket_name.to_string();

            // Try to get the bucket policy
            match client
                .get_bucket_policy()
                .bucket(&bucket_name_str)
                .send()
                .await
            {
                Ok(policy_resp) => {
                    if let Some(policy_doc_str) = policy_resp.policy() {
                        match serde_json::from_str::<serde_json::Value>(policy_doc_str) {
                            Ok(policy) => {
                                // Extract principals from Statement array
                                if let Some(statements) =
                                    policy.get("Statement").and_then(|s| s.as_array())
                                {
                                    for statement in statements {
                                        if let Some(principal) = statement.get("Principal") {
                                            // AWS principals
                                            if let Some(aws_val) = principal.get("AWS") {
                                                for principal_arn in
                                                    extract_string_or_array(aws_val)
                                                {
                                                    edges.push((
                                                        principal_arn,
                                                        bucket_name_str.clone(),
                                                    ));
                                                }
                                            }
                                            // Service principals
                                            if let Some(svc_val) = principal.get("Service") {
                                                for service in extract_string_or_array(svc_val) {
                                                    edges.push((service, bucket_name_str.clone()));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    bucket = %bucket_name_str,
                                    error = %e,
                                    "Failed to parse S3 bucket policy JSON"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        bucket = %bucket_name_str,
                        error = %e,
                        "No bucket policy or permission denied (expected for some buckets)"
                    );
                }
            }
        }

        // Write HasBucketPolicy edges in batches
        let mut edge_count = 0u32;
        if !edges.is_empty() {
            debug!(edge_count = edges.len(), "Writing HasBucketPolicy edges");
            let written =
                load_edges(pool.clone(), graph_name, "HasBucketPolicy", &edges, 100).await?;
            edge_count = written as u32;
        }

        Ok(EnrichmentStats {
            service: self.service().to_string(),
            edges_created: edge_count,
        })
    }
}

/// Extract a string or array of strings from a JSON value.
fn extract_string_or_array(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_string() {
        let value = serde_json::json!("arn:aws:iam::123456789012:root");
        let result = extract_string_or_array(&value);
        assert_eq!(result, vec!["arn:aws:iam::123456789012:root"]);
    }

    #[test]
    fn test_extract_array() {
        let value = serde_json::json!([
            "arn:aws:iam::123456789012:root",
            "arn:aws:iam::987654321098:root"
        ]);
        let result = extract_string_or_array(&value);
        assert_eq!(
            result,
            vec![
                "arn:aws:iam::123456789012:root",
                "arn:aws:iam::987654321098:root"
            ]
        );
    }

    #[test]
    fn test_enricher_has_service_name() {
        let enricher = S3Enricher::new(aws_config::SdkConfig::builder().build());
        assert_eq!(enricher.service(), "s3");
    }
}
