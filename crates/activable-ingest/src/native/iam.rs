//! IAM enricher: parses trust policies and creates CanAssume/TrustedBy edges.

use crate::error::IngestError;
use crate::native::{EnrichmentStats, NativeEnricher};
use activable_graph::loader::load_edges;
use async_trait::async_trait;
use aws_config::SdkConfig;
use deadpool_postgres::Pool;
use std::sync::Arc;
use tracing::{debug, warn};

/// IAM enricher that extracts trust relationships from IAM role assume-role policy documents.
pub struct IamEnricher {
    config: SdkConfig,
}

impl IamEnricher {
    /// Create a new IAM enricher with the given AWS config.
    pub fn new(config: SdkConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NativeEnricher for IamEnricher {
    fn service(&self) -> &str {
        "iam"
    }

    async fn enrich(
        &self,
        pool: &Arc<Pool>,
        graph_name: &str,
    ) -> Result<EnrichmentStats, IngestError> {
        let client = aws_sdk_iam::Client::new(&self.config);
        let mut edges: Vec<(String, String)> = Vec::new();

        debug!("Starting IAM enrichment");

        // List all roles and extract trust relationships
        let mut paginator = client.list_roles().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let page =
                page.map_err(|e| IngestError::AwsSdk(format!("Failed to list IAM roles: {}", e)))?;

            for role in page.roles() {
                let role_arn = role.arn().to_string();
                if role_arn.is_empty() {
                    continue;
                }

                // Get the assume-role policy document
                if let Some(policy_doc) = role.assume_role_policy_document() {
                    // URL-decode the policy document
                    let decoded = match urlencoding::decode(policy_doc) {
                        Ok(d) => d,
                        Err(e) => {
                            tracing::warn!(role = %role_arn, error = %e, "failed to URL-decode trust policy, skipping");
                            continue;
                        }
                    };
                    match serde_json::from_str::<serde_json::Value>(&decoded) {
                        Ok(policy) => {
                            // Extract principals from Statement array
                            if let Some(statements) =
                                policy.get("Statement").and_then(|s| s.as_array())
                            {
                                for statement in statements {
                                    // Extract all principals that can assume this role
                                    if let Some(principal) = statement.get("Principal") {
                                        // AWS principals (ARNs or account IDs)
                                        if let Some(aws_val) = principal.get("AWS") {
                                            for principal_arn in extract_string_or_array(aws_val) {
                                                edges.push((principal_arn, role_arn.clone()));
                                            }
                                        }
                                        // Service principals
                                        if let Some(svc_val) = principal.get("Service") {
                                            for service in extract_string_or_array(svc_val) {
                                                edges.push((service, role_arn.clone()));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                role = %role_arn,
                                error = %e,
                                "Failed to parse IAM trust policy JSON"
                            );
                        }
                    }
                }
            }
        }

        // Ensure source principals exist as nodes before creating edges.
        // Trust policies reference principals that may not be in the graph yet:
        // - "*" (wildcard) → create as Principal node
        // - "cloudformation.amazonaws.com" (service) → create as Principal node
        // - "arn:aws:iam::OTHER_ACCOUNT:root" → create as Principal node
        let mut created_sources = std::collections::HashSet::new();
        for (source, _target) in &edges {
            if !created_sources.contains(source) {
                let source_node = serde_json::json!({
                    "id": source,
                    "name": source,
                    "principal_type": if source.contains(".amazonaws.com") { "Service" }
                                     else if source == "*" { "Wildcard" }
                                     else { "External" },
                });
                // Ignore errors — node may already exist (MERGE semantics)
                let _ = activable_graph::loader::load_nodes(
                    pool.clone(), graph_name, "Principal", &[source_node], 1
                ).await;
                created_sources.insert(source.clone());
            }
        }

        // Write CanAssume edges in batches
        let mut edge_count = 0u32;
        if !edges.is_empty() {
            debug!(edge_count = edges.len(), "Writing CanAssume edges");
            let written = load_edges(pool.clone(), graph_name, "CanAssume", &edges, 100).await?;
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
        let value = serde_json::json!("arn:aws:iam::123456789012:user/admin");
        let result = extract_string_or_array(&value);
        assert_eq!(result, vec!["arn:aws:iam::123456789012:user/admin"]);
    }

    #[test]
    fn test_extract_array() {
        let value = serde_json::json!([
            "arn:aws:iam::123456789012:user/admin",
            "arn:aws:iam::123456789012:user/dev"
        ]);
        let result = extract_string_or_array(&value);
        assert_eq!(
            result,
            vec![
                "arn:aws:iam::123456789012:user/admin",
                "arn:aws:iam::123456789012:user/dev"
            ]
        );
    }

    #[test]
    fn test_extract_empty() {
        let value = serde_json::json!(null);
        let result = extract_string_or_array(&value);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_array_with_non_strings() {
        let value = serde_json::json!(["arn:aws:iam::123456789012:user/admin", 123, null]);
        let result = extract_string_or_array(&value);
        assert_eq!(result, vec!["arn:aws:iam::123456789012:user/admin"]);
    }
}
