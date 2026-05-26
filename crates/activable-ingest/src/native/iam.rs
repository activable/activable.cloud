//! IAM enricher: parses trust policies and creates CanAssume/TrustedBy edges.

use crate::error::IngestError;
use crate::native::{EnrichmentStats, NativeEnricher};
use activable_graph::loader::{load_edges, load_nodes};
use async_trait::async_trait;
use aws_config::SdkConfig;
use deadpool_postgres::Pool;
use serde_json::json;
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
        let mut oidc_provider_nodes: Vec<serde_json::Value> = Vec::new();
        let mut has_oidc_provider_edges: Vec<(String, String)> = Vec::new();

        debug!("Starting IAM enrichment");

        // Get STS caller identity to extract account ID
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
                                        // Federated principals (OIDC providers)
                                        if let Some(fed_val) = principal.get("Federated") {
                                            for federated_arn in extract_string_or_array(fed_val) {
                                                if federated_arn.contains(":oidc-provider/") {
                                                    // Extract provider name and conditions
                                                    if let Some(provider_name) = extract_oidc_provider_name(&federated_arn) {
                                                        let (aud, sub) = extract_oidc_conditions(statement);
                                                        let provider_id = federated_arn.clone();

                                                        // Create OidcProvider node
                                                        oidc_provider_nodes.push(json!({
                                                            "id": provider_id.clone(),
                                                            "provider_name": provider_name,
                                                            "account_id": account_id,
                                                            "aud": aud,
                                                            "sub": sub,
                                                        }));

                                                        // Create HasOidcProvider edge from Account to OidcProvider
                                                        // Source is the raw account ID (matching Account node id)
                                                        has_oidc_provider_edges.push((
                                                            account_id.clone(),
                                                            provider_id,
                                                        ));
                                                    }
                                                }
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

        // Ensure Account node exists (for OIDC HasOidcProvider edges)
        // Account node id is the raw 12-digit account ID (matching resolver queries)
        let account_node = serde_json::json!({
            "id": account_id.clone(),
            "name": account_id.clone(),
            "account_id": account_id.clone(),
        });
        let _ = activable_graph::loader::load_nodes(
            pool.clone(), graph_name, "Account", &[account_node], 1
        ).await;

        // Write OidcProvider nodes
        let mut edge_count = 0u32;
        if !oidc_provider_nodes.is_empty() {
            debug!(count = oidc_provider_nodes.len(), "Writing OidcProvider nodes");
            let _ = load_nodes(
                pool.clone(),
                graph_name,
                "OidcProvider",
                &oidc_provider_nodes,
                100,
            )
            .await?;
        }

        // Write HasOidcProvider edges
        if !has_oidc_provider_edges.is_empty() {
            debug!(count = has_oidc_provider_edges.len(), "Writing HasOidcProvider edges");
            let outcome = load_edges(
                pool.clone(),
                graph_name,
                "HasOidcProvider",
                &has_oidc_provider_edges,
                100,
                false,
            )
            .await?;
            debug!(created = outcome.created, dropped = outcome.dropped, "HasOidcProvider edges outcome");
            edge_count += outcome.created as u32;
        }

        // Write CanAssume edges in batches
        if !edges.is_empty() {
            debug!(edge_count = edges.len(), "Writing CanAssume edges");
            let outcome = load_edges(pool.clone(), graph_name, "CanAssume", &edges, 100, false).await?;
            debug!(created = outcome.created, dropped = outcome.dropped, "CanAssume edges outcome");
            edge_count += outcome.created as u32;
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

/// Extract the provider name (hostname) from an OIDC provider ARN.
/// For example: "arn:aws:iam::222222222222:oidc-provider/token.actions.githubusercontent.com"
/// returns "token.actions.githubusercontent.com".
fn extract_oidc_provider_name(arn: &str) -> Option<String> {
    if let Some(idx) = arn.find(":oidc-provider/") {
        let part = &arn[idx + ":oidc-provider/".len()..];
        if !part.is_empty() {
            return Some(part.to_string());
        }
    }
    None
}

/// Extract aud (audience) and sub (subject) condition values from an OIDC trust statement.
/// Returns (aud, sub) as strings; empty string if not present or if the value is "*".
fn extract_oidc_conditions(statement: &serde_json::Value) -> (String, String) {
    let mut aud = String::new();
    let mut sub = String::new();

    if let Some(condition_obj) = statement.get("Condition").and_then(|c| c.as_object()) {
        // Look for StringEquals or StringLike with aud keys
        for (_op, condition_map) in condition_obj {
            if let Some(cond_map) = condition_map.as_object() {
                for (key, value) in cond_map {
                    if key.ends_with(":aud") {
                        if let Some(s) = value.as_str() {
                            if s != "*" {
                                aud = s.to_string();
                            }
                        } else if let Some(arr) = value.as_array() {
                            if let Some(first) = arr.first().and_then(|v| v.as_str()) {
                                if first != "*" {
                                    aud = first.to_string();
                                }
                            }
                        }
                    } else if key.ends_with(":sub") {
                        if let Some(s) = value.as_str() {
                            if s != "*" {
                                sub = s.to_string();
                            }
                        } else if let Some(arr) = value.as_array() {
                            if let Some(first) = arr.first().and_then(|v| v.as_str()) {
                                if first != "*" {
                                    sub = first.to_string();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    (aud, sub)
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

    #[test]
    fn test_extract_oidc_provider_name() {
        let arn = "arn:aws:iam::222222222222:oidc-provider/token.actions.githubusercontent.com";
        let name = extract_oidc_provider_name(arn);
        assert_eq!(name, Some("token.actions.githubusercontent.com".to_string()));
    }

    #[test]
    fn test_extract_oidc_provider_name_invalid() {
        let arn = "arn:aws:iam::222222222222:role/MyRole";
        let name = extract_oidc_provider_name(arn);
        assert_eq!(name, None);
    }

    #[test]
    fn test_extract_oidc_conditions_with_broad_aud() {
        let statement = serde_json::json!({
            "Effect": "Allow",
            "Principal": { "Federated": "arn:aws:iam::222:oidc-provider/token.actions.githubusercontent.com" },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "*"
                }
            }
        });
        let (aud, sub) = extract_oidc_conditions(&statement);
        assert_eq!(aud, ""); // Wildcard should result in empty string
        assert_eq!(sub, "");
    }

    #[test]
    fn test_extract_oidc_conditions_with_specific_values() {
        let statement = serde_json::json!({
            "Effect": "Allow",
            "Principal": { "Federated": "arn:aws:iam::222:oidc-provider/token.actions.githubusercontent.com" },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "123456789",
                    "token.actions.githubusercontent.com:sub": "repo:org/repo:ref:refs/heads/main"
                }
            }
        });
        let (aud, sub) = extract_oidc_conditions(&statement);
        assert_eq!(aud, "123456789");
        assert_eq!(sub, "repo:org/repo:ref:refs/heads/main");
    }

    #[test]
    fn test_extract_oidc_conditions_array_format() {
        let statement = serde_json::json!({
            "Effect": "Allow",
            "Principal": { "Federated": "arn:aws:iam::222:oidc-provider/token.actions.githubusercontent.com" },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringLike": {
                    "token.actions.githubusercontent.com:sub": ["repo:myorg/repo-a:*", "repo:myorg/repo-b:*"]
                }
            }
        });
        let (aud, sub) = extract_oidc_conditions(&statement);
        assert_eq!(aud, "");
        assert_eq!(sub, "repo:myorg/repo-a:*");
    }

    #[test]
    fn test_extract_oidc_conditions_missing() {
        let statement = serde_json::json!({
            "Effect": "Allow",
            "Principal": { "Federated": "arn:aws:iam::222:oidc-provider/token.actions.githubusercontent.com" },
            "Action": "sts:AssumeRoleWithWebIdentity"
        });
        let (aud, sub) = extract_oidc_conditions(&statement);
        assert_eq!(aud, "");
        assert_eq!(sub, "");
    }
}
