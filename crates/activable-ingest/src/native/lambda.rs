//! Lambda enricher: extracts Function resource-policy AllowsAccessFrom edges.
//! Lambda functions already exist as Resource nodes from native_fallback::fetch_lambda_functions.
//! This enricher adds access policy edges via GetPolicy → parse_resource_policy → AllowsAccessFrom.

use crate::error::IngestError;
use crate::native::access_edges::build_access_edges;
use crate::native::resource_policy::parse_resource_policy;
use crate::native::sentinel::ensure_wildcard_principal;
use crate::native::{EnrichmentStats, NativeEnricher};
use activable_graph::loader::{load_edges_with_props, load_nodes};
use async_trait::async_trait;
use aws_config::SdkConfig;
use deadpool_postgres::Pool;
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, warn};

/// Lambda enricher that extracts resource-policy AllowsAccessFrom edges from Lambda functions.
pub struct LambdaEnricher {
    config: SdkConfig,
}

impl LambdaEnricher {
    /// Create a new Lambda enricher with the given AWS config.
    pub fn new(config: SdkConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NativeEnricher for LambdaEnricher {
    fn service(&self) -> &str {
        "lambda"
    }

    async fn enrich(
        &self,
        pool: &Arc<Pool>,
        graph_name: &str,
    ) -> Result<EnrichmentStats, IngestError> {
        let client = aws_sdk_lambda::Client::new(&self.config);

        debug!("Starting Lambda enrichment");

        // Ensure sentinel nodes exist (wildcard principal)
        ensure_wildcard_principal(pool, graph_name).await?;

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

        // List all Lambda functions and collect policy edges
        let mut principal_nodes_map: std::collections::HashMap<String, Value> =
            std::collections::HashMap::new();
        let mut allows_access_edges: Vec<(String, String, Value)> = Vec::new();

        let mut paginator = client.list_functions().into_paginator().send();
        while let Some(page) = paginator.next().await {
            match page {
                Ok(resp) => {
                    for func in resp.functions() {
                        let function_arn = match func.function_arn() {
                            Some(arn) => arn.to_string(),
                            None => {
                                warn!("Lambda function missing ARN");
                                continue;
                            }
                        };

                        // Try to get resource policy for AllowsAccessFrom edges
                        match client
                            .get_policy()
                            .function_name(&function_arn)
                            .send()
                            .await
                        {
                            Ok(policy_resp) => {
                                if let Some(policy_doc_str) = policy_resp.policy() {
                                    // Parse the resource policy
                                    match parse_resource_policy(policy_doc_str) {
                                        Ok(statements) => {
                                            let (edges, p_nodes) = build_access_edges(
                                                &function_arn,
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
                                                function_arn = %function_arn,
                                                error = %e,
                                                "Failed to parse Lambda resource policy"
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                // Lambda returns error when function has no resource policy — this is NORMAL (debug, not warn)
                                // Distinguish ResourceNotFound from other errors
                                let error_string = format!("{}", e);
                                if error_string.contains("ResourceNotFoundException") {
                                    debug!(
                                        function_arn = %function_arn,
                                        error = %e,
                                        "No resource policy (expected for most Lambda functions)"
                                    );
                                } else {
                                    warn!(
                                        function_arn = %function_arn,
                                        error = %e,
                                        "Failed to get Lambda policy"
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to list Lambda functions (paginator error)");
                    break;
                }
            }
        }

        // Collect already-built Principal nodes from the dedup map
        let principal_nodes: Vec<Value> = principal_nodes_map.into_values().collect();

        // Write nodes and edges
        let mut total_edges = 0u32;

        if !principal_nodes.is_empty() {
            debug!(
                count = principal_nodes.len(),
                "Writing Principal nodes for Lambda resource policies"
            );
            load_nodes(pool.clone(), graph_name, "Principal", &principal_nodes, 100).await?;
        }

        if !allows_access_edges.is_empty() {
            debug!(
                count = allows_access_edges.len(),
                "Writing AllowsAccessFrom edges (Lambda)"
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
    use crate::native::resource_policy::ParsedStatement;

    #[test]
    fn test_lambda_service_principal_edge() {
        // Test that a service principal grant (e.g., events.amazonaws.com invoking a Lambda)
        // creates a Principal node with service=true
        let function_arn = "arn:aws:lambda:us-east-1:999999999999:function:MyFunction";
        let service_principal = "events.amazonaws.com";

        let stmt = ParsedStatement {
            effect: "Allow".to_string(),
            principals: vec![service_principal.to_string()],
            actions: vec!["lambda:InvokeFunction".to_string()],
            condition_keys: vec![],
            wildcard_principal: false,
        };

        let (edges, principal_nodes) = build_access_edges(function_arn, &[stmt], "999999999999");

        // Should have 1 edge and 1 principal node
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].0, function_arn);
        assert_eq!(edges[0].1, service_principal);

        // Principal node should have service=true
        assert_eq!(principal_nodes.len(), 1);
        assert_eq!(principal_nodes[0]["id"], service_principal);
        assert_eq!(principal_nodes[0]["service"], true);
    }

    #[test]
    fn test_lambda_cross_account_principal_edge() {
        // Test that a cross-account principal grant creates an external Principal node
        let function_arn = "arn:aws:lambda:us-east-1:999999999999:function:MyFunction";
        let cross_account_principal = "arn:aws:iam::111111111111:root";

        let stmt = ParsedStatement {
            effect: "Allow".to_string(),
            principals: vec![cross_account_principal.to_string()],
            actions: vec!["lambda:InvokeFunction".to_string()],
            condition_keys: vec![],
            wildcard_principal: false,
        };

        let (edges, principal_nodes) = build_access_edges(function_arn, &[stmt], "999999999999");

        // Should have 1 edge and 1 principal node
        assert_eq!(edges.len(), 1);
        assert_eq!(principal_nodes.len(), 1);

        // Principal node should have external=true
        assert_eq!(principal_nodes[0]["external"], true);
    }

    #[test]
    fn test_lambda_wildcard_principal() {
        // Test that wildcard principal creates a sentinel edge, not a principal node
        let function_arn = "arn:aws:lambda:us-east-1:999999999999:function:MyFunction";

        let stmt = ParsedStatement {
            effect: "Allow".to_string(),
            principals: vec!["*".to_string()],
            actions: vec!["lambda:InvokeFunction".to_string()],
            condition_keys: vec![],
            wildcard_principal: true,
        };

        let (edges, principal_nodes) = build_access_edges(function_arn, &[stmt], "999999999999");

        // Should have 1 edge to wildcard sentinel
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].1, "*");
        assert_eq!(edges[0].2["wildcard_principal"], true);

        // No principal nodes should be created for wildcard
        assert!(principal_nodes.is_empty());
    }

    #[test]
    fn test_lambda_multiple_principals() {
        // Test that multiple principals in a single statement are all captured
        let function_arn = "arn:aws:lambda:us-east-1:999999999999:function:MyFunction";
        let principals = vec![
            "s3.amazonaws.com".to_string(),
            "apigateway.amazonaws.com".to_string(),
            "arn:aws:iam::999999999999:role/InternalRole".to_string(),
        ];

        let stmt = ParsedStatement {
            effect: "Allow".to_string(),
            principals: principals.clone(),
            actions: vec!["lambda:InvokeFunction".to_string()],
            condition_keys: vec![],
            wildcard_principal: false,
        };

        let (edges, principal_nodes) = build_access_edges(function_arn, &[stmt], "999999999999");

        // Should have 3 edges
        assert_eq!(edges.len(), 3);
        assert_eq!(principal_nodes.len(), 3);

        // Verify service principals are marked correctly
        for (i, expected_principal) in principals.iter().enumerate() {
            assert_eq!(edges[i].1, *expected_principal);
            assert_eq!(principal_nodes[i]["id"], *expected_principal);

            if expected_principal.contains(".amazonaws.com") {
                assert_eq!(principal_nodes[i]["service"], true);
            }
        }
    }

    #[test]
    fn test_lambda_cap_exceeded_with_service_principals() {
        // Test that when cap is exceeded, 49 explicit principals + 1 sentinel is produced
        // even with a mix of service and account principals
        let function_arn = "arn:aws:lambda:us-east-1:999999999999:function:MyFunction";

        // Build 60 principals: mix of service and account
        let mut principals = Vec::new();
        for i in 0..30 {
            principals.push(format!("service{}.amazonaws.com", i));
        }
        for i in 0..30 {
            principals.push(format!("arn:aws:iam::999999999999:role/role-{}", i));
        }

        let stmt = ParsedStatement {
            effect: "Allow".to_string(),
            principals: principals.clone(),
            actions: vec!["lambda:InvokeFunction".to_string()],
            condition_keys: vec![],
            wildcard_principal: false,
        };

        let (edges, principal_nodes) = build_access_edges(function_arn, &[stmt], "999999999999");

        // Should have 49 explicit edges + 1 sentinel (cap_exceeded)
        assert_eq!(edges.len(), 50);
        assert_eq!(principal_nodes.len(), 49);

        // Last edge should be the sentinel (cap_exceeded)
        assert_eq!(edges[49].1, "*");
        assert_eq!(edges[49].2["cap_exceeded"], true);
    }

    #[test]
    fn test_lambda_condition_keys_preserved() {
        // Test that condition keys are captured as edge properties
        let function_arn = "arn:aws:lambda:us-east-1:999999999999:function:MyFunction";

        let stmt = ParsedStatement {
            effect: "Allow".to_string(),
            principals: vec!["arn:aws:iam::999999999999:role/MyRole".to_string()],
            actions: vec!["lambda:InvokeFunction".to_string()],
            condition_keys: vec!["aws:username".to_string(), "aws:SourceAccount".to_string()],
            wildcard_principal: false,
        };

        let (edges, _) = build_access_edges(function_arn, &[stmt], "999999999999");

        // Verify condition keys are in edge props
        assert_eq!(edges.len(), 1);
        let condition_keys_val = &edges[0].2["condition_keys"];
        assert!(condition_keys_val.is_array());

        // Check both condition keys are present
        let keys_array = condition_keys_val.as_array().unwrap();
        assert_eq!(keys_array.len(), 2);
    }
}
