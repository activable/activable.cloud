//! Shared access-edge builder for resource-policy enrichers (S3, Secrets Manager, Lambda, KMS).
//! Extracts and builds AllowsAccessFrom edges from parsed resource-policy statements.

use crate::native::principal::build_principal_node;
use crate::native::sentinel::WILDCARD_PRINCIPAL_ID;
use serde_json::{json, Value};

/// Build AllowsAccessFrom edges from parsed resource-policy statements.
/// Mirrors the S3/Secrets Manager/Lambda enricher logic: wildcard principal → sentinel, >50 cap, plus Principal nodes.
/// Returns (edges: Vec<(from, to, props)>, principal_nodes: Vec<Value>).
///
/// **Condition evaluation note:** Captured `condition_keys` are stored as edge props but NOT
/// evaluated. An unconditioned `AllowsAccessFrom` edge represents a v1 over-approximation of
/// the actual access path. Full condition evaluation (Org ID restrictions, IP-based, etc.) is
/// deferred to a future IAM policy evaluator. This enricher's job is to surface
/// the access endpoints and condition metadata for later evaluation.
pub fn build_access_edges(
    resource_arn: &str,
    statements: &[crate::native::resource_policy::ParsedStatement],
    caller_account_id: &str,
) -> (Vec<(String, String, Value)>, Vec<Value>) {
    let mut edges = Vec::new();
    let mut principal_nodes = Vec::new();

    for stmt in statements {
        let condition_keys_json = json!(stmt.condition_keys);

        if stmt.wildcard_principal {
            // Wildcard → single edge to sentinel
            edges.push((
                resource_arn.to_string(),
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
                    edges.push((
                        resource_arn.to_string(),
                        principal.clone(),
                        json!({
                            "condition_keys": condition_keys_json,
                        }),
                    ));
                    principal_nodes.push(build_principal_node(principal, caller_account_id));
                }
                // Emit 1 sentinel edge signaling cap exceeded
                edges.push((
                    resource_arn.to_string(),
                    WILDCARD_PRINCIPAL_ID.to_string(),
                    json!({
                        "cap_exceeded": true,
                        "condition_keys": condition_keys_json,
                    }),
                ));
            } else {
                // Explicit edges for each principal
                for principal in &stmt.principals {
                    edges.push((
                        resource_arn.to_string(),
                        principal.clone(),
                        json!({
                            "condition_keys": condition_keys_json,
                        }),
                    ));
                    principal_nodes.push(build_principal_node(principal, caller_account_id));
                }
            }
        }
    }

    (edges, principal_nodes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_access_edges_wildcard() {
        use crate::native::resource_policy::ParsedStatement;

        let resource_arn = "arn:aws:secretsmanager:us-east-1:999999999999:secret:my-secret-ABC123";
        let stmt = ParsedStatement {
            effect: "Allow".to_string(),
            principals: vec!["*".to_string()],
            actions: vec!["secretsmanager:GetSecretValue".to_string()],
            condition_keys: vec![],
            wildcard_principal: true,
        };

        let (edges, principal_nodes) = build_access_edges(resource_arn, &[stmt], "999999999999");

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].0, resource_arn);
        assert_eq!(edges[0].1, WILDCARD_PRINCIPAL_ID);
        assert_eq!(edges[0].2["wildcard_principal"], true);
        assert!(principal_nodes.is_empty()); // Wildcard doesn't create principal nodes
    }

    #[test]
    fn test_build_access_edges_explicit_single() {
        use crate::native::resource_policy::ParsedStatement;

        let resource_arn = "arn:aws:secretsmanager:us-east-1:999999999999:secret:my-secret-ABC123";
        let principal = "arn:aws:iam::999999999999:role/MyRole";
        let stmt = ParsedStatement {
            effect: "Allow".to_string(),
            principals: vec![principal.to_string()],
            actions: vec!["secretsmanager:GetSecretValue".to_string()],
            condition_keys: vec![],
            wildcard_principal: false,
        };

        let (edges, principal_nodes) = build_access_edges(resource_arn, &[stmt], "999999999999");

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].0, resource_arn);
        assert_eq!(edges[0].1, principal);
        assert_eq!(principal_nodes.len(), 1);
        assert_eq!(principal_nodes[0]["id"], principal);
    }

    #[test]
    fn test_build_access_edges_cap_exceeded() {
        use crate::native::resource_policy::ParsedStatement;

        let resource_arn = "arn:aws:secretsmanager:us-east-1:999999999999:secret:my-secret-ABC123";
        let mut principals = Vec::new();
        for i in 0..60 {
            principals.push(format!("arn:aws:iam::999999999999:role/role-{}", i));
        }

        let stmt = ParsedStatement {
            effect: "Allow".to_string(),
            principals: principals.clone(),
            actions: vec!["secretsmanager:GetSecretValue".to_string()],
            condition_keys: vec![],
            wildcard_principal: false,
        };

        let (edges, principal_nodes) = build_access_edges(resource_arn, &[stmt], "999999999999");

        // Should have 49 explicit edges + 1 sentinel (cap_exceeded)
        assert_eq!(edges.len(), 50);
        assert_eq!(principal_nodes.len(), 49);
        assert_eq!(edges[49].2["cap_exceeded"], true);
    }

    #[test]
    fn test_build_access_edges_cross_account() {
        use crate::native::resource_policy::ParsedStatement;

        let resource_arn = "arn:aws:secretsmanager:us-east-1:999999999999:secret:my-secret-ABC123";
        let cross_account_principal = "arn:aws:iam::111111111111:role/RemoteRole";
        let stmt = ParsedStatement {
            effect: "Allow".to_string(),
            principals: vec![cross_account_principal.to_string()],
            actions: vec!["secretsmanager:GetSecretValue".to_string()],
            condition_keys: vec![],
            wildcard_principal: false,
        };

        let (edges, principal_nodes) = build_access_edges(resource_arn, &[stmt], "999999999999");

        assert_eq!(edges.len(), 1);
        assert_eq!(principal_nodes.len(), 1);
        assert_eq!(principal_nodes[0]["external"], true);
    }

    #[test]
    fn test_build_access_edges_service_principal() {
        use crate::native::resource_policy::ParsedStatement;

        let resource_arn = "arn:aws:secretsmanager:us-east-1:999999999999:secret:my-secret-ABC123";
        let service_principal = "lambda.amazonaws.com";
        let stmt = ParsedStatement {
            effect: "Allow".to_string(),
            principals: vec![service_principal.to_string()],
            actions: vec!["secretsmanager:GetSecretValue".to_string()],
            condition_keys: vec![],
            wildcard_principal: false,
        };

        let (edges, principal_nodes) = build_access_edges(resource_arn, &[stmt], "999999999999");

        assert_eq!(edges.len(), 1);
        assert_eq!(principal_nodes.len(), 1);
        assert_eq!(principal_nodes[0]["service"], true);
    }

    #[test]
    fn test_build_access_edges_deterministic() {
        use crate::native::resource_policy::ParsedStatement;

        let resource_arn = "arn:aws:secretsmanager:us-east-1:999999999999:secret:my-secret-ABC123";
        let principals = vec![
            "arn:aws:iam::999999999999:role/RoleA".to_string(),
            "arn:aws:iam::999999999999:role/RoleB".to_string(),
            "arn:aws:iam::999999999999:role/RoleC".to_string(),
        ];
        let stmt = ParsedStatement {
            effect: "Allow".to_string(),
            principals: principals.clone(),
            actions: vec!["secretsmanager:GetSecretValue".to_string()],
            condition_keys: vec![],
            wildcard_principal: false,
        };

        let stmt_ref = &[stmt];
        let (edges1, _) = build_access_edges(resource_arn, stmt_ref, "999999999999");
        let (edges2, _) = build_access_edges(resource_arn, stmt_ref, "999999999999");

        // Edges should be in the same order (deterministic)
        assert_eq!(edges1.len(), edges2.len());
        for i in 0..edges1.len() {
            assert_eq!(edges1[i].0, edges2[i].0);
            assert_eq!(edges1[i].1, edges2[i].1);
        }
    }
}
