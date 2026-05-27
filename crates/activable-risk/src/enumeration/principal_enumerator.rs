use crate::rule_engine::EffectivePermission;
use crate::signals::GraphQueryService;

/// An enumerated principal with its effective permissions
#[derive(Debug, Clone)]
pub struct EnumeratedPrincipal {
    pub principal_id: String,
    pub effective_permissions: Vec<EffectivePermission>,
}

/// Enumerate all principals from the graph and fetch their effective permissions.
///
/// This replaces manual principal ID entry with automated discovery.
/// Principals are already ingested into the graph via activable-ingest.
///
/// # Arguments
///
/// * `graph` - Graph query service with access to principal data
///
/// # Returns
///
/// A vector of all enumerated principals with their effective permissions,
/// or an error if graph query fails.
///
/// # Example
///
/// ```ignore
/// let principals = enumerate_principals(&graph_service).await?;
/// println!("Enumerated {} principals", principals.len());
/// ```
pub async fn enumerate_principals(
    graph: &dyn GraphQueryService,
) -> Result<Vec<EnumeratedPrincipal>, Box<dyn std::error::Error + Send + Sync>> {
    let principal_ids = graph.list_principal_ids().await?;
    let mut principals = Vec::new();

    for principal_id in principal_ids {
        match graph.get_effective_permissions(&principal_id).await {
            Ok(perms) => {
                let effective_perms: Vec<EffectivePermission> = perms
                    .into_iter()
                    .map(|(action, resource)| EffectivePermission::new(action, resource))
                    .collect();
                principals.push(EnumeratedPrincipal {
                    principal_id,
                    effective_permissions: effective_perms,
                });
            }
            Err(_e) => {
                // Skip principals with permission fetch errors
                // (e.g., deleted principals, permission denied)
                continue;
            }
        }
    }

    Ok(principals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::test_fixtures::MockGraphQueryService;

    #[tokio::test]
    async fn enumerate_principals_empty_graph() {
        let graph = MockGraphQueryService::new();
        let result = enumerate_principals(&graph).await.unwrap();
        assert_eq!(result.len(), 0);
    }

    #[tokio::test]
    async fn enumerate_principals_single_principal() {
        let graph = MockGraphQueryService::new()
            .with_principal_ids(vec!["principal-1".to_string()])
            .with_effective_permissions(
                "principal-1".to_string(),
                vec![
                    (
                        "s3:GetObject".to_string(),
                        "arn:aws:s3:::bucket".to_string(),
                    ),
                    (
                        "s3:ListBucket".to_string(),
                        "arn:aws:s3:::bucket".to_string(),
                    ),
                ],
            );

        let result = enumerate_principals(&graph).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].principal_id, "principal-1");
        assert_eq!(result[0].effective_permissions.len(), 2);
        assert_eq!(result[0].effective_permissions[0].action, "s3:GetObject");
    }

    #[tokio::test]
    async fn enumerate_principals_multiple_principals() {
        let graph = MockGraphQueryService::new()
            .with_principal_ids(vec![
                "principal-1".to_string(),
                "principal-2".to_string(),
                "principal-3".to_string(),
            ])
            .with_effective_permissions(
                "principal-1".to_string(),
                vec![("iam:CreatePolicyVersion".to_string(), "*".to_string())],
            )
            .with_effective_permissions(
                "principal-2".to_string(),
                vec![("s3:*".to_string(), "*".to_string())],
            )
            .with_effective_permissions(
                "principal-3".to_string(),
                vec![("ec2:*".to_string(), "*".to_string())],
            );

        let result = enumerate_principals(&graph).await.unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].principal_id, "principal-1");
        assert_eq!(result[1].principal_id, "principal-2");
        assert_eq!(result[2].principal_id, "principal-3");
    }

    #[tokio::test]
    async fn enumerate_principals_with_mixed_perms() {
        let graph = MockGraphQueryService::new()
            .with_principal_ids(vec!["user-1".to_string(), "role-1".to_string()])
            .with_effective_permissions(
                "user-1".to_string(),
                vec![
                    (
                        "iam:CreateAccessKey".to_string(),
                        "arn:aws:iam::123456789012:user/*".to_string(),
                    ),
                    (
                        "iam:AttachUserPolicy".to_string(),
                        "arn:aws:iam::123456789012:*".to_string(),
                    ),
                    (
                        "sts:AssumeRole".to_string(),
                        "arn:aws:iam::123456789012:role/*".to_string(),
                    ),
                ],
            )
            .with_effective_permissions(
                "role-1".to_string(),
                vec![
                    ("s3:*".to_string(), "*".to_string()),
                    ("dynamodb:*".to_string(), "*".to_string()),
                ],
            );

        let result = enumerate_principals(&graph).await.unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].effective_permissions.len(), 3);
        assert_eq!(result[1].effective_permissions.len(), 2);
    }

    #[tokio::test]
    async fn enumerate_principals_with_empty_permissions() {
        let graph = MockGraphQueryService::new()
            .with_principal_ids(vec!["principal-1".to_string(), "principal-2".to_string()])
            .with_effective_permissions("principal-1".to_string(), vec![])
            .with_effective_permissions(
                "principal-2".to_string(),
                vec![("s3:GetObject".to_string(), "*".to_string())],
            );

        let result = enumerate_principals(&graph).await.unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].effective_permissions.len(), 0);
        assert_eq!(result[1].effective_permissions.len(), 1);
    }
}
