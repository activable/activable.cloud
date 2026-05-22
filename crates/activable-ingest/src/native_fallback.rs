use crate::error::IngestError;
use crate::resource_registry::ResourceTypeConfig;
use activable_graph::loader;
use aws_config::SdkConfig;
use deadpool_postgres::Pool;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::cloud_control::IngestStats;

/// Fetch resources via native AWS SDK (fallback when CCAPI unavailable).
pub async fn fetch_via_native_sdk(
    aws_config: &SdkConfig,
    resource_type: &ResourceTypeConfig,
    pool: Arc<Pool>,
    graph_name: &str,
) -> Result<IngestStats, IngestError> {
    let type_name = &resource_type.type_name;
    let label = &resource_type.label;

    let fallback = match &resource_type.fallback {
        Some(fb) => fb,
        None => {
            warn!(
                type_name = %type_name,
                "No fallback config, skipping native SDK fetch"
            );
            return Ok(IngestStats {
                type_name: type_name.clone(),
                label: label.clone(),
                nodes_ingested: 0,
            });
        }
    };

    debug!(
        type_name = %type_name,
        sdk = %fallback.sdk,
        operation = %fallback.operation,
        "Using native SDK fallback"
    );

    match (fallback.sdk.as_str(), fallback.operation.as_str()) {
        ("iam", "ListUsers") => fetch_iam_users(aws_config, pool, graph_name).await,
        ("iam", "ListRoles") => fetch_iam_roles(aws_config, pool, graph_name).await,
        ("iam", "ListGroups") => fetch_iam_groups(aws_config, pool, graph_name).await,
        ("iam", "ListPolicies") => fetch_iam_policies(aws_config, pool, graph_name).await,
        ("s3", "ListBuckets") => fetch_s3_buckets(aws_config, pool, graph_name).await,
        ("ec2", "DescribeInstances") => fetch_ec2_instances(aws_config, pool, graph_name).await,
        ("ec2", "DescribeSecurityGroups") => {
            fetch_ec2_security_groups(aws_config, pool, graph_name).await
        }
        ("ec2", "DescribeVpcs") => fetch_ec2_vpcs(aws_config, pool, graph_name).await,
        ("lambda", "ListFunctions") => fetch_lambda_functions(aws_config, pool, graph_name).await,
        ("sts", "GetCallerIdentity") => fetch_sts_identity(aws_config, pool, graph_name).await,
        _ => {
            warn!(
                type_name = %type_name,
                sdk = %fallback.sdk,
                operation = %fallback.operation,
                "No native SDK fallback implementation, skipping"
            );
            Ok(IngestStats {
                type_name: type_name.clone(),
                label: label.clone(),
                nodes_ingested: 0,
            })
        }
    }
}

async fn fetch_iam_users(
    config: &SdkConfig,
    pool: Arc<Pool>,
    graph_name: &str,
) -> Result<IngestStats, IngestError> {
    let client = aws_sdk_iam::Client::new(config);
    let mut count = 0u32;

    let mut paginator = client.list_users().into_paginator().send();

    while let Some(page_result) = paginator.next().await {
        let page = page_result.map_err(|e| IngestError::AwsSdk(e.to_string()))?;

        let nodes: Vec<Value> = page
            .users()
            .iter()
            .map(|user| {
                json!({
                    "id": user.arn(),
                    "name": user.user_name(),
                    "user_id": user.user_id(),
                    "path": user.path(),
                    "principal_type": "User",
                })
            })
            .collect();

        if !nodes.is_empty() {
            let written =
                loader::load_nodes(pool.clone(), graph_name, "Principal", &nodes, 100).await?;
            count += written as u32;
            debug!(
                batch_count = written,
                total = count,
                "IAM Users batch written"
            );
        }
    }

    info!(nodes_ingested = count, "IAM Users ingest complete");
    Ok(IngestStats {
        type_name: "AWS::IAM::User".to_string(),
        label: "Principal".to_string(),
        nodes_ingested: count,
    })
}

async fn fetch_iam_roles(
    config: &SdkConfig,
    pool: Arc<Pool>,
    graph_name: &str,
) -> Result<IngestStats, IngestError> {
    let client = aws_sdk_iam::Client::new(config);
    let mut count = 0u32;

    let mut paginator = client.list_roles().into_paginator().send();

    while let Some(page_result) = paginator.next().await {
        let page = page_result.map_err(|e| IngestError::AwsSdk(e.to_string()))?;

        let nodes: Vec<Value> = page
            .roles()
            .iter()
            .map(|role| {
                json!({
                    "id": role.arn(),
                    "name": role.role_name(),
                    "role_id": role.role_id(),
                    "path": role.path(),
                    "principal_type": "Role",
                })
            })
            .collect();

        if !nodes.is_empty() {
            let written =
                loader::load_nodes(pool.clone(), graph_name, "Principal", &nodes, 100).await?;
            count += written as u32;
        }
    }

    info!(nodes_ingested = count, "IAM Roles ingest complete");
    Ok(IngestStats {
        type_name: "AWS::IAM::Role".to_string(),
        label: "Principal".to_string(),
        nodes_ingested: count,
    })
}

async fn fetch_iam_groups(
    config: &SdkConfig,
    pool: Arc<Pool>,
    graph_name: &str,
) -> Result<IngestStats, IngestError> {
    let client = aws_sdk_iam::Client::new(config);
    let mut count = 0u32;

    let mut paginator = client.list_groups().into_paginator().send();

    while let Some(page_result) = paginator.next().await {
        let page = page_result.map_err(|e| IngestError::AwsSdk(e.to_string()))?;

        let nodes: Vec<Value> = page
            .groups()
            .iter()
            .map(|group| {
                json!({
                    "id": group.arn(),
                    "name": group.group_name(),
                    "group_id": group.group_id(),
                    "path": group.path(),
                })
            })
            .collect();

        if !nodes.is_empty() {
            let written =
                loader::load_nodes(pool.clone(), graph_name, "IamGroup", &nodes, 100).await?;
            count += written as u32;
        }
    }

    info!(nodes_ingested = count, "IAM Groups ingest complete");
    Ok(IngestStats {
        type_name: "AWS::IAM::Group".to_string(),
        label: "IamGroup".to_string(),
        nodes_ingested: count,
    })
}

async fn fetch_iam_policies(
    config: &SdkConfig,
    pool: Arc<Pool>,
    graph_name: &str,
) -> Result<IngestStats, IngestError> {
    let client = aws_sdk_iam::Client::new(config);
    let mut count = 0u32;

    let mut paginator = client
        .list_policies()
        .scope(aws_sdk_iam::types::PolicyScopeType::Local)
        .into_paginator()
        .send();

    while let Some(page_result) = paginator.next().await {
        let page = page_result.map_err(|e| IngestError::AwsSdk(e.to_string()))?;

        let nodes: Vec<Value> = page
            .policies()
            .iter()
            .map(|policy| {
                json!({
                    "id": policy.arn(),
                    "name": policy.policy_name(),
                    "policy_id": policy.policy_id(),
                    "path": policy.path(),
                })
            })
            .collect();

        if !nodes.is_empty() {
            let written =
                loader::load_nodes(pool.clone(), graph_name, "Permission", &nodes, 100).await?;
            count += written as u32;
        }
    }

    info!(nodes_ingested = count, "IAM Policies ingest complete");
    Ok(IngestStats {
        type_name: "AWS::IAM::Policy".to_string(),
        label: "Permission".to_string(),
        nodes_ingested: count,
    })
}

async fn fetch_s3_buckets(
    config: &SdkConfig,
    pool: Arc<Pool>,
    graph_name: &str,
) -> Result<IngestStats, IngestError> {
    let client = aws_sdk_s3::Client::new(config);

    let response = client
        .list_buckets()
        .send()
        .await
        .map_err(|e| IngestError::AwsSdk(e.to_string()))?;

    let nodes: Vec<Value> = response
        .buckets()
        .iter()
        .map(|bucket| {
            json!({
                "id": bucket.name(),
                "name": bucket.name(),
            })
        })
        .collect();

    let count = if !nodes.is_empty() {
        let written = loader::load_nodes(pool, graph_name, "Resource", &nodes, 100).await?;
        written as u32
    } else {
        0
    };

    info!(nodes_ingested = count, "S3 Buckets ingest complete");
    Ok(IngestStats {
        type_name: "AWS::S3::Bucket".to_string(),
        label: "Resource".to_string(),
        nodes_ingested: count,
    })
}

async fn fetch_ec2_instances(
    config: &SdkConfig,
    pool: Arc<Pool>,
    graph_name: &str,
) -> Result<IngestStats, IngestError> {
    let client = aws_sdk_ec2::Client::new(config);
    let mut count = 0u32;

    let mut paginator = client.describe_instances().into_paginator().send();

    while let Some(page_result) = paginator.next().await {
        let page = page_result.map_err(|e| IngestError::AwsSdk(e.to_string()))?;

        let nodes: Vec<Value> = page
            .reservations()
            .iter()
            .flat_map(|reservation| {
                reservation.instances().iter().map(|instance| {
                    json!({
                        "id": instance.instance_id(),
                        "instance_id": instance.instance_id(),
                        "instance_type": instance.instance_type().map(|t| format!("{:?}", t)),
                        "state": instance.state().map(|s| s.name()).map(|n| format!("{:?}", n)),
                    })
                })
            })
            .collect();

        if !nodes.is_empty() {
            let written =
                loader::load_nodes(pool.clone(), graph_name, "Resource", &nodes, 100).await?;
            count += written as u32;
        }
    }

    info!(nodes_ingested = count, "EC2 Instances ingest complete");
    Ok(IngestStats {
        type_name: "AWS::EC2::Instance".to_string(),
        label: "Resource".to_string(),
        nodes_ingested: count,
    })
}

async fn fetch_ec2_security_groups(
    config: &SdkConfig,
    pool: Arc<Pool>,
    graph_name: &str,
) -> Result<IngestStats, IngestError> {
    let client = aws_sdk_ec2::Client::new(config);
    let mut count = 0u32;

    let mut paginator = client.describe_security_groups().into_paginator().send();

    while let Some(page_result) = paginator.next().await {
        let page = page_result.map_err(|e| IngestError::AwsSdk(e.to_string()))?;

        let nodes: Vec<Value> = page
            .security_groups()
            .iter()
            .map(|sg| {
                json!({
                    "id": sg.group_id(),
                    "group_id": sg.group_id(),
                    "group_name": sg.group_name(),
                    "vpc_id": sg.vpc_id(),
                })
            })
            .collect();

        if !nodes.is_empty() {
            let written =
                loader::load_nodes(pool.clone(), graph_name, "SecurityGroup", &nodes, 100).await?;
            count += written as u32;
        }
    }

    info!(nodes_ingested = count, "EC2 SecurityGroups ingest complete");
    Ok(IngestStats {
        type_name: "AWS::EC2::SecurityGroup".to_string(),
        label: "SecurityGroup".to_string(),
        nodes_ingested: count,
    })
}

async fn fetch_ec2_vpcs(
    config: &SdkConfig,
    pool: Arc<Pool>,
    graph_name: &str,
) -> Result<IngestStats, IngestError> {
    let client = aws_sdk_ec2::Client::new(config);
    let mut count = 0u32;

    let mut paginator = client.describe_vpcs().into_paginator().send();

    while let Some(page_result) = paginator.next().await {
        let page = page_result.map_err(|e| IngestError::AwsSdk(e.to_string()))?;

        let nodes: Vec<Value> = page
            .vpcs()
            .iter()
            .map(|vpc| {
                json!({
                    "id": vpc.vpc_id(),
                    "vpc_id": vpc.vpc_id(),
                    "cidr": vpc.cidr_block(),
                })
            })
            .collect();

        if !nodes.is_empty() {
            let written = loader::load_nodes(pool.clone(), graph_name, "Vpc", &nodes, 100).await?;
            count += written as u32;
        }
    }

    info!(nodes_ingested = count, "EC2 VPCs ingest complete");
    Ok(IngestStats {
        type_name: "AWS::EC2::VPC".to_string(),
        label: "Vpc".to_string(),
        nodes_ingested: count,
    })
}

async fn fetch_lambda_functions(
    config: &SdkConfig,
    pool: Arc<Pool>,
    graph_name: &str,
) -> Result<IngestStats, IngestError> {
    let client = aws_sdk_lambda::Client::new(config);
    let mut count = 0u32;

    let mut paginator = client.list_functions().into_paginator().send();

    while let Some(page_result) = paginator.next().await {
        let page = page_result.map_err(|e| IngestError::AwsSdk(e.to_string()))?;

        let nodes: Vec<Value> = page
            .functions()
            .iter()
            .map(|func| {
                json!({
                    "id": func.function_arn(),
                    "function_name": func.function_name(),
                    "function_arn": func.function_arn(),
                    "runtime": func.runtime().map(|r| format!("{:?}", r)),
                })
            })
            .collect();

        if !nodes.is_empty() {
            let written =
                loader::load_nodes(pool.clone(), graph_name, "Resource", &nodes, 100).await?;
            count += written as u32;
        }
    }

    info!(nodes_ingested = count, "Lambda Functions ingest complete");
    Ok(IngestStats {
        type_name: "AWS::Lambda::Function".to_string(),
        label: "Resource".to_string(),
        nodes_ingested: count,
    })
}

async fn fetch_sts_identity(
    config: &SdkConfig,
    pool: Arc<Pool>,
    graph_name: &str,
) -> Result<IngestStats, IngestError> {
    let client = aws_sdk_sts::Client::new(config);

    let response = client
        .get_caller_identity()
        .send()
        .await
        .map_err(|e| IngestError::AwsSdk(e.to_string()))?;

    let account_id = response.account().unwrap_or("unknown");
    let arn = response.arn().unwrap_or("unknown");

    let nodes = vec![json!({
        "id": account_id,
        "account_id": account_id,
        "arn": arn,
    })];

    let count = if !nodes.is_empty() {
        let written = loader::load_nodes(pool, graph_name, "Account", &nodes, 100).await?;
        written as u32
    } else {
        0
    };

    info!(nodes_ingested = count, "STS Identity ingest complete");
    Ok(IngestStats {
        type_name: "AWS::STS::CallerIdentity".to_string(),
        label: "Account".to_string(),
        nodes_ingested: count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_structure() {
        let node = json!({
            "id": "arn:aws:iam::123:user/test",
            "name": "test",
            "principal_type": "User",
        });

        assert_eq!(node["id"], "arn:aws:iam::123:user/test");
        assert_eq!(node["name"], "test");
        assert_eq!(node["principal_type"], "User");
    }
}
