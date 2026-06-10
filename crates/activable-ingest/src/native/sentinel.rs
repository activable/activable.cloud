//! Sentinel nodes used by resource-policy ingesters.

use activable_graph::loader::load_nodes;
use deadpool_postgres::Pool;
use serde_json::json;
use std::sync::Arc;

pub const WILDCARD_PRINCIPAL_ID: &str = "*";
pub const AWS_MANAGED_KEY_ID: &str = "AwsManagedKey";

/// Ensure the WildcardPrincipal sentinel node exists in the graph.
/// MERGE semantics — safe to call repeatedly.
pub async fn ensure_wildcard_principal(
    pool: &Arc<Pool>,
    graph_name: &str,
) -> Result<(), crate::error::IngestError> {
    let node = json!({
        "id": WILDCARD_PRINCIPAL_ID,
        "name": "*",
        "wildcard": true,
    });
    load_nodes(pool.clone(), graph_name, "WildcardPrincipal", &[node], 1).await?;
    Ok(())
}

/// Ensure the AwsManagedKey sentinel node exists in the graph.
///
/// **Why this sentinel exists:** A Secret encrypted by an AWS-managed key (e.g., `aws/secretsmanager`)
/// has no customer KmsKey node in the graph. Without this sentinel, the `EncryptedBy` edge would
/// drop (the loader cannot match the endpoint) and the secret would appear UNENCRYPTED.
/// This sentinel makes "missing EncryptedBy edge" unambiguously mean "unknown encryption status",
/// never "unencrypted." MERGE semantics — safe to call repeatedly.
pub async fn ensure_aws_managed_key(
    pool: &Arc<Pool>,
    graph_name: &str,
) -> Result<(), crate::error::IngestError> {
    let node = json!({
        "id": AWS_MANAGED_KEY_ID,
        "key_id": "aws-managed",
        "aws_managed": true,
    });
    load_nodes(pool.clone(), graph_name, "KmsKey", &[node], 1).await?;
    Ok(())
}
