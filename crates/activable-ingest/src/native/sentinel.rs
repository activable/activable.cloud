//! Sentinel nodes used by resource-policy ingesters.

use activable_graph::loader::load_nodes;
use deadpool_postgres::Pool;
use serde_json::json;
use std::sync::Arc;

pub const WILDCARD_PRINCIPAL_ID: &str = "*";

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
