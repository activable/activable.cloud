//! Resolver for finding paths between nodes.

use crate::error::map_graph_error;
use crate::types::GqlPath;
use activable_graph::types::NodeId;
use activable_graph::GraphClient;
use async_graphql::Context;

/// Find paths between two nodes.
pub async fn path_finder(
    ctx: &Context<'_>,
    start: String,
    end: String,
    edge_pattern: Vec<String>,
    max_hops: i32,
) -> async_graphql::Result<Vec<GqlPath>> {
    let client = ctx
        .data::<GraphClient>()
        .map_err(|_| async_graphql::Error::new("GraphClient not available"))?;

    let pattern_refs: Vec<&str> = edge_pattern.iter().map(|s| s.as_str()).collect();

    let paths = client
        .path_finder(
            &NodeId::from(start.as_str()),
            &NodeId::from(end.as_str()),
            &pattern_refs,
            max_hops as u8,
        )
        .await
        .map_err(|e| {
            tracing::error!("path_finder failed: {}", e);
            map_graph_error(e)
        })?;

    Ok(paths.into_iter().map(GqlPath::from).collect())
}
