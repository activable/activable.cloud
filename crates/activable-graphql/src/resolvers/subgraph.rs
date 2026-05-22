//! Resolver for fetching local subgraphs.

use crate::error::map_graph_error;
use crate::types::GqlSubgraph;
use activable_graph::types::NodeId;
use activable_graph::GraphClient;
use async_graphql::Context;

/// Get a subgraph around a center node.
pub async fn subgraph(
    ctx: &Context<'_>,
    center: String,
    radius: i32,
) -> async_graphql::Result<GqlSubgraph> {
    let client = ctx
        .data::<GraphClient>()
        .map_err(|_| async_graphql::Error::new("GraphClient not available"))?;

    let sg = client
        .subgraph(&NodeId::from(center.as_str()), radius as u8)
        .await
        .map_err(|e| {
            tracing::error!("subgraph failed: {}", e);
            map_graph_error(e)
        })?;

    Ok(GqlSubgraph::from(sg))
}
