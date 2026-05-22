//! Resolver for fetching local subgraphs.

use async_graphql::Context;
use activable_graph::GraphClient;
use activable_graph::types::NodeId;
use crate::types::GqlSubgraph;
use crate::error::map_graph_error;

/// Get a subgraph around a center node.
pub async fn subgraph(
    ctx: &Context<'_>,
    center: String,
    radius: i32,
) -> async_graphql::Result<GqlSubgraph> {
    let client = ctx.data::<GraphClient>().map_err(|_| {
        async_graphql::Error::new("GraphClient not available")
    })?;

    let sg = client
        .subgraph(&NodeId::from(center.as_str()), radius as u8)
        .await
        .map_err(|e| {
            tracing::error!("subgraph failed: {}", e);
            map_graph_error(e)
        })?;

    Ok(GqlSubgraph::from(sg))
}
