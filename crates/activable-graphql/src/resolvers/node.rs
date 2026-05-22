//! Resolver for finding nodes by label and ID.

use async_graphql::Context;
use activable_graph::GraphClient;
use activable_graph::types::NodeId;
use crate::types::GqlNode;
use crate::error::map_graph_error;

/// Find a node by its label and ID.
pub async fn find_node(
    ctx: &Context<'_>,
    label: String,
    id: String,
) -> async_graphql::Result<Option<GqlNode>> {
    let client = ctx.data::<GraphClient>().map_err(|_| {
        async_graphql::Error::new("GraphClient not available")
    })?;

    let result = client
        .find_by_id(&label, &NodeId::from(id.as_str()))
        .await
        .map_err(|e| {
            tracing::error!("find_node failed: {}", e);
            map_graph_error(e)
        })?;

    Ok(result.map(|nr| GqlNode {
        id: nr.id.to_string(),
        label: nr.label,
        properties: None,
    }))
}
