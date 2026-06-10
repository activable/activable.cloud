//! Resolvers for graph traversal: walkEdges and blastRadius.

use crate::error::map_graph_error;
use crate::types::GqlNodeRef;
use activable_graph::types::{Direction, NodeId};
use activable_graph::GraphClient;
use async_graphql::Context;
use futures::StreamExt;

const MAX_EDGE_TYPES: usize = 10;
// Equal values, distinct meanings — do not unify: MAX_DEPTH bounds multi-hop
// traversal in blastRadius; MAX_WALK_RESULTS caps the one-hop result count
// in walkEdges.
const MAX_DEPTH: i32 = 10;
const MAX_WALK_RESULTS: i32 = 10;

/// Walk edges one hop from a starting node, returning up to `limit` neighbors.
pub async fn walk_edges(
    ctx: &Context<'_>,
    start: String,
    edge_types: Vec<String>,
    direction: String,
    limit: i32,
) -> async_graphql::Result<Vec<GqlNodeRef>> {
    if edge_types.len() > MAX_EDGE_TYPES {
        return Err(async_graphql::Error::new(format!(
            "Too many edge types (max {})",
            MAX_EDGE_TYPES
        )));
    }
    if !(0..=MAX_WALK_RESULTS).contains(&limit) {
        return Err(async_graphql::Error::new(format!(
            "Limit must be 0-{}",
            MAX_WALK_RESULTS
        )));
    }

    let client = ctx
        .data::<GraphClient>()
        .map_err(|_| async_graphql::Error::new("GraphClient not available"))?;

    let dir = match direction.to_uppercase().as_str() {
        "OUTGOING" => Direction::Outgoing,
        "INCOMING" => Direction::Incoming,
        "BOTH" => Direction::Both,
        _ => return Err(async_graphql::Error::new("Invalid direction")),
    };

    let edge_type_refs: Vec<&str> = edge_types.iter().map(|s| s.as_str()).collect();

    let stream = client
        .walk_edges(
            &NodeId::from(start.as_str()),
            &edge_type_refs,
            dir,
            limit as u8,
        )
        .await
        .map_err(|e| {
            tracing::error!("walk_edges failed: {}", e);
            map_graph_error(e)
        })?;

    let mut nodes = Vec::new();
    let mut stream = Box::pin(stream);
    while let Some(result) = stream.next().await {
        match result {
            Ok(node_ref) => nodes.push(GqlNodeRef::from(node_ref)),
            Err(e) => {
                tracing::error!("Error collecting walk_edges result: {}", e);
                return Err(map_graph_error(e));
            }
        }
    }

    Ok(nodes)
}

/// Find all nodes within max_hops of a starting node.
pub async fn blast_radius(
    ctx: &Context<'_>,
    node: String,
    depth: i32,
) -> async_graphql::Result<Vec<GqlNodeRef>> {
    if !(0..=MAX_DEPTH).contains(&depth) {
        return Err(async_graphql::Error::new(format!(
            "Depth must be 0-{}",
            MAX_DEPTH
        )));
    }

    let client = ctx
        .data::<GraphClient>()
        .map_err(|_| async_graphql::Error::new("GraphClient not available"))?;

    let stream = client
        .blast_radius(&NodeId::from(node.as_str()), &[], depth as u8)
        .await
        .map_err(|e| {
            tracing::error!("blast_radius failed: {}", e);
            map_graph_error(e)
        })?;

    let mut nodes = Vec::new();
    let mut stream = Box::pin(stream);
    while let Some(result) = stream.next().await {
        match result {
            Ok(node_ref) => nodes.push(GqlNodeRef::from(node_ref)),
            Err(e) => {
                tracing::error!("Error collecting blast_radius result: {}", e);
                return Err(map_graph_error(e));
            }
        }
    }

    Ok(nodes)
}
