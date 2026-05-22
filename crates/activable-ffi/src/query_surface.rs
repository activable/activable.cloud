//! FFI read surface — query operations on the graph.

use crate::error::ActivableError;
use crate::runtime::get_global;
use activable_graph::types::NodeId;
use futures::StreamExt;

/// Find a node by label and ID.
///
/// Returns JSON object with node properties, or "null" if not found.
#[uniffi::export]
pub fn query_find_node(label: String, id: String) -> Result<String, ActivableError> {
    let state = get_global()?;

    let node_id = NodeId::from(id.as_str());

    let result = state
        .runtime
        .block_on(async { state.client.find_by_id(&label, &node_id).await })?;

    match result {
        Some(node_ref) => {
            // Return JSON object with id and label
            let json = serde_json::json!({
                "id": node_ref.id.to_string(),
                "label": node_ref.label,
            });
            Ok(serde_json::to_string(&json).unwrap_or_else(|_| "null".to_string()))
        }
        None => Ok("null".to_string()),
    }
}

/// Walk edges from a starting node.
///
/// `edge_types` is a comma-separated list of edge types (e.g., "ALLOW,DENY").
/// Returns JSON array of objects `[{"id": "...", "label": "..."}, ...]`.
#[uniffi::export]
pub fn query_walk_edges(
    start: String,
    edge_types: String,
    direction: String,
    depth_limit: u32,
) -> Result<String, ActivableError> {
    let state = get_global()?;

    let node_id = NodeId::from(start.as_str());
    let edge_type_list: Vec<&str> = edge_types.split(',').map(|s| s.trim()).collect();
    let dir = match direction.to_lowercase().as_str() {
        "outgoing" => activable_graph::types::Direction::Outgoing,
        "incoming" => activable_graph::types::Direction::Incoming,
        "both" => activable_graph::types::Direction::Both,
        _ => activable_graph::types::Direction::Outgoing,
    };

    let result = state.runtime.block_on(async {
        let stream = state
            .client
            .walk_edges(&node_id, &edge_type_list, dir, depth_limit as u8)
            .await?;

        // Collect stream into vector
        let nodes: Vec<_> = std::pin::Pin::from(Box::new(stream))
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        Ok::<Vec<_>, ActivableError>(nodes)
    })?;

    // Convert to JSON array
    let json_array: Vec<serde_json::Value> = result
        .into_iter()
        .map(|node_ref| {
            serde_json::json!({
                "id": node_ref.id.to_string(),
                "label": node_ref.label,
            })
        })
        .collect();

    Ok(serde_json::to_string(&json_array).unwrap_or_else(|_| "[]".to_string()))
}

/// Find paths between two nodes.
///
/// `edge_pattern` is a comma-separated list of edge types to follow.
/// Returns JSON array of path objects.
#[uniffi::export]
pub fn query_path_finder(
    start: String,
    end: String,
    edge_pattern: String,
    max_hops: u32,
) -> Result<String, ActivableError> {
    let state = get_global()?;

    let start_id = NodeId::from(start.as_str());
    let end_id = NodeId::from(end.as_str());
    let pattern_list: Vec<&str> = edge_pattern.split(',').map(|s| s.trim()).collect();

    let paths = state.runtime.block_on(async {
        state
            .client
            .path_finder(&start_id, &end_id, &pattern_list, max_hops as u8)
            .await
    })?;

    // Serialize Vec<Path> to JSON array of path objects
    let json_paths: Vec<serde_json::Value> = paths
        .iter()
        .map(|p| {
            serde_json::json!({
                "nodes": p.nodes.iter().map(|n| serde_json::json!({
                    "id": n.id.as_str(),
                    "label": n.label.to_string(),
                })).collect::<Vec<_>>(),
                "length": p.length(),
            })
        })
        .collect();

    Ok(serde_json::to_string(&json_paths).unwrap_or_else(|_| "[]".to_string()))
}

/// Blast radius query — find all nodes reachable within N hops.
///
/// Returns JSON array of reachable node objects.
#[uniffi::export]
pub fn query_blast_radius(start: String, depth_limit: u32) -> Result<String, ActivableError> {
    let state = get_global()?;

    let node_id = NodeId::from(start.as_str());

    // Use blast_radius method for efficient reachability analysis
    let result = state.runtime.block_on(async {
        let stream = state
            .client
            .blast_radius(&node_id, &[], depth_limit as u8)
            .await?;

        let nodes: Vec<_> = std::pin::Pin::from(Box::new(stream))
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        Ok::<Vec<_>, ActivableError>(nodes)
    })?;

    // Convert to JSON array
    let json_array: Vec<serde_json::Value> = result
        .into_iter()
        .map(|node_ref| {
            serde_json::json!({
                "id": node_ref.id.to_string(),
                "label": node_ref.label,
            })
        })
        .collect();

    Ok(serde_json::to_string(&json_array).unwrap_or_else(|_| "[]".to_string()))
}

/// Subgraph extraction — fetch all nodes and edges matching a pattern.
///
/// `node_labels` is a comma-separated list of labels to include.
/// Returns JSON object with "nodes" and "edges" arrays.
#[uniffi::export]
pub fn query_subgraph(center_id: String, radius: u32) -> Result<String, ActivableError> {
    let state = get_global()?;
    let center = NodeId::from(center_id.as_str());

    let radius_u8 = u8::try_from(radius).unwrap_or(u8::MAX);
    let subgraph = state
        .runtime
        .block_on(async { state.client.subgraph(&center, radius_u8).await })?;

    // Serialize Subgraph to JSON with center + nodes
    let json = serde_json::json!({
        "center": {
            "id": subgraph.center.id.as_str(),
            "label": subgraph.center.label.to_string(),
        },
        "nodes": subgraph.nodes.iter().map(|n| serde_json::json!({
            "id": n.id.as_str(),
            "label": n.label.to_string(),
        })).collect::<Vec<_>>(),
    });

    Ok(serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string()))
}

#[cfg(test)]
mod tests {
    use activable_graph::types::Direction;

    #[test]
    fn test_direction_parsing() {
        let cases = vec!["outgoing", "incoming", "both", "OUTGOING", "invalid"];
        for case in cases {
            let dir = match case.to_lowercase().as_str() {
                "outgoing" => Direction::Outgoing,
                "incoming" => Direction::Incoming,
                "both" => Direction::Both,
                _ => Direction::Outgoing,
            };
            // Verify no panic on any input
            let _ = dir;
        }
    }

    #[test]
    fn test_comma_separated_parsing() {
        let edge_types = "ALLOW,DENY,ASSUME";
        let list: Vec<&str> = edge_types.split(',').map(|s| s.trim()).collect();
        assert_eq!(list, vec!["ALLOW", "DENY", "ASSUME"]);
    }
}
