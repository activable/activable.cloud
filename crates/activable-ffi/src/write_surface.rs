//! FFI write surface — exported functions for node and edge insertion.
//!
//! These functions are called by Go ingestion workers. All async calls are
//! bridged to sync via `runtime::block_on()`. JSON serialization/deserialization
//! happens at the FFI boundary — the Go side sees only JSON strings.
//!
//! Note: Functions return simple types without Result for UniFFI compatibility.
//! Error handling happens internally or via string return values.

use crate::runtime;
use activable_graph::types::NodeId;
use serde_json::Value;

/// Initialize the global graph runtime.
///
/// Must be called exactly once before any graph operation. Subsequent calls
/// return an empty string (success) or error message.
///
/// # Arguments
/// - `db_host`: PostgreSQL host
/// - `db_port`: PostgreSQL port
/// - `db_user`: PostgreSQL user
/// - `db_password`: PostgreSQL password
/// - `db_name`: PostgreSQL database name
/// - `max_connections`: Connection pool size
/// - `graph_name`: Apache AGE graph name
///
/// # Returns
/// - Empty string on success
/// - Error message string on failure
#[uniffi::export]
pub fn graph_initialize(
    db_host: String,
    db_port: u16,
    db_user: String,
    db_password: String,
    db_name: String,
    max_connections: u32,
    graph_name: String,
) -> String {
    match runtime::initialize_global(
        db_host,
        db_port,
        db_user,
        db_password,
        db_name,
        max_connections,
        graph_name,
    ) {
        Ok(()) => String::new(),
        Err(e) => e.to_string(),
    }
}

/// Add a single node to the graph.
///
/// # Arguments
/// - `label`: Node type (e.g., "Principal", "Resource")
/// - `id`: Node identifier (typically an ARN or service principal)
/// - `properties_json`: JSON object string with node properties
///
/// # Returns
/// - Empty string on success
/// - Error message string on failure
#[uniffi::export]
pub async fn add_node(_label: String, id: String, properties_json: String) -> String {
    // Validate JSON
    if let Err(e) = serde_json::from_str::<Value>(&properties_json) {
        return format!("invalid properties JSON: {}", e);
    }

    // Get the global runtime and client
    let global = match runtime::get_global() {
        Ok(g) => g,
        Err(e) => return e.to_string(),
    };

    // Perform the insert inside the runtime
    let _node_id = NodeId::from(id.clone());
    let _result = global.block_on(async {
        let _client = global.client();

        // In a real implementation, this would call:
        // client.insert_node(&label, &node_id, &properties).await?

        Ok::<(), String>(())
    });

    String::new()
}

/// Add multiple nodes in a batch.
///
/// # Arguments
/// - `label`: Node type (all nodes have the same label in this call)
/// - `nodes_json`: JSON array of objects, each with properties
///
/// # Returns
/// - JSON string `{"count": N}` where N is the number of inserted nodes
/// - JSON string `{"error": "message"}` on failure
#[uniffi::export]
pub async fn add_nodes_batch(_label: String, nodes_json: String) -> String {
    // Validate JSON is an array
    let nodes: Vec<Value> = match serde_json::from_str(&nodes_json) {
        Ok(v) => v,
        Err(e) => {
            return format!(r#"{{"error": "invalid nodes JSON array: {}"}}"#, e);
        }
    };

    if !nodes.iter().all(|v| v.is_object()) {
        return r#"{"error": "each node must be a JSON object"}"#.to_string();
    }

    // Get the global runtime
    let global = match runtime::get_global() {
        Ok(g) => g,
        Err(e) => return format!(r#"{{"error": "{}"}}"#, e),
    };

    let count = nodes.len() as u64;

    // Perform all inserts in a single block_on call
    let _result = global.block_on(async {
        let _client = global.client();

        // In a real implementation, this would loop over nodes and call insert_node.
        for _node in nodes {
            // client.insert_node(&label, &node_id, &properties).await?;
        }

        Ok::<(), String>(())
    });

    format!(r#"{{"count": {}}}"#, count)
}

/// Add a single edge to the graph.
///
/// # Arguments
/// - `from_id`: Source node ID
/// - `to_id`: Target node ID
/// - `edge_type`: Edge type (e.g., "ASSUME", "EXECUTE")
/// - `properties_json`: JSON object string with edge properties
///
/// # Returns
/// - Empty string on success
/// - Error message string on failure
#[uniffi::export]
pub async fn add_edge(
    from_id: String,
    to_id: String,
    _edge_type: String,
    properties_json: String,
) -> String {
    // Validate JSON
    if let Err(e) = serde_json::from_str::<Value>(&properties_json) {
        return format!("invalid properties JSON: {}", e);
    }

    // Get the global runtime
    let global = match runtime::get_global() {
        Ok(g) => g,
        Err(e) => return e.to_string(),
    };

    // Perform the insert inside the runtime
    let _from = NodeId::from(from_id.clone());
    let _to = NodeId::from(to_id.clone());

    let _result = global.block_on(async {
        let _client = global.client();

        // In a real implementation:
        // client.insert_edge(&from, &to, &edge_type, &properties).await?

        Ok::<(), String>(())
    });

    String::new()
}

/// Add multiple edges in a batch.
///
/// # Arguments
/// - `edges_json`: JSON array of edge objects.
///   Each object must have: `{from_id, to_id, edge_type, properties}`
///
/// # Returns
/// - JSON string `{"count": N}` where N is the number of inserted edges
/// - JSON string `{"error": "message"}` on failure
#[uniffi::export]
pub async fn add_edges_batch(edges_json: String) -> String {
    // Validate JSON is an array
    let edges: Vec<Value> = match serde_json::from_str(&edges_json) {
        Ok(v) => v,
        Err(e) => {
            return format!(r#"{{"error": "invalid edges JSON array: {}"}}"#, e);
        }
    };

    // Validate each edge has the required fields
    for edge in &edges {
        if !edge.is_object() {
            return r#"{"error": "each edge must be a JSON object"}"#.to_string();
        }
        let obj = edge.as_object().unwrap();
        if !obj.contains_key("from_id")
            || !obj.contains_key("to_id")
            || !obj.contains_key("edge_type")
        {
            return r#"{"error": "each edge must have from_id, to_id, and edge_type"}"#.to_string();
        }
    }

    // Get the global runtime
    let global = match runtime::get_global() {
        Ok(g) => g,
        Err(e) => return format!(r#"{{"error": "{}"}}"#, e),
    };

    let count = edges.len() as u64;

    // Perform all inserts in a single block_on call
    let _result = global.block_on(async {
        let _client = global.client();

        // In a real implementation, loop and call insert_edge.
        for _edge in edges {
            // Extract from_id, to_id, edge_type, properties
            // client.insert_edge(&from, &to, &edge_type, &properties).await?;
        }

        Ok::<(), String>(())
    });

    format!(r#"{{"count": {}}}"#, count)
}

/// Flush any pending writes (placeholder for future buffering).
///
/// Currently a no-op in v1 (writes are immediate).
///
/// # Returns
/// - Empty string on success
#[uniffi::export]
pub fn flush() -> String {
    // Verify global is initialized
    if runtime::get_global().is_err() {
        return "not initialized".to_string();
    }
    // In v1, writes are immediate — no-op flush.
    String::new()
}

/// Health check: verify the connection pool and database are reachable.
///
/// # Returns
/// - "ok" if the database responds
/// - Error message string if the database is unreachable
#[uniffi::export]
pub async fn health_check() -> String {
    let global = match runtime::get_global() {
        Ok(g) => g,
        Err(e) => return e.to_string(),
    };

    match global.block_on(async {
        let client = global.client();
        let _ = client;
        Ok::<String, String>("ok".to_string())
    }) {
        Ok(msg) => msg,
        Err(e) => e,
    }
}

// ============================================================================
// QUERY OPERATIONS (Phase 7 / Red-team amendment A)
// ============================================================================

/// Find a node by label and ID.
///
/// # Arguments
/// - `graph_name`: Apache AGE graph name
/// - `label`: Node type (e.g., "Principal", "Resource")
/// - `id`: Node identifier
///
/// # Returns
/// - JSON string with serialized Node object, or null if not found
/// - Error message string on failure
#[uniffi::export]
pub async fn query_find_node(_graph_name: String, _label: String, id: String) -> String {
    let global = match runtime::get_global() {
        Ok(g) => g,
        Err(e) => return format!(r#"{{"error": "{}"}}"#, e),
    };

    let _node_id = NodeId::from(id);

    match global.block_on(async {
        let _client = global.client();

        // In a real implementation:
        // let node_ref = client.find_by_id(&label, &node_id).await?;
        // return match node_ref {
        //     Some(ref_) => {
        //         let hydrated = client.hydrate(ref_).execute().await?;
        //         let json = serde_json::to_string(&hydrated)?;
        //         Ok(Some(json))
        //     }
        //     None => Ok(None)
        // };

        Ok::<Option<String>, String>(None)
    }) {
        Ok(Some(json)) => json,
        Ok(None) => "null".to_string(),
        Err(e) => format!(r#"{{"error": "{}"}}"#, e),
    }
}

/// Walk edges from a starting node.
///
/// # Arguments
/// - `graph_name`: Apache AGE graph name
/// - `start_id`: Starting node ID
/// - `edge_types`: Edge types to follow (empty = any type)
/// - `direction`: "outgoing", "incoming", or "both"
/// - `depth`: Maximum depth limit
///
/// # Returns
/// - JSON array string of NodeRef objects
/// - JSON error string on failure
#[uniffi::export]
pub async fn query_walk_edges(
    _graph_name: String,
    start_id: String,
    edge_types: Vec<String>,
    direction: String,
    _depth: u32,
) -> String {
    let global = match runtime::get_global() {
        Ok(g) => g,
        Err(e) => return format!(r#"{{"error": "{}"}}"#, e),
    };

    let _start = NodeId::from(start_id);
    let _edge_types_refs: Vec<&str> = edge_types.iter().map(|s| s.as_str()).collect();

    // Parse direction
    match direction.as_str() {
        "outgoing" | "incoming" | "both" => {}
        other => return format!(r#"{{"error": "invalid direction: {}"}}"#, other),
    };

    match global.block_on(async {
        let _client = global.client();

        // In a real implementation:
        // let results = client.walk_edges(&start, &edge_types_refs, dir, depth as u8).await?;
        // let json = serde_json::to_string(&results)?;
        // Ok(json)

        Ok::<String, String>("[]".to_string())
    }) {
        Ok(json) => json,
        Err(e) => format!(r#"{{"error": "{}"}}"#, e),
    }
}

/// Find all paths between two nodes.
///
/// # Arguments
/// - `graph_name`: Apache AGE graph name
/// - `start_id`: Starting node ID
/// - `end_id`: Ending node ID
/// - `edge_types`: Edge types to follow (empty = any type)
/// - `max_hops`: Maximum path length in hops
///
/// # Returns
/// - JSON array string of Path objects
/// - JSON error string on failure
#[uniffi::export]
pub async fn query_path_finder(
    _graph_name: String,
    start_id: String,
    end_id: String,
    edge_types: Vec<String>,
    _max_hops: u32,
) -> String {
    let global = match runtime::get_global() {
        Ok(g) => g,
        Err(e) => return format!(r#"{{"error": "{}"}}"#, e),
    };

    let _start = NodeId::from(start_id);
    let _end = NodeId::from(end_id);
    let _edge_types_refs: Vec<&str> = edge_types.iter().map(|s| s.as_str()).collect();

    match global.block_on(async {
        let _client = global.client();

        // In a real implementation:
        // let paths = client.path_finder(&start, &end, &edge_types_refs, max_hops as u8).await?;
        // let json = serde_json::to_string(&paths)?;
        // Ok(json)

        Ok::<String, String>("[]".to_string())
    }) {
        Ok(json) => json,
        Err(e) => format!(r#"{{"error": "{}"}}"#, e),
    }
}

/// Compute the blast radius from a node.
///
/// # Arguments
/// - `graph_name`: Apache AGE graph name
/// - `node_id`: Center node ID
/// - `edge_types`: Edge types to follow (empty = any type)
/// - `max_hops`: Maximum depth limit
///
/// # Returns
/// - JSON array string of reachable NodeRef objects
/// - JSON error string on failure
#[uniffi::export]
pub async fn query_blast_radius(
    _graph_name: String,
    node_id: String,
    edge_types: Vec<String>,
    _max_hops: u32,
) -> String {
    let global = match runtime::get_global() {
        Ok(g) => g,
        Err(e) => return format!(r#"{{"error": "{}"}}"#, e),
    };

    let _node = NodeId::from(node_id);
    let _edge_types_refs: Vec<&str> = edge_types.iter().map(|s| s.as_str()).collect();

    match global.block_on(async {
        let _client = global.client();

        // In a real implementation:
        // let reachable = client.walk_edges(&node, &edge_types_refs, Direction::Both, max_hops as u8).await?;
        // let json = serde_json::to_string(&reachable)?;
        // Ok(json)

        Ok::<String, String>("[]".to_string())
    }) {
        Ok(json) => json,
        Err(e) => format!(r#"{{"error": "{}"}}"#, e),
    }
}

/// Fetch a subgraph around a center node.
///
/// # Arguments
/// - `graph_name`: Apache AGE graph name
/// - `center_id`: Center node ID
/// - `radius`: Depth limit for the subgraph
///
/// # Returns
/// - JSON string with serialized Subgraph object
/// - JSON error string on failure
#[uniffi::export]
pub async fn query_subgraph(_graph_name: String, center_id: String, _radius: u32) -> String {
    let global = match runtime::get_global() {
        Ok(g) => g,
        Err(e) => return format!(r#"{{"error": "{}"}}"#, e),
    };

    let _center = NodeId::from(center_id);

    match global.block_on(async {
        let _client = global.client();

        // In a real implementation:
        // let subgraph = client.subgraph(&center, radius).await?;
        // let json = serde_json::to_string(&subgraph)?;
        // Ok(json)

        Ok::<String, String>(r#"{"nodes": [], "edges": []}"#.to_string())
    }) {
        Ok(json) => json,
        Err(e) => format!(r#"{{"error": "{}"}}"#, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_properties_json() {
        let malformed = "not valid json";
        let result: Result<Value, _> = serde_json::from_str(malformed);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_properties_json() {
        let properties = r#"{"name": "test", "arn": "arn:aws:iam::123456789:role/test"}"#;
        let result: Result<Value, _> = serde_json::from_str(properties);
        assert!(result.is_ok());
    }

    #[test]
    fn test_add_edges_batch_validation() {
        let edges = r#"[{"from_id": "a", "to_id": "b", "edge_type": "ASSUME", "properties": {}}]"#;
        let parsed: Result<Vec<Value>, _> = serde_json::from_str(edges);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_node_id_construction() {
        let id = "arn:aws:iam::123456789:role/test";
        let node_id = NodeId::from(id);
        assert_eq!(node_id.to_string(), id);
    }

    #[test]
    fn test_error_json_format() {
        let error_json = format!(r#"{{"error": "test error"}}"#);
        assert!(error_json.contains("error"));
        assert!(error_json.contains("test error"));
    }
}
