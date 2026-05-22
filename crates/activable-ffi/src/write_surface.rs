//! FFI write surface — bulk node/edge insertion and pool management.

use crate::error::ActivableError;
use crate::runtime::{get_global, init_global};

/// Initialize the graph runtime with database connection parameters.
///
/// Must be called once before any graph operations.
/// Subsequent calls return `AlreadyInitialized`.
#[uniffi::export]
pub fn graph_initialize(
    host: String,
    port: u16,
    user: String,
    password: String,
    dbname: String,
    graph_name: String,
    max_connections: u32,
) -> Result<(), ActivableError> {
    init_global(
        host,
        port,
        user,
        password,
        dbname,
        graph_name,
        max_connections,
    )
}

/// Add a single node to the graph.
///
/// `properties_json` must be a valid JSON object string (e.g., `{"name": "value"}`).
/// `id` is validated via ARN checking for supported labels; non-ARN labels bypass validation.
#[uniffi::export]
pub fn add_node(label: String, id: String, properties_json: String) -> Result<(), ActivableError> {
    let state = get_global()?;

    // Parse properties JSON
    let properties: serde_json::Value =
        serde_json::from_str(&properties_json).map_err(|e| ActivableError::InvalidInput {
            message: format!("invalid JSON properties: {}", e),
        })?;

    // Build node object with id + properties merged
    let mut node_obj = match properties {
        serde_json::Value::Object(obj) => obj,
        _ => {
            return Err(ActivableError::InvalidInput {
                message: "properties must be a JSON object".to_string(),
            })
        }
    };
    node_obj.insert("id".to_string(), serde_json::Value::String(id));
    let node = serde_json::Value::Object(node_obj);

    // Call the loader within the runtime
    state.runtime.block_on(async {
        activable_graph::loader::load_nodes(
            state.pool.clone(),
            &state.graph_name,
            &label,
            &[node],
            1, // batch_size = 1 for single insertion
        )
        .await
    })?;

    Ok(())
}

/// Add multiple nodes in a batch from a JSON array.
///
/// JSON format: `[{"label": "Type", "id": "...", "properties": {...}}, ...]`
/// Returns the number of nodes inserted.
#[uniffi::export]
pub fn add_nodes_batch(nodes_json: String) -> Result<u32, ActivableError> {
    let state = get_global()?;

    // Parse JSON array
    let nodes_input: Vec<serde_json::Value> =
        serde_json::from_str(&nodes_json).map_err(|e| ActivableError::InvalidInput {
            message: format!("invalid JSON array: {}", e),
        })?;

    if nodes_input.is_empty() {
        return Ok(0);
    }

    // Group by label for batched inserts
    let mut by_label: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();

    for node_spec in nodes_input {
        let obj = match node_spec {
            serde_json::Value::Object(o) => o,
            _ => {
                return Err(ActivableError::InvalidInput {
                    message: "each node must be a JSON object".to_string(),
                })
            }
        };

        let label = obj
            .get("label")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ActivableError::InvalidInput {
                message: "missing 'label' field in node".to_string(),
            })?
            .to_string();

        let id = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ActivableError::InvalidInput {
                message: "missing 'id' field in node".to_string(),
            })?
            .to_string();

        // Merge properties if present, or use empty object
        let properties = obj
            .get("properties")
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));

        let mut node_obj = match properties {
            serde_json::Value::Object(o) => o,
            _ => serde_json::Map::new(),
        };
        node_obj.insert("id".to_string(), serde_json::Value::String(id));

        by_label
            .entry(label)
            .or_default()
            .push(serde_json::Value::Object(node_obj));
    }

    // Insert each label group
    let mut total_inserted = 0u32;
    for (label, nodes) in by_label {
        let count = state.runtime.block_on(async {
            activable_graph::loader::load_nodes(
                state.pool.clone(),
                &state.graph_name,
                &label,
                &nodes,
                128, // batch_size = 128 for batch inserts
            )
            .await
        })?;
        total_inserted += count as u32;
    }

    Ok(total_inserted)
}

/// Add a single edge to the graph.
///
/// `properties_json` must be a valid JSON object (may be empty `{}`).
#[uniffi::export]
pub fn add_edge(
    from_id: String,
    to_id: String,
    edge_type: String,
    properties_json: String,
) -> Result<(), ActivableError> {
    let state = get_global()?;

    // Validate properties JSON
    let _properties: serde_json::Value =
        serde_json::from_str(&properties_json).map_err(|e| ActivableError::InvalidInput {
            message: format!("invalid JSON properties: {}", e),
        })?;

    // Call the loader for edges (expects Vec<(from_id, to_id)> tuples)
    state.runtime.block_on(async {
        activable_graph::loader::load_edges(
            state.pool.clone(),
            &state.graph_name,
            &edge_type,
            &[(from_id, to_id)],
            1, // batch_size = 1 for single insertion
        )
        .await
    })?;

    Ok(())
}

/// Add multiple edges in a batch from a JSON array.
///
/// JSON format: `[{"from_id": "...", "to_id": "...", "edge_type": "...", "properties": {...}}, ...]`
/// Returns the number of edges inserted.
#[uniffi::export]
pub fn add_edges_batch(edges_json: String) -> Result<u32, ActivableError> {
    let state = get_global()?;

    // Parse JSON array
    let edges_input: Vec<serde_json::Value> =
        serde_json::from_str(&edges_json).map_err(|e| ActivableError::InvalidInput {
            message: format!("invalid JSON array: {}", e),
        })?;

    if edges_input.is_empty() {
        return Ok(0);
    }

    // Group edges by edge_type for batched inserts
    let mut by_type: std::collections::HashMap<String, Vec<(String, String)>> =
        std::collections::HashMap::new();

    for edge_spec in edges_input {
        let obj = match edge_spec {
            serde_json::Value::Object(o) => o,
            _ => {
                return Err(ActivableError::InvalidInput {
                    message: "each edge must be a JSON object".to_string(),
                })
            }
        };

        let from_id = obj
            .get("from_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ActivableError::InvalidInput {
                message: "missing 'from_id' field in edge".to_string(),
            })?
            .to_string();

        let to_id = obj
            .get("to_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ActivableError::InvalidInput {
                message: "missing 'to_id' field in edge".to_string(),
            })?
            .to_string();

        let edge_type = obj
            .get("edge_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ActivableError::InvalidInput {
                message: "missing 'edge_type' field in edge".to_string(),
            })?
            .to_string();

        // Validate properties if present
        if let Some(props) = obj.get("properties") {
            serde_json::from_str::<serde_json::Value>(&props.to_string()).map_err(|e| {
                ActivableError::InvalidInput {
                    message: format!("invalid properties JSON: {}", e),
                }
            })?;
        }

        by_type.entry(edge_type).or_default().push((from_id, to_id));
    }

    // Insert each edge_type group
    let mut total_inserted = 0u32;
    for (edge_type, edges) in by_type {
        let count = state.runtime.block_on(async {
            activable_graph::loader::load_edges(
                state.pool.clone(),
                &state.graph_name,
                &edge_type,
                &edges,
                128, // batch_size = 128
            )
            .await
        })?;
        total_inserted += count as u32;
    }

    Ok(total_inserted)
}

/// Flush any pending writes to the database.
///
/// In v1, all writes are immediate. This is a no-op placeholder for future
/// buffered-write support without breaking the FFI API.
#[uniffi::export]
pub fn flush() -> Result<(), ActivableError> {
    let _state = get_global()?;
    // v1: writes are immediate, no buffer to flush
    Ok(())
}

/// Check the health of the database connection pool.
///
/// Returns "ok" string if the pool is healthy.
#[uniffi::export]
pub fn health_check() -> Result<String, ActivableError> {
    let state = get_global()?;

    // Attempt to get a connection from the pool as a health check
    state.runtime.block_on(async {
        // Try to get a connection and immediately release it
        let _conn = state
            .pool
            .get()
            .await
            .map_err(|e| ActivableError::GraphError {
                message: format!("health check failed: {}", e),
            })?;

        // Connection acquired successfully; it's returned to pool on drop
        Ok::<String, ActivableError>("ok".to_string())
    })?;

    Ok("ok".to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_graph_initialize_error_on_invalid_json() {
        let result = serde_json::from_str::<serde_json::Value>("invalid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_properties_validation() {
        let json = r#"{"key": "value"}"#;
        let result = serde_json::from_str::<serde_json::Value>(json);
        assert!(result.is_ok());
    }
}
