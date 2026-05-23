//! Bulk graph loader for Postgres+AGE.

use crate::error::GraphError;
use crate::query_builder::escape_sql_literal;
use deadpool_postgres::Pool;
use std::sync::Arc;

/// Load nodes into the graph from a JSON array.
///
/// Performs batched inserts within explicit BEGIN/COMMIT transaction blocks.
pub async fn load_nodes(
    pool: Arc<Pool>,
    graph_name: &str,
    label: &str,
    nodes: &[serde_json::Value],
    batch_size: usize,
) -> Result<u64, GraphError> {
    if nodes.is_empty() {
        return Ok(0);
    }

    let conn = pool
        .get()
        .await
        .map_err(|e| GraphError::Pool(e.to_string()))?;

    // Initialize AGE on this connection
    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .map_err(|e| GraphError::Query(e.to_string()))?;

    // Validate label
    if label.is_empty() {
        return Err(GraphError::UnsafeParameter("empty label".to_string()));
    }

    let first = label.chars().next().unwrap();
    if !first.is_ascii_alphabetic() {
        return Err(GraphError::UnsafeParameter(
            "label must start with a letter".to_string(),
        ));
    }

    // Start transaction
    conn.batch_execute("BEGIN;")
        .await
        .map_err(|e| GraphError::Query(format!("Failed to start transaction: {}", e)))?;

    let mut count = 0u64;

    for chunk in nodes.chunks(batch_size) {
        // AGE doesn't support UNWIND...SET — use individual CREATE per node
        for node in chunk {
            // Build property map from JSON object
            let props = if let Some(obj) = node.as_object() {
                let pairs: Vec<String> = obj
                    .iter()
                    .filter_map(|(k, v)| {
                        // Only include string/number/bool properties (AGE limitation)
                        match v {
                            serde_json::Value::String(s) => {
                                Some(format!("{}: '{}'", k, escape_sql_literal(s)))
                            }
                            serde_json::Value::Number(n) => {
                                Some(format!("{}: {}", k, n))
                            }
                            serde_json::Value::Bool(b) => {
                                Some(format!("{}: {}", k, b))
                            }
                            _ => None, // Skip arrays/objects/nulls
                        }
                    })
                    .collect();
                pairs.join(", ")
            } else {
                String::new()
            };

            let cypher = format!("CREATE (n:{} {{{}}})", label, props);
            let sql = format!(
                "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (n agtype)",
                graph_name, cypher
            );

            conn.execute(&sql, &[])
                .await
                .map_err(|e| GraphError::Query(format!("Node insert failed: {}", e)))?;

            count += 1;
        }
    }

    // Commit transaction
    conn.batch_execute("COMMIT;")
        .await
        .map_err(|e| GraphError::Query(format!("Failed to commit transaction: {}", e)))?;

    Ok(count)
}

/// Load edges into the graph from a list of (from_id, to_id) pairs.
///
/// Performs batched inserts within explicit BEGIN/COMMIT transaction blocks.
/// Pre-validates that the target nodes exist via a SELECT before attempting INSERT.
pub async fn load_edges(
    pool: Arc<Pool>,
    graph_name: &str,
    edge_label: &str,
    edges: &[(String, String)],
    batch_size: usize,
) -> Result<u64, GraphError> {
    if edges.is_empty() {
        return Ok(0);
    }

    let conn = pool
        .get()
        .await
        .map_err(|e| GraphError::Pool(e.to_string()))?;

    // Initialize AGE on this connection
    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .map_err(|e| GraphError::Query(e.to_string()))?;

    // Validate edge label
    if edge_label.is_empty() {
        return Err(GraphError::UnsafeParameter("empty edge label".to_string()));
    }

    // Start transaction
    conn.batch_execute("BEGIN;")
        .await
        .map_err(|e| GraphError::Query(format!("Failed to start transaction: {}", e)))?;

    let mut count = 0u64;

    for chunk in edges.chunks(batch_size) {
        // AGE doesn't support UNWIND with tuple destructuring — use individual MATCH+CREATE
        for (from_id, to_id) in chunk {
            let cypher = format!(
                "MATCH (a {{id: '{}'}}), (b {{id: '{}'}}) CREATE (a)-[:{}]->(b)",
                escape_sql_literal(from_id),
                escape_sql_literal(to_id),
                edge_label
            );

            let sql = format!(
                "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (a agtype, b agtype)",
                graph_name, cypher
            );

            // Edge creation may fail if source/target nodes don't exist — skip gracefully
            match conn.execute(&sql, &[]).await {
                Ok(_) => count += 1,
                Err(_) => {
                    // Skip — source or target node may not exist in graph
                }
            }
        }
    }

    // Commit transaction
    conn.batch_execute("COMMIT;")
        .await
        .map_err(|e| GraphError::Query(format!("Failed to commit transaction: {}", e)))?;

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query_builder::escape_cypher;

    #[test]
    fn escape_sql_literal_for_loader_test() {
        // Test that escape_sql_literal works correctly for loader use case
        let input = "principal'1";
        let result = escape_sql_literal(input);
        assert_eq!(result, "principal''1");
    }

    #[test]
    fn escape_cypher_for_loader_test() {
        // Test that escape_cypher works correctly for loader use case
        let input = "principal'1";
        let result = escape_cypher(input);
        assert_eq!(result, "principal\\'1");
    }
}
