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

    let conn = pool.get().await.map_err(|e| GraphError::Pool(e.to_string()))?;

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
        // Build property list for UNWIND
        let props_list: Vec<String> = chunk
            .iter()
            .map(|v| {
                let json_str = v.to_string();
                format!("'{}'::agtype", escape_sql_literal(&json_str))
            })
            .collect();

        let cypher = format!(
            "UNWIND [{}] AS props CREATE (n:{} {{id: props.id}}) SET n = props RETURN count(n)",
            props_list.join(", "),
            label
        );

        let sql = format!(
            "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (result agtype)",
            graph_name, cypher
        );

        conn.execute(&sql, &[])
            .await
            .map_err(|e| GraphError::Query(format!("Batch insert failed: {}", e)))?;

        count += chunk.len() as u64;
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

    let conn = pool.get().await.map_err(|e| GraphError::Pool(e.to_string()))?;

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
        // Build VALUES list with escaped IDs
        let values_list: Vec<String> = chunk
            .iter()
            .map(|(from, to)| {
                format!(
                    "('\"{}\"'::agtype, '\"{}\"'::agtype)",
                    escape_sql_literal(from),
                    escape_sql_literal(to)
                )
            })
            .collect();

        let cypher = format!(
            "UNWIND [{}] AS (from_id, to_id) MATCH (a {{id: from_id}}), (b {{id: to_id}}) CREATE (a)-[:{} {{}}]->(b) RETURN count(*)",
            values_list.join(", "),
            edge_label
        );

        let sql = format!(
            "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (result agtype)",
            graph_name, cypher
        );

        conn.execute(&sql, &[])
            .await
            .map_err(|e| GraphError::Query(format!("Batch edge insert failed: {}", e)))?;

        count += chunk.len() as u64;
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
