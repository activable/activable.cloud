//! Bulk graph loader for Postgres+AGE.

use crate::error::GraphError;
use crate::query_builder::escape_sql_literal;
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing;

/// Outcome of an edge-load operation: tracks created edges and dropped edges (missing endpoints).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EdgeLoadOutcome {
    /// Number of edges actually created (endpoints both present).
    pub created: u64,
    /// Number of edges dropped due to missing endpoints.
    pub dropped: u64,
}

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
                        // Arrays/objects are serialized to JSON strings; nulls are skipped
                        match v {
                            serde_json::Value::String(s) => {
                                Some(format!("{}: '{}'", k, escape_sql_literal(s)))
                            }
                            serde_json::Value::Number(n) => Some(format!("{}: {}", k, n)),
                            serde_json::Value::Bool(b) => Some(format!("{}: {}", k, b)),
                            serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                                // Serialize complex types to JSON string
                                let json_str = match serde_json::to_string(v) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to serialize property {} to JSON: {}",
                                            k,
                                            e
                                        );
                                        return None;
                                    }
                                };
                                tracing::debug!(
                                    "Serialized property {} ({:?}) to JSON string",
                                    k,
                                    v
                                );
                                Some(format!("{}: '{}'", k, escape_sql_literal(&json_str)))
                            }
                            serde_json::Value::Null => None, // Skip nulls
                        }
                    })
                    .collect();
                pairs.join(", ")
            } else {
                String::new()
            };

            let cypher = format!("MERGE (n:{} {{{}}})", label, props);
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
/// Returns [`EdgeLoadOutcome`] with accurate counts: an edge increments `created` only if both
/// endpoints exist and the edge was merged. If an endpoint is missing:
/// - **lenient mode** (default): increments `dropped`, logs a structured warning with from_id/to_id/edge_label
/// - **strict mode**: returns `Err(GraphError)` naming the missing endpoint
///
/// # Arguments
/// * `strict` - if true, missing endpoint → Err; if false, missing endpoint → warn + dropped counter
pub async fn load_edges(
    pool: Arc<Pool>,
    graph_name: &str,
    edge_label: &str,
    edges: &[(String, String)],
    batch_size: usize,
    strict: bool,
) -> Result<EdgeLoadOutcome, GraphError> {
    if edges.is_empty() {
        return Ok(EdgeLoadOutcome {
            created: 0,
            dropped: 0,
        });
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

    let mut created = 0u64;
    let mut dropped = 0u64;

    for chunk in edges.chunks(batch_size) {
        // AGE doesn't support UNWIND with tuple destructuring — use individual MATCH+MERGE
        for (from_id, to_id) in chunk {
            let cypher = format!(
                "MATCH (a {{id: '{}'}}), (b {{id: '{}'}}) MERGE (a)-[:{}]->(b) RETURN id(a), id(b)",
                // AGE Cypher has no bound-parameter support; escape_sql_literal is the injection defense — do NOT remove.
                escape_sql_literal(from_id),
                escape_sql_literal(to_id),
                edge_label
            );

            let sql = format!(
                "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (a agtype, b agtype)",
                graph_name, cypher
            );

            // Use query() to check if the edge was actually created.
            // MATCH finds 0 rows if an endpoint is missing; MERGE never runs and returns 0 rows.
            // query() returns an empty Vec if no rows, allowing us to distinguish "created" from "missing endpoint".
            match conn.query(&sql, &[]).await {
                Ok(rows) => {
                    if !rows.is_empty() {
                        // Edge was created (both endpoints matched and merged)
                        created += 1;
                    } else {
                        // MATCH found no endpoints — edge not created
                        dropped += 1;
                        if strict {
                            // Commit and exit before returning error (to clean up the transaction state)
                            conn.batch_execute("COMMIT;").await.map_err(|e| {
                                GraphError::Query(format!("Failed to commit transaction: {}", e))
                            })?;
                            return Err(GraphError::Query(format!(
                                "Strict mode: missing endpoint in edge {} -> {}",
                                from_id, to_id
                            )));
                        } else {
                            // Lenient mode: warn and continue
                            tracing::warn!(
                                from_id = %from_id,
                                to_id = %to_id,
                                edge_label = %edge_label,
                                "Edge not created due to missing endpoint"
                            );
                        }
                    }
                }
                Err(e) => {
                    // Real error (syntax, transaction abort, etc.) — propagate
                    tracing::warn!("Edge insert failed for ({} -> {}): {}", from_id, to_id, e);
                    return Err(GraphError::Query(format!(
                        "Failed to insert edge from {} to {}: {}",
                        from_id, to_id, e
                    )));
                }
            }
        }
    }

    // Commit transaction
    conn.batch_execute("COMMIT;")
        .await
        .map_err(|e| GraphError::Query(format!("Failed to commit transaction: {}", e)))?;

    Ok(EdgeLoadOutcome { created, dropped })
}

/// Load edges with properties into the graph.
///
/// Each edge is created with a set of properties (e.g., action, resource).
/// Properties are passed as a JSON object and set on the relationship.
/// Performs batched inserts within explicit BEGIN/COMMIT transaction blocks.
/// Returns [`EdgeLoadOutcome`] with accurate counts: an edge increments `created` only if both
/// endpoints exist and the edge was merged. If an endpoint is missing:
/// - **lenient mode** (default): increments `dropped`, logs a structured warning with from_id/to_id/edge_label
/// - **strict mode**: returns `Err(GraphError)` naming the missing endpoint
///
/// # Arguments
/// * `strict` - if true, missing endpoint → Err; if false, missing endpoint → warn + dropped counter
pub async fn load_edges_with_props(
    pool: Arc<Pool>,
    graph_name: &str,
    edge_label: &str,
    edges: &[(String, String, serde_json::Value)],
    batch_size: usize,
    strict: bool,
) -> Result<EdgeLoadOutcome, GraphError> {
    load_edges_with_props_identifying(pool, graph_name, edge_label, edges, batch_size, strict, &[])
        .await
}

/// Load edges with properties, specifying which properties are part of the MERGE identifying key.
///
/// For edges where distinct property combinations must be preserved (e.g., `HasEffectivePermission`
/// with different (action, resource) pairs), pass the identifying property names in `identifying_keys`.
/// The MERGE will include these properties in the relationship pattern, preventing property-only
/// variations from collapsing into one edge.
///
/// If `identifying_keys` is empty, behavior is identical to `load_edges_with_props` (MERGE on
/// `(from, to, edge_label)` only).
///
/// # Arguments
/// * `identifying_keys` - property names that are part of the MERGE key (e.g., vec!["action", "resource"])
pub async fn load_edges_with_props_identifying(
    pool: Arc<Pool>,
    graph_name: &str,
    edge_label: &str,
    edges: &[(String, String, serde_json::Value)],
    batch_size: usize,
    strict: bool,
    identifying_keys: &[&str],
) -> Result<EdgeLoadOutcome, GraphError> {
    if edges.is_empty() {
        return Ok(EdgeLoadOutcome {
            created: 0,
            dropped: 0,
        });
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

    let mut created = 0u64;
    let mut dropped = 0u64;

    for chunk in edges.chunks(batch_size) {
        for (from_id, to_id, props) in chunk {
            // Partition properties: identifying vs. settable
            let (identifying_props, settable_props) = partition_properties(props, identifying_keys);

            // Build MERGE clause: include identifying properties in the relationship pattern
            let merge_clause = if identifying_props.is_empty() {
                // No identifying props: simple MERGE (backward compatible)
                format!("(a)-[r:{}]->(b)", edge_label)
            } else {
                // Include identifying props in MERGE pattern
                format!("(a)-[r:{} {{{}}}]->(b)", edge_label, identifying_props)
            };

            // Build SET clause: only for non-identifying properties
            let set_clause = if settable_props.is_empty() {
                String::new()
            } else {
                format!(" SET r += {}", settable_props)
            };

            let cypher = format!(
                "MATCH (a {{id: '{}'}}), (b {{id: '{}'}}) MERGE {}{}  RETURN id(a), id(b)",
                // AGE Cypher has no bound-parameter support; escape_sql_literal is the injection defense — do NOT remove.
                escape_sql_literal(from_id),
                escape_sql_literal(to_id),
                merge_clause,
                set_clause
            );

            let sql = format!(
                "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (a agtype, b agtype)",
                graph_name, cypher
            );

            // Use query() to check if the edge was actually created (same as load_edges).
            match conn.query(&sql, &[]).await {
                Ok(rows) => {
                    if !rows.is_empty() {
                        // Edge was created (both endpoints matched and merged)
                        created += 1;
                    } else {
                        // MATCH found no endpoints — edge not created
                        dropped += 1;
                        if strict {
                            // Commit and exit before returning error
                            conn.batch_execute("COMMIT;").await.map_err(|e| {
                                GraphError::Query(format!("Failed to commit transaction: {}", e))
                            })?;
                            return Err(GraphError::Query(format!(
                                "Strict mode: missing endpoint in edge {} -> {}",
                                from_id, to_id
                            )));
                        } else {
                            // Lenient mode: warn and continue
                            tracing::warn!(
                                from_id = %from_id,
                                to_id = %to_id,
                                edge_label = %edge_label,
                                "Edge not created due to missing endpoint"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Edge insert with props failed for ({} -> {}): {}",
                        from_id,
                        to_id,
                        e
                    );
                    return Err(GraphError::Query(format!(
                        "Failed to insert edge with props from {} to {}: {}",
                        from_id, to_id, e
                    )));
                }
            }
        }
    }

    // Commit transaction
    conn.batch_execute("COMMIT;")
        .await
        .map_err(|e| GraphError::Query(format!("Failed to commit transaction: {}", e)))?;

    Ok(EdgeLoadOutcome { created, dropped })
}

/// Partition properties into identifying and settable groups.
///
/// Properties listed in `identifying_keys` are returned as a comma-separated
/// key-value string suitable for a MERGE pattern: `action: 'value', resource: 'value'`.
/// All other properties are returned as a settable map `{key: value, ...}` for SET clauses.
fn partition_properties(props: &serde_json::Value, identifying_keys: &[&str]) -> (String, String) {
    let map = match props.as_object() {
        Some(m) => m,
        None => return (String::new(), String::new()),
    };

    let mut identifying_parts = Vec::new();
    let mut settable_parts = Vec::new();

    for (k, v) in map {
        let is_identifying = identifying_keys.contains(&k.as_str());
        let value_str = match v {
            serde_json::Value::String(s) => Some(format!("'{}'", escape_sql_literal(s))),
            serde_json::Value::Number(n) => Some(format!("{}", n)),
            serde_json::Value::Bool(b) => Some(format!("{}", b)),
            _ => None, // Skip arrays/objects/nulls
        };

        if let Some(val) = value_str {
            if is_identifying {
                identifying_parts.push(format!("{}: {}", k, val));
            } else {
                settable_parts.push(format!("{}: {}", k, val));
            }
        }
    }

    let identifying_str = identifying_parts.join(", ");
    let settable_str = if settable_parts.is_empty() {
        String::new()
    } else {
        format!("{{{}}}", settable_parts.join(", "))
    };

    (identifying_str, settable_str)
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
