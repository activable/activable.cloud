//! GraphClient — typed query API over Postgres+AGE.

use crate::error::GraphError;
use crate::query_builder::CypherBuilder;
use crate::types::{Direction, HydrationQuery, Node, NodeId, NodeRef, Path, Subgraph};
use deadpool_postgres::Pool;
use futures::stream::{self, Stream};
use std::str::FromStr;
use std::sync::Arc;

/// Parse an agtype scalar value (number, boolean, string) to a typed result.
///
/// AGE returns agtype values as strings via `::text` cast. This helper handles:
/// - Bare numbers: "5" → 5
/// - Quoted strings: "\"hello\"" → stripped to "hello"
/// - JSON Object forms: "{...}" → parsed accordingly
///
/// The caller is responsible for casting the agtype column to `::text` in the SQL
/// to ensure the value arrives as a string rather than raw agtype OID.
///
/// # Examples
/// ```ignore
/// let raw: String = row.try_get(0)?;
/// let count: u32 = parse_agtype_scalar::<u32>(&raw)?;
/// ```
pub fn parse_agtype_scalar<T: FromStr>(raw: &str) -> Result<T, GraphError>
where
    T::Err: std::fmt::Display,
{
    let trimmed = raw.trim();

    // Case 1: bare number (most common from count(*), arithmetic)
    if let Ok(val) = trimmed.parse::<T>() {
        return Ok(val);
    }

    // Case 2: quoted string — strip outer quotes and parse again
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        let inner = &trimmed[1..trimmed.len() - 1];
        if let Ok(val) = inner.trim().parse::<T>() {
            return Ok(val);
        }
    }

    // Case 3: JSON Object form (e.g., count(*) as agtype might return {...})
    // Try to extract a numeric or boolean value from the object if it looks like JSON
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        // For robustness, attempt to deserialize as JSON and extract first numeric field
        if let Ok(obj) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(trimmed)
        {
            // Try the common field names first
            for field_name in &["value", "result", "count", "count(*)"] {
                if let Some(val) = obj.get(*field_name) {
                    if let Some(num) = val.as_i64() {
                        if let Ok(parsed) = format!("{}", num).parse::<T>() {
                            return Ok(parsed);
                        }
                    }
                }
            }
            // Fall through to error below
        }
    }

    // No parse succeeded; return structured error
    Err(GraphError::Parse(format!(
        "Failed to parse agtype scalar to {}: '{}'",
        std::any::type_name::<T>(),
        raw
    )))
}

/// Main graph client for querying the AGE graph.
///
/// Clone-cheap (internally Arc<Pool>).
#[derive(Clone)]
pub struct GraphClient {
    pool: Arc<Pool>,
    graph_name: String,
}

impl GraphClient {
    /// Create a new client from a pool and graph name.
    pub fn new(pool: Arc<Pool>, graph_name: impl Into<String>) -> Self {
        GraphClient {
            pool,
            graph_name: graph_name.into(),
        }
    }

    /// Find a node by label and ID.
    pub async fn find_by_id(
        &self,
        label: &str,
        id: &NodeId,
    ) -> Result<Option<NodeRef>, GraphError> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| GraphError::Pool(e.to_string()))?;

        // Initialize AGE on this connection
        conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        let builder = CypherBuilder::new(&self.graph_name);
        let sql = builder.find_by_id(label, id)?;

        let rows = conn
            .query(&sql, &[])
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        if rows.is_empty() {
            return Ok(None);
        }

        // AGE returns agtype values — extract as string and strip AGE quoting
        let raw: String = rows[0]
            .try_get::<_, String>(0)
            .map_err(|e| GraphError::Parse(e.to_string()))?;

        // AGE wraps string values in extra quotes: "\"value\"" → strip them
        let id_val = raw.trim().trim_matches('"');

        Ok(Some(NodeRef::new(id_val, label)))
    }

    /// Walk edges one hop from a starting node, returning a stream of up to
    /// `result_limit` neighbor references.
    pub async fn walk_edges(
        &self,
        start: &NodeId,
        edge_types: &[&str],
        direction: Direction,
        result_limit: u8,
    ) -> Result<impl Stream<Item = Result<NodeRef, GraphError>>, GraphError> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| GraphError::Pool(e.to_string()))?;

        conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        let builder = CypherBuilder::new(&self.graph_name);
        let sql = builder.walk_edges(start, edge_types, direction, result_limit)?;

        let rows = conn
            .query(&sql, &[])
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        let refs: Vec<NodeRef> = rows
            .iter()
            .map(|row| {
                let raw_id: String = row
                    .try_get::<_, String>(0)
                    .map_err(|e| GraphError::Parse(e.to_string()))?;
                let raw_label: String = row
                    .try_get::<_, String>(1)
                    .map_err(|e| GraphError::Parse(e.to_string()))?;
                // AGE wraps strings in extra quotes — strip them
                let id = raw_id.trim().trim_matches('"');
                let label = raw_label.trim().trim_matches('"');
                Ok(NodeRef::new(id, label))
            })
            .collect::<Result<Vec<_>, GraphError>>()?;

        Ok(stream::iter(refs.into_iter().map(Ok)))
    }

    /// Find paths between two nodes.
    pub async fn path_finder(
        &self,
        start: &NodeId,
        end: &NodeId,
        edge_pattern: &[&str],
        max_hops: u8,
    ) -> Result<Vec<Path>, GraphError> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| GraphError::Pool(e.to_string()))?;

        conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        let builder = CypherBuilder::new(&self.graph_name);
        let sql = builder.path_finder(start, end, edge_pattern, max_hops)?;

        let rows = conn
            .query(&sql, &[])
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        let paths = Vec::new();
        for _row in rows {
            // TODO: parse path structure from agtype JSON
            // For now, return empty path list to allow compilation
            // Real implementation would deserialize the path from agtype JSON
        }

        Ok(paths)
    }

    /// Find the shortest path length between two nodes.
    pub async fn shortest_path_length(
        &self,
        start: &NodeId,
        end: &NodeId,
        max_hops: u8,
    ) -> Result<Option<u32>, GraphError> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| GraphError::Pool(e.to_string()))?;

        conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        let builder = CypherBuilder::new(&self.graph_name);
        let sql = builder.shortest_path_length(start, end, max_hops)?;

        let rows = conn
            .query(&sql, &[])
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        if rows.is_empty() {
            return Ok(None);
        }

        let length_str: &str = rows[0]
            .try_get(0)
            .map_err(|e| GraphError::Parse(e.to_string()))?;

        let length: u32 = length_str
            .parse()
            .map_err(|e| GraphError::Parse(format!("Failed to parse path length: {}", e)))?;

        Ok(Some(length))
    }

    /// Get all nodes within max_hops of a starting node.
    ///
    /// Returns a stream of node references.
    pub async fn blast_radius(
        &self,
        node: &NodeId,
        edge_types: &[&str],
        max_hops: u8,
    ) -> Result<impl Stream<Item = Result<NodeRef, GraphError>>, GraphError> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| GraphError::Pool(e.to_string()))?;

        conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        let builder = CypherBuilder::new(&self.graph_name);
        let sql = builder.blast_radius(node, edge_types, max_hops)?;

        let rows = conn
            .query(&sql, &[])
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        let refs: Vec<NodeRef> = rows
            .iter()
            .map(|row| {
                let raw_id: String = row
                    .try_get::<_, String>(0)
                    .map_err(|e| GraphError::Parse(e.to_string()))?;
                let raw_label: String = row
                    .try_get::<_, String>(1)
                    .map_err(|e| GraphError::Parse(e.to_string()))?;
                let id = raw_id.trim().trim_matches('"');
                let label = raw_label.trim().trim_matches('"');
                Ok(NodeRef::new(id, label))
            })
            .collect::<Result<Vec<_>, GraphError>>()?;

        Ok(stream::iter(refs.into_iter().map(Ok)))
    }

    /// Get a subgraph around a center node.
    pub async fn subgraph(&self, center: &NodeId, radius: u8) -> Result<Subgraph, GraphError> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| GraphError::Pool(e.to_string()))?;

        conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        let builder = CypherBuilder::new(&self.graph_name);
        let sql = builder.subgraph(center, radius)?;

        let rows = conn
            .query(&sql, &[])
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        let nodes: Vec<NodeRef> = rows
            .iter()
            .map(|row| {
                let id: &str = row
                    .try_get(0)
                    .map_err(|e| GraphError::Parse(e.to_string()))?;
                let labels: &str = row
                    .try_get(1)
                    .map_err(|e| GraphError::Parse(e.to_string()))?;
                let label = extract_first_label(labels).unwrap_or("Unknown".to_string());
                Ok(NodeRef::new(id, label))
            })
            .collect::<Result<Vec<_>, GraphError>>()?;

        let center_ref = NodeRef::new(center.as_str(), "Unknown");
        Ok(Subgraph::new(center_ref, nodes))
    }

    /// Start building a hydration query.
    pub fn hydrate(&self, node_ref: &NodeRef) -> HydrationQuery<'_> {
        HydrationQuery::new(self, node_ref.clone())
    }

    /// Execute raw Cypher (escape hatch).
    ///
    /// **Warning:** Caller is responsible for safe interpolation of any runtime values.
    /// Use `escape_cypher()` from `query_builder` before interpolating user-supplied strings.
    pub async fn cypher(&self, cypher: &str) -> Result<Vec<serde_json::Value>, GraphError> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| GraphError::Pool(e.to_string()))?;

        conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        // Cast agtype to ::text — tokio-postgres can't deserialize the agtype OID
        // directly. The text rendering of agtype IS valid JSON, so we can read as
        // String and parse with serde_json.
        let sql = format!(
            "SELECT result::text FROM ag_catalog.cypher('{}', $${}$$) AS (result agtype)",
            self.graph_name, cypher
        );

        let rows = conn
            .query(&sql, &[])
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        let mut results = Vec::new();
        for row in rows {
            let agtype_str_opt: Option<String> = row
                .try_get(0)
                .map_err(|e| GraphError::Parse(e.to_string()))?;
            let agtype_str = match agtype_str_opt {
                None => continue,
                Some(s) => s,
            };
            let agtype_str = agtype_str.as_str();
            let value: serde_json::Value = serde_json::from_str(agtype_str)
                .map_err(|e| GraphError::Parse(format!("Failed to parse agtype: {}", e)))?;
            results.push(value);
        }

        Ok(results)
    }

    /// Execute Cypher query returning multiple columns.
    /// Each row is returned as a Vec<serde_json::Value> (one per column).
    ///
    /// **Warning:** Caller is responsible for safe interpolation of any runtime values.
    /// Use `escape_cypher()` from `query_builder` before interpolating user-supplied strings.
    pub async fn cypher_multi_column(
        &self,
        cypher: &str,
        column_count: usize,
    ) -> Result<Vec<Vec<serde_json::Value>>, GraphError> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| GraphError::Pool(e.to_string()))?;

        conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        // Build SQL with correct number of columns. Cast each agtype column to ::text
        // because tokio-postgres can't deserialize agtype OID directly — it succeeds
        // for text. agtype's text rendering IS valid JSON (quoted strings, JSON arrays
        // etc.), so we can serde_json::from_str the text into Value.
        let column_defs = (0..column_count)
            .map(|i| format!("col{} agtype", i))
            .collect::<Vec<_>>()
            .join(", ");
        let column_selects = (0..column_count)
            .map(|i| format!("col{}::text", i))
            .collect::<Vec<_>>()
            .join(", ");

        let sql = format!(
            "SELECT {} FROM ag_catalog.cypher('{}', $${}$$) AS ({})",
            column_selects, self.graph_name, cypher, column_defs
        );

        let rows = conn
            .query(&sql, &[])
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        let mut results = Vec::new();
        for row in rows {
            let mut row_values = Vec::new();
            for col_idx in 0..column_count {
                let agtype_str: Option<String> = row.try_get(col_idx).map_err(|e| {
                    GraphError::Parse(format!("Failed to read column {}: {}", col_idx, e))
                })?;
                let value = match agtype_str {
                    None => serde_json::Value::Null,
                    Some(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s)),
                };
                row_values.push(value);
            }
            results.push(row_values);
        }

        Ok(results)
    }

    /// Internal hydration method called by HydrationQuery.
    pub(crate) async fn hydrate_internal(
        &self,
        node_ref: NodeRef,
        _fields: Option<Vec<String>>,
    ) -> Result<Node, GraphError> {
        // For now, fetch all properties. In v2, could filter by fields.
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| GraphError::Pool(e.to_string()))?;

        conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        let sql = format!(
            "SELECT * FROM ag_catalog.cypher('{}', $$MATCH (n:{{id: '{}'}}) RETURN n$$) AS (node agtype)",
            self.graph_name, node_ref.id.as_str()
        );

        let rows = conn
            .query(&sql, &[])
            .await
            .map_err(|e| GraphError::Query(e.to_string()))?;

        if rows.is_empty() {
            return Err(GraphError::NotFound);
        }

        let agtype_bytes: &[u8] = rows[0]
            .try_get(0)
            .map_err(|e| GraphError::Parse(e.to_string()))?;
        let agtype_str = String::from_utf8_lossy(agtype_bytes);
        let properties: serde_json::Value = serde_json::from_str(&agtype_str)
            .map_err(|e| GraphError::Parse(format!("Failed to parse node properties: {}", e)))?;

        Ok(Node::new(node_ref, properties))
    }
}

/// Extract the first label from a JSON array string like "[\"Label\"]".
fn extract_first_label(labels_str: &str) -> Option<String> {
    let trimmed = labels_str.trim_matches(|c| c == '[' || c == ']' || c == ' ');
    if trimmed.is_empty() {
        return None;
    }
    let label = trimmed.split(',').next()?.trim_matches('"').to_string();
    if label.is_empty() {
        None
    } else {
        Some(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_first_label_single() {
        let result = extract_first_label("[\"Principal\"]");
        assert_eq!(result, Some("Principal".to_string()));
    }

    #[test]
    fn extract_first_label_multiple() {
        let result = extract_first_label("[\"Principal\", \"User\"]");
        assert_eq!(result, Some("Principal".to_string()));
    }

    #[test]
    fn extract_first_label_empty() {
        let result = extract_first_label("[]");
        assert_eq!(result, None);
    }

    #[test]
    fn extract_first_label_with_spaces() {
        let result = extract_first_label("[ \"Principal\" ]");
        assert_eq!(result, Some("Principal".to_string()));
    }
}
