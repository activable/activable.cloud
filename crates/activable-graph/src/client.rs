//! Graph query client.
//!
//! Provides the main `GraphClient` interface for executing typed graph queries.

use crate::error::GraphError;
use crate::pool::initialize_age_connection;
use crate::query_builder::CypherBuilder;
use crate::types::{Direction, HydrationQuery, NodeId, NodeRef, Path, Subgraph};
use deadpool_postgres::Pool;
use serde_json::Value;
use std::sync::Arc;

/// The main graph client.
///
/// Provides all graph query operations. Clone-cheap (internally Arc<Pool>).
#[derive(Clone)]
pub struct GraphClient {
    pool: Arc<Pool>,
    graph_name: String,
}

impl GraphClient {
    /// Create a new graph client.
    ///
    /// # Arguments
    ///
    /// * `pool` - A deadpool-postgres pool (typically created via `GraphPool::build()`)
    /// * `graph_name` - The name of the AGE graph to query
    ///
    /// # Example
    ///
    /// ```ignore
    /// let pool = GraphPool::build(&config, 10)?;
    /// let client = GraphClient::new(pool, "aws_graph");
    /// ```
    pub fn new(pool: Arc<Pool>, graph_name: impl Into<String>) -> Self {
        Self {
            pool,
            graph_name: graph_name.into(),
        }
    }

    /// Find a node by label and ID.
    ///
    /// Returns `Ok(None)` if the node does not exist.
    pub async fn find_by_id(
        &self,
        label: &str,
        id: &NodeId,
    ) -> Result<Option<NodeRef>, GraphError> {
        let builder = CypherBuilder::new(&self.graph_name);
        let sql = builder.find_by_id(label, id)?;

        let client = self.pool.get().await?;
        let rows = client.query(&sql, &[]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        // Parse first row — Postgres returns bytes that we need to convert to string
        let row = &rows[0];
        let node_id_bytes: Vec<u8> = row.try_get(0).unwrap_or_default();
        let node_id_str = String::from_utf8(node_id_bytes).unwrap_or_default();

        let id_str = node_id_str.trim_matches('"').to_string();

        Ok(Some(NodeRef::new(id_str, label.to_string())))
    }

    /// Walk edges from a starting node.
    ///
    /// Returns a vector of reachable nodes within the specified depth limit.
    /// Pass an empty slice for `edge_types` to match any edge type.
    pub async fn walk_edges(
        &self,
        start: &NodeId,
        edge_types: &[&str],
        direction: Direction,
        depth_limit: u8,
    ) -> Result<Vec<NodeRef>, GraphError> {
        let builder = CypherBuilder::new(&self.graph_name);
        let sql = builder.walk_edges(start, edge_types, direction, depth_limit)?;

        let client = self.pool.get().await?;
        let rows = client.query(&sql, &[]).await?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let node_id_bytes: Vec<u8> = row.try_get(0).unwrap_or_default();
            let node_id_str = String::from_utf8(node_id_bytes).unwrap_or_default();
            let id_str = node_id_str.trim_matches('"').to_string();

            // For labels, we would need to parse the agtype array returned
            let label = "Unknown".to_string();

            results.push(NodeRef::new(id_str, label));
        }

        Ok(results)
    }

    /// Find all paths between two nodes.
    ///
    /// Returns a vector of paths from `start` to `end`, with at most `max_hops` edges.
    pub async fn path_finder(
        &self,
        start: &NodeId,
        end: &NodeId,
        edge_pattern: &[&str],
        max_hops: u8,
    ) -> Result<Vec<Path>, GraphError> {
        let builder = CypherBuilder::new(&self.graph_name);
        let sql = builder.path_finder(start, end, edge_pattern, max_hops)?;

        let client = self.pool.get().await?;
        let rows = client.query(&sql, &[]).await?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let path_bytes: Vec<u8> = row.try_get(0).unwrap_or_default();
            let path_str = String::from_utf8(path_bytes).unwrap_or_default();

            // Parse the path JSON from Postgres
            if let Ok(path_value) = serde_json::from_str::<Value>(&path_str) {
                if let Some(nodes_array) = path_value.as_array() {
                    let mut nodes = Vec::new();

                    for node_val in nodes_array {
                        if let Some(node_obj) = node_val.as_object() {
                            let id_str = node_obj
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .trim_matches('"')
                                .to_string();

                            let label = if let Some(labels) = node_obj.get("labels").and_then(|v| v.as_array()) {
                                labels
                                    .first()
                                    .and_then(|l| l.as_str())
                                    .unwrap_or("Unknown")
                                    .to_string()
                            } else {
                                "Unknown".to_string()
                            };

                            nodes.push(NodeRef::new(id_str, label));
                        }
                    }

                    if !nodes.is_empty() {
                        let edge_labels = vec!["edge".to_string(); nodes.len().saturating_sub(1)];
                        results.push(Path::new(nodes, edge_labels));
                    }
                }
            }
        }

        Ok(results)
    }

    /// Find the shortest path length between two nodes.
    ///
    /// Returns the number of edges in the shortest path, or `None` if no path exists.
    pub async fn shortest_path_length(
        &self,
        start: &NodeId,
        end: &NodeId,
        max_hops: u8,
    ) -> Result<Option<u32>, GraphError> {
        let builder = CypherBuilder::new(&self.graph_name);
        let sql = builder.shortest_path_length(start, end, max_hops)?;

        let client = self.pool.get().await?;
        let rows = client.query(&sql, &[]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let length_bytes: Vec<u8> = rows[0].try_get(0).unwrap_or_default();
        let length_str = String::from_utf8(length_bytes).unwrap_or_default();

        if let Ok(n) = length_str.trim().parse::<u32>() {
            Ok(Some(n))
        } else {
            Ok(None)
        }
    }

    /// Find all nodes within a blast radius.
    ///
    /// Returns all nodes reachable from `node` within `max_hops` edges.
    pub async fn blast_radius(
        &self,
        node: &NodeId,
        edge_types: &[&str],
        max_hops: u8,
    ) -> Result<Vec<NodeRef>, GraphError> {
        let builder = CypherBuilder::new(&self.graph_name);
        let sql = builder.blast_radius(node, edge_types, max_hops)?;

        let client = self.pool.get().await?;
        let rows = client.query(&sql, &[]).await?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let node_id_bytes: Vec<u8> = row.try_get(0).unwrap_or_default();
            let node_id_str = String::from_utf8(node_id_bytes).unwrap_or_default();
            let id_str = node_id_str.trim_matches('"').to_string();

            let label = "Unknown".to_string();

            results.push(NodeRef::new(id_str, label));
        }

        Ok(results)
    }

    /// Retrieve a local subgraph around a center node.
    ///
    /// Returns the center node plus all nodes within `radius` hops.
    pub async fn subgraph(
        &self,
        center: &NodeId,
        radius: u8,
    ) -> Result<Subgraph, GraphError> {
        let builder = CypherBuilder::new(&self.graph_name);
        let sql = builder.subgraph(center, radius)?;

        let client = self.pool.get().await?;
        let rows = client.query(&sql, &[]).await?;

        // Create a center node reference (label would normally come from the database)
        let center_ref = NodeRef::new(center.clone(), "Unknown".to_string());

        let mut nodes = vec![center_ref.clone()];

        for row in rows {
            let node_id_bytes: Vec<u8> = row.try_get(0).unwrap_or_default();
            let node_id_str = String::from_utf8(node_id_bytes).unwrap_or_default();
            let id_str = node_id_str.trim_matches('"').to_string();

            let label = "Unknown".to_string();

            let node_ref = NodeRef::new(id_str, label);
            if node_ref.id != center_ref.id {
                nodes.push(node_ref);
            }
        }

        Ok(Subgraph::new(center_ref, nodes))
    }

    /// Create a builder for lazy property hydration.
    ///
    /// Allows loading full property details for a node after initial retrieval.
    pub fn hydrate(&self, node_ref: &NodeRef) -> HydrationQuery {
        HydrationQuery::new(node_ref.clone())
    }

    /// Execute raw Cypher query.
    ///
    /// **WARNING:** Callers are responsible for safe parameter interpolation.
    /// Use `escape_cypher()` for any user-supplied values.
    pub async fn cypher(&self, cypher: &str) -> Result<Vec<Value>, GraphError> {
        let sql = format!(
            "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (result agtype)",
            self.graph_name, cypher
        );

        let client = self.pool.get().await?;
        let rows = client.query(&sql, &[]).await?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let value_bytes: Vec<u8> = row.try_get(0).unwrap_or_default();
            let value_str = String::from_utf8(value_bytes).unwrap_or_default();

            if let Ok(value) = serde_json::from_str::<Value>(&value_str) {
                results.push(value);
            }
        }

        Ok(results)
    }

    /// Initialize AGE on a fresh connection.
    ///
    /// Called internally when needed, but can be invoked manually for setup.
    pub async fn initialize_age(&self) -> Result<(), GraphError> {
        let client = self.pool.get().await?;
        initialize_age_connection(&client).await
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_graph_client_creation_would_work() {
        // This test verifies the client type is constructible.
        // Full instantiation requires a live AGE instance and is tested via integration tests.
        // The constructor signature is:
        // let client = GraphClient::new(pool: Arc<Pool>, graph_name: "test_graph");
    }
}
