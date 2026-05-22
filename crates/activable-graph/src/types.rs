//! Core graph types for the query API.
//!
//! Defines node references, paths, and other structures returned by graph queries.

use serde::{Deserialize, Serialize};
use std::fmt;

/// An opaque node identifier.
///
/// Wraps the AGE-internal graphid or domain ID (e.g., ARN string).
/// Callers should treat this as an opaque token.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(pub String);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for NodeId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for NodeId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Direction for traversal operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Follow outgoing edges only.
    Outgoing,
    /// Follow incoming edges only.
    Incoming,
    /// Follow both incoming and outgoing edges.
    Both,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Outgoing => f.write_str("outgoing"),
            Self::Incoming => f.write_str("incoming"),
            Self::Both => f.write_str("both"),
        }
    }
}

/// Lightweight node reference without property details.
///
/// This is the default return type for graph queries. To retrieve full
/// property details, use `client.hydrate(node_ref).execute()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRef {
    /// Unique identifier for the node.
    pub id: NodeId,
    /// Label/type of the node.
    pub label: String,
}

impl NodeRef {
    /// Create a new node reference.
    pub fn new(id: impl Into<NodeId>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
        }
    }
}

impl fmt::Display for NodeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.label, self.id)
    }
}

/// A fully hydrated node with properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// The node reference (id and label).
    pub reference: NodeRef,
    /// Property map as a JSON value.
    pub properties: serde_json::Value,
}

impl Node {
    /// Create a new node.
    pub fn new(reference: NodeRef, properties: serde_json::Value) -> Self {
        Self {
            reference,
            properties,
        }
    }
}

/// A path through the graph.
///
/// Represents a sequence of connected nodes. The edge labels between
/// consecutive nodes are stored in `edge_labels`, where `edge_labels[i]`
/// is the type of the edge from `nodes[i]` to `nodes[i+1]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Path {
    /// Sequence of nodes in the path.
    pub nodes: Vec<NodeRef>,
    /// Labels of edges between consecutive nodes.
    /// Length is `nodes.len() - 1`.
    pub edge_labels: Vec<String>,
}

impl Path {
    /// Create a new path.
    pub fn new(nodes: Vec<NodeRef>, edge_labels: Vec<String>) -> Self {
        Self { nodes, edge_labels }
    }

    /// Return the number of edges (hops) in the path.
    pub fn hop_count(&self) -> usize {
        self.edge_labels.len()
    }

    /// Check if the path contains at least two nodes.
    pub fn is_valid(&self) -> bool {
        !self.nodes.is_empty() && self.edge_labels.len() == self.nodes.len() - 1
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.nodes.is_empty() {
            return f.write_str("(empty path)");
        }

        write!(f, "{}", self.nodes[0])?;
        for (i, edge_label) in self.edge_labels.iter().enumerate() {
            if i + 1 < self.nodes.len() {
                write!(f, " -[{}]-> {}", edge_label, self.nodes[i + 1])?;
            }
        }
        Ok(())
    }
}

/// A subgraph centered around a node.
///
/// Contains the central node and all nodes within a specified radius.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subgraph {
    /// The central node.
    pub center: NodeRef,
    /// All reachable nodes (including the center).
    pub nodes: Vec<NodeRef>,
}

impl Subgraph {
    /// Create a new subgraph.
    pub fn new(center: NodeRef, nodes: Vec<NodeRef>) -> Self {
        Self { center, nodes }
    }

    /// Return the number of nodes in the subgraph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl fmt::Display for Subgraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Subgraph(center={}, nodes={})",
            self.center,
            self.node_count()
        )
    }
}

/// Builder for lazy property hydration.
///
/// Used to load full property details for a node after it has been
/// initially retrieved as a lightweight `NodeRef`.
pub struct HydrationQuery {
    /// The node reference to hydrate.
    pub node_ref: NodeRef,
    /// Optional list of property fields to retrieve.
    /// If `None`, all properties are loaded.
    pub fields: Option<Vec<String>>,
}

impl HydrationQuery {
    /// Create a new hydration query for a node reference.
    pub fn new(node_ref: NodeRef) -> Self {
        Self {
            node_ref,
            fields: None,
        }
    }

    /// Restrict hydration to specific property keys.
    pub fn fields(mut self, keys: Vec<String>) -> Self {
        self.fields = Some(keys);
        self
    }

    /// Add a single field to the hydration query.
    pub fn with_field(mut self, key: String) -> Self {
        self.fields.get_or_insert_with(Vec::new).push(key);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_creation() {
        let id = NodeId::from("principal_1");
        assert_eq!(id.0, "principal_1");
    }

    #[test]
    fn test_node_ref_creation() {
        let node = NodeRef::new("id_1", "Principal");
        assert_eq!(node.id.0, "id_1");
        assert_eq!(node.label, "Principal");
    }

    #[test]
    fn test_direction_display() {
        assert_eq!(Direction::Outgoing.to_string(), "outgoing");
        assert_eq!(Direction::Incoming.to_string(), "incoming");
        assert_eq!(Direction::Both.to_string(), "both");
    }

    #[test]
    fn test_path_hop_count() {
        let path = Path::new(
            vec![
                NodeRef::new("n1", "Principal"),
                NodeRef::new("n2", "Resource"),
                NodeRef::new("n3", "Permission"),
            ],
            vec!["CanAccess".to_string(), "HasPermission".to_string()],
        );
        assert_eq!(path.hop_count(), 2);
        assert!(path.is_valid());
    }

    #[test]
    fn test_invalid_path() {
        let path = Path::new(
            vec![NodeRef::new("n1", "Principal")],
            vec!["edge".to_string()], // Too many edge labels
        );
        assert!(!path.is_valid());
    }

    #[test]
    fn test_subgraph_node_count() {
        let center = NodeRef::new("center", "Principal");
        let subgraph = Subgraph::new(
            center.clone(),
            vec![
                center,
                NodeRef::new("n2", "Resource"),
                NodeRef::new("n3", "Permission"),
            ],
        );
        assert_eq!(subgraph.node_count(), 3);
    }

    #[test]
    fn test_hydration_query_builder() {
        let node = NodeRef::new("n1", "Principal");
        let hydration = HydrationQuery::new(node.clone())
            .with_field("name".to_string())
            .with_field("account".to_string());

        assert_eq!(hydration.node_ref.id, node.id);
        assert_eq!(hydration.fields.unwrap().len(), 2);
    }

    #[test]
    fn test_node_id_equality() {
        let id1 = NodeId::from("test");
        let id2 = NodeId::from("test");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_node_ref_display() {
        let node = NodeRef::new("id_123", "Principal");
        assert_eq!(node.to_string(), "Principal(id_123)");
    }
}
