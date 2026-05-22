//! Core graph types: nodes, edges, paths, and queries.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Opaque node identifier. Wraps AGE's graphid or domain-specific IDs (ARNs, principal IDs).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for NodeId {
    fn from(s: String) -> Self {
        NodeId(s)
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        NodeId(s.to_string())
    }
}

/// Lightweight node reference — identifier and label only, no property blobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRef {
    pub id: NodeId,
    pub label: String,
}

impl NodeRef {
    pub fn new(id: impl Into<NodeId>, label: impl Into<String>) -> Self {
        NodeRef {
            id: id.into(),
            label: label.into(),
        }
    }
}

/// Fully hydrated node with property blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub reference: NodeRef,
    pub properties: serde_json::Value,
}

impl Node {
    pub fn new(reference: NodeRef, properties: serde_json::Value) -> Self {
        Node {
            reference,
            properties,
        }
    }
}

/// Direction for edge traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Outgoing,
    Incoming,
    Both,
}

/// A path through the graph: sequence of nodes and edges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Path {
    pub nodes: Vec<NodeRef>,
    pub edge_labels: Vec<String>,
}

impl Path {
    pub fn new(nodes: Vec<NodeRef>, edge_labels: Vec<String>) -> Self {
        Path { nodes, edge_labels }
    }

    pub fn length(&self) -> usize {
        self.nodes.len().saturating_sub(1)
    }
}

/// Local subgraph: a center node and its neighbors within a radius.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subgraph {
    pub center: NodeRef,
    pub nodes: Vec<NodeRef>,
}

impl Subgraph {
    pub fn new(center: NodeRef, nodes: Vec<NodeRef>) -> Self {
        Subgraph { center, nodes }
    }
}

/// Builder for lazy property hydration.
pub struct HydrationQuery<'a> {
    client: &'a crate::client::GraphClient,
    node_ref: NodeRef,
    fields: Option<Vec<String>>,
}

impl<'a> HydrationQuery<'a> {
    pub fn new(client: &'a crate::client::GraphClient, node_ref: NodeRef) -> Self {
        HydrationQuery {
            client,
            node_ref,
            fields: None,
        }
    }

    /// Restrict hydration to specific property keys.
    pub fn fields(mut self, keys: &[&str]) -> Self {
        self.fields = Some(keys.iter().map(|s| s.to_string()).collect());
        self
    }

    /// Execute and return the fully hydrated Node.
    pub async fn execute(self) -> Result<Node, crate::error::GraphError> {
        self.client
            .hydrate_internal(self.node_ref, self.fields)
            .await
    }
}
