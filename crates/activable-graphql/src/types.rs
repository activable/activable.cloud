//! GraphQL type wrappers over activable-graph types.

use async_graphql::SimpleObject;

/// GraphQL representation of a node reference.
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlNodeRef {
    pub id: String,
    pub label: String,
}

impl From<activable_graph::types::NodeRef> for GqlNodeRef {
    fn from(n: activable_graph::types::NodeRef) -> Self {
        GqlNodeRef {
            id: n.id.to_string(),
            label: n.label,
        }
    }
}

/// GraphQL representation of a fully hydrated node.
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlNode {
    pub id: String,
    pub label: String,
    pub properties: Option<String>,
}

/// GraphQL representation of an edge in a path.
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlEdge {
    pub from: String,
    pub to: String,
    #[graphql(name = "type")]
    pub edge_type: String,
    pub properties: Option<String>,
}

/// GraphQL representation of a path through the graph.
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlPath {
    pub nodes: Vec<GqlNodeRef>,
    pub edges: Vec<GqlEdge>,
    pub length: i32,
}

impl From<activable_graph::types::Path> for GqlPath {
    fn from(p: activable_graph::types::Path) -> Self {
        let node_refs: Vec<GqlNodeRef> =
            p.nodes.into_iter().map(GqlNodeRef::from).collect();

        // Construct edges from consecutive node pairs and edge_labels
        let edges = p
            .edge_labels
            .into_iter()
            .enumerate()
            .filter_map(|(i, edge_type)| {
                if i < node_refs.len() && i + 1 < node_refs.len() {
                    Some(GqlEdge {
                        from: node_refs[i].id.clone(),
                        to: node_refs[i + 1].id.clone(),
                        edge_type,
                        properties: None,
                    })
                } else {
                    None
                }
            })
            .collect();

        let length = if node_refs.is_empty() {
            0
        } else {
            (node_refs.len() - 1) as i32
        };

        GqlPath {
            nodes: node_refs,
            edges,
            length,
        }
    }
}

/// GraphQL representation of a local subgraph.
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlSubgraph {
    pub center: GqlNodeRef,
    pub nodes: Vec<GqlNodeRef>,
}

impl From<activable_graph::types::Subgraph> for GqlSubgraph {
    fn from(sg: activable_graph::types::Subgraph) -> Self {
        GqlSubgraph {
            center: GqlNodeRef::from(sg.center),
            nodes: sg.nodes.into_iter().map(GqlNodeRef::from).collect(),
        }
    }
}

/// GraphQL representation of an ingest service status.
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlIngestService {
    pub name: String,
    pub status: String,
    pub node_count: i32,
    pub edge_count: i32,
    pub error: Option<String>,
}

/// GraphQL representation of an ingest run.
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlIngestRun {
    pub id: String,
    pub status: String,
    pub started_at: String,
    pub services: Vec<GqlIngestService>,
}
