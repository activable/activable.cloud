//! GraphQL type wrappers over activable-graph types.

pub mod risk;

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
        let node_refs: Vec<GqlNodeRef> = p.nodes.into_iter().map(GqlNodeRef::from).collect();

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

/// GraphQL representation of a key policy statement
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlKeyPolicyStatement {
    pub effect: String,
    pub principals: Vec<String>,
    pub actions: Vec<String>,
    pub condition_keys: Vec<String>,
}

/// GraphQL representation of a key policy
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlKeyPolicy {
    pub statements: Vec<GqlKeyPolicyStatement>,
    pub policy_arn: Option<String>,
}

/// GraphQL representation of create grant risk
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlCreateGrantRisk {
    pub grantable: bool,
    pub granting_principals: Vec<String>,
    pub severity: risk::GqlSeverity,
    pub wildcard_principal: bool,
}

/// GraphQL representation of key management risks
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlKeyManagementRisks {
    pub key_arn: String,
    pub key_policy: GqlKeyPolicy,
    pub create_grant_risk: GqlCreateGrantRisk,
    pub risk_score: f64,
    pub severity: risk::GqlSeverity,
}

/// GraphQL representation of a resource policy statement
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlResourcePolicyStatement {
    pub effect: String,
    pub principal: String,
    pub condition_keys: Vec<String>,
    pub is_trust_boundary: bool,
}

/// GraphQL representation of a resource policy
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlResourcePolicy {
    pub statements: Vec<GqlResourcePolicyStatement>,
}

/// GraphQL representation of cross-account access
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlCrossAccountAccess {
    pub destination_account_id: String,
    pub principal_count: i32,
    pub severity: risk::GqlSeverity,
}

/// GraphQL representation of resource policy risks
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlResourcePolicyRisks {
    pub resource_arn: String,
    pub resource_type: String,
    pub policy: GqlResourcePolicy,
    pub cross_account_access: Vec<GqlCrossAccountAccess>,
    pub risk_score: f64,
    pub severity: risk::GqlSeverity,
    pub policy_evaluator_version: String,
}

// Re-export risk types for convenient access via `use crate::types::*;`
#[allow(unused_imports)]
pub use risk::{GqlMatchedRule, GqlRiskAssessment, GqlSeverity, GqlSignalContribution};
