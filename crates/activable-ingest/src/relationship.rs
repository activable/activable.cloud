//! Declarative relationship inference engine.
//!
//! Loads relationship rules from YAML and applies them post-ingest,
//! creating edges between nodes by matching properties.
//!
//! Rules use Cypher MERGE queries pushed to the graph database for
//! O(n log n) performance via indexes, not O(n²) in-memory joins.

use crate::error::IngestError;
use deadpool_postgres::Pool;
use serde::Deserialize;
use std::sync::Arc;

const RELATIONSHIPS_YAML: &str = include_str!("config/relationships.yaml");

/// A single relationship rule from the YAML config.
#[derive(Debug, Clone, Deserialize)]
pub struct RelationshipRule {
    /// Human-readable name for the rule.
    pub name: String,
    /// Source node label (e.g., "Resource", "Lambda").
    pub from_label: String,
    /// Target node label (e.g., "SecurityGroup", "Principal").
    pub to_label: String,
    /// Edge type to create (e.g., "HasSecurityGroup", "AssumedBy").
    pub edge_type: String,
    /// Property on the source node to match (e.g., "security_group_id").
    pub from_property: String,
    /// Property on the target node to match against (e.g., "id").
    pub to_property: String,
}

/// Statistics for a single relationship rule execution.
#[derive(Debug, Clone, Default)]
pub struct RelationshipStats {
    pub rule_name: String,
    pub edges_created: u32,
}

/// Complete relationship config loaded from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct RelationshipConfig {
    pub relationships: Vec<RelationshipRule>,
}

/// Load and parse the embedded relationships.yaml config.
pub fn load_relationship_config() -> Result<RelationshipConfig, IngestError> {
    serde_yaml::from_str(RELATIONSHIPS_YAML).map_err(|e| IngestError::YamlParse(e.to_string()))
}

/// Execute all relationship rules against the graph.
///
/// Each rule generates a Cypher MERGE query that is pushed to the database
/// for execution. This keeps matching logic in the database (O(n log n) via indexes)
/// rather than in application code (which would be O(n²)).
///
/// If a rule fails, it is logged and skipped; other rules continue.
pub async fn apply_relationships(
    pool: &Arc<Pool>,
    graph_name: &str,
) -> Result<Vec<RelationshipStats>, IngestError> {
    let config = load_relationship_config()?;
    let mut stats = Vec::new();

    let conn = pool
        .get()
        .await
        .map_err(|e| IngestError::Graph(format!("pool error: {}", e)))?;

    // Initialize AGE on this connection.
    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .map_err(|e| IngestError::Graph(format!("AGE init error: {}", e)))?;

    for rule in &config.relationships {
        match apply_single_rule(&conn, graph_name, rule).await {
            Ok(count) => {
                tracing::info!(
                    rule = %rule.name,
                    edge_type = %rule.edge_type,
                    edges = count,
                    "relationship rule applied"
                );
                stats.push(RelationshipStats {
                    rule_name: rule.name.clone(),
                    edges_created: count,
                });
            }
            Err(e) => {
                tracing::warn!(
                    rule = %rule.name,
                    error = %e,
                    "relationship rule failed, skipping"
                );
                stats.push(RelationshipStats {
                    rule_name: rule.name.clone(),
                    edges_created: 0,
                });
            }
        }
    }

    Ok(stats)
}

/// Build a Cypher MERGE query for a relationship rule.
///
/// Constructs a SQL/Cypher statement that pushes the join to the database
/// for O(n log n) execution via indexes. Each clause (MATCH, WHERE, MERGE,
/// RETURN) is properly space-separated to avoid token fusion.
fn build_relationship_cypher(graph_name: &str, rule: &RelationshipRule) -> String {
    format!(
        "SELECT * FROM cypher('{}', $$MATCH (f:{} ), (t:{} ) WHERE f.{} = t.{} MERGE (f)-[:{}]->(t) RETURN count(*) as edge_count$$) AS (edge_count agtype)",
        graph_name,
        rule.from_label,
        rule.to_label,
        rule.from_property,
        rule.to_property,
        rule.edge_type,
    )
}

/// Apply a single relationship rule by executing a Cypher MERGE query.
///
/// The query pushes the join to the database, leveraging indexes for efficiency.
async fn apply_single_rule(
    conn: &deadpool_postgres::Object,
    graph_name: &str,
    rule: &RelationshipRule,
) -> Result<u32, IngestError> {
    // Validate property names are alphanumeric + underscore only.
    // YAML is trusted (compile-time constant), but validate anyway.
    validate_property_name(&rule.from_property)?;
    validate_property_name(&rule.to_property)?;
    validate_property_name(&rule.edge_type)?;
    validate_property_name(&rule.from_label)?;
    validate_property_name(&rule.to_label)?;

    // Build Cypher MERGE query that pushes the join to the database.
    // This is O(n log n) via DB indexes, not O(n²) in application code.
    let cypher = build_relationship_cypher(graph_name, rule);

    let rows = conn
        .query(&cypher, &[])
        .await
        .map_err(|e| IngestError::Graph(format!("relationship query failed: {}", e)))?;

    // Extract count from AGE agtype result.
    // AGE returns agtype values as strings; parse the count.
    let count = if rows.is_empty() {
        0u32
    } else {
        let raw: String = rows[0]
            .try_get(0)
            .map_err(|e| IngestError::Graph(format!("parse agtype failed: {}", e)))?;

        // AGE agtype for integers serializes as bare numbers.
        raw.trim().parse::<u32>().unwrap_or_else(|_| {
            tracing::warn!(raw_value = %raw, "failed to parse AGE count, defaulting to 0");
            0u32
        })
    };

    Ok(count)
}

/// Validate that a property name is safe for use in Cypher.
/// Only alphanumeric and underscore are allowed.
fn validate_property_name(name: &str) -> Result<(), IngestError> {
    if name.is_empty() {
        return Err(IngestError::Config(
            "property name cannot be empty".to_string(),
        ));
    }

    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(IngestError::Config(format!(
            "property name '{}' contains invalid characters (only alphanumeric + underscore allowed)",
            name
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_relationship_config() {
        let config = load_relationship_config().expect("failed to load config");
        assert!(
            !config.relationships.is_empty(),
            "relationship config should not be empty"
        );
    }

    #[test]
    fn test_relationship_config_has_required_rules() {
        let config = load_relationship_config().expect("failed to load config");
        let names: Vec<_> = config
            .relationships
            .iter()
            .map(|r| r.name.as_str())
            .collect();

        // Verify we have the three expected rules.
        assert!(
            names.contains(&"lambda-execution-role"),
            "should have lambda-execution-role rule"
        );
        assert!(
            names.contains(&"instance-vpc"),
            "should have instance-vpc rule"
        );
        assert!(
            names.contains(&"instance-security-group"),
            "should have instance-security-group rule"
        );
    }

    #[test]
    fn test_relationship_rule_structure() {
        let config = load_relationship_config().expect("failed to load config");
        let rule = config
            .relationships
            .iter()
            .find(|r| r.name == "instance-vpc")
            .expect("instance-vpc rule should exist");

        assert_eq!(rule.from_label, "Resource");
        assert_eq!(rule.to_label, "Vpc");
        assert_eq!(rule.edge_type, "InVpc");
        assert!(!rule.from_property.is_empty());
        assert!(!rule.to_property.is_empty());
    }

    #[test]
    fn test_validate_property_name_valid() {
        assert!(validate_property_name("security_group_id").is_ok());
        assert!(validate_property_name("vpc_id").is_ok());
        assert!(validate_property_name("id").is_ok());
        assert!(validate_property_name("role_arn").is_ok());
        assert!(validate_property_name("_private_prop").is_ok());
        assert!(validate_property_name("prop123").is_ok());
    }

    #[test]
    fn test_validate_property_name_invalid() {
        assert!(validate_property_name("").is_err());
        assert!(validate_property_name("prop-name").is_err());
        assert!(validate_property_name("prop.name").is_err());
        assert!(validate_property_name("prop[0]").is_err());
        assert!(validate_property_name("prop name").is_err());
    }

    #[test]
    fn test_build_relationship_cypher_whitespace_correctness() {
        // Test that Cypher string does not have fused tokens from backslash
        // line continuations. Each clause must be properly space-separated.
        let rule = RelationshipRule {
            name: "test-rule".to_string(),
            from_label: "Resource".to_string(),
            to_label: "Principal".to_string(),
            edge_type: "AssumedBy".to_string(),
            from_property: "role_arn".to_string(),
            to_property: "id".to_string(),
        };

        let cypher = build_relationship_cypher("test_graph", &rule);

        // Assert that problematic token fusions DO NOT exist.
        // These are the specific bugs from the backslash-continuation issue.
        assert!(
            !cypher.contains(")WHERE"),
            "cypher must not have fused ')WHERE' token"
        );
        assert!(
            !cypher.contains("t.idMERGE"),
            "cypher must not have fused 't.idMERGE' token"
        );
        assert!(
            !cypher.contains(")MERGE"),
            "cypher must not have fused ')MERGE' token"
        );
        assert!(
            !cypher.contains(")RETURN"),
            "cypher must not have fused ')RETURN' token"
        );

        // Assert that proper spacing and clause order exist.
        assert!(
            cypher.contains("WHERE f.role_arn = t.id"),
            "cypher must contain properly-spaced WHERE clause"
        );
        assert!(
            cypher.contains("MERGE (f)-[:AssumedBy]->(t)"),
            "cypher must contain properly-spaced MERGE clause with edge type"
        );
        assert!(
            cypher.contains("RETURN count(*) as edge_count"),
            "cypher must contain properly-spaced RETURN clause"
        );

        // Verify the clauses appear in correct order.
        let match_pos = cypher.find("MATCH").expect("MATCH must be present");
        let where_pos = cypher.find("WHERE").expect("WHERE must be present");
        let merge_pos = cypher.find("MERGE").expect("MERGE must be present");
        let return_pos = cypher.find("RETURN").expect("RETURN must be present");

        assert!(
            match_pos < where_pos && where_pos < merge_pos && merge_pos < return_pos,
            "clauses must appear in order: MATCH, WHERE, MERGE, RETURN"
        );
    }
}
