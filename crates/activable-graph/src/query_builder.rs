//! Query builder for generating Cypher statements.
//!
//! Provides safe Cypher generation with automatic escaping and validation.
//! The escape functions are promoted from the spike's load_pg_age module.

use crate::error::GraphError;
use crate::types::{Direction, NodeId};

/// Escape a value for Cypher string literals.
///
/// Converts single quotes to backslash-escaped form (`\'`) and backslashes
/// to double backslashes (`\\`). This function **is not idempotent** — it must
/// be applied exactly once per value. Double-escaping will produce incorrect output.
///
/// Used to safely embed user-supplied strings in Cypher queries.
pub fn escape_cypher(s: &str) -> String {
    // Escape backslashes first, then single quotes
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Escape a value for SQL string literals containing agtype syntax.
///
/// Converts single quotes to SQL-escaped form (`''`) and backslashes to
/// double backslashes (`\\`). This function **is not idempotent** — it must
/// be applied exactly once per value.
///
/// Used to safely embed values in SQL constructs like `'\"value\"'::agtype`.
pub fn escape_sql_literal(s: &str) -> String {
    // Escape backslashes first, then single quotes (SQL standard)
    s.replace('\\', "\\\\").replace('\'', "''")
}

/// Validate that a label/identifier is a valid Cypher identifier.
///
/// Valid identifiers must start with a letter or underscore and contain
/// only alphanumeric characters and underscores.
pub fn validate_label(label: &str) -> Result<&str, GraphError> {
    if label.is_empty() {
        return Err(GraphError::invalid_label("empty label"));
    }

    let first_char = label.chars().next().unwrap();
    if !first_char.is_alphabetic() && first_char != '_' {
        return Err(GraphError::invalid_label(format!(
            "label must start with letter or underscore: {}",
            label
        )));
    }

    if !label.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(GraphError::invalid_label(format!(
            "label contains invalid characters: {}",
            label
        )));
    }

    Ok(label)
}

/// Cypher query builder.
///
/// Internal helper for constructing Cypher statements safely.
/// All user-supplied parameters are escaped before interpolation.
pub struct CypherBuilder {
    graph_name: String,
}

impl CypherBuilder {
    /// Create a new builder for the given graph.
    pub fn new(graph_name: impl Into<String>) -> Self {
        Self {
            graph_name: graph_name.into(),
        }
    }

    /// Build a query to find a node by label and ID.
    pub fn find_by_id(&self, label: &str, id: &NodeId) -> Result<String, GraphError> {
        validate_label(label)?;
        Ok(format!(
            "SELECT * FROM ag_catalog.cypher('{}', $$\
             MATCH (n:{} {{id: '{}'}}) \
             RETURN n.id, labels(n)\
             $$) AS (node_id agtype, node_labels agtype)",
            self.graph_name,
            label,
            escape_cypher(&id.0),
        ))
    }

    /// Build a query to walk edges from a starting node.
    pub fn walk_edges(
        &self,
        start: &NodeId,
        edge_types: &[&str],
        direction: Direction,
        depth_limit: u8,
    ) -> Result<String, GraphError> {
        // Validate all edge types
        for edge_type in edge_types {
            validate_label(edge_type)?;
        }

        let depth_str = if depth_limit == 1 {
            "".to_string()
        } else {
            format!("*1..{}", depth_limit)
        };

        let edge_pattern = if edge_types.is_empty() {
            format!("[{}]", depth_str)
        } else {
            let edge_spec = edge_types.join("|");
            format!("[{}:{}]", depth_str, edge_spec)
        };

        let direction_pattern = match direction {
            Direction::Outgoing => format!("-{}->(t)", edge_pattern),
            Direction::Incoming => format!("<-{}-{}", edge_pattern, "(t)"),
            Direction::Both => format!("-{}-{}", edge_pattern, "(t)"),
        };

        Ok(format!(
            "SELECT * FROM ag_catalog.cypher('{}', $$\
             MATCH (s:{{id: '{}'}}){}  \
             RETURN t.id, labels(t) LIMIT 10000\
             $$) AS (node_id agtype, node_labels agtype)",
            self.graph_name,
            escape_cypher(&start.0),
            direction_pattern,
        ))
    }

    /// Build a query to find shortest paths between two nodes.
    pub fn path_finder(
        &self,
        start: &NodeId,
        end: &NodeId,
        edge_pattern: &[&str],
        max_hops: u8,
    ) -> Result<String, GraphError> {
        // Validate all edge types
        for edge_type in edge_pattern {
            validate_label(edge_type)?;
        }

        let edge_spec = if edge_pattern.is_empty() {
            "*1..8".to_string()
        } else {
            let labels = edge_pattern.join("|");
            format!("[*1..{}:{}]", max_hops, labels)
        };

        Ok(format!(
            "SELECT * FROM ag_catalog.cypher('{}', $$\
             MATCH p = (s:{{id: '{}'}})-{}-(e:{{id: '{}'}}) \
             RETURN [n IN nodes(p) | {{id: n.id, labels: labels(n)}}] AS path_nodes\
             $$) AS (path_nodes agtype)",
            self.graph_name,
            escape_cypher(&start.0),
            edge_spec,
            escape_cypher(&end.0),
        ))
    }

    /// Build a query to find the shortest path length between two nodes.
    pub fn shortest_path_length(
        &self,
        start: &NodeId,
        end: &NodeId,
        max_hops: u8,
    ) -> Result<String, GraphError> {
        Ok(format!(
            "SELECT * FROM ag_catalog.cypher('{}', $$\
             MATCH p = (s:{{id: '{}'}})-[*1..{}]-(e:{{id: '{}'}}) \
             RETURN length(p) AS path_length \
             LIMIT 1\
             $$) AS (path_length agtype)",
            self.graph_name,
            escape_cypher(&start.0),
            max_hops,
            escape_cypher(&end.0),
        ))
    }

    /// Build a query to find all nodes within a blast radius.
    pub fn blast_radius(
        &self,
        node: &NodeId,
        edge_types: &[&str],
        max_hops: u8,
    ) -> Result<String, GraphError> {
        // Validate all edge types
        for edge_type in edge_types {
            validate_label(edge_type)?;
        }

        let edge_pattern = if edge_types.is_empty() {
            format!("[*1..{}]", max_hops)
        } else {
            let labels = edge_types.join("|");
            format!("[*1..{}:{}]", max_hops, labels)
        };

        Ok(format!(
            "SELECT * FROM ag_catalog.cypher('{}', $$\
             MATCH (center:{{id: '{}'}}){}(reachable) \
             RETURN reachable.id, labels(reachable) \
             LIMIT 10000\
             $$) AS (node_id agtype, node_labels agtype)",
            self.graph_name,
            escape_cypher(&node.0),
            edge_pattern,
        ))
    }

    /// Build a query to retrieve a local subgraph.
    pub fn subgraph(&self, center: &NodeId, radius: u8) -> Result<String, GraphError> {
        Ok(format!(
            "SELECT * FROM ag_catalog.cypher('{}', $$\
             MATCH (center:{{id: '{}'}}) \
             MATCH (center)-[*1..{}]-(nearby) \
             RETURN nearby.id, labels(nearby) \
             LIMIT 10000\
             $$) AS (node_id agtype, node_labels agtype)",
            self.graph_name,
            escape_cypher(&center.0),
            radius,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── escape_cypher() ───────────────────────────────────────────────

    #[test]
    fn escape_cypher_empty() {
        assert_eq!(escape_cypher(""), "");
    }

    #[test]
    fn escape_cypher_plain() {
        assert_eq!(escape_cypher("hello_world"), "hello_world");
    }

    #[test]
    fn escape_cypher_single_quote() {
        assert_eq!(escape_cypher("it's"), "it\\'s");
    }

    #[test]
    fn escape_cypher_backslash() {
        assert_eq!(escape_cypher("a\\b"), "a\\\\b");
    }

    #[test]
    fn escape_cypher_both_quote_types() {
        let input = "it's a \"test\"";
        let result = escape_cypher(input);
        assert_eq!(result, "it\\'s a \"test\"");
    }

    #[test]
    fn escape_cypher_sql_injection_canary() {
        let payload = "principal_1' OR '1'='1";
        let result = escape_cypher(payload);
        assert!(!result.contains("' OR '"));
        assert_eq!(result, "principal_1\\' OR \\'1\\'=\\'1");
    }

    #[test]
    fn escape_cypher_drop_table_canary() {
        let payload = "'; DROP TABLE x; --";
        let result = escape_cypher(payload);
        assert!(result.starts_with("\\'"));
    }

    #[test]
    fn escape_cypher_unicode() {
        assert_eq!(escape_cypher("日本語"), "日本語");
        assert_eq!(escape_cypher("🔥"), "🔥");
    }

    #[test]
    fn escape_cypher_very_long_input() {
        let long = "a".repeat(10_001);
        let result = escape_cypher(&long);
        assert_eq!(result.len(), 10_001);
    }

    #[test]
    fn escape_cypher_very_long_with_quotes() {
        let long = "'".repeat(10_001);
        let result = escape_cypher(&long);
        assert_eq!(result.len(), 20_002);
    }

    // ── escape_sql_literal() ───────────────────────────────────────────

    #[test]
    fn escape_sql_literal_empty() {
        assert_eq!(escape_sql_literal(""), "");
    }

    #[test]
    fn escape_sql_literal_plain() {
        assert_eq!(escape_sql_literal("principal_42"), "principal_42");
    }

    #[test]
    fn escape_sql_literal_single_quote() {
        assert_eq!(escape_sql_literal("it's"), "it''s");
    }

    #[test]
    fn escape_sql_literal_backslash() {
        assert_eq!(escape_sql_literal("a\\b"), "a\\\\b");
    }

    #[test]
    fn escape_sql_literal_both() {
        let input = "it's a \"test\"";
        let result = escape_sql_literal(input);
        assert_eq!(result, "it''s a \"test\"");
    }

    #[test]
    fn escape_sql_literal_unicode() {
        assert_eq!(escape_sql_literal("日本語"), "日本語");
    }

    #[test]
    fn escape_sql_literal_very_long_quotes() {
        let long = "'".repeat(10_001);
        let result = escape_sql_literal(&long);
        assert_eq!(result.len(), 20_002);
    }

    // ── validate_label() ──────────────────────────────────────────────

    #[test]
    fn validate_label_simple() {
        assert!(validate_label("Principal").is_ok());
    }

    #[test]
    fn validate_label_with_underscore() {
        assert!(validate_label("_private").is_ok());
    }

    #[test]
    fn validate_label_with_numbers() {
        assert!(validate_label("Type123").is_ok());
    }

    #[test]
    fn validate_label_starts_with_number() {
        assert!(validate_label("123Invalid").is_err());
    }

    #[test]
    fn validate_label_with_dash() {
        assert!(validate_label("Invalid-Label").is_err());
    }

    #[test]
    fn validate_label_empty() {
        assert!(validate_label("").is_err());
    }

    #[test]
    fn validate_label_with_space() {
        assert!(validate_label("Invalid Label").is_err());
    }

    // ── CypherBuilder ──────────────────────────────────────────────────

    #[test]
    fn builder_find_by_id() {
        let builder = CypherBuilder::new("aws_graph");
        let result = builder.find_by_id("Principal", &NodeId::from("p1"));
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("aws_graph"));
        assert!(cypher.contains("Principal"));
    }

    #[test]
    fn builder_find_by_id_with_quote_in_id() {
        let builder = CypherBuilder::new("graph");
        let result = builder.find_by_id("Principal", &NodeId::from("p'1"));
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("\\'"));
    }

    #[test]
    fn builder_walk_edges() {
        let builder = CypherBuilder::new("graph");
        let result =
            builder.walk_edges(&NodeId::from("n1"), &["CanAccess"], Direction::Outgoing, 1);
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("CanAccess"));
    }

    #[test]
    fn builder_walk_edges_multi_hop() {
        let builder = CypherBuilder::new("graph");
        let result = builder.walk_edges(&NodeId::from("n1"), &[], Direction::Both, 3);
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("*1..3"));
    }

    #[test]
    fn builder_path_finder() {
        let builder = CypherBuilder::new("graph");
        let result = builder.path_finder(
            &NodeId::from("start"),
            &NodeId::from("end"),
            &["CanAccess", "HasPermission"],
            8,
        );
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("CanAccess|HasPermission"));
    }

    #[test]
    fn builder_shortest_path_length() {
        let builder = CypherBuilder::new("graph");
        let result = builder.shortest_path_length(&NodeId::from("a"), &NodeId::from("b"), 6);
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("length(p)"));
    }

    #[test]
    fn builder_blast_radius() {
        let builder = CypherBuilder::new("graph");
        let result = builder.blast_radius(&NodeId::from("center"), &["CanAccess"], 2);
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("CanAccess"));
    }

    #[test]
    fn builder_subgraph() {
        let builder = CypherBuilder::new("graph");
        let result = builder.subgraph(&NodeId::from("center"), 2);
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("center"));
    }

    #[test]
    fn builder_invalid_label() {
        let builder = CypherBuilder::new("graph");
        assert!(builder
            .find_by_id("123Invalid", &NodeId::from("id"))
            .is_err());
    }
}
