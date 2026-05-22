//! Cypher query template builder and string escaping functions.

use crate::error::GraphError;
use crate::types::{Direction, NodeId};

/// Escape single quotes in Cypher string literals.
///
/// **NOT idempotent** — call exactly once per value. Double-escape produces double-escaped output.
/// Callers must ensure each value flows through this function exactly once.
pub fn escape_cypher(s: &str) -> String {
    debug_assert!(
        !s.contains("\\'"),
        "escape_cypher called with input containing \\' — possible double-escape; input was: {s:?}"
    );
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Escape a value for embedding inside an agtype string literal in SQL.
///
/// **NOT idempotent** — call exactly once per value. Double-escape produces double-escaped output.
/// Callers must ensure each value flows through this function exactly once.
pub fn escape_sql_literal(s: &str) -> String {
    debug_assert!(
        !s.contains("''"),
        "escape_sql_literal called with input containing '' — possible double-escape; input was: {s:?}"
    );
    s.replace('\\', "\\\\").replace('\'', "''")
}

/// Validate a label string against the allowed pattern: [A-Za-z][A-Za-z0-9_]*
pub fn validate_label(label: &str) -> Result<&str, GraphError> {
    if label.is_empty() {
        return Err(GraphError::UnsafeParameter("empty label".to_string()));
    }

    let first = label.chars().next().unwrap();
    if !first.is_ascii_alphabetic() {
        return Err(GraphError::UnsafeParameter(
            format!("label must start with a letter: {}", label),
        ));
    }

    for c in label.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' {
            return Err(GraphError::UnsafeParameter(
                format!("label contains invalid character '{}': {}", c, label),
            ));
        }
    }

    Ok(label)
}

/// Internal query builder for Cypher templates.
pub(crate) struct CypherBuilder {
    graph_name: String,
}

impl CypherBuilder {
    pub fn new(graph_name: impl Into<String>) -> Self {
        CypherBuilder {
            graph_name: graph_name.into(),
        }
    }

    pub fn find_by_id(&self, label: &str, id: &NodeId) -> Result<String, GraphError> {
        validate_label(label)?;
        let escaped_id = escape_cypher(id.as_str());
        Ok(format!(
            "SELECT * FROM ag_catalog.cypher('{}', $$MATCH (n:{} {{id: '{}'}}) RETURN n.id, labels(n)$$) AS (node_id agtype, node_labels agtype)",
            self.graph_name, label, escaped_id
        ))
    }

    pub fn walk_edges(
        &self,
        start: &NodeId,
        edge_types: &[&str],
        direction: Direction,
        depth_limit: u8,
    ) -> Result<String, GraphError> {
        let escaped_start = escape_cypher(start.as_str());
        let rel_pattern = if edge_types.is_empty() {
            "[r]".to_string()
        } else {
            let labels: Vec<String> = edge_types
                .iter()
                .map(|et| {
                    validate_label(et).unwrap_or(et).to_string()
                })
                .collect();
            format!("[r:{}]", labels.join("|"))
        };

        let (arrow_left, arrow_right) = match direction {
            Direction::Outgoing => ("", "->"),
            Direction::Incoming => ("<-", ""),
            Direction::Both => ("", "-"),
        };

        let cypher = format!(
            "MATCH (s {{id: '{}'}}) {}{}{} (t) RETURN t.id, labels(t) LIMIT {}",
            escaped_start, arrow_left, rel_pattern, arrow_right, depth_limit
        );

        Ok(format!(
            "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (node_id agtype, node_labels agtype)",
            self.graph_name, cypher
        ))
    }

    pub fn path_finder(
        &self,
        start: &NodeId,
        end: &NodeId,
        edge_pattern: &[&str],
        max_hops: u8,
    ) -> Result<String, GraphError> {
        let escaped_start = escape_cypher(start.as_str());
        let escaped_end = escape_cypher(end.as_str());

        let rel_pattern = if edge_pattern.is_empty() {
            format!("[*1..{}]", max_hops)
        } else {
            let labels: Vec<String> = edge_pattern
                .iter()
                .map(|et| validate_label(et).unwrap_or(et).to_string())
                .collect();
            format!("[{}*1..{}]", labels.join("|"), max_hops)
        };

        let cypher = format!(
            "MATCH path = (s {{id: '{}'}}) {}(t {{id: '{}'}}) RETURN [n IN nodes(path) | {{id: n.id, label: labels(n)}}]",
            escaped_start, rel_pattern, escaped_end
        );

        Ok(format!(
            "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (path agtype)",
            self.graph_name, cypher
        ))
    }

    pub fn shortest_path_length(
        &self,
        start: &NodeId,
        end: &NodeId,
        max_hops: u8,
    ) -> Result<String, GraphError> {
        let escaped_start = escape_cypher(start.as_str());
        let escaped_end = escape_cypher(end.as_str());

        let cypher = format!(
            "MATCH path = (s {{id: '{}'}}) [*1..{}] (t {{id: '{}'}}) RETURN length(path) ORDER BY length(path) LIMIT 1",
            escaped_start, max_hops, escaped_end
        );

        Ok(format!(
            "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (path_length agtype)",
            self.graph_name, cypher
        ))
    }

    pub fn blast_radius(
        &self,
        node: &NodeId,
        edge_types: &[&str],
        max_hops: u8,
    ) -> Result<String, GraphError> {
        let escaped_node = escape_cypher(node.as_str());

        let rel_pattern = if edge_types.is_empty() {
            format!("[*1..{}]", max_hops)
        } else {
            let labels: Vec<String> = edge_types
                .iter()
                .map(|et| validate_label(et).unwrap_or(et).to_string())
                .collect();
            format!("[{}*1..{}]", labels.join("|"), max_hops)
        };

        let cypher = format!(
            "MATCH (c {{id: '{}'}}) {} (neighbor) RETURN neighbor.id, labels(neighbor) LIMIT 100",
            escaped_node, rel_pattern
        );

        Ok(format!(
            "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (node_id agtype, node_labels agtype)",
            self.graph_name, cypher
        ))
    }

    pub fn subgraph(&self, center: &NodeId, radius: u8) -> Result<String, GraphError> {
        let escaped_center = escape_cypher(center.as_str());

        let cypher = format!(
            "MATCH (c {{id: '{}'}}) [*1..{}] (neighbor) RETURN neighbor.id, labels(neighbor) LIMIT 100",
            escaped_center, radius
        );

        Ok(format!(
            "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (node_id agtype, node_labels agtype)",
            self.graph_name, cypher
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── escape_cypher tests ────────────────────────────────────────────────

    #[test]
    fn escape_cypher_empty() {
        assert_eq!(escape_cypher(""), "");
    }

    #[test]
    fn escape_cypher_plain_ascii() {
        assert_eq!(escape_cypher("hello_world"), "hello_world");
    }

    #[test]
    fn escape_cypher_single_quote() {
        assert_eq!(escape_cypher("it's"), "it\\'s");
    }

    #[test]
    fn escape_cypher_double_quote() {
        assert_eq!(escape_cypher(r#"he said "hi""#), r#"he said "hi""#);
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
    fn escape_cypher_null_byte() {
        let input = "ab\0cd";
        let result = escape_cypher(input);
        assert_eq!(result, "ab\0cd");
    }

    #[test]
    fn escape_cypher_whitespace() {
        let input = "line1\nline2\r\ntab\there";
        let result = escape_cypher(input);
        assert_eq!(result, input);
    }

    #[test]
    fn escape_cypher_unicode_nfc() {
        assert_eq!(escape_cypher("café"), "café");
    }

    #[test]
    fn escape_cypher_unicode_nfd() {
        let nfd = "cafe\u{0301}";
        assert_eq!(escape_cypher(nfd), nfd);
    }

    #[test]
    fn escape_cypher_japanese() {
        assert_eq!(escape_cypher("日本語"), "日本語");
    }

    #[test]
    fn escape_cypher_emoji() {
        assert_eq!(escape_cypher("🔥"), "🔥");
    }

    #[test]
    fn escape_cypher_rtl_override() {
        let input = "normal\u{202E}reversed";
        let result = escape_cypher(input);
        assert_eq!(result, input);
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
        assert!(result.starts_with("\\'"), "Leading quote must be escaped: {}", result);
        for (i, c) in result.char_indices() {
            if c == '\'' {
                assert!(
                    i > 0 && result.as_bytes()[i - 1] == b'\\',
                    "Unescaped single-quote at index {}: {}",
                    i, result
                );
            }
        }
    }

    #[test]
    fn escape_cypher_cypher_injection_canary() {
        let payload = "} RETURN 1 {";
        let result = escape_cypher(payload);
        assert_eq!(result, payload);
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

    // ── escape_sql_literal tests ───────────────────────────────────────────

    #[test]
    fn escape_sql_literal_empty() {
        assert_eq!(escape_sql_literal(""), "");
    }

    #[test]
    fn escape_sql_literal_plain_ascii() {
        assert_eq!(escape_sql_literal("principal_42"), "principal_42");
    }

    #[test]
    fn escape_sql_literal_single_quote() {
        assert_eq!(escape_sql_literal("it's"), "it''s");
    }

    #[test]
    fn escape_sql_literal_double_quote() {
        assert_eq!(escape_sql_literal(r#"he said "hi""#), r#"he said "hi""#);
    }

    #[test]
    fn escape_sql_literal_backslash() {
        assert_eq!(escape_sql_literal("a\\b"), "a\\\\b");
    }

    #[test]
    fn escape_sql_literal_both_quote_types() {
        let input = "it's a \"test\"";
        let result = escape_sql_literal(input);
        assert_eq!(result, "it''s a \"test\"");
    }

    #[test]
    fn escape_sql_literal_null_byte() {
        let input = "ab\0cd";
        let result = escape_sql_literal(input);
        assert_eq!(result, "ab\0cd");
    }

    #[test]
    fn escape_sql_literal_whitespace() {
        let input = "line1\nline2\r\ntab\there";
        assert_eq!(escape_sql_literal(input), input);
    }

    #[test]
    fn escape_sql_literal_unicode_nfc() {
        assert_eq!(escape_sql_literal("café"), "café");
    }

    #[test]
    fn escape_sql_literal_unicode_nfd() {
        let nfd = "cafe\u{0301}";
        assert_eq!(escape_sql_literal(nfd), nfd);
    }

    #[test]
    fn escape_sql_literal_japanese() {
        assert_eq!(escape_sql_literal("日本語"), "日本語");
    }

    #[test]
    fn escape_sql_literal_emoji() {
        assert_eq!(escape_sql_literal("🔥"), "🔥");
    }

    #[test]
    fn escape_sql_literal_rtl_override() {
        let input = "normal\u{202E}reversed";
        assert_eq!(escape_sql_literal(input), input);
    }

    #[test]
    fn escape_sql_literal_sql_injection_canary() {
        let payload = "principal_1' OR '1'='1";
        let result = escape_sql_literal(payload);
        assert_eq!(result, "principal_1'' OR ''1''=''1");
        let bytes = result.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\'' {
                assert!(
                    i + 1 < bytes.len() && bytes[i + 1] == b'\'',
                    "Unescaped single-quote at index {}: {}",
                    i, result
                );
                i += 2;
            } else {
                i += 1;
            }
        }
    }

    #[test]
    fn escape_sql_literal_drop_table_canary() {
        let payload = "'; DROP TABLE x; --";
        let result = escape_sql_literal(payload);
        assert!(result.starts_with("''"), "Leading quote must be doubled: {}", result);
        let bytes = result.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\'' {
                assert!(
                    i + 1 < bytes.len() && bytes[i + 1] == b'\'',
                    "Unescaped single-quote at index {}: {}",
                    i, result
                );
                i += 2;
            } else {
                i += 1;
            }
        }
    }

    #[test]
    fn escape_sql_literal_cypher_injection_canary() {
        let payload = "} RETURN 1 {";
        let result = escape_sql_literal(payload);
        assert_eq!(result, payload);
    }

    #[test]
    fn escape_sql_literal_very_long_input() {
        let long = "x".repeat(10_001);
        let result = escape_sql_literal(&long);
        assert_eq!(result.len(), 10_001);
    }

    #[test]
    fn escape_sql_literal_many_non_quotes() {
        // Test with many non-quote characters to ensure no blowup in processing.
        let long = "x".repeat(100);
        let result = escape_sql_literal(&long);
        assert_eq!(result.len(), 100);
    }

    // ── validate_label tests ───────────────────────────────────────────────

    #[test]
    fn validate_label_empty() {
        assert!(validate_label("").is_err());
    }

    #[test]
    fn validate_label_valid_simple() {
        assert_eq!(validate_label("Principal").unwrap(), "Principal");
    }

    #[test]
    fn validate_label_valid_with_underscore() {
        assert_eq!(validate_label("My_Label").unwrap(), "My_Label");
    }

    #[test]
    fn validate_label_valid_all_numeric() {
        assert_eq!(validate_label("Label123").unwrap(), "Label123");
    }

    #[test]
    fn validate_label_starts_with_digit() {
        assert!(validate_label("123Label").is_err());
    }

    #[test]
    fn validate_label_starts_with_special() {
        assert!(validate_label("_Label").is_err());
    }

    #[test]
    fn validate_label_contains_dash() {
        assert!(validate_label("Label-Name").is_err());
    }

    #[test]
    fn validate_label_contains_space() {
        assert!(validate_label("Label Name").is_err());
    }

    #[test]
    fn validate_label_unicode() {
        assert!(validate_label("Café").is_err());
    }

    // ── CypherBuilder tests ────────────────────────────────────────────────

    #[test]
    fn builder_find_by_id_valid() {
        let builder = CypherBuilder::new("test_graph");
        let id = NodeId::from("principal_1");
        let sql = builder.find_by_id("Principal", &id).unwrap();
        assert!(sql.contains("Principal"));
        assert!(sql.contains("principal_1"));
        assert!(sql.contains("test_graph"));
    }

    #[test]
    fn builder_find_by_id_escapes_quote() {
        let builder = CypherBuilder::new("test_graph");
        let id = NodeId::from("principal'1");
        let sql = builder.find_by_id("Principal", &id).unwrap();
        assert!(sql.contains("principal\\'1"));
    }

    #[test]
    fn builder_find_by_id_invalid_label() {
        let builder = CypherBuilder::new("test_graph");
        let id = NodeId::from("principal_1");
        let result = builder.find_by_id("123Invalid", &id);
        assert!(result.is_err());
    }

    #[test]
    fn builder_walk_edges_empty_edge_types() {
        let builder = CypherBuilder::new("test_graph");
        let id = NodeId::from("principal_1");
        let sql = builder
            .walk_edges(&id, &[], Direction::Outgoing, 1)
            .unwrap();
        assert!(sql.contains("[r]"));
    }

    #[test]
    fn builder_walk_edges_with_edge_types() {
        let builder = CypherBuilder::new("test_graph");
        let id = NodeId::from("principal_1");
        let sql = builder
            .walk_edges(&id, &["HasPermission"], Direction::Outgoing, 1)
            .unwrap();
        assert!(sql.contains("[r:HasPermission]"));
    }

    #[test]
    fn builder_walk_edges_direction_outgoing() {
        let builder = CypherBuilder::new("test_graph");
        let id = NodeId::from("principal_1");
        let sql = builder
            .walk_edges(&id, &[], Direction::Outgoing, 1)
            .unwrap();
        assert!(sql.contains("->"));
    }

    #[test]
    fn builder_walk_edges_direction_incoming() {
        let builder = CypherBuilder::new("test_graph");
        let id = NodeId::from("principal_1");
        let sql = builder
            .walk_edges(&id, &[], Direction::Incoming, 1)
            .unwrap();
        assert!(sql.contains("<-"));
    }

    #[test]
    fn builder_walk_edges_direction_both() {
        let builder = CypherBuilder::new("test_graph");
        let id = NodeId::from("principal_1");
        let sql = builder
            .walk_edges(&id, &[], Direction::Both, 1)
            .unwrap();
        assert!(!sql.contains("->"));
        assert!(!sql.contains("<-"));
    }

    #[test]
    fn builder_path_finder_valid() {
        let builder = CypherBuilder::new("test_graph");
        let start = NodeId::from("a");
        let end = NodeId::from("b");
        let sql = builder
            .path_finder(&start, &end, &["HasPermission"], 5)
            .unwrap();
        assert!(sql.contains("HasPermission*1..5"));
    }

    #[test]
    fn builder_shortest_path_length_valid() {
        let builder = CypherBuilder::new("test_graph");
        let start = NodeId::from("a");
        let end = NodeId::from("b");
        let sql = builder.shortest_path_length(&start, &end, 8).unwrap();
        assert!(sql.contains("length(path)"));
    }

    #[test]
    fn builder_blast_radius_valid() {
        let builder = CypherBuilder::new("test_graph");
        let node = NodeId::from("principal_1");
        let sql = builder.blast_radius(&node, &[], 3).unwrap();
        assert!(sql.contains("[*1..3]"));
    }

    #[test]
    fn builder_subgraph_valid() {
        let builder = CypherBuilder::new("test_graph");
        let center = NodeId::from("principal_1");
        let sql = builder.subgraph(&center, 2).unwrap();
        assert!(sql.contains("[*1..2]"));
    }
}
