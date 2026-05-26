//! Ingestion run telemetry: statistics and observability for ingest operations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Per-resource-type statistics during ingestion.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[allow(dead_code)] // Will be used when fully wired to ingest runtime
pub struct TypeStats {
    /// Number of resources of this type successfully ingested.
    pub success_count: u64,
    /// Number of resources of this type that failed to ingest.
    pub fail_count: u64,
}

/// Complete telemetry payload for an ingestion run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // Will be used when fully wired to ingest runtime
pub struct IngestRunStats {
    /// AWS account IDs processed in this run.
    pub account_ids: Vec<String>,
    /// Total number of nodes created or updated.
    pub node_count: u64,
    /// Total number of edges created or updated.
    pub edge_count: u64,
    /// Number of edges dropped due to missing endpoints.
    pub dropped_edges: u64,
    /// Duration of the ingest in seconds.
    pub duration_secs: f64,
    /// Per-resource-type success/fail counts.
    pub per_type: HashMap<String, TypeStats>,
    /// Relationship rules that were skipped due to errors (e.g., missing properties).
    pub skipped_rules: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ingest_run_stats_serialization() {
        // Verify that IngestRunStats serializes to valid JSON.
        // This is the critical test: ensures tokio_postgres can bind the JSON value.
        let stats = IngestRunStats {
            account_ids: vec!["123456789012".to_string(), "987654321098".to_string()],
            node_count: 1500,
            edge_count: 3200,
            dropped_edges: 42,
            duration_secs: 45.67,
            per_type: {
                let mut m = HashMap::new();
                m.insert(
                    "Principal".to_string(),
                    TypeStats {
                        success_count: 100,
                        fail_count: 0,
                    },
                );
                m.insert(
                    "Bucket".to_string(),
                    TypeStats {
                        success_count: 50,
                        fail_count: 2,
                    },
                );
                m
            },
            skipped_rules: vec!["cross_account_assume_role".to_string()],
        };

        // Serialize to JSON string
        let json_str = serde_json::to_string(&stats).expect("serialization failed");
        assert!(!json_str.is_empty());

        // Deserialize back to verify round-trip
        let deserialized: IngestRunStats =
            serde_json::from_str(&json_str).expect("deserialization failed");
        assert_eq!(deserialized.account_ids, stats.account_ids);
        assert_eq!(deserialized.node_count, 1500);
        assert_eq!(deserialized.edge_count, 3200);
        assert_eq!(deserialized.dropped_edges, 42);
        assert_eq!(deserialized.per_type.len(), 2);
        assert_eq!(deserialized.skipped_rules.len(), 1);
    }

    #[test]
    fn test_ingest_run_stats_as_json_value() {
        // Verify that IngestRunStats can be converted to serde_json::Value,
        // which is what tokio_postgres::types::Json expects.
        let stats = IngestRunStats {
            account_ids: vec!["123456789012".to_string()],
            node_count: 100,
            edge_count: 200,
            dropped_edges: 5,
            duration_secs: 10.5,
            per_type: HashMap::new(),
            skipped_rules: vec![],
        };

        // This is what the caller will do: convert to Value, wrap in Json for tokio_postgres
        let value = serde_json::to_value(&stats).expect("to_value failed");
        assert!(value.is_object());

        // Serialize the value to string (tokio_postgres::Json does this internally)
        let json_str = value.to_string();
        assert!(!json_str.is_empty());

        // Verify round-trip from Value
        let from_value: IngestRunStats =
            serde_json::from_value(value).expect("from_value failed");
        assert_eq!(from_value.node_count, 100);
    }
}
