use std::env;

/// Configuration for the ingestion runtime.
pub struct IngestConfig {
    pub graph_name: String,
    pub concurrency_limit: usize,
    pub batch_size: usize,
}

impl IngestConfig {
    /// Load configuration from environment variables.
    ///
    /// Environment variables:
    /// - `ACTIVABLE_GRAPH_NAME`: Graph name in PostgreSQL+AGE (default: "cloud")
    /// - `ACTIVABLE_INGEST_CONCURRENCY`: Parallel resource types to ingest (default: 10)
    /// - `ACTIVABLE_INGEST_BATCH_SIZE`: Nodes per graph write batch (default: 100)
    pub fn from_env() -> Self {
        Self {
            graph_name: env::var("ACTIVABLE_GRAPH_NAME").unwrap_or_else(|_| "cloud".to_string()),
            concurrency_limit: env::var("ACTIVABLE_INGEST_CONCURRENCY")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            batch_size: env::var("ACTIVABLE_INGEST_BATCH_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
        }
    }

    /// Create a new config with explicit values.
    pub fn new(graph_name: String, concurrency_limit: usize, batch_size: usize) -> Self {
        Self {
            graph_name,
            concurrency_limit,
            batch_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = IngestConfig::new("test".to_string(), 5, 50);
        assert_eq!(config.graph_name, "test");
        assert_eq!(config.concurrency_limit, 5);
        assert_eq!(config.batch_size, 50);
    }

    #[test]
    fn test_config_from_env_defaults() {
        // Clear env vars to test defaults
        env::remove_var("ACTIVABLE_GRAPH_NAME");
        env::remove_var("ACTIVABLE_INGEST_CONCURRENCY");
        env::remove_var("ACTIVABLE_INGEST_BATCH_SIZE");

        let config = IngestConfig::from_env();
        assert_eq!(config.graph_name, "cloud");
        assert_eq!(config.concurrency_limit, 10);
        assert_eq!(config.batch_size, 100);
    }
}
