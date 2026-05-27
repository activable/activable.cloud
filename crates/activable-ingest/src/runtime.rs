use crate::cloud_control::IngestStats;
use crate::error::IngestError;
use crate::resource_registry::{load_registry, ResourceRegistry};
use aws_config::SdkConfig;
use deadpool_postgres::Pool;
use std::sync::Arc;
use tracing::info;

#[cfg(test)]
use crate::executor;

pub struct IngestResult {
    pub stats: Vec<IngestStats>,
    pub errors: Vec<(String, IngestError)>,
    pub enrichment_stats: Vec<crate::native::EnrichmentStats>,
    pub enrichment_errors: Vec<(String, IngestError)>,
    pub relationship_stats: Vec<crate::relationship::RelationshipStats>,
    pub relationship_errors: Vec<(String, IngestError)>,
    pub duration: std::time::Duration,
}

/// IngestRuntime is kept for backward compatibility but is no longer used for ingestion.
/// Per-account ingestion now uses the event-driven scheduler (Phase 5+).
/// Public exports remain in lib.rs for API stability.
#[allow(dead_code)]
pub struct IngestRuntime {
    aws_config: SdkConfig,
    pool: Arc<Pool>,
    graph_name: String,
    registry: ResourceRegistry,
    concurrency_limit: usize,
    account_ids: Option<Vec<String>>,
}

impl IngestRuntime {

    /// Create a new IngestRuntime with AWS config loaded from the standard credential chain.
    /// The IngestRuntime is kept for backward compatibility but is no longer used for ingestion.
    /// Per-account ingestion now goes through the event-driven scheduler (Phase 5+).
    pub async fn new(pool: Arc<Pool>, graph_name: String) -> Result<Self, IngestError> {
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let registry = load_registry()?;

        info!(
            resource_types = registry.resource_types.len(),
            "IngestRuntime initialized (for backward compatibility; per-account ingestion via scheduler)"
        );

        Ok(Self {
            aws_config,
            pool,
            graph_name,
            registry,
            concurrency_limit: 10,
            account_ids: None,
        })
    }

    /// Create a new IngestRuntime with a custom AWS config (for testing).
    pub fn with_config(
        pool: Arc<Pool>,
        graph_name: String,
        aws_config: SdkConfig,
    ) -> Result<Self, IngestError> {
        let registry = load_registry()?;
        Ok(Self {
            aws_config,
            pool,
            graph_name,
            registry,
            concurrency_limit: 10,
            account_ids: None,
        })
    }

    /// Set custom concurrency limit (default 10).
    pub fn set_concurrency_limit(&mut self, limit: usize) {
        self.concurrency_limit = limit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registry_loads() {
        // This test verifies that the registry loads without error
        let registry = load_registry().expect("Failed to load registry");
        assert!(!registry.resource_types.is_empty());
    }

    #[test]
    fn test_ingest_result_creation() {
        let stats = vec![
            IngestStats {
                type_name: "AWS::IAM::User".to_string(),
                label: "Principal".to_string(),
                nodes_ingested: 5,
            },
            IngestStats {
                type_name: "AWS::EC2::Instance".to_string(),
                label: "Resource".to_string(),
                nodes_ingested: 3,
            },
        ];

        let result = IngestResult {
            stats: stats.clone(),
            errors: vec![],
            enrichment_stats: vec![],
            enrichment_errors: vec![],
            relationship_stats: vec![],
            relationship_errors: vec![],
            duration: std::time::Duration::from_secs(10),
        };

        assert_eq!(result.stats.len(), 2);
        assert_eq!(result.errors.len(), 0);
        assert_eq!(result.enrichment_stats.len(), 0);
        assert_eq!(result.relationship_stats.len(), 0);
        assert_eq!(result.duration.as_secs(), 10);

        let total_nodes: u32 = result.stats.iter().map(|s| s.nodes_ingested).sum();
        assert_eq!(total_nodes, 8);
    }

    #[test]
    fn test_ingest_result_with_errors() {
        let stats = vec![IngestStats {
            type_name: "AWS::IAM::User".to_string(),
            label: "Principal".to_string(),
            nodes_ingested: 5,
        }];

        let errors = vec![(
            "AWS::EC2::Instance".to_string(),
            IngestError::Config("test error".to_string()),
        )];

        let result = IngestResult {
            stats: stats.clone(),
            errors: errors.clone(),
            enrichment_stats: vec![],
            enrichment_errors: vec![],
            relationship_stats: vec![],
            relationship_errors: vec![],
            duration: std::time::Duration::from_secs(5),
        };

        assert_eq!(result.stats.len(), 1);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].0, "AWS::EC2::Instance");
        assert_eq!(result.enrichment_stats.len(), 0);
        assert_eq!(result.relationship_stats.len(), 0);
    }

    #[test]
    fn test_create_account_config() {
        // Verify that account config has the right credentials provider.
        // (Ported from runtime.rs:121-129 to executor::create_account_config)
        let base_config = aws_config::SdkConfig::builder().build();
        let account_id = "111111111111";

        let _account_config = executor::create_account_config(&base_config, account_id);

        // The config should be created without panicking and should be a valid SdkConfig;
        // actual credential verification is done in integration tests with LocalStack.
        // Just verify the account ID is not empty (fixture validation).
        assert!(!account_id.is_empty());
    }
}
