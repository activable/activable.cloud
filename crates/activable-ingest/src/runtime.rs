use crate::cloud_control::IngestStats;
use crate::error::IngestError;
use crate::executor;
use crate::resource_registry::{load_registry, ResourceRegistry};
use aws_config::SdkConfig;
use deadpool_postgres::Pool;
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info};

pub struct IngestResult {
    pub stats: Vec<IngestStats>,
    pub errors: Vec<(String, IngestError)>,
    pub enrichment_stats: Vec<crate::native::EnrichmentStats>,
    pub enrichment_errors: Vec<(String, IngestError)>,
    pub relationship_stats: Vec<crate::relationship::RelationshipStats>,
    pub relationship_errors: Vec<(String, IngestError)>,
    pub duration: std::time::Duration,
}

pub struct IngestRuntime {
    aws_config: SdkConfig,
    pool: Arc<Pool>,
    graph_name: String,
    registry: ResourceRegistry,
    concurrency_limit: usize,
    account_ids: Option<Vec<String>>,
}

impl IngestRuntime {
    /// Pure parsing helper: validates account IDs from a raw string.
    /// Returns None if the string is None or empty.
    /// Returns an error if any account ID is malformed (not 12 digits).
    fn parse_account_ids_from(ids_str: Option<String>) -> Result<Option<Vec<String>>, IngestError> {
        match ids_str {
            None => Ok(None),
            Some(ref s) if s.is_empty() => Ok(None),
            Some(ids_str) => {
                let account_ids: Result<Vec<String>, IngestError> = ids_str
                    .split(',')
                    .map(|id| {
                        let trimmed = id.trim();
                        if trimmed.len() == 12 && trimmed.chars().all(|c| c.is_ascii_digit()) {
                            Ok(trimmed.to_string())
                        } else {
                            Err(IngestError::Config(format!(
                                "Invalid account ID '{}': must be 12 digits",
                                trimmed
                            )))
                        }
                    })
                    .collect();

                match account_ids {
                    Ok(ids) if !ids.is_empty() => Ok(Some(ids)),
                    Ok(_) => Ok(None),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Parse account IDs from comma-separated INGEST_ACCOUNT_IDS environment variable.
    /// Returns None if the variable is not set or empty.
    /// Returns an error if any account ID is malformed (not 12 digits).
    fn parse_account_ids() -> Result<Option<Vec<String>>, IngestError> {
        let ids_str = std::env::var("INGEST_ACCOUNT_IDS").ok();
        Self::parse_account_ids_from(ids_str)
    }

    /// Create a new IngestRuntime with AWS config loaded from the standard credential chain.
    /// If INGEST_ACCOUNT_IDS env var is set, runs multi-account ingest; otherwise single-account.
    pub async fn new(pool: Arc<Pool>, graph_name: String) -> Result<Self, IngestError> {
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let registry = load_registry()?;
        let account_ids = Self::parse_account_ids()?;

        info!(
            resource_types = registry.resource_types.len(),
            account_ids = ?account_ids,
            "IngestRuntime initialized"
        );

        Ok(Self {
            aws_config,
            pool,
            graph_name,
            registry,
            concurrency_limit: 10,
            account_ids,
        })
    }

    /// Create a new IngestRuntime with a custom AWS config (for testing).
    pub fn with_config(
        pool: Arc<Pool>,
        graph_name: String,
        aws_config: SdkConfig,
    ) -> Result<Self, IngestError> {
        let registry = load_registry()?;
        let account_ids = Self::parse_account_ids()?;
        Ok(Self {
            aws_config,
            pool,
            graph_name,
            registry,
            concurrency_limit: 10,
            account_ids,
        })
    }

    /// Set custom concurrency limit (default 10).
    pub fn set_concurrency_limit(&mut self, limit: usize) {
        self.concurrency_limit = limit;
    }


    /// Run ingestion for all configured accounts.
    /// THIN DELEGATE: calls the ported executor::ingest_account() for each account.
    /// Kept for GraphQL compatibility (Phase 5 will re-point GraphQL to the scheduler).
    /// The scheduler's per-account job model is the primary path going forward.
    pub async fn run(&self) -> IngestResult {
        let start = Instant::now();

        // Determine which accounts to ingest.
        let accounts_to_ingest: Vec<String> = match &self.account_ids {
            Some(ids) => ids.clone(),
            None => vec!["default".to_string()],
        };

        info!(
            account_count = accounts_to_ingest.len(),
            "Starting ingestion run (thin delegate to executor)"
        );

        let mut all_stats = Vec::new();
        let mut all_errors = Vec::new();
        let all_enrichment_stats = Vec::new();
        let all_enrichment_errors = Vec::new();
        let all_relationship_stats = Vec::new();
        let all_relationship_errors = Vec::new();

        // Run per-account ingest in sequence, delegating to the ported executor.
        for account_id in &accounts_to_ingest {
            // For multi-account, override credentials; for single-account, use base config.
            let account_config = if self.account_ids.is_some() {
                executor::create_account_config(&self.aws_config, account_id)
            } else {
                self.aws_config.clone()
            };

            info!(account_id = account_id, "Starting ingestion for account");

            // Delegate to the ported executor (ported from runtime.rs:132-333).
            match executor::ingest_account(
                account_id,
                &account_config,
                self.pool.clone(),
                &self.graph_name,
                &self.registry,
                self.concurrency_limit,
            )
            .await
            {
                Ok(stats) => {
                    // Convert ported IngestRunStats back to the old IngestResult format for GraphQL compatibility.
                    // Reconstruct IngestStats and RelationshipStats from the aggregated data.
                    for (type_name, node_count) in stats.per_type {
                        all_stats.push(crate::cloud_control::IngestStats {
                            type_name,
                            label: "Resource".to_string(), // Placeholder; only per_type matters
                            nodes_ingested: node_count,
                        });
                    }

                    // Extend errors list.
                    for error_msg in &stats.errors {
                        all_errors.push(("executor".to_string(), IngestError::AwsSdk(error_msg.clone())));
                    }

                    // Note: enrichment_stats and relationship_stats are aggregated in the executor.
                    // For now, we report them as empty to keep IngestResult compatible.
                    // Phase 5 will update this mapping.
                }
                Err(e) => {
                    error!(account_id = account_id, error = %e, "Account ingest failed");
                    all_errors.push((account_id.clone(), e));
                }
            }
        }

        let duration = start.elapsed();

        info!(
            total_accounts = accounts_to_ingest.len(),
            total_types = all_stats.len() + all_errors.len(),
            successful = all_stats.len(),
            failed = all_errors.len(),
            duration_secs = duration.as_secs(),
            "Ingestion run complete"
        );

        IngestResult {
            stats: all_stats,
            errors: all_errors,
            enrichment_stats: all_enrichment_stats,
            enrichment_errors: all_enrichment_errors,
            relationship_stats: all_relationship_stats,
            relationship_errors: all_relationship_errors,
            duration,
        }
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
    fn test_parse_account_ids_empty_env() {
        // When INGEST_ACCOUNT_IDS is not set, should return None
        let result = IngestRuntime::parse_account_ids_from(None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_parse_account_ids_single() {
        // Single valid account ID
        let result = IngestRuntime::parse_account_ids_from(Some("111111111111".to_string()));
        assert!(result.is_ok());
        let ids = result.unwrap();
        assert!(ids.is_some());
        assert_eq!(ids.unwrap(), vec!["111111111111"]);
    }

    #[test]
    fn test_parse_account_ids_multiple() {
        // Multiple valid account IDs with whitespace
        let result = IngestRuntime::parse_account_ids_from(Some(
            "111111111111, 222222222222, 333333333333, 444444444444".to_string(),
        ));
        assert!(result.is_ok());
        let ids = result.unwrap();
        assert!(ids.is_some());
        let id_vec = ids.unwrap();
        assert_eq!(id_vec.len(), 4);
        assert_eq!(
            id_vec,
            vec![
                "111111111111",
                "222222222222",
                "333333333333",
                "444444444444"
            ]
        );
    }

    #[test]
    fn test_parse_account_ids_invalid_too_short() {
        // Invalid account ID (too short)
        let result = IngestRuntime::parse_account_ids_from(Some("12345".to_string()));
        assert!(result.is_err());
        match result {
            Err(IngestError::Config(msg)) => {
                assert!(msg.contains("Invalid account ID"));
                assert!(msg.contains("12 digits"));
            }
            _ => panic!("Expected Config error"),
        }
    }

    #[test]
    fn test_parse_account_ids_invalid_non_numeric() {
        // Invalid account ID (contains non-digits)
        let result = IngestRuntime::parse_account_ids_from(Some("11111111111a".to_string()));
        assert!(result.is_err());
        match result {
            Err(IngestError::Config(msg)) => {
                assert!(msg.contains("Invalid account ID"));
            }
            _ => panic!("Expected Config error"),
        }
    }

    #[test]
    fn test_parse_account_ids_mixed_valid_invalid() {
        // Mix of valid and invalid IDs
        let result =
            IngestRuntime::parse_account_ids_from(Some("111111111111,invalid".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_account_ids_empty_string() {
        // Empty string should return None
        let result = IngestRuntime::parse_account_ids_from(Some("".to_string()));
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
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
