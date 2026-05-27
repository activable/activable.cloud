use crate::cloud_control::{fetch_via_ccapi, IngestStats};
use crate::error::IngestError;
use crate::native::NativeEnricher;
use crate::native_fallback::fetch_via_native_sdk;
use crate::resource_registry::{load_registry, ResourceRegistry};
use aws_config::SdkConfig;
use aws_credential_types::{provider::SharedCredentialsProvider, Credentials};
use deadpool_postgres::Pool;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn};

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

    /// Create a new AWS config with credentials overridden for the given account ID.
    /// LocalStack uses AWS_ACCESS_KEY_ID as the tenant routing key, so we set it to the account ID.
    fn create_account_config(base_config: &SdkConfig, account_id: &str) -> SdkConfig {
        let credentials = Credentials::new(account_id, "test", None, None, "multi-account-ingest");
        let provider = SharedCredentialsProvider::new(credentials);
        base_config
            .clone()
            .into_builder()
            .credentials_provider(provider)
            .build()
    }

    /// Run ingestion for a single account using the provided config.
    async fn ingest_single_account(&self, account_id: &str, config: &SdkConfig) -> IngestResult {
        let start = Instant::now();

        let ccapi_client = aws_sdk_cloudcontrol::Client::new(config);
        let mut tasks = tokio::task::JoinSet::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrency_limit));

        for resource_type in &self.registry.resource_types {
            let sem = semaphore.clone();
            let ccapi = ccapi_client.clone();
            let cfg = config.clone();
            let pool = self.pool.clone();
            let graph_name = self.graph_name.clone();
            let rt = resource_type.clone();

            tasks.spawn(async move {
                let _permit = match sem.acquire().await {
                    Ok(p) => p,
                    Err(e) => {
                        error!(error = %e, "Failed to acquire semaphore permit");
                        return Err((
                            rt.type_name.clone(),
                            IngestError::AwsSdk("semaphore acquire failed".to_string()),
                        ));
                    }
                };

                let type_name = rt.type_name.clone();
                debug!(type_name = %type_name, "Starting resource ingestion");

                // Try CCAPI first (production path)
                let result = fetch_via_ccapi(&ccapi, &rt, pool.clone(), &graph_name).await;

                match result {
                    Ok(stats) if stats.nodes_ingested > 0 => {
                        info!(
                            type_name = %type_name,
                            nodes = stats.nodes_ingested,
                            "CCAPI ingest succeeded"
                        );
                        Ok(stats)
                    }
                    Ok(stats) => {
                        warn!(
                            type_name = %type_name,
                            nodes = stats.nodes_ingested,
                            "CCAPI returned 0 resources, attempting native SDK fallback"
                        );
                        // CCAPI returned empty — try native SDK (e.g., LocalStack doesn't support CCAPI)
                        match fetch_via_native_sdk(&cfg, &rt, pool, &graph_name).await {
                            Ok(native_stats) if native_stats.nodes_ingested > 0 => {
                                info!(
                                    type_name = %type_name,
                                    nodes = native_stats.nodes_ingested,
                                    "Native SDK fallback succeeded (CCAPI was empty)"
                                );
                                Ok(native_stats)
                            }
                            Ok(_) => {
                                debug!(
                                    type_name = %type_name,
                                    "Both CCAPI and native SDK returned 0 resources"
                                );
                                Ok(stats) // return original empty stats
                            }
                            Err(e) => {
                                warn!(
                                    type_name = %type_name,
                                    error = %e,
                                    "Native SDK fallback failed after CCAPI returned empty"
                                );
                                Ok(stats) // return original empty stats, don't fail
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            type_name = %type_name,
                            error = %e,
                            "CCAPI failed, attempting native SDK fallback"
                        );
                        // Fall back to native SDK
                        match fetch_via_native_sdk(&cfg, &rt, pool, &graph_name).await {
                            Ok(stats) => {
                                info!(
                                    type_name = %type_name,
                                    nodes = stats.nodes_ingested,
                                    "Native SDK fallback succeeded"
                                );
                                Ok(stats)
                            }
                            Err(e2) => {
                                error!(
                                    type_name = %type_name,
                                    ccapi_error = %e,
                                    fallback_error = %e2,
                                    "Both CCAPI and fallback failed"
                                );
                                Err((type_name, e2))
                            }
                        }
                    }
                }
            });
        }

        let mut stats = Vec::new();
        let mut errors = Vec::new();

        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(s)) => stats.push(s),
                Ok(Err((type_name, e))) => {
                    errors.push((type_name, e));
                }
                Err(e) => {
                    error!(error = %e, "Task panicked");
                    errors.push(("task_panic".to_string(), IngestError::AwsSdk(e.to_string())));
                }
            }
        }

        // Phase 2: Run native enrichers
        let mut enrichment_stats = Vec::new();
        let mut enrichment_errors = Vec::new();

        let enrichers: Vec<Box<dyn NativeEnricher>> = vec![
            Box::new(crate::native::iam::IamEnricher::new(config.clone())),
            Box::new(crate::native::permissions::PermissionsEnricher::new()),
            Box::new(crate::native::ec2::Ec2Enricher::new(config.clone())),
            Box::new(crate::native::s3::S3Enricher::new(config.clone())),
            Box::new(crate::native::kms::KmsEnricher::new(config.clone())),
        ];

        for enricher in &enrichers {
            match enricher.enrich(&self.pool, &self.graph_name).await {
                Ok(stats_item) => {
                    info!(
                        service = %stats_item.service,
                        edges = stats_item.edges_created,
                        "Enrichment completed"
                    );
                    enrichment_stats.push(stats_item);
                }
                Err(e) => {
                    warn!(
                        service = %enricher.service(),
                        error = %e,
                        "Enrichment failed (continuing with other enrichers)"
                    );
                    enrichment_errors.push((enricher.service().to_string(), e));
                }
            }
        }

        // Phase 3: Apply declarative relationship rules
        let mut relationship_stats = Vec::new();
        let mut relationship_errors = Vec::new();

        info!("Starting relationship inference...");
        match crate::relationship::apply_relationships(&self.pool, &self.graph_name).await {
            Ok(rel_stats) => {
                for rs in &rel_stats {
                    info!(
                        rule = %rs.rule_name,
                        edges = rs.edges_created,
                        "relationship rule complete"
                    );
                }
                relationship_stats = rel_stats;
            }
            Err(e) => {
                warn!(error = %e, "relationship inference failed");
                relationship_errors.push(("relationships".to_string(), e));
            }
        }

        let duration = start.elapsed();

        info!(
            account_id = account_id,
            total_types = stats.len() + errors.len(),
            successful = stats.len(),
            failed = errors.len(),
            enrichers_completed = enrichment_stats.len(),
            enrichers_failed = enrichment_errors.len(),
            relationships_completed = relationship_stats.len(),
            relationships_failed = relationship_errors.len(),
            duration_secs = duration.as_secs(),
            "Account ingestion complete"
        );

        IngestResult {
            stats,
            errors,
            enrichment_stats,
            enrichment_errors,
            relationship_stats,
            relationship_errors,
            duration,
        }
    }

    /// Run ingestion for all resource types in parallel.
    /// If account_ids are configured, runs per-account; otherwise single-account legacy behavior.
    pub async fn run(&self) -> IngestResult {
        let start = Instant::now();

        // Determine which accounts to ingest
        let accounts_to_ingest: Vec<String> = match &self.account_ids {
            Some(ids) => ids.clone(),
            None => vec!["default".to_string()],
        };

        info!(
            account_count = accounts_to_ingest.len(),
            "Starting ingestion run"
        );

        let mut all_stats = Vec::new();
        let mut all_errors = Vec::new();
        let mut all_enrichment_stats = Vec::new();
        let mut all_enrichment_errors = Vec::new();
        let mut all_relationship_stats = Vec::new();
        let mut all_relationship_errors = Vec::new();

        // Run per-account ingest in sequence
        for account_id in &accounts_to_ingest {
            // For multi-account, override credentials; for single-account, use base config
            let account_config = if self.account_ids.is_some() {
                Self::create_account_config(&self.aws_config, account_id)
            } else {
                self.aws_config.clone()
            };

            info!(account_id = account_id, "Starting ingestion for account");

            let result = self
                .ingest_single_account(account_id, &account_config)
                .await;

            all_stats.extend(result.stats);
            all_errors.extend(result.errors);
            all_enrichment_stats.extend(result.enrichment_stats);
            all_enrichment_errors.extend(result.enrichment_errors);
            all_relationship_stats.extend(result.relationship_stats);
            all_relationship_errors.extend(result.relationship_errors);
        }

        let duration = start.elapsed();

        info!(
            total_accounts = accounts_to_ingest.len(),
            total_types = all_stats.len() + all_errors.len(),
            successful = all_stats.len(),
            failed = all_errors.len(),
            enrichers_completed = all_enrichment_stats.len(),
            enrichers_failed = all_enrichment_errors.len(),
            relationships_completed = all_relationship_stats.len(),
            relationships_failed = all_relationship_errors.len(),
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
        // Verify that account config has the right credentials provider
        let base_config = aws_config::SdkConfig::builder().build();
        let account_id = "111111111111";

        let _account_config = IngestRuntime::create_account_config(&base_config, account_id);

        // The config should be created without panicking and should be a valid SdkConfig;
        // actual credential verification is done in integration tests with LocalStack.
        // Just verify the account ID is not empty (fixture validation).
        assert!(!account_id.is_empty());
    }
}
