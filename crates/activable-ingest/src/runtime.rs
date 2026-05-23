use crate::cloud_control::{fetch_via_ccapi, IngestStats};
use crate::error::IngestError;
use crate::native::NativeEnricher;
use crate::native_fallback::fetch_via_native_sdk;
use crate::resource_registry::{load_registry, ResourceRegistry};
use aws_config::SdkConfig;
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
}

impl IngestRuntime {
    /// Create a new IngestRuntime with AWS config loaded from the standard credential chain.
    pub async fn new(pool: Arc<Pool>, graph_name: String) -> Result<Self, IngestError> {
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let registry = load_registry()?;

        info!(
            resource_types = registry.resource_types.len(),
            "IngestRuntime initialized"
        );

        Ok(Self {
            aws_config,
            pool,
            graph_name,
            registry,
            concurrency_limit: 10,
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
        })
    }

    /// Set custom concurrency limit (default 10).
    pub fn set_concurrency_limit(&mut self, limit: usize) {
        self.concurrency_limit = limit;
    }

    /// Run ingestion for all resource types in parallel.
    pub async fn run(&self) -> IngestResult {
        let start = Instant::now();

        let ccapi_client = aws_sdk_cloudcontrol::Client::new(&self.aws_config);
        let mut tasks = tokio::task::JoinSet::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrency_limit));

        for resource_type in &self.registry.resource_types {
            let sem = semaphore.clone();
            let ccapi = ccapi_client.clone();
            let config = self.aws_config.clone();
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
                        // CCAPI returned empty — try native SDK (e.g., Floci doesn't support CCAPI)
                        match fetch_via_native_sdk(&config, &rt, pool, &graph_name).await {
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
                        match fetch_via_native_sdk(&config, &rt, pool, &graph_name).await {
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
            Box::new(crate::native::iam::IamEnricher::new(
                self.aws_config.clone(),
            )),
            Box::new(crate::native::ec2::Ec2Enricher::new(
                self.aws_config.clone(),
            )),
            Box::new(crate::native::s3::S3Enricher::new(self.aws_config.clone())),
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
            total_types = stats.len() + errors.len(),
            successful = stats.len(),
            failed = errors.len(),
            enrichers_completed = enrichment_stats.len(),
            enrichers_failed = enrichment_errors.len(),
            relationships_completed = relationship_stats.len(),
            relationships_failed = relationship_errors.len(),
            duration_secs = duration.as_secs(),
            "Ingestion run complete"
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
}
