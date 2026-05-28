//! Per-account ingestion executor.
//!
//! PORTED from `runtime.rs:132-333` (ingest_single_account).
//! This module executes the three-phase ingest pipeline for a single AWS account:
//! 1. Fetch resources via CCAPI or native SDK fallback
//! 2. Run native enrichers (IAM, EC2, S3, KMS, permissions)
//! 3. Apply declarative relationship rules
//!
//! The executor is designed to be called per job by the scheduler's handler registry.

use crate::cloud_control::fetch_via_ccapi;
use crate::error::IngestError;
use crate::native::NativeEnricher;
use crate::native_fallback::fetch_via_native_sdk;
use crate::relationship;
use crate::resource_registry::ResourceRegistry;
use aws_config::SdkConfig;
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn};

/// Per-account ingest statistics and metadata.
///
/// Serializes to JSON for storage in the scheduler's job result field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestRunStats {
    /// Number of nodes ingested, per resource type.
    pub per_type: Vec<(String, u32)>,
    /// Total nodes ingested across all types.
    pub total_nodes: u32,
    /// Total edges created (from enrichers + relationships).
    pub total_edges: u32,
    /// Edges that were dropped during load.
    /// None = per-load drop counts are not surfaced by the enricher/relationship stat types yet;
    /// the honest EdgeLoadOutcome drop accounting is internally logged by loaders when
    /// edges are dropped (e.g., due to missing endpoints or failures), but this count is not
    /// aggregated into the per-enricher EnrichmentStats or RelationshipStats structs.
    /// Some(n) = when enricher traits are updated to surface drop counts, will be wired here.
    pub dropped_edges: Option<u32>,
    /// Rules that failed to execute (skipped during relationship inference).
    pub skipped_rules: Vec<String>,
    /// Duration of the full ingest pipeline.
    pub duration_secs: u64,
    /// Errors encountered (should be checked by handler caller).
    pub errors: Vec<String>,
}

/// Create a new AWS config with credentials overridden for the given account ID.
///
/// PORTED from `runtime.rs:121-129`.
/// LocalStack uses AWS_ACCESS_KEY_ID as the tenant routing key, so we set it to the account ID.
pub fn create_account_config(base_config: &SdkConfig, account_id: &str) -> SdkConfig {
    use aws_credential_types::{provider::SharedCredentialsProvider, Credentials};

    let credentials = Credentials::new(account_id, "test", None, None, "multi-account-ingest");
    let provider = SharedCredentialsProvider::new(credentials);
    base_config
        .clone()
        .into_builder()
        .credentials_provider(provider)
        .build()
}

/// Execute ingestion for a single account.
///
/// PORTED from `runtime.rs:132-333` (ingest_single_account).
/// Credential routing: `create_account_config` (runtime.rs:121-129).
/// Pool and graph_name passed as parameters (previously from &self).
/// Concurrency controlled via semaphore (previously `self.concurrency_limit`).
///
/// Returns `IngestRunStats` with counts and metadata.
pub async fn ingest_account(
    account_id: &str,
    config: &SdkConfig,
    pool: Arc<Pool>,
    graph_name: &str,
    registry: &ResourceRegistry,
    concurrency_limit: usize,
) -> Result<IngestRunStats, IngestError> {
    let start = Instant::now();

    // Phase 1: Fetch resources via CCAPI or native SDK fallback.
    let ccapi_client = aws_sdk_cloudcontrol::Client::new(config);
    let mut tasks = tokio::task::JoinSet::new();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency_limit));

    for resource_type in &registry.resource_types {
        let sem = semaphore.clone();
        let ccapi = ccapi_client.clone();
        let cfg = config.clone();
        let pool = pool.clone();
        let graph_name = graph_name.to_string();
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

            // Try CCAPI first (production path).
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
                    // CCAPI returned empty — try native SDK (e.g., LocalStack doesn't support CCAPI).
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
                    // Fall back to native SDK.
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

    // Phase 2: Run native enrichers.
    let mut enrichment_stats = Vec::new();
    let mut enrichment_errors = Vec::new();

    let enrichers: Vec<Box<dyn NativeEnricher>> = vec![
        Box::new(crate::native::iam::IamEnricher::new(config.clone())),
        Box::new(crate::native::permissions::PermissionsEnricher::new()),
        Box::new(crate::native::ec2::Ec2Enricher::new(config.clone())),
        Box::new(crate::native::s3::S3Enricher::new(config.clone())),
        Box::new(crate::native::kms::KmsEnricher::new(config.clone())),
        Box::new(crate::native::secretsmanager::SecretsManagerEnricher::new(
            config.clone(),
        )),
        Box::new(crate::native::lambda::LambdaEnricher::new(config.clone())),
    ];

    for enricher in &enrichers {
        match enricher.enrich(&pool, graph_name).await {
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

    // Phase 3: Apply declarative relationship rules.
    let mut relationship_stats = Vec::new();
    let mut relationship_errors = Vec::new();

    info!("Starting relationship inference...");
    match relationship::apply_relationships(&pool, graph_name).await {
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

    // Aggregate counts and build result.
    let total_nodes: u32 = stats.iter().map(|s| s.nodes_ingested).sum();
    let total_edges: u32 = enrichment_stats
        .iter()
        .map(|s| s.edges_created)
        .sum::<u32>()
        + relationship_stats
            .iter()
            .map(|s| s.edges_created)
            .sum::<u32>();

    // dropped_edges accounting: loaders internally track dropped edges (via EdgeLoadOutcome)
    // but do not surface the counts through EnrichmentStats or RelationshipStats yet.
    // When those traits are extended to include drop counts, wire them here.
    let dropped_edges = None;

    let skipped_rules: Vec<String> = relationship_stats
        .iter()
        .flat_map(|rs| rs.skipped_rules.clone())
        .collect();

    let error_messages: Vec<String> = errors
        .iter()
        .map(|(type_name, e)| format!("{}: {}", type_name, e))
        .chain(
            enrichment_errors
                .iter()
                .map(|(service, e)| format!("enrichment {}: {}", service, e)),
        )
        .chain(
            relationship_errors
                .iter()
                .map(|(rule, e)| format!("relationship {}: {}", rule, e)),
        )
        .collect();

    info!(
        account_id = account_id,
        total_types = stats.len() + errors.len(),
        successful = stats.len(),
        failed = errors.len(),
        enrichers_completed = enrichment_stats.len(),
        enrichers_failed = enrichment_errors.len(),
        relationships_completed = relationship_stats.len(),
        relationships_failed = relationship_errors.len(),
        total_nodes = total_nodes,
        total_edges = total_edges,
        duration_secs = duration.as_secs(),
        "Account ingestion complete"
    );

    let per_type: Vec<(String, u32)> = stats
        .iter()
        .map(|s| (s.type_name.clone(), s.nodes_ingested))
        .collect();

    Ok(IngestRunStats {
        per_type,
        total_nodes,
        total_edges,
        dropped_edges,
        skipped_rules,
        duration_secs: duration.as_secs(),
        errors: error_messages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ingest_run_stats_creation() {
        let stats = IngestRunStats {
            per_type: vec![
                ("AWS::IAM::User".to_string(), 5),
                ("AWS::EC2::Instance".to_string(), 3),
            ],
            total_nodes: 8,
            total_edges: 12,
            dropped_edges: None,
            skipped_rules: vec![],
            duration_secs: 10,
            errors: vec![],
        };

        assert_eq!(stats.total_nodes, 8);
        assert_eq!(stats.total_edges, 12);
        assert_eq!(stats.per_type.len(), 2);
        assert_eq!(stats.duration_secs, 10);
        assert_eq!(stats.dropped_edges, None);
    }

    #[test]
    fn test_ingest_run_stats_serialization() {
        let stats = IngestRunStats {
            per_type: vec![("AWS::IAM::User".to_string(), 5)],
            total_nodes: 5,
            total_edges: 3,
            dropped_edges: None,
            skipped_rules: vec!["some_rule".to_string()],
            duration_secs: 5,
            errors: vec!["some_error".to_string()],
        };

        let json = serde_json::to_value(&stats).expect("Failed to serialize");
        assert!(json.is_object());
        assert_eq!(json["total_nodes"], 5);
        assert_eq!(json["total_edges"], 3);
        assert_eq!(json["dropped_edges"], serde_json::Value::Null);
    }
}
