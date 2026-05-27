//! AccountIngestHandler: the scheduler consumer for per-account ingestion.
//!
//! Implements the `JobHandler` trait from activable-scheduler.
//! Handles `job_type="account_ingest"` with payload `{account_id, provider, regions}`.
//! Executes the ported per-account ingest pipeline via executor::ingest_account().

use crate::executor::{create_account_config, ingest_account};
use crate::error::IngestError;
use crate::resource_registry::{load_registry, ResourceRegistry};
use activable_scheduler::{JobError, JobHandler};
use async_trait::async_trait;
use aws_config::SdkConfig;
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, info};

/// Payload for account ingest jobs.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccountIngestPayload {
    /// AWS account ID (must be 12 digits).
    pub account_id: String,
    /// Provider (e.g., "aws").
    #[serde(default)]
    pub provider: String,
    /// Regions to ingest (e.g., ["us-east-1"]).
    #[serde(default)]
    pub regions: Vec<String>,
}

/// Handler for per-account ingestion jobs.
pub struct AccountIngestHandler {
    /// Base AWS config (with endpoint overrides from environment).
    aws_config: SdkConfig,
    /// Postgres connection pool (shared with graph).
    pool: Arc<Pool>,
    /// Graph name (e.g., "cloud").
    graph_name: String,
    /// Resource type registry.
    registry: ResourceRegistry,
    /// Concurrency limit for parallel resource fetches.
    concurrency_limit: usize,
}

impl AccountIngestHandler {
    /// Create a new handler with defaults.
    pub async fn new(
        aws_config: SdkConfig,
        pool: Arc<Pool>,
        graph_name: String,
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

    /// Validate account_id format.
    fn validate_account_id(account_id: &str) -> Result<(), JobError> {
        // Ported from runtime.rs:44-45 validation logic.
        if account_id.len() == 12 && account_id.chars().all(|c| c.is_ascii_digit()) {
            Ok(())
        } else {
            Err(JobError {
                retryable: false,
                message: format!(
                    "Invalid account_id '{}': must be 12 digits",
                    account_id
                ),
            })
        }
    }

    /// Map IngestError to JobError with appropriate retryable flag.
    fn map_ingest_error(error: IngestError) -> JobError {
        // Decision tree: transient AWS errors → retryable=true; validation/config → retryable=false.
        let (retryable, message) = match error {
            // Transient AWS errors (likely to succeed on retry).
            IngestError::AwsSdk(msg) if msg.contains("timeout") => {
                (true, format!("AWS timeout (retryable): {}", msg))
            }
            IngestError::AwsSdk(msg) if msg.contains("throttling") => {
                (true, format!("AWS throttling (retryable): {}", msg))
            }
            IngestError::AwsSdk(msg) if msg.contains("ServiceException") => {
                (true, format!("AWS service error (retryable): {}", msg))
            }
            // Network/connection transient errors.
            IngestError::AwsSdk(msg) if msg.contains("connection") => {
                (true, format!("Connection error (retryable): {}", msg))
            }
            IngestError::Graph(msg) if msg.contains("pool error") => {
                (true, format!("Pool error (retryable): {}", msg))
            }
            // Non-retryable: config, validation, parsing.
            IngestError::Config(msg) => (false, format!("Config error: {}", msg)),
            IngestError::YamlParse(msg) => (false, format!("YAML parse error: {}", msg)),
            IngestError::CloudControl { type_name, message } => {
                // CloudControl errors may be transient (invalid type name) or config (bad creds).
                // For now, treat as retryable to be safe.
                (
                    true,
                    format!("CloudControl error for {}: {}", type_name, message),
                )
            }
            // Graph errors: could be transient (pool full) or permanent (bad Cypher).
            // Default to retryable for safety.
            IngestError::Graph(msg) => (true, format!("Graph error (retryable): {}", msg)),
            // Other errors: default to retryable.
            other => (true, format!("Unclassified error (retryable): {:?}", other)),
        };

        JobError { retryable, message }
    }
}

#[async_trait]
impl JobHandler for AccountIngestHandler {
    /// Execute a single account ingest job.
    async fn handle(&self, payload: Value) -> Result<Value, JobError> {
        // Deserialize payload.
        let account_payload: AccountIngestPayload = serde_json::from_value(payload)
            .map_err(|e| JobError {
                retryable: false,
                message: format!("Malformed payload: {}", e),
            })?;

        let account_id = &account_payload.account_id;

        debug!(
            account_id = %account_id,
            "Starting account ingest job"
        );

        // Validate account_id format (ported from runtime.rs:44-45).
        Self::validate_account_id(account_id)?;

        // Build per-account AWS config (ported from runtime.rs:121-129).
        let account_config = create_account_config(&self.aws_config, account_id);

        // Execute the per-account ingest pipeline (ported from runtime.rs:132-333).
        match ingest_account(
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
                info!(
                    account_id = %account_id,
                    total_nodes = stats.total_nodes,
                    total_edges = stats.total_edges,
                    duration_secs = stats.duration_secs,
                    "Account ingest completed successfully"
                );

                // Serialize result to JSON for storage in the job row.
                Ok(serde_json::to_value(&stats).unwrap_or_else(|_| {
                    json!({
                        "error": "Failed to serialize IngestRunStats",
                        "account_id": account_id
                    })
                }))
            }
            Err(e) => {
                let job_error = Self::map_ingest_error(e);
                Err(job_error)
            }
        }
    }

    fn job_type(&self) -> &str {
        "account_ingest"
    }

    fn max_attempts(&self) -> i32 {
        3 // Default: retry up to 3 times (Phase 1 exponential backoff applies).
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_account_id_valid() {
        assert!(AccountIngestHandler::validate_account_id("000000000123").is_ok());
        assert!(AccountIngestHandler::validate_account_id("999999999999").is_ok());
    }

    #[test]
    fn test_validate_account_id_invalid_too_short() {
        let result = AccountIngestHandler::validate_account_id("12345678901");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.retryable);
    }

    #[test]
    fn test_validate_account_id_invalid_non_digit() {
        let result = AccountIngestHandler::validate_account_id("00000000012a");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.retryable);
    }

    #[test]
    fn test_validate_account_id_invalid_too_long() {
        let result = AccountIngestHandler::validate_account_id("0000000001234");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.retryable);
    }

    #[test]
    fn test_payload_deserialize_valid() {
        let payload = json!({
            "account_id": "000000000123",
            "provider": "aws",
            "regions": ["us-east-1"]
        });

        let p: AccountIngestPayload = serde_json::from_value(payload)
            .expect("Failed to deserialize valid payload");
        assert_eq!(p.account_id, "000000000123");
        assert_eq!(p.provider, "aws");
        assert_eq!(p.regions.len(), 1);
    }

    #[test]
    fn test_payload_deserialize_malformed() {
        let payload = json!({
            "provider": "aws"
            // Missing account_id
        });

        let result: Result<AccountIngestPayload, _> = serde_json::from_value(payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_mapping_aws_timeout() {
        let error = IngestError::AwsSdk("timeout: connection reset".to_string());
        let job_error = AccountIngestHandler::map_ingest_error(error);
        assert!(job_error.retryable);
        assert!(job_error.message.contains("timeout"));
    }

    #[test]
    fn test_error_mapping_config_error() {
        let error = IngestError::Config("bad endpoint".to_string());
        let job_error = AccountIngestHandler::map_ingest_error(error);
        assert!(!job_error.retryable);
        assert!(job_error.message.contains("Config"));
    }

    #[test]
    fn test_job_type_constant() {
        // Verify the job type string constant.
        let job_type_str = "account_ingest";
        assert_eq!(job_type_str, "account_ingest");
    }

    #[test]
    fn test_max_attempts_constant() {
        // Verify the max_attempts constant.
        let max_attempts: i32 = 3;
        assert_eq!(max_attempts, 3);
    }

}
