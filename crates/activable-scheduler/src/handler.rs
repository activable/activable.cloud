use serde::{Deserialize, Serialize};

/// Error type returned by job handlers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobError {
    /// Whether the error is retryable. If true and attempts < max_attempts,
    /// the job will be requeued with exponential backoff.
    pub retryable: bool,
    /// Error message for logging and storage.
    pub message: String,
}

impl std::fmt::Display for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for JobError {}

/// Handler for a specific job type.
/// Implementations dispatch on job_type and handle the execution logic.
#[async_trait::async_trait]
pub trait JobHandler: Send + Sync {
    /// Execute the job with the given payload.
    /// Return Ok(result) on success; Err(JobError) on failure.
    async fn handle(&self, payload: serde_json::Value) -> Result<serde_json::Value, JobError>;

    /// Return the job type this handler processes.
    fn job_type(&self) -> &str;

    /// Return the maximum number of attempts for this job type.
    fn max_attempts(&self) -> i32;
}
