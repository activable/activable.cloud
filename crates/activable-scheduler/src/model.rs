use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Status of a scheduled job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    /// Job is waiting to be claimed and executed.
    Pending,
    /// Job has been claimed by a worker and is currently executing.
    Running,
    /// Job completed successfully.
    Completed,
    /// Job failed and will not be retried.
    Failed,
}

impl JobStatus {
    /// Return the SQL string representation of the status.
    pub fn as_str(&self) -> &'static str {
        match self {
            JobStatus::Pending => "pending",
            JobStatus::Running => "running",
            JobStatus::Completed => "completed",
            JobStatus::Failed => "failed",
        }
    }

    /// Parse a status from a SQL string.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(JobStatus::Pending),
            "running" => Some(JobStatus::Running),
            "completed" => Some(JobStatus::Completed),
            "failed" => Some(JobStatus::Failed),
            _ => None,
        }
    }
}

/// A scheduled job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: Uuid,
    pub job_type: String,
    pub payload: serde_json::Value,
    pub dedup_key: Option<String>,
    pub status: JobStatus,
    pub attempts: i32,
    pub max_attempts: i32,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub claimed_by: Option<String>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub heartbeat_at: Option<DateTime<Utc>>,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub result: Option<serde_json::Value>,
    pub run_at: Option<DateTime<Utc>>,
}

/// Error type for scheduler operations.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("pool error: {0}")]
    Pool(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("failed to parse row: {0}")]
    RowParse(String),

    #[error("job not found: {0}")]
    NotFound(Uuid),

    #[error("schema initialization failed: {0}")]
    SchemaInit(String),
}

impl From<deadpool_postgres::CreatePoolError> for SchedulerError {
    fn from(err: deadpool_postgres::CreatePoolError) -> Self {
        SchedulerError::Pool(err.to_string())
    }
}

impl From<deadpool_postgres::PoolError> for SchedulerError {
    fn from(err: deadpool_postgres::PoolError) -> Self {
        SchedulerError::Pool(err.to_string())
    }
}

impl From<tokio_postgres::Error> for SchedulerError {
    fn from(err: tokio_postgres::Error) -> Self {
        SchedulerError::Database(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_status_as_str() {
        assert_eq!(JobStatus::Pending.as_str(), "pending");
        assert_eq!(JobStatus::Running.as_str(), "running");
        assert_eq!(JobStatus::Completed.as_str(), "completed");
        assert_eq!(JobStatus::Failed.as_str(), "failed");
    }

    #[test]
    fn job_status_from_str() {
        assert_eq!(JobStatus::from_sql_str("pending"), Some(JobStatus::Pending));
        assert_eq!(JobStatus::from_sql_str("running"), Some(JobStatus::Running));
        assert_eq!(
            JobStatus::from_sql_str("completed"),
            Some(JobStatus::Completed)
        );
        assert_eq!(JobStatus::from_sql_str("failed"), Some(JobStatus::Failed));
        assert_eq!(JobStatus::from_sql_str("unknown"), None);
    }

    #[test]
    fn job_status_serde_roundtrip() {
        let status = JobStatus::Running;
        let serialized = serde_json::to_string(&status).unwrap();
        assert_eq!(serialized, "\"running\"");
        let deserialized: JobStatus = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, status);
    }
}
