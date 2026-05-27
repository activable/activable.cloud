//! WorkerPool integration tests: dispatch, success, retryable/non-retryable errors, panic isolation, graceful shutdown.
//!
//! Run with: DATABASE_URL="postgres://activable:password@localhost:5433/activable" cargo test --test worker_test -- --test-threads 1
//! Skips cleanly if DATABASE_URL not set (gated tests).

use activable_scheduler::handler::{JobError, JobHandler};
use activable_scheduler::model::JobStatus;
use activable_scheduler::{JobStore, JobStoreConfig, WorkerPool};
use serde_json::json;
use std::env;
use std::sync::Arc;
use tokio::sync::RwLock;

fn db_url() -> Option<String> {
    env::var("DATABASE_URL").ok()
}

/// Test handler that succeeds immediately.
struct SuccessHandler;

#[async_trait::async_trait]
impl JobHandler for SuccessHandler {
    async fn handle(&self, _payload: serde_json::Value) -> Result<serde_json::Value, JobError> {
        Ok(json!({"status": "success"}))
    }

    fn job_type(&self) -> &str {
        "success_job"
    }

    fn max_attempts(&self) -> i32 {
        3
    }
}

/// Test handler that fails the first N times with retryable error, then succeeds.
struct RetryableErrorHandler {
    attempt_count: Arc<RwLock<u32>>,
    fail_until_attempt: u32, // fail until this attempt (inclusive); succeed after
}

#[async_trait::async_trait]
impl JobHandler for RetryableErrorHandler {
    async fn handle(&self, _payload: serde_json::Value) -> Result<serde_json::Value, JobError> {
        let mut count = self.attempt_count.write().await;
        *count += 1;
        let current_attempt = *count;
        drop(count); // release lock

        if current_attempt <= self.fail_until_attempt {
            Err(JobError {
                retryable: true,
                message: format!("retryable error on attempt {}", current_attempt),
            })
        } else {
            Ok(json!({"status": "succeeded after retries", "final_attempt": current_attempt}))
        }
    }

    fn job_type(&self) -> &str {
        "retryable_job"
    }

    fn max_attempts(&self) -> i32 {
        3
    }
}

/// Test handler that always fails with non-retryable error.
struct NonRetryableErrorHandler;

#[async_trait::async_trait]
impl JobHandler for NonRetryableErrorHandler {
    async fn handle(&self, _payload: serde_json::Value) -> Result<serde_json::Value, JobError> {
        Err(JobError {
            retryable: false,
            message: "non-retryable error".to_string(),
        })
    }

    fn job_type(&self) -> &str {
        "non_retryable_job"
    }

    fn max_attempts(&self) -> i32 {
        3
    }
}

/// Test handler that panics after an async operation.
struct PanicHandler;

#[async_trait::async_trait]
impl JobHandler for PanicHandler {
    async fn handle(&self, _payload: serde_json::Value) -> Result<serde_json::Value, JobError> {
        // Perform an async operation first to ensure panic happens within the async context
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        panic!("intentional panic for testing panic isolation");
    }

    fn job_type(&self) -> &str {
        "panic_job"
    }

    fn max_attempts(&self) -> i32 {
        3
    }
}

#[tokio::test]
#[ignore]
async fn test_worker_success_marks_job_completed() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let config = JobStoreConfig {
        backoff_base_seconds: 0.0, // immediate retry for testing
        ..config
    };
    let store = Arc::new(JobStore::new(config).await.expect("pool created"));
    store.ensure_schema().await.expect("schema ensured");

    // Enqueue a success job
    let job_type = "success_job";
    let payload = json!({"action": "test"});
    let job_id = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("enqueue succeeded")
        .expect("job enqueued");

    // Build handlers
    let handlers: Vec<Arc<dyn JobHandler + Send + Sync>> =
        vec![Arc::new(SuccessHandler) as Arc<dyn JobHandler + Send + Sync>];

    // Start pool with 1 worker
    let pool = WorkerPool::new(Arc::clone(&store), handlers, 1);
    pool.start().await.expect("pool started");

    // Wait for job to complete with bounded timeout (max 5 seconds)
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    loop {
        let conn = store.pool().get().await.expect("got connection for check");
        let row = conn
            .query_one("SELECT status FROM jobs WHERE id = $1", &[&job_id])
            .await
            .expect("query succeeded");
        let status_str: String = row.get(0);
        let status = JobStatus::from_sql_str(&status_str).expect("valid status");

        if status == JobStatus::Completed {
            assert_eq!(status, JobStatus::Completed, "job should be completed");
            break;
        }

        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timeout waiting for job to complete; final status: {:?}",
                status
            );
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    pool.shutdown().await.expect("pool shutdown");
}

#[tokio::test]
#[ignore]
async fn test_worker_retries_then_succeeds() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let config = JobStoreConfig {
        backoff_base_seconds: 0.0, // immediate retry for testing
        ..config
    };
    let store = Arc::new(JobStore::new(config).await.expect("pool created"));
    store.ensure_schema().await.expect("schema ensured");

    // Enqueue a retryable job with max_attempts = 5
    let job_type = "retryable_job";
    let payload = json!({"action": "test"});
    let job_id = store
        .enqueue(job_type, &payload, None, 0, 5)
        .await
        .expect("enqueue succeeded")
        .expect("job enqueued");

    // Build handler that fails first 2 attempts, then succeeds on 3rd
    let handler = RetryableErrorHandler {
        attempt_count: Arc::new(RwLock::new(0)),
        fail_until_attempt: 2,
    };
    let handlers: Vec<Arc<dyn JobHandler + Send + Sync>> =
        vec![Arc::new(handler) as Arc<dyn JobHandler + Send + Sync>];

    // Start pool with 1 worker
    let pool = WorkerPool::new(Arc::clone(&store), handlers, 1);
    pool.start().await.expect("pool started");

    // Wait for job to complete with bounded timeout (max 10 seconds)
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(10);
    loop {
        let conn = store.pool().get().await.expect("got connection for check");
        let row = conn
            .query_one(
                "SELECT status, attempts FROM jobs WHERE id = $1",
                &[&job_id],
            )
            .await
            .expect("query succeeded");
        let status_str: String = row.get(0);
        let attempts: i32 = row.get(1);

        let status = JobStatus::from_sql_str(&status_str).expect("valid status");

        if status == JobStatus::Completed {
            // Verify: job succeeded after exactly 3 attempts (2 retryable fails + 1 success)
            assert_eq!(
                status,
                JobStatus::Completed,
                "job should be completed after retries"
            );
            assert_eq!(
                attempts, 3,
                "job should have completed after exactly 3 attempts (2 fails + 1 success)"
            );
            break;
        }

        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timeout waiting for job to complete after retries; final status: {:?}, attempts: {}",
                status, attempts
            );
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    pool.shutdown().await.expect("pool shutdown");
}

#[tokio::test]
#[ignore]
async fn test_worker_non_retryable_error_fails_job() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = Arc::new(JobStore::new(config).await.expect("pool created"));
    store.ensure_schema().await.expect("schema ensured");

    // Enqueue a non-retryable job
    let job_type = "non_retryable_job";
    let payload = json!({"action": "test"});
    let job_id = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("enqueue succeeded")
        .expect("job enqueued");

    // Build handlers
    let handlers: Vec<Arc<dyn JobHandler + Send + Sync>> =
        vec![Arc::new(NonRetryableErrorHandler) as Arc<dyn JobHandler + Send + Sync>];

    // Start pool with 1 worker
    let pool = WorkerPool::new(Arc::clone(&store), handlers, 1);
    pool.start().await.expect("pool started");

    // Wait for job to fail with bounded timeout (max 5 seconds)
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    loop {
        let conn = store.pool().get().await.expect("got connection for check");
        let row = conn
            .query_one("SELECT status FROM jobs WHERE id = $1", &[&job_id])
            .await
            .expect("query succeeded");
        let status_str: String = row.get(0);
        let status = JobStatus::from_sql_str(&status_str).expect("valid status");

        if status == JobStatus::Failed {
            assert_eq!(status, JobStatus::Failed, "job should be failed");
            break;
        }

        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timeout waiting for job to fail; final status: {:?}",
                status
            );
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    pool.shutdown().await.expect("pool shutdown");
}

#[tokio::test]
#[ignore]
async fn test_worker_panic_isolation() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let config = JobStoreConfig {
        backoff_base_seconds: 0.0, // immediate requeue for testing
        ..config
    };
    let store = Arc::new(JobStore::new(config).await.expect("pool created"));
    store.ensure_schema().await.expect("schema ensured");

    // Enqueue a panic job
    let job_type = "panic_job";
    let payload = json!({"action": "test"});
    let job_id = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("enqueue succeeded")
        .expect("job enqueued");

    // Build handlers with panic
    let handlers: Vec<Arc<dyn JobHandler + Send + Sync>> =
        vec![Arc::new(PanicHandler) as Arc<dyn JobHandler + Send + Sync>];

    // Start pool with 1 worker
    let pool = WorkerPool::new(Arc::clone(&store), handlers, 1);
    pool.start().await.expect("pool started");

    // Wait for job to be marked failed with bounded timeout (max 5 seconds)
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    loop {
        let conn = store.pool().get().await.expect("got connection for check");
        let row = conn
            .query_one("SELECT status FROM jobs WHERE id = $1", &[&job_id])
            .await
            .expect("query succeeded");
        let status_str: String = row.get(0);
        let status = JobStatus::from_sql_str(&status_str).expect("valid status");

        if status == JobStatus::Failed {
            assert_eq!(
                status,
                JobStatus::Failed,
                "panic should result in job failure (non-retryable)"
            );
            break;
        }

        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timeout waiting for job to fail after panic; final status: {:?}",
                status
            );
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    pool.shutdown().await.expect("pool shutdown");
}

#[tokio::test]
async fn test_worker_id_generation() {
    // Pure logic test (no DB needed)
    let worker_id = WorkerPool::generate_worker_id(0);
    assert!(
        worker_id.starts_with("worker-"),
        "worker id should have prefix"
    );
    assert!(worker_id.contains('-'), "worker id should contain dashes");

    let worker_id2 = WorkerPool::generate_worker_id(1);
    assert_ne!(worker_id, worker_id2, "worker ids should differ by index");
}
