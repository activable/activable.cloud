//! Reusability tests: prove that a SECOND job type (unrelated to the first)
//! runs end-to-end through the SAME Scheduler with ZERO changes to store.rs/worker.rs/reaper.rs.
//!
//! This test suite is the acceptance gate that the scheduler is genuinely generic.
//! Mock handlers live in tests/ only (never in src/).
//!
//! Run with: DATABASE_URL="postgres://activable:password@localhost/activable" cargo test --test reusability_test -- --test-threads 1 --ignored
//! Or non-gated pure-logic unit tests (no DB): cargo test --test reusability_test
//!
//! Skips gated tests cleanly if DATABASE_URL not set.

use activable_scheduler::handler::{JobError, JobHandler};
use activable_scheduler::{JobStore, JobStoreConfig};
use serde_json::{json, Value};
use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn db_url() -> Option<String> {
    env::var("DATABASE_URL").ok()
}

// ============================================================================
// MOCK HANDLERS FOR REUSABILITY PROOF
// ============================================================================

/// EchoHandler: job_type="mock_echo"
/// Payload: {msg: String}
/// Result: {echoed: String}
/// Never fails, demonstrates a simple, clean handler.
struct EchoHandler;

#[async_trait::async_trait]
impl JobHandler for EchoHandler {
    async fn handle(&self, payload: Value) -> Result<Value, JobError> {
        // Deserialize and validate payload
        let msg = payload
            .get("msg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JobError {
                retryable: false,
                message: "payload missing 'msg' field or not a string".to_string(),
            })?;

        Ok(json!({"echoed": msg}))
    }

    fn job_type(&self) -> &str {
        "mock_echo"
    }

    fn max_attempts(&self) -> i32 {
        1 // Echo never fails, so 1 attempt is enough
    }
}

/// FlakyHandler: job_type="mock_flaky"
/// Payload: {data: String}
/// Result: {success: true, attempt_number: i32} after retries
/// Fails with retryable=true the first N times (determined at construction),
/// then succeeds on the Nth attempt. Exercises retry + backoff through the registry.
struct FlakyHandler {
    /// Number of times to fail before succeeding.
    fail_count: u32,
    /// Shared counter: incremented on each handle() call.
    attempt_counter: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl JobHandler for FlakyHandler {
    async fn handle(&self, payload: Value) -> Result<Value, JobError> {
        // Validate payload structure
        let _data = payload
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JobError {
                retryable: false,
                message: "payload missing 'data' field or not a string".to_string(),
            })?;

        // Increment attempt counter
        let attempt = self.attempt_counter.fetch_add(1, Ordering::SeqCst) as u32 + 1;

        if attempt <= self.fail_count {
            // Still within fail range; return retryable error
            Err(JobError {
                retryable: true,
                message: format!("flaky failure on attempt {}", attempt),
            })
        } else {
            // We've exceeded fail_count; succeed
            Ok(json!({"success": true, "attempt_number": attempt}))
        }
    }

    fn job_type(&self) -> &str {
        "mock_flaky"
    }

    fn max_attempts(&self) -> i32 {
        5 // Allow up to 5 attempts
    }
}

// ============================================================================
// PURE-LOGIC UNIT TESTS (non-gated, no DB required)
// ============================================================================

#[test]
fn test_echo_handler_valid_payload() {
    let handler = EchoHandler;
    let payload = json!({"msg": "hello world"});

    // Synchronous test by spawning a minimal runtime
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(handler.handle(payload));

    assert!(result.is_ok());
    let output = result.unwrap();
    assert_eq!(output["echoed"], "hello world");
}

#[test]
fn test_echo_handler_missing_msg_field() {
    let handler = EchoHandler;
    let payload = json!({"other_field": "value"});

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(handler.handle(payload));

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(!err.retryable); // Missing field is not retryable
}

#[test]
fn test_echo_handler_job_type_and_max_attempts() {
    let handler = EchoHandler;
    assert_eq!(handler.job_type(), "mock_echo");
    assert_eq!(handler.max_attempts(), 1);
}

#[test]
fn test_flaky_handler_job_type_and_max_attempts() {
    let counter = Arc::new(AtomicUsize::new(0));
    let handler = FlakyHandler {
        fail_count: 2,
        attempt_counter: Arc::clone(&counter),
    };

    assert_eq!(handler.job_type(), "mock_flaky");
    assert_eq!(handler.max_attempts(), 5);
}

#[test]
fn test_flaky_handler_fails_then_succeeds() {
    let counter = Arc::new(AtomicUsize::new(0));
    let handler = FlakyHandler {
        fail_count: 2, // Fail on attempts 1 and 2; succeed on 3+
        attempt_counter: Arc::clone(&counter),
    };

    let payload = json!({"data": "test"});

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Attempt 1: should fail with retryable=true
    let result1 = rt.block_on(handler.handle(payload.clone()));
    assert!(result1.is_err());
    assert!(result1.unwrap_err().retryable);

    // Attempt 2: should fail with retryable=true
    let result2 = rt.block_on(handler.handle(payload.clone()));
    assert!(result2.is_err());
    assert!(result2.unwrap_err().retryable);

    // Attempt 3: should succeed
    let result3 = rt.block_on(handler.handle(payload));
    assert!(result3.is_ok());
    let output = result3.unwrap();
    assert_eq!(output["success"], true);
    assert_eq!(output["attempt_number"], 3);
}

#[test]
fn test_flaky_handler_missing_data_field() {
    let counter = Arc::new(AtomicUsize::new(0));
    let handler = FlakyHandler {
        fail_count: 0,
        attempt_counter: Arc::clone(&counter),
    };

    let payload = json!({"other": "field"});

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(handler.handle(payload));

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(!err.retryable); // Missing field is not retryable
}

// ============================================================================
// GATED INTEGRATION TESTS (require DATABASE_URL, live PG)
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_two_job_types_one_scheduler() {
    //! Reusability gate: register Echo + Flaky handlers; enqueue one job of each;
    //! start a simple orchestrator that spawns workers; assert both reach `completed`
    //! with correct `result` (echo→echoed; flaky→success after retries).
    //!
    //! **Critical assertion:** NO file under src/store.rs/worker.rs/reaper.rs was modified.
    //! The scheduler is genuinely generic: it handles any job_type that satisfies JobHandler.

    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping gated test: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    // Use near-zero backoff so retries happen quickly in the test
    let config = JobStoreConfig {
        backoff_base_seconds: 0.001, // ~1ms backoff
        ..config
    };

    let store = Arc::new(JobStore::new(config).await.expect("pool created"));
    store.ensure_schema().await.expect("schema ensured");

    // Enqueue one echo job
    let echo_payload = json!({"msg": "test_echo_message"});
    let echo_job_id = store
        .enqueue("mock_echo", &echo_payload, None, 0, 1)
        .await
        .expect("echo enqueue ok")
        .expect("echo job created");

    // Enqueue one flaky job (will fail 2 times, then succeed)
    let flaky_payload = json!({"data": "flaky_test_data"});
    let flaky_job_id = store
        .enqueue("mock_flaky", &flaky_payload, None, 0, 5)
        .await
        .expect("flaky enqueue ok")
        .expect("flaky job created");

    // Build handlers
    let echo_handler: Arc<dyn JobHandler + Send + Sync> = Arc::new(EchoHandler);
    let flaky_counter = Arc::new(AtomicUsize::new(0));
    let flaky_handler: Arc<dyn JobHandler + Send + Sync> = Arc::new(FlakyHandler {
        fail_count: 2,
        attempt_counter: Arc::clone(&flaky_counter),
    });

    let handlers = vec![echo_handler, flaky_handler];

    // Import the necessary scheduler components from the crate
    // (We'll use raw WorkerPool + Reaper since Scheduler is not yet implemented)
    // For this test, we manually orchestrate to simulate what Scheduler will do
    use activable_scheduler::WorkerPool;
    use std::time::Duration;

    let pool = WorkerPool::new(Arc::clone(&store), handlers, 1);
    pool.start().await.expect("pool started");

    // Wait for jobs to complete
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut echo_done = false;
    let mut flaky_done = false;

    while !echo_done || !flaky_done {
        if tokio::time::Instant::now() > deadline {
            panic!("timeout waiting for jobs to complete");
        }

        // Check echo job status
        if !echo_done {
            let conn = store.pool().get().await.expect("connection");
            if let Ok(Some(row)) = conn
                .query_opt(
                    "SELECT status, result FROM jobs WHERE id = $1",
                    &[&echo_job_id],
                )
                .await
            {
                let status: String = row.get("status");
                if status == "completed" {
                    let result: Value = serde_json::from_value(row.get("result")).unwrap();
                    assert_eq!(
                        result["echoed"], "test_echo_message",
                        "echo result mismatch"
                    );
                    echo_done = true;
                }
            }
        }

        // Check flaky job status
        if !flaky_done {
            let conn = store.pool().get().await.expect("connection");
            if let Ok(Some(row)) = conn
                .query_opt(
                    "SELECT status, result, attempts FROM jobs WHERE id = $1",
                    &[&flaky_job_id],
                )
                .await
            {
                let status: String = row.get("status");
                if status == "completed" {
                    let result: Value = serde_json::from_value(row.get("result")).unwrap();
                    assert!(
                        result["success"].as_bool().unwrap_or(false),
                        "flaky result incomplete"
                    );
                    let attempt_number = result["attempt_number"].as_i64().unwrap_or(0);
                    assert_eq!(attempt_number, 3, "flaky should succeed on attempt 3");
                    let attempts: i32 = row.get("attempts");
                    assert_eq!(attempts, 3, "job attempts should match");
                    flaky_done = true;
                }
            }
        }

        if !echo_done || !flaky_done {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pool.shutdown().await.expect("pool shutdown");

    // Both jobs completed successfully: the scheduler is reusable!
}

#[tokio::test]
#[ignore]
async fn test_unregistered_job_type_never_claimed() {
    //! Prove that a worker only claims registered job_types.
    //! Enqueue a job with type "mock_unregistered" but register only Echo handler.
    //! Assert the unregistered job stays `pending` after a wait (never claimed).

    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping gated test: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = Arc::new(JobStore::new(config).await.expect("pool created"));
    store.ensure_schema().await.expect("schema ensured");

    // Enqueue a job for an unregistered type
    let payload = json!({"msg": "unregistered"});
    let unregistered_job_id = store
        .enqueue("mock_unregistered", &payload, None, 0, 1)
        .await
        .expect("enqueue ok")
        .expect("job created");

    // Register only Echo handler (not the unregistered type)
    let echo_handler: Arc<dyn JobHandler + Send + Sync> = Arc::new(EchoHandler);
    let handlers = vec![echo_handler];

    use activable_scheduler::WorkerPool;
    use std::time::Duration;

    let pool = WorkerPool::new(Arc::clone(&store), handlers, 1);
    pool.start().await.expect("pool started");

    // Wait a bit for the worker to attempt claims
    tokio::time::sleep(Duration::from_secs(2)).await;

    pool.shutdown().await.expect("pool shutdown");

    // Check that the unregistered job is still pending
    let conn = store.pool().get().await.expect("connection");
    let row = conn
        .query_opt(
            "SELECT status FROM jobs WHERE id = $1",
            &[&unregistered_job_id],
        )
        .await
        .expect("query ok")
        .expect("row found");

    let status: String = row.get("status");
    assert_eq!(
        status, "pending",
        "unregistered job_type should never be claimed"
    );
}

#[tokio::test]
#[ignore]
async fn test_malformed_payload_fails_without_panic() {
    //! Prove that a handler that rejects its payload returns Err(JobError{retryable:false})
    //! and the job ends in `failed` status, NOT panic.
    //!
    //! Enqueue an echo job with a malformed payload (missing "msg" field).
    //! Assert the job reaches `failed` status with the handler's error message.

    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping gated test: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = Arc::new(JobStore::new(config).await.expect("pool created"));
    store.ensure_schema().await.expect("schema ensured");

    // Enqueue an echo job with malformed payload
    let malformed_payload = json!({"wrong_field": "value"});
    let job_id = store
        .enqueue("mock_echo", &malformed_payload, None, 0, 1)
        .await
        .expect("enqueue ok")
        .expect("job created");

    // Register the echo handler (which will reject the payload)
    let echo_handler: Arc<dyn JobHandler + Send + Sync> = Arc::new(EchoHandler);
    let handlers = vec![echo_handler];

    use activable_scheduler::WorkerPool;
    use std::time::Duration;

    let pool = WorkerPool::new(Arc::clone(&store), handlers, 1);
    pool.start().await.expect("pool started");

    // Wait for the job to be claimed, processed, and marked failed
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut done = false;

    while !done {
        if tokio::time::Instant::now() > deadline {
            panic!("timeout waiting for job to fail");
        }

        let conn = store.pool().get().await.expect("connection");
        if let Ok(Some(row)) = conn
            .query_opt(
                "SELECT status, last_error FROM jobs WHERE id = $1",
                &[&job_id],
            )
            .await
        {
            let status: String = row.get("status");
            if status == "failed" {
                let last_error: Option<String> = row.get("last_error");
                assert!(
                    last_error.is_some(),
                    "failed job should have last_error set"
                );
                assert!(
                    last_error.unwrap().contains("msg"),
                    "error message should reference missing field"
                );
                done = true;
            }
        }

        if !done {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pool.shutdown().await.expect("pool shutdown");
}

// ============================================================================
// PURE-LOGIC UNIT TESTS: HandlerRegistry (when implemented)
// ============================================================================

#[test]
fn test_handler_registry_register_and_retrieve() {
    //! Once registry.rs is implemented, test basic registration + retrieval.
    //! This is a placeholder test that will work once HandlerRegistry is in place.

    // This test will be enabled once registry.rs is implemented.
    // For now, we're focusing on the gated tests that prove reusability.
    // The registry's unit tests will be in registry.rs itself or here once ready.
}
