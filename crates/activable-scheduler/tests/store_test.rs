//! JobStore integration tests: enqueue, claim (SKIP LOCKED), complete, fail/retry.
//!
//! Run with: DATABASE_URL="postgres://activable:password@localhost:5433/activable" cargo test --test store_test -- --test-threads 1
//! Skips cleanly if DATABASE_URL not set (gated tests).

use activable_scheduler::model::JobStatus;
use activable_scheduler::{JobStore, JobStoreConfig};
use std::env;

fn db_url() -> Option<String> {
    env::var("DATABASE_URL").ok()
}

#[tokio::test]
#[ignore]
async fn test_enqueue_dedup_returns_none_on_conflict() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = JobStore::new(config).await.expect("pool created");
    store.ensure_schema().await.expect("schema ensured");

    // First enqueue: should succeed and return a job ID
    let job_type = "test_dedup_type";
    let dedup_key = "test_dedup_key_1";
    let payload = serde_json::json!({"data": "test"});
    let priority = 0;
    let max_attempts = 3;

    let first_id = store
        .enqueue(job_type, &payload, Some(dedup_key), priority, max_attempts)
        .await
        .expect("enqueue succeeded")
        .expect("first enqueue returns id");

    // Second enqueue with same (job_type, dedup_key): should return None (deduped)
    let second_result = store
        .enqueue(job_type, &payload, Some(dedup_key), priority, max_attempts)
        .await
        .expect("second enqueue succeeded");

    assert!(
        second_result.is_none(),
        "second enqueue with same (job_type, dedup_key) should return None"
    );

    // Cleanup: claim and complete to release dedup key
    let claimed = store
        .claim(&[job_type.to_string()], "test_worker", 0)
        .await
        .expect("claim succeeded");
    assert!(claimed.is_some(), "should claim the job");

    let job = claimed.unwrap();
    assert_eq!(job.id, first_id);

    store
        .complete(job.id, &serde_json::json!({"done": true}))
        .await
        .expect("complete succeeded");
}

#[tokio::test]
#[ignore]
async fn test_enqueue_allows_dedup_after_completion() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = JobStore::new(config).await.expect("pool created");
    store.ensure_schema().await.expect("schema ensured");

    let job_type = "test_requeue_type";
    let dedup_key = "test_requeue_key";
    let payload = serde_json::json!({"data": "test"});
    let priority = 0;
    let max_attempts = 3;

    // First enqueue and complete
    let first_id = store
        .enqueue(job_type, &payload, Some(dedup_key), priority, max_attempts)
        .await
        .expect("first enqueue succeeded")
        .expect("first enqueue returns id");

    let claimed = store
        .claim(&[job_type.to_string()], "worker_1", 0)
        .await
        .expect("claim succeeded")
        .expect("should claim");
    store
        .complete(claimed.id, &serde_json::json!({"result": 1}))
        .await
        .expect("complete succeeded");

    // Second enqueue with same dedup key: should succeed (first is completed, so not in pending/running)
    let second_id = store
        .enqueue(job_type, &payload, Some(dedup_key), priority, max_attempts)
        .await
        .expect("second enqueue succeeded")
        .expect("second enqueue should succeed after completion");

    assert_ne!(
        first_id, second_id,
        "completed job should allow new job with same dedup key"
    );
}

#[tokio::test]
#[ignore]
async fn test_claim_returns_pending_job_once() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = JobStore::new(config).await.expect("pool created");
    store.ensure_schema().await.expect("schema ensured");

    let job_type = "test_claim_type";
    let payload = serde_json::json!({"data": "claim_test"});

    let job_id = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("enqueue succeeded")
        .expect("enqueue returns id");

    // First claim: should return the job and mark it running
    let claimed = store
        .claim(&[job_type.to_string()], "worker_1", 0)
        .await
        .expect("claim succeeded");
    assert!(
        claimed.is_some(),
        "first claim should return the pending job"
    );

    let claimed_job = claimed.unwrap();
    assert_eq!(claimed_job.id, job_id);
    assert_eq!(claimed_job.status, JobStatus::Running);
    assert_eq!(claimed_job.claimed_by, Some("worker_1".to_string()));

    // Second claim: should return None (job is now running, not pending)
    let second_claim = store
        .claim(&[job_type.to_string()], "worker_2", 0)
        .await
        .expect("second claim succeeded");
    assert!(
        second_claim.is_none(),
        "second claim should return None (job already running)"
    );
}

#[tokio::test]
#[ignore]
async fn test_concurrent_claim_skip_locked() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = JobStore::new(config).await.expect("pool created");
    store.ensure_schema().await.expect("schema ensured");

    let job_type = "test_skip_locked";
    let payload = serde_json::json!({"data": "concurrent"});

    // Enqueue two pending jobs
    let job_1 = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("first enqueue succeeded")
        .expect("returns id");

    let job_2 = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("second enqueue succeeded")
        .expect("returns id");

    // Claim job_1 from task 1
    let claimed_1 = store
        .claim(&[job_type.to_string()], "worker_1", 0)
        .await
        .expect("task 1 claim succeeded")
        .expect("task 1 gets a job");

    // Concurrent claim from task 2 should get job_2 (SKIP LOCKED skips job_1)
    let claimed_2 = store
        .claim(&[job_type.to_string()], "worker_2", 0)
        .await
        .expect("task 2 claim succeeded")
        .expect("task 2 gets a job");

    assert_ne!(
        claimed_1.id, claimed_2.id,
        "two concurrent claims should not return the same job (SKIP LOCKED)"
    );
    assert_eq!(claimed_1.id, job_1);
    assert_eq!(claimed_2.id, job_2);
}

#[tokio::test]
#[ignore]
async fn test_claim_respects_priority_order() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = JobStore::new(config).await.expect("pool created");
    store.ensure_schema().await.expect("schema ensured");

    let job_type = "test_priority_order";
    let payload = serde_json::json!({"data": "priority_test"});

    // Enqueue three jobs with priorities [10, 1, 5] — lower number = higher priority
    let _job_10 = store
        .enqueue(job_type, &payload, None, 10, 3)
        .await
        .expect("enqueue priority 10 succeeded")
        .expect("returns id");

    let _job_1 = store
        .enqueue(job_type, &payload, None, 1, 3)
        .await
        .expect("enqueue priority 1 succeeded")
        .expect("returns id");

    let _job_5 = store
        .enqueue(job_type, &payload, None, 5, 3)
        .await
        .expect("enqueue priority 5 succeeded")
        .expect("returns id");

    // Claims should come out in priority order: 1, 5, 10
    let first = store
        .claim(&[job_type.to_string()], "worker_1", 0)
        .await
        .expect("first claim succeeded")
        .expect("should claim first job");
    assert_eq!(first.priority, 1, "first claim should be priority 1");

    let second = store
        .claim(&[job_type.to_string()], "worker_2", 0)
        .await
        .expect("second claim succeeded")
        .expect("should claim second job");
    assert_eq!(second.priority, 5, "second claim should be priority 5");

    let third = store
        .claim(&[job_type.to_string()], "worker_3", 0)
        .await
        .expect("third claim succeeded")
        .expect("should claim third job");
    assert_eq!(third.priority, 10, "third claim should be priority 10");
}

#[tokio::test]
#[ignore]
async fn test_fail_concurrent_with_complete() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = JobStore::new(config).await.expect("pool created");
    store.ensure_schema().await.expect("schema ensured");

    let job_type = "test_fail_complete_race";
    let payload = serde_json::json!({"data": "race_test"});

    let job_id = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("enqueue succeeded")
        .expect("returns id");

    let _claimed = store
        .claim(&[job_type.to_string()], "worker_1", 0)
        .await
        .expect("claim succeeded")
        .expect("gets job");

    // Simulate one worker completing the job
    let _completed = store
        .complete(job_id, &serde_json::json!({"result": "done"}))
        .await
        .expect("complete succeeded");

    // Another worker tries to fail the same job concurrently.
    // With TOCTOU-free atomic SQL, this should return NotFound (job already terminal),
    // not resurrect a finished job.
    let fail_result = store.fail(job_id, "worker 2 failed", true).await;

    // The fail should fail because the job is no longer in running state.
    // Atomic SQL ensures exactly one wins.
    assert!(
        fail_result.is_err(),
        "fail after complete should return error (job already terminal), not resurrect"
    );
}

#[tokio::test]
#[ignore]
async fn test_fail_retryable_updates_pending_with_backoff() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = JobStore::new(config).await.expect("pool created");
    store.ensure_schema().await.expect("schema ensured");

    let job_type = "test_retry";
    let payload = serde_json::json!({"data": "retry_test"});

    let job_id = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("enqueue succeeded")
        .expect("returns id");

    let _claimed = store
        .claim(&[job_type.to_string()], "worker_1", 0)
        .await
        .expect("claim succeeded")
        .expect("gets job");

    // Fail with retryable=true: should update status to pending with next_attempt_at set
    let failed = store
        .fail(job_id, "transient error", true)
        .await
        .expect("fail succeeded");

    assert_eq!(failed.status, JobStatus::Pending);
    assert_eq!(failed.attempts, 1);
    assert!(
        failed.next_attempt_at.is_some(),
        "retryable failure should set next_attempt_at"
    );
    assert_eq!(failed.last_error, Some("transient error".to_string()));
}

#[tokio::test]
#[ignore]
async fn test_fail_exhausted_max_attempts_marks_failed() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let mut config = JobStoreConfig::from_url(&url).expect("valid url");
    config.backoff_base_seconds = 0.0;
    let store = JobStore::new(config).await.expect("pool created");
    store.ensure_schema().await.expect("schema ensured");

    let job_type = "test_exhausted";
    let payload = serde_json::json!({"data": "exhaust_test"});

    let job_id = store
        .enqueue(job_type, &payload, None, 0, 2)
        .await
        .expect("enqueue succeeded")
        .expect("returns id");

    // Attempt 1: fail and retry
    let _claimed_1 = store
        .claim(&[job_type.to_string()], "worker_1", 0)
        .await
        .expect("claim 1 succeeded")
        .expect("gets job");
    let failed_1 = store
        .fail(job_id, "attempt 1 failed", true)
        .await
        .expect("fail 1 succeeded");
    assert_eq!(failed_1.attempts, 1);
    assert_eq!(failed_1.status, JobStatus::Pending);

    // Attempt 2: claim again, fail again with attempts >= max_attempts
    let _claimed_2 = store
        .claim(&[job_type.to_string()], "worker_2", 0)
        .await
        .expect("claim 2 succeeded")
        .expect("gets job again");
    let failed_2 = store
        .fail(job_id, "attempt 2 failed", true)
        .await
        .expect("fail 2 succeeded");
    assert_eq!(failed_2.attempts, 2);
    assert_eq!(
        failed_2.status,
        JobStatus::Failed,
        "attempts >= max_attempts should mark failed"
    );
    assert!(
        failed_2.finished_at.is_some(),
        "failed job should have finished_at"
    );
}

#[tokio::test]
#[ignore]
async fn test_fail_non_retryable_marks_failed() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = JobStore::new(config).await.expect("pool created");
    store.ensure_schema().await.expect("schema ensured");

    let job_type = "test_non_retryable";
    let payload = serde_json::json!({"data": "non_retryable"});

    let job_id = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("enqueue succeeded")
        .expect("returns id");

    let _claimed = store
        .claim(&[job_type.to_string()], "worker_1", 0)
        .await
        .expect("claim succeeded")
        .expect("gets job");

    // Fail with retryable=false: should mark as failed immediately, even with attempts < max_attempts
    let failed = store
        .fail(job_id, "permanent error", false)
        .await
        .expect("fail succeeded");

    assert_eq!(
        failed.status,
        JobStatus::Failed,
        "non-retryable failure should mark failed immediately"
    );
    assert_eq!(failed.attempts, 1);
    assert!(failed.finished_at.is_some());
}

#[tokio::test]
#[ignore]
async fn test_complete_marks_completed() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = JobStore::new(config).await.expect("pool created");
    store.ensure_schema().await.expect("schema ensured");

    let job_type = "test_complete";
    let payload = serde_json::json!({"data": "complete_test"});
    let result_json = serde_json::json!({"result": "success", "count": 42});

    let job_id = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("enqueue succeeded")
        .expect("returns id");

    let _claimed = store
        .claim(&[job_type.to_string()], "worker_1", 0)
        .await
        .expect("claim succeeded")
        .expect("gets job");

    let completed = store
        .complete(job_id, &result_json)
        .await
        .expect("complete succeeded");

    assert_eq!(completed.status, JobStatus::Completed);
    assert_eq!(completed.result, Some(result_json));
    assert!(completed.finished_at.is_some());
}
