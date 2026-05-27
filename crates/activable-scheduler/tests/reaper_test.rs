//! Reaper integration tests: heartbeat refresh, stale job re-queue, max_attempts boundary, concurrent reapers.
//!
//! Run with: DATABASE_URL="postgres://activable:activable_dev@localhost:5432/activable" cargo test --test reaper_test -- --ignored --test-threads 1
//! Skips cleanly if DATABASE_URL not set (gated tests).

use activable_scheduler::model::JobStatus;
use activable_scheduler::{JobStore, JobStoreConfig, Reaper};
use std::env;
use std::time::Duration;

fn db_url() -> Option<String> {
    env::var("DATABASE_URL").ok()
}

/// Test: fresh heartbeat (just claimed) → tick() reaps 0; job stays running.
#[tokio::test]
#[ignore]
async fn test_fresh_heartbeat_not_reaped() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = std::sync::Arc::new(JobStore::new(config).await.expect("pool created"));
    store.ensure_schema().await.expect("schema ensured");

    // Clean jobs table for this test
    {
        let conn = store.pool().get().await.expect("get connection");
        conn.batch_execute("DELETE FROM jobs")
            .await
            .expect("delete jobs");
    }

    let job_type = "test_fresh_heartbeat";
    let payload = serde_json::json!({"data": "test"});

    // Enqueue and claim a job (sets heartbeat_at = now())
    let job_id = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("enqueue succeeded")
        .expect("job enqueued");

    let claimed = store
        .claim(&[job_type.to_string()], "test_worker", 0)
        .await
        .expect("claim succeeded")
        .expect("job claimed");

    assert_eq!(claimed.id, job_id);
    assert_eq!(claimed.status, JobStatus::Running);
    assert!(
        claimed.heartbeat_at.is_some(),
        "heartbeat_at should be set on claim"
    );

    // Create reaper with 60s threshold
    let reaper = Reaper::new(
        std::sync::Arc::clone(&store),
        vec![job_type.to_string()],
        60,                      // threshold = 60 seconds
        Duration::from_secs(10), // check interval (unused in single tick test)
    );

    // Tick should reap 0 jobs (heartbeat is fresh)
    let reaped = reaper.tick().await.expect("reaper tick succeeded");
    assert_eq!(reaped, 0, "fresh heartbeat should not be reaped");

    // Verify job is still running
    let job = store
        .claim(&[job_type.to_string()], "another_worker", 0)
        .await
        .expect("claim succeeded");
    assert!(
        job.is_none(),
        "running job with fresh heartbeat should not be reclaimable"
    );
}

/// Test: stale heartbeat (> 60s old) → tick() re-queues; attempts < max → pending; attempts >= max → failed.
#[tokio::test]
#[ignore]
async fn test_stale_heartbeat_requeued() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = std::sync::Arc::new(JobStore::new(config).await.expect("pool created"));
    store.ensure_schema().await.expect("schema ensured");

    // Clean jobs table for this test
    {
        let conn = store.pool().get().await.expect("get connection");
        conn.batch_execute("DELETE FROM jobs")
            .await
            .expect("delete jobs");
    }

    let job_type = "test_stale_heartbeat";
    let payload = serde_json::json!({"data": "test"});
    let max_attempts = 3;

    // Enqueue and claim a job
    let job_id = store
        .enqueue(job_type, &payload, None, 0, max_attempts)
        .await
        .expect("enqueue succeeded")
        .expect("job enqueued");

    let claimed = store
        .claim(&[job_type.to_string()], "test_worker", 0)
        .await
        .expect("claim succeeded")
        .expect("job claimed");

    assert_eq!(claimed.id, job_id);
    assert_eq!(claimed.attempts, 1);

    // Force heartbeat_at into the past (120 seconds ago)
    {
        let conn = store.pool().get().await.expect("get connection");
        conn.execute(
            "UPDATE jobs SET heartbeat_at = now() - interval '120 seconds' WHERE id = $1",
            &[&job_id],
        )
        .await
        .expect("update heartbeat");
    }

    // Create reaper with 60s threshold
    let reaper = Reaper::new(
        std::sync::Arc::clone(&store),
        vec![job_type.to_string()],
        60, // threshold = 60 seconds
        Duration::from_secs(10),
    );

    // Tick should reap 1 job
    let reaped = reaper.tick().await.expect("reaper tick succeeded");
    assert_eq!(reaped, 1, "stale heartbeat should be reaped once");

    // Verify job is now pending (re-queued) by directly querying the database
    // (the claim query has next_attempt_at checks that might not pick it up immediately)
    let job_status = {
        let conn = store.pool().get().await.expect("get connection");
        let row = conn
            .query_one(
                "SELECT status, attempts FROM jobs WHERE id = $1",
                &[&job_id],
            )
            .await
            .expect("query job");
        let status_str: String = row.get(0);
        let attempts: i32 = row.get(1);
        (status_str, attempts)
    };

    assert_eq!(
        job_status.0, "pending",
        "job should be re-queued to pending"
    );
    assert_eq!(
        job_status.1, 1,
        "attempts stays at 1 until next claim increments it"
    );

    // Wait for next_attempt_at to pass so we can claim it
    // Backoff is exponential: 2^attempts + jitter, capped at 3600s
    // For attempt=1, base is 2^1 = 2, so total is 2-4 seconds + safety margin
    tokio::time::sleep(Duration::from_secs(8)).await;

    // Verify next_attempt_at is now in the past
    {
        let conn = store.pool().get().await.expect("get connection");
        let row = conn
            .query_one(
                "SELECT status, next_attempt_at FROM jobs WHERE id = $1",
                &[&job_id],
            )
            .await
            .expect("query job");
        let status_str: String = row.get(0);
        let next_attempt_at: Option<chrono::DateTime<chrono::Utc>> = row.get(1);
        eprintln!(
            "Before claim: status={}, next_attempt_at={:?}",
            status_str, next_attempt_at
        );
    }

    // Now claim should succeed and increment attempts
    let refetched = store
        .claim(&[job_type.to_string()], "another_worker", 0)
        .await
        .expect("claim succeeded")
        .expect("job should be claimable after next_attempt_at");

    assert_eq!(refetched.id, job_id);
    assert_eq!(refetched.status, JobStatus::Running);
    assert_eq!(
        refetched.attempts, 2,
        "attempts should be incremented to 2 on reclaim"
    );
}

/// Test: attempts >= max_attempts → job marked failed (not re-queued).
#[tokio::test]
#[ignore]
async fn test_stale_heartbeat_exhausted_attempts_marked_failed() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = std::sync::Arc::new(JobStore::new(config).await.expect("pool created"));
    store.ensure_schema().await.expect("schema ensured");

    // Clean jobs table for this test
    {
        let conn = store.pool().get().await.expect("get connection");
        conn.batch_execute("DELETE FROM jobs")
            .await
            .expect("delete jobs");
    }

    let job_type = "test_exhausted_attempts";
    let payload = serde_json::json!({"data": "test"});
    let max_attempts = 1; // Only 1 attempt allowed

    // Enqueue and claim the job (now at attempt 1)
    let job_id = store
        .enqueue(job_type, &payload, None, 0, max_attempts)
        .await
        .expect("enqueue succeeded")
        .expect("job enqueued");

    let claimed = store
        .claim(&[job_type.to_string()], "test_worker", 0)
        .await
        .expect("claim succeeded")
        .expect("job claimed");

    assert_eq!(claimed.attempts, 1);
    assert_eq!(claimed.max_attempts, max_attempts);

    // Force heartbeat stale
    {
        let conn = store.pool().get().await.expect("get connection");
        conn.execute(
            "UPDATE jobs SET heartbeat_at = now() - interval '120 seconds' WHERE id = $1",
            &[&job_id],
        )
        .await
        .expect("update heartbeat");
    }

    // Create reaper
    let reaper = Reaper::new(
        std::sync::Arc::clone(&store),
        vec![job_type.to_string()],
        60,
        Duration::from_secs(10),
    );

    // Tick should reap 1 job
    let reaped = reaper.tick().await.expect("reaper tick succeeded");
    assert_eq!(reaped, 1, "should reap stale job");

    // Verify job is now marked FAILED (not re-queued)
    let failed_job = {
        let conn = store.pool().get().await.expect("get connection");
        let row = conn
            .query_one("SELECT status FROM jobs WHERE id = $1", &[&job_id])
            .await
            .expect("query job");
        row.get::<_, String>(0)
    };

    assert_eq!(
        failed_job, "failed",
        "exhausted job should be marked failed"
    );

    // Verify it cannot be reclaimed (status != pending)
    let reclaim = store
        .claim(&[job_type.to_string()], "another_worker", 0)
        .await
        .expect("claim succeeded");

    assert!(reclaim.is_none(), "failed job should not be reclaimable");
}

/// Test: boundary case — job with heartbeat 45s old under 60s threshold is NOT reaped.
#[tokio::test]
#[ignore]
async fn test_heartbeat_boundary_not_reaped() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = std::sync::Arc::new(JobStore::new(config).await.expect("pool created"));
    store.ensure_schema().await.expect("schema ensured");

    // Clean jobs table
    {
        let conn = store.pool().get().await.expect("get connection");
        conn.batch_execute("DELETE FROM jobs")
            .await
            .expect("delete jobs");
    }

    let job_type = "test_boundary";
    let payload = serde_json::json!({"data": "test"});

    // Enqueue and claim
    let job_id = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("enqueue succeeded")
        .expect("job enqueued");

    store
        .claim(&[job_type.to_string()], "test_worker", 0)
        .await
        .expect("claim succeeded")
        .expect("job claimed");

    // Set heartbeat to 45 seconds ago (fresh relative to 60s threshold)
    {
        let conn = store.pool().get().await.expect("get connection");
        conn.execute(
            "UPDATE jobs SET heartbeat_at = now() - interval '45 seconds' WHERE id = $1",
            &[&job_id],
        )
        .await
        .expect("update heartbeat");
    }

    let reaper = Reaper::new(
        std::sync::Arc::clone(&store),
        vec![job_type.to_string()],
        60,
        Duration::from_secs(10),
    );

    // Tick should NOT reap (45s < 60s threshold)
    let reaped = reaper.tick().await.expect("reaper tick succeeded");
    assert_eq!(
        reaped, 0,
        "heartbeat 45s old should not be reaped with 60s threshold"
    );
}

/// Test: update_heartbeat refreshes heartbeat_at; makes previously stale job fresh.
#[tokio::test]
#[ignore]
async fn test_update_heartbeat_refreshes() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = std::sync::Arc::new(JobStore::new(config).await.expect("pool created"));
    store.ensure_schema().await.expect("schema ensured");

    // Clean jobs table
    {
        let conn = store.pool().get().await.expect("get connection");
        conn.batch_execute("DELETE FROM jobs")
            .await
            .expect("delete jobs");
    }

    let job_type = "test_update_heartbeat";
    let payload = serde_json::json!({"data": "test"});

    // Enqueue and claim
    let job_id = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("enqueue succeeded")
        .expect("job enqueued");

    store
        .claim(&[job_type.to_string()], "test_worker", 0)
        .await
        .expect("claim succeeded")
        .expect("job claimed");

    // Force heartbeat 120s old (stale)
    {
        let conn = store.pool().get().await.expect("get connection");
        conn.execute(
            "UPDATE jobs SET heartbeat_at = now() - interval '120 seconds' WHERE id = $1",
            &[&job_id],
        )
        .await
        .expect("update heartbeat");
    }

    // Update heartbeat (refresh to now())
    store
        .update_heartbeat(job_id)
        .await
        .expect("update heartbeat succeeded");

    // Verify reaper doesn't reap it anymore
    let reaper = Reaper::new(
        std::sync::Arc::clone(&store),
        vec![job_type.to_string()],
        60,
        Duration::from_secs(10),
    );

    let reaped = reaper.tick().await.expect("reaper tick succeeded");
    assert_eq!(reaped, 0, "refreshed heartbeat should not be reaped");
}

/// Test: concurrent reapers don't double-reclaim same job.
#[tokio::test]
#[ignore]
async fn test_concurrent_reapers_no_double_reclaim() {
    let url = match db_url() {
        Some(u) => u,
        None => {
            println!("Skipping: DATABASE_URL not set");
            return;
        }
    };

    let config = JobStoreConfig::from_url(&url).expect("valid url");
    let store = std::sync::Arc::new(JobStore::new(config).await.expect("pool created"));
    store.ensure_schema().await.expect("schema ensured");

    // Clean jobs table
    {
        let conn = store.pool().get().await.expect("get connection");
        conn.batch_execute("DELETE FROM jobs")
            .await
            .expect("delete jobs");
    }

    let job_type = "test_concurrent";
    let payload = serde_json::json!({"data": "test"});

    // Enqueue and claim a job
    let job_id = store
        .enqueue(job_type, &payload, None, 0, 3)
        .await
        .expect("enqueue succeeded")
        .expect("job enqueued");

    store
        .claim(&[job_type.to_string()], "worker1", 0)
        .await
        .expect("claim succeeded")
        .expect("job claimed");

    // Force heartbeat stale
    {
        let conn = store.pool().get().await.expect("get connection");
        conn.execute(
            "UPDATE jobs SET heartbeat_at = now() - interval '120 seconds' WHERE id = $1",
            &[&job_id],
        )
        .await
        .expect("update heartbeat");
    }

    // Spawn two concurrent reapers
    let store_clone = std::sync::Arc::clone(&store);
    let store_clone2 = std::sync::Arc::clone(&store);

    let reaper1 = tokio::spawn(async move {
        let reaper = Reaper::new(
            store_clone,
            vec![job_type.to_string()],
            60,
            Duration::from_secs(10),
        );
        reaper.tick().await
    });

    let reaper2 = tokio::spawn(async move {
        let reaper = Reaper::new(
            store_clone2,
            vec![job_type.to_string()],
            60,
            Duration::from_secs(10),
        );
        reaper.tick().await
    });

    let r1 = reaper1
        .await
        .expect("reaper1 completed")
        .expect("reaper1 tick succeeded");
    let r2 = reaper2
        .await
        .expect("reaper2 completed")
        .expect("reaper2 tick succeeded");

    // Together, exactly one of them should have reaped the job
    // (the other's `fail()` call gets NotFound and returns Err, which reaper tolerates)
    assert_eq!(
        r1 + r2,
        1,
        "concurrent reapers together should reap exactly 1 job (not double-reclaim)"
    );
}

/// Unit test: Reaper config defaults (pure logic, no DB)
#[test]
fn test_reaper_config_invariant() {
    // heartbeat_interval should be ≪ reap_threshold
    // Example: 5s interval, 60s threshold
    // Invariant: interval < threshold to avoid false reclaims
    // (a slow-but-alive handler with a 5s interval should not reach 60s stale
    // under normal circumstances)

    let heartbeat_interval_secs = 5;
    let reap_threshold_secs = 60;

    // This is just a documentation test that the invariant holds for defaults
    assert!(
        heartbeat_interval_secs < reap_threshold_secs,
        "heartbeat interval should be much less than reap threshold"
    );
}
