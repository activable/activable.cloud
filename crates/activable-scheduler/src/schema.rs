/// SQL DDL constants and schema initialization.
///
/// CREATE TABLE statement for the jobs table.
/// Idempotent: uses IF NOT EXISTS.
pub const CREATE_JOBS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type varchar NOT NULL,
    payload jsonb NOT NULL,
    dedup_key varchar,
    status varchar NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    attempts int NOT NULL DEFAULT 0,
    max_attempts int NOT NULL DEFAULT 3,
    priority int NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    claimed_by varchar,
    claimed_at timestamptz,
    started_at timestamptz,
    finished_at timestamptz,
    heartbeat_at timestamptz,
    next_attempt_at timestamptz,
    last_error text,
    result jsonb,
    run_at timestamptz
)
"#;

/// Dedup index: partial unique constraint on (job_type, dedup_key).
/// Only applies to pending/running jobs, allowing completed/failed jobs to be re-enqueued.
pub const CREATE_DEDUP_INDEX: &str = r#"
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_dedup
ON jobs (job_type, dedup_key)
WHERE status IN ('pending', 'running') AND dedup_key IS NOT NULL
"#;

/// Claim index: for fast retrieval of next pending job by job_type/priority/creation order.
/// Used by the claim query: SELECT ... WHERE status='pending' AND job_type=ANY(...) ORDER BY priority, created_at.
pub const CREATE_CLAIM_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS idx_jobs_claim
ON jobs (status, job_type, priority, created_at)
"#;

/// Heartbeat/reaper index: for finding stale running jobs.
/// Used by maintenance queries: SELECT ... WHERE status='running' AND heartbeat_at < now() - interval '5 minutes'.
pub const CREATE_HEARTBEAT_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS idx_jobs_heartbeat
ON jobs (status, heartbeat_at)
"#;

/// Utility function to compute exponential backoff delay (in seconds).
/// Formula: min(cap, 2^attempts + jitter)
/// where jitter ∈ [0, 2^attempts).
/// This is a pure-logic function (no DB interaction).
pub fn exponential_backoff_seconds(attempts: i32, cap_seconds: i32) -> i32 {
    use rand::Rng;

    // Clamp attempts to reasonable bounds (avoid overflow)
    let attempts = attempts.min(30);

    // 2^attempts, capped at cap_seconds
    let base = 2_i32.pow(attempts as u32).min(cap_seconds);

    // Add jitter: random value in [0, base)
    let mut rng = rand::thread_rng();
    let jitter = if base > 0 { rng.gen_range(0..base) } else { 0 };

    (base + jitter).min(cap_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_backoff_is_monotonic() {
        // Each attempt should have a delay >= previous attempt
        let mut prev_min = 0;
        for attempts in 0..10 {
            let delay = exponential_backoff_seconds(attempts, 600);
            assert!(delay >= prev_min, "backoff should be monotonic");
            prev_min = delay;
        }
    }

    #[test]
    fn exponential_backoff_respects_cap() {
        let cap = 300;
        for attempts in 0..20 {
            let delay = exponential_backoff_seconds(attempts, cap);
            assert!(delay <= cap, "backoff should not exceed cap");
        }
    }

    #[test]
    fn exponential_backoff_includes_jitter() {
        // Jitter should prevent all retries from being at exactly the same time.
        // With random jitter, the result should be within [base, 2*base) for attempts=3.
        // base = 2^3 = 8, so result should be in [8, 16).
        let delay_1 = exponential_backoff_seconds(3, 600);
        assert!(
            (8..16).contains(&delay_1),
            "backoff(3) with jitter should be in range [8, 16), got {}",
            delay_1
        );
    }

    #[test]
    fn exponential_backoff_0_attempts() {
        let delay = exponential_backoff_seconds(0, 600);
        assert_eq!(delay, 1, "backoff(0) should be 1 second");
    }

    #[test]
    fn exponential_backoff_large_attempts() {
        let delay = exponential_backoff_seconds(100, 600);
        assert!(
            delay <= 600,
            "backoff with large attempts should respect cap"
        );
    }
}
