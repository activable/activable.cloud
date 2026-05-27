# activable-scheduler

A generic, Postgres-backed job queue for event-driven scheduling.

## Features

- **Atomic enqueue with deduplication**: `ON CONFLICT` prevents duplicate jobs with the same `(job_type, dedup_key)` in pending/running state.
- **HA-safe claim**: `FOR UPDATE SKIP LOCKED` ensures concurrent workers never claim the same job.
- **Exponential backoff retry**: Failed jobs can be re-queued with exponential backoff up to a configurable maximum.
- **Type-erased payloads**: Jobs store arbitrary `serde_json::Value` payloads and results.
- **Minimal schema**: Single `jobs` table + 4 indexes; idempotent initialization via `IF NOT EXISTS`.

## API

### `enqueue(job_type, payload, dedup_key?, priority, max_attempts)`
Enqueue a new job. Returns `Some(job_id)` on success, or `None` if dedup blocked the insert.

```rust,ignore
let job_id = store
    .enqueue(
        "process_email",
        &serde_json::json!({"email": "user@example.com"}),
        Some("user@example.com"),  // dedup_key (optional)
        0,  // priority
        3,  // max_attempts
    )
    .await?;
```

### `claim(job_types, worker_id, poll_ms)`
Claim the next pending job for the given job types. Returns `Some(job)` or `None`.

```rust,ignore
let job = store
    .claim(
        &["process_email".to_string(), "send_notification".to_string()],
        "worker_1",
        0,  // poll_ms (reserved for future poling)
    )
    .await?;
```

### `complete(job_id, result)`
Mark a job as completed with a result.

```rust,ignore
store
    .complete(job_id, &serde_json::json!({"sent": true, "message_id": "123"}))
    .await?;
```

### `fail(job_id, error, retryable)`
Mark a job as failed. If `retryable=true` and attempts < max_attempts, re-queues with backoff.

```rust,ignore
store
    .fail(job_id, "connection timeout", true)
    .await?;
```

### `ensure_schema()`
Initialize the schema (table + indexes). Idempotent; safe to call on every startup.

```rust,ignore
store.ensure_schema().await?;
```

## Schema

```sql
CREATE TABLE jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type varchar NOT NULL,
    payload jsonb NOT NULL,
    dedup_key varchar,
    status varchar CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    attempts int DEFAULT 0,
    max_attempts int DEFAULT 3,
    priority int DEFAULT 0,
    created_at timestamp DEFAULT now(),
    claimed_by varchar,
    claimed_at timestamp,
    started_at timestamp,
    finished_at timestamp,
    heartbeat_at timestamp,
    next_attempt_at timestamp,
    last_error text,
    result jsonb,
    run_at timestamp  -- reserved for future cron scheduling
);

-- Dedup index (partial): only applies to pending/running jobs
CREATE UNIQUE INDEX idx_jobs_dedup
ON jobs (job_type, dedup_key)
WHERE status IN ('pending', 'running') AND dedup_key IS NOT NULL;

-- Claim index: fast lookup for next job by type/priority/creation
CREATE INDEX idx_jobs_claim
ON jobs (status, job_type, priority, created_at);

-- Heartbeat/reaper index: find stale running jobs
CREATE INDEX idx_jobs_heartbeat
ON jobs (status, heartbeat_at);
```

## Design Notes

- **Partial unique index on dedup**: Completed/failed jobs are automatically excluded from the uniqueness constraint, allowing the same dedup key to be re-enqueued.
- **FOR UPDATE SKIP LOCKED**: Ensures HA safety without explicit row-level locks. Workers atomically claim the next job in a single statement.
- **Exponential backoff**: `2^attempts + jitter`, capped at 600s. Prevents thundering herd on retries.
- **Type-erased payloads**: Scheduler crate has zero domain knowledge; payloads are `serde_json::Value`.
- **Zero domain coupling**: This crate is generic and reusable across any event stream (ingest, graph processing, notifications, etc.).

## Testing

Run DB tests with DATABASE_URL set:

```bash
DATABASE_URL="postgres://user:pass@localhost:5432/activable" cargo test --test store_test -- --test-threads 1
```

Tests gate on the env var; if DATABASE_URL is not set, tests skip cleanly.

Run pure-logic unit tests (no DB):

```bash
cargo test --lib
```

Expected coverage: ≥98% branch on store + model modules.

## Examples

See `tests/store_test.rs` for full integration test examples.
