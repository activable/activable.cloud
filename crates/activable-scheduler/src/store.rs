use crate::model::{Job, JobStatus, SchedulerError};
use crate::schema::{
    CREATE_CLAIM_INDEX, CREATE_DEDUP_INDEX, CREATE_HEARTBEAT_INDEX, CREATE_JOBS_TABLE,
};
use chrono::Utc;
use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use std::sync::Arc;
use tokio_postgres::NoTls;
use uuid::Uuid;

/// Configuration for connecting to the Postgres backend.
#[derive(Debug, Clone)]
pub struct JobStoreConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub dbname: String,
    pub pool_size: usize,
    pub backoff_base_seconds: f64,
}

impl JobStoreConfig {
    /// Parse a connection URL in format: postgres://user:password@host:port/dbname or postgresql://user:password@host:port/dbname
    pub fn from_url(url: &str) -> Result<Self, SchedulerError> {
        let url_str = if let Some(s) = url.strip_prefix("postgres://") {
            s
        } else if let Some(s) = url.strip_prefix("postgresql://") {
            s
        } else {
            return Err(SchedulerError::Database(
                "URL must start with postgres:// or postgresql://".to_string(),
            ));
        };

        let (auth, rest) = url_str
            .split_once('@')
            .ok_or_else(|| SchedulerError::Database("URL must contain @".to_string()))?;

        let (user, password) = auth
            .split_once(':')
            .ok_or_else(|| SchedulerError::Database("auth section must contain :".to_string()))?;

        let (host_port, dbname) = rest
            .split_once('/')
            .ok_or_else(|| SchedulerError::Database("URL must contain /".to_string()))?;

        let (host, port_str) = host_port.split_once(':').unwrap_or((host_port, "5432"));
        let port: u16 = port_str
            .parse()
            .map_err(|_| SchedulerError::Database(format!("invalid port: {}", port_str)))?;

        Ok(JobStoreConfig {
            host: host.to_string(),
            port,
            user: user.to_string(),
            password: password.to_string(),
            dbname: dbname.to_string(),
            pool_size: 16,
            backoff_base_seconds: 2.0,
        })
    }
}

/// JobStore is the main interface for interacting with the jobs queue.
/// All SQL is parameterized (no string interpolation of values).
pub struct JobStore {
    pool: Arc<Pool>,
    backoff_base_seconds: f64,
}

impl JobStore {
    /// Create a new JobStore from configuration.
    pub async fn new(config: JobStoreConfig) -> Result<Self, SchedulerError> {
        let mut cfg = Config::new();
        cfg.host = Some(config.host);
        cfg.port = Some(config.port);
        cfg.user = Some(config.user);
        cfg.password = Some(config.password);
        cfg.dbname = Some(config.dbname);

        cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Clean,
        });

        let pool = cfg
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .map_err(|e| SchedulerError::Pool(format!("Failed to create pool: {}", e)))?;

        Ok(JobStore {
            pool: Arc::new(pool),
            backoff_base_seconds: config.backoff_base_seconds,
        })
    }

    /// Initialize the schema (create table and indexes).
    /// Idempotent: safe to call multiple times.
    pub async fn ensure_schema(&self) -> Result<(), SchedulerError> {
        let conn = self.pool.get().await?;

        // Advisory lock constant (derived from 'activable_scheduler_schema').
        // All concurrent ensure_schema() calls will serialize on this lock,
        // making CREATE TABLE/INDEX IF NOT EXISTS safe.
        const SCHEMA_LOCK_ID: i64 = 1234567890123456789_i64;

        // Begin transaction and acquire advisory lock.
        conn.batch_execute("BEGIN")
            .await
            .map_err(|e| SchedulerError::SchemaInit(format!("BEGIN failed: {}", e)))?;

        conn.batch_execute(&format!("SELECT pg_advisory_xact_lock({})", SCHEMA_LOCK_ID))
            .await
            .map_err(|e| SchedulerError::SchemaInit(format!("advisory lock failed: {}", e)))?;

        // Execute all DDL statements within the locked transaction.
        conn.batch_execute(CREATE_JOBS_TABLE)
            .await
            .map_err(|e| SchedulerError::SchemaInit(format!("CREATE TABLE failed: {}", e)))?;

        conn.batch_execute(CREATE_DEDUP_INDEX)
            .await
            .map_err(|e| SchedulerError::SchemaInit(format!("CREATE DEDUP INDEX failed: {}", e)))?;

        conn.batch_execute(CREATE_CLAIM_INDEX)
            .await
            .map_err(|e| SchedulerError::SchemaInit(format!("CREATE CLAIM INDEX failed: {}", e)))?;

        conn.batch_execute(CREATE_HEARTBEAT_INDEX)
            .await
            .map_err(|e| {
                SchedulerError::SchemaInit(format!("CREATE HEARTBEAT INDEX failed: {}", e))
            })?;

        // Commit transaction (advisory lock is released at end of transaction).
        conn.batch_execute("COMMIT")
            .await
            .map_err(|e| SchedulerError::SchemaInit(format!("COMMIT failed: {}", e)))?;

        Ok(())
    }

    /// Enqueue a new job.
    /// If `dedup_key` is provided and a pending/running job with the same (job_type, dedup_key) exists,
    /// returns None (silent dedup). Otherwise, returns the new job ID.
    pub async fn enqueue(
        &self,
        job_type: &str,
        payload: &serde_json::Value,
        dedup_key: Option<&str>,
        priority: i32,
        max_attempts: i32,
    ) -> Result<Option<Uuid>, SchedulerError> {
        let conn = self.pool.get().await?;

        // INSERT ... ON CONFLICT ... DO NOTHING RETURNING id
        // The ON CONFLICT clause matches the partial unique index on (job_type, dedup_key)
        // where status IN ('pending', 'running') AND dedup_key IS NOT NULL.
        let query = r#"
            INSERT INTO jobs (job_type, payload, dedup_key, status, attempts, max_attempts, priority, created_at)
            VALUES ($1, $2, $3, 'pending', 0, $4, $5, now())
            ON CONFLICT (job_type, dedup_key) WHERE status IN ('pending', 'running') AND dedup_key IS NOT NULL
            DO NOTHING
            RETURNING id
        "#;

        let rows = conn
            .query(
                query,
                &[&job_type, &payload, &dedup_key, &max_attempts, &priority],
            )
            .await?;

        Ok(rows.first().map(|row| row.get::<_, Uuid>(0)))
    }

    /// Claim the next pending job for the given job types.
    /// Returns the first available pending job (by priority, then created_at).
    /// Marks it as running and increments attempts.
    /// Uses FOR UPDATE SKIP LOCKED to ensure HA safety: concurrent claims never return the same job.
    pub async fn claim(
        &self,
        job_types: &[String],
        worker_id: &str,
        _poll_ms: u64,
    ) -> Result<Option<Job>, SchedulerError> {
        let conn = self.pool.get().await?;

        // UPDATE ... WHERE id = (SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1)
        // The inner SELECT locks the chosen row; SKIP LOCKED skips locked rows.
        // Concurrent workers never pick the same job.
        let query = r#"
            UPDATE jobs
            SET status = 'running', claimed_by = $1, claimed_at = now(), started_at = now(),
                attempts = attempts + 1, heartbeat_at = now()
            WHERE id = (
                SELECT id FROM jobs
                WHERE status = 'pending'
                  AND job_type = ANY($2)
                  AND (next_attempt_at IS NULL OR next_attempt_at <= now())
                ORDER BY priority ASC, created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING id, job_type, payload, dedup_key, status, attempts, max_attempts, priority,
                      created_at, claimed_by, claimed_at, started_at, finished_at, heartbeat_at,
                      next_attempt_at, last_error, result, run_at
        "#;

        let rows = conn.query(query, &[&worker_id, &job_types]).await?;

        match rows.first() {
            Some(row) => self.parse_job_row(row).map(Some),
            None => Ok(None),
        }
    }

    /// Mark a job as completed with the given result.
    pub async fn complete(
        &self,
        id: Uuid,
        result: &serde_json::Value,
    ) -> Result<Job, SchedulerError> {
        let conn = self.pool.get().await?;

        let query = r#"
            UPDATE jobs
            SET status = 'completed', result = $1, finished_at = now()
            WHERE id = $2
            RETURNING id, job_type, payload, dedup_key, status, attempts, max_attempts, priority,
                      created_at, claimed_by, claimed_at, started_at, finished_at, heartbeat_at,
                      next_attempt_at, last_error, result, run_at
        "#;

        let rows = conn.query(query, &[&result, &id]).await?;

        rows.first()
            .map(|row| self.parse_job_row(row))
            .ok_or(SchedulerError::NotFound(id))?
    }

    /// Mark a job as failed.
    /// If retryable=true and attempts < max_attempts, atomically updates status to pending with next_attempt_at set.
    /// Otherwise, marks the job as failed and sets finished_at.
    /// Uses atomic SQL CASE statement to prevent TOCTOU races with concurrent complete/fail operations.
    pub async fn fail(
        &self,
        id: Uuid,
        error: &str,
        retryable: bool,
    ) -> Result<Job, SchedulerError> {
        let conn = self.pool.get().await?;

        // Exponential backoff with jitter: base * 2^attempts + random*base, capped at 3600s.
        // $3 is the base backoff in seconds (double precision), configurable via JobStoreConfig.
        let base_backoff_seconds = self.backoff_base_seconds;

        let query = r#"
            UPDATE jobs
            SET status = CASE
                    WHEN status = 'running' AND $2::boolean AND attempts < max_attempts
                    THEN 'pending'
                    WHEN status = 'running' THEN 'failed'
                    ELSE status
                END,
                next_attempt_at = CASE
                    WHEN status = 'running' AND $2::boolean AND attempts < max_attempts
                    THEN now() + make_interval(secs => LEAST($3::double precision * power(2, attempts::double precision) + random() * $3::double precision, 3600))
                    ELSE next_attempt_at
                END,
                last_error = $1,
                finished_at = CASE
                    WHEN status = 'running' AND (NOT $2::boolean OR attempts >= max_attempts)
                    THEN now()
                    ELSE finished_at
                END
            WHERE id = $4 AND status = 'running'
            RETURNING id, job_type, payload, dedup_key, status, attempts, max_attempts, priority,
                      created_at, claimed_by, claimed_at, started_at, finished_at, heartbeat_at,
                      next_attempt_at, last_error, result, run_at
        "#;

        let rows = conn
            .query(query, &[&error, &retryable, &base_backoff_seconds, &id])
            .await?;

        match rows.first() {
            Some(row) => self.parse_job_row(row),
            None => Err(SchedulerError::NotFound(id)),
        }
    }

    /// Parse a row from the jobs table into a Job struct.
    fn parse_job_row(&self, row: &tokio_postgres::Row) -> Result<Job, SchedulerError> {
        let id: Uuid = row.try_get(0)?;
        let job_type: String = row.try_get(1)?;
        let payload: serde_json::Value = row.try_get(2)?;
        let dedup_key: Option<String> = row.try_get(3)?;
        let status_str: String = row.try_get(4)?;
        let attempts: i32 = row.try_get(5)?;
        let max_attempts: i32 = row.try_get(6)?;
        let priority: i32 = row.try_get(7)?;
        let created_at: chrono::DateTime<Utc> = row.try_get(8)?;
        let claimed_by: Option<String> = row.try_get(9)?;
        let claimed_at: Option<chrono::DateTime<Utc>> = row.try_get(10)?;
        let started_at: Option<chrono::DateTime<Utc>> = row.try_get(11)?;
        let finished_at: Option<chrono::DateTime<Utc>> = row.try_get(12)?;
        let heartbeat_at: Option<chrono::DateTime<Utc>> = row.try_get(13)?;
        let next_attempt_at: Option<chrono::DateTime<Utc>> = row.try_get(14)?;
        let last_error: Option<String> = row.try_get(15)?;
        let result: Option<serde_json::Value> = row.try_get(16)?;
        let run_at: Option<chrono::DateTime<Utc>> = row.try_get(17)?;

        let status = JobStatus::from_sql_str(&status_str)
            .ok_or_else(|| SchedulerError::RowParse(format!("invalid status: {}", status_str)))?;

        Ok(Job {
            id,
            job_type,
            payload,
            dedup_key,
            status,
            attempts,
            max_attempts,
            priority,
            created_at,
            claimed_by,
            claimed_at,
            started_at,
            finished_at,
            heartbeat_at,
            next_attempt_at,
            last_error,
            result,
            run_at,
        })
    }

    /// Update the heartbeat timestamp for a running job.
    /// Sets heartbeat_at = now() if the job is currently running.
    /// No-op if job is not running (safe to call when job status changes).
    /// Uses the idx_jobs_heartbeat index for fast lookup.
    pub async fn update_heartbeat(&self, id: Uuid) -> Result<(), SchedulerError> {
        let conn = self.pool.get().await?;

        let query = r#"
            UPDATE jobs
            SET heartbeat_at = now()
            WHERE id = $1 AND status = 'running'
        "#;

        conn.execute(query, &[&id]).await?;

        Ok(())
    }

    /// Find all running jobs with stale heartbeat (heartbeat_at < now() - threshold_seconds).
    /// Returns a list of job IDs for jobs matching the given job_types and stale threshold.
    /// Uses the idx_jobs_heartbeat index for efficient queries.
    pub async fn find_stale_running(
        &self,
        job_types: &[String],
        threshold_seconds: i64,
    ) -> Result<Vec<Uuid>, SchedulerError> {
        let conn = self.pool.get().await?;

        let query = r#"
            SELECT id FROM jobs
            WHERE status = 'running'
              AND job_type = ANY($1::text[])
              AND heartbeat_at < now() - make_interval(secs => $2::double precision)
        "#;

        // tokio_postgres requires proper parameter types; convert to vector of string references
        let job_types_vec: Vec<&str> = job_types.iter().map(|s| s.as_str()).collect();

        let rows = conn
            .query(query, &[&job_types_vec, &(threshold_seconds as f64)])
            .await?;

        Ok(rows.iter().map(|row| row.get(0)).collect())
    }

    /// Provide access to the underlying Postgres pool.
    /// Intended for testing. Do not use in production code.
    pub fn pool(&self) -> &Arc<Pool> {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_url_valid() {
        let url = "postgres://user:pass@localhost:5432/mydb";
        let config = JobStoreConfig::from_url(url).unwrap();
        assert_eq!(config.user, "user");
        assert_eq!(config.password, "pass");
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.dbname, "mydb");
    }

    #[test]
    fn config_from_url_default_port() {
        let url = "postgres://user:pass@localhost/mydb";
        let config = JobStoreConfig::from_url(url).unwrap();
        assert_eq!(config.port, 5432);
    }

    #[test]
    fn config_from_url_invalid_missing_auth() {
        let url = "postgres://localhost:5432/mydb";
        assert!(JobStoreConfig::from_url(url).is_err());
    }

    #[test]
    fn config_from_url_postgresql_scheme() {
        let url = "postgresql://user:pass@localhost:5432/mydb";
        let config = JobStoreConfig::from_url(url).unwrap();
        assert_eq!(config.user, "user");
        assert_eq!(config.password, "pass");
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.dbname, "mydb");
    }

    #[test]
    fn config_from_url_postgresql_scheme_default_port() {
        let url = "postgresql://user:pass@localhost/mydb";
        let config = JobStoreConfig::from_url(url).unwrap();
        assert_eq!(config.port, 5432);
    }

    #[test]
    fn config_from_url_invalid_scheme() {
        let url = "mysql://user:pass@localhost:5432/mydb";
        assert!(JobStoreConfig::from_url(url).is_err());
    }
}
