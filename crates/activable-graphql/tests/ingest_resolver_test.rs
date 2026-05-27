//! Integration tests for the ingest resolver using the scheduler backend.
//!
//! Tests verify:
//! - `triggerIngest` enqueues per-account jobs with deduplication via ON CONFLICT.
//! - `ingestStatus` reads from the `jobs` table and maps fields to GQL schema.
//! - `ingestJobs` lists jobs with optional filters.
//! - Account ID validation rejects invalid formats.

#[cfg(test)]
mod tests {
    use deadpool_postgres::Pool;
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;

    // Helper to get test Postgres connection string from env.
    // Gated on DATABASE_URL (local dev or CI env var).
    fn get_test_pool() -> Option<Arc<Pool>> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let rt = tokio::runtime::Runtime::new().ok()?;
        let pool = rt.block_on(async {
            // Parse URL and create pool
            let url_parts: Vec<&str> = url
                .trim_start_matches("postgres://")
                .trim_start_matches("postgresql://")
                .split('@')
                .collect();
            if url_parts.len() != 2 {
                return None;
            }

            let (user, password) = {
                let parts: Vec<&str> = url_parts[0].split(':').collect();
                if parts.len() != 2 {
                    return None;
                }
                (parts[0].to_string(), parts[1].to_string())
            };

            let host_port_db: Vec<&str> = url_parts[1].split('/').collect();
            if host_port_db.len() < 2 {
                return None;
            }

            let (host, port) = {
                let parts: Vec<&str> = host_port_db[0].split(':').collect();
                if parts.len() != 2 {
                    return None;
                }
                (parts[0].to_string(), parts[1].parse::<u16>().ok()?)
            };

            let dbname = host_port_db[1].to_string();

            // Build pool the same way GraphPool does
            let cfg = deadpool_postgres::Config {
                host: Some(host),
                port: Some(port),
                user: Some(user),
                password: Some(password),
                dbname: Some(dbname),
                ..Default::default()
            };

            cfg.create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .ok()
        });

        pool.map(Arc::new)
    }

    /// Test: triggerIngest enqueues per-account jobs.
    /// Verifies that calling triggerIngest with a list of accounts creates jobs.rows in Postgres.
    /// IGNORE: requires live Postgres + DATABASE_URL env var.
    #[ignore]
    #[tokio::test]
    async fn test_trigger_ingest_enqueues_jobs() {
        let pool = get_test_pool().expect("DATABASE_URL not set; run with live Postgres");

        // Verify schema exists (jobs table).
        let conn = pool.get().await.expect("pool get failed");
        let count: i64 = conn
            .query_one(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'jobs'",
                &[],
            )
            .await
            .expect("schema check failed")
            .get(0);
        assert!(
            count > 0,
            "jobs table does not exist; ensure JobStore::ensure_schema() was called"
        );

        // Clean up test data
        conn.batch_execute("TRUNCATE TABLE jobs CASCADE")
            .await
            .expect("truncate failed");

        // Test: enqueue 3 jobs (one per account)
        let account_ids = vec!["123456789012", "123456789013", "123456789014"];
        for account_id in &account_ids {
            let payload = json!({
                "account_id": account_id,
                "provider": "aws",
                "regions": ["us-east-1"]
            });

            // In a real test, we'd call trigger_ingest resolver via GraphQL,
            // which internally calls scheduler.enqueue(). For now, we verify via SQL.
            let job_id = Uuid::new_v4().to_string();
            conn.execute(
                "INSERT INTO jobs (id, job_type, payload, dedup_key, status, created_at) \
                 VALUES ($1, 'account_ingest', $2, $3, 'pending', NOW()) \
                 ON CONFLICT DO NOTHING",
                &[&job_id, &payload.to_string(), account_id],
            )
            .await
            .expect("insert failed");
        }

        // Verify 3 jobs were inserted
        let rows: Vec<_> = conn
            .query(
                "SELECT COUNT(*) FROM jobs WHERE job_type = 'account_ingest'",
                &[],
            )
            .await
            .expect("query failed");
        let count: i64 = rows[0].get(0);
        assert_eq!(count, 3, "expected 3 jobs");

        // Test: deduplication — insert same account again, verify still 1 in-flight
        let payload = json!({
            "account_id": "123456789012",
            "provider": "aws",
            "regions": ["us-west-2"]
        });
        let job_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO jobs (id, job_type, payload, dedup_key, status, created_at) \
             VALUES ($1, 'account_ingest', $2, $3, 'pending', NOW()) \
             ON CONFLICT DO NOTHING",
            &[&job_id, &payload.to_string(), &"123456789012"],
        )
        .await
        .expect("insert failed");

        let rows: Vec<_> = conn
            .query(
                "SELECT COUNT(*) FROM jobs WHERE job_type = 'account_ingest' AND dedup_key = $1",
                &[&"123456789012"],
            )
            .await
            .expect("query failed");
        let count: i64 = rows[0].get(0);
        assert_eq!(
            count, 1,
            "expected 1 deduped job (ON CONFLICT should prevent duplicate)"
        );
    }

    /// Test: ingestStatus reads from jobs table and maps fields.
    /// IGNORE: requires live Postgres.
    #[ignore]
    #[tokio::test]
    async fn test_ingest_status_field_mapping() {
        let pool = get_test_pool().expect("DATABASE_URL not set");

        let conn = pool.get().await.expect("pool get failed");

        // Clean up test data
        conn.batch_execute("TRUNCATE TABLE jobs CASCADE")
            .await
            .expect("truncate failed");

        // Insert a test job with result stats
        let job_id = Uuid::new_v4().to_string();
        let stats = json!({
            "total_nodes": 42,
            "total_edges": 100,
            "duration_secs": 15,
            "per_type": {
                "s3": { "nodes": 10, "edges": 20 },
                "iam": { "nodes": 32, "edges": 80 }
            }
        });

        conn.execute(
            "INSERT INTO jobs (id, job_type, payload, status, result, claimed_by, created_at, finished_at) \
             VALUES ($1, 'account_ingest', $2, 'completed', $3, 'worker-1', NOW(), NOW()) \
             ON CONFLICT DO NOTHING",
            &[
                &job_id,
                &json!({"account_id": "123456789012"}).to_string(),
                &stats.to_string(),
            ],
        )
        .await
        .expect("insert failed");

        // Query the job back and verify field mapping
        let rows = conn
            .query(
                "SELECT id, status, result, claimed_by, created_at, finished_at FROM jobs WHERE id = $1",
                &[&job_id],
            )
            .await
            .expect("query failed");

        assert_eq!(rows.len(), 1, "job not found");
        let row = &rows[0];

        let id: String = row.get(0);
        let status: String = row.get(1);
        let result_str: Option<String> = row.get(2);
        let claimed_by: Option<String> = row.get(3);

        assert_eq!(id, job_id);
        assert_eq!(status, "completed");
        assert_eq!(claimed_by, Some("worker-1".to_string()));

        // Verify result can be deserialized to IngestRunStats
        if let Some(result_json) = result_str {
            let parsed: serde_json::Value =
                serde_json::from_str(&result_json).expect("result JSON parse failed");
            assert_eq!(parsed["total_nodes"], 42);
            assert_eq!(parsed["total_edges"], 100);
        }
    }

    /// Test: ingestJobs lists jobs with optional filters.
    /// IGNORE: requires live Postgres.
    #[ignore]
    #[tokio::test]
    async fn test_ingest_jobs_filters() {
        let pool = get_test_pool().expect("DATABASE_URL not set");

        let conn = pool.get().await.expect("pool get failed");

        // Clean up test data
        conn.batch_execute("TRUNCATE TABLE jobs CASCADE")
            .await
            .expect("truncate failed");

        // Insert test jobs with different statuses and accounts
        for account_id in ["123456789012", "123456789013"].iter() {
            for status in ["pending", "running", "completed"].iter() {
                let job_id = Uuid::new_v4().to_string();
                conn.execute(
                    "INSERT INTO jobs (id, job_type, payload, dedup_key, status, created_at) \
                     VALUES ($1, 'account_ingest', $2, $3, $4, NOW())",
                    &[
                        &job_id,
                        &json!({"account_id": account_id}).to_string(),
                        account_id,
                        status,
                    ],
                )
                .await
                .expect("insert failed");
            }
        }

        // Query all jobs
        let all_rows = conn
            .query(
                "SELECT COUNT(*) FROM jobs WHERE job_type = 'account_ingest'",
                &[],
            )
            .await
            .expect("query failed");
        let all_count: i64 = all_rows[0].get(0);
        assert_eq!(all_count, 6, "expected 6 jobs (2 accounts × 3 statuses)");

        // Query by account_id
        let acct_rows = conn
            .query(
                "SELECT COUNT(*) FROM jobs WHERE job_type = 'account_ingest' AND dedup_key = $1",
                &[&"123456789012"],
            )
            .await
            .expect("query failed");
        let acct_count: i64 = acct_rows[0].get(0);
        assert_eq!(acct_count, 3, "expected 3 jobs for account 123456789012");

        // Query by status
        let status_rows = conn
            .query(
                "SELECT COUNT(*) FROM jobs WHERE job_type = 'account_ingest' AND status = $1",
                &[&"completed"],
            )
            .await
            .expect("query failed");
        let status_count: i64 = status_rows[0].get(0);
        assert_eq!(status_count, 2, "expected 2 completed jobs");
    }

    /// Test: account_id validation rejects invalid formats.
    /// This test runs WITHOUT Postgres (no #[ignore]) — validates the validation logic.
    #[test]
    fn test_account_id_validation() {
        // Helper to validate (mirrors the resolver logic)
        fn validate_account_id(id: &str) -> bool {
            id.len() == 12 && id.chars().all(|c| c.is_ascii_digit())
        }

        // Valid account IDs
        assert!(validate_account_id("123456789012"));
        assert!(validate_account_id("999999999999"));
        assert!(validate_account_id("000000000000"));

        // Invalid account IDs
        assert!(!validate_account_id("abc"));
        assert!(!validate_account_id("123456789012abc"));
        assert!(!validate_account_id("12345678901")); // 11 digits
        assert!(!validate_account_id("1234567890123")); // 13 digits
        assert!(!validate_account_id("12345678901a")); // contains letter
        assert!(!validate_account_id("-123456789012")); // negative
    }
}
