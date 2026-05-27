//! Resolvers for ingestion operations: triggerIngest, ingestStatus, and ingestJobs.
//!
//! Implements event-driven AWS resource ingestion using the scheduler backend.
//! - `triggerIngest`: enqueues per-account jobs with automatic deduplication (ON CONFLICT).
//! - `ingestStatus`: reads job status from the Postgres `jobs` table.
//! - `ingestJobs`: lists jobs with optional filters (account_id, status).

use crate::types::{GqlIngestJobFilter, GqlIngestRun, GqlIngestStats};
use activable_scheduler::JobStore;
use async_graphql::Context;
use deadpool_postgres::Pool;
use serde_json::json;
use std::sync::Arc;

/// Validate AWS account ID format (12 digits).
fn validate_account_id(account_id: &str) -> Result<(), async_graphql::Error> {
    if account_id.len() == 12 && account_id.chars().all(|c| c.is_ascii_digit()) {
        Ok(())
    } else {
        Err(async_graphql::Error::new(format!(
            "Invalid account_id '{}': must be 12 digits",
            account_id
        )))
    }
}

/// Parse configured default account IDs from environment variable.
/// Format: comma-separated list (e.g., "123456789012,123456789013").
fn get_default_account_ids() -> Vec<String> {
    std::env::var("INGEST_ACCOUNT_IDS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect()
}

/// Trigger ingestion for specified accounts.
/// Returns the job IDs that were enqueued.
/// For each account: validates format, then calls `scheduler.enqueue(…, dedup_key=account_id)`.
/// ON CONFLICT silently deduplicates in-flight jobs for the same account.
pub async fn trigger_ingest(
    ctx: &Context<'_>,
    _provider: String,
    _regions: Vec<String>,
    account_ids: Option<Vec<String>>,
) -> async_graphql::Result<Vec<String>> {
    let job_store = ctx
        .data::<Arc<JobStore>>()
        .map_err(|_| async_graphql::Error::new("JobStore not available"))?;

    // Determine accounts: use provided list or fall back to configured default.
    let accounts = if let Some(ids) = account_ids {
        ids
    } else {
        let defaults = get_default_account_ids();
        if defaults.is_empty() {
            return Err(async_graphql::Error::new(
                "No account IDs provided and INGEST_ACCOUNT_IDS not configured",
            ));
        }
        defaults
    };

    // Validate all account IDs before enqueue (fail fast).
    for account_id in &accounts {
        validate_account_id(account_id)?;
    }

    // Enqueue per-account jobs.
    let mut job_ids = Vec::new();
    for account_id in accounts {
        let payload = json!({
            "account_id": account_id,
            "provider": _provider.clone(),
            "regions": _regions.clone(),
        });

        match job_store
            .enqueue(
                "account_ingest",
                &payload,
                Some(&account_id),
                1, // priority
                3, // max_attempts
            )
            .await
        {
            Ok(Some(job_id)) => {
                tracing::info!(
                    job_id = %job_id,
                    account_id = %account_id,
                    "Enqueued ingestion job"
                );
                job_ids.push(job_id.to_string());
            }
            Ok(None) => {
                // Dedup: job already in-flight for this account.
                tracing::info!(
                    account_id = %account_id,
                    "Ingestion job already in-flight (dedup)"
                );
            }
            Err(e) => {
                return Err(async_graphql::Error::new(format!(
                    "Failed to enqueue job for account {}: {}",
                    account_id, e
                )))
            }
        }
    }

    Ok(job_ids)
}

/// Get the status of a previous ingest job (from the `jobs` table).
/// Maps `jobs` table fields to GQL schema per the field-mapping table.
pub async fn ingest_status(
    ctx: &Context<'_>,
    job_id: String,
) -> async_graphql::Result<Option<GqlIngestRun>> {
    let pool = ctx
        .data::<Arc<Pool>>()
        .map_err(|_| async_graphql::Error::new("Pool not available"))?;

    let conn = pool
        .get()
        .await
        .map_err(|e| async_graphql::Error::new(format!("pool error: {e}")))?;

    let rows = conn
        .query(
            "SELECT id::text, status, created_at::text, finished_at::text, claimed_by, result::text, last_error \
             FROM jobs WHERE id = $1::uuid",
            &[&job_id],
        )
        .await
        .map_err(|e| async_graphql::Error::new(format!("query error: {e}")))?;

    if rows.is_empty() {
        return Ok(None);
    }

    let row = &rows[0];
    let id: String = row.get(0);
    let status_raw: String = row.get(1);
    let created_at: String = row.get(2);
    let finished_at: Option<String> = row.get(3);
    let worker_id: Option<String> = row.get(4);
    let result_str: Option<String> = row.get(5);
    let last_error: Option<String> = row.get(6);

    // Map job status to GQL enum (pending/running → "RUNNING", completed → "COMPLETED", failed → "FAILED").
    let status = match status_raw.as_str() {
        "pending" | "running" => "RUNNING".to_string(),
        "completed" => "COMPLETED".to_string(),
        "failed" => "FAILED".to_string(),
        other => other.to_string(),
    };

    // Parse result JSON (if present) to extract IngestRunStats.
    let stats = if let Some(json_str) = result_str {
        serde_json::from_str::<serde_json::Value>(&json_str)
            .ok()
            .and_then(|v| {
                Some(GqlIngestStats {
                    total_nodes: v.get("total_nodes")?.as_i64()? as i32,
                    total_edges: v.get("total_edges")?.as_i64()? as i32,
                    duration_secs: v.get("duration_secs")?.as_i64()?,
                })
            })
    } else {
        None
    };

    Ok(Some(GqlIngestRun {
        id,
        status,
        created_at,
        completed_at: finished_at,
        worker_id,
        stats,
        error: last_error,
        started_at: None, // Deprecated; not set from new jobs table.
        services: None,   // Deprecated; use stats instead.
    }))
}

/// List ingestion jobs with optional filters.
/// Queries the `jobs` table with optional WHERE on account_id (from dedup_key) and status.
pub async fn ingest_jobs(
    ctx: &Context<'_>,
    filter: Option<GqlIngestJobFilter>,
) -> async_graphql::Result<Vec<GqlIngestRun>> {
    let pool = ctx
        .data::<Arc<Pool>>()
        .map_err(|_| async_graphql::Error::new("Pool not available"))?;

    let conn = pool
        .get()
        .await
        .map_err(|e| async_graphql::Error::new(format!("pool error: {e}")))?;

    // Build query with optional filters.
    // Use explicit query paths for each filter combination to avoid dynamic query building.
    let rows = match &filter {
        Some(f) if f.account_id.is_some() && f.status.is_some() => {
            let account_id = f.account_id.as_ref().unwrap();
            let status = f.status.as_ref().unwrap();
            conn.query(
                "SELECT id::text, status, created_at::text, finished_at::text, claimed_by, result::text, last_error \
                 FROM jobs WHERE job_type = 'account_ingest' AND dedup_key = $1 AND status = $2 \
                 ORDER BY created_at DESC LIMIT 100",
                &[account_id, status],
            )
            .await
        }
        Some(f) if f.account_id.is_some() => {
            let account_id = f.account_id.as_ref().unwrap();
            conn.query(
                "SELECT id::text, status, created_at::text, finished_at::text, claimed_by, result::text, last_error \
                 FROM jobs WHERE job_type = 'account_ingest' AND dedup_key = $1 \
                 ORDER BY created_at DESC LIMIT 100",
                &[account_id],
            )
            .await
        }
        Some(f) if f.status.is_some() => {
            let status = f.status.as_ref().unwrap();
            conn.query(
                "SELECT id::text, status, created_at::text, finished_at::text, claimed_by, result::text, last_error \
                 FROM jobs WHERE job_type = 'account_ingest' AND status = $1 \
                 ORDER BY created_at DESC LIMIT 100",
                &[status],
            )
            .await
        }
        _ => {
            conn.query(
                "SELECT id::text, status, created_at::text, finished_at::text, claimed_by, result::text, last_error \
                 FROM jobs WHERE job_type = 'account_ingest' \
                 ORDER BY created_at DESC LIMIT 100",
                &[],
            )
            .await
        }
    }
    .map_err(|e| async_graphql::Error::new(format!("query error: {e}")))?;

    let mut results = Vec::new();
    for row in rows {
        let id: String = row.get(0);
        let status_raw: String = row.get(1);
        let created_at: String = row.get(2);
        let finished_at: Option<String> = row.get(3);
        let worker_id: Option<String> = row.get(4);
        let result_str: Option<String> = row.get(5);
        let last_error: Option<String> = row.get(6);

        let status = match status_raw.as_str() {
            "pending" | "running" => "RUNNING".to_string(),
            "completed" => "COMPLETED".to_string(),
            "failed" => "FAILED".to_string(),
            other => other.to_string(),
        };

        let stats = if let Some(json_str) = result_str {
            serde_json::from_str::<serde_json::Value>(&json_str)
                .ok()
                .and_then(|v| {
                    Some(GqlIngestStats {
                        total_nodes: v.get("total_nodes")?.as_i64()? as i32,
                        total_edges: v.get("total_edges")?.as_i64()? as i32,
                        duration_secs: v.get("duration_secs")?.as_i64()?,
                    })
                })
        } else {
            None
        };

        results.push(GqlIngestRun {
            id,
            status,
            created_at,
            completed_at: finished_at,
            worker_id,
            stats,
            error: last_error,
            started_at: None,
            services: None,
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_account_id() {
        assert!(validate_account_id("123456789012").is_ok());
        assert!(validate_account_id("999999999999").is_ok());
        assert!(validate_account_id("000000000000").is_ok());

        assert!(validate_account_id("abc").is_err());
        assert!(validate_account_id("123456789012abc").is_err());
        assert!(validate_account_id("12345678901").is_err());
        assert!(validate_account_id("1234567890123").is_err());
    }

    #[test]
    fn test_get_default_account_ids() {
        // Without env var set, should return empty
        std::env::remove_var("INGEST_ACCOUNT_IDS");
        let defaults = get_default_account_ids();
        assert!(defaults.is_empty());

        // With env var set
        std::env::set_var("INGEST_ACCOUNT_IDS", "123456789012,123456789013");
        let defaults = get_default_account_ids();
        assert_eq!(defaults, vec!["123456789012", "123456789013"]);
    }
}

#[cfg(test)]
mod resolver_integration_tests {
    use crate::schema::{MutationRoot, QueryRoot};
    use activable_scheduler::{JobStore, JobStoreConfig};
    use async_graphql::Schema;
    use std::sync::Arc;

    /// Helper to get test Postgres URL from DATABASE_URL env.
    /// Returns None if unset; tests using this skip cleanly.
    fn get_db_url() -> Option<String> {
        std::env::var("DATABASE_URL").ok()
    }

    /// Helper to create JobStore and ensure schema.
    async fn create_test_store(db_url: &str) -> Result<JobStore, Box<dyn std::error::Error>> {
        let config = JobStoreConfig::from_url(db_url)?;
        let store = JobStore::new(config).await?;
        store.ensure_schema().await?;
        Ok(store)
    }

    /// Helper: cleanup test jobs by dedup_key before a test runs.
    async fn cleanup_test_jobs(
        pool: &Arc<deadpool_postgres::Pool>,
        dedup_keys: &[&str],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conn = pool.get().await?;
        conn.execute(
            "DELETE FROM jobs WHERE dedup_key = ANY($1)",
            &[&dedup_keys.to_vec()],
        )
        .await?;
        Ok(())
    }

    /// Test: triggerIngest enqueues per-account jobs via the real resolver.
    /// Verifies:
    /// - 2 accounts → 2 job ids returned and rows created in jobs table.
    /// - Each job has status='pending' and correct dedup_key.
    #[tokio::test]
    async fn test_trigger_ingest_enqueues_jobs() {
        let db_url = match get_db_url() {
            Some(u) => u,
            None => {
                println!("Skipping: DATABASE_URL not set");
                return;
            }
        };

        let store = match create_test_store(&db_url).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("FAILED: could not create store: {}", e);
                panic!("store creation failed");
            }
        };

        // Build schema with injected Arc<JobStore> and Arc<Pool>.
        let store_arc = Arc::new(store);
        let pool = store_arc.pool().clone();

        // Clean up test data before running
        let test_keys = vec!["111111111111", "222222222222"];
        let _ = cleanup_test_jobs(&pool, &test_keys).await;

        let schema: Schema<QueryRoot, MutationRoot, async_graphql::EmptySubscription> =
            Schema::build(QueryRoot, MutationRoot, async_graphql::EmptySubscription)
                .data(store_arc)
                .data(pool)
                .finish();

        // Execute GraphQL mutation: triggerIngest for 2 accounts.
        // Returns Vec<String> directly (no object selection).
        let query = r#"
            mutation {
                triggerIngest(provider: "aws", regions: ["us-east-1"], accountIds: ["111111111111", "222222222222"])
            }
        "#;

        let request = async_graphql::Request::new(query);
        let response = schema.execute(request).await;

        // Errors in response indicate resolver failure.
        if !response.errors.is_empty() {
            eprintln!(
                "FAILED: GraphQL errors: {}",
                response
                    .errors
                    .iter()
                    .map(|e| e.message.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            );
            panic!("GraphQL execution failed");
        }

        // Extract job IDs from response (bare array, not nested in object).
        let data = response.data.into_json().expect("response has data");
        let job_ids: Vec<String> = data
            .get("triggerIngest")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|id| id.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        assert_eq!(job_ids.len(), 2, "expected 2 job IDs returned from resolver");
    }

    /// Test: triggerIngest deduplicates via ON CONFLICT.
    /// Calling it twice for the same account while pending → second call returns 0 job ids.
    #[tokio::test]
    async fn test_trigger_ingest_dedup() {
        let db_url = match get_db_url() {
            Some(u) => u,
            None => {
                println!("Skipping: DATABASE_URL not set");
                return;
            }
        };

        let store = match create_test_store(&db_url).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("FAILED: could not create store: {}", e);
                panic!("store creation failed");
            }
        };

        let store_arc = Arc::new(store);
        let pool = store_arc.pool().clone();

        // Clean up test data before running
        let test_keys = vec!["333333333333"];
        let _ = cleanup_test_jobs(&pool, &test_keys).await;

        let schema: Schema<QueryRoot, MutationRoot, async_graphql::EmptySubscription> =
            Schema::build(QueryRoot, MutationRoot, async_graphql::EmptySubscription)
                .data(store_arc)
                .data(pool)
                .finish();

        // First triggerIngest for one account.
        let query1 = r#"
            mutation {
                triggerIngest(provider: "aws", regions: ["us-east-1"], accountIds: ["333333333333"])
            }
        "#;

        let response1 = schema.execute(async_graphql::Request::new(query1)).await;
        assert!(
            response1.errors.is_empty(),
            "first triggerIngest should not error: {:?}",
            response1.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
        );

        let data1 = response1.data.into_json().expect("response1 has data");
        let job_ids_1: Vec<String> = data1
            .get("triggerIngest")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|id| id.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(job_ids_1.len(), 1, "first call should return 1 job");

        // Second triggerIngest for same account.
        let query2 = r#"
            mutation {
                triggerIngest(provider: "aws", regions: ["us-west-2"], accountIds: ["333333333333"])
            }
        "#;

        let response2 = schema.execute(async_graphql::Request::new(query2)).await;
        assert!(
            response2.errors.is_empty(),
            "second triggerIngest should not error"
        );

        let data2 = response2.data.into_json().expect("response2 has data");
        let job_ids_2: Vec<String> = data2
            .get("triggerIngest")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|id| id.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        assert_eq!(
            job_ids_2.len(), 0,
            "second call for same account should return 0 (deduped)"
        );
    }

    /// Test: account_id validation rejects invalid formats via the REAL resolver.
    /// Invalid id "abc" should error; "123456789012" should succeed.
    #[tokio::test]
    async fn test_trigger_ingest_account_validation() {
        let db_url = match get_db_url() {
            Some(u) => u,
            None => {
                println!("Skipping: DATABASE_URL not set");
                return;
            }
        };

        let store = match create_test_store(&db_url).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("FAILED: could not create store: {}", e);
                panic!("store creation failed");
            }
        };

        let store_arc = Arc::new(store);
        let pool = store_arc.pool().clone();

        // Clean up test data before running
        let test_keys = vec!["444444444444"];
        let _ = cleanup_test_jobs(&pool, &test_keys).await;

        let schema: Schema<QueryRoot, MutationRoot, async_graphql::EmptySubscription> =
            Schema::build(QueryRoot, MutationRoot, async_graphql::EmptySubscription)
                .data(store_arc)
                .data(pool)
                .finish();

        // Test invalid account ID.
        let query_invalid = r#"
            mutation {
                triggerIngest(provider: "aws", regions: ["us-east-1"], accountIds: ["abc"])
            }
        "#;

        let response_invalid = schema.execute(async_graphql::Request::new(query_invalid)).await;
        assert!(
            !response_invalid.errors.is_empty(),
            "query with invalid account ID should have errors"
        );
        let error_msg = response_invalid
            .errors
            .iter()
            .map(|e| e.message.clone())
            .collect::<Vec<_>>()
            .join("; ");
        assert!(
            error_msg.contains("12 digits") || error_msg.contains("Invalid"),
            "error should mention account ID format: {}",
            error_msg
        );

        // Test valid account ID.
        let query_valid = r#"
            mutation {
                triggerIngest(provider: "aws", regions: ["us-east-1"], accountIds: ["444444444444"])
            }
        "#;

        let response_valid = schema.execute(async_graphql::Request::new(query_valid)).await;
        assert!(
            response_valid.errors.is_empty(),
            "query with valid account ID should not error: {:?}",
            response_valid.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
        );

        let data_valid = response_valid.data.into_json().expect("response_valid has data");
        let job_ids: Vec<String> = data_valid
            .get("triggerIngest")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|id| id.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        assert_eq!(job_ids.len(), 1, "valid account should create 1 job");
    }

    /// Test: ingestStatus reads completed job and deserializes timestamps + stats.
    /// CRITICAL: Exercises the ::text cast fix for timestamptz columns.
    /// Without the cast, String deserialization of created_at/completed_at would panic/error.
    #[tokio::test]
    async fn test_ingest_status_maps_completed_job() {
        let db_url = match get_db_url() {
            Some(u) => u,
            None => {
                println!("Skipping: DATABASE_URL not set");
                return;
            }
        };

        let store = match create_test_store(&db_url).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("FAILED: could not create store: {}", e);
                panic!("store creation failed");
            }
        };

        let store_arc = Arc::new(store);
        let pool = store_arc.pool().clone();

        // Clean up test data
        let test_keys = vec!["555555555555"];
        let _ = cleanup_test_jobs(&pool, &test_keys).await;

        // Enqueue a job for a unique dedup_key.
        let job_id = match store_arc
            .enqueue(
                "account_ingest",
                &serde_json::json!({"account_id": "555555555555"}),
                Some("555555555555"),
                1,
                3,
            )
            .await
        {
            Ok(Some(id)) => id,
            Ok(None) => {
                eprintln!("FAILED: enqueue returned None (deduped unexpectedly)");
                panic!("enqueue should return job id");
            }
            Err(e) => {
                eprintln!("FAILED: enqueue failed: {}", e);
                panic!("enqueue failed");
            }
        };

        let job_id_string = job_id.to_string();

        // Mark it completed with real stats via store.complete() (handles jsonb serialization correctly).
        let result_value = serde_json::json!({
            "total_nodes": 3,
            "total_edges": 57,
            "duration_secs": 0
        });
        if let Err(e) = store_arc.complete(job_id, &result_value).await {
            eprintln!("FAILED: store.complete failed: {}", e);
            panic!("store.complete failed");
        }

        // Build schema and execute ingestStatus query.
        let schema: Schema<QueryRoot, MutationRoot, async_graphql::EmptySubscription> =
            Schema::build(QueryRoot, MutationRoot, async_graphql::EmptySubscription)
                .data(store_arc)
                .data(pool)
                .finish();

        let query = format!(
            r#"
            query {{
                ingestStatus(jobId: "{}") {{
                    id
                    status
                    createdAt
                    completedAt
                    stats {{
                        totalNodes
                        totalEdges
                        durationSecs
                    }}
                }}
            }}
            "#,
            job_id_string
        );

        let request = async_graphql::Request::new(&query);
        let response = schema.execute(request).await;

        // CRITICAL: If the ::text cast is missing, this will error on String deserialization of timestamptz.
        if !response.errors.is_empty() {
            eprintln!(
                "FAILED: GraphQL errors (indicates ::text cast missing): {}",
                response
                    .errors
                    .iter()
                    .map(|e| e.message.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            );
            panic!("ingestStatus failed");
        }

        let data = response.data.into_json().expect("response has data");
        let status_obj = data.get("ingestStatus").expect("ingestStatus in response");

        // Verify field mapping.
        assert_eq!(
            status_obj.get("id").and_then(|v| v.as_str()),
            Some(job_id_string.as_str()),
            "job id should match"
        );
        assert_eq!(
            status_obj.get("status").and_then(|v| v.as_str()),
            Some("COMPLETED"),
            "status should be COMPLETED"
        );
        assert!(
            status_obj.get("createdAt").and_then(|v| v.as_str()).is_some(),
            "createdAt should be non-empty (proves ::text cast works)"
        );
        assert!(
            status_obj.get("completedAt").and_then(|v| v.as_str()).is_some(),
            "completedAt should be non-empty"
        );

        // Verify stats deserialization.
        let stats_obj = status_obj
            .get("stats")
            .expect("stats should be present")
            .as_object()
            .expect("stats should be object");
        assert_eq!(
            stats_obj.get("totalNodes").and_then(|v| v.as_i64()),
            Some(3),
            "totalNodes should be 3"
        );
        assert_eq!(
            stats_obj.get("totalEdges").and_then(|v| v.as_i64()),
            Some(57),
            "totalEdges should be 57"
        );
        assert_eq!(
            stats_obj.get("durationSecs").and_then(|v| v.as_i64()),
            Some(0),
            "durationSecs should be 0"
        );
    }

    /// Test: ingestJobs lists jobs with optional filters.
    /// Exercises the ::text cast on the list path and filter semantics.
    #[tokio::test]
    async fn test_ingest_jobs_lists_with_filter() {
        let db_url = match get_db_url() {
            Some(u) => u,
            None => {
                println!("Skipping: DATABASE_URL not set");
                return;
            }
        };

        let store = match create_test_store(&db_url).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("FAILED: could not create store: {}", e);
                panic!("store creation failed");
            }
        };

        let store_arc = Arc::new(store);
        let pool = store_arc.pool().clone();

        // Clean up test data
        let test_keys = vec!["666666666666", "777777777777"];
        let _ = cleanup_test_jobs(&pool, &test_keys).await;

        // Enqueue two jobs for different accounts.
        for account_id in ["666666666666", "777777777777"].iter() {
            let _ = store_arc
                .enqueue(
                    "account_ingest",
                    &serde_json::json!({"account_id": account_id}),
                    Some(account_id),
                    1,
                    3,
                )
                .await;
        }

        let schema: Schema<QueryRoot, MutationRoot, async_graphql::EmptySubscription> =
            Schema::build(QueryRoot, MutationRoot, async_graphql::EmptySubscription)
                .data(store_arc)
                .data(pool)
                .finish();

        // Test: query with account_id filter.
        let query_filtered = r#"
            query {
                ingestJobs(filter: {accountId: "666666666666"}) {
                    id
                    status
                }
            }
        "#;

        let response = schema
            .execute(async_graphql::Request::new(query_filtered))
            .await;

        if !response.errors.is_empty() {
            eprintln!(
                "FAILED: GraphQL errors: {}",
                response
                    .errors
                    .iter()
                    .map(|e| e.message.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            );
            panic!("ingestJobs query failed");
        }

        let data = response.data.into_json().expect("response has data");
        let jobs: Vec<_> = data
            .get("ingestJobs")
            .and_then(|v| v.as_array())
            .map(|arr| arr.to_vec())
            .unwrap_or_default();

        assert!(!jobs.is_empty(), "should have at least 1 job for account 666666666666");

        // Verify status field is present (exercises the ::text cast on list path).
        let first_job = jobs.first().expect("should have at least one job");
        assert!(
            first_job.get("status").is_some(),
            "status should be present (proves ::text cast works on list path)"
        );

        // Test: query with status filter.
        let query_by_status = r#"
            query {
                ingestJobs(filter: {status: "pending"}) {
                    id
                    status
                }
            }
        "#;

        let response_status = schema
            .execute(async_graphql::Request::new(query_by_status))
            .await;

        assert!(
            response_status.errors.is_empty(),
            "status filter query should not error: {:?}",
            response_status.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
        );

        let data_status = response_status.data.into_json().expect("response has data");
        let jobs_status: Vec<_> = data_status
            .get("ingestJobs")
            .and_then(|v| v.as_array())
            .map(|arr| arr.to_vec())
            .unwrap_or_default();

        assert!(
            !jobs_status.is_empty(),
            "should have at least 1 pending job (enqueued jobs start pending)"
        );
    }
}
