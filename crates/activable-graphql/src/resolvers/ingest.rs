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
            "SELECT id, status, created_at::text, finished_at::text, claimed_by, result, last_error \
             FROM jobs WHERE id = $1",
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
                "SELECT id, status, created_at::text, finished_at::text, claimed_by, result, last_error \
                 FROM jobs WHERE job_type = 'account_ingest' AND dedup_key = $1 AND status = $2 \
                 ORDER BY created_at DESC LIMIT 100",
                &[account_id, status],
            )
            .await
        }
        Some(f) if f.account_id.is_some() => {
            let account_id = f.account_id.as_ref().unwrap();
            conn.query(
                "SELECT id, status, created_at::text, finished_at::text, claimed_by, result, last_error \
                 FROM jobs WHERE job_type = 'account_ingest' AND dedup_key = $1 \
                 ORDER BY created_at DESC LIMIT 100",
                &[account_id],
            )
            .await
        }
        Some(f) if f.status.is_some() => {
            let status = f.status.as_ref().unwrap();
            conn.query(
                "SELECT id, status, created_at::text, finished_at::text, claimed_by, result, last_error \
                 FROM jobs WHERE job_type = 'account_ingest' AND status = $1 \
                 ORDER BY created_at DESC LIMIT 100",
                &[status],
            )
            .await
        }
        _ => {
            conn.query(
                "SELECT id, status, created_at::text, finished_at::text, claimed_by, result, last_error \
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
