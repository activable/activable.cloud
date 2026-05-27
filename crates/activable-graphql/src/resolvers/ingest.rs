//! Resolvers for ingestion operations: triggerIngest and ingestStatus.
//!
//! Implements real AWS resource ingestion via the Rust activable-ingest runtime.
//! Runs ingestion as a tokio task in-process, non-blocking. Run status is persisted
//! to Postgres ingest_runs table for durability across server restarts.

use crate::types::{GqlIngestRun, GqlIngestService};
use activable_ingest::IngestRuntime;
use async_graphql::Context;
use deadpool_postgres::Pool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

/// Format the current time as RFC3339 (e.g., "2026-05-23T01:30:00Z").
fn format_rfc3339_now() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    // Decompose Unix timestamp into date/time components
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Civil date from days since epoch (Rata Die algorithm)
    let z = days as i64 + 719468;
    let era = z / 146097;
    let day_of_era = z - era * 146097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month + 2) / 5 + 1;
    let month = if month < 10 { month + 3 } else { month - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Record the start of an ingestion run in the database.
async fn record_run_start(
    pool: Arc<Pool>,
    run_id: &str,
    started_at: &str,
) -> Result<(), async_graphql::Error> {
    let conn = pool
        .get()
        .await
        .map_err(|e| async_graphql::Error::new(format!("pool error: {e}")))?;

    conn.execute(
        "INSERT INTO ingest_runs (run_id, started_at, status) VALUES ($1, $2, 'running') ON CONFLICT DO NOTHING",
        &[&run_id, &started_at],
    )
    .await
    .map_err(|e| async_graphql::Error::new(format!("DB error: {e}")))?;

    Ok(())
}

/// Record the completion of an ingestion run.
///
/// # Arguments
/// * `stats` - serialized telemetry as a serde_json::Value (if provided, must be valid JSON).
///   The value is converted to a JSON string via to_string(), then bound to the JSONB column
///   with a server-side `::jsonb` cast. NOTE: this JSONB bind path requires live-Postgres
///   verification (covered by the Phase-4 integration harness) — not exercised by unit tests.
async fn record_run_complete(
    pool: Arc<Pool>,
    run_id: &str,
    status: &str,
    error_message: Option<String>,
    stats: Option<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.get().await?;

    // Convert stats JSON value to string (via Value::to_string), then bind with server-side ::jsonb cast.
    // The server-side cast handles JSON parsing; tokio_postgres binds the string parameter.
    let stats_str = stats.map(|v| v.to_string());

    conn.execute(
        "UPDATE ingest_runs SET status = $1, completed_at = NOW(), error_message = $2, stats = $3::jsonb WHERE run_id = $4",
        &[&status, &error_message.as_deref(), &stats_str.as_deref(), &run_id],
    )
    .await?;

    Ok(())
}

/// Trigger an ingestion run.
///
/// Spawns a tokio task to run `IngestRuntime::run()` in the background.
/// Prevents concurrent runs via an atomic flag. Returns immediately with
/// RUNNING status and a run ID that can be polled via `ingest_status`.
pub async fn trigger_ingest(
    ctx: &Context<'_>,
    _provider: String,
    _regions: Vec<String>,
) -> async_graphql::Result<GqlIngestRun> {
    let runtime = ctx
        .data::<Arc<IngestRuntime>>()
        .map_err(|_| async_graphql::Error::new("IngestRuntime not available"))?;

    let active_flag = ctx
        .data::<Arc<AtomicBool>>()
        .map_err(|_| async_graphql::Error::new("Ingest state not available"))?;

    let pool = ctx
        .data::<Arc<Pool>>()
        .map_err(|_| async_graphql::Error::new("Pool not available"))?;

    // Prevent concurrent runs
    if active_flag
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(async_graphql::Error::new("Ingestion already in progress"));
    }

    let run_id = format!(
        "run-{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );

    let started_at = format_rfc3339_now();

    // Record run start in Postgres
    record_run_start(pool.clone(), &run_id, &started_at).await?;

    tracing::info!(
        run_id = %run_id,
        "Ingestion triggered (spawning background task)"
    );

    // Spawn ingestion in background tokio task
    let runtime_clone = runtime.clone();
    let active_clone = active_flag.clone();
    let pool_clone = pool.clone();
    let run_id_clone = run_id.clone();

    tokio::spawn(async move {
        // Guard: ensure active_flag is ALWAYS reset, even if the task panics.
        // Without this, a panic leaves the flag stuck on true and blocks all
        // future ingestion runs until server restart.
        struct ResetOnDrop(Arc<AtomicBool>);
        impl Drop for ResetOnDrop {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _guard = ResetOnDrop(active_clone);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(30 * 60), // 30 minute timeout
            runtime_clone.run(),
        )
        .await;

        match result {
            Ok(ingest_result) => {
                tracing::info!(run_id = %run_id_clone, "ingestion completed");

                let stats_value = serde_json::json!({
                    "resource_types": ingest_result.stats.len(),
                    "errors": ingest_result.errors.len(),
                    "duration_secs": ingest_result.duration.as_secs(),
                });

                if let Err(e) = record_run_complete(
                    pool_clone.clone(),
                    &run_id_clone,
                    "completed",
                    None,
                    Some(stats_value),
                )
                .await
                {
                    tracing::error!(run_id = %run_id_clone, error = %e, "failed to record run completion");
                }
            }
            Err(_) => {
                tracing::error!(
                    run_id = %run_id_clone,
                    "ingestion timed out after 30 minutes"
                );
                if let Err(e) = record_run_complete(
                    pool_clone.clone(),
                    &run_id_clone,
                    "timeout",
                    Some("Ingestion timed out after 30 minutes".to_string()),
                    None,
                )
                .await
                {
                    tracing::error!(run_id = %run_id_clone, error = %e, "failed to record timeout status");
                }
            }
        }
        // _guard dropped here → active_flag reset to false
    });

    // Return immediately with RUNNING status
    // Services list is a v1 placeholder; real services come from runtime config
    let services = vec!["iam", "sts", "s3", "ec2", "lambda"]
        .into_iter()
        .map(|name| GqlIngestService {
            name: name.to_string(),
            status: "PENDING".to_string(),
            node_count: 0,
            edge_count: 0,
            error: None,
        })
        .collect();

    Ok(GqlIngestRun {
        id: run_id,
        status: "RUNNING".to_string(),
        started_at,
        services,
    })
}

/// Get the status of a previous ingest run.
///
/// Queries the Postgres ingest_runs table by run_id and returns the current
/// status. Returns None if the run_id does not exist.
pub async fn ingest_status(
    ctx: &Context<'_>,
    run_id: String,
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
            "SELECT run_id, status, started_at, completed_at FROM ingest_runs WHERE run_id = $1",
            &[&run_id],
        )
        .await
        .map_err(|e| async_graphql::Error::new(format!("query error: {e}")))?;

    if rows.is_empty() {
        return Ok(None);
    }

    let row = &rows[0];
    let status: String = row.get(1);
    let run_id: String = row.get(0);
    let started_at: String = row.get(2);

    // v1: placeholder services list (should come from stats JSON in the future)
    let services = vec!["iam", "sts", "s3", "ec2", "lambda"]
        .into_iter()
        .map(|name| GqlIngestService {
            name: name.to_string(),
            status: if status == "RUNNING" {
                "IN_PROGRESS".to_string()
            } else {
                "COMPLETED".to_string()
            },
            node_count: 0,
            edge_count: 0,
            error: None,
        })
        .collect();

    Ok(Some(GqlIngestRun {
        id: run_id,
        status,
        started_at,
        services,
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_json_stats_serialization() {
        // Verify that serde_json::Value serializes to a valid JSON string
        // for JSONB binding via the ::jsonb SQL cast.
        let stats = serde_json::json!({
            "resource_types": 5,
            "errors": 2,
            "duration_secs": 123,
        });

        // Convert to string for binding to JSONB column
        let json_str = stats.to_string();
        assert!(!json_str.is_empty());

        // Verify round-trip
        let deserialized: serde_json::Value =
            serde_json::from_str(&json_str).expect("should deserialize back");
        assert_eq!(deserialized["resource_types"], 5);
        assert_eq!(deserialized["errors"], 2);
    }
}
