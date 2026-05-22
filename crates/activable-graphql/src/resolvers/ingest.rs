//! Resolvers for ingestion operations: triggerIngest and ingestStatus.

use crate::types::{GqlIngestRun, GqlIngestService};
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
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month + 2) / 5 + 1;
    let month = if month < 10 { month + 3 } else { month - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hours, minutes, seconds)
}

/// Trigger an ingestion run (v1: placeholder that logs and returns pending status).
///
/// Real ingestion is handled by the Go subprocess in Phase 3.
/// This mutation v1 logs the request and returns a pending ingest run.
pub async fn trigger_ingest(
    provider: String,
    regions: Vec<String>,
) -> async_graphql::Result<GqlIngestRun> {
    let run_id = format!(
        "run-{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );

    let started_at = format_rfc3339_now();

    tracing::info!(
        run_id = %run_id,
        provider = %provider,
        regions = ?regions,
        "Ingestion triggered (v1 placeholder)"
    );

    // v1: placeholder services list
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

/// Get the status of a previous ingest run (v1: placeholder).
pub async fn ingest_status(run_id: String) -> async_graphql::Result<Option<GqlIngestRun>> {
    // v1: placeholder — always returns None until Phase 3 implements real persistence
    tracing::debug!(run_id = %run_id, "ingest_status queried (v1 placeholder)");
    Ok(None)
}
