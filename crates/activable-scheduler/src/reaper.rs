use crate::model::SchedulerError;
use crate::store::JobStore;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// A reaper that periodically finds jobs with stale heartbeat (no update > threshold)
/// and re-queues them respecting max_attempts.
/// HA-safe: multiple reaper instances are independent; Postgres isolation via WHERE status='running'
/// and atomic fail() prevents double-reclaiming (if fail() gets NotFound, that reaper's work is done).
pub struct Reaper {
    store: Arc<JobStore>,
    /// Job types to monitor for stale heartbeat.
    job_types: Vec<String>,
    /// Threshold in seconds: jobs with heartbeat_at < now() - threshold are considered stale.
    reap_threshold_seconds: i64,
    /// Interval between reap checks.
    check_interval: Duration,
    /// Shutdown signal (set to true to stop the run() loop).
    shutdown: Arc<AtomicBool>,
}

impl Reaper {
    /// Create a new Reaper.
    /// job_types: list of job types to monitor (e.g., ["account_ingest"]).
    /// reap_threshold_seconds: stale heartbeat threshold in seconds (e.g., 60).
    /// check_interval: how often to run tick() (e.g., Duration::from_secs(10)).
    pub fn new(
        store: Arc<JobStore>,
        job_types: Vec<String>,
        reap_threshold_seconds: i64,
        check_interval: Duration,
    ) -> Self {
        Reaper {
            store,
            job_types,
            reap_threshold_seconds,
            check_interval,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Run a single reap cycle.
    /// Finds all stale running jobs and re-queues them via store.fail(),
    /// respecting max_attempts (status=pending if attempts < max_attempts,
    /// status=failed if attempts >= max_attempts).
    /// Tolerates NotFound errors (another reaper/worker won the row).
    /// Returns the count of successfully reaped jobs.
    pub async fn tick(&self) -> Result<usize, SchedulerError> {
        let stale_ids = self
            .store
            .find_stale_running(&self.job_types, self.reap_threshold_seconds)
            .await?;

        let mut reaped_count = 0;

        for id in stale_ids {
            match self
                .store
                .fail(id, "stale heartbeat", true) // retryable=true
                .await
            {
                Ok(_) => {
                    reaped_count += 1;
                    info!(job_id = %id, "stale job re-queued");
                }
                Err(SchedulerError::NotFound(_)) => {
                    // Another reaper or worker already re-queued/claimed this job.
                    // This is expected in HA setups. Log and continue.
                    info!(job_id = %id, "stale job already reclaimed (expected in HA)");
                }
                Err(e) => {
                    error!(job_id = %id, error = %e, "failed to reap stale job");
                    // Log and continue; don't crash the reaper.
                }
            }
        }

        Ok(reaped_count)
    }

    /// Run the reaper loop indefinitely.
    /// Calls tick() on a regular interval (check_interval).
    /// Stops when shutdown signal is set.
    /// On tick() errors, logs and continues (never crashes the reaper).
    pub async fn run(&self) {
        let mut interval = tokio::time::interval(self.check_interval);

        loop {
            interval.tick().await;

            if self.shutdown.load(Ordering::Relaxed) {
                info!("reaper received shutdown signal");
                break;
            }

            match self.tick().await {
                Ok(count) => {
                    if count > 0 {
                        info!(reaped = count, "reaper tick completed");
                    }
                }
                Err(e) => {
                    error!(error = %e, "reaper tick failed, continuing");
                }
            }
        }

        info!("reaper loop exited");
    }

    /// Signal the reaper to shut down.
    /// The run() loop will exit after the next tick().
    pub fn shutdown_signal(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_reaper_config_invariant() {
        // heartbeat_interval should be ≪ reap_threshold
        // Example: 5s interval, 60s threshold
        // This is a pure-logic test documenting the safety invariant.
        let heartbeat_interval_secs = 5;
        let reap_threshold_secs = 60;
        assert!(
            heartbeat_interval_secs < reap_threshold_secs,
            "heartbeat interval should be much less than reap threshold"
        );
    }
}
