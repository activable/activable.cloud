use crate::handler::JobHandler;
use crate::model::SchedulerError;
use crate::store::JobStore;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{error, info};

/// A worker that claims jobs from the store and dispatches them to handlers.
pub struct Worker {
    id: String,
    store: Arc<JobStore>,
    handlers: Arc<Vec<Arc<dyn JobHandler + Send + Sync>>>,
    shutdown: Arc<AtomicBool>,
    heartbeat_interval: Duration,
}

impl Worker {
    /// Create a new worker with the given ID, store, handlers, and heartbeat interval.
    fn new(
        id: String,
        store: Arc<JobStore>,
        handlers: Arc<Vec<Arc<dyn JobHandler + Send + Sync>>>,
        shutdown: Arc<AtomicBool>,
        heartbeat_interval: Duration,
    ) -> Self {
        Worker {
            id,
            store,
            handlers,
            shutdown,
            heartbeat_interval,
        }
    }

    /// Run the worker's claim-dispatch-complete loop.
    /// Polls for jobs, dispatches to matching handlers, and updates the store.
    async fn run(&self, poll_ms: u64) {
        loop {
            // Check shutdown signal and exit after completing current job
            if self.shutdown.load(Ordering::Relaxed) {
                info!(worker_id = %self.id, "worker received shutdown signal");
                break;
            }

            // Build the list of job types this worker handles
            let job_types: Vec<String> = self
                .handlers
                .iter()
                .map(|h| h.job_type().to_string())
                .collect();

            // Claim the next job
            match self.store.claim(&job_types, &self.id, poll_ms).await {
                Ok(Some(job)) => {
                    info!(
                        worker_id = %self.id,
                        job_id = %job.id,
                        job_type = %job.job_type,
                        "claimed job"
                    );

                    // Find the matching handler
                    let handler = self.handlers.iter().find(|h| h.job_type() == job.job_type);

                    match handler {
                        Some(handler) => {
                            // Spawn the handler in isolation to catch panics without breaking the event loop.
                            // Using tokio::spawn isolates the async context and avoids the "cannot block within a
                            // runtime" panic from catch_unwind + block_on inside an async context.
                            let handler_clone = Arc::clone(handler);
                            let payload_clone = job.payload.clone();

                            // Spawn a heartbeat refresh task that runs concurrently during handler execution.
                            // It updates heartbeat_at every heartbeat_interval to prevent the reaper from
                            // falsely reclaiming this job while it's actively running.
                            let store_clone = Arc::clone(&self.store);
                            let job_id = job.id;
                            let heartbeat_interval = self.heartbeat_interval;

                            let heartbeat_handle = tokio::spawn(async move {
                                let mut interval = tokio::time::interval(heartbeat_interval);
                                loop {
                                    interval.tick().await;
                                    if let Err(e) = store_clone.update_heartbeat(job_id).await {
                                        error!(
                                            job_id = %job_id,
                                            error = %e,
                                            "failed to update heartbeat"
                                        );
                                        // Continue trying; don't crash the heartbeat task
                                    }
                                }
                            });

                            let job_handle =
                                tokio::spawn(
                                    async move { handler_clone.handle(payload_clone).await },
                                );

                            match job_handle.await {
                                Ok(Ok(output)) => {
                                    // Handler succeeded: abort the heartbeat task and complete the job.
                                    heartbeat_handle.abort();

                                    match self.store.complete(job.id, &output).await {
                                        Ok(_) => {
                                            info!(
                                                worker_id = %self.id,
                                                job_id = %job.id,
                                                "job completed successfully"
                                            );
                                        }
                                        Err(e) => {
                                            error!(
                                                worker_id = %self.id,
                                                job_id = %job.id,
                                                error = %e,
                                                "failed to mark job as completed"
                                            );
                                            // Retry the loop on store error rather than silently dropping
                                            tokio::time::sleep(tokio::time::Duration::from_millis(
                                                100,
                                            ))
                                            .await;
                                            continue;
                                        }
                                    }
                                }
                                Ok(Err(job_error)) => {
                                    // Handler returned an error: abort heartbeat and mark failure.
                                    heartbeat_handle.abort();

                                    info!(
                                        worker_id = %self.id,
                                        job_id = %job.id,
                                        retryable = job_error.retryable,
                                        error = %job_error.message,
                                        "handler returned error"
                                    );

                                    match self
                                        .store
                                        .fail(job.id, &job_error.message, job_error.retryable)
                                        .await
                                    {
                                        Ok(_) => {
                                            info!(
                                                worker_id = %self.id,
                                                job_id = %job.id,
                                                "job failure recorded"
                                            );
                                        }
                                        Err(e) => {
                                            error!(
                                                worker_id = %self.id,
                                                job_id = %job.id,
                                                error = %e,
                                                "failed to mark job as failed"
                                            );
                                            // Retry the loop on store error rather than silently dropping
                                            tokio::time::sleep(tokio::time::Duration::from_millis(
                                                100,
                                            ))
                                            .await;
                                            continue;
                                        }
                                    }
                                }
                                Err(join_err) => {
                                    // Task was cancelled or the handler panicked: abort heartbeat.
                                    heartbeat_handle.abort();

                                    // Use is_panic() to detect if it was a panic.
                                    if join_err.is_panic() {
                                        error!(
                                            worker_id = %self.id,
                                            job_id = %job.id,
                                            "handler panicked; marking job as non-retryable failure"
                                        );

                                        match self
                                            .store
                                            .fail(
                                                job.id,
                                                "handler panicked",
                                                false, // non-retryable
                                            )
                                            .await
                                        {
                                            Ok(_) => {
                                                info!(
                                                    worker_id = %self.id,
                                                    job_id = %job.id,
                                                    "panic failure recorded"
                                                );
                                            }
                                            Err(e) => {
                                                error!(
                                                    worker_id = %self.id,
                                                    job_id = %job.id,
                                                    error = %e,
                                                    "failed to mark panicked job as failed"
                                                );
                                                // Retry the loop on store error
                                                tokio::time::sleep(
                                                    tokio::time::Duration::from_millis(100),
                                                )
                                                .await;
                                                continue;
                                            }
                                        }
                                    } else {
                                        // Task was cancelled (e.g., worker shutdown during execution).
                                        error!(
                                            worker_id = %self.id,
                                            job_id = %job.id,
                                            "job task was cancelled"
                                        );
                                    }
                                }
                            }
                        }
                        None => {
                            // No matching handler (defensive; should not happen with proper registry)
                            error!(
                                worker_id = %self.id,
                                job_id = %job.id,
                                job_type = %job.job_type,
                                "no handler found for job type"
                            );

                            match self
                                .store
                                .fail(job.id, "no handler found for job type", false)
                                .await
                            {
                                Ok(_) => {
                                    info!(
                                        worker_id = %self.id,
                                        job_id = %job.id,
                                        job_type = %job.job_type,
                                        "unknown job type failure recorded"
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        worker_id = %self.id,
                                        job_id = %job.id,
                                        error = %e,
                                        "failed to mark job as failed (no handler)"
                                    );
                                    // Retry the loop on store error
                                    tokio::time::sleep(tokio::time::Duration::from_millis(100))
                                        .await;
                                    continue;
                                }
                            }
                        }
                    }
                }
                Ok(None) => {
                    // No job available; sleep and retry
                    tokio::time::sleep(tokio::time::Duration::from_millis(poll_ms)).await;
                }
                Err(e) => {
                    error!(
                        worker_id = %self.id,
                        error = %e,
                        "failed to claim job"
                    );
                    // Backoff before retrying
                    tokio::time::sleep(tokio::time::Duration::from_millis(poll_ms)).await;
                }
            }
        }

        info!(worker_id = %self.id, "worker loop exited");
    }
}

/// A pool of workers that claim and execute jobs concurrently.
pub struct WorkerPool {
    store: Arc<JobStore>,
    handlers: Arc<Vec<Arc<dyn JobHandler + Send + Sync>>>,
    concurrency: usize,
    shutdown: Arc<AtomicBool>,
    worker_handles: tokio::sync::Mutex<Vec<JoinHandle<()>>>,
    /// Interval for heartbeat refresh during job execution (default 5s).
    /// Must be ≪ reaper threshold (e.g., 5s heartbeat, 60s threshold).
    heartbeat_interval: Duration,
}

impl WorkerPool {
    /// Create a new WorkerPool with the given store, handlers, and concurrency level.
    /// Polling interval for unclaimed jobs is fixed at 100ms.
    /// Heartbeat interval defaults to 5 seconds (configurable via with_heartbeat_interval).
    pub fn new(
        store: Arc<JobStore>,
        handlers: Vec<Arc<dyn JobHandler + Send + Sync>>,
        concurrency: usize,
    ) -> Self {
        WorkerPool {
            store,
            handlers: Arc::new(handlers),
            concurrency,
            shutdown: Arc::new(AtomicBool::new(false)),
            worker_handles: tokio::sync::Mutex::new(Vec::new()),
            heartbeat_interval: Duration::from_secs(5),
        }
    }

    /// Set the heartbeat interval for this worker pool.
    /// Heartbeat must be ≪ reaper threshold (e.g., 5s heartbeat, 60s reaper threshold).
    /// Returns self for builder pattern.
    pub fn with_heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Start the worker pool.
    /// Spawns `concurrency` number of worker tasks that poll and execute jobs.
    pub async fn start(&self) -> Result<(), SchedulerError> {
        let mut handles = self.worker_handles.lock().await;

        for i in 0..self.concurrency {
            let worker_id = Self::generate_worker_id(i as u32);
            let worker = Worker::new(
                worker_id,
                Arc::clone(&self.store),
                Arc::clone(&self.handlers),
                Arc::clone(&self.shutdown),
                self.heartbeat_interval,
            );

            let handle = tokio::spawn(async move {
                worker.run(100).await;
            });

            handles.push(handle);
        }

        info!(concurrency = self.concurrency, "worker pool started");
        Ok(())
    }

    /// Gracefully shutdown the worker pool.
    /// Signals workers to stop and waits for in-flight jobs to complete.
    pub async fn shutdown(&self) -> Result<(), SchedulerError> {
        info!("initiating graceful shutdown");
        self.shutdown.store(true, Ordering::Relaxed);

        let mut handles = self.worker_handles.lock().await;
        for handle in handles.drain(..) {
            let _ = handle.await;
        }

        info!("all workers shut down");
        Ok(())
    }

    /// Generate a stable worker ID based on hostname and index.
    /// Format: worker-<hostname>-<index>
    pub fn generate_worker_id(index: u32) -> String {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());

        format!("worker-{}-{}", hostname, index)
    }

    /// Provide access to the underlying store for testing.
    /// This is a test-only method and should not be used in production code.
    #[cfg(test)]
    pub fn store(&self) -> Arc<JobStore> {
        Arc::clone(&self.store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_worker_id() {
        let id0 = WorkerPool::generate_worker_id(0);
        let id1 = WorkerPool::generate_worker_id(1);

        assert!(id0.starts_with("worker-"), "should start with worker-");
        assert!(id1.starts_with("worker-"), "should start with worker-");
        assert_ne!(id0, id1, "ids with different indices should differ");
        assert!(id0.contains('-'), "id should have dashes");
    }
}
