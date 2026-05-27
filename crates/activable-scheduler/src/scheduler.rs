use crate::handler::JobHandler;
use crate::model::SchedulerError;
use crate::reaper::Reaper;
use crate::registry::HandlerRegistry;
use crate::store::JobStore;
use crate::worker::WorkerPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::info;

/// A high-level scheduler facade that orchestrates JobStore, WorkerPool, and Reaper.
///
/// The Scheduler is the main entry point for users: it wires together the low-level
/// components and manages their lifecycle (start/shutdown).
///
/// Internally, it uses HandlerRegistry to manage the set of job handlers, and delegates
/// job claiming/execution to WorkerPool and crash recovery to Reaper.
pub struct Scheduler {
    store: Arc<JobStore>,
    registry: HandlerRegistry,
    pool: Option<WorkerPool>,
    reaper: Option<Reaper>,
    /// Handle to the reaper task (if running)
    reaper_handle: Option<JoinHandle<()>>,
    /// Number of concurrent workers (used in logging)
    concurrency: usize,
}

impl Scheduler {
    /// Create a new builder for constructing a Scheduler.
    pub fn builder() -> SchedulerBuilder {
        SchedulerBuilder::new()
    }

    /// Start the scheduler: initialize schema, spawn the worker pool, and spawn the reaper.
    /// Returns an error if schema initialization, pool start, or reaper spawn fails.
    /// Guard: if already started (reaper_handle is Some), returns error to prevent double-start.
    pub async fn start(&mut self) -> Result<(), SchedulerError> {
        // F5: Guard against double-start
        if self.reaper_handle.is_some() {
            return Err(SchedulerError::Database(
                "scheduler already started".to_string(),
            ));
        }

        // Ensure schema is initialized
        self.store.ensure_schema().await?;

        info!(
            concurrency = self.concurrency,
            job_types = ?self.registry.registered_types(),
            "starting scheduler"
        );

        // Start the worker pool
        if let Some(ref pool) = self.pool {
            pool.start().await?;
        }

        // Spawn the reaper task (if we have a reaper)
        if let Some(ref reaper) = self.reaper {
            let reaper = reaper.clone();
            let handle = tokio::spawn(async move {
                reaper.run().await;
            });
            self.reaper_handle = Some(handle);
        }

        Ok(())
    }

    /// Shut down the scheduler gracefully: stop the worker pool and reaper.
    /// Waits for both to complete before returning.
    pub async fn shutdown(&mut self) -> Result<(), SchedulerError> {
        info!("shutting down scheduler");

        // Shutdown the worker pool
        if let Some(ref pool) = self.pool {
            pool.shutdown().await?;
        }

        // Shutdown the reaper and wait for it to finish
        if let Some(ref reaper) = self.reaper {
            reaper.shutdown_signal();
        }

        if let Some(handle) = self.reaper_handle.take() {
            handle.await.ok(); // Ignore errors from the task
        }

        Ok(())
    }

    /// Return the job store for direct access if needed (e.g., for enqueuing jobs).
    pub fn store(&self) -> Arc<JobStore> {
        Arc::clone(&self.store)
    }

    /// Return the registered job types this scheduler serves.
    pub fn registered_types(&self) -> Vec<String> {
        self.registry.registered_types()
    }
}

/// Builder for constructing a Scheduler with fluent API.
pub struct SchedulerBuilder {
    registry: HandlerRegistry,
    concurrency: usize,
    poll_ms: u64,
    heartbeat_interval: Duration,
    reap_threshold_seconds: i64,
    reap_check_interval: Duration,
}

// F1: poll_ms is now plumbed through to WorkerPool

impl SchedulerBuilder {
    /// Create a new builder with default configuration.
    fn new() -> Self {
        SchedulerBuilder {
            registry: HandlerRegistry::new(),
            concurrency: 2,
            poll_ms: 500,
            heartbeat_interval: Duration::from_secs(5),
            reap_threshold_seconds: 60,
            reap_check_interval: Duration::from_secs(10),
        }
    }

    /// Register a job handler.
    pub fn register(mut self, handler: Arc<dyn JobHandler + Send + Sync>) -> Self {
        self.registry.register(handler);
        self
    }

    /// Set the worker concurrency (number of concurrent workers).
    pub fn concurrency(mut self, n: usize) -> Self {
        self.concurrency = n;
        self
    }

    /// Set the job polling interval (in milliseconds).
    pub fn poll_ms(mut self, ms: u64) -> Self {
        self.poll_ms = ms;
        self
    }

    /// Set the heartbeat update interval (duration between heartbeat updates).
    pub fn heartbeat_interval(mut self, duration: Duration) -> Self {
        self.heartbeat_interval = duration;
        self
    }

    /// Set the reaper's stale job threshold (in seconds).
    pub fn reap_threshold_seconds(mut self, seconds: i64) -> Self {
        self.reap_threshold_seconds = seconds;
        self
    }

    /// Set the reaper's check interval (duration between reap cycles).
    pub fn reap_check_interval(mut self, duration: Duration) -> Self {
        self.reap_check_interval = duration;
        self
    }

    /// Build the Scheduler with the given JobStore.
    /// Returns an error if the store cannot be accessed or handlers are not registered.
    pub fn build(self, store: Arc<JobStore>) -> Result<Scheduler, SchedulerError> {
        if self.registry.is_empty() {
            return Err(SchedulerError::Database(
                "no handlers registered with scheduler".to_string(),
            ));
        }

        let handlers = self.registry.handlers();
        let job_types = self.registry.registered_types();

        // Create the worker pool with configured poll_ms and heartbeat interval
        let pool = WorkerPool::new(Arc::clone(&store), handlers.clone(), self.concurrency)
            .with_poll_ms(self.poll_ms)
            .with_heartbeat_interval(self.heartbeat_interval);

        // Create the reaper
        let reaper = Reaper::new(
            Arc::clone(&store),
            job_types,
            self.reap_threshold_seconds,
            self.reap_check_interval,
        );

        Ok(Scheduler {
            store,
            registry: self.registry,
            pool: Some(pool),
            reaper: Some(reaper),
            reaper_handle: None,
            concurrency: self.concurrency,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::JobError;
    use serde_json::{json, Value};

    /// Minimal test handler
    struct DummyHandler;

    #[async_trait::async_trait]
    impl JobHandler for DummyHandler {
        async fn handle(&self, _payload: Value) -> Result<Value, JobError> {
            Ok(json!({}))
        }

        fn job_type(&self) -> &str {
            "dummy_type"
        }

        fn max_attempts(&self) -> i32 {
            1
        }
    }

    #[test]
    fn test_scheduler_builder_default() {
        let builder = SchedulerBuilder::new();
        assert_eq!(builder.concurrency, 2);
        assert_eq!(builder.poll_ms, 500);
        assert_eq!(builder.heartbeat_interval, Duration::from_secs(5));
        assert_eq!(builder.reap_threshold_seconds, 60);
    }

    #[test]
    fn test_scheduler_builder_register_handler() {
        let handler = Arc::new(DummyHandler) as Arc<dyn JobHandler + Send + Sync>;
        let builder = SchedulerBuilder::new().register(handler);
        assert_eq!(builder.registry.len(), 1);
    }

    #[test]
    fn test_scheduler_builder_configuration() {
        let handler = Arc::new(DummyHandler) as Arc<dyn JobHandler + Send + Sync>;
        let builder = SchedulerBuilder::new()
            .register(handler)
            .concurrency(4)
            .poll_ms(1000)
            .heartbeat_interval(Duration::from_secs(10))
            .reap_threshold_seconds(120)
            .reap_check_interval(Duration::from_secs(20));

        assert_eq!(builder.concurrency, 4);
        assert_eq!(builder.poll_ms, 1000);
        assert_eq!(builder.heartbeat_interval, Duration::from_secs(10));
        assert_eq!(builder.reap_threshold_seconds, 120);
        assert_eq!(builder.reap_check_interval, Duration::from_secs(20));
    }

    // F2: Real tests for build() error + success paths
    #[test]
    fn test_scheduler_build_empty_registry_errors() {
        let result = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let config = crate::JobStoreConfig {
                host: "localhost".to_string(),
                port: 5432,
                user: "test".to_string(),
                password: "test".to_string(),
                dbname: "test".to_string(),
                pool_size: 1,
                backoff_base_seconds: 1.0,
            };

            let builder = SchedulerBuilder::new();
            // Do NOT register any handler; registry is empty
            builder.build(Arc::new(JobStore::new(config).await.unwrap()))
        });

        // Should return Err because no handlers registered
        assert!(result.is_err(), "build with empty registry must error");
        if let Err(SchedulerError::Database(msg)) = result {
            assert!(
                msg.contains("no handlers"),
                "error should mention no handlers: {}",
                msg
            );
        } else {
            panic!("expected SchedulerError::Database");
        }
    }

    #[test]
    fn test_scheduler_build_with_handler_succeeds() {
        let result = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let config = crate::JobStoreConfig {
                host: "localhost".to_string(),
                port: 5432,
                user: "test".to_string(),
                password: "test".to_string(),
                dbname: "test".to_string(),
                pool_size: 1,
                backoff_base_seconds: 1.0,
            };

            let handler = Arc::new(DummyHandler) as Arc<dyn JobHandler + Send + Sync>;
            SchedulerBuilder::new()
                .register(handler)
                .build(Arc::new(JobStore::new(config).await.unwrap()))
        });

        // Should succeed with a registered handler
        assert!(result.is_ok(), "build with registered handler must succeed");
    }
}
