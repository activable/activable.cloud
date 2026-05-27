#![doc = include_str!("../README.md")]

/// Model types: Job, JobStatus, SchedulerError.
pub mod model;

/// Schema: DDL constants and initialization.
pub mod schema;

/// JobStore: the main queue API.
pub mod store;

/// JobHandler trait and JobError type.
pub mod handler;

/// Worker and WorkerPool for job execution.
pub mod worker;

/// Reaper for crash recovery: finds jobs with stale heartbeat and re-queues them.
pub mod reaper;

/// HandlerRegistry: maps job_type -> JobHandler (the sole extension point for reusability).
pub mod registry;

/// Scheduler: high-level facade orchestrating JobStore, WorkerPool, and Reaper.
pub mod scheduler;

// Re-export public API
pub use handler::{JobError, JobHandler};
pub use model::{Job, JobStatus, SchedulerError};
pub use reaper::Reaper;
pub use registry::HandlerRegistry;
pub use scheduler::Scheduler;
pub use store::{JobStore, JobStoreConfig};
pub use worker::WorkerPool;
