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

// Re-export public API
pub use handler::{JobError, JobHandler};
pub use model::{Job, JobStatus, SchedulerError};
pub use reaper::Reaper;
pub use store::{JobStore, JobStoreConfig};
pub use worker::WorkerPool;
