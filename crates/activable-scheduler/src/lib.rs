#![doc = include_str!("../README.md")]

/// Model types: Job, JobStatus, SchedulerError.
pub mod model;

/// Schema: DDL constants and initialization.
pub mod schema;

/// JobStore: the main queue API.
pub mod store;

// Re-export public API
pub use model::{Job, JobStatus, SchedulerError};
pub use store::{JobStore, JobStoreConfig};
