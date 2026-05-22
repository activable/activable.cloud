//! AWS resource ingestion for activable-graph.
//!
//! Provides dual-mode AWS resource fetching via Cloud Control API (production)
//! with automatic fallback to native AWS SDKs (dev/Floci).
//!
//! ## Quick Start
//!
//! ```ignore
//! use activable_ingest::IngestRuntime;
//! use std::sync::Arc;
//! use deadpool_postgres::Pool;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let pool = Arc::new(create_pool()?);
//!     let runtime = IngestRuntime::new(pool, "cloud".to_string()).await?;
//!     let result = runtime.run().await;
//!
//!     println!("Ingested {} types", result.stats.len());
//!     println!("Errors: {}", result.errors.len());
//!     println!("Duration: {:?}", result.duration);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! The runtime ingests AWS resources in three stages:
//!
//! 1. **Resource Type Registry** — YAML-defined resource types with labels and regional flags
//! 2. **Parallel Fetchers** — tokio tasks with per-type error isolation and semaphore-based concurrency
//! 3. **Dual Mode** — Try Cloud Control API first; fall back to native SDK on error
//!
//! Each resource type fetches paginated results and writes nodes directly to activable-graph.

pub mod cloud_control;
pub mod config;
pub mod error;
pub mod native;
pub mod native_fallback;
pub mod resource_registry;
pub mod runtime;

pub use cloud_control::IngestStats;
pub use config::IngestConfig;
pub use error::IngestError;
pub use resource_registry::{load_registry, ResourceRegistry, ResourceTypeConfig};
pub use runtime::{IngestResult, IngestRuntime};
