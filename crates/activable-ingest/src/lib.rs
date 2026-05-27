//! AWS resource ingestion for activable-graph.
//!
//! Provides dual-mode AWS resource fetching via Cloud Control API (production)
//! with automatic fallback to native AWS SDKs (dev/Floci).
//!
//! ## Per-Account Ingestion
//!
//! Per-account ingestion is now managed by the event-driven scheduler (Phase 5+).
//! Use `activable_ingest::AccountIngestHandler` registered with the scheduler's
//! handler registry to execute ingestion jobs enqueued by the GraphQL API.
//!
//! Example: `AccountIngestHandler::new(aws_config, pool, graph_name).await?`
//!
//! ## Architecture
//!
//! The ingester fetches AWS resources in three stages:
//!
//! 1. **Resource Type Registry** — YAML-defined resource types with labels and regional flags
//! 2. **Parallel Fetchers** — tokio tasks with per-type error isolation and semaphore-based concurrency
//! 3. **Dual Mode** — Try Cloud Control API first; fall back to native SDK on error
//!
//! Each resource type fetches paginated results and writes nodes directly to activable-graph.

pub mod cloud_control;
pub mod config;
pub mod error;
pub mod executor;
pub mod handler;
pub mod native;
pub mod native_fallback;
pub mod relationship;
pub mod resource_registry;
pub mod runtime;

pub use cloud_control::IngestStats;
pub use config::IngestConfig;
pub use error::IngestError;
pub use executor::{create_account_config, ingest_account, IngestRunStats};
pub use handler::AccountIngestHandler;
pub use relationship::{RelationshipRule, RelationshipStats};
pub use resource_registry::{load_registry, ResourceRegistry, ResourceTypeConfig};
