//! Activable graph driver for PostgreSQL + Apache AGE.
//!
//! Provides connection pooling, Cypher query helpers, and a typed query API
//! for the cloud attack graph.

pub mod client;
pub mod error;
pub mod known_labels;
pub mod loader;
pub mod pool;
pub mod query_builder;
pub mod types;

// Re-export public API
pub use client::{parse_agtype_scalar, GraphClient};
pub use error::GraphError;
pub use loader::EdgeLoadOutcome;
pub use pool::GraphPool;
pub use query_builder::{escape_cypher, escape_sql_literal, validate_label};
pub use types::{Direction, Node, NodeId, NodeRef, Path, Subgraph};
