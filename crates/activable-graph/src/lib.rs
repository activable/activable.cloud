//! Activable graph driver for PostgreSQL + Apache AGE.
//!
//! Provides connection pooling, typed query API, and utilities for working with
//! the cloud attack graph stored in an AGE-enabled Postgres instance.
//!
//! # Quick Start
//!
//! ```ignore
//! use activable_graph::{GraphClient, GraphPool};
//! use activable_graph::types::NodeId;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a connection pool
//!     let config = tokio_postgres::Config::new()
//!         .host("localhost")
//!         .user("postgres")
//!         .password("password");
//!     let pool = GraphPool::build(&config, 10)?;
//!
//!     // Create a client pointing at the "aws_graph"
//!     let client = GraphClient::new(pool, "aws_graph");
//!
//!     // Query the graph
//!     let node = client.find_by_id("Principal", &NodeId::from("principal_1")).await?;
//!     println!("{:?}", node);
//!
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod error;
pub mod known_labels;
pub mod loader;
pub mod pool;
pub mod query_builder;
pub mod types;

// Re-export commonly used types and functions
pub use client::GraphClient;
pub use error::{GraphError, GraphResult};
pub use pool::GraphPool;
pub use query_builder::{escape_cypher, escape_sql_literal};
pub use types::{Direction, HydrationQuery, Node, NodeId, NodeRef, Path, Subgraph};
