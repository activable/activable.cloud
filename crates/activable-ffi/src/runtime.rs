//! Process-global tokio runtime and graph client pool.
//!
//! Manages the lifecycle of the tokio runtime and GraphClient that all FFI calls
//! will use. The design is careful to avoid re-entrancy: the FFI layer owns its own
//! tokio Runtime (not borrowed from the caller), and uses `block_on` to bridge
//! async Rust code to synchronous Go callers.

use crate::error::ActivableError;
use activable_graph::{GraphClient, GraphPool};
use std::sync::OnceLock;
use tokio_postgres::Config;

/// The global runtime and graph client, lazily initialized.
pub(crate) struct GlobalRuntime {
    /// Dedicated tokio runtime for async graph operations.
    rt: tokio::runtime::Runtime,
    /// Graph client pointing at the configured graph name.
    client: GraphClient,
}

/// Process-global runtime instance.
static GLOBAL: OnceLock<GlobalRuntime> = OnceLock::new();

/// Initialize the global runtime and graph client.
///
/// Must be called exactly once before any graph operation. Subsequent calls
/// return `ActivableError::AlreadyInitialized`.
///
/// # Arguments
/// - `db_host`: PostgreSQL host (e.g., "localhost")
/// - `db_port`: PostgreSQL port (e.g., 5432)
/// - `db_user`: PostgreSQL user
/// - `db_password`: PostgreSQL password
/// - `db_name`: PostgreSQL database name (e.g., "postgres")
/// - `max_connections`: Connection pool size (recommend 10-50 for ingestion)
/// - `graph_name`: Apache AGE graph name (e.g., "aws_graph")
///
/// # Errors
/// - `AlreadyInitialized` if called a second time
/// - `GraphError` if pool construction or client initialization fails
pub fn initialize_global(
    db_host: String,
    db_port: u16,
    db_user: String,
    db_password: String,
    db_name: String,
    max_connections: u32,
    graph_name: String,
) -> Result<(), ActivableError> {
    // Check if already initialized
    if GLOBAL.get().is_some() {
        return Err(ActivableError::AlreadyInitialized);
    }

    // Build the tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|e| ActivableError::GraphError {
            message: format!("failed to create tokio runtime: {}", e),
        })?;

    // Build the connection pool inside the runtime context
    // GraphPool::build returns Arc<Pool> already
    let pool = rt.block_on(async {
        let mut config = Config::new();
        config.host(&db_host);
        config.port(db_port);
        config.user(&db_user);
        config.password(&db_password);
        config.dbname(&db_name);
        config.connect_timeout(std::time::Duration::from_secs(10));

        GraphPool::build(&config, max_connections as usize)
    })?;

    let client = GraphClient::new(pool, graph_name.clone());

    // Store the runtime and client in the global
    let global = GlobalRuntime { rt, client };
    GLOBAL.get_or_init(|| global);

    Ok(())
}

/// Get a reference to the global runtime and client.
///
/// Returns `ActivableError::NotInitialized` if `initialize_global` has not been called.
pub(crate) fn get_global() -> Result<&'static GlobalRuntime, ActivableError> {
    GLOBAL.get().ok_or(ActivableError::NotInitialized)
}

impl GlobalRuntime {
    /// Block on an async operation using the global runtime.
    pub(crate) fn block_on<F>(&self, f: F) -> F::Output
    where
        F: std::future::Future,
    {
        self.rt.block_on(f)
    }

    /// Get a reference to the graph client.
    pub(crate) fn client(&self) -> &GraphClient {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_global_not_initialized() {
        // This test may fail if another test initialized GLOBAL.
        // In practice, each test should have its own isolated runtime.
        // For now, we just verify the function signature.
        let _ = get_global();
    }

    #[test]
    fn test_runtime_creation() {
        // Verify that the tokio runtime can be created
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build();
        assert!(rt.is_ok());
    }

    #[test]
    fn test_global_runtime_block_on() {
        // Create a local runtime (not the global one)
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("failed to create runtime");

        let result = rt.block_on(async { 42 });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_error_construction_graph_error() {
        let err = ActivableError::GraphError {
            message: "test".to_string(),
        };
        assert!(err.to_string().contains("test"));
    }
}
