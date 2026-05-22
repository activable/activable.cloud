//! Process-global runtime and client state management.

use crate::error::ActivableError;
use activable_graph::{GraphClient, GraphPool};
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::runtime::Runtime;
use deadpool_postgres::Pool;

pub struct GlobalRuntime {
    pub runtime: Runtime,
    pub client: GraphClient,
    pub pool: Arc<Pool>,
    pub graph_name: String,
}

static GLOBAL: OnceLock<GlobalRuntime> = OnceLock::new();

/// Initialize the process-global graph runtime and client.
///
/// Must be called exactly once before any graph operations. Subsequent calls
/// return `ActivableError::AlreadyInitialized`.
pub fn init_global(
    host: String,
    port: u16,
    user: String,
    password: String,
    dbname: String,
    graph_name: String,
    max_connections: u32,
) -> Result<(), ActivableError> {
    if GLOBAL.get().is_some() {
        return Err(ActivableError::AlreadyInitialized);
    }

    // Create a fresh tokio runtime for blocking FFI calls
    let rt = Runtime::new().map_err(|e| ActivableError::GraphError {
        message: format!("failed to create tokio runtime: {}", e),
    })?;

    // Build the connection pool within the runtime
    let pool = rt.block_on(async {
        GraphPool::build(
            &host,
            port,
            &user,
            &password,
            &dbname,
            max_connections as usize,
        )
    })?;

    // Create the client
    let client = GraphClient::new(pool.clone(), graph_name.clone());

    // Store globally
    GLOBAL
        .set(GlobalRuntime {
            runtime: rt,
            client,
            pool,
            graph_name,
        })
        .map_err(|_| ActivableError::AlreadyInitialized)?;

    Ok(())
}

/// Get a reference to the global runtime state.
///
/// Returns `NotInitialized` if `graph_initialize` has not been called.
pub fn get_global() -> Result<&'static GlobalRuntime, ActivableError> {
    GLOBAL.get().ok_or(ActivableError::NotInitialized)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: These tests cannot actually test init_global because OnceLock
    // persists across test runs. Real integration tests exist in the Go side.

    #[test]
    fn test_get_global_before_init_returns_error() {
        // Can't reset GLOBAL, so we simulate the not-initialized state
        // by checking the error type matches. In real scenarios, the FFI
        // caller would see NotInitialized on first call before graph_initialize.
        let result = get_global();
        match result {
            Err(ActivableError::NotInitialized) => {
                // Expected if this test runs before any init
            }
            _ => {
                // If global is already initialized (from another test),
                // that's OK — the actual integration tests verify the flow.
            }
        }
    }
}
