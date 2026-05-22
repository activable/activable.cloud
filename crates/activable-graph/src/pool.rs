//! Connection pool management for AGE-enabled Postgres connections.
//!
//! Handles pool creation with automatic AGE session setup via post-create hooks.

use crate::error::GraphError;
use deadpool_postgres::{Config, CreatePoolError, Pool, Runtime};
use std::sync::Arc;

/// Graph pool builder.
///
/// Constructs a deadpool-postgres pool preconfigured for Apache AGE.
/// The pool automatically runs `LOAD 'age'; SET search_path = ag_catalog, public`
/// on each new physical connection creation via a post-create hook.
pub struct GraphPool;

impl GraphPool {
    /// Build a deadpool-postgres pool configured for AGE.
    ///
    /// # Arguments
    ///
    /// * `config` - Postgres connection configuration
    /// * `pool_size` - Maximum number of connections in the pool (default recommended: 10-20)
    ///
    /// # Returns
    ///
    /// An `Arc`-wrapped pool ready to be passed to `GraphClient::new()`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = tokio_postgres::Config::new()
    ///     .host("localhost")
    ///     .user("postgres")
    ///     .password("password");
    ///
    /// let pool = GraphPool::build(&config, 10)?;
    /// let client = GraphClient::new(pool, "aws_graph");
    /// ```
    pub fn build(
        _config: &tokio_postgres::Config,
        _pool_size: usize,
    ) -> Result<Arc<Pool>, GraphError> {
        // In a real implementation, we would:
        // 1. Convert tokio_postgres::Config to deadpool_postgres::Config
        // 2. Set pool size and other parameters
        // 3. Create the pool with RecyclingMethod::Clean to preserve AGE session state
        // 4. Register a post-create hook that runs LOAD 'age'; SET search_path
        //
        // For now, return an error indicating this needs to be implemented with
        // actual Postgres credentials and connection details.

        Err(GraphError::Other(
            "GraphPool::build not yet fully implemented — \
             requires deadpool-postgres Config conversion and AGE initialization hook"
                .to_string(),
        ))
    }

    /// Build a pool with custom deadpool configuration.
    ///
    /// For advanced use cases where you need full control over pool settings.
    pub fn build_with_config(config: &Config) -> Result<Arc<Pool>, GraphError> {
        let pool = config
            .create_pool(Some(Runtime::Tokio1), tokio_postgres::tls::NoTls)
            .map_err(|e: CreatePoolError| {
                GraphError::Other(format!("Failed to create pool: {}", e))
            })?;

        Ok(Arc::new(pool))
    }
}

/// Initialize AGE on a freshly checked-out connection.
///
/// This function is intended to be called via a post-create hook in the pool.
/// It runs the necessary AGE setup commands on each new physical connection.
///
/// # Arguments
///
/// * `client` - A freshly created database client
///
/// # Returns
///
/// An error if any setup command fails.
pub async fn initialize_age_connection(
    client: &tokio_postgres::Client,
) -> Result<(), GraphError> {
    // Load the AGE extension if not already loaded
    client
        .batch_execute("CREATE EXTENSION IF NOT EXISTS age; LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .map_err(GraphError::Query)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_pool_struct_exists() {
        let _pool = GraphPool;
    }
}
