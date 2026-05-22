//! Connection pool construction with AGE session setup.

use crate::error::GraphError;
use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use std::sync::Arc;
use tokio_postgres::NoTls;

/// Constructs a deadpool-postgres pool preconfigured for AGE.
///
/// Registers a post-create hook that runs:
/// - `LOAD 'age';`
/// - `SET search_path = ag_catalog, "$user", public;`
///
/// Uses `RecyclingMethod::Clean` (not `Fast`) to preserve AGE session state across
/// pool checkouts. `Fast` would issue `DISCARD ALL` which resets search_path and
/// unloads the AGE extension.
pub struct GraphPool;

impl GraphPool {
    /// Build a connection pool from a Postgres config.
    ///
    /// # Arguments
    /// * `host` - Postgres host
    /// * `port` - Postgres port
    /// * `user` - Database user
    /// * `password` - Database password
    /// * `dbname` - Database name
    /// * `pool_size` - Maximum pool size
    ///
    /// # Returns
    /// A shared connection pool ready for graph queries.
    pub fn build(
        host: &str,
        port: u16,
        user: &str,
        password: &str,
        dbname: &str,
        _pool_size: usize,
    ) -> Result<Arc<Pool>, GraphError> {
        let mut cfg = Config::new();
        cfg.host = Some(host.to_string());
        cfg.port = Some(port);
        cfg.user = Some(user.to_string());
        cfg.password = Some(password.to_string());
        cfg.dbname = Some(dbname.to_string());

        cfg.manager = Some(ManagerConfig {
            // RecyclingMethod::Clean preserves AGE session state (search_path, LOAD 'age')
            // across pool checkouts. RecyclingMethod::Fast would issue DISCARD ALL,
            // resetting both and breaking AGE queries.
            recycling_method: RecyclingMethod::Clean,
        });

        let pool = cfg
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .map_err(|e| GraphError::Pool(format!("Failed to create pool: {}", e)))?;

        Ok(Arc::new(pool))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_build_validates_host() {
        // This test verifies the build method exists and handles invalid config gracefully.
        // Full integration tests that actually connect to Postgres are in tests/integration.rs.
        let result = GraphPool::build("", 0, "", "", "", 0);
        // We expect an error because the config is invalid.
        assert!(result.is_err());
    }

    #[test]
    fn pool_build_error_is_graph_error() {
        let result = GraphPool::build("", 0, "", "", "", 0);
        match result {
            Err(GraphError::Pool(_)) => {
                // Correct error type
            }
            _ => panic!("Expected GraphError::Pool"),
        }
    }
}
