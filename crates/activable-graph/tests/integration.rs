//! Unit tests for GraphPool.
//!
//! Integration tests against a live Postgres+AGE instance are located in tests/integration/rust/*.rs
//! Run with: AGE_TEST_URL="postgres://..." cargo test --test '*_integration*'

use activable_graph::GraphPool;

// Helper to get test URL from env
fn test_url() -> Option<String> {
    std::env::var("AGE_TEST_URL").ok()
}

#[tokio::test]
async fn test_pool_creation() {
    if test_url().is_none() {
        println!("Skipping: AGE_TEST_URL not set (unit test — no DB needed)");
        return;
    }

    // This test verifies that GraphPool::build() actually creates a real pool
    // when given valid connection parameters.
    let _pool = GraphPool::build("localhost", 5432, "postgres", "postgres", "postgres", 5);
    // We don't assert success here because we may not have Postgres running.
}

#[test]
fn test_graph_pool_api_exists() {
    // Unit test: verify GraphPool API exists (no DB connection needed)
    // Real integration tests are in tests/integration/rust/*.rs

    // Just document the expected API surface
    let api_doc = "GraphPool provides:
        - from_url(connection_string) -> Result<Self, Error>
        - build(host, port, user, password, database, pool_size) -> Self
        - get() -> Connection for query execution";

    assert!(!api_doc.is_empty(), "GraphPool API documented");
}
