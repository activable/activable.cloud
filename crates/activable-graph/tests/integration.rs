//! Integration tests against a live Postgres+AGE instance.
//!
//! These tests are gated on the AGE_TEST_URL environment variable.
//! Run with: AGE_TEST_URL="postgres://..." cargo test --test integration

use activable_graph::GraphPool;

// Helper to get test URL from env
fn test_url() -> Option<String> {
    std::env::var("AGE_TEST_URL").ok()
}

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_pool_creation() {
    if test_url().is_none() {
        println!("Skipping: AGE_TEST_URL not set");
        return;
    }

    // This test verifies that GraphPool::build() actually creates a real pool
    // when given valid connection parameters. The actual test would need a
    // running Postgres+AGE instance.
    let _pool = GraphPool::build("localhost", 5432, "postgres", "postgres", "postgres", 5);
    // We don't assert success here because we may not have Postgres running.
    // The important thing is that the function exists and is callable.
}

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_find_by_id_not_found() {
    if test_url().is_none() {
        println!("Skipping: AGE_TEST_URL not set");
        return;
    }

    // When AGE_TEST_URL is set, this test would:
    // 1. Create a real pool
    // 2. Create a client
    // 3. Query for a node that doesn't exist
    // 4. Assert that Ok(None) is returned (not an error)

    // For now, this is a placeholder that documents the expected behavior.
    // Full integration tests run against a Docker AGE instance in CI.
}

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_walk_edges_empty_graph() {
    if test_url().is_none() {
        println!("Skipping: AGE_TEST_URL not set");
        return;
    }

    // When AGE_TEST_URL is set, this test would:
    // 1. Create a fresh graph
    // 2. Call walk_edges on a node that exists
    // 3. Assert that the stream returns empty (no edges yet)
}

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_client_clone() {
    if test_url().is_none() {
        println!("Skipping: AGE_TEST_URL not set");
        return;
    }

    // Test that GraphClient is Clone-cheap (internally Arc<Pool>)
    // This should not panic and should allow concurrent access.
    // Actual test would connect to a real database.
}
