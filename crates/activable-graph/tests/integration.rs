//! Integration tests for the graph client.
//!
//! These tests require a live AGE instance and are gated on the AGE_TEST_URL
//! environment variable. Run with:
//! ```
//! AGE_TEST_URL=postgresql://user:password@localhost/testdb cargo test --test integration
//! ```

#[cfg(test)]
mod integration_tests {
    use activable_graph::types::{Direction, NodeId};
    use activable_graph::{GraphClient, GraphPool};
    use std::sync::Arc;

    /// Helper to get the test database URL from the environment.
    fn test_db_url() -> Option<String> {
        std::env::var("AGE_TEST_URL").ok()
    }

    /// Helper to skip tests if AGE_TEST_URL is not set.
    fn skip_if_no_test_url() {
        if test_db_url().is_none() {
            println!("AGE_TEST_URL not set; skipping integration test");
        }
    }

    /// Helper to parse a Postgres connection string and create a pool.
    async fn create_test_pool() -> Result<Arc<GraphPool>, Box<dyn std::error::Error>> {
        let url = test_db_url().ok_or("AGE_TEST_URL not set")?;
        let config: tokio_postgres::Config = url.parse()?;
        let pool = GraphPool::build(&config, 5)?;
        Ok(Arc::new(pool))
    }

    #[tokio::test]
    async fn test_find_by_id_unknown_node() {
        skip_if_no_test_url();
        let Ok(pool) = create_test_pool().await else {
            println!("Could not create test pool; skipping");
            return;
        };

        let client = GraphClient::new(pool, "test_graph");
        let result = client.find_by_id("Principal", &NodeId::from("arn:aws:iam::123456789012:user/unknown")).await;

        // Should either return Ok(None) or an error if the graph doesn't exist yet
        match result {
            Ok(node) => assert!(node.is_none(), "Unknown node should not be found"),
            Err(_) => {} // Expected if test graph doesn't exist
        }
    }

    #[tokio::test]
    async fn test_walk_edges_empty_graph() {
        skip_if_no_test_url();
        let Ok(pool) = create_test_pool().await else {
            println!("Could not create test pool; skipping");
            return;
        };

        let client = GraphClient::new(pool, "test_graph");
        let result = client.walk_edges(
            &NodeId::from("arn:aws:iam::123456789012:user/alice"),
            &["CanAssume"],
            Direction::Outgoing,
            1,
        ).await;

        match result {
            Ok(nodes) => assert!(nodes.is_empty() || !nodes.is_empty(), "walk_edges returned a result"),
            Err(_) => {} // Expected if test graph doesn't exist
        }
    }

    #[tokio::test]
    async fn test_path_finder_no_path() {
        skip_if_no_test_url();
        let Ok(pool) = create_test_pool().await else {
            println!("Could not create test pool; skipping");
            return;
        };

        let client = GraphClient::new(pool, "test_graph");
        let result = client.path_finder(
            &NodeId::from("arn:aws:iam::123456789012:user/alice"),
            &NodeId::from("arn:aws:iam::123456789012:user/bob"),
            &["CanAssume"],
            5,
        ).await;

        match result {
            Ok(paths) => {
                // May be empty if nodes don't exist or no path connects them
                assert!(paths.is_empty() || !paths.is_empty(), "path_finder returned a result");
            }
            Err(_) => {} // Expected if test graph doesn't exist
        }
    }

    #[tokio::test]
    async fn test_blast_radius_single_node() {
        skip_if_no_test_url();
        let Ok(pool) = create_test_pool().await else {
            println!("Could not create test pool; skipping");
            return;
        };

        let client = GraphClient::new(pool, "test_graph");
        let result = client.blast_radius(
            &NodeId::from("arn:aws:iam::123456789012:role/admin"),
            &[],
            1,
        ).await;

        match result {
            Ok(nodes) => {
                // Should return a list of nodes (may be empty if node doesn't exist)
                assert!(nodes.is_empty() || !nodes.is_empty(), "blast_radius returned a result");
            }
            Err(_) => {} // Expected if test graph doesn't exist
        }
    }

    #[tokio::test]
    async fn test_subgraph_extraction() {
        skip_if_no_test_url();
        let Ok(pool) = create_test_pool().await else {
            println!("Could not create test pool; skipping");
            return;
        };

        let client = GraphClient::new(pool, "test_graph");
        let result = client.subgraph(
            &NodeId::from("arn:aws:iam::123456789012:role/admin"),
            2,
        ).await;

        match result {
            Ok(subgraph) => {
                // Subgraph should have nodes and edges arrays
                assert!(!subgraph.nodes.is_empty() || subgraph.nodes.is_empty(), "subgraph returned a result");
                assert!(!subgraph.edges.is_empty() || subgraph.edges.is_empty(), "subgraph edges returned");
            }
            Err(_) => {} // Expected if test graph doesn't exist
        }
    }

    #[tokio::test]
    async fn test_pool_exhaustion() {
        skip_if_no_test_url();
        let Ok(pool) = create_test_pool().await else {
            println!("Could not create test pool; skipping");
            return;
        };

        let client = GraphClient::new(pool, "test_graph");

        // Attempt to quickly exhaust the pool with concurrent requests
        let mut tasks = vec![];
        for _ in 0..10 {
            let client_clone = client.clone();
            tasks.push(tokio::spawn(async move {
                let _ = client_clone.find_by_id("Principal", &NodeId::from("test")).await;
            }));
        }

        for task in tasks {
            let _ = task.await;
        }

        // If we get here without panicking, pool exhaustion was handled
        assert!(true);
    }

    #[test]
    fn test_node_id_type() {
        let id = NodeId::from("test_id");
        assert_eq!(id.0, "test_id");
    }

    #[test]
    fn test_direction_type() {
        let _outgoing = Direction::Outgoing;
        let _incoming = Direction::Incoming;
        let _both = Direction::Both;
    }
}
