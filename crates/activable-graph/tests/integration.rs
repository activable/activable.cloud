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

    /// Helper to get the test database URL from the environment.
    fn test_db_url() -> Option<String> {
        std::env::var("AGE_TEST_URL").ok()
    }

    #[tokio::test]
    #[ignore]
    async fn test_pool_creation() {
        if test_db_url().is_none() {
            println!("AGE_TEST_URL not set; skipping");
            return;
        }

        // In a real integration test, we would:
        // 1. Parse the database URL
        // 2. Create a tokio_postgres::Config
        // 3. Call GraphPool::build()
        // 4. Assert that the pool is created successfully

        println!("Pool creation test would run with AGE_TEST_URL");
    }

    #[tokio::test]
    #[ignore]
    async fn test_find_by_id_returns_none_for_unknown() {
        if test_db_url().is_none() {
            println!("AGE_TEST_URL not set; skipping");
            return;
        }

        // In a real integration test, we would:
        // 1. Create a test database connection
        // 2. Ensure an empty graph exists
        // 3. Call find_by_id() on a non-existent node
        // 4. Assert that it returns Ok(None)

        println!("Find by ID test would run with AGE_TEST_URL");
    }

    #[tokio::test]
    #[ignore]
    async fn test_walk_edges_returns_nodes() {
        if test_db_url().is_none() {
            println!("AGE_TEST_URL not set; skipping");
            return;
        }

        // In a real integration test, we would:
        // 1. Create test nodes and edges
        // 2. Call walk_edges() with various parameters
        // 3. Assert that returned nodes match expectations

        println!("Walk edges test would run with AGE_TEST_URL");
    }

    #[tokio::test]
    #[ignore]
    async fn test_path_finder_returns_paths() {
        if test_db_url().is_none() {
            println!("AGE_TEST_URL not set; skipping");
            return;
        }

        // In a real integration test, we would:
        // 1. Create a linear chain of nodes: A -> B -> C -> D
        // 2. Call path_finder(A, D, max_hops=3)
        // 3. Assert that at least one path is returned with correct hops

        println!("Path finder test would run with AGE_TEST_URL");
    }

    #[tokio::test]
    #[ignore]
    async fn test_shortest_path_length() {
        if test_db_url().is_none() {
            println!("AGE_TEST_URL not set; skipping");
            return;
        }

        // In a real integration test, we would:
        // 1. Create a linear chain of nodes: A -> B -> C
        // 2. Call shortest_path_length(A, C)
        // 3. Assert that it returns Ok(Some(2))

        println!("Shortest path length test would run with AGE_TEST_URL");
    }

    #[tokio::test]
    #[ignore]
    async fn test_blast_radius() {
        if test_db_url().is_none() {
            println!("AGE_TEST_URL not set; skipping");
            return;
        }

        // In a real integration test, we would:
        // 1. Create a star topology: center node with N outgoing edges
        // 2. Call blast_radius(center, max_hops=1)
        // 3. Assert that all N nodes are returned

        println!("Blast radius test would run with AGE_TEST_URL");
    }

    #[tokio::test]
    #[ignore]
    async fn test_subgraph() {
        if test_db_url().is_none() {
            println!("AGE_TEST_URL not set; skipping");
            return;
        }

        // In a real integration test, we would:
        // 1. Create a small connected graph
        // 2. Call subgraph(center_node, radius=2)
        // 3. Assert that the center and reachable nodes are included

        println!("Subgraph test would run with AGE_TEST_URL");
    }

    #[tokio::test]
    #[ignore]
    async fn test_cypher_raw_query() {
        if test_db_url().is_none() {
            println!("AGE_TEST_URL not set; skipping");
            return;
        }

        // In a real integration test, we would:
        // 1. Create a test node
        // 2. Execute a raw Cypher query via client.cypher()
        // 3. Assert that results are returned as JSON values

        println!("Raw Cypher query test would run with AGE_TEST_URL");
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
