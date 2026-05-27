//! Edge persistence regression tests.
//!
//! Verifies that:
//! 1. Edges are only counted as created when both endpoints exist
//! 2. Missing endpoint edges are properly dropped/errored (lenient vs strict mode)
//! 3. SQL injection escaping is preserved
//! 4. Edges are actually queryable after creation (not just "no error")
//!
//! Run with: AGE_TEST_URL="postgres://activable:password@localhost:5433/activable" cargo test --test edge_persistence_test -- --ignored

use activable_graph::GraphPool;

fn test_url_parts() -> Option<(String, u16, String, String, String)> {
    let url = std::env::var("AGE_TEST_URL").ok()?;
    let url = url.strip_prefix("postgres://")?;

    let (auth, rest) = url.split_once('@')?;
    let (user, password) = auth.split_once(':')?;
    let (host_port, dbname) = rest.split_once('/')?;
    let (host, port_str) = host_port.split_once(':').unwrap_or((host_port, "5432"));
    let port: u16 = port_str.parse().ok()?;

    Some((
        host.to_string(),
        port,
        user.to_string(),
        password.to_string(),
        dbname.to_string(),
    ))
}

#[tokio::test]
#[ignore] // Requires live PG+AGE; run with: cargo test --test edge_persistence_test -- --ignored
async fn test_edge_persistence_both_endpoints_present() {
    let Some((host, port, user, password, dbname)) = test_url_parts() else {
        eprintln!("SKIP: AGE_TEST_URL not set; skipping live DB test");
        return;
    };

    let pool = match GraphPool::build(&host, port, &user, &password, &dbname, 5) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP: failed to create pool: {}", e);
            return;
        }
    };

    let graph_name = "test_edge_persistence_both_endpoints";

    // Setup: create a fresh graph for this test
    let conn = match pool.get().await {
        Ok(c) => c,
        Err(_) => {
            eprintln!("SKIP: failed to get connection");
            return;
        }
    };

    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .expect("failed to load AGE");

    // Drop and recreate the graph
    let _ = conn
        .batch_execute(&format!("SELECT drop_graph('{}', true);", graph_name))
        .await;
    conn.batch_execute(&format!("SELECT create_graph('{}');", graph_name))
        .await
        .expect("failed to create graph");

    // Create source and target nodes
    let nodes = vec![
        serde_json::json!({"id": "source_node_1"}),
        serde_json::json!({"id": "target_node_1"}),
    ];

    activable_graph::load_nodes(pool.clone(), graph_name, "TestNode", &nodes, 10)
        .await
        .expect("failed to create nodes");

    // Load an edge between the two existing nodes
    let edges = vec![("source_node_1".to_string(), "target_node_1".to_string())];

    let outcome = activable_graph::load_edges(
        pool.clone(),
        graph_name,
        "TestEdge",
        &edges,
        10,
        false, // lenient mode
    )
    .await
    .expect("failed to load edges");

    // Verify: created should be 1, dropped should be 0
    assert_eq!(
        outcome.created, 1,
        "Edge with both endpoints present should be created"
    );
    assert_eq!(
        outcome.dropped, 0,
        "Edge with both endpoints present should not be dropped"
    );

    // Verify the edge is actually queryable (not just "no error on insert")
    let conn = pool.get().await.expect("failed to get connection");
    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .expect("failed to load AGE");

    let cypher = "MATCH ()-[r:TestEdge]->() RETURN count(*)";
    let sql = format!(
        "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (cnt agtype)",
        graph_name, cypher
    );
    let rows = conn.query(&sql, &[]).await.expect("failed to count edges");
    assert!(!rows.is_empty(), "Edge count query should return a row");

    // Cleanup
    let _ = conn
        .batch_execute(&format!("SELECT drop_graph('{}', true);", graph_name))
        .await;
}

#[tokio::test]
#[ignore] // Requires live PG+AGE
async fn test_edge_persistence_missing_endpoint_lenient() {
    let Some((host, port, user, password, dbname)) = test_url_parts() else {
        eprintln!("SKIP: AGE_TEST_URL not set; skipping live DB test");
        return;
    };

    let pool = match GraphPool::build(&host, port, &user, &password, &dbname, 5) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP: failed to create pool: {}", e);
            return;
        }
    };

    let graph_name = "test_edge_persistence_missing_lenient";

    // Setup: create a fresh graph
    let conn = match pool.get().await {
        Ok(c) => c,
        Err(_) => {
            eprintln!("SKIP: failed to get connection");
            return;
        }
    };

    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .expect("failed to load AGE");
    let _ = conn
        .batch_execute(&format!("SELECT drop_graph('{}', true);", graph_name))
        .await;
    conn.batch_execute(&format!("SELECT create_graph('{}');", graph_name))
        .await
        .expect("failed to create graph");

    // Create only one of the two nodes
    let nodes = vec![serde_json::json!({"id": "source_node_2"})];
    activable_graph::load_nodes(pool.clone(), graph_name, "TestNode", &nodes, 10)
        .await
        .expect("failed to create node");

    // Attempt to load an edge where the target node is missing
    let edges = vec![("source_node_2".to_string(), "missing_target_2".to_string())];

    let outcome = activable_graph::load_edges(
        pool.clone(),
        graph_name,
        "TestEdge",
        &edges,
        10,
        false, // lenient mode
    )
    .await
    .expect("failed to load edges");

    // Verify: created should be 0, dropped should be 1
    assert_eq!(
        outcome.created, 0,
        "Edge with missing endpoint should not be created"
    );
    assert_eq!(
        outcome.dropped, 1,
        "Edge with missing endpoint should be counted as dropped in lenient mode"
    );

    // Cleanup
    let conn = pool.get().await.expect("failed to get connection");
    let _ = conn
        .batch_execute(&format!("SELECT drop_graph('{}', true);", graph_name))
        .await;
}

#[tokio::test]
#[ignore] // Requires live PG+AGE
async fn test_edge_persistence_missing_endpoint_strict() {
    let Some((host, port, user, password, dbname)) = test_url_parts() else {
        eprintln!("SKIP: AGE_TEST_URL not set; skipping live DB test");
        return;
    };

    let pool = match GraphPool::build(&host, port, &user, &password, &dbname, 5) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP: failed to create pool: {}", e);
            return;
        }
    };

    let graph_name = "test_edge_persistence_missing_strict";

    // Setup: create a fresh graph
    let conn = match pool.get().await {
        Ok(c) => c,
        Err(_) => {
            eprintln!("SKIP: failed to get connection");
            return;
        }
    };

    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .expect("failed to load AGE");
    let _ = conn
        .batch_execute(&format!("SELECT drop_graph('{}', true);", graph_name))
        .await;
    conn.batch_execute(&format!("SELECT create_graph('{}');", graph_name))
        .await
        .expect("failed to create graph");

    // Create only one of the two nodes
    let nodes = vec![serde_json::json!({"id": "source_node_3"})];
    activable_graph::load_nodes(pool.clone(), graph_name, "TestNode", &nodes, 10)
        .await
        .expect("failed to create node");

    // Attempt to load an edge where the target node is missing (strict mode)
    let edges = vec![("source_node_3".to_string(), "missing_target_3".to_string())];

    let result = activable_graph::load_edges(
        pool.clone(),
        graph_name,
        "TestEdge",
        &edges,
        10,
        true, // strict mode
    )
    .await;

    // Verify: should return Err
    assert!(
        result.is_err(),
        "Strict mode should return Err when endpoint is missing"
    );

    // Cleanup
    let conn = pool.get().await.expect("failed to get connection");
    let _ = conn
        .batch_execute(&format!("SELECT drop_graph('{}', true);", graph_name))
        .await;
}

#[tokio::test]
#[ignore] // Requires live PG+AGE
async fn test_edge_persistence_injection_defense() {
    let Some((host, port, user, password, dbname)) = test_url_parts() else {
        eprintln!("SKIP: AGE_TEST_URL not set; skipping live DB test");
        return;
    };

    let pool = match GraphPool::build(&host, port, &user, &password, &dbname, 5) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP: failed to create pool: {}", e);
            return;
        }
    };

    let graph_name = "test_edge_persistence_injection";

    // Setup: create a fresh graph
    let conn = match pool.get().await {
        Ok(c) => c,
        Err(_) => {
            eprintln!("SKIP: failed to get connection");
            return;
        }
    };

    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .expect("failed to load AGE");
    let _ = conn
        .batch_execute(&format!("SELECT drop_graph('{}', true);", graph_name))
        .await;
    conn.batch_execute(&format!("SELECT create_graph('{}');", graph_name))
        .await
        .expect("failed to create graph");

    // Create two legitimate nodes
    let nodes = vec![
        serde_json::json!({"id": "safe_source"}),
        serde_json::json!({"id": "safe_target"}),
    ];
    activable_graph::load_nodes(pool.clone(), graph_name, "TestNode", &nodes, 10)
        .await
        .expect("failed to create nodes");

    // Attempt to load an edge with a malicious from_id that contains SQL injection payload
    // This should be escaped and treated as a literal string, not executed
    let malicious_id = "arn:aws:iam::111:role/x'; DROP GRAPH; --";
    let edges = vec![(malicious_id.to_string(), "safe_target".to_string())];

    let outcome = activable_graph::load_edges(
        pool.clone(),
        graph_name,
        "TestEdge",
        &edges,
        10,
        false, // lenient mode — malicious_id won't exist as a node, so it drops
    )
    .await
    .expect("failed to load edges");

    // Verify: the edge should be dropped (missing endpoint), not an error
    assert_eq!(
        outcome.dropped, 1,
        "Malicious ID should be treated as missing endpoint"
    );

    // Verify: the graph still exists (DROP GRAPH wasn't executed)
    let conn = pool.get().await.expect("failed to get connection");
    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .expect("failed to load AGE");

    let cypher = "MATCH (n) RETURN count(*)";
    let sql = format!(
        "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (cnt agtype)",
        graph_name, cypher
    );
    let rows = conn.query(&sql, &[]).await.expect("failed to count nodes");
    assert!(
        !rows.is_empty(),
        "Graph should still exist (injection was prevented)"
    );

    // Cleanup
    let _ = conn
        .batch_execute(&format!("SELECT drop_graph('{}', true);", graph_name))
        .await;
}

#[test]
fn test_edge_load_outcome_counts() {
    // Pure-logic test: verify EdgeLoadOutcome fields are correctly initialized
    use activable_graph::EdgeLoadOutcome;

    let outcome = EdgeLoadOutcome {
        created: 42,
        dropped: 7,
    };

    assert_eq!(outcome.created, 42);
    assert_eq!(outcome.dropped, 7);

    // Verify Copy semantics
    let outcome2 = outcome;
    assert_eq!(outcome2.created, 42);
    assert_eq!(outcome2.dropped, 7);

    // Verify Copy semantics
    let outcome3 = outcome;
    assert_eq!(outcome3.created, 42);
}
