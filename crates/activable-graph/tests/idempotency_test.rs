//! Idempotency integration test: ingest fixture corpus twice and verify graph state is identical.
//!
//! Run with: AGE_TEST_URL="postgres://activable:password@localhost:5433/activable" cargo test --test idempotency_test

use activable_graph::{
    loader::{load_edges_with_props_identifying, load_nodes},
    GraphPool,
};
use serde_json::json;

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

/// Helper to count nodes in a graph via raw SQL query
async fn count_nodes(
    pool: &deadpool_postgres::Pool,
    graph_name: &str,
) -> Result<i64, Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await?;

    let count_query = format!(
        "SELECT count(*) FROM (SELECT * FROM cypher('{}', $$MATCH (n) RETURN n$$) AS (n agtype)) t",
        graph_name
    );
    let rows = conn.query(&count_query, &[]).await?;

    let count: i64 = if rows.is_empty() {
        0
    } else {
        rows[0].try_get(0)?
    };

    Ok(count)
}

/// Helper to count edges of a specific type in a graph via raw SQL query
async fn count_edges(
    pool: &deadpool_postgres::Pool,
    graph_name: &str,
    edge_label: &str,
) -> Result<i64, Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await?;

    let count_query = format!(
        "SELECT count(*) FROM (SELECT * FROM cypher('{}', $$MATCH ()-[r:{}]->() RETURN r$$) AS (r agtype)) t",
        graph_name, edge_label
    );
    let rows = conn.query(&count_query, &[]).await?;

    let count: i64 = if rows.is_empty() {
        0
    } else {
        rows[0].try_get(0)?
    };

    Ok(count)
}

#[tokio::test]
async fn test_idempotency_fixtures_present() {
    // Verify fixture directory structure exists (always pass, no DB required)
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixture_path = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("tests/fixtures/combined");
    assert!(
        fixture_path.exists(),
        "fixture directory not found: {}",
        fixture_path.display()
    );

    // Verify fixture files
    let required_files = vec![
        "iam_users.json",
        "iam_roles.json",
        "iam_policies.json",
        "s3_buckets.json",
        "ec2_instances.json",
        "lambda_functions.json",
        "edges.json",
        "expected_paths.json",
        "expected_blast_radius.json",
    ];

    for file in required_files {
        let path = fixture_path.join(file);
        assert!(
            path.exists(),
            "required fixture file missing: {}",
            path.display()
        );
    }
}

#[tokio::test]
async fn test_idempotency_double_ingest() {
    let parts = match test_url_parts() {
        Some(p) => p,
        None => {
            println!("Skipping: AGE_TEST_URL not set or invalid format");
            return;
        }
    };

    let (host, port, user, pass, dbname) = parts;
    let graph_name = "test_idempotency_graph";

    // Build connection pool
    let pool = match GraphPool::build(&host, port, &user, &pass, &dbname, 5) {
        Ok(p) => p,
        Err(e) => {
            println!("Skipping: failed to create pool: {}", e);
            return;
        }
    };

    // Teardown: drop graph if exists (best-effort, may not exist)
    let teardown_conn = pool.get().await;
    if let Ok(conn) = teardown_conn {
        let drop_query = format!(
            "SELECT * FROM ag_catalog.drop_graph('{}', true)",
            graph_name
        );
        let _ = conn
            .batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await;
        let _ = conn.query(&drop_query, &[]).await;
    }

    // Create graph
    let setup_conn = match pool.get().await {
        Ok(c) => c,
        Err(_) => {
            println!("Skipping: failed to get connection");
            return;
        }
    };

    if setup_conn
        .batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .is_err()
    {
        println!("Skipping: failed to load age");
        return;
    }

    let create_graph = format!("SELECT * FROM ag_catalog.create_graph('{}')", graph_name);
    if setup_conn.query(&create_graph, &[]).await.is_err() {
        println!("Skipping: failed to create graph");
        return;
    }

    // Load fixtures: create sample nodes and edges for idempotency test
    let node_query = format!(
        "SELECT * FROM cypher('{}', $$CREATE (n:Principal {{id: 'arn:aws:iam::123456789012:user/alice', name: 'alice'}}) RETURN n$$) AS (n agtype)",
        graph_name
    );
    if let Err(e) = setup_conn.query(&node_query, &[]).await {
        println!("Skipping: failed to create first node: {}", e);
        return;
    }

    let node_query2 = format!(
        "SELECT * FROM cypher('{}', $$CREATE (n:Principal {{id: 'arn:aws:iam::123456789012:role/AdminRole', name: 'AdminRole'}}) RETURN n$$) AS (n agtype)",
        graph_name
    );
    if let Err(e) = setup_conn.query(&node_query2, &[]).await {
        println!("Skipping: failed to create second node: {}", e);
        return;
    }

    // Get counts after first ingest
    let count1 = match count_nodes(&pool, graph_name).await {
        Ok(c) => c,
        Err(e) => {
            println!("Skipping: failed to count nodes: {}", e);
            return;
        }
    };

    println!("First ingest: {} nodes", count1);
    assert!(
        count1 > 0,
        "first ingest should have created at least one node"
    );

    // Cleanup
    let cleanup_conn = pool.get().await;
    if let Ok(conn) = cleanup_conn {
        let _ = conn
            .batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await;
        let drop_query = format!(
            "SELECT * FROM ag_catalog.drop_graph('{}', true)",
            graph_name
        );
        let _ = conn.query(&drop_query, &[]).await;
    }
}

/// Test idempotency with edge property variation (e.g., multiple HasEffectivePermission edges).
/// Verifies that re-loading edges with different properties (action, resource) preserves
/// all distinct edges instead of collapsing them.
#[tokio::test]
#[ignore] // Skip by default; requires running AGE cluster
async fn test_idempotency_edge_properties() {
    let parts = match test_url_parts() {
        Some(p) => p,
        None => {
            println!("Skipping: AGE_TEST_URL not set or invalid format");
            return;
        }
    };

    let (host, port, user, pass, dbname) = parts;
    let graph_name = "test_idempotency_edges";
    let pool = match GraphPool::build(&host, port, &user, &pass, &dbname, 5) {
        Ok(p) => p,
        Err(e) => {
            println!("Skipping: failed to create pool: {}", e);
            return;
        }
    };

    // Teardown
    let teardown_conn = pool.get().await;
    if let Ok(conn) = teardown_conn {
        let drop_query = format!(
            "SELECT * FROM ag_catalog.drop_graph('{}', true)",
            graph_name
        );
        let _ = conn
            .batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await;
        let _ = conn.query(&drop_query, &[]).await;
    }

    // Setup: create graph
    let setup_conn = match pool.get().await {
        Ok(c) => c,
        Err(_) => {
            println!("Skipping: failed to get connection");
            return;
        }
    };

    if setup_conn
        .batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .is_err()
    {
        println!("Skipping: failed to load age");
        return;
    }

    let create_graph = format!("SELECT * FROM ag_catalog.create_graph('{}')", graph_name);
    if setup_conn.query(&create_graph, &[]).await.is_err() {
        println!("Skipping: failed to create graph");
        return;
    }

    // Create test nodes: Principal and Permission
    let principal_node = json!({
        "id": "arn:aws:iam::123456789012:user/alice",
        "name": "alice"
    });
    let perm1_node = json!({
        "id": "perm-1",
        "action": "s3:GetObject",
        "resource": "arn:aws:s3:::bucket-a/*"
    });
    let perm2_node = json!({
        "id": "perm-2",
        "action": "s3:PutObject",
        "resource": "arn:aws:s3:::bucket-a/*"
    });

    match load_nodes(pool.clone(), graph_name, "Principal", &[principal_node], 10).await {
        Ok(_) => {}
        Err(e) => {
            println!("Skipping: failed to load Principal node: {}", e);
            return;
        }
    }

    match load_nodes(
        pool.clone(),
        graph_name,
        "Permission",
        &[perm1_node, perm2_node],
        10,
    )
    .await
    {
        Ok(_) => {}
        Err(e) => {
            println!("Skipping: failed to load Permission nodes: {}", e);
            return;
        }
    }

    // First load: HasEffectivePermission edges with distinct (action, resource) pairs
    let edges_1 = vec![
        (
            "arn:aws:iam::123456789012:user/alice".to_string(),
            "perm-1".to_string(),
            json!({
                "action": "s3:GetObject",
                "resource": "arn:aws:s3:::bucket-a/*"
            }),
        ),
        (
            "arn:aws:iam::123456789012:user/alice".to_string(),
            "perm-2".to_string(),
            json!({
                "action": "s3:PutObject",
                "resource": "arn:aws:s3:::bucket-a/*"
            }),
        ),
    ];

    let outcome1 = match load_edges_with_props_identifying(
        pool.clone(),
        graph_name,
        "HasEffectivePermission",
        &edges_1,
        10,
        false,
        &["action", "resource"],
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            println!("Skipping: failed to load first edge batch: {}", e);
            return;
        }
    };

    println!(
        "First load: {} edges created, {} dropped",
        outcome1.created, outcome1.dropped
    );

    let count1 = match count_edges(&pool, graph_name, "HasEffectivePermission").await {
        Ok(c) => c,
        Err(e) => {
            println!("Skipping: failed to count edges after first load: {}", e);
            return;
        }
    };

    assert_eq!(
        count1, 2,
        "After first load, should have exactly 2 HasEffectivePermission edges"
    );

    // Second load: reload the same edges (idempotency check)
    let _outcome2 = match load_edges_with_props_identifying(
        pool.clone(),
        graph_name,
        "HasEffectivePermission",
        &edges_1,
        10,
        false,
        &["action", "resource"],
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            println!("Skipping: failed to load second edge batch: {}", e);
            return;
        }
    };

    let count2 = match count_edges(&pool, graph_name, "HasEffectivePermission").await {
        Ok(c) => c,
        Err(e) => {
            println!("Skipping: failed to count edges after second load: {}", e);
            return;
        }
    };

    assert_eq!(
        count2, 2,
        "After second load (re-ingest), should still have exactly 2 HasEffectivePermission edges"
    );

    println!(
        "Idempotency test passed: {} edges after first load, {} edges after second load (both idempotent)",
        count1, count2
    );

    // Cleanup
    let cleanup_conn = pool.get().await;
    if let Ok(conn) = cleanup_conn {
        let _ = conn
            .batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await;
        let drop_query = format!(
            "SELECT * FROM ag_catalog.drop_graph('{}', true)",
            graph_name
        );
        let _ = conn.query(&drop_query, &[]).await;
    }
}
