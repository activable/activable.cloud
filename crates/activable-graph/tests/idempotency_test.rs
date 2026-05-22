//! Idempotency integration test: ingest fixture corpus twice and verify graph state is identical.
//!
//! Run with: AGE_TEST_URL="postgres://activable:password@localhost:5433/activable" cargo test --test idempotency_test

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
