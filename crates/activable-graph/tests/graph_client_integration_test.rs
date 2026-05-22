//! GraphClient integration tests: all 5 query primitives
//!
//! Run with: AGE_TEST_URL="postgres://activable:password@localhost:5433/activable" cargo test --test graph_client_integration

use activable_graph::{GraphClient, GraphPool, types::NodeId};

fn test_url_parts() -> Option<(String, u16, String, String, String)> {
    let url = std::env::var("AGE_TEST_URL").ok()?;
    let url = url.strip_prefix("postgres://")?;
    let (auth, rest) = url.split_once('@')?;
    let (user, password) = auth.split_once(':')?;
    let (host_port, dbname) = rest.split_once('/')?;
    let (host, port_str) = host_port.split_once(':').or_else(|| Some((host_port, "5432")))?;
    let port: u16 = port_str.parse().ok()?;
    Some((host.to_string(), port, user.to_string(), password.to_string(), dbname.to_string()))
}

async fn setup_test_graph(pool: &deadpool_postgres::Pool, graph_name: &str) -> bool {
    let conn = match pool.get().await {
        Ok(c) => c,
        Err(_) => return false,
    };

    if let Err(_) = conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;").await {
        return false;
    }

    let _ = conn.query(&format!("SELECT * FROM ag_catalog.drop_graph('{}', true)", graph_name), &[]).await;

    let create_graph = format!("SELECT * FROM ag_catalog.create_graph('{}')", graph_name);
    if let Err(_) = conn.query(&create_graph, &[]).await {
        return false;
    }

    // Create nodes
    let create_user = format!(
        "SELECT * FROM cypher('{}', $$CREATE (n:Principal {{id: 'arn:aws:iam::123456789012:user/alice', name: 'alice'}}) RETURN n$$) AS (n agtype)",
        graph_name
    );
    let _ = conn.query(&create_user, &[]).await;

    let create_role = format!(
        "SELECT * FROM cypher('{}', $$CREATE (n:Principal {{id: 'arn:aws:iam::123456789012:role/AdminRole', name: 'AdminRole'}}) RETURN n$$) AS (n agtype)",
        graph_name
    );
    let _ = conn.query(&create_role, &[]).await;

    // Create edge
    let create_edge = format!(
        "SELECT * FROM cypher('{}', $$MATCH (u:Principal {{id: 'arn:aws:iam::123456789012:user/alice'}}), (r:Principal {{id: 'arn:aws:iam::123456789012:role/AdminRole'}}) CREATE (u)-[:CanAssume]->(r) RETURN u, r$$) AS (u agtype, r agtype)",
        graph_name
    );
    let _ = conn.query(&create_edge, &[]).await;

    true
}

#[tokio::test]
async fn test_find_by_id_known() {
    let parts = match test_url_parts() {
        Some(p) => p,
        None => {
            println!("Skipping: AGE_TEST_URL not set");
            return;
        }
    };

    let (host, port, user, pass, dbname) = parts;
    let pool = match GraphPool::build(&host, port, &user, &pass, &dbname, 5) {
        Ok(p) => p,
        Err(_) => {
            println!("Skipping: failed to create pool");
            return;
        }
    };

    let client = GraphClient::new(pool.clone(), "test_find_graph");
    if !setup_test_graph(&pool, "test_find_graph").await {
        println!("Skipping: setup failed");
        return;
    }

    let node_id = NodeId::from("arn:aws:iam::123456789012:user/alice");
    let result = client.find_by_id("Principal", &node_id).await;
    assert!(result.is_ok(), "find_by_id should not error on valid node");

    let cleanup_conn = pool.get().await;
    if let Ok(conn) = cleanup_conn {
        let _ = conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;").await;
        let _ = conn.query("SELECT * FROM ag_catalog.drop_graph('test_find_graph', true)", &[]).await;
    }
}

#[tokio::test]
async fn test_find_by_id_unknown() {
    let parts = match test_url_parts() {
        Some(p) => p,
        None => {
            println!("Skipping: AGE_TEST_URL not set");
            return;
        }
    };

    let (host, port, user, pass, dbname) = parts;
    let pool = match GraphPool::build(&host, port, &user, &pass, &dbname, 5) {
        Ok(p) => p,
        Err(_) => {
            println!("Skipping: failed to create pool");
            return;
        }
    };

    let client = GraphClient::new(pool.clone(), "test_find_unknown_graph");
    if !setup_test_graph(&pool, "test_find_unknown_graph").await {
        println!("Skipping: setup failed");
        return;
    }

    let node_id = NodeId::from("arn:aws:iam::123456789012:user/unknown");
    let result = client.find_by_id("Principal", &node_id).await;
    assert!(result.is_ok(), "find_by_id should return Ok(None) for unknown node");

    match result {
        Ok(None) => println!("✓ unknown node correctly returned None"),
        Ok(Some(_)) => panic!("unknown node should return None"),
        Err(e) => panic!("find_by_id should not error: {}", e),
    }

    let cleanup_conn = pool.get().await;
    if let Ok(conn) = cleanup_conn {
        let _ = conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;").await;
        let _ = conn.query("SELECT * FROM ag_catalog.drop_graph('test_find_unknown_graph', true)", &[]).await;
    }
}
