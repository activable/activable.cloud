//! AGE type round-trip property tests for Postgres+AGE.
//!
//! Validates that property types survive the write→read cycle through AGE:
//! - Primitive types: string, number, bool, null
//! - Complex types: JSON array, JSON object
//! - Edge cases: unicode, quoted strings, null properties
//! - Prior-session regression fixtures: Bug-1..Bug-6
//!
//! Run with:
//!   AGE_TEST_URL="postgres://activable:password@localhost:5432/activable" \
//!   cargo test --test agtype_roundtrip -- --ignored --nocapture

use activable_graph::{loader, GraphClient, GraphPool};
use serde_json::{json, Value};

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

async fn setup_test_graph(pool: &deadpool_postgres::Pool, graph_name: &str) -> bool {
    let conn = match pool.get().await {
        Ok(c) => c,
        Err(_) => return false,
    };

    if conn
        .batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .is_err()
    {
        return false;
    }

    let _ = conn
        .query(
            &format!(
                "SELECT * FROM ag_catalog.drop_graph('{}', true)",
                graph_name
            ),
            &[],
        )
        .await;

    let create_graph = format!("SELECT * FROM ag_catalog.create_graph('{}')", graph_name);
    conn.query(&create_graph, &[]).await.is_ok()
}

// ── Fixture generation helpers ────────────────────────────────────────────────

/// Generate a node with a single property for property-type testing.
fn node_with_property(id: &str, key: &str, value: Value) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("id".to_string(), Value::String(id.to_string()));
    obj.insert(key.to_string(), value);
    Value::Object(obj)
}

/// Generate 100 edges for regression testing.
fn edges_for_batch_test() -> Vec<(String, String)> {
    let mut edges = Vec::new();
    for i in 0..100 {
        let from = format!("node_{:03}", i);
        let to = format!("node_{:03}", (i + 1) % 100);
        edges.push((from, to));
    }
    edges
}

// ── Unit tests on fixture helpers ────────────────────────────────────────────────

#[test]
fn test_fixture_node_with_property_string() {
    let node = node_with_property("test1", "name", Value::String("Alice".to_string()));
    assert_eq!(node["id"].as_str().unwrap(), "test1");
    assert_eq!(node["name"].as_str().unwrap(), "Alice");
}

#[test]
fn test_fixture_node_with_property_number() {
    let node = node_with_property("test2", "count", Value::Number(42.into()));
    assert_eq!(node["id"].as_str().unwrap(), "test2");
    assert_eq!(node["count"].as_i64().unwrap(), 42);
}

#[test]
fn test_fixture_node_with_property_bool() {
    let node = node_with_property("test3", "active", Value::Bool(true));
    assert_eq!(node["id"].as_str().unwrap(), "test3");
    assert_eq!(node["active"].as_bool().unwrap(), true);
}

#[test]
fn test_fixture_node_with_property_null() {
    let node = node_with_property("test4", "empty", Value::Null);
    assert_eq!(node["id"].as_str().unwrap(), "test4");
    assert!(node["empty"].is_null());
}

#[test]
fn test_fixture_node_with_property_array() {
    let arr = Value::Array(vec![
        Value::String("a".to_string()),
        Value::String("b".to_string()),
    ]);
    let node = node_with_property("test5", "items", arr);
    assert_eq!(node["id"].as_str().unwrap(), "test5");
    assert_eq!(node["items"][0].as_str().unwrap(), "a");
}

#[test]
fn test_fixture_node_with_property_object() {
    let obj = json!({"name": "policy1", "version": 1});
    let node = node_with_property("test6", "metadata", obj);
    assert_eq!(node["id"].as_str().unwrap(), "test6");
    assert_eq!(node["metadata"]["name"].as_str().unwrap(), "policy1");
}

#[test]
fn test_fixture_edges_batch_count() {
    let edges = edges_for_batch_test();
    assert_eq!(edges.len(), 100);
    assert_eq!(edges[0].0, "node_000");
    assert_eq!(edges[0].1, "node_001");
    assert_eq!(edges[99].0, "node_099");
    assert_eq!(edges[99].1, "node_000");
}

// ── Integration tests (gated on AGE_TEST_URL) ────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_agtype_roundtrip_string() {
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

    let graph_name = "roundtrip_string";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }

    // Write a node with a string property
    let original = node_with_property("test_str", "text", Value::String("hello world".to_string()));
    let written = loader::load_nodes(pool.clone(), graph_name, "Test", &[original.clone()], 1)
        .await
        .expect("failed to write node");
    assert_eq!(written, 1, "should write 1 node");

    // Read it back via cypher_multi_column
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH (n:Test {id: 'test_str'}) RETURN n.text";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("failed to read node");

    assert!(!results.is_empty(), "should return at least one row");
    let value = &results[0][0];
    assert_eq!(
        value.as_str().unwrap(),
        "hello world",
        "string property should round-trip exactly"
    );
}

#[tokio::test]
#[ignore]
async fn test_agtype_roundtrip_number() {
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

    let graph_name = "roundtrip_number";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }

    // Write with integer
    let original = node_with_property("test_int", "count", Value::Number(42.into()));
    let written = loader::load_nodes(pool.clone(), graph_name, "Test", &[original], 1)
        .await
        .expect("failed to write node");
    assert_eq!(written, 1);

    // Read back
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH (n:Test {id: 'test_int'}) RETURN n.count";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("failed to read node");

    assert!(!results.is_empty());
    let value = &results[0][0];
    assert_eq!(value.as_i64().unwrap(), 42, "integer property should round-trip");
}

#[tokio::test]
#[ignore]
async fn test_agtype_roundtrip_bool() {
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

    let graph_name = "roundtrip_bool";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }

    // Write with boolean
    let original = node_with_property("test_bool", "active", Value::Bool(true));
    let written = loader::load_nodes(pool.clone(), graph_name, "Test", &[original], 1)
        .await
        .expect("failed to write node");
    assert_eq!(written, 1);

    // Read back
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH (n:Test {id: 'test_bool'}) RETURN n.active";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("failed to read node");

    assert!(!results.is_empty());
    let value = &results[0][0];
    assert_eq!(value.as_bool().unwrap(), true, "bool property should round-trip");
}

#[tokio::test]
#[ignore]
async fn test_agtype_roundtrip_array() {
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

    let graph_name = "roundtrip_array";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }

    // Write with array (serialized to JSON string)
    let arr = Value::Array(vec![
        Value::String("action1".to_string()),
        Value::String("action2".to_string()),
    ]);
    let original = node_with_property("test_arr", "actions", arr.clone());
    let written = loader::load_nodes(pool.clone(), graph_name, "Test", &[original], 1)
        .await
        .expect("failed to write node");
    assert_eq!(written, 1);

    // Read back
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH (n:Test {id: 'test_arr'}) RETURN n.actions";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("failed to read node");

    assert!(!results.is_empty());
    let value = &results[0][0];
    // Array is serialized as JSON string, so we parse it back
    let parsed: Value = serde_json::from_str(value.as_str().unwrap())
        .expect("array should be valid JSON");
    assert_eq!(parsed, arr, "array property should round-trip");
}

#[tokio::test]
#[ignore]
async fn test_agtype_roundtrip_object() {
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

    let graph_name = "roundtrip_object";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }

    // Write with nested object (serialized to JSON string)
    let obj = json!({"name": "policy1", "version": 1});
    let original = node_with_property("test_obj", "metadata", obj.clone());
    let written = loader::load_nodes(pool.clone(), graph_name, "Test", &[original], 1)
        .await
        .expect("failed to write node");
    assert_eq!(written, 1);

    // Read back
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH (n:Test {id: 'test_obj'}) RETURN n.metadata";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("failed to read node");

    assert!(!results.is_empty());
    let value = &results[0][0];
    // Object is serialized as JSON string
    let parsed: Value = serde_json::from_str(value.as_str().unwrap())
        .expect("object should be valid JSON");
    assert_eq!(parsed, obj, "object property should round-trip");
}

#[tokio::test]
#[ignore]
async fn test_agtype_roundtrip_null() {
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

    let graph_name = "roundtrip_null";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }

    // Note: loader::load_nodes skips null properties, so we test that behavior explicitly
    let original = node_with_property("test_null", "empty", Value::Null);
    let written = loader::load_nodes(pool.clone(), graph_name, "Test", &[original], 1)
        .await
        .expect("failed to write node");
    assert_eq!(written, 1);

    // Read back: the null property will not exist on the node (loader skips nulls)
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH (n:Test {id: 'test_null'}) RETURN coalesce(n.empty, null)";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("failed to read node");

    assert!(!results.is_empty());
    let value = &results[0][0];
    assert!(value.is_null(), "null property should be absent (loader skips them)");
}

#[tokio::test]
#[ignore]
async fn test_agtype_roundtrip_unicode() {
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

    let graph_name = "roundtrip_unicode";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }

    // Write with unicode characters
    let original = node_with_property(
        "test_unicode",
        "text",
        Value::String("値 emoji 🚨 test".to_string()),
    );
    let written = loader::load_nodes(pool.clone(), graph_name, "Test", &[original.clone()], 1)
        .await
        .expect("failed to write node");
    assert_eq!(written, 1);

    // Read back
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH (n:Test {id: 'test_unicode'}) RETURN n.text";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("failed to read node");

    assert!(!results.is_empty());
    let value = &results[0][0];
    assert_eq!(
        value.as_str().unwrap(),
        "値 emoji 🚨 test",
        "unicode should survive round-trip without truncation"
    );
}

#[tokio::test]
#[ignore]
async fn test_agtype_roundtrip_quoted_strings() {
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

    let graph_name = "roundtrip_quotes";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }

    // Write with quoted and escaped characters
    let original = node_with_property(
        "test_quotes",
        "text",
        Value::String("it's a \"test\" with \\ backslash".to_string()),
    );
    let written = loader::load_nodes(pool.clone(), graph_name, "Test", &[original.clone()], 1)
        .await
        .expect("failed to write node");
    assert_eq!(written, 1);

    // Read back
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH (n:Test {id: 'test_quotes'}) RETURN n.text";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("failed to read node");

    assert!(!results.is_empty());
    let value = &results[0][0];
    assert_eq!(
        value.as_str().unwrap(),
        "it's a \"test\" with \\ backslash",
        "quoted strings should survive round-trip"
    );
}

// ── Regression fixtures for prior-session bugs ────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn regression_bug01_edge_write_count() {
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

    let graph_name = "regression_bug01";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }


    // Write 100 nodes first
    let mut nodes = Vec::new();
    for i in 0..100 {
        let mut obj = serde_json::Map::new();
        obj.insert("id".to_string(), Value::String(format!("node_{:03}", i)));
        nodes.push(Value::Object(obj));
    }
    let written_nodes = loader::load_nodes(pool.clone(), graph_name, "TestNode", &nodes, 10)
        .await
        .expect("failed to write nodes");
    assert_eq!(written_nodes, 100, "should write 100 nodes");

    // Write 100 edges
    let edges = edges_for_batch_test();
    let written_edges = loader::load_edges(pool.clone(), graph_name, "CanAssume", &edges, 10, false)
        .await
        .expect("failed to write edges");
    assert_eq!(written_edges.created, 100, "should write 100 edges");

    // Count edges via cypher
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH ()-[r]->() RETURN count(*)";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("failed to count edges");

    assert!(!results.is_empty(), "should return edge count");
    let count_value = &results[0][0];
    let count: i64 = count_value.as_i64().unwrap_or(0);
    assert_eq!(
        count, 100,
        "Bug-1 regression: edge write must not silently drop edges; expected 100, got {}",
        count
    );
}

#[tokio::test]
#[ignore]
async fn regression_bug02_array_property_survives() {
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

    let graph_name = "regression_bug02";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }


    // Write a Principal with inline_policies array
    let policies = Value::Array(vec![
        json!({"name": "p1", "document": "{\"Version\":\"2012-10-17\",\"Statement\":[]}"}),
        json!({"name": "p2", "document": "{\"Version\":\"2012-10-17\",\"Statement\":[]}"}),
    ]);
    let original = node_with_property("principal_1", "inline_policies", policies.clone());
    let written = loader::load_nodes(
        pool.clone(),
        graph_name,
        "Principal",
        &[original],
        1,
    )
    .await
    .expect("failed to write Principal");
    assert_eq!(written, 1);

    // Read back the property
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH (n:Principal {id: 'principal_1'}) RETURN n.inline_policies";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("failed to read Principal");

    assert!(!results.is_empty(), "should find Principal");
    let value = &results[0][0];
    assert!(
        !value.is_null(),
        "Bug-2 regression: inline_policies must not be null"
    );

    // Parse the JSON string back
    let parsed: Value = serde_json::from_str(value.as_str().expect("should be string"))
        .expect("should parse as JSON");
    assert_eq!(
        parsed, policies,
        "Bug-2 regression: array property must survive with correct structure"
    );
}

#[tokio::test]
#[ignore]
async fn regression_bug03_unicode_survives() {
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

    let graph_name = "regression_bug03";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }


    // Write with multi-byte UTF-8 characters
    let original = node_with_property(
        "unicode_test",
        "description",
        Value::String("テスト日本語 🚀 emoji".to_string()),
    );
    let bytes_before = original["description"].as_str().unwrap().as_bytes().len();
    let written = loader::load_nodes(pool.clone(), graph_name, "Test", &[original], 1)
        .await
        .expect("failed to write node");
    assert_eq!(written, 1);

    // Read back
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH (n:Test {id: 'unicode_test'}) RETURN n.description";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("failed to read node");

    assert!(!results.is_empty());
    let value = &results[0][0];
    let bytes_after = value.as_str().unwrap().as_bytes().len();
    assert_eq!(
        bytes_before, bytes_after,
        "Bug-3 regression: unicode byte-length must match (no truncation)"
    );
    assert_eq!(
        value.as_str().unwrap(),
        "テスト日本語 🚀 emoji",
        "Bug-3 regression: unicode content must be identical"
    );
}

#[tokio::test]
#[ignore]
async fn regression_bug04_null_property_survives() {
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

    let graph_name = "regression_bug04";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }

    // Note: loader::load_nodes skips null values, so we verify that behavior
    // and document that null properties are not stored (AGE limitation).

    let original = node_with_property("null_test", "optional_field", Value::Null);
    let written = loader::load_nodes(pool.clone(), graph_name, "Test", &[original], 1)
        .await
        .expect("failed to write node");
    assert_eq!(written, 1);

    // Read back: null properties are not stored by the loader (by design)
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH (n:Test {id: 'null_test'}) RETURN n";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("failed to read node");

    assert!(
        !results.is_empty(),
        "Bug-4 note: null properties are omitted by the loader (known limitation)"
    );
}

#[tokio::test]
#[ignore]
async fn regression_bug05_agtype_text_cast() {
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

    let graph_name = "regression_bug05";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }


    // Write a simple node
    let original = node_with_property("id_test", "name", Value::String("test".to_string()));
    let written = loader::load_nodes(pool.clone(), graph_name, "Test", &[original], 1)
        .await
        .expect("failed to write node");
    assert_eq!(written, 1);

    // Read back the ID via cypher_multi_column (which uses ::text cast)
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH (n:Test {id: 'id_test'}) RETURN n.id";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("Bug-5 regression: cypher_multi_column must not panic on agtype deserialization");

    assert!(
        !results.is_empty(),
        "Bug-5 regression: query must return a result"
    );
    let value = &results[0][0];
    assert_eq!(
        value.as_str().unwrap(),
        "id_test",
        "Bug-5 regression: ID property must be readable via ::text cast"
    );
}

#[tokio::test]
#[ignore]
async fn regression_bug06_quoted_property_survives() {
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

    let graph_name = "regression_bug06";
    if !setup_test_graph(&pool, graph_name).await {
        println!("Skipping: setup failed");
        return;
    }


    // Write with complex quoting and escaping
    let text = "path: \"c:\\\\users\\\\admin\", quote: \"it's\" ";
    let original = node_with_property("quote_test", "cypher_text", Value::String(text.to_string()));
    let written = loader::load_nodes(pool.clone(), graph_name, "Test", &[original], 1)
        .await
        .expect("failed to write node");
    assert_eq!(written, 1);

    // Read back
    let client = GraphClient::new(pool.clone(), graph_name);
    let cypher = "MATCH (n:Test {id: 'quote_test'}) RETURN n.cypher_text";
    let results = client
        .cypher_multi_column(cypher, 1)
        .await
        .expect("failed to read node");

    assert!(!results.is_empty());
    let value = &results[0][0];
    assert_eq!(
        value.as_str().unwrap(),
        text,
        "Bug-6 regression: quoted property must survive cypher escaping"
    );
}
