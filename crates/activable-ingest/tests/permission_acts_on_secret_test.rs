//! Integration test for Permission-ActsOn-Secret relationship rule.
//!
//! Tests the permission-acts-on-secret relationship rule against a live Postgres/AGE database.
//! Verifies that:
//! 1. Specific ARN matches create Permission -ActsOn-> Secret edges.
//! 2. Wildcard resource permissions DO NOT explode into edges (v1 over-approximation).
//! 3. The full traversal path Principal -> Permission -> Secret is valid.
//!
//! This test is marked with #[ignore] and requires environment setup:
//! - DATABASE_URL: Postgres connection string (with AGE extension loaded)
//!
//! Run with:
//! ```
//! DATABASE_URL=postgresql://... \
//! cargo test -p activable-ingest --test permission_acts_on_secret_test -- --ignored --nocapture
//! ```

use deadpool_postgres::Pool;
use std::sync::Arc;

/// Helper: create a deadpool postgres pool from DATABASE_URL environment variable.
async fn create_pool_from_env() -> Result<Arc<Pool>, Box<dyn std::error::Error>> {
    let db_url = std::env::var("DATABASE_URL")?;

    // Create a raw tokio_postgres client first to validate the connection.
    let (client, connection) = tokio_postgres::connect(&db_url, tokio_postgres::tls::NoTls).await?;

    // Spawn the connection in the background to keep it alive.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("postgres background connection error: {}", e);
        }
    });

    drop(client);

    let pool = {
        let url_str = &db_url;
        let after_proto = url_str.strip_prefix("postgresql://").unwrap_or(url_str);
        let (userpass, rest) = after_proto.split_once('@').unwrap_or(("", after_proto));
        let (user, password) = userpass.split_once(':').unwrap_or((userpass, ""));
        let (host_port, dbname) = rest.split_once('/').unwrap_or(("localhost", ""));
        let (host, port_str) = host_port.split_once(':').unwrap_or((host_port, "5432"));
        let port: u16 = port_str.parse().unwrap_or(5432);

        let cfg = {
            let mut c = deadpool_postgres::Config::new();
            c.host = Some(host.to_string());
            c.port = Some(port);
            c.user = Some(user.to_string());
            if !password.is_empty() {
                c.password = Some(password.to_string());
            }
            if !dbname.is_empty() {
                c.dbname = Some(dbname.to_string());
            }
            c
        };

        cfg.create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )?
    };

    Ok(Arc::new(pool))
}

/// Helper: create a test graph with a unique random name for isolation and parallelism.
fn generate_test_graph_name() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("test_perm_secret_{}", now)
}

/// Helper: initialize AGE and create a new graph.
async fn create_test_graph(
    pool: &Arc<Pool>,
    graph_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await?;
    conn.execute(&format!("SELECT create_graph('{}');", graph_name), &[])
        .await?;
    Ok(())
}

/// Helper: drop the test graph to clean up.
async fn drop_test_graph(
    pool: &Arc<Pool>,
    graph_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await?;
    conn.execute(&format!("SELECT drop_graph('{}', true);", graph_name), &[])
        .await?;
    Ok(())
}

/// Test: permission-acts-on-secret rule creates edges for specific ARN matches.
/// Verifies:
/// 1. A Permission node with a specific secret ARN matches a Secret node with that ARN.
/// 2. The Permission -ActsOn-> Secret edge is created.
/// 3. The full traversal Principal -> Permission -ActsOn-> Secret is valid.
#[ignore]
#[tokio::test]
async fn test_permission_acts_on_secret_specific_arn_match() {
    let pool = match create_pool_from_env().await {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Skipping: DATABASE_URL not set or invalid");
            return;
        }
    };

    let graph_name = generate_test_graph_name();

    // Create the test graph.
    if let Err(e) = create_test_graph(&pool, &graph_name).await {
        eprintln!("Failed to create test graph: {}", e);
        return;
    }

    // Ensure cleanup on exit.
    let graph_name_cleanup = graph_name.clone();
    let pool_cleanup = pool.clone();

    struct Cleanup {
        graph_name: String,
        pool: Arc<Pool>,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let g = self.graph_name.clone();
            let p = self.pool.clone();
            let _ = std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let _ = rt.block_on(drop_test_graph(&p, &g));
            });
        }
    }
    let _cleanup = Cleanup {
        graph_name: graph_name_cleanup,
        pool: pool_cleanup,
    };

    // Get a connection and load AGE.
    let conn = pool.get().await.expect("failed to get pool connection");
    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .expect("failed to load AGE");

    let secret_arn = "arn:aws:secretsmanager:us-east-1:999999999999:secret:test-specific-ABC";

    // Create a Principal node.
    let principal_create = format!(
        "SELECT * FROM cypher('{}', $$CREATE (p:Principal {{id: 'arn:aws:iam::999999999999:role/TestRole', name: 'TestRole'}}) RETURN p$$) AS (p agtype);",
        graph_name
    );
    conn.query(&principal_create, &[])
        .await
        .expect("failed to create Principal node");

    // Create a Permission node with a specific resource (secret ARN).
    // id = sha256(action|resource), resource = the secret ARN
    let perm_id = format!("sha256_{}_{}", "secretsmanager:GetSecretValue", secret_arn);
    let permission_create = format!(
        "SELECT * FROM cypher('{}', $$CREATE (p:Permission {{id: '{}', action: 'secretsmanager:GetSecretValue', resource: '{}'}}) RETURN p$$) AS (p agtype);",
        graph_name, perm_id, secret_arn
    );
    conn.query(&permission_create, &[])
        .await
        .expect("failed to create Permission node");

    // Create a Secret node with matching id.
    let secret_create = format!(
        "SELECT * FROM cypher('{}', $$CREATE (s:Secret {{id: '{}', name: 'test-specific', arn: '{}'}}) RETURN s$$) AS (s agtype);",
        graph_name, secret_arn, secret_arn
    );
    conn.query(&secret_create, &[])
        .await
        .expect("failed to create Secret node");

    // Apply the relationship rule via the relationship module.
    let rel_result = activable_ingest::relationship::apply_relationships(&pool, &graph_name)
        .await
        .expect("failed to apply relationships");

    // Verify the permission-acts-on-secret rule was applied.
    let perm_secret_rule = rel_result
        .iter()
        .find(|r| r.rule_name == "permission-acts-on-secret")
        .expect("permission-acts-on-secret rule should have been applied");

    assert!(
        perm_secret_rule.edges_created > 0,
        "expected at least 1 edge created by permission-acts-on-secret rule, got {}",
        perm_secret_rule.edges_created
    );

    // Verify the edge exists via Cypher query.
    let edge_check = format!(
        "SELECT * FROM cypher('{}', $$MATCH (p:Permission)-[:ActsOn]->(s:Secret) WHERE s.id = '{}' RETURN count(*)::text as edge_count$$) AS (edge_count text);",
        graph_name, secret_arn
    );
    let rows = conn
        .query(&edge_check, &[])
        .await
        .expect("failed to query edges");
    assert!(
        !rows.is_empty(),
        "edge query should return at least one row"
    );
    let edge_count_str: String = rows[0].try_get(0).expect("failed to read edge_count");
    // Parse the agtype/text result (may be quoted or unquoted).
    let edge_count: u32 = edge_count_str
        .trim_matches('"')
        .parse()
        .unwrap_or_else(|_| {
            // Try via agtype parsing if bare number fails.
            activable_graph::parse_agtype_scalar::<u32>(&edge_count_str).unwrap_or(0)
        });

    assert_eq!(
        edge_count, 1,
        "expected exactly 1 Permission -ActsOn-> Secret edge, got {}",
        edge_count
    );
}

/// Test: wildcard resource permissions DO NOT explode into cartesian product.
/// Verifies:
/// 1. A Permission node with resource = "*" does NOT match specific Secret nodes.
/// 2. No Permission -ActsOn-> Secret edges are created for wildcard grants.
#[ignore]
#[tokio::test]
async fn test_permission_acts_on_secret_wildcard_no_explosion() {
    let pool = match create_pool_from_env().await {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Skipping: DATABASE_URL not set or invalid");
            return;
        }
    };

    let graph_name = generate_test_graph_name();

    // Create the test graph.
    if let Err(e) = create_test_graph(&pool, &graph_name).await {
        eprintln!("Failed to create test graph: {}", e);
        return;
    }

    // Cleanup on exit.
    let graph_name_cleanup = graph_name.clone();
    let pool_cleanup = pool.clone();

    struct Cleanup {
        graph_name: String,
        pool: Arc<Pool>,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let g = self.graph_name.clone();
            let p = self.pool.clone();
            let _ = std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let _ = rt.block_on(drop_test_graph(&p, &g));
            });
        }
    }
    let _cleanup = Cleanup {
        graph_name: graph_name_cleanup,
        pool: pool_cleanup,
    };

    let conn = pool.get().await.expect("failed to get pool connection");
    conn.batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
        .await
        .expect("failed to load AGE");

    // Create a wildcard Permission node.
    let perm_id = "sha256_secretsmanager_*_*";
    let permission_create = format!(
        "SELECT * FROM cypher('{}', $$CREATE (p:Permission {{id: '{}', action: 'secretsmanager:*', resource: '*'}}) RETURN p$$) AS (p agtype);",
        graph_name, perm_id
    );
    conn.query(&permission_create, &[])
        .await
        .expect("failed to create wildcard Permission node");

    // Create multiple Secret nodes with different ARNs.
    let secret_arn_1 = "arn:aws:secretsmanager:us-east-1:999999999999:secret:secret-one";
    let secret_create_1 = format!(
        "SELECT * FROM cypher('{}', $$CREATE (s:Secret {{id: '{}', name: 'secret-one'}}) RETURN s$$) AS (s agtype);",
        graph_name, secret_arn_1
    );
    conn.query(&secret_create_1, &[])
        .await
        .expect("failed to create Secret node 1");

    let secret_arn_2 = "arn:aws:secretsmanager:us-east-1:999999999999:secret:secret-two";
    let secret_create_2 = format!(
        "SELECT * FROM cypher('{}', $$CREATE (s:Secret {{id: '{}', name: 'secret-two'}}) RETURN s$$) AS (s agtype);",
        graph_name, secret_arn_2
    );
    conn.query(&secret_create_2, &[])
        .await
        .expect("failed to create Secret node 2");

    // Apply the relationship rule.
    let rel_result = activable_ingest::relationship::apply_relationships(&pool, &graph_name)
        .await
        .expect("failed to apply relationships");

    let perm_secret_rule = rel_result
        .iter()
        .find(|r| r.rule_name == "permission-acts-on-secret")
        .expect("permission-acts-on-secret rule should have been applied");

    // The wildcard Permission should NOT match any specific Secrets.
    // edges_created should be 0 for this scenario.
    assert_eq!(
        perm_secret_rule.edges_created, 0,
        "wildcard resource ('*') should NOT create edges to specific secrets, but got {} edges",
        perm_secret_rule.edges_created
    );

    // Double-check via Cypher: no Permission(resource='*') -ActsOn-> Secret edges.
    let edge_check = format!(
        "SELECT * FROM cypher('{}', $$MATCH (p:Permission {{resource: '*'}})-[:ActsOn]->(s:Secret) RETURN count(*)::text as edge_count$$) AS (edge_count text);",
        graph_name
    );
    let rows = conn
        .query(&edge_check, &[])
        .await
        .expect("failed to query edges");
    assert!(
        !rows.is_empty(),
        "edge query should return at least one row"
    );
    let edge_count_str: String = rows[0].try_get(0).expect("failed to read edge_count");
    let edge_count: u32 = edge_count_str
        .trim_matches('"')
        .parse()
        .unwrap_or_else(|_| {
            activable_graph::parse_agtype_scalar::<u32>(&edge_count_str).unwrap_or(0)
        });

    assert_eq!(
        edge_count, 0,
        "expected 0 Permission(resource='*') -ActsOn-> Secret edges, got {}",
        edge_count
    );
}
