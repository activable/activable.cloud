//! Multi-edge-type traversal integration tests against live AGE.
//!
//! AGE has no edge-label alternation (`[r:A|B]` is a syntax error) and treats a
//! bare identifier in a variable-length pattern (`[Type*1..n]`) as a variable
//! binding rather than a type filter. These tests pin the corrected behavior:
//! multi-type walks filter via `WHERE label(r) IN [...]`, and typed
//! variable-length traversal actually filters by type.
//!
//! Run with: AGE_TEST_URL="postgres://activable:password@localhost:5433/activable" cargo test --test walk_edges_multi_type_test

use activable_graph::types::{Direction, NodeId};
use activable_graph::{GraphClient, GraphPool};
use futures::StreamExt;

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

/// Build a star graph: alice -CanAssume-> role, alice -HasPermission-> perm,
/// alice -MemberOf-> group. Three outgoing edges with three distinct types.
async fn setup_star_graph(pool: &deadpool_postgres::Pool, graph_name: &str) -> bool {
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

    if conn
        .query(
            &format!("SELECT * FROM ag_catalog.create_graph('{}')", graph_name),
            &[],
        )
        .await
        .is_err()
    {
        return false;
    }

    let statements = [
        "CREATE (n:Principal {id: 'star:alice'}) RETURN n",
        "CREATE (n:Principal {id: 'star:role'}) RETURN n",
        "CREATE (n:Permission {id: 'star:perm'}) RETURN n",
        "CREATE (n:IamGroup {id: 'star:group'}) RETURN n",
        "MATCH (a {id: 'star:alice'}), (b {id: 'star:role'}) CREATE (a)-[:CanAssume]->(b) RETURN a",
        "MATCH (a {id: 'star:alice'}), (b {id: 'star:perm'}) CREATE (a)-[:HasPermission]->(b) RETURN a",
        "MATCH (a {id: 'star:alice'}), (b {id: 'star:group'}) CREATE (a)-[:MemberOf]->(b) RETURN a",
    ];
    for stmt in statements {
        let sql = format!(
            "SELECT * FROM cypher('{}', $${}$$) AS (a agtype)",
            graph_name, stmt
        );
        if conn.query(&sql, &[]).await.is_err() {
            return false;
        }
    }

    true
}

async fn collect_walk(
    client: &GraphClient,
    start: &str,
    edge_types: &[&str],
) -> Result<Vec<String>, activable_graph::error::GraphError> {
    let stream = client
        .walk_edges(
            &NodeId::from(start),
            edge_types,
            Direction::Outgoing,
            10,
        )
        .await?;
    let mut ids = Vec::new();
    let mut stream = Box::pin(stream);
    while let Some(item) = stream.next().await {
        ids.push(item?.id.to_string());
    }
    ids.sort();
    Ok(ids)
}

async fn drop_graph(pool: &deadpool_postgres::Pool, graph_name: &str) {
    if let Ok(conn) = pool.get().await {
        let _ = conn
            .batch_execute("LOAD 'age'; SET search_path = ag_catalog, \"$user\", public;")
            .await;
        let _ = conn
            .query(
                &format!(
                    "SELECT * FROM ag_catalog.drop_graph('{}', true)",
                    graph_name
                ),
                &[],
            )
            .await;
    }
}

#[tokio::test]
async fn walk_edges_two_types_filters_and_does_not_error() {
    let Some((host, port, user, pass, dbname)) = test_url_parts() else {
        println!("Skipping: AGE_TEST_URL not set");
        return;
    };
    let Ok(pool) = GraphPool::build(&host, port, &user, &pass, &dbname, 5) else {
        println!("Skipping: failed to create pool");
        return;
    };

    let graph = "test_walk_multi_graph";
    if !setup_star_graph(&pool, graph).await {
        println!("Skipping: setup failed");
        return;
    }
    let client = GraphClient::new(pool.clone(), graph);

    // Regression: this errored with an AGE syntax error when the builder
    // generated [r:CanAssume|HasPermission].
    let ids = collect_walk(&client, "star:alice", &["CanAssume", "HasPermission"])
        .await
        .expect("multi-type walk must not error");
    assert_eq!(
        ids,
        vec!["star:perm".to_string(), "star:role".to_string()],
        "must return exactly the two matching targets, excluding the MemberOf edge"
    );

    drop_graph(&pool, graph).await;
}

#[tokio::test]
async fn walk_edges_single_type_still_filters() {
    let Some((host, port, user, pass, dbname)) = test_url_parts() else {
        println!("Skipping: AGE_TEST_URL not set");
        return;
    };
    let Ok(pool) = GraphPool::build(&host, port, &user, &pass, &dbname, 5) else {
        println!("Skipping: failed to create pool");
        return;
    };

    let graph = "test_walk_single_graph";
    if !setup_star_graph(&pool, graph).await {
        println!("Skipping: setup failed");
        return;
    }
    let client = GraphClient::new(pool.clone(), graph);

    let ids = collect_walk(&client, "star:alice", &["MemberOf"])
        .await
        .expect("single-type walk must not error");
    assert_eq!(ids, vec!["star:group".to_string()]);

    drop_graph(&pool, graph).await;
}

#[tokio::test]
async fn blast_radius_single_type_actually_filters() {
    let Some((host, port, user, pass, dbname)) = test_url_parts() else {
        println!("Skipping: AGE_TEST_URL not set");
        return;
    };
    let Ok(pool) = GraphPool::build(&host, port, &user, &pass, &dbname, 5) else {
        println!("Skipping: failed to create pool");
        return;
    };

    let graph = "test_blast_typed_graph";
    if !setup_star_graph(&pool, graph).await {
        println!("Skipping: setup failed");
        return;
    }
    let client = GraphClient::new(pool.clone(), graph);

    // Regression: the builder previously generated [CanAssume*1..2] (no colon),
    // which AGE parses as a variable binding matching EVERY edge type — this
    // walk returned all three neighbors instead of one.
    let stream = client
        .blast_radius(&NodeId::from("star:alice"), &["CanAssume"], 2)
        .await
        .expect("typed blast_radius must not error");
    let mut ids = Vec::new();
    let mut stream = Box::pin(stream);
    while let Some(item) = stream.next().await {
        ids.push(item.expect("row must parse").id.to_string());
    }
    ids.sort();
    assert_eq!(
        ids,
        vec!["star:role".to_string()],
        "typed traversal must follow only the requested edge type"
    );

    drop_graph(&pool, graph).await;
}
