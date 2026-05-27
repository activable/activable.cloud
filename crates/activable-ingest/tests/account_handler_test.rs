//! Integration test for AccountIngestHandler.
//!
//! Tests the handler end-to-end against a live LocalStack + Postgres cluster.
//! This test is marked with #[ignore] and requires environment setup:
//! - DATABASE_URL: Postgres connection string (with AGE extension loaded)
//! - AWS_ENDPOINT_URL: LocalStack endpoint (e.g., http://localhost:4566)
//! - AWS_REGION: AWS region (e.g., us-east-1)
//! - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY: LocalStack credentials
//!
//! Run with:
//! ```
//! DATABASE_URL=postgresql://... \
//! AWS_ENDPOINT_URL=http://localhost:4566 \
//! AWS_REGION=us-east-1 \
//! cargo test -p activable-ingest --test account_handler_test -- --ignored --nocapture
//! ```

use activable_ingest::AccountIngestHandler;
use activable_scheduler::JobHandler;
use deadpool_postgres::Pool;
use serde_json::json;
use std::sync::Arc;

/// Helper: create a deadpool postgres pool from DATABASE_URL environment variable.
async fn create_pool_from_env() -> Result<Arc<Pool>, Box<dyn std::error::Error>> {
    let db_url = std::env::var("DATABASE_URL")?;

    // Parse DATABASE_URL and create a deadpool pool.
    // DATABASE_URL format: postgresql://user:password@host:port/dbname
    // Create a raw tokio_postgres client first to validate the connection.
    let (client, connection) = tokio_postgres::connect(&db_url, tokio_postgres::tls::NoTls).await?;

    // Spawn the connection in the background to keep it alive.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("postgres background connection error: {}", e);
        }
    });

    // Drop the test client; we'll create a fresh deadpool pool.
    drop(client);

    let pool = {
        // Parse URL components (basic parsing).
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

/// Real integration test: AccountIngestHandler end-to-end against LocalStack + Postgres.
/// Exercises the full ingest pipeline: fetch via CCAPI/native SDK, enrich, apply relationships.
/// Verifies idempotency: re-running the handler produces stable node+edge counts.
#[ignore]
#[tokio::test]
async fn test_account_ingest_handler_live_integration() {
    // Build AWS config from environment (respects AWS_ENDPOINT_URL for LocalStack).
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;

    // Build Postgres connection pool from DATABASE_URL.
    let pool = create_pool_from_env()
        .await
        .expect("Failed to create connection pool from DATABASE_URL");

    // Create handler.
    let mut handler = AccountIngestHandler::new(aws_config.clone(), pool.clone(), "cloud".to_string())
        .await
        .expect("Failed to create AccountIngestHandler");
    handler.set_concurrency_limit(2); // Keep it low for test to avoid timeouts

    // Test account: 000000000111 (has 4 IAM roles in the seed data)
    let account_id = "000000000111";
    let payload = json!({
        "account_id": account_id,
        "provider": "aws",
        "regions": ["us-east-1"]
    });

    println!("\n=== RUN 1: Initial ingest ===");
    let result1 = handler
        .handle(payload.clone())
        .await
        .expect("First handle() call failed");

    println!("Result 1: {:?}", result1);

    // Parse the result as IngestRunStats.
    let stats1: activable_ingest::executor::IngestRunStats =
        serde_json::from_value(result1.clone())
            .expect("Failed to deserialize IngestRunStats from result");

    println!(
        "Run 1 - total_nodes: {}, total_edges: {}, duration: {}s",
        stats1.total_nodes, stats1.total_edges, stats1.duration_secs
    );

    // Verify meaningful data was ingested.
    assert!(
        stats1.total_nodes > 0,
        "Expected total_nodes > 0, got {}",
        stats1.total_nodes
    );
    // total_edges can be 0 if no enrichment/relationship rules apply; u32 is always >= 0.
    assert!(
        stats1.duration_secs > 0,
        "Expected duration_secs > 0, got {}",
        stats1.duration_secs
    );

    // Verify dropped_edges is None (not yet surfaced by enricher traits).
    assert_eq!(
        stats1.dropped_edges, None,
        "dropped_edges should be None until enricher traits are extended"
    );

    // Wait a moment before second ingest (to ensure clean state).
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    println!("\n=== RUN 2: Idempotency check (re-ingest same account) ===");
    let result2 = handler
        .handle(payload.clone())
        .await
        .expect("Second handle() call failed");

    println!("Result 2: {:?}", result2);

    let stats2: activable_ingest::executor::IngestRunStats =
        serde_json::from_value(result2.clone())
            .expect("Failed to deserialize IngestRunStats from result 2");

    println!(
        "Run 2 - total_nodes: {}, total_edges: {}, duration: {}s",
        stats2.total_nodes, stats2.total_edges, stats2.duration_secs
    );

    // Idempotency check: total_nodes and total_edges should be identical on re-run.
    // (The loaders use MERGE semantics, which is idempotent.)
    assert_eq!(
        stats1.total_nodes, stats2.total_nodes,
        "Idempotency violation: total_nodes changed between runs ({} -> {})",
        stats1.total_nodes, stats2.total_nodes
    );
    assert_eq!(
        stats1.total_edges, stats2.total_edges,
        "Idempotency violation: total_edges changed between runs ({} -> {})",
        stats1.total_edges, stats2.total_edges
    );

    println!("\n=== Idempotency check PASSED ===");
    println!(
        "Stable ingest: {} nodes, {} edges per run",
        stats1.total_nodes, stats1.total_edges
    );
}
