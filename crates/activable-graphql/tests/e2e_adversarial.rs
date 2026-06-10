//! End-to-end integration test: adversarial scenario detection via LocalStack + GraphQL.
//!
//! This test exercises the full pipeline:
//! 1. Reset the graph (delete all nodes/edges)
//! 2. Seed LocalStack with 5 adversarial scenarios
//! 3. Trigger ingest via GraphQL mutation
//! 4. Poll for completion
//! 5. Assert per-scenario risk scores meet thresholds
//!
//! Requirements:
//! - E2E_TEST_URL: GraphQL endpoint (e.g., http://localhost:30080/graphql)
//! - LOCALSTACK_URL: AWS endpoint (e.g., http://localhost:4566)
//! - DATABASE_URL: Postgres connection string (e.g., postgres://localhost/activable)
//!
//! Run: cargo test --test e2e_adversarial -- --ignored --nocapture

use serde_json::{json, Value};
use std::env;
use std::time::Duration;

/// Helper to extract environment variables with fallback for testing.
fn get_env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// E2E test environment holding service URLs and database connection info.
struct E2eEnvironment {
    graphql_url: String,
    localstack_url: String,
    database_url: String,
}

impl E2eEnvironment {
    /// Load environment from E2E_TEST_URL, LOCALSTACK_URL, and DATABASE_URL.
    fn from_env() -> Self {
        Self {
            graphql_url: get_env("E2E_TEST_URL", "http://localhost:30080/graphql"),
            localstack_url: get_env("LOCALSTACK_URL", "http://activable-localstack:4566"),
            database_url: get_env(
                "DATABASE_URL",
                "postgres://postgres:password@localhost/activable",
            ),
        }
    }

    /// Reset the graph: delete all nodes and edges.
    async fn reset_graph(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Use native psql via tokio_postgres to reset the AGE graph.
        // For simplicity, drop and recreate the graph.
        let (client, connection) =
            tokio_postgres::connect(&self.database_url, tokio_postgres::tls::NoTls).await?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("postgres connection error: {}", e);
            }
        });

        // Check if graph exists, then drop and recreate
        let graph_exists = client
            .query_one(
                "SELECT graph_name FROM ag_graph WHERE graph_name = 'detection_graph'",
                &[],
            )
            .await
            .is_ok();

        if graph_exists {
            // Drop the graph
            client
                .execute("DROP GRAPH IF EXISTS detection_graph CASCADE", &[])
                .await?;
        }

        // Create the graph
        client
            .execute("SELECT create_graph('detection_graph')", &[])
            .await?;

        tracing::info!("graph reset complete");
        Ok(())
    }

    /// Run the seed script to populate LocalStack with adversarial scenarios.
    async fn run_seed_script(&self) -> Result<(), Box<dyn std::error::Error>> {
        let script_path = "ops/seed/seed-adversarial.sh";

        // Check if script exists
        if !std::path::Path::new(script_path).exists() {
            return Err(format!("seed script not found at {}", script_path).into());
        }

        let output = tokio::process::Command::new("bash")
            .arg(script_path)
            .env("AWS_ENDPOINT_URL", &self.localstack_url)
            .env("AWS_ACCESS_KEY_ID", "test")
            .env("AWS_SECRET_ACCESS_KEY", "test")
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("seed script failed: {}", stderr).into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        tracing::info!("seed script output:\n{}", stdout);
        Ok(())
    }

    /// Trigger an ingest run via GraphQL mutation.
    async fn trigger_ingest(&self) -> Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();

        let mutation = r#"
            mutation {
                triggerIngest(provider: "aws", regions: ["us-east-1"]) {
                    id
                    status
                    startedAt
                }
            }
        "#;

        let response = client
            .post(&self.graphql_url)
            .json(&json!({ "query": mutation }))
            .send()
            .await?;

        let body: Value = response.json().await?;

        if let Some(errors) = body.get("errors") {
            return Err(format!("GraphQL error: {}", errors).into());
        }

        // New contract: triggerIngest returns Vec<String> (job IDs).
        let job_ids = body["data"]["triggerIngest"]
            .as_array()
            .ok_or("missing jobIds array")?;

        let run_id = job_ids
            .first()
            .and_then(|v| v.as_str())
            .ok_or("no job IDs returned")?
            .to_string();

        tracing::info!(job_id = %run_id, "ingest triggered");
        Ok(run_id)
    }

    /// Poll ingest_status until completion (timeout: 90 seconds).
    /// New contract: ingestStatus now uses jobId instead of runId.
    async fn wait_for_ingest_complete(
        &self,
        job_id: &str,
        timeout_secs: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);

        loop {
            let query = format!(
                r#"
                query {{
                    ingestStatus(jobId: "{}") {{
                        id
                        status
                        createdAt
                    }}
                }}
            "#,
                job_id
            );

            let response = client
                .post(&self.graphql_url)
                .json(&json!({ "query": query }))
                .send()
                .await?;

            let body: Value = response.json().await?;

            if let Some(errors) = body.get("errors") {
                tracing::warn!("GraphQL query error: {}", errors);
            }

            let status = body["data"]["ingestStatus"]["status"]
                .as_str()
                .unwrap_or("unknown");

            if status == "completed" || status == "COMPLETED" {
                tracing::info!(job_id = %job_id, "ingest completed");
                return Ok(());
            }

            if status == "timeout" || status == "TIMEOUT" {
                return Err("ingest timed out".into());
            }

            if std::time::Instant::now() > deadline {
                return Err("ingest polling timeout exceeded".into());
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Query risk score for a principal (Scenario 1: developer-role in account 111111111111).
    async fn scenario_1_score(&self) -> Result<f64, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let principal_id = "arn:aws:iam::111111111111:role/developer-role";

        let query = format!(
            r#"
            query {{
                riskScore(principalId: "{}") {{
                    score
                }}
            }}
        "#,
            principal_id
        );

        let response = client
            .post(&self.graphql_url)
            .json(&json!({ "query": query }))
            .send()
            .await?;

        let body: Value = response.json().await?;

        if let Some(errors) = body.get("errors") {
            return Err(format!("scenario 1 query failed: {}", errors).into());
        }

        let score = body["data"]["riskScore"]["score"]
            .as_f64()
            .ok_or("missing score")?;

        Ok(score)
    }

    /// Query risk score for OIDC scenario (Scenario 2).
    /// If E2E_OIDC_ENABLED is not set, return 0.0 (scenario skipped by design).
    async fn scenario_2_score(&self) -> Result<f64, Box<dyn std::error::Error>> {
        let oidc_enabled = env::var("E2E_OIDC_ENABLED").is_ok();

        if !oidc_enabled {
            tracing::info!("OIDC scenario skipped (E2E_OIDC_ENABLED not set)");
            return Ok(0.0); // Gated; assertion will be >= 0, not > 0.80
        }

        let client = reqwest::Client::new();
        let principal_id = "arn:aws:iam::111111111111:role/github-actions-role";

        let query = format!(
            r#"
            query {{
                riskScore(principalId: "{}") {{
                    score
                }}
            }}
        "#,
            principal_id
        );

        let response = client
            .post(&self.graphql_url)
            .json(&json!({ "query": query }))
            .send()
            .await?;

        let body: Value = response.json().await?;

        if let Some(errors) = body.get("errors") {
            return Err(format!("scenario 2 query failed: {}", errors).into());
        }

        let score = body["data"]["riskScore"]["score"]
            .as_f64()
            .ok_or("missing score")?;

        Ok(score)
    }

    /// Query account risks for Scenario 3 (S3 bucket policy principal boundary confusion).
    async fn scenario_3_score(&self) -> Result<f64, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let account_id = "333333333333"; // production account

        let query = format!(
            r#"
            query {{
                accountRisks(accountId: "{}") {{
                    cascadeRiskScore
                }}
            }}
        "#,
            account_id
        );

        let response = client
            .post(&self.graphql_url)
            .json(&json!({ "query": query }))
            .send()
            .await?;

        let body: Value = response.json().await?;

        if let Some(errors) = body.get("errors") {
            return Err(format!("scenario 3 query failed: {}", errors).into());
        }

        let score = body["data"]["accountRisks"]["cascadeRiskScore"]
            .as_f64()
            .ok_or("missing cascadeRiskScore")?;

        Ok(score)
    }

    /// Query account risks for Scenario 4 (KMS CreateGrant lateral movement).
    async fn scenario_4_score(&self) -> Result<f64, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let account_id = "222222222222"; // staging account

        let query = format!(
            r#"
            query {{
                accountRisks(accountId: "{}") {{
                    cascadeRiskScore
                }}
            }}
        "#,
            account_id
        );

        let response = client
            .post(&self.graphql_url)
            .json(&json!({ "query": query }))
            .send()
            .await?;

        let body: Value = response.json().await?;

        if let Some(errors) = body.get("errors") {
            return Err(format!("scenario 4 query failed: {}", errors).into());
        }

        let score = body["data"]["accountRisks"]["cascadeRiskScore"]
            .as_f64()
            .ok_or("missing cascadeRiskScore")?;

        Ok(score)
    }

    /// Query account risks for Scenario 5 (cross-account cascade).
    async fn scenario_5_cascade(&self) -> Result<f64, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let account_id = "111111111111"; // development account (source of blast radius)

        let query = format!(
            r#"
            query {{
                accountRisks(accountId: "{}") {{
                    cascadeRiskScore
                }}
            }}
        "#,
            account_id
        );

        let response = client
            .post(&self.graphql_url)
            .json(&json!({ "query": query }))
            .send()
            .await?;

        let body: Value = response.json().await?;

        if let Some(errors) = body.get("errors") {
            return Err(format!("scenario 5 query failed: {}", errors).into());
        }

        let score = body["data"]["accountRisks"]["cascadeRiskScore"]
            .as_f64()
            .ok_or("missing cascadeRiskScore")?;

        Ok(score)
    }
}

/// Helper: assert score with descriptive error message including delta.
fn assert_score_threshold(
    scenario: &str,
    score: f64,
    threshold: f64,
    op: &str,
) -> Result<(), String> {
    let passed = match op {
        ">=" => score >= threshold,
        ">" => score > threshold,
        _ => false,
    };

    if !passed {
        let delta = score - threshold;
        return Err(format!(
            "Scenario {}: score {:.4} {} threshold {:.4} (delta: {:.4})",
            scenario, score, op, threshold, delta
        ));
    }

    Ok(())
}

/// Main e2e test: full pipeline against live LocalStack + GraphQL.
#[tokio::test]
#[ignore]
async fn e2e_adversarial_scenarios() {
    // Initialize tracing for diagnostics
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();

    let env = E2eEnvironment::from_env();

    tracing::info!(
        graphql = %env.graphql_url,
        localstack = %env.localstack_url,
        "starting e2e adversarial scenario test"
    );

    // Step 1: Reset graph
    match env.reset_graph().await {
        Ok(_) => tracing::info!("graph reset successful"),
        Err(e) => {
            eprintln!("BLOCKED: graph reset failed: {}", e);
            panic!("cannot continue without graph reset");
        }
    }

    // Step 2: Seed LocalStack
    match env.run_seed_script().await {
        Ok(_) => tracing::info!("seed script successful"),
        Err(e) => {
            eprintln!("BLOCKED: seed script failed: {}", e);
            panic!("cannot continue without seeding");
        }
    }

    // Step 3: Trigger ingest
    let run_id = match env.trigger_ingest().await {
        Ok(id) => {
            tracing::info!(run_id = %id, "ingest triggered");
            id
        }
        Err(e) => {
            eprintln!("BLOCKED: ingest trigger failed: {}", e);
            panic!("cannot trigger ingest");
        }
    };

    // Step 4: Wait for completion (90 second timeout)
    match env.wait_for_ingest_complete(&run_id, 90).await {
        Ok(_) => tracing::info!("ingest completed"),
        Err(e) => {
            eprintln!("BLOCKED: ingest polling failed: {}", e);
            panic!("ingest did not complete");
        }
    }

    // Step 5: Assert scenario thresholds
    let mut assertions_failed = Vec::new();

    // Scenario 1: principal-level risk > 0.80
    match env.scenario_1_score().await {
        Ok(score) => {
            tracing::info!(score = %score, "scenario 1 score");
            if let Err(msg) = assert_score_threshold("1 (CF Service Role Trap)", score, 0.80, ">") {
                assertions_failed.push(msg);
            }
        }
        Err(e) => assertions_failed.push(format!("scenario 1 query error: {}", e)),
    }

    // Scenario 2: OIDC risk >= 0.0 (or > 0.80 if enabled)
    match env.scenario_2_score().await {
        Ok(score) => {
            tracing::info!(score = %score, "scenario 2 score");
            let threshold = if env::var("E2E_OIDC_ENABLED").is_ok() {
                0.80
            } else {
                0.0
            };
            let op = if env::var("E2E_OIDC_ENABLED").is_ok() {
                ">"
            } else {
                ">="
            };
            if let Err(msg) =
                assert_score_threshold("2 (OIDC Configuration Drift)", score, threshold, op)
            {
                assertions_failed.push(msg);
            }
        }
        Err(e) => assertions_failed.push(format!("scenario 2 query error: {}", e)),
    }

    // Scenario 3: account-level cascade > 0.75
    match env.scenario_3_score().await {
        Ok(score) => {
            tracing::info!(score = %score, "scenario 3 score");
            if let Err(msg) =
                assert_score_threshold("3 (S3 Bucket Policy Principal Boundary)", score, 0.75, ">")
            {
                assertions_failed.push(msg);
            }
        }
        Err(e) => assertions_failed.push(format!("scenario 3 query error: {}", e)),
    }

    // Scenario 4: account-level cascade > 0.70
    match env.scenario_4_score().await {
        Ok(score) => {
            tracing::info!(score = %score, "scenario 4 score");
            if let Err(msg) =
                assert_score_threshold("4 (KMS CreateGrant Lateral Movement)", score, 0.70, ">")
            {
                assertions_failed.push(msg);
            }
        }
        Err(e) => assertions_failed.push(format!("scenario 4 query error: {}", e)),
    }

    // Scenario 5: cross-account cascade >= 0.78
    match env.scenario_5_cascade().await {
        Ok(score) => {
            tracing::info!(score = %score, "scenario 5 cascade score");
            if let Err(msg) = assert_score_threshold("5 (Cross-Account Cascade)", score, 0.78, ">=")
            {
                assertions_failed.push(msg);
            }
        }
        Err(e) => assertions_failed.push(format!("scenario 5 query error: {}", e)),
    }

    if !assertions_failed.is_empty() {
        eprintln!("\nAssertion failures:");
        for msg in &assertions_failed {
            eprintln!("  - {}", msg);
        }
        panic!(
            "e2e test failed: {} assertions failed",
            assertions_failed.len()
        );
    }

    tracing::info!("all scenarios passed");
}

#[cfg(test)]
mod helpers {
    //! Unit tests for helper functions.

    use super::*;

    #[test]
    fn test_assert_score_threshold_pass_greater_than() {
        let result = assert_score_threshold("test", 0.85, 0.80, ">");
        assert!(result.is_ok());
    }

    #[test]
    fn test_assert_score_threshold_fail_greater_than() {
        let result = assert_score_threshold("test", 0.75, 0.80, ">");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("0.75") && msg.contains("0.80"));
    }

    #[test]
    fn test_assert_score_threshold_pass_greater_equal() {
        let result = assert_score_threshold("test", 0.80, 0.80, ">=");
        assert!(result.is_ok());
    }

    #[test]
    fn test_assert_score_threshold_fail_greater_equal() {
        let result = assert_score_threshold("test", 0.79, 0.80, ">=");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_env_uses_default() {
        let val = get_env("NONEXISTENT_VAR_FOR_TEST_12345", "default_value");
        assert_eq!(val, "default_value");
    }

    #[test]
    fn test_e2e_environment_from_env() {
        // Should load with defaults if env vars not set
        let env = E2eEnvironment::from_env();
        assert!(!env.graphql_url.is_empty());
        assert!(!env.localstack_url.is_empty());
        assert!(!env.database_url.is_empty());
    }
}
