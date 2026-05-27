//! Activable GraphQL API server using async-graphql and axum.

use activable_graph::pool::GraphPool;
use activable_graph::GraphClient;
use activable_risk::{load_rules_from_embedded, RiskConfig};
use activable_scheduler::{JobStore, JobStoreConfig, Scheduler};
use async_graphql::Schema;
use axum::{extract::DefaultBodyLimit, routing::get, Json, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod error;
mod graph_adapter;
mod graph_client_adapter;
mod resolvers;
mod schema;
mod telemetry;
mod types;

use schema::{AppSchema, MutationRoot, QueryRoot};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing with JSON output
    let env_filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| tracing_subscriber::EnvFilter::try_new(v).ok())
        .or_else(|| tracing_subscriber::EnvFilter::try_new("info").ok())
        .unwrap_or_else(|| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().json())
        .with(env_filter)
        .init();

    tracing::info!("Starting Activable GraphQL server");

    // Read configuration from environment variables
    let db_host = std::env::var("ACTIVABLE_DB_HOST").unwrap_or_else(|_| "localhost".to_string());
    let db_port: u16 = std::env::var("ACTIVABLE_DB_PORT")
        .unwrap_or_else(|_| "5432".to_string())
        .parse()?;
    let db_user = std::env::var("ACTIVABLE_DB_USER").unwrap_or_else(|_| "activable".to_string());
    let db_password =
        std::env::var("ACTIVABLE_DB_PASSWORD").unwrap_or_else(|_| "activable".to_string());
    let db_name = std::env::var("ACTIVABLE_DB_NAME").unwrap_or_else(|_| "activable".to_string());
    let graph_name = std::env::var("ACTIVABLE_GRAPH_NAME").unwrap_or_else(|_| "cloud".to_string());
    let server_port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()?;
    let max_connections: usize = std::env::var("ACTIVABLE_MAX_CONNECTIONS")
        .unwrap_or_else(|_| "20".to_string())
        .parse()?;

    tracing::info!(
        host = %db_host,
        port = %db_port,
        user = %db_user,
        database = %db_name,
        "Initializing database pool"
    );

    // Build the connection pool (used by graph + scheduler)
    let pool = GraphPool::build(
        &db_host,
        db_port,
        &db_user,
        &db_password,
        &db_name,
        max_connections,
    )?;
    tracing::info!(
        "Database pool initialized with max {} connections",
        max_connections
    );

    // Verify connectivity to the database
    let _conn = pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("Database connectivity check failed: {}", e))?;
    tracing::info!("Database connectivity verified");

    // Create the GraphClient
    let client = GraphClient::new(pool.clone(), &graph_name);
    tracing::info!(graph_name = %graph_name, "GraphClient initialized");

    // Run index migrations (create indexes for common node labels)
    {
        let conn = pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get connection for index migrations: {}", e))?;

        let index_statements = &[
            r#"SELECT * FROM cypher('activable', $$ CREATE INDEX IF NOT EXISTS ON :Principal(id) $$) AS (r agtype)"#,
            r#"SELECT * FROM cypher('activable', $$ CREATE INDEX IF NOT EXISTS ON :Permission(id) $$) AS (r agtype)"#,
            r#"SELECT * FROM cypher('activable', $$ CREATE INDEX IF NOT EXISTS ON :Bucket(id) $$) AS (r agtype)"#,
            r#"SELECT * FROM cypher('activable', $$ CREATE INDEX IF NOT EXISTS ON :KmsKey(id) $$) AS (r agtype)"#,
            r#"SELECT * FROM cypher('activable', $$ CREATE INDEX IF NOT EXISTS ON :Policy(id) $$) AS (r agtype)"#,
        ];

        for stmt in index_statements {
            match conn.batch_execute(stmt).await {
                Ok(_) => {
                    tracing::debug!(stmt = %stmt, "index migration ok");
                }
                Err(e) => {
                    // Common: label table doesn't exist yet (no nodes created of that label).
                    // Non-fatal: re-runs on every startup.
                    tracing::warn!(
                        error = %e,
                        stmt = %stmt,
                        "index migration skipped — label table may not exist yet"
                    );
                }
            }
        }
        tracing::info!("index migrations complete");
    }

    // Initialize the scheduler (JobStore + WorkerPool + Reaper).
    // Build JobStoreConfig from the same env as the graph pool to share the Postgres connection.
    let job_store_config = JobStoreConfig {
        host: db_host.clone(),
        port: db_port,
        user: db_user.clone(),
        password: db_password.clone(),
        dbname: db_name.clone(),
        pool_size: max_connections,
        backoff_base_seconds: 2.0,
    };

    let job_store = Arc::new(
        JobStore::new(job_store_config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create JobStore: {}", e))?,
    );

    // Initialize the scheduler's schema (jobs table, indexes).
    job_store
        .ensure_schema()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to initialize scheduler schema: {}", e))?;
    tracing::info!("Scheduler schema initialized");

    // Build the Scheduler with AccountIngestHandler.
    // The handler manages AWS ingestion per account.
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-east-1"))
        .load()
        .await;

    let ingest_handler =
        activable_ingest::AccountIngestHandler::new(aws_config, pool.clone(), graph_name.clone())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create AccountIngestHandler: {}", e))?;

    let mut scheduler = Scheduler::builder()
        .register(Arc::new(ingest_handler))
        .concurrency(4)
        .reap_threshold_seconds(300)
        .reap_check_interval(std::time::Duration::from_secs(30))
        .build(job_store.clone())
        .map_err(|e| anyhow::anyhow!("Failed to build scheduler: {}", e))?;

    // Start the scheduler (spawns worker pool + reaper).
    scheduler
        .start()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start scheduler: {}", e))?;

    tracing::info!("Scheduler started with 4 workers");

    // Initialize risk configuration
    let risk_config = RiskConfig::default();
    tracing::info!(
        signals = ?risk_config.signals,
        "Risk configuration initialized"
    );

    // Load and initialize risk rules
    let _rules = load_rules_from_embedded().expect("embedded rules must parse at startup");
    let rule_count = _rules.len();
    let weight_sum = risk_config.signals_weight_sum();
    tracing::info!(
        rule_count = rule_count,
        weight_sum = %format!("{:.2}", weight_sum),
        "risk engine ready"
    );

    // Initialize graph service for risk scoring
    // Use GraphClientAdapter wrapping the real GraphClient (Phase 1)
    // Fallback to InMemoryGraphService if needed for testing
    let graph_service: Box<dyn activable_risk::signals::GraphQueryService> = Box::new(
        graph_client_adapter::GraphClientAdapter::new(client.clone()),
    );
    tracing::info!("Graph service initialized (GraphClientAdapter wrapping GraphClient)");

    // Build the async-graphql schema
    let schema: AppSchema =
        Schema::build(QueryRoot, MutationRoot, async_graphql::EmptySubscription)
            .data(client)
            .data(pool.clone())
            .data(job_store.clone())
            .data(risk_config)
            .data(graph_service)
            .limit_complexity(500)
            .limit_depth(10)
            .finish();

    tracing::info!("GraphQL schema built with complexity limit 500, depth limit 10");

    // Build the axum router with shared pool state
    let pool_clone = pool.clone();
    let schema_arc = std::sync::Arc::new(schema);

    // App state
    #[derive(Clone)]
    struct AppState {
        schema: std::sync::Arc<AppSchema>,
        pool: std::sync::Arc<deadpool_postgres::Pool>,
    }

    let app_state = AppState {
        schema: schema_arc,
        pool: pool_clone,
    };

    // GraphQL handler - accepts POST requests with JSON body
    async fn graphql_handler(
        axum::extract::State(app_state): axum::extract::State<AppState>,
        Json(request_body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        // Parse the incoming JSON as a GraphQL request
        if let Some(obj) = request_body.as_object() {
            let query = obj.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let operation_name = obj.get("operationName").and_then(|v| v.as_str());

            let mut request = async_graphql::Request::new(query);
            if let Some(vars) = obj.get("variables").cloned() {
                if let Ok(var_map) = serde_json::from_value(vars) {
                    request = request.variables(var_map);
                }
            }
            if let Some(op_name) = operation_name {
                request = request.operation_name(op_name);
            }

            let response = app_state.schema.execute(request).await;
            Json(serde_json::to_value(&response).unwrap_or_else(
                |_| serde_json::json!({"errors": [{"message": "Failed to serialize response"}]}),
            ))
        } else {
            Json(serde_json::json!({"errors": [{"message": "Invalid GraphQL request"}]}))
        }
    }

    // Health handler that uses pool state
    async fn health_with_pool(
        axum::extract::State(app_state): axum::extract::State<AppState>,
    ) -> (axum::http::StatusCode, &'static str) {
        match app_state.pool.get().await {
            Ok(_) => (axum::http::StatusCode::OK, "Healthy"),
            Err(_) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, "Unhealthy"),
        }
    }

    let app = Router::new()
        // GraphQL endpoint
        .route("/graphql", axum::routing::post(graphql_handler))
        // Health check endpoint
        .route("/healthz", get(health_with_pool))
        .with_state(app_state)
        // Limit request body size to 1MB
        .layer(DefaultBodyLimit::max(1024 * 1024))
        // Add request tracing
        .layer(
            tower_http::trace::TraceLayer::new_for_http().make_span_with(
                tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO),
            ),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], server_port));
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    let server_task = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal());

    // Run the server. The scheduler runs in the background and will continue
    // processing jobs until the process is terminated.
    let result = server_task.await;

    tracing::info!("Server shut down gracefully, draining scheduler");

    // Drain the scheduler: stop workers + reaper cleanly on shutdown.
    scheduler.shutdown().await?;
    tracing::info!("Scheduler drained");

    Ok(result?)
}

/// Listen for SIGTERM and graceful shutdown signal.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received CTRL+C signal");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM signal");
        }
    }
}
