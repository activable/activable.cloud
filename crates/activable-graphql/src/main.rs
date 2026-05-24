//! Activable GraphQL API server using async-graphql and axum.

use activable_graph::pool::GraphPool;
use activable_graph::GraphClient;
use activable_risk::{RiskConfig, load_rules_from_embedded};
use async_graphql::Schema;
use axum::{extract::DefaultBodyLimit, routing::get, Json, Router};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod error;
mod graph_adapter;
mod graph_client_adapter;
mod resolvers;
mod schema;
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

    // Build the connection pool
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

    // Initialize ingest_runs table
    {
        let conn = pool.get().await.map_err(|e| {
            anyhow::anyhow!("Failed to get connection for table initialization: {}", e)
        })?;
        conn.batch_execute(
            "CREATE TABLE IF NOT EXISTS ingest_runs (
                run_id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                error_message TEXT,
                stats JSONB
            )",
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create ingest_runs table: {}", e))?;
        tracing::info!("ingest_runs table initialized");
    }

    // Create the GraphClient
    let client = GraphClient::new(pool.clone(), &graph_name);
    tracing::info!(graph_name = %graph_name, "GraphClient initialized");

    // Create the IngestRuntime
    let ingest_runtime =
        activable_ingest::IngestRuntime::new(pool.clone(), graph_name.clone()).await?;
    let ingest_runtime = Arc::new(ingest_runtime);
    tracing::info!("IngestRuntime initialized");

    // Create atomic flag for concurrent run prevention
    let ingest_active = Arc::new(AtomicBool::new(false));

    // Initialize risk configuration
    let risk_config = RiskConfig::default();
    tracing::info!(
        signals = ?risk_config.signals,
        "Risk configuration initialized"
    );

    // Load and initialize risk rules
    let _rules = load_rules_from_embedded()
        .expect("embedded rules must parse at startup");
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
            .data(ingest_runtime)
            .data(ingest_active.clone())
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

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Server shut down gracefully");
    Ok(())
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
