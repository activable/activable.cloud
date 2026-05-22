//! Resolver for the healthz GraphQL query.
//! The HTTP health endpoint is defined inline in main.rs (health_with_pool).

use async_graphql::Context;
use deadpool_postgres::Pool;
use std::sync::Arc;

/// GraphQL query to check database pool health.
pub async fn healthz(ctx: &Context<'_>) -> async_graphql::Result<String> {
    let pool = ctx
        .data::<Arc<Pool>>()
        .map_err(|_| async_graphql::Error::new("Pool not available"))?;

    match pool.get().await {
        Ok(_) => Ok("healthy".to_string()),
        Err(e) => {
            tracing::error!("Health check failed: {}", e);
            Err(async_graphql::Error::new("Database unavailable"))
        }
    }
}
