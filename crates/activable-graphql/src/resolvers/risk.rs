//! Resolver for risk scoring queries.

use crate::types::GqlRiskAssessment;
use activable_risk::RiskConfig;
use async_graphql::Context;

/// Get risk assessment for a principal.
///
/// # Phase 8 Implementation Note
///
/// This resolver establishes the GraphQL contract for risk scoring.
/// Full integration with graph node property reads and caching is deferred
/// to Phase 9, when the GraphClient write API becomes available.
///
/// Currently returns an error indicating the principal is not found,
/// as the infrastructure for storing and retrieving cached risk scores
/// on graph nodes does not yet exist.
pub async fn risk_score(
    ctx: &Context<'_>,
    principal_id: String,
) -> async_graphql::Result<GqlRiskAssessment> {
    let _config = ctx
        .data::<RiskConfig>()
        .map_err(|_| async_graphql::Error::new("RiskConfig not available"))?;

    // Phase 9 will implement:
    // 1. Read cached assessment from graph node property
    // 2. Check staleness against latest ingest timestamp
    // 3. Lazy re-score if stale
    // 4. Return typed response

    tracing::warn!(
        principal_id = %principal_id,
        "risk_score resolver called but not yet integrated with graph"
    );

    Err(async_graphql::Error::new(
        "Principal not found or risk scoring not yet initialized.",
    ))
}

/// Refresh (re-score) a principal's risk assessment.
///
/// # Phase 8 Implementation Note
///
/// This mutation establishes the GraphQL contract for ad-hoc re-scoring.
/// It is intended to replace lazy re-scoring in Phase 9 when full
/// integration with the risk engine is available.
///
/// Currently returns an error as the backing infrastructure is not ready.
pub async fn refresh_risk_score(
    ctx: &Context<'_>,
    principal_id: String,
) -> async_graphql::Result<GqlRiskAssessment> {
    let _config = ctx
        .data::<RiskConfig>()
        .map_err(|_| async_graphql::Error::new("RiskConfig not available"))?;

    // Phase 9 will implement:
    // 1. Call score_principal() from activable-risk
    // 2. Write result to graph node properties
    // 3. Return typed response

    tracing::warn!(
        principal_id = %principal_id,
        "refresh_risk_score mutation called but not yet integrated with graph"
    );

    Err(async_graphql::Error::new(
        "Principal not found or risk scoring not yet initialized.",
    ))
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[tokio::test]
    async fn risk_score_returns_error_when_not_integrated() {
        // Placeholder: test structure for Phase 9 integration tests
        // When graph write API is available, this test will verify:
        // - RiskAssessment is correctly deserialized from graph node
        // - Staleness check is performed
        // - Score is returned with all fields populated
    }

    #[tokio::test]
    async fn refresh_risk_score_returns_error_when_not_integrated() {
        // Placeholder: test structure for Phase 9 integration tests
        // When scoring engine is integrated, this test will verify:
        // - score_principal() is called
        // - Result is written to graph
        // - Response is properly typed
    }
}
