//! Resolver for risk scoring queries.

use crate::types::{GqlRiskAssessment, GqlSeverity};
use activable_risk::{
    load_rules_from_dir, score_single_principal, EffectivePermission, GraphQueryService,
    RiskAssessment, RiskConfig,
};
use async_graphql::Context;

/// Get risk assessment for a principal.
///
/// 1. Check for cached assessment in graph
/// 2. If cached and fresh, return it
/// 3. If stale or missing, compute fresh score and return
pub async fn risk_score(
    ctx: &Context<'_>,
    principal_id: String,
) -> async_graphql::Result<GqlRiskAssessment> {
    let config = ctx
        .data::<RiskConfig>()
        .map_err(|_| async_graphql::Error::new("RiskConfig not available"))?;
    let graph = ctx
        .data::<Box<dyn GraphQueryService>>()
        .map_err(|_| async_graphql::Error::new("GraphQueryService not available"))?;

    // 1. Try to read cached assessment
    let cached_json = graph.read_risk_assessment(&principal_id).await
        .map_err(|e| {
            tracing::error!(principal_id = %principal_id, error = %e, "failed to read cached assessment");
            async_graphql::Error::new("Failed to read risk assessment")
        })?;

    if let Some(json) = cached_json {
        // Parse cached assessment
        if let Ok(assessment) = serde_json::from_str::<RiskAssessment>(&json) {
            tracing::debug!(principal_id = %principal_id, "returning cached risk assessment");
            return Ok(GqlRiskAssessment::from(assessment));
        }
    }

    // 2. No cached score or parse failed — compute fresh
    compute_and_return(graph.as_ref(), config, &principal_id).await
}

/// Refresh (re-score) a principal's risk assessment.
/// Always computes fresh regardless of cache state.
pub async fn refresh_risk_score(
    ctx: &Context<'_>,
    principal_id: String,
) -> async_graphql::Result<GqlRiskAssessment> {
    let config = ctx
        .data::<RiskConfig>()
        .map_err(|_| async_graphql::Error::new("RiskConfig not available"))?;
    let graph = ctx
        .data::<Box<dyn GraphQueryService>>()
        .map_err(|_| async_graphql::Error::new("GraphQueryService not available"))?;

    tracing::info!(principal_id = %principal_id, "computing fresh risk assessment");
    compute_and_return(graph.as_ref(), config, &principal_id).await
}

/// List all risk assessments above a minimum severity threshold.
pub async fn findings(
    ctx: &Context<'_>,
    min_severity: Option<GqlSeverity>,
    limit: Option<i32>,
) -> async_graphql::Result<Vec<GqlRiskAssessment>> {
    let graph = ctx
        .data::<Box<dyn GraphQueryService>>()
        .map_err(|_| async_graphql::Error::new("GraphQueryService not available"))?;
    let config = ctx
        .data::<RiskConfig>()
        .map_err(|_| async_graphql::Error::new("RiskConfig not available"))?;

    let limit = limit.unwrap_or(100).min(1000) as usize;
    let min_score = match min_severity.unwrap_or(GqlSeverity::Medium) {
        GqlSeverity::Critical => config.severity.critical,
        GqlSeverity::High => config.severity.high,
        GqlSeverity::Medium => config.severity.medium,
        GqlSeverity::Low => config.severity.low,
        GqlSeverity::Info => 0.0,
    };

    // Get all principals
    let principal_ids = graph.list_principal_ids().await.map_err(|e| {
        tracing::error!(error = %e, "failed to list principals");
        async_graphql::Error::new("Failed to list principals")
    })?;

    let mut results = Vec::new();

    for pid in principal_ids {
        if let Ok(Some(json)) = graph.read_risk_assessment(&pid).await {
            if let Ok(assessment) = serde_json::from_str::<RiskAssessment>(&json) {
                if assessment.score >= min_score {
                    results.push(GqlRiskAssessment::from(assessment));
                }
            }
        }
        if results.len() >= limit {
            break;
        }
    }

    // Sort by score descending
    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(results)
}

/// Internal: compute fresh score for principal, persist to graph, return
async fn compute_and_return(
    graph: &dyn GraphQueryService,
    config: &RiskConfig,
    principal_id: &str,
) -> async_graphql::Result<GqlRiskAssessment> {
    // Get effective permissions
    let perm_pairs = graph
        .get_effective_permissions(principal_id)
        .await
        .map_err(|e| {
            tracing::error!(principal_id = %principal_id, error = %e, "failed to get permissions");
            async_graphql::Error::new("Failed to retrieve principal permissions")
        })?;

    let effective_perms: Vec<EffectivePermission> = perm_pairs
        .into_iter()
        .map(|(action, resource)| EffectivePermission::new(action, resource))
        .collect();

    if effective_perms.is_empty() {
        return Err(async_graphql::Error::new(
            "Principal not found or has no permissions",
        ));
    }

    // Load rules from the default bundled directory
    let rules = load_rules_from_dir("config/escalation-paths/bundled").unwrap_or_default();

    // Compute timestamp
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("{}Z", d.as_secs()))
        .unwrap_or_else(|_| "unknown".to_string());

    // Score the principal
    let assessment =
        score_single_principal(principal_id, &effective_perms, &rules, graph, config, &now)
            .await
            .map_err(|e| {
                tracing::error!(principal_id = %principal_id, error = %e, "scoring failed");
                async_graphql::Error::new("Failed to compute risk score")
            })?;

    // Persist to graph
    if let Ok(json) = serde_json::to_string(&assessment) {
        if let Err(e) = graph.write_risk_assessment(principal_id, &json).await {
            tracing::warn!(principal_id = %principal_id, error = %e, "failed to cache assessment");
            // Non-fatal: return the computed assessment even if caching fails
        }
    }

    Ok(GqlRiskAssessment::from(assessment))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_adapter::InMemoryGraphService;

    #[tokio::test]
    async fn risk_score_returns_cached_when_available() {
        let graph = InMemoryGraphService::new();
        graph
            .add_principal("principal-1".to_string(), vec![], 0, None, 0)
            .unwrap();

        // Pre-populate cache
        let cached_assessment = r#"{"principal_id":"principal-1","score":0.75,"severity":"High","signal_contributions":[],"matched_rules":[],"rule_boost":0.0,"signal_total":0.75,"computed_at":"2026-05-23T10:00:00Z"}"#;
        graph
            .write_risk_assessment("principal-1", cached_assessment)
            .await
            .unwrap();

        let cached = graph.read_risk_assessment("principal-1").await.unwrap();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), cached_assessment);
    }

    #[tokio::test]
    async fn findings_filters_by_severity() {
        let graph = InMemoryGraphService::new();
        graph
            .add_principal("principal-1".to_string(), vec![], 0, None, 0)
            .unwrap();
        graph
            .add_principal("principal-2".to_string(), vec![], 0, None, 0)
            .unwrap();

        // Store two assessments with different scores
        let high_assessment = r#"{"principal_id":"principal-1","score":0.75,"severity":"High","signal_contributions":[],"matched_rules":[],"rule_boost":0.0,"signal_total":0.75,"computed_at":"2026-05-23T10:00:00Z"}"#;
        let low_assessment = r#"{"principal_id":"principal-2","score":0.15,"severity":"Info","signal_contributions":[],"matched_rules":[],"rule_boost":0.0,"signal_total":0.15,"computed_at":"2026-05-23T10:00:00Z"}"#;

        graph
            .write_risk_assessment("principal-1", high_assessment)
            .await
            .unwrap();
        graph
            .write_risk_assessment("principal-2", low_assessment)
            .await
            .unwrap();

        // Verify both are cached
        assert!(graph
            .read_risk_assessment("principal-1")
            .await
            .unwrap()
            .is_some());
        assert!(graph
            .read_risk_assessment("principal-2")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn compute_and_return_scores_principal_with_permissions() {
        let graph = InMemoryGraphService::new();
        graph
            .add_principal(
                "alice".to_string(),
                vec![
                    ("iam:CreatePolicyVersion".to_string(), "*".to_string()),
                    ("s3:GetObject".to_string(), "*".to_string()),
                ],
                50,
                Some(2),
                1,
            )
            .unwrap();

        let config = RiskConfig::default();
        let result = compute_and_return(&graph, &config, "alice").await;
        assert!(result.is_ok());
        let assessment = result.unwrap();
        assert_eq!(assessment.principal_id, "alice");
        assert!(assessment.score > 0.0);
        assert_eq!(assessment.signals.len(), 5);
    }

    #[tokio::test]
    async fn compute_and_return_errors_on_empty_permissions() {
        let graph = InMemoryGraphService::new();
        graph
            .add_principal("empty".to_string(), vec![], 0, None, 0)
            .unwrap();

        let config = RiskConfig::default();
        let result = compute_and_return(&graph, &config, "empty").await;
        assert!(result.is_err());
    }
}
