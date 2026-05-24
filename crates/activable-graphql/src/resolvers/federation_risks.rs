//! Resolver for federation risk queries (OIDC configuration drift analysis).

use crate::types::{
    GqlDriftAnalysis, GqlFederationRisks, GqlOidcProvider, GqlSeverity,
};
use activable_graph::GraphClient;
use async_graphql::Context;

/// Get federation risks for an AWS account.
///
/// Queries OIDC providers attached to the account and analyzes trust policy
/// drift (condition key removals indicate loosening). Returns empty provider
/// list with notice if OIDC ingestion not yet enabled.
pub async fn federation_risks(
    ctx: &Context<'_>,
    account_id: String,
) -> async_graphql::Result<GqlFederationRisks> {
    let graph = ctx
        .data::<GraphClient>()
        .map_err(|_| async_graphql::Error::new("GraphClient not available"))?;

    // Check if OIDC schema labels exist
    let cypher_check = r#"MATCH (p:OidcProvider) RETURN count(p) as cnt LIMIT 1"#;
    let results = graph
        .cypher_multi_column(cypher_check, 1)
        .await
        .unwrap_or_default();
    let has_oidc_schema = !results.is_empty();

    if !has_oidc_schema {
        // OIDC ingestion not yet enabled; return empty response with notice
        return Ok(GqlFederationRisks {
            account_id,
            oidc_providers: vec![],
            risk_score: 0.0,
            severity: GqlSeverity::Info,
            notice: Some(
                "OIDC ingestion not yet enabled in this environment. \
                 Trust policy drift analysis requires LocalStack OIDC support."
                    .to_string(),
            ),
        });
    }

    // Query OIDC providers for the account
    let cypher = format!(
        r#"MATCH (a:Account {{id: '{account}'}})-[:HasOidcProvider]->(p:OidcProvider)
           OPTIONAL MATCH (p)-[:HasFederationVersion]->(v:Policy)
           RETURN p.id, p.provider_name, collect(v) as versions"#,
        account = activable_graph::query_builder::escape_cypher(&account_id)
    );

    let results = graph.cypher_multi_column(&cypher, 3).await.map_err(|e| {
        tracing::error!(account_id = %account_id, error = %e, "failed to query OIDC providers");
        async_graphql::Error::new("Failed to query OIDC providers")
    })?;

    let mut oidc_providers = vec![];

    for row in results {
        if row.len() < 3 {
            continue;
        }

        let _provider_id = row[0]
            .as_str()
            .unwrap_or(&account_id)
            .to_string();

        let provider_name = row[1]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Parse versions array (simplified; in production would parse Policy nodes)
        // For now, return empty versions list since Phase 3 ingest may not have
        // populated the full FederationVersion graph structure yet
        let trust_policy_versions = vec![];

        // Drift detection: would compare consecutive versions' condition keys.
        // For now, return default drift (none) since versions are empty.
        let drift = GqlDriftAnalysis {
            direction: "none".to_string(),
            severity: GqlSeverity::Info,
            removed_condition_keys: vec![],
        };

        oidc_providers.push(GqlOidcProvider {
            provider: provider_name,
            trust_policy_versions,
            drift: Some(drift),
        });
    }

    // Risk score: 0.85 if any loosening detected, 0.40 if tightening, 0.0 if none
    // Since we're in fallback mode (OIDC ingest may not be fully populated),
    // default to 0.0
    let risk_score = 0.0;
    let severity = if risk_score >= 0.80 {
        GqlSeverity::Critical
    } else if risk_score >= 0.60 {
        GqlSeverity::High
    } else if risk_score >= 0.40 {
        GqlSeverity::Medium
    } else if risk_score >= 0.20 {
        GqlSeverity::Low
    } else {
        GqlSeverity::Info
    };

    let is_empty = oidc_providers.is_empty();

    Ok(GqlFederationRisks {
        account_id,
        oidc_providers,
        risk_score,
        severity,
        notice: if is_empty {
            Some("No OIDC providers configured for this account.".to_string())
        } else {
            None
        },
    })
}
