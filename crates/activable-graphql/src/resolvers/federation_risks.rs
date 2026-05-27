//! Resolver for federation risk queries (OIDC trust boundary scoring).

use crate::types::{GqlFederationRisks, GqlOidcProvider, GqlSeverity};
use activable_graph::GraphClient;
use async_graphql::Context;

/// Get federation risks for an AWS account.
///
/// Queries OIDC providers attached to the account and scores them as trust boundaries.
/// A provider with broad/missing audience or subject conditions is a weak trust boundary.
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
            notice: Some("No OIDC providers configured for this account.".to_string()),
            is_trust_boundary: false,
        });
    }

    // Query OIDC providers for the account
    let escaped_account = activable_graph::query_builder::escape_cypher(&account_id);
    let cypher = format!(
        r#"MATCH (a:Account {{id: '{account}'}})-[:HasOidcProvider]->(p:OidcProvider)
           RETURN p.id, p.provider_name, p.aud, p.sub"#,
        account = escaped_account
    );

    let results = graph.cypher_multi_column(&cypher, 4).await.map_err(|e| {
        tracing::error!(account_id = %account_id, error = %e, "failed to query OIDC providers");
        async_graphql::Error::new("Failed to query OIDC providers")
    })?;

    let mut oidc_providers = vec![];
    let mut has_weak_provider = false;
    let account_level_risk_score = 0.1f64; // Base score when OIDC is present

    for row in results {
        if row.len() < 4 {
            continue;
        }

        let provider_name = row[1]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let aud = row[2].as_str().map(|s| s.to_string()).unwrap_or_default();

        let sub = row[3].as_str().map(|s| s.to_string()).unwrap_or_default();

        // Evaluate trust boundary: broad/missing aud or sub => weak
        let is_weak = evaluate_oidc_weakness(&aud, &sub);
        if is_weak {
            has_weak_provider = true;
        }

        // Return empty trust_policy_versions and drift (not in scope for this phase)
        let trust_policy_versions = vec![];
        let drift = None;

        oidc_providers.push(GqlOidcProvider {
            provider: provider_name,
            trust_policy_versions,
            drift,
        });
    }

    // Compute account-level risk and trust boundary
    // Account is only a trust boundary if ALL providers have specific aud AND sub
    let is_account_trust_boundary = !has_weak_provider && !oidc_providers.is_empty();
    let risk_score = if has_weak_provider {
        0.85
    } else {
        account_level_risk_score
    };
    let severity = score_to_severity(risk_score);

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
        is_trust_boundary: is_account_trust_boundary,
    })
}

/// Evaluate if an OIDC provider configuration is a weak trust boundary.
/// A provider is weak if audience or subject is missing/empty OR contains a wildcard.
/// A GitHub-Actions OIDC sub/aud that contains a wildcard (e.g. `repo:org/*`)
/// lets any repo/branch assume the role — a broad, loosened trust boundary.
/// A properly-scoped trust pins an exact repo+ref with no wildcard.
fn evaluate_oidc_weakness(aud: &str, sub: &str) -> bool {
    aud.is_empty() || aud.contains('*') || sub.is_empty() || sub.contains('*')
}

/// Convert score to severity level.
fn score_to_severity(score: f64) -> GqlSeverity {
    match score {
        s if s >= 0.80 => GqlSeverity::Critical,
        s if s >= 0.60 => GqlSeverity::High,
        s if s >= 0.40 => GqlSeverity::Medium,
        s if s >= 0.20 => GqlSeverity::Low,
        _ => GqlSeverity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_weakness_with_broad_sub_and_specific_aud() {
        // Mirrors real seed: aud="sts.amazonaws.com", sub="repo:myorg/myrepo:*"
        // Sub contains wildcard => weak trust boundary
        let is_weak = evaluate_oidc_weakness("sts.amazonaws.com", "repo:myorg/myrepo:*");
        assert!(is_weak, "Sub with wildcard should be weak");
    }

    #[test]
    fn oidc_strength_with_specific_sub_and_aud() {
        // Properly-scoped: aud="sts.amazonaws.com", sub="repo:myorg/myrepo:ref:refs/heads/main"
        // No wildcards => strong trust boundary
        let is_weak =
            evaluate_oidc_weakness("sts.amazonaws.com", "repo:myorg/myrepo:ref:refs/heads/main");
        assert!(!is_weak, "Sub without wildcard should be strong");
    }

    #[test]
    fn oidc_weakness_with_wildcard_aud() {
        // Aud with wildcard => weak
        let is_weak =
            evaluate_oidc_weakness("*.amazonaws.com", "repo:myorg/myrepo:ref:refs/heads/main");
        assert!(is_weak, "Aud with wildcard should be weak");
    }

    #[test]
    fn oidc_weakness_with_empty_sub() {
        // Empty sub => weak (missing condition)
        let is_weak = evaluate_oidc_weakness("sts.amazonaws.com", "");
        assert!(is_weak, "Empty sub should be weak");
    }

    #[test]
    fn oidc_weakness_with_empty_aud() {
        // Empty aud => weak (missing condition)
        let is_weak = evaluate_oidc_weakness("", "repo:myorg/myrepo:ref:refs/heads/main");
        assert!(is_weak, "Empty aud should be weak");
    }

    #[test]
    fn oidc_weakness_with_literal_wildcard_aud() {
        // Literal "*" for aud => weak
        let is_weak = evaluate_oidc_weakness("*", "repo:myorg/myrepo:ref:refs/heads/main");
        assert!(is_weak, "Literal wildcard aud should be weak");
    }

    #[test]
    fn oidc_weakness_with_literal_wildcard_sub() {
        // Literal "*" for sub => weak
        let is_weak = evaluate_oidc_weakness("sts.amazonaws.com", "*");
        assert!(is_weak, "Literal wildcard sub should be weak");
    }

    #[test]
    fn oidc_strength_both_specific() {
        // Both aud and sub are specific (no wildcards, not empty) => strong
        let is_weak =
            evaluate_oidc_weakness("123456789", "repo:myorg/repo-a:environment:production");
        assert!(!is_weak, "Specific aud and sub should be strong");
    }
}
