//! Domain service for federation (OIDC) risk computation.
//!
//! Encapsulates all orchestration logic for evaluating OIDC trust-boundary
//! health across an AWS account. The GraphQL resolver delegates to this
//! service and maps the result to Gql* types.

use crate::signals::{GraphQueryService, OidcProviderRow};

/// Severity tier for risk scores — mirrors the thresholds used across the codebase.
/// Defined here as a domain type so callers do not depend on GraphQL types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// An evaluated OIDC provider with its trust-boundary status.
#[derive(Debug, Clone)]
pub struct EvaluatedOidcProvider {
    pub provider_name: String,
    pub is_weak: bool,
}

/// Result of the federation risk assessment for one AWS account.
#[derive(Debug, Clone)]
pub struct FederationRiskResult {
    pub account_id: String,
    pub providers: Vec<EvaluatedOidcProvider>,
    pub risk_score: f64,
    pub severity: RiskSeverity,
    /// None when providers are present; set when the account has no OIDC configuration.
    pub notice: Option<String>,
    /// True only when ALL providers have specific (non-wildcard, non-empty) aud AND sub.
    pub is_trust_boundary: bool,
}

/// Compute federation risk for an account.
///
/// Queries OIDC providers via the graph port, evaluates each for weak trust
/// boundaries (broad/missing audience or subject conditions), and returns a
/// scored result.
///
/// Returns `Ok(result)` with an empty provider list + notice when OIDC is not
/// configured. Returns `Err` only on underlying graph query failures.
pub async fn assess_federation_risk(
    graph: &dyn GraphQueryService,
    account_id: &str,
) -> Result<FederationRiskResult, Box<dyn std::error::Error + Send + Sync>> {
    let rows: Vec<OidcProviderRow> = graph.query_oidc_providers(account_id).await?;

    if rows.is_empty() {
        return Ok(FederationRiskResult {
            account_id: account_id.to_string(),
            providers: vec![],
            risk_score: 0.0,
            severity: RiskSeverity::Info,
            notice: Some("No OIDC providers configured for this account.".to_string()),
            is_trust_boundary: false,
        });
    }

    let base_risk_score = 0.1_f64; // Present but not yet evaluated as weak
    let mut has_weak_provider = false;

    let providers: Vec<EvaluatedOidcProvider> = rows
        .into_iter()
        .map(|row| {
            let is_weak = evaluate_oidc_weakness(&row.aud, &row.sub);
            if is_weak {
                has_weak_provider = true;
            }
            EvaluatedOidcProvider {
                provider_name: row.provider_name,
                is_weak,
            }
        })
        .collect();

    // Weak provider means broad trust — highest risk bucket
    let risk_score = if has_weak_provider {
        0.85
    } else {
        base_risk_score
    };
    let severity = score_to_severity(risk_score);

    // Account is a trust boundary only when ALL providers are strong
    let is_trust_boundary = !has_weak_provider;

    Ok(FederationRiskResult {
        account_id: account_id.to_string(),
        providers,
        risk_score,
        severity,
        notice: None,
        is_trust_boundary,
    })
}

/// Evaluate if an OIDC provider configuration represents a weak trust boundary.
///
/// A provider is weak when the audience or subject claim is missing, empty, or
/// contains a wildcard. A GitHub-Actions OIDC subject like `repo:org/*` lets
/// any repo/branch assume the associated role — an intentionally broad grant.
/// A properly-scoped trust pins an exact repo+ref with no wildcard.
pub fn evaluate_oidc_weakness(aud: &str, sub: &str) -> bool {
    aud.is_empty() || aud.contains('*') || sub.is_empty() || sub.contains('*')
}

/// Convert a risk score to a severity level using fixed thresholds.
fn score_to_severity(score: f64) -> RiskSeverity {
    match score {
        s if s >= 0.80 => RiskSeverity::Critical,
        s if s >= 0.60 => RiskSeverity::High,
        s if s >= 0.40 => RiskSeverity::Medium,
        s if s >= 0.20 => RiskSeverity::Low,
        _ => RiskSeverity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::test_fixtures::MockGraphQueryService;

    // -------------------------------------------------------------------------
    // evaluate_oidc_weakness unit tests
    // -------------------------------------------------------------------------

    #[test]
    fn weakness_wildcard_in_sub() {
        assert!(evaluate_oidc_weakness(
            "sts.amazonaws.com",
            "repo:myorg/myrepo:*"
        ));
    }

    #[test]
    fn weakness_wildcard_in_aud() {
        assert!(evaluate_oidc_weakness(
            "*.amazonaws.com",
            "repo:myorg/myrepo:ref:refs/heads/main"
        ));
    }

    #[test]
    fn weakness_empty_sub() {
        assert!(evaluate_oidc_weakness("sts.amazonaws.com", ""));
    }

    #[test]
    fn weakness_empty_aud() {
        assert!(evaluate_oidc_weakness(
            "",
            "repo:myorg/myrepo:ref:refs/heads/main"
        ));
    }

    #[test]
    fn weakness_both_empty() {
        assert!(evaluate_oidc_weakness("", ""));
    }

    #[test]
    fn strength_specific_aud_and_sub() {
        assert!(!evaluate_oidc_weakness(
            "sts.amazonaws.com",
            "repo:myorg/myrepo:ref:refs/heads/main"
        ));
    }

    #[test]
    fn strength_numeric_aud_specific_sub() {
        assert!(!evaluate_oidc_weakness(
            "123456789",
            "repo:myorg/repo-a:environment:production"
        ));
    }

    #[test]
    fn weakness_literal_wildcard_aud() {
        assert!(evaluate_oidc_weakness(
            "*",
            "repo:myorg/myrepo:ref:refs/heads/main"
        ));
    }

    #[test]
    fn weakness_literal_wildcard_sub() {
        assert!(evaluate_oidc_weakness("sts.amazonaws.com", "*"));
    }

    // -------------------------------------------------------------------------
    // assess_federation_risk service tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn no_oidc_schema_returns_empty_with_notice() {
        let graph = MockGraphQueryService::new();
        // No providers registered — empty response expected
        let result = assess_federation_risk(&graph, "123456789012")
            .await
            .unwrap();

        assert_eq!(result.account_id, "123456789012");
        assert!(result.providers.is_empty());
        assert_eq!(result.risk_score, 0.0);
        assert_eq!(result.severity, RiskSeverity::Info);
        assert!(result.notice.is_some());
        assert!(result.notice.unwrap().contains("No OIDC providers"));
        assert!(!result.is_trust_boundary);
    }

    #[tokio::test]
    async fn weak_provider_scores_high() {
        let graph = MockGraphQueryService::new().with_oidc_providers(
            "444444444444".to_string(),
            vec![OidcProviderRow {
                provider_id: "p-1".to_string(),
                provider_name: "token.actions.githubusercontent.com".to_string(),
                aud: "sts.amazonaws.com".to_string(),
                sub: "repo:myorg/myrepo:*".to_string(), // wildcard — weak
            }],
        );

        let result = assess_federation_risk(&graph, "444444444444")
            .await
            .unwrap();

        assert_eq!(result.providers.len(), 1);
        assert!(result.providers[0].is_weak);
        assert!((result.risk_score - 0.85).abs() < 1e-10);
        assert_eq!(result.severity, RiskSeverity::Critical);
        assert!(!result.is_trust_boundary);
        assert!(result.notice.is_none());
    }

    #[tokio::test]
    async fn strong_provider_scores_low() {
        let graph = MockGraphQueryService::new().with_oidc_providers(
            "444444444444".to_string(),
            vec![OidcProviderRow {
                provider_id: "p-1".to_string(),
                provider_name: "token.actions.githubusercontent.com".to_string(),
                aud: "sts.amazonaws.com".to_string(),
                sub: "repo:myorg/myrepo:ref:refs/heads/main".to_string(), // specific
            }],
        );

        let result = assess_federation_risk(&graph, "444444444444")
            .await
            .unwrap();

        assert_eq!(result.providers.len(), 1);
        assert!(!result.providers[0].is_weak);
        assert!((result.risk_score - 0.1).abs() < 1e-10);
        assert_eq!(result.severity, RiskSeverity::Info);
        assert!(result.is_trust_boundary);
        assert!(result.notice.is_none());
    }

    #[tokio::test]
    async fn mixed_providers_weak_takes_precedence() {
        // One strong + one weak → account is NOT a trust boundary
        let graph = MockGraphQueryService::new().with_oidc_providers(
            "444444444444".to_string(),
            vec![
                OidcProviderRow {
                    provider_id: "p-1".to_string(),
                    provider_name: "token.actions.githubusercontent.com".to_string(),
                    aud: "sts.amazonaws.com".to_string(),
                    sub: "repo:myorg/repo-a:ref:refs/heads/main".to_string(),
                },
                OidcProviderRow {
                    provider_id: "p-2".to_string(),
                    provider_name: "token.actions.githubusercontent.com".to_string(),
                    aud: "sts.amazonaws.com".to_string(),
                    sub: "repo:myorg/repo-b:*".to_string(), // wildcard
                },
            ],
        );

        let result = assess_federation_risk(&graph, "444444444444")
            .await
            .unwrap();

        assert_eq!(result.providers.len(), 2);
        assert!(!result.providers[0].is_weak);
        assert!(result.providers[1].is_weak);
        assert!((result.risk_score - 0.85).abs() < 1e-10);
        assert!(!result.is_trust_boundary);
    }

    #[tokio::test]
    async fn multiple_strong_providers_all_trust_boundary() {
        let graph = MockGraphQueryService::new().with_oidc_providers(
            "444444444444".to_string(),
            vec![
                OidcProviderRow {
                    provider_id: "p-1".to_string(),
                    provider_name: "provider-a".to_string(),
                    aud: "sts.amazonaws.com".to_string(),
                    sub: "repo:myorg/repo-a:ref:refs/heads/main".to_string(),
                },
                OidcProviderRow {
                    provider_id: "p-2".to_string(),
                    provider_name: "provider-b".to_string(),
                    aud: "sts.amazonaws.com".to_string(),
                    sub: "repo:myorg/repo-b:environment:production".to_string(),
                },
            ],
        );

        let result = assess_federation_risk(&graph, "444444444444")
            .await
            .unwrap();

        assert_eq!(result.providers.len(), 2);
        assert!(result.providers.iter().all(|p| !p.is_weak));
        assert!(result.is_trust_boundary);
    }

    #[tokio::test]
    async fn provider_with_missing_conditions_is_weak() {
        let graph = MockGraphQueryService::new().with_oidc_providers(
            "111111111111".to_string(),
            vec![OidcProviderRow {
                provider_id: "p-empty".to_string(),
                provider_name: "unconfigured-provider".to_string(),
                aud: "".to_string(), // missing
                sub: "".to_string(), // missing
            }],
        );

        let result = assess_federation_risk(&graph, "111111111111")
            .await
            .unwrap();

        assert!(result.providers[0].is_weak);
        assert!((result.risk_score - 0.85).abs() < 1e-10);
        assert!(!result.is_trust_boundary);
    }

    #[test]
    fn severity_critical_at_085() {
        assert_eq!(score_to_severity(0.85), RiskSeverity::Critical);
    }

    #[test]
    fn severity_high_at_070() {
        assert_eq!(score_to_severity(0.70), RiskSeverity::High);
    }

    #[test]
    fn severity_medium_at_050() {
        assert_eq!(score_to_severity(0.50), RiskSeverity::Medium);
    }

    #[test]
    fn severity_low_at_025() {
        assert_eq!(score_to_severity(0.25), RiskSeverity::Low);
    }

    #[test]
    fn severity_info_at_010() {
        assert_eq!(score_to_severity(0.10), RiskSeverity::Info);
    }
}
