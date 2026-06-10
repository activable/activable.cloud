//! Domain service for account-level risk aggregation.
//!
//! Enumerates all principals in an account, scores each one, buckets matched
//! rules into four categories, computes a harmonic-mean cascade score across
//! those categories, and returns the top-N principals by score.
//!
//! The GraphQL resolver delegates to this service and maps the result to Gql*
//! types. No Cypher strings or scoring arithmetic belong in the resolver.

use crate::batch_runner::score_single_principal;
use crate::cascade::harmonic_mean;
use crate::config::RiskConfig;
use crate::rule_engine::EffectivePermission;
use crate::rule_loader::load_rules_from_embedded;
use crate::signals::GraphQueryService;
use crate::types::MatchedRule;

/// Risk breakdown by category for one account.
/// Each field holds the maximum risk score across all principals in that category.
#[derive(Debug, Clone, Default)]
pub struct AccountCategorySignals {
    /// IAM privilege-escalation category (cf_escalation).
    pub cf_escalation: Option<CategorySignal>,
    /// OIDC drift / federation category (oidc_drift).
    pub oidc_drift: Option<CategorySignal>,
    /// S3 boundary-violation category (s3_boundary).
    pub s3_boundary: Option<CategorySignal>,
    /// KMS grant category (kms_grant).
    pub kms_grant: Option<CategorySignal>,
}

/// Score + matched rule IDs for a single risk category.
#[derive(Debug, Clone)]
pub struct CategorySignal {
    pub score: f64,
    pub matched_rule_ids: Vec<String>,
}

/// A single principal's risk summary within an account assessment.
#[derive(Debug, Clone)]
pub struct PrincipalRiskSummary {
    pub principal_id: String,
    pub score: f64,
    pub matched_rules: Vec<MatchedRule>,
}

/// Full result of an account-level risk assessment.
#[derive(Debug, Clone)]
pub struct AccountRiskResult {
    pub account_id: String,
    pub signals: AccountCategorySignals,
    pub cascade_risk_score: f64,
    /// Top principals sorted by score descending (up to `limit`).
    pub top_principals: Vec<PrincipalRiskSummary>,
    pub computed_at: String,
}

/// Assess risk for all principals in an account.
///
/// Steps:
/// 1. Enumerate principals via HasPrincipal edges, falling back to ARN-prefix.
/// 2. Score each principal using `score_single_principal`.
/// 3. Bucket matched rules into four categories; track the max score per bucket.
/// 4. Compute cascade risk as harmonic mean of the four category sub-scores.
/// 5. Sort principals by score descending; return the top `limit`.
///
/// Returns `Err` only on graph query failure. Returns an `AccountRiskResult`
/// with empty principals when the account has no principals in the graph —
/// callers decide whether that is an application error.
pub async fn assess_account_risk(
    graph: &dyn GraphQueryService,
    config: &RiskConfig,
    account_id: &str,
    limit: usize,
) -> Result<AccountRiskResult, Box<dyn std::error::Error + Send + Sync>> {
    let principal_ids = graph.list_account_principals(account_id).await?;

    let rules =
        load_rules_from_embedded().expect("embedded rules must parse — fix YAML or report bug");

    let mut principal_risks: Vec<(String, f64, Vec<MatchedRule>)> = Vec::new();
    // Per-category accumulator: category name → list of scores from matched principals
    let mut category_score_lists: std::collections::HashMap<String, Vec<f64>> =
        std::collections::HashMap::new();
    // Per-category rule IDs (for the signal summary)
    let mut category_rule_ids: std::collections::HashMap<
        String,
        std::collections::HashSet<String>,
    > = std::collections::HashMap::new();

    for principal_id in &principal_ids {
        let perm_pairs = match graph.get_effective_permissions(principal_id).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    principal_id = %principal_id,
                    error = %e,
                    "failed to get permissions — skipping principal"
                );
                continue;
            }
        };

        let effective_perms: Vec<EffectivePermission> = perm_pairs
            .into_iter()
            .map(|(action, resource)| EffectivePermission::new(action, resource))
            .collect();

        if effective_perms.is_empty() {
            tracing::debug!(principal_id = %principal_id, "principal has no permissions — skipping");
            continue;
        }

        let now = current_timestamp();

        let assessment = match score_single_principal(
            principal_id,
            &effective_perms,
            &rules,
            graph,
            config,
            &now,
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(
                    principal_id = %principal_id,
                    error = %e,
                    "failed to score principal — skipping"
                );
                continue;
            }
        };

        let risk_score = assessment.score;

        // Bucket matched rules by category
        for matched_rule in &assessment.matched_rules {
            let category = categorize_rule(&matched_rule.rule_id);
            if !category.is_empty() {
                category_score_lists
                    .entry(category.clone())
                    .or_default()
                    .push(risk_score);
                category_rule_ids
                    .entry(category)
                    .or_default()
                    .insert(matched_rule.rule_id.clone());
            }
        }

        principal_risks.push((principal_id.clone(), risk_score, assessment.matched_rules));
    }

    // Compute per-category max score
    let mut category_max: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
    for (category, scores) in &category_score_lists {
        if !scores.is_empty() {
            let max = scores.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            category_max.insert(category.clone(), max);
        }
    }

    let build_signal = |cat: &str| -> Option<CategorySignal> {
        category_max.get(cat).map(|&score| {
            let mut rule_ids: Vec<String> = category_rule_ids
                .get(cat)
                .map(|set| {
                    let mut v: Vec<String> = set.iter().cloned().collect();
                    v.sort();
                    v
                })
                .unwrap_or_default();
            rule_ids.sort();
            CategorySignal {
                score,
                matched_rule_ids: rule_ids,
            }
        })
    };

    let signals = AccountCategorySignals {
        cf_escalation: build_signal("cf_escalation"),
        oidc_drift: build_signal("oidc_drift"),
        s3_boundary: build_signal("s3_boundary"),
        kms_grant: build_signal("kms_grant"),
    };

    // Cascade score = harmonic mean of the 4 category sub-scores (zero for absent categories)
    let sub_scores = [
        category_max.get("cf_escalation").copied().unwrap_or(0.0),
        category_max.get("oidc_drift").copied().unwrap_or(0.0),
        category_max.get("s3_boundary").copied().unwrap_or(0.0),
        category_max.get("kms_grant").copied().unwrap_or(0.0),
    ];
    let cascade_risk_score = harmonic_mean(&sub_scores);

    // Sort by score descending and take top `limit`
    principal_risks.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let top_principals = principal_risks
        .into_iter()
        .take(limit)
        .map(
            |(principal_id, score, matched_rules)| PrincipalRiskSummary {
                principal_id,
                score,
                matched_rules,
            },
        )
        .collect();

    Ok(AccountRiskResult {
        account_id: account_id.to_string(),
        signals,
        cascade_risk_score,
        top_principals,
        computed_at: current_timestamp(),
    })
}

/// Categorize a rule by its ID prefix/content into one of the four signal buckets.
///
/// Returns an empty string when the rule ID does not map to any known category
/// (it will be ignored in the bucketing step).
pub fn categorize_rule(rule_id_or_category: &str) -> String {
    let lower = rule_id_or_category.to_lowercase();

    if lower.contains("cf-passrole")
        || lower.contains("lambda")
        || lower.contains("iam-update-trust")
        || lower.starts_with("iam-")
    {
        "cf_escalation".to_string()
    } else if lower.contains("drift") {
        "oidc_drift".to_string()
    } else if lower.contains("s3-org-id") || lower.starts_with("s3-") {
        "s3_boundary".to_string()
    } else if lower.contains("kms-grant") || lower.starts_with("kms-") {
        "kms_grant".to_string()
    } else {
        String::new()
    }
}

fn current_timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("{}Z", d.as_secs()))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::test_fixtures::MockGraphQueryService;

    // -------------------------------------------------------------------------
    // categorize_rule unit tests
    // -------------------------------------------------------------------------

    #[test]
    fn categorize_iam_prefix_is_cf_escalation() {
        assert_eq!(
            categorize_rule("iam-create-policy-version"),
            "cf_escalation"
        );
    }

    #[test]
    fn categorize_lambda_is_cf_escalation() {
        assert_eq!(categorize_rule("lambda-invoke-risk"), "cf_escalation");
    }

    #[test]
    fn categorize_cf_passrole_is_cf_escalation() {
        assert_eq!(categorize_rule("cf-passrole-to-admin"), "cf_escalation");
    }

    #[test]
    fn categorize_iam_update_trust_is_cf_escalation() {
        assert_eq!(categorize_rule("iam-update-trust-policy"), "cf_escalation");
    }

    #[test]
    fn categorize_drift_is_oidc_drift() {
        assert_eq!(categorize_rule("oidc-drift-detected"), "oidc_drift");
    }

    #[test]
    fn categorize_s3_prefix_is_s3_boundary() {
        assert_eq!(categorize_rule("s3-public-access"), "s3_boundary");
    }

    #[test]
    fn categorize_s3_org_id_is_s3_boundary() {
        assert_eq!(
            categorize_rule("s3-org-id-condition-missing"),
            "s3_boundary"
        );
    }

    #[test]
    fn categorize_kms_prefix_is_kms_grant() {
        assert_eq!(categorize_rule("kms-create-grant"), "kms_grant");
    }

    #[test]
    fn categorize_unknown_returns_empty() {
        assert_eq!(categorize_rule("ec2-describe-instances"), "");
        assert_eq!(categorize_rule("unknown-rule"), "");
    }

    // -------------------------------------------------------------------------
    // assess_account_risk service tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn empty_account_returns_zero_cascade() {
        let graph = MockGraphQueryService::new()
            .with_account_principals("123456789012".to_string(), vec![]);

        let config = RiskConfig::default();
        let result = assess_account_risk(&graph, &config, "123456789012", 10)
            .await
            .unwrap();

        assert_eq!(result.account_id, "123456789012");
        assert!(result.top_principals.is_empty());
        assert_eq!(result.cascade_risk_score, 0.0);
    }

    #[tokio::test]
    async fn unknown_account_returns_zero_cascade() {
        // No account registered — list_account_principals returns empty via ARN fallback
        let graph = MockGraphQueryService::new();
        let config = RiskConfig::default();
        let result = assess_account_risk(&graph, &config, "999999999999", 10)
            .await
            .unwrap();

        assert!(result.top_principals.is_empty());
        assert_eq!(result.cascade_risk_score, 0.0);
    }

    #[tokio::test]
    async fn principal_with_no_permissions_is_skipped() {
        let account_id = "111111111111";
        let principal_id = format!("arn:aws:iam::{}:user/empty-user", account_id);
        let graph = MockGraphQueryService::new()
            .with_account_principals(account_id.to_string(), vec![principal_id.clone()])
            .with_effective_permissions(principal_id, vec![]);

        let config = RiskConfig::default();
        let result = assess_account_risk(&graph, &config, account_id, 10)
            .await
            .unwrap();

        assert!(result.top_principals.is_empty());
    }

    #[tokio::test]
    async fn principal_with_iam_permissions_scores_positive() {
        let account_id = "222222222222";
        let principal_id = format!("arn:aws:iam::{}:user/risky-user", account_id);
        let graph = MockGraphQueryService::new()
            .with_account_principals(account_id.to_string(), vec![principal_id.clone()])
            .with_effective_permissions(
                principal_id.clone(),
                vec![
                    ("iam:CreatePolicyVersion".to_string(), "*".to_string()),
                    ("iam:AttachUserPolicy".to_string(), "*".to_string()),
                ],
            )
            .with_reachable(principal_id.clone(), 50)
            .with_shortest_path(principal_id.clone(), Some(2))
            .with_cross_account_hops(principal_id, 0);

        let config = RiskConfig::default();
        let result = assess_account_risk(&graph, &config, account_id, 10)
            .await
            .unwrap();

        assert_eq!(result.top_principals.len(), 1);
        assert!(result.top_principals[0].score > 0.0);
    }

    #[tokio::test]
    async fn limit_caps_top_principals() {
        let account_id = "333333333333";
        let principals: Vec<String> = (0..5)
            .map(|i| format!("arn:aws:iam::{}:user/user-{}", account_id, i))
            .collect();

        let mut graph_builder = MockGraphQueryService::new()
            .with_account_principals(account_id.to_string(), principals.clone());

        for p in &principals {
            graph_builder = graph_builder.with_effective_permissions(
                p.clone(),
                vec![("iam:CreatePolicyVersion".to_string(), "*".to_string())],
            );
        }

        let config = RiskConfig::default();
        let result = assess_account_risk(&graph_builder, &config, account_id, 3)
            .await
            .unwrap();

        assert!(result.top_principals.len() <= 3);
    }

    #[tokio::test]
    async fn top_principals_sorted_by_score_descending() {
        let account_id = "444444444444";
        let high_risk = format!("arn:aws:iam::{}:user/high-risk", account_id);
        let low_risk = format!("arn:aws:iam::{}:user/low-risk", account_id);

        let graph = MockGraphQueryService::new()
            .with_account_principals(
                account_id.to_string(),
                vec![high_risk.clone(), low_risk.clone()],
            )
            .with_effective_permissions(
                high_risk.clone(),
                vec![
                    ("iam:CreatePolicyVersion".to_string(), "*".to_string()),
                    ("iam:AttachUserPolicy".to_string(), "*".to_string()),
                    ("iam:PassRole".to_string(), "*".to_string()),
                ],
            )
            .with_reachable(high_risk.clone(), 200)
            .with_shortest_path(high_risk.clone(), Some(1))
            .with_cross_account_hops(high_risk, 3)
            .with_effective_permissions(
                low_risk.clone(),
                vec![(
                    "s3:GetObject".to_string(),
                    "arn:aws:s3:::bucket/*".to_string(),
                )],
            )
            .with_reachable(low_risk.clone(), 0)
            .with_shortest_path(low_risk.clone(), None)
            .with_cross_account_hops(low_risk, 0);

        let config = RiskConfig::default();
        let result = assess_account_risk(&graph, &config, account_id, 10)
            .await
            .unwrap();

        assert_eq!(result.top_principals.len(), 2);
        assert!(
            result.top_principals[0].score >= result.top_principals[1].score,
            "principals not sorted descending: {} vs {}",
            result.top_principals[0].score,
            result.top_principals[1].score
        );
    }

    // -------------------------------------------------------------------------
    // ARN-prefix fallback path — no explicit account mapping
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn arn_prefix_fallback_finds_principals() {
        let account_id = "555555555555";
        let principal_id = format!("arn:aws:iam::{}:user/fallback-user", account_id);

        // Add principal to the global list WITHOUT an explicit account mapping
        let graph = MockGraphQueryService::new()
            .with_principal_ids(vec![principal_id.clone()])
            .with_effective_permissions(
                principal_id,
                vec![("s3:GetObject".to_string(), "*".to_string())],
            );

        let config = RiskConfig::default();
        let result = assess_account_risk(&graph, &config, account_id, 10)
            .await
            .unwrap();

        // The service must find the principal via ARN-prefix fallback
        assert_eq!(result.top_principals.len(), 1);
    }
}
