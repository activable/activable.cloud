//! Resolver for account-level risk aggregation (cascade scoring across principals).

use crate::types::{
    GqlAccountRisks, GqlAccountSignalSummary, GqlPrincipalRisk, GqlSeverity, GqlSeverityValue,
};
use activable_graph::GraphClient;
use activable_risk::{
    harmonic_mean, load_rules_from_embedded, score_single_principal, EffectivePermission,
    RiskConfig,
};
use async_graphql::{ComplexObject, Context};

/// Get account-level risks by aggregating across all principals in the account.
///
/// 1. Enumerate all principals with ARN matching the account ID
/// 2. Score each principal (reusing principal-level logic)
/// 3. Bucket matched rules into categories (cf_escalation, oidc_drift, s3_boundary, kms_grant)
/// 4. Compute cascade risk score as harmonic mean of category sub-scores
/// 5. Return top N principals sorted by score
pub async fn account_risks(
    ctx: &Context<'_>,
    account_id: String,
) -> async_graphql::Result<GqlAccountRisks> {
    let graph = ctx
        .data::<GraphClient>()
        .map_err(|_| async_graphql::Error::new("GraphClient not available"))?;

    let config = ctx
        .data::<RiskConfig>()
        .map_err(|_| async_graphql::Error::new("RiskConfig not available"))?;

    let graph_service = ctx
        .data::<Box<dyn activable_risk::GraphQueryService>>()
        .map_err(|_| async_graphql::Error::new("GraphQueryService not available"))?;

    let limit = 10_usize; // Default to 10; caller can filter further if needed

    // Query principals in the account
    // First try: explicit HasPrincipal relationship
    let cypher = format!(
        r#"MATCH (a:Account {{id: '{account}'}})
           OPTIONAL MATCH (a)-[:HasPrincipal]->(p:Principal)
           RETURN DISTINCT p.id"#,
        account = activable_graph::query_builder::escape_cypher(&account_id)
    );

    let results = graph.cypher_multi_column(&cypher, 1).await.map_err(|e| {
        tracing::error!(account_id = %account_id, error = %e, "failed to query principals");
        async_graphql::Error::new("Failed to query principals")
    })?;

    let mut principal_ids: Vec<String> = results
        .iter()
        .filter_map(|row| row.first().and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect();

    // Fallback: if no explicit HasPrincipal edges, derive from ARN prefix
    if principal_ids.is_empty() {
        let cypher_fallback = format!(
            r#"MATCH (p:Principal)
               WHERE p.id STARTS WITH 'arn:aws:iam::{account}:'
               RETURN DISTINCT p.id"#,
            account = account_id
        );

        let fallback_results = graph
            .cypher_multi_column(&cypher_fallback, 1)
            .await
            .unwrap_or_default();

        principal_ids = fallback_results
            .iter()
            .filter_map(|row| row.first().and_then(|v| v.as_str()).map(|s| s.to_string()))
            .collect();
    }

    if principal_ids.is_empty() {
        return Err(async_graphql::Error::new(
            "Account not found or has no principals",
        ));
    }

    // Load rules once for all principals
    let rules =
        load_rules_from_embedded().expect("embedded rules must parse — fix YAML or report bug");

    // Score each principal and collect signals
    let mut principal_risks = vec![];
    let mut category_scores: std::collections::HashMap<String, Vec<f64>> =
        std::collections::HashMap::new();

    for principal_id in principal_ids {
        // Get effective permissions for this principal
        match graph_service.get_effective_permissions(&principal_id).await {
            Ok(perm_pairs) => {
                let effective_perms: Vec<EffectivePermission> = perm_pairs
                    .into_iter()
                    .map(|(action, resource)| EffectivePermission::new(action, resource))
                    .collect();

                if effective_perms.is_empty() {
                    tracing::debug!(principal_id = %principal_id, "principal has no permissions");
                    continue;
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| format!("{}Z", d.as_secs()))
                    .unwrap_or_else(|_| "unknown".to_string());

                match score_single_principal(
                    &principal_id,
                    &effective_perms,
                    &rules,
                    graph_service.as_ref(),
                    config,
                    &now,
                )
                .await
                {
                    Ok(assessment) => {
                        let risk_score = assessment.score;
                        let severity = GqlSeverity::from(assessment.severity);

                        // Bucket matched rules by category
                        for matched_rule in &assessment.matched_rules {
                            let category = categorize_rule(&matched_rule.rule_id);
                            if !category.is_empty() {
                                category_scores
                                    .entry(category)
                                    .or_default()
                                    .push(risk_score);
                            }
                        }

                        // Map matched_rules for the principal response
                        let matched_rules = assessment
                            .matched_rules
                            .iter()
                            .map(|mr| crate::types::GqlMatchedRule {
                                rule_id: mr.rule_id.clone(),
                                rule_name: mr.rule_name.clone(),
                                category: mr.category.clone(),
                                severity_tier: mr.severity_tier as i32,
                                boost: mr.boost,
                                matched_permissions: mr.matched_permissions.clone(),
                            })
                            .collect();

                        principal_risks.push((
                            principal_id.clone(),
                            risk_score,
                            severity,
                            matched_rules,
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(
                            principal_id = %principal_id,
                            error = %e,
                            "failed to score principal"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    principal_id = %principal_id,
                    error = %e,
                    "failed to get permissions"
                );
                // Continue with other principals on error
            }
        }
    }

    // Compute categorical max severity and scores
    let mut all_signals = GqlAccountSignalSummary {
        cf_escalation: None,
        oidc_drift: None,
        s3_boundary: None,
        kms_grant: None,
    };

    let mut category_max_scores = std::collections::HashMap::new();

    for (category, scores) in category_scores {
        if !scores.is_empty() {
            let max_score = scores.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            category_max_scores.insert(category, max_score);
        }
    }

    // Map category max scores to signal summary
    if let Some(&score) = category_max_scores.get("cf_escalation") {
        all_signals.cf_escalation = Some(GqlSeverityValue {
            severity: score_to_severity(score, config),
            score,
            matched_rule_ids: find_rule_ids_by_category(&principal_risks, "cf_escalation"),
        });
    }

    if let Some(&score) = category_max_scores.get("oidc_drift") {
        all_signals.oidc_drift = Some(GqlSeverityValue {
            severity: score_to_severity(score, config),
            score,
            matched_rule_ids: find_rule_ids_by_category(&principal_risks, "oidc_drift"),
        });
    }

    if let Some(&score) = category_max_scores.get("s3_boundary") {
        all_signals.s3_boundary = Some(GqlSeverityValue {
            severity: score_to_severity(score, config),
            score,
            matched_rule_ids: find_rule_ids_by_category(&principal_risks, "s3_boundary"),
        });
    }

    if let Some(&score) = category_max_scores.get("kms_grant") {
        all_signals.kms_grant = Some(GqlSeverityValue {
            severity: score_to_severity(score, config),
            score,
            matched_rule_ids: find_rule_ids_by_category(&principal_risks, "kms_grant"),
        });
    }

    // Compute cascade risk score as harmonic mean of the 4 category sub-scores
    let sub_scores = vec![
        category_max_scores
            .get("cf_escalation")
            .copied()
            .unwrap_or(0.0),
        category_max_scores
            .get("oidc_drift")
            .copied()
            .unwrap_or(0.0),
        category_max_scores
            .get("s3_boundary")
            .copied()
            .unwrap_or(0.0),
        category_max_scores.get("kms_grant").copied().unwrap_or(0.0),
    ];

    let cascade_risk_score = harmonic_mean(&sub_scores);
    let cascade_severity = score_to_severity(cascade_risk_score, config);

    // Sort principal risks by score descending and take top N
    principal_risks.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let top_principals: Vec<GqlPrincipalRisk> = principal_risks
        .into_iter()
        .take(limit)
        .map(
            |(principal_id, score, severity, matched_rules)| GqlPrincipalRisk {
                principal_id,
                score,
                severity,
                matched_rules,
            },
        )
        .collect();

    let computed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("{}Z", d.as_secs()))
        .unwrap_or_else(|_| "unknown".to_string());

    // Apply limit to top_principals before returning
    let limited_principals = top_principals;

    Ok(GqlAccountRisks {
        account_id,
        all_signals,
        cascade_risk_score,
        cascade_severity,
        computed_at,
        top_principals: limited_principals,
    })
}

/// ComplexObject implementation for GqlAccountRisks to support field-level arguments.
#[ComplexObject]
impl GqlAccountRisks {
    /// Fetch top principals with optional limit parameter.
    async fn top_principals(&self, #[graphql(default = 10)] limit: i32) -> Vec<GqlPrincipalRisk> {
        self.top_principals
            .iter()
            .take(limit as usize)
            .cloned()
            .collect()
    }
}

/// Categorize a rule by its ID or name.
/// Returns the canonical category name or empty string if unknown.
fn categorize_rule(rule_id_or_category: &str) -> String {
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

/// Find all rule IDs that match a given category across principal risks.
fn find_rule_ids_by_category(
    principal_risks: &[(String, f64, GqlSeverity, Vec<crate::types::GqlMatchedRule>)],
    target_category: &str,
) -> Vec<String> {
    let mut rule_ids = std::collections::HashSet::new();

    for (_, _, _, matched_rules) in principal_risks {
        for rule in matched_rules {
            if categorize_rule(&rule.rule_id) == target_category {
                rule_ids.insert(rule.rule_id.clone());
            }
        }
    }

    let mut sorted: Vec<String> = rule_ids.into_iter().collect();
    sorted.sort();
    sorted
}

/// Convert a risk score to a severity level using the configured thresholds.
fn score_to_severity(score: f64, config: &RiskConfig) -> GqlSeverity {
    if score >= config.severity.critical {
        GqlSeverity::Critical
    } else if score >= config.severity.high {
        GqlSeverity::High
    } else if score >= config.severity.medium {
        GqlSeverity::Medium
    } else if score >= config.severity.low {
        GqlSeverity::Low
    } else {
        GqlSeverity::Info
    }
}
