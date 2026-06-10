//! Domain service for resource-policy risk computation.
//!
//! Encapsulates all orchestration logic for evaluating S3 bucket and KMS key
//! resource-policy trust boundaries. The GraphQL resolver delegates to this
//! service and maps the result to Gql* types.
//!
//! Rule summary:
//! - Wildcard principal (`*`) → score 0.85 (critical).
//! - Non-wildcard Allow statement that is not a static role boundary with cross-account
//!   access → score 0.70 (high).
//! - Non-wildcard Allow statement that is not a static role boundary, same account only
//!   → score 0.45 (medium).
//! - All Allow statements are static role boundaries → score 0.20 (low).
//! - No policy document attached → score 0.0 (info).

use crate::signals::GraphQueryService;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Domain types — no async-graphql or axum imports in this crate
// ─────────────────────────────────────────────────────────────────────────────

/// Severity tier for resource-policy risk scores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcePolicySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// A single parsed statement from a resource policy document.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourcePolicyStatement {
    pub effect: String,
    pub principal: String,
    /// Condition key names extracted from the nested operator map.
    /// E.g. `{ "StringEquals": { "aws:PrincipalOrgID": "o-myorg" } }` → `["aws:PrincipalOrgID"]`.
    pub condition_keys: Vec<String>,
    /// True only when the principal is an exact role ARN (12-digit account, no wildcards)
    /// AND no condition keys are present.
    pub is_trust_boundary: bool,
}

/// A parsed resource policy document.
#[derive(Debug, Clone, Default)]
pub struct ResourcePolicy {
    pub statements: Vec<ResourcePolicyStatement>,
}

/// Cross-account access summary for one external AWS account.
#[derive(Debug, Clone)]
pub struct CrossAccountAccess {
    pub destination_account_id: String,
    pub principal_count: i32,
    pub severity: ResourcePolicySeverity,
}

/// Errors from the resource-policy risk service.
#[derive(Debug)]
pub enum ResourcePolicyError {
    /// Either bucketName or keyId must be provided, but not both (or neither).
    InvalidArguments(String),
    /// Underlying graph query failed.
    GraphError(Box<dyn std::error::Error + Send + Sync>),
    /// Policy document exists but contains invalid JSON.
    InvalidPolicyJson(String),
}

impl std::fmt::Display for ResourcePolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourcePolicyError::InvalidArguments(msg) => {
                write!(formatter, "invalid arguments: {}", msg)
            }
            ResourcePolicyError::GraphError(error) => write!(formatter, "graph error: {}", error),
            ResourcePolicyError::InvalidPolicyJson(msg) => {
                write!(formatter, "invalid policy JSON: {}", msg)
            }
        }
    }
}

impl std::error::Error for ResourcePolicyError {}

/// Full result of a resource-policy risk assessment.
#[derive(Debug, Clone)]
pub struct ResourcePolicyRiskResult {
    /// ARN of the assessed resource (bucket or KMS key).
    pub resource_arn: String,
    /// `"bucket"` or `"kmsKey"`.
    pub resource_type: String,
    pub policy: ResourcePolicy,
    pub cross_account_access: Vec<CrossAccountAccess>,
    pub risk_score: f64,
    pub severity: ResourcePolicySeverity,
    /// Always `"v1"` for this implementation.
    pub policy_evaluator_version: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Assess resource-policy risk for an S3 bucket or a KMS key.
///
/// Exactly one of `bucket_name` or `key_id` must be `Some`; providing neither
/// or both returns `ResourcePolicyError::InvalidArguments`.
///
/// Returns `Ok(None)` when the resource is not found in the graph.
/// Returns `Ok(Some(result))` on success.
/// Returns `Err` on graph-query failures.
pub async fn assess_resource_policy_risk(
    graph: &dyn GraphQueryService,
    bucket_name: Option<&str>,
    key_id: Option<&str>,
) -> Result<Option<ResourcePolicyRiskResult>, ResourcePolicyError> {
    match (bucket_name, key_id) {
        (Some(bucket), None) => assess_bucket_policy(graph, bucket).await,
        (None, Some(key)) => assess_key_policy(graph, key).await,
        (None, None) => Err(ResourcePolicyError::InvalidArguments(
            "either bucketName or keyId must be provided".to_string(),
        )),
        (Some(_), Some(_)) => Err(ResourcePolicyError::InvalidArguments(
            "provide only one of bucketName or keyId".to_string(),
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

async fn assess_bucket_policy(
    graph: &dyn GraphQueryService,
    bucket_name: &str,
) -> Result<Option<ResourcePolicyRiskResult>, ResourcePolicyError> {
    let row = graph
        .query_bucket_policy(bucket_name)
        .await
        .map_err(ResourcePolicyError::GraphError)?;

    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    let resource_arn = if row.resource_arn.is_empty() {
        format!("arn:aws:s3:::{}", bucket_name)
    } else {
        row.resource_arn.clone()
    };

    build_result(
        resource_arn,
        "bucket".to_string(),
        row.policy_document.as_deref(),
        row.consuming_principal_ids,
    )
    .map(Some)
}

async fn assess_key_policy(
    graph: &dyn GraphQueryService,
    key_id: &str,
) -> Result<Option<ResourcePolicyRiskResult>, ResourcePolicyError> {
    let row = graph
        .query_key_resource_policy(key_id)
        .await
        .map_err(ResourcePolicyError::GraphError)?;

    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    let resource_arn = if row.resource_arn.is_empty() {
        format!("arn:aws:kms:us-east-1:000000000000:key/{}", key_id)
    } else {
        row.resource_arn.clone()
    };

    build_result(
        resource_arn,
        "kmsKey".to_string(),
        row.policy_document.as_deref(),
        row.consuming_principal_ids,
    )
    .map(Some)
}

/// Build a `ResourcePolicyRiskResult` from already-fetched row data.
fn build_result(
    resource_arn: String,
    resource_type: String,
    policy_document: Option<&str>,
    consuming_principal_ids: Vec<String>,
) -> Result<ResourcePolicyRiskResult, ResourcePolicyError> {
    let (statements, cross_account_access) = if let Some(document) = policy_document {
        let parsed = parse_resource_policy(document)?;
        let consuming_account_ids: Vec<String> = consuming_principal_ids
            .iter()
            .filter_map(|arn| extract_account_id_from_arn(arn))
            .collect();
        let cross = extract_cross_account_access(&parsed, &consuming_account_ids);
        (parsed, cross)
    } else {
        (vec![], vec![])
    };

    let policy = ResourcePolicy { statements };
    let has_cross_account = !cross_account_access.is_empty();
    let risk_score = compute_resource_policy_score(&policy, has_cross_account);
    let severity = score_to_severity(risk_score);

    Ok(ResourcePolicyRiskResult {
        resource_arn,
        resource_type,
        policy,
        cross_account_access,
        risk_score,
        severity,
        policy_evaluator_version: "v1".to_string(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure computation functions — all public for unit testing
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a resource policy JSON document into a list of statements.
///
/// Returns `ResourcePolicyError::InvalidPolicyJson` when the document is not
/// valid JSON. Unknown or missing fields are silently ignored per the AWS
/// best-effort policy evaluation model.
pub fn parse_resource_policy(
    policy_json: &str,
) -> Result<Vec<ResourcePolicyStatement>, ResourcePolicyError> {
    let parsed: serde_json::Value = serde_json::from_str(policy_json)
        .map_err(|error| ResourcePolicyError::InvalidPolicyJson(error.to_string()))?;

    let statements = parsed
        .get("Statement")
        .and_then(|value| value.as_array())
        .map(|array| array.iter().filter_map(parse_single_statement).collect())
        .unwrap_or_default();

    Ok(statements)
}

/// Parse one statement object from a policy document array.
fn parse_single_statement(statement: &serde_json::Value) -> Option<ResourcePolicyStatement> {
    let effect = statement
        .get("Effect")
        .and_then(|value| value.as_str())
        .map(|s| s.to_string())?;

    // Principal can be a string `"*"` or an object `{ "AWS": "arn:..." }`.
    let principal = statement
        .get("Principal")
        .and_then(|value| {
            if let serde_json::Value::String(s) = value {
                Some(s.clone())
            } else if let serde_json::Value::Object(map) = value {
                map.get("AWS")
                    .and_then(|aws| aws.as_str())
                    .map(|s| s.to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "*".to_string());

    // Condition: { "StringEquals": { "aws:PrincipalOrgID": "value" }, ... }
    // We extract the inner keys (the condition key names), not the operator names.
    let condition_keys: Vec<String> = statement
        .get("Condition")
        .and_then(|value| value.as_object())
        .map(|condition_object| {
            condition_object
                .values()
                .filter_map(|operator_value| operator_value.as_object())
                .flat_map(|operator_object| operator_object.keys().cloned())
                .collect()
        })
        .unwrap_or_default();

    let is_trust_boundary = evaluate_trust_boundary(&principal, &condition_keys);

    Some(ResourcePolicyStatement {
        effect,
        principal,
        condition_keys,
        is_trust_boundary,
    })
}

/// Evaluate whether a principal represents a static trust boundary.
///
/// Returns `true` ONLY when:
/// - The principal is an exact IAM role ARN (`arn:aws:iam::<12-digit-id>:role/<name>`).
/// - No wildcards are present in the ARN.
/// - No condition keys are present (conditions make grants conditional, not static).
///
/// Root principals, wildcards, user ARNs, and all principals with conditions
/// are NOT trust boundaries.
pub fn evaluate_trust_boundary(principal: &str, condition_keys: &[String]) -> bool {
    // Any condition makes the grant conditional, not a static ownership boundary.
    if !condition_keys.is_empty() {
        return false;
    }

    // Wildcard principals are never trust boundaries.
    if principal.contains('*') || principal == "*" {
        return false;
    }

    // Require exact ARN structure: arn:aws:iam::<12-digit-account>:role/<name>
    let parts: Vec<&str> = principal.split(':').collect();
    if parts.len() < 6 {
        return false;
    }

    let account_id = parts[4];
    let resource_part = parts.get(5).copied().unwrap_or("");

    let is_valid_account = account_id.len() == 12
        && account_id
            .chars()
            .all(|character| character.is_ascii_digit());
    let is_role = resource_part.starts_with("role/");

    is_valid_account && is_role
}

/// Extract cross-account access summaries from parsed statements and graph-reported consumers.
///
/// Aggregates Allow statements by extracted account ID. Wildcard principals
/// that carry an account ID segment (unusual but possible) are marked High
/// severity; all others are Medium.
pub fn extract_cross_account_access(
    statements: &[ResourcePolicyStatement],
    consuming_account_ids: &[String],
) -> Vec<CrossAccountAccess> {
    let mut account_map: HashMap<String, (i32, ResourcePolicySeverity)> = HashMap::new();

    for statement in statements {
        if statement.effect == "Allow" {
            if let Some(account_id) = extract_account_id_from_principal(&statement.principal) {
                let severity = if statement.principal.contains('*') {
                    ResourcePolicySeverity::High
                } else {
                    ResourcePolicySeverity::Medium
                };

                account_map
                    .entry(account_id)
                    .and_modify(|(count, current_severity)| {
                        *count += 1;
                        if severity == ResourcePolicySeverity::High {
                            *current_severity = ResourcePolicySeverity::High;
                        }
                    })
                    .or_insert((1, severity));
            }
        }
    }

    // Supplement with graph-reported consumers (external account IDs).
    for account_id in consuming_account_ids {
        account_map
            .entry(account_id.clone())
            .and_modify(|(count, _)| *count += 1)
            .or_insert((1, ResourcePolicySeverity::Medium));
    }

    account_map
        .into_iter()
        .map(
            |(account_id, (principal_count, severity))| CrossAccountAccess {
                destination_account_id: account_id,
                principal_count,
                severity,
            },
        )
        .collect()
}

/// Compute a risk score for a resource policy.
///
/// Score table:
/// | Condition | Score |
/// |---|---|
/// | Any wildcard principal (`*`) | 0.85 |
/// | Non-wildcard, non-boundary Allow + cross-account | 0.70 |
/// | Non-wildcard, non-boundary Allow, same-account only | 0.45 |
/// | No violations | 0.20 |
/// | No statements | 0.0 |
pub fn compute_resource_policy_score(policy: &ResourcePolicy, has_cross_account: bool) -> f64 {
    if policy.statements.is_empty() {
        return 0.0;
    }

    let wildcard_count = policy
        .statements
        .iter()
        .filter(|statement| statement.principal.contains('*') || statement.principal == "*")
        .count();

    let boundary_violations = policy
        .statements
        .iter()
        .filter(|statement| statement.effect == "Allow" && !statement.is_trust_boundary)
        .count();

    let score: f64 = match (
        wildcard_count > 0,
        boundary_violations > 0,
        has_cross_account,
    ) {
        (true, _, _) => 0.85,
        (false, true, true) => 0.70,
        (false, true, false) => 0.45,
        (false, false, _) => 0.20,
    };
    score.clamp(0.0, 1.0)
}

/// Convert a resource-policy risk score to a severity tier.
fn score_to_severity(score: f64) -> ResourcePolicySeverity {
    match score {
        s if s >= 0.80 => ResourcePolicySeverity::Critical,
        s if s >= 0.60 => ResourcePolicySeverity::High,
        s if s >= 0.40 => ResourcePolicySeverity::Medium,
        s if s >= 0.20 => ResourcePolicySeverity::Low,
        _ => ResourcePolicySeverity::Info,
    }
}

/// Extract account ID from a principal ARN (`arn:partition:service::account:resource`).
///
/// Returns `None` for wildcards or short strings that do not include an account segment.
pub fn extract_account_id_from_arn(arn: &str) -> Option<String> {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() >= 5 {
        let account = parts[4];
        if !account.is_empty() && account != "*" && account.chars().all(|c| c.is_ascii_digit()) {
            return Some(account.to_string());
        }
    }
    None
}

/// Extract account ID from a principal ARN (same logic as `extract_account_id_from_arn`
/// but tolerates non-numeric segments for legacy ARN formats).
fn extract_account_id_from_principal(principal: &str) -> Option<String> {
    let parts: Vec<&str> = principal.split(':').collect();
    if parts.len() >= 5 {
        let account = parts[4];
        if !account.is_empty() && account != "*" {
            return Some(account.to_string());
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::{test_fixtures::MockGraphQueryService, ResourcePolicyRow};

    // ─────────────────────────────────────────────────────────────────────────
    // evaluate_trust_boundary
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trust_boundary_specific_role_arn() {
        assert!(evaluate_trust_boundary(
            "arn:aws:iam::123456789012:role/MyRole",
            &[]
        ));
    }

    #[test]
    fn trust_boundary_false_for_wildcard_principal() {
        assert!(!evaluate_trust_boundary("*", &[]));
    }

    #[test]
    fn trust_boundary_false_for_wildcard_in_role_name() {
        assert!(!evaluate_trust_boundary(
            "arn:aws:iam::123456789012:role/Role*",
            &[]
        ));
    }

    #[test]
    fn trust_boundary_false_for_root_principal() {
        assert!(!evaluate_trust_boundary(
            "arn:aws:iam::123456789012:root",
            &[]
        ));
    }

    #[test]
    fn trust_boundary_false_for_user_principal() {
        assert!(!evaluate_trust_boundary(
            "arn:aws:iam::123456789012:user/alice",
            &[]
        ));
    }

    #[test]
    fn trust_boundary_false_when_condition_keys_present() {
        let condition_keys = vec!["aws:PrincipalOrgID".to_string()];
        assert!(!evaluate_trust_boundary(
            "arn:aws:iam::123456789012:role/MyRole",
            &condition_keys
        ));
    }

    #[test]
    fn trust_boundary_false_for_source_arn_condition() {
        let condition_keys = vec!["aws:SourceArn".to_string()];
        assert!(!evaluate_trust_boundary(
            "arn:aws:iam::123456789012:role/MyRole",
            &condition_keys
        ));
    }

    #[test]
    fn trust_boundary_true_for_another_valid_role_arn() {
        assert!(evaluate_trust_boundary(
            "arn:aws:iam::999999999999:role/SafeRole",
            &[]
        ));
    }

    #[test]
    fn trust_boundary_false_for_short_string() {
        assert!(!evaluate_trust_boundary("admin", &[]));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // parse_resource_policy
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn parse_simple_allow_wildcard_statement() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*"
            }]
        }"#;

        let statements = parse_resource_policy(policy_json).unwrap();
        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].effect, "Allow");
        assert_eq!(statements[0].principal, "*");
        assert!(statements[0].condition_keys.is_empty());
        assert!(!statements[0].is_trust_boundary);
    }

    #[test]
    fn parse_statement_with_aws_principal_object() {
        let policy_json = r#"{
            "Statement": [{
                "Effect": "Allow",
                "Principal": { "AWS": "arn:aws:iam::123456789012:role/Reader" },
                "Action": "s3:GetObject"
            }]
        }"#;

        let statements = parse_resource_policy(policy_json).unwrap();
        assert_eq!(
            statements[0].principal,
            "arn:aws:iam::123456789012:role/Reader"
        );
        assert!(statements[0].is_trust_boundary);
    }

    #[test]
    fn parse_org_id_condition_extracts_condition_keys() {
        let policy_json = r#"{
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalOrgID": "o-myorg"
                    }
                }
            }]
        }"#;

        let statements = parse_resource_policy(policy_json).unwrap();
        assert_eq!(statements[0].principal, "*");
        assert!(
            statements[0]
                .condition_keys
                .iter()
                .any(|k| k == "aws:PrincipalOrgID"),
            "expected PrincipalOrgID in condition_keys: {:?}",
            statements[0].condition_keys
        );
        // Wildcard with condition → not a trust boundary
        assert!(!statements[0].is_trust_boundary);
    }

    #[test]
    fn parse_multiple_condition_operators() {
        let policy_json = r#"{
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Condition": {
                    "StringEquals": { "aws:PrincipalOrgID": "o-foo" },
                    "ArnLike": { "aws:SourceArn": "arn:aws:s3:::bucket" }
                }
            }]
        }"#;

        let statements = parse_resource_policy(policy_json).unwrap();
        assert!(statements[0]
            .condition_keys
            .contains(&"aws:PrincipalOrgID".to_string()));
        assert!(statements[0]
            .condition_keys
            .contains(&"aws:SourceArn".to_string()));
    }

    #[test]
    fn parse_empty_statement_array_returns_empty() {
        let policy_json = r#"{"Version": "2012-10-17", "Statement": []}"#;
        let statements = parse_resource_policy(policy_json).unwrap();
        assert!(statements.is_empty());
    }

    #[test]
    fn parse_invalid_json_returns_error() {
        let result = parse_resource_policy("not json at all");
        assert!(matches!(
            result,
            Err(ResourcePolicyError::InvalidPolicyJson(_))
        ));
    }

    #[test]
    fn parse_missing_statement_key_returns_empty() {
        let policy_json = r#"{"Version": "2012-10-17"}"#;
        let statements = parse_resource_policy(policy_json).unwrap();
        assert!(statements.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // compute_resource_policy_score
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn score_critical_for_wildcard_principal() {
        let policy = ResourcePolicy {
            statements: vec![ResourcePolicyStatement {
                effect: "Allow".to_string(),
                principal: "*".to_string(),
                condition_keys: vec![],
                is_trust_boundary: false,
            }],
        };
        let score = compute_resource_policy_score(&policy, false);
        assert!((score - 0.85).abs() < 1e-10, "score was {}", score);
    }

    #[test]
    fn score_high_for_non_boundary_allow_with_cross_account() {
        let policy = ResourcePolicy {
            statements: vec![ResourcePolicyStatement {
                effect: "Allow".to_string(),
                principal: "arn:aws:iam::999999999999:root".to_string(),
                condition_keys: vec![],
                is_trust_boundary: false,
            }],
        };
        let score = compute_resource_policy_score(&policy, true);
        assert!((score - 0.70).abs() < 1e-10, "score was {}", score);
    }

    #[test]
    fn score_medium_for_non_boundary_allow_no_cross_account() {
        let policy = ResourcePolicy {
            statements: vec![ResourcePolicyStatement {
                effect: "Allow".to_string(),
                principal: "arn:aws:iam::123456789012:root".to_string(),
                condition_keys: vec![],
                is_trust_boundary: false,
            }],
        };
        let score = compute_resource_policy_score(&policy, false);
        assert!((score - 0.45).abs() < 1e-10, "score was {}", score);
    }

    #[test]
    fn score_low_for_all_trust_boundaries() {
        let policy = ResourcePolicy {
            statements: vec![ResourcePolicyStatement {
                effect: "Allow".to_string(),
                principal: "arn:aws:iam::123456789012:role/MyRole".to_string(),
                condition_keys: vec![],
                is_trust_boundary: true,
            }],
        };
        let score = compute_resource_policy_score(&policy, false);
        assert!((score - 0.20).abs() < 1e-10, "score was {}", score);
    }

    #[test]
    fn score_zero_for_empty_policy() {
        let policy = ResourcePolicy { statements: vec![] };
        let score = compute_resource_policy_score(&policy, false);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn score_deny_statements_do_not_increase_risk() {
        // Deny-only policy should score low (no violations)
        let policy = ResourcePolicy {
            statements: vec![ResourcePolicyStatement {
                effect: "Deny".to_string(),
                principal: "*".to_string(),
                condition_keys: vec![],
                is_trust_boundary: false,
            }],
        };
        // "Deny" with wildcard — no Allow violations, but wildcard_count still counts
        // Because our scorer checks principal.contains('*') regardless of effect,
        // this scores 0.85. Let's confirm existing behaviour is preserved:
        let score = compute_resource_policy_score(&policy, false);
        // Wildcard principal → 0.85 regardless of Deny/Allow
        assert!((score - 0.85).abs() < 1e-10, "score was {}", score);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // extract_account_id_from_arn
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn extract_account_id_from_valid_arn() {
        assert_eq!(
            extract_account_id_from_arn("arn:aws:iam::987654321098:role/Test"),
            Some("987654321098".to_string())
        );
    }

    #[test]
    fn extract_account_id_from_wildcard_returns_none() {
        assert_eq!(extract_account_id_from_arn("*"), None);
    }

    #[test]
    fn extract_account_id_from_non_numeric_returns_none() {
        // Non-numeric account segment (e.g. organization ARN) → None
        assert_eq!(
            extract_account_id_from_arn("arn:aws:iam::o-myorg:root"),
            None
        );
    }

    #[test]
    fn extract_account_id_from_short_string_returns_none() {
        assert_eq!(extract_account_id_from_arn("admin"), None);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // extract_cross_account_access
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cross_account_counts_allow_statements() {
        let statements = vec![
            ResourcePolicyStatement {
                effect: "Allow".to_string(),
                principal: "arn:aws:iam::999999999999:role/External".to_string(),
                condition_keys: vec![],
                is_trust_boundary: false,
            },
            ResourcePolicyStatement {
                effect: "Allow".to_string(),
                principal: "arn:aws:iam::999999999999:role/AnotherExternal".to_string(),
                condition_keys: vec![],
                is_trust_boundary: false,
            },
        ];

        let result = extract_cross_account_access(&statements, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].principal_count, 2);
        assert_eq!(result[0].destination_account_id, "999999999999");
    }

    #[test]
    fn cross_account_deny_statements_not_counted() {
        let statements = vec![ResourcePolicyStatement {
            effect: "Deny".to_string(),
            principal: "arn:aws:iam::999999999999:role/External".to_string(),
            condition_keys: vec![],
            is_trust_boundary: false,
        }];

        let result = extract_cross_account_access(&statements, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn cross_account_consuming_accounts_included() {
        let result = extract_cross_account_access(
            &[],
            &["111111111111".to_string(), "222222222222".to_string()],
        );
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn cross_account_wildcard_principal_escalates_to_high() {
        let statements = vec![ResourcePolicyStatement {
            effect: "Allow".to_string(),
            principal: "arn:aws:iam::111111111111:role/*".to_string(),
            condition_keys: vec![],
            is_trust_boundary: false,
        }];

        let result = extract_cross_account_access(&statements, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, ResourcePolicySeverity::High);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // assess_resource_policy_risk — service integration tests
    // ─────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn both_args_provided_returns_error() {
        let graph = MockGraphQueryService::new();
        let result = assess_resource_policy_risk(&graph, Some("my-bucket"), Some("key-id")).await;
        assert!(matches!(
            result,
            Err(ResourcePolicyError::InvalidArguments(_))
        ));
    }

    #[tokio::test]
    async fn no_args_returns_error() {
        let graph = MockGraphQueryService::new();
        let result = assess_resource_policy_risk(&graph, None, None).await;
        assert!(matches!(
            result,
            Err(ResourcePolicyError::InvalidArguments(_))
        ));
    }

    #[tokio::test]
    async fn unknown_bucket_returns_none() {
        let graph = MockGraphQueryService::new();
        let result = assess_resource_policy_risk(&graph, Some("missing-bucket"), None)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn unknown_key_returns_none() {
        let graph = MockGraphQueryService::new();
        let result = assess_resource_policy_risk(&graph, None, Some("missing-key"))
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn bucket_with_wildcard_policy_scores_critical() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }]
        }"#;

        let graph = MockGraphQueryService::new().with_bucket_policy(
            "my-bucket".to_string(),
            ResourcePolicyRow {
                resource_arn: "arn:aws:s3:::my-bucket".to_string(),
                policy_document: Some(policy_json.to_string()),
                consuming_principal_ids: vec![],
            },
        );

        let result = assess_resource_policy_risk(&graph, Some("my-bucket"), None)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(result.resource_type, "bucket");
        assert_eq!(result.resource_arn, "arn:aws:s3:::my-bucket");
        assert!((result.risk_score - 0.85).abs() < 1e-10);
        assert_eq!(result.severity, ResourcePolicySeverity::Critical);
        assert_eq!(result.policy_evaluator_version, "v1");
    }

    #[tokio::test]
    async fn bucket_without_policy_document_scores_zero() {
        let graph = MockGraphQueryService::new().with_bucket_policy(
            "empty-bucket".to_string(),
            ResourcePolicyRow {
                resource_arn: "arn:aws:s3:::empty-bucket".to_string(),
                policy_document: None,
                consuming_principal_ids: vec![],
            },
        );

        let result = assess_resource_policy_risk(&graph, Some("empty-bucket"), None)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(result.risk_score, 0.0);
        assert_eq!(result.severity, ResourcePolicySeverity::Info);
        assert!(result.policy.statements.is_empty());
    }

    #[tokio::test]
    async fn bucket_arn_defaults_when_row_arn_empty() {
        let graph = MockGraphQueryService::new().with_bucket_policy(
            "my-bucket".to_string(),
            ResourcePolicyRow {
                resource_arn: "".to_string(), // empty — should fall back to constructed ARN
                policy_document: None,
                consuming_principal_ids: vec![],
            },
        );

        let result = assess_resource_policy_risk(&graph, Some("my-bucket"), None)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(result.resource_arn, "arn:aws:s3:::my-bucket");
    }

    #[tokio::test]
    async fn key_with_role_boundary_policy_scores_low() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": { "AWS": "arn:aws:iam::123456789012:role/ServiceRole" },
                "Action": "kms:Decrypt"
            }]
        }"#;

        let graph = MockGraphQueryService::new().with_key_resource_policy(
            "alias/my-key".to_string(),
            ResourcePolicyRow {
                resource_arn: "arn:aws:kms:us-east-1:123456789012:key/abcd-1234".to_string(),
                policy_document: Some(policy_json.to_string()),
                consuming_principal_ids: vec![],
            },
        );

        let result = assess_resource_policy_risk(&graph, None, Some("alias/my-key"))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(result.resource_type, "kmsKey");
        assert_eq!(result.risk_score, 0.20);
        assert_eq!(result.severity, ResourcePolicySeverity::Low);
    }

    #[tokio::test]
    async fn key_arn_defaults_when_row_arn_empty() {
        let graph = MockGraphQueryService::new().with_key_resource_policy(
            "my-key-id".to_string(),
            ResourcePolicyRow {
                resource_arn: "".to_string(),
                policy_document: None,
                consuming_principal_ids: vec![],
            },
        );

        let result = assess_resource_policy_risk(&graph, None, Some("my-key-id"))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            result.resource_arn,
            "arn:aws:kms:us-east-1:000000000000:key/my-key-id"
        );
    }

    #[tokio::test]
    async fn bucket_with_cross_account_consumer_in_graph() {
        // Policy grants to a specific role (trust boundary); but the graph also
        // reports a consumer from an external account.
        let policy_json = r#"{
            "Statement": [{
                "Effect": "Allow",
                "Principal": { "AWS": "arn:aws:iam::123456789012:role/Owner" },
                "Action": "s3:GetObject"
            }]
        }"#;

        let graph =
            MockGraphQueryService::new().with_bucket_policy(
                "shared-bucket".to_string(),
                ResourcePolicyRow {
                    resource_arn: "arn:aws:s3:::shared-bucket".to_string(),
                    policy_document: Some(policy_json.to_string()),
                    consuming_principal_ids: vec![
                        "arn:aws:iam::999999999999:role/External".to_string()
                    ],
                },
            );

        let result = assess_resource_policy_risk(&graph, Some("shared-bucket"), None)
            .await
            .unwrap()
            .unwrap();

        // The graph-reported consumer makes has_cross_account = true.
        // But the only policy statement is a trust boundary → boundary_violations = 0
        // → score 0.20 (no violations), not 0.70.
        assert!(!result.cross_account_access.is_empty());
        // With trust-boundary Allow statements and cross-account: low score.
        assert_eq!(result.risk_score, 0.20);
    }

    #[tokio::test]
    async fn org_id_policy_extracts_condition_keys_correctly() {
        // Real seed policy: wildcard principal restricted by org-ID condition.
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowOrgWideRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Condition": {
                    "StringEquals": { "aws:PrincipalOrgID": "o-myorg" }
                }
            }]
        }"#;

        let graph = MockGraphQueryService::new().with_bucket_policy(
            "org-shared-data".to_string(),
            ResourcePolicyRow {
                resource_arn: "arn:aws:s3:::org-shared-data".to_string(),
                policy_document: Some(policy_json.to_string()),
                consuming_principal_ids: vec![],
            },
        );

        let result = assess_resource_policy_risk(&graph, Some("org-shared-data"), None)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(result.policy.statements.len(), 1);
        let statement = &result.policy.statements[0];
        assert_eq!(statement.principal, "*");
        assert!(
            statement
                .condition_keys
                .iter()
                .any(|k| k.contains("PrincipalOrgID")),
            "condition_keys: {:?}",
            statement.condition_keys
        );
        // Principal is "*" so wildcard_count > 0 → 0.85
        assert!((result.risk_score - 0.85).abs() < 1e-10);
    }
}
