//! Domain service for KMS key management risk computation.
//!
//! Evaluates the risk of kms:CreateGrant exposure for a KMS key. The GraphQL
//! resolver delegates to this service and maps the result to Gql* types.

use crate::signals::GraphQueryService;

/// Result of the KMS key risk assessment.
#[derive(Debug, Clone)]
pub struct KeyManagementRiskResult {
    pub key_arn: String,
    pub key_policy: KeyPolicy,
    pub create_grant_risk: CreateGrantRisk,
    pub risk_score: f64,
    pub severity: KeyRiskSeverity,
}

/// Severity for key management risk — mirrors the thresholds used in the API layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRiskSeverity {
    High,
    Medium,
    Low,
}

/// Parsed key policy structure.
#[derive(Debug, Clone)]
pub struct KeyPolicy {
    pub statements: Vec<KeyPolicyStatement>,
    pub policy_arn: Option<String>,
}

/// A single statement from a key policy document.
#[derive(Debug, Clone)]
pub struct KeyPolicyStatement {
    pub effect: String,
    pub principals: Vec<String>,
    pub actions: Vec<String>,
    pub condition_keys: Vec<String>,
}

/// Risk assessment for the kms:CreateGrant capability.
#[derive(Debug, Clone)]
pub struct CreateGrantRisk {
    /// Whether any principal has the KmsGrantable capability on this key.
    pub grantable: bool,
    /// All principal IDs that can grant access.
    pub granting_principals: Vec<String>,
    pub severity: KeyRiskSeverity,
    /// Whether any granting principal uses a wildcard (`*`).
    pub wildcard_principal: bool,
}

/// Error returned when a key cannot be found or the key ID format is invalid.
#[derive(Debug)]
pub enum KeyRiskError {
    InvalidKeyId(String),
    KeyNotFound(String),
    GraphError(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for KeyRiskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyRiskError::InvalidKeyId(msg) => write!(f, "Invalid key ID: {}", msg),
            KeyRiskError::KeyNotFound(key_id) => write!(f, "KMS key not found: {}", key_id),
            KeyRiskError::GraphError(e) => write!(f, "Graph query error: {}", e),
        }
    }
}

impl std::error::Error for KeyRiskError {}

/// Assess KMS key management risk for a given key identifier.
///
/// Accepts both full ARN (`arn:aws:kms:region:account:key/uuid`) and bare UUID.
/// Looks up the key via the graph port, parses the key policy, evaluates grant
/// risk, and returns a structured result.
///
/// Returns `Err(KeyRiskError::KeyNotFound)` when the key is absent from the graph.
/// Returns `Err(KeyRiskError::InvalidKeyId)` when the ARN format is malformed.
pub async fn assess_key_management_risk(
    graph: &dyn GraphQueryService,
    key_id: &str,
) -> Result<KeyManagementRiskResult, KeyRiskError> {
    let (key_arn, key_uuid) = normalize_key_id(key_id)?;

    let row = graph
        .query_kms_key(&key_arn, &key_uuid)
        .await
        .map_err(KeyRiskError::GraphError)?
        .ok_or_else(|| KeyRiskError::KeyNotFound(key_id.to_string()))?;

    let key_policy = if let Some(ref doc) = row.policy_document {
        parse_key_policy(doc).unwrap_or(KeyPolicy {
            statements: vec![],
            policy_arn: None,
        })
    } else {
        KeyPolicy {
            statements: vec![],
            policy_arn: None,
        }
    };

    let grantable = !row.grantable_principal_ids.is_empty();
    let wildcard_principal = row
        .grantable_principal_ids
        .iter()
        .any(|p| p.contains('*') || p == "*");

    let key_account = extract_account_from_key_arn(&row.key_arn);
    let has_cross_account_grant = grantable
        && row.grantable_principal_ids.iter().any(|p| {
            extract_account_id_from_arn(p)
                .map(|acct| acct != key_account)
                .unwrap_or(false)
        });

    let severity = compute_grant_severity(grantable, wildcard_principal, has_cross_account_grant);
    let risk_score = compute_key_risk_score(grantable, wildcard_principal, has_cross_account_grant);

    let create_grant_risk = CreateGrantRisk {
        grantable,
        granting_principals: row.grantable_principal_ids,
        severity,
        wildcard_principal,
    };

    Ok(KeyManagementRiskResult {
        key_arn: row.key_arn,
        key_policy,
        create_grant_risk,
        risk_score,
        severity,
    })
}

/// Normalize a key identifier into (full_arn, bare_uuid).
///
/// For full ARN (`arn:aws:kms:region:account:key/uuid`) extracts the UUID as
/// the last path segment after `/`. For a bare UUID constructs a placeholder
/// ARN so both forms can be matched in the graph.
pub fn normalize_key_id(key_id: &str) -> Result<(String, String), KeyRiskError> {
    if key_id.starts_with("arn:aws:kms:") {
        let uuid = key_id
            .rsplit('/')
            .next()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                KeyRiskError::InvalidKeyId(
                    "Invalid KMS key ARN: missing UUID after '/'".to_string(),
                )
            })?;
        Ok((key_id.to_string(), uuid))
    } else {
        // Bare UUID — build a placeholder ARN for graph matching
        let arn = format!("arn:aws:kms:us-east-1:000000000000:key/{}", key_id);
        Ok((arn, key_id.to_string()))
    }
}

/// Parse a JSON key policy document into a structured `KeyPolicy`.
///
/// Returns `None` on JSON parse failure (caller falls back to an empty policy).
pub fn parse_key_policy(policy_json: &str) -> Option<KeyPolicy> {
    let parsed: serde_json::Value = serde_json::from_str(policy_json).ok()?;

    let statements = parsed
        .get("Statement")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_key_policy_statement).collect())
        .unwrap_or_default();

    Some(KeyPolicy {
        statements,
        policy_arn: parsed
            .get("PolicyArn")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

/// Parse a single policy statement into a `KeyPolicyStatement`.
pub fn parse_key_policy_statement(stmt: &serde_json::Value) -> Option<KeyPolicyStatement> {
    let effect = stmt
        .get("Effect")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())?;

    let principals = stmt
        .get("Principal")
        .and_then(|v| match v {
            serde_json::Value::String(s) => Some(vec![s.clone()]),
            serde_json::Value::Array(arr) => Some(
                arr.iter()
                    .filter_map(|p| p.as_str().map(|s| s.to_string()))
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default();

    let actions = stmt
        .get("Action")
        .and_then(|v| match v {
            serde_json::Value::String(s) => Some(vec![s.clone()]),
            serde_json::Value::Array(arr) => Some(
                arr.iter()
                    .filter_map(|a| a.as_str().map(|s| s.to_string()))
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default();

    let condition_keys: Vec<String> = stmt
        .get("Condition")
        .and_then(|v| v.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();

    Some(KeyPolicyStatement {
        effect,
        principals,
        actions,
        condition_keys,
    })
}

/// Compute grant severity.
///
/// - Not grantable → Low (no delegation risk)
/// - Wildcard or cross-account → High (anyone / external account can escalate)
/// - Same-account grantable only → Medium (restricted but delegates key access)
pub fn compute_grant_severity(
    grantable: bool,
    wildcard: bool,
    cross_account: bool,
) -> KeyRiskSeverity {
    if !grantable {
        KeyRiskSeverity::Low
    } else if wildcard || cross_account {
        KeyRiskSeverity::High
    } else {
        KeyRiskSeverity::Medium
    }
}

/// Compute the numeric risk score for a KMS key.
///
/// - not grantable → 0.0 (no CreateGrant permission → no delegation risk)
/// - grantable + wildcard → 0.90 (anyone can delegate → maximum escalation)
/// - grantable + cross-account → 0.80 (external account can escalate)
/// - grantable + same-account only → 0.55 (restricted delegation)
pub fn compute_key_risk_score(grantable: bool, wildcard: bool, cross_account: bool) -> f64 {
    match (grantable, wildcard, cross_account) {
        (false, _, _) => 0.0,
        (true, true, _) => 0.90,
        (true, false, true) => 0.80,
        (true, false, false) => 0.55,
    }
}

/// Extract the account ID from a KMS key ARN.
/// KMS ARN format: `arn:aws:kms:region:account:key/uuid`
pub fn extract_account_from_key_arn(key_arn: &str) -> String {
    let parts: Vec<&str> = key_arn.split(':').collect();
    if parts.len() >= 5 {
        parts[4].to_string()
    } else {
        "000000000000".to_string()
    }
}

/// Extract account ID from a principal ARN.
/// Returns `None` for wildcards or malformed ARNs.
pub fn extract_account_id_from_arn(principal_arn: &str) -> Option<String> {
    let parts: Vec<&str> = principal_arn.split(':').collect();
    if parts.len() >= 5 {
        let account = parts[4];
        if !account.is_empty() && account != "*" && account.len() == 12 {
            return Some(account.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::{test_fixtures::MockGraphQueryService, KmsKeyRow};

    // -------------------------------------------------------------------------
    // normalize_key_id
    // -------------------------------------------------------------------------

    #[test]
    fn normalize_full_arn_extracts_uuid() {
        let (arn, uuid) = normalize_key_id(
            "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
        )
        .unwrap();
        assert_eq!(
            arn,
            "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        );
        assert_eq!(uuid, "12345678-1234-1234-1234-123456789012");
    }

    #[test]
    fn normalize_bare_uuid_builds_arn() {
        let (arn, uuid) = normalize_key_id("12345678-1234-1234-1234-123456789012").unwrap();
        assert!(arn.contains("12345678-1234-1234-1234-123456789012"));
        assert!(arn.starts_with("arn:aws:kms:"));
        assert_eq!(uuid, "12345678-1234-1234-1234-123456789012");
    }

    #[test]
    fn normalize_seed_arn_extracts_correct_uuid() {
        let (arn, uuid) = normalize_key_id(
            "arn:aws:kms:us-east-1:000000000000:key/a48a7767-96eb-490f-9442-9656c9524547",
        )
        .unwrap();
        assert_eq!(
            arn,
            "arn:aws:kms:us-east-1:000000000000:key/a48a7767-96eb-490f-9442-9656c9524547"
        );
        assert_eq!(uuid, "a48a7767-96eb-490f-9442-9656c9524547");
    }

    // -------------------------------------------------------------------------
    // compute_grant_severity
    // -------------------------------------------------------------------------

    #[test]
    fn severity_low_when_not_grantable() {
        assert_eq!(
            compute_grant_severity(false, false, false),
            KeyRiskSeverity::Low
        );
    }

    #[test]
    fn severity_high_when_wildcard() {
        assert_eq!(
            compute_grant_severity(true, true, false),
            KeyRiskSeverity::High
        );
    }

    #[test]
    fn severity_high_when_cross_account() {
        assert_eq!(
            compute_grant_severity(true, false, true),
            KeyRiskSeverity::High
        );
    }

    #[test]
    fn severity_medium_when_same_account_grantable() {
        assert_eq!(
            compute_grant_severity(true, false, false),
            KeyRiskSeverity::Medium
        );
    }

    // -------------------------------------------------------------------------
    // compute_key_risk_score
    // -------------------------------------------------------------------------

    #[test]
    fn score_zero_when_not_grantable() {
        assert_eq!(compute_key_risk_score(false, false, false), 0.0);
    }

    #[test]
    fn score_090_when_wildcard_grantable() {
        assert_eq!(compute_key_risk_score(true, true, false), 0.90);
    }

    #[test]
    fn score_080_when_cross_account_grantable() {
        assert_eq!(compute_key_risk_score(true, false, true), 0.80);
    }

    #[test]
    fn score_055_when_same_account_grantable() {
        assert_eq!(compute_key_risk_score(true, false, false), 0.55);
    }

    // -------------------------------------------------------------------------
    // extract_account_from_key_arn
    // -------------------------------------------------------------------------

    #[test]
    fn extract_account_from_valid_arn() {
        assert_eq!(
            extract_account_from_key_arn(
                "arn:aws:kms:us-east-1:444444444444:key/12345678-abcd-1234-abcd-123456789012"
            ),
            "444444444444"
        );
    }

    #[test]
    fn extract_account_from_malformed_arn_returns_default() {
        assert_eq!(extract_account_from_key_arn("invalid-arn"), "000000000000");
    }

    // -------------------------------------------------------------------------
    // extract_account_id_from_arn
    // -------------------------------------------------------------------------

    #[test]
    fn extract_account_id_from_valid_principal_arn() {
        assert_eq!(
            extract_account_id_from_arn("arn:aws:iam::987654321098:role/Test"),
            Some("987654321098".to_string())
        );
    }

    #[test]
    fn extract_account_id_wildcard_returns_none() {
        assert_eq!(extract_account_id_from_arn("*"), None);
    }

    #[test]
    fn extract_account_id_too_short_returns_none() {
        assert_eq!(
            extract_account_id_from_arn("arn:aws:iam::123:role/Test"),
            None
        );
    }

    // -------------------------------------------------------------------------
    // parse_key_policy
    // -------------------------------------------------------------------------

    #[test]
    fn parse_policy_with_one_statement() {
        let policy = serde_json::json!({
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "arn:aws:iam::123456789012:root",
                    "Action": ["kms:CreateGrant"],
                    "Condition": {
                        "StringEquals": { "kms:ViaService": "secretsmanager.us-east-1.amazonaws.com" }
                    }
                }
            ],
            "PolicyArn": "arn:aws:kms:us-east-1:123456789012:key/12345678"
        });

        let result = parse_key_policy(&policy.to_string()).unwrap();
        assert_eq!(result.statements.len(), 1);
        assert_eq!(result.statements[0].effect, "Allow");
        assert_eq!(result.statements[0].actions.len(), 1);
        assert_eq!(
            result.policy_arn,
            Some("arn:aws:kms:us-east-1:123456789012:key/12345678".to_string())
        );
    }

    #[test]
    fn parse_policy_with_array_principal() {
        let stmt = serde_json::json!({
            "Effect": "Allow",
            "Principal": ["arn:aws:iam::123456789012:root", "arn:aws:iam::123456789012:role/test"],
            "Action": "kms:*",
            "Condition": {}
        });
        let result = parse_key_policy_statement(&stmt).unwrap();
        assert_eq!(result.principals.len(), 2);
        assert_eq!(result.actions.len(), 1);
    }

    #[test]
    fn parse_policy_returns_none_on_invalid_json() {
        assert!(parse_key_policy("not-json").is_none());
    }

    // -------------------------------------------------------------------------
    // assess_key_management_risk service tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn key_not_found_returns_error() {
        let graph = MockGraphQueryService::new();
        let result = assess_key_management_risk(
            &graph,
            "arn:aws:kms:us-east-1:444444444444:key/nonexistent",
        )
        .await;
        assert!(matches!(result, Err(KeyRiskError::KeyNotFound(_))));
    }

    #[tokio::test]
    async fn non_grantable_key_scores_zero() {
        let key_arn = "arn:aws:kms:us-east-1:444444444444:key/test-uuid".to_string();
        let graph = MockGraphQueryService::new().with_kms_key(
            key_arn.clone(),
            KmsKeyRow {
                key_arn: key_arn.clone(),
                policy_document: None,
                grantable_principal_ids: vec![],
            },
        );

        let result = assess_key_management_risk(&graph, &key_arn).await.unwrap();
        assert_eq!(result.risk_score, 0.0);
        assert_eq!(result.create_grant_risk.severity, KeyRiskSeverity::Low);
        assert!(!result.create_grant_risk.grantable);
    }

    #[tokio::test]
    async fn same_account_grantable_scores_medium() {
        let key_arn = "arn:aws:kms:us-east-1:444444444444:key/same-acct-key".to_string();
        let graph = MockGraphQueryService::new().with_kms_key(
            key_arn.clone(),
            KmsKeyRow {
                key_arn: key_arn.clone(),
                policy_document: None,
                grantable_principal_ids: vec![
                    "arn:aws:iam::444444444444:role/same-acct-role".to_string()
                ],
            },
        );

        let result = assess_key_management_risk(&graph, &key_arn).await.unwrap();
        assert_eq!(result.risk_score, 0.55);
        assert_eq!(result.create_grant_risk.severity, KeyRiskSeverity::Medium);
        assert!(result.create_grant_risk.grantable);
        assert!(!result.create_grant_risk.wildcard_principal);
    }

    #[tokio::test]
    async fn cross_account_grantable_scores_high() {
        let key_arn = "arn:aws:kms:us-east-1:444444444444:key/cross-acct-key".to_string();
        let graph = MockGraphQueryService::new().with_kms_key(
            key_arn.clone(),
            KmsKeyRow {
                key_arn: key_arn.clone(),
                policy_document: None,
                grantable_principal_ids: vec![
                    "arn:aws:iam::999999999999:role/external-role".to_string()
                ],
            },
        );

        let result = assess_key_management_risk(&graph, &key_arn).await.unwrap();
        assert_eq!(result.risk_score, 0.80);
        assert_eq!(result.create_grant_risk.severity, KeyRiskSeverity::High);
    }

    #[tokio::test]
    async fn wildcard_grantable_scores_highest() {
        let key_arn = "arn:aws:kms:us-east-1:444444444444:key/wildcard-key".to_string();
        let graph = MockGraphQueryService::new().with_kms_key(
            key_arn.clone(),
            KmsKeyRow {
                key_arn: key_arn.clone(),
                policy_document: None,
                grantable_principal_ids: vec!["*".to_string()],
            },
        );

        let result = assess_key_management_risk(&graph, &key_arn).await.unwrap();
        assert_eq!(result.risk_score, 0.90);
        assert_eq!(result.create_grant_risk.severity, KeyRiskSeverity::High);
        assert!(result.create_grant_risk.wildcard_principal);
    }

    #[tokio::test]
    async fn key_with_policy_document_is_parsed() {
        let key_arn = "arn:aws:kms:us-east-1:444444444444:key/policy-key".to_string();
        let policy_json = serde_json::json!({
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "arn:aws:iam::444444444444:root",
                    "Action": ["kms:CreateGrant", "kms:DescribeKey"]
                }
            ]
        })
        .to_string();

        let graph = MockGraphQueryService::new().with_kms_key(
            key_arn.clone(),
            KmsKeyRow {
                key_arn: key_arn.clone(),
                policy_document: Some(policy_json),
                grantable_principal_ids: vec![],
            },
        );

        let result = assess_key_management_risk(&graph, &key_arn).await.unwrap();
        assert_eq!(result.key_policy.statements.len(), 1);
        assert_eq!(result.key_policy.statements[0].effect, "Allow");
    }

    #[tokio::test]
    async fn bare_uuid_input_resolved_via_normalized_arn() {
        let uuid = "a48a7767-96eb-490f-9442-9656c9524547";
        let placeholder_arn = format!("arn:aws:kms:us-east-1:000000000000:key/{}", uuid);
        let graph = MockGraphQueryService::new().with_kms_key(
            placeholder_arn.clone(),
            KmsKeyRow {
                key_arn: placeholder_arn.clone(),
                policy_document: None,
                grantable_principal_ids: vec![],
            },
        );

        let result = assess_key_management_risk(&graph, uuid).await.unwrap();
        assert_eq!(result.key_arn, placeholder_arn);
    }
}
