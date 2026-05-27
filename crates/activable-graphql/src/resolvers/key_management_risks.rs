//! Resolver for key management risk queries.

use crate::resolvers::policy_helpers::{extract_account_id_from_arn, policy_value_to_json};
use crate::types::{
    GqlCreateGrantRisk, GqlKeyManagementRisks, GqlKeyPolicy, GqlKeyPolicyStatement, GqlSeverity,
};
use activable_graph::GraphClient;
use async_graphql::Context;

/// Get key management risks for a KMS key.
///
/// Looks up the key by ARN or key UUID, extracts the key policy,
/// and evaluates the risk of granting capabilities.
pub async fn key_management_risks(
    ctx: &Context<'_>,
    key_id: String,
) -> async_graphql::Result<GqlKeyManagementRisks> {
    let graph = ctx
        .data::<GraphClient>()
        .map_err(|_| async_graphql::Error::new("GraphClient not available"))?;

    // Normalize key_id: accept both full ARN and bare UUID
    let (key_arn, key_uuid) = normalize_key_id(&key_id)?;

    // Query for the KMS key node and its policy
    let cypher = format!(
        r#"MATCH (k:KmsKey)
           WHERE k.id = '{arn}' OR k.key_id = '{uuid}'
           OPTIONAL MATCH (k)-[:HasKeyPolicy]->(p:Policy)
           OPTIONAL MATCH (granter:Principal)-[:KmsGrantable]->(k)
           RETURN k.id, p.document, collect(DISTINCT granter.id)"#,
        arn = activable_graph::query_builder::escape_cypher(&key_arn),
        uuid = activable_graph::query_builder::escape_cypher(&key_uuid)
    );

    let results = graph.cypher_multi_column(&cypher, 3).await.map_err(|e| {
        tracing::error!(key_id = %key_id, error = %e, "failed to query KMS key");
        async_graphql::Error::new("Failed to query KMS key")
    })?;

    if results.is_empty() {
        return Err(async_graphql::Error::new("KMS key not found"));
    }

    // Parse the first result row: [key_arn, policy_doc, grantable_principals]
    let first = &results[0];
    if first.len() < 3 {
        return Err(async_graphql::Error::new("Invalid query result structure"));
    }

    let key_arn_val = first[0]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or(key_arn.clone());

    let policy_doc_owned = policy_value_to_json(&first[1]);
    let policy_doc = policy_doc_owned.as_deref();
    let grantable_principals: Vec<String> = first[2]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Parse key policy if present
    let key_policy = if let Some(doc) = policy_doc {
        parse_key_policy(doc)?
    } else {
        GqlKeyPolicy {
            statements: vec![],
            policy_arn: None,
        }
    };

    // Compute create grant risk
    let grantable = !grantable_principals.is_empty();
    let wildcard_principal = grantable_principals
        .iter()
        .any(|p| p.contains("*") || p == "*");

    // Extract the key's account ID from the ARN
    let key_account = extract_key_account(&key_arn_val);

    // Detect cross-account grant capability
    let has_cross_account_grant = grantable
        && grantable_principals.iter().any(|p| {
            extract_account_id_from_arn(p)
                .map(|acct| acct != key_account)
                .unwrap_or(false)
        });

    let severity = compute_grant_severity(grantable, wildcard_principal, has_cross_account_grant);
    let risk_score = compute_key_risk_score(grantable, wildcard_principal, has_cross_account_grant);

    let create_grant_risk = GqlCreateGrantRisk {
        grantable,
        granting_principals: grantable_principals,
        severity,
        wildcard_principal,
    };

    Ok(GqlKeyManagementRisks {
        key_arn: key_arn_val,
        key_policy,
        create_grant_risk,
        risk_score,
        severity,
    })
}

/// Normalize a key ID: accept both full ARN and bare UUID.
///
/// For ARN format (arn:aws:kms:region:account:key/uuid), extracts the UUID as the last segment after '/'.
/// For bare UUID format, constructs a full ARN using us-east-1 + default account (000000000000).
fn normalize_key_id(key_id: &str) -> async_graphql::Result<(String, String)> {
    if key_id.starts_with("arn:aws:kms:") {
        // Full ARN format: extract UUID from the last path segment after '/'
        // arn:aws:kms:region:account:key/uuid → (arn, uuid)
        let uuid = key_id
            .rsplit('/')
            .next()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                async_graphql::Error::new("Invalid KMS key ARN: missing UUID after '/'")
            })?;
        Ok((key_id.to_string(), uuid))
    } else {
        // Bare UUID format: construct full ARN
        // Input is just the UUID; build a complete ARN
        let arn = format!("arn:aws:kms:us-east-1:000000000000:key/{}", key_id);
        Ok((arn, key_id.to_string()))
    }
}

/// Parse a JSON policy document into GqlKeyPolicy structure.
fn parse_key_policy(policy_json: &str) -> async_graphql::Result<GqlKeyPolicy> {
    let parsed: serde_json::Value = serde_json::from_str(policy_json).map_err(|e| {
        tracing::warn!(error = %e, "failed to parse key policy JSON");
        async_graphql::Error::new("Invalid policy JSON")
    })?;

    let statements = parsed
        .get("Statement")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_policy_statement).collect())
        .unwrap_or_default();

    Ok(GqlKeyPolicy {
        statements,
        policy_arn: parsed
            .get("PolicyArn")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

/// Parse a single policy statement into GqlKeyPolicyStatement.
fn parse_policy_statement(stmt: &serde_json::Value) -> Option<GqlKeyPolicyStatement> {
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

    Some(GqlKeyPolicyStatement {
        effect,
        principals,
        actions,
        condition_keys,
    })
}

/// Compute grant severity: HIGH if wildcard or cross-account, MEDIUM if same-account grantable, LOW otherwise.
/// - Wildcard principal → anyone can kms:CreateGrant (highest escalation) → HIGH
/// - Cross-account principal → external account can escalate (privilege boundary breach) → HIGH
/// - Same-account grantable → restricted but still risky → MEDIUM
/// - Not grantable → LOW
fn compute_grant_severity(grantable: bool, wildcard: bool, cross_account: bool) -> GqlSeverity {
    if !grantable {
        GqlSeverity::Low
    } else if wildcard || cross_account {
        GqlSeverity::High
    } else {
        GqlSeverity::Medium
    }
}

/// Compute key risk score based on grantability and principal scope.
/// Scores reflect the escalation risk of kms:CreateGrant:
/// - not grantable → 0.0 (no CreateGrant permission → no delegation risk)
/// - grantable + wildcard → 0.90 (anyone can delegate the key to themselves → max escalation)
/// - grantable + cross-account principal → 0.80 (external account can escalate key access → privilege boundary breach)
/// - grantable + same-account only → 0.55 (restricted within org, but still allows delegation)
fn compute_key_risk_score(grantable: bool, wildcard: bool, cross_account: bool) -> f64 {
    match (grantable, wildcard, cross_account) {
        (false, _, _) => 0.0,
        (true, true, _) => 0.90,
        (true, false, true) => 0.80,
        (true, false, false) => 0.55,
    }
}

/// Extract the account ID from a KMS key ARN.
/// KMS ARN format: arn:aws:kms:region:account:key/uuid
fn extract_key_account(key_arn: &str) -> String {
    let parts: Vec<&str> = key_arn.split(':').collect();
    if parts.len() >= 5 {
        parts[4].to_string()
    } else {
        "000000000000".to_string() // Default if malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_full_arn() {
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
    fn normalize_bare_uuid() {
        let (arn, uuid) = normalize_key_id("12345678-1234-1234-1234-123456789012").unwrap();
        assert!(arn.contains("12345678-1234-1234-1234-123456789012"));
        assert_eq!(uuid, "12345678-1234-1234-1234-123456789012");
    }

    #[test]
    fn normalize_key_id_arn_parses_uuid() {
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

    #[test]
    fn normalize_key_id_bare_uuid() {
        let (arn, uuid) = normalize_key_id("a48a7767-96eb-490f-9442-9656c9524547").unwrap();
        assert_eq!(uuid, "a48a7767-96eb-490f-9442-9656c9524547");
        assert!(arn.starts_with("arn:aws:kms:"));
        assert!(arn.contains("a48a7767-96eb-490f-9442-9656c9524547"));
    }

    #[test]
    fn severity_high_if_wildcard() {
        assert_eq!(compute_grant_severity(true, true, false), GqlSeverity::High);
    }

    #[test]
    fn severity_high_if_cross_account() {
        assert_eq!(compute_grant_severity(true, false, true), GqlSeverity::High);
    }

    #[test]
    fn severity_medium_if_grantable_no_wildcard_same_account() {
        assert_eq!(
            compute_grant_severity(true, false, false),
            GqlSeverity::Medium
        );
    }

    #[test]
    fn severity_low_if_not_grantable() {
        assert_eq!(
            compute_grant_severity(false, false, false),
            GqlSeverity::Low
        );
    }

    #[test]
    fn score_zero_if_not_grantable() {
        assert_eq!(compute_key_risk_score(false, false, false), 0.0);
    }

    #[test]
    fn score_high_if_wildcard_grantable() {
        assert_eq!(compute_key_risk_score(true, true, false), 0.90);
    }

    #[test]
    fn score_high_if_cross_account_grantable() {
        assert_eq!(compute_key_risk_score(true, false, true), 0.80);
    }

    #[test]
    fn score_medium_if_grantable_no_wildcard_same_account() {
        assert_eq!(compute_key_risk_score(true, false, false), 0.55);
    }

    #[test]
    fn extract_key_account_from_full_arn() {
        let arn = "arn:aws:kms:us-east-1:444444444444:key/12345678-abcd-1234-abcd-123456789012";
        let account = extract_key_account(arn);
        assert_eq!(account, "444444444444");
    }

    #[test]
    fn extract_key_account_from_malformed_arn() {
        let arn = "invalid-arn";
        let account = extract_key_account(arn);
        assert_eq!(account, "000000000000"); // Default
    }

    #[test]
    fn parse_simple_policy_document() {
        let policy = json!({
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
    fn parse_policy_statement_handles_multiple_principals() {
        let stmt = json!({
            "Effect": "Allow",
            "Principal": ["arn:aws:iam::123456789012:root", "arn:aws:iam::123456789012:role/test"],
            "Action": "kms:*",
            "Condition": {}
        });

        let result = parse_policy_statement(&stmt).unwrap();
        assert_eq!(result.principals.len(), 2);
        assert_eq!(result.actions.len(), 1);
    }
}
