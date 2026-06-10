//! Resolver for resource policy risk queries.

use crate::resolvers::policy_helpers::{extract_account_id_from_arn, policy_value_to_json};
use crate::types::{
    GqlCrossAccountAccess, GqlResourcePolicy, GqlResourcePolicyRisks, GqlResourcePolicyStatement,
    GqlSeverity,
};
use activable_graph::GraphClient;
use async_graphql::Context;
use std::collections::HashMap;

/// Get resource policy risks for a bucket or KMS key.
///
/// Either bucketName or keyId must be provided (not both).
/// Analyzes the attached resource policy for cross-account access and trust boundaries.
pub async fn resource_policy_risks(
    ctx: &Context<'_>,
    bucket_name: Option<String>,
    key_id: Option<String>,
) -> async_graphql::Result<Option<GqlResourcePolicyRisks>> {
    let graph = ctx
        .data::<GraphClient>()
        .map_err(|_| async_graphql::Error::new("GraphClient not available"))?;

    match (bucket_name, key_id) {
        (Some(bucket), None) => query_bucket_policy(graph, &bucket).await,
        (None, Some(key)) => query_key_policy(graph, &key).await,
        (None, None) => Err(async_graphql::Error::new(
            "Either bucketName or keyId must be provided",
        )),
        (Some(_), Some(_)) => Err(async_graphql::Error::new(
            "Provide only one of bucketName or keyId",
        )),
    }
}

/// Query and analyze bucket policy risks.
async fn query_bucket_policy(
    graph: &GraphClient,
    bucket_name: &str,
) -> async_graphql::Result<Option<GqlResourcePolicyRisks>> {
    let escaped_name = activable_graph::query_builder::escape_cypher(bucket_name);

    let cypher = format!(
        r#"MATCH (b:Bucket)
           WHERE b.name = '{name}'
           OPTIONAL MATCH (b)-[:HasBucketPolicy]->(p:Policy)
           OPTIONAL MATCH (b)-[:AllowsAccessFrom]->(consumer:Principal)
           RETURN b.id, p.document, collect(DISTINCT consumer.id)"#,
        name = &escaped_name
    );

    let results = graph.cypher_multi_column(&cypher, 3).await.map_err(|e| {
        tracing::error!(bucket = %bucket_name, error = %e, "failed to query bucket policy");
        async_graphql::Error::new("Failed to query bucket policy")
    })?;

    if results.is_empty() {
        return Ok(None);
    }

    let first = &results[0];
    if first.len() < 3 {
        return Err(async_graphql::Error::new("Invalid query result structure"));
    }

    let resource_arn = first[0]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("arn:aws:s3:::{}", bucket_name));

    let policy_doc_owned = policy_value_to_json(&first[1]);
    let policy_doc = policy_doc_owned.as_deref();
    let consuming_accounts: Vec<String> = first[2]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.as_str())
                .filter_map(extract_account_id_from_arn)
                .collect()
        })
        .unwrap_or_default();

    build_resource_policy_risks(&resource_arn, "bucket", policy_doc, consuming_accounts)
}

/// Query and analyze KMS key policy risks.
async fn query_key_policy(
    graph: &GraphClient,
    key_id: &str,
) -> async_graphql::Result<Option<GqlResourcePolicyRisks>> {
    let escaped_key = activable_graph::query_builder::escape_cypher(key_id);

    let cypher = format!(
        r#"MATCH (k:KmsKey)
           WHERE k.id = '{key_id}' OR k.key_id = '{key_id}'
           OPTIONAL MATCH (k)-[:HasKeyPolicy]->(p:Policy)
           OPTIONAL MATCH (k)-[:AllowsAccessFrom]->(user:Principal)
           RETURN k.id, p.document, collect(DISTINCT user.id)"#,
        key_id = &escaped_key
    );

    let results = graph.cypher_multi_column(&cypher, 3).await.map_err(|e| {
        tracing::error!(key_id = %key_id, error = %e, "failed to query key policy");
        async_graphql::Error::new("Failed to query key policy")
    })?;

    if results.is_empty() {
        return Ok(None);
    }

    let first = &results[0];
    if first.len() < 3 {
        return Err(async_graphql::Error::new("Invalid query result structure"));
    }

    let resource_arn = first[0]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("arn:aws:kms:us-east-1:000000000000:key/{}", key_id));

    let policy_doc_owned = policy_value_to_json(&first[1]);
    let policy_doc = policy_doc_owned.as_deref();
    let consuming_accounts: Vec<String> = first[2]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.as_str())
                .filter_map(extract_account_id_from_arn)
                .collect()
        })
        .unwrap_or_default();

    build_resource_policy_risks(&resource_arn, "kmsKey", policy_doc, consuming_accounts)
}

/// Build the complete GqlResourcePolicyRisks response.
fn build_resource_policy_risks(
    resource_arn: &str,
    resource_type: &str,
    policy_doc: Option<&str>,
    consuming_accounts: Vec<String>,
) -> async_graphql::Result<Option<GqlResourcePolicyRisks>> {
    let (statements, cross_account_access) = if let Some(doc) = policy_doc {
        let parsed_stmts = parse_resource_policy(doc)?;
        let cross_acct = extract_cross_account_access(&parsed_stmts, &consuming_accounts);
        (parsed_stmts, cross_acct)
    } else {
        (vec![], vec![])
    };

    let policy = GqlResourcePolicy { statements };
    let risk_score = compute_resource_policy_score(&policy, !cross_account_access.is_empty());
    let severity = score_to_severity(risk_score);

    Ok(Some(GqlResourcePolicyRisks {
        resource_arn: resource_arn.to_string(),
        resource_type: resource_type.to_string(),
        policy,
        cross_account_access,
        risk_score,
        severity,
        policy_evaluator_version: "v1".to_string(),
    }))
}

/// Parse a resource policy document into statements.
fn parse_resource_policy(
    policy_json: &str,
) -> async_graphql::Result<Vec<GqlResourcePolicyStatement>> {
    let parsed: serde_json::Value = serde_json::from_str(policy_json).map_err(|e| {
        tracing::warn!(error = %e, "failed to parse resource policy JSON");
        async_graphql::Error::new("Invalid policy JSON")
    })?;

    let statements = parsed
        .get("Statement")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_resource_statement).collect())
        .unwrap_or_default();

    Ok(statements)
}

/// Parse a single resource policy statement.
fn parse_resource_statement(stmt: &serde_json::Value) -> Option<GqlResourcePolicyStatement> {
    let effect = stmt
        .get("Effect")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())?;

    let principal = stmt
        .get("Principal")
        .and_then(|v| {
            if let serde_json::Value::String(s) = v {
                Some(s.clone())
            } else if let serde_json::Value::Object(obj) = v {
                obj.get("AWS")
                    .and_then(|aws| aws.as_str())
                    .map(|s| s.to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "*".to_string());

    // Extract condition keys from nested operator objects (StringEquals, StringLike, etc.)
    // Condition: { "StringEquals": { "aws:PrincipalOrgID": "value", ... }, ... }
    // We need the inner keys (aws:PrincipalOrgID, etc.), not the operator names
    let condition_keys: Vec<String> = stmt
        .get("Condition")
        .and_then(|v| v.as_object())
        .map(|condition_obj| {
            condition_obj
                .values()
                .filter_map(|operator_val| operator_val.as_object())
                .flat_map(|operator_obj| operator_obj.keys().cloned())
                .collect()
        })
        .unwrap_or_default();

    let is_trust_boundary = evaluate_trust_boundary(&principal, &condition_keys[..]);

    Some(GqlResourcePolicyStatement {
        effect,
        principal,
        condition_keys,
        is_trust_boundary,
    })
}

/// Evaluate if a principal is a trust boundary.
/// True ONLY if principal is arn:aws:iam::<12-digit-account>:role/<role-name> with no wildcards
/// AND no condition keys are present. Conditions (PrincipalOrgID, SourceArn, aud/sub, etc.)
/// make the grant conditional and require runtime evaluation, so they are not static trust boundaries.
fn evaluate_trust_boundary(principal: &str, condition_keys: &[String]) -> bool {
    // If ANY condition key is present, the grant is conditional, not a static boundary.
    if !condition_keys.is_empty() {
        return false;
    }

    // Pattern: arn:aws:iam::123456789012:role/rolename
    // Must be exact role ARN with specific account, no wildcards
    if principal.contains('*') || principal == "*" {
        return false;
    }

    // Match the specific role ARN pattern
    let parts: Vec<&str> = principal.split(':').collect();
    if parts.len() < 6 {
        return false;
    }

    // parts[4] should be account ID (12 digits)
    // parts[5] should start with "role/"
    let account_id = parts[4];
    let resource_part = parts.get(5).unwrap_or(&"");

    let is_valid_account = account_id.len() == 12 && account_id.chars().all(|c| c.is_ascii_digit());
    let is_role = resource_part.starts_with("role/");

    is_valid_account && is_role
}

/// Extract cross-account access summary from statements.
fn extract_cross_account_access(
    statements: &[GqlResourcePolicyStatement],
    consuming_accounts: &[String],
) -> Vec<GqlCrossAccountAccess> {
    let mut account_map: HashMap<String, (i32, GqlSeverity)> = HashMap::new();

    for stmt in statements {
        if stmt.effect == "Allow" {
            // Extract account ID from principal ARN
            if let Some(acct_id) = extract_account_from_principal(&stmt.principal) {
                let severity = if stmt.principal.contains('*') {
                    GqlSeverity::High
                } else {
                    GqlSeverity::Medium
                };

                account_map
                    .entry(acct_id)
                    .and_modify(|(count, sev)| {
                        *count += 1;
                        if severity == GqlSeverity::High {
                            *sev = GqlSeverity::High;
                        }
                    })
                    .or_insert((1, severity));
            }
        }
    }

    // Include consuming accounts from graph
    for acct in consuming_accounts {
        account_map
            .entry(acct.clone())
            .and_modify(|(count, _)| *count += 1)
            .or_insert((1, GqlSeverity::Medium));
    }

    account_map
        .into_iter()
        .map(
            |(account_id, (principal_count, severity))| GqlCrossAccountAccess {
                destination_account_id: account_id,
                principal_count,
                severity,
            },
        )
        .collect()
}

/// Extract account ID from a principal ARN.
fn extract_account_from_principal(principal: &str) -> Option<String> {
    let parts: Vec<&str> = principal.split(':').collect();
    if parts.len() >= 5 {
        let account = parts[4];
        if !account.is_empty() && account != "*" {
            return Some(account.to_string());
        }
    }
    None
}

/// Compute resource policy risk score.
fn compute_resource_policy_score(policy: &GqlResourcePolicy, has_cross_account: bool) -> f64 {
    let wildcard_count = policy
        .statements
        .iter()
        .filter(|s| s.principal.contains('*') || s.principal == "*")
        .count();

    let boundary_violations = policy
        .statements
        .iter()
        .filter(|s| s.effect == "Allow" && !s.is_trust_boundary)
        .count();

    let base_score: f64 = match (
        wildcard_count > 0,
        boundary_violations > 0,
        has_cross_account,
    ) {
        (true, _, _) => 0.85,
        (false, true, true) => 0.70,
        (false, true, false) => 0.45,
        (false, false, _) => 0.20,
    };

    base_score.clamp(0.0, 1.0)
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
    fn trust_boundary_specific_role_arn() {
        assert!(evaluate_trust_boundary(
            "arn:aws:iam::123456789012:role/MyRole",
            &[]
        ));
    }

    #[test]
    fn trust_boundary_false_wildcard_principal() {
        assert!(!evaluate_trust_boundary("*", &[]));
    }

    #[test]
    fn trust_boundary_false_wildcard_in_role() {
        assert!(!evaluate_trust_boundary(
            "arn:aws:iam::123456789012:role/Role*",
            &[]
        ));
    }

    #[test]
    fn trust_boundary_false_root_principal() {
        assert!(!evaluate_trust_boundary(
            "arn:aws:iam::123456789012:root",
            &[]
        ));
    }

    #[test]
    fn trust_boundary_false_with_principal_org_id_condition() {
        // org-ID condition makes the grant conditional, not an ownership boundary
        let condition_keys = vec!["aws:PrincipalOrgID".to_string()];
        assert!(!evaluate_trust_boundary(
            "arn:aws:iam::123456789012:role/MyRole",
            &condition_keys
        ));
    }

    #[test]
    fn trust_boundary_false_with_any_condition() {
        // Any condition present (SourceArn, aud, sub, etc.) makes it non-static
        let conditions = vec![
            vec!["aws:SourceArn".to_string()],
            vec!["aud".to_string()],
            vec!["sub".to_string()],
        ];
        for cond_keys in conditions {
            assert!(!evaluate_trust_boundary(
                "arn:aws:iam::123456789012:role/MyRole",
                &cond_keys
            ));
        }
    }

    #[test]
    fn trust_boundary_true_only_unconditioned_role_arn() {
        // Must be a role ARN with no conditions to be a static trust boundary
        assert!(evaluate_trust_boundary(
            "arn:aws:iam::999999999999:role/SafeRole",
            &[]
        ));
    }

    #[test]
    fn score_high_if_wildcard() {
        let policy = GqlResourcePolicy {
            statements: vec![GqlResourcePolicyStatement {
                effect: "Allow".to_string(),
                principal: "*".to_string(),
                condition_keys: vec![],
                is_trust_boundary: false,
            }],
        };
        let score = compute_resource_policy_score(&policy, false);
        assert!(score > 0.80);
    }

    #[test]
    fn score_medium_if_boundary_violation_cross_account() {
        let policy = GqlResourcePolicy {
            statements: vec![GqlResourcePolicyStatement {
                effect: "Allow".to_string(),
                principal: "arn:aws:iam::999999999999:root".to_string(),
                condition_keys: vec![],
                is_trust_boundary: false,
            }],
        };
        let score = compute_resource_policy_score(&policy, true);
        assert!(score > 0.60 && score < 0.80);
    }

    #[test]
    fn score_low_if_trust_boundary() {
        let policy = GqlResourcePolicy {
            statements: vec![GqlResourcePolicyStatement {
                effect: "Allow".to_string(),
                principal: "arn:aws:iam::123456789012:role/MyRole".to_string(),
                condition_keys: vec![],
                is_trust_boundary: true,
            }],
        };
        let score = compute_resource_policy_score(&policy, false);
        assert!(score < 0.40);
    }

    #[test]
    fn extract_account_id_from_arn() {
        let account = extract_account_from_principal("arn:aws:iam::987654321098:role/Test");
        assert_eq!(account, Some("987654321098".to_string()));
    }

    #[test]
    fn extract_account_id_wildcard_returns_none() {
        let account = extract_account_from_principal("*");
        assert_eq!(account, None);
    }

    #[test]
    fn score_to_severity_maps_critical() {
        assert_eq!(score_to_severity(0.85), GqlSeverity::Critical);
    }

    #[test]
    fn score_to_severity_maps_high() {
        assert_eq!(score_to_severity(0.70), GqlSeverity::High);
    }

    #[test]
    fn score_to_severity_maps_medium() {
        assert_eq!(score_to_severity(0.50), GqlSeverity::Medium);
    }

    #[test]
    fn score_to_severity_maps_low() {
        assert_eq!(score_to_severity(0.25), GqlSeverity::Low);
    }

    #[test]
    fn score_to_severity_maps_info() {
        assert_eq!(score_to_severity(0.05), GqlSeverity::Info);
    }

    #[test]
    fn parse_real_seed_org_shared_data_bucket_policy() {
        // Real bucket policy from ops/seed/seed-adversarial.sh (org-shared-data bucket)
        // Principal: "*", Effect: Allow, Condition: StringEquals aws:PrincipalOrgID = "o-myorg"
        let policy_json = r#"{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOrgWideRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::org-shared-data",
        "arn:aws:s3:::org-shared-data/*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-myorg"
        }
      }
    }
  ]
}"#;

        // Parse the policy
        let statements =
            parse_resource_policy(policy_json).expect("policy should parse successfully");

        // Verify: exactly 1 statement
        assert_eq!(statements.len(), 1, "should have exactly 1 statement");

        let stmt = &statements[0];
        // Principal should be "*" (string form, not array)
        assert_eq!(stmt.principal, "*", "principal should be wildcard");
        // Effect should be "Allow"
        assert_eq!(stmt.effect, "Allow", "effect should be Allow");
        // Condition keys should contain the org-ID constraint
        assert!(
            !stmt.condition_keys.is_empty(),
            "condition_keys should not be empty (got: {:?})",
            stmt.condition_keys
        );
        assert!(
            stmt.condition_keys
                .iter()
                .any(|k| k.contains("PrincipalOrgID")),
            "should extract PrincipalOrgID condition key from {:?}",
            stmt.condition_keys
        );
        // With condition keys present, trust boundary should be false
        assert!(
            !stmt.is_trust_boundary,
            "principal with condition should NOT be a trust boundary"
        );
    }

    #[test]
    fn policy_value_to_json_handles_string_document() {
        // Policy document already as a JSON string (quoted scalar)
        let json_string = serde_json::json!(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*"}]}"#
        );
        let result = policy_value_to_json(&json_string);
        assert!(result.is_some(), "should handle string value");
        let s = result.unwrap();
        assert!(s.contains("Version"), "should preserve document content");
    }

    #[test]
    fn policy_value_to_json_handles_object_document() {
        // Policy document as a JSON object (maps from agtype)
        // This is the actual bug case: AGE returns document as object instead of string
        let json_obj = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::bucket/*"
                }
            ]
        });
        let result = policy_value_to_json(&json_obj);
        assert!(result.is_some(), "should handle object value");
        let s = result.unwrap();
        // Serialize the object to JSON and parse it back to verify structure is intact
        let reparsed: serde_json::Value =
            serde_json::from_str(&s).expect("serialized object should parse back");
        assert!(reparsed.is_object(), "reparsed should be an object");
        assert_eq!(
            reparsed.get("Version").and_then(|v| v.as_str()),
            Some("2012-10-17")
        );
    }

    #[test]
    fn policy_value_to_json_rejects_null() {
        let null_value = serde_json::Value::Null;
        let result = policy_value_to_json(&null_value);
        assert!(result.is_none(), "should return None for null value");
    }

    #[test]
    fn policy_value_to_json_handles_array_document() {
        // Edge case: if document is somehow an array (unlikely but possible)
        let json_array = serde_json::json!([
            {"Effect": "Allow", "Principal": "*"}
        ]);
        let result = policy_value_to_json(&json_array);
        assert!(result.is_some(), "should handle array value");
        let s = result.unwrap();
        let reparsed: serde_json::Value =
            serde_json::from_str(&s).expect("serialized array should parse back");
        assert!(reparsed.is_array(), "reparsed should be an array");
    }

    #[test]
    fn policy_value_to_json_roundtrip_with_parser() {
        // Integration: parse a policy document extracted as object (real bug case)
        let policy_obj = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowOrgWideRead",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:GetObject"],
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalOrgID": "o-myorg"
                        }
                    }
                }
            ]
        });

        // Simulate the fix: convert object to string
        let policy_string =
            policy_value_to_json(&policy_obj).expect("should convert object to string");

        // Then parse it like the real resolver does
        let statements =
            parse_resource_policy(&policy_string).expect("should parse the converted document");

        // Verify the structure came through
        assert_eq!(statements.len(), 1, "should have 1 statement");
        assert_eq!(statements[0].principal, "*");
        assert!(
            statements[0]
                .condition_keys
                .iter()
                .any(|k| k.contains("PrincipalOrgID")),
            "should extract condition key from nested object"
        );
    }
}
