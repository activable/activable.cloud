//! Federation trust analysis for SAML and OIDC providers.
//!
//! Parses AssumeRolePolicyDocument to extract federation trust relationships,
//! identifies weak federation conditions (missing audience/subject), and
//! detects escalation vectors via external IdP compromise.

use serde_json::Value;

/// Type of federation provider
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationProviderType {
    Saml,
    Oidc,
}

impl FederationProviderType {
    pub fn as_str(&self) -> &str {
        match self {
            FederationProviderType::Saml => "SAML",
            FederationProviderType::Oidc => "OIDC",
        }
    }
}

/// A federation trust relationship between an IdP and a role
#[derive(Debug, Clone)]
pub struct FederationTrust {
    /// ARN of the SAML/OIDC provider (e.g., "arn:aws:iam::123456789012:saml-provider/Okta")
    pub provider_arn: String,
    /// Type of federation provider (SAML or OIDC)
    pub provider_type: FederationProviderType,
    /// ARN of the role being trusted
    pub role_arn: String,
    /// Conditions on the federation trust
    pub conditions: Vec<FederationCondition>,
    /// Detected weakness in the trust, if any
    pub weakness: Option<FederationWeakness>,
}

/// A condition on a federation trust (audience, subject, etc.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationCondition {
    /// Condition key (e.g., "SAML:aud", "oidc.example.com:sub")
    pub condition_key: String,
    /// Operator (e.g., "StringEquals", "StringLike")
    pub operator: String,
    /// Expected values
    pub values: Vec<String>,
}

/// Weakness detected in a federation trust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationWeakness {
    /// No audience (aud) condition — any IdP app can generate tokens
    MissingAudience,
    /// No subject (sub) condition — any user from IdP can assume role
    MissingSubject,
    /// Both audience and subject missing — fully open to IdP compromise
    MissingAudienceAndSubject,
    /// Wildcard principal (trust *) — open to any IdP
    WildcardPrincipal,
    /// No conditions at all on the trust policy
    NoConditions,
}

/// Extract federation trust relationships from a role's trust policy.
///
/// Parses the AssumeRolePolicyDocument JSON looking for SAML/OIDC principals
/// in the Principal field. Extracts conditions and detects weaknesses.
///
/// # Arguments
/// * `trust_policy_json` - The AssumeRolePolicyDocument as JSON string
/// * `role_arn` - The ARN of the role being analyzed
///
/// # Returns
/// A vector of FederationTrust relationships found
pub fn extract_federation_trusts(
    trust_policy_json: &str,
    role_arn: &str,
) -> Result<Vec<FederationTrust>, String> {
    let policy_value: Value =
        serde_json::from_str(trust_policy_json).map_err(|e| format!("JSON parse error: {}", e))?;

    let policy_obj = policy_value
        .as_object()
        .ok_or("Trust policy must be a JSON object")?;

    let statements = policy_obj
        .get("Statement")
        .and_then(|v| v.as_array())
        .ok_or("Statement array not found in trust policy")?;

    let mut trusts = Vec::new();

    for stmt in statements {
        let stmt_obj = stmt.as_object().ok_or("Statement must be an object")?;

        // Only process Allow statements
        let effect = stmt_obj
            .get("Effect")
            .and_then(|v| v.as_str())
            .unwrap_or("Allow");

        if effect != "Allow" {
            continue;
        }

        // Extract principals
        if let Some(principal_value) = stmt_obj.get("Principal") {
            let (saml_principals, oidc_principals) =
                extract_federation_principals(principal_value)?;

            // Extract conditions (could be empty)
            let conditions: Vec<FederationCondition> = stmt_obj
                .get("Condition")
                .and_then(|v| v.as_object())
                .map(extract_federation_conditions)
                .unwrap_or_default();

            // Process SAML principals
            for principal_arn in saml_principals {
                let weakness = detect_weakness(&conditions, &FederationProviderType::Saml);
                trusts.push(FederationTrust {
                    provider_arn: principal_arn,
                    provider_type: FederationProviderType::Saml,
                    role_arn: role_arn.to_string(),
                    conditions: conditions.clone(),
                    weakness,
                });
            }

            // Process OIDC principals
            for principal_arn in oidc_principals {
                let weakness = detect_weakness(&conditions, &FederationProviderType::Oidc);
                trusts.push(FederationTrust {
                    provider_arn: principal_arn,
                    provider_type: FederationProviderType::Oidc,
                    role_arn: role_arn.to_string(),
                    conditions: conditions.clone(),
                    weakness,
                });
            }
        }
    }

    Ok(trusts)
}

/// Extract SAML and OIDC principals from a Principal value.
///
/// Principal can be:
/// - A string (e.g., "*", "arn:aws:iam::123456789012:saml-provider/NAME")
/// - An object with keys like "AWS", "Service", "Federated"
/// - An array of strings
fn extract_federation_principals(value: &Value) -> Result<(Vec<String>, Vec<String>), String> {
    let mut saml_principals = Vec::new();
    let mut oidc_principals = Vec::new();

    match value {
        Value::String(s) if is_federation_principal(s) => {
            categorize_federation_principal(s, &mut saml_principals, &mut oidc_principals);
        }
        Value::Object(obj) => {
            // Handle Federated key
            if let Some(federated_val) = obj.get("Federated") {
                for principal_str in extract_string_or_array(federated_val) {
                    categorize_federation_principal(
                        &principal_str,
                        &mut saml_principals,
                        &mut oidc_principals,
                    );
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                if let Value::String(s) = item {
                    if is_federation_principal(s) {
                        categorize_federation_principal(
                            s,
                            &mut saml_principals,
                            &mut oidc_principals,
                        );
                    }
                }
            }
        }
        _ => {}
    }

    Ok((saml_principals, oidc_principals))
}

/// Check if a string is a federation principal (SAML or OIDC ARN).
fn is_federation_principal(s: &str) -> bool {
    s.contains("saml-provider") || s.contains("oidc-provider")
}

/// Categorize a federation principal as SAML or OIDC.
fn categorize_federation_principal(
    principal: &str,
    saml_principals: &mut Vec<String>,
    oidc_principals: &mut Vec<String>,
) {
    if principal.contains("saml-provider") {
        saml_principals.push(principal.to_string());
    } else if principal.contains("oidc-provider") {
        oidc_principals.push(principal.to_string());
    }
}

/// Extract strings from a value that can be either a string or array of strings.
fn extract_string_or_array(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => vec![s.clone()],
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect(),
        _ => Vec::new(),
    }
}

/// Extract federation-specific conditions from the Condition object.
///
/// Looks for SAML:aud, SAML:sub, SAML:namequalifier and
/// oidc-provider conditions like aud, sub.
fn extract_federation_conditions(
    condition_obj: &serde_json::Map<String, Value>,
) -> Vec<FederationCondition> {
    let mut conditions = Vec::new();

    for (operator, operator_obj_value) in condition_obj {
        if let Some(operator_obj) = operator_obj_value.as_object() {
            for (key, values_value) in operator_obj {
                // Only extract federation-related condition keys
                if is_federation_condition_key(key) {
                    let values = extract_string_or_array(values_value);
                    if !values.is_empty() {
                        conditions.push(FederationCondition {
                            condition_key: key.clone(),
                            operator: operator.clone(),
                            values,
                        });
                    }
                }
            }
        }
    }

    conditions
}

/// Check if a condition key is federation-related.
fn is_federation_condition_key(key: &str) -> bool {
    // SAML condition keys
    if key.contains("SAML:") {
        return true;
    }
    // OIDC condition keys (format: https://provider-url:aud or :sub)
    if key.contains(":aud") || key.contains(":sub") || key.contains(":oid") {
        return true;
    }
    false
}

/// Detect weaknesses in a federation trust's conditions.
///
/// Returns None if conditions are properly constrained,
/// or Some(weakness) if a weakness is detected.
pub fn detect_weakness(
    conditions: &[FederationCondition],
    _provider_type: &FederationProviderType,
) -> Option<FederationWeakness> {
    if conditions.is_empty() {
        return Some(FederationWeakness::NoConditions);
    }

    let has_audience = conditions.iter().any(|c| {
        c.condition_key.to_lowercase().contains(":aud")
            || c.condition_key.to_lowercase().contains(":audience")
    });

    let has_subject = conditions.iter().any(|c| {
        c.condition_key.to_lowercase().contains(":sub")
            || c.condition_key.to_lowercase().contains(":namequalifier")
    });

    match (has_audience, has_subject) {
        (false, false) => Some(FederationWeakness::MissingAudienceAndSubject),
        (false, true) => Some(FederationWeakness::MissingAudience),
        (true, false) => Some(FederationWeakness::MissingSubject),
        (true, true) => None, // Properly constrained
    }
}

/// Analyze all roles in a set for federation weaknesses.
///
/// Returns all weak federation trusts found.
pub fn find_weak_federation_trusts(
    role_trust_policies: &[(&str, &str)],
) -> Result<Vec<FederationTrust>, String> {
    let mut weak_trusts = Vec::new();

    for (role_arn, policy_json) in role_trust_policies {
        let trusts = extract_federation_trusts(policy_json, role_arn)?;
        for trust in trusts {
            if trust.weakness.is_some() {
                weak_trusts.push(trust);
            }
        }
    }

    Ok(weak_trusts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_saml_principal() {
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:saml-provider/Okta"
                },
                "Action": "sts:AssumeRoleWithSAML",
                "Condition": {
                    "StringEquals": {
                        "SAML:aud": "https://signin.aws.amazon.com/saml"
                    }
                }
            }]
        });

        let trusts = extract_federation_trusts(
            &policy.to_string(),
            "arn:aws:iam::123456789012:role/FederatedRole",
        )
        .unwrap();
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0].provider_type, FederationProviderType::Saml);
        assert!(!trusts[0].conditions.is_empty());
    }

    #[test]
    fn test_extract_oidc_principal() {
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.example.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "oidc.example.com:aud": "my-app-id"
                    }
                }
            }]
        });

        let trusts = extract_federation_trusts(
            &policy.to_string(),
            "arn:aws:iam::123456789012:role/OIDCRole",
        )
        .unwrap();
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0].provider_type, FederationProviderType::Oidc);
    }

    #[test]
    fn test_saml_with_aud_and_sub_conditions() {
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:saml-provider/Okta"
                },
                "Action": "sts:AssumeRoleWithSAML",
                "Condition": {
                    "StringEquals": {
                        "SAML:aud": "https://signin.aws.amazon.com/saml",
                        "SAML:sub": "user@example.com"
                    }
                }
            }]
        });

        let trusts = extract_federation_trusts(
            &policy.to_string(),
            "arn:aws:iam::123456789012:role/FederatedRole",
        )
        .unwrap();
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0].weakness, None);
    }

    #[test]
    fn test_saml_missing_subject_condition() {
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:saml-provider/Okta"
                },
                "Action": "sts:AssumeRoleWithSAML",
                "Condition": {
                    "StringEquals": {
                        "SAML:aud": "https://signin.aws.amazon.com/saml"
                    }
                }
            }]
        });

        let trusts = extract_federation_trusts(
            &policy.to_string(),
            "arn:aws:iam::123456789012:role/FederatedRole",
        )
        .unwrap();
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0].weakness, Some(FederationWeakness::MissingSubject));
    }

    #[test]
    fn test_saml_missing_audience_condition() {
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:saml-provider/Okta"
                },
                "Action": "sts:AssumeRoleWithSAML",
                "Condition": {
                    "StringEquals": {
                        "SAML:sub": "user@example.com"
                    }
                }
            }]
        });

        let trusts = extract_federation_trusts(
            &policy.to_string(),
            "arn:aws:iam::123456789012:role/FederatedRole",
        )
        .unwrap();
        assert_eq!(trusts.len(), 1);
        assert_eq!(
            trusts[0].weakness,
            Some(FederationWeakness::MissingAudience)
        );
    }

    #[test]
    fn test_saml_missing_both_conditions() {
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:saml-provider/Okta"
                },
                "Action": "sts:AssumeRoleWithSAML"
            }]
        });

        let trusts = extract_federation_trusts(
            &policy.to_string(),
            "arn:aws:iam::123456789012:role/FederatedRole",
        )
        .unwrap();
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0].weakness, Some(FederationWeakness::NoConditions));
    }

    #[test]
    fn test_no_federation_principals() {
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }]
        });

        let trusts =
            extract_federation_trusts(&policy.to_string(), "arn:aws:iam::123456789012:role/Lambda")
                .unwrap();
        assert_eq!(trusts.len(), 0);
    }

    #[test]
    fn test_deny_statement_skipped() {
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:saml-provider/Okta"
                },
                "Action": "sts:AssumeRoleWithSAML"
            }]
        });

        let trusts = extract_federation_trusts(
            &policy.to_string(),
            "arn:aws:iam::123456789012:role/FederatedRole",
        )
        .unwrap();
        assert_eq!(trusts.len(), 0);
    }

    #[test]
    fn test_multiple_federation_principals() {
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Federated": [
                        "arn:aws:iam::123456789012:saml-provider/Okta",
                        "arn:aws:iam::123456789012:saml-provider/Azure"
                    ]
                },
                "Action": "sts:AssumeRoleWithSAML"
            }]
        });

        let trusts = extract_federation_trusts(
            &policy.to_string(),
            "arn:aws:iam::123456789012:role/FederatedRole",
        )
        .unwrap();
        assert_eq!(trusts.len(), 2);
        assert!(trusts
            .iter()
            .all(|t| t.weakness == Some(FederationWeakness::NoConditions)));
    }

    #[test]
    fn test_oidc_with_aud_and_sub() {
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.example.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "oidc.example.com:aud": "my-app-id",
                        "oidc.example.com:sub": "repo:myorg/myrepo"
                    }
                }
            }]
        });

        let trusts = extract_federation_trusts(
            &policy.to_string(),
            "arn:aws:iam::123456789012:role/GHARole",
        )
        .unwrap();
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0].weakness, None);
    }

    #[test]
    fn test_find_weak_federation_trusts() {
        let policies = vec![
            (
                "arn:aws:iam::123456789012:role/Role1",
                r#"{
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Federated": "arn:aws:iam::123456789012:saml-provider/Okta"},
                        "Action": "sts:AssumeRoleWithSAML"
                    }]
                }"#,
            ),
            (
                "arn:aws:iam::123456789012:role/Role2",
                r#"{
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Federated": "arn:aws:iam::123456789012:saml-provider/Azure"},
                        "Action": "sts:AssumeRoleWithSAML",
                        "Condition": {
                            "StringEquals": {
                                "SAML:aud": "https://signin.aws.amazon.com/saml",
                                "SAML:sub": "user@example.com"
                            }
                        }
                    }]
                }"#,
            ),
        ];

        let weak_trusts = find_weak_federation_trusts(&policies).unwrap();
        assert_eq!(weak_trusts.len(), 1);
        assert!(weak_trusts[0].role_arn.contains("Role1"));
    }

    #[test]
    fn test_saml_namequalifier_as_subject() {
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:saml-provider/Okta"
                },
                "Action": "sts:AssumeRoleWithSAML",
                "Condition": {
                    "StringEquals": {
                        "SAML:aud": "https://signin.aws.amazon.com/saml",
                        "SAML:namequalifier": "urn:amazon:webservices"
                    }
                }
            }]
        });

        let trusts = extract_federation_trusts(
            &policy.to_string(),
            "arn:aws:iam::123456789012:role/FederatedRole",
        )
        .unwrap();
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0].weakness, None);
    }

    #[test]
    fn test_complex_policy_multiple_statements() {
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::123456789012:saml-provider/Okta"
                    },
                    "Action": "sts:AssumeRoleWithSAML",
                    "Condition": {
                        "StringEquals": {
                            "SAML:aud": "https://signin.aws.amazon.com/saml"
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.example.com"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "oidc.example.com:aud": "my-app",
                            "oidc.example.com:sub": "repo:myorg/myrepo"
                        }
                    }
                }
            ]
        });

        let trusts =
            extract_federation_trusts(&policy.to_string(), "arn:aws:iam::123456789012:role/Multi")
                .unwrap();
        assert_eq!(trusts.len(), 2);
        assert_eq!(trusts[0].weakness, Some(FederationWeakness::MissingSubject));
        assert_eq!(trusts[1].weakness, None);
    }

    #[test]
    fn test_invalid_json() {
        let result =
            extract_federation_trusts("not valid json", "arn:aws:iam::123456789012:role/Test");
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_statement() {
        let policy = json!({
            "Version": "2012-10-17"
        });

        let result =
            extract_federation_trusts(&policy.to_string(), "arn:aws:iam::123456789012:role/Test");
        assert!(result.is_err());
    }
}
