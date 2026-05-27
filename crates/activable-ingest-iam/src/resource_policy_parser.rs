//! Resource-based policy parser.
//!
//! Parses resource-based policy JSON (from AWS services like S3, SNS, SQS, KMS, Lambda)
//! and extracts Principal information alongside standard policy structure.
//!
//! Resource policies use the same JSON format as identity policies, with the addition
//! of a `Principal` field in each statement that specifies who can access the resource.

use serde_json::Value;

use crate::error::{PolicyParseError, PolicyParseResult};
use crate::policy_parser::parse_policy;
use crate::types::ParsedPolicy;

/// A resource-based policy with its associated resource and service information.
#[derive(Debug, Clone)]
pub struct ResourcePolicy {
    /// The ARN of the resource this policy applies to (e.g., "arn:aws:s3:::my-bucket")
    pub resource_arn: String,
    /// The service type (e.g., "s3", "sns", "sqs", "kms", "lambda")
    pub service_type: String,
    /// The parsed policy containing Action, Resource, Effect, Condition
    pub policy: ParsedPolicy,
    /// Principals extracted from all statements in the policy
    pub principals: Vec<PolicyPrincipal>,
}

/// A principal referenced in a resource-based policy statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyPrincipal {
    /// Specific principal ARN (e.g., "arn:aws:iam::123456789012:role/MyRole")
    Arn(String),
    /// AWS account root (e.g., "arn:aws:iam::123456789012:root")
    AccountRoot(String),
    /// AWS service principal (e.g., "s3.amazonaws.com", "lambda.amazonaws.com")
    Service(String),
    /// Wildcard principal — grants access to any authenticated principal
    Wildcard,
    /// Federated identity provider
    Federated(String),
}

impl PolicyPrincipal {
    /// Extract the account ID from this principal, if applicable.
    pub fn account_id(&self) -> Option<&str> {
        match self {
            PolicyPrincipal::Arn(arn) | PolicyPrincipal::AccountRoot(arn) => {
                crate::resource_policy_evaluator::extract_account_from_arn(arn)
            }
            _ => None,
        }
    }

    /// Return true if this principal is a wildcard (grants to everyone).
    pub fn is_wildcard(&self) -> bool {
        matches!(self, PolicyPrincipal::Wildcard)
    }

    /// Return true if this principal is account-scoped (account root or all roles/users in account).
    pub fn is_account_scoped(&self) -> bool {
        matches!(self, PolicyPrincipal::AccountRoot(_))
    }
}

/// Parse a resource-based policy JSON string.
///
/// # Arguments
/// * `policy_json` - The policy document as a JSON string
/// * `resource_arn` - The ARN of the resource this policy applies to
/// * `service_type` - The AWS service type (e.g., "s3", "sns", "sqs", "kms", "lambda")
///
/// # Returns
/// A `ResourcePolicy` containing the parsed policy and extracted principals
///
/// # Errors
/// Returns `PolicyParseError` if:
/// - The JSON is invalid
/// - Required fields (Version, Statement) are missing
/// - Policy structure is malformed
pub fn parse_resource_policy(
    policy_json: &str,
    resource_arn: &str,
    service_type: &str,
) -> PolicyParseResult<ResourcePolicy> {
    // First, parse the core policy structure using the standard parser
    let policy = parse_policy(policy_json)?;

    // Then, extract principals from the JSON manually
    let principals = extract_principals_from_json(policy_json)?;

    Ok(ResourcePolicy {
        resource_arn: resource_arn.to_string(),
        service_type: service_type.to_string(),
        policy,
        principals,
    })
}

/// Extract all principals from a resource policy JSON document.
fn extract_principals_from_json(policy_json: &str) -> PolicyParseResult<Vec<PolicyPrincipal>> {
    let value: Value = serde_json::from_str(policy_json)?;
    let obj = value
        .as_object()
        .ok_or_else(|| PolicyParseError::MissingField("root must be an object".to_string()))?;

    let statements_array = obj
        .get("Statement")
        .and_then(|v| v.as_array())
        .ok_or_else(|| PolicyParseError::MissingField("Statement".to_string()))?;

    let mut all_principals = Vec::new();

    for stmt in statements_array {
        let stmt_obj = stmt.as_object().ok_or_else(|| {
            PolicyParseError::InvalidStatement("statement must be an object".to_string())
        })?;

        if let Some(principal_value) = stmt_obj.get("Principal") {
            let stmts = extract_principal_value(principal_value)?;
            all_principals.extend(stmts);
        }
    }

    // Deduplicate principals
    all_principals.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));
    all_principals.dedup();

    Ok(all_principals)
}

/// Extract principals from a Principal field value.
///
/// Principal can be:
/// - A string (e.g., "*", "arn:aws:iam::123456789012:root", "s3.amazonaws.com")
/// - An object with keys like "AWS", "Service", "Federated"
/// - An array of strings (for some services)
fn extract_principal_value(value: &Value) -> PolicyParseResult<Vec<PolicyPrincipal>> {
    match value {
        Value::String(s) => Ok(vec![parse_principal_string(s)]),
        Value::Object(obj) => {
            let mut principals = Vec::new();

            // AWS principals (IAM ARNs)
            if let Some(aws_val) = obj.get("AWS") {
                for principal_str in extract_string_or_array(aws_val) {
                    principals.push(parse_principal_string(&principal_str));
                }
            }

            // Service principals
            if let Some(svc_val) = obj.get("Service") {
                for svc_str in extract_string_or_array(svc_val) {
                    principals.push(PolicyPrincipal::Service(svc_str));
                }
            }

            // Federated principals
            if let Some(fed_val) = obj.get("Federated") {
                for fed_str in extract_string_or_array(fed_val) {
                    principals.push(PolicyPrincipal::Federated(fed_str));
                }
            }

            Ok(principals)
        }
        Value::Array(arr) => {
            let mut principals = Vec::new();
            for item in arr {
                if let Value::String(s) = item {
                    principals.push(parse_principal_string(s));
                }
            }
            Ok(principals)
        }
        _ => Err(PolicyParseError::InvalidStatement(
            "Principal must be a string or object".to_string(),
        )),
    }
}

/// Parse a principal string into the appropriate PolicyPrincipal variant.
fn parse_principal_string(s: &str) -> PolicyPrincipal {
    match s {
        "*" => PolicyPrincipal::Wildcard,
        s if s.ends_with(":root") && s.starts_with("arn:") => {
            PolicyPrincipal::AccountRoot(s.to_string())
        }
        s if s.starts_with("arn:") => PolicyPrincipal::Arn(s.to_string()),
        s if s.contains(".amazonaws.com") => PolicyPrincipal::Service(s.to_string()),
        s => PolicyPrincipal::Federated(s.to_string()), // Default to federated for unknown formats
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_s3_bucket_policy_with_specific_principal() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/CrossAccountRole"
                    },
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        }"#;

        let result = parse_resource_policy(policy_json, "arn:aws:s3:::my-bucket", "s3")
            .expect("Failed to parse policy");

        assert_eq!(result.resource_arn, "arn:aws:s3:::my-bucket");
        assert_eq!(result.service_type, "s3");
        assert_eq!(result.principals.len(), 1);
        assert!(matches!(
            result.principals[0],
            PolicyPrincipal::Arn(ref s) if s == "arn:aws:iam::123456789012:role/CrossAccountRole"
        ));
    }

    #[test]
    fn parse_s3_bucket_policy_with_wildcard_principal() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        }"#;

        let result = parse_resource_policy(policy_json, "arn:aws:s3:::my-bucket", "s3")
            .expect("Failed to parse policy");

        assert_eq!(result.principals.len(), 1);
        assert!(matches!(result.principals[0], PolicyPrincipal::Wildcard));
    }

    #[test]
    fn parse_s3_bucket_policy_with_account_root() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:root"
                    },
                    "Action": "s3:*",
                    "Resource": "*"
                }
            ]
        }"#;

        let result = parse_resource_policy(policy_json, "arn:aws:s3:::my-bucket", "s3")
            .expect("Failed to parse policy");

        assert_eq!(result.principals.len(), 1);
        assert!(matches!(
            result.principals[0],
            PolicyPrincipal::AccountRoot(ref s) if s == "arn:aws:iam::123456789012:root"
        ));
    }

    #[test]
    fn parse_sns_topic_policy_with_service_principal() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "lambda.amazonaws.com"
                    },
                    "Action": "sns:Publish",
                    "Resource": "arn:aws:sns:us-east-1:123456789012:my-topic"
                }
            ]
        }"#;

        let result = parse_resource_policy(
            policy_json,
            "arn:aws:sns:us-east-1:123456789012:my-topic",
            "sns",
        )
        .expect("Failed to parse policy");

        assert_eq!(result.principals.len(), 1);
        assert!(matches!(
            result.principals[0],
            PolicyPrincipal::Service(ref s) if s == "lambda.amazonaws.com"
        ));
    }

    #[test]
    fn parse_policy_with_multiple_principals_in_statement() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::123456789012:role/RoleA",
                            "arn:aws:iam::987654321098:role/RoleB"
                        ]
                    },
                    "Action": "s3:GetObject",
                    "Resource": "*"
                }
            ]
        }"#;

        let result = parse_resource_policy(policy_json, "arn:aws:s3:::my-bucket", "s3")
            .expect("Failed to parse policy");

        assert_eq!(result.principals.len(), 2);
    }

    #[test]
    fn parse_policy_with_multiple_statements() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/RoleA"
                    },
                    "Action": "s3:GetObject",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Principal": {
                        "AWS": "arn:aws:iam::987654321098:role/RoleB"
                    },
                    "Action": "s3:*",
                    "Resource": "*"
                }
            ]
        }"#;

        let result = parse_resource_policy(policy_json, "arn:aws:s3:::my-bucket", "s3")
            .expect("Failed to parse policy");

        assert_eq!(result.principals.len(), 2);
    }

    #[test]
    fn parse_policy_with_mixed_principal_types() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/MyRole",
                        "Service": "s3.amazonaws.com"
                    },
                    "Action": "sns:Publish",
                    "Resource": "*"
                }
            ]
        }"#;

        let result = parse_resource_policy(
            policy_json,
            "arn:aws:sns:us-east-1:123456789012:my-topic",
            "sns",
        )
        .expect("Failed to parse policy");

        assert_eq!(result.principals.len(), 2);
    }

    #[test]
    fn parse_kms_key_policy() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Enable IAM policies",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:root"
                    },
                    "Action": "kms:*",
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::987654321098:role/CrossAccountKMS"
                    },
                    "Action": [
                        "kms:Decrypt",
                        "kms:DescribeKey"
                    ],
                    "Resource": "*"
                }
            ]
        }"#;

        let result = parse_resource_policy(
            policy_json,
            "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            "kms",
        )
        .expect("Failed to parse policy");

        assert_eq!(result.principals.len(), 2);
        assert!(result.principals[0].is_account_scoped());
        assert!(!result.principals[1].is_account_scoped());
    }

    #[test]
    fn parse_lambda_function_policy() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "apigateway.amazonaws.com"
                    },
                    "Action": "lambda:InvokeFunction",
                    "Resource": "arn:aws:lambda:us-east-1:123456789012:function:MyFunction"
                }
            ]
        }"#;

        let result = parse_resource_policy(
            policy_json,
            "arn:aws:lambda:us-east-1:123456789012:function:MyFunction",
            "lambda",
        )
        .expect("Failed to parse policy");

        assert_eq!(result.principals.len(), 1);
        assert!(matches!(result.principals[0], PolicyPrincipal::Service(_)));
    }

    #[test]
    fn principal_account_id_extraction() {
        let principal = PolicyPrincipal::Arn("arn:aws:iam::123456789012:role/MyRole".to_string());
        assert_eq!(principal.account_id(), Some("123456789012"));
    }

    #[test]
    fn account_root_account_id_extraction() {
        let principal = PolicyPrincipal::AccountRoot("arn:aws:iam::999888777666:root".to_string());
        assert_eq!(principal.account_id(), Some("999888777666"));
    }

    #[test]
    fn service_principal_no_account_id() {
        let principal = PolicyPrincipal::Service("s3.amazonaws.com".to_string());
        assert_eq!(principal.account_id(), None);
    }

    #[test]
    fn wildcard_principal_is_wildcard() {
        let principal = PolicyPrincipal::Wildcard;
        assert!(principal.is_wildcard());
    }

    #[test]
    fn account_root_is_account_scoped() {
        let principal = PolicyPrincipal::AccountRoot("arn:aws:iam::123456789012:root".to_string());
        assert!(principal.is_account_scoped());
    }

    #[test]
    fn invalid_json_returns_error() {
        let result = parse_resource_policy("invalid json", "arn:aws:s3:::bucket", "s3");
        assert!(result.is_err());
    }

    #[test]
    fn missing_statement_returns_error() {
        let policy_json = r#"{"Version": "2012-10-17"}"#;
        let result = parse_resource_policy(policy_json, "arn:aws:s3:::bucket", "s3");
        assert!(result.is_err());
    }

    #[test]
    fn parse_policy_with_no_principal_in_statement() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        }"#;

        let result = parse_resource_policy(policy_json, "arn:aws:s3:::my-bucket", "s3")
            .expect("Failed to parse policy");

        // Statement with no Principal should result in empty principals list
        assert_eq!(result.principals.len(), 0);
    }

    #[test]
    fn duplicate_principals_are_deduplicated() {
        let policy_json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::123456789012:role/MyRole",
                            "arn:aws:iam::123456789012:role/MyRole"
                        ]
                    },
                    "Action": "s3:GetObject",
                    "Resource": "*"
                }
            ]
        }"#;

        let result = parse_resource_policy(policy_json, "arn:aws:s3:::my-bucket", "s3")
            .expect("Failed to parse policy");

        // Should have only 1 principal after deduplication
        assert_eq!(result.principals.len(), 1);
    }
}
