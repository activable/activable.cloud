//! Resource-policy parser (S3 bucket policies, KMS key policies).
//! Extracts (principal, action_set, condition_keys, wildcard?) tuples
//! from each Allow statement.

use serde_json::Value;

#[cfg(test)]
use serde_json::json;

#[derive(Debug, Clone)]
pub struct ParsedStatement {
    pub effect: String,
    pub principals: Vec<String>, // ARNs (or "*" if wildcard)
    pub actions: Vec<String>,
    pub condition_keys: Vec<String>,
    pub wildcard_principal: bool,
}

/// Parse a resource policy document and extract allow statements with principals + actions.
pub fn parse_resource_policy(policy_doc: &str) -> Result<Vec<ParsedStatement>, serde_json::Error> {
    let policy: Value = serde_json::from_str(policy_doc)?;

    let mut statements = Vec::new();

    if let Some(stmt_array) = policy.get("Statement").and_then(|s| s.as_array()) {
        for stmt in stmt_array {
            let effect = stmt
                .get("Effect")
                .and_then(|e| e.as_str())
                .unwrap_or("Allow")
                .to_string();

            // Skip Deny statements
            if effect == "Deny" {
                continue;
            }

            // Extract principals
            let mut principals: Vec<String> = Vec::new();
            let mut wildcard_principal = false;

            if let Some(principal_val) = stmt.get("Principal") {
                match principal_val {
                    Value::String(s) => {
                        if s == "*" {
                            wildcard_principal = true;
                            principals.push("*".to_string());
                        } else {
                            principals.push(s.clone());
                        }
                    }
                    Value::Object(obj) => {
                        // "Principal": { "AWS": [...], "Service": [...], ... }
                        for (_key, val) in obj.iter() {
                            match val {
                                Value::String(s) => {
                                    if s == "*" {
                                        wildcard_principal = true;
                                    }
                                    principals.push(s.clone());
                                }
                                Value::Array(arr) => {
                                    for v in arr {
                                        if let Value::String(s) = v {
                                            if s == "*" {
                                                wildcard_principal = true;
                                            }
                                            principals.push(s.clone());
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Value::Array(arr) => {
                        for v in arr {
                            if let Value::String(s) = v {
                                if s == "*" {
                                    wildcard_principal = true;
                                }
                                principals.push(s.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Extract actions
            let mut actions: Vec<String> = Vec::new();
            if let Some(action_val) = stmt.get("Action") {
                match action_val {
                    Value::String(s) => actions.push(s.clone()),
                    Value::Array(arr) => {
                        for v in arr {
                            if let Value::String(s) = v {
                                actions.push(s.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Extract condition keys from nested objects in Condition
            // Condition format: { "StringEquals": { "key1": "val", ... }, ... }
            let mut condition_keys: Vec<String> = Vec::new();
            if let Some(condition_obj) = stmt.get("Condition").and_then(|c| c.as_object()) {
                for (_operator, keys_obj) in condition_obj.iter() {
                    if let Some(keys_map) = keys_obj.as_object() {
                        for key in keys_map.keys() {
                            condition_keys.push(key.clone());
                        }
                    }
                }
            }

            if !principals.is_empty() && !actions.is_empty() {
                statements.push(ParsedStatement {
                    effect,
                    principals,
                    actions,
                    condition_keys,
                    wildcard_principal,
                });
            }
        }
    }

    Ok(statements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_s3_bucket_policy_with_org_id() {
        let policy_doc = r#"{
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

        let result = parse_resource_policy(policy_doc).unwrap();
        assert_eq!(result.len(), 1);
        let stmt = &result[0];
        assert_eq!(stmt.effect, "Allow");
        assert!(stmt.wildcard_principal);
        assert_eq!(stmt.principals, vec!["*"]);
        assert!(stmt.actions.contains(&"s3:GetObject".to_string()));
        assert!(stmt
            .condition_keys
            .contains(&"aws:PrincipalOrgID".to_string()));
    }

    #[test]
    fn test_parse_kms_key_policy_with_create_grant() {
        let policy_doc = r#"{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AdminManagement",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::444444444444:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowAppAccountGrants",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:root"
      },
      "Action": [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ],
      "Resource": "*"
    }
  ]
}"#;

        let result = parse_resource_policy(policy_doc).unwrap();
        assert_eq!(result.len(), 2);

        let grant_stmt = &result[1];
        assert_eq!(grant_stmt.effect, "Allow");
        assert_eq!(
            grant_stmt.principals,
            vec!["arn:aws:iam::111111111111:root"]
        );
        assert!(grant_stmt.actions.contains(&"kms:CreateGrant".to_string()));
    }

    #[test]
    fn test_cap_50_principals_explicit_list() {
        let mut principals = vec![];
        for i in 0..60 {
            principals.push(format!("arn:aws:iam::111111111111:role/role-{}", i));
        }

        let stmt_json = json!({
            "Sid": "ManyPrincipals",
            "Effect": "Allow",
            "Principal": {
                "AWS": principals
            },
            "Action": "s3:*",
            "Resource": "*"
        });

        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [stmt_json]
        });

        let result = parse_resource_policy(&policy.to_string()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].principals.len(), 60);
        assert!(!result[0].wildcard_principal);
    }
}
