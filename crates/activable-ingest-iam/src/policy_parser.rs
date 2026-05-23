//! IAM policy JSON parser with validation for AWS quirks.

use serde_json::Value;

use crate::error::{PolicyParseError, PolicyParseResult};
use crate::types::{
    ActionPattern, Condition, Effect, ParsedPolicy, PolicyStatement, ResourcePattern,
};

/// Parse a JSON string into a structured IAM policy with full validation.
///
/// Handles AWS policy quirks:
/// - `Action` and `NotAction` can be strings or arrays
/// - `Resource` and `NotResource` can be strings or arrays
/// - `Condition` block is a nested object structure
///
/// Validates:
/// - Both `Version` and `Statement` fields are present
/// - No statement has both `Action` and `NotAction`
/// - No statement has both `Resource` and `NotResource`
/// - Effect is exactly "Allow" or "Deny"
pub fn parse_policy(json: &str) -> PolicyParseResult<ParsedPolicy> {
    let value: Value = serde_json::from_str(json)?;

    // Require top-level object
    let obj = value
        .as_object()
        .ok_or_else(|| PolicyParseError::MissingField("root must be an object".to_string()))?;

    // Require Version field
    let version = obj
        .get("Version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PolicyParseError::MissingField("Version".to_string()))?
        .to_string();

    // Require Statement field
    let statements_value = obj
        .get("Statement")
        .ok_or_else(|| PolicyParseError::MissingField("Statement".to_string()))?;

    let statements_array = statements_value.as_array().ok_or_else(|| {
        PolicyParseError::InvalidStatement("Statement must be an array".to_string())
    })?;

    let mut statements = Vec::new();
    for (idx, stmt_value) in statements_array.iter().enumerate() {
        let stmt = parse_statement(stmt_value).map_err(|e| {
            PolicyParseError::InvalidStatement(format!("Statement[{}]: {}", idx, e))
        })?;
        statements.push(stmt);
    }

    Ok(ParsedPolicy {
        version,
        statements,
    })
}

/// Parse a single statement object.
fn parse_statement(value: &Value) -> PolicyParseResult<PolicyStatement> {
    let obj = value.as_object().ok_or_else(|| {
        PolicyParseError::InvalidStatement("statement must be an object".to_string())
    })?;

    // Parse Effect (required)
    let effect_str = obj
        .get("Effect")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PolicyParseError::MissingField("Effect".to_string()))?;

    let effect = match effect_str {
        "Allow" => Effect::Allow,
        "Deny" => Effect::Deny,
        other => {
            return Err(PolicyParseError::InvalidEffect(other.to_string()));
        }
    };

    // Parse Sid (optional)
    let sid = obj
        .get("Sid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Parse Action / NotAction (at least one, mutually exclusive)
    let actions = parse_action_field(obj.get("Action"))?;
    let not_actions = parse_action_field(obj.get("NotAction"))?;

    if !actions.is_empty() && !not_actions.is_empty() {
        return Err(PolicyParseError::ActionAndNotActionTogether);
    }
    if actions.is_empty() && not_actions.is_empty() {
        return Err(PolicyParseError::InvalidStatement(
            "must have Action or NotAction".to_string(),
        ));
    }

    // Parse Resource / NotResource (at least one, mutually exclusive)
    let resources = parse_resource_field(obj.get("Resource"))?;
    let not_resources = parse_resource_field(obj.get("NotResource"))?;

    if !resources.is_empty() && !not_resources.is_empty() {
        return Err(PolicyParseError::ResourceAndNotResourceTogether);
    }
    if resources.is_empty() && not_resources.is_empty() {
        return Err(PolicyParseError::InvalidStatement(
            "must have Resource or NotResource".to_string(),
        ));
    }

    // Parse Condition (optional)
    let conditions = parse_conditions(obj.get("Condition"))?;

    Ok(PolicyStatement {
        sid,
        effect,
        actions,
        not_actions,
        resources,
        not_resources,
        conditions,
    })
}

/// Parse Action field: can be a string or array of strings.
fn parse_action_field(value: Option<&Value>) -> PolicyParseResult<Vec<ActionPattern>> {
    match value {
        None => Ok(Vec::new()),
        Some(v) => match v {
            Value::String(s) => Ok(vec![ActionPattern(s.clone())]),
            Value::Array(arr) => {
                let mut patterns = Vec::new();
                for item in arr {
                    if let Some(s) = item.as_str() {
                        patterns.push(ActionPattern(s.to_string()));
                    } else {
                        return Err(PolicyParseError::InvalidStatement(
                            "Action array items must be strings".to_string(),
                        ));
                    }
                }
                Ok(patterns)
            }
            _ => Err(PolicyParseError::InvalidStatement(
                "Action must be a string or array".to_string(),
            )),
        },
    }
}

/// Parse Resource field: can be a string or array of strings.
fn parse_resource_field(value: Option<&Value>) -> PolicyParseResult<Vec<ResourcePattern>> {
    match value {
        None => Ok(Vec::new()),
        Some(v) => match v {
            Value::String(s) => Ok(vec![ResourcePattern(s.clone())]),
            Value::Array(arr) => {
                let mut patterns = Vec::new();
                for item in arr {
                    if let Some(s) = item.as_str() {
                        patterns.push(ResourcePattern(s.to_string()));
                    } else {
                        return Err(PolicyParseError::InvalidStatement(
                            "Resource array items must be strings".to_string(),
                        ));
                    }
                }
                Ok(patterns)
            }
            _ => Err(PolicyParseError::InvalidStatement(
                "Resource must be a string or array".to_string(),
            )),
        },
    }
}

/// Parse Condition block: outer key = operator, inner key = condition key, value = string or array.
fn parse_conditions(value: Option<&Value>) -> PolicyParseResult<Vec<Condition>> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Object(operators)) => {
            let mut conditions = Vec::new();
            for (operator, condition_block) in operators {
                if let Some(cond_obj) = condition_block.as_object() {
                    for (key, values) in cond_obj {
                        let value_list = match values {
                            Value::String(s) => vec![s.clone()],
                            Value::Array(arr) => {
                                let mut list = Vec::new();
                                for item in arr {
                                    if let Some(s) = item.as_str() {
                                        list.push(s.to_string());
                                    } else {
                                        return Err(PolicyParseError::InvalidStatement(
                                            "Condition values must be strings or arrays of strings"
                                                .to_string(),
                                        ));
                                    }
                                }
                                list
                            }
                            _ => {
                                return Err(PolicyParseError::InvalidStatement(
                                    "Condition values must be strings or arrays".to_string(),
                                ))
                            }
                        };

                        conditions.push(Condition {
                            operator: operator.clone(),
                            key: key.clone(),
                            values: value_list,
                        });
                    }
                } else {
                    return Err(PolicyParseError::InvalidStatement(
                        "Condition operator value must be an object".to_string(),
                    ));
                }
            }
            Ok(conditions)
        }
        Some(_) => Err(PolicyParseError::InvalidStatement(
            "Condition must be an object".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Test group 1: Parse simple Allow policy =====

    #[test]
    fn parse_simple_allow_policy() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }]
        }"#;
        let policy = parse_policy(json).unwrap();
        assert_eq!(policy.statements.len(), 1);
        assert_eq!(policy.statements[0].effect, Effect::Allow);
        assert_eq!(policy.statements[0].actions.len(), 1);
        assert_eq!(policy.statements[0].actions[0].0, "s3:GetObject");
    }

    // ===== Test group 2: Parse multi-statement with Deny =====

    #[test]
    fn parse_deny_with_conditions() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*",
                 "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}}}
            ]
        }"#;
        let policy = parse_policy(json).unwrap();
        assert_eq!(policy.statements.len(), 2);
        assert_eq!(policy.statements[1].effect, Effect::Deny);
        assert_eq!(policy.statements[1].conditions.len(), 1);
        assert_eq!(
            policy.statements[1].conditions[0].operator,
            "StringNotEquals"
        );
    }

    // ===== Test group 3: Parse NotAction / NotResource =====

    #[test]
    fn parse_not_action() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "NotAction": ["iam:ChangePassword", "iam:GetUser"],
                "Resource": "*"
            }]
        }"#;
        let policy = parse_policy(json).unwrap();
        assert!(policy.statements[0].actions.is_empty());
        assert_eq!(policy.statements[0].not_actions.len(), 2);
    }

    // ===== Test group 6: Malformed input handling =====

    #[test]
    fn parse_empty_json_returns_error() {
        assert!(parse_policy("{}").is_err());
    }

    #[test]
    fn parse_invalid_json_returns_error() {
        assert!(parse_policy("not json").is_err());
    }

    #[test]
    fn parse_action_as_string_and_array() {
        // AWS allows Action as both string and array
        let single = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
        let array = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}"#;
        assert_eq!(parse_policy(single).unwrap().statements[0].actions.len(), 1);
        assert_eq!(parse_policy(array).unwrap().statements[0].actions.len(), 1);
    }

    // ===== Validation tests (red-team amendment) =====

    #[test]
    fn reject_action_and_not_action_together() {
        let json = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","NotAction":"iam:*","Resource":"*"}]}"#;
        assert!(parse_policy(json).is_err());
    }

    #[test]
    fn reject_resource_and_not_resource_together() {
        let json = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","NotResource":"arn:aws:s3:::secret"}]}"#;
        assert!(parse_policy(json).is_err());
    }

    #[test]
    fn reject_unknown_effect() {
        let json = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Action":"s3:*","Resource":"*"}]}"#;
        assert!(parse_policy(json).is_err());
    }

    #[test]
    fn reject_missing_version() {
        let json = r#"{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;
        assert!(parse_policy(json).is_err());
    }

    #[test]
    fn reject_missing_statement() {
        let json = r#"{"Version":"2012-10-17"}"#;
        assert!(parse_policy(json).is_err());
    }

    #[test]
    fn reject_missing_action_and_not_action() {
        let json = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Resource":"*"}]}"#;
        assert!(parse_policy(json).is_err());
    }

    #[test]
    fn reject_missing_resource_and_not_resource() {
        let json = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*"}]}"#;
        assert!(parse_policy(json).is_err());
    }
}
