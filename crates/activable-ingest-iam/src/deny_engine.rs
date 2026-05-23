//! Deny engine for IAM policy evaluation.
//!
//! Implements explicit Deny override semantics. Deny statements block actions,
//! even if Allow statements permit them.
//!
//! Handles:
//! - Deny with Action: deny if action matches any pattern
//! - Deny with NotAction: deny if action does NOT match any pattern (inversion!)
//! - Deny with Resource: deny if resource matches
//! - Deny with NotResource: deny if resource does NOT match
//! - Deny with Conditions: only deny if ALL conditions evaluate to true

use crate::action_matcher::action_matches;
use crate::condition_evaluator::evaluate_condition;
use crate::eval_context::EvalContext;
use crate::resource_matcher::resource_matches;
use crate::types::{Effect, PolicyStatement};

/// Result of deny evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalResult {
    /// An explicit Deny statement matched.
    ExplicitDeny,
    /// No explicit Deny statement matched.
    NoExplicitDeny,
}

/// Evaluate Deny statements against an action+resource pair (without conditions).
///
/// Returns `ExplicitDeny` if ANY Deny statement matches.
///
/// # Arguments
/// - `statements`: The policy statements to evaluate
/// - `action`: The action being evaluated (e.g., "s3:GetObject")
/// - `resource`: The resource ARN being evaluated
pub fn evaluate_deny(statements: &[PolicyStatement], action: &str, resource: &str) -> EvalResult {
    let context = EvalContext::default();
    evaluate_deny_with_context(statements, action, resource, &context)
}

/// Evaluate Deny statements against an action+resource pair WITH condition context.
///
/// Returns `ExplicitDeny` if ANY Deny statement matches (actions/resources match
/// AND all conditions evaluate to true).
///
/// # Arguments
/// - `statements`: The policy statements to evaluate
/// - `action`: The action being evaluated
/// - `resource`: The resource ARN being evaluated
/// - `context`: Evaluation context (region, IP, etc.)
pub fn evaluate_deny_with_context(
    statements: &[PolicyStatement],
    action: &str,
    resource: &str,
    context: &EvalContext,
) -> EvalResult {
    for stmt in statements {
        // Only evaluate Deny statements
        if stmt.effect != Effect::Deny {
            continue;
        }

        // Check if action matches
        let action_matches_result = if !stmt.not_actions.is_empty() {
            // NotAction: deny if action does NOT match any pattern
            !stmt
                .not_actions
                .iter()
                .any(|pattern| action_matches(&pattern.0, action))
        } else if !stmt.actions.is_empty() {
            // Action: deny if action matches any pattern
            stmt.actions
                .iter()
                .any(|pattern| action_matches(&pattern.0, action))
        } else {
            // No Action or NotAction specified: match everything
            true
        };

        if !action_matches_result {
            continue;
        }

        // Check if resource matches
        let resource_matches_result = if !stmt.not_resources.is_empty() {
            // NotResource: deny if resource does NOT match any pattern
            !stmt
                .not_resources
                .iter()
                .any(|pattern| resource_matches(&pattern.0, resource))
        } else if !stmt.resources.is_empty() {
            // Resource: deny if resource matches any pattern
            stmt.resources
                .iter()
                .any(|pattern| resource_matches(&pattern.0, resource))
        } else {
            // No Resource or NotResource specified: match everything
            true
        };

        if !resource_matches_result {
            continue;
        }

        // Check if conditions match (all must be true)
        let conditions_match = if stmt.conditions.is_empty() {
            // No conditions: always match
            true
        } else {
            // All conditions must evaluate to true
            stmt.conditions.iter().all(|condition| {
                let actual_value = match condition.key.as_str() {
                    "aws:RequestedRegion" => &context.region,
                    "aws:SourceIp" => &context.source_ip,
                    "aws:SourceArn" => &context.source_arn,
                    "aws:SecureTransport" => {
                        if context.secure_transport {
                            "true"
                        } else {
                            "false"
                        }
                    }
                    _ => "",
                };
                let values: Vec<&str> = condition.values.iter().map(|s| s.as_str()).collect();
                evaluate_condition(&condition.operator, &condition.key, &values, actual_value)
            })
        };

        if conditions_match {
            return EvalResult::ExplicitDeny;
        }
    }

    EvalResult::NoExplicitDeny
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ActionPattern, ResourcePattern};

    fn stmt(effect: Effect, actions: &[&str], resources: &[&str]) -> PolicyStatement {
        PolicyStatement {
            sid: None,
            effect,
            actions: actions
                .iter()
                .map(|a| ActionPattern(a.to_string()))
                .collect(),
            not_actions: vec![],
            resources: resources
                .iter()
                .map(|r| ResourcePattern(r.to_string()))
                .collect(),
            not_resources: vec![],
            conditions: vec![],
        }
    }

    #[test]
    fn test_deny_exact_action() {
        let statements = vec![
            stmt(Effect::Allow, &["s3:*"], &["*"]),
            stmt(Effect::Deny, &["s3:DeleteBucket"], &["*"]),
        ];
        let result = evaluate_deny(&statements, "s3:DeleteBucket", "*");
        assert_eq!(result, EvalResult::ExplicitDeny);
    }

    #[test]
    fn test_deny_wildcard_action() {
        let statements = vec![stmt(Effect::Deny, &["s3:*"], &["*"])];
        let result = evaluate_deny(&statements, "s3:DeleteBucket", "*");
        assert_eq!(result, EvalResult::ExplicitDeny);
    }

    #[test]
    fn test_no_deny_match() {
        let statements = vec![
            stmt(Effect::Allow, &["s3:*"], &["*"]),
            stmt(Effect::Deny, &["iam:*"], &["*"]),
        ];
        let result = evaluate_deny(&statements, "s3:GetObject", "*");
        assert_eq!(result, EvalResult::NoExplicitDeny);
    }

    #[test]
    fn test_deny_with_resource_match() {
        let statements = vec![stmt(Effect::Deny, &["s3:*"], &["arn:aws:s3:::secret-*"])];
        let result = evaluate_deny(&statements, "s3:GetObject", "arn:aws:s3:::secret-data");
        assert_eq!(result, EvalResult::ExplicitDeny);
    }

    #[test]
    fn test_deny_with_resource_no_match() {
        let statements = vec![stmt(Effect::Deny, &["s3:*"], &["arn:aws:s3:::secret-*"])];
        let result = evaluate_deny(&statements, "s3:GetObject", "arn:aws:s3:::public-data");
        assert_eq!(result, EvalResult::NoExplicitDeny);
    }
}
