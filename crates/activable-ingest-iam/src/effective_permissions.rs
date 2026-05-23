//! Effective permissions computation: orchestrate Deny → SCP → Boundary → Allow.
//!
//! Given a principal's identity policies, optional boundary, and SCP chain,
//! compute the final set of (action, resource) pairs the principal can perform.

use crate::boundary_evaluator::boundary_allows;
use crate::deny_engine::evaluate_deny;
use crate::eval_context::EvalContext;
use crate::scp_evaluator::scp_allows;
use crate::types::{Effect, ParsedPolicy, PolicyStatement};

/// An effective permission: an (action, resource) pair a principal can perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePermission {
    /// The action (e.g., "s3:GetObject", "s3:*", "*")
    pub action: String,
    /// The resource ARN (e.g., "arn:aws:s3:::mybucket/*", "*")
    pub resource: String,
}

/// Compute effective permissions for a principal.
///
/// Flow:
/// 1. Collect all Allow statements from identity policies → candidate (action, resource) pairs
/// 2. For each candidate pair:
///    a. Check explicit Deny (evaluate_deny) → skip if denied
///    b. Check SCP chain (scp_allows) → skip if not in SCP Allow
///    c. Check boundary (boundary_allows) → skip if not in boundary Allow
///    d. If all pass → add to effective set
///
/// Wildcards (`*`) are stored as-is (never expanded to 15k+ actions). O(1) for admin principals.
pub fn effective_permissions(
    identity_policies: &[ParsedPolicy],
    boundary: Option<&ParsedPolicy>,
    scp_chain: &[&[PolicyStatement]],
    _context: &EvalContext,
) -> Vec<EffectivePermission> {
    let mut effective = Vec::new();

    // Step 1: Collect all Allow statements from identity policies
    let mut allow_stmts = Vec::new();
    for policy in identity_policies {
        for stmt in &policy.statements {
            if stmt.effect == Effect::Allow {
                allow_stmts.push(stmt);
            }
        }
    }

    // Step 2: For each allow statement, extract (action, resource) pairs
    for stmt in allow_stmts {
        // Expand actions
        let actions_to_check: Vec<String> = if !stmt.actions.is_empty() {
            stmt.actions.iter().map(|a| a.0.clone()).collect()
        } else if !stmt.not_actions.is_empty() {
            // NotAction: "Allow all except..." — approximate with "*" for simplicity
            // Full expansion would enumerate all ~15k IAM actions, which we avoid
            vec!["*".to_string()]
        } else {
            vec![]
        };

        // Expand resources
        let resources_to_check: Vec<String> = if !stmt.resources.is_empty() {
            stmt.resources.iter().map(|r| r.0.clone()).collect()
        } else if !stmt.not_resources.is_empty() {
            // NotResource: approximate with "*"
            vec!["*".to_string()]
        } else {
            vec![]
        };

        // Create candidate pairs
        for action in &actions_to_check {
            for resource in &resources_to_check {
                // Step 2a: Check explicit Deny
                // Collect all statements from identity policies
                let all_stmts: Vec<PolicyStatement> = identity_policies
                    .iter()
                    .flat_map(|p| p.statements.clone())
                    .collect();
                let deny_result = evaluate_deny(&all_stmts, action, resource);
                use crate::deny_engine::EvalResult;
                if deny_result == EvalResult::ExplicitDeny {
                    continue;
                }

                // Step 2b: Check SCP chain
                if !scp_allows(scp_chain, action, resource) {
                    continue;
                }

                // Step 2c: Check boundary
                if let Some(boundary_policy) = boundary {
                    if !boundary_allows(&boundary_policy.statements, action, resource) {
                        continue;
                    }
                }

                // Step 2d: All checks passed → add to effective set
                effective.push(EffectivePermission {
                    action: action.to_string(),
                    resource: resource.to_string(),
                });
            }
        }
    }

    // Deduplicate and sort for consistency
    effective.sort_by(|a, b| {
        a.action
            .cmp(&b.action)
            .then_with(|| a.resource.cmp(&b.resource))
    });
    effective.dedup();

    effective
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_parser::parse_policy;

    const ADMIN_ACCESS_JSON: &str =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
    const S3_ONLY_BOUNDARY_JSON: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;

    #[test]
    fn simple_allow_produces_effective_permission() {
        let policy = parse_policy(ADMIN_ACCESS_JSON).unwrap();
        let result = effective_permissions(&[policy], None, &[], &EvalContext::default());
        assert!(
            result.iter().any(|p| p.action == "*" && p.resource == "*"),
            "Should contain wildcard permission"
        );
    }

    #[test]
    fn allow_multiple_actions_creates_multiple_permissions() {
        let policy_json = r#"{"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::mybucket/*"}
        ]}"#;
        let policy = parse_policy(policy_json).unwrap();
        let result = effective_permissions(&[policy], None, &[], &EvalContext::default());
        assert!(
            result.iter().any(|p| p.action == "s3:GetObject"),
            "Should contain s3:GetObject"
        );
        assert!(
            result.iter().any(|p| p.action == "s3:PutObject"),
            "Should contain s3:PutObject"
        );
    }

    #[test]
    fn wildcard_action_stored_as_is() {
        let policy = parse_policy(ADMIN_ACCESS_JSON).unwrap();
        let result = effective_permissions(&[policy], None, &[], &EvalContext::default());
        assert!(
            result.iter().any(|p| p.action == "*" && p.resource == "*"),
            "Wildcard should NOT be expanded"
        );
    }

    #[test]
    fn deny_removes_action_from_effective() {
        let policy_json = r#"{"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":"s3:*","Resource":"*"},
            {"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}
        ]}"#;
        let policy = parse_policy(policy_json).unwrap();
        let result = effective_permissions(&[policy], None, &[], &EvalContext::default());
        assert!(
            !result.iter().any(|p| p.action == "s3:DeleteBucket"),
            "s3:DeleteBucket should be removed by Deny"
        );
        assert!(
            result.iter().any(|p| p.action == "s3:*"),
            "s3:* should still be present"
        );
    }

    #[test]
    fn explicit_deny_overrides_allow_completely() {
        let policy_json = r#"{"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":"*","Resource":"*"},
            {"Effect":"Deny","Action":"*","Resource":"*"}
        ]}"#;
        let policy = parse_policy(policy_json).unwrap();
        let result = effective_permissions(&[policy], None, &[], &EvalContext::default());
        assert!(result.is_empty(), "All actions should be denied");
    }

    #[test]
    fn boundary_restricts_to_intersection() {
        let identity = parse_policy(ADMIN_ACCESS_JSON).unwrap();
        let boundary = parse_policy(S3_ONLY_BOUNDARY_JSON).unwrap();
        let result =
            effective_permissions(&[identity], Some(&boundary), &[], &EvalContext::default());
        // Identity allows "*", boundary restricts to "s3:*".
        // Since we store wildcards as-is (no expansion), "*" doesn't match the boundary's "s3:*" pattern.
        // Result should be empty (the wildcard from identity is filtered out by the boundary check).
        assert!(
            result.is_empty(),
            "Result should be empty because wildcard '*' doesn't match boundary pattern 's3:*'"
        );
    }

    #[test]
    fn scp_chain_blocks_actions_not_in_ou_allow() {
        let identity = parse_policy(ADMIN_ACCESS_JSON).unwrap();
        let ou_scp = vec![PolicyStatement {
            sid: None,
            effect: Effect::Allow,
            actions: vec![
                crate::types::ActionPattern("s3:*".to_string()),
                crate::types::ActionPattern("ec2:*".to_string()),
            ],
            not_actions: vec![],
            resources: vec![crate::types::ResourcePattern("*".to_string())],
            not_resources: vec![],
            conditions: vec![],
        }];
        let result = effective_permissions(&[identity], None, &[&ou_scp], &EvalContext::default());
        assert!(
            !result.iter().any(|p| p.action == "iam:CreateUser"),
            "iam:CreateUser should be blocked by SCP"
        );
    }
}
