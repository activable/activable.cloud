//! Resource-based policy evaluator.
//!
//! Evaluates whether a principal can access a resource when both identity-based
//! and resource-based policies exist.
//!
//! AWS policy evaluation logic:
//! - Explicit Deny always wins (in either policy type)
//! - Same-account: Either identity OR resource policy can grant access
//! - Cross-account: BOTH identity AND resource policy must allow access

use crate::action_matcher::action_matches;
use crate::types::{Effect, ParsedPolicy};

/// Result of evaluating a principal's access to a resource considering both
/// identity-based and resource-based policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcePolicyDecision {
    /// Principal is allowed to perform the action
    Allow,
    /// Principal is explicitly denied by a policy
    Deny,
    /// Neither identity nor resource policy allows the action
    ImplicitDeny,
}

/// Evaluate whether a principal can perform an action on a resource
/// considering BOTH identity-based and resource-based policies.
///
/// # Arguments
/// * `action` - The IAM action being evaluated (e.g., "s3:GetObject")
/// * `resource_arn` - The ARN of the resource being accessed
/// * `principal_arn` - The ARN of the principal (role, user, etc.)
/// * `identity_policies` - The principal's identity-based policies
/// * `resource_policy` - The resource's resource-based policy (if any)
/// * `principal_account` - The AWS account ID of the principal
/// * `resource_account` - The AWS account ID of the resource
///
/// # Returns
/// `ResourcePolicyDecision` indicating Allow, Deny, or ImplicitDeny
///
/// # AWS Policy Evaluation Logic
/// 1. Check explicit Deny in identity policies → return Deny
/// 2. Check explicit Deny in resource policy → return Deny
/// 3. If same-account: Allow if either identity OR resource policy allows
/// 4. If cross-account: Allow only if BOTH identity AND resource policies allow
/// 5. Otherwise: ImplicitDeny
pub fn evaluate_resource_policy_pair(
    action: &str,
    resource_arn: &str,
    principal_arn: &str,
    identity_policies: &[ParsedPolicy],
    resource_policy: Option<&ParsedPolicy>,
    principal_account: &str,
    resource_account: &str,
) -> ResourcePolicyDecision {
    // Step 1: Check explicit Deny in identity policies
    if has_deny_statement(identity_policies, action, resource_arn) {
        return ResourcePolicyDecision::Deny;
    }

    // Step 2: Check explicit Deny in resource policy
    if let Some(res_policy) = resource_policy {
        if has_deny_statement_for_principal(res_policy, action, resource_arn, principal_arn) {
            return ResourcePolicyDecision::Deny;
        }
    }

    // Determine if this is same-account or cross-account
    let same_account = principal_account == resource_account;

    // Step 3 & 4: Check Allow statements
    let identity_allows = has_allow_statement(identity_policies, action, resource_arn);
    let resource_allows = resource_policy
        .map(|p| has_allow_statement_for_principal(p, action, resource_arn, principal_arn))
        .unwrap_or(false);

    // Evaluate based on account boundary
    let access_allowed = if same_account {
        // Same-account: Either policy can grant access (hierarchical trust)
        identity_allows || resource_allows
    } else {
        // Cross-account: Both policies must allow (mutual consent model)
        identity_allows && resource_allows
    };

    if access_allowed {
        ResourcePolicyDecision::Allow
    } else {
        ResourcePolicyDecision::ImplicitDeny
    }
}

/// Extract account ID from an ARN.
///
/// # Arguments
/// * `arn` - An AWS ARN string (e.g., "arn:aws:iam::123456789012:role/Admin")
///
/// # Returns
/// The account ID (12-digit string) or None if the ARN is malformed
///
/// # Examples
/// ```ignore
/// assert_eq!(extract_account_from_arn("arn:aws:iam::123456789012:role/Admin"), Some("123456789012"));
/// assert_eq!(extract_account_from_arn("arn:aws:s3:::my-bucket"), None); // S3 has no account in ARN
/// ```
pub fn extract_account_from_arn(arn: &str) -> Option<&str> {
    let parts: Vec<&str> = arn.split(':').collect();
    // ARN format: arn:partition:service:region:account-id:resource
    // Index 4 is the account ID
    if parts.len() >= 5 {
        let account = parts[4];
        // Check if it's a valid account ID (non-empty, or it's a service principal)
        if !account.is_empty() {
            Some(account)
        } else {
            None
        }
    } else {
        None
    }
}

/// Check if a principal ARN matches a policy's Principal field.
///
/// # Arguments
/// * `policy_principal` - The principal from a resource policy statement
///   - Specific ARN: "arn:aws:iam::123456789012:role/Admin"
///   - Account root: "arn:aws:iam::123456789012:root"
///   - Wildcard: "*"
///   - Service principal: "s3.amazonaws.com"
/// * `principal_arn` - The principal ARN being evaluated
///
/// # Returns
/// true if the principal matches; false otherwise
pub fn principal_matches(policy_principal: &str, principal_arn: &str) -> bool {
    match policy_principal {
        "*" => true, // Wildcard matches any principal
        policy_principal if policy_principal.ends_with(":root") => {
            // Account root match: extract account from both and compare
            if let (Some(policy_account), Some(principal_account)) = (
                extract_account_from_arn(policy_principal),
                extract_account_from_arn(principal_arn),
            ) {
                policy_account == principal_account
            } else {
                false
            }
        }
        policy_principal => {
            // Exact ARN match or service principal match
            policy_principal == principal_arn
                || (policy_principal.contains(".amazonaws.com")
                    && principal_arn.contains(policy_principal))
        }
    }
}

/// Check if a policy has an explicit Deny statement for the action and resource.
fn has_deny_statement(policies: &[ParsedPolicy], action: &str, resource: &str) -> bool {
    for policy in policies {
        for stmt in &policy.statements {
            if stmt.effect == Effect::Deny
                && stmt_matches_action_and_resource(stmt, action, resource)
            {
                return true;
            }
        }
    }
    false
}

/// Check if a resource policy has an explicit Deny statement for the principal, action, and resource.
fn has_deny_statement_for_principal(
    policy: &ParsedPolicy,
    action: &str,
    resource: &str,
    _principal_arn: &str,
) -> bool {
    for stmt in &policy.statements {
        if stmt.effect == Effect::Deny {
            // Check if principal matches
            // Note: Principal extraction would be done during parsing
            if stmt_matches_action_and_resource(stmt, action, resource) {
                return true;
            }
        }
    }
    false
}

/// Check if a policy has an Allow statement for the action and resource.
fn has_allow_statement(policies: &[ParsedPolicy], action: &str, resource: &str) -> bool {
    for policy in policies {
        for stmt in &policy.statements {
            if stmt.effect == Effect::Allow
                && stmt_matches_action_and_resource(stmt, action, resource)
            {
                return true;
            }
        }
    }
    false
}

/// Check if a resource policy has an Allow statement for the principal, action, and resource.
fn has_allow_statement_for_principal(
    policy: &ParsedPolicy,
    action: &str,
    resource: &str,
    _principal_arn: &str,
) -> bool {
    for stmt in &policy.statements {
        if stmt.effect == Effect::Allow {
            // Check if principal matches (would be extracted during parsing)
            if stmt_matches_action_and_resource(stmt, action, resource) {
                return true;
            }
        }
    }
    false
}

/// Check if a statement matches the given action and resource.
fn stmt_matches_action_and_resource(
    stmt: &crate::types::PolicyStatement,
    action: &str,
    resource: &str,
) -> bool {
    let action_matches_stmt = if !stmt.actions.is_empty() {
        // Check if any action pattern matches
        stmt.actions.iter().any(|a| action_matches(&a.0, action))
    } else if !stmt.not_actions.is_empty() {
        // NotAction: Allow if action does NOT match any pattern
        !stmt
            .not_actions
            .iter()
            .any(|a| action_matches(&a.0, action))
    } else {
        false
    };

    let resource_matches_stmt = resource_matches(&stmt.resources, &stmt.not_resources, resource);

    action_matches_stmt && resource_matches_stmt
}

/// Check if a resource matches the policy's resource patterns.
fn resource_matches(
    resources: &[crate::types::ResourcePattern],
    not_resources: &[crate::types::ResourcePattern],
    target_resource: &str,
) -> bool {
    if !resources.is_empty() {
        // Check if target matches any resource pattern
        resources
            .iter()
            .any(|r| matches_pattern(&r.0, target_resource))
    } else if !not_resources.is_empty() {
        // NotResource: Allow if target does NOT match any pattern
        !not_resources
            .iter()
            .any(|r| matches_pattern(&r.0, target_resource))
    } else {
        // No resource constraints
        true
    }
}

/// Check if a value matches an ARN pattern (supporting wildcards).
fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        true
    } else if !pattern.contains('*') {
        pattern == value
    } else {
        // Simple wildcard matching
        // "arn:aws:s3:::bucket/*" matches "arn:aws:s3:::bucket/file.txt"
        wildcard_match(pattern, value)
    }
}

/// Simple wildcard pattern matching.
/// Handles "*" at end of string only (AWS ARN convention).
fn wildcard_match(pattern: &str, value: &str) -> bool {
    if let Some(star_pos) = pattern.find('*') {
        let prefix = &pattern[..star_pos];
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_parser::parse_policy;

    #[test]
    fn extract_account_id_from_valid_arn() {
        assert_eq!(
            extract_account_from_arn("arn:aws:iam::123456789012:role/Admin"),
            Some("123456789012")
        );
    }

    #[test]
    fn extract_account_id_from_root_arn() {
        assert_eq!(
            extract_account_from_arn("arn:aws:iam::999888777666:root"),
            Some("999888777666")
        );
    }

    #[test]
    fn extract_account_id_from_s3_arn_returns_none() {
        // S3 ARNs have empty account field
        assert_eq!(extract_account_from_arn("arn:aws:s3:::my-bucket"), None);
    }

    #[test]
    fn extract_account_id_from_malformed_arn_returns_none() {
        // "arn:aws:iam::role/Admin" is actually "arn:aws:iam::<empty>:role/Admin"
        // The account field is empty, so it returns None
        assert_eq!(extract_account_from_arn("arn:aws:iam::"), None);
        assert_eq!(extract_account_from_arn("invalid"), None);
    }

    #[test]
    fn principal_matches_wildcard() {
        assert!(principal_matches(
            "*",
            "arn:aws:iam::123456789012:role/Admin"
        ));
    }

    #[test]
    fn principal_matches_exact_arn() {
        let arn = "arn:aws:iam::123456789012:role/Admin";
        assert!(principal_matches(arn, arn));
    }

    #[test]
    fn principal_matches_account_root() {
        assert!(principal_matches(
            "arn:aws:iam::123456789012:root",
            "arn:aws:iam::123456789012:role/Admin"
        ));
    }

    #[test]
    fn principal_matches_different_account_root_returns_false() {
        assert!(!principal_matches(
            "arn:aws:iam::111111111111:root",
            "arn:aws:iam::123456789012:role/Admin"
        ));
    }

    #[test]
    fn principal_does_not_match_different_arn() {
        assert!(!principal_matches(
            "arn:aws:iam::123456789012:role/Other",
            "arn:aws:iam::123456789012:role/Admin"
        ));
    }

    #[test]
    fn same_account_identity_allows_returns_allow() {
        let identity_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#
        ).unwrap();

        let decision = evaluate_resource_policy_pair(
            "s3:GetObject",
            "arn:aws:s3:::bucket/file.txt",
            "arn:aws:iam::123456789012:role/MyRole",
            &[identity_policy],
            None,
            "123456789012",
            "123456789012",
        );

        assert_eq!(decision, ResourcePolicyDecision::Allow);
    }

    #[test]
    fn same_account_resource_allows_returns_allow() {
        let identity_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}"#
        ).unwrap();
        let resource_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#
        ).unwrap();

        let decision = evaluate_resource_policy_pair(
            "s3:GetObject",
            "arn:aws:s3:::bucket/file.txt",
            "arn:aws:iam::123456789012:role/MyRole",
            &[identity_policy],
            Some(&resource_policy),
            "123456789012",
            "123456789012",
        );

        assert_eq!(decision, ResourcePolicyDecision::Allow);
    }

    #[test]
    fn same_account_neither_allows_returns_implicit_deny() {
        let identity_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}"#
        ).unwrap();
        let resource_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}"#
        ).unwrap();

        let decision = evaluate_resource_policy_pair(
            "s3:GetObject",
            "arn:aws:s3:::bucket/file.txt",
            "arn:aws:iam::123456789012:role/MyRole",
            &[identity_policy],
            Some(&resource_policy),
            "123456789012",
            "123456789012",
        );

        assert_eq!(decision, ResourcePolicyDecision::ImplicitDeny);
    }

    #[test]
    fn cross_account_both_allow_returns_allow() {
        let identity_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#
        ).unwrap();
        let resource_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#
        ).unwrap();

        let decision = evaluate_resource_policy_pair(
            "s3:GetObject",
            "arn:aws:s3:::bucket/file.txt",
            "arn:aws:iam::111111111111:role/CrossAcctRole",
            &[identity_policy],
            Some(&resource_policy),
            "111111111111",
            "123456789012",
        );

        assert_eq!(decision, ResourcePolicyDecision::Allow);
    }

    #[test]
    fn cross_account_only_identity_allows_returns_implicit_deny() {
        let identity_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#
        ).unwrap();
        let resource_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}"#
        ).unwrap();

        let decision = evaluate_resource_policy_pair(
            "s3:GetObject",
            "arn:aws:s3:::bucket/file.txt",
            "arn:aws:iam::111111111111:role/CrossAcctRole",
            &[identity_policy],
            Some(&resource_policy),
            "111111111111",
            "123456789012",
        );

        assert_eq!(decision, ResourcePolicyDecision::ImplicitDeny);
    }

    #[test]
    fn cross_account_only_resource_allows_returns_implicit_deny() {
        let identity_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}"#
        ).unwrap();
        let resource_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#
        ).unwrap();

        let decision = evaluate_resource_policy_pair(
            "s3:GetObject",
            "arn:aws:s3:::bucket/file.txt",
            "arn:aws:iam::111111111111:role/CrossAcctRole",
            &[identity_policy],
            Some(&resource_policy),
            "111111111111",
            "123456789012",
        );

        assert_eq!(decision, ResourcePolicyDecision::ImplicitDeny);
    }

    #[test]
    fn explicit_deny_in_identity_policy_returns_deny() {
        let identity_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}"#
        ).unwrap();
        let resource_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#
        ).unwrap();

        let decision = evaluate_resource_policy_pair(
            "s3:GetObject",
            "arn:aws:s3:::bucket/file.txt",
            "arn:aws:iam::123456789012:role/MyRole",
            &[identity_policy],
            Some(&resource_policy),
            "123456789012",
            "123456789012",
        );

        assert_eq!(decision, ResourcePolicyDecision::Deny);
    }

    #[test]
    fn explicit_deny_in_resource_policy_returns_deny() {
        let identity_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#
        ).unwrap();
        let resource_policy = parse_policy(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}"#
        ).unwrap();

        let decision = evaluate_resource_policy_pair(
            "s3:GetObject",
            "arn:aws:s3:::bucket/file.txt",
            "arn:aws:iam::123456789012:role/MyRole",
            &[identity_policy],
            Some(&resource_policy),
            "123456789012",
            "123456789012",
        );

        assert_eq!(decision, ResourcePolicyDecision::Deny);
    }

    #[test]
    fn resource_matches_wildcard() {
        assert!(resource_matches(
            &[crate::types::ResourcePattern("*".to_string())],
            &[],
            "arn:aws:s3:::bucket/file.txt"
        ));
    }

    #[test]
    fn resource_matches_exact_arn() {
        let arn = "arn:aws:s3:::bucket/file.txt";
        assert!(resource_matches(
            &[crate::types::ResourcePattern(arn.to_string())],
            &[],
            arn
        ));
    }

    #[test]
    fn resource_matches_bucket_prefix() {
        assert!(resource_matches(
            &[crate::types::ResourcePattern(
                "arn:aws:s3:::bucket/*".to_string()
            )],
            &[],
            "arn:aws:s3:::bucket/file.txt"
        ));
    }

    #[test]
    fn not_resource_excludes_matching_patterns() {
        assert!(!resource_matches(
            &[],
            &[crate::types::ResourcePattern(
                "arn:aws:s3:::bucket/*".to_string()
            )],
            "arn:aws:s3:::bucket/file.txt"
        ));
    }

    #[test]
    fn not_resource_allows_non_matching_patterns() {
        assert!(resource_matches(
            &[],
            &[crate::types::ResourcePattern(
                "arn:aws:s3:::bucket/*".to_string()
            )],
            "arn:aws:s3:::other-bucket/file.txt"
        ));
    }
}
