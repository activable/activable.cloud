//! SCP (Service Control Policy) evaluator for AWS Organizations.
//!
//! SCPs are evaluated as a CHAIN where each level (root, OU, account) must
//! explicitly allow the action. If ANY level in the chain does not allow an
//! action, it is blocked.
//!
//! Formula:
//! effective = (root_scp_allow) ∩ (ou_scp_allow) ∩ (account_scp_allow) ∩ ...
//!
//! Empty chain = no SCP restriction.

use crate::action_matcher::action_matches;
use crate::resource_matcher::resource_matches;
use crate::types::{Effect, PolicyStatement};

/// Check if action+resource is allowed by the entire SCP chain.
///
/// Each level in the chain must have at least one Allow statement matching
/// the action+resource. If ANY level blocks it, the result is false.
///
/// # Arguments
/// - `chain`: Slice of SCP statement slices, one per organizational level
/// - `action`: The action being evaluated
/// - `resource`: The resource ARN being evaluated
pub fn scp_allows(chain: &[&[PolicyStatement]], action: &str, resource: &str) -> bool {
    // Empty chain = no SCP restriction
    if chain.is_empty() {
        return true;
    }

    // Each level in the chain must allow the action
    for level_statements in chain {
        let level_allows = statement_slice_allows(level_statements, action, resource);
        if !level_allows {
            return false;
        }
    }

    true
}

/// Check if a single SCP level (set of statements) allows the action+resource.
fn statement_slice_allows(statements: &[PolicyStatement], action: &str, resource: &str) -> bool {
    // Scan Allow statements in this level
    for stmt in statements {
        if stmt.effect != Effect::Allow {
            continue;
        }

        // Check if action matches
        let action_matches_result = if !stmt.not_actions.is_empty() {
            // NotAction: allow if action does NOT match any pattern
            !stmt
                .not_actions
                .iter()
                .any(|pattern| action_matches(&pattern.0, action))
        } else if !stmt.actions.is_empty() {
            // Action: allow if action matches any pattern
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
            // NotResource: allow if resource does NOT match any pattern
            !stmt
                .not_resources
                .iter()
                .any(|pattern| resource_matches(&pattern.0, resource))
        } else if !stmt.resources.is_empty() {
            // Resource: allow if resource matches any pattern
            stmt.resources
                .iter()
                .any(|pattern| resource_matches(&pattern.0, resource))
        } else {
            // No Resource or NotResource specified: match everything
            true
        };

        if resource_matches_result {
            // Found a matching Allow statement at this level
            return true;
        }
    }

    // No matching Allow statement at this level
    false
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
    fn test_scp_chain_all_allow() {
        let root_scp = vec![stmt(Effect::Allow, &["*"], &["*"])];
        let ou_scp = vec![stmt(Effect::Allow, &["s3:*", "ec2:*"], &["*"])];
        let chain: &[&[PolicyStatement]] = &[&root_scp, &ou_scp];
        assert!(scp_allows(chain, "s3:GetObject", "*"));
    }

    #[test]
    fn test_scp_chain_ou_blocks() {
        let root_scp = vec![stmt(Effect::Allow, &["*"], &["*"])];
        let ou_scp = vec![stmt(Effect::Allow, &["s3:*"], &["*"])]; // no iam
        let chain: &[&[PolicyStatement]] = &[&root_scp, &ou_scp];
        assert!(!scp_allows(chain, "iam:CreateUser", "*"));
    }

    #[test]
    fn test_empty_scp_chain() {
        assert!(scp_allows(&[], "iam:CreateUser", "*"));
    }

    #[test]
    fn test_scp_chain_multiple_levels() {
        let root_scp = vec![stmt(Effect::Allow, &["*"], &["*"])];
        let ou_scp = vec![stmt(Effect::Allow, &["s3:*"], &["*"])];
        let account_scp = vec![stmt(Effect::Allow, &["s3:Get*"], &["*"])];
        let chain: &[&[PolicyStatement]] = &[&root_scp, &ou_scp, &account_scp];
        assert!(scp_allows(chain, "s3:GetObject", "*")); // all levels allow
        assert!(!scp_allows(chain, "s3:DeleteBucket", "*")); // account_scp blocks
    }
}
