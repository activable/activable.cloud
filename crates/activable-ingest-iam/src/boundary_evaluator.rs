//! Boundary evaluator for AWS IAM permission boundaries.
//!
//! Permission boundaries are a set intersection: effective permissions are the
//! intersection of identity policy Allow statements and boundary Allow statements.
//!
//! Formula:
//! effective = (identity_allows) ∩ (boundary_allows) - explicit_denies

use crate::action_matcher::action_matches;
use crate::resource_matcher::resource_matches;
use crate::types::{Effect, PolicyStatement};

/// Result of boundary evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryResult {
    /// No boundary attached to the principal.
    NoBoundary,
    /// Action is within the boundary Allow set.
    Allowed,
    /// Action is NOT within the boundary Allow set (denied by boundary).
    NotInBoundary,
}

/// Check if action+resource is allowed by the boundary policy.
///
/// Returns `true` if the boundary allows the action, `false` otherwise.
///
/// # Arguments
/// - `boundary_statements`: The boundary policy statements
/// - `action`: The action being evaluated
/// - `resource`: The resource ARN being evaluated
pub fn boundary_allows(
    boundary_statements: &[PolicyStatement],
    action: &str,
    resource: &str,
) -> bool {
    // Empty boundary = no restriction
    if boundary_statements.is_empty() {
        return true;
    }

    // Scan Allow statements in the boundary
    for stmt in boundary_statements {
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
            // Found a matching Allow statement in the boundary
            return true;
        }
    }

    // No matching Allow statement in the boundary
    false
}

/// Evaluate the result of applying a boundary to an action+resource pair.
///
/// Returns:
/// - `NoBoundary` if the boundary is empty (no restriction)
/// - `Allowed` if the boundary allows the action+resource
/// - `NotInBoundary` if the boundary blocks the action+resource
///
/// # Arguments
/// - `boundary_statements`: The boundary policy statements
/// - `action`: The action being evaluated
/// - `resource`: The resource ARN being evaluated
pub fn evaluate_with_boundary(
    boundary_statements: &[PolicyStatement],
    action: &str,
    resource: &str,
) -> BoundaryResult {
    if boundary_statements.is_empty() {
        return BoundaryResult::NoBoundary;
    }

    if boundary_allows(boundary_statements, action, resource) {
        BoundaryResult::Allowed
    } else {
        BoundaryResult::NotInBoundary
    }
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
    fn test_boundary_allows_action() {
        let boundary = vec![stmt(Effect::Allow, &["s3:*"], &["*"])];
        assert!(boundary_allows(&boundary, "s3:GetObject", "*"));
    }

    #[test]
    fn test_boundary_denies_action() {
        let boundary = vec![stmt(Effect::Allow, &["s3:*"], &["*"])];
        assert!(!boundary_allows(&boundary, "iam:CreateUser", "*"));
    }

    #[test]
    fn test_empty_boundary_allows_everything() {
        assert!(boundary_allows(&[], "iam:CreateUser", "*"));
    }

    #[test]
    fn test_boundary_with_resource_pattern() {
        let boundary = vec![stmt(Effect::Allow, &["s3:*"], &["arn:aws:s3:::public-*"])];
        assert!(boundary_allows(
            &boundary,
            "s3:GetObject",
            "arn:aws:s3:::public-data"
        ));
        assert!(!boundary_allows(
            &boundary,
            "s3:GetObject",
            "arn:aws:s3:::private-data"
        ));
    }

    #[test]
    fn test_evaluate_with_boundary_no_boundary() {
        let result = evaluate_with_boundary(&[], "iam:CreateUser", "*");
        assert_eq!(result, BoundaryResult::NoBoundary);
    }

    #[test]
    fn test_evaluate_with_boundary_allowed() {
        let boundary = vec![stmt(Effect::Allow, &["s3:*"], &["*"])];
        let result = evaluate_with_boundary(&boundary, "s3:GetObject", "*");
        assert_eq!(result, BoundaryResult::Allowed);
    }

    #[test]
    fn test_evaluate_with_boundary_not_in_boundary() {
        let boundary = vec![stmt(Effect::Allow, &["s3:*"], &["*"])];
        let result = evaluate_with_boundary(&boundary, "iam:CreateUser", "*");
        assert_eq!(result, BoundaryResult::NotInBoundary);
    }
}
