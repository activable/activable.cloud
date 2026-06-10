//! Session policy constraint evaluation for AssumeRole temporary credentials.
//!
//! Session policies work as INTERSECTION constraints on effective permissions.
//! When a principal assumes a role with a session policy, the effective permissions become:
//!
//! ```text
//! effective = (identity_allows ∩ session_allows) - explicit_deny
//! ```
//!
//! Session policies are optional — if absent, no filtering is applied.

use crate::action_matcher::action_matches;
use crate::resource_matcher::resource_matches;
use crate::types::{Effect, ParsedPolicy};

/// Result of session policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionConstraintResult {
    /// Session policy allows this action/resource pair.
    Allowed,
    /// Session policy does not allow (filtered out by constraint).
    Constrained,
    /// No session policy present (no filtering applied).
    Unconstrained,
}

/// Check if a session policy allows a specific action on a resource.
///
/// Session policies work as INTERSECTION constraints:
/// - If session policy has Allow statement for this action+resource → Allowed
/// - If session policy exists but doesn't Allow this action+resource → Constrained (filtered out)
/// - If no session policy → Unconstrained (no filtering)
///
/// # Arguments
/// - `session_policy`: Optional session policy to evaluate. `None` means unconstrained.
/// - `action`: The IAM action to check (e.g., "s3:GetObject", "iam:CreateUser")
/// - `resource`: The resource ARN to check (e.g., "arn:aws:s3:::mybucket/*")
///
/// # Returns
/// `SessionConstraintResult` indicating whether the session policy allows this action/resource.
///
/// # Example
///
/// ```no_run
/// # use activable_iam_engine::{parse_policy, session_policy};
/// let session_json = r#"{"Version":"2012-10-17","Statement":[
///   {"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}
/// ]}"#;
/// let session = parse_policy(session_json).ok();
/// let result = session_policy::session_allows(session.as_ref(), "s3:GetObject", "arn:aws:s3:::mybucket/key");
/// assert_eq!(result, session_policy::SessionConstraintResult::Allowed);
/// ```
pub fn session_allows(
    session_policy: Option<&ParsedPolicy>,
    action: &str,
    resource: &str,
) -> SessionConstraintResult {
    let policy = match session_policy {
        Some(p) => p,
        None => return SessionConstraintResult::Unconstrained,
    };

    // Check if any Allow statement in the session policy covers this action+resource
    for stmt in &policy.statements {
        // Skip Deny statements; they're handled separately in effective permissions
        if stmt.effect != Effect::Allow {
            continue;
        }

        // Check if this statement's actions match
        let action_matched = if !stmt.not_actions.is_empty() {
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
            // No Action or NotAction: match all
            true
        };

        if !action_matched {
            continue;
        }

        // Check if this statement's resources match
        let resource_matched = if !stmt.not_resources.is_empty() {
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
            // No Resource or NotResource: match all
            true
        };

        if resource_matched {
            // Found a matching Allow statement in the session policy
            return SessionConstraintResult::Allowed;
        }
    }

    // No matching Allow statement in the session policy
    SessionConstraintResult::Constrained
}

/// Compute effective permissions with session policy constraint applied.
///
/// Effective permissions are the intersection of:
/// 1. Base effective permissions (identity + boundary + SCP + deny)
/// 2. Session policy Allow statements
///
/// This extends `effective_permissions()` by adding session policy as a filtering layer.
///
/// # Arguments
/// - `base_permissions`: Effective permissions computed without session policy constraint
/// - `session_policy`: Optional session policy to apply as constraint
///
/// # Returns
/// Filtered list of effective permissions that satisfy both base permissions AND session policy.
/// If no session policy is present, returns all base permissions unchanged.
///
/// # Example
///
/// ```no_run
/// # use activable_iam_engine::{EffectivePermission, parse_policy, session_policy};
/// let base = vec![
///     EffectivePermission { action: "s3:GetObject".to_string(), resource: "*".to_string() },
///     EffectivePermission { action: "iam:CreateUser".to_string(), resource: "*".to_string() },
/// ];
/// let session_json = r#"{"Version":"2012-10-17","Statement":[
///   {"Effect":"Allow","Action":"s3:*","Resource":"*"}
/// ]}"#;
/// let session = parse_policy(session_json).ok();
/// let result = session_policy::effective_permissions_with_session(&base, session.as_ref());
/// // Result contains only s3:GetObject (matches session policy)
/// assert_eq!(result.len(), 1);
/// ```
pub fn effective_permissions_with_session(
    base_permissions: &[crate::effective_permissions::EffectivePermission],
    session_policy: Option<&ParsedPolicy>,
) -> Vec<crate::effective_permissions::EffectivePermission> {
    // If no session policy, return base permissions unchanged
    let policy = match session_policy {
        Some(p) => p,
        None => return base_permissions.to_vec(),
    };

    // Filter: keep only permissions that the session policy also allows
    base_permissions
        .iter()
        .filter(|perm| {
            let session_result = session_allows(Some(policy), &perm.action, &perm.resource);
            matches!(session_result, SessionConstraintResult::Allowed)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ActionPattern, PolicyStatement, ResourcePattern};

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

    // ==================== session_allows tests ====================

    #[test]
    fn no_session_policy_returns_unconstrained() {
        let result = session_allows(None, "s3:GetObject", "arn:aws:s3:::bucket/*");
        assert_eq!(result, SessionConstraintResult::Unconstrained);
    }

    #[test]
    fn session_policy_allows_exact_action_resource() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![stmt(
                Effect::Allow,
                &["s3:GetObject"],
                &["arn:aws:s3:::mybucket/*"],
            )],
        };
        let result = session_allows(Some(&policy), "s3:GetObject", "arn:aws:s3:::mybucket/key");
        assert_eq!(result, SessionConstraintResult::Allowed);
    }

    #[test]
    fn session_policy_constrains_action_not_in_allow() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![stmt(Effect::Allow, &["s3:GetObject"], &["*"])],
        };
        let result = session_allows(Some(&policy), "s3:PutObject", "*");
        assert_eq!(result, SessionConstraintResult::Constrained);
    }

    #[test]
    fn session_policy_constrains_resource_not_in_allow() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![stmt(Effect::Allow, &["s3:*"], &["arn:aws:s3:::public-*"])],
        };
        let result = session_allows(Some(&policy), "s3:GetObject", "arn:aws:s3:::private-data");
        assert_eq!(result, SessionConstraintResult::Constrained);
    }

    #[test]
    fn session_policy_wildcard_action_allows_all() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![stmt(Effect::Allow, &["*"], &["*"])],
        };
        let result = session_allows(Some(&policy), "iam:CreateUser", "*");
        assert_eq!(result, SessionConstraintResult::Allowed);
    }

    #[test]
    fn session_policy_action_wildcard_suffix() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![stmt(Effect::Allow, &["s3:Get*"], &["*"])],
        };
        assert_eq!(
            session_allows(Some(&policy), "s3:GetObject", "*"),
            SessionConstraintResult::Allowed
        );
        assert_eq!(
            session_allows(Some(&policy), "s3:GetBucketPolicy", "*"),
            SessionConstraintResult::Allowed
        );
        assert_eq!(
            session_allows(Some(&policy), "s3:PutObject", "*"),
            SessionConstraintResult::Constrained
        );
    }

    #[test]
    fn session_policy_resource_wildcard_suffix() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![stmt(Effect::Allow, &["s3:*"], &["arn:aws:s3:::mybucket/*"])],
        };
        assert_eq!(
            session_allows(Some(&policy), "s3:GetObject", "arn:aws:s3:::mybucket/key"),
            SessionConstraintResult::Allowed
        );
        assert_eq!(
            session_allows(
                Some(&policy),
                "s3:GetObject",
                "arn:aws:s3:::otherbucket/key"
            ),
            SessionConstraintResult::Constrained
        );
    }

    #[test]
    fn session_policy_multiple_allow_statements() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![
                stmt(
                    Effect::Allow,
                    &["s3:GetObject"],
                    &["arn:aws:s3:::bucket1/*"],
                ),
                stmt(
                    Effect::Allow,
                    &["dynamodb:GetItem"],
                    &["arn:aws:dynamodb:*:*:table/users"],
                ),
            ],
        };
        assert_eq!(
            session_allows(Some(&policy), "s3:GetObject", "arn:aws:s3:::bucket1/key"),
            SessionConstraintResult::Allowed
        );
        assert_eq!(
            session_allows(
                Some(&policy),
                "dynamodb:GetItem",
                "arn:aws:dynamodb:us-east-1:123456789012:table/users"
            ),
            SessionConstraintResult::Allowed
        );
        assert_eq!(
            session_allows(Some(&policy), "iam:CreateUser", "*"),
            SessionConstraintResult::Constrained
        );
    }

    #[test]
    fn session_policy_deny_statement_ignored() {
        // Deny statements in session policies don't override Allow at the session level.
        // The effective permissions engine handles deny separately.
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![
                stmt(Effect::Allow, &["s3:*"], &["*"]),
                stmt(Effect::Deny, &["s3:DeleteBucket"], &["*"]),
            ],
        };
        // Session policy still "allows" s3:DeleteBucket (deny is separate filter)
        let result = session_allows(Some(&policy), "s3:DeleteBucket", "*");
        assert_eq!(result, SessionConstraintResult::Allowed);
    }

    #[test]
    fn session_policy_empty_allows_nothing() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![],
        };
        let result = session_allows(Some(&policy), "s3:GetObject", "*");
        assert_eq!(result, SessionConstraintResult::Constrained);
    }

    #[test]
    fn session_policy_with_notaction() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![PolicyStatement {
                sid: None,
                effect: Effect::Allow,
                actions: vec![],
                not_actions: vec![ActionPattern("iam:*".to_string())],
                resources: vec![ResourcePattern("*".to_string())],
                not_resources: vec![],
                conditions: vec![],
            }],
        };
        // NotAction: allow all EXCEPT iam:*
        assert_eq!(
            session_allows(Some(&policy), "s3:GetObject", "*"),
            SessionConstraintResult::Allowed
        );
        assert_eq!(
            session_allows(Some(&policy), "iam:CreateUser", "*"),
            SessionConstraintResult::Constrained
        );
    }

    #[test]
    fn session_policy_with_notresource() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![PolicyStatement {
                sid: None,
                effect: Effect::Allow,
                actions: vec![ActionPattern("s3:*".to_string())],
                not_actions: vec![],
                resources: vec![],
                not_resources: vec![ResourcePattern("arn:aws:s3:::restricted-*".to_string())],
                conditions: vec![],
            }],
        };
        // NotResource: allow s3:* on all EXCEPT arn:aws:s3:::restricted-*
        assert_eq!(
            session_allows(Some(&policy), "s3:GetObject", "arn:aws:s3:::public-bucket"),
            SessionConstraintResult::Allowed
        );
        assert_eq!(
            session_allows(
                Some(&policy),
                "s3:GetObject",
                "arn:aws:s3:::restricted-data"
            ),
            SessionConstraintResult::Constrained
        );
    }

    #[test]
    fn session_policy_case_insensitive_action() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![stmt(Effect::Allow, &["s3:getobject"], &["*"])],
        };
        let result = session_allows(Some(&policy), "S3:GETOBJECT", "*");
        assert_eq!(result, SessionConstraintResult::Allowed);
    }

    // ==================== effective_permissions_with_session tests ====================

    #[test]
    fn effective_permissions_no_session_returns_base() {
        let base = vec![
            crate::effective_permissions::EffectivePermission {
                action: "s3:GetObject".to_string(),
                resource: "*".to_string(),
            },
            crate::effective_permissions::EffectivePermission {
                action: "iam:CreateUser".to_string(),
                resource: "*".to_string(),
            },
        ];
        let result = effective_permissions_with_session(&base, None);
        assert_eq!(result, base);
    }

    #[test]
    fn effective_permissions_session_restricts() {
        let base = vec![
            crate::effective_permissions::EffectivePermission {
                action: "s3:GetObject".to_string(),
                resource: "*".to_string(),
            },
            crate::effective_permissions::EffectivePermission {
                action: "iam:CreateUser".to_string(),
                resource: "*".to_string(),
            },
        ];
        let session = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![stmt(Effect::Allow, &["s3:*"], &["*"])],
        };
        let result = effective_permissions_with_session(&base, Some(&session));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].action, "s3:GetObject");
    }

    #[test]
    fn effective_permissions_session_removes_all() {
        let base = vec![crate::effective_permissions::EffectivePermission {
            action: "iam:CreateUser".to_string(),
            resource: "*".to_string(),
        }];
        let session = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![stmt(Effect::Allow, &["s3:*"], &["*"])],
        };
        let result = effective_permissions_with_session(&base, Some(&session));
        assert!(result.is_empty());
    }

    #[test]
    fn effective_permissions_empty_base_with_session() {
        let base: Vec<crate::effective_permissions::EffectivePermission> = vec![];
        let session = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![stmt(Effect::Allow, &["s3:*"], &["*"])],
        };
        let result = effective_permissions_with_session(&base, Some(&session));
        assert!(result.is_empty());
    }

    #[test]
    fn effective_permissions_session_broader_than_base() {
        let base = vec![crate::effective_permissions::EffectivePermission {
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::restricted/*".to_string(),
        }];
        // Session policy is broader (allows all resources)
        let session = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![stmt(Effect::Allow, &["s3:GetObject"], &["*"])],
        };
        let result = effective_permissions_with_session(&base, Some(&session));
        // Intersection: base's resource constraint wins (more restrictive)
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].resource, "arn:aws:s3:::restricted/*");
    }

    #[test]
    fn effective_permissions_multiple_base_filtered_by_session() {
        let base = vec![
            crate::effective_permissions::EffectivePermission {
                action: "s3:GetObject".to_string(),
                resource: "*".to_string(),
            },
            crate::effective_permissions::EffectivePermission {
                action: "s3:PutObject".to_string(),
                resource: "*".to_string(),
            },
            crate::effective_permissions::EffectivePermission {
                action: "dynamodb:GetItem".to_string(),
                resource: "*".to_string(),
            },
            crate::effective_permissions::EffectivePermission {
                action: "iam:ListUsers".to_string(),
                resource: "*".to_string(),
            },
        ];
        let session = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![
                stmt(Effect::Allow, &["s3:GetObject"], &["*"]),
                stmt(Effect::Allow, &["dynamodb:*"], &["*"]),
            ],
        };
        let result = effective_permissions_with_session(&base, Some(&session));
        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|p| p.action == "s3:GetObject"));
        assert!(result.iter().any(|p| p.action == "dynamodb:GetItem"));
        assert!(!result.iter().any(|p| p.action == "s3:PutObject"));
        assert!(!result.iter().any(|p| p.action == "iam:ListUsers"));
    }

    #[test]
    fn effective_permissions_preserves_resource_matching() {
        let base = vec![
            crate::effective_permissions::EffectivePermission {
                action: "s3:GetObject".to_string(),
                resource: "arn:aws:s3:::bucket1/*".to_string(),
            },
            crate::effective_permissions::EffectivePermission {
                action: "s3:GetObject".to_string(),
                resource: "arn:aws:s3:::bucket2/*".to_string(),
            },
        ];
        let session = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![stmt(
                Effect::Allow,
                &["s3:GetObject"],
                &["arn:aws:s3:::bucket1/*"],
            )],
        };
        let result = effective_permissions_with_session(&base, Some(&session));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].resource, "arn:aws:s3:::bucket1/*");
    }
}
