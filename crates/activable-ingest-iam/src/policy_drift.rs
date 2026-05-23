//! Semantic policy drift detection and version comparison.
//!
//! Compares two policy versions at the action + resource level to detect
//! permission expansion, contraction, and dangerous changes.

use std::collections::BTreeSet;

use crate::action_matcher::action_matches;
use crate::types::{Effect, ParsedPolicy};

/// A policy version with metadata
#[derive(Debug, Clone)]
pub struct PolicyVersion {
    pub version_id: String,
    pub policy_arn: String,
    pub is_default: bool,
    pub created_at: String, // ISO 8601
    pub policy: ParsedPolicy,
}

/// Result of comparing two policy versions
#[derive(Debug, Clone)]
pub struct PolicyDiff {
    pub policy_arn: String,
    pub from_version: String,
    pub to_version: String,
    pub actions_added: Vec<String>,     // new actions granted
    pub actions_removed: Vec<String>,   // actions revoked
    pub resources_added: Vec<String>,   // new resources accessible
    pub resources_removed: Vec<String>, // resources no longer accessible
    pub permission_expanded: bool,      // true if net permissions grew
    pub severity: DriftSeverity,
}

/// Severity classification of policy drift
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftSeverity {
    Critical, // admin-level actions added (iam:*, *)
    High,     // dangerous actions added (iam:CreatePolicyVersion, etc.)
    Medium,   // new actions/resources added
    Low,      // actions/resources removed (permissions contracted)
    None,     // no meaningful change
}

/// A set of (action, resource) permission pairs for semantic comparison
#[derive(Debug, Clone)]
struct PermissionSet {
    pairs: BTreeSet<(String, String)>,
}

impl PermissionSet {
    /// Extract all effective (action, resource) pairs from an Allow policy
    fn from_policy(policy: &ParsedPolicy) -> Self {
        let mut pairs = BTreeSet::new();

        for stmt in &policy.statements {
            // Only process Allow statements for permission sets
            if stmt.effect != Effect::Allow {
                continue;
            }

            // Get actions: use explicit actions if present, otherwise compute from NotAction
            let actions = if !stmt.actions.is_empty() {
                // clippy: non-empty is clearer than len() > 0
                stmt.actions.iter().map(|a| a.0.clone()).collect::<Vec<_>>()
            } else {
                // For NotAction, we can't enumerate all possible actions.
                // In a full implementation, we'd use a predefined set of all AWS actions.
                // For now, we represent NotAction actions as empty set and handle separately.
                vec![]
            };

            // Get resources: use explicit resources if present, otherwise compute from NotResource
            let resources = if !stmt.resources.is_empty() {
                // clippy: non-empty is clearer
                stmt.resources
                    .iter()
                    .map(|r| r.0.clone())
                    .collect::<Vec<_>>()
            } else {
                // For NotResource, similarly we can't enumerate all possible resources.
                vec![]
            };

            // Add all (action, resource) pairs
            if !actions.is_empty() && !resources.is_empty() {
                for action in &actions {
                    for resource in &resources {
                        pairs.insert((action.clone(), resource.clone()));
                    }
                }
            }
        }

        PermissionSet { pairs }
    }

    /// Compute set operations on permission sets
    fn difference(&self, other: &PermissionSet) -> Vec<(String, String)> {
        self.pairs
            .iter()
            .filter(|p| !other.pairs.contains(p))
            .cloned()
            .collect()
    }

    #[allow(dead_code)]
    fn union(&self, other: &PermissionSet) -> Vec<(String, String)> {
        self.pairs.union(&other.pairs).cloned().collect()
    }
}

/// Check if an action is dangerous (could lead to privilege escalation)
fn is_dangerous_action(action: &str) -> bool {
    let action_lower = action.to_lowercase();

    // Wildcard patterns that are always dangerous
    if action_lower == "*" {
        return true;
    }
    if action_lower == "iam:*" {
        return true;
    }

    // Specific dangerous IAM actions
    let dangerous_patterns = [
        "iam:CreatePolicyVersion",
        "iam:CreatePolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:PutGroupPolicy",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachGroupPolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:SetDefaultPolicyVersion",
        "iam:PassRole",
        "sts:AssumeRole",
    ];

    for pattern in &dangerous_patterns {
        if action_matches(pattern, action) {
            return true;
        }
    }

    false
}

/// Compare two parsed policies and produce a semantic diff.
///
/// Analyzes at the action+resource level, not string diff.
pub fn diff_policies(
    from: &ParsedPolicy,
    to: &ParsedPolicy,
    policy_arn: &str,
    from_version: &str,
    to_version: &str,
) -> PolicyDiff {
    let from_set = PermissionSet::from_policy(from);
    let to_set = PermissionSet::from_policy(to);

    // Compute differences
    let added_pairs = to_set.difference(&from_set);
    let removed_pairs = from_set.difference(&to_set);

    // Extract actions and resources from pairs
    let mut actions_added = BTreeSet::new();
    let mut resources_added = BTreeSet::new();

    for (action, resource) in &added_pairs {
        actions_added.insert(action.clone());
        resources_added.insert(resource.clone());
    }

    let mut actions_removed = BTreeSet::new();
    let mut resources_removed = BTreeSet::new();

    for (action, resource) in &removed_pairs {
        actions_removed.insert(action.clone());
        resources_removed.insert(resource.clone());
    }

    let actions_added_vec: Vec<String> = actions_added.into_iter().collect();
    let actions_removed_vec: Vec<String> = actions_removed.into_iter().collect();
    let resources_added_vec: Vec<String> = resources_added.into_iter().collect();
    let resources_removed_vec: Vec<String> = resources_removed.into_iter().collect();

    // Determine if permissions expanded
    let permission_expanded = !added_pairs.is_empty();

    // Determine severity
    let severity = if actions_added_vec.iter().any(|a| is_dangerous_action(a)) {
        if actions_added_vec.iter().any(|a| a == "*" || a == "iam:*") {
            DriftSeverity::Critical
        } else {
            DriftSeverity::High
        }
    } else if permission_expanded {
        DriftSeverity::Medium
    } else if !removed_pairs.is_empty() {
        DriftSeverity::Low
    } else {
        DriftSeverity::None
    };

    PolicyDiff {
        policy_arn: policy_arn.to_string(),
        from_version: from_version.to_string(),
        to_version: to_version.to_string(),
        actions_added: actions_added_vec,
        actions_removed: actions_removed_vec,
        resources_added: resources_added_vec,
        resources_removed: resources_removed_vec,
        permission_expanded,
        severity,
    }
}

/// Analyze a sequence of policy versions for drift patterns.
/// Returns diffs between consecutive versions.
pub fn analyze_version_history(versions: &[PolicyVersion]) -> Vec<PolicyDiff> {
    if versions.len() < 2 {
        return Vec::new();
    }

    // Sort by created_at to ensure chronological order
    let mut sorted_versions = versions.to_vec();
    sorted_versions.sort_by(|a, b| a.created_at.cmp(&b.created_at));

    let mut diffs = Vec::new();

    // Compare consecutive versions
    for i in 0..sorted_versions.len() - 1 {
        let from = &sorted_versions[i];
        let to = &sorted_versions[i + 1];

        let diff = diff_policies(
            &from.policy,
            &to.policy,
            &from.policy_arn,
            &from.version_id,
            &to.version_id,
        );
        diffs.push(diff);
    }

    diffs
}

/// Calculate a drift score (0.0-1.0) from policy diffs.
/// Higher = more permission expansion over time.
pub fn compute_drift_score(diffs: &[PolicyDiff]) -> f64 {
    if diffs.is_empty() {
        return 0.0;
    }

    let mut expansion_count = 0;
    let mut critical_count = 0;
    let mut high_count = 0;

    for diff in diffs {
        if diff.permission_expanded {
            expansion_count += 1;
        }

        match diff.severity {
            DriftSeverity::Critical => critical_count += 1,
            DriftSeverity::High => high_count += 1,
            _ => {}
        }
    }

    let expansion_ratio = expansion_count as f64 / diffs.len() as f64;

    // Weight by severity: critical and high severity changes increase score more
    let severity_weight =
        (critical_count as f64 * 1.0 + high_count as f64 * 0.5) / diffs.len() as f64;

    // Combine: 70% expansion ratio, 30% severity
    let score = (expansion_ratio * 0.7) + (severity_weight * 0.3);

    // Clamp to [0.0, 1.0]
    score.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy(
        version: &str,
        effects_actions_resources: Vec<(Effect, Vec<&str>, Vec<&str>)>,
    ) -> ParsedPolicy {
        use crate::types::{ActionPattern, ResourcePattern};

        let statements = effects_actions_resources
            .into_iter()
            .enumerate()
            .map(
                |(idx, (effect, actions, resources))| crate::types::PolicyStatement {
                    sid: Some(format!("Stmt{}", idx)),
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
                },
            )
            .collect();

        ParsedPolicy {
            version: version.to_string(),
            statements,
        }
    }

    // ===== Test: No changes → severity None =====

    #[test]
    fn diff_identical_policies() {
        let policy = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let diff = diff_policies(
            &policy,
            &policy,
            "arn:aws:iam::123456789:policy/Test",
            "v1",
            "v2",
        );

        assert_eq!(diff.severity, DriftSeverity::None);
        assert!(!diff.permission_expanded);
        assert!(diff.actions_added.is_empty());
        assert!(diff.actions_removed.is_empty());
    }

    // ===== Test: Action added → severity Medium + permission_expanded=true =====

    #[test]
    fn diff_action_added() {
        let from = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let to = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject", "s3:PutObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let diff = diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2");

        assert_eq!(diff.severity, DriftSeverity::Medium);
        assert!(diff.permission_expanded);
        assert!(diff.actions_added.contains(&"s3:PutObject".to_string()));
    }

    // ===== Test: Dangerous action added (iam:*) → severity Critical =====

    #[test]
    fn diff_dangerous_action_all_iam() {
        let from = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let to = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject", "iam:*"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let diff = diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2");

        assert_eq!(diff.severity, DriftSeverity::Critical);
        assert!(diff.permission_expanded);
    }

    // ===== Test: Dangerous action added (*) → severity Critical =====

    #[test]
    fn diff_dangerous_action_all() {
        let from = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let to = make_policy("2012-10-17", vec![(Effect::Allow, vec!["*"], vec!["*"])]);

        let diff = diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2");

        assert_eq!(diff.severity, DriftSeverity::Critical);
        assert!(diff.permission_expanded);
    }

    // ===== Test: Dangerous action added (iam:CreatePolicyVersion) → severity High =====

    #[test]
    fn diff_dangerous_action_create_policy_version() {
        let from = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let to = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject", "iam:CreatePolicyVersion"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let diff = diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2");

        assert_eq!(diff.severity, DriftSeverity::High);
        assert!(diff.permission_expanded);
    }

    // ===== Test: Action removed → severity Low =====

    #[test]
    fn diff_action_removed() {
        let from = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject", "s3:PutObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let to = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let diff = diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2");

        assert_eq!(diff.severity, DriftSeverity::Low);
        assert!(!diff.permission_expanded);
        assert!(diff.actions_removed.contains(&"s3:PutObject".to_string()));
    }

    // ===== Test: Resource expanded (specific→*) → severity Medium (new resource permission pair) =====

    #[test]
    fn diff_resource_expanded() {
        let from = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject"],
                vec!["arn:aws:s3:::specific-bucket/*"],
            )],
        );

        let to = make_policy(
            "2012-10-17",
            vec![(Effect::Allow, vec!["s3:GetObject"], vec!["arn:aws:s3:::*"])],
        );

        let diff = diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2");

        assert_eq!(diff.severity, DriftSeverity::Medium);
        assert!(diff.permission_expanded);
        assert!(diff.resources_added.contains(&"arn:aws:s3:::*".to_string()));
    }

    // ===== Test: analyze_version_history with 3 versions → 2 diffs =====

    #[test]
    fn analyze_three_versions() {
        let v1 = PolicyVersion {
            version_id: "v1".to_string(),
            policy_arn: "arn:aws:iam::123456789:policy/Test".to_string(),
            is_default: false,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            policy: make_policy(
                "2012-10-17",
                vec![(
                    Effect::Allow,
                    vec!["s3:GetObject"],
                    vec!["arn:aws:s3:::bucket/*"],
                )],
            ),
        };

        let v2 = PolicyVersion {
            version_id: "v2".to_string(),
            policy_arn: "arn:aws:iam::123456789:policy/Test".to_string(),
            is_default: false,
            created_at: "2024-01-02T00:00:00Z".to_string(),
            policy: make_policy(
                "2012-10-17",
                vec![(
                    Effect::Allow,
                    vec!["s3:GetObject", "s3:PutObject"],
                    vec!["arn:aws:s3:::bucket/*"],
                )],
            ),
        };

        let v3 = PolicyVersion {
            version_id: "v3".to_string(),
            policy_arn: "arn:aws:iam::123456789:policy/Test".to_string(),
            is_default: true,
            created_at: "2024-01-03T00:00:00Z".to_string(),
            policy: make_policy(
                "2012-10-17",
                vec![(Effect::Allow, vec!["s3:*"], vec!["arn:aws:s3:::*"])],
            ),
        };

        let diffs = analyze_version_history(&[v2.clone(), v1.clone(), v3.clone()]);

        assert_eq!(diffs.len(), 2);
        assert_eq!(diffs[0].from_version, "v1");
        assert_eq!(diffs[0].to_version, "v2");
        assert_eq!(diffs[1].from_version, "v2");
        assert_eq!(diffs[1].to_version, "v3");
    }

    // ===== Test: analyze_version_history with single version → empty diffs =====

    #[test]
    fn analyze_single_version() {
        let v1 = PolicyVersion {
            version_id: "v1".to_string(),
            policy_arn: "arn:aws:iam::123456789:policy/Test".to_string(),
            is_default: true,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            policy: make_policy(
                "2012-10-17",
                vec![(
                    Effect::Allow,
                    vec!["s3:GetObject"],
                    vec!["arn:aws:s3:::bucket/*"],
                )],
            ),
        };

        let diffs = analyze_version_history(&[v1]);

        assert_eq!(diffs.len(), 0);
    }

    // ===== Test: compute_drift_score with no expansions → 0.0 =====

    #[test]
    fn compute_score_no_expansions() {
        let from = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject", "s3:PutObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let to = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let diff = diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2");
        let score = compute_drift_score(&[diff]);

        assert_eq!(score, 0.0);
    }

    // ===== Test: compute_drift_score with multiple critical expansions → high score =====

    #[test]
    fn compute_score_critical_expansions() {
        let diffs = vec![
            {
                let from = make_policy(
                    "2012-10-17",
                    vec![(
                        Effect::Allow,
                        vec!["s3:GetObject"],
                        vec!["arn:aws:s3:::bucket/*"],
                    )],
                );
                let to = make_policy("2012-10-17", vec![(Effect::Allow, vec!["*"], vec!["*"])]);
                diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2")
            },
            {
                let from = make_policy("2012-10-17", vec![(Effect::Allow, vec!["*"], vec!["*"])]);
                let to = make_policy("2012-10-17", vec![(Effect::Allow, vec!["*"], vec!["*"])]);
                diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v2", "v3")
            },
        ];

        let score = compute_drift_score(&diffs);

        // First diff: expansion_ratio=1.0, severity=1.0 (critical)
        // Second diff: expansion_ratio=0.0, severity=0.0 (none)
        // Average expansion: 0.5, average severity: 0.5
        // Score = 0.5 * 0.7 + 0.5 * 0.3 = 0.5
        assert!(score > 0.4 && score < 0.6);
    }

    // ===== Test: Version ordering by created_at =====

    #[test]
    fn version_ordering() {
        let v1 = PolicyVersion {
            version_id: "v1".to_string(),
            policy_arn: "arn:aws:iam::123456789:policy/Test".to_string(),
            is_default: false,
            created_at: "2024-01-03T00:00:00Z".to_string(),
            policy: make_policy(
                "2012-10-17",
                vec![(
                    Effect::Allow,
                    vec!["s3:GetObject"],
                    vec!["arn:aws:s3:::bucket/*"],
                )],
            ),
        };

        let v2 = PolicyVersion {
            version_id: "v2".to_string(),
            policy_arn: "arn:aws:iam::123456789:policy/Test".to_string(),
            is_default: false,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            policy: make_policy(
                "2012-10-17",
                vec![(
                    Effect::Allow,
                    vec!["s3:GetObject", "s3:PutObject"],
                    vec!["arn:aws:s3:::bucket/*"],
                )],
            ),
        };

        let v3 = PolicyVersion {
            version_id: "v3".to_string(),
            policy_arn: "arn:aws:iam::123456789:policy/Test".to_string(),
            is_default: true,
            created_at: "2024-01-02T00:00:00Z".to_string(),
            policy: make_policy(
                "2012-10-17",
                vec![(Effect::Allow, vec!["s3:*"], vec!["arn:aws:s3:::*"])],
            ),
        };

        let diffs = analyze_version_history(&[v1, v2, v3]);

        // Should be in order: v2 (01-01), v3 (01-02), v1 (01-03)
        assert_eq!(diffs[0].from_version, "v2");
        assert_eq!(diffs[0].to_version, "v3");
        assert_eq!(diffs[1].from_version, "v3");
        assert_eq!(diffs[1].to_version, "v1");
    }

    // ===== Test: Multiple actions added =====

    #[test]
    fn diff_multiple_actions_added() {
        let from = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let to = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let diff = diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2");

        assert_eq!(diff.actions_added.len(), 2);
        assert!(diff.actions_added.contains(&"s3:PutObject".to_string()));
        assert!(diff.actions_added.contains(&"s3:DeleteObject".to_string()));
    }

    // ===== Test: Wildcard action matching =====

    #[test]
    fn diff_wildcard_action_expansion() {
        let from = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["s3:Get*"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let to = make_policy(
            "2012-10-17",
            vec![(Effect::Allow, vec!["s3:*"], vec!["arn:aws:s3:::bucket/*"])],
        );

        let diff = diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2");

        assert!(diff.permission_expanded);
    }

    // ===== Test: Empty policy (no statements) =====

    #[test]
    fn diff_empty_policies() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![],
        };

        let diff = diff_policies(
            &policy,
            &policy,
            "arn:aws:iam::123456789:policy/Test",
            "v1",
            "v2",
        );

        assert_eq!(diff.severity, DriftSeverity::None);
        assert!(!diff.permission_expanded);
    }

    // ===== Test: Deny statements are ignored in Allow set =====

    #[test]
    fn diff_only_deny_statements() {
        let from = make_policy(
            "2012-10-17",
            vec![(
                Effect::Deny,
                vec!["s3:DeleteObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let to = make_policy(
            "2012-10-17",
            vec![(
                Effect::Deny,
                vec!["s3:DeleteObject", "s3:PutObject"],
                vec!["arn:aws:s3:::bucket/*"],
            )],
        );

        let diff = diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2");

        // Deny changes don't affect the Allow set
        assert_eq!(diff.severity, DriftSeverity::None);
        assert!(!diff.permission_expanded);
    }

    // ===== Test: Mixed Allow and Deny statements =====

    #[test]
    fn diff_mixed_allow_deny() {
        let from = make_policy(
            "2012-10-17",
            vec![
                (
                    Effect::Allow,
                    vec!["s3:GetObject"],
                    vec!["arn:aws:s3:::bucket/*"],
                ),
                (
                    Effect::Deny,
                    vec!["s3:DeleteObject"],
                    vec!["arn:aws:s3:::bucket/secure/*"],
                ),
            ],
        );

        let to = make_policy(
            "2012-10-17",
            vec![
                (
                    Effect::Allow,
                    vec!["s3:GetObject", "s3:PutObject"],
                    vec!["arn:aws:s3:::bucket/*"],
                ),
                (
                    Effect::Deny,
                    vec!["s3:DeleteObject"],
                    vec!["arn:aws:s3:::bucket/secure/*"],
                ),
            ],
        );

        let diff = diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2");

        // Only the Allow diff should affect result
        assert!(diff.permission_expanded);
        assert!(diff.actions_added.contains(&"s3:PutObject".to_string()));
    }

    // ===== Test: PassRole and AssumeRole (dangerous actions) =====

    #[test]
    fn diff_dangerous_action_pass_role() {
        let from = make_policy(
            "2012-10-17",
            vec![(Effect::Allow, vec!["ec2:DescribeInstances"], vec!["*"])],
        );

        let to = make_policy(
            "2012-10-17",
            vec![(
                Effect::Allow,
                vec!["ec2:DescribeInstances", "iam:PassRole"],
                vec!["*"],
            )],
        );

        let diff = diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2");

        assert_eq!(diff.severity, DriftSeverity::High);
    }

    // ===== Test: compute_drift_score with empty diffs → 0.0 =====

    #[test]
    fn compute_score_empty_diffs() {
        let score = compute_drift_score(&[]);
        assert_eq!(score, 0.0);
    }

    // ===== Test: compute_drift_score returns clamped value [0.0, 1.0] =====

    #[test]
    fn compute_score_clamped() {
        let diffs = vec![{
            let from = make_policy(
                "2012-10-17",
                vec![(
                    Effect::Allow,
                    vec!["s3:GetObject"],
                    vec!["arn:aws:s3:::bucket/*"],
                )],
            );
            let to = make_policy("2012-10-17", vec![(Effect::Allow, vec!["*"], vec!["*"])]);
            diff_policies(&from, &to, "arn:aws:iam::123456789:policy/Test", "v1", "v2")
        }];

        let score = compute_drift_score(&diffs);

        assert!((0.0..=1.0).contains(&score));
    }
}
