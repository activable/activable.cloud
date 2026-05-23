//! Dangerous IAM actions registry and detection.
//!
//! Loads a YAML registry of dangerous actions organized by escalation tier and severity.
//! Detects dangerous actions and combos in an effective permissions set.

use serde::{Deserialize, Serialize};

/// Severity level for dangerous actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
        }
    }
}

/// A dangerous action definition from the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DangerousAction {
    /// Unique identifier (e.g., "policy-rewrite", "pass-role-ec2")
    pub id: String,
    /// Escalation tier (1 = instant self-escalation, 2 = lateral/role assumption, 3 = enabler)
    pub tier: u8,
    /// Severity classification
    pub severity: Severity,
    /// Actions that trigger this danger
    pub actions: Vec<String>,
    /// If true, ALL actions must be present; if false, ANY action is sufficient
    pub combo: bool,
    /// Human-readable description
    #[serde(default)]
    pub description: String,
}

/// A match of an effective permission against a dangerous action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DangerousActionMatch {
    pub id: String,
    pub tier: u8,
    pub severity: Severity,
    pub reason: String, // e.g., "iam:CreatePolicyVersion (self-escalation)"
}

/// Load the dangerous actions registry from embedded YAML.
pub fn load_dangerous_actions_registry() -> Vec<DangerousAction> {
    let yaml_content = include_str!("../config/dangerous-actions.yaml");

    #[derive(Debug, Deserialize)]
    struct RegistryRoot {
        actions: Vec<DangerousAction>,
    }

    match serde_yaml::from_str::<RegistryRoot>(yaml_content) {
        Ok(root) => root.actions,
        Err(e) => {
            tracing::error!("Failed to parse dangerous-actions.yaml: {}", e);
            vec![]
        }
    }
}

/// An effective permission (action + resource pair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePermission {
    pub action: String,
    pub resource: String,
}

/// Detect dangerous actions and combos in an effective permissions set.
///
/// # Logic
/// - For non-combo actions: ANY effective permission matching the action is sufficient.
/// - For combo actions: ALL actions in the combo must be present in effective permissions.
/// - Wildcard `*` effective permission matches ANY dangerous action (O(1) special case).
pub fn detect_dangerous_actions(
    effective_perms: &[EffectivePermission],
    registry: &[DangerousAction],
) -> Vec<DangerousActionMatch> {
    let mut matches = Vec::new();

    // Special case: if principal has wildcard permission, all dangers are present
    if effective_perms.iter().any(|p| p.action == "*") {
        for danger in registry {
            matches.push(DangerousActionMatch {
                id: danger.id.clone(),
                tier: danger.tier,
                severity: danger.severity,
                reason: "* (wildcard — all actions allowed)".to_string(),
            });
        }
        return matches;
    }

    for danger in registry {
        if danger.combo {
            // Combo: ALL actions must be present
            let all_present = danger.actions.iter().all(|action| {
                effective_perms
                    .iter()
                    .any(|p| action_matches_pattern(&p.action, action))
            });
            if all_present {
                matches.push(DangerousActionMatch {
                    id: danger.id.clone(),
                    tier: danger.tier,
                    severity: danger.severity,
                    reason: format!("{} (combo)", danger.actions.join(" + ")),
                });
            }
        } else {
            // Non-combo: ANY action is sufficient
            let any_present = danger.actions.iter().any(|action| {
                effective_perms
                    .iter()
                    .any(|p| action_matches_pattern(&p.action, action))
            });
            if any_present {
                let matched_action = danger
                    .actions
                    .iter()
                    .find(|action| {
                        effective_perms
                            .iter()
                            .any(|p| action_matches_pattern(&p.action, action))
                    })
                    .cloned()
                    .unwrap_or_default();
                matches.push(DangerousActionMatch {
                    id: danger.id.clone(),
                    tier: danger.tier,
                    severity: danger.severity,
                    reason: format!("{} (single-action)", matched_action),
                });
            }
        }
    }

    matches
}

/// Check if an effective permission's action pattern matches a specific action.
/// Handles wildcards: "s3:*" matches "s3:GetObject", "*" matches everything.
fn action_matches_pattern(pattern: &str, action: &str) -> bool {
    if pattern == "*" || pattern == action {
        return true;
    }

    if let Some(star_pos) = pattern.find('*') {
        let prefix = &pattern[..star_pos];
        action.starts_with(prefix)
    } else {
        pattern == action
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eff(action: &str, resource: &str) -> EffectivePermission {
        EffectivePermission {
            action: action.to_string(),
            resource: resource.to_string(),
        }
    }

    #[test]
    fn load_registry_succeeds() {
        let registry = load_dangerous_actions_registry();
        assert!(!registry.is_empty(), "Registry should load successfully");
        assert!(registry.iter().any(|d| d.id == "policy-rewrite"));
        assert!(registry.iter().any(|d| d.id == "pass-role-ec2"));
    }

    #[test]
    fn wildcard_permission_matches_all_dangers() {
        let registry = load_dangerous_actions_registry();
        let perms = vec![eff("*", "*")];
        let matches = detect_dangerous_actions(&perms, &registry);
        assert_eq!(
            matches.len(),
            registry.len(),
            "Wildcard should match all dangers"
        );
    }

    #[test]
    fn single_action_danger_detected() {
        let registry = load_dangerous_actions_registry();
        let perms = vec![eff("iam:CreatePolicyVersion", "*")];
        let matches = detect_dangerous_actions(&perms, &registry);
        assert!(
            matches.iter().any(|m| m.id == "policy-rewrite"),
            "Should detect policy-rewrite"
        );
    }

    #[test]
    fn combo_danger_requires_all_actions() {
        let registry = load_dangerous_actions_registry();

        // Only PassRole — should NOT match combo
        let perms = vec![eff("iam:PassRole", "*")];
        let matches = detect_dangerous_actions(&perms, &registry);
        assert!(
            !matches.iter().any(|m| m.id == "pass-role-ec2"),
            "Combo should require both actions"
        );

        // Both PassRole and EC2 — SHOULD match combo
        let perms = vec![eff("iam:PassRole", "*"), eff("ec2:RunInstances", "*")];
        let matches = detect_dangerous_actions(&perms, &registry);
        assert!(
            matches.iter().any(|m| m.id == "pass-role-ec2"),
            "Combo should match when both actions present"
        );
    }

    #[test]
    fn action_matches_pattern_with_wildcard() {
        assert!(action_matches_pattern("s3:*", "s3:GetObject"));
        assert!(action_matches_pattern("s3:*", "s3:DeleteBucket"));
        assert!(action_matches_pattern("*", "any:action"));
        assert!(!action_matches_pattern("s3:*", "iam:CreateUser"));
        assert!(action_matches_pattern(
            "iam:CreatePolicyVersion",
            "iam:CreatePolicyVersion"
        ));
    }
}
