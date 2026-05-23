//! Escalation edge derivation from dangerous actions.
//!
//! Derive `CanEscalateTo` edges from effective permissions and dangerous action registry.
//! - Single-action tier-1 dangers → self-escalation edge (P → P)
//! - PassRole combos → lateral edge from principal to passable role (P → R)

use crate::dangerous_actions::{
    detect_dangerous_actions, load_dangerous_actions_registry, DangerousAction,
    EffectivePermission, Severity,
};

/// An escalation edge from one principal to another (or self-escalation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationEdge {
    /// Source principal ARN
    pub from: String,
    /// Target principal ARN (or "*" for wildcard, or self for self-escalation)
    pub to: String,
    /// Edge type (always "CanEscalateTo")
    pub edge_type: String,
    /// Human-readable reason (e.g., "iam:CreatePolicyVersion (self-escalation)")
    pub reason: String,
    /// Escalation tier
    pub tier: u8,
    /// Severity
    pub severity: Severity,
}

/// Derive escalation edges from a principal's effective permissions.
///
/// Logic:
/// - Single-action tier-1 dangers → self-escalation edge (P → P)
/// - PassRole combos → find roles in resource constraint, create edge P → R
///   - If PassRole resource is "*", create edge to wildcard target ("*" or "any_role")
pub fn derive_escalation_edges(
    principal: &str,
    effective_perms: &[EffectivePermission],
    registry: &[DangerousAction],
) -> Vec<EscalationEdge> {
    let mut edges = Vec::new();

    // Detect dangerous actions in this principal's permissions
    let dangerous_matches = detect_dangerous_actions(effective_perms, registry);

    for matched_danger in dangerous_matches {
        // Look up the full danger definition from registry
        let danger_def = registry
            .iter()
            .find(|d| d.id == matched_danger.id)
            .cloned();

        if danger_def.is_none() {
            continue;
        }
        let danger = danger_def.unwrap();

        // Tier 1 single-action: self-escalation
        if danger.tier == 1 && !danger.combo {
            edges.push(EscalationEdge {
                from: principal.to_string(),
                to: principal.to_string(),
                edge_type: "CanEscalateTo".to_string(),
                reason: format!("{} (self-escalation, tier 1)", danger.id),
                tier: danger.tier,
                severity: danger.severity,
            });
        }

        // PassRole combos: extract target role from resource constraint
        if danger.id.starts_with("pass-role") && danger.combo {
            // Find the PassRole permission's resource constraint
            let passrole_resources: Vec<String> = effective_perms
                .iter()
                .filter(|p| p.action == "iam:PassRole")
                .map(|p| p.resource.clone())
                .collect();

            for resource in passrole_resources {
                let target = if resource == "*" {
                    "*".to_string()
                } else {
                    // Resource is the target role ARN
                    resource
                };

                edges.push(EscalationEdge {
                    from: principal.to_string(),
                    to: target,
                    edge_type: "CanEscalateTo".to_string(),
                    reason: format!("{} (via PassRole + compute)", danger.id),
                    tier: danger.tier,
                    severity: danger.severity,
                });
            }
        }

        // Tier 2/3 single-action with PassRole: lateral movement
        if danger.id == "pass-role" && !danger.combo {
            let passrole_resources: Vec<String> = effective_perms
                .iter()
                .filter(|p| p.action == "iam:PassRole")
                .map(|p| p.resource.clone())
                .collect();

            for resource in passrole_resources {
                let target = if resource == "*" {
                    "*".to_string()
                } else {
                    resource
                };

                edges.push(EscalationEdge {
                    from: principal.to_string(),
                    to: target,
                    edge_type: "CanEscalateTo".to_string(),
                    reason: format!("iam:PassRole (lateral movement)"),
                    tier: danger.tier,
                    severity: danger.severity,
                });
            }
        }
    }

    // Deduplicate edges
    edges.sort_by(|a, b| {
        a.from
            .cmp(&b.from)
            .then_with(|| a.to.cmp(&b.to))
            .then_with(|| a.reason.cmp(&b.reason))
    });
    edges.dedup();

    edges
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
    fn self_escalation_edge_from_create_policy_version() {
        let principal = "arn:aws:iam::123456789012:user/alice";
        let perms = vec![eff("iam:CreatePolicyVersion", "arn:aws:iam::123456789012:policy/MyPolicy")];
        let registry = load_dangerous_actions_registry();
        let edges = derive_escalation_edges(principal, &perms, &registry);
        assert!(
            edges.iter().any(|e| e.from == principal && e.to == principal
                && e.edge_type == "CanEscalateTo"),
            "Should have self-escalation edge"
        );
    }

    #[test]
    fn passrole_ec2_creates_edge_to_passable_role() {
        let principal = "arn:aws:iam::123456789012:user/alice";
        let role = "arn:aws:iam::123456789012:role/admin-role";
        let perms = vec![
            eff("iam:PassRole", role),
            eff("ec2:RunInstances", "*"),
        ];
        let registry = load_dangerous_actions_registry();
        let edges = derive_escalation_edges(principal, &perms, &registry);
        assert!(
            edges.iter().any(|e| e.from == principal && e.to == role
                && e.edge_type == "CanEscalateTo"),
            "Should have edge to passable role"
        );
    }

    #[test]
    fn multiple_passable_roles_create_multiple_edges() {
        let principal = "arn:aws:iam::123456789012:user/alice";
        let role1 = "arn:aws:iam::123456789012:role/admin-role";
        let role2 = "arn:aws:iam::123456789012:role/lambda-role";
        let perms = vec![
            eff("iam:PassRole", role1),
            eff("iam:PassRole", role2),
            eff("ec2:RunInstances", "*"),
        ];
        let registry = load_dangerous_actions_registry();
        let edges = derive_escalation_edges(principal, &perms, &registry);
        let edge_targets: Vec<&String> = edges.iter().map(|e| &e.to).collect();
        assert!(edge_targets.contains(&&role1.to_string()));
        assert!(edge_targets.contains(&&role2.to_string()));
    }

    #[test]
    fn wildcard_passrole_creates_wildcard_target_edge() {
        let principal = "arn:aws:iam::123456789012:user/alice";
        let perms = vec![
            eff("iam:PassRole", "*"),
            eff("ec2:RunInstances", "*"),
        ];
        let registry = load_dangerous_actions_registry();
        let edges = derive_escalation_edges(principal, &perms, &registry);
        assert!(
            edges.iter().any(|e| e.from == principal && e.to == "*"),
            "Should have edge to wildcard target"
        );
    }

    #[test]
    fn tier_and_severity_propagate_to_edges() {
        let principal = "arn:aws:iam::123456789012:user/alice";
        let perms = vec![eff("iam:CreatePolicyVersion", "*")];
        let registry = load_dangerous_actions_registry();
        let edges = derive_escalation_edges(principal, &perms, &registry);
        assert!(
            edges.iter().any(|e| e.tier == 1 && e.severity == Severity::Critical),
            "Should propagate tier and severity"
        );
    }
}
