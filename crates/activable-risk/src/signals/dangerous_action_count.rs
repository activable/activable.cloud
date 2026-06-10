/// Dangerous Action Count Signal: Tier-weighted dangerous IAM actions
///
/// Detects high-impact IAM actions that enable escalation or lateral movement.
/// Uses the dangerous_actions registry from activable-iam-engine.
///
/// Raw value: tier-weighted sum (tier 1=3, tier 2=2, tier 3=1)
/// Normalized: min(1.0, raw / 10.0) — 10 weighted units = max score
/// Pure Rust — no graph queries, works on effective permissions directly.
use crate::rule_engine::EffectivePermission;

/// Tier weights for dangerous actions
/// Tier 1 (instant self-escalation): weight 3
/// Tier 2 (lateral/new-passrole): weight 2
/// Tier 3 (credential access / enabler): weight 1
fn tier_weight(tier: u8) -> f64 {
    match tier {
        1 => 3.0,
        2 => 2.0,
        3 => 1.0,
        _ => 0.5,
    }
}

/// Dangerous action count signal: tier-weighted dangerous actions
pub struct DangerousActionCountSignal;

impl DangerousActionCountSignal {
    /// Compute dangerous action count synchronously from effective permissions.
    /// No async needed — this is pure Rust, no graph queries.
    pub fn compute_sync(&self, effective_perms: &[EffectivePermission]) -> super::SignalResult {
        let registry = activable_iam_engine::load_dangerous_actions_registry();

        // Convert from crate::EffectivePermission to activable_iam_engine's DangerousActionEffectivePermission
        let ingest_perms: Vec<activable_iam_engine::DangerousActionEffectivePermission> =
            effective_perms
                .iter()
                .map(
                    |p| activable_iam_engine::DangerousActionEffectivePermission {
                        action: p.action.clone(),
                        resource: p.resource.clone(),
                    },
                )
                .collect();

        let matches = activable_iam_engine::detect_dangerous_actions(&ingest_perms, &registry);

        // Sum tier weights
        let raw_value: f64 = matches.iter().map(|m| tier_weight(m.tier)).sum();

        // Normalize: cap at 10 weighted units
        let normalized = (raw_value / 10.0).min(1.0);

        super::SignalResult::new(
            "dangerous_action_count",
            raw_value,
            normalized,
            0.25, // moderate weight
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eff(action: &str, resource: &str) -> EffectivePermission {
        EffectivePermission::new(action, resource)
    }

    #[test]
    fn no_dangerous_actions() {
        let perms = vec![eff("s3:GetObject", "*")]; // safe
        let signal = DangerousActionCountSignal;
        let result = signal.compute_sync(&perms);
        assert_eq!(result.raw_value, 0.0);
        assert_eq!(result.normalized, 0.0);
    }

    #[test]
    fn single_tier1_action() {
        // iam:CreatePolicyVersion is tier 1 (policy rewrite)
        let perms = vec![eff("iam:CreatePolicyVersion", "*")];
        let signal = DangerousActionCountSignal;
        let result = signal.compute_sync(&perms);
        // Should match at least one tier 1 action (3 point weight)
        assert!(result.raw_value >= 3.0);
        assert!(result.normalized >= 0.3);
    }

    #[test]
    fn single_tier2_action() {
        // sts:AssumeRole is tier 2 (lateral movement)
        let perms = vec![eff("sts:AssumeRole", "*")];
        let signal = DangerousActionCountSignal;
        let result = signal.compute_sync(&perms);
        // Should match assume-role (tier 2 = weight 2)
        assert!(result.raw_value >= 2.0);
        assert!(result.normalized >= 0.2);
    }

    #[test]
    fn single_tier3_action() {
        // iam:CreateInstanceProfile is tier 3
        let perms = vec![eff("iam:CreateInstanceProfile", "*")];
        let signal = DangerousActionCountSignal;
        let result = signal.compute_sync(&perms);
        // Should match at least one tier 3 action (weight 1)
        assert!(result.raw_value >= 1.0);
        assert!(result.normalized >= 0.1);
    }

    #[test]
    fn mixed_tiers() {
        // Combination of dangerous actions
        let perms = vec![
            eff("iam:CreatePolicyVersion", "*"),   // tier 1 = 3+
            eff("sts:AssumeRole", "*"),            // tier 2 = 2+
            eff("iam:CreateInstanceProfile", "*"), // tier 3 = 1+
        ];
        let signal = DangerousActionCountSignal;
        let result = signal.compute_sync(&perms);
        // Should have at least 3 + 2 + 1 = 6 points
        assert!(result.raw_value >= 6.0);
        assert!(result.normalized >= 0.6);
    }

    #[test]
    fn exceeds_normalization_cap() {
        // Multiple dangerous actions exceeding 10 weighted units
        let perms = vec![
            eff("iam:CreatePolicyVersion", "*"),
            eff("iam:AttachUserPolicy", "*"),
            eff("iam:AttachRolePolicy", "*"),
            eff("iam:PutUserPolicy", "*"),
            eff("sts:AssumeRole", "*"),
        ];
        let signal = DangerousActionCountSignal;
        let result = signal.compute_sync(&perms);
        // Multiple tier 1 actions (3 each) should exceed 10
        assert!(result.raw_value >= 10.0);
        assert_eq!(result.normalized, 1.0); // capped at 1.0
    }

    #[test]
    fn wildcard_matches_all_dangerous_actions() {
        // Principal with * permission should match all dangerous actions
        let perms = vec![eff("*", "*")];
        let signal = DangerousActionCountSignal;
        let result = signal.compute_sync(&perms);
        assert!(result.raw_value > 0.0); // should have matched dangerous actions
        assert_eq!(result.normalized, 1.0); // definitely exceeds 10 weighted units
    }

    #[test]
    fn dangerous_action_signal_has_correct_name() {
        let signal = DangerousActionCountSignal;
        let result = signal.compute_sync(&[]);
        assert_eq!(result.name, "dangerous_action_count");
    }
}
