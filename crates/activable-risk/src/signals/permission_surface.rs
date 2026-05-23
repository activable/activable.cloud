/// Permission Surface Signal: Total count of effective permissions
///
/// Measures the attack surface — broader permissions = more paths to exploit.
/// Wildcard `*` is expanded to ~15000 (AWS's full IAM action catalog).
///
/// Raw value: count of effective permissions (expand `*` to 15000)
/// Normalized: log10(raw + 1) / log10(15000.0) — full AWS catalog = max
/// Pure Rust — no graph queries, works on effective permissions directly.
use crate::rule_engine::EffectivePermission;
use super::{log_normalize, SignalResult};

/// Approximate size of AWS IAM action catalog
const AWS_CATALOG_SIZE: f64 = 15000.0;

/// Permission surface signal: count of effective permissions
pub struct PermissionSurfaceSignal;

impl PermissionSurfaceSignal {
    /// Compute permission surface synchronously from effective permissions.
    /// No async needed — this is pure Rust, no graph queries.
    pub fn compute_sync(&self, effective_perms: &[EffectivePermission]) -> SignalResult {
        // Count permissions, expanding wildcards
        let raw_value = effective_perms.iter().fold(0.0, |acc, perm| {
            if perm.action == "*" {
                // Wildcard action matches all AWS actions
                acc + AWS_CATALOG_SIZE
            } else {
                acc + 1.0
            }
        });

        // Normalize: log scale to cap at ~15000 actions
        let normalized = log_normalize(raw_value, AWS_CATALOG_SIZE);

        SignalResult::new(
            "permission_surface",
            raw_value,
            normalized,
            0.20, // moderate weight
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
    fn permission_surface_empty() {
        let perms = vec![];
        let signal = PermissionSurfaceSignal;
        let result = signal.compute_sync(&perms);
        assert_eq!(result.raw_value, 0.0);
        assert_eq!(result.normalized, 0.0);
    }

    #[test]
    fn permission_surface_single_specific_action() {
        let perms = vec![eff("s3:GetObject", "*")];
        let signal = PermissionSurfaceSignal;
        let result = signal.compute_sync(&perms);
        assert_eq!(result.raw_value, 1.0);
        assert!(result.normalized > 0.0 && result.normalized < 0.2);
    }

    #[test]
    fn permission_surface_multiple_specific_actions() {
        let perms = (0..50)
            .map(|i| eff(&format!("s3:Get{}", i), "*"))
            .collect::<Vec<_>>();
        let signal = PermissionSurfaceSignal;
        let result = signal.compute_sync(&perms);
        assert_eq!(result.raw_value, 50.0);
        assert!(result.normalized > 0.0 && result.normalized < 0.5); // 50 is low
    }

    #[test]
    fn permission_surface_wildcard_action() {
        // Wildcard action = all AWS actions
        let perms = vec![eff("*", "*")];
        let signal = PermissionSurfaceSignal;
        let result = signal.compute_sync(&perms);
        assert_eq!(result.raw_value, AWS_CATALOG_SIZE);
        assert!(result.normalized > 0.95); // ~15000 actions = nearly max
    }

    #[test]
    fn permission_surface_admin() {
        // Principal with admin policy (usually includes * actions)
        let perms = vec![eff("*", "*")];
        let signal = PermissionSurfaceSignal;
        let result = signal.compute_sync(&perms);
        assert!(result.normalized > 0.95);
    }

    #[test]
    fn permission_surface_readonly() {
        // Readonly principal (safe actions only)
        let perms = vec![
            eff("s3:GetObject", "*"),
            eff("s3:ListBucket", "*"),
            eff("dynamodb:GetItem", "*"),
        ];
        let signal = PermissionSurfaceSignal;
        let result = signal.compute_sync(&perms);
        assert_eq!(result.raw_value, 3.0);
        assert!(result.normalized < 0.3);
    }

    #[test]
    fn permission_surface_mixed_wildcards_and_specific() {
        // Some specific actions + some wildcard services
        let perms = vec![
            eff("s3:GetObject", "*"),
            eff("s3:*", "*"),     // s3 wildcard = 1 perm
            eff("ec2:*", "*"),    // ec2 wildcard = 1 perm
            eff("*", "*"),        // full wildcard = 15000 perms
        ];
        let signal = PermissionSurfaceSignal;
        let result = signal.compute_sync(&perms);
        // 1 + 1 + 1 + 15000 = 15003
        assert!(result.raw_value > 15000.0);
        // Normalized should be capped at ~1.0 (log normalization may have small float precision)
        assert!((result.normalized - 1.0).abs() < 0.01);
    }

    #[test]
    fn permission_surface_signal_has_correct_name() {
        let signal = PermissionSurfaceSignal;
        let result = signal.compute_sync(&[]);
        assert_eq!(result.name, "permission_surface");
    }

    #[test]
    fn permission_surface_log_normalized() {
        // Verify log normalization for permission surface
        // 100 permissions should normalize to something reasonable
        let perms = (0..100)
            .map(|i| eff(&format!("s3:Get{}", i), "*"))
            .collect::<Vec<_>>();
        let signal = PermissionSurfaceSignal;
        let result = signal.compute_sync(&perms);
        assert_eq!(result.raw_value, 100.0);
        // log10(101) / log10(15000) ≈ 0.37
        assert!(result.normalized > 0.3 && result.normalized < 0.5);
    }
}
