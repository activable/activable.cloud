use crate::types::{EscalationRule, MatchedRule};
use activable_ingest_iam::action_matches;

/// Effective permission for a principal
#[derive(Debug, Clone)]
pub struct EffectivePermission {
    pub action: String,
    pub resource: String,
}

impl EffectivePermission {
    /// Create a new effective permission
    pub fn new(action: impl Into<String>, resource: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            resource: resource.into(),
        }
    }
}

/// Match a single rule against effective permissions.
///
/// Prerequisites (admin/lateral paths) are **advisory-only** — they document
/// conditions needed for exploitation but are not enforced during matching.
/// pathfinding.cloud itself treats prerequisites as documentation for human
/// analysts, not programmatic gates. Resource constraints are similarly
/// advisory in the current implementation.
pub fn match_rule(
    rule: &EscalationRule,
    effective_perms: &[EffectivePermission],
) -> Option<MatchedRule> {
    // Check if all required permissions are present
    let mut matched_perms = Vec::new();

    for required in &rule.permissions_required {
        let mut found = false;

        for effective in effective_perms {
            // Check if effective permission matches required permission
            // Wildcard "*" effective action matches any required action
            if effective.action == "*" || action_matches(&effective.action, &required.permission) {
                matched_perms.push(required.permission.clone());
                found = true;
                break;
            }
        }

        // If any required permission is missing, rule doesn't match
        if !found {
            return None;
        }
    }

    // All required permissions found
    Some(MatchedRule {
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        category: rule.category.clone(),
        severity_tier: rule.severity_tier,
        boost: rule.boost,
        matched_permissions: matched_perms,
    })
}

/// Match all rules against effective permissions
pub fn match_all_rules(
    rules: &[EscalationRule],
    effective_perms: &[EffectivePermission],
) -> Vec<MatchedRule> {
    rules
        .iter()
        .filter_map(|rule| match_rule(rule, effective_perms))
        .collect()
}

/// Compute total rule boost (capped at 0.30)
pub fn compute_rule_boost(matches: &[MatchedRule]) -> f64 {
    let total: f64 = matches.iter().map(|m| m.boost).sum();
    total.min(0.30)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rule(id: &str, permissions: &[&str], tier: u8) -> EscalationRule {
        use crate::types::{Prerequisites, RequiredPermission};

        EscalationRule {
            id: id.to_string(),
            name: format!("Test rule {}", id),
            category: match tier {
                1 => "self-escalation".to_string(),
                2 => "new-passrole".to_string(),
                3 => "credential-access".to_string(),
                4 => "data-access".to_string(),
                _ => "other".to_string(),
            },
            services: vec!["test".to_string()],
            permissions_required: permissions
                .iter()
                .map(|p| RequiredPermission {
                    permission: p.to_string(),
                    resource_constraints: None,
                })
                .collect(),
            prerequisites: Prerequisites::default(),
            severity_tier: tier,
            boost: match tier {
                1 => 0.15,
                2 => 0.10,
                3 => 0.05,
                4 => 0.03,
                _ => 0.02,
            },
            description: None,
        }
    }

    fn eff(action: &str, resource: &str) -> EffectivePermission {
        EffectivePermission::new(action, resource)
    }

    #[test]
    fn match_single_permission_rule() {
        let rule = test_rule("iam-001", &["iam:CreatePolicyVersion"], 1);
        let perms = vec![
            eff("iam:CreatePolicyVersion", "*"),
            eff("s3:GetObject", "*"),
        ];
        let result = match_rule(&rule, &perms);
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "iam-001");
    }

    #[test]
    fn match_combo_rule_both_present() {
        let rule = test_rule("ec2-001", &["iam:PassRole", "ec2:RunInstances"], 2);
        let perms = vec![eff("iam:PassRole", "*"), eff("ec2:RunInstances", "*")];
        assert!(match_rule(&rule, &perms).is_some());
    }

    #[test]
    fn no_match_combo_rule_partial() {
        let rule = test_rule("ec2-001", &["iam:PassRole", "ec2:RunInstances"], 2);
        let perms = vec![eff("iam:PassRole", "*")]; // missing ec2:RunInstances
        assert!(match_rule(&rule, &perms).is_none());
    }

    #[test]
    fn admin_access_matches_all_rules() {
        let rules = vec![
            test_rule("iam-001", &["iam:CreatePolicyVersion"], 1),
            test_rule("ec2-001", &["iam:PassRole", "ec2:RunInstances"], 2),
        ];
        let perms = vec![eff("*", "*")]; // AdministratorAccess
        let matches = match_all_rules(&rules, &perms);
        assert_eq!(matches.len(), 2); // both rules match
    }

    #[test]
    fn total_boost_capped_at_030() {
        let matches = vec![
            MatchedRule {
                rule_id: "iam-001".to_string(),
                rule_name: "Test 1".to_string(),
                category: "self-escalation".to_string(),
                severity_tier: 1,
                boost: 0.15,
                matched_permissions: vec!["iam:CreatePolicyVersion".to_string()],
            },
            MatchedRule {
                rule_id: "iam-002".to_string(),
                rule_name: "Test 2".to_string(),
                category: "self-escalation".to_string(),
                severity_tier: 1,
                boost: 0.15,
                matched_permissions: vec!["iam:AttachUserPolicy".to_string()],
            },
            MatchedRule {
                rule_id: "iam-003".to_string(),
                rule_name: "Test 3".to_string(),
                category: "self-escalation".to_string(),
                severity_tier: 1,
                boost: 0.15,
                matched_permissions: vec!["iam:PutUserPolicy".to_string()],
            },
        ];
        let total_boost = compute_rule_boost(&matches);
        assert!((total_boost - 0.30).abs() < f64::EPSILON); // capped at 0.30
    }

    #[test]
    fn match_all_rules_returns_empty_when_no_match() {
        let rules = vec![test_rule("iam-001", &["iam:CreatePolicyVersion"], 1)];
        let perms = vec![eff("s3:GetObject", "*")];
        let matches = match_all_rules(&rules, &perms);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn wildcard_matches_any_permission() {
        let rule = test_rule("test-001", &["iam:CreatePolicyVersion"], 1);
        let perms = vec![eff("*", "*")];
        let result = match_rule(&rule, &perms);
        assert!(result.is_some());
    }

    #[test]
    fn compute_rule_boost_empty_list() {
        let total = compute_rule_boost(&[]);
        assert!((total - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_rule_boost_single_below_cap() {
        let matches = vec![MatchedRule {
            rule_id: "t".to_string(),
            rule_name: "t".to_string(),
            category: "self-escalation".to_string(),
            severity_tier: 1,
            boost: 0.15,
            matched_permissions: vec![],
        }];
        let total = compute_rule_boost(&matches);
        assert!((total - 0.15).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_rule_boost_many_small_rules() {
        let matches: Vec<MatchedRule> = (0..10)
            .map(|i| MatchedRule {
                rule_id: format!("r-{}", i),
                rule_name: format!("rule {}", i),
                category: "other".to_string(),
                severity_tier: 5,
                boost: 0.02,
                matched_permissions: vec![],
            })
            .collect();
        // 10 × 0.02 = 0.20, below cap
        let total = compute_rule_boost(&matches);
        assert!((total - 0.20).abs() < 0.001);
    }
}
