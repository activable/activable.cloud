use crate::types::{EscalationRule, MatchedRule, RuleRequirement};
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

/// Recursively evaluate a RuleRequirement tree against available permissions.
/// Returns (matches: bool, matched_permission_strings: Vec<String>)
fn evaluate_requirement(
    req: &RuleRequirement,
    effective_perms: &[EffectivePermission],
) -> (bool, Vec<String>) {
    match req {
        RuleRequirement::Single(rp) => {
            let mut matched = Vec::new();
            for effective in effective_perms {
                // Wildcard "*" effective action matches any required action
                if effective.action == "*" || action_matches(&effective.action, &rp.permission) {
                    matched.push(rp.permission.clone());
                }
            }
            (!matched.is_empty(), matched)
        }
        RuleRequirement::AllOf { all_of } => {
            let mut all_matched = true;
            let mut all_perms = Vec::new();

            for sub_req in all_of {
                let (matched, perms) = evaluate_requirement(sub_req, effective_perms);
                if !matched {
                    all_matched = false;
                    break;
                }
                all_perms.extend(perms);
            }

            (all_matched, all_perms)
        }
        RuleRequirement::AnyOf { any_of } => {
            for sub_req in any_of {
                let (matched, perms) = evaluate_requirement(sub_req, effective_perms);
                if matched {
                    return (true, perms);
                }
            }
            (false, Vec::new())
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
    // Cascade rules are handled separately in match_all_rules
    if rule.trigger.is_some() {
        return None;
    }

    match &rule.permissions {
        None => None,
        Some(req) => {
            let (matched, matched_perms) = evaluate_requirement(req, effective_perms);
            if matched {
                Some(MatchedRule {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    category: rule.category.clone(),
                    severity_tier: rule.severity_tier,
                    boost: rule.boost,
                    matched_permissions: matched_perms,
                })
            } else {
                None
            }
        }
    }
}

/// Match all rules against effective permissions.
/// Two-phase evaluation:
/// 1. Match primary (non-cascade) rules.
/// 2. Match cascade rules based on primary match counts.
pub fn match_all_rules(
    rules: &[EscalationRule],
    effective_perms: &[EffectivePermission],
) -> Vec<MatchedRule> {
    // Phase 1: match all non-cascade rules
    let primary_matches: Vec<MatchedRule> = rules
        .iter()
        .filter_map(|rule| match_rule(rule, effective_perms))
        .collect();

    let mut all_matches = primary_matches.clone();

    // Phase 2: match cascade rules based on primary match counts
    for rule in rules {
        if let Some(trigger) = &rule.trigger {
            // Count primary matches that qualify for cascade
            let qualifying_count = primary_matches
                .iter()
                .filter(|m| m.severity_tier <= trigger.min_tier)
                .count() as u32;

            if qualifying_count >= trigger.match_count {
                all_matches.push(MatchedRule {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    category: rule.category.clone(),
                    severity_tier: rule.severity_tier,
                    boost: rule.boost,
                    matched_permissions: vec![],
                });
            }
        }
    }

    all_matches
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

        let permissions_req = if permissions.is_empty() {
            None
        } else {
            Some(RuleRequirement::AllOf {
                all_of: permissions
                    .iter()
                    .map(|p| {
                        RuleRequirement::Single(RequiredPermission {
                            permission: p.to_string(),
                            resource_constraints: None,
                        })
                    })
                    .collect(),
            })
        };

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
            permissions: permissions_req,
            prerequisites: Prerequisites::default(),
            severity_tier: tier,
            boost: match tier {
                1 => 0.15,
                2 => 0.10,
                3 => 0.05,
                4 => 0.03,
                _ => 0.02,
            },
            trigger: None,
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

    #[test]
    fn evaluate_requirement_single() {
        let req = RuleRequirement::Single(crate::types::RequiredPermission {
            permission: "iam:CreatePolicyVersion".to_string(),
            resource_constraints: None,
        });
        let perms = vec![
            eff("iam:CreatePolicyVersion", "*"),
            eff("s3:GetObject", "*"),
        ];
        let (matched, _) = evaluate_requirement(&req, &perms);
        assert!(matched);
    }

    #[test]
    fn evaluate_requirement_single_missing() {
        let req = RuleRequirement::Single(crate::types::RequiredPermission {
            permission: "iam:DeleteRole".to_string(),
            resource_constraints: None,
        });
        let perms = vec![eff("iam:CreatePolicyVersion", "*")];
        let (matched, _) = evaluate_requirement(&req, &perms);
        assert!(!matched);
    }

    #[test]
    fn evaluate_requirement_all_of() {
        let req = RuleRequirement::AllOf {
            all_of: vec![
                RuleRequirement::Single(crate::types::RequiredPermission {
                    permission: "iam:PassRole".to_string(),
                    resource_constraints: None,
                }),
                RuleRequirement::Single(crate::types::RequiredPermission {
                    permission: "ec2:RunInstances".to_string(),
                    resource_constraints: None,
                }),
            ],
        };
        let perms = vec![eff("iam:PassRole", "*"), eff("ec2:RunInstances", "*")];
        let (matched, _) = evaluate_requirement(&req, &perms);
        assert!(matched);
    }

    #[test]
    fn evaluate_requirement_all_of_partial() {
        let req = RuleRequirement::AllOf {
            all_of: vec![
                RuleRequirement::Single(crate::types::RequiredPermission {
                    permission: "iam:PassRole".to_string(),
                    resource_constraints: None,
                }),
                RuleRequirement::Single(crate::types::RequiredPermission {
                    permission: "ec2:RunInstances".to_string(),
                    resource_constraints: None,
                }),
            ],
        };
        let perms = vec![eff("iam:PassRole", "*")]; // missing ec2:RunInstances
        let (matched, _) = evaluate_requirement(&req, &perms);
        assert!(!matched);
    }

    #[test]
    fn evaluate_requirement_any_of() {
        let req = RuleRequirement::AnyOf {
            any_of: vec![
                RuleRequirement::Single(crate::types::RequiredPermission {
                    permission: "cloudformation:CreateStack".to_string(),
                    resource_constraints: None,
                }),
                RuleRequirement::Single(crate::types::RequiredPermission {
                    permission: "cloudformation:UpdateStack".to_string(),
                    resource_constraints: None,
                }),
            ],
        };
        let perms = vec![eff("cloudformation:UpdateStack", "*")];
        let (matched, _) = evaluate_requirement(&req, &perms);
        assert!(matched);
    }

    #[test]
    fn evaluate_requirement_any_of_none() {
        let req = RuleRequirement::AnyOf {
            any_of: vec![
                RuleRequirement::Single(crate::types::RequiredPermission {
                    permission: "cloudformation:CreateStack".to_string(),
                    resource_constraints: None,
                }),
                RuleRequirement::Single(crate::types::RequiredPermission {
                    permission: "cloudformation:UpdateStack".to_string(),
                    resource_constraints: None,
                }),
            ],
        };
        let perms = vec![eff("s3:GetObject", "*")];
        let (matched, _) = evaluate_requirement(&req, &perms);
        assert!(!matched);
    }

    #[test]
    fn cascade_rule_fires_with_three_primaries() {
        use crate::types::CascadeTrigger;

        // Create 4 primary rules
        let rule1 = test_rule("iam-001", &["iam:CreatePolicyVersion"], 1);
        let rule2 = test_rule("ec2-001", &["ec2:RunInstances"], 2);
        let rule3 = test_rule("s3-001", &["s3:GetObject"], 3);
        let rule4 = test_rule("data-001", &["s3:PutObject"], 4);

        // Create cascade rule: fires when 3+ tier-3-or-lower rules match
        let cascade_rule = EscalationRule {
            id: "cascade-001".to_string(),
            name: "Test cascade".to_string(),
            category: "cascade".to_string(),
            services: vec![],
            permissions: None,
            prerequisites: crate::types::Prerequisites::default(),
            severity_tier: 1,
            boost: 0.15,
            trigger: Some(CascadeTrigger {
                match_count: 3,
                min_tier: 3,
                scope: crate::types::CascadeScope::Principal,
            }),
            description: None,
        };

        // Permissions that trigger rules 1, 2, 3 (cascade should fire)
        let perms = vec![
            eff("iam:CreatePolicyVersion", "*"),
            eff("ec2:RunInstances", "*"),
            eff("s3:GetObject", "*"),
        ];

        let rules = vec![rule1, rule2, rule3, rule4, cascade_rule.clone()];
        let matches = match_all_rules(&rules, &perms);

        // Should have 3 primary + 1 cascade = 4 matches
        assert_eq!(matches.len(), 4);
        assert!(matches.iter().any(|m| m.rule_id == "cascade-001"));
    }

    #[test]
    fn cascade_rule_does_not_fire_with_two_primaries() {
        use crate::types::CascadeTrigger;

        let rule1 = test_rule("iam-001", &["iam:CreatePolicyVersion"], 1);
        let rule2 = test_rule("ec2-001", &["ec2:RunInstances"], 2);
        let rule3 = test_rule("s3-001", &["s3:GetObject"], 3);

        let cascade_rule = EscalationRule {
            id: "cascade-001".to_string(),
            name: "Test cascade".to_string(),
            category: "cascade".to_string(),
            services: vec![],
            permissions: None,
            prerequisites: crate::types::Prerequisites::default(),
            severity_tier: 1,
            boost: 0.15,
            trigger: Some(CascadeTrigger {
                match_count: 3,
                min_tier: 3,
                scope: crate::types::CascadeScope::Principal,
            }),
            description: None,
        };

        // Only match 2 primaries (rule1, rule2)
        let perms = vec![
            eff("iam:CreatePolicyVersion", "*"),
            eff("ec2:RunInstances", "*"),
        ];

        let rules = vec![rule1, rule2, rule3, cascade_rule];
        let matches = match_all_rules(&rules, &perms);

        // Should have 2 primary, NO cascade
        assert_eq!(matches.len(), 2);
        assert!(!matches.iter().any(|m| m.rule_id == "cascade-001"));
    }
}
