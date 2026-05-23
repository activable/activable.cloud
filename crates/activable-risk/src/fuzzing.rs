use crate::rule_engine::{match_all_rules, EffectivePermission};
use crate::types::EscalationRule;

/// A discovered escalation pattern from fuzzing
#[derive(Debug, Clone)]
pub struct FuzzDiscovery {
    pub actions: Vec<String>, // action combination that triggers escalation
    pub matched_rules: Vec<String>, // rule IDs that matched
    pub is_novel: bool,       // true if not already in existing rules
    pub severity: FuzzSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzSeverity {
    Critical, // admin-level escalation discovered
    High,     // privilege escalation discovered
    Medium,   // access expansion discovered
    Low,      // minor escalation
}

/// Configuration for the fuzzing engine
pub struct FuzzConfig {
    pub max_combo_size: usize, // 2 or 3 action combinations, default: 2
    pub service_families: Vec<Vec<String>>, // action groups to combine
    pub known_rule_ids: Vec<String>, // already-known rules to exclude from "novel"
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            max_combo_size: 2,
            service_families: default_service_families(),
            known_rule_ids: vec![],
        }
    }
}

/// Default service families for fuzzing — groups of actions known to interact
fn default_service_families() -> Vec<Vec<String>> {
    vec![
        // IAM self-escalation
        vec![
            "iam:CreatePolicyVersion",
            "iam:AttachUserPolicy",
            "iam:PutUserPolicy",
            "iam:AttachRolePolicy",
            "iam:PutRolePolicy",
            "iam:CreateAccessKey",
            "iam:UpdateAssumeRolePolicy",
            "iam:AddUserToGroup",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        // IAM + compute (PassRole combos)
        vec![
            "iam:PassRole",
            "ec2:RunInstances",
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
            "ecs:RegisterTaskDefinition",
            "ecs:RunTask",
            "codebuild:StartBuild",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        // STS + cross-account
        vec![
            "sts:AssumeRole",
            "sts:AssumeRoleWithSAML",
            "sts:AssumeRoleWithWebIdentity",
            "sts:GetSessionToken",
            "sts:GetFederationToken",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        // Data access + exfiltration
        vec![
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteBucket",
            "s3:PutBucketPolicy",
            "kms:Decrypt",
            "kms:CreateGrant",
            "secretsmanager:GetSecretValue",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    ]
}

/// Generate all 2-action combinations from a service family.
pub fn generate_pairs(family: &[String]) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for i in 0..family.len() {
        for j in (i + 1)..family.len() {
            pairs.push((family[i].clone(), family[j].clone()));
        }
    }
    pairs
}

/// Generate all 3-action combinations from a service family.
pub fn generate_triples(family: &[String]) -> Vec<(String, String, String)> {
    let mut triples = Vec::new();
    for i in 0..family.len() {
        for j in (i + 1)..family.len() {
            for k in (j + 1)..family.len() {
                triples.push((family[i].clone(), family[j].clone(), family[k].clone()));
            }
        }
    }
    triples
}

/// Classify severity based on actions involved
fn classify_discovery_severity(actions: &[&str]) -> FuzzSeverity {
    let has_admin = actions.iter().any(|a| *a == "*" || *a == "iam:*");
    let has_dangerous = actions.iter().any(|a| {
        a.starts_with("iam:Create")
            || a.starts_with("iam:Attach")
            || a.starts_with("iam:Put")
            || a.contains("PassRole")
    });

    if has_admin {
        FuzzSeverity::Critical
    } else if has_dangerous {
        FuzzSeverity::High
    } else {
        FuzzSeverity::Medium
    }
}

/// Run the fuzzer: enumerate action combinations, test against rules, report discoveries.
pub fn run_fuzzer(rules: &[EscalationRule], config: &FuzzConfig) -> Vec<FuzzDiscovery> {
    let mut discoveries = Vec::new();

    for family in &config.service_families {
        // Generate pairs
        let pairs = generate_pairs(family);
        for (a1, a2) in pairs {
            let perms = vec![
                EffectivePermission::new(&a1, "*"),
                EffectivePermission::new(&a2, "*"),
            ];
            let matched = match_all_rules(rules, &perms);
            if !matched.is_empty() {
                let rule_ids: Vec<String> = matched.iter().map(|m| m.rule_id.clone()).collect();
                let is_novel = rule_ids
                    .iter()
                    .all(|id| !config.known_rule_ids.contains(id));
                let severity = classify_discovery_severity(&[&a1, &a2]);
                discoveries.push(FuzzDiscovery {
                    actions: vec![a1, a2],
                    matched_rules: rule_ids,
                    is_novel,
                    severity,
                });
            }
        }

        // Generate triples if configured
        if config.max_combo_size >= 3 {
            let triples = generate_triples(family);
            for (a1, a2, a3) in triples {
                let perms = vec![
                    EffectivePermission::new(&a1, "*"),
                    EffectivePermission::new(&a2, "*"),
                    EffectivePermission::new(&a3, "*"),
                ];
                let matched = match_all_rules(rules, &perms);
                if !matched.is_empty() {
                    let rule_ids: Vec<String> = matched.iter().map(|m| m.rule_id.clone()).collect();
                    let is_novel = rule_ids
                        .iter()
                        .all(|id| !config.known_rule_ids.contains(id));
                    let severity = classify_discovery_severity(&[&a1, &a2, &a3]);
                    discoveries.push(FuzzDiscovery {
                        actions: vec![a1, a2, a3],
                        matched_rules: rule_ids,
                        is_novel,
                        severity,
                    });
                }
            }
        }
    }

    discoveries
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

    #[test]
    fn test_generate_pairs_4_items() {
        let family = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        let pairs = generate_pairs(&family);
        // 4 choose 2 = 6
        assert_eq!(pairs.len(), 6);
        assert!(pairs.contains(&("a".to_string(), "b".to_string())));
        assert!(pairs.contains(&("a".to_string(), "c".to_string())));
        assert!(pairs.contains(&("a".to_string(), "d".to_string())));
        assert!(pairs.contains(&("b".to_string(), "c".to_string())));
        assert!(pairs.contains(&("b".to_string(), "d".to_string())));
        assert!(pairs.contains(&("c".to_string(), "d".to_string())));
    }

    #[test]
    fn test_generate_pairs_empty() {
        let family: Vec<String> = vec![];
        let pairs = generate_pairs(&family);
        assert_eq!(pairs.len(), 0);
    }

    #[test]
    fn test_generate_pairs_single_item() {
        let family = vec!["a".to_string()];
        let pairs = generate_pairs(&family);
        assert_eq!(pairs.len(), 0);
    }

    #[test]
    fn test_generate_pairs_two_items() {
        let family = vec!["a".to_string(), "b".to_string()];
        let pairs = generate_pairs(&family);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("a".to_string(), "b".to_string()));
    }

    #[test]
    fn test_generate_triples_4_items() {
        let family = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        let triples = generate_triples(&family);
        // 4 choose 3 = 4
        assert_eq!(triples.len(), 4);
        assert!(triples.contains(&("a".to_string(), "b".to_string(), "c".to_string())));
        assert!(triples.contains(&("a".to_string(), "b".to_string(), "d".to_string())));
        assert!(triples.contains(&("a".to_string(), "c".to_string(), "d".to_string())));
        assert!(triples.contains(&("b".to_string(), "c".to_string(), "d".to_string())));
    }

    #[test]
    fn test_generate_triples_empty() {
        let family: Vec<String> = vec![];
        let triples = generate_triples(&family);
        assert_eq!(triples.len(), 0);
    }

    #[test]
    fn test_generate_triples_two_items() {
        let family = vec!["a".to_string(), "b".to_string()];
        let triples = generate_triples(&family);
        assert_eq!(triples.len(), 0);
    }

    #[test]
    fn test_default_service_families_returns_4_families() {
        let families = default_service_families();
        assert_eq!(families.len(), 4);
        // Check that each family has multiple actions
        for family in families {
            assert!(family.len() > 1);
        }
    }

    #[test]
    fn test_classify_severity_admin_action() {
        let actions = vec!["*", "s3:GetObject"];
        let severity = classify_discovery_severity(&actions);
        assert_eq!(severity, FuzzSeverity::Critical);
    }

    #[test]
    fn test_classify_severity_iam_wildcard() {
        let actions = vec!["iam:*"];
        let severity = classify_discovery_severity(&actions);
        assert_eq!(severity, FuzzSeverity::Critical);
    }

    #[test]
    fn test_classify_severity_dangerous_iam_action() {
        let actions = vec!["iam:CreatePolicyVersion", "s3:GetObject"];
        let severity = classify_discovery_severity(&actions);
        assert_eq!(severity, FuzzSeverity::High);
    }

    #[test]
    fn test_classify_severity_passrole_action() {
        let actions = vec!["iam:PassRole", "ec2:RunInstances"];
        let severity = classify_discovery_severity(&actions);
        assert_eq!(severity, FuzzSeverity::High);
    }

    #[test]
    fn test_classify_severity_data_access() {
        let actions = vec!["s3:GetObject", "s3:DeleteBucket"];
        let severity = classify_discovery_severity(&actions);
        assert_eq!(severity, FuzzSeverity::Medium);
    }

    #[test]
    fn test_run_fuzzer_with_known_iam_rules() {
        let rules = vec![
            test_rule("iam-001", &["iam:CreatePolicyVersion"], 1),
            test_rule("ec2-001", &["iam:PassRole", "ec2:RunInstances"], 2),
        ];

        let config = FuzzConfig {
            max_combo_size: 2,
            service_families: vec![
                vec![
                    "iam:CreatePolicyVersion".to_string(),
                    "iam:AttachUserPolicy".to_string(),
                ],
                vec!["iam:PassRole".to_string(), "ec2:RunInstances".to_string()],
            ],
            known_rule_ids: vec![],
        };

        let discoveries = run_fuzzer(&rules, &config);
        // Both families should have discoveries
        assert!(!discoveries.is_empty());

        // ec2-001 should be discovered
        let ec2_found = discoveries.iter().any(|d| {
            d.actions.len() == 2
                && d.matched_rules.contains(&"ec2-001".to_string())
                && d.actions.contains(&"iam:PassRole".to_string())
                && d.actions.contains(&"ec2:RunInstances".to_string())
        });
        assert!(ec2_found);
    }

    #[test]
    fn test_run_fuzzer_with_known_rule_ids_filter() {
        let rules = vec![test_rule("iam-001", &["iam:CreatePolicyVersion"], 1)];

        let config = FuzzConfig {
            max_combo_size: 2,
            service_families: vec![vec!["iam:CreatePolicyVersion".to_string()]],
            known_rule_ids: vec!["iam-001".to_string()],
        };

        let discoveries = run_fuzzer(&rules, &config);
        // Should have discovery but marked as not novel
        for discovery in &discoveries {
            if discovery.matched_rules.contains(&"iam-001".to_string()) {
                assert!(!discovery.is_novel);
            }
        }
    }

    #[test]
    fn test_run_fuzzer_with_empty_rules() {
        let rules: Vec<EscalationRule> = vec![];

        let config = FuzzConfig {
            max_combo_size: 2,
            service_families: vec![vec![
                "iam:CreatePolicyVersion".to_string(),
                "iam:AttachUserPolicy".to_string(),
            ]],
            known_rule_ids: vec![],
        };

        let discoveries = run_fuzzer(&rules, &config);
        assert_eq!(discoveries.len(), 0);
    }

    #[test]
    fn test_run_fuzzer_with_triple_combos() {
        let rules = vec![test_rule(
            "iam-003",
            &[
                "iam:CreatePolicyVersion",
                "iam:AttachUserPolicy",
                "iam:PutUserPolicy",
            ],
            1,
        )];

        let config = FuzzConfig {
            max_combo_size: 3,
            service_families: vec![vec![
                "iam:CreatePolicyVersion".to_string(),
                "iam:AttachUserPolicy".to_string(),
                "iam:PutUserPolicy".to_string(),
                "iam:AddUserToGroup".to_string(),
            ]],
            known_rule_ids: vec![],
        };

        let discoveries = run_fuzzer(&rules, &config);
        // Should include both pairs and triples
        let has_triple = discoveries
            .iter()
            .any(|d| d.actions.len() == 3 && d.matched_rules.contains(&"iam-003".to_string()));
        assert!(has_triple);
    }

    #[test]
    fn test_fuzz_discovery_captures_rule_ids() {
        let rules = vec![
            test_rule("iam-001", &["iam:CreatePolicyVersion"], 1),
            test_rule(
                "iam-combined",
                &["iam:CreatePolicyVersion", "iam:AttachUserPolicy"],
                1,
            ),
        ];

        let config = FuzzConfig {
            max_combo_size: 2,
            service_families: vec![vec![
                "iam:CreatePolicyVersion".to_string(),
                "iam:AttachUserPolicy".to_string(),
            ]],
            known_rule_ids: vec![],
        };

        let discoveries = run_fuzzer(&rules, &config);

        // Find pair discovery
        let pair_discovery = discoveries
            .iter()
            .find(|d| {
                d.actions.len() == 2
                    && d.actions.contains(&"iam:CreatePolicyVersion".to_string())
                    && d.actions.contains(&"iam:AttachUserPolicy".to_string())
            })
            .unwrap();

        // Should match both rules
        assert!(pair_discovery
            .matched_rules
            .contains(&"iam-combined".to_string()));
    }

    #[test]
    fn test_fuzz_config_default() {
        let config = FuzzConfig::default();
        assert_eq!(config.max_combo_size, 2);
        assert_eq!(config.service_families.len(), 4);
        assert_eq!(config.known_rule_ids.len(), 0);
    }

    #[test]
    fn test_fuzz_discovery_novelty_detection() {
        let rules = vec![test_rule(
            "ec2-001",
            &["iam:PassRole", "ec2:RunInstances"],
            2,
        )];

        let config = FuzzConfig {
            max_combo_size: 2,
            service_families: vec![vec![
                "iam:PassRole".to_string(),
                "ec2:RunInstances".to_string(),
            ]],
            known_rule_ids: vec!["other-001".to_string()],
        };

        let discoveries = run_fuzzer(&rules, &config);

        for discovery in discoveries {
            if discovery.matched_rules.contains(&"ec2-001".to_string()) {
                // ec2-001 is not in known_rule_ids, so should be marked novel
                assert!(discovery.is_novel);
            }
        }
    }

    #[test]
    fn test_classify_severity_attach_action() {
        let actions = vec!["iam:AttachUserPolicy"];
        let severity = classify_discovery_severity(&actions);
        assert_eq!(severity, FuzzSeverity::High);
    }

    #[test]
    fn test_classify_severity_put_action() {
        let actions = vec!["iam:PutUserPolicy"];
        let severity = classify_discovery_severity(&actions);
        assert_eq!(severity, FuzzSeverity::High);
    }
}
