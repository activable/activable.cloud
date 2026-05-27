use activable_risk::{load_rules_from_dir, parse_rule};

#[test]
fn load_bundled_rules_from_directory() {
    // Use the manifest dir to find the config directory
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let rules_path = format!("{}/config/escalation-paths/bundled", manifest_dir);
    let rules = load_rules_from_dir(&rules_path).expect("Failed to load rules");

    // Should have at least 5 rules
    assert!(
        rules.len() >= 5,
        "Expected at least 5 rules, got {}",
        rules.len()
    );

    // All rules should have valid tier
    assert!(rules
        .iter()
        .all(|r| r.severity_tier >= 1 && r.severity_tier <= 5));

    // Check for specific rules
    assert!(rules.iter().any(|r| r.id == "iam-001"));
    assert!(rules.iter().any(|r| r.id == "iam-002"));
    assert!(rules.iter().any(|r| r.id == "iam-003"));
    assert!(rules.iter().any(|r| r.id == "ec2-001"));
    assert!(rules.iter().any(|r| r.id == "lambda-001"));
}

#[test]
fn parse_iam_001_rule() {
    let yaml = r#"
id: iam-001
name: "iam:CreatePolicyVersion"
category: self-escalation
services:
  - iam
permissions:
  required:
    - permission: "iam:CreatePolicyVersion"
      resourceConstraints: "Policy ARN must be attached to the actor"
description: "A principal can create a new policy version with admin perms"
"#;
    let rule = parse_rule(yaml).expect("Failed to parse rule");
    assert_eq!(rule.id, "iam-001");
    assert_eq!(rule.name, "iam:CreatePolicyVersion");
    assert_eq!(rule.category, "self-escalation");
    assert_eq!(rule.severity_tier, 1);
    assert_eq!(rule.boost, 0.15);
    // Verify that permissions field is Some and contains 1 requirement in AllOf
    assert!(
        rule.permissions.is_some(),
        "permissions field should not be None"
    );
    match rule.permissions.as_ref().unwrap() {
        activable_risk::types::RuleRequirement::AllOf { all_of } => {
            assert_eq!(all_of.len(), 1, "Expected 1 permission in AllOf");
        }
        _ => panic!("Expected permissions to be wrapped in AllOf"),
    }
}
