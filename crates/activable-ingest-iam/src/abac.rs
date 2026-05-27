//! ABAC tag manipulation detection.
//!
//! Detects attribute-based access control (ABAC) tag manipulation as an escalation vector.
//! Principals with iam:TagUser/TagRole/TagResource permissions without proper RequestTag
//! conditions can manipulate tags that other policies depend on for access control.

use crate::action_matcher::action_matches;
use crate::types::ParsedPolicy;

/// A tag dependency found in a policy condition
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagDependency {
    pub tag_key: String,
    pub condition_type: TagConditionType,
    pub required_values: Vec<String>, // values that must match for access
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagConditionType {
    PrincipalTag, // aws:PrincipalTag/<key>
    ResourceTag,  // aws:ResourceTag/<key>
    RequestTag,   // aws:RequestTag/<key>
}

/// Result of ABAC tag manipulation analysis
#[derive(Debug, Clone)]
pub struct TagManipulationRisk {
    pub principal_can_self_tag: bool, // has iam:TagUser/TagRole without RequestTag guard
    pub tag_dependent_policies: Vec<String>, // policy IDs / keys that depend on tags
    pub exploitable_tags: Vec<String>, // tag keys that can be forged for escalation
    pub risk_level: TagRiskLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagRiskLevel {
    Critical, // can self-tag + tag-dependent policy grants admin
    High,     // can self-tag + tag-dependent policy grants sensitive access
    Medium,   // can self-tag but no sensitive tag-dependent policy found
    None,     // cannot self-tag or no tag-dependent policies
}

/// Tag-manipulating IAM actions
const TAG_MANIPULATION_ACTIONS: &[&str] = &[
    "iam:TagUser",
    "iam:TagRole",
    "iam:TagPolicy",
    "iam:TagInstanceProfile",
    "iam:TagOpenIDConnectProvider",
    "iam:TagSAMLProvider",
    "iam:TagServerCertificate",
    "ec2:CreateTags",
    "ec2:DeleteTags",
    "s3:PutObjectTagging",
    "s3:PutBucketTagging",
    "lambda:TagResource",
    "rds:AddTagsToResource",
    "kms:TagResource",
];

/// Extract tag dependencies from policy conditions.
///
/// Scans for condition keys like "aws:PrincipalTag/team", "aws:ResourceTag/env", "aws:RequestTag/session".
/// Returns all tag-dependent conditions found across all policies.
pub fn extract_tag_dependencies(policies: &[ParsedPolicy]) -> Vec<TagDependency> {
    let mut dependencies = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for policy in policies {
        for statement in &policy.statements {
            for condition in &statement.conditions {
                if let Some(dep) = extract_single_tag_dependency(&condition.key, &condition.values)
                {
                    let key = format!("{}:{}", dep.tag_key, dep.condition_type_str());
                    if seen.insert(key) {
                        dependencies.push(dep);
                    }
                }
            }
        }
    }

    dependencies
}

/// Extract a single tag dependency from a condition key.
fn extract_single_tag_dependency(key: &str, values: &[String]) -> Option<TagDependency> {
    let lower_key = key.to_lowercase();

    if let Some(tag_key) = lower_key.strip_prefix("aws:principaltag/") {
        return Some(TagDependency {
            tag_key: tag_key.to_string(),
            condition_type: TagConditionType::PrincipalTag,
            required_values: values.to_vec(),
        });
    }

    if let Some(tag_key) = lower_key.strip_prefix("aws:resourcetag/") {
        return Some(TagDependency {
            tag_key: tag_key.to_string(),
            condition_type: TagConditionType::ResourceTag,
            required_values: values.to_vec(),
        });
    }

    if let Some(tag_key) = lower_key.strip_prefix("aws:requesttag/") {
        return Some(TagDependency {
            tag_key: tag_key.to_string(),
            condition_type: TagConditionType::RequestTag,
            required_values: values.to_vec(),
        });
    }

    None
}

impl TagDependency {
    fn condition_type_str(&self) -> &str {
        match self.condition_type {
            TagConditionType::PrincipalTag => "PrincipalTag",
            TagConditionType::ResourceTag => "ResourceTag",
            TagConditionType::RequestTag => "RequestTag",
        }
    }
}

/// Check if a principal has tag manipulation actions WITHOUT RequestTag condition guards.
///
/// A principal that can self-tag without constraints can forge tag values.
/// Returns the list of unguarded tag manipulation actions found.
pub fn detect_unguarded_tag_manipulation(
    effective_actions: &[&str],
    policies: &[ParsedPolicy],
) -> Vec<String> {
    let mut unguarded = Vec::new();

    for tag_action in TAG_MANIPULATION_ACTIONS {
        // Check if principal has this tag action
        let has_action = effective_actions
            .iter()
            .any(|ea| action_matches(ea, tag_action));

        if !has_action {
            continue;
        }

        // Check if ANY policy granting this action has a RequestTag condition
        // If there's at least one policy granting the action with a RequestTag guard, it's not unguarded
        let has_requesttag_guard = policies.iter().any(|policy| {
            policy.statements.iter().any(|stmt| {
                // Check if this statement grants the tag action
                let grants_action = stmt
                    .actions
                    .iter()
                    .any(|ap| action_matches(&ap.0, tag_action));

                if !grants_action {
                    return false;
                }

                // Check if this statement has a RequestTag condition
                stmt.conditions
                    .iter()
                    .any(|cond| cond.key.to_lowercase().contains("aws:requesttag"))
            })
        });

        // If no RequestTag guard found, this action is unguarded
        if !has_requesttag_guard {
            unguarded.push(tag_action.to_string());
        }
    }

    unguarded
}

/// Full ABAC tag manipulation analysis for a principal.
///
/// Returns a TagManipulationRisk struct with:
/// - principal_can_self_tag: whether principal can modify tags without RequestTag guard
/// - tag_dependent_policies: list of tag keys that policies depend on
/// - exploitable_tags: intersection of self-taggable + tag-dependent
/// - risk_level: Critical/High/Medium/None based on exposure
pub fn analyze_tag_manipulation_risk(
    effective_actions: &[&str],
    policies: &[ParsedPolicy],
) -> TagManipulationRisk {
    let tag_deps = extract_tag_dependencies(policies);
    let unguarded = detect_unguarded_tag_manipulation(effective_actions, policies);

    let can_self_tag = !unguarded.is_empty();

    // Extract exploitable tag keys (only if principal can self-tag)
    let exploitable = if can_self_tag {
        tag_deps
            .iter()
            .filter(|d| {
                // Only PrincipalTag and ResourceTag can be self-set
                // RequestTag cannot be self-set (it's set by AWS)
                matches!(
                    d.condition_type,
                    TagConditionType::PrincipalTag | TagConditionType::ResourceTag
                )
            })
            .map(|d| d.tag_key.clone())
            .collect::<Vec<_>>()
    } else {
        vec![]
    };

    // Tag-dependent policies (all keys, for reference)
    let tag_dependent_policies: Vec<String> = tag_deps.iter().map(|d| d.tag_key.clone()).collect();

    // Determine risk level
    let risk_level = match (
        can_self_tag,
        tag_deps.is_empty(),
        tag_dependent_policies.is_empty(),
    ) {
        (false, _, _) => TagRiskLevel::None, // Can't self-tag → no risk
        (true, true, _) | (true, _, true) => {
            // Can self-tag but no tag-dependent policies
            TagRiskLevel::Medium
        }
        (true, false, false) => {
            // Can self-tag + tag-dependent policies exist
            // Conservative: mark as High (could grant admin via tags)
            TagRiskLevel::High
        }
    };

    TagManipulationRisk {
        principal_can_self_tag: can_self_tag,
        tag_dependent_policies,
        exploitable_tags: exploitable,
        risk_level,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ActionPattern, Condition, Effect, PolicyStatement, ResourcePattern};

    fn make_policy_with_conditions(conditions: Vec<Condition>) -> ParsedPolicy {
        ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![PolicyStatement {
                sid: None,
                effect: Effect::Allow,
                actions: vec![],
                not_actions: vec![],
                resources: vec![],
                not_resources: vec![],
                conditions,
            }],
        }
    }

    fn make_condition(key: &str, values: Vec<&str>) -> Condition {
        Condition {
            operator: "StringEquals".to_string(),
            key: key.to_string(),
            values: values.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn make_policy_statement(actions: Vec<&str>, conditions: Vec<Condition>) -> PolicyStatement {
        PolicyStatement {
            sid: None,
            effect: Effect::Allow,
            actions: actions
                .into_iter()
                .map(|a| ActionPattern(a.to_string()))
                .collect(),
            not_actions: vec![],
            resources: vec![ResourcePattern("*".to_string())],
            not_resources: vec![],
            conditions,
        }
    }

    fn make_full_policy(actions: Vec<&str>, conditions: Vec<Condition>) -> ParsedPolicy {
        ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![make_policy_statement(actions, conditions)],
        }
    }

    // ========== Tag Dependency Extraction Tests ==========

    #[test]
    fn test_extract_principal_tag_dependency() {
        let policy = make_policy_with_conditions(vec![make_condition(
            "aws:PrincipalTag/team",
            vec!["engineering"],
        )]);

        let deps = extract_tag_dependencies(&[policy]);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].tag_key, "team");
        assert_eq!(deps[0].condition_type, TagConditionType::PrincipalTag);
        assert_eq!(deps[0].required_values, vec!["engineering"]);
    }

    #[test]
    fn test_extract_resource_tag_dependency() {
        let policy = make_policy_with_conditions(vec![make_condition(
            "aws:ResourceTag/environment",
            vec!["production"],
        )]);

        let deps = extract_tag_dependencies(&[policy]);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].tag_key, "environment");
        assert_eq!(deps[0].condition_type, TagConditionType::ResourceTag);
    }

    #[test]
    fn test_extract_request_tag_dependency() {
        let policy = make_policy_with_conditions(vec![make_condition(
            "aws:RequestTag/session",
            vec!["mfa"],
        )]);

        let deps = extract_tag_dependencies(&[policy]);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].tag_key, "session");
        assert_eq!(deps[0].condition_type, TagConditionType::RequestTag);
    }

    #[test]
    fn test_extract_multiple_tags() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![PolicyStatement {
                sid: None,
                effect: Effect::Allow,
                actions: vec![],
                not_actions: vec![],
                resources: vec![],
                not_resources: vec![],
                conditions: vec![
                    make_condition("aws:PrincipalTag/team", vec!["eng"]),
                    make_condition("aws:ResourceTag/env", vec!["prod"]),
                    make_condition("aws:RequestTag/mfa", vec!["true"]),
                ],
            }],
        };

        let deps = extract_tag_dependencies(&[policy]);
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.tag_key == "team"));
        assert!(deps.iter().any(|d| d.tag_key == "env"));
        assert!(deps.iter().any(|d| d.tag_key == "mfa"));
    }

    #[test]
    fn test_extract_deduplicates_same_tag() {
        let policy1 =
            make_policy_with_conditions(vec![make_condition("aws:PrincipalTag/team", vec!["eng"])]);
        let policy2 =
            make_policy_with_conditions(vec![make_condition("aws:PrincipalTag/team", vec!["ops"])]);

        let deps = extract_tag_dependencies(&[policy1, policy2]);
        // Should deduplicate by tag_key + condition_type
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].tag_key, "team");
    }

    #[test]
    fn test_extract_no_tag_conditions() {
        let policy = make_policy_with_conditions(vec![make_condition("aws:SourceIp", vec![])]);

        let deps = extract_tag_dependencies(&[policy]);
        assert_eq!(deps.len(), 0);
    }

    #[test]
    fn test_extract_case_insensitive_key() {
        let policy =
            make_policy_with_conditions(vec![make_condition("AWS:PRINCIPALTAG/TEAM", vec!["eng"])]);

        let deps = extract_tag_dependencies(&[policy]);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].tag_key, "team");
    }

    // ========== Unguarded Tag Manipulation Tests ==========

    #[test]
    fn test_unguarded_tag_user_no_request_tag() {
        let policy = make_full_policy(vec!["iam:TagUser"], vec![]);
        let actions = vec!["iam:TagUser"];

        let unguarded = detect_unguarded_tag_manipulation(&actions, &[policy]);
        assert_eq!(unguarded, vec!["iam:TagUser"]);
    }

    #[test]
    fn test_guarded_tag_user_with_request_tag() {
        let policy = make_full_policy(
            vec!["iam:TagUser"],
            vec![make_condition("aws:RequestTag/mfa", vec!["true"])],
        );
        let actions = vec!["iam:TagUser"];

        let unguarded = detect_unguarded_tag_manipulation(&actions, &[policy]);
        assert!(
            unguarded.is_empty(),
            "RequestTag guard should prevent self-tagging"
        );
    }

    #[test]
    fn test_unguarded_tag_role() {
        let policy = make_full_policy(vec!["iam:TagRole"], vec![]);
        let actions = vec!["iam:TagRole"];

        let unguarded = detect_unguarded_tag_manipulation(&actions, &[policy]);
        assert_eq!(unguarded, vec!["iam:TagRole"]);
    }

    #[test]
    fn test_unguarded_ec2_create_tags() {
        let policy = make_full_policy(vec!["ec2:CreateTags"], vec![]);
        let actions = vec!["ec2:CreateTags"];

        let unguarded = detect_unguarded_tag_manipulation(&actions, &[policy]);
        assert_eq!(unguarded, vec!["ec2:CreateTags"]);
    }

    #[test]
    fn test_unguarded_s3_put_object_tagging() {
        let policy = make_full_policy(vec!["s3:PutObjectTagging"], vec![]);
        let actions = vec!["s3:PutObjectTagging"];

        let unguarded = detect_unguarded_tag_manipulation(&actions, &[policy]);
        assert_eq!(unguarded, vec!["s3:PutObjectTagging"]);
    }

    #[test]
    fn test_no_tag_actions() {
        let policy = make_full_policy(vec!["s3:GetObject"], vec![]);
        let actions = vec!["s3:GetObject"];

        let unguarded = detect_unguarded_tag_manipulation(&actions, &[policy]);
        assert!(unguarded.is_empty());
    }

    #[test]
    fn test_principal_without_tag_actions() {
        let policy = make_full_policy(vec![], vec![]);
        let actions: Vec<&str> = vec![];

        let unguarded = detect_unguarded_tag_manipulation(&actions, &[policy]);
        assert!(unguarded.is_empty());
    }

    #[test]
    fn test_wildcard_tag_action() {
        let policy = make_full_policy(vec!["iam:Tag*"], vec![]);
        let actions = vec!["iam:Tag*"];

        let unguarded = detect_unguarded_tag_manipulation(&actions, &[policy]);
        // Should detect iam:Tag* as unguarded for TagUser, TagRole, etc.
        assert!(!unguarded.is_empty());
    }

    #[test]
    fn test_service_wildcard_tag_action() {
        let policy = make_full_policy(vec!["s3:*"], vec![]);
        let actions = vec!["s3:*"];

        let unguarded = detect_unguarded_tag_manipulation(&actions, &[policy]);
        // Should detect s3:* as unguarded for s3:PutObjectTagging
        assert!(!unguarded.is_empty());
    }

    #[test]
    fn test_multiple_unguarded_actions() {
        let policy = make_full_policy(vec!["iam:TagUser", "iam:TagRole"], vec![]);
        let actions = vec!["iam:TagUser", "iam:TagRole"];

        let unguarded = detect_unguarded_tag_manipulation(&actions, &[policy]);
        assert_eq!(unguarded.len(), 2);
    }

    #[test]
    fn test_mixed_guarded_and_unguarded() {
        let policy1 = make_full_policy(
            vec!["iam:TagUser"],
            vec![make_condition("aws:RequestTag/mfa", vec!["true"])],
        );
        let policy2 = make_full_policy(vec!["iam:TagRole"], vec![]);
        let actions = vec!["iam:TagUser", "iam:TagRole"];

        let unguarded = detect_unguarded_tag_manipulation(&actions, &[policy1, policy2]);
        // TagUser is guarded, TagRole is not
        assert_eq!(unguarded, vec!["iam:TagRole"]);
    }

    // ========== Full Risk Analysis Tests ==========

    #[test]
    fn test_risk_level_no_tag_actions() {
        let policy = make_full_policy(vec!["s3:GetObject"], vec![]);
        let actions = vec!["s3:GetObject"];

        let risk = analyze_tag_manipulation_risk(&actions, &[policy]);
        assert!(!risk.principal_can_self_tag);
        assert_eq!(risk.risk_level, TagRiskLevel::None);
    }

    #[test]
    fn test_risk_level_can_self_tag_no_tag_policies() {
        let policy = make_full_policy(vec!["iam:TagUser"], vec![]);
        let actions = vec!["iam:TagUser"];

        let risk = analyze_tag_manipulation_risk(&actions, &[policy]);
        assert!(risk.principal_can_self_tag);
        assert_eq!(risk.risk_level, TagRiskLevel::Medium);
        assert!(risk.tag_dependent_policies.is_empty());
    }

    #[test]
    fn test_risk_level_can_self_tag_with_tag_policies() {
        let tag_policy =
            make_policy_with_conditions(vec![make_condition("aws:PrincipalTag/team", vec!["eng"])]);
        let self_tag_policy = make_full_policy(vec!["iam:TagUser"], vec![]);
        let actions = vec!["iam:TagUser"];

        let risk = analyze_tag_manipulation_risk(&actions, &[tag_policy, self_tag_policy]);
        assert!(risk.principal_can_self_tag);
        assert!(!risk.tag_dependent_policies.is_empty());
        assert_eq!(risk.risk_level, TagRiskLevel::High);
    }

    #[test]
    fn test_risk_level_guarded_tag_action() {
        let tag_policy =
            make_policy_with_conditions(vec![make_condition("aws:PrincipalTag/team", vec!["eng"])]);
        let self_tag_policy = make_full_policy(
            vec!["iam:TagUser"],
            vec![make_condition("aws:RequestTag/mfa", vec!["true"])],
        );
        let actions = vec!["iam:TagUser"];

        let risk = analyze_tag_manipulation_risk(&actions, &[tag_policy, self_tag_policy]);
        assert!(!risk.principal_can_self_tag);
        assert_eq!(risk.risk_level, TagRiskLevel::None);
    }

    #[test]
    fn test_exploitable_tags_principal_tag() {
        let tag_policy =
            make_policy_with_conditions(vec![make_condition("aws:PrincipalTag/team", vec![])]);
        let self_tag_policy = make_full_policy(vec!["iam:TagUser"], vec![]);
        let actions = vec!["iam:TagUser"];

        let risk = analyze_tag_manipulation_risk(&actions, &[tag_policy, self_tag_policy]);
        assert!(risk.exploitable_tags.contains(&"team".to_string()));
    }

    #[test]
    fn test_exploitable_tags_resource_tag() {
        let tag_policy =
            make_policy_with_conditions(vec![make_condition("aws:ResourceTag/env", vec![])]);
        let self_tag_policy = make_full_policy(vec!["ec2:CreateTags"], vec![]);
        let actions = vec!["ec2:CreateTags"];

        let risk = analyze_tag_manipulation_risk(&actions, &[tag_policy, self_tag_policy]);
        assert!(risk.exploitable_tags.contains(&"env".to_string()));
    }

    #[test]
    fn test_non_exploitable_request_tag() {
        let tag_policy =
            make_policy_with_conditions(vec![make_condition("aws:RequestTag/mfa", vec![])]);
        let self_tag_policy = make_full_policy(vec!["iam:TagUser"], vec![]);
        let actions = vec!["iam:TagUser"];

        let risk = analyze_tag_manipulation_risk(&actions, &[tag_policy, self_tag_policy]);
        // RequestTag can't be self-set, so shouldn't be in exploitable
        assert!(!risk.exploitable_tags.contains(&"mfa".to_string()));
    }

    #[test]
    fn test_multiple_exploitable_tags() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![PolicyStatement {
                sid: None,
                effect: Effect::Allow,
                actions: vec![],
                not_actions: vec![],
                resources: vec![],
                not_resources: vec![],
                conditions: vec![
                    make_condition("aws:PrincipalTag/team", vec![]),
                    make_condition("aws:PrincipalTag/env", vec![]),
                    make_condition("aws:ResourceTag/region", vec![]),
                ],
            }],
        };
        let self_tag_policy = make_full_policy(vec!["iam:TagUser"], vec![]);
        let actions = vec!["iam:TagUser"];

        let risk = analyze_tag_manipulation_risk(&actions, &[policy, self_tag_policy]);
        assert_eq!(risk.exploitable_tags.len(), 3);
    }

    #[test]
    fn test_tag_dependent_policies_list() {
        let policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![PolicyStatement {
                sid: None,
                effect: Effect::Allow,
                actions: vec![],
                not_actions: vec![],
                resources: vec![],
                not_resources: vec![],
                conditions: vec![
                    make_condition("aws:PrincipalTag/team", vec![]),
                    make_condition("aws:ResourceTag/env", vec![]),
                ],
            }],
        };
        let self_tag_policy = make_full_policy(vec!["iam:TagUser"], vec![]);
        let actions = vec!["iam:TagUser"];

        let risk = analyze_tag_manipulation_risk(&actions, &[policy, self_tag_policy]);
        assert_eq!(risk.tag_dependent_policies.len(), 2);
        assert!(risk.tag_dependent_policies.contains(&"team".to_string()));
        assert!(risk.tag_dependent_policies.contains(&"env".to_string()));
    }

    #[test]
    fn test_case_insensitive_action_matching() {
        let policy = make_full_policy(vec!["IAM:TAGUSER"], vec![]);
        let actions = vec!["iam:taguser"];

        let unguarded = detect_unguarded_tag_manipulation(&actions, &[policy]);
        assert!(!unguarded.is_empty());
    }

    #[test]
    fn test_complex_scenario_with_multiple_policies() {
        let tag_policy = ParsedPolicy {
            version: "2012-10-17".to_string(),
            statements: vec![PolicyStatement {
                sid: Some("DenyUntagged".to_string()),
                effect: Effect::Allow,
                actions: vec![],
                not_actions: vec![],
                resources: vec![],
                not_resources: vec![],
                conditions: vec![make_condition("aws:PrincipalTag/approved", vec!["true"])],
            }],
        };

        let tag_action_policy = make_full_policy(vec!["iam:TagUser"], vec![]);
        let s3_policy = make_full_policy(vec!["s3:GetObject"], vec![]);

        let actions = vec!["iam:TagUser", "s3:GetObject"];

        let risk =
            analyze_tag_manipulation_risk(&actions, &[tag_policy, tag_action_policy, s3_policy]);
        assert!(risk.principal_can_self_tag);
        assert!(!risk.tag_dependent_policies.is_empty());
        assert!(risk.exploitable_tags.contains(&"approved".to_string()));
        assert_eq!(risk.risk_level, TagRiskLevel::High);
    }
}
