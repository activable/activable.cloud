//! CloudGoat escalation path regression tests.
//!
//! Validates that all 7 known escalation chains from CloudGoat scenarios
//! are correctly detected by the risk scoring pipeline.

use activable_risk::{
    batch_score_all, load_rules_from_dir, match_all_rules,
    signals::{GraphQueryError, GraphQueryService, SignalError},
    EffectivePermission, RiskConfig,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;

/// In-memory graph service for testing (local copy)
struct TestGraphService {
    principals: RwLock<PrincipalStore>,
}

struct PrincipalStore {
    principal_ids: Vec<String>,
    effective_permissions: HashMap<String, Vec<(String, String)>>,
    reachable_counts: HashMap<String, u64>,
    shortest_paths: HashMap<String, Option<u32>>,
    cross_account_hops: HashMap<String, u32>,
}

impl TestGraphService {
    fn new() -> Self {
        Self {
            principals: RwLock::new(PrincipalStore {
                principal_ids: Vec::new(),
                effective_permissions: HashMap::new(),
                reachable_counts: HashMap::new(),
                shortest_paths: HashMap::new(),
                cross_account_hops: HashMap::new(),
            }),
        }
    }

    fn add_principal(
        &self,
        principal_id: String,
        permissions: Vec<(String, String)>,
        reachable: u64,
        shortest_path: Option<u32>,
        cross_account_hops: u32,
    ) -> Result<(), SignalError> {
        let mut store = self
            .principals
            .write()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;

        if !store.principal_ids.contains(&principal_id) {
            store.principal_ids.push(principal_id.clone());
        }
        store
            .effective_permissions
            .insert(principal_id.clone(), permissions);
        store
            .reachable_counts
            .insert(principal_id.clone(), reachable);
        store
            .shortest_paths
            .insert(principal_id.clone(), shortest_path);
        store
            .cross_account_hops
            .insert(principal_id, cross_account_hops);
        Ok(())
    }
}

#[async_trait]
impl GraphQueryService for TestGraphService {
    async fn reachable_count(&self, principal_id: &str, _max_hops: u8) -> Result<u64, SignalError> {
        let store = self
            .principals
            .read()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;
        Ok(store
            .reachable_counts
            .get(principal_id)
            .copied()
            .unwrap_or(0))
    }

    async fn shortest_path_to_admin(
        &self,
        principal_id: &str,
        _max_depth: u8,
    ) -> Result<Option<u32>, SignalError> {
        let store = self
            .principals
            .read()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;
        Ok(store.shortest_paths.get(principal_id).copied().flatten())
    }

    async fn cross_account_hop_count(&self, principal_id: &str) -> Result<u32, SignalError> {
        let store = self
            .principals
            .read()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;
        Ok(store
            .cross_account_hops
            .get(principal_id)
            .copied()
            .unwrap_or(0))
    }

    async fn list_principal_ids(&self) -> Result<Vec<String>, SignalError> {
        let store = self
            .principals
            .read()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;
        Ok(store.principal_ids.clone())
    }

    async fn get_effective_permissions(
        &self,
        principal_id: &str,
    ) -> Result<Vec<(String, String)>, SignalError> {
        let store = self
            .principals
            .read()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;
        Ok(store
            .effective_permissions
            .get(principal_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn read_risk_assessment(
        &self,
        _principal_id: &str,
    ) -> Result<Option<String>, SignalError> {
        let _store = self
            .principals
            .read()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;
        Ok(None)
    }

    async fn write_risk_assessment(
        &self,
        _principal_id: &str,
        _assessment_json: &str,
    ) -> Result<(), SignalError> {
        Ok(())
    }

    async fn list_account_principals(&self, _account_id: &str) -> Result<Vec<String>, SignalError> {
        Ok(Vec::new())
    }

    async fn query_oidc_providers(
        &self,
        _account_id: &str,
    ) -> Result<Vec<activable_risk::signals::OidcProviderRow>, SignalError> {
        Ok(Vec::new())
    }

    async fn query_kms_key(
        &self,
        _key_arn: &str,
        _key_uuid: &str,
    ) -> Result<Option<activable_risk::signals::KmsKeyRow>, SignalError> {
        Ok(None)
    }

    async fn query_bucket_policy(
        &self,
        _bucket_name: &str,
    ) -> Result<Option<activable_risk::signals::ResourcePolicyRow>, SignalError> {
        Ok(None)
    }

    async fn query_key_resource_policy(
        &self,
        _key_id: &str,
    ) -> Result<Option<activable_risk::signals::ResourcePolicyRow>, SignalError> {
        Ok(None)
    }
}

/// Helper to load rules from bundled config
fn load_bundled_rules() -> Vec<activable_risk::EscalationRule> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let rules_path = format!("{}/config/escalation-paths/bundled", manifest_dir);
    load_rules_from_dir(&rules_path).expect("Failed to load bundled rules")
}

/// Scenario 1: iam:CreatePolicyVersion self-escalation
#[test]
fn cloudgoat_scenario_1_create_policy_version() {
    let rules = load_bundled_rules();

    // Principal with iam:CreatePolicyVersion can create new policy versions,
    // attach them to their own identity, gaining admin access
    let perms = vec![EffectivePermission::new(
        "iam:CreatePolicyVersion",
        "arn:aws:iam::123456789012:policy/*",
    )];

    let matched = match_all_rules(&rules, &perms);

    // Should match iam-001 rule
    assert!(
        matched.iter().any(|r| r.rule_id == "iam-001"),
        "Expected iam-001 rule to match for iam:CreatePolicyVersion"
    );
}

/// Scenario 2: iam:AttachUserPolicy to attach admin policy
#[test]
fn cloudgoat_scenario_2_attach_user_policy() {
    let rules = load_bundled_rules();

    let perms = vec![EffectivePermission::new(
        "iam:AttachUserPolicy",
        "arn:aws:iam::123456789012:user/*",
    )];

    let matched = match_all_rules(&rules, &perms);

    // Should match iam-002 rule
    assert!(
        matched.iter().any(|r| r.rule_id == "iam-002"),
        "Expected iam-002 rule to match for iam:AttachUserPolicy"
    );
}

/// Scenario 3: iam:CreateAccessKey credential access
#[test]
fn cloudgoat_scenario_3_create_access_key() {
    let rules = load_bundled_rules();

    let perms = vec![EffectivePermission::new(
        "iam:CreateAccessKey",
        "arn:aws:iam::123456789012:user/*",
    )];

    let matched = match_all_rules(&rules, &perms);

    // Should match iam-003 rule
    assert!(
        matched.iter().any(|r| r.rule_id == "iam-003"),
        "Expected iam-003 rule to match for iam:CreateAccessKey"
    );
}

/// Scenario 4: iam:PassRole + ec2:RunInstances instance profile escalation
#[test]
fn cloudgoat_scenario_4_passrole_ec2_run_instances() {
    let rules = load_bundled_rules();

    let perms = vec![
        EffectivePermission::new("iam:PassRole", "arn:aws:iam::123456789012:role/*"),
        EffectivePermission::new("ec2:RunInstances", "arn:aws:ec2:*:123456789012:instance/*"),
    ];

    let matched = match_all_rules(&rules, &perms);

    // Should match ec2-001 rule
    assert!(
        matched.iter().any(|r| r.rule_id == "ec2-001"),
        "Expected ec2-001 rule to match for iam:PassRole + ec2:RunInstances"
    );
}

/// Scenario 5: iam:PassRole + lambda:CreateFunction lambda escalation
#[test]
fn cloudgoat_scenario_5_passrole_lambda_create() {
    let rules = load_bundled_rules();

    let perms = vec![
        EffectivePermission::new("iam:PassRole", "arn:aws:iam::123456789012:role/*"),
        EffectivePermission::new(
            "lambda:CreateFunction",
            "arn:aws:lambda:*:123456789012:function/*",
        ),
        EffectivePermission::new(
            "lambda:InvokeFunction",
            "arn:aws:lambda:*:123456789012:function/*",
        ),
    ];

    let matched = match_all_rules(&rules, &perms);

    // Should match lambda-001 rule
    assert!(
        matched.iter().any(|r| r.rule_id == "lambda-001"),
        "Expected lambda-001 rule to match for iam:PassRole + lambda:CreateFunction"
    );
}

/// Scenario 6: Admin ("*") should match ALL escalation rules
#[test]
fn cloudgoat_scenario_6_admin_wildcard() {
    let rules = load_bundled_rules();

    // Admin principal with wildcard access
    let perms = vec![EffectivePermission::new("*", "*")];

    let matched = match_all_rules(&rules, &perms);

    // Should match all 5 escalation rules (iam-001, iam-002, iam-003, ec2-001, lambda-001)
    assert!(
        matched.iter().any(|r| r.rule_id == "iam-001"),
        "Expected iam-001 to match for admin (*)"
    );
    assert!(
        matched.iter().any(|r| r.rule_id == "iam-002"),
        "Expected iam-002 to match for admin (*)"
    );
    assert!(
        matched.iter().any(|r| r.rule_id == "iam-003"),
        "Expected iam-003 to match for admin (*)"
    );
    assert!(
        matched.iter().any(|r| r.rule_id == "ec2-001"),
        "Expected ec2-001 to match for admin (*)"
    );
    assert!(
        matched.iter().any(|r| r.rule_id == "lambda-001"),
        "Expected lambda-001 to match for admin (*)"
    );
}

/// Scenario 7: Safe read-only principal should match NO escalation rules
#[test]
fn cloudgoat_scenario_7_readonly_safe() {
    let rules = load_bundled_rules();

    // Read-only permissions
    let perms = vec![
        EffectivePermission::new("s3:GetObject", "arn:aws:s3:::bucket/*"),
        EffectivePermission::new("s3:ListBucket", "arn:aws:s3:::bucket"),
    ];

    let matched = match_all_rules(&rules, &perms);

    // Should match no escalation rules
    assert!(
        matched.is_empty(),
        "Expected no rules to match for read-only S3 permissions, but got: {:?}",
        matched.iter().map(|r| &r.rule_id).collect::<Vec<_>>()
    );
}

/// Integration test: Admin principal full pipeline (using in-memory graph)
#[tokio::test]
async fn integration_admin_principal_full_pipeline() {
    let rules = load_bundled_rules();
    let config = RiskConfig::default();

    // Create in-memory graph with admin principal
    let graph = TestGraphService::new();
    graph
        .add_principal(
            "admin-principal".to_string(),
            vec![(String::from("*"), String::from("*"))],
            5000,    // high reachability
            Some(0), // is admin
            3,       // cross-account hops
        )
        .expect("Failed to add principal");

    // Run batch scoring
    let result = batch_score_all(&rules, &graph, &config, "2026-05-23T00:00:00Z").await;

    assert_eq!(result.total_principals, 1);
    assert_eq!(result.scored_count, 1);
    assert_eq!(result.errors.len(), 0);

    // Admin should have critical severity and high score
    let assessment = &result.assessments[0];
    assert_eq!(assessment.principal_id, "admin-principal");
    assert!(
        assessment.score >= 0.75,
        "Admin principal should have high score >= 0.75, got {}",
        assessment.score
    );
    // Admin should be High or Critical (depends on signal weights)
    let sev = assessment.severity.to_string();
    assert!(
        sev == "Critical" || sev == "High",
        "Admin principal should be Critical or High severity, got {}",
        sev
    );

    // Should match all 5 escalation rules
    assert!(
        assessment.matched_rules.len() >= 5,
        "Admin should match at least 5 rules, got {}",
        assessment.matched_rules.len()
    );
}

/// Integration test: Read-only principal full pipeline (using in-memory graph)
#[tokio::test]
async fn integration_readonly_principal_full_pipeline() {
    let rules = load_bundled_rules();
    let config = RiskConfig::default();

    // Create in-memory graph with read-only principal
    let graph = TestGraphService::new();
    graph
        .add_principal(
            "readonly-principal".to_string(),
            vec![
                (
                    String::from("s3:GetObject"),
                    String::from("arn:aws:s3:::bucket/*"),
                ),
                (
                    String::from("s3:ListBucket"),
                    String::from("arn:aws:s3:::bucket"),
                ),
            ],
            5,    // low reachability
            None, // no path to admin
            0,    // no cross-account access
        )
        .expect("Failed to add principal");

    // Run batch scoring
    let result = batch_score_all(&rules, &graph, &config, "2026-05-23T00:00:00Z").await;

    assert_eq!(result.total_principals, 1);
    assert_eq!(result.scored_count, 1);
    assert_eq!(result.errors.len(), 0);

    // Read-only should have low score and Info severity
    let assessment = &result.assessments[0];
    assert_eq!(assessment.principal_id, "readonly-principal");
    assert!(
        assessment.score < 0.20,
        "Read-only principal should have low score, got {}",
        assessment.score
    );
    assert_eq!(
        assessment.severity.to_string(),
        "Info",
        "Read-only principal should be Info severity"
    );

    // Should match no escalation rules
    assert_eq!(
        assessment.matched_rules.len(),
        0,
        "Read-only should match no escalation rules, got {}",
        assessment.matched_rules.len()
    );
}

/// Integration test: Moderate-risk developer with PassRole (using in-memory graph)
#[tokio::test]
async fn integration_moderate_developer_passrole() {
    let rules = load_bundled_rules();
    let config = RiskConfig::default();

    // Create in-memory graph with developer that has PassRole
    let graph = TestGraphService::new();
    graph
        .add_principal(
            "developer-principal".to_string(),
            vec![
                (
                    String::from("iam:PassRole"),
                    String::from("arn:aws:iam::123456789012:role/*"),
                ),
                (
                    String::from("ec2:RunInstances"),
                    String::from("arn:aws:ec2:*:123456789012:instance/*"),
                ),
                (
                    String::from("s3:GetObject"),
                    String::from("arn:aws:s3:::bucket/*"),
                ),
                (
                    String::from("s3:PutObject"),
                    String::from("arn:aws:s3:::bucket/*"),
                ),
            ],
            50,      // moderate reachability
            Some(3), // 3 hops to admin
            1,       // 1 cross-account hop
        )
        .expect("Failed to add principal");

    // Run batch scoring
    let result = batch_score_all(&rules, &graph, &config, "2026-05-23T00:00:00Z").await;

    assert_eq!(result.total_principals, 1);
    assert_eq!(result.scored_count, 1);
    assert_eq!(result.errors.len(), 0);

    let assessment = &result.assessments[0];
    assert_eq!(assessment.principal_id, "developer-principal");

    // Score should be moderate
    assert!(
        assessment.score >= 0.20 && assessment.score <= 0.70,
        "Developer score should be moderate, got {}",
        assessment.score
    );

    // Should match ec2-001 rule (PassRole + ec2:RunInstances)
    assert!(
        assessment
            .matched_rules
            .iter()
            .any(|r| r.rule_id == "ec2-001"),
        "Developer should match ec2-001 rule"
    );
}
