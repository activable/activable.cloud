use activable_risk::{
    config::RiskConfig,
    enumeration::{enumerate_principals, run_iterative_scoring, IterationConfig},
    types::{EscalationRule, Prerequisites, RequiredPermission, RuleRequirement},
};
use async_trait::async_trait;
use std::collections::HashMap;

// Local mock implementation for integration tests
#[derive(Default)]
pub struct TestGraphQueryService {
    pub principal_ids: Vec<String>,
    pub reachable_counts: HashMap<String, u64>,
    pub shortest_paths: HashMap<String, Option<u32>>,
    pub cross_account_hops: HashMap<String, u32>,
    pub effective_permissions: HashMap<String, Vec<(String, String)>>,
}

impl TestGraphQueryService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_principal_ids(mut self, ids: Vec<String>) -> Self {
        self.principal_ids = ids;
        self
    }

    pub fn with_reachable(mut self, principal_id: String, count: u64) -> Self {
        self.reachable_counts.insert(principal_id, count);
        self
    }

    pub fn with_shortest_path(mut self, principal_id: String, distance: Option<u32>) -> Self {
        self.shortest_paths.insert(principal_id, distance);
        self
    }

    pub fn with_cross_account_hops(mut self, principal_id: String, hops: u32) -> Self {
        self.cross_account_hops.insert(principal_id, hops);
        self
    }

    pub fn with_effective_permissions(
        mut self,
        principal_id: String,
        perms: Vec<(String, String)>,
    ) -> Self {
        self.effective_permissions.insert(principal_id, perms);
        self
    }
}

#[async_trait]
impl activable_risk::signals::GraphQueryService for TestGraphQueryService {
    async fn reachable_count(
        &self,
        principal_id: &str,
        _max_hops: u8,
    ) -> Result<u64, activable_risk::signals::SignalError> {
        Ok(self
            .reachable_counts
            .get(principal_id)
            .copied()
            .unwrap_or(0))
    }

    async fn shortest_path_to_admin(
        &self,
        principal_id: &str,
        _max_depth: u8,
    ) -> Result<Option<u32>, activable_risk::signals::SignalError> {
        Ok(self.shortest_paths.get(principal_id).copied().flatten())
    }

    async fn cross_account_hop_count(
        &self,
        principal_id: &str,
    ) -> Result<u32, activable_risk::signals::SignalError> {
        Ok(self
            .cross_account_hops
            .get(principal_id)
            .copied()
            .unwrap_or(0))
    }

    async fn list_principal_ids(
        &self,
    ) -> Result<Vec<String>, activable_risk::signals::SignalError> {
        Ok(self.principal_ids.clone())
    }

    async fn get_effective_permissions(
        &self,
        principal_id: &str,
    ) -> Result<Vec<(String, String)>, activable_risk::signals::SignalError> {
        Ok(self
            .effective_permissions
            .get(principal_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn read_risk_assessment(
        &self,
        _principal_id: &str,
    ) -> Result<Option<String>, activable_risk::signals::SignalError> {
        Ok(None)
    }

    async fn write_risk_assessment(
        &self,
        _principal_id: &str,
        _assessment_json: &str,
    ) -> Result<(), activable_risk::signals::SignalError> {
        Ok(())
    }
}

fn test_rule(id: &str, permissions: &[&str], tier: u8) -> EscalationRule {
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

#[tokio::test]
async fn integration_10_principal_cross_account_scenario() {
    // Test with 10 principals simulating a cross-account scenario
    // with multiple escalation paths
    let config = RiskConfig::default();
    let iter_config = IterationConfig::default();

    let graph = TestGraphQueryService::new()
        .with_principal_ids(vec![
            "user-1".to_string(),
            "user-2".to_string(),
            "role-1".to_string(),
            "role-2".to_string(),
            "role-3".to_string(),
            "cross-account-role-1".to_string(),
            "cross-account-role-2".to_string(),
            "group-1".to_string(),
            "group-2".to_string(),
            "service-role".to_string(),
        ])
        // User 1: can create policies
        .with_reachable("user-1".to_string(), 50)
        .with_effective_permissions(
            "user-1".to_string(),
            vec![
                (
                    "iam:CreatePolicyVersion".to_string(),
                    "arn:aws:iam::111111111111:*".to_string(),
                ),
                (
                    "sts:AssumeRole".to_string(),
                    "arn:aws:iam::111111111111:role/*".to_string(),
                ),
            ],
        )
        // User 2: can pass role and run instances
        .with_reachable("user-2".to_string(), 30)
        .with_effective_permissions(
            "user-2".to_string(),
            vec![
                (
                    "iam:PassRole".to_string(),
                    "arn:aws:iam::111111111111:role/*".to_string(),
                ),
                (
                    "ec2:RunInstances".to_string(),
                    "arn:aws:ec2:*:111111111111:*".to_string(),
                ),
                (
                    "sts:AssumeRole".to_string(),
                    "arn:aws:iam::222222222222:role/*".to_string(),
                ),
            ],
        )
        // Role 1: administrative
        .with_reachable("role-1".to_string(), 200)
        .with_effective_permissions(
            "role-1".to_string(),
            vec![("*".to_string(), "*".to_string())],
        )
        // Role 2: data access
        .with_reachable("role-2".to_string(), 15)
        .with_effective_permissions(
            "role-2".to_string(),
            vec![("s3:*".to_string(), "arn:aws:s3:::*".to_string())],
        )
        // Role 3: can assume another role
        .with_reachable("role-3".to_string(), 25)
        .with_effective_permissions(
            "role-3".to_string(),
            vec![(
                "sts:AssumeRole".to_string(),
                "arn:aws:iam::222222222222:role/*".to_string(),
            )],
        )
        // Cross-account roles
        .with_reachable("cross-account-role-1".to_string(), 80)
        .with_effective_permissions(
            "cross-account-role-1".to_string(),
            vec![
                (
                    "iam:AttachUserPolicy".to_string(),
                    "arn:aws:iam::222222222222:*".to_string(),
                ),
                (
                    "sts:AssumeRole".to_string(),
                    "arn:aws:iam::111111111111:role/*".to_string(),
                ),
            ],
        )
        .with_reachable("cross-account-role-2".to_string(), 40)
        .with_effective_permissions(
            "cross-account-role-2".to_string(),
            vec![(
                "ec2:*".to_string(),
                "arn:aws:ec2:*:222222222222:*".to_string(),
            )],
        )
        // Groups
        .with_reachable("group-1".to_string(), 5)
        .with_effective_permissions(
            "group-1".to_string(),
            vec![("s3:ListBucket".to_string(), "arn:aws:s3:::*".to_string())],
        )
        .with_reachable("group-2".to_string(), 10)
        .with_effective_permissions(
            "group-2".to_string(),
            vec![("iam:GetUser".to_string(), "*".to_string())],
        )
        // Service role: limited
        .with_reachable("service-role".to_string(), 20)
        .with_effective_permissions(
            "service-role".to_string(),
            vec![(
                "logs:CreateLogGroup".to_string(),
                "arn:aws:logs:*:111111111111:*".to_string(),
            )],
        );

    let rules = vec![
        test_rule("iam-001", &["iam:CreatePolicyVersion"], 1),
        test_rule("iam-002", &["iam:AttachUserPolicy"], 2),
        test_rule("iam-003", &["iam:PassRole", "ec2:RunInstances"], 2),
        test_rule("admin-001", &["*"], 1),
    ];

    let stats = run_iterative_scoring(
        &graph,
        &rules,
        &config,
        &iter_config,
        "2026-05-23T10:00:00Z",
    )
    .await
    .unwrap();

    // Verify basic counts
    assert_eq!(stats.total_principals, 10);
    assert!(stats.assessments.len() <= 10); // Some principals may have been skipped
    assert!(stats.iterations_completed >= 1);
    assert!(stats.iterations_completed <= iter_config.max_iterations);

    // Verify at least some rules were matched
    let total_matched_rules: usize = stats
        .assessments
        .iter()
        .map(|a| a.matched_rules.len())
        .sum();
    assert!(
        total_matched_rules > 0,
        "Expected at least some rules to match"
    );

    // Verify convergence stats are reasonable
    if stats.converged {
        // If converged, should have detected no new edges below threshold
        let last_edges = stats.new_edges_per_iteration.last();
        if let Some(&edges) = last_edges {
            assert!(edges < iter_config.convergence_threshold);
        }
    }
}

#[tokio::test]
async fn integration_enumerate_and_score_workflow() {
    // Test the complete workflow: enumerate → score → assess
    let graph = TestGraphQueryService::new()
        .with_principal_ids(vec!["principal-a".to_string(), "principal-b".to_string()])
        .with_reachable("principal-a".to_string(), 25)
        .with_reachable("principal-b".to_string(), 10)
        .with_effective_permissions(
            "principal-a".to_string(),
            vec![
                ("iam:CreateAccessKey".to_string(), "*".to_string()),
                ("iam:AttachUserPolicy".to_string(), "*".to_string()),
            ],
        )
        .with_effective_permissions(
            "principal-b".to_string(),
            vec![("s3:*".to_string(), "*".to_string())],
        );

    // Step 1: Enumerate principals
    let principals = enumerate_principals(&graph).await.unwrap();
    assert_eq!(principals.len(), 2);
    assert_eq!(principals[0].principal_id, "principal-a");
    assert_eq!(principals[0].effective_permissions.len(), 2);
    assert_eq!(principals[1].principal_id, "principal-b");
    assert_eq!(principals[1].effective_permissions.len(), 1);

    // Step 2: Score all principals iteratively
    let config = RiskConfig::default();
    let iter_config = IterationConfig::default();
    let rules = vec![
        test_rule("rule-1", &["iam:CreateAccessKey"], 1),
        test_rule("rule-2", &["iam:AttachUserPolicy"], 2),
    ];

    let stats = run_iterative_scoring(
        &graph,
        &rules,
        &config,
        &iter_config,
        "2026-05-23T10:00:00Z",
    )
    .await
    .unwrap();

    // Verify results
    assert_eq!(stats.total_principals, 2);
    assert_eq!(stats.assessments.len(), 2);

    // Principal A should match 2 rules
    let principal_a = stats
        .assessments
        .iter()
        .find(|a| a.principal_id == "principal-a")
        .unwrap();
    assert_eq!(principal_a.matched_rules.len(), 2);

    // Principal B should match 0 rules
    let principal_b = stats
        .assessments
        .iter()
        .find(|a| a.principal_id == "principal-b")
        .unwrap();
    assert_eq!(principal_b.matched_rules.len(), 0);
}

#[tokio::test]
async fn integration_convergence_with_100_principals() {
    // Test convergence detection with a larger principal set
    let config = RiskConfig::default();
    let iter_config = IterationConfig::default();

    // Create 100 principals
    let mut principal_ids = Vec::new();
    for i in 0..100 {
        principal_ids.push(format!("principal-{}", i));
    }

    let mut graph = TestGraphQueryService::new().with_principal_ids(principal_ids.clone());

    // Add different permissions to different groups
    for (idx, principal_id) in principal_ids.iter().enumerate() {
        if idx % 4 == 0 {
            // 25 principals with escalation permission
            graph = graph.with_effective_permissions(
                principal_id.clone(),
                vec![("iam:CreatePolicyVersion".to_string(), "*".to_string())],
            );
        } else if idx % 4 == 1 {
            // 25 principals with PassRole
            graph = graph.with_effective_permissions(
                principal_id.clone(),
                vec![("iam:PassRole".to_string(), "*".to_string())],
            );
        } else if idx % 4 == 2 {
            // 25 principals with data access
            graph = graph.with_effective_permissions(
                principal_id.clone(),
                vec![("s3:GetObject".to_string(), "*".to_string())],
            );
        } else {
            // 25 principals with no dangerous permissions
            graph = graph.with_effective_permissions(
                principal_id.clone(),
                vec![("logs:DescribeLogGroups".to_string(), "*".to_string())],
            );
        }

        graph = graph.with_reachable(principal_id.clone(), (idx as u64) % 100);
    }

    let rules = vec![
        test_rule("iam-001", &["iam:CreatePolicyVersion"], 1),
        test_rule("iam-002", &["iam:PassRole"], 1),
    ];

    let stats = run_iterative_scoring(
        &graph,
        &rules,
        &config,
        &iter_config,
        "2026-05-23T10:00:00Z",
    )
    .await
    .unwrap();

    // Verify results
    assert_eq!(stats.total_principals, 100);
    assert!(stats.iterations_completed >= 1);
    assert!(stats.iterations_completed <= iter_config.max_iterations);

    // Should converge because we only have 50 matched rules (25 + 25)
    // After first iteration, all 50 chains are visited
    // After second iteration, no new chains → converges
    assert!(stats.converged);

    // Verify we got assessments for all principals
    assert_eq!(stats.assessments.len(), 100);

    // About 50 principals should have matched rules
    let with_matches = stats
        .assessments
        .iter()
        .filter(|a| !a.matched_rules.is_empty())
        .count();
    assert!((45..=55).contains(&with_matches));
}

#[tokio::test]
async fn integration_cycle_scenario_a_to_b_to_a() {
    // Test cycle detection: A assumes B, B assumes A
    let config = RiskConfig::default();
    let iter_config = IterationConfig::default();

    let graph = TestGraphQueryService::new()
        .with_principal_ids(vec!["principal-a".to_string(), "principal-b".to_string()])
        .with_reachable("principal-a".to_string(), 10)
        .with_reachable("principal-b".to_string(), 10)
        .with_effective_permissions(
            "principal-a".to_string(),
            vec![(
                "sts:AssumeRole".to_string(),
                "arn:aws:iam::*:role/*".to_string(),
            )],
        )
        .with_effective_permissions(
            "principal-b".to_string(),
            vec![(
                "sts:AssumeRole".to_string(),
                "arn:aws:iam::*:role/*".to_string(),
            )],
        );

    let rules = vec![test_rule("assume-rule", &["sts:AssumeRole"], 1)];

    let stats = run_iterative_scoring(
        &graph,
        &rules,
        &config,
        &iter_config,
        "2026-05-23T10:00:00Z",
    )
    .await
    .unwrap();

    // Both principals match the rule
    assert_eq!(stats.total_principals, 2);
    assert_eq!(stats.assessments.len(), 2);

    // First iteration: 2 new edges (A→assume-rule, B→assume-rule)
    // 2 < threshold (5) → converges immediately
    assert!(stats.converged);
    assert_eq!(stats.iterations_completed, 1);
    assert_eq!(stats.new_edges_per_iteration[0], 2);
}

#[tokio::test]
async fn integration_assessment_scores_reasonable() {
    // Test that risk scores are computed reasonably
    let config = RiskConfig::default();
    let iter_config = IterationConfig::default();

    let graph = TestGraphQueryService::new()
        .with_principal_ids(vec![
            "safe-principal".to_string(),
            "risky-principal".to_string(),
        ])
        .with_reachable("safe-principal".to_string(), 0)
        .with_reachable("risky-principal".to_string(), 200)
        .with_shortest_path("safe-principal".to_string(), None)
        .with_shortest_path("risky-principal".to_string(), Some(2))
        .with_cross_account_hops("safe-principal".to_string(), 0)
        .with_cross_account_hops("risky-principal".to_string(), 5)
        .with_effective_permissions(
            "safe-principal".to_string(),
            vec![("logs:DescribeLogGroups".to_string(), "*".to_string())],
        )
        .with_effective_permissions(
            "risky-principal".to_string(),
            vec![
                ("iam:CreateAccessKey".to_string(), "*".to_string()),
                ("iam:AttachUserPolicy".to_string(), "*".to_string()),
                ("sts:AssumeRole".to_string(), "*".to_string()),
            ],
        );

    let rules = vec![
        test_rule("iam-001", &["iam:CreateAccessKey"], 1),
        test_rule("iam-002", &["iam:AttachUserPolicy"], 2),
    ];

    let stats = run_iterative_scoring(
        &graph,
        &rules,
        &config,
        &iter_config,
        "2026-05-23T10:00:00Z",
    )
    .await
    .unwrap();

    let safe = stats
        .assessments
        .iter()
        .find(|a| a.principal_id == "safe-principal")
        .unwrap();
    let risky = stats
        .assessments
        .iter()
        .find(|a| a.principal_id == "risky-principal")
        .unwrap();

    // Safe principal should have low score
    assert!(
        safe.score < 0.2,
        "Safe principal score too high: {}",
        safe.score
    );

    // Risky principal should have higher score
    assert!(
        risky.score > safe.score,
        "Risky principal score {} not > safe score {}",
        risky.score,
        safe.score
    );

    // Risky principal should match rules
    assert!(!risky.matched_rules.is_empty());
}
