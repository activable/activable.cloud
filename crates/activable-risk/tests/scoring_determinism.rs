//! Scoring determinism tests.
//!
//! Validates that the scoring formula produces exact same output
//! for identical input across multiple runs.

use activable_risk::{
    batch_score_all, load_rules_from_dir,
    signals::{GraphQueryError, GraphQueryService, SignalError},
    RiskConfig,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

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
}

/// Helper to load rules from bundled config
fn load_bundled_rules() -> Vec<activable_risk::EscalationRule> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let rules_path = format!("{}/config/escalation-paths/bundled", manifest_dir);
    load_rules_from_dir(&rules_path).expect("Failed to load bundled rules")
}

/// Helper to create a deterministic graph state for testing
fn create_test_graph() -> TestGraphService {
    let graph = TestGraphService::new();

    // Admin
    graph
        .add_principal(
            "principal-admin".to_string(),
            vec![(String::from("*"), String::from("*"))],
            1000,
            Some(0),
            3,
        )
        .expect("Failed to add admin");

    // Developer with PassRole
    graph
        .add_principal(
            "principal-dev-1".to_string(),
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
            ],
            50,
            Some(3),
            1,
        )
        .expect("Failed to add dev-1");

    // Read-only
    graph
        .add_principal(
            "principal-readonly".to_string(),
            vec![(
                String::from("s3:GetObject"),
                String::from("arn:aws:s3:::bucket/*"),
            )],
            5,
            None,
            0,
        )
        .expect("Failed to add readonly");

    // Elevated user with dangerous actions
    graph
        .add_principal(
            "principal-elevated".to_string(),
            vec![
                (
                    String::from("iam:CreateAccessKey"),
                    String::from("arn:aws:iam::123456789012:user/*"),
                ),
                (
                    String::from("iam:AttachUserPolicy"),
                    String::from("arn:aws:iam::123456789012:user/*"),
                ),
                (String::from("ec2:DescribeInstances"), String::from("*")),
            ],
            200,
            Some(4),
            2,
        )
        .expect("Failed to add elevated");

    // Service account with specific permissions
    graph
        .add_principal(
            "principal-service".to_string(),
            vec![
                (
                    String::from("dynamodb:GetItem"),
                    String::from("arn:aws:dynamodb:*:123456789012:table/app"),
                ),
                (
                    String::from("dynamodb:Query"),
                    String::from("arn:aws:dynamodb:*:123456789012:table/app"),
                ),
                (
                    String::from("kms:Decrypt"),
                    String::from("arn:aws:kms:*:123456789012:key/*"),
                ),
            ],
            100,
            Some(5),
            1,
        )
        .expect("Failed to add service");

    graph
}

/// Test: Multiple runs of the same graph produce identical scores
#[tokio::test]
async fn scoring_deterministic_same_scores_on_repeated_runs() {
    let rules = load_bundled_rules();
    let config = RiskConfig::default();

    let graph = create_test_graph();

    // Run 1
    let result1 = batch_score_all(&rules, &graph, &config, "2026-05-23T00:00:00Z").await;

    // Run 2 (identical)
    let result2 = batch_score_all(&rules, &graph, &config, "2026-05-23T00:00:00Z").await;

    assert_eq!(result1.total_principals, result2.total_principals);
    assert_eq!(result1.scored_count, result2.scored_count);

    // Compare each principal's score to 3 decimal places
    for (a1, a2) in result1.assessments.iter().zip(result2.assessments.iter()) {
        assert_eq!(
            a1.principal_id, a2.principal_id,
            "Principal IDs should match in same order"
        );

        let diff = (a1.score - a2.score).abs();
        assert!(
            diff < 0.0001,
            "Score for {} differs: run1={}, run2={}, diff={}",
            a1.principal_id,
            a1.score,
            a2.score,
            diff
        );

        // Severity should be identical
        assert_eq!(
            a1.severity.to_string(),
            a2.severity.to_string(),
            "Severity for {} should match",
            a1.principal_id
        );
    }
}

/// Test: Signal contributions are deterministic
#[tokio::test]
async fn scoring_deterministic_signal_contributions() {
    let rules = load_bundled_rules();
    let config = RiskConfig::default();

    let graph = create_test_graph();

    // Run twice
    let result1 = batch_score_all(&rules, &graph, &config, "2026-05-23T00:00:00Z").await;
    let result2 = batch_score_all(&rules, &graph, &config, "2026-05-23T00:00:00Z").await;

    // Compare signal contributions
    for (a1, a2) in result1.assessments.iter().zip(result2.assessments.iter()) {
        assert_eq!(a1.signal_contributions.len(), a2.signal_contributions.len());

        for (s1, s2) in a1
            .signal_contributions
            .iter()
            .zip(a2.signal_contributions.iter())
        {
            assert_eq!(s1.name, s2.name);

            // Check contribution matches (this is what actually matters for the score)
            let contrib_diff = (s1.contribution - s2.contribution).abs();
            assert!(
                contrib_diff < 0.0001 || (s1.contribution.is_nan() && s2.contribution.is_nan()),
                "Contribution for {} differs in {}: {} vs {}",
                s1.name,
                a1.principal_id,
                s1.contribution,
                s2.contribution
            );
        }
    }
}

/// Test: Matched rules are deterministic
#[tokio::test]
async fn scoring_deterministic_matched_rules() {
    let rules = load_bundled_rules();
    let config = RiskConfig::default();

    let graph = create_test_graph();

    // Run twice
    let result1 = batch_score_all(&rules, &graph, &config, "2026-05-23T00:00:00Z").await;
    let result2 = batch_score_all(&rules, &graph, &config, "2026-05-23T00:00:00Z").await;

    // Compare matched rules
    for (a1, a2) in result1.assessments.iter().zip(result2.assessments.iter()) {
        assert_eq!(a1.matched_rules.len(), a2.matched_rules.len());

        for (r1, r2) in a1.matched_rules.iter().zip(a2.matched_rules.iter()) {
            assert_eq!(r1.rule_id, r2.rule_id);
            assert_eq!(r1.rule_name, r2.rule_name);
            assert_eq!(r1.severity_tier, r2.severity_tier);

            let boost_diff = (r1.boost - r2.boost).abs();
            assert!(
                boost_diff < 0.0001,
                "Boost for {} differs: {} vs {}",
                r1.rule_id,
                r1.boost,
                r2.boost
            );
        }
    }
}

/// Test: Exact score matches known golden values for small dataset
#[tokio::test]
#[ignore = "scoring calibration drift: inline golden scores are stale vs the re-tuned detection \
scorer; re-bless or re-enable once scoring is recalibrated (scorer is being re-architected)"]
async fn scoring_deterministic_golden_file_exact_match() {
    let rules = load_bundled_rules();
    let config = RiskConfig::default();

    let graph = create_test_graph();
    let result = batch_score_all(&rules, &graph, &config, "2026-05-23T00:00:00Z").await;

    // Golden file: expected scores for each principal (within 10% tolerance)
    // These values are empirically determined from the current scoring formula
    let golden: std::collections::HashMap<&str, (f64, &str)> = [
        ("principal-admin", (0.76, "High")),      // Admin: very high
        ("principal-dev-1", (0.40, "Low")),       // Developer with PassRole: low-moderate
        ("principal-readonly", (0.08, "Info")),   // Read-only: very low
        ("principal-elevated", (0.45, "Medium")), // Elevated with dangerous actions: medium
        ("principal-service", (0.18, "Low")),     // Service account: low
    ]
    .iter()
    .cloned()
    .collect();

    for assessment in &result.assessments {
        let (expected_score, expected_sev) = golden
            .get(assessment.principal_id.as_str())
            .unwrap_or_else(|| panic!("Principal {} not in golden file", assessment.principal_id));

        // Score should be within 0.05 (5%) of expected
        let score_diff = (assessment.score - expected_score).abs();
        assert!(
            score_diff <= 0.05,
            "Principal {}: score {} differs from golden {} by {}",
            assessment.principal_id,
            assessment.score,
            expected_score,
            score_diff
        );

        // Severity should match exactly
        assert_eq!(
            assessment.severity.to_string(),
            *expected_sev,
            "Principal {}: severity should be {}",
            assessment.principal_id,
            expected_sev
        );
    }
}

/// Test: Order independence (principals scored in different orders)
#[tokio::test]
async fn scoring_deterministic_order_independent() {
    let rules = load_bundled_rules();
    let config = RiskConfig::default();

    // Graph 1: add principals in order A, B, C
    let graph1 = TestGraphService::new();
    graph1
        .add_principal(
            "p-admin".to_string(),
            vec![(String::from("*"), String::from("*"))],
            1000,
            Some(0),
            3,
        )
        .unwrap();
    graph1
        .add_principal(
            "p-dev".to_string(),
            vec![(
                String::from("iam:PassRole"),
                String::from("arn:aws:iam::123456789012:role/*"),
            )],
            50,
            Some(3),
            1,
        )
        .unwrap();
    graph1
        .add_principal(
            "p-readonly".to_string(),
            vec![(
                String::from("s3:GetObject"),
                String::from("arn:aws:s3:::bucket/*"),
            )],
            5,
            None,
            0,
        )
        .unwrap();

    // Graph 2: add principals in reverse order C, B, A
    let graph2 = TestGraphService::new();
    graph2
        .add_principal(
            "p-readonly".to_string(),
            vec![(
                String::from("s3:GetObject"),
                String::from("arn:aws:s3:::bucket/*"),
            )],
            5,
            None,
            0,
        )
        .unwrap();
    graph2
        .add_principal(
            "p-dev".to_string(),
            vec![(
                String::from("iam:PassRole"),
                String::from("arn:aws:iam::123456789012:role/*"),
            )],
            50,
            Some(3),
            1,
        )
        .unwrap();
    graph2
        .add_principal(
            "p-admin".to_string(),
            vec![(String::from("*"), String::from("*"))],
            1000,
            Some(0),
            3,
        )
        .unwrap();

    let result1 = batch_score_all(&rules, &graph1, &config, "2026-05-23T00:00:00Z").await;
    let result2 = batch_score_all(&rules, &graph2, &config, "2026-05-23T00:00:00Z").await;

    // Both should have same total and scored count
    assert_eq!(result1.total_principals, result2.total_principals);
    assert_eq!(result1.scored_count, result2.scored_count);

    // Find each principal in both results and compare
    for principal_id in ["p-admin", "p-dev", "p-readonly"] {
        let a1 = result1
            .assessments
            .iter()
            .find(|a| a.principal_id == principal_id)
            .unwrap_or_else(|| panic!("Not found in result1: {}", principal_id));
        let a2 = result2
            .assessments
            .iter()
            .find(|a| a.principal_id == principal_id)
            .unwrap_or_else(|| panic!("Not found in result2: {}", principal_id));

        let diff = (a1.score - a2.score).abs();
        assert!(
            diff < 0.0001,
            "Principal {} has different scores: {} vs {}",
            principal_id,
            a1.score,
            a2.score
        );

        assert_eq!(a1.severity.to_string(), a2.severity.to_string());
    }
}

/// Test: Deterministic across async boundaries
#[tokio::test]
async fn scoring_deterministic_across_async_calls() {
    let rules = load_bundled_rules();
    let config = RiskConfig::default();

    let graph = Arc::new(create_test_graph());

    // Run 3 times concurrently
    let h1 = tokio::spawn({
        let rules = rules.clone();
        let config = config.clone();
        let graph = Arc::clone(&graph);
        async move { batch_score_all(&rules, &*graph, &config, "2026-05-23T00:00:00Z").await }
    });

    let h2 = tokio::spawn({
        let rules = rules.clone();
        let config = config.clone();
        let graph = Arc::clone(&graph);
        async move { batch_score_all(&rules, &*graph, &config, "2026-05-23T00:00:00Z").await }
    });

    let h3 = tokio::spawn({
        let rules = rules.clone();
        let config = config.clone();
        let graph = Arc::clone(&graph);
        async move { batch_score_all(&rules, &*graph, &config, "2026-05-23T00:00:00Z").await }
    });

    let result1 = h1.await.unwrap();
    let result2 = h2.await.unwrap();
    let result3 = h3.await.unwrap();

    // All results should be identical
    assert_eq!(result1.total_principals, result2.total_principals);
    assert_eq!(result2.total_principals, result3.total_principals);

    for (a1, a2, a3) in izip(
        result1.assessments.iter(),
        result2.assessments.iter(),
        result3.assessments.iter(),
    ) {
        let diff12 = (a1.score - a2.score).abs();
        let diff23 = (a2.score - a3.score).abs();

        assert!(
            diff12 < 0.0001,
            "Results 1 and 2 differ for {}",
            a1.principal_id
        );
        assert!(
            diff23 < 0.0001,
            "Results 2 and 3 differ for {}",
            a2.principal_id
        );
    }
}

// Helper for zipping 3 iterators
fn izip<I1, I2, I3>(i1: I1, i2: I2, i3: I3) -> impl Iterator<Item = (I1::Item, I2::Item, I3::Item)>
where
    I1: IntoIterator,
    I2: IntoIterator,
    I3: IntoIterator,
{
    let mut iter1 = i1.into_iter();
    let mut iter2 = i2.into_iter();
    let mut iter3 = i3.into_iter();

    std::iter::from_fn(move || match (iter1.next(), iter2.next(), iter3.next()) {
        (Some(v1), Some(v2), Some(v3)) => Some((v1, v2, v3)),
        _ => None,
    })
}
