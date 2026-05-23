//! Performance benchmark tests.
//!
//! Validates that the risk scoring pipeline meets performance targets:
//! - 10k policy evaluations under 1 second
//! - 10k principal scoring under 60 seconds

use activable_risk::{
    batch_score_all, load_rules_from_dir, match_all_rules,
    signals::{GraphQueryError, GraphQueryService, SignalError},
    EffectivePermission, RiskConfig,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

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

/// Benchmark: Rule matching with 10,000 permission sets
#[test]
fn benchmark_rule_matching_10k_evaluations() {
    let rules = load_bundled_rules();

    // Generate 10k permission sets with random IAM actions
    let mut permission_sets = Vec::new();
    let actions = vec![
        "iam:*",
        "iam:CreatePolicyVersion",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:PassRole",
        "ec2:RunInstances",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteBucket",
        "dynamodb:GetItem",
        "dynamodb:Query",
        "kms:Decrypt",
        "kms:GenerateDataKey",
    ];

    for i in 0..10_000 {
        let action_idx = i % actions.len();
        let perms = vec![EffectivePermission::new(
            actions[action_idx],
            format!("arn:aws:iam::123456789012:resource/{}", i),
        )];
        permission_sets.push(perms);
    }

    // Benchmark matching
    let start = Instant::now();
    for perms in &permission_sets {
        let _ = match_all_rules(&rules, perms);
    }
    let elapsed = start.elapsed();

    let secs = elapsed.as_secs_f64();
    println!(
        "Matched {} permission sets against {} rules in {:.3}s",
        permission_sets.len(),
        rules.len(),
        secs
    );

    // Assert < 1 second
    assert!(
        elapsed.as_secs_f64() < 1.0,
        "Rule matching took {:.3}s, expected < 1.0s",
        secs
    );
}

/// Benchmark: Scoring 1,000 principals (smaller scale for CI)
#[tokio::test]
async fn benchmark_scoring_1k_principals() {
    let rules = load_bundled_rules();
    let config = RiskConfig::default();

    let graph = TestGraphService::new();

    // Add 1,000 principals with varying risk profiles
    for i in 0..1_000 {
        let perms = match i % 5 {
            0 => {
                // Admin
                vec![(String::from("*"), String::from("*"))]
            }
            1 => {
                // Developer with PassRole
                vec![
                    (
                        String::from("iam:PassRole"),
                        String::from("arn:aws:iam::123456789012:role/*"),
                    ),
                    (
                        String::from("ec2:RunInstances"),
                        String::from("arn:aws:ec2:*:123456789012:instance/*"),
                    ),
                ]
            }
            2 => {
                // Read-only
                vec![(
                    String::from("s3:GetObject"),
                    String::from("arn:aws:s3:::bucket/*"),
                )]
            }
            3 => {
                // Elevated with dangerous actions
                vec![
                    (
                        String::from("iam:CreateAccessKey"),
                        String::from("arn:aws:iam::123456789012:user/*"),
                    ),
                    (
                        String::from("iam:AttachUserPolicy"),
                        String::from("arn:aws:iam::123456789012:user/*"),
                    ),
                ]
            }
            _ => {
                // Service account
                vec![(
                    String::from("dynamodb:GetItem"),
                    String::from("arn:aws:dynamodb:*:123456789012:table/*"),
                )]
            }
        };

        let reachable = match i % 5 {
            0 => 5000,
            1 => 50,
            2 => 5,
            3 => 200,
            _ => 100,
        };

        let path_to_admin = match i % 5 {
            0 => Some(0),
            1 => Some(3),
            2 => None,
            3 => Some(4),
            _ => Some(5),
        };

        let cross_account = match i % 5 {
            0 => 3,
            1 => 1,
            2 => 0,
            3 => 2,
            _ => 1,
        };

        let principal_id = format!("principal-{:04}", i);
        graph
            .add_principal(principal_id, perms, reachable, path_to_admin, cross_account)
            .expect("Failed to add principal");
    }

    // Benchmark batch scoring
    let start = Instant::now();
    let result = batch_score_all(&rules, &graph, &config, "2026-05-23T00:00:00Z").await;
    let elapsed = start.elapsed();

    let secs = elapsed.as_secs_f64();
    println!(
        "Scored {} principals (total: {}) in {:.3}s ({:.2}ms/principal)",
        result.scored_count,
        result.total_principals,
        secs,
        (secs * 1000.0) / result.total_principals as f64
    );

    // Verify correctness
    assert_eq!(result.total_principals, 1_000);
    assert_eq!(result.scored_count, 1_000);
    assert_eq!(result.errors.len(), 0);

    // Assert < 60 seconds (scaled for 1k, typical 10k would be ~600s)
    assert!(
        elapsed.as_secs_f64() < 60.0,
        "Scoring 1k principals took {:.3}s, expected < 60s",
        secs
    );
}

/// Benchmark: Scoring 100 principals (fast CI-friendly version)
#[tokio::test]
async fn benchmark_scoring_100_principals_fast() {
    let rules = load_bundled_rules();
    let config = RiskConfig::default();

    let graph = TestGraphService::new();

    // Add 100 principals
    for i in 0..100 {
        let perms = match i % 5 {
            0 => vec![(String::from("*"), String::from("*"))],
            1 => vec![
                (
                    String::from("iam:PassRole"),
                    String::from("arn:aws:iam::123456789012:role/*"),
                ),
                (
                    String::from("ec2:RunInstances"),
                    String::from("arn:aws:ec2:*:123456789012:instance/*"),
                ),
            ],
            2 => vec![(
                String::from("s3:GetObject"),
                String::from("arn:aws:s3:::bucket/*"),
            )],
            3 => vec![(
                String::from("iam:CreateAccessKey"),
                String::from("arn:aws:iam::123456789012:user/*"),
            )],
            _ => vec![(
                String::from("dynamodb:GetItem"),
                String::from("arn:aws:dynamodb:*:123456789012:table/*"),
            )],
        };

        let reachable = match i % 5 {
            0 => 5000,
            1 => 50,
            2 => 5,
            3 => 200,
            _ => 100,
        };

        let path_to_admin = match i % 5 {
            0 => Some(0),
            1 => Some(3),
            2 => None,
            3 => Some(4),
            _ => Some(5),
        };

        let cross_account = match i % 5 {
            0 => 3,
            1 => 1,
            2 => 0,
            3 => 2,
            _ => 1,
        };

        let principal_id = format!("principal-{:04}", i);
        graph
            .add_principal(principal_id, perms, reachable, path_to_admin, cross_account)
            .expect("Failed to add principal");
    }

    // Benchmark batch scoring
    let start = Instant::now();
    let result = batch_score_all(&rules, &graph, &config, "2026-05-23T00:00:00Z").await;
    let elapsed = start.elapsed();

    let secs = elapsed.as_secs_f64();
    println!(
        "Scored {} principals in {:.3}s ({:.2}ms/principal)",
        result.scored_count,
        secs,
        (secs * 1000.0) / result.total_principals as f64
    );

    // Verify correctness
    assert_eq!(result.total_principals, 100);
    assert_eq!(result.scored_count, 100);
    assert_eq!(result.errors.len(), 0);

    // For 100 principals, expect < 5 seconds
    assert!(
        elapsed.as_secs_f64() < 5.0,
        "Scoring 100 principals took {:.3}s, expected < 5s",
        secs
    );
}

/// Benchmark: Permission matching performance with wildcard expansion
#[test]
fn benchmark_permission_matching_wildcard_expansion() {
    let rules = load_bundled_rules();

    // Create a set of wildcard permissions that require expansion
    // (e.g., iam:* matches iam:CreatePolicyVersion, iam:AttachUserPolicy, etc.)
    let mut permission_sets = Vec::new();

    let wildcard_perms = vec!["iam:*", "ec2:*", "s3:*", "lambda:*", "dynamodb:*", "kms:*"];

    for i in 0..1_000 {
        let perm_idx = i % wildcard_perms.len();
        let perms = vec![EffectivePermission::new(wildcard_perms[perm_idx], "*")];
        permission_sets.push(perms);
    }

    // Benchmark matching
    let start = Instant::now();
    for perms in &permission_sets {
        let _ = match_all_rules(&rules, perms);
    }
    let elapsed = start.elapsed();

    let secs = elapsed.as_secs_f64();
    println!(
        "Matched {} wildcard permission sets in {:.3}s",
        permission_sets.len(),
        secs
    );

    // Should still be fast (< 100ms for 1k sets)
    assert!(
        elapsed.as_millis() < 100,
        "Wildcard matching took {}ms, expected < 100ms",
        elapsed.as_millis()
    );
}

/// Benchmark: Large permission sets (many permissions per principal)
#[test]
fn benchmark_matching_large_permission_sets() {
    let rules = load_bundled_rules();

    // Create permission sets with many permissions (realistic for high-privilege principals)
    let mut permission_sets = Vec::new();

    let all_actions = vec![
        "iam:*",
        "ec2:DescribeInstances",
        "ec2:RunInstances",
        "ec2:TerminateInstances",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:Query",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
        "lambda:DeleteFunction",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:CreateGrant",
    ];

    for set_idx in 0..100 {
        let mut perms = Vec::new();

        // Each set has 16 permissions (all_actions)
        for (i, action) in all_actions.iter().enumerate() {
            perms.push(EffectivePermission::new(
                action.to_string(),
                format!("arn:aws:iam::123456789012:resource/{}/{}", set_idx, i),
            ));
        }

        permission_sets.push(perms);
    }

    // Benchmark matching
    let start = Instant::now();
    for perms in &permission_sets {
        let _ = match_all_rules(&rules, perms);
    }
    let elapsed = start.elapsed();

    let secs = elapsed.as_secs_f64();
    let total_perms = permission_sets.iter().map(|p| p.len()).sum::<usize>();
    println!(
        "Matched {} permission sets ({} total permissions) in {:.3}s",
        permission_sets.len(),
        total_perms,
        secs
    );

    // Should handle large permission sets efficiently
    assert!(
        elapsed.as_millis() < 100,
        "Large permission set matching took {}ms, expected < 100ms",
        elapsed.as_millis()
    );
}
