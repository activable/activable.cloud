use std::collections::{HashMap, HashSet};

/// A snapshot of the AWS IAM action catalog at a point in time
#[derive(Debug, Clone)]
pub struct ActionCatalogSnapshot {
    pub timestamp: String,                      // ISO 8601
    pub services: HashMap<String, Vec<String>>, // service → actions (e.g., "s3" → ["GetObject", "PutObject", ...])
    pub total_action_count: usize,
}

/// Result of comparing two catalog snapshots
#[derive(Debug, Clone)]
pub struct CatalogDiff {
    pub from_timestamp: String,
    pub to_timestamp: String,
    pub new_services: Vec<String>,     // entirely new services
    pub removed_services: Vec<String>, // services no longer present
    pub new_actions: HashMap<String, Vec<String>>, // service → new actions
    pub removed_actions: HashMap<String, Vec<String>>,
    pub total_new_actions: usize,
    pub total_removed_actions: usize,
}

/// Impact of catalog changes on existing policies
#[derive(Debug, Clone)]
pub struct ExpansionImpact {
    pub affected_principal: String,       // principal with wildcard policy
    pub wildcard_pattern: String,         // e.g., "s3:*" or "*"
    pub new_actions_covered: Vec<String>, // new actions now covered by wildcard
    pub severity: ExpansionSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpansionSeverity {
    Critical, // new dangerous action covered by wildcard
    High,     // new write action covered
    Medium,   // new read action covered
    Low,      // minimal impact
}

/// Create a catalog snapshot from a map of service → actions.
pub fn create_snapshot(
    services: HashMap<String, Vec<String>>,
    timestamp: &str,
) -> ActionCatalogSnapshot {
    let total = services.values().map(|v| v.len()).sum();
    ActionCatalogSnapshot {
        timestamp: timestamp.to_string(),
        services,
        total_action_count: total,
    }
}

/// Diff two catalog snapshots to find new/removed services and actions.
pub fn diff_catalogs(from: &ActionCatalogSnapshot, to: &ActionCatalogSnapshot) -> CatalogDiff {
    let from_services: HashSet<_> = from.services.keys().cloned().collect();
    let to_services: HashSet<_> = to.services.keys().cloned().collect();

    // Find new and removed services
    let new_services: Vec<String> = to_services.difference(&from_services).cloned().collect();
    let removed_services: Vec<String> = from_services.difference(&to_services).cloned().collect();

    // Find new and removed actions per service
    let mut new_actions: HashMap<String, Vec<String>> = HashMap::new();
    let mut removed_actions: HashMap<String, Vec<String>> = HashMap::new();

    for service in from_services.intersection(&to_services) {
        let from_actions: HashSet<_> = from
            .services
            .get(service)
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default();
        let to_actions: HashSet<_> = to
            .services
            .get(service)
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default();

        let new: Vec<String> = to_actions.difference(&from_actions).cloned().collect();
        let removed: Vec<String> = from_actions.difference(&to_actions).cloned().collect();

        if !new.is_empty() {
            new_actions.insert(service.clone(), new);
        }
        if !removed.is_empty() {
            removed_actions.insert(service.clone(), removed);
        }
    }

    // Count total new and removed actions
    let total_new_actions: usize = new_actions.values().map(|v| v.len()).sum::<usize>()
        + new_services
            .iter()
            .filter_map(|s| to.services.get(s).map(|v| v.len()))
            .sum::<usize>();

    let total_removed_actions: usize = removed_actions.values().map(|v| v.len()).sum::<usize>()
        + removed_services
            .iter()
            .filter_map(|s| from.services.get(s).map(|v| v.len()))
            .sum::<usize>();

    CatalogDiff {
        from_timestamp: from.timestamp.clone(),
        to_timestamp: to.timestamp.clone(),
        new_services,
        removed_services,
        new_actions,
        removed_actions,
        total_new_actions,
        total_removed_actions,
    }
}

/// Determine severity of an action based on its name
fn classify_action_severity(action: &str) -> ExpansionSeverity {
    let action_lower = action.to_lowercase();

    // Critical actions: IAM, assume role, policy mutation, key generation
    if action_lower.contains("iam")
        || action_lower.contains("role")
        || action_lower.contains("policy")
        || action_lower.contains("key")
        || action_lower.contains("credential")
        || action_lower.contains("password")
    {
        return ExpansionSeverity::Critical;
    }

    // High: write/put/delete operations
    if action_lower.starts_with("put")
        || action_lower.starts_with("delete")
        || action_lower.starts_with("create")
        || action_lower.starts_with("update")
        || action_lower.starts_with("modify")
    {
        return ExpansionSeverity::High;
    }

    // Medium: read operations
    if action_lower.starts_with("get")
        || action_lower.starts_with("list")
        || action_lower.starts_with("describe")
        || action_lower.starts_with("fetch")
    {
        return ExpansionSeverity::Medium;
    }

    ExpansionSeverity::Low
}

/// Extract service from wildcard pattern (e.g., "s3:*" → "s3", "*" → None)
fn extract_service_from_wildcard(pattern: &str) -> Option<String> {
    if pattern == "*" {
        return None; // full wildcard covers all services
    }
    pattern.split(':').next().map(|s| s.to_lowercase())
}

/// Given a catalog diff and a list of wildcard policies,
/// determine which principals are impacted by new actions.
pub fn assess_expansion_impact(
    diff: &CatalogDiff,
    wildcard_policies: &[(&str, &str)], // (principal_id, wildcard_pattern like "s3:*")
) -> Vec<ExpansionImpact> {
    let mut impacts = Vec::new();

    for (principal_id, wildcard_pattern) in wildcard_policies {
        let affected_service = extract_service_from_wildcard(wildcard_pattern);

        let mut covered_new_actions = Vec::new();

        // Full wildcard (*) covers all new actions
        if *wildcard_pattern == "*" {
            for actions_vec in diff.new_actions.values() {
                covered_new_actions.extend(actions_vec.clone());
            }
        } else if let Some(service) = affected_service {
            // Service-specific wildcard (e.g., "s3:*")
            if let Some(new_actions_for_service) = diff.new_actions.get(&service) {
                covered_new_actions.extend(new_actions_for_service.clone());
            }
        }

        // Only create impact if there are new actions covered
        if !covered_new_actions.is_empty() {
            // Determine overall severity (most severe action in the list)
            let severity = covered_new_actions
                .iter()
                .map(|a| classify_action_severity(a))
                .max_by_key(|s| match s {
                    ExpansionSeverity::Critical => 3,
                    ExpansionSeverity::High => 2,
                    ExpansionSeverity::Medium => 1,
                    ExpansionSeverity::Low => 0,
                })
                .unwrap_or(ExpansionSeverity::Low);

            impacts.push(ExpansionImpact {
                affected_principal: principal_id.to_string(),
                wildcard_pattern: wildcard_pattern.to_string(),
                new_actions_covered: covered_new_actions,
                severity,
            });
        }
    }

    impacts
}

/// Compute an expansion score (0.0-1.0) based on catalog changes + policy impact.
pub fn compute_expansion_score(impacts: &[ExpansionImpact]) -> f64 {
    if impacts.is_empty() {
        return 0.0;
    }

    let total_score: f64 = impacts
        .iter()
        .map(|impact| {
            let severity_score = match impact.severity {
                ExpansionSeverity::Critical => 0.4,
                ExpansionSeverity::High => 0.2,
                ExpansionSeverity::Medium => 0.1,
                ExpansionSeverity::Low => 0.05,
            };
            // Increase score based on number of new actions (but cap contribution)
            let action_bonus = (impact.new_actions_covered.len() as f64).log10() * 0.1;
            severity_score + action_bonus
        })
        .sum();

    // Normalize and cap at 1.0
    (total_score / impacts.len() as f64).min(1.0)
}

/// A built-in partial catalog for offline use (common AWS services).
/// In production, this would be fetched from AWS IAM reference data.
pub fn builtin_catalog() -> ActionCatalogSnapshot {
    let mut services = HashMap::new();

    services.insert(
        "iam".to_string(),
        vec![
            "CreateUser",
            "DeleteUser",
            "CreateRole",
            "DeleteRole",
            "CreatePolicy",
            "DeletePolicy",
            "CreatePolicyVersion",
            "AttachUserPolicy",
            "DetachUserPolicy",
            "AttachRolePolicy",
            "PutUserPolicy",
            "PutRolePolicy",
            "CreateAccessKey",
            "PassRole",
            "TagUser",
            "TagRole",
            "UpdateAssumeRolePolicy",
            "AddUserToGroup",
            "CreateGroup",
            "CreateInstanceProfile",
            "ListUsers",
            "GetUser",
            "UpdateUser",
            "ListRoles",
            "GetRole",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    services.insert(
        "s3".to_string(),
        vec![
            "GetObject",
            "PutObject",
            "DeleteObject",
            "ListBucket",
            "CreateBucket",
            "DeleteBucket",
            "PutBucketPolicy",
            "GetBucketPolicy",
            "PutObjectTagging",
            "GetObjectTagging",
            "WriteAccessPoint",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    services.insert(
        "sts".to_string(),
        vec![
            "AssumeRole",
            "AssumeRoleWithSAML",
            "AssumeRoleWithWebIdentity",
            "GetSessionToken",
            "GetCallerIdentity",
            "GetFederationToken",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    services.insert(
        "ec2".to_string(),
        vec![
            "RunInstances",
            "TerminateInstances",
            "DescribeInstances",
            "CreateTags",
            "DeleteTags",
            "CreateSecurityGroup",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    services.insert(
        "lambda".to_string(),
        vec![
            "CreateFunction",
            "InvokeFunction",
            "UpdateFunctionCode",
            "AddPermission",
            "TagResource",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );

    create_snapshot(services, "2026-01-01T00:00:00Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: create_snapshot counts actions correctly
    #[test]
    fn test_create_snapshot_counts_actions() {
        let mut services = HashMap::new();
        services.insert(
            "s3".to_string(),
            vec!["GetObject".to_string(), "PutObject".to_string()],
        );
        services.insert("iam".to_string(), vec!["CreateUser".to_string()]);

        let snapshot = create_snapshot(services, "2026-05-23T00:00:00Z");

        assert_eq!(snapshot.total_action_count, 3);
        assert_eq!(snapshot.timestamp, "2026-05-23T00:00:00Z");
    }

    // Test 2: diff_catalogs with identical catalogs → no changes
    #[test]
    fn test_diff_catalogs_identical() {
        let mut services = HashMap::new();
        services.insert(
            "s3".to_string(),
            vec!["GetObject".to_string(), "PutObject".to_string()],
        );

        let snap1 = create_snapshot(services.clone(), "2026-01-01T00:00:00Z");
        let snap2 = create_snapshot(services, "2026-05-23T00:00:00Z");

        let diff = diff_catalogs(&snap1, &snap2);

        assert!(diff.new_services.is_empty());
        assert!(diff.removed_services.is_empty());
        assert!(diff.new_actions.is_empty());
        assert!(diff.removed_actions.is_empty());
        assert_eq!(diff.total_new_actions, 0);
        assert_eq!(diff.total_removed_actions, 0);
    }

    // Test 3: diff_catalogs with new service added
    #[test]
    fn test_diff_catalogs_new_service() {
        let mut services1 = HashMap::new();
        services1.insert("s3".to_string(), vec!["GetObject".to_string()]);

        let mut services2 = HashMap::new();
        services2.insert("s3".to_string(), vec!["GetObject".to_string()]);
        services2.insert(
            "dynamodb".to_string(),
            vec!["GetItem".to_string(), "PutItem".to_string()],
        );

        let snap1 = create_snapshot(services1, "2026-01-01T00:00:00Z");
        let snap2 = create_snapshot(services2, "2026-05-23T00:00:00Z");

        let diff = diff_catalogs(&snap1, &snap2);

        assert_eq!(diff.new_services.len(), 1);
        assert!(diff.new_services.contains(&"dynamodb".to_string()));
        assert_eq!(diff.total_new_actions, 2);
    }

    // Test 4: diff_catalogs with new action in existing service
    #[test]
    fn test_diff_catalogs_new_action() {
        let mut services1 = HashMap::new();
        services1.insert("s3".to_string(), vec!["GetObject".to_string()]);

        let mut services2 = HashMap::new();
        services2.insert(
            "s3".to_string(),
            vec!["GetObject".to_string(), "PutObject".to_string()],
        );

        let snap1 = create_snapshot(services1, "2026-01-01T00:00:00Z");
        let snap2 = create_snapshot(services2, "2026-05-23T00:00:00Z");

        let diff = diff_catalogs(&snap1, &snap2);

        assert!(diff.new_services.is_empty());
        assert_eq!(diff.total_new_actions, 1);
        assert!(diff
            .new_actions
            .get("s3")
            .map(|v| v.contains(&"PutObject".to_string()))
            .unwrap_or(false));
    }

    // Test 5: diff_catalogs with action removed
    #[test]
    fn test_diff_catalogs_action_removed() {
        let mut services1 = HashMap::new();
        services1.insert(
            "s3".to_string(),
            vec!["GetObject".to_string(), "PutObject".to_string()],
        );

        let mut services2 = HashMap::new();
        services2.insert("s3".to_string(), vec!["GetObject".to_string()]);

        let snap1 = create_snapshot(services1, "2026-01-01T00:00:00Z");
        let snap2 = create_snapshot(services2, "2026-05-23T00:00:00Z");

        let diff = diff_catalogs(&snap1, &snap2);

        assert_eq!(diff.total_removed_actions, 1);
        assert!(diff
            .removed_actions
            .get("s3")
            .map(|v| v.contains(&"PutObject".to_string()))
            .unwrap_or(false));
    }

    // Test 6: assess_expansion_impact with s3:* wildcard and new s3 action
    #[test]
    fn test_assess_expansion_impact_s3_wildcard() {
        let mut from_services = HashMap::new();
        from_services.insert("s3".to_string(), vec!["GetObject".to_string()]);

        let mut to_services = HashMap::new();
        to_services.insert(
            "s3".to_string(),
            vec!["GetObject".to_string(), "WriteAccessPoint".to_string()],
        );

        let snap1 = create_snapshot(from_services, "2026-01-01T00:00:00Z");
        let snap2 = create_snapshot(to_services, "2026-05-23T00:00:00Z");

        let diff = diff_catalogs(&snap1, &snap2);

        let policies = vec![("principal-123", "s3:*")];
        let impacts = assess_expansion_impact(&diff, &policies);

        assert_eq!(impacts.len(), 1);
        assert_eq!(impacts[0].affected_principal, "principal-123");
        assert_eq!(impacts[0].wildcard_pattern, "s3:*");
        assert!(impacts[0]
            .new_actions_covered
            .contains(&"WriteAccessPoint".to_string()));
    }

    // Test 7: assess_expansion_impact with iam:* wildcard and new iam action → Critical severity
    #[test]
    fn test_assess_expansion_impact_iam_critical() {
        let mut from_services = HashMap::new();
        from_services.insert("iam".to_string(), vec!["ListUsers".to_string()]);

        let mut to_services = HashMap::new();
        to_services.insert(
            "iam".to_string(),
            vec!["ListUsers".to_string(), "CreateAccessKey".to_string()],
        );

        let snap1 = create_snapshot(from_services, "2026-01-01T00:00:00Z");
        let snap2 = create_snapshot(to_services, "2026-05-23T00:00:00Z");

        let diff = diff_catalogs(&snap1, &snap2);

        let policies = vec![("principal-123", "iam:*")];
        let impacts = assess_expansion_impact(&diff, &policies);

        assert_eq!(impacts.len(), 1);
        assert_eq!(impacts[0].severity, ExpansionSeverity::Critical);
    }

    // Test 8: assess_expansion_impact with no wildcard policies
    #[test]
    fn test_assess_expansion_impact_no_wildcards() {
        let mut from_services = HashMap::new();
        from_services.insert("s3".to_string(), vec!["GetObject".to_string()]);

        let mut to_services = HashMap::new();
        to_services.insert(
            "s3".to_string(),
            vec!["GetObject".to_string(), "PutObject".to_string()],
        );

        let snap1 = create_snapshot(from_services, "2026-01-01T00:00:00Z");
        let snap2 = create_snapshot(to_services, "2026-05-23T00:00:00Z");

        let diff = diff_catalogs(&snap1, &snap2);

        let policies: Vec<(&str, &str)> = vec![];
        let impacts = assess_expansion_impact(&diff, &policies);

        assert_eq!(impacts.len(), 0);
    }

    // Test 9: compute_expansion_score with no impacts → 0.0
    #[test]
    fn test_compute_expansion_score_empty() {
        let impacts = vec![];
        let score = compute_expansion_score(&impacts);
        assert_eq!(score, 0.0);
    }

    // Test 10: compute_expansion_score with multiple impacts
    #[test]
    fn test_compute_expansion_score_multiple_impacts() {
        let impacts = vec![
            ExpansionImpact {
                affected_principal: "principal-1".to_string(),
                wildcard_pattern: "s3:*".to_string(),
                new_actions_covered: vec!["PutObject".to_string()],
                severity: ExpansionSeverity::High,
            },
            ExpansionImpact {
                affected_principal: "principal-2".to_string(),
                wildcard_pattern: "iam:*".to_string(),
                new_actions_covered: vec!["CreateAccessKey".to_string()],
                severity: ExpansionSeverity::Critical,
            },
        ];

        let score = compute_expansion_score(&impacts);

        // Should be > 0 and <= 1.0
        assert!(score > 0.0);
        assert!(score <= 1.0);
    }

    // Test 11: builtin_catalog has expected services and action counts
    #[test]
    fn test_builtin_catalog_structure() {
        let catalog = builtin_catalog();

        assert!(catalog.total_action_count >= 50); // expect at least 50 actions total
        assert!(catalog.services.contains_key("s3"));
        assert!(catalog.services.contains_key("iam"));
        assert!(catalog.services.contains_key("sts"));
        assert!(catalog.services.contains_key("ec2"));
        assert!(catalog.services.contains_key("lambda"));

        // Verify counts for known services
        let s3_actions = &catalog.services["s3"];
        assert!(s3_actions.len() >= 5);
        assert!(s3_actions.contains(&"GetObject".to_string()));

        let iam_actions = &catalog.services["iam"];
        assert!(iam_actions.len() >= 10);
        assert!(iam_actions.contains(&"CreateUser".to_string()));
    }

    // Test 12: Full wildcard (*) covers all new actions
    #[test]
    fn test_assess_expansion_impact_full_wildcard() {
        let mut from_services = HashMap::new();
        from_services.insert("s3".to_string(), vec!["GetObject".to_string()]);
        from_services.insert("iam".to_string(), vec!["ListUsers".to_string()]);

        let mut to_services = HashMap::new();
        to_services.insert(
            "s3".to_string(),
            vec!["GetObject".to_string(), "PutObject".to_string()],
        );
        to_services.insert(
            "iam".to_string(),
            vec!["ListUsers".to_string(), "CreateUser".to_string()],
        );

        let snap1 = create_snapshot(from_services, "2026-01-01T00:00:00Z");
        let snap2 = create_snapshot(to_services, "2026-05-23T00:00:00Z");

        let diff = diff_catalogs(&snap1, &snap2);

        let policies = vec![("principal-admin", "*")];
        let impacts = assess_expansion_impact(&diff, &policies);

        assert_eq!(impacts.len(), 1);
        assert_eq!(impacts[0].new_actions_covered.len(), 2); // both new actions covered
        assert!(impacts[0]
            .new_actions_covered
            .contains(&"PutObject".to_string()));
        assert!(impacts[0]
            .new_actions_covered
            .contains(&"CreateUser".to_string()));
    }
}
