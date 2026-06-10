//! Integration tests for federation trust analysis.

use activable_iam_engine::{
    extract_federation_trusts, find_weak_federation_trusts, FederationProviderType,
    FederationWeakness,
};

#[test]
fn test_real_world_okta_federation() {
    // Real-world example: Okta SAML federation with proper conditions
    let policy = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:saml-provider/Okta"
                },
                "Action": "sts:AssumeRoleWithSAML",
                "Condition": {
                    "StringEquals": {
                        "SAML:aud": "https://signin.aws.amazon.com/saml"
                    }
                }
            }
        ]
    }"#;

    let trusts = extract_federation_trusts(policy, "arn:aws:iam::123456789012:role/OktaRole")
        .expect("Should parse valid policy");

    assert_eq!(trusts.len(), 1);
    assert_eq!(trusts[0].provider_type, FederationProviderType::Saml);
    assert_eq!(
        trusts[0].provider_arn,
        "arn:aws:iam::123456789012:saml-provider/Okta"
    );
    // Missing subject condition
    assert_eq!(trusts[0].weakness, Some(FederationWeakness::MissingSubject));
}

#[test]
fn test_real_world_github_actions_oidc() {
    // Real-world example: GitHub Actions OIDC with proper conditions
    let policy = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:ref:refs/heads/main"
                    }
                }
            }
        ]
    }"#;

    let trusts =
        extract_federation_trusts(policy, "arn:aws:iam::123456789012:role/GitHubActionsRole")
            .expect("Should parse valid policy");

    assert_eq!(trusts.len(), 1);
    assert_eq!(trusts[0].provider_type, FederationProviderType::Oidc);
    // Both aud and sub present — no weakness
    assert_eq!(trusts[0].weakness, None);
}

#[test]
fn test_vulnerable_azure_ad_no_conditions() {
    // Vulnerable example: Azure AD federation with NO conditions
    let policy = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:saml-provider/AzureAD"
                },
                "Action": "sts:AssumeRoleWithSAML"
            }
        ]
    }"#;

    let trusts = extract_federation_trusts(policy, "arn:aws:iam::123456789012:role/AzureRole")
        .expect("Should parse valid policy");

    assert_eq!(trusts.len(), 1);
    assert_eq!(trusts[0].weakness, Some(FederationWeakness::NoConditions));
}

#[test]
fn test_cross_account_federation() {
    // Account A trusting Account B's OIDC provider
    let policy = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::111111111111:oidc-provider/oidc.example.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "oidc.example.com:aud": "cross-account-app"
                    }
                }
            }
        ]
    }"#;

    let trusts =
        extract_federation_trusts(policy, "arn:aws:iam::999999999999:role/CrossAccountRole")
            .expect("Should parse valid policy");

    assert_eq!(trusts.len(), 1);
    assert_eq!(trusts[0].weakness, Some(FederationWeakness::MissingSubject));
}

#[test]
fn test_multiple_federation_providers_in_single_role() {
    // A role that trusts multiple IdPs (federated access from multiple orgs)
    let policy = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": [
                        "arn:aws:iam::123456789012:saml-provider/Okta",
                        "arn:aws:iam::123456789012:saml-provider/Azure"
                    ]
                },
                "Action": "sts:AssumeRoleWithSAML",
                "Condition": {
                    "StringEquals": {
                        "SAML:aud": "https://signin.aws.amazon.com/saml",
                        "SAML:sub": ["contractor@acme.com", "contractor@example.com"]
                    }
                }
            }
        ]
    }"#;

    let trusts = extract_federation_trusts(policy, "arn:aws:iam::123456789012:role/FederatedRole")
        .expect("Should parse valid policy");

    // Should extract 2 trusts (one per SAML provider)
    assert_eq!(trusts.len(), 2);
    // Both should have no weakness (aud + sub conditions present)
    assert!(trusts.iter().all(|t| t.weakness.is_none()));
}

#[test]
fn test_find_weak_federation_across_multiple_roles() {
    let roles = vec![
        (
            "arn:aws:iam::123456789012:role/SecureRole",
            r#"{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::123456789012:saml-provider/Okta"},
                    "Action": "sts:AssumeRoleWithSAML",
                    "Condition": {
                        "StringEquals": {
                            "SAML:aud": "https://signin.aws.amazon.com/saml",
                            "SAML:sub": "admin@example.com"
                        }
                    }
                }]
            }"#,
        ),
        (
            "arn:aws:iam::123456789012:role/VulnerableRole",
            r#"{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::123456789012:saml-provider/AzureAD"},
                    "Action": "sts:AssumeRoleWithSAML"
                }]
            }"#,
        ),
        (
            "arn:aws:iam::123456789012:role/PartiallySecureRole",
            r#"{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.example.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "oidc.example.com:aud": "my-app"
                        }
                    }
                }]
            }"#,
        ),
    ];

    let weak_trusts = find_weak_federation_trusts(&roles).expect("Should analyze all roles");

    // Should find 2 weak trusts:
    // 1. VulnerableRole with no conditions
    // 2. PartiallySecureRole with missing subject
    assert_eq!(weak_trusts.len(), 2);

    // Verify the weak trusts are identified correctly
    let vulnerable_found = weak_trusts.iter().any(|t| {
        t.role_arn.contains("VulnerableRole")
            && t.weakness == Some(FederationWeakness::NoConditions)
    });
    assert!(
        vulnerable_found,
        "Should find VulnerableRole with no conditions"
    );

    let partially_weak_found = weak_trusts.iter().any(|t| {
        t.role_arn.contains("PartiallySecureRole")
            && t.weakness == Some(FederationWeakness::MissingSubject)
    });
    assert!(
        partially_weak_found,
        "Should find PartiallySecureRole with missing subject"
    );
}

#[test]
fn test_federation_condition_extraction() {
    let policy = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:saml-provider/Okta"
                },
                "Action": "sts:AssumeRoleWithSAML",
                "Condition": {
                    "StringEquals": {
                        "SAML:aud": "https://signin.aws.amazon.com/saml",
                        "SAML:sub": "user@example.com",
                        "SAML:namequalifier": "urn:amazon:webservices"
                    },
                    "StringLike": {
                        "SAML:sub": "contractor@*.com"
                    }
                }
            }
        ]
    }"#;

    let trusts = extract_federation_trusts(policy, "arn:aws:iam::123456789012:role/TestRole")
        .expect("Should parse policy");

    assert_eq!(trusts.len(), 1);
    // Should extract 4 conditions (2 StringEquals, 1 StringLike)
    assert!(trusts[0].conditions.len() >= 3);

    // Verify all relevant condition keys are present
    let condition_keys: Vec<&str> = trusts[0]
        .conditions
        .iter()
        .map(|c| c.condition_key.as_str())
        .collect();

    assert!(condition_keys.contains(&"SAML:aud"));
    assert!(condition_keys.contains(&"SAML:sub"));
    assert!(condition_keys.contains(&"SAML:namequalifier"));
}

#[test]
fn test_mixed_federation_types_in_single_policy() {
    // A role with both SAML and OIDC trust relationships
    let policy = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:saml-provider/Okta"
                },
                "Action": "sts:AssumeRoleWithSAML",
                "Condition": {
                    "StringEquals": {
                        "SAML:aud": "https://signin.aws.amazon.com/saml"
                    }
                }
            },
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.example.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "oidc.example.com:aud": "my-app",
                        "oidc.example.com:sub": "service-account"
                    }
                }
            }
        ]
    }"#;

    let trusts = extract_federation_trusts(policy, "arn:aws:iam::123456789012:role/MixedRole")
        .expect("Should parse policy with mixed federation types");

    assert_eq!(trusts.len(), 2);

    let saml_trusts: Vec<_> = trusts
        .iter()
        .filter(|t| t.provider_type == FederationProviderType::Saml)
        .collect();
    let oidc_trusts: Vec<_> = trusts
        .iter()
        .filter(|t| t.provider_type == FederationProviderType::Oidc)
        .collect();

    assert_eq!(saml_trusts.len(), 1);
    assert_eq!(oidc_trusts.len(), 1);

    // SAML missing subject
    assert_eq!(
        saml_trusts[0].weakness,
        Some(FederationWeakness::MissingSubject)
    );
    // OIDC properly constrained
    assert_eq!(oidc_trusts[0].weakness, None);
}

#[test]
fn test_non_federation_principals_ignored() {
    // Ensure we don't extract non-federation principals
    let policy = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            },
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789012:role/AnotherRole"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }"#;

    let trusts = extract_federation_trusts(policy, "arn:aws:iam::123456789012:role/TestRole")
        .expect("Should parse policy");

    // Should extract zero federation trusts
    assert_eq!(trusts.len(), 0);
}

#[test]
fn test_deny_statements_excluded() {
    // Deny statements should not be included in federation trusts
    let policy = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:saml-provider/Malicious"
                },
                "Action": "sts:AssumeRoleWithSAML"
            }
        ]
    }"#;

    let trusts = extract_federation_trusts(policy, "arn:aws:iam::123456789012:role/TestRole")
        .expect("Should parse policy");

    assert_eq!(trusts.len(), 0);
}

#[test]
fn test_invalid_json_error_handling() {
    let result = extract_federation_trusts("not valid json", "arn:aws:iam::123456789012:role/Test");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("JSON parse error"));
}

#[test]
fn test_missing_statement_error_handling() {
    let result = extract_federation_trusts(
        r#"{"Version": "2012-10-17"}"#,
        "arn:aws:iam::123456789012:role/Test",
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Statement"));
}
