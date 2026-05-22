//! Property structs for each node type in the cloud attack graph.
//!
//! Each node in the graph carries type-specific properties. All nodes share
//! `CommonProperties` (id, ingest metadata). Type-specific properties are
//! organized in per-type structs, wrapped by the `NodeProperties` enum
//! for generic handling.

use crate::arn::Arn;
use crate::labels::NodeLabel;
use serde_json::Value;

/// Properties shared across all node types.
#[derive(Debug, Clone, PartialEq)]
pub struct CommonProperties {
    /// Canonical AWS ARN identifying this node.
    pub id: Arn,
    /// UUID of the ingestion run that discovered this node (as string).
    pub ingest_run_id: String,
    /// ISO 8601 timestamp when this node was ingested (as string).
    pub ingested_at: String,
}

/// Properties for Principal nodes (IAM users, roles, service principals).
#[derive(Debug, Clone, PartialEq)]
pub struct PrincipalProperties {
    pub common: CommonProperties,
    /// Display name of the principal.
    pub name: String,
    /// Type: "User", "Role", "Group", "ServicePrincipal", or "Federated".
    pub principal_type: String,
    /// AWS account ID.
    pub account: String,
    /// Optional IAM path (e.g., "/engineering/admin/").
    pub path: Option<String>,
}

/// Properties for Resource nodes (S3 buckets, EC2 instances, Lambda functions, etc.).
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceProperties {
    pub common: CommonProperties,
    /// Display name of the resource.
    pub name: String,
    /// Resource type (e.g., "s3:bucket", "ec2:instance", "lambda:function").
    pub resource_type: String,
    /// AWS account ID.
    pub account: String,
    /// AWS region.
    pub region: String,
}

/// Properties for Permission nodes (policy statements or permission grants).
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionProperties {
    pub common: CommonProperties,
    /// Optional statement ID (from policy documents).
    pub sid: Option<String>,
    /// "Allow" or "Deny".
    pub effect: String,
    /// List of IAM actions (e.g., ["s3:GetObject", "s3:PutObject"]).
    pub actions: Vec<String>,
    /// List of resource ARNs this permission applies to.
    pub resources: Vec<String>,
}

/// Properties for Account nodes (AWS accounts).
#[derive(Debug, Clone, PartialEq)]
pub struct AccountProperties {
    pub common: CommonProperties,
    /// Display name of the account.
    pub name: String,
    /// Optional AWS Organization ID.
    pub organization_id: Option<String>,
}

/// Properties for VPC nodes (Virtual Private Clouds).
#[derive(Debug, Clone, PartialEq)]
pub struct VpcProperties {
    pub common: CommonProperties,
    /// CIDR block of the VPC.
    pub cidr_block: String,
    /// AWS region.
    pub region: String,
    /// Whether this is the default VPC for the account.
    pub is_default: bool,
}

/// Properties for IamGroup nodes.
#[derive(Debug, Clone, PartialEq)]
pub struct IamGroupProperties {
    pub common: CommonProperties,
    /// Display name of the group.
    pub name: String,
    /// AWS account ID.
    pub account: String,
    /// Optional IAM path.
    pub path: Option<String>,
}

/// Properties for KmsKey nodes.
#[derive(Debug, Clone, PartialEq)]
pub struct KmsKeyProperties {
    pub common: CommonProperties,
    /// Display name of the key.
    pub name: String,
    /// AWS account ID.
    pub account: String,
    /// AWS region.
    pub region: String,
}

/// Properties for AccessKey nodes (AWS access credentials).
#[derive(Debug, Clone, PartialEq)]
pub struct AccessKeyProperties {
    pub common: CommonProperties,
    /// The public part of the access key.
    pub access_key_id: String,
    /// AWS account ID.
    pub account: String,
    /// Status: "Active" or "Inactive".
    pub status: String,
}

/// Properties for FederatedProvider nodes (SAML/OIDC providers).
#[derive(Debug, Clone, PartialEq)]
pub struct FederatedProviderProperties {
    pub common: CommonProperties,
    /// Display name of the provider.
    pub name: String,
    /// AWS account ID.
    pub account: String,
    /// Provider type: "SAML" or "OIDC".
    pub provider_type: String,
}

/// Wrapper enum for all node property types.
///
/// Enables generic handling of properties from any node type. The `Custom(Value)`
/// variant captures properties for node types not yet defined in the schema.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum NodeProperties {
    Principal(PrincipalProperties),
    Resource(ResourceProperties),
    Permission(PermissionProperties),
    Account(AccountProperties),
    Vpc(VpcProperties),
    IamGroup(IamGroupProperties),
    KmsKey(KmsKeyProperties),
    AccessKey(AccessKeyProperties),
    FederatedProvider(FederatedProviderProperties),
    /// Fallback for unknown node types.
    Custom(Value),
}

impl NodeProperties {
    /// Returns the label (type) of this node.
    #[must_use]
    pub fn label(&self) -> NodeLabel {
        match self {
            Self::Principal(_) => NodeLabel::Principal,
            Self::Resource(_) => NodeLabel::Resource,
            Self::Permission(_) => NodeLabel::Permission,
            Self::Account(_) => NodeLabel::Account,
            Self::Vpc(_) => NodeLabel::Vpc,
            Self::IamGroup(_) => NodeLabel::IamGroup,
            Self::KmsKey(_) => NodeLabel::KmsKey,
            Self::AccessKey(_) => NodeLabel::AccessKey,
            Self::FederatedProvider(_) => NodeLabel::FederatedProvider,
            Self::Custom(_) => NodeLabel::Custom("Unknown".to_string()),
        }
    }

    /// Returns a reference to the node's ARN (identifier), if available.
    ///
    /// Returns `None` for the `Custom` variant (which may not have a
    /// structured ARN). Callers must handle the `None` case.
    #[must_use]
    pub fn id(&self) -> Option<&Arn> {
        match self {
            Self::Principal(p) => Some(&p.common.id),
            Self::Resource(r) => Some(&r.common.id),
            Self::Permission(p) => Some(&p.common.id),
            Self::Account(a) => Some(&a.common.id),
            Self::Vpc(v) => Some(&v.common.id),
            Self::IamGroup(g) => Some(&g.common.id),
            Self::KmsKey(k) => Some(&k.common.id),
            Self::AccessKey(a) => Some(&a.common.id),
            Self::FederatedProvider(f) => Some(&f.common.id),
            Self::Custom(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_arn() -> Arn {
        Arn::parse("arn:aws:iam::123456789012:user/test").expect("Valid ARN")
    }

    #[test]
    fn test_principal_properties() {
        let common = CommonProperties {
            id: create_test_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };
        let props = PrincipalProperties {
            common: common.clone(),
            name: "alice".to_string(),
            principal_type: "User".to_string(),
            account: "123456789012".to_string(),
            path: Some("/engineering/".to_string()),
        };
        assert_eq!(props.common.id, common.id);
        assert_eq!(props.name, "alice");
    }

    #[test]
    fn test_resource_properties() {
        let common = CommonProperties {
            id: create_test_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };
        let props = ResourceProperties {
            common: common.clone(),
            name: "my-bucket".to_string(),
            resource_type: "s3:bucket".to_string(),
            account: "123456789012".to_string(),
            region: "us-east-1".to_string(),
        };
        assert_eq!(props.resource_type, "s3:bucket");
        assert_eq!(props.region, "us-east-1");
    }

    #[test]
    fn test_permission_properties() {
        let common = CommonProperties {
            id: create_test_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };
        let props = PermissionProperties {
            common: common.clone(),
            sid: Some("AllowS3Read".to_string()),
            effect: "Allow".to_string(),
            actions: vec!["s3:GetObject".to_string(), "s3:ListBucket".to_string()],
            resources: vec!["arn:aws:s3:::my-bucket".to_string()],
        };
        assert_eq!(props.effect, "Allow");
        assert_eq!(props.actions.len(), 2);
    }

    #[test]
    fn test_account_properties() {
        let common = CommonProperties {
            id: create_test_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };
        let props = AccountProperties {
            common: common.clone(),
            name: "prod-account".to_string(),
            organization_id: Some("o-abc123def456".to_string()),
        };
        assert_eq!(props.name, "prod-account");
        assert!(props.organization_id.is_some());
    }

    #[test]
    fn test_vpc_properties() {
        let common = CommonProperties {
            id: create_test_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };
        let props = VpcProperties {
            common: common.clone(),
            cidr_block: "10.0.0.0/16".to_string(),
            region: "us-west-2".to_string(),
            is_default: false,
        };
        assert_eq!(props.cidr_block, "10.0.0.0/16");
        assert!(!props.is_default);
    }

    #[test]
    fn test_iam_group_properties() {
        let common = CommonProperties {
            id: create_test_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };
        let props = IamGroupProperties {
            common: common.clone(),
            name: "developers".to_string(),
            account: "123456789012".to_string(),
            path: Some("/engineering/".to_string()),
        };
        assert_eq!(props.name, "developers");
    }

    #[test]
    fn test_kms_key_properties() {
        let common = CommonProperties {
            id: create_test_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };
        let props = KmsKeyProperties {
            common: common.clone(),
            name: "prod-encryption-key".to_string(),
            account: "123456789012".to_string(),
            region: "us-east-1".to_string(),
        };
        assert_eq!(props.name, "prod-encryption-key");
    }

    #[test]
    fn test_access_key_properties() {
        let common = CommonProperties {
            id: create_test_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };
        let props = AccessKeyProperties {
            common: common.clone(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            account: "123456789012".to_string(),
            status: "Active".to_string(),
        };
        assert_eq!(props.status, "Active");
    }

    #[test]
    fn test_federated_provider_properties() {
        let common = CommonProperties {
            id: create_test_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };
        let props = FederatedProviderProperties {
            common: common.clone(),
            name: "okta-production".to_string(),
            account: "123456789012".to_string(),
            provider_type: "OIDC".to_string(),
        };
        assert_eq!(props.provider_type, "OIDC");
    }

    #[test]
    fn test_node_properties_label_principal() {
        let arn = create_test_arn();
        let common = CommonProperties {
            id: arn,
            ingest_run_id: "test-uuid".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };
        let principal = PrincipalProperties {
            common,
            name: "alice".to_string(),
            principal_type: "User".to_string(),
            account: "123456789012".to_string(),
            path: None,
        };
        let props = NodeProperties::Principal(principal);
        assert_eq!(props.label(), NodeLabel::Principal);
    }

    #[test]
    fn test_node_properties_label_resource() {
        let arn = create_test_arn();
        let common = CommonProperties {
            id: arn,
            ingest_run_id: "test-uuid".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };
        let resource = ResourceProperties {
            common,
            name: "bucket".to_string(),
            resource_type: "s3:bucket".to_string(),
            account: "123456789012".to_string(),
            region: "us-east-1".to_string(),
        };
        let props = NodeProperties::Resource(resource);
        assert_eq!(props.label(), NodeLabel::Resource);
    }

    #[test]
    fn test_node_properties_id() {
        let arn = create_test_arn();
        let common = CommonProperties {
            id: arn.clone(),
            ingest_run_id: "test-uuid".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };
        let principal = PrincipalProperties {
            common,
            name: "alice".to_string(),
            principal_type: "User".to_string(),
            account: "123456789012".to_string(),
            path: None,
        };
        let props = NodeProperties::Principal(principal);
        assert_eq!(props.id(), Some(&arn));

        // Custom variant returns None (P0 fix: no panic on external data)
        let custom = NodeProperties::Custom(serde_json::json!({"arbitrary": "data"}));
        assert_eq!(custom.id(), None);
    }
}
