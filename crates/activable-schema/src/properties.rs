//! Property schemas for graph nodes.
//!
//! Defines typed property structs for each node type, shared CommonProperties,
//! and a wrapper enum for generic node property handling.

use crate::arn::Arn;

/// Properties shared across all node types.
#[derive(Debug, Clone, PartialEq)]
pub struct CommonProperties {
    /// The node's unique ARN identifier.
    pub id: Arn,
    /// UUID of the ingestion run that created this node.
    pub ingest_run_id: String,
    /// ISO 8601 timestamp when this node was ingested.
    pub ingested_at: String,
}

/// Properties for a Principal (IAM user, role, group, service principal, federated).
#[derive(Debug, Clone, PartialEq)]
pub struct PrincipalProperties {
    pub common: CommonProperties,
    /// The principal's name (e.g., "Admin", "Lambda-Execution-Role").
    pub name: String,
    /// The principal's type (e.g., "User", "Role", "Group", "ServicePrincipal", "Federated").
    pub principal_type: String,
    /// AWS account ID where this principal exists.
    pub account: String,
    /// IAM path (e.g., "/engineering/", "/service-roles/").
    pub path: Option<String>,
}

/// Properties for a Resource (S3 bucket, EC2 instance, etc.).
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceProperties {
    pub common: CommonProperties,
    /// The resource's name or identifier.
    pub name: String,
    /// The resource's type (e.g., "s3:bucket", "ec2:instance", "rds:db").
    pub resource_type: String,
    /// AWS account ID where this resource exists.
    pub account: String,
    /// AWS region where this resource is located.
    pub region: String,
}

/// Properties for a Permission (inline or managed policy).
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionProperties {
    pub common: CommonProperties,
    /// Optional statement ID from the policy.
    pub sid: Option<String>,
    /// "Allow" or "Deny".
    pub effect: String,
    /// List of IAM actions (e.g., "s3:GetObject", "iam:AssumeRole").
    pub actions: Vec<String>,
    /// List of resource ARNs or patterns.
    pub resources: Vec<String>,
    /// Additional conditions on the policy (stored as JSON string).
    pub conditions: Option<String>,
}

/// Properties for an AWS Account.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountProperties {
    pub common: CommonProperties,
    /// The account's friendly name.
    pub name: String,
    /// Organization ID if this account is part of an AWS Organization.
    pub organization_id: Option<String>,
}

/// Properties for a VPC (Virtual Private Cloud).
#[derive(Debug, Clone, PartialEq)]
pub struct VpcProperties {
    pub common: CommonProperties,
    /// The CIDR block assigned to this VPC.
    pub cidr_block: String,
    /// The AWS region containing this VPC.
    pub region: String,
    /// Whether this is the default VPC for the account.
    pub is_default: bool,
}

/// Properties for an IAM Group.
#[derive(Debug, Clone, PartialEq)]
pub struct IamGroupProperties {
    pub common: CommonProperties,
    /// The group's name.
    pub name: String,
    /// The group's IAM path.
    pub path: Option<String>,
}

/// Properties for a KMS Key.
#[derive(Debug, Clone, PartialEq)]
pub struct KmsKeyProperties {
    pub common: CommonProperties,
    /// Optional alias for this key (e.g., "alias/my-key").
    pub alias: Option<String>,
    /// The key's state (e.g., "Enabled", "Disabled", "PendingDeletion").
    pub key_state: String,
}

/// Properties for an Access Key (API credential).
#[derive(Debug, Clone, PartialEq)]
pub struct AccessKeyProperties {
    pub common: CommonProperties,
    /// The access key's status ("Active" or "Inactive").
    pub status: String,
    /// ISO 8601 timestamp when this key was created.
    pub created_at: Option<String>,
}

/// Properties for a Federated Provider (SAML, OIDC, etc.).
#[derive(Debug, Clone, PartialEq)]
pub struct FederatedProviderProperties {
    pub common: CommonProperties,
    /// The provider's name.
    pub name: String,
    /// The provider's type (e.g., "SAML", "OIDC").
    pub provider_type: String,
}

/// Wrapper enum for all node property types.
///
/// Allows generic handling of properties while preserving type information.
/// Custom variant holds arbitrary JSON properties for unknown node types.
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
    /// Custom properties for node types not yet in the v1 schema.
    Custom(serde_json::Value),
}

impl NodeProperties {
    /// Returns the node label corresponding to this property variant.
    pub fn label(&self) -> crate::labels::NodeLabel {
        use crate::labels::NodeLabel;
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

    /// Returns the common properties if this is a known node type.
    ///
    /// Returns None for Custom variant since it may not have CommonProperties.
    pub fn common(&self) -> Option<&CommonProperties> {
        match self {
            Self::Principal(p) => Some(&p.common),
            Self::Resource(p) => Some(&p.common),
            Self::Permission(p) => Some(&p.common),
            Self::Account(p) => Some(&p.common),
            Self::Vpc(p) => Some(&p.common),
            Self::IamGroup(p) => Some(&p.common),
            Self::KmsKey(p) => Some(&p.common),
            Self::AccessKey(p) => Some(&p.common),
            Self::FederatedProvider(p) => Some(&p.common),
            Self::Custom(_) => None,
        }
    }

    /// Returns the node ID if this is a known node type.
    ///
    /// Returns None for Custom variant.
    pub fn id(&self) -> Option<&Arn> {
        self.common().map(|c| &c.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_arn() -> Arn {
        Arn {
            partition: "aws".to_string(),
            service: "iam".to_string(),
            region: "".to_string(),
            account: "123456789012".to_string(),
            resource: "user/admin".to_string(),
        }
    }

    #[test]
    fn test_common_properties() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        assert_eq!(common.id.account, "123456789012");
        assert_eq!(common.ingest_run_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(common.ingested_at, "2026-05-22T10:30:00Z");
    }

    #[test]
    fn test_principal_properties() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let principal = PrincipalProperties {
            common,
            name: "Admin".to_string(),
            principal_type: "Role".to_string(),
            account: "123456789012".to_string(),
            path: Some("/service-roles/".to_string()),
        };

        assert_eq!(principal.name, "Admin");
        assert_eq!(principal.principal_type, "Role");
        assert_eq!(principal.path, Some("/service-roles/".to_string()));
    }

    #[test]
    fn test_resource_properties() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let resource = ResourceProperties {
            common,
            name: "my-bucket".to_string(),
            resource_type: "s3:bucket".to_string(),
            account: "123456789012".to_string(),
            region: "us-east-1".to_string(),
        };

        assert_eq!(resource.name, "my-bucket");
        assert_eq!(resource.resource_type, "s3:bucket");
        assert_eq!(resource.region, "us-east-1");
    }

    #[test]
    fn test_permission_properties() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let permission = PermissionProperties {
            common,
            sid: Some("AllowS3Read".to_string()),
            effect: "Allow".to_string(),
            actions: vec!["s3:GetObject".to_string()],
            resources: vec!["arn:aws:s3:::my-bucket/*".to_string()],
            conditions: None,
        };

        assert_eq!(permission.sid, Some("AllowS3Read".to_string()));
        assert_eq!(permission.effect, "Allow");
        assert_eq!(permission.actions.len(), 1);
        assert_eq!(permission.resources.len(), 1);
    }

    #[test]
    fn test_account_properties() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let account = AccountProperties {
            common,
            name: "Production".to_string(),
            organization_id: Some("o-abc123def456".to_string()),
        };

        assert_eq!(account.name, "Production");
        assert_eq!(account.organization_id, Some("o-abc123def456".to_string()));
    }

    #[test]
    fn test_vpc_properties() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let vpc = VpcProperties {
            common,
            cidr_block: "10.0.0.0/16".to_string(),
            region: "us-west-2".to_string(),
            is_default: false,
        };

        assert_eq!(vpc.cidr_block, "10.0.0.0/16");
        assert_eq!(vpc.region, "us-west-2");
        assert!(!vpc.is_default);
    }

    #[test]
    fn test_iam_group_properties() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let group = IamGroupProperties {
            common,
            name: "Developers".to_string(),
            path: Some("/engineering/".to_string()),
        };

        assert_eq!(group.name, "Developers");
        assert_eq!(group.path, Some("/engineering/".to_string()));
    }

    #[test]
    fn test_kms_key_properties() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let key = KmsKeyProperties {
            common,
            alias: Some("alias/my-key".to_string()),
            key_state: "Enabled".to_string(),
        };

        assert_eq!(key.alias, Some("alias/my-key".to_string()));
        assert_eq!(key.key_state, "Enabled");
    }

    #[test]
    fn test_access_key_properties() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let access_key = AccessKeyProperties {
            common,
            status: "Active".to_string(),
            created_at: Some("2026-01-15T08:00:00Z".to_string()),
        };

        assert_eq!(access_key.status, "Active");
        assert_eq!(
            access_key.created_at,
            Some("2026-01-15T08:00:00Z".to_string())
        );
    }

    #[test]
    fn test_federated_provider_properties() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let provider = FederatedProviderProperties {
            common,
            name: "Okta".to_string(),
            provider_type: "SAML".to_string(),
        };

        assert_eq!(provider.name, "Okta");
        assert_eq!(provider.provider_type, "SAML");
    }

    #[test]
    fn test_node_properties_label_principal() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let principal = PrincipalProperties {
            common,
            name: "Admin".to_string(),
            principal_type: "Role".to_string(),
            account: "123456789012".to_string(),
            path: None,
        };

        let props = NodeProperties::Principal(principal);
        assert_eq!(props.label(), crate::labels::NodeLabel::Principal);
    }

    #[test]
    fn test_node_properties_label_resource() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
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
        assert_eq!(props.label(), crate::labels::NodeLabel::Resource);
    }

    #[test]
    fn test_node_properties_common() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let principal = PrincipalProperties {
            common: common.clone(),
            name: "Admin".to_string(),
            principal_type: "Role".to_string(),
            account: "123456789012".to_string(),
            path: None,
        };

        let props = NodeProperties::Principal(principal);
        assert_eq!(props.common(), Some(&common));
    }

    #[test]
    fn test_node_properties_custom_no_common() {
        let custom_value = serde_json::json!({
            "type": "unknown",
            "data": {}
        });

        let props = NodeProperties::Custom(custom_value);
        assert_eq!(props.common(), None);
    }

    #[test]
    fn test_node_properties_id() {
        let arn = sample_arn();
        let common = CommonProperties {
            id: arn.clone(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let principal = PrincipalProperties {
            common,
            name: "Admin".to_string(),
            principal_type: "Role".to_string(),
            account: "123456789012".to_string(),
            path: None,
        };

        let props = NodeProperties::Principal(principal);
        assert_eq!(props.id(), Some(&arn));
    }

    #[test]
    fn test_node_properties_id_custom_returns_none() {
        let custom_value = serde_json::json!({});
        let props = NodeProperties::Custom(custom_value);
        assert_eq!(props.id(), None);
    }

    #[test]
    fn test_principal_properties_clone() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let principal = PrincipalProperties {
            common,
            name: "Admin".to_string(),
            principal_type: "Role".to_string(),
            account: "123456789012".to_string(),
            path: Some("/service/".to_string()),
        };

        let cloned = principal.clone();
        assert_eq!(cloned, principal);
    }

    #[test]
    fn test_all_node_types_have_common() {
        let common = CommonProperties {
            id: sample_arn(),
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let principal = NodeProperties::Principal(PrincipalProperties {
            common: common.clone(),
            name: "A".to_string(),
            principal_type: "Role".to_string(),
            account: "123456789012".to_string(),
            path: None,
        });
        assert!(principal.common().is_some());

        let resource = NodeProperties::Resource(ResourceProperties {
            common: common.clone(),
            name: "B".to_string(),
            resource_type: "s3:bucket".to_string(),
            account: "123456789012".to_string(),
            region: "us-east-1".to_string(),
        });
        assert!(resource.common().is_some());

        let permission = NodeProperties::Permission(PermissionProperties {
            common: common.clone(),
            sid: None,
            effect: "Allow".to_string(),
            actions: vec![],
            resources: vec![],
            conditions: None,
        });
        assert!(permission.common().is_some());

        let account = NodeProperties::Account(AccountProperties {
            common: common.clone(),
            name: "C".to_string(),
            organization_id: None,
        });
        assert!(account.common().is_some());

        let vpc = NodeProperties::Vpc(VpcProperties {
            common: common.clone(),
            cidr_block: "10.0.0.0/16".to_string(),
            region: "us-east-1".to_string(),
            is_default: false,
        });
        assert!(vpc.common().is_some());

        let iam_group = NodeProperties::IamGroup(IamGroupProperties {
            common: common.clone(),
            name: "D".to_string(),
            path: None,
        });
        assert!(iam_group.common().is_some());

        let kms_key = NodeProperties::KmsKey(KmsKeyProperties {
            common: common.clone(),
            alias: None,
            key_state: "Enabled".to_string(),
        });
        assert!(kms_key.common().is_some());

        let access_key = NodeProperties::AccessKey(AccessKeyProperties {
            common: common.clone(),
            status: "Active".to_string(),
            created_at: None,
        });
        assert!(access_key.common().is_some());

        let federated_provider = NodeProperties::FederatedProvider(FederatedProviderProperties {
            common,
            name: "E".to_string(),
            provider_type: "SAML".to_string(),
        });
        assert!(federated_provider.common().is_some());
    }
}
