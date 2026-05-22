//! Known node and edge label constants.
//!
//! Provides compile-time accessible string constants for schema labels.
//! Avoids magic strings while keeping the API flexible for future schema extensions.

/// Node labels for the cloud attack graph.
pub mod node_label {
    /// Principal (IAM user, role, service principal, etc.)
    pub const PRINCIPAL: &str = "Principal";

    /// Resource (S3 bucket, EC2 instance, Lambda function, etc.)
    pub const RESOURCE: &str = "Resource";

    /// Permission (policy statement or permission grant)
    pub const PERMISSION: &str = "Permission";

    /// Service Principal (AWS service or cross-account principal)
    pub const SERVICE_PRINCIPAL: &str = "ServicePrincipal";

    /// Federated Provider (external identity provider)
    pub const FEDERATED_PROVIDER: &str = "FederatedProvider";

    /// Access Key (AWS access key credential)
    pub const ACCESS_KEY: &str = "AccessKey";

    /// Account (AWS account)
    pub const ACCOUNT: &str = "Account";

    /// VPC (Virtual Private Cloud)
    pub const VPC: &str = "Vpc";

    /// IAM Group (IAM group)
    pub const IAM_GROUP: &str = "IamGroup";

    /// KMS Key (AWS Key Management Service key)
    pub const KMS_KEY: &str = "KmsKey";
}

/// Edge labels for the cloud attack graph.
pub mod edge_label {
    /// Principal can assume another principal's role
    pub const CAN_ASSUME: &str = "CanAssume";

    /// Principal or resource has a permission
    pub const HAS_PERMISSION: &str = "HasPermission";

    /// Principal or account contains a resource
    pub const CONTAINS: &str = "Contains";

    /// Principal is a member of a group
    pub const MEMBER_OF: &str = "MemberOf";

    /// Principal or resource is signed by another principal
    pub const SIGNED_BY: &str = "SignedBy";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_labels_are_strings() {
        assert_eq!(node_label::PRINCIPAL, "Principal");
        assert_eq!(node_label::RESOURCE, "Resource");
        assert_eq!(node_label::PERMISSION, "Permission");
    }

    #[test]
    fn test_edge_labels_are_strings() {
        assert_eq!(edge_label::CAN_ASSUME, "CanAssume");
        assert_eq!(edge_label::HAS_PERMISSION, "HasPermission");
    }

    #[test]
    fn test_no_duplicate_node_labels() {
        let labels = vec![
            node_label::PRINCIPAL,
            node_label::RESOURCE,
            node_label::PERMISSION,
            node_label::SERVICE_PRINCIPAL,
            node_label::FEDERATED_PROVIDER,
            node_label::ACCESS_KEY,
            node_label::ACCOUNT,
            node_label::VPC,
            node_label::IAM_GROUP,
            node_label::KMS_KEY,
        ];

        let mut seen = std::collections::HashSet::new();
        for label in labels {
            assert!(seen.insert(label), "Duplicate node label found: {}", label);
        }
    }

    #[test]
    fn test_no_duplicate_edge_labels() {
        let labels = vec![
            edge_label::CAN_ASSUME,
            edge_label::HAS_PERMISSION,
            edge_label::CONTAINS,
            edge_label::MEMBER_OF,
            edge_label::SIGNED_BY,
        ];

        let mut seen = std::collections::HashSet::new();
        for label in labels {
            assert!(seen.insert(label), "Duplicate edge label found: {}", label);
        }
    }
}
