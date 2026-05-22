//! Edge validation and edge property schemas.
//!
//! Defines valid edge relationships between node types and edge property structures.

use crate::labels::{EdgeType, NodeLabel};

/// Properties shared across all edge types.
#[derive(Debug, Clone, PartialEq)]
pub struct CommonEdgeProperties {
    /// UUID of the ingestion run that created this edge.
    pub ingest_run_id: String,
    /// ISO 8601 timestamp when this edge was ingested.
    pub ingested_at: String,
}

/// Validates whether an edge from a source node to a target node is allowed.
///
/// The v1 schema permits:
/// - Principal -[CanAssume]-> Principal (cross-account role assumption)
/// - Principal -[HasPermission]-> Permission (policy attachment)
/// - Account -[Contains]-> any (organizational containment)
/// - Principal -[MemberOf]-> IamGroup (group membership)
/// - AccessKey -[SignedBy]-> Principal (key ownership)
///
/// Custom node types bypass validation (forward compatibility).
///
/// # Examples
/// ```
/// use activable_schema::{is_valid_edge, NodeLabel, EdgeType};
///
/// // Valid: Principal can assume Principal
/// assert!(is_valid_edge(
///     &NodeLabel::Principal,
///     &EdgeType::CanAssume,
///     &NodeLabel::Principal
/// ));
///
/// // Invalid: Principal cannot assume Permission
/// assert!(!is_valid_edge(
///     &NodeLabel::Principal,
///     &EdgeType::CanAssume,
///     &NodeLabel::Permission
/// ));
///
/// // Custom types always pass (unknown schema)
/// assert!(is_valid_edge(
///     &NodeLabel::Custom("Kubernetes".to_string()),
///     &EdgeType::Custom("Schedules".to_string()),
///     &NodeLabel::Custom("Pod".to_string())
/// ));
/// ```
pub fn is_valid_edge(from: &NodeLabel, edge: &EdgeType, to: &NodeLabel) -> bool {
    // If either endpoint is a custom type, allow the edge (unknown schema).
    if matches!(from, NodeLabel::Custom(_)) || matches!(to, NodeLabel::Custom(_)) {
        return true;
    }

    // If the edge type is custom, allow it (unknown relationship type).
    if matches!(edge, EdgeType::Custom(_)) {
        return true;
    }

    // Standard v1 edge constraints.
    matches!(
        (from, edge, to),
        // CanAssume: Principal assumes another Principal (cross-account role assumption)
        (NodeLabel::Principal, EdgeType::CanAssume, NodeLabel::Principal)
        // HasPermission: Principal has a Permission policy
        | (NodeLabel::Principal, EdgeType::HasPermission, NodeLabel::Permission)
        // Contains: Account contains any resource (organizational relationship)
        | (NodeLabel::Account, EdgeType::Contains, NodeLabel::Principal)
        | (NodeLabel::Account, EdgeType::Contains, NodeLabel::Resource)
        | (NodeLabel::Account, EdgeType::Contains, NodeLabel::Permission)
        | (NodeLabel::Account, EdgeType::Contains, NodeLabel::Account)
        | (NodeLabel::Account, EdgeType::Contains, NodeLabel::Vpc)
        | (NodeLabel::Account, EdgeType::Contains, NodeLabel::IamGroup)
        | (NodeLabel::Account, EdgeType::Contains, NodeLabel::KmsKey)
        | (NodeLabel::Account, EdgeType::Contains, NodeLabel::AccessKey)
        | (NodeLabel::Account, EdgeType::Contains, NodeLabel::FederatedProvider)
        // MemberOf: Principal is a member of an IamGroup
        | (NodeLabel::Principal, EdgeType::MemberOf, NodeLabel::IamGroup)
        // SignedBy: AccessKey is signed by (belongs to) a Principal
        | (NodeLabel::AccessKey, EdgeType::SignedBy, NodeLabel::Principal)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_principal_can_assume_principal() {
        assert!(is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::CanAssume,
            &NodeLabel::Principal
        ));
    }

    #[test]
    fn test_invalid_principal_can_assume_resource() {
        assert!(!is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::CanAssume,
            &NodeLabel::Resource
        ));
    }

    #[test]
    fn test_invalid_principal_can_assume_permission() {
        assert!(!is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::CanAssume,
            &NodeLabel::Permission
        ));
    }

    #[test]
    fn test_invalid_resource_can_assume_principal() {
        assert!(!is_valid_edge(
            &NodeLabel::Resource,
            &EdgeType::CanAssume,
            &NodeLabel::Principal
        ));
    }

    #[test]
    fn test_valid_principal_has_permission() {
        assert!(is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::HasPermission,
            &NodeLabel::Permission
        ));
    }

    #[test]
    fn test_invalid_principal_has_resource() {
        assert!(!is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::HasPermission,
            &NodeLabel::Resource
        ));
    }

    #[test]
    fn test_invalid_resource_has_permission() {
        assert!(!is_valid_edge(
            &NodeLabel::Resource,
            &EdgeType::HasPermission,
            &NodeLabel::Permission
        ));
    }

    #[test]
    fn test_valid_account_contains_principal() {
        assert!(is_valid_edge(
            &NodeLabel::Account,
            &EdgeType::Contains,
            &NodeLabel::Principal
        ));
    }

    #[test]
    fn test_valid_account_contains_resource() {
        assert!(is_valid_edge(
            &NodeLabel::Account,
            &EdgeType::Contains,
            &NodeLabel::Resource
        ));
    }

    #[test]
    fn test_valid_account_contains_vpc() {
        assert!(is_valid_edge(
            &NodeLabel::Account,
            &EdgeType::Contains,
            &NodeLabel::Vpc
        ));
    }

    #[test]
    fn test_valid_account_contains_iam_group() {
        assert!(is_valid_edge(
            &NodeLabel::Account,
            &EdgeType::Contains,
            &NodeLabel::IamGroup
        ));
    }

    #[test]
    fn test_valid_account_contains_kms_key() {
        assert!(is_valid_edge(
            &NodeLabel::Account,
            &EdgeType::Contains,
            &NodeLabel::KmsKey
        ));
    }

    #[test]
    fn test_valid_account_contains_access_key() {
        assert!(is_valid_edge(
            &NodeLabel::Account,
            &EdgeType::Contains,
            &NodeLabel::AccessKey
        ));
    }

    #[test]
    fn test_valid_account_contains_federated_provider() {
        assert!(is_valid_edge(
            &NodeLabel::Account,
            &EdgeType::Contains,
            &NodeLabel::FederatedProvider
        ));
    }

    #[test]
    fn test_invalid_resource_contains_principal() {
        assert!(!is_valid_edge(
            &NodeLabel::Resource,
            &EdgeType::Contains,
            &NodeLabel::Principal
        ));
    }

    #[test]
    fn test_valid_principal_member_of_iam_group() {
        assert!(is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::MemberOf,
            &NodeLabel::IamGroup
        ));
    }

    #[test]
    fn test_invalid_principal_member_of_resource() {
        assert!(!is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::MemberOf,
            &NodeLabel::Resource
        ));
    }

    #[test]
    fn test_invalid_resource_member_of_iam_group() {
        assert!(!is_valid_edge(
            &NodeLabel::Resource,
            &EdgeType::MemberOf,
            &NodeLabel::IamGroup
        ));
    }

    #[test]
    fn test_valid_access_key_signed_by_principal() {
        assert!(is_valid_edge(
            &NodeLabel::AccessKey,
            &EdgeType::SignedBy,
            &NodeLabel::Principal
        ));
    }

    #[test]
    fn test_invalid_access_key_signed_by_resource() {
        assert!(!is_valid_edge(
            &NodeLabel::AccessKey,
            &EdgeType::SignedBy,
            &NodeLabel::Resource
        ));
    }

    #[test]
    fn test_invalid_principal_signed_by_principal() {
        assert!(!is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::SignedBy,
            &NodeLabel::Principal
        ));
    }

    #[test]
    fn test_custom_source_always_valid() {
        let custom_from = NodeLabel::Custom("CustomType".to_string());
        assert!(is_valid_edge(
            &custom_from,
            &EdgeType::CanAssume,
            &NodeLabel::Principal
        ));
        assert!(is_valid_edge(
            &custom_from,
            &EdgeType::HasPermission,
            &NodeLabel::Resource
        ));
        assert!(is_valid_edge(
            &custom_from,
            &EdgeType::Contains,
            &NodeLabel::Custom("AnotherCustom".to_string())
        ));
    }

    #[test]
    fn test_custom_target_always_valid() {
        let custom_to = NodeLabel::Custom("CustomType".to_string());
        assert!(is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::CanAssume,
            &custom_to
        ));
        assert!(is_valid_edge(
            &NodeLabel::Resource,
            &EdgeType::HasPermission,
            &custom_to
        ));
    }

    #[test]
    fn test_custom_edge_always_valid() {
        let custom_edge = EdgeType::Custom("IsConnectedTo".to_string());
        assert!(is_valid_edge(
            &NodeLabel::Principal,
            &custom_edge,
            &NodeLabel::Resource
        ));
        assert!(is_valid_edge(
            &NodeLabel::Vpc,
            &custom_edge,
            &NodeLabel::KmsKey
        ));
    }

    #[test]
    fn test_both_custom_nodes_valid() {
        let custom_from = NodeLabel::Custom("A".to_string());
        let custom_to = NodeLabel::Custom("B".to_string());
        assert!(is_valid_edge(
            &custom_from,
            &EdgeType::CanAssume,
            &custom_to
        ));
    }

    #[test]
    fn test_custom_edge_and_custom_nodes() {
        let custom_from = NodeLabel::Custom("X".to_string());
        let custom_to = NodeLabel::Custom("Y".to_string());
        let custom_edge = EdgeType::Custom("Unknown".to_string());
        assert!(is_valid_edge(&custom_from, &custom_edge, &custom_to));
    }

    #[test]
    fn test_invalid_permission_can_assume_principal() {
        assert!(!is_valid_edge(
            &NodeLabel::Permission,
            &EdgeType::CanAssume,
            &NodeLabel::Principal
        ));
    }

    #[test]
    fn test_invalid_account_member_of_iam_group() {
        assert!(!is_valid_edge(
            &NodeLabel::Account,
            &EdgeType::MemberOf,
            &NodeLabel::IamGroup
        ));
    }

    #[test]
    fn test_invalid_vpc_signed_by_principal() {
        assert!(!is_valid_edge(
            &NodeLabel::Vpc,
            &EdgeType::SignedBy,
            &NodeLabel::Principal
        ));
    }

    #[test]
    fn test_common_edge_properties() {
        let props = CommonEdgeProperties {
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        assert_eq!(props.ingest_run_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(props.ingested_at, "2026-05-22T10:30:00Z");
    }

    #[test]
    fn test_common_edge_properties_clone() {
        let props = CommonEdgeProperties {
            ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ingested_at: "2026-05-22T10:30:00Z".to_string(),
        };

        let cloned = props.clone();
        assert_eq!(cloned, props);
    }

    #[test]
    fn test_invalid_principal_contains_resource() {
        assert!(!is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::Contains,
            &NodeLabel::Resource
        ));
    }

    #[test]
    fn test_valid_account_contains_permission() {
        assert!(is_valid_edge(
            &NodeLabel::Account,
            &EdgeType::Contains,
            &NodeLabel::Permission
        ));
    }

    #[test]
    fn test_valid_account_contains_account() {
        assert!(is_valid_edge(
            &NodeLabel::Account,
            &EdgeType::Contains,
            &NodeLabel::Account
        ));
    }

    #[test]
    fn test_invalid_kms_key_member_of_iam_group() {
        assert!(!is_valid_edge(
            &NodeLabel::KmsKey,
            &EdgeType::MemberOf,
            &NodeLabel::IamGroup
        ));
    }

    #[test]
    fn test_invalid_federated_provider_signed_by_principal() {
        assert!(!is_valid_edge(
            &NodeLabel::FederatedProvider,
            &EdgeType::SignedBy,
            &NodeLabel::Principal
        ));
    }
}
