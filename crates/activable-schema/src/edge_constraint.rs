//! Edge constraint validation and edge property types.
//!
//! Validates that edges exist only between compatible node types.
//! Supports per-edge-type property structs for metadata.

use crate::labels::{EdgeType, NodeLabel};

/// Properties shared across all edge types.
#[derive(Debug, Clone, PartialEq)]
pub struct CommonEdgeProperties {
    /// UUID of the ingestion run that discovered this edge (as string).
    pub ingest_run_id: String,
    /// ISO 8601 timestamp when this edge was ingested (as string).
    pub ingested_at: String,
}

/// Validates whether an edge of the specified type can exist between two node types.
///
/// # Behavior
///
/// - If either endpoint is a `Custom` node type, returns `true` (custom types bypass validation).
/// - If the edge type is `Custom`, returns `true` (custom edge types bypass validation).
/// - For known node and edge types, validates against the defined compatibility matrix.
/// - The v1 substrate defines these valid edges:
///   - `Principal` --CanAssume--> `Principal`
///   - `Principal` --HasPermission--> `Permission`
///   - `Account` --Contains--> any node type
///   - `Principal` --MemberOf--> `IamGroup`
///   - `AccessKey` --SignedBy--> `Principal`
///
/// # Returns
///
/// `true` if the edge is valid (or involves custom types), `false` otherwise.
pub fn is_valid_edge(from: &NodeLabel, edge: &EdgeType, to: &NodeLabel) -> bool {
    // Custom types bypass validation
    if matches!(from, NodeLabel::Custom(_)) || matches!(to, NodeLabel::Custom(_)) {
        return true;
    }

    // Custom edge types bypass validation
    if matches!(edge, EdgeType::Custom(_)) {
        return true;
    }

    // Known type validation matrix
    matches!(
        (from, edge, to),
        (
            NodeLabel::Principal,
            EdgeType::CanAssume,
            NodeLabel::Principal
        ) | (
            NodeLabel::Principal,
            EdgeType::HasPermission,
            NodeLabel::Permission
        ) | (NodeLabel::Account, EdgeType::Contains, _)
            | (
                NodeLabel::Principal,
                EdgeType::MemberOf,
                NodeLabel::IamGroup
            )
            | (
                NodeLabel::AccessKey,
                EdgeType::SignedBy,
                NodeLabel::Principal
            )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_edge_principal_can_assume_principal() {
        let valid = is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::CanAssume,
            &NodeLabel::Principal,
        );
        assert!(valid);
    }

    #[test]
    fn test_is_valid_edge_principal_has_permission_permission() {
        let valid = is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::HasPermission,
            &NodeLabel::Permission,
        );
        assert!(valid);
    }

    #[test]
    fn test_is_valid_edge_account_contains_any() {
        let valid_resource = is_valid_edge(
            &NodeLabel::Account,
            &EdgeType::Contains,
            &NodeLabel::Resource,
        );
        assert!(valid_resource);

        let valid_vpc = is_valid_edge(&NodeLabel::Account, &EdgeType::Contains, &NodeLabel::Vpc);
        assert!(valid_vpc);

        let valid_principal = is_valid_edge(
            &NodeLabel::Account,
            &EdgeType::Contains,
            &NodeLabel::Principal,
        );
        assert!(valid_principal);
    }

    #[test]
    fn test_is_valid_edge_principal_member_of_iam_group() {
        let valid = is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::MemberOf,
            &NodeLabel::IamGroup,
        );
        assert!(valid);
    }

    #[test]
    fn test_is_valid_edge_access_key_signed_by_principal() {
        let valid = is_valid_edge(
            &NodeLabel::AccessKey,
            &EdgeType::SignedBy,
            &NodeLabel::Principal,
        );
        assert!(valid);
    }

    #[test]
    fn test_is_valid_edge_invalid_principal_can_assume_resource() {
        let invalid = is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::CanAssume,
            &NodeLabel::Resource,
        );
        assert!(!invalid);
    }

    #[test]
    fn test_is_valid_edge_invalid_resource_has_permission_permission() {
        let invalid = is_valid_edge(
            &NodeLabel::Resource,
            &EdgeType::HasPermission,
            &NodeLabel::Permission,
        );
        assert!(!invalid);
    }

    #[test]
    fn test_is_valid_edge_invalid_permission_member_of_iam_group() {
        let invalid = is_valid_edge(
            &NodeLabel::Permission,
            &EdgeType::MemberOf,
            &NodeLabel::IamGroup,
        );
        assert!(!invalid);
    }

    #[test]
    fn test_is_valid_edge_custom_from_node_always_valid() {
        let custom_from = is_valid_edge(
            &NodeLabel::Custom("FutureNodeType".to_string()),
            &EdgeType::CanAssume,
            &NodeLabel::Principal,
        );
        assert!(custom_from);
    }

    #[test]
    fn test_is_valid_edge_custom_to_node_always_valid() {
        let custom_to = is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::CanAssume,
            &NodeLabel::Custom("FutureNodeType".to_string()),
        );
        assert!(custom_to);
    }

    #[test]
    fn test_is_valid_edge_custom_edge_type_always_valid() {
        let custom_edge = is_valid_edge(
            &NodeLabel::Principal,
            &EdgeType::Custom("FutureEdgeType".to_string()),
            &NodeLabel::Resource,
        );
        assert!(custom_edge);
    }

    #[test]
    fn test_is_valid_edge_custom_nodes_and_edge_always_valid() {
        let all_custom = is_valid_edge(
            &NodeLabel::Custom("Future1".to_string()),
            &EdgeType::Custom("FutureEdge".to_string()),
            &NodeLabel::Custom("Future2".to_string()),
        );
        assert!(all_custom);
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
}
