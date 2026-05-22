//! Node labels and edge types for the attack graph.
//!
//! Defines the cloud entity types (Principal, Resource, Permission, etc.) and
//! relationship types (CanAssume, HasPermission, etc.) used in the graph model.
//! Both enums use Custom(String) as an escape hatch for forward compatibility.

use std::fmt;
use std::str::FromStr;

/// Cloud entity node label.
///
/// # Examples
/// ```
/// use activable_schema::NodeLabel;
/// use std::str::FromStr;
///
/// let label = NodeLabel::Principal;
/// assert_eq!(label.to_string(), "Principal");
///
/// // Unknown labels become Custom
/// let custom = NodeLabel::from_str("K8sCluster").unwrap();
/// assert!(matches!(custom, NodeLabel::Custom(_)));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeLabel {
    Principal,
    Resource,
    Permission,
    Account,
    Vpc,
    IamGroup,
    KmsKey,
    AccessKey,
    FederatedProvider,
    /// Escape hatch for types not yet in the v1 schema.
    Custom(String),
}

impl NodeLabel {
    /// Returns the canonical string representation of this label.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Principal => "Principal",
            Self::Resource => "Resource",
            Self::Permission => "Permission",
            Self::Account => "Account",
            Self::Vpc => "Vpc",
            Self::IamGroup => "IamGroup",
            Self::KmsKey => "KmsKey",
            Self::AccessKey => "AccessKey",
            Self::FederatedProvider => "FederatedProvider",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for NodeLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NodeLabel {
    type Err = std::convert::Infallible;

    /// Parses a string into a NodeLabel.
    ///
    /// Known variants return their enum value. Unknown strings map to Custom.
    /// Never fails (Infallible error type).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Principal" => Self::Principal,
            "Resource" => Self::Resource,
            "Permission" => Self::Permission,
            "Account" => Self::Account,
            "Vpc" => Self::Vpc,
            "IamGroup" => Self::IamGroup,
            "KmsKey" => Self::KmsKey,
            "AccessKey" => Self::AccessKey,
            "FederatedProvider" => Self::FederatedProvider,
            other => Self::Custom(other.to_string()),
        })
    }
}

impl AsRef<str> for NodeLabel {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Edge type in the attack graph.
///
/// # Examples
/// ```
/// use activable_schema::EdgeType;
/// use std::str::FromStr;
///
/// let edge = EdgeType::CanAssume;
/// assert_eq!(edge.to_string(), "CanAssume");
///
/// // Unknown edge types become Custom
/// let custom = EdgeType::from_str("IsEncryptedBy").unwrap();
/// assert!(matches!(custom, EdgeType::Custom(_)));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EdgeType {
    CanAssume,
    HasPermission,
    Contains,
    MemberOf,
    SignedBy,
    /// Escape hatch for relationship types not yet in the v1 schema.
    Custom(String),
}

impl EdgeType {
    /// Returns the canonical string representation of this edge type.
    pub fn as_str(&self) -> &str {
        match self {
            Self::CanAssume => "CanAssume",
            Self::HasPermission => "HasPermission",
            Self::Contains => "Contains",
            Self::MemberOf => "MemberOf",
            Self::SignedBy => "SignedBy",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for EdgeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EdgeType {
    type Err = std::convert::Infallible;

    /// Parses a string into an EdgeType.
    ///
    /// Known variants return their enum value. Unknown strings map to Custom.
    /// Never fails (Infallible error type).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "CanAssume" => Self::CanAssume,
            "HasPermission" => Self::HasPermission,
            "Contains" => Self::Contains,
            "MemberOf" => Self::MemberOf,
            "SignedBy" => Self::SignedBy,
            other => Self::Custom(other.to_string()),
        })
    }
}

impl AsRef<str> for EdgeType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_label_display() {
        assert_eq!(NodeLabel::Principal.to_string(), "Principal");
        assert_eq!(NodeLabel::Resource.to_string(), "Resource");
        assert_eq!(NodeLabel::Permission.to_string(), "Permission");
        assert_eq!(NodeLabel::Account.to_string(), "Account");
        assert_eq!(NodeLabel::Vpc.to_string(), "Vpc");
        assert_eq!(NodeLabel::IamGroup.to_string(), "IamGroup");
        assert_eq!(NodeLabel::KmsKey.to_string(), "KmsKey");
        assert_eq!(NodeLabel::AccessKey.to_string(), "AccessKey");
        assert_eq!(
            NodeLabel::FederatedProvider.to_string(),
            "FederatedProvider"
        );
    }

    #[test]
    fn node_label_custom_display() {
        let custom = NodeLabel::Custom("K8sCluster".to_string());
        assert_eq!(custom.to_string(), "K8sCluster");
    }

    #[test]
    fn node_label_from_str_known() {
        assert_eq!(
            NodeLabel::from_str("Principal").unwrap(),
            NodeLabel::Principal
        );
        assert_eq!(
            NodeLabel::from_str("Resource").unwrap(),
            NodeLabel::Resource
        );
        assert_eq!(
            NodeLabel::from_str("Permission").unwrap(),
            NodeLabel::Permission
        );
        assert_eq!(NodeLabel::from_str("Account").unwrap(), NodeLabel::Account);
        assert_eq!(NodeLabel::from_str("Vpc").unwrap(), NodeLabel::Vpc);
        assert_eq!(
            NodeLabel::from_str("IamGroup").unwrap(),
            NodeLabel::IamGroup
        );
        assert_eq!(NodeLabel::from_str("KmsKey").unwrap(), NodeLabel::KmsKey);
        assert_eq!(
            NodeLabel::from_str("AccessKey").unwrap(),
            NodeLabel::AccessKey
        );
        assert_eq!(
            NodeLabel::from_str("FederatedProvider").unwrap(),
            NodeLabel::FederatedProvider
        );
    }

    #[test]
    fn node_label_from_str_unknown() {
        let custom = NodeLabel::from_str("UnknownType").unwrap();
        assert_eq!(custom, NodeLabel::Custom("UnknownType".to_string()));
    }

    #[test]
    fn node_label_from_str_empty() {
        let custom = NodeLabel::from_str("").unwrap();
        assert_eq!(custom, NodeLabel::Custom("".to_string()));
    }

    #[test]
    fn node_label_round_trip() {
        for s in &[
            "Principal",
            "Resource",
            "Permission",
            "Account",
            "Vpc",
            "IamGroup",
            "KmsKey",
            "AccessKey",
            "FederatedProvider",
        ] {
            let label = NodeLabel::from_str(s).unwrap();
            assert_eq!(label.to_string(), *s);
        }
    }

    #[test]
    fn node_label_as_ref() {
        assert_eq!(NodeLabel::Principal.as_ref(), "Principal");
        assert_eq!(NodeLabel::Custom("Foo".to_string()).as_ref(), "Foo");
    }

    #[test]
    fn edge_type_display() {
        assert_eq!(EdgeType::CanAssume.to_string(), "CanAssume");
        assert_eq!(EdgeType::HasPermission.to_string(), "HasPermission");
        assert_eq!(EdgeType::Contains.to_string(), "Contains");
        assert_eq!(EdgeType::MemberOf.to_string(), "MemberOf");
        assert_eq!(EdgeType::SignedBy.to_string(), "SignedBy");
    }

    #[test]
    fn edge_type_custom_display() {
        let custom = EdgeType::Custom("IsEncryptedBy".to_string());
        assert_eq!(custom.to_string(), "IsEncryptedBy");
    }

    #[test]
    fn edge_type_from_str_known() {
        assert_eq!(
            EdgeType::from_str("CanAssume").unwrap(),
            EdgeType::CanAssume
        );
        assert_eq!(
            EdgeType::from_str("HasPermission").unwrap(),
            EdgeType::HasPermission
        );
        assert_eq!(EdgeType::from_str("Contains").unwrap(), EdgeType::Contains);
        assert_eq!(EdgeType::from_str("MemberOf").unwrap(), EdgeType::MemberOf);
        assert_eq!(EdgeType::from_str("SignedBy").unwrap(), EdgeType::SignedBy);
    }

    #[test]
    fn edge_type_from_str_unknown() {
        let custom = EdgeType::from_str("IsEncryptedBy").unwrap();
        assert_eq!(custom, EdgeType::Custom("IsEncryptedBy".to_string()));
    }

    #[test]
    fn edge_type_round_trip() {
        for s in &[
            "CanAssume",
            "HasPermission",
            "Contains",
            "MemberOf",
            "SignedBy",
        ] {
            let edge = EdgeType::from_str(s).unwrap();
            assert_eq!(edge.to_string(), *s);
        }
    }

    #[test]
    fn edge_type_as_ref() {
        assert_eq!(EdgeType::CanAssume.as_ref(), "CanAssume");
        assert_eq!(EdgeType::Custom("Bar".to_string()).as_ref(), "Bar");
    }

    #[test]
    fn node_label_partial_eq() {
        assert_eq!(NodeLabel::Principal, NodeLabel::Principal);
        assert_ne!(NodeLabel::Principal, NodeLabel::Resource);
        assert_eq!(
            NodeLabel::Custom("A".to_string()),
            NodeLabel::Custom("A".to_string())
        );
        assert_ne!(
            NodeLabel::Custom("A".to_string()),
            NodeLabel::Custom("B".to_string())
        );
    }

    #[test]
    fn edge_type_partial_eq() {
        assert_eq!(EdgeType::CanAssume, EdgeType::CanAssume);
        assert_ne!(EdgeType::CanAssume, EdgeType::HasPermission);
        assert_eq!(
            EdgeType::Custom("X".to_string()),
            EdgeType::Custom("X".to_string())
        );
    }
}
