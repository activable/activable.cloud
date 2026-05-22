//! Node and edge type enums for the cloud attack graph.
//!
//! Defines labeled node types and edge types using a non-exhaustive enum pattern.
//! Unknown types are captured as `Custom(String)` for forward compatibility.

use std::fmt;
use std::str::FromStr;

/// Node labels representing entity types in the cloud attack graph.
///
/// The v1 substrate defines 9 known node types. Unknown types are mapped to
/// `Custom(String)` to support future extensions without breaking existing code.
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
    /// Escape hatch for types not yet promoted to a named variant.
    Custom(String),
}

impl NodeLabel {
    /// Returns the string representation of the node label.
    ///
    /// For known variants, returns the literal name (e.g., "Principal").
    /// For `Custom(s)`, returns the inner string.
    #[must_use]
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
            Self::Custom(s) => s,
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
            other => Self::Custom(other.to_owned()),
        })
    }
}

impl AsRef<str> for NodeLabel {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Edge types representing relationships between nodes in the graph.
///
/// The v1 substrate defines 5 known edge types. Unknown types are mapped to
/// `Custom(String)` for forward compatibility.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EdgeType {
    CanAssume,
    HasPermission,
    Contains,
    MemberOf,
    SignedBy,
    /// Escape hatch for edge types not yet promoted to a named variant.
    Custom(String),
}

impl EdgeType {
    /// Returns the string representation of the edge type.
    ///
    /// For known variants, returns the literal name (e.g., "CanAssume").
    /// For `Custom(s)`, returns the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::CanAssume => "CanAssume",
            Self::HasPermission => "HasPermission",
            Self::Contains => "Contains",
            Self::MemberOf => "MemberOf",
            Self::SignedBy => "SignedBy",
            Self::Custom(s) => s,
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

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "CanAssume" => Self::CanAssume,
            "HasPermission" => Self::HasPermission,
            "Contains" => Self::Contains,
            "MemberOf" => Self::MemberOf,
            "SignedBy" => Self::SignedBy,
            other => Self::Custom(other.to_owned()),
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
    fn test_node_label_display() {
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
    fn test_node_label_custom_display() {
        let custom = NodeLabel::Custom("MyCustomType".to_string());
        assert_eq!(custom.to_string(), "MyCustomType");
    }

    #[test]
    fn test_node_label_from_str_known_variants() {
        assert_eq!(
            "Principal".parse::<NodeLabel>().ok(),
            Some(NodeLabel::Principal)
        );
        assert_eq!(
            "Resource".parse::<NodeLabel>().ok(),
            Some(NodeLabel::Resource)
        );
        assert_eq!(
            "Permission".parse::<NodeLabel>().ok(),
            Some(NodeLabel::Permission)
        );
        assert_eq!(
            "Account".parse::<NodeLabel>().ok(),
            Some(NodeLabel::Account)
        );
        assert_eq!("Vpc".parse::<NodeLabel>().ok(), Some(NodeLabel::Vpc));
        assert_eq!(
            "IamGroup".parse::<NodeLabel>().ok(),
            Some(NodeLabel::IamGroup)
        );
        assert_eq!("KmsKey".parse::<NodeLabel>().ok(), Some(NodeLabel::KmsKey));
        assert_eq!(
            "AccessKey".parse::<NodeLabel>().ok(),
            Some(NodeLabel::AccessKey)
        );
        assert_eq!(
            "FederatedProvider".parse::<NodeLabel>().ok(),
            Some(NodeLabel::FederatedProvider)
        );
    }

    #[test]
    fn test_node_label_from_str_custom() {
        let unknown = "UnknownType".parse::<NodeLabel>().unwrap();
        match unknown {
            NodeLabel::Custom(s) => assert_eq!(s, "UnknownType"),
            _ => panic!("Expected Custom variant"),
        }
    }

    #[test]
    fn test_node_label_roundtrip() {
        let variants = vec![
            NodeLabel::Principal,
            NodeLabel::Resource,
            NodeLabel::Permission,
            NodeLabel::Account,
            NodeLabel::Vpc,
            NodeLabel::IamGroup,
            NodeLabel::KmsKey,
            NodeLabel::AccessKey,
            NodeLabel::FederatedProvider,
        ];

        for variant in variants {
            let string_form = variant.to_string();
            let parsed = string_form.parse::<NodeLabel>().unwrap();
            assert_eq!(variant, parsed);
        }
    }

    #[test]
    fn test_node_label_as_ref() {
        let label = NodeLabel::Principal;
        let s: &str = label.as_ref();
        assert_eq!(s, "Principal");
    }

    #[test]
    fn test_edge_type_display() {
        assert_eq!(EdgeType::CanAssume.to_string(), "CanAssume");
        assert_eq!(EdgeType::HasPermission.to_string(), "HasPermission");
        assert_eq!(EdgeType::Contains.to_string(), "Contains");
        assert_eq!(EdgeType::MemberOf.to_string(), "MemberOf");
        assert_eq!(EdgeType::SignedBy.to_string(), "SignedBy");
    }

    #[test]
    fn test_edge_type_custom_display() {
        let custom = EdgeType::Custom("MyCustomEdge".to_string());
        assert_eq!(custom.to_string(), "MyCustomEdge");
    }

    #[test]
    fn test_edge_type_from_str_known_variants() {
        assert_eq!(
            "CanAssume".parse::<EdgeType>().ok(),
            Some(EdgeType::CanAssume)
        );
        assert_eq!(
            "HasPermission".parse::<EdgeType>().ok(),
            Some(EdgeType::HasPermission)
        );
        assert_eq!(
            "Contains".parse::<EdgeType>().ok(),
            Some(EdgeType::Contains)
        );
        assert_eq!(
            "MemberOf".parse::<EdgeType>().ok(),
            Some(EdgeType::MemberOf)
        );
        assert_eq!(
            "SignedBy".parse::<EdgeType>().ok(),
            Some(EdgeType::SignedBy)
        );
    }

    #[test]
    fn test_edge_type_from_str_custom() {
        let unknown = "UnknownEdgeType".parse::<EdgeType>().unwrap();
        match unknown {
            EdgeType::Custom(s) => assert_eq!(s, "UnknownEdgeType"),
            _ => panic!("Expected Custom variant"),
        }
    }

    #[test]
    fn test_edge_type_roundtrip() {
        let variants = vec![
            EdgeType::CanAssume,
            EdgeType::HasPermission,
            EdgeType::Contains,
            EdgeType::MemberOf,
            EdgeType::SignedBy,
        ];

        for variant in variants {
            let string_form = variant.to_string();
            let parsed = string_form.parse::<EdgeType>().unwrap();
            assert_eq!(variant, parsed);
        }
    }

    #[test]
    fn test_edge_type_as_ref() {
        let edge = EdgeType::CanAssume;
        let s: &str = edge.as_ref();
        assert_eq!(s, "CanAssume");
    }
}
