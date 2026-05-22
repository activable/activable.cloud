use crate::error::IngestError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackConfig {
    pub sdk: String,
    pub operation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceTypeConfig {
    pub type_name: String,
    pub label: String,
    pub regional: bool,
    #[serde(default)]
    pub fallback: Option<FallbackConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRegistry {
    pub resource_types: Vec<ResourceTypeConfig>,
}

const RESOURCE_TYPES_YAML: &str = include_str!("config/resource_types.yaml");

pub fn load_registry() -> Result<ResourceRegistry, IngestError> {
    serde_yaml::from_str(RESOURCE_TYPES_YAML).map_err(|e| IngestError::YamlParse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_registry() {
        let registry = load_registry().expect("Failed to load registry");
        assert!(
            !registry.resource_types.is_empty(),
            "Registry should have resource types"
        );

        // Verify first resource type structure
        let first = &registry.resource_types[0];
        assert!(!first.type_name.is_empty(), "type_name should not be empty");
        assert!(!first.label.is_empty(), "label should not be empty");
    }

    #[test]
    fn test_registry_has_iam_user() {
        let registry = load_registry().expect("Failed to load registry");
        let iam_user = registry
            .resource_types
            .iter()
            .find(|rt| rt.type_name == "AWS::IAM::User")
            .expect("IAM User should be in registry");

        assert_eq!(iam_user.label, "Principal");
        assert!(!iam_user.regional);
        assert!(iam_user.fallback.is_some());

        let fallback = iam_user.fallback.as_ref().unwrap();
        assert_eq!(fallback.sdk, "iam");
        assert_eq!(fallback.operation, "ListUsers");
    }

    #[test]
    fn test_registry_has_regional_types() {
        let registry = load_registry().expect("Failed to load registry");
        let ec2_instance = registry
            .resource_types
            .iter()
            .find(|rt| rt.type_name == "AWS::EC2::Instance")
            .expect("EC2 Instance should be in registry");

        assert!(ec2_instance.regional, "EC2 Instance should be regional");
    }
}
