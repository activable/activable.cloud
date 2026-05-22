//! Serialization and deserialization for property types.
//!
//! Implements conversion between property structs and `serde_json::Value`
//! for interchange with AGE (Apache AGE) property bags.

use crate::labels::NodeLabel;
use crate::properties::*;
use serde_json::{json, Value};

// === Serialization: XxxProperties -> serde_json::Value ===

impl From<&PrincipalProperties> for Value {
    fn from(props: &PrincipalProperties) -> Self {
        json!({
            "id": props.common.id.canonical(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "name": props.name,
            "principal_type": props.principal_type,
            "account": props.account,
            "path": props.path,
        })
    }
}

impl From<&ResourceProperties> for Value {
    fn from(props: &ResourceProperties) -> Self {
        json!({
            "id": props.common.id.canonical(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "name": props.name,
            "resource_type": props.resource_type,
            "account": props.account,
            "region": props.region,
        })
    }
}

impl From<&PermissionProperties> for Value {
    fn from(props: &PermissionProperties) -> Self {
        json!({
            "id": props.common.id.canonical(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "sid": props.sid,
            "effect": props.effect,
            "actions": props.actions,
            "resources": props.resources,
        })
    }
}

impl From<&AccountProperties> for Value {
    fn from(props: &AccountProperties) -> Self {
        json!({
            "id": props.common.id.canonical(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "name": props.name,
            "organization_id": props.organization_id,
        })
    }
}

impl From<&VpcProperties> for Value {
    fn from(props: &VpcProperties) -> Self {
        json!({
            "id": props.common.id.canonical(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "cidr_block": props.cidr_block,
            "region": props.region,
            "is_default": props.is_default,
        })
    }
}

impl From<&IamGroupProperties> for Value {
    fn from(props: &IamGroupProperties) -> Self {
        json!({
            "id": props.common.id.canonical(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "name": props.name,
            "account": props.account,
            "path": props.path,
        })
    }
}

impl From<&KmsKeyProperties> for Value {
    fn from(props: &KmsKeyProperties) -> Self {
        json!({
            "id": props.common.id.canonical(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "name": props.name,
            "account": props.account,
            "region": props.region,
        })
    }
}

impl From<&AccessKeyProperties> for Value {
    fn from(props: &AccessKeyProperties) -> Self {
        json!({
            "id": props.common.id.canonical(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "access_key_id": props.access_key_id,
            "account": props.account,
            "status": props.status,
        })
    }
}

impl From<&FederatedProviderProperties> for Value {
    fn from(props: &FederatedProviderProperties) -> Self {
        json!({
            "id": props.common.id.canonical(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "name": props.name,
            "account": props.account,
            "provider_type": props.provider_type,
        })
    }
}

// === Deserialization: (NodeLabel, serde_json::Value) -> NodeProperties ===

impl TryFrom<(&NodeLabel, Value)> for NodeProperties {
    type Error = String;

    fn try_from((label, value): (&NodeLabel, Value)) -> Result<Self, Self::Error> {
        match label {
            NodeLabel::Principal => {
                let props = PrincipalProperties::try_from(&value)?;
                Ok(NodeProperties::Principal(props))
            }
            NodeLabel::Resource => {
                let props = ResourceProperties::try_from(&value)?;
                Ok(NodeProperties::Resource(props))
            }
            NodeLabel::Permission => {
                let props = PermissionProperties::try_from(&value)?;
                Ok(NodeProperties::Permission(props))
            }
            NodeLabel::Account => {
                let props = AccountProperties::try_from(&value)?;
                Ok(NodeProperties::Account(props))
            }
            NodeLabel::Vpc => {
                let props = VpcProperties::try_from(&value)?;
                Ok(NodeProperties::Vpc(props))
            }
            NodeLabel::IamGroup => {
                let props = IamGroupProperties::try_from(&value)?;
                Ok(NodeProperties::IamGroup(props))
            }
            NodeLabel::KmsKey => {
                let props = KmsKeyProperties::try_from(&value)?;
                Ok(NodeProperties::KmsKey(props))
            }
            NodeLabel::AccessKey => {
                let props = AccessKeyProperties::try_from(&value)?;
                Ok(NodeProperties::AccessKey(props))
            }
            NodeLabel::FederatedProvider => {
                let props = FederatedProviderProperties::try_from(&value)?;
                Ok(NodeProperties::FederatedProvider(props))
            }
            NodeLabel::Custom(_) => Ok(NodeProperties::Custom(value)),
        }
    }
}

impl TryFrom<&Value> for PrincipalProperties {
    type Error = String;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let obj = value.as_object().ok_or("Expected JSON object")?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'id'")?;
        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingest_run_id'")?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingested_at'")?
            .to_string();

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'name'")?
            .to_string();

        let principal_type = obj
            .get("principal_type")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'principal_type'")?
            .to_string();

        let account = obj
            .get("account")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'account'")?
            .to_string();

        let path = obj
            .get("path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(PrincipalProperties {
            common: CommonProperties {
                id,
                ingest_run_id,
                ingested_at,
            },
            name,
            principal_type,
            account,
            path,
        })
    }
}

impl TryFrom<&Value> for ResourceProperties {
    type Error = String;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let obj = value.as_object().ok_or("Expected JSON object")?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'id'")?;
        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingest_run_id'")?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingested_at'")?
            .to_string();

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'name'")?
            .to_string();

        let resource_type = obj
            .get("resource_type")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'resource_type'")?
            .to_string();

        let account = obj
            .get("account")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'account'")?
            .to_string();

        let region = obj
            .get("region")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'region'")?
            .to_string();

        Ok(ResourceProperties {
            common: CommonProperties {
                id,
                ingest_run_id,
                ingested_at,
            },
            name,
            resource_type,
            account,
            region,
        })
    }
}

impl TryFrom<&Value> for PermissionProperties {
    type Error = String;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let obj = value.as_object().ok_or("Expected JSON object")?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'id'")?;
        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingest_run_id'")?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingested_at'")?
            .to_string();

        let sid = obj
            .get("sid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let effect = obj
            .get("effect")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'effect'")?
            .to_string();

        let actions = obj
            .get("actions")
            .and_then(|v| v.as_array())
            .ok_or("Missing or invalid 'actions'")?
            .iter()
            .map(|v| v.as_str().map(|s| s.to_string()).ok_or("Non-string action"))
            .collect::<Result<Vec<_>, _>>()?;

        let resources = obj
            .get("resources")
            .and_then(|v| v.as_array())
            .ok_or("Missing or invalid 'resources'")?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .ok_or("Non-string resource")
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(PermissionProperties {
            common: CommonProperties {
                id,
                ingest_run_id,
                ingested_at,
            },
            sid,
            effect,
            actions,
            resources,
        })
    }
}

impl TryFrom<&Value> for AccountProperties {
    type Error = String;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let obj = value.as_object().ok_or("Expected JSON object")?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'id'")?;
        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingest_run_id'")?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingested_at'")?
            .to_string();

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'name'")?
            .to_string();

        let organization_id = obj
            .get("organization_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(AccountProperties {
            common: CommonProperties {
                id,
                ingest_run_id,
                ingested_at,
            },
            name,
            organization_id,
        })
    }
}

impl TryFrom<&Value> for VpcProperties {
    type Error = String;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let obj = value.as_object().ok_or("Expected JSON object")?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'id'")?;
        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingest_run_id'")?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingested_at'")?
            .to_string();

        let cidr_block = obj
            .get("cidr_block")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'cidr_block'")?
            .to_string();

        let region = obj
            .get("region")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'region'")?
            .to_string();

        let is_default = obj
            .get("is_default")
            .and_then(|v| v.as_bool())
            .ok_or("Missing or invalid 'is_default'")?;

        Ok(VpcProperties {
            common: CommonProperties {
                id,
                ingest_run_id,
                ingested_at,
            },
            cidr_block,
            region,
            is_default,
        })
    }
}

impl TryFrom<&Value> for IamGroupProperties {
    type Error = String;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let obj = value.as_object().ok_or("Expected JSON object")?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'id'")?;
        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingest_run_id'")?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingested_at'")?
            .to_string();

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'name'")?
            .to_string();

        let account = obj
            .get("account")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'account'")?
            .to_string();

        let path = obj
            .get("path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(IamGroupProperties {
            common: CommonProperties {
                id,
                ingest_run_id,
                ingested_at,
            },
            name,
            account,
            path,
        })
    }
}

impl TryFrom<&Value> for KmsKeyProperties {
    type Error = String;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let obj = value.as_object().ok_or("Expected JSON object")?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'id'")?;
        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingest_run_id'")?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingested_at'")?
            .to_string();

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'name'")?
            .to_string();

        let account = obj
            .get("account")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'account'")?
            .to_string();

        let region = obj
            .get("region")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'region'")?
            .to_string();

        Ok(KmsKeyProperties {
            common: CommonProperties {
                id,
                ingest_run_id,
                ingested_at,
            },
            name,
            account,
            region,
        })
    }
}

impl TryFrom<&Value> for AccessKeyProperties {
    type Error = String;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let obj = value.as_object().ok_or("Expected JSON object")?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'id'")?;
        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingest_run_id'")?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingested_at'")?
            .to_string();

        let access_key_id = obj
            .get("access_key_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'access_key_id'")?
            .to_string();

        let account = obj
            .get("account")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'account'")?
            .to_string();

        let status = obj
            .get("status")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'status'")?
            .to_string();

        Ok(AccessKeyProperties {
            common: CommonProperties {
                id,
                ingest_run_id,
                ingested_at,
            },
            access_key_id,
            account,
            status,
        })
    }
}

impl TryFrom<&Value> for FederatedProviderProperties {
    type Error = String;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let obj = value.as_object().ok_or("Expected JSON object")?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'id'")?;
        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingest_run_id'")?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ingested_at'")?
            .to_string();

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'name'")?
            .to_string();

        let account = obj
            .get("account")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'account'")?
            .to_string();

        let provider_type = obj
            .get("provider_type")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'provider_type'")?
            .to_string();

        Ok(FederatedProviderProperties {
            common: CommonProperties {
                id,
                ingest_run_id,
                ingested_at,
            },
            name,
            account,
            provider_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_arn() -> crate::arn::Arn {
        crate::arn::Arn::parse("arn:aws:iam::123456789012:user/test").expect("Valid ARN")
    }

    #[test]
    fn test_principal_roundtrip() {
        let arn = create_test_arn();
        let props = PrincipalProperties {
            common: CommonProperties {
                id: arn,
                ingest_run_id: "uuid-123".to_string(),
                ingested_at: "2026-05-22T10:30:00Z".to_string(),
            },
            name: "alice".to_string(),
            principal_type: "User".to_string(),
            account: "123456789012".to_string(),
            path: Some("/engineering/".to_string()),
        };

        let value = Value::from(&props);
        let deserialized = PrincipalProperties::try_from(&value).expect("Deserialization failed");

        assert_eq!(props, deserialized);
    }

    #[test]
    fn test_resource_roundtrip() {
        let arn = create_test_arn();
        let props = ResourceProperties {
            common: CommonProperties {
                id: arn,
                ingest_run_id: "uuid-456".to_string(),
                ingested_at: "2026-05-22T11:00:00Z".to_string(),
            },
            name: "my-bucket".to_string(),
            resource_type: "s3:bucket".to_string(),
            account: "123456789012".to_string(),
            region: "us-east-1".to_string(),
        };

        let value = Value::from(&props);
        let deserialized = ResourceProperties::try_from(&value).expect("Deserialization failed");

        assert_eq!(props, deserialized);
    }

    #[test]
    fn test_permission_roundtrip() {
        let arn = create_test_arn();
        let props = PermissionProperties {
            common: CommonProperties {
                id: arn,
                ingest_run_id: "uuid-789".to_string(),
                ingested_at: "2026-05-22T12:00:00Z".to_string(),
            },
            sid: Some("AllowS3".to_string()),
            effect: "Allow".to_string(),
            actions: vec!["s3:GetObject".to_string()],
            resources: vec!["arn:aws:s3:::bucket".to_string()],
        };

        let value = Value::from(&props);
        let deserialized = PermissionProperties::try_from(&value).expect("Deserialization failed");

        assert_eq!(props, deserialized);
    }

    #[test]
    fn test_node_properties_roundtrip() {
        let arn = create_test_arn();
        let props = PrincipalProperties {
            common: CommonProperties {
                id: arn,
                ingest_run_id: "uuid-abc".to_string(),
                ingested_at: "2026-05-22T13:00:00Z".to_string(),
            },
            name: "bob".to_string(),
            principal_type: "Role".to_string(),
            account: "123456789012".to_string(),
            path: None,
        };

        let node_props = NodeProperties::Principal(props.clone());
        let label = node_props.label();

        let value = Value::from(&props);
        let deserialized =
            NodeProperties::try_from((&label, value)).expect("Deserialization failed");

        match deserialized {
            NodeProperties::Principal(inner) => assert_eq!(inner, props),
            _ => panic!("Expected Principal variant"),
        }
    }
}
