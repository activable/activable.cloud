//! Serialization and deserialization for AGE graph types.
//!
//! Implements conversion between typed property structs and serde_json::Value
//! for storage in AGE's agtype property bags.

use crate::labels::NodeLabel;
use crate::properties::*;

/// Serializes PrincipalProperties to JSON.
impl From<&PrincipalProperties> for serde_json::Value {
    fn from(props: &PrincipalProperties) -> Self {
        serde_json::json!({
            "id": props.common.id.to_string(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "name": props.name,
            "principal_type": props.principal_type,
            "account": props.account,
            "path": props.path,
        })
    }
}

/// Deserializes PrincipalProperties from JSON.
impl TryFrom<(&NodeLabel, serde_json::Value)> for PrincipalProperties {
    type Error = String;

    fn try_from((label, value): (&NodeLabel, serde_json::Value)) -> Result<Self, Self::Error> {
        if !matches!(label, NodeLabel::Principal) {
            return Err("Expected NodeLabel::Principal".to_string());
        }

        let obj = value
            .as_object()
            .ok_or_else(|| "Value must be a JSON object".to_string())?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'id' field".to_string())?;

        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingest_run_id' field".to_string())?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingested_at' field".to_string())?
            .to_string();

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'name' field".to_string())?
            .to_string();

        let principal_type = obj
            .get("principal_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'principal_type' field".to_string())?
            .to_string();

        let account = obj
            .get("account")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'account' field".to_string())?
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

/// Serializes ResourceProperties to JSON.
impl From<&ResourceProperties> for serde_json::Value {
    fn from(props: &ResourceProperties) -> Self {
        serde_json::json!({
            "id": props.common.id.to_string(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "name": props.name,
            "resource_type": props.resource_type,
            "account": props.account,
            "region": props.region,
        })
    }
}

/// Deserializes ResourceProperties from JSON.
impl TryFrom<(&NodeLabel, serde_json::Value)> for ResourceProperties {
    type Error = String;

    fn try_from((label, value): (&NodeLabel, serde_json::Value)) -> Result<Self, Self::Error> {
        if !matches!(label, NodeLabel::Resource) {
            return Err("Expected NodeLabel::Resource".to_string());
        }

        let obj = value
            .as_object()
            .ok_or_else(|| "Value must be a JSON object".to_string())?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'id' field".to_string())?;

        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingest_run_id' field".to_string())?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingested_at' field".to_string())?
            .to_string();

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'name' field".to_string())?
            .to_string();

        let resource_type = obj
            .get("resource_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'resource_type' field".to_string())?
            .to_string();

        let account = obj
            .get("account")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'account' field".to_string())?
            .to_string();

        let region = obj
            .get("region")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'region' field".to_string())?
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

/// Serializes PermissionProperties to JSON.
impl From<&PermissionProperties> for serde_json::Value {
    fn from(props: &PermissionProperties) -> Self {
        serde_json::json!({
            "id": props.common.id.to_string(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "sid": props.sid,
            "effect": props.effect,
            "actions": props.actions,
            "resources": props.resources,
            "conditions": props.conditions,
        })
    }
}

/// Deserializes PermissionProperties from JSON.
impl TryFrom<(&NodeLabel, serde_json::Value)> for PermissionProperties {
    type Error = String;

    fn try_from((label, value): (&NodeLabel, serde_json::Value)) -> Result<Self, Self::Error> {
        if !matches!(label, NodeLabel::Permission) {
            return Err("Expected NodeLabel::Permission".to_string());
        }

        let obj = value
            .as_object()
            .ok_or_else(|| "Value must be a JSON object".to_string())?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'id' field".to_string())?;

        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingest_run_id' field".to_string())?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingested_at' field".to_string())?
            .to_string();

        let sid = obj
            .get("sid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let effect = obj
            .get("effect")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'effect' field".to_string())?
            .to_string();

        let actions = obj
            .get("actions")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "Missing or invalid 'actions' field".to_string())?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| "Invalid action in 'actions' array".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;

        let resources = obj
            .get("resources")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "Missing or invalid 'resources' field".to_string())?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| "Invalid resource in 'resources' array".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;

        let conditions = obj.get("conditions").and_then(|v| {
            if v.is_null() {
                None
            } else if let Some(s) = v.as_str() {
                Some(s.to_string())
            } else {
                // If conditions is a nested object, serialize it to string
                Some(v.to_string())
            }
        });

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
            conditions,
        })
    }
}

/// Serializes AccountProperties to JSON.
impl From<&AccountProperties> for serde_json::Value {
    fn from(props: &AccountProperties) -> Self {
        serde_json::json!({
            "id": props.common.id.to_string(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "name": props.name,
            "organization_id": props.organization_id,
        })
    }
}

/// Deserializes AccountProperties from JSON.
impl TryFrom<(&NodeLabel, serde_json::Value)> for AccountProperties {
    type Error = String;

    fn try_from((label, value): (&NodeLabel, serde_json::Value)) -> Result<Self, Self::Error> {
        if !matches!(label, NodeLabel::Account) {
            return Err("Expected NodeLabel::Account".to_string());
        }

        let obj = value
            .as_object()
            .ok_or_else(|| "Value must be a JSON object".to_string())?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'id' field".to_string())?;

        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingest_run_id' field".to_string())?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingested_at' field".to_string())?
            .to_string();

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'name' field".to_string())?
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

/// Serializes VpcProperties to JSON.
impl From<&VpcProperties> for serde_json::Value {
    fn from(props: &VpcProperties) -> Self {
        serde_json::json!({
            "id": props.common.id.to_string(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "cidr_block": props.cidr_block,
            "region": props.region,
            "is_default": props.is_default,
        })
    }
}

/// Deserializes VpcProperties from JSON.
impl TryFrom<(&NodeLabel, serde_json::Value)> for VpcProperties {
    type Error = String;

    fn try_from((label, value): (&NodeLabel, serde_json::Value)) -> Result<Self, Self::Error> {
        if !matches!(label, NodeLabel::Vpc) {
            return Err("Expected NodeLabel::Vpc".to_string());
        }

        let obj = value
            .as_object()
            .ok_or_else(|| "Value must be a JSON object".to_string())?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'id' field".to_string())?;

        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingest_run_id' field".to_string())?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingested_at' field".to_string())?
            .to_string();

        let cidr_block = obj
            .get("cidr_block")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'cidr_block' field".to_string())?
            .to_string();

        let region = obj
            .get("region")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'region' field".to_string())?
            .to_string();

        let is_default = obj
            .get("is_default")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| "Missing or invalid 'is_default' field".to_string())?;

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

/// Serializes IamGroupProperties to JSON.
impl From<&IamGroupProperties> for serde_json::Value {
    fn from(props: &IamGroupProperties) -> Self {
        serde_json::json!({
            "id": props.common.id.to_string(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "name": props.name,
            "path": props.path,
        })
    }
}

/// Deserializes IamGroupProperties from JSON.
impl TryFrom<(&NodeLabel, serde_json::Value)> for IamGroupProperties {
    type Error = String;

    fn try_from((label, value): (&NodeLabel, serde_json::Value)) -> Result<Self, Self::Error> {
        if !matches!(label, NodeLabel::IamGroup) {
            return Err("Expected NodeLabel::IamGroup".to_string());
        }

        let obj = value
            .as_object()
            .ok_or_else(|| "Value must be a JSON object".to_string())?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'id' field".to_string())?;

        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingest_run_id' field".to_string())?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingested_at' field".to_string())?
            .to_string();

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'name' field".to_string())?
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
            path,
        })
    }
}

/// Serializes KmsKeyProperties to JSON.
impl From<&KmsKeyProperties> for serde_json::Value {
    fn from(props: &KmsKeyProperties) -> Self {
        serde_json::json!({
            "id": props.common.id.to_string(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "alias": props.alias,
            "key_state": props.key_state,
        })
    }
}

/// Deserializes KmsKeyProperties from JSON.
impl TryFrom<(&NodeLabel, serde_json::Value)> for KmsKeyProperties {
    type Error = String;

    fn try_from((label, value): (&NodeLabel, serde_json::Value)) -> Result<Self, Self::Error> {
        if !matches!(label, NodeLabel::KmsKey) {
            return Err("Expected NodeLabel::KmsKey".to_string());
        }

        let obj = value
            .as_object()
            .ok_or_else(|| "Value must be a JSON object".to_string())?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'id' field".to_string())?;

        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingest_run_id' field".to_string())?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingested_at' field".to_string())?
            .to_string();

        let alias = obj
            .get("alias")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let key_state = obj
            .get("key_state")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'key_state' field".to_string())?
            .to_string();

        Ok(KmsKeyProperties {
            common: CommonProperties {
                id,
                ingest_run_id,
                ingested_at,
            },
            alias,
            key_state,
        })
    }
}

/// Serializes AccessKeyProperties to JSON.
impl From<&AccessKeyProperties> for serde_json::Value {
    fn from(props: &AccessKeyProperties) -> Self {
        serde_json::json!({
            "id": props.common.id.to_string(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "status": props.status,
            "created_at": props.created_at,
        })
    }
}

/// Deserializes AccessKeyProperties from JSON.
impl TryFrom<(&NodeLabel, serde_json::Value)> for AccessKeyProperties {
    type Error = String;

    fn try_from((label, value): (&NodeLabel, serde_json::Value)) -> Result<Self, Self::Error> {
        if !matches!(label, NodeLabel::AccessKey) {
            return Err("Expected NodeLabel::AccessKey".to_string());
        }

        let obj = value
            .as_object()
            .ok_or_else(|| "Value must be a JSON object".to_string())?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'id' field".to_string())?;

        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingest_run_id' field".to_string())?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingested_at' field".to_string())?
            .to_string();

        let status = obj
            .get("status")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'status' field".to_string())?
            .to_string();

        let created_at = obj
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(AccessKeyProperties {
            common: CommonProperties {
                id,
                ingest_run_id,
                ingested_at,
            },
            status,
            created_at,
        })
    }
}

/// Serializes FederatedProviderProperties to JSON.
impl From<&FederatedProviderProperties> for serde_json::Value {
    fn from(props: &FederatedProviderProperties) -> Self {
        serde_json::json!({
            "id": props.common.id.to_string(),
            "ingest_run_id": props.common.ingest_run_id,
            "ingested_at": props.common.ingested_at,
            "name": props.name,
            "provider_type": props.provider_type,
        })
    }
}

/// Deserializes FederatedProviderProperties from JSON.
impl TryFrom<(&NodeLabel, serde_json::Value)> for FederatedProviderProperties {
    type Error = String;

    fn try_from((label, value): (&NodeLabel, serde_json::Value)) -> Result<Self, Self::Error> {
        if !matches!(label, NodeLabel::FederatedProvider) {
            return Err("Expected NodeLabel::FederatedProvider".to_string());
        }

        let obj = value
            .as_object()
            .ok_or_else(|| "Value must be a JSON object".to_string())?;

        let id_str = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'id' field".to_string())?;

        let id = crate::arn::Arn::parse(id_str).map_err(|e| format!("Invalid ARN: {}", e))?;

        let ingest_run_id = obj
            .get("ingest_run_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingest_run_id' field".to_string())?
            .to_string();

        let ingested_at = obj
            .get("ingested_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'ingested_at' field".to_string())?
            .to_string();

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'name' field".to_string())?
            .to_string();

        let provider_type = obj
            .get("provider_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing or invalid 'provider_type' field".to_string())?
            .to_string();

        Ok(FederatedProviderProperties {
            common: CommonProperties {
                id,
                ingest_run_id,
                ingested_at,
            },
            name,
            provider_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arn::Arn;

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
    fn test_principal_round_trip() {
        let props = PrincipalProperties {
            common: CommonProperties {
                id: sample_arn(),
                ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ingested_at: "2026-05-22T10:30:00Z".to_string(),
            },
            name: "Admin".to_string(),
            principal_type: "Role".to_string(),
            account: "123456789012".to_string(),
            path: Some("/service-roles/".to_string()),
        };

        let json: serde_json::Value = (&props).into();
        let restored = PrincipalProperties::try_from((&NodeLabel::Principal, json)).unwrap();

        assert_eq!(restored, props);
    }

    #[test]
    fn test_resource_round_trip() {
        let props = ResourceProperties {
            common: CommonProperties {
                id: sample_arn(),
                ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ingested_at: "2026-05-22T10:30:00Z".to_string(),
            },
            name: "my-bucket".to_string(),
            resource_type: "s3:bucket".to_string(),
            account: "123456789012".to_string(),
            region: "us-east-1".to_string(),
        };

        let json: serde_json::Value = (&props).into();
        let restored = ResourceProperties::try_from((&NodeLabel::Resource, json)).unwrap();

        assert_eq!(restored, props);
    }

    #[test]
    fn test_permission_round_trip() {
        let props = PermissionProperties {
            common: CommonProperties {
                id: sample_arn(),
                ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ingested_at: "2026-05-22T10:30:00Z".to_string(),
            },
            sid: Some("AllowS3Read".to_string()),
            effect: "Allow".to_string(),
            actions: vec!["s3:GetObject".to_string()],
            resources: vec!["arn:aws:s3:::my-bucket/*".to_string()],
            conditions: None,
        };

        let json: serde_json::Value = (&props).into();
        let restored = PermissionProperties::try_from((&NodeLabel::Permission, json)).unwrap();

        assert_eq!(restored, props);
    }

    #[test]
    fn test_account_round_trip() {
        let props = AccountProperties {
            common: CommonProperties {
                id: sample_arn(),
                ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ingested_at: "2026-05-22T10:30:00Z".to_string(),
            },
            name: "Production".to_string(),
            organization_id: Some("o-abc123def456".to_string()),
        };

        let json: serde_json::Value = (&props).into();
        let restored = AccountProperties::try_from((&NodeLabel::Account, json)).unwrap();

        assert_eq!(restored, props);
    }

    #[test]
    fn test_vpc_round_trip() {
        let props = VpcProperties {
            common: CommonProperties {
                id: sample_arn(),
                ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ingested_at: "2026-05-22T10:30:00Z".to_string(),
            },
            cidr_block: "10.0.0.0/16".to_string(),
            region: "us-west-2".to_string(),
            is_default: false,
        };

        let json: serde_json::Value = (&props).into();
        let restored = VpcProperties::try_from((&NodeLabel::Vpc, json)).unwrap();

        assert_eq!(restored, props);
    }

    #[test]
    fn test_iam_group_round_trip() {
        let props = IamGroupProperties {
            common: CommonProperties {
                id: sample_arn(),
                ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ingested_at: "2026-05-22T10:30:00Z".to_string(),
            },
            name: "Developers".to_string(),
            path: Some("/engineering/".to_string()),
        };

        let json: serde_json::Value = (&props).into();
        let restored = IamGroupProperties::try_from((&NodeLabel::IamGroup, json)).unwrap();

        assert_eq!(restored, props);
    }

    #[test]
    fn test_kms_key_round_trip() {
        let props = KmsKeyProperties {
            common: CommonProperties {
                id: sample_arn(),
                ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ingested_at: "2026-05-22T10:30:00Z".to_string(),
            },
            alias: Some("alias/my-key".to_string()),
            key_state: "Enabled".to_string(),
        };

        let json: serde_json::Value = (&props).into();
        let restored = KmsKeyProperties::try_from((&NodeLabel::KmsKey, json)).unwrap();

        assert_eq!(restored, props);
    }

    #[test]
    fn test_access_key_round_trip() {
        let props = AccessKeyProperties {
            common: CommonProperties {
                id: sample_arn(),
                ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ingested_at: "2026-05-22T10:30:00Z".to_string(),
            },
            status: "Active".to_string(),
            created_at: Some("2026-01-15T08:00:00Z".to_string()),
        };

        let json: serde_json::Value = (&props).into();
        let restored = AccessKeyProperties::try_from((&NodeLabel::AccessKey, json)).unwrap();

        assert_eq!(restored, props);
    }

    #[test]
    fn test_federated_provider_round_trip() {
        let props = FederatedProviderProperties {
            common: CommonProperties {
                id: sample_arn(),
                ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ingested_at: "2026-05-22T10:30:00Z".to_string(),
            },
            name: "Okta".to_string(),
            provider_type: "SAML".to_string(),
        };

        let json: serde_json::Value = (&props).into();
        let restored =
            FederatedProviderProperties::try_from((&NodeLabel::FederatedProvider, json)).unwrap();

        assert_eq!(restored, props);
    }

    #[test]
    fn test_principal_deserialize_wrong_label() {
        let json = serde_json::json!({"id": "arn:aws:iam::123456789012:user/admin"});
        let result = PrincipalProperties::try_from((&NodeLabel::Resource, json));
        assert!(result.is_err());
    }

    #[test]
    fn test_permission_with_conditions_round_trip() {
        let props = PermissionProperties {
            common: CommonProperties {
                id: sample_arn(),
                ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ingested_at: "2026-05-22T10:30:00Z".to_string(),
            },
            sid: Some("ConditionalAllow".to_string()),
            effect: "Allow".to_string(),
            actions: vec!["s3:GetObject".to_string()],
            resources: vec!["arn:aws:s3:::bucket/*".to_string()],
            conditions: Some(r#"{"StringEquals":{"aws:SourceVpc":"vpc-123"}}"#.to_string()),
        };

        let json: serde_json::Value = (&props).into();
        let restored = PermissionProperties::try_from((&NodeLabel::Permission, json)).unwrap();

        assert_eq!(restored, props);
    }

    #[test]
    fn test_principal_missing_required_field() {
        let json = serde_json::json!({
            "id": "arn:aws:iam::123456789012:user/admin",
            "ingest_run_id": "550e8400-e29b-41d4-a716-446655440000",
            "ingested_at": "2026-05-22T10:30:00Z",
            // missing "name"
            "principal_type": "User",
            "account": "123456789012",
        });

        let result = PrincipalProperties::try_from((&NodeLabel::Principal, json));
        assert!(result.is_err());
    }

    #[test]
    fn test_resource_invalid_arn() {
        let json = serde_json::json!({
            "id": "not-an-arn",
            "ingest_run_id": "550e8400-e29b-41d4-a716-446655440000",
            "ingested_at": "2026-05-22T10:30:00Z",
            "name": "bucket",
            "resource_type": "s3:bucket",
            "account": "123456789012",
            "region": "us-east-1",
        });

        let result = ResourceProperties::try_from((&NodeLabel::Resource, json));
        assert!(result.is_err());
    }

    #[test]
    fn test_vpc_not_default() {
        let props = VpcProperties {
            common: CommonProperties {
                id: sample_arn(),
                ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ingested_at: "2026-05-22T10:30:00Z".to_string(),
            },
            cidr_block: "10.0.0.0/16".to_string(),
            region: "us-west-2".to_string(),
            is_default: false,
        };

        let json: serde_json::Value = (&props).into();
        assert_eq!(json["is_default"], false);
    }

    #[test]
    fn test_principal_json_all_fields_present() {
        let props = PrincipalProperties {
            common: CommonProperties {
                id: sample_arn(),
                ingest_run_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ingested_at: "2026-05-22T10:30:00Z".to_string(),
            },
            name: "Admin".to_string(),
            principal_type: "Role".to_string(),
            account: "123456789012".to_string(),
            path: Some("/service-roles/".to_string()),
        };

        let json: serde_json::Value = (&props).into();
        let obj = json.as_object().unwrap();

        assert!(obj.contains_key("id"));
        assert!(obj.contains_key("ingest_run_id"));
        assert!(obj.contains_key("ingested_at"));
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("principal_type"));
        assert!(obj.contains_key("account"));
        assert!(obj.contains_key("path"));
    }
}
