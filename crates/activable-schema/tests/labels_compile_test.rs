//! Compile tests for new label structs and their derives.

use activable_schema::{
    BucketProperties, CommonProperties, KmsKeyExtendedProperties, PolicyProperties,
    WildcardPrincipalProperties,
};

#[test]
fn new_labels_have_required_fields() {
    let common = CommonProperties {
        id: activable_schema::Arn {
            partition: "aws".to_string(),
            service: "iam".to_string(),
            region: "us-east-1".to_string(),
            account: "123456789012".to_string(),
            resource: "bucket/my-bucket".to_string(),
        },
        ingest_run_id: "run-123".to_string(),
        ingested_at: "2026-05-24T10:00:00Z".to_string(),
    };

    let _bucket = BucketProperties {
        common: common.clone(),
        name: "my-bucket".to_string(),
        region: "us-east-1".to_string(),
        account_id: "123456789012".to_string(),
        created_at: Some("2026-05-20T00:00:00Z".to_string()),
    };

    let _key = KmsKeyExtendedProperties {
        common: common.clone(),
        key_id: "abc-def-123".to_string(),
        region: "us-east-1".to_string(),
        account_id: "123456789012".to_string(),
        key_usage: Some("ENCRYPT_DECRYPT".to_string()),
        key_state: Some("Enabled".to_string()),
    };

    let _policy = PolicyProperties {
        common: common.clone(),
        name: "MyPolicy".to_string(),
        document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
        version_id: Some("v2".to_string()),
        source: "managed".to_string(),
    };

    let _wildcard = WildcardPrincipalProperties {
        common: common.clone(),
    };
}

#[test]
fn bucket_properties_clone() {
    let common = CommonProperties {
        id: activable_schema::Arn {
            partition: "aws".to_string(),
            service: "iam".to_string(),
            region: "us-east-1".to_string(),
            account: "123456789012".to_string(),
            resource: "bucket/my-bucket".to_string(),
        },
        ingest_run_id: "run-123".to_string(),
        ingested_at: "2026-05-24T10:00:00Z".to_string(),
    };

    let bucket = BucketProperties {
        common,
        name: "my-bucket".to_string(),
        region: "us-east-1".to_string(),
        account_id: "123456789012".to_string(),
        created_at: None,
    };

    let cloned = bucket.clone();
    assert_eq!(cloned.name, bucket.name);
    assert_eq!(cloned.region, bucket.region);
}

#[test]
fn policy_properties_debug() {
    let common = CommonProperties {
        id: activable_schema::Arn {
            partition: "aws".to_string(),
            service: "iam".to_string(),
            region: "us-east-1".to_string(),
            account: "123456789012".to_string(),
            resource: "policy/MyPolicy".to_string(),
        },
        ingest_run_id: "run-123".to_string(),
        ingested_at: "2026-05-24T10:00:00Z".to_string(),
    };

    let policy = PolicyProperties {
        common,
        name: "MyPolicy".to_string(),
        document: "{}".to_string(),
        version_id: Some("v1".to_string()),
        source: "inline".to_string(),
    };

    let debug_str = format!("{:?}", policy);
    assert!(debug_str.contains("PolicyProperties"));
    assert!(debug_str.contains("MyPolicy"));
}

#[test]
fn kms_key_extended_properties_equality() {
    let common1 = CommonProperties {
        id: activable_schema::Arn {
            partition: "aws".to_string(),
            service: "kms".to_string(),
            region: "us-east-1".to_string(),
            account: "123456789012".to_string(),
            resource: "key/abc-def".to_string(),
        },
        ingest_run_id: "run-123".to_string(),
        ingested_at: "2026-05-24T10:00:00Z".to_string(),
    };

    let common2 = common1.clone();

    let key1 = KmsKeyExtendedProperties {
        common: common1,
        key_id: "abc-def-123".to_string(),
        region: "us-east-1".to_string(),
        account_id: "123456789012".to_string(),
        key_usage: Some("ENCRYPT_DECRYPT".to_string()),
        key_state: Some("Enabled".to_string()),
    };

    let key2 = KmsKeyExtendedProperties {
        common: common2,
        key_id: "abc-def-123".to_string(),
        region: "us-east-1".to_string(),
        account_id: "123456789012".to_string(),
        key_usage: Some("ENCRYPT_DECRYPT".to_string()),
        key_state: Some("Enabled".to_string()),
    };

    assert_eq!(key1, key2);
}
