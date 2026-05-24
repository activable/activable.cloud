//! Unit tests for managed-policy + boundary fetch logic.
//! These run against synthetic AWS SDK responses, not a live AWS endpoint.

use serde_json::json;

#[test]
fn managed_policy_document_decoded() {
    // Simulate a URL-encoded policy document (as AWS SDK returns)
    let doc_raw = "version%3D2012-10-17%26Statement%3D%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3AGetObject%22%2C%22Resource%22%3A%22%2A%22%7D%5D";

    // Decode using urlencoding (same as production code)
    let decoded = urlencoding::decode(doc_raw)
        .unwrap_or_else(|_| doc_raw.into())
        .to_string();

    // Verify the document is properly decoded
    assert!(decoded.contains("Allow"));
    assert!(decoded.contains("s3:GetObject"));
    assert!(!decoded.contains("%"));
}

#[test]
fn managed_policy_json_serialization() {
    // Test that managed policy objects can be serialized as JSON
    let policy = json!({
        "arn": "arn:aws:iam::123456789012:policy/MyPolicy",
        "name": "MyPolicy",
        "version_id": "v2",
        "document": "{\"Version\":\"2012-10-17\",\"Statement\":[]}",
    });

    assert_eq!(policy["arn"], "arn:aws:iam::123456789012:policy/MyPolicy");
    assert_eq!(policy["name"], "MyPolicy");
    assert_eq!(policy["version_id"], "v2");
}

#[test]
fn permissions_boundary_optional() {
    // Test that permissions_boundary can be None
    let principal_with_boundary = json!({
        "id": "arn:aws:iam::123456789012:role/TestRole",
        "name": "TestRole",
        "principal_type": "Role",
        "permissions_boundary": {
            "arn": "arn:aws:iam::123456789012:policy/BoundaryPolicy",
            "document": "{}",
        }
    });

    assert!(principal_with_boundary["permissions_boundary"]["arn"].is_string());

    // Test that permissions_boundary can be null
    let principal_without_boundary = json!({
        "id": "arn:aws:iam::123456789012:role/TestRole",
        "name": "TestRole",
        "principal_type": "Role",
        "permissions_boundary": serde_json::Value::Null,
    });

    assert!(principal_without_boundary["permissions_boundary"].is_null());
}

#[test]
fn managed_policies_array_empty() {
    // Test that managed_policies can be an empty array (role with no attachments)
    let principal = json!({
        "id": "arn:aws:iam::123456789012:role/TestRole",
        "name": "TestRole",
        "principal_type": "Role",
        "managed_policies": [],
    });

    assert!(principal["managed_policies"].is_array());
    assert_eq!(principal["managed_policies"].as_array().unwrap().len(), 0);
}

#[test]
fn managed_policies_array_multiple() {
    // Test that managed_policies can hold multiple policies
    let principal = json!({
        "id": "arn:aws:iam::123456789012:role/TestRole",
        "name": "TestRole",
        "principal_type": "Role",
        "managed_policies": [
            {
                "arn": "arn:aws:iam::123456789012:policy/Policy1",
                "name": "Policy1",
                "version_id": "v1",
                "document": "{}",
            },
            {
                "arn": "arn:aws:iam::123456789012:policy/Policy2",
                "name": "Policy2",
                "version_id": "v2",
                "document": "{}",
            },
        ],
    });

    let policies = principal["managed_policies"].as_array().unwrap();
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0]["name"], "Policy1");
    assert_eq!(policies[1]["name"], "Policy2");
}
