package s3

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	ingest "github.com/activable-cloud/activable.cloud/go/internal/ingest"
)

// BucketToResourceSpec transforms an S3 Bucket to a Resource ResourceSpec.
// ARN is constructed as arn:aws:s3:::<bucket-name> (no region, no account).
func BucketToResourceSpec(bucket types.Bucket) ingest.ResourceSpec {
	bucketName := ""
	if bucket.Name != nil {
		bucketName = *bucket.Name
	}

	bucketARN := fmt.Sprintf("arn:aws:s3:::%s", bucketName)

	createdAtUnix := int64(0)
	if bucket.CreationDate != nil {
		createdAtUnix = bucket.CreationDate.Unix()
	}

	spec := ingest.ResourceSpec{
		Label: "Resource",
		ID:    bucketARN,
		Properties: map[string]interface{}{
			"name":       bucketName,
			"created_at": createdAtUnix,
			"service":    "s3",
			"type":       "Bucket",
		},
	}
	return spec
}

// BucketPolicyToPermissionSpec transforms bucket policy statements into Permission specs.
// Parses the policy JSON and extracts statements, emitting a Permission node per statement.
func BucketPolicyToPermissionSpec(bucketName string, policyJSON string) ([]ingest.ResourceSpec, error) {
	var policyDoc map[string]interface{}
	if err := json.Unmarshal([]byte(policyJSON), &policyDoc); err != nil {
		return nil, fmt.Errorf("failed to parse bucket policy JSON: %w", err)
	}

	var specs []ingest.ResourceSpec

	if stmts, ok := policyDoc["Statement"].([]interface{}); ok {
		for idx, stmt := range stmts {
			if stmtMap, ok := stmt.(map[string]interface{}); ok {
				// Extract SID
				sid := ""
				if sidVal, ok := stmtMap["Sid"].(string); ok {
					sid = sidVal
				} else {
					sid = fmt.Sprintf("stmt-%d", idx)
				}

				// Extract actions
				actions := parseStringOrStringArray(stmtMap["Action"])

				// Extract resources from the policy statement
				resources := parseStringOrStringArray(stmtMap["Resource"])

				// Create Permission spec
				spec := PolicyStatementToPermissionSpec(bucketName, sid, actions, resources)
				specs = append(specs, spec)
			}
		}
	}

	return specs, nil
}

// PolicyStatementToPermissionSpec transforms a single bucket policy statement to a Permission node.
func PolicyStatementToPermissionSpec(bucketName string, sid string, actions []string, resources []string) ingest.ResourceSpec {
	// Create a canonical ID for this permission node: bucketName:sid
	permissionID := fmt.Sprintf("arn:aws:s3:::%s:permission:%s", bucketName, sid)

	spec := ingest.ResourceSpec{
		Label: "Permission",
		ID:    permissionID,
		Properties: map[string]interface{}{
			"bucket_name": bucketName,
			"sid":         sid,
			"actions":     actions,
			"resources":   resources,
			"service":     "s3",
		},
	}

	// Create Contains edges from Permission to each Resource in the statement.
	// Filter out wildcards.
	for _, resource := range resources {
		if resource != "" && resource != "*" {
			edge := ingest.EdgeSpec{
				TargetID: resource,
				EdgeType: "Contains",
				Properties: map[string]interface{}{
					"source": permissionID,
				},
			}
			spec.Edges = append(spec.Edges, edge)
		}
	}

	return spec
}

// BucketLocationToRegion normalizes bucket location metadata.
// S3 returns empty string for us-east-1; this normalizes it.
// LocationConstraint is a string type alias, not a pointer.
func BucketLocationToRegion(locationConstraint string) string {
	if locationConstraint == "" {
		return "us-east-1"
	}
	return locationConstraint
}

// Helper functions

// parseStringOrStringArray parses an interface that may be a string or array of strings.
func parseStringOrStringArray(val interface{}) []string {
	var result []string
	switch v := val.(type) {
	case string:
		result = append(result, v)
	case []interface{}:
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
	}
	return result
}

// NormalizeARN ensures the ARN is well-formed for S3 buckets.
// S3 bucket ARNs have no region or account: arn:aws:s3:::bucket-name
func NormalizeARN(bucketName string) string {
	return fmt.Sprintf("arn:aws:s3:::%s", strings.TrimSpace(bucketName))
}
