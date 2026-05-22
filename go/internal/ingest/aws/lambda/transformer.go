package lambda

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	ingest "github.com/activable-cloud/activable.cloud/go/internal/ingest"
)

// FunctionToResourceSpec transforms a Lambda Function to a Resource spec.
// ARN is provided directly by the SDK (no construction needed).
func FunctionToResourceSpec(function types.FunctionConfiguration) ingest.ResourceSpec {
	functionName := ""
	if function.FunctionName != nil {
		functionName = *function.FunctionName
	}

	functionARN := ""
	if function.FunctionArn != nil {
		functionARN = *function.FunctionArn
	}

	spec := ingest.ResourceSpec{
		Label: "Resource",
		ID:    functionARN,
		Properties: map[string]interface{}{
			"function_name": functionName,
			"runtime":       string(function.Runtime),
			"handler":       stringValue(function.Handler),
			"memory_size":   function.MemorySize,
			"timeout":       function.Timeout,
			"service":       "lambda",
			"type":          "Function",
			"last_modified": stringValue(function.LastModified),
		},
	}

	// Add edge to execution role if present
	if function.Role != nil {
		roleARN := *function.Role
		spec.Edges = append(spec.Edges, ingest.EdgeSpec{
			FromID:   functionARN,
			TargetID: roleARN,
			EdgeType: "CanAssume",
			Properties: map[string]interface{}{
				"source": functionARN,
			},
		})
	}

	return spec
}

// FunctionPolicyToPermissionSpec transforms Lambda function policy statements into Permission specs.
// Parses the policy JSON and extracts statements.
func FunctionPolicyToPermissionSpec(functionName string, policyJSON string) ([]ingest.ResourceSpec, error) {
	var policyDoc map[string]interface{}
	if err := json.Unmarshal([]byte(policyJSON), &policyDoc); err != nil {
		return nil, fmt.Errorf("failed to parse function policy JSON: %w", err)
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

				// Extract resources
				resources := parseStringOrStringArray(stmtMap["Resource"])

				// Create Permission spec
				spec := PolicyStatementToPermissionSpec(functionName, sid, actions, resources)
				specs = append(specs, spec)
			}
		}
	}

	return specs, nil
}

// PolicyStatementToPermissionSpec transforms a single Lambda policy statement to a Permission node.
func PolicyStatementToPermissionSpec(functionName string, sid string, actions []string, resources []string) ingest.ResourceSpec {
	// Create a canonical ID for this permission node: functionName:sid
	permissionID := fmt.Sprintf("arn:aws:lambda:*:*:function:%s:permission:%s", functionName, sid)

	spec := ingest.ResourceSpec{
		Label: "Permission",
		ID:    permissionID,
		Properties: map[string]interface{}{
			"function_name": functionName,
			"sid":           sid,
			"actions":       actions,
			"resources":     resources,
			"service":       "lambda",
		},
	}

	// Create Contains edges from Permission to each Resource in the statement.
	// Filter out wildcards.
	for _, resource := range resources {
		if resource != "" && resource != "*" {
			edge := ingest.EdgeSpec{
				FromID:   permissionID,
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

// Helper functions

// stringValue safely extracts string pointers
func stringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

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

// NormalizeRoleARN ensures the IAM role ARN is well-formed.
// Validates that it follows the standard IAM role ARN format.
func NormalizeRoleARN(roleARN string) (string, error) {
	if !strings.HasPrefix(roleARN, "arn:aws:iam::") {
		return "", fmt.Errorf("invalid IAM role ARN format: %s", roleARN)
	}
	return roleARN, nil
}
