package lambda

import (
	"encoding/json"
	"fmt"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
)

// FunctionInfo holds metadata about a Lambda function.
type FunctionInfo struct {
	FunctionName string
	FunctionArn  string
	Role         string
}

// FunctionToResourceSpec transforms a Lambda function to a ResourceSpec with Resource label.
func FunctionToResourceSpec(arn, functionName, accountID string) ingest.ResourceSpec {
	return ingest.ResourceSpec{
		Label: "Resource",
		ID:    arn,
		Properties: map[string]interface{}{
			"resource_type":  "lambda:function",
			"function_name":  functionName,
			"account_id":     accountID,
		},
		Edges: []ingest.EdgeSpec{},
	}
}

// PolicyDocument represents a parsed IAM/resource policy document.
type PolicyDocument struct {
	Statement []Statement `json:"Statement"`
}

// Statement represents a single statement in a policy document.
type Statement struct {
	Sid       string      `json:"Sid"`
	Effect    string      `json:"Effect"`
	Resource  interface{} `json:"Resource"` // Can be string or []string
	Action    interface{} `json:"Action"`   // Can be string or []string
	Principal interface{} `json:"Principal"` // For resource-based policies
}

// ParsePolicyDocument parses a JSON policy document string.
func ParsePolicyDocument(policyJSON string) (PolicyDocument, error) {
	var doc PolicyDocument
	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return PolicyDocument{}, fmt.Errorf("failed to parse policy JSON: %w", err)
	}
	return doc, nil
}

// StringArrayFromInterface converts a value that can be either string or []string to []string.
func StringArrayFromInterface(val interface{}) []string {
	switch v := val.(type) {
	case string:
		return []string{v}
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	default:
		return []string{}
	}
}

// IsValidNodeID checks if a string is a valid node ID (not a wildcard).
func IsValidNodeID(id string) bool {
	return id != "" && id != "*"
}
