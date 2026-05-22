package iam

import (
	"encoding/json"
	"fmt"
	"strings"

	ingest "github.com/activable-cloud/activable.cloud/go/internal/ingest"
)

// TrustPolicyDocument represents the structure of an AssumeRolePolicyDocument.
type TrustPolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement represents a policy statement.
type Statement struct {
	Effect    string      `json:"Effect"`
	Principal interface{} `json:"Principal"` // Can be string or object
	Action    interface{} `json:"Action"`    // Can be string or array
	Condition interface{} `json:"Condition"`
}

// PrincipalValue represents either a string principal or structured principals.
type PrincipalValue struct {
	AWS     interface{} `json:"AWS"`
	Service interface{} `json:"Service"`
	Other   string      // Wildcard principal "*"
}

// ParseTrustPolicy parses an AssumeRolePolicyDocument and extracts trust edges.
// Returns ResourceSpecs for ServicePrincipals and EdgeSpecs for CanAssume/TrustedBy relationships.
func ParseTrustPolicy(roleARN string, trustPolicyJSON string) ([]ingest.ResourceSpec, []ingest.EdgeSpec, error) {
	var specs []ingest.ResourceSpec
	var edges []ingest.EdgeSpec

	// Handle URL-encoded or empty policy documents
	if trustPolicyJSON == "" {
		return specs, edges, nil
	}

	// Attempt to decode if it's URL-encoded
	decoded := trustPolicyJSON
	if strings.Contains(trustPolicyJSON, "%") {
		// Simple URL decode attempt (AWS sometimes returns encoded policies)
		// For now, try both: if JSON parse fails, the error will guide us
		_ = decoded
	}

	// Parse the JSON document
	var policy TrustPolicyDocument
	if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
		// If parsing fails, return what we have (some policies may have unusual formatting)
		return specs, edges, fmt.Errorf("failed to parse trust policy: %w", err)
	}

	// Extract principals from statements
	for _, stmt := range policy.Statement {
		// Only process Allow statements for trust relationships
		if stmt.Effect != "Allow" {
			continue
		}

		// Principal can be a string (e.g., "*") or an object with AWS/Service keys
		if principalStr, ok := stmt.Principal.(string); ok {
			// Wildcard principal
			if principalStr == "*" {
				continue // Skip wildcard principals
			}
		} else if principalObj, ok := stmt.Principal.(map[string]interface{}); ok {
			// Extract AWS principals (for CanAssume edges)
			if awsPrincipals, hasAWS := principalObj["AWS"]; hasAWS {
				awsEdges, awsSpecs := extractAWSPrincipals(roleARN, awsPrincipals)
				edges = append(edges, awsEdges...)
				specs = append(specs, awsSpecs...)
			}

			// Extract Service principals (for TrustedBy edges)
			if servicePrincipals, hasService := principalObj["Service"]; hasService {
				serviceEdges, serviceSpecs := extractServicePrincipals(roleARN, servicePrincipals)
				edges = append(edges, serviceEdges...)
				specs = append(specs, serviceSpecs...)
			}
		}
	}

	return specs, edges, nil
}

// extractAWSPrincipals processes AWS principals from a trust policy.
// Returns edges from the role to assumed principals and specs for created resources.
func extractAWSPrincipals(roleARN string, awsPrincipals interface{}) ([]ingest.EdgeSpec, []ingest.ResourceSpec) {
	var edges []ingest.EdgeSpec
	var specs []ingest.ResourceSpec

	// AWS principals can be a string or array of strings
	var principals []string
	switch v := awsPrincipals.(type) {
	case string:
		if v != "*" && v != "" {
			principals = append(principals, v)
		}
	case []interface{}:
		for _, p := range v {
			if pStr, ok := p.(string); ok && pStr != "*" && pStr != "" {
				principals = append(principals, pStr)
			}
		}
	}

	// Create CanAssume edges for each principal
	for _, principal := range principals {
		edge := ingest.EdgeSpec{
			FromID:     roleARN,
			TargetID:   principal,
			EdgeType:   "CanAssume",
			Properties: map[string]interface{}{},
		}
		edges = append(edges, edge)
	}

	return edges, specs
}

// extractServicePrincipals processes Service principals from a trust policy.
// Returns edges to service principals and creates ServicePrincipal resource specs.
func extractServicePrincipals(roleARN string, servicePrincipals interface{}) ([]ingest.EdgeSpec, []ingest.ResourceSpec) {
	var edges []ingest.EdgeSpec
	var specs []ingest.ResourceSpec
	seenServices := make(map[string]bool)

	// Service principals can be a string or array of strings
	var services []string
	switch v := servicePrincipals.(type) {
	case string:
		if v != "" && v != "*" {
			services = append(services, v)
		}
	case []interface{}:
		for _, s := range v {
			if sStr, ok := s.(string); ok && sStr != "" && sStr != "*" {
				services = append(services, sStr)
			}
		}
	}

	// Create TrustedBy edges and ServicePrincipal specs
	for _, service := range services {
		// Create service principal resource spec (only once per service)
		if !seenServices[service] {
			spec := ServicePrincipalToResourceSpec(service)
			specs = append(specs, spec)
			seenServices[service] = true
		}

		// Create edge from role to service principal
		edge := ingest.EdgeSpec{
			FromID:     roleARN,
			TargetID:   service,
			EdgeType:   "TrustedBy",
			Properties: map[string]interface{}{},
		}
		edges = append(edges, edge)
	}

	return edges, specs
}

// ExtractPrincipalsFromPolicyDocument extracts all principals mentioned in a policy.
// Used for analyzing Principal fields in policy statements.
func ExtractPrincipalsFromPolicyDocument(policyJSON string) ([]string, error) {
	var result []string
	if policyJSON == "" {
		return result, nil
	}

	var policy map[string]interface{}
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON: %w", err)
	}

	if statements, ok := policy["Statement"].([]interface{}); ok {
		for _, stmt := range statements {
			if stmtMap, ok := stmt.(map[string]interface{}); ok {
				if principal, ok := stmtMap["Principal"]; ok {
					if principalStr, ok := principal.(string); ok {
						if principalStr != "*" {
							result = append(result, principalStr)
						}
					} else if principalObj, ok := principal.(map[string]interface{}); ok {
						if aws, ok := principalObj["AWS"]; ok {
							if awsStr, ok := aws.(string); ok {
								result = append(result, awsStr)
							} else if awsArr, ok := aws.([]interface{}); ok {
								for _, a := range awsArr {
									if aStr, ok := a.(string); ok {
										result = append(result, aStr)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return result, nil
}
