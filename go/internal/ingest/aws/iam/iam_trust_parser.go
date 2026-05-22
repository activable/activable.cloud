package iam

import (
	"encoding/json"
	"fmt"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
)

// TrustPolicyDocument represents the structure of an AssumeRolePolicyDocument.
type TrustPolicyDocument struct {
	Version   string        `json:"Version"`
	Statement []TrustPolicy `json:"Statement"`
}

// TrustPolicy represents a single statement in the trust policy.
type TrustPolicy struct {
	Effect    string      `json:"Effect"`
	Principal interface{} `json:"Principal"` // Can be string ("*") or object ({"AWS": [...], "Service": [...]})
	Action    interface{} `json:"Action"`
	Condition interface{} `json:"Condition,omitempty"`
}

// PrincipalField handles both string and object forms of Principal.
type PrincipalField struct {
	AWS     []string `json:"AWS,omitempty"`
	Service []string `json:"Service,omitempty"`
	Raw     string   `json:"-"`
}

// ParseTrustPolicy parses an AssumeRolePolicyDocument and returns ResourceSpecs for any ServicePrincipals
// and EdgeSpecs for CanAssume and TrustedBy relationships.
func ParseTrustPolicy(roleArn string, trustPolicyJSON string) ([]ingest.ResourceSpec, []ingest.EdgeSpec, error) {
	var doc TrustPolicyDocument
	err := json.Unmarshal([]byte(trustPolicyJSON), &doc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal trust policy: %w", err)
	}

	var resources []ingest.ResourceSpec
	var edges []ingest.EdgeSpec

	for _, stmt := range doc.Statement {
		// Only process Allow statements (Deny doesn't grant permissions)
		if stmt.Effect != "Allow" {
			continue
		}

		principals := parsePrincipalField(stmt.Principal)

		// Process AWS principals (CanAssume edges)
		for _, awsPrincipal := range principals.AWS {
			// Skip wildcard principals
			if !IsValidNodeID(awsPrincipal) {
				continue
			}

			// Create CanAssume edge: roleArn -> targetPrincipal
			edge := CanAssumeEdgeSpec(roleArn, awsPrincipal)
			edges = append(edges, edge)
		}

		// Process Service principals (TrustedBy edges + ServicePrincipal nodes)
		for _, serviceName := range principals.Service {
			if !IsValidNodeID(serviceName) {
				continue
			}

			// Create ServicePrincipal resource node
			servicePrincipal := ServicePrincipalToResourceSpec(serviceName)
			resources = append(resources, servicePrincipal)

			// Create TrustedBy edge: roleArn -> serviceName
			edge := TrustedByEdgeSpec(roleArn, serviceName)
			edges = append(edges, edge)
		}
	}

	return resources, edges, nil
}

// parsePrincipalField handles both string and object forms of Principal field.
func parsePrincipalField(principal interface{}) PrincipalField {
	pf := PrincipalField{}

	switch p := principal.(type) {
	case string:
		// Principal: "*" case
		pf.Raw = p
	case map[string]interface{}:
		// Principal: { "AWS": [...], "Service": [...] } case
		if aws, ok := p["AWS"]; ok {
			pf.AWS = parseStringArray(aws)
		}
		if service, ok := p["Service"]; ok {
			pf.Service = parseStringArray(service)
		}
	}

	return pf
}

// parseStringArray handles both single strings and arrays in JSON.
func parseStringArray(val interface{}) []string {
	var result []string

	switch v := val.(type) {
	case string:
		result = []string{v}
	case []interface{}:
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
	}

	return result
}
