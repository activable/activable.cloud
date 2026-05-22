package iam

import (
	"crypto/md5"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	ingest "github.com/activable-cloud/activable.cloud/go/internal/ingest"
)

// UserToResourceSpec transforms an IAM User to a Principal ResourceSpec.
func UserToResourceSpec(user types.User, accountID string) ingest.ResourceSpec {
	userName := StringValue(user.UserName)
	userPath := StringValue(user.Path)
	userID := StringValue(user.UserId)
	createdAt := int64(0)
	if user.CreateDate != nil {
		createdAt = user.CreateDate.Unix()
	}

	spec := ingest.ResourceSpec{
		Label: "Principal",
		ID:    constructARN(accountID, "iam", "", "user", userName),
		Properties: map[string]interface{}{
			"name":           userName,
			"principal_type": "User",
			"created_at":     createdAt,
			"path":           userPath,
			"user_id":        userID,
		},
	}
	if user.Arn != nil {
		spec.ID = *user.Arn
	}
	return spec
}

// RoleToResourceSpec transforms an IAM Role to a Principal ResourceSpec.
func RoleToResourceSpec(role types.Role, accountID string) ingest.ResourceSpec {
	roleName := StringValue(role.RoleName)
	rolePath := StringValue(role.Path)
	roleID := StringValue(role.RoleId)
	policyDoc := StringValue(role.AssumeRolePolicyDocument)
	createdAt := int64(0)
	if role.CreateDate != nil {
		createdAt = role.CreateDate.Unix()
	}

	spec := ingest.ResourceSpec{
		Label: "Principal",
		ID:    constructARN(accountID, "iam", "", "role", roleName),
		Properties: map[string]interface{}{
			"name":                roleName,
			"principal_type":      "Role",
			"created_at":          createdAt,
			"path":                rolePath,
			"role_id":             roleID,
			"assume_role_policy":  policyDoc,
		},
	}
	if role.Arn != nil {
		spec.ID = *role.Arn
	}
	return spec
}

// GroupToResourceSpec transforms an IAM Group to an IamGroup ResourceSpec.
func GroupToResourceSpec(group types.Group, accountID string) ingest.ResourceSpec {
	groupName := StringValue(group.GroupName)
	groupPath := StringValue(group.Path)
	groupID := StringValue(group.GroupId)
	createdAt := int64(0)
	if group.CreateDate != nil {
		createdAt = group.CreateDate.Unix()
	}

	spec := ingest.ResourceSpec{
		Label: "IamGroup",
		ID:    constructARN(accountID, "iam", "", "group", groupName),
		Properties: map[string]interface{}{
			"name":       groupName,
			"created_at": createdAt,
			"path":       groupPath,
			"group_id":   groupID,
		},
	}
	if group.Arn != nil {
		spec.ID = *group.Arn
	}
	return spec
}

// PolicyStatementToResourceSpec transforms a single policy statement to a Permission ResourceSpec.
func PolicyStatementToResourceSpec(policyArn string, sid string, actions []string, resources []string) ingest.ResourceSpec {
	// Create a canonical ID for this permission node
	// Hash: policyArn + SID
	hash := md5.New()
	io.WriteString(hash, fmt.Sprintf("%s:%s", policyArn, sid))
	permissionID := fmt.Sprintf("permission:%s:%x", policyArn, hash.Sum(nil))

	spec := ingest.ResourceSpec{
		Label: "Permission",
		ID:    permissionID,
		Properties: map[string]interface{}{
			"policy_arn": policyArn,
			"sid":        sid,
			"actions":    actions,
			"resources":  resources,
		},
	}

	return spec
}

// AccessKeyToResourceSpec transforms an IAM AccessKey to an AccessKey ResourceSpec
// and returns both the node and its SignedBy edge to the user.
func AccessKeyToResourceSpec(accessKey types.AccessKeyMetadata, userARN string) (ingest.ResourceSpec, ingest.EdgeSpec) {
	accessKeyID := StringValue(accessKey.AccessKeyId)
	status := string(accessKey.Status)
	createDate := int64(0)
	if accessKey.CreateDate != nil {
		createDate = accessKey.CreateDate.Unix()
	}

	nodeSpec := ingest.ResourceSpec{
		Label: "AccessKey",
		ID:    accessKeyID,
		Properties: map[string]interface{}{
			"access_key_id": accessKeyID,
			"status":        status,
			"create_date":   createDate,
		},
	}

	edgeSpec := ingest.EdgeSpec{
		FromID:     accessKeyID,
		TargetID:   userARN,
		EdgeType:   "SignedBy",
		Properties: map[string]interface{}{},
	}

	return nodeSpec, edgeSpec
}

// GroupMemberEdgeSpec creates an edge from a user to a group.
func GroupMemberEdgeSpec(userARN string, groupARN string) ingest.EdgeSpec {
	return ingest.EdgeSpec{
		FromID:     userARN,
		TargetID:   groupARN,
		EdgeType:   "MemberOf",
		Properties: map[string]interface{}{},
	}
}

// AttachedPolicyEdgeSpec creates an edge from a principal to an attached policy.
func AttachedPolicyEdgeSpec(principalARN string, policyARN string) ingest.EdgeSpec {
	return ingest.EdgeSpec{
		FromID:     principalARN,
		TargetID:   policyARN,
		EdgeType:   "HasPermission",
		Properties: map[string]interface{}{},
	}
}

// InlinePolicyEdgeSpec creates edges from a principal to inline policy statements.
func InlinePolicyEdgeSpec(principalARN string, policyName string, sids []string) []ingest.EdgeSpec {
	var edges []ingest.EdgeSpec

	for _, sid := range sids {
		// Create a permission ID for this inline policy statement
		hash := md5.New()
		io.WriteString(hash, fmt.Sprintf("%s:%s:%s", principalARN, policyName, sid))
		permissionID := fmt.Sprintf("permission:%s:%s:%x", principalARN, policyName, hash.Sum(nil))

		edge := ingest.EdgeSpec{
			FromID:     principalARN,
			TargetID:   permissionID,
			EdgeType:   "HasPermission",
			Properties: map[string]interface{}{},
		}
		edges = append(edges, edge)
	}

	return edges
}

// ContainsEdgeSpecs creates edges from a permission to resource ARNs.
// Filters out wildcard ARNs that are not valid node IDs.
func ContainsEdgeSpecs(permissionID string, resourceARNs []string) []ingest.EdgeSpec {
	var edges []ingest.EdgeSpec

	for _, arn := range resourceARNs {
		// Skip wildcard-only ARNs
		if arn == "*" || arn == "" {
			continue
		}

		edge := ingest.EdgeSpec{
			FromID:     permissionID,
			TargetID:   arn,
			EdgeType:   "Contains",
			Properties: map[string]interface{}{},
		}
		edges = append(edges, edge)
	}

	return edges
}

// ServicePrincipalToResourceSpec transforms a service principal FQDN to a resource spec.
func ServicePrincipalToResourceSpec(serviceFQDN string) ingest.ResourceSpec {
	return ingest.ResourceSpec{
		Label: "Principal",
		ID:    serviceFQDN,
		Properties: map[string]interface{}{
			"name":               serviceFQDN,
			"principal_type":     "Service",
			"service_principal":  true,
		},
	}
}

// FederatedProviderToResourceSpec transforms a federated provider ARN to a resource spec.
func FederatedProviderToResourceSpec(providerARN string) ingest.ResourceSpec {
	return ingest.ResourceSpec{
		Label: "FederatedProvider",
		ID:    providerARN,
		Properties: map[string]interface{}{
			"provider_arn": providerARN,
		},
	}
}

// Helper functions

// constructARN builds an ARN from components (best-effort; prefers actual ARNs from AWS)
func constructARN(accountID string, service string, region string, resourceType string, resourceName string) string {
	if region == "" {
		return fmt.Sprintf("arn:aws:%s::%s:%s/%s", service, accountID, resourceType, resourceName)
	}
	return fmt.Sprintf("arn:aws:%s:%s:%s:%s/%s", service, region, accountID, resourceType, resourceName)
}

// flattenStringList converts a slice of strings to a flat string for storage.
// Preserves the list as a single property value (can be parsed back if needed).
func flattenStringList(items []string) interface{} {
	if len(items) == 0 {
		return []string{}
	}
	return items
}

// UnixTimeOrZero safely converts a *time.Time to Unix timestamp.
func UnixTimeOrZero(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.Unix()
}

// StringValue safely dereferences a *string.
func StringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// StringSliceValue safely dereferences a slice of *string.
func StringSliceValue(items []*string) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item != nil {
			result = append(result, *item)
		}
	}
	return result
}

// ExtractPrincipalTypeFromARN extracts the principal type (User, Role, Group) from an ARN.
func ExtractPrincipalTypeFromARN(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) >= 2 {
		resourceType := parts[len(parts)-2]
		if resourceType == "user" || resourceType == "role" || resourceType == "group" {
			return strings.ToTitle(strings.ToLower(resourceType))
		}
	}
	return "Unknown"
}

// ParseYAMLPolicyDocument is a basic parser for AWS policy documents (often URL-encoded JSON).
// Returns the decoded JSON string.
func ParseYAMLPolicyDocument(encoded string) (string, error) {
	// AWS may URL-encode or JSON-escape policy documents; attempt to decode
	// For now, return as-is; real implementations would unmarshal and re-marshal
	return encoded, nil
}
