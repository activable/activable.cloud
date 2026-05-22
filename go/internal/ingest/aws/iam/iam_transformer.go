package iam

import (
	"fmt"
	"strings"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// UserToResourceSpec transforms an IAM User to a ResourceSpec with Principal label.
func UserToResourceSpec(u types.User, accountID string) ingest.ResourceSpec {
	arn := *u.Arn
	return ingest.ResourceSpec{
		Label: "Principal",
		ID:    arn,
		Properties: map[string]interface{}{
			"principal_type": "User",
			"name":           *u.UserName,
			"path":           *u.Path,
			"created_at":     u.CreateDate.Unix(),
			"account_id":     accountID,
		},
		Edges: []ingest.EdgeSpec{},
	}
}

// RoleToResourceSpec transforms an IAM Role to a ResourceSpec with Principal label.
func RoleToResourceSpec(r types.Role, accountID string) ingest.ResourceSpec {
	arn := *r.Arn
	return ingest.ResourceSpec{
		Label: "Principal",
		ID:    arn,
		Properties: map[string]interface{}{
			"principal_type":        "Role",
			"name":                  *r.RoleName,
			"path":                  *r.Path,
			"created_at":            r.CreateDate.Unix(),
			"account_id":            accountID,
			"assume_role_policy":    r.AssumeRolePolicyDocument,
			"max_session_duration":  *r.MaxSessionDuration,
		},
		Edges: []ingest.EdgeSpec{},
	}
}

// GroupToResourceSpec transforms an IAM Group to a ResourceSpec with IamGroup label.
func GroupToResourceSpec(g types.Group, accountID string) ingest.ResourceSpec {
	arn := *g.Arn
	return ingest.ResourceSpec{
		Label: "IamGroup",
		ID:    arn,
		Properties: map[string]interface{}{
			"name":       *g.GroupName,
			"path":       *g.Path,
			"created_at": g.CreateDate.Unix(),
			"account_id": accountID,
		},
		Edges: []ingest.EdgeSpec{},
	}
}

// PolicyToResourceSpec transforms a managed policy to a ResourceSpec with Permission label.
func PolicyToResourceSpec(policyARN string, policyName string, accountID string, document string) ingest.ResourceSpec {
	return ingest.ResourceSpec{
		Label: "Permission",
		ID:    policyARN,
		Properties: map[string]interface{}{
			"name":         policyName,
			"account_id":   accountID,
			"document":     document,
			"policy_type":  "ManagedPolicy",
		},
		Edges: []ingest.EdgeSpec{},
	}
}

// AccessKeyToResourceSpec transforms an IAM AccessKey to a ResourceSpec and SignedBy edge.
// Returns both the AccessKey node and the SignedBy edge linking it to the user.
func AccessKeyToResourceSpec(k types.AccessKeyMetadata, userArn string, accountID string) (ingest.ResourceSpec, ingest.EdgeSpec) {
	accessKeyID := *k.AccessKeyId
	resourceSpec := ingest.ResourceSpec{
		Label: "AccessKey",
		ID:    accessKeyID,
		Properties: map[string]interface{}{
			"access_key_id": accessKeyID,
			"status":        k.Status,
			"create_date":   k.CreateDate.Unix(),
			"account_id":    accountID,
		},
		Edges: []ingest.EdgeSpec{},
	}

	edge := ingest.EdgeSpec{
		FromID:   accessKeyID,
		ToID:     userArn,
		EdgeType: "SignedBy",
		Properties: map[string]interface{}{
			"created_at": k.CreateDate.Unix(),
		},
	}

	return resourceSpec, edge
}

// AttachedPolicyToEdgeSpec creates a HasPermission edge between a principal and an attached policy.
func AttachedPolicyToEdgeSpec(principalArn, policyArn string) ingest.EdgeSpec {
	return ingest.EdgeSpec{
		FromID:   principalArn,
		ToID:     policyArn,
		EdgeType: "HasPermission",
		Properties: map[string]interface{}{
			"attachment_type": "direct",
		},
	}
}

// GroupMemberEdgeSpec creates a MemberOf edge between a user and a group.
func GroupMemberEdgeSpec(userArn, groupArn string) ingest.EdgeSpec {
	return ingest.EdgeSpec{
		FromID:   userArn,
		ToID:     groupArn,
		EdgeType: "MemberOf",
		Properties: map[string]interface{}{},
	}
}

// ContainsEdgeSpec creates a Contains edge between a permission and a resource.
// This is used for inline policy statements where the Resource field is directly linked.
func ContainsEdgeSpec(permissionID, resourceID string) ingest.EdgeSpec {
	return ingest.EdgeSpec{
		FromID:   permissionID,
		ToID:     resourceID,
		EdgeType: "Contains",
		Properties: map[string]interface{}{},
	}
}

// ServicePrincipalToResourceSpec creates a ServicePrincipal node from an FQDN like lambda.amazonaws.com.
func ServicePrincipalToResourceSpec(serviceFQDN string) ingest.ResourceSpec {
	return ingest.ResourceSpec{
		Label: "FederatedProvider",
		ID:    serviceFQDN,
		Properties: map[string]interface{}{
			"name":       serviceFQDN,
			"type":       "ServicePrincipal",
			"account_id": "aws",
		},
		Edges: []ingest.EdgeSpec{},
	}
}

// StatementToPermissionID generates a stable ID for an inline policy statement.
// Format: "principal_arn:policy_name:statement_index:sid"
func StatementToPermissionID(principalArn, policyName string, statementIndex int, sid string) string {
	// Normalize the SID: if empty, use the statement index
	if sid == "" {
		sid = fmt.Sprintf("stmt_%d", statementIndex)
	}
	// Create a composite ID to ensure uniqueness across policies and statements
	return fmt.Sprintf("%s#%s#%s", principalArn, policyName, sid)
}

// TrustedByEdgeSpec creates a TrustedBy edge between a role and a service principal.
func TrustedByEdgeSpec(roleArn, serviceFQDN string) ingest.EdgeSpec {
	return ingest.EdgeSpec{
		FromID:   roleArn,
		ToID:     serviceFQDN,
		EdgeType: "TrustedBy",
		Properties: map[string]interface{}{},
	}
}

// CanAssumeEdgeSpec creates a CanAssume edge between two principals.
func CanAssumeEdgeSpec(sourceArn, targetArn string) ingest.EdgeSpec {
	return ingest.EdgeSpec{
		FromID:   sourceArn,
		ToID:     targetArn,
		EdgeType: "CanAssume",
		Properties: map[string]interface{}{},
	}
}

// IsValidNodeID checks if a string is a valid node ID (not a wildcard).
// For now, we filter out the literal "*" wildcard.
func IsValidNodeID(id string) bool {
	return id != "" && id != "*"
}

// ExtractAccountIDFromARN extracts the account ID from an ARN string.
// ARN format: arn:partition:service:region:account-id:resourcetype/resource
func ExtractAccountIDFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
