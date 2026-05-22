package iam

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// TestUserToResourceSpec_BasicUser tests transformation of a simple IAM user.
func TestUserToResourceSpec_BasicUser(t *testing.T) {
	now := time.Now()
	user := types.User{
		UserName:   ptrString("alice"),
		UserId:     ptrString("AIDAQ123456789ABC"),
		Arn:        ptrString("arn:aws:iam::123456789012:user/alice"),
		Path:       ptrString("/"),
		CreateDate: &now,
	}

	spec := UserToResourceSpec(user, "123456789012")

	if spec.Label != "Principal" {
		t.Errorf("expected label 'Principal', got %s", spec.Label)
	}
	if spec.ID != "arn:aws:iam::123456789012:user/alice" {
		t.Errorf("expected ID 'arn:aws:iam::123456789012:user/alice', got %s", spec.ID)
	}
	if spec.Properties["name"] != "alice" {
		t.Errorf("expected name 'alice', got %v", spec.Properties["name"])
	}
	if spec.Properties["principal_type"] != "User" {
		t.Errorf("expected principal_type 'User', got %v", spec.Properties["principal_type"])
	}
}

// TestRoleToResourceSpec_BasicRole tests transformation of a simple IAM role.
func TestRoleToResourceSpec_BasicRole(t *testing.T) {
	now := time.Now()
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	role := types.Role{
		RoleName:                 ptrString("lambda-executor"),
		RoleId:                   ptrString("AIDAQ987654321GHI"),
		Arn:                      ptrString("arn:aws:iam::123456789012:role/lambda-executor"),
		Path:                     ptrString("/"),
		CreateDate:               &now,
		AssumeRolePolicyDocument: ptrString(policy),
	}

	spec := RoleToResourceSpec(role, "123456789012")

	if spec.Label != "Principal" {
		t.Errorf("expected label 'Principal', got %s", spec.Label)
	}
	if spec.ID != "arn:aws:iam::123456789012:role/lambda-executor" {
		t.Errorf("expected ID 'arn:aws:iam::123456789012:role/lambda-executor', got %s", spec.ID)
	}
	if spec.Properties["name"] != "lambda-executor" {
		t.Errorf("expected name 'lambda-executor', got %v", spec.Properties["name"])
	}
	if spec.Properties["principal_type"] != "Role" {
		t.Errorf("expected principal_type 'Role', got %v", spec.Properties["principal_type"])
	}
}

// TestGroupToResourceSpec_BasicGroup tests transformation of a simple IAM group.
func TestGroupToResourceSpec_BasicGroup(t *testing.T) {
	now := time.Now()
	group := types.Group{
		GroupName:  ptrString("developers"),
		GroupId:    ptrString("AGPAQ987654321JKL"),
		Arn:        ptrString("arn:aws:iam::123456789012:group/developers"),
		Path:       ptrString("/"),
		CreateDate: &now,
	}

	spec := GroupToResourceSpec(group, "123456789012")

	if spec.Label != "IamGroup" {
		t.Errorf("expected label 'IamGroup', got %s", spec.Label)
	}
	if spec.ID != "arn:aws:iam::123456789012:group/developers" {
		t.Errorf("expected ID 'arn:aws:iam::123456789012:group/developers', got %s", spec.ID)
	}
}

// TestServicePrincipalToResourceSpec tests creation of a service principal resource.
func TestServicePrincipalToResourceSpec(t *testing.T) {
	spec := ServicePrincipalToResourceSpec("lambda.amazonaws.com")

	if spec.Label != "Principal" {
		t.Errorf("expected label 'Principal', got %s", spec.Label)
	}
	if spec.ID != "lambda.amazonaws.com" {
		t.Errorf("expected ID 'lambda.amazonaws.com', got %s", spec.ID)
	}
	if spec.Properties["principal_type"] != "Service" {
		t.Errorf("expected principal_type 'Service', got %v", spec.Properties["principal_type"])
	}
}

// TestAccessKeyToResourceSpec_ActiveKey tests transformation of an active access key.
func TestAccessKeyToResourceSpec_ActiveKey(t *testing.T) {
	now := time.Now()
	key := types.AccessKeyMetadata{
		AccessKeyId: ptrString("AKIAIOSFODNN7EXAMPLE"),
		Status:      types.StatusTypeActive,
		CreateDate:  &now,
	}
	userARN := "arn:aws:iam::123456789012:user/alice"

	nodeSpec, edgeSpec := AccessKeyToResourceSpec(key, userARN)

	if nodeSpec.Label != "AccessKey" {
		t.Errorf("expected label 'AccessKey', got %s", nodeSpec.Label)
	}
	if nodeSpec.ID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("expected ID 'AKIAIOSFODNN7EXAMPLE', got %s", nodeSpec.ID)
	}
	if edgeSpec.EdgeType != "SignedBy" {
		t.Errorf("expected edge type 'SignedBy', got %s", edgeSpec.EdgeType)
	}
	if edgeSpec.TargetID != userARN {
		t.Errorf("expected target ID %s, got %s", userARN, edgeSpec.TargetID)
	}
}

// TestContainsEdgeSpecs_FiltersWildcards tests that wildcard ARNs are filtered.
func TestContainsEdgeSpecs_FiltersWildcards(t *testing.T) {
	resourceARNs := []string{
		"arn:aws:s3:::my-bucket",
		"*",
		"arn:aws:s3:::other-bucket",
		"",
	}

	edges := ContainsEdgeSpecs("permission-id", resourceARNs)

	// Should have 2 edges (wildcard and empty string filtered out)
	if len(edges) != 2 {
		t.Errorf("expected 2 edges, got %d", len(edges))
	}
	if edges[0].EdgeType != "Contains" {
		t.Errorf("expected edge type 'Contains', got %s", edges[0].EdgeType)
	}
}

// TestGroupMemberEdgeSpec tests creation of a group membership edge.
func TestGroupMemberEdgeSpec(t *testing.T) {
	userARN := "arn:aws:iam::123456789012:user/alice"
	groupARN := "arn:aws:iam::123456789012:group/developers"

	edge := GroupMemberEdgeSpec(userARN, groupARN)

	if edge.EdgeType != "MemberOf" {
		t.Errorf("expected edge type 'MemberOf', got %s", edge.EdgeType)
	}
	if edge.TargetID != groupARN {
		t.Errorf("expected target ID %s, got %s", groupARN, edge.TargetID)
	}
}

// TestParseTrustPolicy_ServicePrincipal tests parsing a service principal trust policy.
func TestParseTrustPolicy_ServicePrincipal(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/lambda-executor"
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {
					"Service": "lambda.amazonaws.com"
				},
				"Action": "sts:AssumeRole"
			}
		]
	}`

	specs, edges, err := ParseTrustPolicy(roleARN, policy)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(specs) != 1 {
		t.Errorf("expected 1 spec, got %d", len(specs))
	}
	if len(edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(edges))
	}

	if specs[0].Label != "Principal" {
		t.Errorf("expected label 'Principal', got %s", specs[0].Label)
	}
	if specs[0].ID != "lambda.amazonaws.com" {
		t.Errorf("expected ID 'lambda.amazonaws.com', got %s", specs[0].ID)
	}

	if edges[0].EdgeType != "TrustedBy" {
		t.Errorf("expected edge type 'TrustedBy', got %s", edges[0].EdgeType)
	}
}

// TestParseTrustPolicy_CrossAccountAssume tests parsing a cross-account trust policy.
func TestParseTrustPolicy_CrossAccountAssume(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/assume-me"
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {
					"AWS": "arn:aws:iam::999888777666:root"
				},
				"Action": "sts:AssumeRole"
			}
		]
	}`

	specs, edges, err := ParseTrustPolicy(roleARN, policy)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(specs) != 0 {
		t.Errorf("expected 0 specs, got %d", len(specs))
	}
	if len(edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(edges))
	}

	if edges[0].EdgeType != "CanAssume" {
		t.Errorf("expected edge type 'CanAssume', got %s", edges[0].EdgeType)
	}
	if edges[0].TargetID != "arn:aws:iam::999888777666:root" {
		t.Errorf("expected target ID 'arn:aws:iam::999888777666:root', got %s", edges[0].TargetID)
	}
}

// TestParseTrustPolicy_WildcardPrincipalSkipped tests that wildcard principals are skipped.
func TestParseTrustPolicy_WildcardPrincipalSkipped(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/public-role"
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": "*",
				"Action": "sts:AssumeRole"
			}
		]
	}`

	specs, edges, err := ParseTrustPolicy(roleARN, policy)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(specs) != 0 {
		t.Errorf("expected 0 specs, got %d", len(specs))
	}
	if len(edges) != 0 {
		t.Errorf("expected 0 edges, got %d", len(edges))
	}
}

// Helper function for test

func ptrString(s string) *string {
	return &s
}
