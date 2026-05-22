package iam

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// TestTransformerUserToResourceSpec tests the UserToResourceSpec transformer.
func TestTransformerUserToResourceSpec(t *testing.T) {
	tests := []struct {
		name       string
		user       types.User
		accountID  string
		wantLabel  string
		wantID     string
		wantName   string
		wantPath   string
	}{
		{
			name: "simple user",
			user: types.User{
				UserName:   strPtr("alice"),
				Arn:        strPtr("arn:aws:iam::123456789012:user/alice"),
				Path:       strPtr("/"),
				CreateDate: timePtr(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
			accountID: "123456789012",
			wantLabel: "Principal",
			wantID:    "arn:aws:iam::123456789012:user/alice",
			wantName:  "alice",
			wantPath:  "/",
		},
		{
			name: "user with path",
			user: types.User{
				UserName:   strPtr("bob"),
				Arn:        strPtr("arn:aws:iam::123456789012:user/engineering/bob"),
				Path:       strPtr("/engineering/"),
				CreateDate: timePtr(time.Date(2023, 6, 15, 0, 0, 0, 0, time.UTC)),
			},
			accountID: "123456789012",
			wantLabel: "Principal",
			wantID:    "arn:aws:iam::123456789012:user/engineering/bob",
			wantName:  "bob",
			wantPath:  "/engineering/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := UserToResourceSpec(tt.user, tt.accountID)

			if spec.Label != tt.wantLabel {
				t.Errorf("Label = %q, want %q", spec.Label, tt.wantLabel)
			}
			if spec.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", spec.ID, tt.wantID)
			}

			if name, ok := spec.Properties["name"]; !ok || name != tt.wantName {
				t.Errorf("name = %v, want %q", name, tt.wantName)
			}
			if path, ok := spec.Properties["path"]; !ok || path != tt.wantPath {
				t.Errorf("path = %v, want %q", path, tt.wantPath)
			}
		})
	}
}

// TestTransformerAccessKeyToResourceSpec tests AccessKey transformation.
func TestTransformerAccessKeyToResourceSpec(t *testing.T) {
	keyID := "AKIA1234567890ABCDEF"
	userARN := "arn:aws:iam::123456789012:user/alice"
	createTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

	keyMeta := types.AccessKeyMetadata{
		AccessKeyId: &keyID,
		UserName:    strPtr("alice"),
		Status:      types.StatusTypeActive,
		CreateDate:  &createTime,
	}

	spec, edge := AccessKeyToResourceSpec(keyMeta, userARN, "123456789012")

	if spec.Label != "AccessKey" {
		t.Errorf("Label = %q, want AccessKey", spec.Label)
	}
	if spec.ID != keyID {
		t.Errorf("ID = %q, want %q", spec.ID, keyID)
	}

	if edge.EdgeType != "SignedBy" {
		t.Errorf("EdgeType = %q, want SignedBy", edge.EdgeType)
	}
	if edge.FromID != keyID {
		t.Errorf("FromID = %q, want %q", edge.FromID, keyID)
	}
	if edge.ToID != userARN {
		t.Errorf("ToID = %q, want %q", edge.ToID, userARN)
	}
}

// TestTrustParserServicePrincipal tests parsing a trust policy with a service principal.
func TestTrustParserServicePrincipal(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/lambda-execution-role"
	trustPolicy := `{
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

	resources, edges, err := ParseTrustPolicy(roleARN, trustPolicy)
	if err != nil {
		t.Fatalf("ParseTrustPolicy failed: %v", err)
	}

	// Should have 1 ServicePrincipal resource
	if len(resources) != 1 {
		t.Errorf("len(resources) = %d, want 1", len(resources))
	}
	if len(resources) > 0 && resources[0].ID != "lambda.amazonaws.com" {
		t.Errorf("ServicePrincipal ID = %q, want lambda.amazonaws.com", resources[0].ID)
	}

	// Should have 1 TrustedBy edge
	if len(edges) != 1 {
		t.Errorf("len(edges) = %d, want 1", len(edges))
	}
	if len(edges) > 0 {
		if edges[0].EdgeType != "TrustedBy" {
			t.Errorf("EdgeType = %q, want TrustedBy", edges[0].EdgeType)
		}
		if edges[0].FromID != roleARN {
			t.Errorf("FromID = %q, want %q", edges[0].FromID, roleARN)
		}
		if edges[0].ToID != "lambda.amazonaws.com" {
			t.Errorf("ToID = %q, want lambda.amazonaws.com", edges[0].ToID)
		}
	}
}

// TestTrustParserCrossAccountAssume tests parsing a trust policy with cross-account assume.
func TestTrustParserCrossAccountAssume(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/cross-account-role"
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {
					"AWS": "arn:aws:iam::210987654321:root"
				},
				"Action": "sts:AssumeRole"
			}
		]
	}`

	resources, edges, err := ParseTrustPolicy(roleARN, trustPolicy)
	if err != nil {
		t.Fatalf("ParseTrustPolicy failed: %v", err)
	}

	// Should have no resources (AWS principal is not a service)
	if len(resources) != 0 {
		t.Errorf("len(resources) = %d, want 0", len(resources))
	}

	// Should have 1 CanAssume edge
	if len(edges) != 1 {
		t.Errorf("len(edges) = %d, want 1", len(edges))
	}
	if len(edges) > 0 {
		if edges[0].EdgeType != "CanAssume" {
			t.Errorf("EdgeType = %q, want CanAssume", edges[0].EdgeType)
		}
		if edges[0].FromID != roleARN {
			t.Errorf("FromID = %q, want %q", edges[0].FromID, roleARN)
		}
		if edges[0].ToID != "arn:aws:iam::210987654321:root" {
			t.Errorf("ToID = %q, want arn:aws:iam::210987654321:root", edges[0].ToID)
		}
	}
}

// TestTrustParserWildcardPrincipalSkipped tests that wildcard principals are skipped.
func TestTrustParserWildcardPrincipalSkipped(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/public-role"
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": "*",
				"Action": "sts:AssumeRole"
			}
		]
	}`

	resources, edges, err := ParseTrustPolicy(roleARN, trustPolicy)
	if err != nil {
		t.Fatalf("ParseTrustPolicy failed: %v", err)
	}

	// Should have no resources or edges (wildcard is skipped)
	if len(resources) != 0 {
		t.Errorf("len(resources) = %d, want 0", len(resources))
	}
	if len(edges) != 0 {
		t.Errorf("len(edges) = %d, want 0", len(edges))
	}
}

// TestTrustParserMultipleStatements tests parsing a trust policy with multiple statements.
func TestTrustParserMultipleStatements(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/multi-trust-role"
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {
					"Service": "lambda.amazonaws.com"
				},
				"Action": "sts:AssumeRole"
			},
			{
				"Effect": "Allow",
				"Principal": {
					"AWS": "arn:aws:iam::210987654321:root"
				},
				"Action": "sts:AssumeRole"
			}
		]
	}`

	resources, edges, err := ParseTrustPolicy(roleARN, trustPolicy)
	if err != nil {
		t.Fatalf("ParseTrustPolicy failed: %v", err)
	}

	// Should have 1 ServicePrincipal resource
	if len(resources) != 1 {
		t.Errorf("len(resources) = %d, want 1", len(resources))
	}

	// Should have 2 edges (1 TrustedBy + 1 CanAssume)
	if len(edges) != 2 {
		t.Errorf("len(edges) = %d, want 2", len(edges))
	}

	// Verify edge types
	edgeTypes := make(map[string]int)
	for _, edge := range edges {
		edgeTypes[edge.EdgeType]++
	}

	if edgeTypes["TrustedBy"] != 1 {
		t.Errorf("TrustedBy edges = %d, want 1", edgeTypes["TrustedBy"])
	}
	if edgeTypes["CanAssume"] != 1 {
		t.Errorf("CanAssume edges = %d, want 1", edgeTypes["CanAssume"])
	}
}

// TestTransformerIsValidNodeID tests the IsValidNodeID filter.
func TestTransformerIsValidNodeID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"arn:aws:s3:::my-bucket", true},
		{"*", false},
		{"", false},
		{"arn:aws:iam::123456789012:user/alice", true},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			result := IsValidNodeID(tt.id)
			if result != tt.valid {
				t.Errorf("IsValidNodeID(%q) = %v, want %v", tt.id, result, tt.valid)
			}
		})
	}
}

// TestTransformerExtractAccountID tests ARN account ID extraction.
func TestTransformerExtractAccountID(t *testing.T) {
	tests := []struct {
		arn       string
		wantAccID string
	}{
		{"arn:aws:iam::123456789012:user/alice", "123456789012"},
		{"arn:aws:iam::aws:policy/AdministratorAccess", "aws"},
		{"arn:aws:s3:::my-bucket", ""},
		{"invalid-arn", ""},
	}

	for _, tt := range tests {
		t.Run(tt.arn, func(t *testing.T) {
			accID := ExtractAccountIDFromARN(tt.arn)
			if accID != tt.wantAccID {
				t.Errorf("ExtractAccountIDFromARN(%q) = %q, want %q", tt.arn, accID, tt.wantAccID)
			}
		})
	}
}

// TestPolicyDocumentParsing tests parsing policy documents.
func TestPolicyDocumentParsing(t *testing.T) {
	policyDoc := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "S3Access",
				"Effect": "Allow",
				"Action": ["s3:GetObject", "s3:PutObject"],
				"Resource": "arn:aws:s3:::my-bucket/*"
			}
		]
	}`

	doc, err := ParsePolicyDocument(policyDoc)
	if err != nil {
		t.Fatalf("ParsePolicyDocument failed: %v", err)
	}

	if len(doc.Statement) != 1 {
		t.Errorf("len(Statement) = %d, want 1", len(doc.Statement))
	}

	if len(doc.Statement) > 0 {
		stmt := doc.Statement[0]
		if stmt.Sid != "S3Access" {
			t.Errorf("Sid = %q, want S3Access", stmt.Sid)
		}
		if stmt.Effect != "Allow" {
			t.Errorf("Effect = %q, want Allow", stmt.Effect)
		}
	}
}

// TestStringArrayFromInterface tests the StringArrayFromInterface conversion.
func TestStringArrayFromInterface(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  []string
	}{
		{
			name:  "single string",
			input: "s3:GetObject",
			want:  []string{"s3:GetObject"},
		},
		{
			name:  "array of strings",
			input: []interface{}{"s3:GetObject", "s3:PutObject"},
			want:  []string{"s3:GetObject", "s3:PutObject"},
		},
		{
			name:  "empty array",
			input: []interface{}{},
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StringArrayFromInterface(tt.input)
			if !stringSliceEqual(result, tt.want) {
				t.Errorf("StringArrayFromInterface(%v) = %v, want %v", tt.input, result, tt.want)
			}
		})
	}
}

// TestTransformerRoleToResourceSpec tests RoleToResourceSpec.
func TestTransformerRoleToResourceSpec(t *testing.T) {
	roleName := "test-role"
	roleARN := "arn:aws:iam::123456789012:role/test-role"
	assumeRolePolicy := `{"Version":"2012-10-17","Statement":[]}`
	maxSessionDuration := int32(3600)
	createTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

	role := types.Role{
		RoleName:                    &roleName,
		Arn:                         &roleARN,
		Path:                        strPtr("/"),
		CreateDate:                  &createTime,
		AssumeRolePolicyDocument:    &assumeRolePolicy,
		MaxSessionDuration:          &maxSessionDuration,
	}

	spec := RoleToResourceSpec(role, "123456789012")

	if spec.Label != "Principal" {
		t.Errorf("Label = %q, want Principal", spec.Label)
	}
	if spec.ID != roleARN {
		t.Errorf("ID = %q, want %q", spec.ID, roleARN)
	}
	if pt, ok := spec.Properties["principal_type"]; !ok || pt != "Role" {
		t.Errorf("principal_type = %v, want Role", pt)
	}
}

// TestTransformerGroupToResourceSpec tests GroupToResourceSpec.
func TestTransformerGroupToResourceSpec(t *testing.T) {
	groupName := "test-group"
	groupARN := "arn:aws:iam::123456789012:group/test-group"
	createTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

	group := types.Group{
		GroupName:  &groupName,
		Arn:        &groupARN,
		Path:       strPtr("/"),
		CreateDate: &createTime,
	}

	spec := GroupToResourceSpec(group, "123456789012")

	if spec.Label != "IamGroup" {
		t.Errorf("Label = %q, want IamGroup", spec.Label)
	}
	if spec.ID != groupARN {
		t.Errorf("ID = %q, want %q", spec.ID, groupARN)
	}
}

// TestTransformerAttachedPolicyToEdgeSpec tests AttachedPolicyToEdgeSpec.
func TestTransformerAttachedPolicyToEdgeSpec(t *testing.T) {
	principalARN := "arn:aws:iam::123456789012:user/alice"
	policyARN := "arn:aws:iam::123456789012:policy/MyPolicy"

	edge := AttachedPolicyToEdgeSpec(principalARN, policyARN)

	if edge.FromID != principalARN {
		t.Errorf("FromID = %q, want %q", edge.FromID, principalARN)
	}
	if edge.ToID != policyARN {
		t.Errorf("ToID = %q, want %q", edge.ToID, policyARN)
	}
	if edge.EdgeType != "HasPermission" {
		t.Errorf("EdgeType = %q, want HasPermission", edge.EdgeType)
	}
}

// TestTransformerGroupMemberEdgeSpec tests GroupMemberEdgeSpec.
func TestTransformerGroupMemberEdgeSpec(t *testing.T) {
	userARN := "arn:aws:iam::123456789012:user/alice"
	groupARN := "arn:aws:iam::123456789012:group/engineering"

	edge := GroupMemberEdgeSpec(userARN, groupARN)

	if edge.FromID != userARN {
		t.Errorf("FromID = %q, want %q", edge.FromID, userARN)
	}
	if edge.ToID != groupARN {
		t.Errorf("ToID = %q, want %q", edge.ToID, groupARN)
	}
	if edge.EdgeType != "MemberOf" {
		t.Errorf("EdgeType = %q, want MemberOf", edge.EdgeType)
	}
}

// TestTransformerStatementToPermissionID tests StatementToPermissionID.
func TestTransformerStatementToPermissionID(t *testing.T) {
	principalARN := "arn:aws:iam::123456789012:user/alice"
	policyName := "InlinePolicy"
	statementIndex := 0
	sid := "S3Access"

	permID := StatementToPermissionID(principalARN, policyName, statementIndex, sid)

	if permID != "arn:aws:iam::123456789012:user/alice#InlinePolicy#S3Access" {
		t.Errorf("StatementToPermissionID = %q, want principal#policyName#sid format", permID)
	}

	// Test with empty SID
	permID2 := StatementToPermissionID(principalARN, policyName, 2, "")

	if permID2 != "arn:aws:iam::123456789012:user/alice#InlinePolicy#stmt_2" {
		t.Errorf("StatementToPermissionID (empty SID) = %q, want principal#policyName#stmt_N format", permID2)
	}
}

// TestTransformerPolicyToResourceSpec tests PolicyToResourceSpec.
func TestTransformerPolicyToResourceSpec(t *testing.T) {
	policyARN := "arn:aws:iam::123456789012:policy/MyPolicy"
	policyName := "MyPolicy"
	document := `{"Version":"2012-10-17","Statement":[]}`

	spec := PolicyToResourceSpec(policyARN, policyName, "123456789012", document)

	if spec.Label != "Permission" {
		t.Errorf("Label = %q, want Permission", spec.Label)
	}
	if spec.ID != policyARN {
		t.Errorf("ID = %q, want %q", spec.ID, policyARN)
	}
	if name, ok := spec.Properties["name"]; !ok || name != policyName {
		t.Errorf("name = %v, want %q", name, policyName)
	}
}

// TestTransformerContainsEdgeSpec tests ContainsEdgeSpec.
func TestTransformerContainsEdgeSpec(t *testing.T) {
	permissionID := "arn:aws:iam::123456789012:user/alice#MyPolicy#S3Access"
	resourceID := "arn:aws:s3:::my-bucket/*"

	edge := ContainsEdgeSpec(permissionID, resourceID)

	if edge.FromID != permissionID {
		t.Errorf("FromID = %q, want %q", edge.FromID, permissionID)
	}
	if edge.ToID != resourceID {
		t.Errorf("ToID = %q, want %q", edge.ToID, resourceID)
	}
	if edge.EdgeType != "Contains" {
		t.Errorf("EdgeType = %q, want Contains", edge.EdgeType)
	}
}

// TestParsePrincipalFieldString tests parsing Principal as a string.
func TestParsePrincipalFieldString(t *testing.T) {
	pf := parsePrincipalField("*")

	if pf.Raw != "*" {
		t.Errorf("Raw = %q, want *", pf.Raw)
	}
	if len(pf.AWS) != 0 {
		t.Errorf("AWS array should be empty, got %v", pf.AWS)
	}
}

// TestParsePrincipalFieldObject tests parsing Principal as an object.
func TestParsePrincipalFieldObject(t *testing.T) {
	principalObj := map[string]interface{}{
		"AWS":     []interface{}{"arn:aws:iam::210987654321:root", "arn:aws:iam::321098765432:root"},
		"Service": []interface{}{"lambda.amazonaws.com"},
	}

	pf := parsePrincipalField(principalObj)

	if len(pf.AWS) != 2 {
		t.Errorf("len(AWS) = %d, want 2", len(pf.AWS))
	}
	if len(pf.Service) != 1 {
		t.Errorf("len(Service) = %d, want 1", len(pf.Service))
	}
	if pf.Service[0] != "lambda.amazonaws.com" {
		t.Errorf("Service[0] = %q, want lambda.amazonaws.com", pf.Service[0])
	}
}

// Helper functions

func strPtr(s string) *string {
	return &s
}

func timePtr(t time.Time) *time.Time {
	return &t
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
