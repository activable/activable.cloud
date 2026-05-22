package iam

import (
	"context"
	"fmt"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"golang.org/x/sync/semaphore"
)

const (
	// MaxConcurrentCalls is the maximum number of concurrent AWS API calls for IAM.
	MaxConcurrentCalls = 3
)

// IAMIngester implements the Ingester interface for AWS IAM.
type IAMIngester struct {
	client    *iam.Client
	accountID string
	semaphore *semaphore.Weighted
}

// NewIAMIngester creates a new IAM ingester.
func NewIAMIngester(client *iam.Client, accountID string) *IAMIngester {
	return &IAMIngester{
		client:    client,
		accountID: accountID,
		semaphore: semaphore.NewWeighted(MaxConcurrentCalls),
	}
}

// Service returns the service name.
func (i *IAMIngester) Service() string {
	return "iam"
}

// RequiredIAMActions returns the IAM actions required for this ingester.
func (i *IAMIngester) RequiredIAMActions() []string {
	return []string{
		"iam:ListUsers",
		"iam:ListRoles",
		"iam:ListGroups",
		"iam:ListPolicies",
		"iam:GetPolicyVersion",
		"iam:ListAttachedUserPolicies",
		"iam:ListAttachedRolePolicies",
		"iam:ListAttachedGroupPolicies",
		"iam:ListAccessKeys",
		"iam:ListGroupsForUser",
		"iam:ListUserPolicies",
		"iam:GetUserPolicy",
		"iam:ListRolePolicies",
		"iam:GetRolePolicy",
		"iam:ListGroupPolicies",
		"iam:GetGroupPolicy",
	}
}

// Enumerate fetches all IAM resources and emits them as ResourceSpec items.
// IAM is a global service, so the region parameter is ignored.
func (i *IAMIngester) Enumerate(ctx context.Context, region string) (<-chan ingest.ResourceSpec, <-chan error) {
	resourcesChan := make(chan ingest.ResourceSpec, 100)
	errorsChan := make(chan error, 10)

	go func() {
		defer close(resourcesChan)
		defer close(errorsChan)

		// Enumerate users
		users, err := FetchUsers(ctx, i.client, i.semaphore)
		if err != nil {
			errorsChan <- fmt.Errorf("failed to fetch users: %w", err)
			return
		}

		for _, user := range users {
			userARN := *user.Arn
			userSpec := UserToResourceSpec(user, i.accountID)
			resourcesChan <- userSpec

			// Fetch access keys for this user
			accessKeys, err := FetchAccessKeys(ctx, i.client, i.semaphore, *user.UserName)
			if err != nil {
				errorsChan <- fmt.Errorf("failed to fetch access keys for user %s: %w", *user.UserName, err)
				// Continue with other users
				continue
			}

			for _, key := range accessKeys {
				keySpec, signedByEdge := AccessKeyToResourceSpec(key, userARN, i.accountID)
				keySpec.Edges = append(keySpec.Edges, signedByEdge)
				resourcesChan <- keySpec
			}

			// Fetch groups for this user
			groups, err := FetchGroupsForUser(ctx, i.client, i.semaphore, *user.UserName)
			if err != nil {
				errorsChan <- fmt.Errorf("failed to fetch groups for user %s: %w", *user.UserName, err)
				// Continue with other users
				continue
			}

			for _, group := range groups {
				groupARN := *group.Arn
				memberEdge := GroupMemberEdgeSpec(userARN, groupARN)
				// We'll add this edge to an existing group resource; for now, track it
				// in a temporary map (handled in final consolidation)
				_ = memberEdge // Placeholder; will be emitted via separate edge enumeration
			}

			// Fetch attached policies for this user
			attachedPolicies, err := FetchAttachedPolicies(ctx, i.client, i.semaphore, *user.UserName, "User")
			if err != nil {
				errorsChan <- fmt.Errorf("failed to fetch attached policies for user %s: %w", *user.UserName, err)
				// Continue
				continue
			}

			for _, policy := range attachedPolicies {
				hasPermissionEdge := AttachedPolicyToEdgeSpec(userARN, *policy.PolicyArn)
				userSpec.Edges = append(userSpec.Edges, hasPermissionEdge)
			}

			// Fetch inline policies for this user
			inlinePolicies, err := FetchInlinePolicies(ctx, i.client, i.semaphore, *user.UserName, "User")
			if err != nil {
				errorsChan <- fmt.Errorf("failed to fetch inline policies for user %s: %w", *user.UserName, err)
				// Continue
				continue
			}

			for _, inlinePolicy := range inlinePolicies {
				// Parse the inline policy document
				doc, err := ParsePolicyDocument(inlinePolicy.Document)
				if err != nil {
					errorsChan <- fmt.Errorf("failed to parse inline policy %s for user %s: %w", inlinePolicy.PolicyName, *user.UserName, err)
					continue
				}

				// Create Permission node for each statement
				for idx, stmt := range doc.Statement {
					if stmt.Effect != "Allow" {
						continue
					}

					permissionID := StatementToPermissionID(userARN, inlinePolicy.PolicyName, idx, stmt.Sid)
					permissionSpec := ingest.ResourceSpec{
						Label: "Permission",
						ID:    permissionID,
						Properties: map[string]interface{}{
							"policy_name":  inlinePolicy.PolicyName,
							"statement_id": stmt.Sid,
							"effect":       stmt.Effect,
							"inline":       true,
							"account_id":   i.accountID,
						},
						Edges: []ingest.EdgeSpec{},
					}
					resourcesChan <- permissionSpec

					// Create HasPermission edge
					hasPermissionEdge := ingest.EdgeSpec{
						FromID:   userARN,
						ToID:     permissionID,
						EdgeType: "HasPermission",
						Properties: map[string]interface{}{
							"attachment_type": "inline",
						},
					}
					userSpec.Edges = append(userSpec.Edges, hasPermissionEdge)

					// Process Resource array in the statement
					resources := StringArrayFromInterface(stmt.Resource)
					for _, resource := range resources {
						if IsValidNodeID(resource) {
							containsEdge := ContainsEdgeSpec(permissionID, resource)
							permissionSpec.Edges = append(permissionSpec.Edges, containsEdge)
						}
					}
				}
			}
		}

		// Enumerate roles
		roles, err := FetchRoles(ctx, i.client, i.semaphore)
		if err != nil {
			errorsChan <- fmt.Errorf("failed to fetch roles: %w", err)
			return
		}

		for _, role := range roles {
			roleARN := *role.Arn
			roleSpec := RoleToResourceSpec(role, i.accountID)
			resourcesChan <- roleSpec

			// Parse trust policy to get CanAssume and TrustedBy edges
			trustPolicyJSON := *role.AssumeRolePolicyDocument
			servicePrincipals, trustEdges, err := ParseTrustPolicy(roleARN, trustPolicyJSON)
			if err != nil {
				errorsChan <- fmt.Errorf("failed to parse trust policy for role %s: %w", *role.RoleName, err)
				// Continue with other roles
				continue
			}

			// Emit ServicePrincipal resources
			for _, sp := range servicePrincipals {
				resourcesChan <- sp
			}

			// Attach trust edges to the role spec
			roleSpec.Edges = append(roleSpec.Edges, trustEdges...)

			// Fetch attached policies for this role
			attachedPolicies, err := FetchAttachedPolicies(ctx, i.client, i.semaphore, *role.RoleName, "Role")
			if err != nil {
				errorsChan <- fmt.Errorf("failed to fetch attached policies for role %s: %w", *role.RoleName, err)
				// Continue
				continue
			}

			for _, policy := range attachedPolicies {
				hasPermissionEdge := AttachedPolicyToEdgeSpec(roleARN, *policy.PolicyArn)
				roleSpec.Edges = append(roleSpec.Edges, hasPermissionEdge)
			}

			// Fetch inline policies for this role
			inlinePolicies, err := FetchInlinePolicies(ctx, i.client, i.semaphore, *role.RoleName, "Role")
			if err != nil {
				errorsChan <- fmt.Errorf("failed to fetch inline policies for role %s: %w", *role.RoleName, err)
				// Continue
				continue
			}

			for _, inlinePolicy := range inlinePolicies {
				// Parse the inline policy document
				doc, err := ParsePolicyDocument(inlinePolicy.Document)
				if err != nil {
					errorsChan <- fmt.Errorf("failed to parse inline policy %s for role %s: %w", inlinePolicy.PolicyName, *role.RoleName, err)
					continue
				}

				// Create Permission node for each statement
				for idx, stmt := range doc.Statement {
					if stmt.Effect != "Allow" {
						continue
					}

					permissionID := StatementToPermissionID(roleARN, inlinePolicy.PolicyName, idx, stmt.Sid)
					permissionSpec := ingest.ResourceSpec{
						Label: "Permission",
						ID:    permissionID,
						Properties: map[string]interface{}{
							"policy_name":  inlinePolicy.PolicyName,
							"statement_id": stmt.Sid,
							"effect":       stmt.Effect,
							"inline":       true,
							"account_id":   i.accountID,
						},
						Edges: []ingest.EdgeSpec{},
					}
					resourcesChan <- permissionSpec

					// Create HasPermission edge
					hasPermissionEdge := ingest.EdgeSpec{
						FromID:   roleARN,
						ToID:     permissionID,
						EdgeType: "HasPermission",
						Properties: map[string]interface{}{
							"attachment_type": "inline",
						},
					}
					roleSpec.Edges = append(roleSpec.Edges, hasPermissionEdge)

					// Process Resource array in the statement
					resources := StringArrayFromInterface(stmt.Resource)
					for _, resource := range resources {
						if IsValidNodeID(resource) {
							containsEdge := ContainsEdgeSpec(permissionID, resource)
							permissionSpec.Edges = append(permissionSpec.Edges, containsEdge)
						}
					}
				}
			}
		}

		// Enumerate groups
		groups, err := FetchGroups(ctx, i.client, i.semaphore)
		if err != nil {
			errorsChan <- fmt.Errorf("failed to fetch groups: %w", err)
			return
		}

		for _, group := range groups {
			groupARN := *group.Arn
			groupSpec := GroupToResourceSpec(group, i.accountID)
			resourcesChan <- groupSpec

			// Fetch attached policies for this group
			attachedPolicies, err := FetchAttachedPolicies(ctx, i.client, i.semaphore, *group.GroupName, "Group")
			if err != nil {
				errorsChan <- fmt.Errorf("failed to fetch attached policies for group %s: %w", *group.GroupName, err)
				// Continue
				continue
			}

			for _, policy := range attachedPolicies {
				hasPermissionEdge := AttachedPolicyToEdgeSpec(groupARN, *policy.PolicyArn)
				groupSpec.Edges = append(groupSpec.Edges, hasPermissionEdge)
			}

			// Fetch inline policies for this group
			inlinePolicies, err := FetchInlinePolicies(ctx, i.client, i.semaphore, *group.GroupName, "Group")
			if err != nil {
				errorsChan <- fmt.Errorf("failed to fetch inline policies for group %s: %w", *group.GroupName, err)
				// Continue
				continue
			}

			for _, inlinePolicy := range inlinePolicies {
				// Parse the inline policy document
				doc, err := ParsePolicyDocument(inlinePolicy.Document)
				if err != nil {
					errorsChan <- fmt.Errorf("failed to parse inline policy %s for group %s: %w", inlinePolicy.PolicyName, *group.GroupName, err)
					continue
				}

				// Create Permission node for each statement
				for idx, stmt := range doc.Statement {
					if stmt.Effect != "Allow" {
						continue
					}

					permissionID := StatementToPermissionID(groupARN, inlinePolicy.PolicyName, idx, stmt.Sid)
					permissionSpec := ingest.ResourceSpec{
						Label: "Permission",
						ID:    permissionID,
						Properties: map[string]interface{}{
							"policy_name":  inlinePolicy.PolicyName,
							"statement_id": stmt.Sid,
							"effect":       stmt.Effect,
							"inline":       true,
							"account_id":   i.accountID,
						},
						Edges: []ingest.EdgeSpec{},
					}
					resourcesChan <- permissionSpec

					// Create HasPermission edge
					hasPermissionEdge := ingest.EdgeSpec{
						FromID:   groupARN,
						ToID:     permissionID,
						EdgeType: "HasPermission",
						Properties: map[string]interface{}{
							"attachment_type": "inline",
						},
					}
					groupSpec.Edges = append(groupSpec.Edges, hasPermissionEdge)

					// Process Resource array in the statement
					resources := StringArrayFromInterface(stmt.Resource)
					for _, resource := range resources {
						if IsValidNodeID(resource) {
							containsEdge := ContainsEdgeSpec(permissionID, resource)
							permissionSpec.Edges = append(permissionSpec.Edges, containsEdge)
						}
					}
				}
			}
		}

		// Enumerate managed policies
		policies, err := FetchPolicies(ctx, i.client, i.semaphore)
		if err != nil {
			errorsChan <- fmt.Errorf("failed to fetch policies: %w", err)
			return
		}

		for _, policy := range policies {
			policyARN := *policy.Policy.Arn
			policySpec := PolicyToResourceSpec(policyARN, *policy.Policy.PolicyName, i.accountID, policy.Document)
			resourcesChan <- policySpec
		}
	}()

	return resourcesChan, errorsChan
}
