package iam

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"golang.org/x/sync/semaphore"
)

// FetchUsers lists all IAM users in the account.
func FetchUsers(ctx context.Context, client *iam.Client, sem *semaphore.Weighted) ([]types.User, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("failed to acquire semaphore: %w", err)
	}
	defer sem.Release(1)

	var users []types.User
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListUsers failed: %w", err)
		}
		users = append(users, page.Users...)
	}

	return users, nil
}

// FetchRoles lists all IAM roles in the account.
func FetchRoles(ctx context.Context, client *iam.Client, sem *semaphore.Weighted) ([]types.Role, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("failed to acquire semaphore: %w", err)
	}
	defer sem.Release(1)

	var roles []types.Role
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListRoles failed: %w", err)
		}
		roles = append(roles, page.Roles...)
	}

	return roles, nil
}

// FetchGroups lists all IAM groups in the account.
func FetchGroups(ctx context.Context, client *iam.Client, sem *semaphore.Weighted) ([]types.Group, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("failed to acquire semaphore: %w", err)
	}
	defer sem.Release(1)

	var groups []types.Group
	paginator := iam.NewListGroupsPaginator(client, &iam.ListGroupsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListGroups failed: %w", err)
		}
		groups = append(groups, page.Groups...)
	}

	return groups, nil
}

// PolicyDocument holds a managed policy and its document.
type PolicyDocument struct {
	Policy   types.Policy
	Document string
}

// FetchPolicies lists all customer-managed policies and their documents.
// Scope=Local filters out AWS-managed policies; we discover those only via attached policy lists.
func FetchPolicies(ctx context.Context, client *iam.Client, sem *semaphore.Weighted) ([]PolicyDocument, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("failed to acquire semaphore: %w", err)
	}
	defer sem.Release(1)

	var policies []PolicyDocument
	paginator := iam.NewListPoliciesPaginator(client, &iam.ListPoliciesInput{
		Scope: "Local", // Customer-managed only
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListPolicies failed: %w", err)
		}

		for _, policy := range page.Policies {
			// Fetch the default version document
			docOutput, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: policy.Arn,
				VersionId: policy.DefaultVersionId,
			})
			if err != nil {
				// Skip policies with fetch errors; log in real implementation
				continue
			}

			// Decode the policy document (URL-encoded JSON)
			docStr := *docOutput.PolicyVersion.Document
			policies = append(policies, PolicyDocument{
				Policy:   policy,
				Document: docStr,
			})
		}
	}

	return policies, nil
}

// FetchAccessKeys lists all access keys for a specific user.
func FetchAccessKeys(ctx context.Context, client *iam.Client, sem *semaphore.Weighted, userName string) ([]types.AccessKeyMetadata, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("failed to acquire semaphore: %w", err)
	}
	defer sem.Release(1)

	var keys []types.AccessKeyMetadata
	paginator := iam.NewListAccessKeysPaginator(client, &iam.ListAccessKeysInput{
		UserName: &userName,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListAccessKeys failed for user %s: %w", userName, err)
		}
		keys = append(keys, page.AccessKeyMetadata...)
	}

	return keys, nil
}

// FetchGroupsForUser lists all groups that a user belongs to.
func FetchGroupsForUser(ctx context.Context, client *iam.Client, sem *semaphore.Weighted, userName string) ([]types.Group, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("failed to acquire semaphore: %w", err)
	}
	defer sem.Release(1)

	var groups []types.Group
	paginator := iam.NewListGroupsForUserPaginator(client, &iam.ListGroupsForUserInput{
		UserName: &userName,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListGroupsForUser failed for user %s: %w", userName, err)
		}
		groups = append(groups, page.Groups...)
	}

	return groups, nil
}

// FetchAttachedPolicies lists all policies attached to a principal (user, role, or group).
func FetchAttachedPolicies(ctx context.Context, client *iam.Client, sem *semaphore.Weighted, principalName string, principalType string) ([]types.AttachedPolicy, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("failed to acquire semaphore: %w", err)
	}
	defer sem.Release(1)

	var attachedPolicies []types.AttachedPolicy

	switch principalType {
	case "User":
		paginator := iam.NewListAttachedUserPoliciesPaginator(client, &iam.ListAttachedUserPoliciesInput{
			UserName: &principalName,
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("ListAttachedUserPolicies failed: %w", err)
			}
			attachedPolicies = append(attachedPolicies, page.AttachedPolicies...)
		}

	case "Role":
		paginator := iam.NewListAttachedRolePoliciesPaginator(client, &iam.ListAttachedRolePoliciesInput{
			RoleName: &principalName,
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("ListAttachedRolePolicies failed: %w", err)
			}
			attachedPolicies = append(attachedPolicies, page.AttachedPolicies...)
		}

	case "Group":
		paginator := iam.NewListAttachedGroupPoliciesPaginator(client, &iam.ListAttachedGroupPoliciesInput{
			GroupName: &principalName,
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("ListAttachedGroupPolicies failed: %w", err)
			}
			attachedPolicies = append(attachedPolicies, page.AttachedPolicies...)
		}

	default:
		return nil, fmt.Errorf("unknown principal type: %s", principalType)
	}

	return attachedPolicies, nil
}

// InlinePolicyDocument holds an inline policy and its document.
type InlinePolicyDocument struct {
	PolicyName string
	Document   string
}

// FetchInlinePolicies lists all inline policies attached to a principal.
func FetchInlinePolicies(ctx context.Context, client *iam.Client, sem *semaphore.Weighted, principalName string, principalType string) ([]InlinePolicyDocument, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("failed to acquire semaphore: %w", err)
	}
	defer sem.Release(1)

	var inlinePolicies []InlinePolicyDocument

	switch principalType {
	case "User":
		paginator := iam.NewListUserPoliciesPaginator(client, &iam.ListUserPoliciesInput{
			UserName: &principalName,
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("ListUserPolicies failed: %w", err)
			}

			for _, policyName := range page.PolicyNames {
				docOutput, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
					UserName:   &principalName,
					PolicyName: &policyName,
				})
				if err != nil {
					continue
				}
				inlinePolicies = append(inlinePolicies, InlinePolicyDocument{
					PolicyName: policyName,
					Document:   *docOutput.PolicyDocument,
				})
			}
		}

	case "Role":
		paginator := iam.NewListRolePoliciesPaginator(client, &iam.ListRolePoliciesInput{
			RoleName: &principalName,
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("ListRolePolicies failed: %w", err)
			}

			for _, policyName := range page.PolicyNames {
				docOutput, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
					RoleName:   &principalName,
					PolicyName: &policyName,
				})
				if err != nil {
					continue
				}
				inlinePolicies = append(inlinePolicies, InlinePolicyDocument{
					PolicyName: policyName,
					Document:   *docOutput.PolicyDocument,
				})
			}
		}

	case "Group":
		paginator := iam.NewListGroupPoliciesPaginator(client, &iam.ListGroupPoliciesInput{
			GroupName: &principalName,
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("ListGroupPolicies failed: %w", err)
			}

			for _, policyName := range page.PolicyNames {
				docOutput, err := client.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{
					GroupName:  &principalName,
					PolicyName: &policyName,
				})
				if err != nil {
					continue
				}
				inlinePolicies = append(inlinePolicies, InlinePolicyDocument{
					PolicyName: policyName,
					Document:   *docOutput.PolicyDocument,
				})
			}
		}

	default:
		return nil, fmt.Errorf("unknown principal type: %s", principalType)
	}

	return inlinePolicies, nil
}

// PolicyStatementDocument represents a parsed policy document with its statements.
type PolicyStatementDocument struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

// PolicyStatement represents a single statement in a policy document.
type PolicyStatement struct {
	Sid       string        `json:"Sid,omitempty"`
	Effect    string        `json:"Effect"`
	Action    interface{}   `json:"Action"`
	Resource  interface{}   `json:"Resource"`
	Condition interface{}   `json:"Condition,omitempty"`
}

// ParsePolicyDocument parses a policy document JSON and returns statement details.
func ParsePolicyDocument(docJSON string) (PolicyStatementDocument, error) {
	var doc PolicyStatementDocument
	err := json.Unmarshal([]byte(docJSON), &doc)
	return doc, err
}

// StringArrayFromInterface converts an interface that could be a string or []string to a []string.
func StringArrayFromInterface(val interface{}) []string {
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
