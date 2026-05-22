package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	ingest "github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"golang.org/x/sync/semaphore"
)

// IAMIngester implements the ingest.Ingester interface for AWS IAM resources.
type IAMIngester struct {
	client    IAMClient
	accountID string
	sem       *semaphore.Weighted
}

// NewIAMIngester creates a new IAM ingester.
func NewIAMIngester(client IAMClient, accountID string, concurrencyLimit int64) *IAMIngester {
	if concurrencyLimit <= 0 {
		concurrencyLimit = 3 // Default to 3 concurrent calls for IAM
	}

	return &IAMIngester{
		client:    client,
		accountID: accountID,
		sem:       semaphore.NewWeighted(concurrencyLimit),
	}
}

// Service returns the service name for this ingester.
func (i *IAMIngester) Service() string {
	return "iam"
}

// RequiredIAMActions returns the list of IAM actions required for this ingester.
func (i *IAMIngester) RequiredIAMActions() []string {
	return []string{
		"iam:ListUsers",
		"iam:GetUser",
		"iam:ListRoles",
		"iam:GetRole",
		"iam:ListGroups",
		"iam:GetGroup",
		"iam:ListGroupsForUser",
		"iam:ListPolicies",
		"iam:GetPolicy",
		"iam:GetPolicyVersion",
		"iam:ListAttachedUserPolicies",
		"iam:ListAttachedRolePolicies",
		"iam:ListAttachedGroupPolicies",
		"iam:ListUserPolicies",
		"iam:GetUserPolicy",
		"iam:ListRolePolicies",
		"iam:GetRolePolicy",
		"iam:ListGroupPolicies",
		"iam:GetGroupPolicy",
		"iam:ListAccessKeys",
		"iam:ListSAMLProviders",
		"iam:ListOpenIDConnectProviders",
	}
}

// Enumerate enumerates all IAM resources and returns them via a channel.
func (i *IAMIngester) Enumerate(ctx context.Context) (<-chan ingest.ResourceSpec, <-chan error) {
	resourcesChan := make(chan ingest.ResourceSpec, 100)
	errorsChan := make(chan error, 20)

	go func() {
		defer close(resourcesChan)
		defer close(errorsChan)

		// Enumerate users
		if err := i.enumerateUsers(ctx, resourcesChan); err != nil {
			errorsChan <- fmt.Errorf("enumerate users: %w", err)
		}

		// Enumerate roles
		if err := i.enumerateRoles(ctx, resourcesChan); err != nil {
			errorsChan <- fmt.Errorf("enumerate roles: %w", err)
		}

		// Enumerate groups
		if err := i.enumerateGroups(ctx, resourcesChan); err != nil {
			errorsChan <- fmt.Errorf("enumerate groups: %w", err)
		}

		// Enumerate policies
		if err := i.enumeratePolicies(ctx, resourcesChan); err != nil {
			errorsChan <- fmt.Errorf("enumerate policies: %w", err)
		}

		// Enumerate access keys
		if err := i.enumerateAccessKeys(ctx, resourcesChan); err != nil {
			errorsChan <- fmt.Errorf("enumerate access keys: %w", err)
		}

		// Enumerate federated providers
		if err := i.enumerateFederatedProviders(ctx, resourcesChan); err != nil {
			errorsChan <- fmt.Errorf("enumerate federated providers: %w", err)
		}
	}()

	return resourcesChan, errorsChan
}

// enumerateUsers fetches all IAM users and emits them as resource specs.
func (i *IAMIngester) enumerateUsers(ctx context.Context, resourcesChan chan<- ingest.ResourceSpec) error {
	if err := i.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer i.sem.Release(1)

	paginator := iam.NewListUsersPaginator(i.client, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ListUsers pagination error: %w", err)
		}

		for _, user := range page.Users {
			spec := UserToResourceSpec(user, i.accountID)
			select {
			case resourcesChan <- spec:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return nil
}

// enumerateRoles fetches all IAM roles and emits them as resource specs.
func (i *IAMIngester) enumerateRoles(ctx context.Context, resourcesChan chan<- ingest.ResourceSpec) error {
	if err := i.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer i.sem.Release(1)

	paginator := iam.NewListRolesPaginator(i.client, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ListRoles pagination error: %w", err)
		}

		for _, role := range page.Roles {
			spec := RoleToResourceSpec(role, i.accountID)
			select {
			case resourcesChan <- spec:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return nil
}

// enumerateGroups fetches all IAM groups and emits them as resource specs.
func (i *IAMIngester) enumerateGroups(ctx context.Context, resourcesChan chan<- ingest.ResourceSpec) error {
	if err := i.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer i.sem.Release(1)

	paginator := iam.NewListGroupsPaginator(i.client, &iam.ListGroupsInput{})

	for paginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ListGroups pagination error: %w", err)
		}

		for _, group := range page.Groups {
			spec := GroupToResourceSpec(group, i.accountID)
			select {
			case resourcesChan <- spec:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return nil
}

// enumeratePolicies fetches all IAM policies and emits their statements as Permission specs.
func (i *IAMIngester) enumeratePolicies(ctx context.Context, resourcesChan chan<- ingest.ResourceSpec) error {
	if err := i.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer i.sem.Release(1)

	paginator := iam.NewListPoliciesPaginator(i.client, &iam.ListPoliciesInput{
		Scope: types.PolicyScopeTypeLocal, // Customer-managed policies only in v1
	})

	for paginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ListPolicies pagination error: %w", err)
		}

		for _, policy := range page.Policies {
			policyArn := StringValue(policy.Arn)

			// Fetch the policy version to get the statement
			policyVersionID := StringValue(policy.DefaultVersionId)
			getResp, err := i.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: &policyArn,
				VersionId: &policyVersionID,
			})
			if err != nil {
				log.Printf("failed to get policy version for %s: %v", policyArn, err)
				continue
			}

			if getResp.PolicyVersion == nil || getResp.PolicyVersion.Document == nil {
				continue
			}

			// Parse the policy document to extract statements
			// The Document is a URL-encoded JSON string
			policyDocument := StringValue(getResp.PolicyVersion.Document)

			var policyObj map[string]interface{}
			if err := parsePolicyDocument(policyDocument, &policyObj); err != nil {
				log.Printf("failed to parse policy document for %s: %v", policyArn, err)
				continue
			}

			// Extract statements and emit Permission specs
			if statements, ok := policyObj["Statement"].([]interface{}); ok {
				for idx, stmt := range statements {
					if stmtMap, ok := stmt.(map[string]interface{}); ok {
						// Extract SID
						sid := ""
						if sidVal, ok := stmtMap["Sid"].(string); ok {
							sid = sidVal
						} else {
							sid = fmt.Sprintf("stmt-%d", idx)
						}

						// Extract action list
						actions := parseStringOrStringArray(stmtMap["Action"])

						// Extract resource list
						resources := parseStringOrStringArray(stmtMap["Resource"])

						// Create Permission spec
						spec := PolicyStatementToResourceSpec(policyArn, sid, actions, resources)
						select {
						case resourcesChan <- spec:
						case <-ctx.Done():
							return ctx.Err()
						}
					}
				}
			}
		}
	}

	return nil
}

// enumerateAccessKeys fetches access keys for all users and emits them as resource specs.
func (i *IAMIngester) enumerateAccessKeys(ctx context.Context, resourcesChan chan<- ingest.ResourceSpec) error {
	if err := i.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer i.sem.Release(1)

	// First, get all users
	userPaginator := iam.NewListUsersPaginator(i.client, &iam.ListUsersInput{})

	for userPaginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		userPage, err := userPaginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ListUsers for access keys: %w", err)
		}

		for _, user := range userPage.Users {
			userName := StringValue(user.UserName)
			userArn := StringValue(user.Arn)

			// List access keys for this user
			keyPaginator := iam.NewListAccessKeysPaginator(i.client, &iam.ListAccessKeysInput{
				UserName: &userName,
			})

			for keyPaginator.HasMorePages() {
				keyPage, err := keyPaginator.NextPage(ctx)
				if err != nil {
					log.Printf("failed to list access keys for user %s: %v", userName, err)
					continue
				}

				for _, key := range keyPage.AccessKeyMetadata {
					nodeSpec, edgeSpec := AccessKeyToResourceSpec(key, userArn)

					select {
					case resourcesChan <- nodeSpec:
					case <-ctx.Done():
						return ctx.Err()
					}

					// Note: edges are handled separately in EnumerateEdges
					_ = edgeSpec
				}
			}
		}
	}

	return nil
}

// enumerateFederatedProviders fetches SAML and OIDC providers and emits them as resource specs.
func (i *IAMIngester) enumerateFederatedProviders(ctx context.Context, resourcesChan chan<- ingest.ResourceSpec) error {
	if err := i.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer i.sem.Release(1)

	// List SAML providers
	samlResp, err := i.client.ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{})
	if err != nil {
		log.Printf("failed to list SAML providers: %v", err)
	} else if samlResp.SAMLProviderList != nil {
		for _, provider := range samlResp.SAMLProviderList {
			providerArn := StringValue(provider.Arn)
			if providerArn != "" {
				spec := FederatedProviderToResourceSpec(providerArn)
				select {
				case resourcesChan <- spec:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}

	// List OpenID Connect providers
	oidcResp, err := i.client.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		log.Printf("failed to list OpenID Connect providers: %v", err)
	} else if oidcResp.OpenIDConnectProviderList != nil {
		for _, provider := range oidcResp.OpenIDConnectProviderList {
			providerArn := StringValue(provider.Arn)
			if providerArn != "" {
				spec := FederatedProviderToResourceSpec(providerArn)
				select {
				case resourcesChan <- spec:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}

	return nil
}

// Helper functions

// parsePolicyDocument parses a policy document (which may be URL-encoded JSON).
func parsePolicyDocument(docStr string, result *map[string]interface{}) error {
	// For now, attempt direct JSON parsing; AWS policy documents are typically valid JSON
	// In production, handle URL encoding if needed
	return json.Unmarshal([]byte(docStr), result)
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
