package sts

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	ingest "github.com/activable-cloud/activable.cloud/go/internal/ingest"
)

// STSIngester implements the ingest.Ingester interface for AWS STS.
// In v1, STS produces no graph nodes; it serves only to resolve the account ID.
// The account ID resolution is handled by Runtime.Ingest.
type STSIngester struct {
	client    STSClient
	accountID string
}

// NewSTSIngester creates a new STS ingester.
func NewSTSIngester(client STSClient, accountID string) *STSIngester {
	return &STSIngester{
		client:    client,
		accountID: accountID,
	}
}

// Service returns the service name for this ingester.
func (i *STSIngester) Service() string {
	return "sts"
}

// RequiredIAMActions returns the list of IAM actions required for this ingester.
func (i *STSIngester) RequiredIAMActions() []string {
	return []string{
		"sts:GetCallerIdentity",
	}
}

// Enumerate returns channels for resources and errors.
// STS produces no resources in v1; the channel is closed immediately.
// Account ID resolution is tested separately via ResolveAccountID.
func (i *STSIngester) Enumerate(ctx context.Context) (<-chan ingest.ResourceSpec, <-chan error) {
	resourcesChan := make(chan ingest.ResourceSpec)
	errorsChan := make(chan error)

	go func() {
		defer close(resourcesChan)
		defer close(errorsChan)
		// STS produces no nodes in v1; just exit cleanly.
	}()

	return resourcesChan, errorsChan
}

// ResolveAccountID resolves the AWS account ID for the current caller.
// Returns the account ID string or an error if the call fails.
func (i *STSIngester) ResolveAccountID(ctx context.Context) (string, error) {
	input := &sts.GetCallerIdentityInput{}
	output, err := i.client.GetCallerIdentity(ctx, input)
	if err != nil {
		return "", fmt.Errorf("GetCallerIdentity failed: %w", err)
	}

	if output.Account == nil {
		return "", fmt.Errorf("GetCallerIdentity returned no account ID")
	}

	return *output.Account, nil
}
