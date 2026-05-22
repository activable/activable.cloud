package sts

import (
	"context"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// STSIngester implements the Ingester interface for AWS STS.
// STS is used primarily to resolve the account ID via GetCallerIdentity.
// In v1, STS does not produce graph nodes; it is used internally by Runtime
// to establish account context.
type STSIngester struct {
	client    *sts.Client
	accountID string
}

// NewSTSIngester creates a new STS ingester.
func NewSTSIngester(client *sts.Client, accountID string) *STSIngester {
	return &STSIngester{
		client:    client,
		accountID: accountID,
	}
}

// Service returns the service name.
func (i *STSIngester) Service() string {
	return "sts"
}

// RequiredIAMActions returns the IAM actions required for this ingester.
func (i *STSIngester) RequiredIAMActions() []string {
	return []string{
		"sts:GetCallerIdentity",
	}
}

// Enumerate fetches account identity and emits a single Account node.
// STS is a global service, so the region parameter is ignored.
func (i *STSIngester) Enumerate(ctx context.Context, region string) (<-chan ingest.ResourceSpec, <-chan error) {
	resourcesChan := make(chan ingest.ResourceSpec, 10)
	errorsChan := make(chan error, 5)

	go func() {
		defer close(resourcesChan)
		defer close(errorsChan)

		// Emit account node
		accountSpec := ingest.ResourceSpec{
			Label: "Account",
			ID:    i.accountID,
			Properties: map[string]interface{}{
				"account_id": i.accountID,
			},
			Edges: []ingest.EdgeSpec{},
		}
		resourcesChan <- accountSpec
	}()

	return resourcesChan, errorsChan
}
