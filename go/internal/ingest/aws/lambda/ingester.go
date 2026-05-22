package lambda

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	ingest "github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"golang.org/x/sync/semaphore"
)

// LambdaIngester implements the ingest.Ingester interface for AWS Lambda resources.
// Lambda is regional; instantiate one ingester per enabled region.
type LambdaIngester struct {
	client    LambdaClient
	region    string
	accountID string
	sem       *semaphore.Weighted
}

// NewLambdaIngester creates a new Lambda ingester for a specific region.
func NewLambdaIngester(client LambdaClient, region string, accountID string, concurrencyLimit int64) *LambdaIngester {
	if concurrencyLimit <= 0 {
		concurrencyLimit = 3 // Default to 3 concurrent calls for Lambda
	}

	return &LambdaIngester{
		client:    client,
		region:    region,
		accountID: accountID,
		sem:       semaphore.NewWeighted(concurrencyLimit),
	}
}

// Service returns the service name for this ingester.
func (i *LambdaIngester) Service() string {
	return "lambda"
}

// RequiredIAMActions returns the list of IAM actions required for this ingester.
func (i *LambdaIngester) RequiredIAMActions() []string {
	return []string{
		"lambda:ListFunctions",
		"lambda:GetPolicy",
	}
}

// Enumerate enumerates all Lambda functions in the ingester's region.
func (i *LambdaIngester) Enumerate(ctx context.Context) (<-chan ingest.ResourceSpec, <-chan error) {
	resourcesChan := make(chan ingest.ResourceSpec, 100)
	errorsChan := make(chan error, 10)

	go func() {
		defer close(resourcesChan)
		defer close(errorsChan)

		if err := i.enumerateFunctions(ctx, resourcesChan); err != nil {
			errorsChan <- fmt.Errorf("enumerate functions: %w", err)
		}
	}()

	return resourcesChan, errorsChan
}

// enumerateFunctions fetches all Lambda functions in the region.
func (i *LambdaIngester) enumerateFunctions(ctx context.Context, resourcesChan chan<- ingest.ResourceSpec) error {
	if err := i.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer i.sem.Release(1)

	paginator := lambda.NewListFunctionsPaginator(i.client, &lambda.ListFunctionsInput{})

	for paginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ListFunctions pagination error: %w", err)
		}

		if len(page.Functions) == 0 {
			continue
		}

		for _, function := range page.Functions {
			// Emit function resource spec
			spec := FunctionToResourceSpec(function)
			select {
			case resourcesChan <- spec:
			case <-ctx.Done():
				return ctx.Err()
			}

			// Fetch function policy
			if function.FunctionName != nil {
				functionName := *function.FunctionName
				policy, err := i.client.GetPolicy(ctx, &lambda.GetPolicyInput{
					FunctionName: &functionName,
				})

				// GetPolicy returns 404 (ResourceNotFoundException) if no policy exists.
				// This is expected and not an error.
				if err != nil {
					if !isNotFoundError(err) {
						log.Printf("failed to get policy for function %s: %v", functionName, err)
					}
					continue
				}

				if policy.Policy == nil {
					continue
				}

				// Parse the policy and emit Permission specs
				permissionSpecs, err := FunctionPolicyToPermissionSpec(functionName, *policy.Policy)
				if err != nil {
					log.Printf("failed to parse policy for function %s: %v", functionName, err)
					continue
				}

				for _, permSpec := range permissionSpecs {
					select {
					case resourcesChan <- permSpec:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			}
		}
	}

	return nil
}

// isNotFoundError checks if the error is a 404 ResourceNotFoundException.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// Check if it's a 404 error code by checking the error message.
	errMsg := err.Error()
	return errMsg == "ResourceNotFoundException"
}
