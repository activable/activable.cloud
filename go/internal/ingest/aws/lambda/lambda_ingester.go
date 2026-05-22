package lambda

import (
	"context"
	"fmt"
	"sync"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"golang.org/x/sync/semaphore"
)

const (
	// MaxConcurrentCalls is the maximum number of concurrent AWS API calls for Lambda.
	MaxConcurrentCalls = 3
)

// LambdaClient defines the interface for Lambda API calls we use in the ingester.
type LambdaClient interface {
	ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

// LambdaIngester implements the Ingester interface for AWS Lambda.
// Lambda is a regional service; one ingester is instantiated per region.
type LambdaIngester struct {
	client    LambdaClient
	region    string
	accountID string
	semaphore *semaphore.Weighted
}

// NewLambdaIngester creates a new Lambda ingester for a specific region.
func NewLambdaIngester(client LambdaClient, region, accountID string) *LambdaIngester {
	return &LambdaIngester{
		client:    client,
		region:    region,
		accountID: accountID,
		semaphore: semaphore.NewWeighted(MaxConcurrentCalls),
	}
}

// Service returns the service name.
func (i *LambdaIngester) Service() string {
	return "lambda"
}

// RequiredIAMActions returns the IAM actions required for this ingester.
func (i *LambdaIngester) RequiredIAMActions() []string {
	return []string{
		"lambda:ListFunctions",
		"lambda:GetPolicy",
	}
}

// Enumerate fetches all Lambda functions and their policies, emitting them as resources.
// Lambda is regional; the region parameter determines which region to enumerate.
func (i *LambdaIngester) Enumerate(ctx context.Context, region string) (<-chan ingest.ResourceSpec, <-chan error) {
	resourcesChan := make(chan ingest.ResourceSpec, 100)
	errorsChan := make(chan error, 10)

	go func() {
		defer close(resourcesChan)
		defer close(errorsChan)

		// Use region parameter if provided, otherwise use instance region
		enumRegion := region
		if enumRegion == "" {
			enumRegion = i.region
		}

		// Fetch all functions
		functions, err := FetchFunctions(ctx, i.client, i.semaphore)
		if err != nil {
			errorsChan <- fmt.Errorf("failed to fetch functions: %w", err)
			return
		}

		// Process each function
		var wg sync.WaitGroup
		funcChan := make(chan ingest.ResourceSpec, len(functions))
		errChan := make(chan error, len(functions))

		for _, fn := range functions {
			wg.Add(1)
			go func(fn FunctionInfo) {
				defer wg.Done()

				functionARN := fn.FunctionArn
				functionName := fn.FunctionName

				// Emit function resource
				funcSpec := FunctionToResourceSpec(functionARN, functionName, i.accountID)

				// Add CanAssume edge to execution role if present
				if fn.Role != "" {
					funcSpec.Edges = append(funcSpec.Edges, ingest.EdgeSpec{
						FromID:   functionARN,
						ToID:     fn.Role,
						EdgeType: "CanAssume",
						Properties: map[string]interface{}{},
					})
				}

				funcChan <- funcSpec

				// Fetch function policy
				policyJSON, err := FetchFunctionPolicy(ctx, i.client, i.semaphore, functionName)
				if err != nil {
					// 404 is expected for functions with no policy
					errChan <- fmt.Errorf("failed to fetch policy for function %s: %w", functionName, err)
					return
				}

				if policyJSON == "" {
					// No policy attached to this function
					return
				}

				// Parse the policy document and emit Permission nodes
				doc, err := ParsePolicyDocument(policyJSON)
				if err != nil {
					errChan <- fmt.Errorf("failed to parse policy for function %s: %w", functionName, err)
					return
				}

				// Emit Permission nodes for each statement
				for idx, stmt := range doc.Statement {
					if stmt.Effect != "Allow" {
						continue
					}

					permissionID := fmt.Sprintf("%s#function-policy#stmt_%d", functionARN, idx)
					permissionSpec := ingest.ResourceSpec{
						Label: "Permission",
						ID:    permissionID,
						Properties: map[string]interface{}{
							"policy_type":     "FunctionPolicy",
							"statement_id":    stmt.Sid,
							"effect":          stmt.Effect,
							"function_name":   functionName,
							"account_id":      i.accountID,
						},
						Edges: []ingest.EdgeSpec{},
					}
					funcChan <- permissionSpec

					// Emit Contains edges from Permission to Resource ARNs
					resources := StringArrayFromInterface(stmt.Resource)
					for _, resource := range resources {
						if IsValidNodeID(resource) {
							containsEdge := ingest.EdgeSpec{
								FromID:   permissionID,
								ToID:     resource,
								EdgeType: "Contains",
								Properties: map[string]interface{}{},
							}
							permissionSpec.Edges = append(permissionSpec.Edges, containsEdge)
						}
					}
				}
			}(fn)
		}

		// Wait for all goroutines and close channels
		go func() {
			wg.Wait()
			close(funcChan)
			close(errChan)
		}()

		// Drain channels
		for {
			select {
			case fn, ok := <-funcChan:
				if !ok {
					funcChan = nil
				} else {
					resourcesChan <- fn
				}
			case err, ok := <-errChan:
				if !ok {
					errChan = nil
				} else {
					errorsChan <- err
				}
			}
			if funcChan == nil && errChan == nil {
				break
			}
		}
	}()

	return resourcesChan, errorsChan
}
