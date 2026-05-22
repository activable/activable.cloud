package lambda

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/smithy-go"
	"golang.org/x/sync/semaphore"
)

// FetchFunctions fetches all Lambda functions in the region.
func FetchFunctions(ctx context.Context, client LambdaClient, sem *semaphore.Weighted) ([]FunctionInfo, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("semaphore acquire failed: %w", err)
	}
	defer sem.Release(1)

	output, err := client.ListFunctions(ctx, &lambda.ListFunctionsInput{})
	if err != nil {
		return nil, fmt.Errorf("ListFunctions failed: %w", err)
	}

	if output == nil || output.Functions == nil {
		return []FunctionInfo{}, nil
	}

	var functions []FunctionInfo
	for _, fn := range output.Functions {
		role := ""
		if fn.Role != nil {
			role = *fn.Role
		}

		functions = append(functions, FunctionInfo{
			FunctionName: *fn.FunctionName,
			FunctionArn:  *fn.FunctionArn,
			Role:         role,
		})
	}

	return functions, nil
}

// FetchFunctionPolicy fetches the resource policy for a Lambda function.
// Returns an empty string if the function has no policy (404 ResourceNotFoundException).
// Returns an error for other API failures.
func FetchFunctionPolicy(ctx context.Context, client LambdaClient, sem *semaphore.Weighted, functionName string) (string, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return "", fmt.Errorf("semaphore acquire failed: %w", err)
	}
	defer sem.Release(1)

	output, err := client.GetPolicy(ctx, &lambda.GetPolicyInput{
		FunctionName: aws.String(functionName),
	})

	// Handle ResourceNotFoundException (404) as "no policy" rather than an error
	if err != nil {
		if isResourceNotFoundError(err) {
			return "", nil
		}
		return "", fmt.Errorf("GetPolicy failed: %w", err)
	}

	if output == nil || output.Policy == nil {
		return "", nil
	}

	return *output.Policy, nil
}

// isResourceNotFoundError checks if an error is a ResourceNotFoundException (404) error.
func isResourceNotFoundError(err error) bool {
	var apiErr smithy.APIError
	if err == nil {
		return false
	}
	if !as(err, &apiErr) {
		return false
	}
	return apiErr.ErrorCode() == "ResourceNotFoundException"
}

// as is a simple type assertion helper to avoid verbose error casting.
func as(err error, target interface{}) bool {
	return errorAs(err, target)
}

// errorAs mimics the behavior of errors.As for API errors.
func errorAs(err error, target interface{}) bool {
	if err == nil {
		return false
	}
	switch target := target.(type) {
	case *smithy.APIError:
		if apiErr, ok := err.(smithy.APIError); ok {
			*target = apiErr
			return true
		}
	}
	return false
}
