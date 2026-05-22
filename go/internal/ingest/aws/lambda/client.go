package lambda

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

// LambdaClient defines the interface for AWS Lambda API operations.
// This interface allows for mock testing without making real AWS calls.
type LambdaClient interface {
	ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}
