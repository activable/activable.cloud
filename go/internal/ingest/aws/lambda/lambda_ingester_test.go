package lambda

import (
	"context"
	"testing"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// MockLambdaClient implements LambdaClient for testing.
type MockLambdaClient struct {
	listFunctionsFunc func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	getPolicyFunc     func(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

func (m *MockLambdaClient) ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if m.listFunctionsFunc != nil {
		return m.listFunctionsFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *MockLambdaClient) GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	if m.getPolicyFunc != nil {
		return m.getPolicyFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// TestLambdaIngesterService tests that the service name is correct.
func TestLambdaIngesterService(t *testing.T) {
	ingester := NewLambdaIngester(&MockLambdaClient{}, "us-east-1", "123456789012")
	if got := ingester.Service(); got != "lambda" {
		t.Errorf("Service() = %q, want %q", got, "lambda")
	}
}

// TestLambdaIngesterEnumerateEmitsFunctions tests that functions are enumerated and emitted as Resource nodes.
func TestLambdaIngesterEnumerateEmitsFunctions(t *testing.T) {
	accountID := "123456789012"
	region := "us-east-1"

	mockClient := &MockLambdaClient{
		listFunctionsFunc: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
			return &lambda.ListFunctionsOutput{
				Functions: []types.FunctionConfiguration{
					{
						FunctionName: aws.String("my-function-1"),
						FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-function-1"),
						Role:         aws.String("arn:aws:iam::123456789012:role/lambda-execution-role"),
					},
					{
						FunctionName: aws.String("my-function-2"),
						FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-function-2"),
						Role:         aws.String("arn:aws:iam::123456789012:role/lambda-execution-role"),
					},
					{
						FunctionName: aws.String("my-function-3"),
						FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-function-3"),
						Role:         aws.String("arn:aws:iam::123456789012:role/lambda-execution-role"),
					},
				},
			}, nil
		},
		getPolicyFunc: func(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
			// Return ResourceNotFoundException (404) for all functions
			return nil, &ErrResourceNotFound{}
		},
	}

	ingester := NewLambdaIngester(mockClient, region, accountID)
	resourcesChan, errorsChan := ingester.Enumerate(context.Background(), region)

	// Collect resources
	var resources []ingest.ResourceSpec
	var errors []error

	for {
		select {
		case res, ok := <-resourcesChan:
			if !ok {
				resourcesChan = nil
			} else {
				resources = append(resources, res)
			}
		case err, ok := <-errorsChan:
			if !ok {
				errorsChan = nil
			} else {
				errors = append(errors, err)
			}
		}
		if resourcesChan == nil && errorsChan == nil {
			break
		}
	}

	// We expect 3 function Resource nodes
	functionResources := []ingest.ResourceSpec{}
	for _, res := range resources {
		if res.Label == "Resource" && res.Properties["resource_type"] == "lambda:function" {
			functionResources = append(functionResources, res)
		}
	}

	if len(functionResources) != 3 {
		t.Errorf("Expected 3 function Resource nodes, got %d", len(functionResources))
	}
}

// TestLambdaIngesterEnumerateEmitsCanAssumeEdges tests that CanAssume edges are emitted from functions to roles.
func TestLambdaIngesterEnumerateEmitsCanAssumeEdges(t *testing.T) {
	accountID := "123456789012"
	region := "us-east-1"
	roleARN := "arn:aws:iam::123456789012:role/lambda-execution-role"

	mockClient := &MockLambdaClient{
		listFunctionsFunc: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
			return &lambda.ListFunctionsOutput{
				Functions: []types.FunctionConfiguration{
					{
						FunctionName: aws.String("my-function"),
						FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-function"),
						Role:         aws.String(roleARN),
					},
				},
			}, nil
		},
		getPolicyFunc: func(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
			return nil, &ErrResourceNotFound{}
		},
	}

	ingester := NewLambdaIngester(mockClient, region, accountID)
	resourcesChan, errorsChan := ingester.Enumerate(context.Background(), region)

	// Collect resources
	var resources []ingest.ResourceSpec
	var errors []error

	for {
		select {
		case res, ok := <-resourcesChan:
			if !ok {
				resourcesChan = nil
			} else {
				resources = append(resources, res)
			}
		case err, ok := <-errorsChan:
			if !ok {
				errorsChan = nil
			} else {
				errors = append(errors, err)
			}
		}
		if resourcesChan == nil && errorsChan == nil {
			break
		}
	}

	// Find function resource and check for CanAssume edge
	var foundEdge bool
	for _, res := range resources {
		if res.Label == "Resource" && res.Properties["resource_type"] == "lambda:function" {
			for _, edge := range res.Edges {
				if edge.EdgeType == "CanAssume" && edge.ToID == roleARN {
					foundEdge = true
				}
			}
		}
	}

	if !foundEdge {
		t.Errorf("Expected CanAssume edge to role, not found")
	}
}

// TestLambdaIngesterEnumerateHandlesFunctionWithPolicy tests that function policies are parsed and Permission nodes are emitted.
func TestLambdaIngesterEnumerateHandlesFunctionWithPolicy(t *testing.T) {
	accountID := "123456789012"
	region := "us-east-1"
	functionName := "my-function"

	policyDoc := `{
		"Statement": [
			{
				"Sid": "AllowInvoke",
				"Effect": "Allow",
				"Resource": "arn:aws:s3:::my-bucket/*",
				"Action": "lambda:InvokeFunction"
			}
		]
	}`

	mockClient := &MockLambdaClient{
		listFunctionsFunc: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
			return &lambda.ListFunctionsOutput{
				Functions: []types.FunctionConfiguration{
					{
						FunctionName: aws.String(functionName),
						FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-function"),
						Role:         aws.String("arn:aws:iam::123456789012:role/lambda-execution-role"),
					},
				},
			}, nil
		},
		getPolicyFunc: func(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
			return &lambda.GetPolicyOutput{
				Policy: aws.String(policyDoc),
			}, nil
		},
	}

	ingester := NewLambdaIngester(mockClient, region, accountID)
	resourcesChan, errorsChan := ingester.Enumerate(context.Background(), region)

	// Collect resources
	var resources []ingest.ResourceSpec
	var errors []error

	for {
		select {
		case res, ok := <-resourcesChan:
			if !ok {
				resourcesChan = nil
			} else {
				resources = append(resources, res)
			}
		case err, ok := <-errorsChan:
			if !ok {
				errorsChan = nil
			} else {
				errors = append(errors, err)
			}
		}
		if resourcesChan == nil && errorsChan == nil {
			break
		}
	}

	// We expect 1 function Resource + 1 Permission node
	if len(resources) < 2 {
		t.Errorf("Expected at least 2 resources (function + permission), got %d", len(resources))
		return
	}

	// Check for Permission node
	var permissionFound bool
	for _, res := range resources {
		if res.Label == "Permission" {
			permissionFound = true
			if pt, ok := res.Properties["policy_type"]; !ok || pt != "FunctionPolicy" {
				t.Errorf("Permission policy_type = %v, want FunctionPolicy", pt)
			}
		}
	}
	if !permissionFound {
		t.Errorf("Expected Permission node, but none found")
	}
}

// TestFunctionToResourceSpec tests the transformer function.
func TestFunctionToResourceSpec(t *testing.T) {
	arn := "arn:aws:lambda:us-east-1:123456789012:function:my-function"
	functionName := "my-function"
	accountID := "123456789012"

	spec := FunctionToResourceSpec(arn, functionName, accountID)

	if spec.Label != "Resource" {
		t.Errorf("Label = %q, want Resource", spec.Label)
	}
	if spec.ID != arn {
		t.Errorf("ID = %q, want %q", spec.ID, arn)
	}

	if rt, ok := spec.Properties["resource_type"]; !ok || rt != "lambda:function" {
		t.Errorf("resource_type = %v, want lambda:function", rt)
	}
}

// TestParsePolicyDocument tests the policy document parser.
func TestParsePolicyDocument(t *testing.T) {
	policyJSON := `{
		"Statement": [
			{
				"Sid": "AllowInvoke",
				"Effect": "Allow",
				"Resource": "arn:aws:lambda:us-east-1:123456789012:function:my-function"
			}
		]
	}`

	doc, err := ParsePolicyDocument(policyJSON)
	if err != nil {
		t.Errorf("ParsePolicyDocument failed: %v", err)
	}

	if len(doc.Statement) != 1 {
		t.Errorf("Expected 1 statement, got %d", len(doc.Statement))
	}

	stmt := doc.Statement[0]
	if stmt.Sid != "AllowInvoke" {
		t.Errorf("Sid = %q, want AllowInvoke", stmt.Sid)
	}
	if stmt.Effect != "Allow" {
		t.Errorf("Effect = %q, want Allow", stmt.Effect)
	}
}

// TestStringArrayFromInterface tests the interface converter.
func TestStringArrayFromInterface(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  []string
	}{
		{
			name:  "string input",
			input: "arn:aws:lambda:us-east-1:123456789012:function:my-function",
			want:  []string{"arn:aws:lambda:us-east-1:123456789012:function:my-function"},
		},
		{
			name:  "array input",
			input: []interface{}{"arn1", "arn2"},
			want:  []string{"arn1", "arn2"},
		},
		{
			name:  "empty array",
			input: []interface{}{},
			want:  []string{},
		},
		{
			name:  "nil input",
			input: nil,
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StringArrayFromInterface(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("len(StringArrayFromInterface()) = %d, want %d", len(got), len(tt.want))
				return
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("StringArrayFromInterface()[%d] = %q, want %q", i, v, tt.want[i])
				}
			}
		})
	}
}

// ErrResourceNotFound is a mock error for testing 404 responses.
type ErrResourceNotFound struct{}

func (e *ErrResourceNotFound) Error() string {
	return "ResourceNotFoundException"
}

func (e *ErrResourceNotFound) ErrorCode() string {
	return "ResourceNotFoundException"
}

func (e *ErrResourceNotFound) ErrorMessage() string {
	return "The resource does not exist"
}

// Ensure ErrResourceNotFound implements smithy.APIError interface.
var _ interface{ ErrorCode() string } = (*ErrResourceNotFound)(nil)
