package lambda

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// MockLambdaClient is a simple mock for testing.
type MockLambdaClient struct {
	ListFunctionsFunc func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	GetPolicyFunc     func(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

func (m *MockLambdaClient) ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if m.ListFunctionsFunc != nil {
		return m.ListFunctionsFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *MockLambdaClient) GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	if m.GetPolicyFunc != nil {
		return m.GetPolicyFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// TestFunctionToResourceSpec tests transformation of a Lambda function.
func TestFunctionToResourceSpec(t *testing.T) {
	function := types.FunctionConfiguration{
		FunctionName: aws.String("my-function"),
		FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-function"),
		Runtime:      types.RuntimeGo1x,
		Handler:      aws.String("index.handler"),
		MemorySize:   aws.Int32(256),
		Timeout:      aws.Int32(60),
		Role:         aws.String("arn:aws:iam::123456789012:role/lambda-role"),
		LastModified: aws.String("2024-01-01T00:00:00Z"),
	}

	spec := FunctionToResourceSpec(function)

	if spec.Label != "Resource" {
		t.Errorf("expected label 'Resource', got %s", spec.Label)
	}
	if spec.ID != "arn:aws:lambda:us-east-1:123456789012:function:my-function" {
		t.Errorf("expected correct ARN, got %s", spec.ID)
	}
	if spec.Properties["function_name"] != "my-function" {
		t.Errorf("expected function_name, got %v", spec.Properties["function_name"])
	}
	// Check for CanAssume edge to execution role
	if len(spec.Edges) < 1 {
		t.Errorf("expected at least 1 edge (execution role), got %d", len(spec.Edges))
	}
	if len(spec.Edges) > 0 && spec.Edges[0].EdgeType != "CanAssume" {
		t.Errorf("expected CanAssume edge, got %s", spec.Edges[0].EdgeType)
	}
}

// TestFunctionPolicyToPermissionSpec tests parsing of function policy.
func TestFunctionPolicyToPermissionSpec(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AllowAPIGatewayInvoke",
				"Effect": "Allow",
				"Principal": {
					"Service": "apigateway.amazonaws.com"
				},
				"Action": "lambda:InvokeFunction",
				"Resource": "arn:aws:lambda:us-east-1:123456789012:function:my-function"
			}
		]
	}`

	specs, err := FunctionPolicyToPermissionSpec("my-function", policyJSON)
	if err != nil {
		t.Fatalf("FunctionPolicyToPermissionSpec failed: %v", err)
	}

	if len(specs) != 1 {
		t.Errorf("expected 1 permission spec, got %d", len(specs))
	}

	spec := specs[0]
	if spec.Label != "Permission" {
		t.Errorf("expected label 'Permission', got %s", spec.Label)
	}
	if spec.Properties["sid"] != "AllowAPIGatewayInvoke" {
		t.Errorf("expected sid 'AllowAPIGatewayInvoke', got %v", spec.Properties["sid"])
	}
}

// TestNormalizeRoleARN tests ARN validation.
func TestNormalizeRoleARN_Valid(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/lambda-role"
	normalized, err := NormalizeRoleARN(roleARN)
	if err != nil {
		t.Fatalf("NormalizeRoleARN failed: %v", err)
	}
	if normalized != roleARN {
		t.Errorf("expected %s, got %s", roleARN, normalized)
	}
}

// TestNormalizeRoleARN_Invalid tests ARN validation failure.
func TestNormalizeRoleARN_Invalid(t *testing.T) {
	roleARN := "invalid-arn"
	_, err := NormalizeRoleARN(roleARN)
	if err == nil {
		t.Fatalf("expected error for invalid ARN, got nil")
	}
}

// TestLambdaService returns the correct service name.
func TestLambdaService(t *testing.T) {
	mock := &MockLambdaClient{}
	ingester := NewLambdaIngester(mock, "us-east-1", "123456789012", 3)

	if ingester.Service() != "lambda" {
		t.Errorf("expected service 'lambda', got %s", ingester.Service())
	}
}

// TestLambdaRequiredIAMActions returns the correct IAM actions.
func TestLambdaRequiredIAMActions(t *testing.T) {
	mock := &MockLambdaClient{}
	ingester := NewLambdaIngester(mock, "us-east-1", "123456789012", 3)

	actions := ingester.RequiredIAMActions()
	if len(actions) == 0 {
		t.Fatalf("expected non-empty IAM actions list")
	}

	required := []string{"lambda:ListFunctions", "lambda:GetPolicy"}
	for _, req := range required {
		found := false
		for _, action := range actions {
			if action == req {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected action '%s' in RequiredIAMActions", req)
		}
	}
}

// TestRegionalInstantiation tests that regional ingesters have correct region.
func TestLambdaRegionalInstantiation(t *testing.T) {
	mock := &MockLambdaClient{}
	ingester1 := NewLambdaIngester(mock, "us-east-1", "123456789012", 3)
	ingester2 := NewLambdaIngester(mock, "eu-west-1", "123456789012", 3)

	if ingester1.region != "us-east-1" {
		t.Errorf("expected region us-east-1, got %s", ingester1.region)
	}
	if ingester2.region != "eu-west-1" {
		t.Errorf("expected region eu-west-1, got %s", ingester2.region)
	}
}

// TestEnumerate_NoFunctions tests enumeration with no functions.
func TestLambdaEnumerate_NoFunctions(t *testing.T) {
	mock := &MockLambdaClient{
		ListFunctionsFunc: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
			return &lambda.ListFunctionsOutput{
				Functions: []types.FunctionConfiguration{},
			}, nil
		},
	}

	ingester := NewLambdaIngester(mock, "us-east-1", "123456789012", 3)
	resourcesChan, errorsChan := ingester.Enumerate(context.Background())

	resourceCount := 0
	for range resourcesChan {
		resourceCount++
	}

	errorCount := 0
	for range errorsChan {
		errorCount++
	}

	if resourceCount != 0 {
		t.Errorf("expected 0 resources, got %d", resourceCount)
	}
	if errorCount != 0 {
		t.Errorf("expected 0 errors, got %d", errorCount)
	}
}

// TestEnumerate_WithFunctions tests enumeration with multiple functions.
func TestLambdaEnumerate_WithFunctions(t *testing.T) {
	mock := &MockLambdaClient{
		ListFunctionsFunc: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
			return &lambda.ListFunctionsOutput{
				Functions: []types.FunctionConfiguration{
					{
						FunctionName: aws.String("func-1"),
						FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:func-1"),
						Role:         aws.String("arn:aws:iam::123456789012:role/role-1"),
					},
					{
						FunctionName: aws.String("func-2"),
						FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:func-2"),
						Role:         aws.String("arn:aws:iam::123456789012:role/role-2"),
					},
					{
						FunctionName: aws.String("func-3"),
						FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:func-3"),
						Role:         aws.String("arn:aws:iam::123456789012:role/role-3"),
					},
				},
			}, nil
		},
		GetPolicyFunc: func(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
			// Return empty policy (no policy exists) - but with a valid output struct
			return &lambda.GetPolicyOutput{}, nil
		},
	}

	ingester := NewLambdaIngester(mock, "us-east-1", "123456789012", 3)
	resourcesChan, errorsChan := ingester.Enumerate(context.Background())

	resourceCount := 0
	for range resourcesChan {
		resourceCount++
	}

	errorCount := 0
	for range errorsChan {
		errorCount++
	}

	// We should get at least 3 resources (one per function)
	if resourceCount < 3 {
		t.Errorf("expected at least 3 resources, got %d", resourceCount)
	}
	if errorCount != 0 {
		t.Errorf("expected 0 errors, got %d", errorCount)
	}
}
