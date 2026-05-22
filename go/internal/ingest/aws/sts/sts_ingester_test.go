package sts

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// MockSTSClient is a simple mock for testing.
type MockSTSClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *MockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.GetCallerIdentityFunc != nil {
		return m.GetCallerIdentityFunc(ctx, params, optFns...)
	}
	return nil, errors.New("not implemented")
}

// TestResolveAccountID_Success tests successful account ID resolution.
func TestResolveAccountID_Success(t *testing.T) {
	mock := &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				UserId:  aws.String("AIDACKCEVSQ6C2EXAMPLE"),
				Arn:     aws.String("arn:aws:iam::123456789012:user/test-user"),
			}, nil
		},
	}

	ingester := NewSTSIngester(mock, "")
	accountID, err := ingester.ResolveAccountID(context.Background())

	if err != nil {
		t.Fatalf("ResolveAccountID failed: %v", err)
	}
	if accountID != "123456789012" {
		t.Errorf("expected account ID '123456789012', got %s", accountID)
	}
}

// TestResolveAccountID_NoAccountID tests handling of missing account ID in response.
func TestResolveAccountID_NoAccountID(t *testing.T) {
	mock := &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				UserId: aws.String("AIDACKCEVSQ6C2EXAMPLE"),
				Arn:    aws.String("arn:aws:iam::123456789012:user/test-user"),
			}, nil
		},
	}

	ingester := NewSTSIngester(mock, "")
	_, err := ingester.ResolveAccountID(context.Background())

	if err == nil {
		t.Fatalf("expected error when account ID is missing, got nil")
	}
}

// TestResolveAccountID_APIError tests handling of API errors.
func TestResolveAccountID_APIError(t *testing.T) {
	mock := &MockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return nil, fmt.Errorf("STS service unavailable")
		},
	}

	ingester := NewSTSIngester(mock, "")
	_, err := ingester.ResolveAccountID(context.Background())

	if err == nil {
		t.Fatalf("expected error on API failure, got nil")
	}
}

// TestEnumerate_ProducesNoResources tests that Enumerate closes channels immediately.
func TestEnumerate_ProducesNoResources(t *testing.T) {
	mock := &MockSTSClient{}
	ingester := NewSTSIngester(mock, "123456789012")

	resourcesChan, errorsChan := ingester.Enumerate(context.Background())

	// Read from channels to ensure they close.
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

// TestService returns the correct service name.
func TestService(t *testing.T) {
	mock := &MockSTSClient{}
	ingester := NewSTSIngester(mock, "123456789012")

	if ingester.Service() != "sts" {
		t.Errorf("expected service 'sts', got %s", ingester.Service())
	}
}

// TestRequiredIAMActions returns the correct IAM actions.
func TestRequiredIAMActions(t *testing.T) {
	mock := &MockSTSClient{}
	ingester := NewSTSIngester(mock, "123456789012")

	actions := ingester.RequiredIAMActions()
	if len(actions) == 0 {
		t.Fatalf("expected non-empty IAM actions list")
	}

	found := false
	for _, action := range actions {
		if action == "sts:GetCallerIdentity" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'sts:GetCallerIdentity' in RequiredIAMActions, got %v", actions)
	}
}
