package s3

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// MockS3Client is a simple mock for testing.
type MockS3Client struct {
	ListBucketsFunc      func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketPolicyFunc  func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	GetBucketLocationFunc func(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
}

func (m *MockS3Client) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if m.ListBucketsFunc != nil {
		return m.ListBucketsFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *MockS3Client) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	if m.GetBucketPolicyFunc != nil {
		return m.GetBucketPolicyFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *MockS3Client) GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	if m.GetBucketLocationFunc != nil {
		return m.GetBucketLocationFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// TestBucketToResourceSpec tests transformation of an S3 bucket.
func TestBucketToResourceSpec(t *testing.T) {
	now := time.Now()
	bucketName := "my-test-bucket"

	// Create a bucket with the required fields
	bucket := types.Bucket{
		Name:         aws.String(bucketName),
		CreationDate: aws.Time(now),
	}

	spec := BucketToResourceSpec(bucket)

	if spec.Label != "Resource" {
		t.Errorf("expected label 'Resource', got %s", spec.Label)
	}
	if spec.ID != "arn:aws:s3:::my-test-bucket" {
		t.Errorf("expected ID 'arn:aws:s3:::my-test-bucket', got %s", spec.ID)
	}
	if spec.Properties["name"] != bucketName {
		t.Errorf("expected name %s, got %v", bucketName, spec.Properties["name"])
	}
	if spec.Properties["type"] != "Bucket" {
		t.Errorf("expected type 'Bucket', got %v", spec.Properties["type"])
	}
}

// TestBucketPolicyToPermissionSpec tests parsing of bucket policy.
func TestBucketPolicyToPermissionSpec(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "PublicRead",
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::my-bucket/*"
			}
		]
	}`

	specs, err := BucketPolicyToPermissionSpec("my-bucket", policyJSON)
	if err != nil {
		t.Fatalf("BucketPolicyToPermissionSpec failed: %v", err)
	}

	if len(specs) != 1 {
		t.Errorf("expected 1 permission spec, got %d", len(specs))
	}

	spec := specs[0]
	if spec.Label != "Permission" {
		t.Errorf("expected label 'Permission', got %s", spec.Label)
	}
	if spec.Properties["sid"] != "PublicRead" {
		t.Errorf("expected sid 'PublicRead', got %v", spec.Properties["sid"])
	}
}

// TestBucketLocationToRegion tests region normalization.
func TestBucketLocationToRegion_USEast1Empty(t *testing.T) {
	region := BucketLocationToRegion("")
	if region != "us-east-1" {
		t.Errorf("expected 'us-east-1' for empty string, got %s", region)
	}
}

// TestBucketLocationToRegion_OtherRegion tests non-us-east-1 regions.
func TestBucketLocationToRegion_OtherRegion(t *testing.T) {
	region := BucketLocationToRegion("eu-west-1")
	if region != "eu-west-1" {
		t.Errorf("expected 'eu-west-1', got %s", region)
	}
}

// TestNormalizeARN tests ARN normalization.
func TestNormalizeARN(t *testing.T) {
	arn := NormalizeARN("my-bucket")
	expected := "arn:aws:s3:::my-bucket"
	if arn != expected {
		t.Errorf("expected %s, got %s", expected, arn)
	}
}

// TestService returns the correct service name.
func TestS3Service(t *testing.T) {
	mock := &MockS3Client{}
	ingester := NewS3Ingester(mock, "123456789012", 3)

	if ingester.Service() != "s3" {
		t.Errorf("expected service 's3', got %s", ingester.Service())
	}
}

// TestRequiredIAMActions returns the correct IAM actions.
func TestS3RequiredIAMActions(t *testing.T) {
	mock := &MockS3Client{}
	ingester := NewS3Ingester(mock, "123456789012", 3)

	actions := ingester.RequiredIAMActions()
	if len(actions) == 0 {
		t.Fatalf("expected non-empty IAM actions list")
	}

	required := []string{"s3:ListAllMyBuckets", "s3:GetBucketPolicy", "s3:GetBucketLocation"}
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

// TestEnumerate_NoBuckets tests enumeration with no buckets.
func TestS3Enumerate_NoBuckets(t *testing.T) {
	mock := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{},
			}, nil
		},
	}

	ingester := NewS3Ingester(mock, "123456789012", 3)
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

// TestEnumerate_WithBuckets tests enumeration with multiple buckets.
func TestS3Enumerate_WithBuckets(t *testing.T) {
	now := time.Now()
	mock := &MockS3Client{
		ListBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{
					{Name: aws.String("bucket-1"), CreationDate: aws.Time(now)},
					{Name: aws.String("bucket-2"), CreationDate: aws.Time(now)},
					{Name: aws.String("bucket-3"), CreationDate: aws.Time(now)},
				},
			}, nil
		},
		GetBucketLocationFunc: func(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		GetBucketPolicyFunc: func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
			// Return empty policy (no policy exists) - but with a valid output struct
			return &s3.GetBucketPolicyOutput{}, nil
		},
	}

	ingester := NewS3Ingester(mock, "123456789012", 3)
	resourcesChan, errorsChan := ingester.Enumerate(context.Background())

	resourceCount := 0
	for range resourcesChan {
		resourceCount++
	}

	errorCount := 0
	for range errorsChan {
		errorCount++
	}

	// We should get at least 3 resources (one per bucket)
	if resourceCount < 3 {
		t.Errorf("expected at least 3 resources, got %d", resourceCount)
	}
	if errorCount != 0 {
		t.Errorf("expected 0 errors, got %d", errorCount)
	}
}
