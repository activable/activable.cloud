package s3

import (
	"context"
	"testing"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// MockS3Client implements S3Client for testing.
type MockS3Client struct {
	listBucketsFunc   func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	getBucketPolicyFunc func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	getBucketLocationFunc func(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
}

func (m *MockS3Client) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if m.listBucketsFunc != nil {
		return m.listBucketsFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *MockS3Client) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	if m.getBucketPolicyFunc != nil {
		return m.getBucketPolicyFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *MockS3Client) GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	if m.getBucketLocationFunc != nil {
		return m.getBucketLocationFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// TestS3IngesterService tests that the service name is correct.
func TestS3IngesterService(t *testing.T) {
	ingester := NewS3Ingester(&MockS3Client{}, "123456789012")
	if got := ingester.Service(); got != "s3" {
		t.Errorf("Service() = %q, want %q", got, "s3")
	}
}

// TestS3IngesterEnumerateEmitsBuckets tests that buckets are enumerated and emitted as Resource nodes.
func TestS3IngesterEnumerateEmitsBuckets(t *testing.T) {
	accountID := "123456789012"

	mockClient := &MockS3Client{
		listBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{
					{Name: aws.String("bucket-1")},
					{Name: aws.String("bucket-2")},
					{Name: aws.String("bucket-3")},
				},
			}, nil
		},
		getBucketPolicyFunc: func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
			// Return NoSuchBucketPolicy (404) for all buckets
			return nil, &ErrNoSuchBucketPolicy{}
		},
	}

	ingester := NewS3Ingester(mockClient, accountID)
	resourcesChan, errorsChan := ingester.Enumerate(context.Background(), "")

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

	// We expect 3 bucket Resource nodes
	bucketResources := []ingest.ResourceSpec{}
	for _, res := range resources {
		if res.Label == "Resource" {
			bucketResources = append(bucketResources, res)
		}
	}

	if len(bucketResources) != 3 {
		t.Errorf("Expected 3 bucket Resource nodes, got %d", len(bucketResources))
	}

	// Validate first bucket
	if len(bucketResources) > 0 {
		bucket := bucketResources[0]
		if bucket.ID != "arn:aws:s3:::bucket-1" {
			t.Errorf("Bucket 0 ID = %q, want %q", bucket.ID, "arn:aws:s3:::bucket-1")
		}
	}
}

// ErrNoSuchBucketPolicy is a mock error for testing 404 responses.
type ErrNoSuchBucketPolicy struct{}

func (e *ErrNoSuchBucketPolicy) Error() string {
	return "NoSuchBucketPolicy"
}

func (e *ErrNoSuchBucketPolicy) ErrorCode() string {
	return "NoSuchBucketPolicy"
}

func (e *ErrNoSuchBucketPolicy) ErrorMessage() string {
	return "The bucket policy does not exist"
}

// TestS3IngesterEnumerateHandlesBucketWithPolicy tests that bucket policies are parsed and Permission nodes are emitted.
func TestS3IngesterEnumerateHandlesBucketWithPolicy(t *testing.T) {
	accountID := "123456789012"
	bucketName := "secure-bucket"

	policyDoc := `{
		"Statement": [
			{
				"Sid": "AllowPublicRead",
				"Effect": "Allow",
				"Resource": "arn:aws:s3:::secure-bucket/*",
				"Action": "s3:GetObject"
			}
		]
	}`

	mockClient := &MockS3Client{
		listBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{
					{Name: aws.String(bucketName)},
				},
			}, nil
		},
		getBucketPolicyFunc: func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
			return &s3.GetBucketPolicyOutput{
				Policy: aws.String(policyDoc),
			}, nil
		},
	}

	ingester := NewS3Ingester(mockClient, accountID)
	resourcesChan, errorsChan := ingester.Enumerate(context.Background(), "")

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

	// We expect 1 bucket Resource + 1 Permission node
	if len(resources) < 2 {
		t.Errorf("Expected at least 2 resources (bucket + permission), got %d", len(resources))
		return
	}

	// Check for Permission node
	var permissionFound bool
	for _, res := range resources {
		if res.Label == "Permission" {
			permissionFound = true
			if pt, ok := res.Properties["policy_type"]; !ok || pt != "BucketPolicy" {
				t.Errorf("Permission policy_type = %v, want BucketPolicy", pt)
			}
		}
	}
	if !permissionFound {
		t.Errorf("Expected Permission node, but none found")
	}
}

// TestS3IngesterEnumerateHandlesEmptyBucketList tests that empty bucket list is handled gracefully.
func TestS3IngesterEnumerateHandlesEmptyBucketList(t *testing.T) {
	mockClient := &MockS3Client{
		listBucketsFunc: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{},
			}, nil
		},
	}

	ingester := NewS3Ingester(mockClient, "123456789012")
	resourcesChan, errorsChan := ingester.Enumerate(context.Background(), "")

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

	if len(resources) != 0 {
		t.Errorf("Expected 0 resources for empty bucket list, got %d", len(resources))
	}
	if len(errors) != 0 {
		t.Errorf("Expected 0 errors for empty bucket list, got %d", len(errors))
	}
}

// TestBucketToResourceSpec tests the transformer function.
func TestBucketToResourceSpec(t *testing.T) {
	arn := "arn:aws:s3:::my-bucket"
	bucketName := "my-bucket"
	accountID := "123456789012"

	spec := BucketToResourceSpec(arn, bucketName, accountID)

	if spec.Label != "Resource" {
		t.Errorf("Label = %q, want Resource", spec.Label)
	}
	if spec.ID != arn {
		t.Errorf("ID = %q, want %q", spec.ID, arn)
	}

	if rt, ok := spec.Properties["resource_type"]; !ok || rt != "s3:bucket" {
		t.Errorf("resource_type = %v, want s3:bucket", rt)
	}
}

// TestParsePolicyDocument tests the policy document parser.
func TestParsePolicyDocument(t *testing.T) {
	policyJSON := `{
		"Statement": [
			{
				"Sid": "AllowRead",
				"Effect": "Allow",
				"Resource": "arn:aws:s3:::bucket/*"
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
	if stmt.Sid != "AllowRead" {
		t.Errorf("Sid = %q, want AllowRead", stmt.Sid)
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
			input: "arn:aws:s3:::bucket",
			want:  []string{"arn:aws:s3:::bucket"},
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
