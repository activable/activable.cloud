package s3

import (
	"context"
	"fmt"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Client defines the interface for S3 API calls we use in the ingester.
// This allows for easy mocking in tests.
type S3Client interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
}

// S3Ingester implements the Ingester interface for AWS S3.
type S3Ingester struct {
	client    S3Client
	accountID string
}

// NewS3Ingester creates a new S3 ingester.
func NewS3Ingester(client S3Client, accountID string) *S3Ingester {
	return &S3Ingester{
		client:    client,
		accountID: accountID,
	}
}

// Service returns the service name.
func (i *S3Ingester) Service() string {
	return "s3"
}

// RequiredIAMActions returns the IAM actions required for this ingester.
func (i *S3Ingester) RequiredIAMActions() []string {
	return []string{
		"s3:ListAllMyBuckets",
		"s3:GetBucketPolicy",
		"s3:GetBucketLocation",
	}
}

// Enumerate fetches all S3 buckets and emits them as Resource items.
// S3 is a global service, so the region parameter is ignored.
func (i *S3Ingester) Enumerate(ctx context.Context, region string) (<-chan ingest.ResourceSpec, <-chan error) {
	resourcesChan := make(chan ingest.ResourceSpec, 100)
	errorsChan := make(chan error, 10)

	go func() {
		defer close(resourcesChan)
		defer close(errorsChan)

		// List all buckets
		buckets, err := FetchBuckets(ctx, i.client)
		if err != nil {
			errorsChan <- fmt.Errorf("failed to fetch buckets: %w", err)
			return
		}

		for _, bucket := range buckets {
			bucketName := *bucket.Name
			bucketARN := fmt.Sprintf("arn:aws:s3:::%s", bucketName)

			bucketSpec := BucketToResourceSpec(bucketARN, bucketName, i.accountID)
			resourcesChan <- bucketSpec

			// Fetch bucket policy
			policyJSON, err := FetchBucketPolicy(ctx, i.client, bucketName)
			if err != nil {
				// 404 is expected for buckets with no policy; continue silently
				errorsChan <- fmt.Errorf("failed to fetch policy for bucket %s: %w", bucketName, err)
				continue
			}

			if policyJSON == "" {
				// No policy attached to this bucket
				continue
			}

			// Parse the policy document and emit Permission nodes
			doc, err := ParsePolicyDocument(policyJSON)
			if err != nil {
				errorsChan <- fmt.Errorf("failed to parse policy for bucket %s: %w", bucketName, err)
				continue
			}

			// Emit Permission nodes for each statement
			for idx, stmt := range doc.Statement {
				if stmt.Effect != "Allow" {
					continue
				}

				permissionID := fmt.Sprintf("%s#bucket-policy#stmt_%d", bucketARN, idx)
				permissionSpec := ingest.ResourceSpec{
					Label: "Permission",
					ID:    permissionID,
					Properties: map[string]interface{}{
						"policy_type":  "BucketPolicy",
						"statement_id": stmt.Sid,
						"effect":       stmt.Effect,
						"bucket_name": bucketName,
						"account_id":   i.accountID,
					},
					Edges: []ingest.EdgeSpec{},
				}
				resourcesChan <- permissionSpec

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
		}
	}()

	return resourcesChan, errorsChan
}
