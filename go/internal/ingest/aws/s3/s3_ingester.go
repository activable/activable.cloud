package s3

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	ingest "github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"golang.org/x/sync/semaphore"
)

// S3Ingester implements the ingest.Ingester interface for AWS S3 resources.
type S3Ingester struct {
	client    S3Client
	accountID string
	sem       *semaphore.Weighted
}

// NewS3Ingester creates a new S3 ingester.
func NewS3Ingester(client S3Client, accountID string, concurrencyLimit int64) *S3Ingester {
	if concurrencyLimit <= 0 {
		concurrencyLimit = 3 // Default to 3 concurrent calls
	}

	return &S3Ingester{
		client:    client,
		accountID: accountID,
		sem:       semaphore.NewWeighted(concurrencyLimit),
	}
}

// Service returns the service name for this ingester.
func (i *S3Ingester) Service() string {
	return "s3"
}

// RequiredIAMActions returns the list of IAM actions required for this ingester.
func (i *S3Ingester) RequiredIAMActions() []string {
	return []string{
		"s3:ListAllMyBuckets",
		"s3:GetBucketPolicy",
		"s3:GetBucketLocation",
	}
}

// Enumerate enumerates all S3 buckets and returns them via a channel.
func (i *S3Ingester) Enumerate(ctx context.Context) (<-chan ingest.ResourceSpec, <-chan error) {
	resourcesChan := make(chan ingest.ResourceSpec, 100)
	errorsChan := make(chan error, 10)

	go func() {
		defer close(resourcesChan)
		defer close(errorsChan)

		if err := i.enumerateBuckets(ctx, resourcesChan); err != nil {
			errorsChan <- fmt.Errorf("enumerate buckets: %w", err)
		}
	}()

	return resourcesChan, errorsChan
}

// enumerateBuckets fetches all S3 buckets and emits them as resource specs.
// Also fetches bucket policies and location metadata.
func (i *S3Ingester) enumerateBuckets(ctx context.Context, resourcesChan chan<- ingest.ResourceSpec) error {
	if err := i.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer i.sem.Release(1)

	// List all buckets
	output, err := i.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("ListBuckets failed: %w", err)
	}

	if output.Buckets == nil || len(output.Buckets) == 0 {
		return nil
	}

	// Emit bucket resource specs
	for _, bucket := range output.Buckets {
		spec := BucketToResourceSpec(bucket)

		select {
		case resourcesChan <- spec:
		case <-ctx.Done():
			return ctx.Err()
		}

		// Fetch bucket location (metadata)
		if bucket.Name != nil {
			bucketName := *bucket.Name
			location, err := i.client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
				Bucket: &bucketName,
			})
			if err != nil {
				log.Printf("failed to get bucket location for %s: %v", bucketName, err)
			} else if location != nil {
				// LocationConstraint is a string (type alias)
				region := BucketLocationToRegion(string(location.LocationConstraint))
				spec.Properties["region"] = region
			}
		}

		// Fetch bucket policy
		if bucket.Name != nil {
			bucketName := *bucket.Name
			policy, err := i.client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
				Bucket: &bucketName,
			})

			// GetBucketPolicy returns 404 (NoSuchBucketPolicy) if no policy exists.
			// This is expected and not an error.
			if err != nil {
				if !isNotFoundError(err) {
					log.Printf("failed to get bucket policy for %s: %v", bucketName, err)
				}
				continue
			}

			if policy.Policy == nil {
				continue
			}

			// Parse the policy and emit Permission specs
			permissionSpecs, err := BucketPolicyToPermissionSpec(bucketName, *policy.Policy)
			if err != nil {
				log.Printf("failed to parse bucket policy for %s: %v", bucketName, err)
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

	return nil
}

// isNotFoundError checks if the error is a 404 NoSuchBucketPolicy.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// Check if it's a 404 error code by checking the error message.
	// GetBucketPolicy returns NoSuchBucketPolicy when no policy exists.
	errMsg := err.Error()
	// Simple string check for the error code
	return err != nil && (errMsg == "NoSuchBucketPolicy" || errMsg == "NoSuchBucketPolicy: The bucket policy does not exist.")
}
