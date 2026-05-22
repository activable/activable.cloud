package s3

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// FetchBuckets fetches all S3 buckets using the ListBuckets API.
func FetchBuckets(ctx context.Context, client S3Client) ([]types.Bucket, error) {
	output, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("ListBuckets failed: %w", err)
	}

	if output == nil || output.Buckets == nil {
		return []types.Bucket{}, nil
	}

	return output.Buckets, nil
}

// FetchBucketPolicy fetches the policy document for a bucket.
// Returns an empty string if the bucket has no policy (404 NoSuchBucketPolicy).
// Returns an error for other API failures.
func FetchBucketPolicy(ctx context.Context, client S3Client, bucketName string) (string, error) {
	output, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})

	// Handle NoSuchBucketPolicy (404) as "no policy" rather than an error
	if err != nil {
		if isNoSuchBucketPolicyError(err) {
			return "", nil
		}
		return "", fmt.Errorf("GetBucketPolicy failed: %w", err)
	}

	if output == nil || output.Policy == nil {
		return "", nil
	}

	return *output.Policy, nil
}

// isNoSuchBucketPolicyError checks if an error is a NoSuchBucketPolicy (404) error.
func isNoSuchBucketPolicyError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if !as(err, &apiErr) {
		return false
	}
	return apiErr.ErrorCode() == "NoSuchBucketPolicy"
}

// as is a simple type assertion helper to avoid verbose error casting.
func as(err error, target interface{}) bool {
	return errorAs(err, target)
}

// errorAs mimics the behavior of errors.As for API errors.
// This is a helper to maintain compatibility across different error types.
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
