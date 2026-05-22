package aws

import (
	"context"
	"net/url"
	"os"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// LocalDevEndpointResolver returns a config load option that overrides all AWS
// service endpoints to point to a local emulator (e.g., floci at localhost:4566).
// This enables local development against mock AWS services without actual AWS API calls.
func LocalDevEndpointResolver(baseURL string) config.LoadOptionsFunc {
	return func(o *config.LoadOptions) error {
		// Validate the base URL is parseable
		if _, err := url.Parse(baseURL); err != nil {
			return err
		}

		// Set endpoint resolver for all AWS services
		//nolint:staticcheck // AWS SDK v2 migration to service-specific endpoint resolvers is deferred
		o.EndpointResolverWithOptions = awssdk.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (awssdk.Endpoint, error) {
				// If no base URL configured, use default AWS endpoints (production path)
				if baseURL == "" {
					return awssdk.Endpoint{}, nil
				}

				// Development path: all services (IAM, STS, S3, EC2, Lambda, etc.)
				// point to the local emulator
				return awssdk.Endpoint{
					URL:                baseURL,
					SigningRegion:      region,
					HostnameImmutable:  true,
					Source:             awssdk.EndpointSourceCustom,
				}, nil
			},
		)

		return nil
	}
}

// LoadConfig loads the AWS SDK config with endpoint override if in local dev mode.
// In production (AWS_ENDPOINT_URL not set), uses default AWS service endpoints.
// In development (AWS_ENDPOINT_URL set), all services route to the endpoint (e.g., floci).
//
// Environment variables:
//   - AWS_ENDPOINT_URL: If set, all services use this endpoint (e.g., http://localhost:4566)
//   - AWS_REGION: AWS region (default: us-east-1)
//   - AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY: AWS credentials (required)
func LoadConfig(ctx context.Context) (awssdk.Config, error) {
	opts := []func(*config.LoadOptions) error{}

	// Check if local dev endpoint is configured
	endpointURL := os.Getenv("AWS_ENDPOINT_URL")
	if endpointURL != "" {
		opts = append(opts, LocalDevEndpointResolver(endpointURL))
	}

	// Load config with optional endpoint override
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return awssdk.Config{}, err
	}

	return cfg, nil
}
