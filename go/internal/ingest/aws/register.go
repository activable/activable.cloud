package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	ec2ingester "github.com/activable-cloud/activable.cloud/go/internal/ingest/aws/ec2"
	iamingester "github.com/activable-cloud/activable.cloud/go/internal/ingest/aws/iam"
	lambdaingester "github.com/activable-cloud/activable.cloud/go/internal/ingest/aws/lambda"
	s3ingester "github.com/activable-cloud/activable.cloud/go/internal/ingest/aws/s3"
	stsingester "github.com/activable-cloud/activable.cloud/go/internal/ingest/aws/sts"
)

// RegisterAllIngesters registers all AWS service ingesters.
// Returns a map of service name to ingester instances.
// Supports regional ingesters (EC2, Lambda) by creating instances per region.
func RegisterAllIngesters(ctx context.Context, cfg aws.Config, enabledRegions []string) (map[string][]ingest.Ingester, error) {
	if len(enabledRegions) == 0 {
		enabledRegions = []string{"us-east-1"} // Default to us-east-1
	}

	ingesters := make(map[string][]ingest.Ingester)

	// Resolve account ID via STS
	stsClient := sts.NewFromConfig(cfg)
	stsIngester := stsingester.NewSTSIngester(stsClient, "")
	accountID, err := stsIngester.ResolveAccountID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve account ID: %w", err)
	}

	// STS ingester (produces no nodes, but we register it for completeness)
	ingesters["sts"] = []ingest.Ingester{stsIngester}

	// IAM ingester (account-level, not regional)
	iamClient := iam.NewFromConfig(cfg)
	iamIngester := iamingester.NewIAMIngester(iamClient, accountID, 3)
	ingesters["iam"] = []ingest.Ingester{iamIngester}

	// S3 ingester (account-level, not regional)
	s3Client := s3.NewFromConfig(cfg)
	s3Ingester := s3ingester.NewS3Ingester(s3Client, accountID, 3)
	ingesters["s3"] = []ingest.Ingester{s3Ingester}

	// EC2 ingesters (one per region)
	ec2Ingesters := make([]ingest.Ingester, 0, len(enabledRegions))
	for _, region := range enabledRegions {
		// Create a config for this region
		regionCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return nil, fmt.Errorf("failed to load config for region %s: %w", region, err)
		}
		ec2Client := ec2.NewFromConfig(regionCfg)
		ec2Ingester := ec2ingester.NewEC2Ingester(ec2Client, region, accountID, 5)
		ec2Ingesters = append(ec2Ingesters, ec2Ingester)
	}
	ingesters["ec2"] = ec2Ingesters

	// Lambda ingesters (one per region)
	lambdaIngesters := make([]ingest.Ingester, 0, len(enabledRegions))
	for _, region := range enabledRegions {
		// Create a config for this region
		regionCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return nil, fmt.Errorf("failed to load config for region %s: %w", region, err)
		}
		lambdaClient := lambda.NewFromConfig(regionCfg)
		lambdaIngester := lambdaingester.NewLambdaIngester(lambdaClient, region, accountID, 3)
		lambdaIngesters = append(lambdaIngesters, lambdaIngester)
	}
	ingesters["lambda"] = lambdaIngesters

	return ingesters, nil
}

// FlattenIngesters flattens the map of ingesters into a single slice.
// Useful for iterating over all ingesters regardless of region.
func FlattenIngesters(ingesters map[string][]ingest.Ingester) []ingest.Ingester {
	var result []ingest.Ingester
	for _, ingestList := range ingesters {
		result = append(result, ingestList...)
	}
	return result
}
