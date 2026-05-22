package aws

import (
	"context"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/activable-cloud/activable.cloud/go/internal/ingest/aws/ec2"
	"github.com/activable-cloud/activable.cloud/go/internal/ingest/aws/iam"
	"github.com/activable-cloud/activable.cloud/go/internal/ingest/aws/lambda"
	"github.com/activable-cloud/activable.cloud/go/internal/ingest/aws/s3"
	"github.com/activable-cloud/activable.cloud/go/internal/ingest/aws/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
)

// RegisterAll registers all AWS service ingesters with the runtime.
// This includes IAM, STS, S3, EC2, and Lambda ingesters.
// IAM and S3 are global services (registered once).
// EC2 and Lambda are regional services (registered once per enabled region).
func RegisterAll(ctx context.Context, rt *ingest.Runtime, cfg aws.Config, accountID string) error {
	// Create service clients
	stsClient := awssts.NewFromConfig(cfg)
	s3Client := awss3.NewFromConfig(cfg)
	iamClient := awsiam.NewFromConfig(cfg)

	// Register IAM ingester (global service)
	iamIngester := iam.NewIAMIngester(iamClient, accountID)
	rt.Register(iamIngester)

	// Register STS ingester (global service)
	stsIngester := sts.NewSTSIngester(stsClient, accountID)
	rt.Register(stsIngester)

	// Register S3 ingester (global service)
	s3Ingester := s3.NewS3Ingester(s3Client, accountID)
	rt.Register(s3Ingester)

	// Register EC2 and Lambda ingesters for each enabled region
	regions, err := rt.EnabledRegions(ctx)
	if err != nil {
		return err
	}

	for _, region := range regions {
		// Create regional clients
		regionalCfg := cfg.Copy()
		regionalCfg.Region = region

		regionalEC2Client := awsec2.NewFromConfig(regionalCfg)
		regionalLambdaClient := awslambda.NewFromConfig(regionalCfg)

		// Register regional ingesters
		ec2Ingester := ec2.NewEC2Ingester(regionalEC2Client, region, accountID)
		rt.Register(ec2Ingester)

		lambdaIngester := lambda.NewLambdaIngester(regionalLambdaClient, region, accountID)
		rt.Register(lambdaIngester)
	}

	return nil
}
