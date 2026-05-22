package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type SeedResult struct {
	IAMUsers      int    `json:"iam_users"`
	IAMRoles      int    `json:"iam_roles"`
	IAMGroups     int    `json:"iam_groups"`
	IAMPolicies   int    `json:"iam_policies"`
	S3Buckets     int    `json:"s3_buckets"`
	Timestamp     string `json:"timestamp"`
	Idempotent    bool   `json:"idempotent"`
}

func main() {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Load AWS endpoint and credentials from environment
	endpoint := os.Getenv("AWS_ENDPOINT_URL")
	if endpoint == "" {
		endpoint = "http://localhost:4566"
	}

	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	if accessKey == "" {
		accessKey = "test"
	}

	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if secretKey == "" {
		secretKey = "test"
	}

	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		region = "us-east-1"
	}

	logger.Info("Seeding Floci with test AWS resources",
		"endpoint", endpoint,
		"region", region,
	)

	// Build AWS config with custom endpoint
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			accessKey, secretKey, "",
		)),
	)
	if err != nil {
		logger.Error("failed to load AWS config", "error", err)
		os.Exit(1)
	}

	// Create IAM client with custom endpoint
	iamClient := iam.NewFromConfig(cfg, func(o *iam.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})

	// Create S3 client with custom endpoint
	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})

	result := &SeedResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Idempotent: true,
	}

	// 1. Create IAM users
	logger.Info("Creating IAM users")
	userNames := []string{"alice", "bob", "charlie"}
	for _, name := range userNames {
		_, err := iamClient.CreateUser(ctx, &iam.CreateUserInput{
			UserName: aws.String(name),
		})
		if err != nil {
			logger.Warn("failed to create user (likely exists)", "user", name, "error", err)
		} else {
			result.IAMUsers++
		}
	}
	logger.Info("Created IAM users", "count", result.IAMUsers)

	// 2. Create IAM roles with trust policy
	logger.Info("Creating IAM roles")
	trustPolicy := `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}`

	roleNames := []string{"AdminRole", "LambdaExecutionRole"}
	for _, name := range roleNames {
		_, err := iamClient.CreateRole(ctx, &iam.CreateRoleInput{
			RoleName:                 aws.String(name),
			AssumeRolePolicyDocument: aws.String(trustPolicy),
		})
		if err != nil {
			logger.Warn("failed to create role (likely exists)", "role", name, "error", err)
		} else {
			result.IAMRoles++
		}
	}
	logger.Info("Created IAM roles", "count", result.IAMRoles)

	// 3. Create IAM managed policy
	logger.Info("Creating IAM policy")
	policyDoc := `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"],
    "Resource": ["arn:aws:s3:::activable-data/*", "arn:aws:s3:::activable-data"]
  }]
}`

	_, err = iamClient.CreatePolicy(ctx, &iam.CreatePolicyInput{
		PolicyName:     aws.String("S3DataAccess"),
		PolicyDocument: aws.String(policyDoc),
	})
	if err != nil {
		logger.Warn("failed to create policy (likely exists)", "error", err)
	} else {
		result.IAMPolicies++
	}
	logger.Info("Created IAM policy", "count", result.IAMPolicies)

	// 4. Attach policies to users and roles
	logger.Info("Attaching policies")
	_, err = iamClient.AttachUserPolicy(ctx, &iam.AttachUserPolicyInput{
		UserName:  aws.String("alice"),
		PolicyArn: aws.String("arn:aws:iam::000000000000:policy/S3DataAccess"),
	})
	if err != nil {
		logger.Warn("failed to attach user policy", "error", err)
	}

	_, err = iamClient.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  aws.String("AdminRole"),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	})
	if err != nil {
		logger.Warn("failed to attach role policy", "error", err)
	}

	_, err = iamClient.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  aws.String("LambdaExecutionRole"),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"),
	})
	if err != nil {
		logger.Warn("failed to attach lambda role policy", "error", err)
	}

	// 5. Create IAM group and add users
	logger.Info("Creating IAM group")
	_, err = iamClient.CreateGroup(ctx, &iam.CreateGroupInput{
		GroupName: aws.String("engineering"),
	})
	if err != nil {
		logger.Warn("failed to create group (likely exists)", "error", err)
	} else {
		result.IAMGroups++
	}

	_, err = iamClient.AddUserToGroup(ctx, &iam.AddUserToGroupInput{
		GroupName: aws.String("engineering"),
		UserName:  aws.String("alice"),
	})
	if err != nil {
		logger.Warn("failed to add alice to engineering group", "error", err)
	}

	_, err = iamClient.AddUserToGroup(ctx, &iam.AddUserToGroupInput{
		GroupName: aws.String("engineering"),
		UserName:  aws.String("bob"),
	})
	if err != nil {
		logger.Warn("failed to add bob to engineering group", "error", err)
	}

	// 6. Create S3 buckets
	logger.Info("Creating S3 buckets")
	bucketNames := []string{"activable-data", "activable-logs", "activable-backups"}
	for _, name := range bucketNames {
		_, err := s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: aws.String(name),
		})
		if err != nil {
			logger.Warn("failed to create bucket (likely exists)", "bucket", name, "error", err)
		} else {
			result.S3Buckets++
		}
	}
	logger.Info("Created S3 buckets", "count", result.S3Buckets)

	// 7. Upload sample object to S3
	logger.Info("Uploading sample object to S3")
	sampleObj := map[string]interface{}{
		"test":      true,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	objData, err := json.Marshal(sampleObj)
	if err != nil {
		logger.Warn("failed to marshal sample object", "error", err)
	} else {
		_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String("activable-data"),
			Key:    aws.String("test.json"),
			Body:   strings.NewReader(string(objData)),
		})
		if err != nil {
			logger.Warn("failed to upload sample object", "error", err)
		}
	}

	// 8. Print summary
	fmt.Println()
	fmt.Println("=== Floci seed complete ===")
	fmt.Println()
	fmt.Println("Created resources:")
	fmt.Printf("  IAM: %d users, %d roles, %d group(s), %d policy(ies)\n",
		result.IAMUsers, result.IAMRoles, result.IAMGroups, result.IAMPolicies)
	fmt.Printf("  S3: %d buckets, 1 object\n", result.S3Buckets)
	fmt.Println()
	fmt.Printf("AWS endpoint: %s\n", endpoint)
	fmt.Printf("Region: %s\n", region)
	fmt.Println()

	// Output JSON result for programmatic use
	resultJSON, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println("Result (JSON):")
	fmt.Println(string(resultJSON))
}
