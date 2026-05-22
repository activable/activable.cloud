package ec2

import (
	"context"
	"fmt"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"golang.org/x/sync/semaphore"
)

const (
	// MaxConcurrentCalls is the maximum number of concurrent AWS API calls for EC2.
	MaxConcurrentCalls = 5
)

// EC2Client defines the interface for EC2 API calls we use in the ingester.
type EC2Client interface {
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeVpcs(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

// EC2Ingester implements the Ingester interface for AWS EC2.
// EC2 is a regional service; one ingester is instantiated per region.
type EC2Ingester struct {
	client    EC2Client
	region    string
	accountID string
	semaphore *semaphore.Weighted
}

// NewEC2Ingester creates a new EC2 ingester for a specific region.
func NewEC2Ingester(client EC2Client, region, accountID string) *EC2Ingester {
	return &EC2Ingester{
		client:    client,
		region:    region,
		accountID: accountID,
		semaphore: semaphore.NewWeighted(MaxConcurrentCalls),
	}
}

// Service returns the service name.
func (i *EC2Ingester) Service() string {
	return "ec2"
}

// RequiredIAMActions returns the IAM actions required for this ingester.
func (i *EC2Ingester) RequiredIAMActions() []string {
	return []string{
		"ec2:DescribeInstances",
		"ec2:DescribeVpcs",
		"ec2:DescribeSecurityGroups",
	}
}

// Enumerate fetches all EC2 resources (instances, VPCs, security groups) and emits them.
// EC2 is regional; the region parameter determines which region to enumerate.
func (i *EC2Ingester) Enumerate(ctx context.Context, region string) (<-chan ingest.ResourceSpec, <-chan error) {
	resourcesChan := make(chan ingest.ResourceSpec, 100)
	errorsChan := make(chan error, 10)

	go func() {
		defer close(resourcesChan)
		defer close(errorsChan)

		// Use region parameter if provided, otherwise use instance region
		enumRegion := region
		if enumRegion == "" {
			enumRegion = i.region
		}

		// Track emitted VPCs to avoid duplicates
		vpcEmitted := make(map[string]bool)

		// Fetch and emit VPCs
		vpcs, err := FetchVpcs(ctx, i.client, i.semaphore)
		if err != nil {
			errorsChan <- fmt.Errorf("failed to fetch VPCs: %w", err)
			return
		}

		for _, vpc := range vpcs {
			vpcID := *vpc.VpcId
			vpcARN := fmt.Sprintf("arn:aws:ec2:%s:%s:vpc/%s", enumRegion, i.accountID, vpcID)
			vpcSpec := VpcToResourceSpec(vpcARN, vpcID, i.accountID)
			resourcesChan <- vpcSpec
			vpcEmitted[vpcID] = true
		}

		// Fetch security groups
		securityGroups, err := FetchSecurityGroups(ctx, i.client, i.semaphore)
		if err != nil {
			errorsChan <- fmt.Errorf("failed to fetch security groups: %w", err)
			return
		}

		sgByID := make(map[string]bool)
		for _, sg := range securityGroups {
			sgID := *sg.GroupId
			sgARN := fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", enumRegion, i.accountID, sgID)
			sgSpec := SecurityGroupToResourceSpec(sgARN, sgID, i.accountID)
			resourcesChan <- sgSpec
			sgByID[sgID] = true
		}

		// Fetch instances
		instances, err := FetchInstances(ctx, i.client, i.semaphore)
		if err != nil {
			errorsChan <- fmt.Errorf("failed to fetch instances: %w", err)
			return
		}

		for _, instance := range instances {
			instanceID := *instance.InstanceId
			instanceARN := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", enumRegion, i.accountID, instanceID)
			instanceSpec := InstanceToResourceSpec(instanceARN, instanceID, i.accountID)

			// Add Contains edge to VPC if present
			if instance.VpcId != nil {
				vpcID := *instance.VpcId
				vpcARN := fmt.Sprintf("arn:aws:ec2:%s:%s:vpc/%s", enumRegion, i.accountID, vpcID)

				// Emit VPC if not already emitted
				if !vpcEmitted[vpcID] {
					vpcSpec := ingest.ResourceSpec{
						Label: "Vpc",
						ID:    vpcARN,
						Properties: map[string]interface{}{
							"vpc_id":     vpcID,
							"account_id": i.accountID,
						},
						Edges: []ingest.EdgeSpec{},
					}
					resourcesChan <- vpcSpec
					vpcEmitted[vpcID] = true
				}

				instanceSpec.Edges = append(instanceSpec.Edges, ingest.EdgeSpec{
					FromID:   instanceARN,
					ToID:     vpcARN,
					EdgeType: "Contains",
					Properties: map[string]interface{}{},
				})
			}

			// Add Contains edges to security groups
			for _, sg := range instance.SecurityGroups {
				sgID := *sg.GroupId
				sgARN := fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", enumRegion, i.accountID, sgID)

				instanceSpec.Edges = append(instanceSpec.Edges, ingest.EdgeSpec{
					FromID:   instanceARN,
					ToID:     sgARN,
					EdgeType: "Contains",
					Properties: map[string]interface{}{},
				})
			}

			// Add CanAssume edge to IAM role if present
			if instance.IamInstanceProfile != nil && instance.IamInstanceProfile.Arn != nil {
				roleARN := *instance.IamInstanceProfile.Arn
				instanceSpec.Edges = append(instanceSpec.Edges, ingest.EdgeSpec{
					FromID:   instanceARN,
					ToID:     roleARN,
					EdgeType: "CanAssume",
					Properties: map[string]interface{}{},
				})
			}

			resourcesChan <- instanceSpec
		}
	}()

	return resourcesChan, errorsChan
}
