package ec2

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ingest "github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"golang.org/x/sync/semaphore"
)

// EC2Ingester implements the ingest.Ingester interface for AWS EC2 resources.
// EC2 is regional; instantiate one ingester per enabled region.
type EC2Ingester struct {
	client    EC2Client
	region    string
	accountID string
	sem       *semaphore.Weighted
}

// NewEC2Ingester creates a new EC2 ingester for a specific region.
func NewEC2Ingester(client EC2Client, region string, accountID string, concurrencyLimit int64) *EC2Ingester {
	if concurrencyLimit <= 0 {
		concurrencyLimit = 5 // Default to 5 concurrent calls for EC2
	}

	return &EC2Ingester{
		client:    client,
		region:    region,
		accountID: accountID,
		sem:       semaphore.NewWeighted(concurrencyLimit),
	}
}

// Service returns the service name for this ingester.
func (i *EC2Ingester) Service() string {
	return "ec2"
}

// RequiredIAMActions returns the list of IAM actions required for this ingester.
func (i *EC2Ingester) RequiredIAMActions() []string {
	return []string{
		"ec2:DescribeInstances",
		"ec2:DescribeSecurityGroups",
		"ec2:DescribeVpcs",
	}
}

// Enumerate enumerates all EC2 resources in the ingester's region.
func (i *EC2Ingester) Enumerate(ctx context.Context) (<-chan ingest.ResourceSpec, <-chan error) {
	resourcesChan := make(chan ingest.ResourceSpec, 100)
	errorsChan := make(chan error, 10)

	go func() {
		defer close(resourcesChan)
		defer close(errorsChan)

		// Enumerate VPCs first (since instances reference them)
		if err := i.enumerateVpcs(ctx, resourcesChan); err != nil {
			errorsChan <- fmt.Errorf("enumerate VPCs: %w", err)
		}

		// Enumerate security groups
		if err := i.enumerateSecurityGroups(ctx, resourcesChan); err != nil {
			errorsChan <- fmt.Errorf("enumerate security groups: %w", err)
		}

		// Enumerate instances
		if err := i.enumerateInstances(ctx, resourcesChan); err != nil {
			errorsChan <- fmt.Errorf("enumerate instances: %w", err)
		}
	}()

	return resourcesChan, errorsChan
}

// enumerateInstances fetches all EC2 instances in the region.
func (i *EC2Ingester) enumerateInstances(ctx context.Context, resourcesChan chan<- ingest.ResourceSpec) error {
	if err := i.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer i.sem.Release(1)

	paginator := ec2.NewDescribeInstancesPaginator(i.client, &ec2.DescribeInstancesInput{})

	for paginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("DescribeInstances pagination error: %w", err)
		}

		if len(page.Reservations) == 0 {
			continue
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				spec := InstanceToResourceSpec(instance, i.region, i.accountID)
				select {
				case resourcesChan <- spec:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}

	return nil
}

// enumerateSecurityGroups fetches all security groups in the region.
func (i *EC2Ingester) enumerateSecurityGroups(ctx context.Context, resourcesChan chan<- ingest.ResourceSpec) error {
	if err := i.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer i.sem.Release(1)

	paginator := ec2.NewDescribeSecurityGroupsPaginator(i.client, &ec2.DescribeSecurityGroupsInput{})

	for paginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("DescribeSecurityGroups pagination error: %w", err)
		}

		if len(page.SecurityGroups) == 0 {
			continue
		}

		for _, sg := range page.SecurityGroups {
			spec := SecurityGroupToResourceSpec(sg, i.region, i.accountID)
			select {
			case resourcesChan <- spec:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return nil
}

// enumerateVpcs fetches all VPCs in the region.
func (i *EC2Ingester) enumerateVpcs(ctx context.Context, resourcesChan chan<- ingest.ResourceSpec) error {
	if err := i.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer i.sem.Release(1)

	paginator := ec2.NewDescribeVpcsPaginator(i.client, &ec2.DescribeVpcsInput{})

	for paginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("DescribeVpcs pagination error: %w", err)
		}

		if len(page.Vpcs) == 0 {
			continue
		}

		for _, vpc := range page.Vpcs {
			spec := VpcToResourceSpec(vpc, i.region, i.accountID)
			select {
			case resourcesChan <- spec:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return nil
}
