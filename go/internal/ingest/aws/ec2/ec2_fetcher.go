package ec2

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"golang.org/x/sync/semaphore"
)

// FetchInstances fetches all EC2 instances from all reservations.
func FetchInstances(ctx context.Context, client EC2Client, sem *semaphore.Weighted) ([]types.Instance, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("semaphore acquire failed: %w", err)
	}
	defer sem.Release(1)

	output, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("DescribeInstances failed: %w", err)
	}

	if output == nil || output.Reservations == nil {
		return []types.Instance{}, nil
	}

	var instances []types.Instance
	for _, reservation := range output.Reservations {
		if reservation.Instances != nil {
			instances = append(instances, reservation.Instances...)
		}
	}

	return instances, nil
}

// FetchVpcs fetches all VPCs in the region.
func FetchVpcs(ctx context.Context, client EC2Client, sem *semaphore.Weighted) ([]types.Vpc, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("semaphore acquire failed: %w", err)
	}
	defer sem.Release(1)

	output, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("DescribeVpcs failed: %w", err)
	}

	if output == nil || output.Vpcs == nil {
		return []types.Vpc{}, nil
	}

	return output.Vpcs, nil
}

// FetchSecurityGroups fetches all security groups in the region.
func FetchSecurityGroups(ctx context.Context, client EC2Client, sem *semaphore.Weighted) ([]types.SecurityGroup, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("semaphore acquire failed: %w", err)
	}
	defer sem.Release(1)

	output, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("DescribeSecurityGroups failed: %w", err)
	}

	if output == nil || output.SecurityGroups == nil {
		return []types.SecurityGroup{}, nil
	}

	return output.SecurityGroups, nil
}
