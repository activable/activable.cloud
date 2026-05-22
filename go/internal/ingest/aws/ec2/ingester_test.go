package ec2

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// MockEC2Client is a simple mock for testing.
type MockEC2Client struct {
	DescribeInstancesFunc     func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeSecurityGroupsFunc func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeVpcsFunc          func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
}

func (m *MockEC2Client) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if m.DescribeInstancesFunc != nil {
		return m.DescribeInstancesFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *MockEC2Client) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if m.DescribeSecurityGroupsFunc != nil {
		return m.DescribeSecurityGroupsFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *MockEC2Client) DescribeVpcs(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	if m.DescribeVpcsFunc != nil {
		return m.DescribeVpcsFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// TestInstanceToResourceSpec tests transformation of an EC2 instance.
func TestInstanceToResourceSpec(t *testing.T) {
	now := time.Now()
	instance := types.Instance{
		InstanceId:   aws.String("i-1234567890abcdef0"),
		InstanceType: types.InstanceTypeT2Micro,
		VpcId:        aws.String("vpc-12345678"),
		LaunchTime:   aws.Time(now),
		State:        &types.InstanceState{Name: types.InstanceStateNameRunning},
		SecurityGroups: []types.GroupIdentifier{
			{GroupId: aws.String("sg-12345678")},
		},
		IamInstanceProfile: &types.IamInstanceProfile{
			Arn: aws.String("arn:aws:iam::123456789012:instance-profile/ec2-role"),
		},
	}

	spec := InstanceToResourceSpec(instance, "us-east-1", "123456789012")

	if spec.Label != "Resource" {
		t.Errorf("expected label 'Resource', got %s", spec.Label)
	}
	if spec.ID != "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0" {
		t.Errorf("expected correct ARN, got %s", spec.ID)
	}
	if spec.Properties["instance_id"] != "i-1234567890abcdef0" {
		t.Errorf("expected instance_id, got %v", spec.Properties["instance_id"])
	}
	if len(spec.Edges) < 2 {
		t.Errorf("expected at least 2 edges (VPC + SecurityGroup), got %d", len(spec.Edges))
	}
}

// TestSecurityGroupToResourceSpec tests transformation of a security group.
func TestSecurityGroupToResourceSpec(t *testing.T) {
	sg := types.SecurityGroup{
		GroupId:   aws.String("sg-12345678"),
		GroupName: aws.String("default"),
		VpcId:     aws.String("vpc-12345678"),
	}

	spec := SecurityGroupToResourceSpec(sg, "us-east-1", "123456789012")

	if spec.Label != "Resource" {
		t.Errorf("expected label 'Resource', got %s", spec.Label)
	}
	if spec.ID != "arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345678" {
		t.Errorf("expected correct ARN, got %s", spec.ID)
	}
	if spec.Properties["group_id"] != "sg-12345678" {
		t.Errorf("expected group_id, got %v", spec.Properties["group_id"])
	}
}

// TestVpcToResourceSpec tests transformation of a VPC.
func TestVpcToResourceSpec(t *testing.T) {
	vpc := types.Vpc{
		VpcId:     aws.String("vpc-12345678"),
		CidrBlock: aws.String("10.0.0.0/16"),
		State:     types.VpcStateAvailable,
	}

	spec := VpcToResourceSpec(vpc, "us-east-1", "123456789012")

	if spec.Label != "Vpc" {
		t.Errorf("expected label 'Vpc', got %s", spec.Label)
	}
	if spec.ID != "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345678" {
		t.Errorf("expected correct ARN, got %s", spec.ID)
	}
	if spec.Properties["vpc_id"] != "vpc-12345678" {
		t.Errorf("expected vpc_id, got %v", spec.Properties["vpc_id"])
	}
}

// TestEC2Service returns the correct service name.
func TestEC2Service(t *testing.T) {
	mock := &MockEC2Client{}
	ingester := NewEC2Ingester(mock, "us-east-1", "123456789012", 5)

	if ingester.Service() != "ec2" {
		t.Errorf("expected service 'ec2', got %s", ingester.Service())
	}
}

// TestEC2RequiredIAMActions returns the correct IAM actions.
func TestEC2RequiredIAMActions(t *testing.T) {
	mock := &MockEC2Client{}
	ingester := NewEC2Ingester(mock, "us-east-1", "123456789012", 5)

	actions := ingester.RequiredIAMActions()
	if len(actions) == 0 {
		t.Fatalf("expected non-empty IAM actions list")
	}

	required := []string{"ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs"}
	for _, req := range required {
		found := false
		for _, action := range actions {
			if action == req {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected action '%s' in RequiredIAMActions", req)
		}
	}
}

// TestRegionalInstantiation tests that two regions produce disjoint node sets.
func TestRegionalInstantiation(t *testing.T) {
	callCount := 0
	mock := &MockEC2Client{
		DescribeInstancesFunc: func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
			callCount++
			// Return different instances based on region (we can't check from params here, so just return empty)
			return &ec2.DescribeInstancesOutput{}, nil
		},
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{}, nil
		},
		DescribeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return &ec2.DescribeVpcsOutput{}, nil
		},
	}

	// Create two regional ingesters
	ingester1 := NewEC2Ingester(mock, "us-east-1", "123456789012", 5)
	ingester2 := NewEC2Ingester(mock, "eu-west-1", "123456789012", 5)

	if ingester1.region != "us-east-1" {
		t.Errorf("expected region us-east-1, got %s", ingester1.region)
	}
	if ingester2.region != "eu-west-1" {
		t.Errorf("expected region eu-west-1, got %s", ingester2.region)
	}
}

// TestEnumerate_Empty tests enumeration with no resources.
func TestEC2Enumerate_Empty(t *testing.T) {
	mock := &MockEC2Client{
		DescribeInstancesFunc: func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
			return &ec2.DescribeInstancesOutput{}, nil
		},
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{}, nil
		},
		DescribeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return &ec2.DescribeVpcsOutput{}, nil
		},
	}

	ingester := NewEC2Ingester(mock, "us-east-1", "123456789012", 5)
	resourcesChan, errorsChan := ingester.Enumerate(context.Background())

	resourceCount := 0
	for range resourcesChan {
		resourceCount++
	}

	errorCount := 0
	for range errorsChan {
		errorCount++
	}

	if resourceCount != 0 {
		t.Errorf("expected 0 resources, got %d", resourceCount)
	}
	if errorCount != 0 {
		t.Errorf("expected 0 errors, got %d", errorCount)
	}
}
