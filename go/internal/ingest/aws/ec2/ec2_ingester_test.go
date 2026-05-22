package ec2

import (
	"context"
	"testing"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// MockEC2Client implements EC2Client for testing.
type MockEC2Client struct {
	describeInstancesFunc    func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	describeVpcsFunc         func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	describeSecurityGroupsFunc func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

func (m *MockEC2Client) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if m.describeInstancesFunc != nil {
		return m.describeInstancesFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *MockEC2Client) DescribeVpcs(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	if m.describeVpcsFunc != nil {
		return m.describeVpcsFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *MockEC2Client) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if m.describeSecurityGroupsFunc != nil {
		return m.describeSecurityGroupsFunc(ctx, params, optFns...)
	}
	return nil, nil
}

// TestEC2IngesterService tests that the service name is correct.
func TestEC2IngesterService(t *testing.T) {
	ingester := NewEC2Ingester(&MockEC2Client{}, "us-east-1", "123456789012")
	if got := ingester.Service(); got != "ec2" {
		t.Errorf("Service() = %q, want %q", got, "ec2")
	}
}

// TestEC2IngesterEnumerateEmitsInstances tests that instances are enumerated and emitted as Resource nodes.
func TestEC2IngesterEnumerateEmitsInstances(t *testing.T) {
	accountID := "123456789012"
	region := "us-east-1"

	mockClient := &MockEC2Client{
		describeInstancesFunc: func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
			return &ec2.DescribeInstancesOutput{
				Reservations: []types.Reservation{
					{
						Instances: []types.Instance{
							{
								InstanceId: aws.String("i-1234567890abcdef0"),
								VpcId:      aws.String("vpc-12345678"),
							},
							{
								InstanceId: aws.String("i-0987654321fedcba0"),
								VpcId:      aws.String("vpc-87654321"),
							},
						},
					},
				},
			}, nil
		},
		describeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return &ec2.DescribeVpcsOutput{
				Vpcs: []types.Vpc{
					{VpcId: aws.String("vpc-12345678")},
					{VpcId: aws.String("vpc-87654321")},
				},
			}, nil
		},
		describeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []types.SecurityGroup{},
			}, nil
		},
	}

	ingester := NewEC2Ingester(mockClient, region, accountID)
	resourcesChan, errorsChan := ingester.Enumerate(context.Background(), region)

	// Collect resources
	var resources []ingest.ResourceSpec
	var errors []error

	for {
		select {
		case res, ok := <-resourcesChan:
			if !ok {
				resourcesChan = nil
			} else {
				resources = append(resources, res)
			}
		case err, ok := <-errorsChan:
			if !ok {
				errorsChan = nil
			} else {
				errors = append(errors, err)
			}
		}
		if resourcesChan == nil && errorsChan == nil {
			break
		}
	}

	// Count instance resources
	instanceCount := 0
	for _, res := range resources {
		if res.Label == "Resource" && res.Properties["resource_type"] == "ec2:instance" {
			instanceCount++
		}
	}

	if instanceCount != 2 {
		t.Errorf("Expected 2 instance Resource nodes, got %d", instanceCount)
	}
}

// TestEC2IngesterEnumerateEmitsVpcs tests that VPCs are enumerated and emitted.
func TestEC2IngesterEnumerateEmitsVpcs(t *testing.T) {
	accountID := "123456789012"
	region := "us-east-1"

	mockClient := &MockEC2Client{
		describeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return &ec2.DescribeVpcsOutput{
				Vpcs: []types.Vpc{
					{VpcId: aws.String("vpc-12345678")},
					{VpcId: aws.String("vpc-87654321")},
				},
			}, nil
		},
		describeInstancesFunc: func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
			return &ec2.DescribeInstancesOutput{
				Reservations: []types.Reservation{},
			}, nil
		},
		describeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []types.SecurityGroup{},
			}, nil
		},
	}

	ingester := NewEC2Ingester(mockClient, region, accountID)
	resourcesChan, errorsChan := ingester.Enumerate(context.Background(), region)

	// Collect resources
	var resources []ingest.ResourceSpec
	var errors []error

	for {
		select {
		case res, ok := <-resourcesChan:
			if !ok {
				resourcesChan = nil
			} else {
				resources = append(resources, res)
			}
		case err, ok := <-errorsChan:
			if !ok {
				errorsChan = nil
			} else {
				errors = append(errors, err)
			}
		}
		if resourcesChan == nil && errorsChan == nil {
			break
		}
	}

	// Count VPC nodes
	vpcCount := 0
	for _, res := range resources {
		if res.Label == "Vpc" {
			vpcCount++
		}
	}

	if vpcCount != 2 {
		t.Errorf("Expected 2 Vpc nodes, got %d", vpcCount)
	}
}

// TestEC2IngesterEnumerateEmitsSecurityGroups tests that security groups are enumerated.
func TestEC2IngesterEnumerateEmitsSecurityGroups(t *testing.T) {
	accountID := "123456789012"
	region := "us-east-1"

	mockClient := &MockEC2Client{
		describeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []types.SecurityGroup{
					{GroupId: aws.String("sg-12345678")},
					{GroupId: aws.String("sg-87654321")},
					{GroupId: aws.String("sg-11111111")},
				},
			}, nil
		},
		describeInstancesFunc: func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
			return &ec2.DescribeInstancesOutput{
				Reservations: []types.Reservation{},
			}, nil
		},
		describeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return &ec2.DescribeVpcsOutput{
				Vpcs: []types.Vpc{},
			}, nil
		},
	}

	ingester := NewEC2Ingester(mockClient, region, accountID)
	resourcesChan, errorsChan := ingester.Enumerate(context.Background(), region)

	// Collect resources
	var resources []ingest.ResourceSpec
	var errors []error

	for {
		select {
		case res, ok := <-resourcesChan:
			if !ok {
				resourcesChan = nil
			} else {
				resources = append(resources, res)
			}
		case err, ok := <-errorsChan:
			if !ok {
				errorsChan = nil
			} else {
				errors = append(errors, err)
			}
		}
		if resourcesChan == nil && errorsChan == nil {
			break
		}
	}

	// Count security group nodes
	sgCount := 0
	for _, res := range resources {
		if res.Label == "Resource" && res.Properties["resource_type"] == "ec2:security-group" {
			sgCount++
		}
	}

	if sgCount != 3 {
		t.Errorf("Expected 3 security group Resource nodes, got %d", sgCount)
	}
}

// TestEC2IngesterEnumerateEmitInstanceVpcContainsEdges tests that Contains edges are emitted from instances to VPCs.
func TestEC2IngesterEnumerateEmitInstanceVpcContainsEdges(t *testing.T) {
	accountID := "123456789012"
	region := "us-east-1"

	mockClient := &MockEC2Client{
		describeInstancesFunc: func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
			return &ec2.DescribeInstancesOutput{
				Reservations: []types.Reservation{
					{
						Instances: []types.Instance{
							{
								InstanceId: aws.String("i-1234567890abcdef0"),
								VpcId:      aws.String("vpc-12345678"),
								SecurityGroups: []types.GroupIdentifier{
									{GroupId: aws.String("sg-12345678")},
								},
							},
						},
					},
				},
			}, nil
		},
		describeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return &ec2.DescribeVpcsOutput{
				Vpcs: []types.Vpc{
					{VpcId: aws.String("vpc-12345678")},
				},
			}, nil
		},
		describeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []types.SecurityGroup{
					{GroupId: aws.String("sg-12345678")},
				},
			}, nil
		},
	}

	ingester := NewEC2Ingester(mockClient, region, accountID)
	resourcesChan, errorsChan := ingester.Enumerate(context.Background(), region)

	// Collect resources
	var resources []ingest.ResourceSpec
	var errors []error

	for {
		select {
		case res, ok := <-resourcesChan:
			if !ok {
				resourcesChan = nil
			} else {
				resources = append(resources, res)
			}
		case err, ok := <-errorsChan:
			if !ok {
				errorsChan = nil
			} else {
				errors = append(errors, err)
			}
		}
		if resourcesChan == nil && errorsChan == nil {
			break
		}
	}

	// Find instance resource and check for Contains edges
	var foundInstance bool
	for _, res := range resources {
		if res.Label == "Resource" && res.Properties["resource_type"] == "ec2:instance" {
			foundInstance = true
			if len(res.Edges) < 2 {
				t.Errorf("Instance should have at least 2 edges (VPC and SG), got %d", len(res.Edges))
			}

			// Check for VPC Contains edge
			var foundVpcEdge bool
			for _, edge := range res.Edges {
				if edge.EdgeType == "Contains" && edge.ToID == "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345678" {
					foundVpcEdge = true
				}
			}
			if !foundVpcEdge {
				t.Errorf("Expected Contains edge to VPC, not found")
			}
		}
	}

	if !foundInstance {
		t.Errorf("Expected to find instance resource")
	}
}

// TestInstanceToResourceSpec tests the transformer function.
func TestInstanceToResourceSpec(t *testing.T) {
	arn := "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
	instanceID := "i-1234567890abcdef0"
	accountID := "123456789012"

	spec := InstanceToResourceSpec(arn, instanceID, accountID)

	if spec.Label != "Resource" {
		t.Errorf("Label = %q, want Resource", spec.Label)
	}
	if spec.ID != arn {
		t.Errorf("ID = %q, want %q", spec.ID, arn)
	}

	if rt, ok := spec.Properties["resource_type"]; !ok || rt != "ec2:instance" {
		t.Errorf("resource_type = %v, want ec2:instance", rt)
	}
}

// TestVpcToResourceSpec tests the VPC transformer function.
func TestVpcToResourceSpec(t *testing.T) {
	arn := "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345678"
	vpcID := "vpc-12345678"
	accountID := "123456789012"

	spec := VpcToResourceSpec(arn, vpcID, accountID)

	if spec.Label != "Vpc" {
		t.Errorf("Label = %q, want Vpc", spec.Label)
	}
	if spec.ID != arn {
		t.Errorf("ID = %q, want %q", spec.ID, arn)
	}

	if vpcProp, ok := spec.Properties["vpc_id"]; !ok || vpcProp != vpcID {
		t.Errorf("vpc_id = %v, want %q", vpcProp, vpcID)
	}
}

// TestSecurityGroupToResourceSpec tests the security group transformer function.
func TestSecurityGroupToResourceSpec(t *testing.T) {
	arn := "arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345678"
	groupID := "sg-12345678"
	accountID := "123456789012"

	spec := SecurityGroupToResourceSpec(arn, groupID, accountID)

	if spec.Label != "Resource" {
		t.Errorf("Label = %q, want Resource", spec.Label)
	}
	if spec.ID != arn {
		t.Errorf("ID = %q, want %q", spec.ID, arn)
	}

	if rt, ok := spec.Properties["resource_type"]; !ok || rt != "ec2:security-group" {
		t.Errorf("resource_type = %v, want ec2:security-group", rt)
	}
}
