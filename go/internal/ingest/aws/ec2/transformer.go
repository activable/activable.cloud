package ec2

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	ingest "github.com/activable-cloud/activable.cloud/go/internal/ingest"
)

// InstanceToResourceSpec transforms an EC2 Instance to a Resource spec.
// ARN is constructed as arn:aws:ec2:<region>:<account>:instance/<instance-id>.
func InstanceToResourceSpec(instance types.Instance, region string, accountID string) ingest.ResourceSpec {
	instanceID := ""
	if instance.InstanceId != nil {
		instanceID = *instance.InstanceId
	}

	instanceARN := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, accountID, instanceID)

	launchTimeUnix := int64(0)
	if instance.LaunchTime != nil {
		launchTimeUnix = instance.LaunchTime.Unix()
	}

	spec := ingest.ResourceSpec{
		Label: "Resource",
		ID:    instanceARN,
		Properties: map[string]interface{}{
			"instance_id":   instanceID,
			"instance_type": string(instance.InstanceType),
			"state":         string(instance.State.Name),
			"launched_at":   launchTimeUnix,
			"service":       "ec2",
			"type":          "Instance",
			"region":        region,
		},
	}

	// Add edges to VPC and security groups
	if instance.VpcId != nil {
		vpcID := *instance.VpcId
		vpcARN := fmt.Sprintf("arn:aws:ec2:%s:%s:vpc/%s", region, accountID, vpcID)
		spec.Edges = append(spec.Edges, ingest.EdgeSpec{
			TargetID: vpcARN,
			EdgeType: "Contains",
			Properties: map[string]interface{}{
				"source": instanceARN,
			},
		})
	}

	// Add edges to security groups
	for _, sg := range instance.SecurityGroups {
		if sg.GroupId != nil {
			sgID := *sg.GroupId
			sgARN := fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", region, accountID, sgID)
			spec.Edges = append(spec.Edges, ingest.EdgeSpec{
				TargetID: sgARN,
				EdgeType: "Contains",
				Properties: map[string]interface{}{
					"source": instanceARN,
				},
			})
		}
	}

	// Add edge to IAM role if present (instance profile)
	if instance.IamInstanceProfile != nil && instance.IamInstanceProfile.Arn != nil {
		roleARN := *instance.IamInstanceProfile.Arn
		spec.Edges = append(spec.Edges, ingest.EdgeSpec{
			TargetID: roleARN,
			EdgeType: "Contains",
			Properties: map[string]interface{}{
				"source": instanceARN,
			},
		})
	}

	return spec
}

// SecurityGroupToResourceSpec transforms an EC2 SecurityGroup to a Resource spec.
// ARN is constructed as arn:aws:ec2:<region>:<account>:security-group/<group-id>.
func SecurityGroupToResourceSpec(sg types.SecurityGroup, region string, accountID string) ingest.ResourceSpec {
	groupID := ""
	if sg.GroupId != nil {
		groupID = *sg.GroupId
	}

	sgARN := fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", region, accountID, groupID)

	spec := ingest.ResourceSpec{
		Label: "Resource",
		ID:    sgARN,
		Properties: map[string]interface{}{
			"group_id":   groupID,
			"group_name": stringValue(sg.GroupName),
			"vpc_id":     stringValue(sg.VpcId),
			"service":    "ec2",
			"type":       "SecurityGroup",
			"region":     region,
		},
	}

	return spec
}

// VpcToResourceSpec transforms an EC2 VPC to a Vpc spec.
// ARN is constructed as arn:aws:ec2:<region>:<account>:vpc/<vpc-id>.
func VpcToResourceSpec(vpc types.Vpc, region string, accountID string) ingest.ResourceSpec {
	vpcID := ""
	if vpc.VpcId != nil {
		vpcID = *vpc.VpcId
	}

	vpcARN := fmt.Sprintf("arn:aws:ec2:%s:%s:vpc/%s", region, accountID, vpcID)

	spec := ingest.ResourceSpec{
		Label: "Vpc",
		ID:    vpcARN,
		Properties: map[string]interface{}{
			"vpc_id":  vpcID,
			"cidr":    stringValue(vpc.CidrBlock),
			"state":   string(vpc.State),
			"service": "ec2",
			"region":  region,
		},
	}

	return spec
}

// Helper function to safely extract string pointers
func stringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
