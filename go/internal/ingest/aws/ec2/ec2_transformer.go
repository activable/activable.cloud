package ec2

import (
	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// InstanceToResourceSpec transforms an EC2 Instance to a ResourceSpec with Resource label.
func InstanceToResourceSpec(arn, instanceID, accountID string) ingest.ResourceSpec {
	return ingest.ResourceSpec{
		Label: "Resource",
		ID:    arn,
		Properties: map[string]interface{}{
			"resource_type": "ec2:instance",
			"instance_id":   instanceID,
			"account_id":    accountID,
		},
		Edges: []ingest.EdgeSpec{},
	}
}

// VpcToResourceSpec transforms an EC2 VPC to a ResourceSpec with Vpc label.
func VpcToResourceSpec(arn, vpcID, accountID string) ingest.ResourceSpec {
	return ingest.ResourceSpec{
		Label: "Vpc",
		ID:    arn,
		Properties: map[string]interface{}{
			"vpc_id":     vpcID,
			"account_id": accountID,
		},
		Edges: []ingest.EdgeSpec{},
	}
}

// SecurityGroupToResourceSpec transforms an EC2 SecurityGroup to a ResourceSpec with Resource label.
func SecurityGroupToResourceSpec(arn, groupID, accountID string) ingest.ResourceSpec {
	return ingest.ResourceSpec{
		Label: "Resource",
		ID:    arn,
		Properties: map[string]interface{}{
			"resource_type": "ec2:security-group",
			"group_id":      groupID,
			"account_id":    accountID,
		},
		Edges: []ingest.EdgeSpec{},
	}
}

// ExtractInstanceIDFromARN extracts the instance ID from an EC2 instance ARN.
func ExtractInstanceIDFromARN(arn string) string {
	// ARN format: arn:aws:ec2:region:account:instance/instanceid
	// This is a simple extraction; a full parser would use the arn library.
	// For now, return the last segment after the last slash.
	for i := len(arn) - 1; i >= 0; i-- {
		if arn[i] == '/' {
			return arn[i+1:]
		}
	}
	return ""
}

// Reservation holds instances in a describe result (part of the SDK structure).
type Reservation interface {
	GetInstances() []types.Instance
}
