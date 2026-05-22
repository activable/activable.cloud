package sts

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// STSClient defines the interface for AWS STS API operations.
// This interface allows for mock testing without making real AWS calls.
type STSClient interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}
