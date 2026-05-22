package ingest

import (
	"context"
)

// ResourceSpec represents a cloud resource to be ingested into the graph.
type ResourceSpec struct {
	Label      string                 `json:"label"`
	ID         string                 `json:"id"`
	Properties map[string]interface{} `json:"properties"`
	Edges      []EdgeSpec             `json:"edges"`
}

// EdgeSpec represents a relationship between resources.
type EdgeSpec struct {
	TargetID   string                 `json:"target_id"`
	EdgeType   string                 `json:"edge_type"`
	Properties map[string]interface{} `json:"properties"`
}

// Ingester defines the interface for cloud provider resource enumerators.
type Ingester interface {
	// Service returns the name of the cloud service (e.g., "iam", "s3", "ec2").
	Service() string

	// RequiredIAMActions returns the list of IAM actions required for this ingester.
	RequiredIAMActions() []string

	// Enumerate returns channels for resources and errors discovered by this ingester.
	// The resource channel is closed when enumeration is complete.
	// Errors are sent on the error channel; a nil error signals the ingester finished successfully.
	Enumerate(ctx context.Context) (<-chan ResourceSpec, <-chan error)
}
