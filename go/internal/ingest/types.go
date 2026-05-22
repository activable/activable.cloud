package ingest

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Ingester defines the interface for cloud service ingestors.
// Each ingester is responsible for enumerating resources from a specific AWS service
// and producing typed ResourceSpec and EdgeSpec structs.
type Ingester interface {
	// Service returns the name of the service this ingester handles (e.g., "iam", "s3", "ec2").
	Service() string

	// RequiredIAMActions returns a list of IAM actions required for this ingester to operate.
	// Used for documentation and least-privilege enforcement in future versions.
	RequiredIAMActions() []string

	// Enumerate fetches and returns resources from the cloud service.
	// Resources are sent to the returned channel; errors are sent to the error channel.
	// The context can be used to cancel the enumeration.
	Enumerate(ctx context.Context, region string) (<-chan ResourceSpec, <-chan error)
}

// ResourceSpec represents a single cloud resource to be ingested into the graph.
type ResourceSpec struct {
	// Label is the node type (e.g., "Principal", "Resource", "Permission").
	Label string `json:"label"`

	// ID is the canonical resource identifier, typically an ARN.
	ID string `json:"id"`

	// Properties is a JSON-serializable map of resource attributes.
	Properties map[string]interface{} `json:"properties"`

	// Edges are the outgoing edges from this resource to other resources.
	Edges []EdgeSpec `json:"edges"`
}

// EdgeSpec represents a directed edge between two resources in the graph.
type EdgeSpec struct {
	// FromID is the source node ID (typically the parent ResourceSpec's ID).
	FromID string `json:"from_id"`

	// ToID is the target node ID.
	ToID string `json:"to_id"`

	// EdgeType is the type of relationship (e.g., "CanAssume", "HasPermission", "Contains").
	EdgeType string `json:"edge_type"`

	// Properties is a JSON-serializable map of edge attributes.
	Properties map[string]interface{} `json:"properties"`
}

// RunStatus tracks the status of a single ingestion run.
type RunStatus struct {
	// RunID is a UUID identifying this specific ingestion run.
	RunID uuid.UUID `db:"run_id"`

	// StartedAt is the timestamp when the run began.
	StartedAt time.Time `db:"started_at"`

	// FinishedAt is the timestamp when the run completed (only set after Run() finishes).
	FinishedAt time.Time `db:"finished_at"`

	// Status is the overall run status: "running", "completed", "partial_failure", or "failed".
	Status string `db:"status"`

	// PartialFailures is a JSON array of service names that failed during this run.
	// Empty if no failures occurred.
	PartialFailures []string `db:"partial_failures"`
}

// ServiceStatus tracks the completion status of a single ingester within a run.
type ServiceStatus struct {
	// Name is the service name (e.g., "iam", "s3").
	Name string

	// Status is "completed", "partial_failure", "failed", or "skipped".
	Status string

	// NodeCount is the number of nodes written for this service.
	NodeCount int64

	// EdgeCount is the number of edges written for this service.
	EdgeCount int64

	// Error contains the error message if Status is not "completed".
	Error string

	// Regions is the list of regions enumerated for this service.
	Regions []string
}
