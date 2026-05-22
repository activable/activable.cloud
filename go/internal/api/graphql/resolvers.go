package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// FFIClient is an interface for FFI function calls.
// This allows mocking FFI behavior in tests without linking against Rust.
type FFIClient interface {
	QueryFindNode(graphName string, label string, id string) string
	QueryWalkEdges(graphName string, startID string, edgeTypes []string, direction string, depth uint32) string
	QueryPathFinder(graphName string, startID string, endID string, edgeTypes []string, maxHops uint32) string
	QueryBlastRadius(graphName string, nodeID string, edgeTypes []string, maxHops uint32) string
	QuerySubgraph(graphName string, centerID string, radius uint32) string
	HealthCheck() string
}

// RealFFIClient implements FFIClient using actual Rust FFI bindings.
type RealFFIClient struct{}

// Implement FFIClient interface for RealFFIClient
func (c *RealFFIClient) QueryFindNode(graphName string, label string, id string) string {
	// Dynamically import activable_ffi only when needed (avoids link errors in tests)
	// For now, this is a placeholder that will be called only when Rust FFI is available
	return "null"
}

func (c *RealFFIClient) QueryWalkEdges(graphName string, startID string, edgeTypes []string, direction string, depth uint32) string {
	return "[]"
}

func (c *RealFFIClient) QueryPathFinder(graphName string, startID string, endID string, edgeTypes []string, maxHops uint32) string {
	return "[]"
}

func (c *RealFFIClient) QueryBlastRadius(graphName string, nodeID string, edgeTypes []string, maxHops uint32) string {
	return "[]"
}

func (c *RealFFIClient) QuerySubgraph(graphName string, centerID string, radius uint32) string {
	return `{"nodes": [], "edges": []}`
}

func (c *RealFFIClient) HealthCheck() string {
	return "ok"
}

// Resolver implements the GraphQL resolvers.
type Resolver struct {
	logger   *slog.Logger
	ffi      FFIClient
	graphName string
}

// NewResolver creates a new Resolver with real FFI.
func NewResolver(logger *slog.Logger) *Resolver {
	return NewResolverWithFFI(logger, &RealFFIClient{}, "default")
}

// NewResolverWithFFI creates a new Resolver with a custom FFI client (for testing).
func NewResolverWithFFI(logger *slog.Logger, ffi FFIClient, graphName string) *Resolver {
	return &Resolver{
		logger:    logger,
		ffi:       ffi,
		graphName: graphName,
	}
}

// Query resolvers

// FindNode finds a node by label and ID.
func (r *Resolver) FindNode(ctx context.Context, label string, id string) (*Node, error) {
	r.logger.InfoContext(ctx, "FindNode", "label", label, "id", id)

	result := r.ffi.QueryFindNode(r.graphName, label, id)

	if result == "null" || result == "" {
		return nil, nil
	}

	// Check for error in result
	var errMap map[string]interface{}
	if err := json.Unmarshal([]byte(result), &errMap); err == nil {
		if errMsg, ok := errMap["error"]; ok {
			return nil, fmt.Errorf("query error: %v", errMsg)
		}
	}

	// Parse the node
	var node Node
	if err := json.Unmarshal([]byte(result), &node); err != nil {
		r.logger.ErrorContext(ctx, "Failed to unmarshal node", "error", err)
		return nil, fmt.Errorf("failed to parse node: %w", err)
	}

	return &node, nil
}

// WalkEdges walks edges from a starting node.
func (r *Resolver) WalkEdges(ctx context.Context, startID string, edgeTypes []string, direction string, depth int) ([]*NodeRef, error) {
	r.logger.InfoContext(ctx, "WalkEdges", "startID", startID, "edgeTypes", edgeTypes, "direction", direction, "depth", depth)

	if direction != "outgoing" && direction != "incoming" && direction != "both" {
		return nil, fmt.Errorf("invalid direction: %s", direction)
	}

	result := r.ffi.QueryWalkEdges(r.graphName, startID, edgeTypes, direction, uint32(depth))

	var errMap map[string]interface{}
	if err := json.Unmarshal([]byte(result), &errMap); err == nil {
		if errMsg, ok := errMap["error"]; ok {
			return nil, fmt.Errorf("query error: %v", errMsg)
		}
	}

	var refs []*NodeRef
	if err := json.Unmarshal([]byte(result), &refs); err != nil {
		r.logger.ErrorContext(ctx, "Failed to unmarshal node refs", "error", err)
		return nil, fmt.Errorf("failed to parse node refs: %w", err)
	}

	return refs, nil
}

// PathFinder finds all paths between two nodes.
func (r *Resolver) PathFinder(ctx context.Context, startID string, endID string, edgeTypes []string, maxHops int) ([]*Path, error) {
	r.logger.InfoContext(ctx, "PathFinder", "startID", startID, "endID", endID, "edgeTypes", edgeTypes, "maxHops", maxHops)

	result := r.ffi.QueryPathFinder(r.graphName, startID, endID, edgeTypes, uint32(maxHops))

	var errMap map[string]interface{}
	if err := json.Unmarshal([]byte(result), &errMap); err == nil {
		if errMsg, ok := errMap["error"]; ok {
			return nil, fmt.Errorf("query error: %v", errMsg)
		}
	}

	var paths []*Path
	if err := json.Unmarshal([]byte(result), &paths); err != nil {
		r.logger.ErrorContext(ctx, "Failed to unmarshal paths", "error", err)
		return nil, fmt.Errorf("failed to parse paths: %w", err)
	}

	return paths, nil
}

// BlastRadius computes the blast radius from a node.
func (r *Resolver) BlastRadius(ctx context.Context, nodeID string, edgeTypes []string, maxHops int) ([]*NodeRef, error) {
	r.logger.InfoContext(ctx, "BlastRadius", "nodeID", nodeID, "edgeTypes", edgeTypes, "maxHops", maxHops)

	result := r.ffi.QueryBlastRadius(r.graphName, nodeID, edgeTypes, uint32(maxHops))

	var errMap map[string]interface{}
	if err := json.Unmarshal([]byte(result), &errMap); err == nil {
		if errMsg, ok := errMap["error"]; ok {
			return nil, fmt.Errorf("query error: %v", errMsg)
		}
	}

	var refs []*NodeRef
	if err := json.Unmarshal([]byte(result), &refs); err != nil {
		r.logger.ErrorContext(ctx, "Failed to unmarshal blast radius", "error", err)
		return nil, fmt.Errorf("failed to parse blast radius: %w", err)
	}

	return refs, nil
}

// Subgraph fetches a subgraph around a center node.
func (r *Resolver) Subgraph(ctx context.Context, centerID string, radius int) (*Subgraph, error) {
	r.logger.InfoContext(ctx, "Subgraph", "centerID", centerID, "radius", radius)

	result := r.ffi.QuerySubgraph(r.graphName, centerID, uint32(radius))

	var errMap map[string]interface{}
	if err := json.Unmarshal([]byte(result), &errMap); err == nil {
		if errMsg, ok := errMap["error"]; ok {
			return nil, fmt.Errorf("query error: %v", errMsg)
		}
	}

	var subgraph Subgraph
	if err := json.Unmarshal([]byte(result), &subgraph); err != nil {
		r.logger.ErrorContext(ctx, "Failed to unmarshal subgraph", "error", err)
		return nil, fmt.Errorf("failed to parse subgraph: %w", err)
	}

	return &subgraph, nil
}

// IngestStatus retrieves the status of an ingest run.
func (r *Resolver) IngestStatus(ctx context.Context, runID string) (*IngestRun, error) {
	r.logger.InfoContext(ctx, "IngestStatus", "runID", runID)

	// In v1, ingest runs are stored in memory or in a metadata table.
	// For now, return a placeholder implementation.
	// TODO: Query ingest_run metadata table from database.

	return &IngestRun{
		ID:        runID,
		Status:    "RUNNING",
		StartedAt: time.Now().Format(time.RFC3339),
		Services:  []*ServiceStatus{},
	}, nil
}

// Mutation resolvers

// IngestRunStore is a simple in-memory store for ingest runs (for v1 demo).
var ingestRunStore = make(map[string]*IngestRun)

// TriggerIngest triggers an async ingest job.
func (r *Resolver) TriggerIngest(ctx context.Context, provider string, regions []string) (*IngestRun, error) {
	r.logger.InfoContext(ctx, "TriggerIngest", "provider", provider, "regions", regions)

	if provider != "AWS" {
		return nil, fmt.Errorf("unsupported provider: %s (only AWS is supported in v1)", provider)
	}

	if len(regions) == 0 {
		return nil, fmt.Errorf("regions cannot be empty")
	}

	// Create an ingest run record.
	runID := uuid.New().String()
	ingestRun := &IngestRun{
		ID:        runID,
		Status:    "RUNNING",
		StartedAt: time.Now().Format(time.RFC3339),
		Services: []*ServiceStatus{
			{
				Name:      "AWS",
				Status:    "RUNNING",
				NodeCount: 0,
				EdgeCount: 0,
				Error:     nil,
			},
		},
	}

	// Store it for later status queries.
	ingestRunStore[runID] = ingestRun

	// TODO: Spawn async ingestion goroutine here.
	// For now, just return the record with RUNNING status.

	r.logger.InfoContext(ctx, "TriggerIngest completed", "runID", runID)

	return ingestRun, nil
}

// Model types

type Node struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Properties string `json:"properties"`
}

type NodeRef struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type Path struct {
	Nodes  []*NodeRef `json:"nodes"`
	Length int        `json:"length"`
}

type Subgraph struct {
	Nodes []*NodeRef `json:"nodes"`
	Edges []*Edge    `json:"edges"`
}

type Edge struct {
	FromID   string `json:"fromId"`
	ToID     string `json:"toId"`
	EdgeType string `json:"edgeType"`
}

type IngestRun struct {
	ID        string            `json:"id"`
	Status    string            `json:"status"`
	StartedAt string            `json:"startedAt"`
	Services  []*ServiceStatus  `json:"services"`
}

type ServiceStatus struct {
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	NodeCount int     `json:"nodeCount"`
	EdgeCount int     `json:"edgeCount"`
	Error     *string `json:"error"`
}
