package ingest

// Ingestor defines the interface for cloud provider ingestors.
// Implementations will be populated in Phase 4.
type Ingestor interface {
	// Ingest fetches and returns resources from the cloud provider.
	Ingest(ctx interface{}) error
}
