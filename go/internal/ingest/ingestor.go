package ingest

// Ingestor defines the interface for cloud provider ingestors.
// Pending implementation: AWS, GCP, Azure provider adapters.
type Ingestor interface {
	// Ingest fetches and returns resources from the cloud provider.
	Ingest(ctx interface{}) error
}
