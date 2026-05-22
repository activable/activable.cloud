package ingest

// Runtime manages the ingestion lifecycle.
// Pending implementation: provider registration and orchestration.
type Runtime struct {
	ingestors map[string]Ingestor
}

// NewRuntime creates a new ingestion runtime.
func NewRuntime() *Runtime {
	return &Runtime{
		ingestors: make(map[string]Ingestor),
	}
}
