package ingest

// Runtime manages the ingestion lifecycle.
// Populated in Phase 4.
type Runtime struct {
	ingestors map[string]Ingestor
}

// NewRuntime creates a new ingestion runtime.
func NewRuntime() *Runtime {
	return &Runtime{
		ingestors: make(map[string]Ingestor),
	}
}
