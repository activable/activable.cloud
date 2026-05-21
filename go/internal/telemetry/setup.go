package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
)

// InitTelemetry initializes OpenTelemetry with the given endpoint.
// Returns a shutdown function to be called on graceful shutdown.
func InitTelemetry(endpoint string) (func(context.Context) error, error) {
	// Placeholder implementation. Phase 4 will wire up OTLP exporter.
	return func(ctx context.Context) error { return nil }, nil
}

// GetTracer returns the global tracer for the application.
func GetTracer(name string) interface{} {
	return otel.Tracer(name)
}
