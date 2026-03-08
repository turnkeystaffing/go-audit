package audit

import "context"

// AuditWriter is the interface for audit event destinations.
// Implementations can be critical (fail-fast) or non-critical (best-effort).
//
// Critical writers (e.g., PostgreSQL for compliance):
//   - WriteBatch MUST return errors on failure
//   - Failures will block the audit operation
//   - Health check failures will mark the system as unhealthy
//
// Non-critical writers (e.g., OpenTelemetry, File):
//   - WriteBatch SHOULD return nil even on errors (log internally)
//   - Failures will be logged but not block operations
//   - Health check failures will be logged as warnings
type AuditWriter interface {
	// WriteBatch writes a batch of audit events to the destination.
	// Must be idempotent - duplicate events should be handled gracefully.
	// Critical writers return errors, non-critical writers return nil and log internally.
	WriteBatch(ctx context.Context, events []FinalAuditEvent) error

	// Shutdown flushes all pending events and closes connections.
	// Must complete within the configured shutdown timeout (default 30s).
	Shutdown(ctx context.Context) error

	// Health checks the availability and health of this writer.
	// Must complete within 5 seconds.
	Health(ctx context.Context) error

	// Name returns a unique identifier for this writer.
	// Used for logging, metrics, and ensuring uniqueness.
	Name() string
}
