package audit

import (
	"fmt"
	"time"
)

// AuditTable is the canonical table name for the standalone audit service.
// Migrations hardcode this name, so it must not be changed at runtime.
const AuditTable = "audit.audit_logs"

// DispatchStrategy controls how the AuditRouter delivers events to registered writers.
type DispatchStrategy int

const (
	// DispatchFanOut sends events to ALL writers in parallel (default).
	// Used by the service side: PostgresWriter + OtelWriter + FileWriter all receive every event.
	DispatchFanOut DispatchStrategy = iota

	// DispatchChain tries writers sequentially in registration order, stopping on first success.
	// Used by the producer side: HTTPWriter (primary) → RedisQueueWriter (fallback) → FileWriter (last-resort).
	DispatchChain
)

// AuditConfig contains configuration for the audit pipeline (router, batching, flushing).
// Writer and archiver configuration belongs at the service level, not here.
type AuditConfig struct {
	Enabled         bool          // Master switch for audit system
	BufferSize      int           // Event channel capacity (default: 1024)
	BatchSize       int           // Max events per batch (default: 100)
	FlushInterval   time.Duration // Max time between flushes (default: 5s)
	AlertThreshold  float64       // Buffer usage % for alerts (default: 0.8)
	ShutdownTimeout time.Duration // Max time for graceful shutdown (default: 30s)

	// Partition management
	PartitionCheckInterval time.Duration // How often to check/create partitions (default: 24h)

	// Dispatch strategy (default: DispatchFanOut — all writers in parallel).
	// Set to DispatchChain for ordered fallback: try writers in registration order, stop on first success.
	DispatchStrategy DispatchStrategy
}

// DefaultConfig returns a pipeline configuration with sensible defaults.
func DefaultConfig() *AuditConfig {
	return &AuditConfig{
		Enabled:                true,
		BufferSize:             1024,
		BatchSize:              100,
		FlushInterval:          5 * time.Second,
		AlertThreshold:         0.8,
		ShutdownTimeout:        30 * time.Second,
		PartitionCheckInterval: 24 * time.Hour,
	}
}

// Validate checks the pipeline configuration for errors.
func (c *AuditConfig) Validate() error {
	if c.DispatchStrategy != DispatchFanOut && c.DispatchStrategy != DispatchChain {
		return fmt.Errorf("dispatch strategy must be DispatchFanOut (0) or DispatchChain (1), got %d", c.DispatchStrategy)
	}

	if c.BufferSize < 100 {
		return fmt.Errorf("buffer size must be >= 100, got %d", c.BufferSize)
	}

	if c.BatchSize > c.BufferSize {
		return fmt.Errorf("batch size (%d) must be <= buffer size (%d)", c.BatchSize, c.BufferSize)
	}

	if c.BatchSize < 1 {
		return fmt.Errorf("batch size must be >= 1, got %d", c.BatchSize)
	}

	// 50ms minimum allows fast testing; production should use >= 1s
	if c.FlushInterval < 50*time.Millisecond {
		return fmt.Errorf("flush interval must be >= 50ms, got %v", c.FlushInterval)
	}
	if c.FlushInterval > 60*time.Second {
		return fmt.Errorf("flush interval must be <= 60s, got %v", c.FlushInterval)
	}

	if c.AlertThreshold < 0.0 || c.AlertThreshold > 1.0 {
		return fmt.Errorf("alert threshold must be between 0.0 and 1.0, got %f", c.AlertThreshold)
	}

	if c.ShutdownTimeout < 1*time.Second {
		return fmt.Errorf("shutdown timeout must be >= 1s, got %v", c.ShutdownTimeout)
	}
	if c.ShutdownTimeout > 5*time.Minute {
		return fmt.Errorf("shutdown timeout must be <= 5m, got %v", c.ShutdownTimeout)
	}

	if c.PartitionCheckInterval < 1*time.Hour {
		return fmt.Errorf("partition check interval must be >= 1h, got %v", c.PartitionCheckInterval)
	}

	return nil
}
