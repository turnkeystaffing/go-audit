package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/turnkeystaffing/go-redis"
	"io"
	"testing"
	"time"

	"log/slog"
	"os"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock Enricher Function
func createMockEnricher(enricherID string, shouldFail bool) Enricher {
	return func(ctx context.Context, event *AuditEvent) error {
		if event.ContextData == nil {
			event.ContextData = make(map[string]interface{})
		}
		if shouldFail {
			return fmt.Errorf("enricher %s failed", enricherID)
		}
		// Use "enrichment." prefix so the router extracts these into EnrichmentMetadata
		event.ContextData["enrichment."+enricherID] = fmt.Sprintf("enriched_by_%s", enricherID)
		return nil
	}
}

// Helper: noop Redis client for tests that don't need Redis.
func testNoopRedis() redis.RedisClient {
	return redis.NewNoopClient()
}

// Helper: Create test config with minimum valid values
func createTestConfig() *AuditConfig {
	return &AuditConfig{
		Enabled:                true,
		BufferSize:             100, // Minimum: 100
		BatchSize:              10,
		FlushInterval:          100 * time.Millisecond, // Minimum: 50ms, Maximum: 60s
		AlertThreshold:         0.8,
		ShutdownTimeout:        5 * time.Second,
		PartitionCheckInterval: 24 * time.Hour,
	}
}

// Helper: Create test event
func createTestEvent() *AuditEvent {
	userID := uuid.New()
	return &AuditEvent{
		ID:        uuid.New(),
		UserID:    &userID,
		Action:    "test_action",
		Outcome:   OutcomeSuccess,
		Timestamp: time.Now(),
		IPAddress: strPtr("127.0.0.1"),
		UserAgent: "test-agent",
		RequestID: uuid.New(), // Required by validation
	}
}

// Test: NewAuditRouter
func TestNewAuditRouter(t *testing.T) {
	t.Run("creates router with valid config", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))

		router := NewAuditRouter(config, log, testNoopRedis())

		require.NotNil(t, router)
		assert.Equal(t, config, router.config)
		assert.NotNil(t, router.eventChannel)
		assert.Equal(t, config.BufferSize, cap(router.eventChannel))
		assert.NotNil(t, router.metrics)
		assert.False(t, router.started.Load())
	})

	t.Run("panics on nil logger", func(t *testing.T) {
		config := createTestConfig()
		assert.PanicsWithValue(t, "logger is required for AuditRouter", func() {
			NewAuditRouter(config, nil, testNoopRedis())
		})
	})

	t.Run("panics on nil redisClient", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		assert.Panics(t, func() {
			NewAuditRouter(config, log, nil)
		})
	})
}

// Test: RegisterWriter
func TestAuditRouter_RegisterWriter(t *testing.T) {
	t.Run("registers critical writer successfully", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("test-writer")
		router.RegisterWriter(writer, true)

		assert.Len(t, router.writers, 1)
		assert.Len(t, router.criticalWriters, 1)
		assert.Equal(t, writer, router.criticalWriters[0])
	})

	t.Run("registers non-critical writer successfully", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("test-writer")
		router.RegisterWriter(writer, false)

		assert.Len(t, router.writers, 1)
		assert.Len(t, router.criticalWriters, 0)
	})

	t.Run("prevents duplicate writer registration", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer1 := NewMockWriter("test-writer")
		writer2 := NewMockWriter("test-writer") // Same name

		router.RegisterWriter(writer1, false)
		router.RegisterWriter(writer2, false) // Should be rejected

		assert.Len(t, router.writers, 1)
		assert.Equal(t, writer1, router.writers[0])
	})

	t.Run("prevents registration after Start()", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		// Register one writer and start
		writer1 := NewMockWriter("writer-1")
		router.RegisterWriter(writer1, true)
		require.NoError(t, router.Start(context.Background()))

		// Try to register another writer after Start()
		writer2 := NewMockWriter("writer-2")
		router.RegisterWriter(writer2, false)

		assert.Len(t, router.writers, 1) // Only first writer registered
	})
}

// Test: RegisterEnricher
func TestAuditRouter_RegisterEnricher(t *testing.T) {
	t.Run("registers enricher successfully", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		enricher := createMockEnricher("enricher-1", false)
		router.RegisterEnricher(enricher)

		assert.Len(t, router.enrichers, 1)
	})

	t.Run("preserves registration order", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		enricher1 := createMockEnricher("enricher-1", false)
		enricher2 := createMockEnricher("enricher-2", false)
		enricher3 := createMockEnricher("enricher-3", false)

		router.RegisterEnricher(enricher1)
		router.RegisterEnricher(enricher2)
		router.RegisterEnricher(enricher3)

		assert.Len(t, router.enrichers, 3)
	})

	t.Run("prevents registration after Start()", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		// Register writer and start
		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))

		// Try to register enricher after Start()
		enricher := createMockEnricher("enricher-1", false)
		router.RegisterEnricher(enricher)

		assert.Len(t, router.enrichers, 0) // No enrichers registered
	})
}

// Test: Start
func TestAuditRouter_Start(t *testing.T) {
	t.Run("starts successfully with valid config", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)

		err := router.Start(context.Background())

		assert.NoError(t, err)
		assert.True(t, router.started.Load())
		assert.True(t, router.metrics.WorkerHealthy.Load())
	})

	t.Run("fails if no writers registered", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		err := router.Start(context.Background())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no writers registered")
		assert.False(t, router.started.Load())
	})

	t.Run("fails on invalid config", func(t *testing.T) {
		config := &AuditConfig{
			Enabled:    true,
			BufferSize: 0, // Invalid
		}
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)

		err := router.Start(context.Background())

		assert.Error(t, err)
		assert.False(t, router.started.Load())
	})

	t.Run("prevents multiple Start() calls", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)

		err1 := router.Start(context.Background())
		assert.NoError(t, err1)

		err2 := router.Start(context.Background())
		assert.Error(t, err2)
		assert.Contains(t, err2.Error(), "already started")
	})
}

// Test: Log (async)
func TestAuditRouter_Log(t *testing.T) {
	t.Run("logs event successfully", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		event := createTestEvent()
		err := router.Log(context.Background(), event)

		assert.NoError(t, err)
		assert.Equal(t, uint64(1), router.metrics.EventsReceived.Load())

		// Wait for flush interval to trigger writer
		require.True(t, writer.WaitForEvents(1, 2*time.Second), "Timed out waiting for event write")
		assert.Greater(t, writer.GetWriteBatchCallCount(), 0)
	})

	t.Run("fails validation for invalid event", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		invalidEvent := &AuditEvent{
			// Missing required fields
		}

		err := router.Log(context.Background(), invalidEvent)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid audit event")
	})

	t.Run("fails if router not started", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		event := createTestEvent()
		err := router.Log(context.Background(), event)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not started")
	})

	t.Run("updates buffer high water mark", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		// Send multiple events — high water mark is updated atomically on send,
		// so it's guaranteed to be > 0 after any successful Log() call.
		for i := 0; i < 5; i++ {
			event := createTestEvent()
			router.Log(context.Background(), event)
		}

		assert.Greater(t, router.metrics.BufferHighWater.Load(), uint64(0))
	})
}

// Test: LogCritical (sync)
func TestAuditRouter_LogCritical(t *testing.T) {
	t.Run("writes synchronously to critical writer", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true) // Critical
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		event := createTestEvent()
		err := router.LogCritical(context.Background(), event)

		assert.NoError(t, err)
		assert.Equal(t, 1, writer.GetWriteBatchCallCount())
		assert.Equal(t, uint64(1), router.metrics.EventsProcessed.Load())
	})

	t.Run("fails when critical writer fails", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		writer.SetWriteBatchError(errors.New("write failed"))
		router.RegisterWriter(writer, true) // Critical
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		event := createTestEvent()
		err := router.LogCritical(context.Background(), event)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "critical audit write failed")
		assert.Equal(t, uint64(1), router.metrics.EventsFailed.Load())
	})

	t.Run("continues when non-critical writer fails", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		criticalWriter := NewMockWriter("critical-writer")
		nonCriticalWriter := NewMockWriter("non-critical-writer")
		nonCriticalWriter.SetWriteBatchError(errors.New("write failed"))

		router.RegisterWriter(criticalWriter, true)
		router.RegisterWriter(nonCriticalWriter, false)
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		event := createTestEvent()
		err := router.LogCritical(context.Background(), event)

		assert.NoError(t, err) // Should succeed despite non-critical failure
		assert.Equal(t, 1, criticalWriter.GetWriteBatchCallCount())
		assert.Equal(t, 1, nonCriticalWriter.GetWriteBatchCallCount())
	})

	t.Run("validates event before processing", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		invalidEvent := &AuditEvent{}

		err := router.LogCritical(context.Background(), invalidEvent)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid audit event")
		assert.Equal(t, 0, writer.GetWriteBatchCallCount())
	})
}

// Test: Worker Batching
func TestAuditRouter_WorkerBatching(t *testing.T) {
	t.Run("batches events by size", func(t *testing.T) {
		config := createTestConfig()
		config.BatchSize = 5
		config.FlushInterval = 10 * time.Second // Long interval to test size-based batching

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		// Send exactly BatchSize events
		for i := 0; i < config.BatchSize; i++ {
			event := createTestEvent()
			router.Log(context.Background(), event)
		}

		// Wait for batch to be processed
		require.True(t, writer.WaitForEvents(config.BatchSize, 2*time.Second), "Timed out waiting for batch write")

		calls := writer.GetWriteBatchCalls()
		require.Len(t, calls, 1)
		assert.Len(t, calls[0], config.BatchSize)
	})

	t.Run("flushes events by time interval", func(t *testing.T) {
		config := createTestConfig()
		config.BatchSize = 100                        // Large batch size
		config.FlushInterval = 100 * time.Millisecond // Short interval for time-based flush

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		// Send few events (less than BatchSize)
		for i := 0; i < 3; i++ {
			event := createTestEvent()
			router.Log(context.Background(), event)
		}

		// Wait for flush interval to trigger
		require.True(t, writer.WaitForEvents(3, 2*time.Second), "Timed out waiting for flush interval write")

		calls := writer.GetWriteBatchCalls()
		require.Greater(t, len(calls), 0)
		assert.Len(t, calls[0], 3) // All 3 events in one batch
	})
}

// Test: Enricher Execution
func TestAuditRouter_EnricherExecution(t *testing.T) {
	t.Run("executes enrichers in order", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)

		// Register enrichers in specific order
		enricher1 := createMockEnricher("enricher-1", false)
		enricher2 := createMockEnricher("enricher-2", false)
		enricher3 := createMockEnricher("enricher-3", false)

		router.RegisterEnricher(enricher1)
		router.RegisterEnricher(enricher2)
		router.RegisterEnricher(enricher3)

		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		event := createTestEvent()
		err := router.LogCritical(context.Background(), event)

		assert.NoError(t, err)

		// Verify all enrichers were applied
		calls := writer.GetWriteBatchCalls()
		require.Len(t, calls, 1)
		enrichedEvent := calls[0][0]

		assert.Contains(t, enrichedEvent.EnrichmentMetadata, "enrichment.enricher-1")
		assert.Contains(t, enrichedEvent.EnrichmentMetadata, "enrichment.enricher-2")
		assert.Contains(t, enrichedEvent.EnrichmentMetadata, "enrichment.enricher-3")
	})

	t.Run("continues processing when enricher fails", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)

		// Register enrichers with one that fails
		enricher1 := createMockEnricher("enricher-1", false)
		enricher2 := createMockEnricher("enricher-2", true) // Fails
		enricher3 := createMockEnricher("enricher-3", false)

		router.RegisterEnricher(enricher1)
		router.RegisterEnricher(enricher2)
		router.RegisterEnricher(enricher3)

		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		event := createTestEvent()
		err := router.LogCritical(context.Background(), event)

		// Should succeed despite enricher failure
		assert.NoError(t, err)

		calls := writer.GetWriteBatchCalls()
		require.Len(t, calls, 1)
		enrichedEvent := calls[0][0]

		// enricher-1 and enricher-3 should have run
		assert.Contains(t, enrichedEvent.EnrichmentMetadata, "enrichment.enricher-1")
		assert.Contains(t, enrichedEvent.EnrichmentMetadata, "enrichment.enricher-3")
		// enricher-2 should not be present (it failed)
		assert.NotContains(t, enrichedEvent.EnrichmentMetadata, "enrichment.enricher-2")
	})
}

// Test: Graceful Shutdown
func TestAuditRouter_Shutdown(t *testing.T) {
	t.Run("drains pending events on shutdown", func(t *testing.T) {
		config := createTestConfig()
		config.FlushInterval = 10 * time.Second // Long interval to accumulate events
		config.BatchSize = 10                   // Explicit batch size for deterministic behavior

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))

		// Send events immediately (Start() doesn't send any events, so no Reset needed)
		eventCount := 15
		for i := 0; i < eventCount; i++ {
			event := createTestEvent()
			router.Log(context.Background(), event)
		}

		// Wait for first batch (10 events) to be processed before shutdown
		require.True(t, writer.WaitForEvents(10, 2*time.Second), "Timed out waiting for first batch")

		// Shutdown immediately (before flush interval)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := router.Shutdown(ctx)

		assert.NoError(t, err)

		// Verify all events were written
		calls := writer.GetWriteBatchCalls()
		totalEvents := 0
		for _, batch := range calls {
			totalEvents += len(batch)
		}
		assert.Equal(t, eventCount, totalEvents, "Expected %d events, but got %d events",
			eventCount, totalEvents)
	})

	t.Run("respects shutdown timeout", func(t *testing.T) {
		config := createTestConfig()
		config.ShutdownTimeout = 1 * time.Second // Minimum valid timeout

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		// Create writer that blocks
		writer := &MockWriter{
			name: "slow-writer",
		}
		writer.SetShutdownError(errors.New("shutdown timeout"))

		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))

		// Shutdown with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		err := router.Shutdown(ctx)

		// Should timeout because of slow writer
		assert.Error(t, err)
	})

	t.Run("calls Shutdown on all writers", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer1 := NewMockWriter("writer-1")
		writer2 := NewMockWriter("writer-2")
		router.RegisterWriter(writer1, true)
		router.RegisterWriter(writer2, false)
		require.NoError(t, router.Start(context.Background()))

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := router.Shutdown(ctx)

		assert.NoError(t, err)
		assert.Equal(t, 1, writer1.shutdownCalls)
		assert.Equal(t, 1, writer2.shutdownCalls)
	})
}

// Test: Health Check
func TestAuditRouter_Health(t *testing.T) {
	t.Run("returns healthy when all checks pass", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		err := router.Health(context.Background())

		assert.NoError(t, err)
	})

	t.Run("fails if router not started", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		err := router.Health(context.Background())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not started")
	})

	t.Run("fails when critical writer unhealthy", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		writer.SetHealthError(errors.New("database connection failed"))
		router.RegisterWriter(writer, true) // Critical
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		err := router.Health(context.Background())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unhealthy")
	})

	t.Run("succeeds when non-critical writer unhealthy", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		criticalWriter := NewMockWriter("critical-writer")
		nonCriticalWriter := NewMockWriter("non-critical-writer")
		nonCriticalWriter.SetHealthError(errors.New("file system full"))

		router.RegisterWriter(criticalWriter, true)
		router.RegisterWriter(nonCriticalWriter, false)
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		err := router.Health(context.Background())

		assert.NoError(t, err) // Should succeed despite non-critical failure
	})

	t.Run("warns when buffer usage exceeds threshold", func(t *testing.T) {
		config := createTestConfig()
		config.BufferSize = 100                 // Minimum valid buffer size
		config.AlertThreshold = 0.8             // 80%
		config.FlushInterval = 10 * time.Second // Long interval to keep buffer filled

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		// Fill buffer beyond threshold (90% of 100 = 90 events)
		for i := 0; i < 90; i++ {
			event := createTestEvent()
			router.Log(context.Background(), event)
		}

		err := router.Health(context.Background())

		// Should still return healthy but log warning
		assert.NoError(t, err)
	})

	t.Run("fails when buffer critically full", func(t *testing.T) {
		config := createTestConfig()
		config.BufferSize = 100                 // Minimum valid buffer size
		config.BatchSize = 10                   // Small batch to trigger processing
		config.FlushInterval = 10 * time.Second // Long interval

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		// Use blocking writer to prevent worker from draining channel
		writer := NewBlockingMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer func() {
			writer.Unblock() // Unblock before shutdown
			router.Shutdown(context.Background())
		}()

		// Send BatchSize events to trigger first flush attempt
		for i := 0; i < 10; i++ {
			event := createTestEvent()
			router.Log(context.Background(), event)
		}

		// Wait for worker to block in WriteBatch
		writer.WaitForBlock()

		// Now fill buffer to 96% while worker is blocked (96 of 100 events)
		for i := 0; i < 96; i++ {
			event := createTestEvent()
			router.Log(context.Background(), event)
		}

		// Small delay to ensure events are in channel
		time.Sleep(50 * time.Millisecond)

		// Check health while buffer is critically full
		err := router.Health(context.Background())

		// Should fail when buffer >= 95%
		require.Error(t, err)
		assert.Contains(t, err.Error(), "critically full")
	})
}

// Test: Buffer Overflow Behavior
func TestAuditRouter_BufferOverflow(t *testing.T) {
	t.Run("fires alert at threshold", func(t *testing.T) {
		config := createTestConfig()
		config.BufferSize = 100 // Minimum valid buffer size
		config.AlertThreshold = 0.8
		config.BatchSize = 10 // Small batch to trigger processing

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		// Use blocking writer to prevent worker from draining channel
		writer := NewBlockingMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer func() {
			writer.Unblock() // Unblock before shutdown
			router.Shutdown(context.Background())
		}()

		// Send BatchSize events to trigger first flush attempt and block worker
		for i := 0; i < 10; i++ {
			event := createTestEvent()
			router.Log(context.Background(), event)
		}

		// Wait for worker to block in WriteBatch
		writer.WaitForBlock()

		// Fill buffer to 85% while worker is blocked (85 of 100 events)
		for i := 0; i < 85; i++ {
			event := createTestEvent()
			router.Log(context.Background(), event)
		}

		time.Sleep(50 * time.Millisecond)

		// Alert should be fired (buffer above 80%)
		assert.True(t, router.metrics.BufferAlertFired.Load())
	})

	t.Run("switches to synchronous write when buffer full", func(t *testing.T) {
		config := createTestConfig()
		config.BufferSize = 100 // Minimum valid buffer size

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		// Fill buffer completely (100 events)
		for i := 0; i < 100; i++ {
			event := createTestEvent()
			router.Log(context.Background(), event)
		}

		// Next event should trigger synchronous write
		event := createTestEvent()
		err := router.Log(context.Background(), event)

		// Should succeed via synchronous fallback
		assert.NoError(t, err)
	})

	t.Run("resets alert when buffer drains below threshold", func(t *testing.T) {
		config := createTestConfig()
		config.BufferSize = 100                       // Minimum valid buffer size
		config.AlertThreshold = 0.8                   // 80% threshold
		config.BatchSize = 10                         // Small batch to trigger processing
		config.FlushInterval = 100 * time.Millisecond // Fast flush for test

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		// Use blocking writer to control worker processing
		writer := NewBlockingMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer func() {
			writer.Unblock() // Unblock before shutdown
			router.Shutdown(context.Background())
		}()

		// Send BatchSize events to trigger first flush attempt and block worker
		for i := 0; i < 10; i++ {
			event := createTestEvent()
			router.Log(context.Background(), event)
		}

		// Wait for worker to block in WriteBatch
		writer.WaitForBlock()

		// Fill buffer to 85% while worker is blocked (85 of 100 events)
		for i := 0; i < 85; i++ {
			event := createTestEvent()
			router.Log(context.Background(), event)
		}

		time.Sleep(50 * time.Millisecond)

		// Alert should be fired (buffer above 80%)
		assert.True(t, router.metrics.BufferAlertFired.Load())

		// Unblock worker to let it drain the buffer
		writer.Unblock()

		// Wait for all 95 events (10 initial + 85 fill) to be written
		require.True(t, writer.WaitForEvents(95, 2*time.Second), "Timed out waiting for buffer drain")

		// Send one more event (buffer now below threshold)
		event := createTestEvent()
		router.Log(context.Background(), event)

		time.Sleep(100 * time.Millisecond)

		// Alert should be reset (buffer below 80%)
		assert.False(t, router.metrics.BufferAlertFired.Load())
	})
}

// Test: NoopAuditRouter
func TestNoopAuditRouter(t *testing.T) {
	t.Run("all methods return nil/success", func(t *testing.T) {
		router := NewNoopAuditRouter()

		event := createTestEvent()

		assert.NoError(t, router.Log(context.Background(), event))
		assert.NoError(t, router.LogCritical(context.Background(), event))
		assert.NoError(t, router.Start(context.Background()))
		assert.NoError(t, router.Shutdown(context.Background()))
		assert.NoError(t, router.Health(context.Background()))

		// These should not panic
		router.RegisterWriter(nil, false)
		router.RegisterEnricher(nil)
	})
}

// Test: GetMetrics
func TestAuditRouter_GetMetrics(t *testing.T) {
	t.Run("returns metrics object", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		metrics := router.GetMetrics()

		require.NotNil(t, metrics)
		assert.Equal(t, router.metrics, metrics)
	})

	t.Run("metrics reflect actual router state", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		// Send some events
		for i := 0; i < 3; i++ {
			event := createTestEvent()
			router.LogCritical(context.Background(), event)
		}

		metrics := router.GetMetrics()
		assert.Equal(t, uint64(3), metrics.EventsReceived.Load())
		assert.Equal(t, uint64(3), metrics.EventsProcessed.Load())
		assert.True(t, metrics.WorkerHealthy.Load())
	})
}

// Test: processBatch scenarios for improved coverage
func TestAuditRouter_ProcessBatch(t *testing.T) {
	t.Run("handles enrichment failure gracefully", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)

		// Register failing enricher
		failingEnricher := createMockEnricher("failing-enricher", true)
		router.RegisterEnricher(failingEnricher)

		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		// Log event - should succeed despite enricher failure
		event := createTestEvent()
		err := router.LogCritical(context.Background(), event)

		assert.NoError(t, err)
		assert.Equal(t, 1, writer.GetWriteBatchCallCount())
	})

	t.Run("handles critical writer failure in batch", func(t *testing.T) {
		config := createTestConfig()
		config.BatchSize = 3
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		// Critical writer that fails
		criticalWriter := NewMockWriter("critical-writer")
		criticalWriter.SetWriteBatchError(errors.New("database connection lost"))
		router.RegisterWriter(criticalWriter, true)

		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		// Send batch of events
		for i := 0; i < 3; i++ {
			router.Log(context.Background(), createTestEvent())
		}

		// Wait for batch processing
		require.True(t, criticalWriter.WaitForEvents(3, 2*time.Second), "Timed out waiting for batch write")
		time.Sleep(10 * time.Millisecond) // Allow router to update metrics

		// Metrics should show failures
		assert.Greater(t, router.metrics.EventsFailed.Load(), uint64(0))
	})

	t.Run("handles non-critical writer failure in batch", func(t *testing.T) {
		config := createTestConfig()
		config.BatchSize = 3
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		// Critical writer succeeds
		criticalWriter := NewMockWriter("critical-writer")
		router.RegisterWriter(criticalWriter, true)

		// Non-critical writer fails
		nonCriticalWriter := NewMockWriter("non-critical-writer")
		nonCriticalWriter.SetWriteBatchError(errors.New("disk full"))
		router.RegisterWriter(nonCriticalWriter, false)

		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		// Send batch of events
		for i := 0; i < 3; i++ {
			router.Log(context.Background(), createTestEvent())
		}

		// Wait on non-critical writer (last in chain) so all writers + metrics are updated
		require.True(t, nonCriticalWriter.WaitForEvents(3, 2*time.Second), "Timed out waiting for batch write")
		time.Sleep(10 * time.Millisecond) // Allow router to update metrics

		// Events should be processed (no failures counted for non-critical)
		assert.Equal(t, uint64(3), router.metrics.EventsProcessed.Load())
		assert.Equal(t, uint64(0), router.metrics.EventsFailed.Load())
	})

	t.Run("processes empty batch without error", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)

		// Call processBatch directly with empty batch
		router.processBatch([]eventEntry{})

		// Should not panic and writer should not be called
		assert.Equal(t, 0, writer.GetWriteBatchCallCount())
	})
}

// Test: Shutdown scenarios for improved coverage
func TestAuditRouter_ShutdownCoverage(t *testing.T) {
	t.Run("returns error when not started", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		ctx := context.Background()
		err := router.Shutdown(ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not started")
	})

	t.Run("returns nil on second shutdown call (idempotency)", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))

		// First shutdown
		ctx := context.Background()
		err1 := router.Shutdown(ctx)
		assert.NoError(t, err1)

		// Second shutdown should return nil (idempotent)
		err2 := router.Shutdown(ctx)
		assert.NoError(t, err2)
	})

	t.Run("returns error when writer shutdown fails", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		writer.SetShutdownError(errors.New("writer shutdown failed"))
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))

		ctx := context.Background()
		err := router.Shutdown(ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "writer shutdown errors")
	})

	t.Run("respects context timeout", func(t *testing.T) {
		config := createTestConfig()
		config.ShutdownTimeout = 30 * time.Second // Long config timeout
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		// Register BOTH writers BEFORE starting the router
		writer := NewMockWriter("writer-1")
		blockWriter := NewBlockingMockWriter("block-writer")
		router.RegisterWriter(writer, true)
		router.RegisterWriter(blockWriter, false)

		require.NoError(t, router.Start(context.Background()))

		// Ensure cleanup even if test fails
		defer func() {
			blockWriter.Unblock()
			// No need to call Shutdown here as the test calls it below
		}()

		// Send events to fill buffer
		for i := 0; i < 10; i++ {
			router.Log(context.Background(), createTestEvent())
		}

		// Wait for writer to block
		blockWriter.WaitForBlock()

		// Use very short context timeout (shorter than config timeout)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// Shutdown with short timeout should fail with context error
		err := router.Shutdown(ctx)

		assert.Error(t, err)
	})
}

// Test: Log scenarios for improved coverage
func TestAuditRouter_LogCoverage(t *testing.T) {
	t.Run("returns error when router is shut down", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))

		// Shutdown the router
		ctx := context.Background()
		require.NoError(t, router.Shutdown(ctx))

		// Try to log after shutdown
		event := createTestEvent()
		err := router.Log(context.Background(), event)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "shut down")
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		// Use blocking writer to make channel send block
		writer := NewBlockingMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer func() {
			writer.Unblock()
			router.Shutdown(context.Background())
		}()

		// Fill buffer completely
		for i := 0; i < config.BufferSize; i++ {
			router.Log(context.Background(), createTestEvent())
		}

		writer.WaitForBlock()

		// Try to log with cancelled context (channel is full, so send will block)
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		event := createTestEvent()
		err := router.Log(ctx, event)

		// Should return context error or succeed via synchronous write
		// (both are acceptable outcomes)
		if err != nil {
			assert.True(t, errors.Is(err, context.Canceled) || err.Error() == "audit router shut down")
		}
	})

	t.Run("falls back to synchronous write on channel timeout", func(t *testing.T) {
		config := createTestConfig()
		config.BufferSize = 100 // Minimum valid buffer size
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		// Use blocking writer to prevent channel draining
		writer := NewBlockingMockWriter("writer-1")
		router.RegisterWriter(writer, true)
		require.NoError(t, router.Start(context.Background()))
		defer func() {
			writer.Unblock()
			router.Shutdown(context.Background())
		}()

		// Fill buffer completely
		for i := 0; i < config.BufferSize; i++ {
			router.Log(context.Background(), createTestEvent())
		}

		writer.WaitForBlock()

		// Wait for channel to be full
		time.Sleep(50 * time.Millisecond)

		// Next Log should trigger timeout and fall back to synchronous write
		event := createTestEvent()
		err := router.Log(context.Background(), event)

		// Should succeed via synchronous fallback (LogCritical)
		assert.NoError(t, err)
	})
}

// ============================================================================
// Story 2-5: Critical Event Rejection & Best-Effort Delivery Tests
// ============================================================================

// Test 4.1: EventBuilder WithCritical
func TestEventBuilder_WithCritical(t *testing.T) {
	t.Run("WithCritical sets Critical to true", func(t *testing.T) {
		event := NewEventBuilder().
			WithAction("test_action").
			WithSuccess().
			WithCritical().
			Build()

		assert.True(t, event.Critical)
	})

	t.Run("default Critical is false", func(t *testing.T) {
		event := NewEventBuilder().
			WithAction("test_action").
			WithSuccess().
			Build()

		assert.False(t, event.Critical)
	})
}

// Test 4.2: Critical field JSON round-trip
func TestCritical_JSONRoundTrip(t *testing.T) {
	t.Run("Critical=true survives marshal/unmarshal", func(t *testing.T) {
		event := createTestEvent()
		event.Critical = true

		data, err := json.Marshal(event)
		require.NoError(t, err)

		var decoded AuditEvent
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.True(t, decoded.Critical)
	})

	t.Run("Critical=false survives marshal/unmarshal", func(t *testing.T) {
		event := createTestEvent()
		event.Critical = false

		data, err := json.Marshal(event)
		require.NoError(t, err)

		var decoded AuditEvent
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.False(t, decoded.Critical)
	})
}

// Test 4.3: Critical field propagates through enrichment to FinalAuditEvent
func TestCritical_FinalEvent_Propagation(t *testing.T) {
	config := createTestConfig()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	writer := NewMockWriter("writer-1")
	router.RegisterWriter(writer, true)
	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	event := createTestEvent()
	event.Critical = true

	err := router.LogCritical(context.Background(), event)
	require.NoError(t, err)

	calls := writer.GetWriteBatchCalls()
	require.Len(t, calls, 1)
	require.Len(t, calls[0], 1)
	assert.True(t, calls[0][0].Critical, "FinalAuditEvent.Critical should be true after enrichment")
}

// Test 4.4: Critical event, all writers fail → Log() returns error
func TestLog_CriticalEvent_AllWritersFail_ReturnsError(t *testing.T) {
	config := createTestConfig()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	writer1 := NewMockWriter("critical-writer")
	writer1.SetWriteBatchError(errors.New("http connection refused"))
	router.RegisterWriter(writer1, true)

	writer2 := NewMockWriter("fallback-writer-1")
	writer2.SetWriteBatchError(errors.New("redis connection refused"))
	router.RegisterWriter(writer2, false)

	writer3 := NewMockWriter("fallback-writer-2")
	writer3.SetWriteBatchError(errors.New("file system error"))
	router.RegisterWriter(writer3, false)

	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	event := createTestEvent()
	event.Critical = true

	err := router.Log(context.Background(), event)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "critical audit event rejected")
}

// Test 4.5: Critical event, critical writer fails but non-critical succeeds → nil
func TestLog_CriticalEvent_OneWriterSucceeds_ReturnsNil(t *testing.T) {
	config := createTestConfig()
	var logBuf bytes.Buffer
	logWriter := io.MultiWriter(os.Stdout, &logBuf)
	log := slog.New(slog.NewTextHandler(logWriter, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	criticalWriter := NewMockWriter("critical-writer")
	criticalWriter.SetWriteBatchError(errors.New("http connection refused"))
	router.RegisterWriter(criticalWriter, true)

	nonCriticalWriter := NewMockWriter("non-critical-writer")
	// No error set — this writer succeeds
	router.RegisterWriter(nonCriticalWriter, false)

	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	event := createTestEvent()
	event.Critical = true

	err := router.Log(context.Background(), event)

	assert.NoError(t, err, "Log() should return nil when at least one writer succeeds")

	// AC3: "warnings are logged for the writers that failed"
	logStr := logBuf.String()
	assert.Contains(t, logStr, "writer failed for critical event",
		"Should log warning for the failed critical writer")
	assert.Contains(t, logStr, "critical-writer",
		"Warning should identify the failed writer by name")
}

// Test 4.6: Critical event, critical writer succeeds, non-critical fails → nil
func TestLog_CriticalEvent_CriticalWriterSucceeds_ReturnsNil(t *testing.T) {
	config := createTestConfig()
	var logBuf bytes.Buffer
	logWriter := io.MultiWriter(os.Stdout, &logBuf)
	log := slog.New(slog.NewTextHandler(logWriter, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	criticalWriter := NewMockWriter("critical-writer")
	// No error set — succeeds
	router.RegisterWriter(criticalWriter, true)

	nonCriticalWriter := NewMockWriter("non-critical-writer")
	nonCriticalWriter.SetWriteBatchError(errors.New("redis connection refused"))
	router.RegisterWriter(nonCriticalWriter, false)

	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	event := createTestEvent()
	event.Critical = true

	err := router.Log(context.Background(), event)

	assert.NoError(t, err, "Log() should return nil when critical writer succeeds")

	// AC3: "warnings are logged for the writers that failed"
	logStr := logBuf.String()
	assert.Contains(t, logStr, "writer failed for critical event",
		"Should log warning for the failed non-critical writer")
	assert.Contains(t, logStr, "non-critical-writer",
		"Warning should identify the failed writer by name")
}

// Test 4.7: Non-critical event, all writers fail → Log() returns nil
func TestLog_NonCriticalEvent_AllWritersFail_ReturnsNil(t *testing.T) {
	config := createTestConfig()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	writer1 := NewMockWriter("writer-1")
	writer1.SetWriteBatchError(errors.New("connection refused"))
	router.RegisterWriter(writer1, true)

	writer2 := NewMockWriter("writer-2")
	writer2.SetWriteBatchError(errors.New("disk full"))
	router.RegisterWriter(writer2, false)

	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	event := createTestEvent()
	// Critical = false (default)

	err := router.Log(context.Background(), event)

	assert.NoError(t, err, "Log() should return nil for non-critical events regardless of writer failures")
}

// Test 4.8: Non-critical event, all writers fail → EventsLost metric incremented
func TestLog_NonCriticalEvent_AllWritersFail_EventsLostMetric(t *testing.T) {
	config := createTestConfig()
	config.BatchSize = 1                         // Small batch for immediate processing
	config.FlushInterval = 50 * time.Millisecond // Short interval
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	writer := NewMockWriter("writer-1")
	writer.SetWriteBatchError(errors.New("connection refused"))
	router.RegisterWriter(writer, true)

	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	event := createTestEvent()
	// Critical = false (default)

	err := router.Log(context.Background(), event)
	require.NoError(t, err)

	// Wait for async processing
	require.True(t, writer.WaitForEvents(1, 2*time.Second), "Timed out waiting for batch write")

	// Allow metrics to update after processBatch completes
	require.Eventually(t, func() bool {
		return router.metrics.EventsLost.Load() > 0
	}, 2*time.Second, 10*time.Millisecond, "EventsLost should be incremented")
}

// Test 4.9: Critical event rejected → EventsCriticalRejected metric incremented
func TestLog_CriticalEvent_EventsCriticalRejectedMetric(t *testing.T) {
	config := createTestConfig()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	writer := NewMockWriter("writer-1")
	writer.SetWriteBatchError(errors.New("connection refused"))
	router.RegisterWriter(writer, true)

	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	event := createTestEvent()
	event.Critical = true

	err := router.Log(context.Background(), event)
	require.Error(t, err)

	assert.Equal(t, uint64(1), router.metrics.EventsCriticalRejected.Load(),
		"EventsCriticalRejected should be incremented on critical event rejection")
}

// Test 4.10: LogCritical() backwards compatibility — event.Critical doesn't affect behavior
func TestLogCritical_BackwardsCompat(t *testing.T) {
	t.Run("critical writer fails with event.Critical=true", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("critical-writer")
		writer.SetWriteBatchError(errors.New("database connection lost"))
		router.RegisterWriter(writer, true)

		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		event := createTestEvent()
		event.Critical = true

		err := router.LogCritical(context.Background(), event)

		assert.Error(t, err, "LogCritical() should still return error when critical writer fails")
		assert.Contains(t, err.Error(), "critical audit write failed")
	})

	t.Run("critical writer fails with event.Critical=false", func(t *testing.T) {
		config := createTestConfig()
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(config, log, testNoopRedis())

		writer := NewMockWriter("critical-writer")
		writer.SetWriteBatchError(errors.New("database connection lost"))
		router.RegisterWriter(writer, true)

		require.NoError(t, router.Start(context.Background()))
		defer router.Shutdown(context.Background())

		event := createTestEvent()
		// event.Critical = false (default)

		err := router.LogCritical(context.Background(), event)

		assert.Error(t, err, "LogCritical() should return error regardless of event.Critical value")
		assert.Contains(t, err.Error(), "critical audit write failed")
	})
}

// Test 4.11: Critical event sync path respects 100ms timeout
func TestLog_CriticalEvent_ContextTimeout(t *testing.T) {
	config := createTestConfig()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	// Use blocking writer — blocks until context cancelled
	blockWriter := NewBlockingMockWriter("slow-writer")
	router.RegisterWriter(blockWriter, true)

	require.NoError(t, router.Start(context.Background()))
	defer func() {
		blockWriter.Unblock()
		router.Shutdown(context.Background())
	}()

	event := createTestEvent()
	event.Critical = true

	start := time.Now()
	err := router.Log(context.Background(), event)
	elapsed := time.Since(start)

	// Should return error (writer blocked → context timeout → all writers fail)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "critical audit event rejected")

	// Should complete within ~100ms (the criticalEventTimeout) with margin for scheduling
	assert.Less(t, elapsed, 150*time.Millisecond,
		"Critical event rejection should occur within ~100ms (NFR24)")
}

// Test 4.12: Non-critical events go through async path, not sync
func TestLog_NonCriticalEvent_AsyncPath_Unchanged(t *testing.T) {
	config := createTestConfig()
	config.FlushInterval = 5 * time.Second // Long interval — no time-based flush
	config.BatchSize = 100                 // Large batch — no size-based flush
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	writer := NewMockWriter("writer-1")
	router.RegisterWriter(writer, true)

	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	event := createTestEvent()
	// Critical = false (default)

	err := router.Log(context.Background(), event)
	require.NoError(t, err)

	// Immediately after Log(), writer should NOT have been called yet.
	// Non-critical events go through the async buffered channel, not the sync path.
	// Safety: with BatchSize=100 and FlushInterval=5s, the worker cannot process the
	// event between Log() return and this assertion — the batch isn't full and the
	// flush timer hasn't fired.
	assert.Equal(t, 0, writer.GetWriteBatchCallCount(),
		"Non-critical event should go through async path, not sync write")
}

// Test: writeCriticalSync with zero writers — defensive guard (unreachable via public API)
func TestWriteCriticalSync_ZeroWriters(t *testing.T) {
	config := createTestConfig()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(config, log, testNoopRedis())
	// No writers registered — Start() would reject this, but writeCriticalSync handles it defensively

	event := createTestEvent()

	err := router.writeCriticalSync(context.Background(), event)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no writers registered")
	assert.Equal(t, uint64(1), router.metrics.EventsCriticalRejected.Load())
	assert.Equal(t, uint64(1), router.metrics.EventsFailed.Load())
}

// Test: Critical event with already-cancelled parent context
func TestLog_CriticalEvent_CancelledContext(t *testing.T) {
	config := createTestConfig()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	// BlockingMockWriter respects context — returns ctx.Err() when context is cancelled
	blockWriter := NewBlockingMockWriter("blocking-writer")
	router.RegisterWriter(blockWriter, true)

	require.NoError(t, router.Start(context.Background()))
	defer func() {
		blockWriter.Unblock()
		router.Shutdown(context.Background())
	}()

	event := createTestEvent()
	event.Critical = true

	// Cancel context before calling Log
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := router.Log(ctx, event)

	// Cancelled parent → writeCriticalSync's timeout context is immediately expired →
	// blocking writer returns context.Canceled → all writers fail → error returned
	require.Error(t, err)
	assert.Contains(t, err.Error(), "critical audit event rejected")
}

// ============================================================================
// QA Tests: Panic Recovery and Metric Verification
// ============================================================================

// panickingWriter is a test-only writer that panics in WriteBatch.
type panickingWriter struct {
	name string
}

func (p *panickingWriter) WriteBatch(_ context.Context, _ []FinalAuditEvent) error {
	panic("writer exploded")
}
func (p *panickingWriter) Shutdown(_ context.Context) error { return nil }
func (p *panickingWriter) Health(_ context.Context) error   { return nil }
func (p *panickingWriter) Name() string                     { return p.name }

// QA Test: Enricher panic during writeCriticalSync is recovered and converted to error
func TestWriteCriticalSync_EnricherPanic_Recovered(t *testing.T) {
	config := createTestConfig()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	writer := NewMockWriter("writer-1")
	router.RegisterWriter(writer, true)

	// Register a panicking enricher
	router.RegisterEnricher(func(_ context.Context, _ *AuditEvent) error {
		panic("enricher exploded")
	})

	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	event := createTestEvent()
	event.Critical = true

	// Should NOT panic — recover() catches it and returns error
	err := router.Log(context.Background(), event)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "critical audit event rejected")
	// Error is sanitized ("internal error") — panic details only in logs, not returned to caller
	assert.Contains(t, err.Error(), "internal error")
	assert.Equal(t, uint64(1), router.metrics.EventsCriticalRejected.Load())
}

// QA Test: Writer panic during writeCriticalSync is recovered and counted as failure
func TestWriteCriticalSync_WriterPanic_Recovered(t *testing.T) {
	config := createTestConfig()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	// Register a panicking writer (only writer → all fail → error)
	router.RegisterWriter(&panickingWriter{name: "panicking-writer"}, true)

	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	event := createTestEvent()
	event.Critical = true

	// Should NOT crash the program — per-goroutine recover() catches writer panic
	err := router.Log(context.Background(), event)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "critical audit event rejected")
	// Writer panic details in error list but specific error info sanitized from caller
	assert.Contains(t, err.Error(), "writers failed")
	assert.Equal(t, uint64(1), router.metrics.EventsCriticalRejected.Load())
}

// QA Test: Writer panic with another writer succeeding → returns nil (panic doesn't block)
func TestWriteCriticalSync_WriterPanic_OtherSucceeds(t *testing.T) {
	config := createTestConfig()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	// One panicking writer + one succeeding writer
	router.RegisterWriter(&panickingWriter{name: "panicking-writer"}, true)
	router.RegisterWriter(NewMockWriter("good-writer"), false)

	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	event := createTestEvent()
	event.Critical = true

	err := router.Log(context.Background(), event)

	// Good writer succeeded → anySuccess = true → returns nil despite the panic
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), router.metrics.EventsProcessed.Load())
}

// QA Test: Critical event that succeeds increments EventsProcessed
func TestLog_CriticalEvent_SuccessMetric(t *testing.T) {
	config := createTestConfig()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(config, log, testNoopRedis())

	writer := NewMockWriter("writer-1")
	router.RegisterWriter(writer, true)

	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	event := createTestEvent()
	event.Critical = true

	err := router.Log(context.Background(), event)
	require.NoError(t, err)

	assert.Equal(t, uint64(1), router.metrics.EventsProcessed.Load(),
		"EventsProcessed should be incremented on successful critical event delivery")
	assert.Equal(t, uint64(1), router.metrics.EventsReceived.Load(),
		"EventsReceived should be incremented for critical events")
	assert.Equal(t, uint64(0), router.metrics.EventsCriticalRejected.Load(),
		"EventsCriticalRejected should NOT be incremented on success")
}
