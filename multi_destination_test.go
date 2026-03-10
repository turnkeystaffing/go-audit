package audit

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helpers for DRY principle

// createTestAuditConfig returns a standard test audit configuration
func createTestAuditConfig(_, _, _ bool) *AuditConfig {
	return &AuditConfig{
		Enabled:                true,
		BufferSize:             1024,
		BatchSize:              1, // Small batch so events process immediately without waiting for flush
		FlushInterval:          100 * time.Millisecond,
		AlertThreshold:         0.8,
		ShutdownTimeout:        30 * time.Second,
		PartitionCheckInterval: 24 * time.Hour,
	}
}

// createMultiDestTestEvent creates a standard test audit event for multi-destination tests
func createMultiDestTestEvent() *AuditEvent {
	userID := uuid.New()
	return &AuditEvent{
		UserID:      &userID,
		Action:      testActionLogin,
		Outcome:     OutcomeSuccess,
		IPAddress:   strPtr("192.168.1.100"),
		UserAgent:   "Mozilla/5.0",
		RequestID:   uuid.New(),
		Timestamp:   time.Now(),
		ContextData: make(map[string]interface{}),
	}
}

// setupRouterWithMockWriters creates router with mock writers and starts it
func setupRouterWithMockWriters(t *testing.T, cfg *AuditConfig, writers map[string]bool) (*AuditRouter, map[string]*MockWriter) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(cfg, log, testNoopRedis())

	mockWriters := make(map[string]*MockWriter)
	for name, critical := range writers {
		mockWriter := NewMockWriter(name)
		mockWriters[name] = mockWriter
		router.RegisterWriter(mockWriter, critical)
	}

	err := router.Start(context.Background())
	require.NoError(t, err, "Router should start successfully")

	return router, mockWriters
}

// verifyEventInWriter checks if an event with specific action/outcome exists in writer's calls
func verifyEventInWriter(t *testing.T, writer *MockWriter, action string, outcome string) bool {
	calls := writer.GetWriteBatchCalls()
	if len(calls) == 0 {
		return false
	}

	for _, batch := range calls {
		for _, event := range batch {
			if event.Action == action && event.Outcome == outcome {
				return true
			}
		}
	}
	return false
}

// assertEventInWriter asserts that event exists in writer's calls
func assertEventInWriter(t *testing.T, writer *MockWriter, writerName string, action string, outcome string) {
	calls := writer.GetWriteBatchCalls()
	assert.GreaterOrEqual(t, len(calls), 1, "%s should have been called", writerName)
	assert.True(t, verifyEventInWriter(t, writer, action, outcome),
		"Event with action=%s outcome=%s should be found in %s", action, outcome, writerName)
}

// TestMultiDestination validates that audit events are written to multiple destinations
// simultaneously according to specs/002-implement-unified-audit/plan.md - Multi-Destination
//
// CRITICAL: This test MUST FAIL before implementation (TDD - Phase 3.2, T010)
//
// Scenarios tested:
// 1. PostgreSQL (critical) + Otel (non-critical) + File (non-critical)
// 2. Critical destination failure → entire write fails
// 3. Non-critical destination failure → write continues
// 4. Destination health monitoring and statistics
func TestMultiDestination(t *testing.T) {
	t.Run("AllDestinations_Enabled", func(t *testing.T) {
		// Setup with all three destinations
		cfg := createTestAuditConfig(true, true, true)
		router, mockWriters := setupRouterWithMockWriters(t, cfg, map[string]bool{
			"postgres": true,  // critical
			"otel":     false, // non-critical
			"file":     false, // non-critical
		})
		defer router.Shutdown(context.Background())

		// Create and log test event
		event := createMultiDestTestEvent()
		err := router.Log(context.Background(), event)
		require.NoError(t, err)
		// Wait for ALL writers since processBatch calls them in parallel goroutines
		require.True(t, mockWriters["postgres"].WaitForEvents(1, 2*time.Second), "Timed out waiting for postgres write")
		require.True(t, mockWriters["otel"].WaitForEvents(1, 2*time.Second), "Timed out waiting for otel write")
		require.True(t, mockWriters["file"].WaitForEvents(1, 2*time.Second), "Timed out waiting for file write")

		// Assert - verify event written to all three destinations
		assertEventInWriter(t, mockWriters["postgres"], "PostgreSQL", testActionLogin, OutcomeSuccess)
		assertEventInWriter(t, mockWriters["otel"], "Otel", testActionLogin, OutcomeSuccess)
		assertEventInWriter(t, mockWriters["file"], "File", testActionLogin, OutcomeSuccess)
	})

	t.Run("PostgreSQL_Only", func(t *testing.T) {
		// Setup - PostgreSQL only (critical destination)
		cfg := createTestAuditConfig(true, false, false)
		router, mockWriters := setupRouterWithMockWriters(t, cfg, map[string]bool{
			"postgres": true, // critical
		})
		defer router.Shutdown(context.Background())

		// Create and log test event
		event := createMultiDestTestEvent()
		err := router.Log(context.Background(), event)
		require.NoError(t, err)
		require.True(t, mockWriters["postgres"].WaitForEvents(1, 2*time.Second), "Timed out waiting for event write")

		// Assert - verify event written to PostgreSQL only
		assertEventInWriter(t, mockWriters["postgres"], "PostgreSQL", testActionLogin, OutcomeSuccess)

		// Verify only one writer was registered
		assert.Equal(t, 1, len(mockWriters), "Only PostgreSQL writer should be registered")
	})

	t.Run("CriticalDestination_Failure", func(t *testing.T) {
		// Setup - simulate PostgreSQL connection failure
		cfg := createTestAuditConfig(true, false, false)
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(cfg, log, testNoopRedis())

		// Create mock writer that fails
		failingWriter := NewMockWriter("postgres")
		failingWriter.SetWriteBatchError(errors.New("database connection failed"))
		router.RegisterWriter(failingWriter, true) // critical writer

		err := router.Start(context.Background())
		require.NoError(t, err)
		defer router.Shutdown(context.Background())

		// Create and log test event
		event := createMultiDestTestEvent()
		router.Log(context.Background(), event)
		require.True(t, failingWriter.WaitForEvents(1, 2*time.Second), "Timed out waiting for event write")
		time.Sleep(10 * time.Millisecond) // Allow router to update metrics after writer returns

		// Assert - critical writer should have been called despite failure
		assert.GreaterOrEqual(t, failingWriter.GetWriteBatchCallCount(), 1,
			"Critical writer should have been called")

		// Verify metrics show failed events
		metrics := router.GetMetrics()
		eventsFailed := metrics.EventsFailed.Load()
		assert.Greater(t, eventsFailed, uint64(0), "Failed events count should be greater than 0")
	})

	t.Run("NonCriticalDestination_Failure", func(t *testing.T) {
		// Setup - PostgreSQL (critical, succeeds) + Otel (non-critical, fails)
		cfg := createTestAuditConfig(true, true, false)
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(cfg, log, testNoopRedis())

		// Create PostgreSQL writer that succeeds
		postgresWriter := NewMockWriter("postgres")
		router.RegisterWriter(postgresWriter, true) // critical

		// Create Otel writer that fails
		otelWriter := NewMockWriter("otel")
		otelWriter.SetWriteBatchError(errors.New("otel connection failed"))
		router.RegisterWriter(otelWriter, false) // non-critical

		err := router.Start(context.Background())
		require.NoError(t, err)
		defer router.Shutdown(context.Background())

		// Create and log test event
		event := createMultiDestTestEvent()
		err = router.Log(context.Background(), event)
		require.NoError(t, err, "Log should succeed even with non-critical writer failure")
		// Wait on otel (last writer) so all writers + metrics are updated
		require.True(t, otelWriter.WaitForEvents(1, 2*time.Second), "Timed out waiting for event write")
		time.Sleep(10 * time.Millisecond) // Allow router to update metrics after all writers

		// Assert - PostgreSQL write should succeed even if Otel fails
		assertEventInWriter(t, postgresWriter, "PostgreSQL", testActionLogin, OutcomeSuccess)

		// Assert - Otel writer was called but failed
		assert.GreaterOrEqual(t, otelWriter.GetWriteBatchCallCount(), 1,
			"Otel writer should have been called despite being non-critical")

		// Assert - metrics should show successful processing (non-critical failures don't fail the event)
		metrics := router.GetMetrics()
		eventsProcessed := metrics.EventsProcessed.Load()
		assert.Greater(t, eventsProcessed, uint64(0), "Events should be marked as processed despite non-critical failure")
	})

	t.Run("DestinationHealthMetrics", func(t *testing.T) {
		// Setup with PostgreSQL and Otel destinations
		cfg := createTestAuditConfig(true, true, false)
		router, mockWriters := setupRouterWithMockWriters(t, cfg, map[string]bool{
			"postgres": true,  // critical
			"otel":     false, // non-critical
		})
		defer router.Shutdown(context.Background())

		// Write several events
		for i := 0; i < 10; i++ {
			event := createMultiDestTestEvent()
			router.Log(context.Background(), event)
		}

		// Wait on otel writer (last in chain) so all writers + metrics are updated
		require.True(t, mockWriters["otel"].WaitForEvents(10, 2*time.Second), "Timed out waiting for event writes")
		time.Sleep(10 * time.Millisecond) // Allow router to update metrics after last writer

		// Get health metrics via ISP accessors
		metrics := router.GetMetrics()

		// Verify events_received count
		eventsReceived := metrics.EventsReceived.Load()
		assert.Equal(t, uint64(10), eventsReceived, "Should have received 10 events")

		// Verify events_processed count (events successfully written)
		eventsProcessed := metrics.EventsProcessed.Load()
		assert.Equal(t, uint64(10), eventsProcessed, "Should have processed 10 events")

		// Verify last_flush_time timestamp exists
		lastFlushTime := metrics.LastFlushTime.Load()
		assert.Greater(t, lastFlushTime, int64(0), "Last flush time should be set")

		// Verify worker_healthy status
		workerHealthy := metrics.WorkerHealthy.Load()
		assert.True(t, workerHealthy, "Worker should be healthy")

		// Verify both writers received events
		assert.GreaterOrEqual(t, mockWriters["postgres"].GetWriteBatchCallCount(), 1,
			"PostgreSQL writer should have been called")
		assert.GreaterOrEqual(t, mockWriters["otel"].GetWriteBatchCallCount(), 1,
			"Otel writer should have been called")
	})

	t.Run("DestinationStatistics_ViewModes", func(t *testing.T) {
		// Setup with all three destinations
		cfg := createTestAuditConfig(true, true, true)
		router, mockWriters := setupRouterWithMockWriters(t, cfg, map[string]bool{
			"postgres": true,  // critical
			"otel":     false, // non-critical
			"file":     false, // non-critical
		})
		defer router.Shutdown(context.Background())

		// Write events
		for i := 0; i < 5; i++ {
			event := createMultiDestTestEvent()
			router.Log(context.Background(), event)
		}

		// Wait on file writer (last in chain) so all writers + metrics are updated
		require.True(t, mockWriters["file"].WaitForEvents(5, 2*time.Second), "Timed out waiting for event writes")
		time.Sleep(10 * time.Millisecond) // Allow router to update metrics after last writer

		// Verify metrics via ISP accessors
		metrics := router.GetMetrics()
		assert.Equal(t, uint64(5), metrics.EventsReceived.Load(), "Should have received 5 events")
		assert.Equal(t, uint64(5), metrics.EventsProcessed.Load(), "Should have processed 5 events")
		assert.True(t, metrics.WorkerHealthy.Load(), "Worker should be healthy")

		// Verify all three writers received events
		assert.GreaterOrEqual(t, mockWriters["postgres"].GetWriteBatchCallCount(), 1,
			"PostgreSQL writer should have been called")
		assert.GreaterOrEqual(t, mockWriters["otel"].GetWriteBatchCallCount(), 1,
			"Otel writer should have been called")
		assert.GreaterOrEqual(t, mockWriters["file"].GetWriteBatchCallCount(), 1,
			"File writer should have been called")

		// Verify buffer stats via ISP accessors
		bufferCap := router.BufferCap()
		assert.Equal(t, 1024, bufferCap, "Capacity should match config")
	})

	t.Run("FileRotation_Daily", func(t *testing.T) {
		// Setup - file writer only (non-critical destination)
		cfg := createTestAuditConfig(false, false, true)
		router, mockWriters := setupRouterWithMockWriters(t, cfg, map[string]bool{
			"file": false, // non-critical
		})
		defer router.Shutdown(context.Background())

		// Write multiple events to simulate daily operations
		for i := 0; i < 3; i++ {
			event := createMultiDestTestEvent()
			err := router.Log(context.Background(), event)
			require.NoError(t, err)
		}
		require.True(t, mockWriters["file"].WaitForEvents(3, 2*time.Second), "Timed out waiting for event writes")

		// Assert - verify file writer received events
		fileWriter := mockWriters["file"]
		assertEventInWriter(t, fileWriter, "File", testActionLogin, OutcomeSuccess)

		// Verify all events were written (file writer batches events)
		assert.GreaterOrEqual(t, fileWriter.GetWriteBatchCallCount(), 1,
			"File writer should have been called at least once")

		// Note: Actual file naming verification (audit-YYYY-MM-DD.log format)
		// should be tested in file_writer_test.go integration tests with real filesystem
	})
}
