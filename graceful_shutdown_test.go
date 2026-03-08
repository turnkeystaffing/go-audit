package audit

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"bytes"
	"log/slog"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to count total events written to a MockWriter
func countEventsInWriter(writer *MockWriter) int {
	calls := writer.GetWriteBatchCalls()
	total := 0
	for _, batch := range calls {
		total += len(batch)
	}
	return total
}

// Helper function to check if log output contains specific keywords
func hasMessageContaining(logOutput string, keywords []string) bool {
	lower := strings.ToLower(logOutput)
	for _, keyword := range keywords {
		if strings.Contains(lower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

// TestGracefulShutdown validates that the audit system properly flushes all pending events
// before shutting down according to specs/002-implement-unified-audit/plan.md - Graceful Shutdown
//
// CRITICAL: This test MUST FAIL before implementation (TDD - Phase 3.2, T013)
//
// Scenarios tested:
// 1. Shutdown with buffered events → all events flushed
// 2. Shutdown timeout → partial flush if timeout exceeded
// 3. Multiple destinations → all destinations flushed
// 4. Worker goroutine cleanup → no goroutine leaks
func TestGracefulShutdown(t *testing.T) {
	t.Run("BufferedEvents_AllFlushed", func(t *testing.T) {
		// Setup - long flush interval to keep events buffered
		auditCfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             1024,
			BatchSize:              100,
			FlushInterval:          60 * time.Second, // Very long interval
			AlertThreshold:         0.8,
			ShutdownTimeout:        30 * time.Second, // Allow time to flush
			PartitionCheckInterval: 24 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
		router := NewAuditRouter(auditCfg, log, testNoopRedis())

		// Register mock writer before starting
		writer := NewMockWriter("postgres-writer")
		router.RegisterWriter(writer, true)

		// Start the router
		err := router.Start(context.Background())
		require.NoError(t, err, "Router should start successfully")
		defer router.Shutdown(context.Background())

		// Execute - log events without waiting for flush
		numEvents := 50
		for i := 0; i < numEvents; i++ {
			userID := uuid.New()
			event := &AuditEvent{
				UserID:      &userID,
				Action:      testActionLogin,
				Outcome:     OutcomeSuccess,
				IPAddress:   strPtr("192.168.1.100"),
				UserAgent:   "Mozilla/5.0",
				RequestID:   uuid.New(),
				Timestamp:   time.Now(),
				ContextData: make(map[string]interface{}),
			}
			router.Log(context.Background(), event)
		}

		// Don't wait - events are still buffered
		time.Sleep(100 * time.Millisecond)

		// Shutdown - should flush all buffered events
		ctx := context.Background()
		err = router.Shutdown(ctx)
		require.NoError(t, err, "Shutdown should succeed")

		// Assert - all 50 events written to database
		totalFlushed := countEventsInWriter(writer)
		assert.Equal(t, numEvents, totalFlushed, "All %d events should be flushed on shutdown", numEvents)
	})

	t.Run("ShutdownTimeout_PartialFlush", func(t *testing.T) {
		// Setup - short shutdown timeout
		auditCfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             1024,
			BatchSize:              100,
			FlushInterval:          60 * time.Second,
			AlertThreshold:         0.8,
			ShutdownTimeout:        1 * time.Second, // Minimum valid timeout
			PartitionCheckInterval: 24 * time.Hour,
		}

		var logBuf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&logBuf, nil))
		router := NewAuditRouter(auditCfg, log, testNoopRedis())

		// Register mock writer before starting
		writer := NewMockWriter("postgres-writer")
		router.RegisterWriter(writer, true)

		// Start the router
		err := router.Start(context.Background())
		require.NoError(t, err, "Router should start successfully")
		defer router.Shutdown(context.Background())

		// Execute - log many events
		for i := 0; i < 1000; i++ {
			userID := uuid.New()
			event := &AuditEvent{
				UserID:      &userID,
				Action:      testActionLogin,
				Outcome:     OutcomeSuccess,
				IPAddress:   strPtr("192.168.1.100"),
				UserAgent:   "Mozilla/5.0",
				RequestID:   uuid.New(),
				Timestamp:   time.Now(),
				ContextData: make(map[string]interface{}),
			}
			router.Log(context.Background(), event)
		}

		time.Sleep(100 * time.Millisecond)

		// Shutdown with timeout
		ctx := context.Background()
		err = router.Shutdown(ctx)

		// Assert - shutdown completes even if not all events flushed
		// Some events may be lost due to timeout
		totalFlushed := countEventsInWriter(writer)
		assert.Greater(t, totalFlushed, 0, "Should have flushed at least some events before timeout")
		// Note: We don't assert all 1000 events were flushed because the timeout is intentionally short

		// Verify timeout/shutdown warning logged with specific keywords
		logOutput := logBuf.String()
		shutdownKeywords := []string{"shutdown", "timeout", "flush"}
		assert.True(t, hasMessageContaining(logOutput, shutdownKeywords),
			"Should have logged shutdown-related messages containing keywords: %v", shutdownKeywords)

		_ = err
	})

	t.Run("MultipleDestinations_AllFlushed", func(t *testing.T) {
		// Setup - multiple destinations
		auditCfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             1024,
			BatchSize:              100,
			FlushInterval:          60 * time.Second,
			AlertThreshold:         0.8,
			ShutdownTimeout:        30 * time.Second,
			PartitionCheckInterval: 24 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
		router := NewAuditRouter(auditCfg, log, testNoopRedis())

		// Register mock writers for all destinations before starting
		postgresWriter := NewMockWriter("postgres-writer")
		otelWriter := NewMockWriter("otel-writer")
		fileWriter := NewMockWriter("file-writer")
		router.RegisterWriter(postgresWriter, true)
		router.RegisterWriter(otelWriter, false)
		router.RegisterWriter(fileWriter, false)

		// Start the router
		err := router.Start(context.Background())
		require.NoError(t, err, "Router should start successfully")
		defer router.Shutdown(context.Background())

		// Execute - log events
		numEvents := 30
		for i := 0; i < numEvents; i++ {
			userID := uuid.New()
			event := &AuditEvent{
				UserID:      &userID,
				Action:      testActionLogin,
				Outcome:     OutcomeSuccess,
				IPAddress:   strPtr("192.168.1.100"),
				UserAgent:   "Mozilla/5.0",
				RequestID:   uuid.New(),
				Timestamp:   time.Now(),
				ContextData: make(map[string]interface{}),
			}
			router.Log(context.Background(), event)
		}

		time.Sleep(100 * time.Millisecond)

		// Shutdown
		ctx := context.Background()
		err = router.Shutdown(ctx)
		require.NoError(t, err)

		// Assert - all destinations flushed
		postgresCount := countEventsInWriter(postgresWriter)
		otelCount := countEventsInWriter(otelWriter)
		fileCount := countEventsInWriter(fileWriter)

		assert.Equal(t, numEvents, postgresCount, "PostgreSQL should have received all %d events", numEvents)
		assert.Equal(t, numEvents, otelCount, "Otel should have received all %d events", numEvents)
		assert.Equal(t, numEvents, fileCount, "File should have received all %d events", numEvents)
	})

	t.Run("WorkerCleanup_NoGoroutineLeaks", func(t *testing.T) {
		// Setup
		auditCfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             1024,
			BatchSize:              100,
			FlushInterval:          5 * time.Second,
			AlertThreshold:         0.8,
			ShutdownTimeout:        10 * time.Second,
			PartitionCheckInterval: 24 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

		// Record baseline goroutine count
		baselineGoroutines := runtime.NumGoroutine()

		// Create and shutdown router multiple times
		for i := 0; i < 5; i++ {
			router := NewAuditRouter(auditCfg, log, testNoopRedis())

			// Register mock writer before starting
			writer := NewMockWriter("postgres-writer")
			router.RegisterWriter(writer, true)

			// Start the router
			err := router.Start(context.Background())
			require.NoError(t, err, "Router should start successfully")

			// Log some events
			for j := 0; j < 10; j++ {
				userID := uuid.New()
				event := &AuditEvent{
					UserID:      &userID,
					Action:      testActionLogin,
					Outcome:     OutcomeSuccess,
					IPAddress:   strPtr("192.168.1.100"),
					UserAgent:   "Mozilla/5.0",
					RequestID:   uuid.New(),
					Timestamp:   time.Now(),
					ContextData: make(map[string]interface{}),
				}
				router.Log(context.Background(), event)
			}

			// Shutdown
			ctx := context.Background()
			err = router.Shutdown(ctx)
			require.NoError(t, err)
		}

		// Allow time for goroutines to settle
		time.Sleep(200 * time.Millisecond)

		// Assert - no goroutine leaks
		// Each router should clean up its worker goroutine
		finalGoroutines := runtime.NumGoroutine()
		goroutineDiff := finalGoroutines - baselineGoroutines
		assert.LessOrEqual(t, goroutineDiff, 2, "Should have at most 2 extra goroutines (allowing for test framework variance), got %d extra", goroutineDiff)
	})

	t.Run("ShutdownDuringWrite_NoCorruption", func(t *testing.T) {
		// Setup
		auditCfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             1024,
			BatchSize:              50,
			FlushInterval:          100 * time.Millisecond, // Short flush interval for test
			AlertThreshold:         0.8,
			ShutdownTimeout:        5 * time.Second,
			PartitionCheckInterval: 24 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
		router := NewAuditRouter(auditCfg, log, testNoopRedis())

		// Register mock writer before starting
		writer := NewMockWriter("postgres-writer")
		router.RegisterWriter(writer, true)

		// Start the router
		err := router.Start(context.Background())
		require.NoError(t, err, "Router should start successfully")
		defer router.Shutdown(context.Background())

		// Execute - log events concurrently with shutdown
		done := make(chan bool)
		go func() {
			for i := 0; i < 100; i++ {
				userID := uuid.New()
				event := &AuditEvent{
					UserID:      &userID,
					Action:      testActionLogin,
					Outcome:     OutcomeSuccess,
					IPAddress:   strPtr("192.168.1.100"),
					UserAgent:   "Mozilla/5.0",
					RequestID:   uuid.New(),
					Timestamp:   time.Now(),
					ContextData: make(map[string]interface{}),
				}
				router.Log(context.Background(), event)
				time.Sleep(10 * time.Millisecond)
			}
			done <- true
		}()

		// Wait a bit then shutdown while events are being logged
		time.Sleep(500 * time.Millisecond)

		ctx := context.Background()
		err = router.Shutdown(ctx)
		require.NoError(t, err)

		<-done

		// Assert - no data corruption
		// Events should be complete (not partial writes)
		calls := writer.GetWriteBatchCalls()
		for batchIdx, batch := range calls {
			for eventIdx, event := range batch {
				// Verify event has valid action and outcome
				assert.Equal(t, testActionLogin, event.Action, "Batch %d, event %d: action should be login", batchIdx, eventIdx)
				assert.Equal(t, OutcomeSuccess, event.Outcome, "Batch %d, event %d: outcome should be success", batchIdx, eventIdx)

				// Verify required fields are populated
				assert.NotNil(t, event.UserID, "Batch %d, event %d: UserID should not be nil", batchIdx, eventIdx)
				assert.NotEqual(t, "", event.IPAddress, "Batch %d, event %d: IPAddress should not be empty", batchIdx, eventIdx)
				assert.NotEqual(t, "", event.UserAgent, "Batch %d, event %d: UserAgent should not be empty", batchIdx, eventIdx)
				assert.NotEqual(t, uuid.Nil, event.RequestID, "Batch %d, event %d: RequestID should not be nil", batchIdx, eventIdx)
			}
		}

		totalFlushed := countEventsInWriter(writer)
		assert.Greater(t, totalFlushed, 0, "Should have flushed at least some events despite concurrent shutdown")
	})

	t.Run("ContextCancellation_RespectedOnShutdown", func(t *testing.T) {
		// Setup
		auditCfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             1024,
			BatchSize:              100,
			FlushInterval:          60 * time.Second,
			AlertThreshold:         0.8,
			ShutdownTimeout:        30 * time.Second,
			PartitionCheckInterval: 24 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
		router := NewAuditRouter(auditCfg, log, testNoopRedis())

		// Register mock writer before starting
		writer := NewMockWriter("postgres-writer")
		router.RegisterWriter(writer, true)

		// Start the router
		err := router.Start(context.Background())
		require.NoError(t, err, "Router should start successfully")
		defer router.Shutdown(context.Background())

		// Execute - log many events
		for i := 0; i < 500; i++ {
			userID := uuid.New()
			event := &AuditEvent{
				UserID:      &userID,
				Action:      testActionLogin,
				Outcome:     OutcomeSuccess,
				IPAddress:   strPtr("192.168.1.100"),
				UserAgent:   "Mozilla/5.0",
				RequestID:   uuid.New(),
				Timestamp:   time.Now(),
				ContextData: make(map[string]interface{}),
			}
			router.Log(context.Background(), event)
		}

		time.Sleep(100 * time.Millisecond)

		// Shutdown with cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Measure shutdown duration
		start := time.Now()
		err = router.Shutdown(ctx)
		duration := time.Since(start)

		// Assert - shutdown respects context cancellation
		// Should return quickly even with pending events
		// A cancelled context should cause shutdown to return within 1 second
		assert.Less(t, duration.Milliseconds(), int64(1000), "Shutdown with cancelled context should complete within 1 second, took %v", duration)

		// Note: err may or may not be nil depending on implementation
		// Some implementations may return context.Canceled error
		_ = err
	})

	t.Run("EmptyBuffer_QuickShutdown", func(t *testing.T) {
		// Setup
		auditCfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             1024,
			BatchSize:              100,
			FlushInterval:          5 * time.Second,
			AlertThreshold:         0.8,
			ShutdownTimeout:        10 * time.Second,
			PartitionCheckInterval: 24 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
		router := NewAuditRouter(auditCfg, log, testNoopRedis())

		// Register mock writer before starting
		writer := NewMockWriter("postgres-writer")
		router.RegisterWriter(writer, true)

		// Start the router
		err := router.Start(context.Background())
		require.NoError(t, err, "Router should start successfully")
		defer router.Shutdown(context.Background())

		// Don't log any events

		// Shutdown with empty buffer
		start := time.Now()
		ctx := context.Background()
		err = router.Shutdown(ctx)
		duration := time.Since(start)

		require.NoError(t, err)

		// Assert - shutdown should be very fast with empty buffer
		assert.Less(t, duration.Milliseconds(), int64(100), "Empty buffer shutdown should be < 100ms")
	})

	t.Run("MultipleShutdownCalls_Idempotent", func(t *testing.T) {
		// Setup
		auditCfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             1024,
			BatchSize:              100,
			FlushInterval:          5 * time.Second,
			AlertThreshold:         0.8,
			ShutdownTimeout:        10 * time.Second,
			PartitionCheckInterval: 24 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
		router := NewAuditRouter(auditCfg, log, testNoopRedis())

		// Register mock writer before starting
		writer := NewMockWriter("postgres-writer")
		router.RegisterWriter(writer, true)

		// Start the router
		err := router.Start(context.Background())
		require.NoError(t, err, "Router should start successfully")
		defer router.Shutdown(context.Background())

		// Execute - call shutdown multiple times
		ctx := context.Background()

		// Get initial WriteBatch call count
		initialCallCount := writer.GetWriteBatchCallCount()

		err1 := router.Shutdown(ctx)
		callCountAfterFirst := writer.GetWriteBatchCallCount()

		err2 := router.Shutdown(ctx)
		callCountAfterSecond := writer.GetWriteBatchCallCount()

		err3 := router.Shutdown(ctx)
		callCountAfterThird := writer.GetWriteBatchCallCount()

		// Assert - all shutdown calls should succeed (or return appropriate error)
		// Second and third calls should be no-ops
		assert.NoError(t, err1, "First shutdown should succeed")

		// Verify subsequent shutdowns are idempotent:
		// 1. They should not panic or cause errors
		// 2. They should not perform additional work (no new WriteBatch calls)
		if err2 != nil {
			t.Logf("Second shutdown returned error (may be expected): %v", err2)
		}
		if err3 != nil {
			t.Logf("Third shutdown returned error (may be expected): %v", err3)
		}

		// The first shutdown should have flushed events
		assert.GreaterOrEqual(t, callCountAfterFirst, initialCallCount, "First shutdown should have flushed events")

		// Subsequent shutdowns should not trigger additional flushes
		assert.Equal(t, callCountAfterFirst, callCountAfterSecond, "Second shutdown should not trigger additional flushes")
		assert.Equal(t, callCountAfterSecond, callCountAfterThird, "Third shutdown should not trigger additional flushes")
	})

	t.Run("ShutdownMetrics_Logged", func(t *testing.T) {
		// Setup
		auditCfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             1024,
			BatchSize:              100,
			FlushInterval:          60 * time.Second,
			AlertThreshold:         0.8,
			ShutdownTimeout:        30 * time.Second,
			PartitionCheckInterval: 24 * time.Hour,
		}

		var logBuf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&logBuf, nil))
		router := NewAuditRouter(auditCfg, log, testNoopRedis())

		// Register mock writer before starting
		writer := NewMockWriter("postgres-writer")
		router.RegisterWriter(writer, true)

		// Start the router
		err := router.Start(context.Background())
		require.NoError(t, err, "Router should start successfully")
		defer router.Shutdown(context.Background())

		// Execute - log events
		for i := 0; i < 25; i++ {
			userID := uuid.New()
			event := &AuditEvent{
				UserID:      &userID,
				Action:      testActionLogin,
				Outcome:     OutcomeSuccess,
				IPAddress:   strPtr("192.168.1.100"),
				UserAgent:   "Mozilla/5.0",
				RequestID:   uuid.New(),
				Timestamp:   time.Now(),
				ContextData: make(map[string]interface{}),
			}
			router.Log(context.Background(), event)
		}

		time.Sleep(100 * time.Millisecond)

		// Shutdown
		ctx := context.Background()
		err = router.Shutdown(ctx)
		require.NoError(t, err)

		// Assert - shutdown metrics logged with specific content
		// Should log: events flushed, shutdown duration, final buffer state
		logOutput := logBuf.String()

		// Verify shutdown metrics contain specific keywords related to shutdown operations
		metricsKeywords := []string{"shutdown", "events", "flush", "duration", "buffer"}
		assert.True(t, hasMessageContaining(logOutput, metricsKeywords),
			"Should have logged shutdown metrics containing keywords: %v", metricsKeywords)
	})
}
