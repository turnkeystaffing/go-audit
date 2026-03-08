package audit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"log/slog"
	"os"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	audit "github.com/turnkeystaffing/go-audit"
	"github.com/turnkeystaffing/go-redis"
)

// TestEnrichment validates audit router's enrichment mechanism
// Tests focus on router behavior, not specific enricher implementations
func TestEnrichment(t *testing.T) {
	// Setup
	auditCfg := &audit.AuditConfig{
		Enabled:                true,
		BufferSize:             1024,
		BatchSize:              100,
		FlushInterval:          100 * time.Millisecond,
		AlertThreshold:         0.8,
		ShutdownTimeout:        30 * time.Second,
		PartitionCheckInterval: 24 * time.Hour,
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	t.Run("EnricherFailure_DoesNotBlockWrite", func(t *testing.T) {
		// Setup - create mock writer to capture events
		mockWriter := audit.NewMockWriter("test-writer")
		router := audit.NewAuditRouter(auditCfg, log, redis.NewNoopClient())
		router.RegisterWriter(mockWriter, false)

		// Register enricher that will fail BEFORE starting router
		failingEnricher := func(ctx context.Context, event *audit.AuditEvent) error {
			return errors.New("simulated enrichment failure")
		}
		router.RegisterEnricher(failingEnricher)

		// Start router after enrichers are registered
		router.Start(context.Background())
		defer router.Shutdown(context.Background())

		// Create event
		userID := uuid.New()
		event := &audit.AuditEvent{
			UserID:      &userID,
			Action:      "login",
			Outcome:     audit.OutcomeSuccess,
			IPAddress:   strPtr("192.168.1.100"),
			UserAgent:   "Mozilla/5.0",
			RequestID:   uuid.New(),
			Timestamp:   time.Now(),
			ContextData: make(map[string]interface{}),
		}

		// Execute
		router.Log(context.Background(), event)
		assert.True(t, mockWriter.WaitForEvents(1, 2*time.Second), "Timed out waiting for event write")

		// Assert - event should be written even if enrichment fails
		calls := mockWriter.GetWriteBatchCalls()
		assert.GreaterOrEqual(t, len(calls), 1, "Writer should have been called even if enrichment failed")

		if len(calls) > 0 {
			events := calls[0]
			assert.GreaterOrEqual(t, len(events), 1, "Event should be written despite enrichment failure")
			assert.NotNil(t, events[0].UserID, "Event should contain user ID")
			assert.Equal(t, "login", events[0].Action, "Event should contain correct action")
		}
	})

	t.Run("NoEnrichers_EventStillWritten", func(t *testing.T) {
		// Setup - create mock writer to capture events (no enrichers registered)
		mockWriter := audit.NewMockWriter("test-writer")
		router := audit.NewAuditRouter(auditCfg, log, redis.NewNoopClient())
		router.RegisterWriter(mockWriter, false)
		router.Start(context.Background())
		defer router.Shutdown(context.Background())

		// Don't register any enrichers

		// Create event
		userID := uuid.New()
		event := &audit.AuditEvent{
			UserID:      &userID,
			Action:      "login",
			Outcome:     audit.OutcomeSuccess,
			IPAddress:   strPtr("192.168.1.100"),
			UserAgent:   "Mozilla/5.0",
			RequestID:   uuid.New(),
			Timestamp:   time.Now(),
			ContextData: make(map[string]interface{}),
		}

		// Execute
		router.Log(context.Background(), event)
		assert.True(t, mockWriter.WaitForEvents(1, 2*time.Second), "Timed out waiting for event write")

		// Assert - event should be written successfully with no enrichment namespaces
		calls := mockWriter.GetWriteBatchCalls()
		assert.GreaterOrEqual(t, len(calls), 1, "Writer should have been called")

		if len(calls) > 0 {
			events := calls[0]
			assert.GreaterOrEqual(t, len(events), 1, "Event should be written")

			writtenEvent := events[0]
			assert.Equal(t, "login", writtenEvent.Action, "Event should contain correct action")
			assert.NotNil(t, writtenEvent.UserID, "Event should contain user ID")

			// Verify no enrichment.* keys exist in ContextData
			for key := range writtenEvent.ContextData {
				assert.NotContains(t, key, "enrichment.", "Event should not contain enrichment data when no enrichers registered")
			}
		}
	})

	t.Run("EnrichmentPerformance_LowLatency", func(t *testing.T) {
		// Setup - register a simple enricher to test performance
		mockWriter := audit.NewMockWriter("test-writer")
		router := audit.NewAuditRouter(auditCfg, log, redis.NewNoopClient())
		router.RegisterWriter(mockWriter, false)

		// Register a fast enricher that just adds a timestamp
		fastEnricher := func(ctx context.Context, event *audit.AuditEvent) error {
			if event.ContextData == nil {
				event.ContextData = make(map[string]interface{})
			}
			event.ContextData["enrichment.test"] = map[string]interface{}{
				"timestamp": time.Now(),
			}
			return nil
		}
		router.RegisterEnricher(fastEnricher)

		err := router.Start(context.Background())
		assert.NoError(t, err, "Router should start successfully")
		defer router.Shutdown(context.Background())

		// Measure Log() call latency (should be non-blocking due to async channel)
		start := time.Now()

		userID := uuid.New()
		event := &audit.AuditEvent{
			UserID:      &userID,
			Action:      "login",
			Outcome:     audit.OutcomeSuccess,
			IPAddress:   strPtr("192.168.1.100"),
			UserAgent:   "Mozilla/5.0",
			RequestID:   uuid.New(),
			Timestamp:   time.Now(),
			ContextData: make(map[string]interface{}),
		}

		err = router.Log(context.Background(), event)
		assert.NoError(t, err, "Log should succeed")

		duration := time.Since(start)

		// Assert - Log() should return immediately (< 10ms) because it's async
		assert.Less(t, duration.Milliseconds(), int64(10), "Log() should be non-blocking (async channel send)")

		// Wait for actual enrichment and writing to complete
		assert.True(t, mockWriter.WaitForEvents(1, 2*time.Second), "Timed out waiting for event write")

		// Verify enrichment actually happened
		calls := mockWriter.GetWriteBatchCalls()
		if assert.GreaterOrEqual(t, len(calls), 1, "Writer should have been called") {
			events := calls[0]
			if assert.GreaterOrEqual(t, len(events), 1, "Event should be written") {
				enrichedEvent := events[0]
				assert.Contains(t, enrichedEvent.EnrichmentMetadata, "enrichment.test", "Event should have test enrichment")
			}
		}
	})
}

func strPtr(s string) *string { return &s }
