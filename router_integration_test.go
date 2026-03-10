//go:build integration

package audit

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkgredis "github.com/turnkeystaffing/go-redis"
)

// Test 5.1: Critical event rejection timing < 100ms with all writers unreachable (NFR24)
//
// Uses real HTTPWriter + RedisQueueWriter pointing to unreachable addresses.
// FileWriter is excluded: its WriteBatch returns nil by design (best-effort, last-resort).
// In production, if FileWriter is available, critical events succeed via local fallback.
// This test verifies timing when only network writers are registered and all fail.
func TestLog_CriticalEvent_Integration_RejectionTiming(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// HTTPWriter → unreachable server (connection refused fast)
	httpCfg := DefaultHTTPWriterConfig()
	httpCfg.BaseURL = "http://localhost:19999"
	httpCfg.ServiceName = "test-service"
	httpWriter, err := NewHTTPWriter(httpCfg, NewMockTokenProvider("test-token"), log)
	require.NoError(t, err)

	// RedisQueueWriter → deliberately unreachable Redis (NOT sharedRedisAddr per G18)
	unreachableRedis := redis.NewClient(&redis.Options{
		Addr: "localhost:19998",
	})
	t.Cleanup(func() { _ = unreachableRedis.Close() })
	redisClient := pkgredis.NewPrefixedClient(unreachableRedis, "test:unreachable:")
	redisWriter, err := NewRedisQueueWriter(DefaultRedisQueueWriterConfig(), redisClient, log)
	require.NoError(t, err)

	// Create router with network writers only (both will fail)
	config := createTestConfig()
	router := NewAuditRouter(config, log, testNoopRedis())
	router.RegisterWriter(httpWriter, true)
	router.RegisterWriter(redisWriter, false)
	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	// Create critical event
	event := createTestEvent()
	event.Critical = true

	// Measure rejection timing
	start := time.Now()
	err = router.Log(context.Background(), event)
	elapsed := time.Since(start)

	// Verify rejection
	require.Error(t, err)
	assert.Contains(t, err.Error(), "critical audit event rejected")

	// NFR24: rejection within 100ms — allow margin for CI/scheduling jitter
	assert.Less(t, elapsed, 150*time.Millisecond,
		"Critical event rejection should occur within ~100ms (NFR24), actual: %v", elapsed)

	// Verify metrics
	assert.Equal(t, uint64(1), router.metrics.EventsCriticalRejected.Load())
	assert.Equal(t, uint64(1), router.metrics.EventsFailed.Load())
}

// Test 5.2: Full lifecycle with mock writers — critical event error propagation
func TestLog_CriticalEvent_Integration_WithMockWriters(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := createTestConfig()
	router := NewAuditRouter(config, log, testNoopRedis())

	httpMock := NewMockWriter("http-writer")
	redisMock := NewMockWriter("redis-writer")
	fileMock := NewMockWriter("file-writer")

	router.RegisterWriter(httpMock, true) // critical
	router.RegisterWriter(redisMock, false)
	router.RegisterWriter(fileMock, false)
	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	// Scenario 1: All writers fail → error
	httpMock.SetWriteBatchError(errors.New("http: connection refused"))
	redisMock.SetWriteBatchError(errors.New("redis: connection refused"))
	fileMock.SetWriteBatchError(errors.New("file: permission denied"))

	event1 := NewEventBuilder().
		WithAction("critical_action").
		WithSuccess().
		WithHTTPContext("10.0.0.1", "test-agent").
		WithCritical().
		Build()

	err := router.Log(context.Background(), event1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "critical audit event rejected")
	assert.Contains(t, err.Error(), "all 3 writers failed")
	assert.Equal(t, uint64(1), router.metrics.EventsCriticalRejected.Load())

	// Scenario 2: HTTP fails, file succeeds → nil (fallback chain works)
	httpMock.SetWriteBatchError(errors.New("http: connection refused"))
	redisMock.SetWriteBatchError(errors.New("redis: connection refused"))
	fileMock.SetWriteBatchError(nil) // file writer succeeds

	event2 := NewEventBuilder().
		WithAction("critical_action_2").
		WithSuccess().
		WithHTTPContext("10.0.0.1", "test-agent").
		WithCritical().
		Build()

	err = router.Log(context.Background(), event2)
	assert.NoError(t, err, "Should succeed when file writer succeeds (fallback chain)")
	assert.Equal(t, uint64(1), router.metrics.EventsCriticalRejected.Load(), "Should not increment again")
	assert.Equal(t, uint64(1), router.metrics.EventsProcessed.Load())

	// Scenario 3: All succeed → nil
	httpMock.SetWriteBatchError(nil)
	redisMock.SetWriteBatchError(nil)

	event3 := NewEventBuilder().
		WithAction("critical_action_3").
		WithSuccess().
		WithHTTPContext("10.0.0.1", "test-agent").
		WithCritical().
		Build()

	err = router.Log(context.Background(), event3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(2), router.metrics.EventsProcessed.Load())
}

// Test 5.3: Non-critical event best-effort — all writers fail, Log() returns nil, EventsLost incremented
func TestLog_NonCriticalEvent_Integration_BestEffort(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := createTestConfig()
	config.BatchSize = 1                         // Immediate processing
	config.FlushInterval = 50 * time.Millisecond // Fast flush
	router := NewAuditRouter(config, log, testNoopRedis())

	writer1 := NewMockWriter("writer-1")
	writer1.SetWriteBatchError(errors.New("connection refused"))
	router.RegisterWriter(writer1, true)

	writer2 := NewMockWriter("writer-2")
	writer2.SetWriteBatchError(errors.New("disk full"))
	router.RegisterWriter(writer2, false)

	require.NoError(t, router.Start(context.Background()))
	defer router.Shutdown(context.Background())

	// Send non-critical event
	event := NewEventBuilder().
		WithAction("non_critical_action").
		WithSuccess().
		WithHTTPContext("10.0.0.1", "test-agent").
		Build()
	// Critical = false (default)

	err := router.Log(context.Background(), event)
	assert.NoError(t, err, "Non-critical event should return nil even when all writers will fail")

	// Wait for async processing
	require.True(t, writer1.WaitForEvents(1, 2*time.Second), "Timed out waiting for batch processing")

	// Verify EventsLost metric incremented
	require.Eventually(t, func() bool {
		return router.metrics.EventsLost.Load() > 0
	}, 2*time.Second, 10*time.Millisecond, "EventsLost should be incremented when all writers fail")

	assert.Equal(t, uint64(1), router.metrics.EventsLost.Load())
}
