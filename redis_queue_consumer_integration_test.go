//go:build integration

package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgredis "github.com/turnkeystaffing/go-redis"
)

// setupRedisConsumer creates a RedisQueueConsumer backed by a real Redis testcontainer.
// Uses a unique prefix per test to avoid key collisions.
// Returns the consumer (not started), the Redis client, and the capturing router.
func setupRedisConsumer(t *testing.T) (*RedisQueueConsumer, pkgredis.RedisClient, *capturingLogger) {
	t.Helper()

	rawClient := redis.NewClient(&redis.Options{
		Addr: sharedRedisAddr,
	})
	require.NoError(t, rawClient.Ping(context.Background()).Err(), "Redis container should be reachable")

	prefix := "test:" + uuid.New().String()[:8] + ":"
	client := pkgredis.NewPrefixedClient(rawClient, prefix)

	t.Cleanup(func() { _ = client.Close() })

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	router := &capturingLogger{}

	cfg := RedisQueueConsumerConfig{
		QueueKey:     "audit:fallback:queue",
		BRPOPTimeout: 200 * time.Millisecond, // fast for tests
	}
	consumer := NewRedisQueueConsumer(cfg, client, router, log)

	return consumer, client, router
}

// capturingLogger captures routed events for assertion.
type capturingLogger struct {
	mu     sync.Mutex
	events []*AuditEvent
}

func (c *capturingLogger) Log(_ context.Context, event *AuditEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
	return nil
}

func (c *capturingLogger) LogCritical(_ context.Context, event *AuditEvent) error {
	return c.Log(context.Background(), event)
}

func (c *capturingLogger) getEvents() []*AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]*AuditEvent, len(c.events))
	copy(result, c.events)
	return result
}

// TestRedisQueueConsumer_Integration_EndToEnd verifies producer → Redis → consumer → router
// with a real Redis testcontainer, testing BRPOP, deserialization, and routing.
func TestRedisQueueConsumer_Integration_EndToEnd(t *testing.T) {
	consumer, client, router := setupRedisConsumer(t)
	ctx := context.Background()

	// Push events via RedisQueueWriter (producer side)
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	writerCfg := DefaultRedisQueueWriterConfig()
	writer, err := NewRedisQueueWriter(writerCfg, client, log)
	require.NoError(t, err)

	events := make([]FinalAuditEvent, 5)
	for i := range events {
		events[i] = createTestFinalEvent()
		events[i].ContextData["seq"] = float64(i)
	}

	require.NoError(t, writer.WriteBatch(ctx, events))

	// Verify events are in Redis
	queueLen, err := client.LLen(ctx, "audit:fallback:queue")
	require.NoError(t, err)
	assert.Equal(t, int64(5), queueLen)

	// Start consumer — it should drain all events
	require.NoError(t, consumer.Start(ctx))

	require.Eventually(t, func() bool {
		return len(router.getEvents()) >= 5
	}, 5*time.Second, 50*time.Millisecond)

	require.NoError(t, consumer.Shutdown(ctx))

	// Verify all events routed
	routed := router.getEvents()
	require.Len(t, routed, 5)

	// Verify queue is empty
	queueLen, err = client.LLen(ctx, "audit:fallback:queue")
	require.NoError(t, err)
	assert.Equal(t, int64(0), queueLen)
}

// TestRedisQueueConsumer_Integration_FIFO verifies events are routed in FIFO order.
func TestRedisQueueConsumer_Integration_FIFO(t *testing.T) {
	consumer, client, router := setupRedisConsumer(t)
	ctx := context.Background()

	// Push events with sequential actions: "event-0", "event-1", ... "event-9"
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	writerCfg := DefaultRedisQueueWriterConfig()
	writer, err := NewRedisQueueWriter(writerCfg, client, log)
	require.NoError(t, err)

	const count = 10
	events := make([]FinalAuditEvent, count)
	for i := range events {
		events[i] = createTestFinalEvent()
		events[i].Action = "event-" + uuid.New().String()[:8]
		events[i].ContextData["order"] = float64(i)
	}

	require.NoError(t, writer.WriteBatch(ctx, events))

	// Start consumer
	require.NoError(t, consumer.Start(ctx))

	require.Eventually(t, func() bool {
		return len(router.getEvents()) >= count
	}, 5*time.Second, 50*time.Millisecond)

	require.NoError(t, consumer.Shutdown(ctx))

	// Verify FIFO: LPUSH + BRPOP = queue semantics
	routed := router.getEvents()
	require.Len(t, routed, count)
	for i, ev := range routed {
		assert.Equal(t, events[i].ID, ev.ID, "event %d ID matches", i)
		assert.Equal(t, events[i].Action, ev.Action, "event %d action matches", i)
	}
}

// TestRedisQueueConsumer_Integration_MalformedEvent verifies malformed entries
// are skipped and valid entries are still processed.
func TestRedisQueueConsumer_Integration_MalformedEvent(t *testing.T) {
	consumer, client, router := setupRedisConsumer(t)
	ctx := context.Background()

	// Push a valid event via writer
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	writerCfg := DefaultRedisQueueWriterConfig()
	writer, err := NewRedisQueueWriter(writerCfg, client, log)
	require.NoError(t, err)

	validEvent := createTestFinalEvent()
	require.NoError(t, writer.WriteBatch(ctx, []FinalAuditEvent{validEvent}))

	// Push malformed JSON directly via LPUSH (goes to head of list).
	// BRPOP pops from tail, so the valid event (pushed first) is consumed first,
	// then the malformed entry. Both are consumed; malformed is skipped.
	_, err = client.LPush(ctx, "audit:fallback:queue", "not-valid-json{{{")
	require.NoError(t, err)

	// Start consumer — should skip malformed and process valid
	require.NoError(t, consumer.Start(ctx))

	require.Eventually(t, func() bool {
		return len(router.getEvents()) >= 1
	}, 5*time.Second, 50*time.Millisecond)

	// Give it a moment to confirm no more events arrive
	time.Sleep(300 * time.Millisecond)

	require.NoError(t, consumer.Shutdown(ctx))

	routed := router.getEvents()
	require.Len(t, routed, 1)
	assert.Equal(t, validEvent.ID, routed[0].ID)

	// Queue should be empty (both entries consumed — malformed skipped, valid routed)
	queueLen, err := client.LLen(ctx, "audit:fallback:queue")
	require.NoError(t, err)
	assert.Equal(t, int64(0), queueLen)
}

// TestRedisQueueConsumer_Integration_GracefulShutdown verifies the consumer
// exits cleanly within a bounded time after Shutdown() is called.
func TestRedisQueueConsumer_Integration_GracefulShutdown(t *testing.T) {
	consumer, _, _ := setupRedisConsumer(t)
	ctx := context.Background()

	require.NoError(t, consumer.Start(ctx))

	// Let it run a few BRPOP cycles
	time.Sleep(500 * time.Millisecond)

	start := time.Now()
	err := consumer.Shutdown(ctx)
	elapsed := time.Since(start)

	require.NoError(t, err)
	// Shutdown should complete within BRPOP timeout (200ms) + margin
	assert.Less(t, elapsed, 2*time.Second, "shutdown should be bounded")
}

// TestRedisQueueConsumer_Integration_ProducerConsumerRoundTrip exercises the full
// RedisQueueWriter → Redis → RedisQueueConsumer pipeline including field preservation.
func TestRedisQueueConsumer_Integration_ProducerConsumerRoundTrip(t *testing.T) {
	consumer, client, router := setupRedisConsumer(t)
	ctx := context.Background()

	// Build a detailed event with all fields populated
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	writerCfg := DefaultRedisQueueWriterConfig()
	writer, err := NewRedisQueueWriter(writerCfg, client, log)
	require.NoError(t, err)

	original := createTestFinalEvent()
	original.Action = "user.login"
	original.ResourceType = "session"
	original.Outcome = OutcomeSuccess
	original.ContextData["browser"] = "chrome"

	require.NoError(t, writer.WriteBatch(ctx, []FinalAuditEvent{original}))

	// Start consumer
	require.NoError(t, consumer.Start(ctx))

	require.Eventually(t, func() bool {
		return len(router.getEvents()) >= 1
	}, 5*time.Second, 50*time.Millisecond)

	require.NoError(t, consumer.Shutdown(ctx))

	routed := router.getEvents()
	require.Len(t, routed, 1)

	// Verify field preservation through Redis round-trip
	ev := routed[0]
	assert.Equal(t, original.ID, ev.ID)
	assert.Equal(t, original.UserID.String(), ev.UserID.String())
	assert.Equal(t, "user.login", ev.Action)
	assert.Equal(t, "session", ev.ResourceType)
	assert.Equal(t, OutcomeSuccess, ev.Outcome)
	assert.Equal(t, "chrome", ev.ContextData["browser"])
	assert.Equal(t, original.IPAddress, ev.IPAddress)
	assert.Equal(t, original.UserAgent, ev.UserAgent)

	// Verify the consumer passes AuditEvent (not FinalAuditEvent) to router
	// by checking the event is not wrapped
	raw, _ := json.Marshal(ev)
	var check map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &check))
	_, hasEnrichedAt := check["enriched_at"]
	assert.False(t, hasEnrichedAt, "router receives AuditEvent, not FinalAuditEvent")
}
