//go:build integration

package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgredis "github.com/turnkeystaffing/go-redis"
)

// setupRedisWriter creates a RedisQueueWriter backed by a real Redis testcontainer.
// Uses a unique prefix per test to avoid key collisions.
func setupRedisWriter(t *testing.T) (*RedisQueueWriter, pkgredis.RedisClient) {
	t.Helper()

	rawClient := redis.NewClient(&redis.Options{
		Addr: sharedRedisAddr,
	})
	require.NoError(t, rawClient.Ping(context.Background()).Err(), "Redis container should be reachable")

	prefix := "test:" + uuid.New().String()[:8] + ":"
	client := pkgredis.NewPrefixedClient(rawClient, prefix)

	t.Cleanup(func() { _ = client.Close() })

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	w, err := NewRedisQueueWriter(DefaultRedisQueueWriterConfig(), client, log)
	require.NoError(t, err)

	return w, client
}

func TestRedisQueueWriter_Integration_RoundTrip(t *testing.T) {
	w, client := setupRedisWriter(t)
	ctx := context.Background()

	// Create events with known data
	events := make([]FinalAuditEvent, 3)
	for i := range events {
		events[i] = createTestFinalEvent()
		events[i].ContextData["seq"] = float64(i)
	}

	// Push via WriteBatch
	err := w.WriteBatch(ctx, events)
	require.NoError(t, err)

	// Verify queue length via LLen
	queueLen, err := client.LLen(ctx, "audit:fallback:queue")
	require.NoError(t, err)
	assert.Equal(t, int64(3), queueLen, "3 events in queue")

	// Pop all via RPOP (FIFO: LPUSH + RPOP = queue semantics)
	// RPOP from the prefixed key — we need the raw client for RPOP
	// since RedisClient interface doesn't expose it (it's consumer-side, Story 2-6).
	// NOTE: fullKey couples to PrefixedClient.GetPrefix() internals — this is acceptable
	// because the service-side consumer (Story 2-6) must know the full key to BRPOP.
	fullKey := client.GetPrefix() + "audit:fallback:queue"
	rawAddr := sharedRedisAddr
	rawClient := redis.NewClient(&redis.Options{Addr: rawAddr})
	defer rawClient.Close()

	for i := 0; i < 3; i++ {
		raw, err := rawClient.RPop(ctx, fullKey).Result()
		require.NoError(t, err)

		var decoded FinalAuditEvent
		require.NoError(t, json.Unmarshal([]byte(raw), &decoded))

		// LPUSH prepends; RPOP pops from tail → FIFO: first event out first
		assert.Equal(t, events[i].ID, decoded.ID, "event %d round-trip ID", i)
		assert.Equal(t, events[i].Action, decoded.Action, "event %d action", i)
		assert.Equal(t, events[i].Outcome, decoded.Outcome, "event %d outcome", i)
		assert.Equal(t, float64(i), decoded.ContextData["seq"], "event %d seq", i)
		assert.NotNil(t, decoded.UserID, "event %d user ID preserved", i)
		assert.Equal(t, events[i].UserID.String(), decoded.UserID.String(), "event %d user ID value", i)
	}
}

func TestRedisQueueWriter_Integration_LargeEventBatch(t *testing.T) {
	w, client := setupRedisWriter(t)
	ctx := context.Background()

	const batchSize = 100
	events := make([]FinalAuditEvent, batchSize)
	for i := range events {
		events[i] = createTestFinalEvent()
		events[i].ContextData["idx"] = float64(i)
	}

	err := w.WriteBatch(ctx, events)
	require.NoError(t, err)

	// Verify LLen
	queueLen, err := client.LLen(ctx, "audit:fallback:queue")
	require.NoError(t, err)
	assert.Equal(t, int64(batchSize), queueLen, "all 100 events in queue")

	// Pop all and verify count (see RoundTrip test for key coupling note)
	fullKey := client.GetPrefix() + "audit:fallback:queue"
	rawClient := redis.NewClient(&redis.Options{Addr: sharedRedisAddr})
	defer rawClient.Close()

	for i := 0; i < batchSize; i++ {
		raw, err := rawClient.RPop(ctx, fullKey).Result()
		require.NoError(t, err, "RPOP event %d", i)

		var decoded FinalAuditEvent
		require.NoError(t, json.Unmarshal([]byte(raw), &decoded))
		assert.Equal(t, float64(i), decoded.ContextData["idx"], "event %d order preserved", i)
	}

	// Queue should be empty
	queueLen, err = client.LLen(ctx, "audit:fallback:queue")
	require.NoError(t, err)
	assert.Equal(t, int64(0), queueLen, "queue drained")
}

func TestRedisQueueWriter_Integration_Health(t *testing.T) {
	w, _ := setupRedisWriter(t)

	err := w.Health(context.Background())
	require.NoError(t, err, "health check against real Redis should pass")
}
