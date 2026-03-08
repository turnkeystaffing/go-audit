package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgredis "github.com/turnkeystaffing/go-redis"
)

// mockAuditLogger implements AuditLogger for tests.
type mockAuditLogger struct {
	mu     sync.Mutex
	events []*AuditEvent
	logErr error // if set, Log() returns this error
}

func (m *mockAuditLogger) Log(_ context.Context, event *AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.logErr != nil {
		return m.logErr
	}
	m.events = append(m.events, event)
	return nil
}

func (m *mockAuditLogger) LogCritical(_ context.Context, event *AuditEvent) error {
	return m.Log(context.Background(), event)
}

func (m *mockAuditLogger) getEvents() []*AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*AuditEvent, len(m.events))
	copy(result, m.events)
	return result
}

// syncBuffer is a thread-safe bytes.Buffer for use with slog in concurrent tests.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *syncBuffer) Write(p []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Write(p)
}

func (sb *syncBuffer) String() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.String()
}

// bufTestLogger creates a slog.Logger that writes to a syncBuffer for assertions.
// Named differently from testLogger() in http_writer_test.go (same package).
func bufTestLogger(buf *syncBuffer) *slog.Logger {
	var w io.Writer = buf
	if buf == nil {
		w = io.Discard
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func defaultTestConfig() RedisQueueConsumerConfig {
	return RedisQueueConsumerConfig{
		QueueKey:     "test:queue",
		BRPOPTimeout: 50 * time.Millisecond,
	}
}

func pushEvent(t *testing.T, client *pkgredis.MockRedisClient, key string, event *AuditEvent) {
	t.Helper()
	finalEvent := FinalAuditEvent{
		AuditEvent: *event,
		EnrichedAt: time.Now(),
	}
	data, err := json.Marshal(finalEvent)
	require.NoError(t, err)
	_, err = client.LPush(context.Background(), key, string(data))
	require.NoError(t, err)
}

func TestNewRedisQueueConsumer_NilRedisClient_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "NewRedisQueueConsumer: redisClient cannot be nil", func() {
		NewRedisQueueConsumer(defaultTestConfig(), nil, &mockAuditLogger{}, bufTestLogger(nil))
	})
}

func TestNewRedisQueueConsumer_NilRouter_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "NewRedisQueueConsumer: router cannot be nil", func() {
		NewRedisQueueConsumer(defaultTestConfig(), pkgredis.NewMockRedisClient(), nil, bufTestLogger(nil))
	})
}

func TestNewRedisQueueConsumer_NilLogger_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "NewRedisQueueConsumer: log cannot be nil", func() {
		NewRedisQueueConsumer(defaultTestConfig(), pkgredis.NewMockRedisClient(), &mockAuditLogger{}, nil)
	})
}

func TestRedisQueueConsumer_StartShutdown_HappyPath(t *testing.T) {
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(nil))

	ctx := context.Background()
	err := consumer.Start(ctx)
	require.NoError(t, err)

	err = consumer.Shutdown(ctx)
	require.NoError(t, err)
}

func TestRedisQueueConsumer_DoubleStart_ReturnsError(t *testing.T) {
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(nil))

	ctx := context.Background()
	err := consumer.Start(ctx)
	require.NoError(t, err)
	defer consumer.Shutdown(ctx) //nolint:errcheck

	err = consumer.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

func TestRedisQueueConsumer_DoubleShutdown_Idempotent(t *testing.T) {
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(nil))

	ctx := context.Background()
	err := consumer.Start(ctx)
	require.NoError(t, err)

	err = consumer.Shutdown(ctx)
	require.NoError(t, err)

	// Second shutdown should be idempotent — no panic from double close(stopCh)
	err = consumer.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestRedisQueueConsumer_DrainOne_ValidEvent(t *testing.T) {
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(nil))

	event := &AuditEvent{
		Action:       "test.action",
		ResourceType: "test.resource",
	}
	pushEvent(t, client, "test:queue", event)

	ctx := context.Background()
	err := consumer.Start(ctx)
	require.NoError(t, err)

	// Wait for the consumer to drain the event
	require.Eventually(t, func() bool {
		return len(router.getEvents()) >= 1
	}, 2*time.Second, 10*time.Millisecond)

	consumer.Shutdown(ctx) //nolint:errcheck

	events := router.getEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "test.action", events[0].Action)
	assert.Equal(t, "test.resource", events[0].ResourceType)
}

func TestRedisQueueConsumer_DrainOne_MalformedJSON(t *testing.T) {
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	logBuf := &syncBuffer{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(logBuf))

	// Push invalid JSON
	_, err := client.LPush(context.Background(), "test:queue", "not-valid-json{{{")
	require.NoError(t, err)

	ctx := context.Background()
	err = consumer.Start(ctx)
	require.NoError(t, err)

	// Wait for the consumer to process (and skip) the malformed event
	require.Eventually(t, func() bool {
		return logBuf.String() != "" && len(client.GetListData("test:queue")) == 0
	}, 2*time.Second, 10*time.Millisecond)

	consumer.Shutdown(ctx) //nolint:errcheck

	// No events routed — malformed was skipped
	assert.Empty(t, router.getEvents())
	// Error was logged
	assert.Contains(t, logBuf.String(), "malformed event")
}

func TestRedisQueueConsumer_DrainOne_BRPopTimeout(t *testing.T) {
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	logBuf := &syncBuffer{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(logBuf))

	ctx := context.Background()
	err := consumer.Start(ctx)
	require.NoError(t, err)

	// Assert no "brpop error" log appears over 150ms of empty-queue BRPOP cycles.
	// Uses require.Never instead of time.Sleep per project test rules.
	require.Never(t, func() bool {
		return strings.Contains(logBuf.String(), "brpop error")
	}, 150*time.Millisecond, 10*time.Millisecond)

	consumer.Shutdown(ctx) //nolint:errcheck

	// No events routed
	assert.Empty(t, router.getEvents())
}

func TestRedisQueueConsumer_DrainOne_RouterLogError(t *testing.T) {
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{logErr: errors.New("router failure")}
	logBuf := &syncBuffer{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(logBuf))

	event := &AuditEvent{Action: "test.action", ResourceType: "test.resource"}
	pushEvent(t, client, "test:queue", event)

	ctx := context.Background()
	err := consumer.Start(ctx)
	require.NoError(t, err)

	// Wait for the consumer to process the event
	require.Eventually(t, func() bool {
		return logBuf.String() != "" && len(client.GetListData("test:queue")) == 0
	}, 2*time.Second, 10*time.Millisecond)

	consumer.Shutdown(ctx) //nolint:errcheck

	assert.Contains(t, logBuf.String(), "failed to route event")
}

func TestRedisQueueConsumer_ContextCancellation(t *testing.T) {
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(nil))

	ctx, cancel := context.WithCancel(context.Background())
	err := consumer.Start(ctx)
	require.NoError(t, err)

	// Cancel context — consumer should exit
	cancel()

	// Consumer should stop within a reasonable time
	require.Eventually(t, func() bool {
		// After context cancellation, Shutdown should be a no-op or succeed quickly
		return consumer.Shutdown(context.Background()) == nil
	}, 2*time.Second, 10*time.Millisecond)
}

func TestRedisQueueConsumer_ShutdownInterruptsBRPOP(t *testing.T) {
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(nil))

	ctx := context.Background()
	err := consumer.Start(ctx)
	require.NoError(t, err)

	start := time.Now()
	err = consumer.Shutdown(ctx)
	require.NoError(t, err)
	elapsed := time.Since(start)

	// Shutdown should complete within a reasonable time (BRPOP timeout + margin)
	assert.Less(t, elapsed, 5*time.Second)
}

func TestRedisQueueConsumer_PanicRecovery(t *testing.T) {
	client := pkgredis.NewMockRedisClient()
	logBuf := &syncBuffer{}

	// Create a router that panics
	panicRouter := &panicAuditLogger{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, panicRouter, bufTestLogger(logBuf))

	event := &AuditEvent{Action: "panic.trigger", ResourceType: "test"}
	pushEvent(t, client, "test:queue", event)

	ctx := context.Background()
	err := consumer.Start(ctx)
	require.NoError(t, err)

	// Wait specifically for the panic log — not just any log content, since
	// Start() itself writes to the buffer. The goroutine panics during drainOne
	// when panicAuditLogger.Log() is called, then defer recovery writes the panic log.
	require.Eventually(t, func() bool {
		return strings.Contains(logBuf.String(), "goroutine panicked")
	}, 2*time.Second, 10*time.Millisecond)

	consumer.Shutdown(ctx) //nolint:errcheck

	assert.Contains(t, logBuf.String(), "goroutine panicked")
	assert.Contains(t, logBuf.String(), "stack")
}

type panicAuditLogger struct{}

func (p *panicAuditLogger) Log(_ context.Context, _ *AuditEvent) error {
	panic("intentional panic in router")
}

func (p *panicAuditLogger) LogCritical(_ context.Context, _ *AuditEvent) error {
	panic("intentional panic in router")
}

func TestRedisQueueConsumer_RedisErrorBackoff(t *testing.T) {
	router := &mockAuditLogger{}
	logBuf := &syncBuffer{}

	// Create a mock that returns errors on BRPop
	errorClient := &brpopErrorClient{
		MockRedisClient: pkgredis.NewMockRedisClient(),
		brpopErr:        errors.New("connection refused"),
		callCount:       &atomic.Int32{},
	}

	consumer := NewRedisQueueConsumer(defaultTestConfig(), errorClient, router, bufTestLogger(logBuf))

	ctx := context.Background()
	err := consumer.Start(ctx)
	require.NoError(t, err)

	// Let it run — with backoff, it should NOT spin rapidly
	time.Sleep(300 * time.Millisecond)

	consumer.Shutdown(ctx) //nolint:errcheck

	// With exponential backoff (1s, 2s, 4s...), in 300ms we should have very few calls
	calls := errorClient.callCount.Load()
	assert.Less(t, calls, int32(10), "expected backoff to limit call rate, got %d calls", calls)

	assert.Contains(t, logBuf.String(), "brpop error")
	assert.Contains(t, logBuf.String(), "backing off")
}

func TestRedisQueueConsumer_BackoffResets_OnSuccess(t *testing.T) {
	router := &mockAuditLogger{}
	client := pkgredis.NewMockRedisClient()

	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(nil))

	// Push an event — success should reset the backoff counter
	event := &AuditEvent{Action: "test.success", ResourceType: "test"}
	pushEvent(t, client, "test:queue", event)

	ctx := context.Background()
	err := consumer.Start(ctx)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return len(router.getEvents()) >= 1
	}, 2*time.Second, 10*time.Millisecond)

	consumer.Shutdown(ctx) //nolint:errcheck

	assert.Len(t, router.getEvents(), 1)
}

func TestRedisQueueConsumer_ConfigValidation(t *testing.T) {
	cfg := RedisQueueConsumerConfig{BRPOPTimeout: -1}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must not be negative")
}

func TestRedisQueueConsumer_ConfigDefaults(t *testing.T) {
	cfg := DefaultRedisQueueConsumerConfig()
	assert.Equal(t, "audit:fallback:queue", cfg.QueueKey)
	assert.Equal(t, 2*time.Second, cfg.BRPOPTimeout)

	// Validate should pass on default config
	require.NoError(t, cfg.Validate())
}

func TestRedisQueueConsumer_MultipleEvents_FIFO(t *testing.T) {
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(nil))

	// Push events in order: A, B, C
	for _, action := range []string{"A", "B", "C"} {
		pushEvent(t, client, "test:queue", &AuditEvent{
			Action:       action,
			ResourceType: "test",
		})
	}

	ctx := context.Background()
	err := consumer.Start(ctx)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return len(router.getEvents()) >= 3
	}, 2*time.Second, 10*time.Millisecond)

	consumer.Shutdown(ctx) //nolint:errcheck

	events := router.getEvents()
	require.Len(t, events, 3)
	// LPUSH+BRPOP = FIFO: A first, then B, then C
	assert.Equal(t, "A", events[0].Action)
	assert.Equal(t, "B", events[1].Action)
	assert.Equal(t, "C", events[2].Action)
}

// brpopErrorClient wraps MockRedisClient but overrides BRPop to return errors.
type brpopErrorClient struct {
	*pkgredis.MockRedisClient
	brpopErr  error
	callCount *atomic.Int32
}

func (c *brpopErrorClient) BRPop(ctx context.Context, timeout time.Duration, keys ...string) ([]string, error) {
	c.callCount.Add(1)
	if c.brpopErr != nil {
		return nil, c.brpopErr
	}
	return c.MockRedisClient.BRPop(ctx, timeout, keys...)
}

// Ensure brpopErrorClient satisfies RedisClient
var _ pkgredis.RedisClient = (*brpopErrorClient)(nil)

// Ensure mockAuditLogger satisfies AuditLogger
var _ AuditLogger = (*mockAuditLogger)(nil)

func TestRedisQueueConsumer_ShutdownWithoutStart(t *testing.T) {
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(nil))

	// Shutdown without Start should be a no-op (idempotent)
	err := consumer.Shutdown(context.Background())
	assert.NoError(t, err)
}

func TestRedisQueueConsumer_InvalidConfig_Panics(t *testing.T) {
	assert.Panics(t, func() {
		NewRedisQueueConsumer(
			RedisQueueConsumerConfig{BRPOPTimeout: -1},
			pkgredis.NewMockRedisClient(),
			&mockAuditLogger{},
			bufTestLogger(nil),
		)
	})
}

func TestRedisQueueConsumer_DrainOne_ShortResult(t *testing.T) {
	// Test the len(result) < 2 guard
	client := &shortResultClient{
		MockRedisClient: pkgredis.NewMockRedisClient(),
	}
	router := &mockAuditLogger{}
	logBuf := &syncBuffer{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(logBuf))

	ctx := context.Background()
	err := consumer.drainOne(ctx)
	require.NoError(t, err)

	assert.Contains(t, logBuf.String(), "unexpected brpop result length")
}

type shortResultClient struct {
	*pkgredis.MockRedisClient
}

func (c *shortResultClient) BRPop(ctx context.Context, timeout time.Duration, keys ...string) ([]string, error) {
	return []string{"only-key"}, nil
}

var _ pkgredis.RedisClient = (*shortResultClient)(nil)

func TestRedisQueueConsumer_DrainOne_ContextCancelled(t *testing.T) {
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(nil))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Pre-cancel

	err := consumer.drainOne(ctx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestRedisQueueConsumer_DrainOne_OversizedEvent(t *testing.T) {
	// Events exceeding 1MB should be rejected before json.Unmarshal (OOM prevention)
	oversizedPayload := strings.Repeat("x", 1<<20+1) // 1MB + 1 byte
	client := &oversizedResultClient{
		MockRedisClient: pkgredis.NewMockRedisClient(),
		payload:         oversizedPayload,
	}
	router := &mockAuditLogger{}
	logBuf := &syncBuffer{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(logBuf))

	err := consumer.drainOne(context.Background())
	require.NoError(t, err)

	assert.Contains(t, logBuf.String(), "event exceeds size limit")
	assert.Empty(t, router.getEvents(), "oversized event should be skipped")
}

type oversizedResultClient struct {
	*pkgredis.MockRedisClient
	payload string
}

func (c *oversizedResultClient) BRPop(_ context.Context, _ time.Duration, keys ...string) ([]string, error) {
	return []string{keys[0], c.payload}, nil
}

var _ pkgredis.RedisClient = (*oversizedResultClient)(nil)

func TestRedisQueueConsumer_DrainOne_EmptyBRPopResult(t *testing.T) {
	// BRPop returns empty slice — should log warning, not panic
	client := &emptyResultClient{
		MockRedisClient: pkgredis.NewMockRedisClient(),
	}
	router := &mockAuditLogger{}
	logBuf := &syncBuffer{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(logBuf))

	err := consumer.drainOne(context.Background())
	require.NoError(t, err)

	assert.Contains(t, logBuf.String(), "unexpected brpop result length")
	assert.Empty(t, router.getEvents())
}

type emptyResultClient struct {
	*pkgredis.MockRedisClient
}

func (c *emptyResultClient) BRPop(_ context.Context, _ time.Duration, _ ...string) ([]string, error) {
	return []string{}, nil
}

var _ pkgredis.RedisClient = (*emptyResultClient)(nil)

func TestRedisQueueConsumer_DrainOne_ValidJSONWrongStructure(t *testing.T) {
	// Valid JSON but wrong structure (array instead of object) — json.Unmarshal
	// into a struct returns an error, so this is treated as malformed and skipped.
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	logBuf := &syncBuffer{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(logBuf))

	// Push valid JSON that can't unmarshal into FinalAuditEvent
	_, err := client.LPush(context.Background(), "test:queue", `["not","an","object"]`)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, consumer.Start(ctx))

	require.Eventually(t, func() bool {
		return len(client.GetListData("test:queue")) == 0
	}, 2*time.Second, 10*time.Millisecond)

	consumer.Shutdown(ctx) //nolint:errcheck

	// Array-into-struct unmarshal error → logged and skipped, no event routed
	assert.Empty(t, router.getEvents(), "wrong-structure JSON should be skipped")
	assert.Contains(t, logBuf.String(), "malformed event")
}

func TestRedisQueueConsumer_GoroutineActuallyRuns(t *testing.T) {
	// Verify that after Start(), the goroutine is executing by observing
	// it drain an event within a bounded time.
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(nil))

	event := &AuditEvent{Action: "goroutine.proof", ResourceType: "test"}
	pushEvent(t, client, "test:queue", event)

	ctx := context.Background()
	require.NoError(t, consumer.Start(ctx))

	// If goroutine wasn't running, this would timeout
	require.Eventually(t, func() bool {
		return len(router.getEvents()) >= 1
	}, 2*time.Second, 10*time.Millisecond, "goroutine must be running to drain event")

	consumer.Shutdown(ctx) //nolint:errcheck

	events := router.getEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "goroutine.proof", events[0].Action)
}

func TestRedisQueueConsumer_ContextDeadlineExceeded(t *testing.T) {
	// Verify context.DeadlineExceeded is handled without spurious WARN log
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	logBuf := &syncBuffer{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(logBuf))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	require.NoError(t, consumer.Start(ctx))

	// Wait for deadline to expire and consumer to exit
	require.Eventually(t, func() bool {
		return consumer.Shutdown(context.Background()) == nil
	}, 2*time.Second, 10*time.Millisecond)

	// Should NOT contain backoff warning — deadline is handled cleanly
	assert.NotContains(t, logBuf.String(), "brpop error, backing off")
}

func TestRedisQueueConsumer_StartShutdownStart_Cycle(t *testing.T) {
	// Verify consumer cannot be restarted after Shutdown — running flag
	// is cleared by Shutdown, but channels are closed. A new Start must
	// create fresh channels.
	client := pkgredis.NewMockRedisClient()
	router := &mockAuditLogger{}
	consumer := NewRedisQueueConsumer(defaultTestConfig(), client, router, bufTestLogger(nil))

	ctx := context.Background()

	// First cycle
	require.NoError(t, consumer.Start(ctx))
	require.NoError(t, consumer.Shutdown(ctx))

	// Second cycle — Start should create new channels and work
	require.NoError(t, consumer.Start(ctx))

	// Push event to verify second cycle is functional
	pushEvent(t, client, "test:queue", &AuditEvent{Action: "cycle2", ResourceType: "test"})

	require.Eventually(t, func() bool {
		return len(router.getEvents()) >= 1
	}, 2*time.Second, 10*time.Millisecond)

	require.NoError(t, consumer.Shutdown(ctx))

	events := router.getEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "cycle2", events[0].Action)
}
