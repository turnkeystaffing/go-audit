package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	pkgredis "github.com/turnkeystaffing/go-redis"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errRedis is a sentinel error for simulating Redis failures in tests.
var errRedis = errors.New("redis: connection refused")

// mockRedisClientWithErrors wraps MockRedisClient to inject errors for specific operations.
type mockRedisClientWithErrors struct {
	*pkgredis.MockRedisClient
	mu        sync.Mutex
	lpushErr  error
	llenErr   error
	pingErr   error
	expireErr error
	lpushCnt  int
}

func newMockRedisWithErrors() *mockRedisClientWithErrors {
	return &mockRedisClientWithErrors{
		MockRedisClient: pkgredis.NewMockRedisClient(),
	}
}

func (m *mockRedisClientWithErrors) LPush(ctx context.Context, key string, values ...interface{}) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lpushCnt++
	if m.lpushErr != nil {
		return 0, m.lpushErr
	}
	return m.MockRedisClient.LPush(ctx, key, values...)
}

func (m *mockRedisClientWithErrors) Ping(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pingErr != nil {
		return m.pingErr
	}
	return m.MockRedisClient.Ping(ctx)
}

func (m *mockRedisClientWithErrors) LLen(ctx context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.llenErr != nil {
		return 0, m.llenErr
	}
	return m.MockRedisClient.LLen(ctx, key)
}

func (m *mockRedisClientWithErrors) Expire(ctx context.Context, key string, expiration time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.expireErr != nil {
		return false, m.expireErr
	}
	return m.MockRedisClient.Expire(ctx, key, expiration)
}

func (m *mockRedisClientWithErrors) setExpireErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireErr = err
}

func (m *mockRedisClientWithErrors) setLLenErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.llenErr = err
}

func (m *mockRedisClientWithErrors) setLPushErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lpushErr = err
}

func (m *mockRedisClientWithErrors) setPingErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pingErr = err
}

func (m *mockRedisClientWithErrors) getLPushCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lpushCnt
}

func (m *mockRedisClientWithErrors) resetLPushCount() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lpushCnt = 0
}

// createTestFinalEvent creates a FinalAuditEvent for testing.
func createTestFinalEvent() FinalAuditEvent {
	userID := uuid.New()
	return FinalAuditEvent{
		AuditEvent: AuditEvent{
			ID:           uuid.Must(uuid.NewV7()),
			UserID:       &userID,
			Action:       testActionLogin,
			ResourceType: testResourceTypeSession,
			Outcome:      OutcomeSuccess,
			Timestamp:    time.Now().UTC(),
			IPAddress:    strPtr("192.168.1.100"),
			UserAgent:    "Mozilla/5.0",
			RequestID:    uuid.New(),
			ContextData:  map[string]interface{}{"test": "value"},
		},
		EnrichmentMetadata: map[string]interface{}{"enricher": "test"},
		EnrichedAt:         time.Now().UTC(),
	}
}

func newTestWriter(t *testing.T, redis pkgredis.RedisClient) *RedisQueueWriter {
	t.Helper()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	w, err := NewRedisQueueWriter(DefaultRedisQueueWriterConfig(), redis, log)
	require.NoError(t, err)
	return w
}

// --- WriteBatch tests ---

func TestRedisQueueWriter_WriteBatch_Success(t *testing.T) {
	mock := newMockRedisWithErrors()
	w := newTestWriter(t, mock)

	events := []FinalAuditEvent{createTestFinalEvent(), createTestFinalEvent()}
	err := w.WriteBatch(context.Background(), events)

	require.NoError(t, err)
	assert.Equal(t, 1, mock.getLPushCount(), "single LPUSH call for the batch")

	// Verify events are in the list
	list := mock.GetListData("audit:fallback:queue")
	require.Len(t, list, 2, "both events should be in the queue")

	// Verify JSON deserialization round-trip
	var decoded FinalAuditEvent
	require.NoError(t, json.Unmarshal([]byte(list[0]), &decoded))
	assert.Equal(t, events[1].ID, decoded.ID, "LPUSH prepends — last pushed is first")
}

func TestRedisQueueWriter_WriteBatch_EmptyBatch(t *testing.T) {
	mock := newMockRedisWithErrors()
	w := newTestWriter(t, mock)

	err := w.WriteBatch(context.Background(), nil)

	require.NoError(t, err)
	assert.Equal(t, 0, mock.getLPushCount(), "no LPUSH for empty batch")

	err = w.WriteBatch(context.Background(), []FinalAuditEvent{})
	require.NoError(t, err)
	assert.Equal(t, 0, mock.getLPushCount(), "no LPUSH for zero-length batch")
}

func TestRedisQueueWriter_WriteBatch_RedisError(t *testing.T) {
	mock := newMockRedisWithErrors()
	mock.setLPushErr(errRedis)
	w := newTestWriter(t, mock)

	events := []FinalAuditEvent{createTestFinalEvent()}
	err := w.WriteBatch(context.Background(), events)

	require.Error(t, err)
	assert.ErrorIs(t, err, errRedis)
	assert.Contains(t, err.Error(), "redis queue writer: LPUSH failed")
}

func TestRedisQueueWriter_WriteBatch_ContextCancellation(t *testing.T) {
	mock := newMockRedisWithErrors()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	w := newTestWriter(t, mock)
	events := []FinalAuditEvent{createTestFinalEvent()}
	err := w.WriteBatch(ctx, events)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled, "should return context.Canceled on pre-cancelled context")
	assert.Equal(t, 0, mock.getLPushCount(), "LPUSH should not be called on cancelled context")
}

func TestRedisQueueWriter_WriteBatch_Serialization(t *testing.T) {
	mock := newMockRedisWithErrors()
	w := newTestWriter(t, mock)

	event := createTestFinalEvent()
	event.ContextData = map[string]interface{}{
		"string_val": "hello",
		"int_val":    float64(42), // JSON numbers are float64
		"bool_val":   true,
	}
	event.FailureReason = "test-reason"

	err := w.WriteBatch(context.Background(), []FinalAuditEvent{event})
	require.NoError(t, err)

	list := mock.GetListData("audit:fallback:queue")
	require.Len(t, list, 1)

	var decoded FinalAuditEvent
	require.NoError(t, json.Unmarshal([]byte(list[0]), &decoded))

	assert.Equal(t, event.ID, decoded.ID)
	assert.Equal(t, event.Action, decoded.Action)
	assert.Equal(t, event.Outcome, decoded.Outcome)
	assert.Equal(t, event.FailureReason, decoded.FailureReason)
	assert.Equal(t, event.ResourceType, decoded.ResourceType)
	assert.WithinDuration(t, event.Timestamp, decoded.Timestamp, time.Second)
	assert.Equal(t, event.ContextData["string_val"], decoded.ContextData["string_val"])
	assert.Equal(t, event.ContextData["int_val"], decoded.ContextData["int_val"])
	assert.Equal(t, event.ContextData["bool_val"], decoded.ContextData["bool_val"])
	assert.Equal(t, event.EnrichmentMetadata["enricher"], decoded.EnrichmentMetadata["enricher"])
}

func TestRedisQueueWriter_WriteBatch_MultipleBatches(t *testing.T) {
	mock := newMockRedisWithErrors()
	w := newTestWriter(t, mock)

	batch1 := []FinalAuditEvent{createTestFinalEvent()}
	batch2 := []FinalAuditEvent{createTestFinalEvent(), createTestFinalEvent()}

	require.NoError(t, w.WriteBatch(context.Background(), batch1))
	require.NoError(t, w.WriteBatch(context.Background(), batch2))

	assert.Equal(t, 2, mock.getLPushCount(), "LPUSH called twice")

	list := mock.GetListData("audit:fallback:queue")
	assert.Len(t, list, 3, "all 3 events across both batches")
}

// --- Health tests ---

func TestRedisQueueWriter_Health_Success(t *testing.T) {
	mock := newMockRedisWithErrors()
	w := newTestWriter(t, mock)

	err := w.Health(context.Background())
	require.NoError(t, err)
}

func TestRedisQueueWriter_Health_Failure(t *testing.T) {
	mock := newMockRedisWithErrors()
	mock.setPingErr(errRedis)
	w := newTestWriter(t, mock)

	err := w.Health(context.Background())
	require.ErrorIs(t, err, errRedis)
}

func TestRedisQueueWriter_Health_Cache(t *testing.T) {
	mock := newMockRedisWithErrors()
	w := newTestWriter(t, mock)

	// First call — hits Redis
	require.NoError(t, w.Health(context.Background()))

	// Inject error AFTER first health check
	mock.setPingErr(errRedis)

	// Second call within 30s — returns cached nil (success)
	require.NoError(t, w.Health(context.Background()), "should return cached result")
}

func TestRedisQueueWriter_Health_CacheInvalidation(t *testing.T) {
	mock := newMockRedisWithErrors()
	w := newTestWriter(t, mock)

	// Prime cache with success
	require.NoError(t, w.Health(context.Background()))

	// Force LPUSH failure — this invalidates health cache
	mock.setLPushErr(errRedis)
	_ = w.WriteBatch(context.Background(), []FinalAuditEvent{createTestFinalEvent()})

	// Now inject ping error — should be detected since cache was invalidated
	mock.setPingErr(errRedis)
	err := w.Health(context.Background())
	require.ErrorIs(t, err, errRedis, "cache should be invalidated after WriteBatch error")
}

// --- Constructor tests ---

func TestNewRedisQueueWriter_NilLogger_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "audit: logger is required", func() {
		NewRedisQueueWriter(DefaultRedisQueueWriterConfig(), pkgredis.NewMockRedisClient(), nil)
	})
}

func TestNewRedisQueueWriter_NilRedisClient_Panics(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	assert.PanicsWithValue(t, "audit: redis client is required", func() {
		NewRedisQueueWriter(DefaultRedisQueueWriterConfig(), nil, log)
	})
}

func TestNewRedisQueueWriter_DefaultConfig(t *testing.T) {
	mock := pkgredis.NewMockRedisClient()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	w, err := NewRedisQueueWriter(RedisQueueWriterConfig{}, mock, log)
	require.NoError(t, err)
	assert.Equal(t, "audit:fallback:queue", w.queueKey, "empty QueueKey should default")
	assert.Equal(t, 7*24*time.Hour, w.queueTTL, "zero QueueTTL should default to 7 days")
}

// --- Name and Shutdown tests ---

func TestRedisQueueWriter_Name(t *testing.T) {
	mock := pkgredis.NewMockRedisClient()
	w := newTestWriter(t, mock)
	assert.Equal(t, "redis-queue", w.Name())
}

func TestRedisQueueWriter_Shutdown(t *testing.T) {
	mock := pkgredis.NewMockRedisClient()
	w := newTestWriter(t, mock)

	err := w.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestRedisQueueWriter_WriteBatch_AfterShutdown(t *testing.T) {
	mock := newMockRedisWithErrors()
	w := newTestWriter(t, mock)

	// Shutdown first
	require.NoError(t, w.Shutdown(context.Background()))

	// WriteBatch should still work — AC5 reusability contract
	events := []FinalAuditEvent{createTestFinalEvent()}
	err := w.WriteBatch(context.Background(), events)
	require.NoError(t, err, "writer must be reusable after Shutdown per AC5")
	assert.Equal(t, 1, mock.getLPushCount(), "LPUSH should succeed after Shutdown")
}

// --- Concurrent WriteBatch ---

func TestRedisQueueWriter_Concurrent_WriteBatch(t *testing.T) {
	mock := newMockRedisWithErrors()
	w := newTestWriter(t, mock)

	var wg sync.WaitGroup
	errs := make([]error, 50)

	for i := 0; i < 10; i++ {
		for j := 0; j < 5; j++ {
			idx := i*5 + j
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				events := []FinalAuditEvent{createTestFinalEvent()}
				errs[idx] = w.WriteBatch(context.Background(), events)
			}(idx)
		}
	}

	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, fmt.Sprintf("goroutine %d should succeed", i))
	}
	assert.Equal(t, 50, mock.getLPushCount(), "all 50 LPUSH calls completed")
}

// --- MaxQueueSize tests ---

func TestRedisQueueWriter_WriteBatch_QueueFull(t *testing.T) {
	mock := newMockRedisWithErrors()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := RedisQueueWriterConfig{QueueKey: "audit:fallback:queue", MaxQueueSize: 5}
	w, err := NewRedisQueueWriter(cfg, mock, log)
	require.NoError(t, err)

	// Fill queue to capacity
	for i := 0; i < 5; i++ {
		require.NoError(t, w.WriteBatch(context.Background(), []FinalAuditEvent{createTestFinalEvent()}))
	}

	// Next push should be rejected — queue is at 5/5, adding 1 would exceed
	err = w.WriteBatch(context.Background(), []FinalAuditEvent{createTestFinalEvent()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "queue capacity exceeded")
}

func TestRedisQueueWriter_WriteBatch_QueueUnlimited(t *testing.T) {
	mock := newMockRedisWithErrors()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := RedisQueueWriterConfig{QueueKey: "audit:fallback:queue", MaxQueueSize: 0}
	w, err := NewRedisQueueWriter(cfg, mock, log)
	require.NoError(t, err)

	// Should always succeed with unlimited queue
	for i := 0; i < 20; i++ {
		require.NoError(t, w.WriteBatch(context.Background(), []FinalAuditEvent{createTestFinalEvent()}))
	}
	assert.Equal(t, 20, mock.getLPushCount())
}

// --- LLen error path (warn-and-proceed) ---

func TestRedisQueueWriter_WriteBatch_LLenError_ProceedsWithLPush(t *testing.T) {
	mock := newMockRedisWithErrors()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := RedisQueueWriterConfig{QueueKey: "audit:fallback:queue", MaxQueueSize: 100}
	w, err := NewRedisQueueWriter(cfg, mock, log)
	require.NoError(t, err)

	// Inject LLen error — should warn but still proceed with LPUSH
	mock.setLLenErr(errRedis)

	events := []FinalAuditEvent{createTestFinalEvent()}
	err = w.WriteBatch(context.Background(), events)

	require.NoError(t, err, "LLen failure should not block LPUSH")
	assert.Equal(t, 1, mock.getLPushCount(), "LPUSH should proceed despite LLen error")

	list := mock.GetListData("audit:fallback:queue")
	assert.Len(t, list, 1, "event should be in the queue")
}

// --- Custom queue key ---

func TestRedisQueueWriter_WriteBatch_CustomQueueKey(t *testing.T) {
	mock := newMockRedisWithErrors()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := RedisQueueWriterConfig{QueueKey: "my:custom:queue"}
	w, err := NewRedisQueueWriter(cfg, mock, log)
	require.NoError(t, err)

	events := []FinalAuditEvent{createTestFinalEvent()}
	err = w.WriteBatch(context.Background(), events)
	require.NoError(t, err)

	// Verify events landed in the custom key, not the default
	defaultList := mock.GetListData("audit:fallback:queue")
	assert.Nil(t, defaultList, "default key should be empty")

	customList := mock.GetListData("my:custom:queue")
	assert.Len(t, customList, 1, "event should be in the custom queue key")
}

// --- Config Validate tests ---

func TestRedisQueueWriterConfig_Validate(t *testing.T) {
	t.Run("empty key gets default", func(t *testing.T) {
		cfg := RedisQueueWriterConfig{}
		cfg.Validate()
		assert.Equal(t, "audit:fallback:queue", cfg.QueueKey)
		assert.Equal(t, int64(0), cfg.MaxQueueSize, "zero stays zero (unlimited)")
		assert.Equal(t, 7*24*time.Hour, cfg.QueueTTL, "zero QueueTTL defaults to 7 days")
	})

	t.Run("custom key preserved", func(t *testing.T) {
		cfg := RedisQueueWriterConfig{QueueKey: "custom:queue", MaxQueueSize: 500, QueueTTL: 48 * time.Hour}
		cfg.Validate()
		assert.Equal(t, "custom:queue", cfg.QueueKey)
		assert.Equal(t, int64(500), cfg.MaxQueueSize)
		assert.Equal(t, 48*time.Hour, cfg.QueueTTL, "custom QueueTTL preserved")
	})

	t.Run("negative MaxQueueSize gets default", func(t *testing.T) {
		cfg := RedisQueueWriterConfig{MaxQueueSize: -1}
		cfg.Validate()
		assert.Equal(t, int64(10000), cfg.MaxQueueSize)
	})

	t.Run("negative QueueTTL preserved (explicit disable)", func(t *testing.T) {
		cfg := RedisQueueWriterConfig{QueueTTL: -1}
		cfg.Validate()
		assert.Equal(t, time.Duration(-1), cfg.QueueTTL, "negative QueueTTL means disabled")
	})
}

func TestDefaultRedisQueueWriterConfig(t *testing.T) {
	cfg := DefaultRedisQueueWriterConfig()
	assert.Equal(t, "audit:fallback:queue", cfg.QueueKey)
	assert.Equal(t, int64(10000), cfg.MaxQueueSize)
	assert.Equal(t, 7*24*time.Hour, cfg.QueueTTL)
}

// --- Security fix tests ---

func TestRedisQueueWriter_WriteBatch_SetsTTLAfterLPush(t *testing.T) {
	mock := newMockRedisWithErrors()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := DefaultRedisQueueWriterConfig()
	w, err := NewRedisQueueWriter(cfg, mock, log)
	require.NoError(t, err)

	events := []FinalAuditEvent{createTestFinalEvent()}
	err = w.WriteBatch(context.Background(), events)
	require.NoError(t, err)

	// Verify events are in the list
	list := mock.GetListData("audit:fallback:queue")
	assert.Len(t, list, 1, "event should be in queue")
	// MockRedisClient.Expire checks all stores (data, listData, hashData) —
	// returns true for the queue key since LPush created it in listData.
}

func TestRedisQueueWriter_WriteBatch_NoTTLWhenNegative(t *testing.T) {
	mock := newMockRedisWithErrors()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// QueueTTL<0 explicitly disables TTL (Validate() defaults 0 to 7 days)
	cfg := RedisQueueWriterConfig{QueueKey: "audit:fallback:queue", QueueTTL: -1}
	w, err := NewRedisQueueWriter(cfg, mock, log)
	require.NoError(t, err)

	events := []FinalAuditEvent{createTestFinalEvent()}
	err = w.WriteBatch(context.Background(), events)
	require.NoError(t, err, "negative QueueTTL should skip Expire and not error")
}

// --- QA-generated tests (Step 07) ---

func TestRedisQueueWriter_WriteBatch_ExpireError_NonFatal(t *testing.T) {
	mock := newMockRedisWithErrors()
	mock.setExpireErr(errors.New("READONLY"))
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := DefaultRedisQueueWriterConfig()
	w, err := NewRedisQueueWriter(cfg, mock, log)
	require.NoError(t, err)

	events := []FinalAuditEvent{createTestFinalEvent()}
	err = w.WriteBatch(context.Background(), events)

	require.NoError(t, err, "Expire error should be non-fatal — events still delivered")

	list := mock.GetListData("audit:fallback:queue")
	assert.Len(t, list, 1, "event should be in queue despite Expire failure")
}

func TestRedisQueueWriter_WriteBatch_MarshalError(t *testing.T) {
	mock := newMockRedisWithErrors()
	w := newTestWriter(t, mock)

	// ContextData with unmarshalable value (func) causes json.Marshal to fail
	event := createTestFinalEvent()
	event.ContextData = map[string]interface{}{
		"bad_value": func() {}, // json.Marshal cannot serialize functions
	}

	err := w.WriteBatch(context.Background(), []FinalAuditEvent{event})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "redis queue writer: failed to marshal event")
	assert.Equal(t, 0, mock.getLPushCount(), "LPUSH should not be called on marshal failure")
}

func TestRedisQueueWriter_WriteBatch_QueueAtExactCapacity(t *testing.T) {
	mock := newMockRedisWithErrors()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := RedisQueueWriterConfig{QueueKey: "audit:fallback:queue", MaxQueueSize: 5}
	w, err := NewRedisQueueWriter(cfg, mock, log)
	require.NoError(t, err)

	// Fill queue to 4, then push 1 → total 5 == max → should succeed (strict > check)
	for i := 0; i < 4; i++ {
		require.NoError(t, w.WriteBatch(context.Background(), []FinalAuditEvent{createTestFinalEvent()}))
	}

	// 4 + 1 = 5 == maxQueueSize → not greater than, should succeed
	err = w.WriteBatch(context.Background(), []FinalAuditEvent{createTestFinalEvent()})
	require.NoError(t, err, "queue at exact capacity (5/5) should succeed — check is strict >")

	list := mock.GetListData("audit:fallback:queue")
	assert.Len(t, list, 5, "all 5 events should be in the queue")

	// 5 + 1 = 6 > 5 → should fail
	err = w.WriteBatch(context.Background(), []FinalAuditEvent{createTestFinalEvent()})
	require.Error(t, err, "queue over capacity should be rejected")
	assert.Contains(t, err.Error(), "queue capacity exceeded")
}
