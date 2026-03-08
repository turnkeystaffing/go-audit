//go:build !production

package audit

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createChainTestConfig returns a valid AuditConfig with DispatchChain strategy.
func createChainTestConfig() *AuditConfig {
	cfg := createTestConfig()
	cfg.DispatchStrategy = DispatchChain
	return cfg
}

// --- DispatchStrategy defaults ---

func TestDispatchStrategy_DefaultIsFanOut(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, DispatchFanOut, cfg.DispatchStrategy, "default strategy must be DispatchFanOut")
}

func TestDispatchStrategy_ZeroValueIsFanOut(t *testing.T) {
	var strategy DispatchStrategy
	assert.Equal(t, DispatchFanOut, strategy, "zero-value strategy must be DispatchFanOut")
}

// --- processBatch chain dispatch ---

func TestProcessBatchChain_FirstWriterSucceeds_OthersNotCalled(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := createChainTestConfig()
	router := NewAuditRouter(cfg, log, testNoopRedis())

	primary := NewMockWriter("primary")
	secondary := NewMockWriter("secondary")
	tertiary := NewMockWriter("tertiary")

	router.RegisterWriter(primary, true)
	router.RegisterWriter(secondary, false)
	router.RegisterWriter(tertiary, false)

	require.NoError(t, router.Start(context.Background()))
	defer func() { _ = router.Shutdown(context.Background()) }()

	event := createTestEvent()
	require.NoError(t, router.Log(context.Background(), event))

	// Wait for async processing
	require.True(t, primary.WaitForEvents(1, 2*time.Second), "primary should receive 1 event")

	// Short delay to ensure others would have been called if they were going to be
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 1, primary.GetWriteBatchCallCount(), "primary should be called once")
	assert.Equal(t, 0, secondary.GetWriteBatchCallCount(), "secondary should NOT be called when primary succeeds")
	assert.Equal(t, 0, tertiary.GetWriteBatchCallCount(), "tertiary should NOT be called when primary succeeds")
}

func TestProcessBatchChain_FirstFails_SecondSucceeds_ThirdNotCalled(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := createChainTestConfig()
	router := NewAuditRouter(cfg, log, testNoopRedis())

	primary := NewMockWriter("primary")
	primary.SetWriteBatchError(errors.New("HTTP unavailable"))
	secondary := NewMockWriter("secondary")
	tertiary := NewMockWriter("tertiary")

	router.RegisterWriter(primary, true)
	router.RegisterWriter(secondary, false)
	router.RegisterWriter(tertiary, false)

	require.NoError(t, router.Start(context.Background()))
	defer func() { _ = router.Shutdown(context.Background()) }()

	event := createTestEvent()
	require.NoError(t, router.Log(context.Background(), event))

	require.True(t, secondary.WaitForEvents(1, 2*time.Second), "secondary should receive 1 event")

	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 1, primary.GetWriteBatchCallCount(), "primary should be called once (and fail)")
	assert.Equal(t, 1, secondary.GetWriteBatchCallCount(), "secondary should be called once (and succeed)")
	assert.Equal(t, 0, tertiary.GetWriteBatchCallCount(), "tertiary should NOT be called when secondary succeeds")
}

func TestProcessBatchChain_AllWritersFail_EventsLost(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := createChainTestConfig()
	router := NewAuditRouter(cfg, log, testNoopRedis())

	primary := NewMockWriter("primary")
	primary.SetWriteBatchError(errors.New("HTTP unavailable"))
	secondary := NewMockWriter("secondary")
	secondary.SetWriteBatchError(errors.New("Redis unavailable"))
	tertiary := NewMockWriter("tertiary")
	tertiary.SetWriteBatchError(errors.New("File I/O error"))

	router.RegisterWriter(primary, true)
	router.RegisterWriter(secondary, false)
	router.RegisterWriter(tertiary, false)

	require.NoError(t, router.Start(context.Background()))

	event := createTestEvent()
	require.NoError(t, router.Log(context.Background(), event))

	// Wait for async processing then shutdown to ensure batch is flushed
	time.Sleep(500 * time.Millisecond)
	_ = router.Shutdown(context.Background())

	assert.Equal(t, 1, primary.GetWriteBatchCallCount(), "primary should be called")
	assert.Equal(t, 1, secondary.GetWriteBatchCallCount(), "secondary should be called")
	assert.Equal(t, 1, tertiary.GetWriteBatchCallCount(), "tertiary should be called")

	// Metrics should show failure
	assert.True(t, router.metrics.EventsFailed.Load() > 0, "EventsFailed should be incremented")
	assert.True(t, router.metrics.EventsLost.Load() > 0, "EventsLost should be incremented")
}

// --- writeCriticalSync chain dispatch ---

func TestWriteCriticalChain_FirstWriterSucceeds(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := createChainTestConfig()
	router := NewAuditRouter(cfg, log, testNoopRedis())

	primary := NewMockWriter("primary")
	secondary := NewMockWriter("secondary")

	router.RegisterWriter(primary, true)
	router.RegisterWriter(secondary, false)

	require.NoError(t, router.Start(context.Background()))
	defer func() { _ = router.Shutdown(context.Background()) }()

	event := createTestEvent()
	event.Critical = true
	err := router.Log(context.Background(), event)
	require.NoError(t, err)

	assert.Equal(t, 1, primary.GetWriteBatchCallCount(), "primary should be called")
	assert.Equal(t, 0, secondary.GetWriteBatchCallCount(), "secondary should NOT be called")
	assert.Equal(t, uint64(1), router.metrics.EventsProcessed.Load())
}

func TestWriteCriticalChain_AllFail_Rejected(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := createChainTestConfig()
	router := NewAuditRouter(cfg, log, testNoopRedis())

	primary := NewMockWriter("primary")
	primary.SetWriteBatchError(errors.New("fail"))
	secondary := NewMockWriter("secondary")
	secondary.SetWriteBatchError(errors.New("fail"))

	router.RegisterWriter(primary, true)
	router.RegisterWriter(secondary, false)

	require.NoError(t, router.Start(context.Background()))
	defer func() { _ = router.Shutdown(context.Background()) }()

	event := createTestEvent()
	event.Critical = true
	err := router.Log(context.Background(), event)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all 2 writers failed")
	assert.Equal(t, uint64(1), router.metrics.EventsCriticalRejected.Load())
}

func TestWriteCriticalChain_SequentialWithin100msTimeout(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := createChainTestConfig()
	router := NewAuditRouter(cfg, log, testNoopRedis())

	primary := NewMockWriter("primary")
	primary.SetWriteBatchError(errors.New("fail"))
	secondary := NewMockWriter("secondary")
	// secondary succeeds

	router.RegisterWriter(primary, true)
	router.RegisterWriter(secondary, false)

	require.NoError(t, router.Start(context.Background()))
	defer func() { _ = router.Shutdown(context.Background()) }()

	event := createTestEvent()
	event.Critical = true

	start := time.Now()
	err := router.Log(context.Background(), event)
	duration := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, duration, 100*time.Millisecond, "chain dispatch should complete within 100ms timeout")
	assert.Equal(t, 1, secondary.GetWriteBatchCallCount())
}

// --- LogCritical chain dispatch ---

func TestLogCriticalChain_StopsOnFirstSuccess(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := createChainTestConfig()
	router := NewAuditRouter(cfg, log, testNoopRedis())

	primary := NewMockWriter("primary")
	secondary := NewMockWriter("secondary")

	router.RegisterWriter(primary, true)
	router.RegisterWriter(secondary, false)

	require.NoError(t, router.Start(context.Background()))
	defer func() { _ = router.Shutdown(context.Background()) }()

	event := createTestEvent()
	err := router.LogCritical(context.Background(), event)
	require.NoError(t, err)

	assert.Equal(t, 1, primary.GetWriteBatchCallCount(), "primary should be called")
	assert.Equal(t, 0, secondary.GetWriteBatchCallCount(), "secondary should NOT be called")
}

func TestLogCriticalChain_CascadesOnFailure(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := createChainTestConfig()
	router := NewAuditRouter(cfg, log, testNoopRedis())

	primary := NewMockWriter("primary")
	primary.SetWriteBatchError(errors.New("fail"))
	secondary := NewMockWriter("secondary")

	router.RegisterWriter(primary, true)
	router.RegisterWriter(secondary, false)

	require.NoError(t, router.Start(context.Background()))
	defer func() { _ = router.Shutdown(context.Background()) }()

	event := createTestEvent()
	err := router.LogCritical(context.Background(), event)
	require.NoError(t, err)

	assert.Equal(t, 1, primary.GetWriteBatchCallCount(), "primary should be called and fail")
	assert.Equal(t, 1, secondary.GetWriteBatchCallCount(), "secondary should be called and succeed")
}

func TestLogCriticalChain_AllFail_ReturnsError(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := createChainTestConfig()
	router := NewAuditRouter(cfg, log, testNoopRedis())

	primary := NewMockWriter("primary")
	primary.SetWriteBatchError(errors.New("fail"))
	secondary := NewMockWriter("secondary")
	secondary.SetWriteBatchError(errors.New("fail"))

	router.RegisterWriter(primary, true)
	router.RegisterWriter(secondary, false)

	require.NoError(t, router.Start(context.Background()))
	defer func() { _ = router.Shutdown(context.Background()) }()

	event := createTestEvent()
	err := router.LogCritical(context.Background(), event)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all 2 writers failed")
	assert.Equal(t, uint64(1), router.metrics.EventsFailed.Load(), "EventsFailed should be incremented")
	assert.Equal(t, uint64(1), router.metrics.EventsCriticalRejected.Load(), "EventsCriticalRejected should be incremented")
}

// --- FanOut dispatch unchanged ---

func TestFanOut_AllWritersCalledInParallel(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := createTestConfig() // Default = DispatchFanOut
	router := NewAuditRouter(cfg, log, testNoopRedis())

	writer1 := NewMockWriter("writer-1")
	writer2 := NewMockWriter("writer-2")
	writer3 := NewMockWriter("writer-3")

	router.RegisterWriter(writer1, true)
	router.RegisterWriter(writer2, false)
	router.RegisterWriter(writer3, false)

	require.NoError(t, router.Start(context.Background()))
	defer func() { _ = router.Shutdown(context.Background()) }()

	event := createTestEvent()
	require.NoError(t, router.Log(context.Background(), event))

	// Wait for all writers to receive the event
	require.True(t, writer1.WaitForEvents(1, 2*time.Second))
	require.True(t, writer2.WaitForEvents(1, 2*time.Second))
	require.True(t, writer3.WaitForEvents(1, 2*time.Second))

	assert.Equal(t, 1, writer1.GetWriteBatchCallCount(), "all writers should be called in fanout")
	assert.Equal(t, 1, writer2.GetWriteBatchCallCount(), "all writers should be called in fanout")
	assert.Equal(t, 1, writer3.GetWriteBatchCallCount(), "all writers should be called in fanout")
}

// --- RegisterWriter order semantics ---

func TestRegisterWriter_OrderDeterminesChainPriority(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := createChainTestConfig()
	router := NewAuditRouter(cfg, log, testNoopRedis())

	// Register in reverse order to verify registration order matters
	lastResort := NewMockWriter("last-resort")
	fallback := NewMockWriter("fallback")
	primary := NewMockWriter("primary")
	primary.SetWriteBatchError(errors.New("fail"))
	fallback.SetWriteBatchError(errors.New("fail"))

	// Register: primary first, then fallback, then last-resort
	router.RegisterWriter(primary, true)
	router.RegisterWriter(fallback, false)
	router.RegisterWriter(lastResort, false)

	require.NoError(t, router.Start(context.Background()))
	defer func() { _ = router.Shutdown(context.Background()) }()

	event := createTestEvent()
	require.NoError(t, router.LogCritical(context.Background(), event))

	// primary fails, fallback fails, last-resort succeeds
	assert.Equal(t, 1, primary.GetWriteBatchCallCount())
	assert.Equal(t, 1, fallback.GetWriteBatchCallCount())
	assert.Equal(t, 1, lastResort.GetWriteBatchCallCount())
}
