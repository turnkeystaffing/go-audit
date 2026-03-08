//go:build !production

package audit

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgredis "github.com/turnkeystaffing/go-redis"
)

func testProducerRouterConfig(t *testing.T) ProducerRouterConfig {
	t.Helper()
	fileDir := filepath.Join(t.TempDir(), "audit-files")
	return ProducerRouterConfig{
		HTTP: HTTPWriterConfig{
			BaseURL:     "http://localhost:9090",
			ServiceName: "test-service",
		},
		TokenProvider: NewStaticTokenProvider("test-token"),
		RedisClient:   pkgredis.NewMockRedisClient(),
		FileDir:       fileDir,
	}
}

func TestNewProducerRouter_Success(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := testProducerRouterConfig(t)

	pr, err := NewProducerRouter(cfg, log)
	require.NoError(t, err)
	require.NotNil(t, pr)
	require.NotNil(t, pr.Router)
	require.NotNil(t, pr.Replayer)

	// Verify chain strategy
	assert.Equal(t, DispatchChain, pr.Router.config.DispatchStrategy)

	// Verify 3 writers registered in correct order
	writers := pr.Router.GetWritersSnapshot()
	require.Len(t, writers, 3)
	assert.Equal(t, "http", writers[0].Name())
	assert.Equal(t, "redis-queue", writers[1].Name())
	assert.Equal(t, "file", writers[2].Name())

	// Verify HTTPWriter is registered as critical
	assert.True(t, pr.Router.IsCriticalWriter("http"))
	assert.False(t, pr.Router.IsCriticalWriter("redis-queue"))
	assert.False(t, pr.Router.IsCriticalWriter("file"))
}

func TestNewProducerRouter_CustomRouterConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := testProducerRouterConfig(t)
	cfg.RouterConfig = &AuditConfig{
		Enabled:                true,
		BufferSize:             200,
		BatchSize:              50,
		FlushInterval:          1 * time.Second,
		AlertThreshold:         0.9,
		ShutdownTimeout:        10 * time.Second,
		PartitionCheckInterval: 24 * time.Hour,
	}

	pr, err := NewProducerRouter(cfg, log)
	require.NoError(t, err)

	// Strategy should be overridden to DispatchChain regardless of input
	assert.Equal(t, DispatchChain, pr.Router.config.DispatchStrategy)
	assert.Equal(t, 200, pr.Router.config.BufferSize)
}

func TestNewProducerRouter_PanicsOnNilLogger(t *testing.T) {
	cfg := testProducerRouterConfig(t)
	assert.Panics(t, func() {
		_, _ = NewProducerRouter(cfg, nil)
	})
}

func TestNewProducerRouter_PanicsOnNilTokenProvider(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := testProducerRouterConfig(t)
	cfg.TokenProvider = nil
	assert.Panics(t, func() {
		_, _ = NewProducerRouter(cfg, log)
	})
}

func TestNewProducerRouter_NilRedisClient_TwoTierChain(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := testProducerRouterConfig(t)
	cfg.RedisClient = nil

	pr, err := NewProducerRouter(cfg, log)
	require.NoError(t, err)
	require.NotNil(t, pr)

	// Verify chain strategy
	assert.Equal(t, DispatchChain, pr.Router.config.DispatchStrategy)

	// Verify 2 writers registered: HTTP → File (no Redis)
	writers := pr.Router.GetWritersSnapshot()
	require.Len(t, writers, 2)
	assert.Equal(t, "http", writers[0].Name())
	assert.Equal(t, "file", writers[1].Name())
}

func TestNewProducerRouter_ErrorOnEmptyFileDir(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := testProducerRouterConfig(t)
	cfg.FileDir = ""

	pr, err := NewProducerRouter(cfg, log)
	assert.Error(t, err)
	assert.Nil(t, pr)
	assert.Contains(t, err.Error(), "FileDir is required")
}

func TestNewProducerRouter_ErrorOnInvalidHTTPConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := testProducerRouterConfig(t)
	cfg.HTTP.BaseURL = "" // Invalid

	pr, err := NewProducerRouter(cfg, log)
	assert.Error(t, err)
	assert.Nil(t, pr)
	assert.Contains(t, err.Error(), "http writer")
}

func TestNewProducerRouter_LifecycleStartShutdown(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := testProducerRouterConfig(t)

	pr, err := NewProducerRouter(cfg, log)
	require.NoError(t, err)

	ctx := context.Background()

	// Start router and replayer
	require.NoError(t, pr.Router.Start(ctx))
	require.NoError(t, pr.Replayer.Start(ctx))

	// Shutdown in reverse order
	require.NoError(t, pr.Replayer.Shutdown(ctx))
	require.NoError(t, pr.Router.Shutdown(ctx))
}
