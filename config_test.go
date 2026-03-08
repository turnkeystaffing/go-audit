package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, 1024, cfg.BufferSize)
	assert.Equal(t, 100, cfg.BatchSize)
	assert.Equal(t, 5*time.Second, cfg.FlushInterval)
	assert.Equal(t, 0.8, cfg.AlertThreshold)
	assert.Equal(t, 30*time.Second, cfg.ShutdownTimeout)
	assert.Equal(t, 24*time.Hour, cfg.PartitionCheckInterval)
}

func TestDefaultConfig_Validates(t *testing.T) {
	cfg := DefaultConfig()
	assert.NoError(t, cfg.Validate())
}

func TestConfig_Validate_BufferTooSmall(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BufferSize = 50
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "buffer size must be >= 100")
}

func TestConfig_Validate_BatchExceedsBuffer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BufferSize = 100
	cfg.BatchSize = 200
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "batch size")
}

func TestConfig_Validate_BatchSizeZero(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BatchSize = 0
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "batch size must be >= 1")
}

func TestConfig_Validate_FlushIntervalTooLow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FlushInterval = 10 * time.Millisecond
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "flush interval must be >= 50ms")
}

func TestConfig_Validate_FlushIntervalTooHigh(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FlushInterval = 120 * time.Second
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "flush interval must be <= 60s")
}

func TestConfig_Validate_AlertThresholdOutOfRange(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AlertThreshold = 1.5
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "alert threshold")
}

func TestConfig_Validate_ShutdownTimeoutTooLow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ShutdownTimeout = 500 * time.Millisecond
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shutdown timeout must be >= 1s")
}

func TestConfig_Validate_ShutdownTimeoutTooHigh(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ShutdownTimeout = 10 * time.Minute
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shutdown timeout must be <= 5m")
}

func TestConfig_Validate_PartitionIntervalTooLow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PartitionCheckInterval = 30 * time.Minute
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "partition check interval must be >= 1h")
}
