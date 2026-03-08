package audit

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewFileWriter tests the constructor validation
func TestNewFileWriter(t *testing.T) {
	t.Run("panics when logger is nil", func(t *testing.T) {
		assert.PanicsWithValue(t, "audit: logger is required", func() {
			NewFileWriter("/tmp/audit", "daily", 0, nil)
		})
	})

	t.Run("returns error when directory is empty", func(t *testing.T) {
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))

		writer, err := NewFileWriter("", "daily", 0, log)

		assert.Error(t, err)
		assert.Nil(t, writer)
		assert.Contains(t, err.Error(), "directory is required")
	})

	t.Run("creates writer successfully with valid parameters", func(t *testing.T) {
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))

		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 1024*1024, log)

		assert.NoError(t, err)
		assert.NotNil(t, writer)
		assert.Equal(t, "file", writer.Name())
		assert.Equal(t, tmpDir, writer.directory)
		assert.Equal(t, "daily", writer.rotation)
		assert.Equal(t, int64(1024*1024), writer.maxSize)
	})

	t.Run("creates directory if it doesn't exist", func(t *testing.T) {
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))

		tmpDir := filepath.Join(t.TempDir(), "nested", "audit", "logs")
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)

		assert.NoError(t, err)
		assert.NotNil(t, writer)

		// Verify directory was created
		info, err := os.Stat(tmpDir)
		assert.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("accepts different rotation types", func(t *testing.T) {
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))

		rotations := []string{"daily", "hourly", "size"}

		for _, rotation := range rotations {
			tmpDir := t.TempDir()
			writer, err := NewFileWriter(tmpDir, rotation, 1024*1024, log)

			assert.NoError(t, err)
			assert.NotNil(t, writer)
			assert.Equal(t, rotation, writer.rotation)
		}
	})
}

// TestFileWriter_WriteBatch tests the WriteBatch method
func TestFileWriter_WriteBatch(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	t.Run("handles empty batch", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)

		err = writer.WriteBatch(context.Background(), []FinalAuditEvent{})

		assert.NoError(t, err)
		// No file should be created for empty batch
		assert.Nil(t, writer.currentFile)
	})

	t.Run("writes single event successfully", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)
		defer writer.Shutdown(context.Background())

		events := []FinalAuditEvent{
			{
				AuditEvent: AuditEvent{
					ID:        uuid.New(),
					Action:    "user.login",
					Outcome:   "success",
					Timestamp: time.Now(),
				},
			},
		}

		err = writer.WriteBatch(context.Background(), events)

		assert.NoError(t, err)
		assert.NotNil(t, writer.currentFile)

		// Verify file was created
		files, err := os.ReadDir(tmpDir)
		assert.NoError(t, err)
		assert.Len(t, files, 1)
		assert.Contains(t, files[0].Name(), "audit-")
		assert.Contains(t, files[0].Name(), ".jsonl")
	})

	t.Run("writes multiple events successfully", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)
		defer writer.Shutdown(context.Background())

		events := []FinalAuditEvent{
			{
				AuditEvent: AuditEvent{
					ID:        uuid.New(),
					Action:    "user.login",
					Outcome:   "success",
					Timestamp: time.Now(),
				},
			},
			{
				AuditEvent: AuditEvent{
					ID:        uuid.New(),
					Action:    "user.logout",
					Outcome:   "success",
					Timestamp: time.Now(),
				},
			},
			{
				AuditEvent: AuditEvent{
					ID:        uuid.New(),
					Action:    "user.update",
					Outcome:   "success",
					Timestamp: time.Now(),
				},
			},
		}

		err = writer.WriteBatch(context.Background(), events)

		assert.NoError(t, err)
		assert.NotNil(t, writer.currentFile)
	})

	t.Run("always returns nil for non-critical writer", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)
		defer writer.Shutdown(context.Background())

		events := []FinalAuditEvent{
			{
				AuditEvent: AuditEvent{
					ID:        uuid.New(),
					Action:    "user.login",
					Outcome:   "success",
					Timestamp: time.Now(),
				},
			},
		}

		err = writer.WriteBatch(context.Background(), events)

		// Non-critical writer always returns nil
		assert.NoError(t, err)
	})

	t.Run("creates JSONL format output", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)
		defer writer.Shutdown(context.Background())

		eventID := uuid.New()
		events := []FinalAuditEvent{
			{
				AuditEvent: AuditEvent{
					ID:        eventID,
					Action:    "user.login",
					Outcome:   "success",
					Timestamp: time.Now(),
				},
			},
		}

		err = writer.WriteBatch(context.Background(), events)
		require.NoError(t, err)

		// Close file to ensure data is flushed
		writer.Shutdown(context.Background())

		// Read file and verify JSONL format
		files, err := os.ReadDir(tmpDir)
		require.NoError(t, err)
		require.Len(t, files, 1)

		content, err := os.ReadFile(filepath.Join(tmpDir, files[0].Name()))
		require.NoError(t, err)

		// Verify JSON line format (ends with newline)
		assert.Contains(t, string(content), eventID.String())
		assert.Contains(t, string(content), "user.login")
		assert.Contains(t, string(content), "success")
		assert.True(t, len(content) > 0 && content[len(content)-1] == '\n')
	})

	t.Run("handles size-based rotation", func(t *testing.T) {
		tmpDir := t.TempDir()
		// Set very small max size to trigger rotation (50 bytes)
		writer, err := NewFileWriter(tmpDir, "size", 50, log)
		require.NoError(t, err)
		defer writer.Shutdown(context.Background())

		// Write multiple events that will trigger rotation
		// Each event as JSON is ~200+ bytes, so should trigger rotation multiple times
		for i := 0; i < 5; i++ {
			events := []FinalAuditEvent{
				{
					AuditEvent: AuditEvent{
						ID:        uuid.New(),
						Action:    "user.login",
						Outcome:   "success",
						Timestamp: time.Now(),
					},
				},
			}

			err = writer.WriteBatch(context.Background(), events)
			// Rotation doesn't cause errors - non-critical writer always returns nil
			assert.NoError(t, err)
		}

		// Write one more event to ensure file reopens after rotation
		finalEvents := []FinalAuditEvent{
			{
				AuditEvent: AuditEvent{
					ID:        uuid.New(),
					Action:    "user.logout",
					Outcome:   "success",
					Timestamp: time.Now(),
				},
			},
		}
		err = writer.WriteBatch(context.Background(), finalEvents)
		assert.NoError(t, err)

		// After writes complete successfully, file should be open
		assert.NotNil(t, writer.currentFile)
	})

	t.Run("logs debug message with batch statistics", func(t *testing.T) {
		debugLog := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, debugLog)
		require.NoError(t, err)
		defer writer.Shutdown(context.Background())

		events := []FinalAuditEvent{
			{
				AuditEvent: AuditEvent{
					ID:        uuid.New(),
					Action:    "user.login",
					Outcome:   "success",
					Timestamp: time.Now(),
				},
			},
		}

		err = writer.WriteBatch(context.Background(), events)

		assert.NoError(t, err)
	})
}

// TestFileWriter_Shutdown tests the Shutdown method
func TestFileWriter_Shutdown(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	t.Run("returns nil without error", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)

		// Write an event to open a file
		events := []FinalAuditEvent{
			{
				AuditEvent: AuditEvent{
					ID:        uuid.New(),
					Action:    "user.login",
					Outcome:   "success",
					Timestamp: time.Now(),
				},
			},
		}
		err = writer.WriteBatch(context.Background(), events)
		require.NoError(t, err)

		err = writer.Shutdown(context.Background())

		assert.NoError(t, err)
		assert.Nil(t, writer.currentFile)
	})

	t.Run("is idempotent", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)

		// Call shutdown multiple times
		err1 := writer.Shutdown(context.Background())
		err2 := writer.Shutdown(context.Background())
		err3 := writer.Shutdown(context.Background())

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NoError(t, err3)
	})

	t.Run("closes open file", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)

		// Write an event to open a file
		events := []FinalAuditEvent{
			{
				AuditEvent: AuditEvent{
					ID:        uuid.New(),
					Action:    "user.login",
					Outcome:   "success",
					Timestamp: time.Now(),
				},
			},
		}
		err = writer.WriteBatch(context.Background(), events)
		require.NoError(t, err)
		require.NotNil(t, writer.currentFile)

		err = writer.Shutdown(context.Background())

		assert.NoError(t, err)
		assert.Nil(t, writer.currentFile)
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Shutdown should still succeed even with cancelled context
		err = writer.Shutdown(ctx)

		assert.NoError(t, err)
	})
}

// TestFileWriter_Health tests the Health method
func TestFileWriter_Health(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	t.Run("succeeds with writable directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)

		err = writer.Health(context.Background())

		assert.NoError(t, err)

		// Verify no health check file remains
		files, err := os.ReadDir(tmpDir)
		assert.NoError(t, err)
		for _, file := range files {
			assert.NotEqual(t, ".health_check", file.Name())
		}
	})

	t.Run("health check is idempotent", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)

		// Multiple health checks should all succeed
		err1 := writer.Health(context.Background())
		err2 := writer.Health(context.Background())
		err3 := writer.Health(context.Background())

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NoError(t, err3)
	})

	t.Run("fails with non-writable directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)

		// Make directory read-only
		err = os.Chmod(tmpDir, 0444)
		require.NoError(t, err)
		defer os.Chmod(tmpDir, 0755) // Restore permissions for cleanup

		err = writer.Health(context.Background())

		// When running as root, write permissions succeed even on read-only directories
		// For non-root users, the health check should fail with permission error
		if os.Getuid() == 0 {
			// Root can write to read-only directories, so health check succeeds
			assert.NoError(t, err, "Health check should succeed when running as root")
		} else {
			// Non-root users cannot write to read-only directories
			assert.Error(t, err, "Health check should fail for non-root users")
			assert.Contains(t, err.Error(), "file directory not writable")
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Health check should still work - it doesn't check context
		err = writer.Health(ctx)

		// Health check doesn't use context, so it succeeds
		assert.NoError(t, err)
	})
}

// TestFileWriter_Name tests the Name method
func TestFileWriter_Name(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	t.Run("returns file identifier", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)

		name := writer.Name()

		assert.Equal(t, "file", name)
	})
}

// TestFileWriter_Rotation tests file rotation behavior
func TestFileWriter_Rotation(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	t.Run("daily rotation creates date-based filename", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "daily", 0, log)
		require.NoError(t, err)
		defer writer.Shutdown(context.Background())

		events := []FinalAuditEvent{
			{
				AuditEvent: AuditEvent{
					ID:        uuid.New(),
					Action:    "user.login",
					Outcome:   "success",
					Timestamp: time.Now(),
				},
			},
		}

		err = writer.WriteBatch(context.Background(), events)
		require.NoError(t, err)

		// Verify filename contains date
		files, err := os.ReadDir(tmpDir)
		require.NoError(t, err)
		require.Len(t, files, 1)

		expectedDateFormat := time.Now().Format("2006-01-02")
		assert.Contains(t, files[0].Name(), expectedDateFormat)
	})

	t.Run("hourly rotation creates hour-based filename", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "hourly", 0, log)
		require.NoError(t, err)
		defer writer.Shutdown(context.Background())

		events := []FinalAuditEvent{
			{
				AuditEvent: AuditEvent{
					ID:        uuid.New(),
					Action:    "user.login",
					Outcome:   "success",
					Timestamp: time.Now(),
				},
			},
		}

		err = writer.WriteBatch(context.Background(), events)
		require.NoError(t, err)

		// Verify filename contains date and hour
		files, err := os.ReadDir(tmpDir)
		require.NoError(t, err)
		require.Len(t, files, 1)

		expectedDateFormat := time.Now().Format("2006-01-02-15")
		assert.Contains(t, files[0].Name(), expectedDateFormat)
	})

	t.Run("default rotation uses daily format", func(t *testing.T) {
		tmpDir := t.TempDir()
		writer, err := NewFileWriter(tmpDir, "unknown", 0, log)
		require.NoError(t, err)
		defer writer.Shutdown(context.Background())

		events := []FinalAuditEvent{
			{
				AuditEvent: AuditEvent{
					ID:        uuid.New(),
					Action:    "user.login",
					Outcome:   "success",
					Timestamp: time.Now(),
				},
			},
		}

		err = writer.WriteBatch(context.Background(), events)
		require.NoError(t, err)

		// Verify filename contains date (daily format)
		files, err := os.ReadDir(tmpDir)
		require.NoError(t, err)
		require.Len(t, files, 1)

		expectedDateFormat := time.Now().Format("2006-01-02")
		assert.Contains(t, files[0].Name(), expectedDateFormat)
	})
}
