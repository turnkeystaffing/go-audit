package audit

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"encoding/json"
)

// FileWriter implements AuditWriter for file-based audit logging with rotation.
// This is a NON-CRITICAL writer - failures will be logged but not block operations.
type FileWriter struct {
	directory     string
	rotation      string // daily, hourly, size
	maxSize       int64
	log           *slog.Logger
	currentFile   *os.File
	currentSize   int64
	currentDate   string
	mu            sync.Mutex
	lastHealthAt  time.Time // last successful health check timestamp
	lastHealthErr error     // cached health check result
}

// NewFileWriter creates a new file-based audit writer.
func NewFileWriter(directory, rotation string, maxSize int64, log *slog.Logger) (*FileWriter, error) {
	if log == nil {
		panic("audit: logger is required")
	}
	if directory == "" {
		return nil, fmt.Errorf("directory is required")
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	return &FileWriter{
		directory: directory,
		rotation:  rotation,
		maxSize:   maxSize,
		log:       log,
	}, nil
}

// WriteBatch writes audit events to file with rotation.
// This is a non-critical writer - always returns nil and logs errors internally.
func (w *FileWriter) WriteBatch(ctx context.Context, events []FinalAuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	start := time.Now()
	successCount := 0

	// Ensure file is open and check rotation
	if err := w.ensureFile(); err != nil {
		w.invalidateHealthCache()
		w.log.Error("Failed to ensure audit log file",
			"error", err)
		return nil // Non-critical writer - return nil
	}

	for _, event := range events {
		eventJSON, err := json.Marshal(event)
		if err != nil {
			w.log.Error("Failed to marshal audit event to JSON",
				"error", err,
				"event_id", event.ID)
			continue
		}

		// Write JSON line to file
		line := string(eventJSON) + "\n"
		n, err := w.currentFile.WriteString(line)
		if err != nil {
			w.invalidateHealthCache()
			w.log.Error("Failed to write audit event to file",
				"error", err,
				"event_id", event.ID)
			continue
		}

		w.currentSize += int64(n)
		successCount++

		// Check size rotation
		if w.rotation == "size" && w.currentSize >= w.maxSize {
			if err := w.rotateFile(); err != nil {
				w.log.Error("Failed to rotate audit log file",
					"error", err)
			}
			// Reopen file after rotation to continue writing
			if err := w.ensureFile(); err != nil {
				w.log.Error("Failed to ensure audit log file after rotation",
					"error", err)
				continue
			}
		}
	}

	// Sync to disk
	if w.currentFile != nil {
		if err := w.currentFile.Sync(); err != nil {
			w.log.Error("Failed to sync audit log file",
				"error", err)
		}
	}

	w.log.Debug("Wrote audit events to file",
		"batch_size", len(events),
		"success_count", successCount,
		"duration_ms", time.Since(start).Milliseconds())

	// Non-critical writer - always return nil
	return nil
}

// ensureFile opens the current log file or creates a new one.
func (w *FileWriter) ensureFile() error {
	now := time.Now()
	var dateFormat string

	switch w.rotation {
	case "hourly":
		dateFormat = now.Format("2006-01-02-15")
	case "daily":
		dateFormat = now.Format("2006-01-02")
	case "size":
		dateFormat = now.Format("2006-01-02")
	default:
		dateFormat = now.Format("2006-01-02")
	}

	// Check if rotation needed (date changed)
	if w.currentFile != nil && w.currentDate != dateFormat {
		if err := w.rotateFile(); err != nil {
			return err
		}
	}

	// Open file if not already open
	if w.currentFile == nil {
		filename := filepath.Join(w.directory, fmt.Sprintf("audit-%s.jsonl", dateFormat))
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to open audit log file: %w", err)
		}

		// Get current file size
		stat, err := f.Stat()
		if err != nil {
			f.Close()
			return fmt.Errorf("failed to stat audit log file: %w", err)
		}

		w.currentFile = f
		w.currentSize = stat.Size()
		w.currentDate = dateFormat
	}

	return nil
}

// rotateFile closes the current file and prepares for a new one.
func (w *FileWriter) rotateFile() error {
	if w.currentFile != nil {
		if err := w.currentFile.Close(); err != nil {
			return fmt.Errorf("failed to close audit log file: %w", err)
		}
		w.currentFile = nil
		w.currentSize = 0
	}
	return nil
}

// Shutdown flushes all pending events and closes the file.
func (w *FileWriter) Shutdown(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.currentFile != nil {
		if err := w.currentFile.Sync(); err != nil {
			w.log.Error("Failed to sync audit log file on shutdown",
				"error", err)
		}
		if err := w.currentFile.Close(); err != nil {
			w.log.Error("Failed to close audit log file on shutdown",
				"error", err)
		}
		w.currentFile = nil
	}

	w.log.Info("FileWriter shutdown complete")
	return nil
}

// invalidateHealthCache forces the next Health() call to perform a real check.
// Called when WriteBatch encounters I/O errors (mu must already be held).
func (w *FileWriter) invalidateHealthCache() {
	w.lastHealthAt = time.Time{}
}

// Health checks file system availability and writability.
// Results are cached for 30 seconds to avoid repeated disk I/O on frequent health checks.
// The cache is invalidated on write errors so failures are reported promptly.
func (w *FileWriter) Health(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	const healthCacheTTL = 30 * time.Second
	if time.Since(w.lastHealthAt) < healthCacheTTL {
		return w.lastHealthErr
	}

	// Check directory exists and is writable
	testFile := filepath.Join(w.directory, ".health_check")
	f, err := os.Create(testFile)
	if err != nil {
		w.lastHealthAt = time.Now()
		w.lastHealthErr = fmt.Errorf("file directory not writable: %w", err)
		return w.lastHealthErr
	}
	f.Close()
	os.Remove(testFile)

	w.lastHealthAt = time.Now()
	w.lastHealthErr = nil
	return nil
}

// Name returns the unique identifier for this writer.
func (w *FileWriter) Name() string {
	return "file"
}

var _ AuditWriter = (*FileWriter)(nil)
