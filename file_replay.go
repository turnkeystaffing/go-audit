package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// FileReplayConfig configures the FileReplayer for replaying buffered JSONL files via HTTPWriter.
// Per P3 (hardening): this config is component-specific, separate from AuditConfig (pipeline config).
type FileReplayConfig struct {
	Directory     string        // Directory to scan for JSONL files (must match FileWriter output)
	CheckInterval time.Duration // How often to check service health (default: 30s)
	BatchSize     int           // Events per HTTPWriter.WriteBatch call (default: 100)
	MaxBackoff    time.Duration // Maximum backoff for recovery polling (default: 5m)
}

// DefaultFileReplayConfig returns a FileReplayConfig with sensible defaults.
// Directory must be set by the caller.
func DefaultFileReplayConfig(directory string) FileReplayConfig {
	return FileReplayConfig{
		Directory:     directory,
		CheckInterval: 30 * time.Second,
		BatchSize:     100,
		MaxBackoff:    5 * time.Minute,
	}
}

// Validate checks the FileReplayConfig and applies defaults for zero values.
func (c *FileReplayConfig) Validate() error {
	if c.Directory == "" {
		return fmt.Errorf("file replayer: directory is required")
	}

	if c.CheckInterval < 0 {
		return fmt.Errorf("file replayer: check interval must not be negative")
	}
	if c.CheckInterval == 0 {
		c.CheckInterval = 30 * time.Second
	}

	if c.BatchSize < 0 {
		return fmt.Errorf("file replayer: batch size must not be negative")
	}
	if c.BatchSize == 0 {
		c.BatchSize = 100
	}

	if c.MaxBackoff < 0 {
		return fmt.Errorf("file replayer: max backoff must not be negative")
	}
	if c.MaxBackoff == 0 {
		c.MaxBackoff = 5 * time.Minute
	}

	return nil
}

// calcBackoff computes exponential backoff: base * 2^attempt, capped at max.
// Same algorithm as HTTPWriter.backoffDelay().
func calcBackoff(base, max time.Duration, attempt int) time.Duration {
	delay := base
	for i := 0; i < attempt; i++ {
		delay *= 2
		if delay > max {
			return max
		}
	}
	return delay
}

// FileReplayer is a background goroutine that reads JSONL files written by FileWriter
// and replays them via HTTPWriter when the audit service recovers.
// It does NOT implement AuditWriter — it is a lifecycle component with Start()/Shutdown().
type FileReplayer struct {
	httpWriter     *HTTPWriter
	directory      string
	checkInterval  time.Duration
	batchSize      int
	maxBackoff     time.Duration
	maxFileRetries int // default: 10 — poison pill prevention
	log            *slog.Logger

	stopCh      chan struct{}
	doneCh      chan struct{}
	running     atomic.Bool
	fileRetries map[string]int // in-memory retry counter per filename
}

const defaultMaxFileRetries = 10

// NewFileReplayer creates a new FileReplayer that replays buffered JSONL files via HTTPWriter.
func NewFileReplayer(cfg FileReplayConfig, httpWriter *HTTPWriter, log *slog.Logger) (*FileReplayer, error) {
	if log == nil {
		panic("audit: logger is required")
	}
	if httpWriter == nil {
		panic("audit: http writer is required")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &FileReplayer{
		httpWriter:     httpWriter,
		directory:      cfg.Directory,
		checkInterval:  cfg.CheckInterval,
		batchSize:      cfg.BatchSize,
		maxBackoff:     cfg.MaxBackoff,
		maxFileRetries: defaultMaxFileRetries,
		log:            log,
		fileRetries:    make(map[string]int),
	}, nil
}

// Start begins the background replay goroutine.
func (fr *FileReplayer) Start(ctx context.Context) error {
	if !fr.running.CompareAndSwap(false, true) {
		return fmt.Errorf("file replayer: already running")
	}

	fr.stopCh = make(chan struct{})
	fr.doneCh = make(chan struct{})

	go fr.runLoop(ctx)

	fr.log.Info("file replayer started",
		"directory", fr.directory,
		"check_interval", fr.checkInterval,
		"batch_size", fr.batchSize)

	return nil
}

// runLoop is the background goroutine that polls HTTPWriter health and replays files on recovery.
func (fr *FileReplayer) runLoop(ctx context.Context) {
	defer close(fr.doneCh)
	defer func() {
		if recovered := recover(); recovered != nil {
			fr.log.Error("file replayer: goroutine panicked",
				"panic", recovered,
				"stack", string(debug.Stack()))
		}
	}()

	attempt := 0

	for {
		delay := calcBackoff(fr.checkInterval, fr.maxBackoff, attempt)

		timer := time.NewTimer(delay)
		select {
		case <-fr.stopCh:
			timer.Stop()
			fr.log.Info("file replayer: stop signal received")
			return
		case <-ctx.Done():
			timer.Stop()
			fr.log.Info("file replayer: context canceled")
			return
		case <-timer.C:
		}

		// Check health — note: HTTPWriter.Health() caches results for 30s.
		// Recovery detection latency = backoff_delay + up to 30s cache staleness.
		// Cache is invalidated on WriteBatch failures, so normal operation is unaffected.
		if err := fr.httpWriter.Health(ctx); err != nil {
			attempt++
			fr.log.Debug("file replayer: service unhealthy, backing off",
				"attempt", attempt,
				"next_delay", calcBackoff(fr.checkInterval, fr.maxBackoff, attempt))
			continue
		}

		// Service healthy — attempt replay
		if err := fr.replayFiles(ctx); err != nil {
			attempt++
			fr.log.Warn("file replayer: replay failed, backing off",
				"error", err,
				"attempt", attempt)
			continue
		}

		// Success — reset backoff
		attempt = 0
	}
}

// replayFiles scans the directory for JSONL files and replays them in chronological order.
func (fr *FileReplayer) replayFiles(ctx context.Context) error {
	entries, err := os.ReadDir(fr.directory)
	if err != nil {
		return fmt.Errorf("file replayer: read directory: %w", err)
	}

	// Filter and sort JSONL files chronologically (oldest first by name)
	type fileEntry struct {
		name    string
		modTime time.Time
	}
	var files []fileEntry

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			fr.log.Warn("file replayer: stat file failed",
				"file", entry.Name(),
				"error", err)
			continue
		}

		files = append(files, fileEntry{
			name:    entry.Name(),
			modTime: info.ModTime(),
		})
	}

	// Sort by name (includes date, so oldest first)
	sort.Slice(files, func(i, j int) bool {
		return files[i].name < files[j].name
	})

	now := time.Now()
	for _, f := range files {
		// Active file guard: skip files modified within 60 seconds (G17)
		if now.Sub(f.modTime) < 60*time.Second {
			fr.log.Debug("file replayer: skipping active file",
				"file", f.name,
				"mod_time", f.modTime)
			continue
		}

		// Check context before processing each file
		if ctx.Err() != nil {
			return ctx.Err()
		}

		filePath := filepath.Join(fr.directory, f.name)

		// Poison pill check: skip files that exceeded max retries
		if fr.fileRetries[f.name] >= fr.maxFileRetries {
			fr.log.Error("file replayer: file exceeded max retries, moving to .failed",
				"file", f.name,
				"retries", fr.fileRetries[f.name])
			if err := fr.moveToFailed(filePath); err != nil {
				fr.log.Error("file replayer: failed to move file",
					"file", f.name,
					"error", err)
			}
			delete(fr.fileRetries, f.name)
			continue
		}

		if err := fr.replayFile(ctx, filePath); err != nil {
			fr.fileRetries[f.name]++
			fr.log.Warn("file replayer: file replay failed",
				"file", f.name,
				"error", err,
				"retry_count", fr.fileRetries[f.name])
			return err
		}

		// Successful replay — clear retry counter
		delete(fr.fileRetries, f.name)
	}

	return nil
}

// replayFile reads a single JSONL file, deserializes events, and sends them via HTTPWriter.
func (fr *FileReplayer) replayFile(ctx context.Context, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("file replayer: open file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1MB max line — matches HTTPWriter body limit
	var batch []FinalAuditEvent
	lineNum := 0
	totalEvents := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Deserialize using json.Unmarshal (NOT encode.FromJson — Design Decision #7, G6)
		var event FinalAuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			fr.log.Error("file replayer: malformed JSON line, skipping",
				"file", filepath.Base(filePath),
				"line", lineNum,
				"error", err)
			continue
		}

		batch = append(batch, event)
		totalEvents++

		// Send batch when full
		if len(batch) >= fr.batchSize {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := fr.httpWriter.WriteBatch(ctx, batch); err != nil {
				return fmt.Errorf("file replayer: write batch: %w", err)
			}
			fr.log.Debug("file replayer: batch replayed",
				"file", filepath.Base(filePath),
				"batch_size", len(batch))
			batch = batch[:0]
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("file replayer: scan file: %w", err)
	}

	// Send remaining events
	if len(batch) > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := fr.httpWriter.WriteBatch(ctx, batch); err != nil {
			return fmt.Errorf("file replayer: write batch: %w", err)
		}
		fr.log.Debug("file replayer: final batch replayed",
			"file", filepath.Base(filePath),
			"batch_size", len(batch))
	}

	// All events sent — delete file
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("file replayer: remove file: %w", err)
	}

	fr.log.Info("file replayer: file replayed and deleted",
		"file", filepath.Base(filePath),
		"events", totalEvents)

	return nil
}

// moveToFailed moves a file to a .failed subdirectory for poison pill quarantine.
// Note: MkdirAll uses 0700 for new directories. If .failed/ already exists with
// different permissions, MkdirAll succeeds without changing them. This is acceptable
// because the parent directory is also 0700, limiting exposure.
func (fr *FileReplayer) moveToFailed(filePath string) error {
	failedDir := filepath.Join(fr.directory, ".failed")
	if err := os.MkdirAll(failedDir, 0700); err != nil {
		return fmt.Errorf("file replayer: create .failed directory: %w", err)
	}

	// Append timestamp to avoid overwriting a previously-failed file with the same name
	base := filepath.Base(filePath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	dest := filepath.Join(failedDir, fmt.Sprintf("%s.%d%s", name, time.Now().UnixNano(), ext))
	return os.Rename(filePath, dest)
}

// Shutdown gracefully stops the FileReplayer, waiting for in-progress replay to complete.
// Uses CompareAndSwap for idempotent shutdown (same pattern as AuditRouter.Shutdown).
func (fr *FileReplayer) Shutdown(ctx context.Context) error {
	if !fr.running.CompareAndSwap(true, false) {
		return nil
	}

	close(fr.stopCh)

	select {
	case <-fr.doneCh:
	case <-ctx.Done():
		fr.log.Warn("file replayer: shutdown context expired")
		return ctx.Err()
	}

	fr.log.Info("file replayer: shutdown complete")
	return nil
}
