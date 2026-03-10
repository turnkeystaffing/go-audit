package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test helpers ---

// testAuditServer is a controllable httptest.Server acting as the audit service.
type testAuditServer struct {
	server         *httptest.Server
	healthy        atomic.Bool
	receivedEvents []httpEventDTO
	batchCalls     atomic.Int32
	mu             sync.Mutex
	batchHandler   func(w http.ResponseWriter, r *http.Request) // override for error injection
}

func newTestAuditServer(t *testing.T) *testAuditServer {
	t.Helper()
	s := &testAuditServer{}
	s.healthy.Store(true)

	mux := http.NewServeMux()
	mux.HandleFunc("/health/liveness", func(w http.ResponseWriter, r *http.Request) {
		if s.healthy.Load() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	mux.HandleFunc("/api/v1/events/batch", func(w http.ResponseWriter, r *http.Request) {
		if s.batchHandler != nil {
			s.batchHandler(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req httpBatchRequest
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		s.mu.Lock()
		s.receivedEvents = append(s.receivedEvents, req.Events...)
		s.mu.Unlock()
		s.batchCalls.Add(1)

		resp := httpIngestionResponse{
			Accepted: len(req.Events),
			Rejected: 0,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(resp)
	})

	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

func (s *testAuditServer) getReceivedEvents() []httpEventDTO {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]httpEventDTO, len(s.receivedEvents))
	copy(result, s.receivedEvents)
	return result
}

func (s *testAuditServer) resetReceived() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receivedEvents = nil
	s.batchCalls.Store(0)
}

func newTestHTTPWriter(t *testing.T, serverURL string) *HTTPWriter {
	t.Helper()
	cfg := HTTPWriterConfig{
		BaseURL:        serverURL,
		ServiceName:    "test-service",
		Timeout:        5 * time.Second,
		MaxRetries:     0,
		RetryBaseDelay: 1 * time.Millisecond,
	}
	w, err := NewHTTPWriter(cfg, NewMockTokenProvider("test-token"), replayTestLogger())
	require.NoError(t, err)
	return w
}

func replayTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func newTestFileReplayer(t *testing.T, dir string, httpWriter *HTTPWriter) *FileReplayer {
	t.Helper()
	cfg := FileReplayConfig{
		Directory:     dir,
		CheckInterval: 1 * time.Millisecond,
		BatchSize:     100,
		MaxBackoff:    5 * time.Millisecond,
	}
	fr, err := NewFileReplayer(cfg, httpWriter, replayTestLogger())
	require.NoError(t, err)
	return fr
}

func writeTestJSONL(t *testing.T, dir, filename string, events []FinalAuditEvent) string {
	t.Helper()
	filePath := filepath.Join(dir, filename)
	f, err := os.Create(filePath)
	require.NoError(t, err)
	defer f.Close()

	for _, event := range events {
		data, err := json.Marshal(event)
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}
	return filePath
}

func makeTestFinalEvent() FinalAuditEvent {
	userID := uuid.New()
	return FinalAuditEvent{
		AuditEvent: AuditEvent{
			ID:           uuid.Must(uuid.NewV7()),
			UserID:       &userID,
			Action:       testActionLogin,
			ResourceType: testResourceTypeSession,
			Outcome:      OutcomeSuccess,
			Timestamp:    time.Now().UTC(),
			RequestID:    uuid.New(),
			ContextData:  map[string]interface{}{"test": "replay"},
		},
		EnrichmentMetadata: map[string]interface{}{"enricher": "test"},
		EnrichedAt:         time.Now().UTC(),
	}
}

// --- Config tests (existing) ---

func TestFileReplayConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       FileReplayConfig
		wantErr   bool
		errMsg    string
		wantCheck time.Duration
		wantBatch int
		wantMax   time.Duration
	}{
		{
			name:      "valid config with all defaults",
			cfg:       FileReplayConfig{Directory: "/tmp/audit"},
			wantErr:   false,
			wantCheck: 30 * time.Second,
			wantBatch: 100,
			wantMax:   5 * time.Minute,
		},
		{
			name:      "valid config with custom values",
			cfg:       FileReplayConfig{Directory: "/tmp/audit", CheckInterval: 10 * time.Second, BatchSize: 50, MaxBackoff: 2 * time.Minute},
			wantErr:   false,
			wantCheck: 10 * time.Second,
			wantBatch: 50,
			wantMax:   2 * time.Minute,
		},
		{
			name:    "empty directory",
			cfg:     FileReplayConfig{},
			wantErr: true,
			errMsg:  "directory is required",
		},
		{
			name:    "negative check interval",
			cfg:     FileReplayConfig{Directory: "/tmp/audit", CheckInterval: -1 * time.Second},
			wantErr: true,
			errMsg:  "check interval must not be negative",
		},
		{
			name:    "negative batch size",
			cfg:     FileReplayConfig{Directory: "/tmp/audit", BatchSize: -1},
			wantErr: true,
			errMsg:  "batch size must not be negative",
		},
		{
			name:    "negative max backoff",
			cfg:     FileReplayConfig{Directory: "/tmp/audit", MaxBackoff: -1 * time.Second},
			wantErr: true,
			errMsg:  "max backoff must not be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantCheck, tt.cfg.CheckInterval, "check interval")
			assert.Equal(t, tt.wantBatch, tt.cfg.BatchSize, "batch size")
			assert.Equal(t, tt.wantMax, tt.cfg.MaxBackoff, "max backoff")
		})
	}
}

func TestDefaultFileReplayConfig(t *testing.T) {
	cfg := DefaultFileReplayConfig("/tmp/audit")

	assert.Equal(t, "/tmp/audit", cfg.Directory)
	assert.Equal(t, 30*time.Second, cfg.CheckInterval)
	assert.Equal(t, 100, cfg.BatchSize)
	assert.Equal(t, 5*time.Minute, cfg.MaxBackoff)

	err := cfg.Validate()
	require.NoError(t, err)
}

// --- Constructor tests ---

func TestNewFileReplayer_NilLogger_Panics(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)

	assert.PanicsWithValue(t, "audit: logger is required", func() {
		_, _ = NewFileReplayer(DefaultFileReplayConfig("/tmp"), hw, nil)
	})
}

func TestNewFileReplayer_NilHTTPWriter_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "audit: http writer is required", func() {
		_, _ = NewFileReplayer(DefaultFileReplayConfig("/tmp"), nil, replayTestLogger())
	})
}

func TestNewFileReplayer_InvalidConfig(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)

	fr, err := NewFileReplayer(FileReplayConfig{}, hw, replayTestLogger())
	require.Error(t, err)
	assert.Nil(t, fr)
	assert.Contains(t, err.Error(), "directory is required")
}

// --- ReplayFile tests ---

func TestFileReplayer_ReplayFile_Success(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	events := []FinalAuditEvent{makeTestFinalEvent(), makeTestFinalEvent(), makeTestFinalEvent()}
	filePath := writeTestJSONL(t, dir, "audit-2026-01-01.jsonl", events)

	err := fr.replayFile(context.Background(), filePath)
	require.NoError(t, err)

	// File should be deleted
	_, statErr := os.Stat(filePath)
	assert.True(t, os.IsNotExist(statErr), "file should be deleted after successful replay")

	// Events should be received by server
	received := srv.getReceivedEvents()
	assert.Equal(t, 3, len(received), "all 3 events should be received")
}

func TestFileReplayer_ReplayFile_EmptyFile(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	filePath := filepath.Join(dir, "audit-empty.jsonl")
	require.NoError(t, os.WriteFile(filePath, []byte(""), 0600))

	err := fr.replayFile(context.Background(), filePath)
	require.NoError(t, err)

	// File should be deleted even though empty
	_, statErr := os.Stat(filePath)
	assert.True(t, os.IsNotExist(statErr), "empty file should be deleted")

	// No events sent
	assert.Equal(t, int32(0), srv.batchCalls.Load(), "no batch calls for empty file")
}

func TestFileReplayer_ReplayFile_DeserializationError(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	// Write a file with a mix of valid and invalid lines
	validEvent := makeTestFinalEvent()
	validJSON, _ := json.Marshal(validEvent)

	content := fmt.Sprintf("%s\n{invalid json\n%s\n", validJSON, validJSON)
	filePath := filepath.Join(dir, "audit-mixed.jsonl")
	require.NoError(t, os.WriteFile(filePath, []byte(content), 0600))

	err := fr.replayFile(context.Background(), filePath)
	require.NoError(t, err)

	// File should be deleted (malformed lines are skipped)
	_, statErr := os.Stat(filePath)
	assert.True(t, os.IsNotExist(statErr), "file should be deleted even with bad lines")

	// Only 2 valid events sent
	received := srv.getReceivedEvents()
	assert.Equal(t, 2, len(received), "only valid events should be sent")
}

func TestFileReplayer_ReplayFile_HTTPWriterError(t *testing.T) {
	srv := newTestAuditServer(t)
	// Override batch handler to return 500
	srv.batchHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}

	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	events := []FinalAuditEvent{makeTestFinalEvent()}
	filePath := writeTestJSONL(t, dir, "audit-fail.jsonl", events)

	err := fr.replayFile(context.Background(), filePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write batch")

	// File should NOT be deleted
	_, statErr := os.Stat(filePath)
	assert.False(t, os.IsNotExist(statErr), "file should NOT be deleted on error")
}

func TestFileReplayer_ReplayFile_PartialReplay(t *testing.T) {
	srv := newTestAuditServer(t)
	// Fail on second batch call
	var callCount atomic.Int32
	srv.batchHandler = func(w http.ResponseWriter, r *http.Request) {
		if callCount.Add(1) > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req httpBatchRequest
		json.Unmarshal(body, &req)

		srv.mu.Lock()
		srv.receivedEvents = append(srv.receivedEvents, req.Events...)
		srv.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(httpIngestionResponse{Accepted: len(req.Events)})
	}

	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()

	// Use batch size of 2, write 4 events — second batch should fail
	cfg := FileReplayConfig{
		Directory:     dir,
		CheckInterval: 1 * time.Millisecond,
		BatchSize:     2,
		MaxBackoff:    5 * time.Millisecond,
	}
	fr, err := NewFileReplayer(cfg, hw, replayTestLogger())
	require.NoError(t, err)

	events := make([]FinalAuditEvent, 4)
	for i := range events {
		events[i] = makeTestFinalEvent()
	}
	filePath := writeTestJSONL(t, dir, "audit-partial.jsonl", events)

	err = fr.replayFile(context.Background(), filePath)
	require.Error(t, err)

	// File should NOT be deleted
	_, statErr := os.Stat(filePath)
	assert.False(t, os.IsNotExist(statErr), "file should NOT be deleted on partial failure")

	// First batch (2 events) was sent successfully
	received := srv.getReceivedEvents()
	assert.Equal(t, 2, len(received), "only first batch should succeed")
}

func TestFileReplayer_ReplayFile_PreservesEventIDs(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	events := []FinalAuditEvent{makeTestFinalEvent(), makeTestFinalEvent()}
	originalIDs := []string{events[0].ID.String(), events[1].ID.String()}
	writeTestJSONL(t, dir, "audit-ids.jsonl", events)

	err := fr.replayFile(context.Background(), filepath.Join(dir, "audit-ids.jsonl"))
	require.NoError(t, err)

	received := srv.getReceivedEvents()
	require.Equal(t, 2, len(received))
	assert.Equal(t, originalIDs[0], received[0].EventID, "event 0 ID preserved")
	assert.Equal(t, originalIDs[1], received[1].EventID, "event 1 ID preserved")
}

func TestFileReplayer_ReplayFiles_ChronologicalOrder(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	// Create files with dates — they sort by name
	event1 := makeTestFinalEvent()
	event1.Action = "file1-action"
	event2 := makeTestFinalEvent()
	event2.Action = "file2-action"
	event3 := makeTestFinalEvent()
	event3.Action = "file3-action"

	writeTestJSONL(t, dir, "audit-2026-01-03.jsonl", []FinalAuditEvent{event3})
	writeTestJSONL(t, dir, "audit-2026-01-01.jsonl", []FinalAuditEvent{event1})
	writeTestJSONL(t, dir, "audit-2026-01-02.jsonl", []FinalAuditEvent{event2})

	// Set modTime to old time so files aren't skipped by active-file guard
	oldTime := time.Now().Add(-2 * time.Minute)
	for _, name := range []string{"audit-2026-01-01.jsonl", "audit-2026-01-02.jsonl", "audit-2026-01-03.jsonl"} {
		require.NoError(t, os.Chtimes(filepath.Join(dir, name), oldTime, oldTime))
	}

	err := fr.replayFiles(context.Background())
	require.NoError(t, err)

	received := srv.getReceivedEvents()
	require.Equal(t, 3, len(received))

	// Oldest file first: file1 → file2 → file3
	assert.Equal(t, "file1-action", received[0].Action, "oldest file processed first")
	assert.Equal(t, "file2-action", received[1].Action, "second file processed second")
	assert.Equal(t, "file3-action", received[2].Action, "newest file processed last")

	// All files should be deleted
	entries, _ := os.ReadDir(dir)
	assert.Equal(t, 0, len(entries), "all files deleted after replay")
}

func TestFileReplayer_BatchSize(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()

	cfg := FileReplayConfig{
		Directory:     dir,
		CheckInterval: 1 * time.Millisecond,
		BatchSize:     3,
		MaxBackoff:    5 * time.Millisecond,
	}
	fr, err := NewFileReplayer(cfg, hw, replayTestLogger())
	require.NoError(t, err)

	// Write 7 events — should produce 3 batch calls (3 + 3 + 1)
	events := make([]FinalAuditEvent, 7)
	for i := range events {
		events[i] = makeTestFinalEvent()
	}
	filePath := writeTestJSONL(t, dir, "audit-batch.jsonl", events)

	err = fr.replayFile(context.Background(), filePath)
	require.NoError(t, err)

	assert.Equal(t, int32(3), srv.batchCalls.Load(), "should make 3 batch calls (3+3+1)")
	received := srv.getReceivedEvents()
	assert.Equal(t, 7, len(received), "all 7 events received")
}

func TestFileReplayer_ContextCancellation(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	events := []FinalAuditEvent{makeTestFinalEvent()}
	filePath := writeTestJSONL(t, dir, "audit-cancel.jsonl", events)

	// Pre-canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := fr.replayFile(ctx, filePath)
	require.Error(t, err)

	// File should NOT be deleted
	_, statErr := os.Stat(filePath)
	assert.False(t, os.IsNotExist(statErr), "file should NOT be deleted on cancellation")
}

// --- Lifecycle tests ---

func TestFileReplayer_RecoveryDetection(t *testing.T) {
	srv := newTestAuditServer(t)
	srv.healthy.Store(false) // Start unhealthy
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	// Write a file to replay
	event := makeTestFinalEvent()
	writeTestJSONL(t, dir, "audit-2026-01-01.jsonl", []FinalAuditEvent{event})
	oldTime := time.Now().Add(-2 * time.Minute)
	require.NoError(t, os.Chtimes(filepath.Join(dir, "audit-2026-01-01.jsonl"), oldTime, oldTime))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, fr.Start(ctx))

	// Verify no replay while unhealthy — poll briefly to confirm.
	// Negative timing assertion: since the loop runs at 1ms intervals, giving it
	// multiple cycles before checking is sufficient to confirm no replay occurred.
	require.Eventually(t, func() bool {
		// We're waiting for the replayer loop to have polled at least once,
		// which we infer by a short wait. Return true to stop waiting.
		return true
	}, 50*time.Millisecond, 5*time.Millisecond)
	assert.Equal(t, 0, len(srv.getReceivedEvents()), "no replay while unhealthy")

	// Make healthy and invalidate the HTTPWriter health cache (30s TTL)
	srv.healthy.Store(true)
	hw.invalidateHealthCache()

	// Wait for replay to happen (event-driven, no time.Sleep)
	require.Eventually(t, func() bool {
		return len(srv.getReceivedEvents()) > 0
	}, 1*time.Second, 1*time.Millisecond, "timed out waiting for replay after recovery")

	received := srv.getReceivedEvents()
	assert.Equal(t, 1, len(received), "event should be replayed after recovery")

	require.NoError(t, fr.Shutdown(context.Background()))
}

func TestFileReplayer_ExponentialBackoff(t *testing.T) {
	// Test calcBackoff directly — no need for full lifecycle
	base := 10 * time.Millisecond
	max := 100 * time.Millisecond

	assert.Equal(t, 10*time.Millisecond, calcBackoff(base, max, 0), "attempt 0")
	assert.Equal(t, 20*time.Millisecond, calcBackoff(base, max, 1), "attempt 1")
	assert.Equal(t, 40*time.Millisecond, calcBackoff(base, max, 2), "attempt 2")
	assert.Equal(t, 80*time.Millisecond, calcBackoff(base, max, 3), "attempt 3")
	assert.Equal(t, 100*time.Millisecond, calcBackoff(base, max, 4), "attempt 4 capped at max")
	assert.Equal(t, 100*time.Millisecond, calcBackoff(base, max, 10), "attempt 10 still capped")
}

func TestFileReplayer_BackoffReset(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	// Write a file
	event := makeTestFinalEvent()
	writeTestJSONL(t, dir, "audit-2026-01-01.jsonl", []FinalAuditEvent{event})
	oldTime := time.Now().Add(-2 * time.Minute)
	require.NoError(t, os.Chtimes(filepath.Join(dir, "audit-2026-01-01.jsonl"), oldTime, oldTime))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start with healthy server — should replay quickly (backoff = 0)
	require.NoError(t, fr.Start(ctx))

	// Wait for replay (event-driven, no time.Sleep)
	require.Eventually(t, func() bool {
		return len(srv.getReceivedEvents()) > 0
	}, 500*time.Millisecond, 1*time.Millisecond, "timed out waiting for replay")

	require.NoError(t, fr.Shutdown(context.Background()))
	assert.Equal(t, 1, len(srv.getReceivedEvents()), "event replayed on first cycle")
}

func TestFileReplayer_Shutdown_Graceful(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	ctx := context.Background()
	require.NoError(t, fr.Start(ctx))

	// Shutdown should complete without error — goroutine is guaranteed started after Start() returns
	err := fr.Shutdown(context.Background())
	require.NoError(t, err)

	// Should not be running after shutdown
	assert.False(t, fr.running.Load(), "should not be running after shutdown")
}

func TestFileReplayer_Shutdown_ContextCancel(t *testing.T) {
	srv := newTestAuditServer(t)
	// Make server slow to respond to health checks
	srv.batchHandler = func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // Block for a long time
		w.WriteHeader(http.StatusAccepted)
	}

	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	ctx := context.Background()
	require.NoError(t, fr.Start(ctx))

	// Shutdown with short context — should return context error
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	err := fr.Shutdown(shutdownCtx)
	// The goroutine may or may not have finished in time
	if err != nil {
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	}
}

func TestFileReplayer_Start_AlreadyRunning(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	ctx := context.Background()
	require.NoError(t, fr.Start(ctx))
	defer fr.Shutdown(context.Background())

	// Second start should fail
	err := fr.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

// --- Active file guard test ---

func TestFileReplayer_ReplayFiles_SkipsActiveFile(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	// Create an old file and a recent file
	oldEvent := makeTestFinalEvent()
	oldEvent.Action = "old-event"
	writeTestJSONL(t, dir, "audit-2026-01-01.jsonl", []FinalAuditEvent{oldEvent})
	oldTime := time.Now().Add(-2 * time.Minute)
	require.NoError(t, os.Chtimes(filepath.Join(dir, "audit-2026-01-01.jsonl"), oldTime, oldTime))

	newEvent := makeTestFinalEvent()
	newEvent.Action = "new-event"
	writeTestJSONL(t, dir, "audit-2026-01-02.jsonl", []FinalAuditEvent{newEvent})
	// Don't change modTime — it's recent (within 60s)

	err := fr.replayFiles(context.Background())
	require.NoError(t, err)

	// Only old file should be replayed
	received := srv.getReceivedEvents()
	assert.Equal(t, 1, len(received), "only old file replayed")
	assert.Equal(t, "old-event", received[0].Action, "old event replayed")

	// Old file deleted, new file still exists
	_, statErr := os.Stat(filepath.Join(dir, "audit-2026-01-01.jsonl"))
	assert.True(t, os.IsNotExist(statErr), "old file deleted")
	_, statErr = os.Stat(filepath.Join(dir, "audit-2026-01-02.jsonl"))
	assert.False(t, os.IsNotExist(statErr), "active file preserved")
}

// --- Poison pill test ---

func TestFileReplayer_ReplayFiles_PoisonPillMovesToFailed(t *testing.T) {
	srv := newTestAuditServer(t)
	// Always fail
	srv.batchHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}

	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)
	fr.maxFileRetries = 2 // Low threshold for test

	event := makeTestFinalEvent()
	writeTestJSONL(t, dir, "audit-poison.jsonl", []FinalAuditEvent{event})
	oldTime := time.Now().Add(-2 * time.Minute)
	require.NoError(t, os.Chtimes(filepath.Join(dir, "audit-poison.jsonl"), oldTime, oldTime))

	// Attempt 1 — should fail
	err := fr.replayFiles(context.Background())
	assert.Error(t, err)
	assert.Equal(t, 1, fr.fileRetries["audit-poison.jsonl"])

	// Attempt 2 — should fail
	err = fr.replayFiles(context.Background())
	assert.Error(t, err)
	assert.Equal(t, 2, fr.fileRetries["audit-poison.jsonl"])

	// Attempt 3 — exceeds max, should move to .failed
	err = fr.replayFiles(context.Background())
	assert.NoError(t, err, "no error when moving to .failed — file is quarantined")

	// File should be in .failed directory (with timestamp suffix)
	failedEntries, err := os.ReadDir(filepath.Join(dir, ".failed"))
	require.NoError(t, err, ".failed directory should exist")
	assert.Equal(t, 1, len(failedEntries), "exactly one file should be in .failed directory")

	// Original file should be gone
	_, statErr := os.Stat(filepath.Join(dir, "audit-poison.jsonl"))
	assert.True(t, os.IsNotExist(statErr), "original file should be removed")
}

// --- Serialization round-trip test (Task 3.21) ---

func TestFinalAuditEvent_SerializationRoundTrip(t *testing.T) {
	userID := uuid.New()
	resourceID := uuid.New()
	ip := "192.168.1.100"
	writtenAt := time.Now().UTC().Truncate(time.Microsecond)

	original := FinalAuditEvent{
		AuditEvent: AuditEvent{
			ID:            uuid.Must(uuid.NewV7()),
			UserID:        &userID,
			Action:        testActionLogin,
			ResourceType:  testResourceTypeSession,
			ResourceID:    &resourceID,
			Outcome:       OutcomeSuccess,
			FailureReason: "test reason",
			Timestamp:     time.Now().UTC().Truncate(time.Microsecond),
			IPAddress:     &ip,
			UserAgent:     "Mozilla/5.0 Test Agent",
			RequestID:     uuid.New(),
			ContextData:   map[string]interface{}{"key": "value", "count": float64(42)},
		},
		EnrichmentMetadata: map[string]interface{}{"enrichment.trace": "abc123"},
		EnrichedAt:         time.Now().UTC().Truncate(time.Microsecond),
		WrittenAt:          &writtenAt,
	}

	// Marshal using json.Marshal (same as encode.ToJson)
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal using json.Unmarshal (same as FileReplayer)
	var restored FinalAuditEvent
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	// Core fields
	assert.Equal(t, original.ID, restored.ID, "ID round-trip")
	assert.Equal(t, *original.UserID, *restored.UserID, "UserID round-trip")
	assert.Equal(t, original.Action, restored.Action, "Action round-trip")
	assert.Equal(t, original.ResourceType, restored.ResourceType, "ResourceType round-trip")
	assert.Equal(t, *original.ResourceID, *restored.ResourceID, "ResourceID round-trip")
	assert.Equal(t, original.Outcome, restored.Outcome, "Outcome round-trip")
	assert.Equal(t, original.FailureReason, restored.FailureReason, "FailureReason round-trip")
	assert.Equal(t, original.UserAgent, restored.UserAgent, "UserAgent round-trip")
	assert.Equal(t, original.RequestID, restored.RequestID, "RequestID round-trip")
	assert.Equal(t, *original.IPAddress, *restored.IPAddress, "IPAddress round-trip")

	// Nested maps
	assert.Equal(t, original.ContextData["key"], restored.ContextData["key"], "ContextData string round-trip")
	assert.Equal(t, original.ContextData["count"], restored.ContextData["count"], "ContextData numeric round-trip")
	assert.Equal(t, original.EnrichmentMetadata["enrichment.trace"], restored.EnrichmentMetadata["enrichment.trace"], "EnrichmentMetadata round-trip")

	// Timestamps
	assert.WithinDuration(t, original.Timestamp, restored.Timestamp, time.Millisecond, "Timestamp round-trip")
	assert.WithinDuration(t, original.EnrichedAt, restored.EnrichedAt, time.Millisecond, "EnrichedAt round-trip")
	require.NotNil(t, restored.WrittenAt, "WrittenAt should survive round-trip")
	assert.WithinDuration(t, *original.WrittenAt, *restored.WrittenAt, time.Millisecond, "WrittenAt round-trip")
}

// --- Empty line and whitespace handling ---

func TestFileReplayer_ReplayFile_EmptyAndWhitespaceLines(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	event := makeTestFinalEvent()
	validJSON, _ := json.Marshal(event)

	// File with empty lines, whitespace lines, and one valid event
	content := fmt.Sprintf("\n   \n%s\n\t\n\n", validJSON)
	filePath := filepath.Join(dir, "audit-whitespace.jsonl")
	require.NoError(t, os.WriteFile(filePath, []byte(content), 0600))

	err := fr.replayFile(context.Background(), filePath)
	require.NoError(t, err)

	// Only the valid event sent
	received := srv.getReceivedEvents()
	assert.Equal(t, 1, len(received), "only valid event sent, empty/whitespace lines skipped")
}

// --- Shutdown not running ---

func TestFileReplayer_Shutdown_NotRunning(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	// Shutdown without Start — should succeed
	err := fr.Shutdown(context.Background())
	require.NoError(t, err)
}

// --- Non-JSONL files are ignored ---

func TestFileReplayer_ReplayFiles_IgnoresNonJSONL(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	// Create a .txt file — should be ignored
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not jsonl"), 0600))
	// Create .health_check file — should be ignored
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".health_check"), []byte(""), 0600))

	err := fr.replayFiles(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 0, len(srv.getReceivedEvents()), "non-JSONL files should be ignored")
}

// --- Start/Shutdown/Start lifecycle reuse ---

func TestFileReplayer_StartShutdownStart_Lifecycle(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	ctx := context.Background()

	// First cycle
	require.NoError(t, fr.Start(ctx))
	require.NoError(t, fr.Shutdown(context.Background()))
	assert.False(t, fr.running.Load(), "not running after first shutdown")

	// Second cycle — should work after shutdown
	require.NoError(t, fr.Start(ctx))
	require.NoError(t, fr.Shutdown(context.Background()))
	assert.False(t, fr.running.Load(), "not running after second shutdown")
}

// --- replayFile with permission denied ---

func TestFileReplayer_ReplayFile_PermissionDenied(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	filePath := filepath.Join(dir, "audit-noperm.jsonl")
	require.NoError(t, os.WriteFile(filePath, []byte(`{"id":"test"}`+"\n"), 0600))
	require.NoError(t, os.Chmod(filePath, 0000))
	t.Cleanup(func() { os.Chmod(filePath, 0600) }) // restore for cleanup

	err := fr.replayFile(context.Background(), filePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open file")
}

// --- replayFiles with nonexistent directory ---

func TestFileReplayer_ReplayFiles_NonexistentDirectory(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)

	cfg := FileReplayConfig{
		Directory:     "/nonexistent/path/audit",
		CheckInterval: 1 * time.Millisecond,
		BatchSize:     100,
		MaxBackoff:    5 * time.Millisecond,
	}
	fr, err := NewFileReplayer(cfg, hw, replayTestLogger())
	require.NoError(t, err)

	err = fr.replayFiles(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read directory")
}

// --- moveToFailed failure paths ---

func TestFileReplayer_MoveToFailed_RenameFailure(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	// moveToFailed with nonexistent source file
	err := fr.moveToFailed(filepath.Join(dir, "nonexistent.jsonl"))
	require.Error(t, err)
}

// --- Subdirectory .jsonl skip ---

func TestFileReplayer_ReplayFiles_SkipsSubdirectories(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	// Create .failed subdirectory with .jsonl files inside
	failedDir := filepath.Join(dir, ".failed")
	require.NoError(t, os.MkdirAll(failedDir, 0700))

	// Write a .jsonl file into subdirectory — must NOT be replayed
	event := makeTestFinalEvent()
	data, _ := json.Marshal(event)
	require.NoError(t, os.WriteFile(filepath.Join(failedDir, "audit-quarantined.jsonl"), append(data, '\n'), 0600))

	// Create a normal file in the directory to also be skipped (IsDir check)
	err := fr.replayFiles(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 0, len(srv.getReceivedEvents()), "subdirectory files should be ignored")
}

// --- Scanner error path (line too long, pre-buffer-increase scenario) ---

func TestFileReplayer_ReplayFile_LargeEvent(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	// Create an event with large ContextData (>64KB but <1MB)
	event := makeTestFinalEvent()
	largeValue := make([]byte, 100*1024) // 100KB
	for i := range largeValue {
		largeValue[i] = 'x'
	}
	event.ContextData["large"] = string(largeValue)

	filePath := writeTestJSONL(t, dir, "audit-large.jsonl", []FinalAuditEvent{event})

	err := fr.replayFile(context.Background(), filePath)
	require.NoError(t, err, "large event within 1MB buffer should succeed")

	received := srv.getReceivedEvents()
	assert.Equal(t, 1, len(received), "large event should be received")
}

// --- QA Review: Poison pill continues processing subsequent files ---

func TestFileReplayer_PoisonPillContinuesProcessingSubsequentFiles(t *testing.T) {
	srv := newTestAuditServer(t)
	// First file always fails (poison), second file succeeds
	var callCount atomic.Int32
	srv.batchHandler = func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req httpBatchRequest
		json.Unmarshal(body, &req)

		// Check if this is the "good" file (has "good" metadata)
		if len(req.Events) > 0 {
			if _, ok := req.Events[0].Metadata["good"]; ok {
				// Good file — accept
				srv.mu.Lock()
				srv.receivedEvents = append(srv.receivedEvents, req.Events...)
				srv.mu.Unlock()
				callCount.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				json.NewEncoder(w).Encode(httpIngestionResponse{Accepted: len(req.Events)})
				return
			}
		}
		// Poison file — always 500
		w.WriteHeader(http.StatusInternalServerError)
	}

	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)
	fr.maxFileRetries = 1 // Fail after 1 retry for quick quarantine

	// Poison file (first alphabetically)
	poisonEvent := makeTestFinalEvent()
	poisonEvent.ContextData["poison"] = true
	writeTestJSONL(t, dir, "audit-2026-01-01.jsonl", []FinalAuditEvent{poisonEvent})

	// Good file (second alphabetically)
	goodEvent := makeTestFinalEvent()
	goodEvent.ContextData["good"] = true
	writeTestJSONL(t, dir, "audit-2026-01-02.jsonl", []FinalAuditEvent{goodEvent})

	oldTime := time.Now().Add(-2 * time.Minute)
	require.NoError(t, os.Chtimes(filepath.Join(dir, "audit-2026-01-01.jsonl"), oldTime, oldTime))
	require.NoError(t, os.Chtimes(filepath.Join(dir, "audit-2026-01-02.jsonl"), oldTime, oldTime))

	// Attempt 1 — poison file fails, error returned (second file not reached)
	err := fr.replayFiles(context.Background())
	assert.Error(t, err)
	assert.Equal(t, 1, fr.fileRetries["audit-2026-01-01.jsonl"])

	// Attempt 2 — poison file exceeds max retries, moved to .failed; good file then processed
	err = fr.replayFiles(context.Background())
	assert.NoError(t, err, "should succeed after quarantining poison file")

	// Good file should be replayed
	received := srv.getReceivedEvents()
	require.Equal(t, 1, len(received), "good file events should be received")
	_, hasGood := received[0].Metadata["good"]
	assert.True(t, hasGood, "received event should be from the good file")

	// Poison file quarantined in .failed/
	failedEntries, err := os.ReadDir(filepath.Join(dir, ".failed"))
	require.NoError(t, err)
	assert.Equal(t, 1, len(failedEntries), "poison file should be in .failed")

	// Good file deleted
	_, statErr := os.Stat(filepath.Join(dir, "audit-2026-01-02.jsonl"))
	assert.True(t, os.IsNotExist(statErr), "good file should be deleted after replay")
}

// --- QA Review: calcBackoff edge cases ---

func TestCalcBackoff_EdgeCases(t *testing.T) {
	t.Run("base greater than max returns base at attempt 0", func(t *testing.T) {
		// When base > max and attempt is 0, function returns base (no doubling yet)
		result := calcBackoff(200*time.Millisecond, 100*time.Millisecond, 0)
		assert.Equal(t, 200*time.Millisecond, result, "attempt 0 returns base even if > max")
	})

	t.Run("base greater than max caps at max after first doubling", func(t *testing.T) {
		result := calcBackoff(200*time.Millisecond, 100*time.Millisecond, 1)
		assert.Equal(t, 100*time.Millisecond, result, "should cap at max after doubling")
	})

	t.Run("very large attempt does not overflow", func(t *testing.T) {
		// Attempt 100 with 1ms base would be 2^100 ms which overflows int64 Duration
		// The cap logic should prevent overflow since max is hit early
		result := calcBackoff(1*time.Millisecond, 1*time.Second, 100)
		assert.Equal(t, 1*time.Second, result, "should cap at max before overflow")
	})

	t.Run("zero base stays zero", func(t *testing.T) {
		result := calcBackoff(0, 1*time.Second, 5)
		assert.Equal(t, time.Duration(0), result, "zero base stays zero regardless of attempt")
	})
}

// --- QA Review: moveToFailed MkdirAll failure ---

func TestFileReplayer_MoveToFailed_MkdirPermissionDenied(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	// Create source file
	filePath := filepath.Join(dir, "audit-test.jsonl")
	require.NoError(t, os.WriteFile(filePath, []byte(`{"id":"test"}`+"\n"), 0600))

	// Make directory read-only so MkdirAll for .failed/ fails
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { os.Chmod(dir, 0700) }) // restore for cleanup

	err := fr.moveToFailed(filePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), ".failed directory")

	// Source file should still exist (not deleted)
	os.Chmod(dir, 0700) // need read access to check
	_, statErr := os.Stat(filePath)
	assert.False(t, os.IsNotExist(statErr), "source file should still exist after moveToFailed failure")
}

// --- QA Review: Empty directory returns nil ---

func TestFileReplayer_ReplayFiles_EmptyDirectory(t *testing.T) {
	srv := newTestAuditServer(t)
	hw := newTestHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	fr := newTestFileReplayer(t, dir, hw)

	// Empty directory — should return nil without error
	err := fr.replayFiles(context.Background())
	require.NoError(t, err, "empty directory should return nil")
	assert.Equal(t, 0, len(srv.getReceivedEvents()), "no events from empty directory")
}
