//go:build integration

package audit

import (
	"context"
	"encoding/json"
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// integrationAuditServer is a controllable httptest.Server for integration tests.
type integrationAuditServer struct {
	server         *httptest.Server
	healthy        atomic.Bool
	receivedEvents []httpEventDTO
	mu             sync.Mutex
}

func newIntegrationAuditServer(t *testing.T) *integrationAuditServer {
	t.Helper()
	s := &integrationAuditServer{}
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
		if !s.healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
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

		resp := httpIngestionResponse{Accepted: len(req.Events)}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(resp)
	})

	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

func (s *integrationAuditServer) getReceivedEvents() []httpEventDTO {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]httpEventDTO, len(s.receivedEvents))
	copy(result, s.receivedEvents)
	return result
}

func newIntegrationHTTPWriter(t *testing.T, serverURL string) *HTTPWriter {
	t.Helper()
	cfg := HTTPWriterConfig{
		BaseURL:        serverURL,
		ServiceName:    "test-service",
		Timeout:        5 * time.Second,
		MaxRetries:     1,
		RetryBaseDelay: 1 * time.Millisecond,
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	w, err := NewHTTPWriter(cfg, NewStaticTokenProvider("test-token"), log)
	require.NoError(t, err)
	return w
}

func TestFileReplayer_Integration_FullChain(t *testing.T) {
	srv := newIntegrationAuditServer(t)
	hw := newIntegrationHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Write real JSONL files using FileWriter
	fw, err := NewFileWriter(dir, "daily", 0, log)
	require.NoError(t, err)

	events := make([]FinalAuditEvent, 5)
	for i := range events {
		events[i] = makeTestFinalEvent()
		events[i].ContextData["seq"] = float64(i)
	}

	err = fw.WriteBatch(context.Background(), events)
	require.NoError(t, err)
	require.NoError(t, fw.Shutdown(context.Background()))

	// Verify JSONL file was created
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var jsonlFiles []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".jsonl" {
			jsonlFiles = append(jsonlFiles, e.Name())
		}
	}
	require.Equal(t, 1, len(jsonlFiles), "FileWriter should create exactly 1 JSONL file")

	// Set modTime to old so FileReplayer doesn't skip it
	oldTime := time.Now().Add(-2 * time.Minute)
	require.NoError(t, os.Chtimes(filepath.Join(dir, jsonlFiles[0]), oldTime, oldTime))

	// Create FileReplayer and replay
	cfg := FileReplayConfig{
		Directory:     dir,
		CheckInterval: 1 * time.Millisecond,
		BatchSize:     100,
		MaxBackoff:    5 * time.Millisecond,
	}
	fr, err := NewFileReplayer(cfg, hw, log)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, fr.Start(ctx))

	// Wait for replay to complete
	deadline := time.After(3 * time.Second)
	for {
		received := srv.getReceivedEvents()
		if len(received) >= 5 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for replay, got %d events", len(srv.getReceivedEvents()))
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	require.NoError(t, fr.Shutdown(context.Background()))

	// Verify all events received with original IDs
	received := srv.getReceivedEvents()
	require.Equal(t, 5, len(received))

	for i, recv := range received {
		assert.Equal(t, events[i].ID.String(), recv.EventID, "event %d ID preserved", i)
	}

	// File should be deleted
	entries, _ = os.ReadDir(dir)
	jsonlCount := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".jsonl" {
			jsonlCount++
		}
	}
	assert.Equal(t, 0, jsonlCount, "JSONL file should be deleted after replay")
}

func TestFileReplayer_Integration_MultipleFiles(t *testing.T) {
	srv := newIntegrationAuditServer(t)
	hw := newIntegrationHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Write multiple JSONL files manually (simulating different dates)
	for i, name := range []string{"audit-2026-01-01.jsonl", "audit-2026-01-02.jsonl", "audit-2026-01-03.jsonl"} {
		event := makeTestFinalEvent()
		event.ContextData["file_idx"] = float64(i)
		data, err := json.Marshal(event)
		require.NoError(t, err)

		filePath := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(filePath, append(data, '\n'), 0600))

		// Set old modTime
		oldTime := time.Now().Add(-time.Duration(3-i) * time.Minute)
		require.NoError(t, os.Chtimes(filePath, oldTime, oldTime))
	}

	cfg := FileReplayConfig{
		Directory:     dir,
		CheckInterval: 1 * time.Millisecond,
		BatchSize:     100,
		MaxBackoff:    5 * time.Millisecond,
	}
	fr, err := NewFileReplayer(cfg, hw, log)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, fr.Start(ctx))

	// Wait for all 3 events
	deadline := time.After(3 * time.Second)
	for {
		if len(srv.getReceivedEvents()) >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out, got %d events", len(srv.getReceivedEvents()))
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	require.NoError(t, fr.Shutdown(context.Background()))

	// Verify chronological order (file_idx 0, 1, 2)
	received := srv.getReceivedEvents()
	require.Equal(t, 3, len(received))
	for i, recv := range received {
		idx, ok := recv.Metadata["file_idx"]
		require.True(t, ok, "event %d should have file_idx metadata", i)
		assert.Equal(t, float64(i), idx, "event %d should be from file %d (chronological order)", i, i)
	}

	// All files should be deleted
	entries, _ := os.ReadDir(dir)
	jsonlCount := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".jsonl" {
			jsonlCount++
		}
	}
	assert.Equal(t, 0, jsonlCount, "all JSONL files cleaned up")
}

func TestFileReplayer_Integration_RecoveryAfterFailure(t *testing.T) {
	srv := newIntegrationAuditServer(t)
	srv.healthy.Store(false) // Start unhealthy
	hw := newIntegrationHTTPWriter(t, srv.server.URL)
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Write a JSONL file
	event := makeTestFinalEvent()
	data, _ := json.Marshal(event)
	filePath := filepath.Join(dir, "audit-2026-01-01.jsonl")
	require.NoError(t, os.WriteFile(filePath, append(data, '\n'), 0600))
	oldTime := time.Now().Add(-2 * time.Minute)
	require.NoError(t, os.Chtimes(filePath, oldTime, oldTime))

	cfg := FileReplayConfig{
		Directory:     dir,
		CheckInterval: 1 * time.Millisecond,
		BatchSize:     100,
		MaxBackoff:    5 * time.Millisecond,
	}
	fr, err := NewFileReplayer(cfg, hw, log)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, fr.Start(ctx))

	// Wait while unhealthy — no events should be received
	time.Sleep(30 * time.Millisecond)
	assert.Equal(t, 0, len(srv.getReceivedEvents()), "no events while server is down")

	// Bring server back up
	srv.healthy.Store(true)
	hw.invalidateHealthCache()

	// Wait for replay
	deadline := time.After(3 * time.Second)
	for {
		if len(srv.getReceivedEvents()) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for replay after recovery")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	require.NoError(t, fr.Shutdown(context.Background()))

	received := srv.getReceivedEvents()
	require.Equal(t, 1, len(received))
	assert.Equal(t, event.ID.String(), received[0].EventID, "original event ID preserved")

	// File should be cleaned up
	_, statErr := os.Stat(filePath)
	assert.True(t, os.IsNotExist(statErr), "file cleaned up after successful replay")
}
