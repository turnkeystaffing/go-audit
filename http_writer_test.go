package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test helpers ---

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, nil))
}

func testHTTPWriterConfig(serverURL string) HTTPWriterConfig {
	return HTTPWriterConfig{
		BaseURL:        serverURL,
		ServiceName:    "test-service",
		Timeout:        5 * time.Second,
		MaxRetries:     2,
		RetryBaseDelay: 1 * time.Millisecond, // fast retries for tests
	}
}

func testFinalAuditEvent(t *testing.T) FinalAuditEvent {
	t.Helper()
	userID := uuid.New()
	resourceID := uuid.New()
	return FinalAuditEvent{
		AuditEvent: AuditEvent{
			ID:           uuid.New(),
			UserID:       &userID,
			Action:       "test.action." + t.Name(),
			ResourceType: "test_resource",
			ResourceID:   &resourceID,
			Outcome:      OutcomeSuccess,
			Timestamp:    time.Now().UTC(),
			RequestID:    uuid.New(),
			ContextData:  map[string]interface{}{"key": "value"},
		},
		EnrichmentMetadata: map[string]interface{}{"enrichment.trace": "abc"},
		EnrichedAt:         time.Now().UTC(),
	}
}

type errorTokenProvider struct {
	err error
}

func (p *errorTokenProvider) Token(_ context.Context) (string, error) {
	return "", p.err
}

// rotatingTokenProvider returns a different token for each call (QA: verify per-retry token refresh).
type rotatingTokenProvider struct {
	tokens []string
	idx    atomic.Int32
}

func (p *rotatingTokenProvider) Token(_ context.Context) (string, error) {
	i := int(p.idx.Add(1) - 1)
	if i >= len(p.tokens) {
		return p.tokens[len(p.tokens)-1], nil
	}
	return p.tokens[i], nil
}

// --- Constructor tests ---

func TestNewHTTPWriter_NilLogger_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "audit: logger is required", func() {
		_, _ = NewHTTPWriter(HTTPWriterConfig{}, NewMockTokenProvider("tok"), nil)
	})
}

func TestNewHTTPWriter_NilTokenProvider_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "audit: token provider is required", func() {
		_, _ = NewHTTPWriter(HTTPWriterConfig{}, nil, testLogger())
	})
}

func TestNewHTTPWriter_EmptyBaseURL_Error(t *testing.T) {
	cfg := HTTPWriterConfig{ServiceName: "svc"}
	writer, err := NewHTTPWriter(cfg, NewMockTokenProvider("tok"), testLogger())
	assert.Error(t, err)
	assert.Nil(t, writer)
	assert.Contains(t, err.Error(), "base URL is required")
}

func TestNewHTTPWriter_InvalidURL_Error(t *testing.T) {
	cfg := HTTPWriterConfig{BaseURL: "ftp://not-http.com", ServiceName: "svc"}
	writer, err := NewHTTPWriter(cfg, NewMockTokenProvider("tok"), testLogger())
	assert.Error(t, err)
	assert.Nil(t, writer)
	assert.Contains(t, err.Error(), "scheme must be http or https")
}

func TestNewHTTPWriter_ValidConfig_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testHTTPWriterConfig(srv.URL)
	writer, err := NewHTTPWriter(cfg, NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)
	assert.NotNil(t, writer)
	assert.Equal(t, "http", writer.Name())
}

// --- WriteBatch tests ---

func TestHTTPWriter_WriteBatch_Success(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/api/v1/events/batch")

		body, _ := io.ReadAll(r.Body)
		var req httpBatchRequest
		require.NoError(t, json.Unmarshal(body, &req))
		assert.Len(t, req.Events, 2)

		w.WriteHeader(http.StatusAccepted)
		resp := map[string]interface{}{"accepted": 2, "rejected": 0, "event_ids": []string{"a", "b"}, "errors": []interface{}{}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("test-token"), testLogger())
	require.NoError(t, err)

	events := []FinalAuditEvent{testFinalAuditEvent(t), testFinalAuditEvent(t)}
	err = writer.WriteBatch(context.Background(), events)

	assert.NoError(t, err)
	assert.Equal(t, int32(1), requestCount.Load())
}

func TestHTTPWriter_WriteBatch_PartialRejection_StillNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		resp := map[string]interface{}{"accepted": 1, "rejected": 1, "event_ids": []string{"a"}, "errors": []interface{}{map[string]interface{}{"index": 1, "reason": "invalid"}}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t), testFinalAuditEvent(t)})
	assert.NoError(t, err) // 202 = success regardless of rejections
}

func TestHTTPWriter_WriteBatch_ServerError_RetrySuccess(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := requestCount.Add(1)
		if count <= 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": 1, "rejected": 0, "event_ids": []string{"a"}, "errors": []interface{}{}})
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
	assert.NoError(t, err)
	assert.Equal(t, int32(2), requestCount.Load()) // 1 fail + 1 success
}

func TestHTTPWriter_WriteBatch_ServerError_RetryExhausted(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := testHTTPWriterConfig(srv.URL)
	cfg.MaxRetries = 2
	writer, err := NewHTTPWriter(cfg, NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
	assert.Equal(t, int32(3), requestCount.Load()) // 1 initial + 2 retries
}

func TestHTTPWriter_WriteBatch_RateLimited_429(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := requestCount.Add(1)
		if count <= 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": 1, "rejected": 0, "event_ids": []string{"a"}, "errors": []interface{}{}})
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
	assert.NoError(t, err)
	assert.Equal(t, int32(2), requestCount.Load())
}

func TestHTTPWriter_WriteBatch_ClientError_NoRetry(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 400")
	assert.Equal(t, int32(1), requestCount.Load()) // No retry for 4xx
}

func TestHTTPWriter_WriteBatch_Unauthorized_401(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 401")
	assert.Equal(t, int32(1), requestCount.Load()) // No retry for 401
}

func TestHTTPWriter_WriteBatch_NetworkError(t *testing.T) {
	// Connect to a port that's not listening
	cfg := HTTPWriterConfig{
		BaseURL:        "http://127.0.0.1:1", // port 1 — guaranteed to fail
		ServiceName:    "test-service",
		Timeout:        1 * time.Second,
		MaxRetries:     1,
		RetryBaseDelay: 1 * time.Millisecond,
	}
	writer, err := NewHTTPWriter(cfg, NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network error")
}

func TestHTTPWriter_WriteBatch_TokenError(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tokenErr := errors.New("token refresh failed")
	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), &errorTokenProvider{err: tokenErr}, testLogger())
	require.NoError(t, err)

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token error")
	assert.ErrorIs(t, err, tokenErr)
	assert.Equal(t, int32(0), requestCount.Load()) // No HTTP call on token error
}

func TestHTTPWriter_WriteBatch_EmptyBatch(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{})
	assert.NoError(t, err)
	assert.Equal(t, int32(0), requestCount.Load()) // No HTTP call for empty batch
}

func TestHTTPWriter_WriteBatch_ContextCancellation(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	err = writer.WriteBatch(ctx, []FinalAuditEvent{testFinalAuditEvent(t)})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "error should wrap context.Canceled")
}

func TestHTTPWriter_WriteBatch_WireFormat(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": 1, "rejected": 0, "event_ids": []string{"a"}, "errors": []interface{}{}})
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	event := testFinalAuditEvent(t)
	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{event})
	require.NoError(t, err)

	// Verify wire format
	var req httpBatchRequest
	require.NoError(t, json.Unmarshal(receivedBody, &req))
	require.Len(t, req.Events, 1)

	dto := req.Events[0]
	assert.Equal(t, event.ID.String(), dto.EventID)
	assert.Equal(t, "test-service", dto.Service)
	assert.Equal(t, event.Action, dto.Action)
	assert.Equal(t, event.UserID.String(), dto.Actor)
	assert.Equal(t, event.ResourceType, dto.Resource.Type)
	assert.Equal(t, event.ResourceID.String(), dto.Resource.ID)
	assert.Equal(t, event.Outcome, dto.Outcome)
	assert.Equal(t, event.Timestamp.Format(time.RFC3339Nano), dto.Timestamp)
	assert.Equal(t, "value", dto.Metadata["key"])
}

func TestHTTPWriter_WriteBatch_BearerToken(t *testing.T) {
	expectedToken := "secret-bearer-token-" + t.Name()
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": 1, "rejected": 0, "event_ids": []string{"a"}, "errors": []interface{}{}})
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider(expectedToken), testLogger())
	require.NoError(t, err)

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
	require.NoError(t, err)

	assert.Equal(t, "Bearer "+expectedToken, receivedAuth)
}

func TestHTTPWriter_WriteBatch_NilUserID(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": 1, "rejected": 0, "event_ids": []string{"a"}, "errors": []interface{}{}})
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	event := testFinalAuditEvent(t)
	event.UserID = nil // nil actor
	event.ResourceID = nil

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{event})
	require.NoError(t, err)

	var req httpBatchRequest
	require.NoError(t, json.Unmarshal(receivedBody, &req))
	assert.Equal(t, "", req.Events[0].Actor)
	assert.Equal(t, "", req.Events[0].Resource.ID)
}

// --- Health tests ---

func TestHTTPWriter_Health_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/liveness" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"status":"healthy"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	err = writer.Health(context.Background())
	assert.NoError(t, err)
}

func TestHTTPWriter_Health_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/liveness" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	err = writer.Health(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 503")
}

func TestHTTPWriter_Health_Cache(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/liveness" {
			requestCount.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	// First call — hits server
	err = writer.Health(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, int32(1), requestCount.Load())

	// Second call within 30s — cached
	err = writer.Health(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, int32(1), requestCount.Load()) // still 1 — cached
}

func TestHTTPWriter_Health_CacheInvalidation(t *testing.T) {
	var healthCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/liveness" {
			healthCount.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		// Batch endpoint returns 400 to trigger cache invalidation
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	// Prime health cache
	err = writer.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(1), healthCount.Load())

	// Trigger WriteBatch failure → invalidates health cache
	_ = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})

	// Next Health call should bypass cache
	err = writer.Health(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, int32(2), healthCount.Load()) // cache was invalidated
}

// --- Other tests ---

func TestHTTPWriter_Shutdown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": 1, "rejected": 0, "event_ids": []string{"a"}, "errors": []interface{}{}})
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	err = writer.Shutdown(context.Background())
	assert.NoError(t, err)

	// Writer should remain functional after shutdown (per AuditWriter contract)
	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
	assert.NoError(t, err)
}

func TestHTTPWriter_Name(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	assert.Equal(t, "http", writer.Name())
}

func TestHTTPWriter_ConcurrentWriteBatchAndHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/liveness" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": 1, "rejected": 0, "event_ids": []string{"a"}, "errors": []interface{}{}})
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	const goroutines = 10
	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 5; j++ {
				_ = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
				_ = writer.Health(context.Background())
			}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

func TestHTTPWriter_WriteBatch_WireFormat_FailureReason(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": 1, "rejected": 0, "event_ids": []string{"a"}, "errors": []interface{}{}})
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	event := testFinalAuditEvent(t)
	event.Outcome = OutcomeFailure
	event.FailureReason = "invalid_credentials"

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{event})
	require.NoError(t, err)

	var req httpBatchRequest
	require.NoError(t, json.Unmarshal(receivedBody, &req))
	require.Len(t, req.Events, 1)

	dto := req.Events[0]
	assert.Equal(t, OutcomeFailure, dto.Outcome)
	assert.Equal(t, "invalid_credentials", dto.FailureReason)
}

func TestHTTPWriter_WriteBatch_RetryAfterHonored(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := requestCount.Add(1)
		if count <= 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": 1, "rejected": 0, "event_ids": []string{"a"}, "errors": []interface{}{}})
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	start := time.Now()
	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
	elapsed := time.Since(start)

	assert.NoError(t, err)
	assert.Equal(t, int32(2), requestCount.Load())
	// Retry-After: 1 means 1 second delay — verify the delay was meaningful
	assert.GreaterOrEqual(t, elapsed.Milliseconds(), int64(900), "should honor Retry-After delay")
}

func TestHTTPWriter_BackoffDelay_ExponentialWithCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(HTTPWriterConfig{
		BaseURL:        srv.URL,
		ServiceName:    "test",
		Timeout:        5 * time.Second,
		MaxRetries:     0,
		RetryBaseDelay: 100 * time.Millisecond,
	}, NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	// Exponential progression: 100ms -> 200ms -> 400ms -> 800ms -> 1600ms -> 3200ms -> 5000ms (cap)
	assert.Equal(t, 100*time.Millisecond, writer.backoffDelay(0))
	assert.Equal(t, 200*time.Millisecond, writer.backoffDelay(1))
	assert.Equal(t, 400*time.Millisecond, writer.backoffDelay(2))
	assert.Equal(t, 800*time.Millisecond, writer.backoffDelay(3))
	assert.Equal(t, 1600*time.Millisecond, writer.backoffDelay(4))
	assert.Equal(t, 3200*time.Millisecond, writer.backoffDelay(5))
	assert.Equal(t, maxRetryBackoff, writer.backoffDelay(6))  // capped
	assert.Equal(t, maxRetryBackoff, writer.backoffDelay(10)) // still capped
}

func TestHTTPWriter_RetryDelay_RetryAfterCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(HTTPWriterConfig{
		BaseURL:        srv.URL,
		ServiceName:    "test",
		Timeout:        5 * time.Second,
		MaxRetries:     0,
		RetryBaseDelay: 100 * time.Millisecond,
	}, NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	// Retry-After within cap → honored
	err1 := &retryableError{err: fmt.Errorf("429"), retryAfter: 2 * time.Second}
	assert.Equal(t, 2*time.Second, writer.retryDelay(err1, 0))

	// Retry-After exceeds cap → capped at maxRetryAfter
	err2 := &retryableError{err: fmt.Errorf("429"), retryAfter: 3600 * time.Second}
	assert.Equal(t, maxRetryAfter, writer.retryDelay(err2, 0))

	// No retryAfter → falls back to backoff
	err3 := &retryableError{err: fmt.Errorf("500")}
	assert.Equal(t, 100*time.Millisecond, writer.retryDelay(err3, 0))
	assert.Equal(t, 200*time.Millisecond, writer.retryDelay(err3, 1))

	// Non-retryable error → falls back to backoff
	err4 := fmt.Errorf("plain error")
	assert.Equal(t, 100*time.Millisecond, writer.retryDelay(err4, 0))
}

func TestHTTPWriter_WriteBatch_ContextCancelDuringRetry(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := requestCount.Add(1)
		if count <= 1 {
			w.WriteHeader(http.StatusInternalServerError) // trigger retry
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	cfg := testHTTPWriterConfig(srv.URL)
	cfg.MaxRetries = 3
	cfg.RetryBaseDelay = 5 * time.Second // long delay so context cancel fires during wait
	writer, err := NewHTTPWriter(cfg, NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = writer.WriteBatch(ctx, []FinalAuditEvent{testFinalAuditEvent(t)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context")
	assert.Equal(t, int32(1), requestCount.Load()) // only 1 request before cancel during retry wait
}

func TestHTTPWriter_WriteBatch_429_NoRetryAfterHeader(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := requestCount.Add(1)
		if count <= 1 {
			w.WriteHeader(http.StatusTooManyRequests) // no Retry-After header
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": 1, "rejected": 0, "event_ids": []string{"a"}, "errors": []interface{}{}})
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
	assert.NoError(t, err)
	assert.Equal(t, int32(2), requestCount.Load()) // retried with backoff
}

func TestHTTPWriter_WriteBatch_429_NonNumericRetryAfter(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := requestCount.Add(1)
		if count <= 1 {
			w.Header().Set("Retry-After", "not-a-number")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": 1, "rejected": 0, "event_ids": []string{"a"}, "errors": []interface{}{}})
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
	assert.NoError(t, err)
	assert.Equal(t, int32(2), requestCount.Load()) // retried with backoff (non-numeric ignored)
}

func TestHTTPWriter_WriteBatch_NilContextData(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": 1, "rejected": 0, "event_ids": []string{"a"}, "errors": []interface{}{}})
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	event := testFinalAuditEvent(t)
	event.ContextData = nil // no metadata

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{event})
	require.NoError(t, err)

	var req httpBatchRequest
	require.NoError(t, json.Unmarshal(receivedBody, &req))
	assert.Nil(t, req.Events[0].Metadata) // metadata omitted when nil
}

func TestHTTPWriter_Health_CachedError(t *testing.T) {
	var healthCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/liveness" {
			healthCount.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), NewMockTokenProvider("tok"), testLogger())
	require.NoError(t, err)

	// First call — unhealthy
	err = writer.Health(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 503")
	assert.Equal(t, int32(1), healthCount.Load())

	// Second call within 30s — returns cached error, no new HTTP request
	err = writer.Health(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 503")
	assert.Equal(t, int32(1), healthCount.Load()) // still 1 — cached error
}

func TestDefaultHTTPWriterConfig_Values(t *testing.T) {
	cfg := DefaultHTTPWriterConfig()
	assert.Equal(t, 10*time.Second, cfg.Timeout)
	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, cfg.RetryBaseDelay)
	assert.Empty(t, cfg.BaseURL)
	assert.Empty(t, cfg.ServiceName)
}

func TestHTTPWriterConfig_Validate_ClampingBehavior(t *testing.T) {
	cfg := HTTPWriterConfig{
		BaseURL:        "https://audit.example.com",
		ServiceName:    "svc",
		Timeout:        -1 * time.Second,
		MaxRetries:     -5,
		RetryBaseDelay: -100 * time.Millisecond,
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, 10*time.Second, cfg.Timeout)
	assert.Equal(t, 0, cfg.MaxRetries)
	assert.Equal(t, time.Duration(0), cfg.RetryBaseDelay)
}

func TestHTTPWriterConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     HTTPWriterConfig
		wantErr string
	}{
		{
			name:    "empty base URL",
			cfg:     HTTPWriterConfig{ServiceName: "svc"},
			wantErr: "base URL is required",
		},
		{
			name:    "empty service name",
			cfg:     HTTPWriterConfig{BaseURL: "http://localhost:8080"},
			wantErr: "service name is required",
		},
		{
			name:    "invalid URL scheme",
			cfg:     HTTPWriterConfig{BaseURL: "ftp://localhost", ServiceName: "svc"},
			wantErr: "scheme must be http or https",
		},
		{
			name:    "missing host",
			cfg:     HTTPWriterConfig{BaseURL: "http://", ServiceName: "svc"},
			wantErr: "must include a host",
		},
		{
			name: "valid config",
			cfg: HTTPWriterConfig{
				BaseURL:     "https://audit.example.com",
				ServiceName: "auth-service",
				Timeout:     10 * time.Second,
			},
		},
		{
			name: "zero timeout gets default",
			cfg: HTTPWriterConfig{
				BaseURL:     "https://audit.example.com",
				ServiceName: "auth-service",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- QA Test: Token refreshed between retries (Task 4 verification) ---

func TestHTTPWriter_WriteBatch_TokenRefreshedBetweenRetries(t *testing.T) {
	var requestCount atomic.Int32
	receivedTokens := make([]string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := int(requestCount.Add(1))
		if idx <= len(receivedTokens) {
			receivedTokens[idx-1] = r.Header.Get("Authorization")
		}
		if idx <= 1 {
			w.WriteHeader(http.StatusInternalServerError) // trigger retry
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": 1, "rejected": 0, "event_ids": []string{"a"}, "errors": []interface{}{}})
	}))
	defer srv.Close()

	provider := &rotatingTokenProvider{tokens: []string{"token-v1", "token-v2"}}
	writer, err := NewHTTPWriter(testHTTPWriterConfig(srv.URL), provider, testLogger())
	require.NoError(t, err)

	err = writer.WriteBatch(context.Background(), []FinalAuditEvent{testFinalAuditEvent(t)})
	assert.NoError(t, err)

	assert.Equal(t, int32(2), requestCount.Load())
	assert.Equal(t, "Bearer token-v1", receivedTokens[0]) // first attempt
	assert.Equal(t, "Bearer token-v2", receivedTokens[1]) // retry with refreshed token
}
