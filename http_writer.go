package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/turnkeystaffing/go-opentelemetry"
)

// HTTPWriterConfig configures the HTTPWriter for delivering audit events to the audit service.
// Per P3 (hardening): this config is writer-specific, separate from AuditConfig (pipeline config).
type HTTPWriterConfig struct {
	BaseURL        string        // Audit service base URL (required, e.g. "https://audit.example.com")
	ServiceName    string        // Producer service name for wire format (required, e.g. "auth-service")
	Timeout        time.Duration // HTTP request timeout (default: 10s)
	MaxRetries     int           // Max retry attempts for transient failures (default: 3)
	RetryBaseDelay time.Duration // Base delay for exponential backoff (default: 100ms)
}

// DefaultHTTPWriterConfig returns an HTTPWriterConfig with sensible defaults.
// BaseURL and ServiceName must be set by the caller.
func DefaultHTTPWriterConfig() HTTPWriterConfig {
	return HTTPWriterConfig{
		Timeout:        10 * time.Second,
		MaxRetries:     3,
		RetryBaseDelay: 100 * time.Millisecond,
	}
}

// Validate checks the HTTPWriterConfig for errors.
func (c *HTTPWriterConfig) Validate() error {
	if c.BaseURL == "" {
		return fmt.Errorf("http writer: base URL is required")
	}

	parsed, err := url.Parse(c.BaseURL)
	if err != nil {
		return fmt.Errorf("http writer: invalid base URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("http writer: base URL scheme must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("http writer: base URL must include a host")
	}

	if c.ServiceName == "" {
		return fmt.Errorf("http writer: service name is required")
	}

	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.MaxRetries < 0 {
		c.MaxRetries = 0
	}
	if c.RetryBaseDelay < 0 {
		c.RetryBaseDelay = 0
	}

	return nil
}

// httpBatchRequest is the wire format for the audit service batch endpoint.
// Matches internal/audit/gateway/dto/ingestion.go:IngestionRequest.
type httpBatchRequest struct {
	Events []httpEventDTO `json:"events"`
}

// httpEventDTO is the wire format for a single audit event.
// Matches internal/audit/gateway/dto/ingestion.go:EventDTO.
type httpEventDTO struct {
	EventID       string                 `json:"event_id"`
	Service       string                 `json:"service"`
	Action        string                 `json:"action"`
	Actor         string                 `json:"actor"`
	Resource      httpResourceDTO        `json:"resource"`
	Outcome       string                 `json:"outcome"`
	Timestamp     string                 `json:"timestamp"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	FailureReason string                 `json:"failure_reason,omitempty"`
}

// httpResourceDTO is the wire format for a resource reference.
// Matches internal/audit/gateway/dto/ingestion.go:ResourceDTO.
type httpResourceDTO struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

// httpIngestionResponse is the wire format for the batch endpoint response.
// Matches internal/audit/gateway/dto/ingestion.go:IngestionResponse.
type httpIngestionResponse struct {
	Accepted int      `json:"accepted"`
	Rejected int      `json:"rejected"`
	EventIDs []string `json:"event_ids"`
}

// finalEventToDTO converts a FinalAuditEvent to the audit service wire format.
func finalEventToDTO(event FinalAuditEvent, serviceName string) httpEventDTO {
	dto := httpEventDTO{
		EventID:       event.ID.String(),
		Service:       serviceName,
		Action:        event.Action,
		Outcome:       event.Outcome,
		Timestamp:     event.Timestamp.Format(time.RFC3339Nano),
		FailureReason: event.FailureReason,
		Resource: httpResourceDTO{
			Type: event.ResourceType,
		},
	}

	if event.UserID != nil {
		dto.Actor = event.UserID.String()
	}

	if event.ResourceID != nil {
		dto.Resource.ID = event.ResourceID.String()
	}

	// Defensive copy of metadata map
	if len(event.ContextData) > 0 {
		dto.Metadata = make(map[string]interface{}, len(event.ContextData))
		for k, v := range event.ContextData {
			dto.Metadata[k] = v
		}
	}

	return dto
}

// HTTPWriter implements AuditWriter for delivering audit events to the audit service via HTTP.
// This is the primary delivery channel on the producer side. WriteBatch returns errors on failure
// so the AuditRouter can apply its dispatch strategy (chain fallback or fan-out).
type HTTPWriter struct {
	client         *http.Client
	batchURL       string // pre-computed: baseURL + "/api/v1/events/batch"
	healthURL      string // pre-computed: baseURL + "/health/liveness"
	serviceName    string
	tokenProvider  TokenProvider
	maxRetries     int
	retryBaseDelay time.Duration
	log            *slog.Logger

	// Health check caching (same pattern as FileWriter)
	mu            sync.Mutex
	lastHealthAt  time.Time
	lastHealthErr error
}

const (
	maxRetryBackoff = 5 * time.Second
	maxRetryAfter   = 5 * time.Second // cap server-provided Retry-After — must not stall the worker
)

// NewHTTPWriter creates a new HTTP-based audit writer.
func NewHTTPWriter(cfg HTTPWriterConfig, tokenProvider TokenProvider, log *slog.Logger) (*HTTPWriter, error) {
	if log == nil {
		panic("audit: logger is required")
	}
	if tokenProvider == nil {
		panic("audit: token provider is required")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	baseURL := strings.TrimRight(cfg.BaseURL, "/")

	if strings.HasPrefix(baseURL, "http://") {
		log.Warn("http writer: BaseURL uses plaintext HTTP — Bearer token will be transmitted without TLS",
			"base_url", baseURL)
	}

	baseClient := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 10,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // reject redirects to prevent SSRF/token leak
		},
	}
	client := opentelemetry.NewInstrumentedHTTPClient(baseClient)

	return &HTTPWriter{
		client:         client,
		batchURL:       baseURL + "/api/v1/events/batch",
		healthURL:      baseURL + "/health/liveness",
		serviceName:    cfg.ServiceName,
		tokenProvider:  tokenProvider,
		maxRetries:     cfg.MaxRetries,
		retryBaseDelay: cfg.RetryBaseDelay,
		log:            log,
	}, nil
}

// WriteBatch sends a batch of audit events to the audit service via HTTP POST.
// Returns nil on successful delivery (202), error on failure.
func (w *HTTPWriter) WriteBatch(ctx context.Context, events []FinalAuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	// Convert events to wire format
	dtos := make([]httpEventDTO, len(events))
	for i, event := range events {
		dtos[i] = finalEventToDTO(event, w.serviceName)
	}

	// Marshal request body
	body, err := json.Marshal(httpBatchRequest{Events: dtos})
	if err != nil {
		return fmt.Errorf("http writer: marshal error: %w", err)
	}

	// Retry loop — token fetched per attempt so background refresh is picked up between retries
	// (Story 2-1 deferred finding: re-fetch token on each retry attempt)
	var lastErr error
	for attempt := 0; attempt <= w.maxRetries; attempt++ {
		if attempt > 0 {
			delay := w.retryDelay(lastErr, attempt-1)
			w.log.Warn("http writer: retrying after transient failure",
				"attempt", attempt+1,
				"max_attempts", w.maxRetries+1,
				"retry_delay", delay.String(),
				"events", len(events))

			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return fmt.Errorf("http writer: context canceled during retry: %w", ctx.Err())
			case <-timer.C:
			}
		}

		// Get bearer token per attempt (picks up refreshed tokens between retries)
		token, err := w.tokenProvider.Token(ctx)
		if err != nil {
			return fmt.Errorf("http writer: token error: %w", err)
		}

		lastErr = w.doRequest(ctx, body, token, len(events))
		if lastErr == nil {
			return nil
		}

		// Check if error is retryable
		if !isRetryable(lastErr) {
			w.invalidateHealthCache()
			return lastErr
		}
	}

	w.invalidateHealthCache()
	w.log.Error("http writer: delivery failed after retries",
		"attempts", w.maxRetries+1,
		"events", len(events))
	return lastErr
}

// doRequest executes a single HTTP POST to the batch endpoint.
func (w *HTTPWriter) doRequest(ctx context.Context, body []byte, token string, eventCount int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.batchURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("http writer: request creation error: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := w.client.Do(req)
	if err != nil {
		return &retryableError{err: fmt.Errorf("http writer: network error: %w", err)}
	}
	defer resp.Body.Close()

	// Read response body (limit to 1MB to prevent abuse)
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusAccepted {
		// Parse response to check for rejections
		var ingestionResp httpIngestionResponse
		if err := json.Unmarshal(respBody, &ingestionResp); err == nil && ingestionResp.Rejected > 0 {
			w.log.Warn("http writer: audit service rejected some events",
				"accepted", ingestionResp.Accepted,
				"rejected", ingestionResp.Rejected,
				"total_sent", eventCount)
		}
		return nil
	}

	// Non-2xx responses
	statusErr := fmt.Errorf("http writer: delivery failed with status %d", resp.StatusCode)

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		// 429 — extract Retry-After if present
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
				return &retryableError{err: statusErr, retryAfter: time.Duration(seconds) * time.Second}
			}
		}
		return &retryableError{err: statusErr}
	case resp.StatusCode >= 500:
		return &retryableError{err: statusErr}
	default:
		// 4xx (except 429) — not retryable
		return statusErr
	}
}

// retryDelay computes the delay before the next retry attempt.
// Uses server-provided Retry-After if available (capped at maxRetryAfter),
// otherwise falls back to exponential backoff with jitter.
func (w *HTTPWriter) retryDelay(lastErr error, attempt int) time.Duration {
	// Honor server-provided Retry-After (e.g., from 429)
	var re *retryableError
	if errors.As(lastErr, &re) && re.retryAfter > 0 {
		delay := re.retryAfter
		if delay > maxRetryAfter {
			delay = maxRetryAfter
		}
		return delay
	}
	return w.backoffDelay(attempt)
}

// backoffDelay computes exponential backoff: baseDelay * 2^attempt, capped at maxRetryBackoff.
func (w *HTTPWriter) backoffDelay(attempt int) time.Duration {
	return calcBackoff(w.retryBaseDelay, maxRetryBackoff, attempt)
}

// Shutdown closes idle HTTP connections.
func (w *HTTPWriter) Shutdown(_ context.Context) error {
	w.client.CloseIdleConnections()
	w.log.Info("HTTPWriter shutdown complete")
	return nil
}

// Health checks audit service availability via the liveness probe.
// Results are cached for 30 seconds to avoid excessive probing.
// Cache is invalidated on WriteBatch errors.
// The mutex is NOT held during the HTTP call to avoid blocking WriteBatch.
func (w *HTTPWriter) Health(ctx context.Context) error {
	const healthCacheTTL = 30 * time.Second

	// Check cache under lock
	w.mu.Lock()
	if !w.lastHealthAt.IsZero() && time.Since(w.lastHealthAt) < healthCacheTTL {
		err := w.lastHealthErr
		w.mu.Unlock()
		return err
	}
	w.mu.Unlock()

	// Perform HTTP call WITHOUT holding the lock
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(healthCtx, http.MethodGet, w.healthURL, nil)
	if err != nil {
		healthErr := fmt.Errorf("http writer health: request creation error: %w", err)
		w.updateHealthCache(healthErr)
		return healthErr
	}

	resp, err := w.client.Do(req)
	if err != nil {
		healthErr := fmt.Errorf("http writer health: %w", err)
		w.updateHealthCache(healthErr)
		return healthErr
	}
	defer resp.Body.Close()
	// Drain body (bounded) to enable connection reuse
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		healthErr := fmt.Errorf("http writer health: audit service returned status %d", resp.StatusCode)
		w.updateHealthCache(healthErr)
		return healthErr
	}

	w.updateHealthCache(nil)
	return nil
}

// updateHealthCache stores the health check result under the mutex.
func (w *HTTPWriter) updateHealthCache(err error) {
	w.mu.Lock()
	w.lastHealthAt = time.Now()
	w.lastHealthErr = err
	w.mu.Unlock()
}

// invalidateHealthCache forces the next Health() call to perform a real check.
func (w *HTTPWriter) invalidateHealthCache() {
	w.mu.Lock()
	w.lastHealthAt = time.Time{}
	w.mu.Unlock()
}

// Name returns the unique identifier for this writer.
func (w *HTTPWriter) Name() string {
	return "http"
}

// retryableError wraps an error that indicates a transient failure eligible for retry.
type retryableError struct {
	err        error
	retryAfter time.Duration // non-zero if server provided Retry-After
}

func (e *retryableError) Error() string { return e.err.Error() }
func (e *retryableError) Unwrap() error { return e.err }

// isRetryable checks if an error should be retried.
func isRetryable(err error) bool {
	var re *retryableError
	return errors.As(err, &re)
}

var _ AuditWriter = (*HTTPWriter)(nil)
