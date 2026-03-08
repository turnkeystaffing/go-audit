package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"encoding/json"

	"github.com/turnkeystaffing/go-redis"
)

// AuditLogger is the thin interface for logging audit events.
// This is the interface that application code should depend on.
type AuditLogger interface {
	Log(ctx context.Context, event *AuditEvent) error
	LogCritical(ctx context.Context, event *AuditEvent) error
}

// AuditConfigurable is the thin interface for configuring the audit system.
// This is used during application initialization.
type AuditConfigurable interface {
	RegisterWriter(writer AuditWriter, critical bool)
	RegisterEnricher(enricher Enricher)
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
	Health(ctx context.Context) error
}

// eventEntry pairs an event with the request context that produced it.
// This allows enrichers to access request-scoped values (client_id, IP, trace)
// even when the event is processed asynchronously by the background worker.
type eventEntry struct {
	ctx   context.Context
	event *AuditEvent
}

// AuditRouter is the central coordinator for audit event processing.
// It routes events to multiple destinations (writers) after enriching them
// with contextual metadata (enrichers).
type AuditRouter struct {
	writers                []AuditWriter
	enrichers              []Enricher
	eventChannel           chan eventEntry   // Buffered channel for async events
	criticalWriters        []AuditWriter     // Writers that must succeed
	criticalWriterNames    map[string]bool   // O(1) lookup for critical writer check
	rootCtx                context.Context   // Root context from Start(), used by background workers
	workerWg               sync.WaitGroup    // Worker goroutine coordination
	publisherWg            sync.WaitGroup    // Metrics publisher goroutine coordination
	publisherShutdown      chan struct{}     // Metrics publisher shutdown signal
	config                 *AuditConfig      // Configuration
	mu                     sync.RWMutex      // Protects writers and enrichers during registration
	sendMu                 sync.RWMutex      // Protects eventChannel send/close coordination
	started                atomic.Bool       // Whether Start() has been called
	shutdown               atomic.Bool       // Whether Shutdown() has been called (idempotency guard)
	bufferPending          atomic.Uint64     // Events sent to channel but not yet consumed by worker
	log                    *slog.Logger      // Logger for audit operations
	metrics                *AuditMetrics     // Performance and health metrics
	redisClient            redis.RedisClient // Redis client for metrics publishing (optional, can be nil)
	metricsPublishInterval time.Duration     // How often to publish metrics to Redis (default: 10s)
}

// AuditMetrics tracks performance and health statistics for the audit system.
type AuditMetrics struct {
	EventsReceived         atomic.Uint64 // Total events received (lifetime)
	EventsProcessed        atomic.Uint64 // Total events successfully written (lifetime)
	EventsFailed           atomic.Uint64 // Total events that failed to write (lifetime)
	EventsInLastInterval   atomic.Uint64 // Events processed in current flush interval (reset each flush)
	BufferHighWater        atomic.Uint64 // Maximum buffer usage seen
	StartedAt              atomic.Int64  // Unix timestamp when router started (set once in Start())
	LastFlushTime          atomic.Int64  // Unix timestamp of last flush
	LastIntervalProcessed  atomic.Uint64 // Events processed in previous flush interval (for rate display)
	LastIntervalDurationM  atomic.Int64  // Previous flush interval duration in milliseconds
	EventsCriticalRejected atomic.Uint64 // Critical events rejected due to total writer failure (FR12)
	EventsLost             atomic.Uint64 // Non-critical events lost due to total writer failure (FR13)
	WorkerHealthy          atomic.Bool   // Whether worker goroutine is running
	BufferAlertFired       atomic.Bool   // Whether buffer alert has been triggered
	EnrichmentMetrics      *EnricherMetricsTracker
}

// EnricherMetricsTracker tracks per-enricher performance metrics.
type EnricherMetricsTracker struct {
	mu      sync.RWMutex
	metrics map[int]*EnricherMetrics // Key: enricher index
}

// EnricherMetrics tracks performance for a single enricher.
type EnricherMetrics struct {
	Invocations atomic.Uint64 // Total times invoked
	Timeouts    atomic.Uint64 // Total timeout occurrences
	Failures    atomic.Uint64 // Total non-timeout failures
	TotalTimeNs atomic.Uint64 // Total time spent (nanoseconds)
	MaxTimeNs   atomic.Uint64 // Maximum time observed (nanoseconds)
}

// NewEnricherMetricsTracker creates a new enricher metrics tracker.
func NewEnricherMetricsTracker() *EnricherMetricsTracker {
	return &EnricherMetricsTracker{
		metrics: make(map[int]*EnricherMetrics),
	}
}

// GetOrCreate retrieves or creates metrics for an enricher index.
func (emt *EnricherMetricsTracker) GetOrCreate(index int) *EnricherMetrics {
	emt.mu.RLock()
	if m, exists := emt.metrics[index]; exists {
		emt.mu.RUnlock()
		return m
	}
	emt.mu.RUnlock()

	// Create new metrics
	emt.mu.Lock()
	defer emt.mu.Unlock()

	// Double-check after acquiring write lock
	if m, exists := emt.metrics[index]; exists {
		return m
	}

	m := &EnricherMetrics{}
	emt.metrics[index] = m
	return m
}

// GetAll returns a snapshot of all enricher metrics.
func (emt *EnricherMetricsTracker) GetAll() map[int]map[string]interface{} {
	emt.mu.RLock()
	defer emt.mu.RUnlock()

	result := make(map[int]map[string]interface{}, len(emt.metrics))
	for index, m := range emt.metrics {
		invocations := m.Invocations.Load()
		totalTimeNs := m.TotalTimeNs.Load()
		maxTimeNs := m.MaxTimeNs.Load()

		avgTimeNs := uint64(0)
		if invocations > 0 {
			avgTimeNs = totalTimeNs / invocations
		}

		result[index] = map[string]interface{}{
			"invocations":     invocations,
			"timeouts":        m.Timeouts.Load(),
			"failures":        m.Failures.Load(),
			"avg_duration_ms": float64(avgTimeNs) / 1_000_000,
			"max_duration_ms": float64(maxTimeNs) / 1_000_000,
		}
	}
	return result
}

// NewAuditRouter creates a new audit router with the given configuration.
// Use redis.NewNoopClient() when Redis metrics publishing is not needed.
func NewAuditRouter(config *AuditConfig, log *slog.Logger, redisClient redis.RedisClient) *AuditRouter {
	if log == nil {
		panic("logger is required for AuditRouter")
	}
	if redisClient == nil {
		panic("redisClient is required for AuditRouter (use redis.NewNoopClient() when Redis is not configured)")
	}

	return &AuditRouter{
		writers:                make([]AuditWriter, 0),
		enrichers:              make([]Enricher, 0),
		eventChannel:           make(chan eventEntry, config.BufferSize),
		criticalWriters:        make([]AuditWriter, 0),
		criticalWriterNames:    make(map[string]bool),
		publisherShutdown:      make(chan struct{}),
		config:                 config,
		log:                    log,
		redisClient:            redisClient,
		metricsPublishInterval: 10 * time.Second, // Default: publish every 10 seconds
		metrics: &AuditMetrics{
			EnrichmentMetrics: NewEnricherMetricsTracker(),
		},
	}
}

// SetMetricsPublishInterval configures how often metrics are published to Redis.
// Default is 10 seconds. Call this before Start() to change the interval.
func (r *AuditRouter) SetMetricsPublishInterval(interval time.Duration) {
	if r.started.Load() {
		r.log.Error("cannot set metrics publish interval after router started")
		return
	}
	if interval < time.Second {
		r.log.Warn("metrics publish interval too short, using 1 second minimum",
			"requested", interval)
		interval = time.Second
	}
	r.metricsPublishInterval = interval
	r.log.Info("metrics publish interval configured",
		"interval", interval)
}

// criticalEventTimeout is the maximum time allowed for critical event delivery.
// NFR24 requires rejection within 100ms when all services are unreachable.
const criticalEventTimeout = 100 * time.Millisecond

// Log sends an audit event for asynchronous processing.
// This is used for routine events that should not block the caller.
// The event is sent to a buffered channel and processed by a background worker.
//
// If event.Critical is true, the event bypasses the async channel and is written
// synchronously to all writers with a tight timeout. An error is returned only
// when ALL writers fail (total infrastructure failure). See writeCriticalSync().
func (r *AuditRouter) Log(ctx context.Context, event *AuditEvent) error {
	// Validate event before accepting
	if err := event.Validate(); err != nil {
		r.log.Warn("invalid audit event rejected",
			"action", event.Action,
			"error", err.Error())
		return fmt.Errorf("invalid audit event: %w", err)
	}

	// Check if audit system is started
	if !r.started.Load() {
		r.log.Warn("audit router not started, dropping event",
			"action", event.Action)
		return errors.New("audit router not started")
	}

	// Check if audit system has been shut down
	if r.shutdown.Load() {
		r.log.Warn("audit router shut down, dropping event",
			"action", event.Action)
		return errors.New("audit router shut down")
	}

	// Critical events bypass the async channel — write synchronously to all writers.
	// Returns error only when ALL writers fail (FR12/NFR24).
	if event.Critical {
		return r.writeCriticalSync(ctx, event)
	}

	// Track buffer usage metrics
	r.metrics.EventsReceived.Add(1)
	currentSize := uint64(len(r.eventChannel))

	// Check buffer alert threshold (80%)
	bufferUsage := float64(currentSize) / float64(r.config.BufferSize)
	if bufferUsage >= r.config.AlertThreshold {
		if !r.metrics.BufferAlertFired.Load() {
			r.log.Warn("audit buffer usage exceeds threshold",
				"usage_percent", int(bufferUsage*100),
				"threshold_percent", int(r.config.AlertThreshold*100),
				"buffer_size", currentSize,
				"capacity", r.config.BufferSize)
			r.metrics.BufferAlertFired.Store(true)
		}

		// If buffer is 100% full, switch to synchronous write to prevent data loss
		if currentSize >= uint64(r.config.BufferSize) {
			r.log.Error("audit buffer full, switching to synchronous write",
				"action", event.Action)
			return r.LogCritical(ctx, event)
		}
	} else {
		// Reset alert if we've dropped below threshold
		r.metrics.BufferAlertFired.Store(false)
	}

	// Send to channel (non-blocking with timeout).
	// Recover protects against the narrow race where Shutdown() closes the channel
	// between the r.shutdown.Load() check above and the send below.
	sent, err := r.trySendEvent(ctx, event)
	if err != nil {
		return err
	}
	if !sent {
		r.log.Warn("failed to send event to channel, using synchronous write",
			"action", event.Action)
		return r.LogCritical(ctx, event)
	}
	return nil
}

// trySendEvent attempts to send an event to the channel with a timeout.
// Returns (true, nil) on success, (false, nil) on timeout, or (false, err) on context cancel.
// Holds sendMu.RLock to prevent Shutdown() from closing the channel mid-send.
func (r *AuditRouter) trySendEvent(ctx context.Context, event *AuditEvent) (sent bool, err error) {
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()

	// Re-check shutdown under lock — Shutdown() sets the flag before acquiring sendMu.Lock().
	if r.shutdown.Load() {
		return false, errors.New("audit router shut down")
	}

	select {
	case r.eventChannel <- eventEntry{ctx: ctx, event: event}:
		// Increment pending count and update high water mark atomically.
		// This is race-free: pending is incremented before the worker can
		// decrement it, so the high water mark is never underreported.
		pending := r.bufferPending.Add(1)
		for {
			oldMax := r.metrics.BufferHighWater.Load()
			if pending <= oldMax || r.metrics.BufferHighWater.CompareAndSwap(oldMax, pending) {
				break
			}
		}
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	case <-time.After(100 * time.Millisecond):
		return false, nil
	}
}

// LogCritical sends an audit event for synchronous processing.
// This is used for critical security events (password resets, login failures)
// that must be written immediately before the operation completes.
//
// Dispatch behavior depends on config.DispatchStrategy:
//   - DispatchFanOut: writes to all critical writers, then non-critical (best-effort).
//     Returns error if ANY critical writer fails.
//   - DispatchChain: tries writers sequentially in registration order, stops on first success.
//     Returns error only if ALL writers fail.
func (r *AuditRouter) LogCritical(ctx context.Context, event *AuditEvent) error {
	// Validate event before processing
	if err := event.Validate(); err != nil {
		r.log.Warn("invalid audit event rejected",
			"action", event.Action,
			"error", err.Error())
		return fmt.Errorf("invalid audit event: %w", err)
	}

	r.metrics.EventsReceived.Add(1)

	// Enrich the event
	enriched, err := r.enrichEvent(ctx, event)
	if err != nil {
		r.log.Error("failed to enrich critical event",
			"error", err,
			"action", event.Action)
		// Continue with unenriched event for critical writes
	}

	switch r.config.DispatchStrategy {
	case DispatchChain:
		return r.logCriticalChain(ctx, event, enriched)
	default:
		return r.logCriticalFanOut(ctx, event, enriched)
	}
}

// logCriticalFanOut writes to all critical writers, then non-critical (best-effort).
// Returns error if ANY critical writer fails.
func (r *AuditRouter) logCriticalFanOut(ctx context.Context, event *AuditEvent, enriched FinalAuditEvent) error {
	// Write to all critical writers synchronously
	var writeErrors []error
	for _, writer := range r.criticalWriters {
		if err := writer.WriteBatch(ctx, []FinalAuditEvent{enriched}); err != nil {
			r.log.Error("critical writer failed",
				"writer", writer.Name(),
				"error", err,
				"action", event.Action)
			writeErrors = append(writeErrors, fmt.Errorf("%s: %w", writer.Name(), err))
		}
	}

	// Write to non-critical writers (best effort, don't fail on errors)
	r.mu.RLock()
	nonCriticalWriters := make([]AuditWriter, 0, len(r.writers))
	for _, w := range r.writers {
		if !r.IsCriticalWriter(w.Name()) {
			nonCriticalWriters = append(nonCriticalWriters, w)
		}
	}
	r.mu.RUnlock()

	for _, writer := range nonCriticalWriters {
		if err := writer.WriteBatch(ctx, []FinalAuditEvent{enriched}); err != nil {
			// Log but don't fail for non-critical writers
			r.log.Warn("non-critical writer failed",
				"writer", writer.Name(),
				"error", err,
				"action", event.Action)
		}
	}

	// Only return errors from critical writers
	if len(writeErrors) > 0 {
		r.metrics.EventsFailed.Add(1)
		return fmt.Errorf("critical audit write failed: %v", writeErrors)
	}

	r.metrics.EventsProcessed.Add(1)
	return nil
}

// logCriticalChain tries writers sequentially in registration order, stopping on first success.
func (r *AuditRouter) logCriticalChain(ctx context.Context, event *AuditEvent, enriched FinalAuditEvent) error {
	r.mu.RLock()
	writers := make([]AuditWriter, len(r.writers))
	copy(writers, r.writers)
	r.mu.RUnlock()

	for _, w := range writers {
		if err := w.WriteBatch(ctx, []FinalAuditEvent{enriched}); err != nil {
			r.log.Warn("LogCritical chain dispatch: writer failed, trying next",
				"writer", w.Name(),
				"error", err,
				"action", event.Action)
			continue
		}
		r.metrics.EventsProcessed.Add(1)
		return nil
	}

	// All writers failed — critical event rejected and lost
	r.metrics.EventsFailed.Add(1)
	r.metrics.EventsCriticalRejected.Add(1)
	r.metrics.EventsLost.Add(1)
	return fmt.Errorf("critical audit write failed: all %d writers failed", len(writers))
}

// writeCriticalSync writes a critical event synchronously to writers with a tight
// timeout (criticalEventTimeout). Returns error only when ALL writers fail.
// This is a separate code path from LogCritical() — see Design Decision #10.
//
// Dispatch behavior depends on config.DispatchStrategy:
//   - DispatchFanOut: writes to ALL writers concurrently within the timeout
//   - DispatchChain: tries writers sequentially in registration order within the timeout
//
// Panic safety: enricher panics on the caller goroutine and writer panics in spawned
// goroutines are recovered and converted to errors.
func (r *AuditRouter) writeCriticalSync(ctx context.Context, event *AuditEvent) (retErr error) {
	// Recover from enricher panics on the caller goroutine.
	defer func() {
		if p := recover(); p != nil {
			r.log.Error("CRITICAL: panic in critical event processing",
				"panic", p,
				"action", event.Action)
			r.metrics.EventsFailed.Add(1)
			r.metrics.EventsCriticalRejected.Add(1)
			retErr = errors.New("critical audit event rejected: internal error")
		}
	}()

	r.metrics.EventsReceived.Add(1)

	// Single timeout for entire operation (enrichment + writes) — NFR24 compliance.
	// enrichEvent has its own internal timeout, but the parent context bounds the total.
	critCtx, cancel := context.WithTimeout(ctx, criticalEventTimeout)
	defer cancel()

	// Enrich within the timeout budget (validation already done by Log() caller)
	enriched, err := r.enrichEvent(critCtx, event)
	if err != nil {
		r.log.Error("failed to enrich critical event",
			"error", err,
			"action", event.Action)
	}

	// Get writers snapshot
	r.mu.RLock()
	writers := make([]AuditWriter, len(r.writers))
	copy(writers, r.writers)
	r.mu.RUnlock()

	if len(writers) == 0 {
		r.metrics.EventsFailed.Add(1)
		r.metrics.EventsCriticalRejected.Add(1)
		return errors.New("critical audit event rejected: no writers registered")
	}

	switch r.config.DispatchStrategy {
	case DispatchChain:
		return r.writeCriticalChain(critCtx, event, enriched, writers)
	default:
		return r.writeCriticalFanOut(critCtx, event, enriched, writers)
	}
}

// writeCriticalFanOut writes to ALL writers concurrently. Returns error only when ALL fail.
func (r *AuditRouter) writeCriticalFanOut(critCtx context.Context, event *AuditEvent, enriched FinalAuditEvent, writers []AuditWriter) error {
	var (
		wg         sync.WaitGroup
		anySuccess atomic.Bool
		mu         sync.Mutex
		errList    []string
	)

	for _, writer := range writers {
		wg.Add(1)
		go func(w AuditWriter) {
			defer wg.Done()
			// Recover from writer panics — unrecovered goroutine panics terminate the program.
			defer func() {
				if p := recover(); p != nil {
					mu.Lock()
					errList = append(errList, fmt.Sprintf("%s: panic: %v", w.Name(), p))
					mu.Unlock()
					r.log.Error("writer panicked during critical event",
						"writer", w.Name(),
						"panic", p,
						"action", event.Action)
				}
			}()
			if wErr := w.WriteBatch(critCtx, []FinalAuditEvent{enriched}); wErr != nil {
				mu.Lock()
				errList = append(errList, fmt.Sprintf("%s: %v", w.Name(), wErr))
				mu.Unlock()
				r.log.Warn("writer failed for critical event",
					"writer", w.Name(),
					"error", wErr,
					"action", event.Action)
			} else {
				anySuccess.Store(true)
				r.log.Debug("critical event written",
					"writer", w.Name(),
					"action", event.Action)
			}
		}(writer)
	}

	wg.Wait()

	if anySuccess.Load() {
		r.metrics.EventsProcessed.Add(1)
		return nil
	}

	// ALL writers failed — reject the critical event.
	r.metrics.EventsFailed.Add(1)
	r.metrics.EventsCriticalRejected.Add(1)
	r.log.Error("critical audit event rejected: all writers failed",
		"writer_count", len(writers),
		"errors", strings.Join(errList, "; "),
		"action", event.Action)
	return fmt.Errorf("critical audit event rejected: all %d writers failed", len(writers))
}

// writeCriticalChain tries writers sequentially in registration order within the 100ms timeout.
// Stops on first success. Returns error only when ALL writers fail (rejected).
func (r *AuditRouter) writeCriticalChain(critCtx context.Context, event *AuditEvent, enriched FinalAuditEvent, writers []AuditWriter) error {
	var errList []string

	for _, w := range writers {
		// Check timeout before attempting next writer
		if critCtx.Err() != nil {
			errList = append(errList, fmt.Sprintf("timeout before %s", w.Name()))
			break
		}

		if wErr := w.WriteBatch(critCtx, []FinalAuditEvent{enriched}); wErr != nil {
			errList = append(errList, fmt.Sprintf("%s: %v", w.Name(), wErr))
			r.log.Warn("critical chain dispatch: writer failed, trying next",
				"writer", w.Name(),
				"error", wErr,
				"action", event.Action)
			continue
		}

		r.log.Debug("critical event written via chain dispatch",
			"writer", w.Name(),
			"action", event.Action)
		r.metrics.EventsProcessed.Add(1)
		return nil
	}

	// ALL writers failed — reject the critical event.
	r.metrics.EventsFailed.Add(1)
	r.metrics.EventsCriticalRejected.Add(1)
	r.log.Error("critical audit event rejected: all writers failed (chain)",
		"writer_count", len(writers),
		"errors", strings.Join(errList, "; "),
		"action", event.Action)
	return fmt.Errorf("critical audit event rejected: all %d writers failed", len(writers))
}

// RegisterWriter adds a new destination for audit events.
// If critical is true, the writer's failures will block audit operations.
func (r *AuditRouter) RegisterWriter(writer AuditWriter, critical bool) {
	// Prevent registration after Start()
	if r.started.Load() {
		r.log.Error("cannot register writer after router started",
			"writer", writer.Name())
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate writer names
	for _, existing := range r.writers {
		if existing.Name() == writer.Name() {
			r.log.Warn("writer with name already registered, skipping",
				"writer", writer.Name())
			return
		}
	}

	// Add to writers list
	r.writers = append(r.writers, writer)

	// Add to critical writers if specified
	if critical {
		r.criticalWriters = append(r.criticalWriters, writer)
		r.criticalWriterNames[writer.Name()] = true
		r.log.Info("registered critical writer",
			"writer", writer.Name())
	} else {
		r.log.Info("registered non-critical writer",
			"writer", writer.Name())
	}
}

// RegisterEnricher adds a new enricher function to the router.
// Enrichers are executed in the order they are registered.
func (r *AuditRouter) RegisterEnricher(enricher Enricher) {
	// Prevent registration after Start()
	if r.started.Load() {
		r.log.Error("cannot register enricher after router started")
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.enrichers = append(r.enrichers, enricher)
	r.log.Info("registered enricher",
		"total_enrichers", len(r.enrichers))
}

// Start begins the background worker goroutine for processing events.
func (r *AuditRouter) Start(ctx context.Context) error {
	// Validate configuration
	if err := r.config.Validate(); err != nil {
		return fmt.Errorf("invalid audit configuration: %w", err)
	}

	// Check at least one writer is registered
	r.mu.RLock()
	writerCount := len(r.writers)
	r.mu.RUnlock()

	if writerCount == 0 {
		return errors.New("cannot start audit router: no writers registered")
	}

	// Validate event channel capacity
	if cap(r.eventChannel) == 0 {
		return errors.New("event channel capacity must be > 0")
	}

	// Mark as started
	if !r.started.CompareAndSwap(false, true) {
		return errors.New("audit router already started")
	}

	r.rootCtx = ctx

	// Record start time and set worker as healthy
	r.metrics.StartedAt.Store(time.Now().Unix())
	r.metrics.WorkerHealthy.Store(true)

	// Start background worker goroutine
	r.workerWg.Add(1)
	go r.worker()

	// Start metrics publisher goroutine (noop client makes this safe when Redis is unconfigured)
	r.publisherWg.Add(1)
	go r.metricsPublisher()

	r.log.Info("audit router started",
		"writers", writerCount,
		"enrichers", len(r.enrichers),
		"buffer_size", cap(r.eventChannel))

	return nil
}

// worker is the background goroutine that processes audit events.
// It batches events and writes them to all registered destinations.
func (r *AuditRouter) worker() {
	defer r.workerWg.Done()
	defer r.metrics.WorkerHealthy.Store(false)

	// Panic recovery to prevent application crash
	defer func() {
		if recovered := recover(); recovered != nil {
			r.log.Error("CRITICAL: audit worker goroutine panicked - application recovered but audit processing stopped",
				"panic", recovered)
			// Worker will exit, but application continues running
		}
	}()

	// Create ticker for flush interval
	flushTicker := time.NewTicker(r.config.FlushInterval)
	defer flushTicker.Stop()

	// Batch accumulator
	batch := make([]eventEntry, 0, r.config.BatchSize)

	// Helper function to flush and reset batch (DRY principle)
	flushBatch := func() {
		if len(batch) > 0 {
			r.processBatch(batch)
			batch = batch[:0]
		}
	}

	for {
		select {
		case entry, ok := <-r.eventChannel:
			if !ok {
				// Channel closed (shutdown): flush final batch and exit.
				// All buffered events have already been received via this
				// same case (ok=true) before ok becomes false.
				r.log.Info("event channel closed, flushing final batch",
					"size", len(batch))
				flushBatch()
				return
			}

			r.bufferPending.Add(^uint64(0)) // atomic decrement

			// Add to batch
			batch = append(batch, entry)

			// Flush if batch is full
			if len(batch) >= r.config.BatchSize {
				flushBatch()
			}

		case <-flushTicker.C:
			// Periodic flush
			if len(batch) > 0 {
				r.log.Debug("periodic flush triggered",
					"batch_size", len(batch))
			}
			flushBatch()
		}
	}
}

// metricsPublisher is a background goroutine that periodically publishes audit metrics to Redis.
// This enables CLI access to live statistics when the web service is running.
func (r *AuditRouter) metricsPublisher() {
	defer r.publisherWg.Done()

	// Create ticker for publish interval
	ticker := time.NewTicker(r.metricsPublishInterval)
	defer ticker.Stop()

	ctx := r.rootCtx

	// Publish initial metrics immediately
	r.publishMetricsToRedis(ctx)

	for {
		select {
		case <-ticker.C:
			r.publishMetricsToRedis(ctx)

		case <-r.publisherShutdown:
			// Graceful shutdown: publish final metrics
			r.log.Info("metrics publisher shutdown signal received")
			r.publishMetricsToRedis(ctx)
			r.log.Info("metrics publisher shutdown complete")
			return
		}
	}
}

// publishMetricsToRedis collects current metrics and publishes them to Redis.
// Safe to call with a noop Redis client (Set returns nil, metrics silently discarded).
func (r *AuditRouter) publishMetricsToRedis(ctx context.Context) {
	// Collect buffer stats
	bufferSize := uint64(len(r.eventChannel))
	bufferCapacity := uint64(cap(r.eventChannel))
	bufferUsagePercent := float64(bufferSize) / float64(bufferCapacity) * 100

	// Collect router metrics
	metricsData := map[string]interface{}{
		"events_received":           r.metrics.EventsReceived.Load(),
		"events_processed":          r.metrics.EventsProcessed.Load(),
		"events_failed":             r.metrics.EventsFailed.Load(),
		"events_critical_rejected":  r.metrics.EventsCriticalRejected.Load(),
		"events_lost":               r.metrics.EventsLost.Load(),
		"last_interval_processed":   r.metrics.LastIntervalProcessed.Load(),
		"last_interval_duration_ms": r.metrics.LastIntervalDurationM.Load(),
		"buffer_high_water":         r.metrics.BufferHighWater.Load(),
		"buffer_size":               bufferSize,
		"buffer_capacity":           bufferCapacity,
		"buffer_usage_percent":      bufferUsagePercent,
		"buffer_alert_fired":        r.metrics.BufferAlertFired.Load(),
		"worker_healthy":            r.metrics.WorkerHealthy.Load(),
		"started_at":                r.metrics.StartedAt.Load(),
		"last_flush_time":           r.metrics.LastFlushTime.Load(),
		"published_at":              time.Now().Unix(),
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(metricsData)
	if err != nil {
		r.log.Error("failed to marshal metrics to JSON",
			"error", err)
		return
	}

	// Publish to Redis with TTL (30 seconds for staleness detection)
	// Key will be auto-prefixed by PrefixedRedisClient: "audit:metrics:latest" -> "get-native-auth:audit:metrics:latest"
	redisCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err = r.redisClient.Set(redisCtx, "audit:metrics:latest", jsonData, 30*time.Second)
	if err != nil {
		r.log.Error("failed to publish metrics to Redis",
			"error", err)
		return
	}

	r.log.Debug("metrics published to Redis",
		"events_processed", r.metrics.EventsProcessed.Load(),
		"buffer_usage", int(bufferUsagePercent))
}

// processBatch enriches and writes a batch of events to registered writers.
// Dispatch behavior depends on config.DispatchStrategy:
//   - DispatchFanOut (default): all writers receive every event in parallel
//   - DispatchChain: writers are tried sequentially in registration order; stops on first success
func (r *AuditRouter) processBatch(entries []eventEntry) {
	if len(entries) == 0 {
		return
	}

	// Enrich all events using their original request context
	enrichedEvents := make([]FinalAuditEvent, 0, len(entries))
	for _, entry := range entries {
		enriched, err := r.enrichEvent(entry.ctx, entry.event)
		if err != nil {
			r.log.Error("failed to enrich event",
				"error", err,
				"action", entry.event.Action)
			// Include unenriched event
		}
		enrichedEvents = append(enrichedEvents, enriched)
	}

	r.mu.RLock()
	writers := make([]AuditWriter, len(r.writers))
	copy(writers, r.writers)
	r.mu.RUnlock()

	switch r.config.DispatchStrategy {
	case DispatchChain:
		r.processBatchChain(writers, enrichedEvents)
	default:
		r.processBatchFanOut(writers, enrichedEvents)
	}

	// Snapshot the interval rate: swap current interval counter and record duration.
	now := time.Now()
	lastFlush := r.metrics.LastFlushTime.Load()
	if lastFlush > 0 {
		intervalMs := now.Sub(time.Unix(lastFlush, 0)).Milliseconds()
		intervalProcessed := r.metrics.EventsInLastInterval.Swap(0)
		r.metrics.LastIntervalProcessed.Store(intervalProcessed)
		r.metrics.LastIntervalDurationM.Store(intervalMs)
	}
	r.metrics.LastFlushTime.Store(now.Unix())
}

// processBatchFanOut writes to ALL writers in parallel (service-side behavior).
func (r *AuditRouter) processBatchFanOut(writers []AuditWriter, enrichedEvents []FinalAuditEvent) {
	var wg sync.WaitGroup
	var criticalFailed atomic.Bool
	var anyWriterSucceeded atomic.Bool

	for _, writer := range writers {
		wg.Add(1)
		go func(w AuditWriter) {
			defer wg.Done()

			writeCtx, cancel := context.WithTimeout(r.rootCtx, 10*time.Second)
			defer cancel()

			if err := w.WriteBatch(writeCtx, enrichedEvents); err != nil {
				if r.IsCriticalWriter(w.Name()) {
					r.log.Error("critical writer failed in batch",
						"writer", w.Name(),
						"error", err,
						"batch_size", len(enrichedEvents))
					criticalFailed.Store(true)
				} else {
					r.log.Warn("non-critical writer failed in batch",
						"writer", w.Name(),
						"error", err,
						"batch_size", len(enrichedEvents))
				}
			} else {
				anyWriterSucceeded.Store(true)
				r.log.Debug("batch written successfully",
					"writer", w.Name(),
					"batch_size", len(enrichedEvents))
			}
		}(writer)
	}

	wg.Wait()
	batchSize := uint64(len(enrichedEvents))

	// Track total writer failure for non-critical event loss detection (FR13)
	if !anyWriterSucceeded.Load() && len(writers) > 0 {
		r.metrics.EventsLost.Add(batchSize)
		r.log.Error("non-critical audit events lost: all writers failed",
			"batch_size", batchSize)
	}

	if criticalFailed.Load() {
		r.metrics.EventsFailed.Add(batchSize)
	} else {
		r.metrics.EventsProcessed.Add(batchSize)
		r.metrics.EventsInLastInterval.Add(batchSize)
	}
}

// processBatchChain tries writers sequentially in registration order, stopping on first success.
// This implements the producer-side ordered fallback: HTTP → Redis → File.
func (r *AuditRouter) processBatchChain(writers []AuditWriter, enrichedEvents []FinalAuditEvent) {
	batchSize := uint64(len(enrichedEvents))

	for _, w := range writers {
		writeCtx, cancel := context.WithTimeout(r.rootCtx, 10*time.Second)
		err := w.WriteBatch(writeCtx, enrichedEvents)
		cancel()

		if err == nil {
			r.log.Debug("batch written via chain dispatch",
				"writer", w.Name(),
				"batch_size", len(enrichedEvents))
			r.metrics.EventsProcessed.Add(batchSize)
			r.metrics.EventsInLastInterval.Add(batchSize)
			return
		}

		r.log.Warn("chain dispatch: writer failed, trying next",
			"writer", w.Name(),
			"error", err,
			"batch_size", len(enrichedEvents))
	}

	// All writers failed
	r.metrics.EventsFailed.Add(batchSize)
	r.metrics.EventsLost.Add(batchSize)
	r.log.Error("chain dispatch: all writers failed, events lost",
		"writer_count", len(writers),
		"batch_size", batchSize)
}

// enrichEvent runs all registered enrichers on an event and returns a FinalAuditEvent.
func (r *AuditRouter) enrichEvent(ctx context.Context, event *AuditEvent) (FinalAuditEvent, error) {
	// Create context with timeout for enrichment
	enrichCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	// Shallow copy — scalar fields are isolated from the caller, but ContextData
	// map is shared. This is safe because callers discard the original after enrichment.
	eventCopy := *event

	if eventCopy.ContextData == nil {
		eventCopy.ContextData = make(map[string]interface{})
	}

	// Run all enrichers in order
	r.mu.RLock()
	enrichers := make([]Enricher, len(r.enrichers))
	copy(enrichers, r.enrichers)
	r.mu.RUnlock()

	for i, enricher := range enrichers {
		// Get or create metrics tracker for this enricher
		metrics := r.metrics.EnrichmentMetrics.GetOrCreate(i)
		metrics.Invocations.Add(1)

		// Measure duration and call enricher
		// Note: Worker-level panic recovery will catch any enricher panics
		start := time.Now()
		err := enricher(enrichCtx, &eventCopy)
		duration := time.Since(start)

		// Update duration metrics
		durationNs := uint64(duration.Nanoseconds())
		metrics.TotalTimeNs.Add(durationNs)

		// Update max duration with atomic compare-and-swap
		for {
			oldMax := metrics.MaxTimeNs.Load()
			if durationNs <= oldMax || metrics.MaxTimeNs.CompareAndSwap(oldMax, durationNs) {
				break
			}
		}

		// Track timeout vs failure
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				metrics.Timeouts.Add(1)
			} else {
				metrics.Failures.Add(1)
			}

			r.log.Warn("enricher failed",
				"enricher_index", i,
				"error", err,
				"action", event.Action,
				"duration_ms", duration.Milliseconds())
			// Continue with other enrichers
		}
	}

	// Enforce immutability contract: enrichers must not mutate core fields
	if eventCopy.ID != event.ID || eventCopy.Timestamp != event.Timestamp ||
		eventCopy.Action != event.Action || eventCopy.Outcome != event.Outcome ||
		eventCopy.Critical != event.Critical {
		r.log.Error("enricher violated immutability contract: core fields were mutated",
			"original_id", event.ID, "mutated_id", eventCopy.ID,
			"original_action", event.Action, "mutated_action", eventCopy.Action)
		eventCopy.ID = event.ID
		eventCopy.Timestamp = event.Timestamp
		eventCopy.Action = event.Action
		eventCopy.Outcome = event.Outcome
		eventCopy.Critical = event.Critical
	}

	// Extract enricher-added keys (prefixed with "enrichment.") into EnrichmentMetadata
	// and remove them from ContextData so the DB metadata column stays app-context only.
	enrichmentMetadata := make(map[string]interface{})
	for k, v := range eventCopy.ContextData {
		if strings.HasPrefix(k, "enrichment.") {
			enrichmentMetadata[k] = v
		}
	}
	for k := range enrichmentMetadata {
		delete(eventCopy.ContextData, k)
	}

	finalEvent := FinalAuditEvent{
		AuditEvent:         eventCopy,
		EnrichmentMetadata: enrichmentMetadata,
		EnrichedAt:         time.Now(),
	}

	return finalEvent, nil
}

// Shutdown gracefully stops the router, draining all pending events.
func (r *AuditRouter) Shutdown(ctx context.Context) error {
	if !r.started.Load() {
		return errors.New("audit router not started")
	}

	// Check if already shut down (idempotency guard)
	if !r.shutdown.CompareAndSwap(false, true) {
		r.log.Info("audit router already shut down")
		return nil
	}

	r.log.Info("initiating graceful shutdown")

	// Signal shutdown to metrics publisher
	close(r.publisherShutdown)

	// Close event channel to signal worker to drain and exit.
	// sendMu.Lock() waits for any in-flight trySendEvent (which holds RLock) to finish,
	// ensuring no goroutine is mid-send when we close. trySendEvent re-checks the
	// shutdown flag under RLock, so any sender arriving after this point returns early.
	r.sendMu.Lock()
	close(r.eventChannel)
	r.sendMu.Unlock()

	// Wait for both worker and publisher to finish with timeout
	shutdownDone := make(chan struct{})
	go func() {
		r.workerWg.Wait()
		r.publisherWg.Wait()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		r.log.Info("worker and publisher shutdown complete")
	case <-ctx.Done():
		r.log.Error("shutdown timeout exceeded, forcing shutdown")
		return ctx.Err()
	case <-time.After(r.config.ShutdownTimeout):
		r.log.Error("shutdown timeout exceeded",
			"timeout", r.config.ShutdownTimeout)
		return fmt.Errorf("shutdown timeout after %v", r.config.ShutdownTimeout)
	}

	// Shutdown all writers
	var shutdownErrors []error
	r.mu.RLock()
	writers := make([]AuditWriter, len(r.writers))
	copy(writers, r.writers)
	r.mu.RUnlock()

	for _, writer := range writers {
		shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := writer.Shutdown(shutdownCtx); err != nil {
			shutdownErrors = append(shutdownErrors, fmt.Errorf("%s: %w", writer.Name(), err))
		}
		cancel()
	}

	r.log.Info("audit router shutdown complete",
		"events_received", r.metrics.EventsReceived.Load(),
		"events_processed", r.metrics.EventsProcessed.Load(),
		"events_failed", r.metrics.EventsFailed.Load())

	if len(shutdownErrors) > 0 {
		return fmt.Errorf("writer shutdown errors: %v", shutdownErrors)
	}

	return nil
}

// Health checks the health of all registered writers.
func (r *AuditRouter) Health(ctx context.Context) error {
	// Check if router is started
	if !r.started.Load() {
		return errors.New("audit router not started")
	}

	// Check worker health
	if !r.metrics.WorkerHealthy.Load() {
		return errors.New("audit worker goroutine not healthy")
	}

	// Check buffer usage
	bufferSize := uint64(len(r.eventChannel))
	bufferCapacity := uint64(cap(r.eventChannel))
	bufferUsage := float64(bufferSize) / float64(bufferCapacity)

	if bufferUsage > 0.95 {
		return fmt.Errorf("audit buffer critically full: %.1f%% (size=%d, capacity=%d)",
			bufferUsage*100, bufferSize, bufferCapacity)
	}

	if bufferUsage > r.config.AlertThreshold {
		r.log.Warn("audit buffer usage high",
			"usage_percent", int(bufferUsage*100),
			"size", bufferSize,
			"capacity", bufferCapacity)
	}

	// Check all writers' health in parallel
	type healthResult struct {
		writerName string
		err        error
		isCritical bool
	}

	healthChan := make(chan healthResult, len(r.writers))

	r.mu.RLock()
	writers := make([]AuditWriter, len(r.writers))
	copy(writers, r.writers)
	r.mu.RUnlock()

	for _, writer := range writers {
		go func(w AuditWriter, critical bool) {
			healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			err := w.Health(healthCtx)
			healthChan <- healthResult{
				writerName: w.Name(),
				err:        err,
				isCritical: critical,
			}
		}(writer, r.IsCriticalWriter(writer.Name()))
	}

	// Collect health check results
	var healthErrors []error
	for i := 0; i < len(writers); i++ {
		result := <-healthChan
		if result.err != nil {
			if result.isCritical {
				healthErrors = append(healthErrors, fmt.Errorf("critical writer %s unhealthy: %w",
					result.writerName, result.err))
			} else {
				r.log.Warn("non-critical writer unhealthy",
					"writer", result.writerName,
					"error", result.err)
			}
		}
	}

	if len(healthErrors) > 0 {
		return fmt.Errorf("audit system unhealthy: %v", healthErrors)
	}

	return nil
}

// NoopAuditRouter is a no-operation implementation of AuditRouter for when auditing is disabled.
// It silently discards all audit events without processing them.
type NoopAuditRouter struct{}

// NewNoopAuditRouter creates a new no-op audit router.
func NewNoopAuditRouter() *NoopAuditRouter {
	return &NoopAuditRouter{}
}

// Log silently discards the event.
func (n *NoopAuditRouter) Log(ctx context.Context, event *AuditEvent) error {
	return nil
}

// LogCritical silently discards the event.
func (n *NoopAuditRouter) LogCritical(ctx context.Context, event *AuditEvent) error {
	return nil
}

// RegisterWriter is a no-op.
func (n *NoopAuditRouter) RegisterWriter(writer AuditWriter, critical bool) {}

// RegisterEnricher is a no-op.
func (n *NoopAuditRouter) RegisterEnricher(enricher Enricher) {}

// Start is a no-op.
func (n *NoopAuditRouter) Start(ctx context.Context) error {
	return nil
}

// Shutdown is a no-op.
func (n *NoopAuditRouter) Shutdown(ctx context.Context) error {
	return nil
}

// Health always returns healthy.
func (n *NoopAuditRouter) Health(ctx context.Context) error {
	return nil
}

var (
	_ AuditLogger       = (*AuditRouter)(nil)
	_ AuditConfigurable = (*AuditRouter)(nil)
	_ AuditLogger       = (*NoopAuditRouter)(nil)
	_ AuditConfigurable = (*NoopAuditRouter)(nil)
)

// BufferLen returns the current number of events in the buffer.
func (r *AuditRouter) BufferLen() int {
	return len(r.eventChannel)
}

// BufferCap returns the buffer capacity.
func (r *AuditRouter) BufferCap() int {
	return cap(r.eventChannel)
}

// GetConfig returns a copy of the router's configuration.
func (r *AuditRouter) GetConfig() AuditConfig {
	return *r.config
}

// GetWritersSnapshot returns a thread-safe copy of all registered writers.
func (r *AuditRouter) GetWritersSnapshot() []AuditWriter {
	r.mu.RLock()
	writers := make([]AuditWriter, len(r.writers))
	copy(writers, r.writers)
	r.mu.RUnlock()
	return writers
}

// IsCriticalWriter returns true if the named writer is registered as critical.
func (r *AuditRouter) IsCriticalWriter(name string) bool {
	return r.criticalWriterNames[name]
}

// GetMetrics returns the router's live metrics. Callers must use atomic .Load() methods only.
func (r *AuditRouter) GetMetrics() *AuditMetrics {
	return r.metrics
}
