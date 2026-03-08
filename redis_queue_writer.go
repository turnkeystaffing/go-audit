package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	pkgredis "github.com/turnkeystaffing/go-redis"
)

// DefaultFallbackQueueKey is the default Redis List key used by both
// RedisQueueWriter (producer) and RedisQueueConsumer (consumer).
const DefaultFallbackQueueKey = "audit:fallback:queue"

// RedisQueueWriterConfig configures the RedisQueueWriter.
// Redis connection is injected via RedisClient, not configured here (per P3).
type RedisQueueWriterConfig struct {
	QueueKey     string        // Redis List key for fallback queue (default: "audit:fallback:queue")
	MaxQueueSize int64         // Maximum queue length before rejecting writes (default: 10000, 0 = unlimited)
	QueueTTL     time.Duration // TTL on the queue key to bound PII retention (default: 7 days, 0 = no expiry)
}

// DefaultRedisQueueWriterConfig returns a config with sensible defaults.
func DefaultRedisQueueWriterConfig() RedisQueueWriterConfig {
	return RedisQueueWriterConfig{
		QueueKey:     DefaultFallbackQueueKey,
		MaxQueueSize: 10000,
		QueueTTL:     7 * 24 * time.Hour, // 7 days — bounds PII retention in fallback queue
	}
}

// Validate checks the config and applies defaults for empty fields.
// QueueTTL=0 is treated as unset and defaults to 7 days (PII retention bound).
// QueueTTL<0 explicitly disables TTL (not recommended — PII persists indefinitely).
func (c *RedisQueueWriterConfig) Validate() {
	if c.QueueKey == "" {
		c.QueueKey = DefaultFallbackQueueKey
	}
	if c.MaxQueueSize < 0 {
		c.MaxQueueSize = 10000
	}
	if c.QueueTTL == 0 {
		c.QueueTTL = 7 * 24 * time.Hour
	}
}

// RedisQueueWriter implements AuditWriter for Redis List-based fallback queuing.
// Events are serialized to JSON and pushed to a Redis List via LPUSH.
// The service-side queue consumer (RedisQueueConsumer) drains this queue via BRPOP.
//
// WriteBatch returns errors on failure. When used with DispatchChain strategy, the
// AuditRouter will try the next writer in registration order (typically FileWriter).
// When used with DispatchFanOut strategy, all writers receive events in parallel.
type RedisQueueWriter struct {
	redis        pkgredis.RedisClient
	queueKey     string
	maxQueueSize int64
	queueTTL     time.Duration
	log          *slog.Logger

	mu            sync.Mutex
	lastHealthAt  time.Time
	lastHealthErr error
}

const healthCacheTTL = 30 * time.Second

// NewRedisQueueWriter creates a new Redis-backed fallback queue writer.
func NewRedisQueueWriter(cfg RedisQueueWriterConfig, redisClient pkgredis.RedisClient, log *slog.Logger) (*RedisQueueWriter, error) {
	if log == nil {
		panic("audit: logger is required")
	}
	if redisClient == nil {
		panic("audit: redis client is required")
	}
	cfg.Validate()

	if cfg.QueueTTL < 0 {
		log.Warn("redis queue writer: QueueTTL disabled — PII may persist indefinitely in Redis",
			"queue_key", cfg.QueueKey, "queue_ttl", cfg.QueueTTL)
	}

	return &RedisQueueWriter{
		redis:        redisClient,
		queueKey:     cfg.QueueKey,
		maxQueueSize: cfg.MaxQueueSize,
		queueTTL:     cfg.QueueTTL,
		log:          log,
	}, nil
}

// WriteBatch serializes events to JSON and pushes them to the Redis List via LPUSH.
// Returns errors on failure so the AuditRouter can apply its dispatch strategy.
func (w *RedisQueueWriter) WriteBatch(ctx context.Context, events []FinalAuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("redis queue writer: %w", err)
	}

	// Check queue size BEFORE serialization (avoid wasted CPU when queue is full)
	if w.maxQueueSize > 0 {
		qLen, err := w.redis.LLen(ctx, w.queueKey)
		if err != nil {
			w.log.Warn("redis queue writer: LLen check failed, proceeding with LPUSH",
				"error", err, "queue_key", w.queueKey)
			// Non-fatal — proceed with LPUSH. LLen failure shouldn't block event delivery.
		} else if qLen+int64(len(events)) > w.maxQueueSize {
			w.log.Warn("redis queue writer: queue full, rejecting batch",
				"queue_key", w.queueKey,
				"queue_len", qLen,
				"max_queue_size", w.maxQueueSize,
				"batch_size", len(events))
			return fmt.Errorf("redis queue writer: queue capacity exceeded, rejecting batch of %d", len(events))
		}
	}

	// Serialize each event to JSON
	values := make([]interface{}, len(events))
	for i, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("redis queue writer: failed to marshal event %s: %w", event.ID, err)
		}
		values[i] = data
	}

	// Push all events in a single atomic LPUSH
	_, err := w.redis.LPush(ctx, w.queueKey, values...)
	if err != nil {
		w.invalidateHealthCache()
		return fmt.Errorf("redis queue writer: LPUSH failed: %w", err)
	}

	// Set TTL on queue key to bound PII retention (resets on each write)
	if w.queueTTL > 0 {
		if _, expErr := w.redis.Expire(ctx, w.queueKey, w.queueTTL); expErr != nil {
			w.log.Warn("redis queue writer: failed to set queue TTL",
				"error", expErr, "queue_key", w.queueKey, "ttl", w.queueTTL)
		}
	}

	w.log.Debug("batch written to redis queue",
		"writer", w.Name(),
		"batch_size", len(events),
		"queue_key", w.queueKey)

	return nil
}

// Health verifies Redis connectivity via Ping. Results are cached for 30 seconds.
// The mutex is NOT held during the Redis Ping to avoid blocking WriteBatch.
func (w *RedisQueueWriter) Health(ctx context.Context) error {
	// Check cache under lock
	w.mu.Lock()
	if !w.lastHealthAt.IsZero() && time.Since(w.lastHealthAt) < healthCacheTTL {
		err := w.lastHealthErr
		w.mu.Unlock()
		return err
	}
	w.mu.Unlock()

	// Perform Redis Ping WITHOUT holding the lock
	err := w.redis.Ping(ctx)
	w.updateHealthCache(err)
	return err
}

// updateHealthCache stores the health check result under the mutex.
func (w *RedisQueueWriter) updateHealthCache(err error) {
	w.mu.Lock()
	w.lastHealthAt = time.Now()
	w.lastHealthErr = err
	w.mu.Unlock()
}

// Shutdown logs shutdown with remaining queue depth for post-incident analysis.
// No connections to close — RedisClient lifecycle managed by caller.
func (w *RedisQueueWriter) Shutdown(ctx context.Context) error {
	qLen, err := w.redis.LLen(ctx, w.queueKey)
	if err != nil {
		w.log.Info("redis queue writer shutting down",
			"queue_key", w.queueKey, "pending_events", "unknown")
	} else {
		w.log.Info("redis queue writer shutting down",
			"queue_key", w.queueKey, "pending_events", qLen)
	}
	return nil
}

// Name returns the writer identifier.
func (w *RedisQueueWriter) Name() string {
	return "redis-queue"
}

// invalidateHealthCache forces the next Health() call to re-check.
func (w *RedisQueueWriter) invalidateHealthCache() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastHealthAt = time.Time{}
}

// Compile-time interface assertion
var _ AuditWriter = (*RedisQueueWriter)(nil)
