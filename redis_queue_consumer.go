package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync/atomic"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/turnkeystaffing/go-redis"
)

// RedisQueueConsumerConfig configures the RedisQueueConsumer.
type RedisQueueConsumerConfig struct {
	QueueKey     string        // Redis list key (default: "audit:fallback:queue")
	BRPOPTimeout time.Duration // BRPOP blocking timeout (default: 2s — allows shutdown check)
}

// DefaultRedisQueueConsumerConfig returns a config with sensible defaults.
func DefaultRedisQueueConsumerConfig() RedisQueueConsumerConfig {
	return RedisQueueConsumerConfig{
		QueueKey:     DefaultFallbackQueueKey,
		BRPOPTimeout: 2 * time.Second,
	}
}

// Validate checks the config for invalid values. Zero-value defaults are applied by
// DefaultRedisQueueConsumerConfig() or config.applyDefaults() — Validate only rejects
// invalid states, not missing ones, to avoid redundant default logic.
func (c *RedisQueueConsumerConfig) Validate() error {
	if c.BRPOPTimeout < 0 {
		return fmt.Errorf("redis queue consumer: brpop timeout must not be negative")
	}
	return nil
}

// RedisQueueConsumer is a background goroutine that drains events from the Redis
// fallback queue (written by RedisQueueWriter) and routes them through the AuditRouter.
// It is a lifecycle component (Start/Shutdown), NOT an AuditWriter.
type RedisQueueConsumer struct {
	redisClient  redis.RedisClient
	auditRouter  AuditLogger
	queueKey     string
	brpopTimeout time.Duration
	log          *slog.Logger

	stopCh  chan struct{}
	doneCh  chan struct{}
	running atomic.Bool
}

// NewRedisQueueConsumer creates a new queue consumer. Panics on nil dependencies (fail-fast).
func NewRedisQueueConsumer(cfg RedisQueueConsumerConfig, redisClient redis.RedisClient, router AuditLogger, log *slog.Logger) *RedisQueueConsumer {
	if redisClient == nil {
		panic("NewRedisQueueConsumer: redisClient cannot be nil")
	}
	if router == nil {
		panic("NewRedisQueueConsumer: router cannot be nil")
	}
	if log == nil {
		panic("NewRedisQueueConsumer: log cannot be nil")
	}

	if err := cfg.Validate(); err != nil {
		panic(fmt.Sprintf("NewRedisQueueConsumer: %v", err))
	}

	return &RedisQueueConsumer{
		redisClient:  redisClient,
		auditRouter:  router,
		queueKey:     cfg.QueueKey,
		brpopTimeout: cfg.BRPOPTimeout,
		log:          log,
	}
}

// Start launches the consumer goroutine. Returns error if already running.
func (c *RedisQueueConsumer) Start(ctx context.Context) error {
	if !c.running.CompareAndSwap(false, true) {
		return fmt.Errorf("redis queue consumer: already running")
	}

	c.stopCh = make(chan struct{})
	c.doneCh = make(chan struct{})

	go c.runLoop(ctx)

	c.log.Info("redis queue consumer started",
		"queue_key", c.queueKey,
		"brpop_timeout", c.brpopTimeout)

	return nil
}

// runLoop is the background goroutine that BRPOP-drains the queue.
func (c *RedisQueueConsumer) runLoop(ctx context.Context) {
	defer close(c.doneCh)
	defer func() {
		if recovered := recover(); recovered != nil {
			c.log.Error("redis queue consumer: goroutine panicked",
				"panic", recovered,
				"stack", string(debug.Stack()))
		}
	}()

	var consecutiveErrors int

	for {
		select {
		case <-c.stopCh:
			c.log.Info("redis queue consumer: stop signal received")
			return
		case <-ctx.Done():
			c.log.Info("redis queue consumer: context canceled")
			return
		default:
		}

		err := c.drainOne(ctx)
		if err == nil {
			consecutiveErrors = 0
			continue
		}

		// redis.Nil = BRPOP timeout (empty queue) — normal, no backoff
		if errors.Is(err, goredis.Nil) {
			consecutiveErrors = 0
			continue
		}

		// Context cancellation — exit cleanly without spurious WARN log
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			continue // next loop iteration exits via ctx.Done check
		}

		// Real error — apply backoff
		consecutiveErrors++
		delay := calcBackoff(time.Second, 30*time.Second, consecutiveErrors-1)
		c.log.Warn("redis queue consumer: brpop error, backing off",
			"error", err,
			"consecutive_errors", consecutiveErrors,
			"backoff", delay)

		timer := time.NewTimer(delay)
		select {
		case <-c.stopCh:
			timer.Stop()
			return
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// drainOne performs a single BRPOP, deserializes the event, and routes it.
// Returns nil on success, redis.Nil on empty queue, or an error for BRPOP failures.
// Deserialization and routing errors are handled internally (logged and skipped).
func (c *RedisQueueConsumer) drainOne(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	result, err := c.redisClient.BRPop(ctx, c.brpopTimeout, c.queueKey)
	if err != nil {
		return err
	}

	if len(result) < 2 {
		c.log.Warn("redis queue consumer: unexpected brpop result length",
			"length", len(result))
		return nil
	}

	// Defense-in-depth: reject oversized payloads before json.Unmarshal to prevent
	// OOM from a compromised Redis or malicious producer. 1MB matches HTTPWriter body limit.
	const maxEventSize = 1 << 20 // 1 MB
	if len(result[1]) > maxEventSize {
		c.log.Error("redis queue consumer: event exceeds size limit, skipping",
			"raw_length", len(result[1]),
			"max_size", maxEventSize)
		return nil
	}

	var event FinalAuditEvent
	if err := json.Unmarshal([]byte(result[1]), &event); err != nil {
		c.log.Error("redis queue consumer: malformed event, skipping",
			"error", err,
			"raw_length", len(result[1]))
		return nil
	}

	if err := c.auditRouter.Log(ctx, &event.AuditEvent); err != nil {
		c.log.Error("redis queue consumer: failed to route event",
			"error", err,
			"event_id", event.AuditEvent.ID)
	}

	return nil
}

// Shutdown stops the consumer goroutine and waits for it to exit. Idempotent.
func (c *RedisQueueConsumer) Shutdown(ctx context.Context) error {
	if !c.running.CompareAndSwap(true, false) {
		return nil
	}

	close(c.stopCh)

	select {
	case <-c.doneCh:
	case <-ctx.Done():
		c.log.Warn("redis queue consumer: shutdown context expired")
		return ctx.Err()
	}

	c.log.Info("redis queue consumer: shutdown complete")
	return nil
}
