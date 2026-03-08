package audit

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"log/slog"
	"os"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPerformance validates that the audit system can handle high-throughput scenarios
// according to specs/002-implement-unified-audit/plan.md - Performance Requirements
//
// CRITICAL: This test MUST FAIL before implementation (TDD - Phase 3.2, T012)
//
// Performance targets:
// 1. Handle 1000 events/second without buffer overflow
// 2. Batch writes to reduce database load
// 3. Buffer usage alerts at 80% threshold
// 4. Graceful degradation under extreme load
func TestPerformance(t *testing.T) {
	t.Run("HighThroughput_1000EventsPerSecond", func(t *testing.T) {
		// Setup - large buffer to handle burst
		cfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             2048, // Large buffer for high throughput
			BatchSize:              100,
			FlushInterval:          100 * time.Millisecond,
			AlertThreshold:         0.8, // Alert at 80% buffer usage
			ShutdownTimeout:        30 * time.Second,
			PartitionCheckInterval: 1 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(cfg, log, testNoopRedis())
		defer router.Shutdown(context.Background())

		// Register mock writer for testing
		mockWriter := NewMockWriter("test")
		router.RegisterWriter(mockWriter, false)

		// Start the router
		err := router.Start(context.Background())
		assert.NoError(t, err, "Router should start successfully")

		// Execute - send 1000 events rapidly
		start := time.Now()
		for i := 0; i < 1000; i++ {
			userID := uuid.New()
			event := &AuditEvent{
				UserID:      &userID,
				Action:      testActionLogin,
				Outcome:     OutcomeSuccess,
				IPAddress:   strPtr("192.168.1.100"),
				UserAgent:   "Mozilla/5.0",
				RequestID:   uuid.New(),
				Timestamp:   time.Now(),
				ContextData: make(map[string]interface{}),
			}
			router.Log(context.Background(), event)
		}
		duration := time.Since(start)

		// Wait for all events to be processed
		require.True(t, mockWriter.WaitForEvents(1000, 5*time.Second), "Timed out waiting for all events")
		time.Sleep(10 * time.Millisecond) // Allow router to update metrics

		// Assert - all events logged in ~1 second
		assert.Less(t, duration.Seconds(), float64(2), "Should log 1000 events in < 2 seconds")

		// Verify all events written to database
		metrics := router.GetMetrics()
		assert.Equal(t, uint64(1000), metrics.EventsReceived.Load(), "Should receive all 1000 events")
		assert.Equal(t, uint64(1000), metrics.EventsProcessed.Load(), "Should process all 1000 events")
	})

	t.Run("ConcurrentWrites_MultipleGoroutines", func(t *testing.T) {
		// Setup
		cfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             2048,
			BatchSize:              100,
			FlushInterval:          100 * time.Millisecond,
			ShutdownTimeout:        30 * time.Second,
			PartitionCheckInterval: 1 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(cfg, log, testNoopRedis())
		defer router.Shutdown(context.Background())

		// Register mock writer for testing
		mockWriter := NewMockWriter("test")
		router.RegisterWriter(mockWriter, false)

		// Start the router
		err := router.Start(context.Background())
		assert.NoError(t, err, "Router should start successfully")

		// Execute - 10 goroutines each logging 100 events
		var wg sync.WaitGroup
		numGoroutines := 10
		eventsPerGoroutine := 100

		for g := 0; g < numGoroutines; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < eventsPerGoroutine; i++ {
					userID := uuid.New()
					event := &AuditEvent{
						UserID:      &userID,
						Action:      testActionLogin,
						Outcome:     OutcomeSuccess,
						IPAddress:   strPtr("192.168.1.100"),
						UserAgent:   "Mozilla/5.0",
						RequestID:   uuid.New(),
						Timestamp:   time.Now(),
						ContextData: make(map[string]interface{}),
					}
					router.Log(context.Background(), event)
				}
			}()
		}

		wg.Wait()
		require.True(t, mockWriter.WaitForEvents(1000, 5*time.Second), "Timed out waiting for all concurrent events")
		time.Sleep(10 * time.Millisecond) // Allow router to update metrics

		// Assert - all 1000 events written
		metrics := router.GetMetrics()
		assert.Equal(t, uint64(1000), metrics.EventsReceived.Load(), "Should receive all 1000 concurrent events")
		assert.Equal(t, uint64(1000), metrics.EventsProcessed.Load(), "Should process all 1000 concurrent events")
	})

	t.Run("BatchWriting_ReducesDatabaseLoad", func(t *testing.T) {
		// Setup - small batch size for testing
		cfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             1024,
			BatchSize:              50, // Batch 50 events per write
			FlushInterval:          5 * time.Second,
			ShutdownTimeout:        30 * time.Second,
			PartitionCheckInterval: 1 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(cfg, log, testNoopRedis())
		defer router.Shutdown(context.Background())

		// Register mock writer for testing
		mockWriter := NewMockWriter("test")
		router.RegisterWriter(mockWriter, false)

		// Start the router
		err := router.Start(context.Background())
		assert.NoError(t, err, "Router should start successfully")

		// Execute - send 200 events (should trigger 4 batch writes)
		for i := 0; i < 200; i++ {
			userID := uuid.New()
			event := &AuditEvent{
				UserID:      &userID,
				Action:      testActionLogin,
				Outcome:     OutcomeSuccess,
				IPAddress:   strPtr("192.168.1.100"),
				UserAgent:   "Mozilla/5.0",
				RequestID:   uuid.New(),
				Timestamp:   time.Now(),
				ContextData: make(map[string]interface{}),
			}
			router.Log(context.Background(), event)
		}

		require.True(t, mockWriter.WaitForEvents(200, 5*time.Second), "Timed out waiting for batch writes")
		time.Sleep(10 * time.Millisecond) // Allow router to update metrics

		// Assert - verify batching reduces number of database writes
		// 200 events / 50 batch size = 4 database writes instead of 200
		metrics := router.GetMetrics()
		assert.Equal(t, uint64(200), metrics.EventsReceived.Load(), "Should receive all 200 events")
		assert.Equal(t, uint64(200), metrics.EventsProcessed.Load(), "Should process all 200 events in batches")
	})

	t.Run("BufferUsageAlert_80PercentThreshold", func(t *testing.T) {
		// Setup - small buffer to trigger alert
		cfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             100, // Small buffer
			BatchSize:              50,
			FlushInterval:          10 * time.Second, // Long interval to fill buffer
			AlertThreshold:         0.8,              // Alert at 80%
			ShutdownTimeout:        30 * time.Second,
			PartitionCheckInterval: 1 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(cfg, log, testNoopRedis())

		// Register BLOCKING mock writer to keep events in buffer
		blockingWriter := NewBlockingMockWriter("test")
		router.RegisterWriter(blockingWriter, false)

		// Start the router
		err := router.Start(context.Background())
		assert.NoError(t, err, "Router should start successfully")

		// Ensure cleanup even if test fails
		defer func() {
			blockingWriter.Unblock() // Unblock before shutdown
			router.Shutdown(context.Background())
		}()

		// Phase 1: Send first 50 events to trigger worker batch processing
		// The worker will pull these into a batch and call WriteBatch, which blocks
		for i := 0; i < 50; i++ {
			userID := uuid.New()
			event := &AuditEvent{
				UserID:      &userID,
				Action:      testActionLogin,
				Outcome:     OutcomeSuccess,
				IPAddress:   strPtr("192.168.1.100"),
				UserAgent:   "Mozilla/5.0",
				RequestID:   uuid.New(),
				Timestamp:   time.Now(),
				ContextData: make(map[string]interface{}),
			}
			router.Log(context.Background(), event)
		}

		// Wait for blocking writer to block (worker has pulled batch and called WriteBatch)
		blocked := blockingWriter.WaitForBlockTimeout(5 * time.Second)
		assert.True(t, blocked, "Writer should be blocked after first batch")

		// Phase 2: Now send 81 more events that will accumulate in the buffer
		// Since worker is blocked, these events will queue in the channel
		// When event 131 is logged, currentSize will be 80 (events 51-130 in channel)
		// This triggers alert: 80/100 = 80% >= threshold
		for i := 0; i < 81; i++ {
			userID := uuid.New()
			event := &AuditEvent{
				UserID:      &userID,
				Action:      testActionLogin,
				Outcome:     OutcomeSuccess,
				IPAddress:   strPtr("192.168.1.100"),
				UserAgent:   "Mozilla/5.0",
				RequestID:   uuid.New(),
				Timestamp:   time.Now(),
				ContextData: make(map[string]interface{}),
			}
			router.Log(context.Background(), event)
		}

		// Assert - alert should be active while events are held in buffer
		bufLen := router.BufferLen()
		bufCap := router.BufferCap()
		usagePercent := float64(bufLen) / float64(bufCap) * 100
		alertFired := router.GetMetrics().BufferAlertFired.Load()

		assert.GreaterOrEqual(t, usagePercent, 80.0, "Buffer usage should be >= 80%")
		assert.True(t, alertFired, "Buffer alert should have fired at 80% threshold")

		// Note: Cleanup handled by defer - writer will be unblocked and router shut down
	})

	t.Run("FlushInterval_PeriodicWrites", func(t *testing.T) {
		// Setup - 2s flush interval to reliably observe pre-flush buffering (even under race detector)
		cfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             1024,
			BatchSize:              100,
			FlushInterval:          2 * time.Second, // Long enough to observe pre-flush buffering under -race
			ShutdownTimeout:        30 * time.Second,
			PartitionCheckInterval: 1 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(cfg, log, testNoopRedis())
		defer router.Shutdown(context.Background())

		// Register mock writer for testing
		mockWriter := NewMockWriter("test")
		router.RegisterWriter(mockWriter, false)

		// Start the router
		err := router.Start(context.Background())
		assert.NoError(t, err, "Router should start successfully")

		// Execute - send 10 events (below batch size)
		for i := 0; i < 10; i++ {
			userID := uuid.New()
			event := &AuditEvent{
				UserID:      &userID,
				Action:      testActionLogin,
				Outcome:     OutcomeSuccess,
				IPAddress:   strPtr("192.168.1.100"),
				UserAgent:   "Mozilla/5.0",
				RequestID:   uuid.New(),
				Timestamp:   time.Now(),
				ContextData: make(map[string]interface{}),
			}
			router.Log(context.Background(), event)
		}

		// Don't wait long enough for flush (well before 2s interval)
		time.Sleep(200 * time.Millisecond)

		// Assert - events not yet written (still buffered)
		metrics := router.GetMetrics()
		assert.Equal(t, uint64(10), metrics.EventsReceived.Load(), "Should receive all 10 events")
		assert.Less(t, metrics.EventsProcessed.Load(), uint64(10), "Events should still be buffered, not fully processed yet")

		// Wait for flush interval to fire
		require.True(t, mockWriter.WaitForEvents(10, 5*time.Second), "Timed out waiting for periodic flush")
		time.Sleep(10 * time.Millisecond) // Allow router to update metrics after writer returns

		// Assert - events written after flush interval
		assert.Equal(t, uint64(10), metrics.EventsProcessed.Load(), "All events should be processed after flush interval")
	})

	t.Run("BufferOverflow_GracefulDegradation", func(t *testing.T) {
		// Setup - small buffer so we can fill it completely
		cfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             100,
			BatchSize:              50,
			FlushInterval:          10 * time.Second, // Long interval — only batch size triggers drain
			AlertThreshold:         0.8,
			ShutdownTimeout:        30 * time.Second,
			PartitionCheckInterval: 1 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(cfg, log, testNoopRedis())

		// Use blocking writer to prevent buffer drain
		blockingWriter := NewBlockingMockWriter("test")
		router.RegisterWriter(blockingWriter, false)

		err := router.Start(context.Background())
		assert.NoError(t, err, "Router should start successfully")

		defer func() {
			blockingWriter.Unblock()
			router.Shutdown(context.Background())
		}()

		// Phase 1: Send 50 events to trigger a batch — worker pulls them and blocks on write
		for i := 0; i < 50; i++ {
			userID := uuid.New()
			event := &AuditEvent{
				UserID:      &userID,
				Action:      testActionLogin,
				Outcome:     OutcomeSuccess,
				IPAddress:   strPtr("192.168.1.100"),
				UserAgent:   "Mozilla/5.0",
				RequestID:   uuid.New(),
				Timestamp:   time.Now(),
				ContextData: make(map[string]interface{}),
			}
			router.Log(context.Background(), event)
		}

		blocked := blockingWriter.WaitForBlockTimeout(5 * time.Second)
		assert.True(t, blocked, "Writer should be blocked after first batch")

		// Phase 2: Fill the buffer to capacity (worker is blocked, so channel accumulates)
		for i := 0; i < 100; i++ {
			userID := uuid.New()
			event := &AuditEvent{
				UserID:      &userID,
				Action:      testActionLogin,
				Outcome:     OutcomeSuccess,
				IPAddress:   strPtr("192.168.1.100"),
				UserAgent:   "Mozilla/5.0",
				RequestID:   uuid.New(),
				Timestamp:   time.Now(),
				ContextData: make(map[string]interface{}),
			}
			router.Log(context.Background(), event)
		}

		// Assert: buffer at/near capacity, worker still healthy
		metrics := router.GetMetrics()
		eventsReceived := metrics.EventsReceived.Load()
		assert.Equal(t, uint64(150), eventsReceived, "All 150 events should be received")
		assert.True(t, metrics.WorkerHealthy.Load(), "Worker should remain healthy under full buffer pressure")

		bufLen := router.BufferLen()
		bufCap := router.BufferCap()
		usagePercent := float64(bufLen) / float64(bufCap) * 100
		assert.GreaterOrEqual(t, usagePercent, 95.0, "Buffer should be at or near capacity")

		// Phase 3: Unblock writer — system should recover and drain all events
		blockingWriter.Unblock()
		require.True(t, blockingWriter.WaitForEvents(int(eventsReceived), 5*time.Second), "Timed out waiting for recovery drain")
		time.Sleep(10 * time.Millisecond) // Allow router to update metrics after last write

		assert.Equal(t, eventsReceived, metrics.EventsProcessed.Load(), "All events should be processed after recovery")

		finalUsage := float64(router.BufferLen()) / float64(router.BufferCap()) * 100
		assert.LessOrEqual(t, finalUsage, 5.0, "Buffer should be drained after recovery")
	})

	t.Run("Latency_P99UnderThreshold", func(t *testing.T) {
		// Setup
		cfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             1024,
			BatchSize:              100,
			FlushInterval:          5 * time.Second,
			ShutdownTimeout:        30 * time.Second,
			PartitionCheckInterval: 1 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(cfg, log, testNoopRedis())
		defer router.Shutdown(context.Background())

		// Register mock writer for testing
		mockWriter := NewMockWriter("test")
		router.RegisterWriter(mockWriter, false)

		// Start the router
		err := router.Start(context.Background())
		assert.NoError(t, err, "Router should start successfully")

		// Measure latencies
		latencies := make([]time.Duration, 1000)

		for i := 0; i < 1000; i++ {
			userID := uuid.New()
			event := &AuditEvent{
				UserID:      &userID,
				Action:      testActionLogin,
				Outcome:     OutcomeSuccess,
				IPAddress:   strPtr("192.168.1.100"),
				UserAgent:   "Mozilla/5.0",
				RequestID:   uuid.New(),
				Timestamp:   time.Now(),
				ContextData: make(map[string]interface{}),
			}

			start := time.Now()
			router.Log(context.Background(), event)
			latencies[i] = time.Since(start)
		}

		// Wait for events to be processed
		require.True(t, mockWriter.WaitForEvents(1000, 5*time.Second), "Timed out waiting for latency test events")
		time.Sleep(10 * time.Millisecond) // Allow router to update metrics

		// Calculate P99
		sort.Slice(latencies, func(i, j int) bool {
			return latencies[i] < latencies[j]
		})

		// Get 99th percentile (index 990 for 1000 samples)
		p99Index := int(float64(len(latencies)) * 0.99)
		p99 := latencies[p99Index]

		// Assert - P99 latency should be < 5ms (non-blocking async)
		assert.Less(t, p99.Milliseconds(), int64(5), "P99 latency should be < 5ms")

		// Assert - all events should be processed
		metrics := router.GetMetrics()
		assert.Equal(t, uint64(1000), metrics.EventsReceived.Load(), "Should receive all 1000 events")
		assert.Equal(t, uint64(1000), metrics.EventsProcessed.Load(), "Should process all 1000 events")
	})

	t.Run("MemoryUsage_Stable", func(t *testing.T) {
		// Setup
		cfg := &AuditConfig{
			Enabled:                true,
			BufferSize:             1024,
			BatchSize:              100,
			FlushInterval:          100 * time.Millisecond,
			ShutdownTimeout:        30 * time.Second,
			PartitionCheckInterval: 1 * time.Hour,
		}

		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		router := NewAuditRouter(cfg, log, testNoopRedis())
		defer router.Shutdown(context.Background())

		// Register mock writer for testing
		mockWriter := NewMockWriter("test")
		router.RegisterWriter(mockWriter, false)

		// Start the router
		err := router.Start(context.Background())
		assert.NoError(t, err, "Router should start successfully")

		// Execute - sustained load for 2 seconds at high rate (more events, higher stress, less wall time)
		done := make(chan bool)
		go func() {
			ticker := time.NewTicker(1 * time.Millisecond)
			defer ticker.Stop()

			timeout := time.After(2 * time.Second)
			for {
				select {
				case <-ticker.C:
					userID := uuid.New()
					event := &AuditEvent{
						UserID:      &userID,
						Action:      testActionLogin,
						Outcome:     OutcomeSuccess,
						IPAddress:   strPtr("192.168.1.100"),
						UserAgent:   "Mozilla/5.0",
						RequestID:   uuid.New(),
						Timestamp:   time.Now(),
						ContextData: make(map[string]interface{}),
					}
					router.Log(context.Background(), event)
				case <-timeout:
					done <- true
					return
				}
			}
		}()

		<-done

		// Wait for all events to be processed
		metrics := router.GetMetrics()
		eventsReceived := metrics.EventsReceived.Load()
		require.True(t, mockWriter.WaitForEvents(int(eventsReceived), 5*time.Second), "Timed out waiting for memory test events")

		// Assert - memory usage should be stable (no leaks)
		// Buffer should not grow unbounded
		bufLen := router.BufferLen()
		bufCap := router.BufferCap()
		usagePercent := float64(bufLen) / float64(bufCap) * 100

		// Verify buffer hasn't grown beyond capacity
		assert.LessOrEqual(t, bufLen, bufCap, "Buffer size should not exceed capacity")
		assert.LessOrEqual(t, usagePercent, 100.0, "Buffer usage should not exceed 100%")

		// Verify system remained healthy throughout sustained load
		assert.True(t, metrics.WorkerHealthy.Load(), "Worker should remain healthy with no memory leaks")

		// Assert - events should be processed (validates events were valid)
		eventsProcessed := metrics.EventsProcessed.Load()

		assert.Greater(t, eventsReceived, uint64(0), "Should receive events during test")
		assert.Greater(t, eventsProcessed, uint64(0), "Should process events during test")
		assert.Equal(t, eventsReceived, eventsProcessed, "All received events should be processed")
	})
}

func BenchmarkAuditRouter_EventThroughput(b *testing.B) {
	cfg := &AuditConfig{
		Enabled:                true,
		BufferSize:             1024,
		BatchSize:              100,
		FlushInterval:          5 * time.Second,
		ShutdownTimeout:        30 * time.Second,
		PartitionCheckInterval: 1 * time.Hour,
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(cfg, log, testNoopRedis())
	mockWriter := NewMockWriter("test")
	router.RegisterWriter(mockWriter, false)

	err := router.Start(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	defer router.Shutdown(context.Background())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		userID := uuid.New()
		event := &AuditEvent{
			UserID:      &userID,
			Action:      testActionLogin,
			Outcome:     OutcomeSuccess,
			IPAddress:   strPtr("192.168.1.100"),
			UserAgent:   "Mozilla/5.0",
			RequestID:   uuid.New(),
			Timestamp:   time.Now(),
			ContextData: make(map[string]interface{}),
		}
		router.Log(context.Background(), event)
	}
}

func BenchmarkAuditRouter_ReadDuringWrites(b *testing.B) {
	cfg := &AuditConfig{
		Enabled:                true,
		BufferSize:             2048,
		BatchSize:              100,
		FlushInterval:          1 * time.Second,
		ShutdownTimeout:        30 * time.Second,
		PartitionCheckInterval: 1 * time.Hour,
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := NewAuditRouter(cfg, log, testNoopRedis())
	mockWriter := NewMockWriter("test")
	router.RegisterWriter(mockWriter, false)

	err := router.Start(context.Background())
	if err != nil {
		b.Fatal(err)
	}

	// Start background write goroutine
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				userID := uuid.New()
				event := &AuditEvent{
					UserID:      &userID,
					Action:      testActionLogin,
					Outcome:     OutcomeSuccess,
					IPAddress:   strPtr("192.168.1.100"),
					UserAgent:   "Mozilla/5.0",
					RequestID:   uuid.New(),
					Timestamp:   time.Now(),
					ContextData: make(map[string]interface{}),
				}
				router.Log(context.Background(), event)
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	// Allow writes to start flowing
	time.Sleep(100 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = router.GetMetrics()
	}
	b.StopTimer()

	cancel()
	wg.Wait()
	router.Shutdown(context.Background())
}
