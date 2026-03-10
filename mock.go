//go:build !production

package audit

import (
	"context"
	"sync"
	"time"
)

// MockTokenProvider is a test-only TokenProvider that returns a fixed token.
type MockTokenProvider struct {
	token string
}

func NewMockTokenProvider(token string) *MockTokenProvider {
	return &MockTokenProvider{token: token}
}

func (p *MockTokenProvider) Token(_ context.Context) (string, error) {
	return p.token, nil
}

// MockWriter is a test-only mock implementation of AuditWriter for router tests.
type MockWriter struct {
	name            string
	writeBatchCalls [][]FinalAuditEvent
	writeBatchError error
	shutdownCalls   int
	shutdownError   error
	healthError     error
	mu              sync.Mutex
	totalEvents     int           // cumulative count of individual events across all WriteBatch calls
	eventNotify     chan struct{} // signaled on each WriteBatch call
}

func NewMockWriter(name string) *MockWriter {
	return &MockWriter{
		name:            name,
		writeBatchCalls: make([][]FinalAuditEvent, 0),
		eventNotify:     make(chan struct{}, 1),
	}
}

func (m *MockWriter) WriteBatch(ctx context.Context, events []FinalAuditEvent) error {
	m.mu.Lock()
	m.writeBatchCalls = append(m.writeBatchCalls, events)
	m.totalEvents += len(events)
	err := m.writeBatchError
	m.mu.Unlock()

	// Signal any waiters (non-blocking)
	select {
	case m.eventNotify <- struct{}{}:
	default:
	}

	return err
}

func (m *MockWriter) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shutdownCalls++
	return m.shutdownError
}

func (m *MockWriter) Health(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.healthError
}

func (m *MockWriter) Name() string {
	return m.name
}

func (m *MockWriter) GetWriteBatchCalls() [][]FinalAuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	calls := make([][]FinalAuditEvent, len(m.writeBatchCalls))
	copy(calls, m.writeBatchCalls)
	return calls
}

func (m *MockWriter) GetWriteBatchCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.writeBatchCalls)
}

func (m *MockWriter) SetWriteBatchError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeBatchError = err
}

func (m *MockWriter) SetHealthError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthError = err
}

func (m *MockWriter) SetShutdownError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shutdownError = err
}

func (m *MockWriter) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeBatchCalls = make([][]FinalAuditEvent, 0)
	m.shutdownCalls = 0
	m.totalEvents = 0
	// Drain any pending notification
	select {
	case <-m.eventNotify:
	default:
	}
}

// WaitForEvents blocks until at least count total events have been written,
// or until the timeout expires. Returns true if the target was reached.
func (m *MockWriter) WaitForEvents(count int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		m.mu.Lock()
		current := m.totalEvents
		m.mu.Unlock()

		if current >= count {
			return true
		}

		select {
		case <-m.eventNotify:
			// A new batch arrived, loop and re-check
		case <-deadline:
			return false
		}
	}
}

// TotalEvents returns the cumulative count of individual events written.
func (m *MockWriter) TotalEvents() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.totalEvents
}

// BlockingMockWriter - Writer that blocks in WriteBatch to test buffer fullness
type BlockingMockWriter struct {
	*MockWriter
	blockChan            chan struct{}
	unblockChan          chan struct{}
	blocked              bool
	permanentlyUnblocked bool // Once set, WriteBatch never blocks again
	mu                   sync.Mutex
}

func NewBlockingMockWriter(name string) *BlockingMockWriter {
	return &BlockingMockWriter{
		MockWriter:           NewMockWriter(name),
		blockChan:            make(chan struct{}, 1), // Buffered to prevent signal loss
		unblockChan:          make(chan struct{}, 1), // Buffered to prevent deadlock
		blocked:              false,
		permanentlyUnblocked: false,
	}
}

func (b *BlockingMockWriter) WriteBatch(ctx context.Context, events []FinalAuditEvent) error {
	// Check if permanently unblocked (fast path for shutdown)
	b.mu.Lock()
	if b.permanentlyUnblocked {
		b.mu.Unlock()
		return b.MockWriter.WriteBatch(ctx, events)
	}

	// Signal that we're blocking
	b.blocked = true
	b.mu.Unlock()

	select {
	case b.blockChan <- struct{}{}:
	default:
		// Channel full, signal already sent
	}

	// Block until unblocked or context cancelled
	select {
	case <-b.unblockChan:
		b.mu.Lock()
		b.blocked = false
		b.mu.Unlock()
	case <-ctx.Done():
		b.mu.Lock()
		b.blocked = false
		b.mu.Unlock()
		return ctx.Err()
	}

	// Call parent's WriteBatch
	return b.MockWriter.WriteBatch(ctx, events)
}

func (b *BlockingMockWriter) WaitForBlock() bool {
	return b.WaitForBlockTimeout(10 * time.Second)
}

func (b *BlockingMockWriter) WaitForBlockTimeout(timeout time.Duration) bool {
	select {
	case <-b.blockChan:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Unblock unblocks the current blocked WriteBatch call and sets permanent unblock mode.
// After calling Unblock(), all future WriteBatch calls will pass through immediately.
func (b *BlockingMockWriter) Unblock() {
	b.mu.Lock()
	b.permanentlyUnblocked = true
	b.mu.Unlock()

	select {
	case b.unblockChan <- struct{}{}:
	default:
		// Channel full, already unblocked
	}
}

func (b *BlockingMockWriter) IsBlocked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.blocked
}
