package dispatch

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSender records sent packets and errors.
type mockSender struct {
	mu      sync.Mutex
	packets [][]byte
	err     error
	closed  bool
}

func (s *mockSender) Send(pkt []byte) error {
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	s.packets = append(s.packets, cp)
	return nil
}

func (s *mockSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *mockSender) Sent() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([][]byte, len(s.packets))
	copy(result, s.packets)
	return result
}

func TestTryEnqueueWhenDisabled(t *testing.T) {
	rt := NewRuntime(context.Background())
	defer rt.Stop()

	ok := rt.TryEnqueue([]byte{1, 2, 3})
	assert.False(t, ok)

	snap := rt.Stats().Snapshot()
	assert.Equal(t, uint64(1), snap.DroppedPackets)
	assert.Equal(t, uint64(0), snap.EnqueuePackets)
}

func TestTryEnqueueSuccess(t *testing.T) {
	rt := NewRuntime(context.Background())
	sender := &mockSender{}

	require.NoError(t, rt.Start(sender, Options{QueueSize: 16}))
	defer rt.Stop()

	ok := rt.TryEnqueue([]byte{1, 2, 3})
	assert.True(t, ok)

	snap := rt.Stats().Snapshot()
	assert.Equal(t, uint64(1), snap.EnqueuePackets)

	// Wait for worker to process.
	require.Eventually(t, func() bool {
		return len(sender.Sent()) == 1
	}, time.Second, 10*time.Millisecond)

	snap = rt.Stats().Snapshot()
	assert.Equal(t, uint64(1), snap.Packets)
	assert.Equal(t, uint64(0), snap.ErrorPackets)
}

func TestTryEnqueueQueueFull(t *testing.T) {
	rt := NewRuntime(context.Background())
	sender := &mockSender{err: context.DeadlineExceeded} // block sends

	require.NoError(t, rt.Start(sender, Options{QueueSize: 2}))
	defer rt.Stop()

	// Fill the queue.
	assert.True(t, rt.TryEnqueue([]byte{1}))
	assert.True(t, rt.TryEnqueue([]byte{2}))

	// Queue is full.
	assert.False(t, rt.TryEnqueue([]byte{3}))

	snap := rt.Stats().Snapshot()
	assert.Equal(t, uint64(1), snap.QueueFullPackets)
	assert.Equal(t, uint64(1), snap.DroppedPackets)
}

func TestTryEnqueueAfterStop(t *testing.T) {
	rt := NewRuntime(context.Background())
	sender := &mockSender{}

	require.NoError(t, rt.Start(sender, Options{QueueSize: 16}))
	rt.Stop()

	ok := rt.TryEnqueue([]byte{1, 2, 3})
	assert.False(t, ok)

	snap := rt.Stats().Snapshot()
	assert.Equal(t, uint64(1), snap.DroppedPackets)
}

func TestStopDrainsQueue(t *testing.T) {
	rt := NewRuntime(context.Background())
	// Use a sender that returns error so worker can't drain the queue fast enough.
	sender := &mockSender{err: context.DeadlineExceeded}

	require.NoError(t, rt.Start(sender, Options{QueueSize: 16}))

	rt.TryEnqueue([]byte{1})
	rt.TryEnqueue([]byte{2})
	rt.TryEnqueue([]byte{3})

	rt.Stop()

	snap := rt.Stats().Snapshot()
	// Packets are either drained as dropped or consumed and errored by worker.
	assert.Equal(t, uint64(3), snap.DroppedPackets+snap.ErrorPackets)
}

func TestSenderError(t *testing.T) {
	rt := NewRuntime(context.Background())
	sender := &mockSender{err: assert.AnError}

	require.NoError(t, rt.Start(sender, Options{QueueSize: 16}))
	defer rt.Stop()

	rt.TryEnqueue([]byte{1})

	// Wait for worker to attempt send.
	require.Eventually(t, func() bool {
		return rt.Stats().Snapshot().ErrorPackets > 0
	}, time.Second, 10*time.Millisecond)

	snap := rt.Stats().Snapshot()
	assert.Equal(t, uint64(1), snap.ErrorPackets)
	assert.Equal(t, uint64(0), snap.Packets)
}

func TestIsEnabled(t *testing.T) {
	rt := NewRuntime(context.Background())
	assert.False(t, rt.IsEnabled())

	sender := &mockSender{}
	require.NoError(t, rt.Start(sender, Options{QueueSize: 16}))
	assert.True(t, rt.IsEnabled())

	rt.Stop()
	assert.False(t, rt.IsEnabled())
}

func TestMultiplePackets(t *testing.T) {
	rt := NewRuntime(context.Background())
	sender := &mockSender{}

	require.NoError(t, rt.Start(sender, Options{QueueSize: 64}))
	defer rt.Stop()

	for i := range 10 {
		rt.TryEnqueue([]byte{byte(i)})
	}

	require.Eventually(t, func() bool {
		return len(sender.Sent()) == 10
	}, time.Second, 10*time.Millisecond)

	snap := rt.Stats().Snapshot()
	assert.Equal(t, uint64(10), snap.EnqueuePackets)
	assert.Equal(t, uint64(10), snap.Packets)
}

func TestConcurrentEnqueue(t *testing.T) {
	rt := NewRuntime(context.Background())
	sender := &mockSender{}

	require.NoError(t, rt.Start(sender, Options{QueueSize: 1024}))
	defer rt.Stop()

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(n byte) {
			defer wg.Done()
			rt.TryEnqueue([]byte{n})
		}(byte(i))
	}
	wg.Wait()

	require.Eventually(t, func() bool {
		return len(sender.Sent()) == 100
	}, time.Second, 10*time.Millisecond)

	snap := rt.Stats().Snapshot()
	assert.Equal(t, uint64(100), snap.Packets)
}

func TestRestartRuntime(t *testing.T) {
	rt := NewRuntime(context.Background())
	sender1 := &mockSender{}

	require.NoError(t, rt.Start(sender1, Options{QueueSize: 16}))
	rt.TryEnqueue([]byte{1})

	require.Eventually(t, func() bool {
		return len(sender1.Sent()) == 1
	}, time.Second, 10*time.Millisecond)

	// Restart with new sender.
	sender2 := &mockSender{}
	require.NoError(t, rt.Start(sender2, Options{QueueSize: 16}))

	// Old sender should be closed.
	assert.True(t, sender1.closed)

	rt.TryEnqueue([]byte{2})

	require.Eventually(t, func() bool {
		return len(sender2.Sent()) == 1
	}, time.Second, 10*time.Millisecond)

	rt.Stop()
}

func TestStatsSnapshotConcurrency(t *testing.T) {
	rt := NewRuntime(context.Background())
	sender := &mockSender{}

	require.NoError(t, rt.Start(sender, Options{QueueSize: 64}))
	defer rt.Stop()

	var wg sync.WaitGroup
	var enqueueCount atomic.Uint64

	for i := range 50 {
		wg.Add(2)
		go func(n byte) {
			defer wg.Done()
			if rt.TryEnqueue([]byte{n}) {
				enqueueCount.Add(1)
			}
		}(byte(i))
		go func() {
			defer wg.Done()
			_ = rt.Stats().Snapshot()
		}()
	}

	wg.Wait()
}
