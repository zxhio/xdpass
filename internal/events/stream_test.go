package events

import (
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeReader is a controllable RingbufReader for tests.
type fakeReader struct {
	mu     sync.Mutex
	closed bool
	done   chan struct{}
}

func newFakeReader() *fakeReader {
	return &fakeReader{done: make(chan struct{})}
}

func (r *fakeReader) Read() (ringbuf.Record, error) {
	<-r.done
	return ringbuf.Record{}, ringbuf.ErrClosed
}

func (r *fakeReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		close(r.done)
	}
	return nil
}

func (r *fakeReader) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func fakeReaderFactory(_ *ebpf.Map) (RingbufReader, error) {
	return newFakeReader(), nil
}

func failingReaderFactory(_ *ebpf.Map) (RingbufReader, error) {
	return nil, assert.AnError
}

func TestStreamStartReaderDuplicate(t *testing.T) {
	s := NewStreamWithFactory(t.Context(), fakeReaderFactory)
	defer s.Stop()

	err := s.StartReader(nil, 3)
	require.NoError(t, err)

	err = s.StartReader(nil, 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already started")
}

func TestStreamStopReader(t *testing.T) {
	s := NewStreamWithFactory(t.Context(), fakeReaderFactory)

	err := s.StartReader(nil, 3)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		s.StopReader(3)
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(time.Second):
		t.Fatal("StopReader blocked")
	}
}

func TestStreamStopReaderNonExistent(t *testing.T) {
	s := NewStreamWithFactory(t.Context(), fakeReaderFactory)
	defer s.Stop()

	// Should be a no-op, not panic.
	s.StopReader(99)
}

func TestStreamStopAll(t *testing.T) {
	s := NewStreamWithFactory(t.Context(), fakeReaderFactory)

	require.NoError(t, s.StartReader(nil, 1))
	require.NoError(t, s.StartReader(nil, 2))
	require.NoError(t, s.StartReader(nil, 3))

	done := make(chan struct{})
	go func() {
		s.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(time.Second):
		t.Fatal("Stop blocked")
	}
}

func TestStreamStartReaderFactoryError(t *testing.T) {
	s := NewStreamWithFactory(t.Context(), failingReaderFactory)

	err := s.StartReader(nil, 3)
	assert.Error(t, err)
}

func TestStreamReaderCount(t *testing.T) {
	s := NewStreamWithFactory(t.Context(), fakeReaderFactory)

	require.NoError(t, s.StartReader(nil, 1))
	require.NoError(t, s.StartReader(nil, 2))

	s.mu.RLock()
	count := len(s.readers)
	s.mu.RUnlock()
	assert.Equal(t, 2, count)

	s.StopReader(1)

	s.mu.RLock()
	count = len(s.readers)
	s.mu.RUnlock()
	assert.Equal(t, 1, count)
}
