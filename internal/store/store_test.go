package store

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"xdpass/internal/api"
	"xdpass/internal/attachment"
	"xdpass/internal/dispatch"
	"xdpass/internal/events"
	"xdpass/internal/response"
	"xdpass/internal/xsk"
)

func mockStoreLoadBPF() (*ebpf.Collection, error) {
	return &ebpf.Collection{
		Programs: map[string]*ebpf.Program{},
		Maps:     map[string]*ebpf.Map{},
	}, nil
}

func mockStoreLoadBPFWithEventRingbuf() (*ebpf.Collection, error) {
	rbMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.RingBuf,
		MaxEntries: 4096,
	})
	if err != nil {
		return nil, err
	}
	return &ebpf.Collection{
		Programs: map[string]*ebpf.Program{},
		Maps:     map[string]*ebpf.Map{"event_ringbuf": rbMap},
	}, nil
}

func mockStoreAttachXDP(_ *ebpf.Program, _ int, _ string) (link.Link, error) {
	return nil, nil
}

func TestDeleteAttachmentWithCallbacksReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attRuntime := attachment.New(mockStoreLoadBPF, mockStoreAttachXDP)
	eventStream := events.NewStream(ctx)
	responseRuntime := response.NewRuntime(ctx, &response.RulesetRuleLookup{})
	xskRuntime := xsk.NewRuntime(ctx)
	dispatchRuntime := dispatch.NewRuntime(ctx)
	t.Cleanup(responseRuntime.Stop)
	t.Cleanup(xskRuntime.StopAll)
	t.Cleanup(dispatchRuntime.Stop)
	t.Cleanup(eventStream.Stop)

	s := New(attRuntime, eventStream, responseRuntime, xskRuntime, dispatchRuntime)
	s.WireXSKCallbacks()
	s.WireEventCallbacks()

	_, err := s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.DeleteAttachment(ctx, 3)
	}()

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("delete attachment blocked with XSK callbacks wired")
	}
}

// fakeReader is a controllable ringbufReader for tests.
type fakeReader struct {
	closed chan struct{}
}

func newFakeReader() *fakeReader {
	return &fakeReader{closed: make(chan struct{})}
}

func (r *fakeReader) Read() (ringbuf.Record, error) {
	<-r.closed
	return ringbuf.Record{}, ringbuf.ErrClosed
}

func (r *fakeReader) Close() error {
	select {
	case <-r.closed:
	default:
		close(r.closed)
	}
	return nil
}

func fakeReaderFactory(_ *ebpf.Map) (events.RingbufReader, error) {
	return newFakeReader(), nil
}

func failingReaderFactory(_ *ebpf.Map) (events.RingbufReader, error) {
	return nil, assert.AnError
}

func newTestStoreWithEventFactory(t *testing.T, loadBPF attachment.LoadFunc, factory events.RingbufReaderFactory) *Store {
	t.Helper()
	ctx := t.Context()
	attRuntime := attachment.New(loadBPF, mockStoreAttachXDP)
	eventStream := events.NewStreamWithFactory(ctx, factory)
	responseRuntime := response.NewRuntime(ctx, &response.RulesetRuleLookup{})
	xskRuntime := xsk.NewRuntime(ctx)
	dispatchRuntime := dispatch.NewRuntime(ctx)
	t.Cleanup(responseRuntime.Stop)
	t.Cleanup(xskRuntime.StopAll)
	t.Cleanup(dispatchRuntime.Stop)
	t.Cleanup(eventStream.Stop)

	s := New(attRuntime, eventStream, responseRuntime, xskRuntime, dispatchRuntime)
	s.WireXSKCallbacks()
	s.WireEventCallbacks()
	return s
}

func TestEventReaderStartFailureRollsBack(t *testing.T) {
	s := newTestStoreWithEventFactory(t, mockStoreLoadBPFWithEventRingbuf, failingReaderFactory)
	ctx := t.Context()

	_, err := s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "event reader start")

	// Attachment should not exist after rollback.
	_, err = s.GetAttachment(ctx, 3)
	assert.Error(t, err)
}

func TestEventReaderCreateStartsReader(t *testing.T) {
	s := newTestStoreWithEventFactory(t, mockStoreLoadBPFWithEventRingbuf, fakeReaderFactory)
	ctx := t.Context()

	_, err := s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
	require.NoError(t, err)

	// Duplicate start should fail (reader already running).
	err = s.eventStream.StartReader(nil, 3)
	assert.Error(t, err)
}

func TestEventReaderDisableStopsReader(t *testing.T) {
	s := newTestStoreWithEventFactory(t, mockStoreLoadBPFWithEventRingbuf, fakeReaderFactory)
	ctx := t.Context()

	_, err := s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
	require.NoError(t, err)

	// Disable should stop the reader.
	_, err = s.PatchAttachment(ctx, 3, false)
	require.NoError(t, err)

	// Re-starting should succeed (reader was stopped).
	err = s.eventStream.StartReader(nil, 3)
	assert.NoError(t, err)
	s.eventStream.StopReader(3)
}

func TestEventReaderDeleteStopsReader(t *testing.T) {
	s := newTestStoreWithEventFactory(t, mockStoreLoadBPFWithEventRingbuf, fakeReaderFactory)
	ctx := t.Context()

	_, err := s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
	require.NoError(t, err)

	// Delete should stop the reader.
	err = s.DeleteAttachment(ctx, 3)
	require.NoError(t, err)

	// Re-starting should succeed (reader was stopped).
	err = s.eventStream.StartReader(nil, 3)
	assert.NoError(t, err)
	s.eventStream.StopReader(3)
}
