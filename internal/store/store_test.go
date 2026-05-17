package store

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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
