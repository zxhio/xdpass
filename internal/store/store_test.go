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

	"golang.org/x/sys/unix"

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

type noopPromiscuousHandle struct{}

func (noopPromiscuousHandle) Close() error { return nil }

func disableTestPromiscuous(rt *attachment.Runtime) {
	rt.SetPromiscuousOpen(func(uint32) (attachment.PromiscuousHandle, error) {
		return noopPromiscuousHandle{}, nil
	})
}

func TestDeleteAttachmentWithCallbacksReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attRuntime := attachment.New(mockStoreLoadBPF, mockStoreAttachXDP)
	disableTestPromiscuous(attRuntime)
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
	disableTestPromiscuous(attRuntime)
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

// --- Ruleset lifecycle apply tests ---

// mockStoreLoadBPFWithRulesetMaps creates a BPF collection with all maps needed by ruleset.WriteMaps.
func mockStoreLoadBPFWithRulesetMaps() (*ebpf.Collection, error) {
	ruleIndexMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  12, // sizeof(bpfRuleMeta)
		MaxEntries: 512,
	})
	if err != nil {
		return nil, err
	}

	globalCfgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  1416, // sizeof(bpfGlobalCfg)
		MaxEntries: 1,
	})
	if err != nil {
		ruleIndexMap.Close()
		return nil, err
	}

	newHashMap := func() (*ebpf.Map, error) {
		return ebpf.NewMap(&ebpf.MapSpec{
			Type:       ebpf.Hash,
			KeySize:    2,
			ValueSize:  64,
			MaxEntries: 256,
		})
	}

	srcPortMap, err := newHashMap()
	if err != nil {
		ruleIndexMap.Close()
		globalCfgMap.Close()
		return nil, err
	}

	dstPortMap, err := newHashMap()
	if err != nil {
		ruleIndexMap.Close()
		globalCfgMap.Close()
		srcPortMap.Close()
		return nil, err
	}

	vlanMap, err := newHashMap()
	if err != nil {
		ruleIndexMap.Close()
		globalCfgMap.Close()
		srcPortMap.Close()
		dstPortMap.Close()
		return nil, err
	}

	newLpmMap := func() (*ebpf.Map, error) {
		return ebpf.NewMap(&ebpf.MapSpec{
			Type:       ebpf.LPMTrie,
			KeySize:    8,
			ValueSize:  64,
			MaxEntries: 256,
			Flags:      unix.BPF_F_NO_PREALLOC,
		})
	}

	srcLpmMap, err := newLpmMap()
	if err != nil {
		ruleIndexMap.Close()
		globalCfgMap.Close()
		srcPortMap.Close()
		dstPortMap.Close()
		vlanMap.Close()
		return nil, err
	}

	dstLpmMap, err := newLpmMap()
	if err != nil {
		ruleIndexMap.Close()
		globalCfgMap.Close()
		srcPortMap.Close()
		dstPortMap.Close()
		vlanMap.Close()
		srcLpmMap.Close()
		return nil, err
	}

	return &ebpf.Collection{
		Programs: map[string]*ebpf.Program{},
		Maps: map[string]*ebpf.Map{
			"rule_index_map":     ruleIndexMap,
			"global_cfg_map":     globalCfgMap,
			"src_port_index_map": srcPortMap,
			"dst_port_index_map": dstPortMap,
			"vlan_index_map":     vlanMap,
			"src_prefix_lpm_map": srcLpmMap,
			"dst_prefix_lpm_map": dstLpmMap,
		},
	}, nil
}

// newTestStoreWithRulesetMaps creates a store with BPF maps that support ruleset writes.
func newTestStoreWithRulesetMaps(t *testing.T) *Store {
	t.Helper()
	ctx := t.Context()
	attRuntime := attachment.New(mockStoreLoadBPFWithRulesetMaps, mockStoreAttachXDP)
	disableTestPromiscuous(attRuntime)
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
	s.WireRulesetCallbacks()
	return s
}

func TestRulesetLifecycleApply(t *testing.T) {
	t.Run("create with ruleset applies", func(t *testing.T) {
		s := newTestStoreWithRulesetMaps(t)
		ctx := t.Context()

		apiRules := []api.RuleResponse{
			{RuleID: 1001, Priority: 10, Response: api.ResponseResponse{Action: "alert"}},
		}
		_, err := s.ReplaceRuleset(ctx, apiRules)
		require.NoError(t, err)

		_, err = s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
		require.NoError(t, err)

		_, gen := s.rulesetRuntime.CurrentCompiled()
		assert.Equal(t, gen, s.applyGeneration[3])
	})

	t.Run("create without ruleset skips apply", func(t *testing.T) {
		s := newTestStoreWithRulesetMaps(t)
		ctx := t.Context()

		_, err := s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
		require.NoError(t, err)

		_, exists := s.applyGeneration[3]
		assert.False(t, exists)
	})

	t.Run("enable applies ruleset", func(t *testing.T) {
		s := newTestStoreWithRulesetMaps(t)
		ctx := t.Context()

		_, err := s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
		require.NoError(t, err)
		_, err = s.PatchAttachment(ctx, 3, false)
		require.NoError(t, err)

		apiRules := []api.RuleResponse{
			{RuleID: 1001, Priority: 10, Response: api.ResponseResponse{Action: "alert"}},
		}
		_, err = s.ReplaceRuleset(ctx, apiRules)
		require.NoError(t, err)

		_, err = s.PatchAttachment(ctx, 3, true)
		require.NoError(t, err)

		_, gen := s.rulesetRuntime.CurrentCompiled()
		assert.Equal(t, gen, s.applyGeneration[3])
	})

	t.Run("create failure rolls back attachment", func(t *testing.T) {
		ctx := t.Context()
		attRuntime := attachment.New(mockStoreLoadBPF, mockStoreAttachXDP)
		disableTestPromiscuous(attRuntime)
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
		s.WireRulesetCallbacks()

		apiRules := []api.RuleResponse{
			{RuleID: 1001, Priority: 10, Response: api.ResponseResponse{Action: "alert"}},
		}
		_, err := s.ReplaceRuleset(ctx, apiRules)
		require.NoError(t, err)

		_, err = s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ruleset apply")

		_, err = s.GetAttachment(ctx, 3)
		assert.Error(t, err)
	})

	t.Run("disable and delete clear generation", func(t *testing.T) {
		s := newTestStoreWithRulesetMaps(t)
		ctx := t.Context()

		apiRules := []api.RuleResponse{
			{RuleID: 1001, Priority: 10, Response: api.ResponseResponse{Action: "alert"}},
		}
		_, err := s.ReplaceRuleset(ctx, apiRules)
		require.NoError(t, err)

		// Create two attachments.
		_, err = s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
		require.NoError(t, err)
		_, err = s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 4})
		require.NoError(t, err)
		assert.Equal(t, uint64(1), s.applyGeneration[3])
		assert.Equal(t, uint64(1), s.applyGeneration[4])

		// Disable clears generation for that attachment.
		_, err = s.PatchAttachment(ctx, 3, false)
		require.NoError(t, err)
		_, exists := s.applyGeneration[3]
		assert.False(t, exists)
		assert.Equal(t, uint64(1), s.applyGeneration[4]) // other unaffected

		// Delete clears generation for that attachment.
		err = s.DeleteAttachment(ctx, 4)
		require.NoError(t, err)
		_, exists = s.applyGeneration[4]
		assert.False(t, exists)
	})

	t.Run("ruleset delete clears all generations", func(t *testing.T) {
		s := newTestStoreWithRulesetMaps(t)
		ctx := t.Context()

		apiRules := []api.RuleResponse{
			{RuleID: 1001, Priority: 10, Response: api.ResponseResponse{Action: "alert"}},
		}
		_, err := s.ReplaceRuleset(ctx, apiRules)
		require.NoError(t, err)

		_, err = s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
		require.NoError(t, err)
		_, err = s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 4})
		require.NoError(t, err)

		err = s.DeleteRuleset(ctx)
		require.NoError(t, err)

		_, exists3 := s.applyGeneration[3]
		_, exists4 := s.applyGeneration[4]
		assert.False(t, exists3)
		assert.False(t, exists4)
	})

	t.Run("ruleset replace updates existing attachments", func(t *testing.T) {
		s := newTestStoreWithRulesetMaps(t)
		ctx := t.Context()

		// Create attachment before any ruleset.
		_, err := s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
		require.NoError(t, err)
		_, exists := s.applyGeneration[3]
		assert.False(t, exists)

		// ReplaceRuleset should update generation for existing enabled attachments.
		apiRules := []api.RuleResponse{
			{RuleID: 1001, Priority: 10, Response: api.ResponseResponse{Action: "alert"}},
		}
		_, err = s.ReplaceRuleset(ctx, apiRules)
		require.NoError(t, err)

		_, gen := s.rulesetRuntime.CurrentCompiled()
		assert.Equal(t, gen, s.applyGeneration[3])
	})
}

// issuesWithCode returns issues matching the given code.
func issuesWithCode(issues []api.StatusIssue, code string) []api.StatusIssue {
	var result []api.StatusIssue
	for _, issue := range issues {
		if issue.Code == code {
			result = append(result, issue)
		}
	}
	return result
}

func TestStatusDegradedHealth(t *testing.T) {
	t.Run("running with no attachments and no ruleset", func(t *testing.T) {
		s := newTestStoreWithRulesetMaps(t)
		ctx := t.Context()

		resp, err := s.Status(ctx)
		require.NoError(t, err)
		assert.Equal(t, "running", resp.Status)
		assert.Nil(t, resp.Issues)
		assert.Equal(t, 0, resp.Attachments)
		assert.False(t, resp.RulesetLoaded)
	})

	t.Run("degraded with userspace action without xsk", func(t *testing.T) {
		s := newTestStoreWithRulesetMaps(t)
		ctx := t.Context()

		// icmp_echo_reply is a userspace action.
		apiRules := []api.RuleResponse{
			{RuleID: 1001, Priority: 10, Response: api.ResponseResponse{Action: "icmp_echo_reply"}},
		}
		_, err := s.ReplaceRuleset(ctx, apiRules)
		require.NoError(t, err)

		// Create attachment without XSK.
		_, err = s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
		require.NoError(t, err)

		resp, err := s.Status(ctx)
		require.NoError(t, err)
		assert.Equal(t, "degraded", resp.Status)
		assert.NotEmpty(t, issuesWithCode(resp.Issues, "userspace_action_without_xsk"))
	})

	t.Run("degraded with ruleset not applied", func(t *testing.T) {
		s := newTestStoreWithRulesetMaps(t)
		ctx := t.Context()

		_, err := s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
		require.NoError(t, err)

		apiRules := []api.RuleResponse{
			{RuleID: 1001, Priority: 10, Response: api.ResponseResponse{Action: "alert"}},
		}
		_, err = s.ReplaceRuleset(ctx, apiRules)
		require.NoError(t, err)

		// Manually clear generation to simulate not-applied state.
		delete(s.applyGeneration, 3)

		resp, err := s.Status(ctx)
		require.NoError(t, err)
		assert.Equal(t, "degraded", resp.Status)

		matches := issuesWithCode(resp.Issues, "ruleset_not_applied")
		require.Len(t, matches, 1)
		assert.Equal(t, uint32(3), matches[0].IfIndex)
	})

	t.Run("degraded with stale generation", func(t *testing.T) {
		s := newTestStoreWithRulesetMaps(t)
		ctx := t.Context()

		apiRules := []api.RuleResponse{
			{RuleID: 1001, Priority: 10, Response: api.ResponseResponse{Action: "alert"}},
		}
		_, err := s.ReplaceRuleset(ctx, apiRules)
		require.NoError(t, err)

		_, err = s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
		require.NoError(t, err)

		// Replace ruleset again — generation advances.
		apiRules2 := []api.RuleResponse{
			{RuleID: 1001, Priority: 10, Response: api.ResponseResponse{Action: "alert"}},
			{RuleID: 1002, Priority: 20, Response: api.ResponseResponse{Action: "alert"}},
		}
		_, err = s.ReplaceRuleset(ctx, apiRules2)
		require.NoError(t, err)

		// Reset attachment's generation to stale.
		s.applyGeneration[3] = 1

		resp, err := s.Status(ctx)
		require.NoError(t, err)
		assert.Equal(t, "degraded", resp.Status)
		assert.NotEmpty(t, issuesWithCode(resp.Issues, "ruleset_not_applied"))
	})

	t.Run("running after disable clears issues", func(t *testing.T) {
		s := newTestStoreWithRulesetMaps(t)
		ctx := t.Context()

		apiRules := []api.RuleResponse{
			{RuleID: 1001, Priority: 10, Response: api.ResponseResponse{Action: "icmp_echo_reply"}},
		}
		_, err := s.ReplaceRuleset(ctx, apiRules)
		require.NoError(t, err)

		_, err = s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
		require.NoError(t, err)

		// Disable attachment — userspace_action_without_xsk should clear.
		_, err = s.PatchAttachment(ctx, 3, false)
		require.NoError(t, err)

		resp, err := s.Status(ctx)
		require.NoError(t, err)
		assert.Equal(t, "running", resp.Status)
		assert.Nil(t, resp.Issues)
	})

	t.Run("no userspace_action issue for non-userspace action", func(t *testing.T) {
		s := newTestStoreWithRulesetMaps(t)
		ctx := t.Context()

		// alert is not a userspace action.
		apiRules := []api.RuleResponse{
			{RuleID: 1001, Priority: 10, Response: api.ResponseResponse{Action: "alert"}},
		}
		_, err := s.ReplaceRuleset(ctx, apiRules)
		require.NoError(t, err)

		_, err = s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
		require.NoError(t, err)

		resp, err := s.Status(ctx)
		require.NoError(t, err)
		assert.Empty(t, issuesWithCode(resp.Issues, "userspace_action_without_xsk"))
	})

	t.Run("running when ruleset applied and no ruleset issues", func(t *testing.T) {
		s := newTestStoreWithRulesetMaps(t)
		ctx := t.Context()

		apiRules := []api.RuleResponse{
			{RuleID: 1001, Priority: 10, Response: api.ResponseResponse{Action: "alert"}},
		}
		_, err := s.ReplaceRuleset(ctx, apiRules)
		require.NoError(t, err)

		_, err = s.CreateAttachment(ctx, api.AttachmentRequest{IfIndex: 3})
		require.NoError(t, err)

		resp, err := s.Status(ctx)
		require.NoError(t, err)
		assert.True(t, resp.RulesetLoaded)
		assert.Equal(t, 1, resp.Rules)
		// No ruleset-specific issues.
		assert.Empty(t, issuesWithCode(resp.Issues, "ruleset_not_applied"))
		assert.Empty(t, issuesWithCode(resp.Issues, "userspace_action_without_xsk"))
	})
}
