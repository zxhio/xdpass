package attachment

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"xdpass/internal/xsk"
)

func mockLoadBPF() (*ebpf.Collection, error) {
	return &ebpf.Collection{
		Programs: map[string]*ebpf.Program{},
		Maps:     map[string]*ebpf.Map{},
	}, nil
}

func mockAttachXDP(_ *ebpf.Program, _ int, _ string) (link.Link, error) {
	return nil, nil
}

type noopPromiscuousHandle struct{}

func (noopPromiscuousHandle) Close() error { return nil }

func newTestRuntime() *Runtime {
	rt := New(mockLoadBPF, mockAttachXDP)
	rt.SetQueueProbe(func(uint32) (uint32, error) { return 2, nil })
	rt.SetPromiscuousOpen(func(uint32) (PromiscuousHandle, error) {
		return noopPromiscuousHandle{}, nil
	})
	return rt
}

func TestDryRunDoesNotPersist(t *testing.T) {
	rt := newTestRuntime()
	att, err := rt.DryRun(&Request{IfIndex: 3})
	require.NoError(t, err)
	assert.Equal(t, uint32(3), att.IfIndex)
	assert.True(t, att.Enabled)

	_, err = rt.Get(3)
	var nfe *NotFoundError
	assert.ErrorAs(t, err, &nfe)
}

func TestCreateConflict(t *testing.T) {
	rt := newTestRuntime()
	_, err := rt.Create(&Request{IfIndex: 3})
	require.NoError(t, err)

	_, err = rt.Create(&Request{IfIndex: 3})
	var ce *ConflictError
	require.ErrorAs(t, err, &ce)
}

func TestDeleteNotFound(t *testing.T) {
	rt := newTestRuntime()
	err := rt.Delete(999)
	var nfe *NotFoundError
	require.ErrorAs(t, err, &nfe)
}

func TestCreateAndDelete(t *testing.T) {
	rt := newTestRuntime()
	att, err := rt.Create(&Request{IfIndex: 3})
	require.NoError(t, err)
	assert.Equal(t, uint32(3), att.IfIndex)
	assert.True(t, att.Enabled)

	got, err := rt.Get(3)
	require.NoError(t, err)
	assert.Equal(t, uint32(3), got.IfIndex)

	err = rt.Delete(3)
	require.NoError(t, err)

	_, err = rt.Get(3)
	var nfe *NotFoundError
	assert.ErrorAs(t, err, &nfe)
}

func TestPatchEnabledToggle(t *testing.T) {
	rt := newTestRuntime()
	_, err := rt.Create(&Request{IfIndex: 3})
	require.NoError(t, err)

	att, err := rt.PatchEnabled(3, false)
	require.NoError(t, err)
	assert.False(t, att.Enabled)

	att, err = rt.PatchEnabled(3, true)
	require.NoError(t, err)
	assert.True(t, att.Enabled)
}

func TestPatchEnabledNotFound(t *testing.T) {
	rt := newTestRuntime()
	_, err := rt.PatchEnabled(999, true)
	var nfe *NotFoundError
	require.ErrorAs(t, err, &nfe)
}

func TestXSKConfigPreserved(t *testing.T) {
	rt := newTestRuntime()
	att, err := rt.Create(&Request{
		IfIndex: 3,
		XSK:     &XSKConfig{Enabled: true, Queues: []uint32{0, 1}},
	})
	require.NoError(t, err)
	assert.True(t, att.XSK.Enabled)
	assert.Equal(t, []uint32{0, 1}, att.XSK.Queues)
}

func TestXSKConfigNormalized(t *testing.T) {
	rt := newTestRuntime()
	att, err := rt.Create(&Request{
		IfIndex: 3,
		XSK:     &XSKConfig{Enabled: true},
	})
	require.NoError(t, err)

	assert.Equal(t, uint32(2), att.Channels.MaxRxQueueCount)
	assert.Equal(t, []uint32{0, 1}, att.XSK.Queues)
	assert.Equal(t, xsk.DefaultOptions(), att.XSK.UMEM)
}

func TestXSKQueueMustBeWithinEnabledRXQueues(t *testing.T) {
	rt := newTestRuntime()
	_, err := rt.Create(&Request{
		IfIndex:  3,
		Channels: &ChannelsConfig{RxQueueCount: 1},
		XSK:      &XSKConfig{Enabled: true, Queues: []uint32{1}},
	})
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "exceeds enabled rx queues")
}

func TestLoadBPFFailureRollback(t *testing.T) {
	rt := New(func() (*ebpf.Collection, error) {
		return nil, errors.New("bpf load failed")
	}, mockAttachXDP)
	rt.SetPromiscuousOpen(func(uint32) (PromiscuousHandle, error) {
		return noopPromiscuousHandle{}, nil
	})

	_, err := rt.Create(&Request{IfIndex: 3})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bpf load failed")

	_, err = rt.Get(3)
	var nfe *NotFoundError
	assert.ErrorAs(t, err, &nfe)
}

func TestListAttachments(t *testing.T) {
	rt := newTestRuntime()
	_, err := rt.Create(&Request{IfIndex: 3})
	require.NoError(t, err)
	_, err = rt.Create(&Request{IfIndex: 5})
	require.NoError(t, err)

	list := rt.List()
	assert.Len(t, list, 2)
}

func TestToAPIResponseIncludesRuntimeResources(t *testing.T) {
	att := &Attachment{
		IfIndex:     3,
		AttachMode:  "native",
		Enabled:     true,
		MissVerdict: "pass",
		Channels:    ChannelsConfig{RxQueueCount: 1, MaxRxQueueCount: 2},
		XSK:         XSKConfig{Enabled: true, Queues: []uint32{0}, UMEM: xsk.DefaultOptions()},
		ProgramID:   128,
		MapSetID:    "ifindex-3",
	}
	resp := att.ToAPIResponse()

	assert.Equal(t, uint32(2), resp.Channels.MaxRxQueueCount)
	require.NotNil(t, resp.XSK.UMEM)
	assert.Equal(t, uint32(2048), resp.XSK.UMEM.FrameSize)
	assert.Equal(t, uint32(128), resp.Runtime.ProgramID)
	assert.Equal(t, "ifindex-3", resp.Runtime.MapSetID)
}
