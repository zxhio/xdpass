package attachment

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func newTestRuntime() *Runtime {
	return New(mockLoadBPF, mockAttachXDP)
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

func TestLoadBPFFailureRollback(t *testing.T) {
	rt := New(func() (*ebpf.Collection, error) {
		return nil, errors.New("bpf load failed")
	}, mockAttachXDP)

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

func TestToAPIResponse(t *testing.T) {
	att := &Attachment{
		IfIndex:     3,
		AttachMode:  "native",
		Enabled:     true,
		MissVerdict: "pass",
		XSK:         XSKConfig{Enabled: true, Queues: []uint32{0}},
	}
	resp := att.ToAPIResponse()
	assert.Equal(t, uint32(3), resp.IfIndex)
	assert.True(t, resp.Enabled)
	assert.True(t, resp.XSK.Enabled)
	assert.Equal(t, []uint32{0}, resp.XSK.Queues)
}
