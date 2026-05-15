package stats

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
)

func TestZeroResponse(t *testing.T) {
	resp := ZeroResponse()
	assert.Equal(t, uint64(0), resp.Ingress.Packets)
	assert.Equal(t, uint64(0), resp.Parse.OKPackets)
	assert.Equal(t, uint64(0), resp.Match.HitPackets)
	assert.Equal(t, uint64(0), resp.KernelResponse.Packets)
	assert.Equal(t, uint64(0), resp.XSKRedirect.Packets)
	assert.Equal(t, uint64(0), resp.UserspaceResponse.Packets)
	assert.Equal(t, uint64(0), resp.Errors.XDPPackets)
	assert.Equal(t, uint64(0), resp.Errors.XSKPackets)
}

func TestSnapshotNilMaps(t *testing.T) {
	resp := Snapshot(nil)
	assert.Equal(t, uint64(0), resp.Ingress.Packets)
}

func TestSnapshotEmptyMaps(t *testing.T) {
	resp := Snapshot([]*ebpf.Map{})
	assert.Equal(t, uint64(0), resp.Ingress.Packets)
}

func TestEncodeCounter(t *testing.T) {
	b := EncodeCounter(1000)
	assert.Len(t, b, 8)
	// Verify it's little-endian
	assert.Equal(t, byte(1000&0xFF), b[0])
	assert.Equal(t, byte((1000>>8)&0xFF), b[1])
}
