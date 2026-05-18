package stats

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSnapshotNilMaps(t *testing.T) {
	resp := Snapshot(nil, nil, nil)
	assert.Equal(t, uint64(0), resp.Ingress.Packets)
	assert.Equal(t, uint64(0), resp.Parse.OKPackets)
	assert.Equal(t, uint64(0), resp.Match.HitPackets)
	assert.Equal(t, uint64(0), resp.KernelResponse.Packets)
	assert.Equal(t, uint64(0), resp.XSKRedirect.Packets)
	assert.Equal(t, uint64(0), resp.UserspaceResponse.Packets)
	assert.Equal(t, uint64(0), resp.Errors.XDPPackets)
	assert.Equal(t, uint64(0), resp.Errors.XSKPackets)
}

func TestSnapshotWithUserspaceStats(t *testing.T) {
	us := &UserspaceResponseStats{
		XSKRXPackets: 10,
		Packets:      8,
		ErrorPackets: 2,
	}
	resp := Snapshot(nil, us, nil)
	assert.Equal(t, uint64(10), resp.UserspaceResponse.XSKRXPackets)
	assert.Equal(t, uint64(8), resp.UserspaceResponse.Packets)
	assert.Equal(t, uint64(2), resp.UserspaceResponse.ErrorPackets)
	assert.Equal(t, uint64(2), resp.Errors.XSKPackets)
}
