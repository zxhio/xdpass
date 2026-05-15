package events

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeEventRaw(ruleID uint32, action uint16, verdict uint8, sip, dip uint32, sport, dport uint16, ipProto uint8, tsNs uint64) [ruleEventSize]byte {
	var raw [ruleEventSize]byte
	binary.LittleEndian.PutUint64(raw[0:8], tsNs)
	binary.LittleEndian.PutUint32(raw[8:12], ruleID)
	binary.LittleEndian.PutUint32(raw[12:16], 0) // pkt_conds
	// IPv4 addresses are stored in network byte order (big-endian) by BPF.
	binary.BigEndian.PutUint32(raw[16:20], sip)
	binary.BigEndian.PutUint32(raw[20:24], dip)
	binary.LittleEndian.PutUint16(raw[24:26], action)
	binary.LittleEndian.PutUint16(raw[26:28], sport)
	binary.LittleEndian.PutUint16(raw[28:30], dport)
	raw[30] = verdict
	raw[31] = ipProto
	return raw
}

func TestDecodeEventBasic(t *testing.T) {
	raw := makeEventRaw(1001, 2, 1, 0x0A01020A, 0xC0A80114, 52345, 80, 6, 1710000000000000000)
	event, err := DecodeEvent(raw, 3, 0)
	require.NoError(t, err)

	assert.Equal(t, "rule_event", event.Type)
	assert.Equal(t, uint32(1001), event.RuleID)
	assert.Equal(t, "tcp_reset", event.Action)
	assert.Equal(t, "kernel", event.Path)
	assert.Equal(t, "xdp_tx", event.Verdict)
	assert.Equal(t, "sent", event.Result)
	assert.Equal(t, uint32(3), event.IfIndex)
	assert.Equal(t, "10.1.2.10", event.SIP)
	assert.Equal(t, "192.168.1.20", event.DIP)
	assert.Equal(t, uint16(52345), event.Sport)
	assert.Equal(t, uint16(80), event.Dport)
	assert.Equal(t, uint8(6), event.IPProto)
}

func TestDecodeEventTimestampConversion(t *testing.T) {
	// 1 second in nanoseconds
	raw := makeEventRaw(1, 0, 0, 0, 0, 0, 0, 0, 1000000000)
	event, err := DecodeEvent(raw, 1, 1710000000)
	require.NoError(t, err)
	assert.Equal(t, int64(1710000001), event.Timestamp)
}

func TestDecodeEventIPv4Zero(t *testing.T) {
	raw := makeEventRaw(1, 0, 0, 0, 0, 0, 0, 0, 0)
	event, err := DecodeEvent(raw, 1, 0)
	require.NoError(t, err)
	assert.Equal(t, "", event.SIP)
	assert.Equal(t, "", event.DIP)
}

func TestDecodeEventActionPaths(t *testing.T) {
	cases := []struct {
		action uint16
		path   string
	}{
		{0, "none"},
		{1, "none"},
		{2, "kernel"},
		{3, "userspace"},
		{4, "userspace"},
		{5, "userspace"},
		{6, "kernel"},
		{7, "userspace"},
		{8, "userspace"},
		{9, "kernel"},
		{10, "kernel"},
		{11, "userspace"},
	}
	for _, tc := range cases {
		raw := makeEventRaw(1, tc.action, 0, 0, 0, 0, 0, 0, 0)
		event, err := DecodeEvent(raw, 1, 0)
		require.NoError(t, err, "action=%d", tc.action)
		assert.Equal(t, tc.path, event.Path, "action=%d", tc.action)
	}
}

func TestDecodeEventVerdictNames(t *testing.T) {
	cases := []struct {
		verdict uint8
		name    string
	}{
		{0, "observe"},
		{1, "xdp_tx"},
		{2, "xsk_redirect"},
		{3, "redirect_tx"},
	}
	for _, tc := range cases {
		raw := makeEventRaw(1, 0, tc.verdict, 0, 0, 0, 0, 0, 0)
		event, err := DecodeEvent(raw, 1, 0)
		require.NoError(t, err, "verdict=%d", tc.verdict)
		assert.Equal(t, tc.name, event.Verdict, "verdict=%d", tc.verdict)
	}
}

func TestDeriveResultNoneAction(t *testing.T) {
	assert.Equal(t, "matched", deriveResult(0, 0)) // none action
	assert.Equal(t, "matched", deriveResult(1, 0)) // alert action
}

func TestDeriveResultKernelSuccess(t *testing.T) {
	assert.Equal(t, "sent", deriveResult(2, 1)) // tcp_reset, VERDICT_TX
	assert.Equal(t, "sent", deriveResult(2, 3)) // tcp_reset, VERDICT_REDIRECT_TX
}

func TestDeriveResultKernelFailure(t *testing.T) {
	assert.Equal(t, "failed", deriveResult(2, 0)) // tcp_reset, VERDICT_OBSERVE
	assert.Equal(t, "failed", deriveResult(2, 2)) // tcp_reset, VERDICT_XSK_REDIRECT
}

func TestIPv4ToString(t *testing.T) {
	assert.Equal(t, "10.1.2.10", ipv4ToString(0x0A01020A))
	assert.Equal(t, "192.168.1.1", ipv4ToString(0xC0A80101))
	assert.Equal(t, "", ipv4ToString(0))
}

func TestBootTimeOffset(t *testing.T) {
	offset := BootTimeOffset()
	// The offset should be a reasonable value (positive, roughly the system uptime)
	assert.Greater(t, offset, int64(0))
}
