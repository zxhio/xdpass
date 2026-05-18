package events

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"xdpass/internal/dataplane/abi"
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

func TestDecodeEventFields(t *testing.T) {
	raw := makeEventRaw(1001, abi.ActionTCPReset, abi.VerdictTX, 0x0A01020A, 0xC0A80114, 52345, 80, 6, 1710000000000000000)
	event, err := DecodeEvent(raw, 3, 0)
	require.NoError(t, err)

	assert.Equal(t, "rule_event", event.Type)
	assert.Equal(t, uint32(1001), event.RuleID)
	assert.Equal(t, uint32(3), event.IfIndex)
	assert.Equal(t, "10.1.2.10", event.SIP)
	assert.Equal(t, "192.168.1.20", event.DIP)
	assert.Equal(t, uint16(52345), event.Sport)
	assert.Equal(t, uint16(80), event.Dport)
	assert.Equal(t, uint8(6), event.IPProto)
}

func TestDecodeEventTimestampConversion(t *testing.T) {
	// 1 second in nanoseconds
	raw := makeEventRaw(1, abi.ActionNone, abi.VerdictObserve, 0, 0, 0, 0, 0, 1000000000)
	event, err := DecodeEvent(raw, 1, 1710000000)
	require.NoError(t, err)
	assert.Equal(t, int64(1710000001), event.Timestamp)
}
