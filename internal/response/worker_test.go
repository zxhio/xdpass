package response

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWorkerProcessPacketRuleNotFound(t *testing.T) {
	stats := &Stats{}
	lookup := &RulesetRuleLookup{Rules: nil}
	w := NewWorker(3, lookup, stats, EgressConfig{}, 0, nil)

	// Process with a rule_id that doesn't exist.
	w.ProcessPacket([]byte{0x00}, XSKMeta{RuleID: 999, Action: ActionICMPEchoReply})

	assert.Equal(t, uint64(1), stats.XSKRXPackets.Load())
	assert.Equal(t, uint64(1), stats.ErrorPackets.Load())
	assert.Equal(t, uint64(0), stats.Packets.Load())
}

func TestWorkerProcessPacketUnimplementedAction(t *testing.T) {
	stats := &Stats{}
	lookup := &RulesetRuleLookup{
		Rules: []RuleEntry{
			{RuleID: 1001, Action: "tcp_syn_ack", Params: nil},
		},
	}
	w := NewWorker(3, lookup, stats, EgressConfig{}, 0, nil)

	w.ProcessPacket([]byte{0x00}, XSKMeta{RuleID: 1001, Action: ActionTCPSynAck})

	assert.Equal(t, uint64(1), stats.XSKRXPackets.Load())
	assert.Equal(t, uint64(1), stats.ErrorPackets.Load())
	assert.Equal(t, uint64(0), stats.Packets.Load())
}

func TestRulesetRuleLookup(t *testing.T) {
	lookup := &RulesetRuleLookup{
		Rules: []RuleEntry{
			{RuleID: 1001, Action: "icmp_echo_reply", Params: nil},
			{RuleID: 1002, Action: "arp_reply", Params: map[string]any{"hardware_addr": "aa:bb:cc:dd:ee:ff", "sender_ipv4": "10.0.0.1"}},
		},
	}

	action, params, ok := lookup.LookupByRuleID(1001)
	assert.True(t, ok)
	assert.Equal(t, "icmp_echo_reply", action)
	assert.Nil(t, params)

	action, params, ok = lookup.LookupByRuleID(1002)
	assert.True(t, ok)
	assert.Equal(t, "arp_reply", action)
	assert.NotNil(t, params)

	_, _, ok = lookup.LookupByRuleID(9999)
	assert.False(t, ok)
}

func TestStatsSnapshot(t *testing.T) {
	stats := &Stats{}
	stats.XSKRXPackets.Add(10)
	stats.Packets.Add(8)
	stats.ErrorPackets.Add(2)
	stats.AFPacketTXPackets.Add(5)

	snap := stats.Snapshot()
	assert.Equal(t, uint64(10), snap.XSKRXPackets)
	assert.Equal(t, uint64(8), snap.Packets)
	assert.Equal(t, uint64(2), snap.ErrorPackets)
	assert.Equal(t, uint64(5), snap.AFPacketTXPackets)
	assert.Equal(t, uint64(0), snap.XSKTXPackets)
}
