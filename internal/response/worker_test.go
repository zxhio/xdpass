package response

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"xdpass/internal/dataplane/abi"
)

func TestWorkerProcessPacketRuleNotFound(t *testing.T) {
	stats := &Stats{}
	lookup := &RulesetRuleLookup{Rules: nil}
	w := NewWorker(3, lookup, stats, EgressConfig{}, 0, nil)

	// Process with a rule_id that doesn't exist.
	w.ProcessPacket([]byte{0x00}, XSKMeta{RuleID: 999, Action: abi.ActionICMPEchoReply})

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

	w.ProcessPacket([]byte{0x00}, XSKMeta{RuleID: 1001, Action: abi.ActionTCPSynAck})

	assert.Equal(t, uint64(1), stats.XSKRXPackets.Load())
	assert.Equal(t, uint64(1), stats.ErrorPackets.Load())
	assert.Equal(t, uint64(0), stats.Packets.Load())
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

func TestWorkerProcessPacketResultCallbackRuleNotFound(t *testing.T) {
	stats := &Stats{}
	lookup := &RulesetRuleLookup{Rules: nil}
	w := NewWorker(3, lookup, stats, EgressConfig{}, 0, nil)

	var gotIfIndex, gotRuleID uint32
	var gotAction, gotResult string
	w.OnResponseResult = func(ifIndex, ruleID uint32, action, result string) {
		gotIfIndex = ifIndex
		gotRuleID = ruleID
		gotAction = action
		gotResult = result
	}

	w.ProcessPacket([]byte{0x00}, XSKMeta{RuleID: 999, Action: abi.ActionICMPEchoReply})

	assert.Equal(t, uint32(3), gotIfIndex)
	assert.Equal(t, uint32(999), gotRuleID)
	assert.Equal(t, "", gotAction)
	assert.Equal(t, "failed", gotResult)
}

func TestWorkerProcessPacketResultCallbackBuildFailed(t *testing.T) {
	stats := &Stats{}
	lookup := &RulesetRuleLookup{
		Rules: []RuleEntry{
			{RuleID: 1001, Action: "tcp_syn_ack", Params: nil},
		},
	}
	w := NewWorker(3, lookup, stats, EgressConfig{}, 0, nil)

	var gotIfIndex, gotRuleID uint32
	var gotAction, gotResult string
	w.OnResponseResult = func(ifIndex, ruleID uint32, action, result string) {
		gotIfIndex = ifIndex
		gotRuleID = ruleID
		gotAction = action
		gotResult = result
	}

	// tcp_syn_ack packet is too short for builder.
	w.ProcessPacket([]byte{0x00}, XSKMeta{RuleID: 1001, Action: abi.ActionTCPSynAck})

	assert.Equal(t, uint32(3), gotIfIndex)
	assert.Equal(t, uint32(1001), gotRuleID)
	assert.Equal(t, "tcp_syn_ack", gotAction)
	assert.Equal(t, "failed", gotResult)
}
