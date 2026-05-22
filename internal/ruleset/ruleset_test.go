package ruleset

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"xdpass/internal/dataplane/abi"
)

// --- Validation tests ---

func TestValidateEmptyRuleset(t *testing.T) {
	err := Validate(nil)
	assert.NoError(t, err)
}

func TestValidateMaxRules(t *testing.T) {
	rules := make([]Rule, abi.MaxRuleSlots+1)
	for i := range rules {
		rules[i] = Rule{RuleID: uint32(i + 1), Response: Response{Action: "alert"}}
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "512")
}

func TestValidateExactly512Rules(t *testing.T) {
	rules := make([]Rule, abi.MaxRuleSlots)
	for i := range rules {
		rules[i] = Rule{RuleID: uint32(i + 1), Response: Response{Action: "alert"}}
	}
	err := Validate(rules)
	assert.NoError(t, err)
}

func TestValidateDuplicateRuleID(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Response: Response{Action: "alert"}},
		{RuleID: 1, Response: Response{Action: "alert"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "duplicate")
}

func TestValidateZeroRuleID(t *testing.T) {
	rules := []Rule{
		{RuleID: 0, Response: Response{Action: "alert"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "rule_id")
}

func TestValidateInvalidProtocol(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "sctp"}, Response: Response{Action: "alert"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "protocol")
}

func TestValidateInvalidAction(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Response: Response{Action: "invalid_action"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "action")
}

func TestValidateEmptyAction(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Response: Response{Action: ""}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "required")
}

func TestValidateInvalidCIDR(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{SrcCIDRs: []string{"not-a-cidr"}}, Response: Response{Action: "alert"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "cidr")
}

func TestValidateInvalidICMPType(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{ICMP: &ICMPMatch{Type: "echo_reply"}}, Response: Response{Action: "alert"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "icmp.type")
}

func TestValidateInvalidARPOp(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{ARP: &ARPMatch{Op: "invalid"}}, Response: Response{Action: "alert"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "arp.op")
}

func TestValidateFalseTCPFlag(t *testing.T) {
	syn := false
	rules := []Rule{
		{RuleID: 1, Match: Match{TCP: &TCPMatch{Flags: &TCPFlags{SYN: &syn}}}, Response: Response{Action: "alert"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "tcp.flags")
}

// --- Match/Action compatibility tests ---

func TestCompatTCPResetWithTCP(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "tcp"}, Response: Response{Action: "tcp_reset"}},
	}
	assert.NoError(t, Validate(rules))
}

func TestCompatTCPResetWithUDP(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "udp"}, Response: Response{Action: "tcp_reset"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "tcp")
}

func TestCompatICMPEchoReplyWithICMP(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "icmp", ICMP: &ICMPMatch{Type: "echo_request"}}, Response: Response{Action: "icmp_echo_reply"}},
	}
	assert.NoError(t, Validate(rules))
}

func TestCompatICMPEchoReplyWithTCP(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "tcp"}, Response: Response{Action: "icmp_echo_reply"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "icmp")
}

func TestCompatARPReplyWithARPRequest(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "arp", ARP: &ARPMatch{Op: "request"}}, Response: Response{Action: "arp_reply"}},
	}
	assert.NoError(t, Validate(rules))
}

func TestCompatARPReplyWithARPReply(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "arp", ARP: &ARPMatch{Op: "reply"}}, Response: Response{Action: "arp_reply"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "arp.op")
}

func TestCompatDNSRefusedWithUDP(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "udp", DstPorts: []uint16{53}}, Response: Response{Action: "dns_refused"}},
	}
	assert.NoError(t, Validate(rules))
}

func TestCompatDNSRefusedWithTCP(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "tcp"}, Response: Response{Action: "dns_refused"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "udp")
}

func TestCompatNoneWithAnyProtocol(t *testing.T) {
	for _, proto := range []string{"tcp", "udp", "icmp", "arp", ""} {
		rules := []Rule{
			{RuleID: 1, Match: Match{Protocol: proto}, Response: Response{Action: "none"}},
		}
		assert.NoError(t, Validate(rules), "protocol=%q", proto)
	}
}

func TestCompatAlertWithAnyProtocol(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Response: Response{Action: "alert"}},
	}
	assert.NoError(t, Validate(rules))
}

// --- Compiler tests ---

func TestCompileEmptyRuleset(t *testing.T) {
	compiled, err := Compile(nil, "pass")
	require.NoError(t, err)
	assert.Empty(t, compiled.Rules)
}

func TestCompileSortingByPriority(t *testing.T) {
	rules := []Rule{
		{RuleID: 3, Priority: 20, Response: Response{Action: "alert"}},
		{RuleID: 1, Priority: 10, Response: Response{Action: "alert"}},
		{RuleID: 2, Priority: 10, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)
	require.Len(t, compiled.Rules, 3)
	assert.Equal(t, uint32(1), compiled.Rules[0].RuleID)
	assert.Equal(t, uint32(2), compiled.Rules[1].RuleID)
	assert.Equal(t, uint32(3), compiled.Rules[2].RuleID)
}

func TestCompileSlotAllocation(t *testing.T) {
	rules := []Rule{
		{RuleID: 10, Priority: 5, Response: Response{Action: "alert"}},
		{RuleID: 20, Priority: 10, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)
	assert.Equal(t, uint32(0), compiled.Rules[0].Slot)
	assert.Equal(t, uint32(1), compiled.Rules[1].Slot)
}

func TestCompileRuleMeta(t *testing.T) {
	syn := true
	rules := []Rule{
		{
			RuleID:   100,
			Priority: 10,
			Match:    Match{Protocol: "tcp", DstPorts: []uint16{80}, TCP: &TCPMatch{Flags: &TCPFlags{SYN: &syn}}},
			Response: Response{Action: "tcp_reset"},
		},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)
	require.Len(t, compiled.Rules, 1)

	meta := compiled.Rules[0].Meta
	assert.Equal(t, uint32(100), meta.RuleID)
	assert.Equal(t, abi.ActionTCPReset, meta.Action)
	assert.Equal(t, uint8(0), meta.Flags)

	// required_mask: COND_PROTO_TCP | COND_DST_PORT | COND_TCP_SYN
	expectedMask := abi.CondProtoTCP | abi.CondDstPort | abi.CondTCPSyn
	assert.Equal(t, expectedMask, meta.RequiredMask)
}

func TestCompileRequiredMaskWildcard(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)
	assert.Equal(t, uint32(0), compiled.Rules[0].Meta.RequiredMask)
}

func TestCompileIngressVerdictDrop(t *testing.T) {
	compiled, err := Compile(nil, "drop")
	require.NoError(t, err)
	assert.Equal(t, uint32(1), compiled.GlobalCfg.IngressVerdict)
}

func TestCompileIngressVerdictPass(t *testing.T) {
	compiled, err := Compile(nil, "pass")
	require.NoError(t, err)
	assert.Equal(t, uint32(0), compiled.GlobalCfg.IngressVerdict)
}

func TestCompileAllActiveRulesBitmap(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Response: Response{Action: "alert"}},
		{RuleID: 2, Response: Response{Action: "alert"}},
		{RuleID: 3, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)
	// Slots 0, 1, 2 -> bits 0, 1, 2 in group 0
	assert.Equal(t, uint64(0b111), compiled.GlobalCfg.AllActiveRules[0])
}

func TestCompilePortIndex(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{DstPorts: []uint16{80, 443}}, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)

	assert.Equal(t, slotBit(0), compiled.Indexes.DstPortIndex[80])
	assert.Equal(t, slotBit(0), compiled.Indexes.DstPortIndex[443])
}

func TestCompileVlanIndex(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{VLANS: []uint16{100}}, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)

	assert.Equal(t, slotBit(0), compiled.Indexes.VlanIndex[100])
}

func TestCompileCIDRLPMIndex(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{SrcCIDRs: []string{"10.0.0.0/8"}}, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)

	require.Len(t, compiled.Indexes.SrcPrefixLPM, 1)
	assert.Equal(t, uint32(8), compiled.Indexes.SrcPrefixLPM[0].Prefixlen)
	assert.Equal(t, binary.LittleEndian.Uint32(net.IP{10, 0, 0, 0}.To4()), compiled.Indexes.SrcPrefixLPM[0].Addr)
	assert.Equal(t, slotBit(0), compiled.Indexes.SrcPrefixLPM[0].Mask)
}

func TestCompileCIDRLPMIndexCanonicalizesNetworkAddress(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{SrcCIDRs: []string{"10.1.2.3/8"}}, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)

	require.Len(t, compiled.Indexes.SrcPrefixLPM, 1)
	assert.Equal(t, binary.LittleEndian.Uint32(net.IP{10, 0, 0, 0}.To4()), compiled.Indexes.SrcPrefixLPM[0].Addr)
}

func TestCompileOptionalBitmaps(t *testing.T) {
	// Rule with no VLAN, no ports, no CIDRs -> all optional
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "tcp"}, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)

	assert.Equal(t, slotBit(0), compiled.GlobalCfg.VlanOptionalRules)
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.SrcPortOptionalRules)
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.DstPortOptionalRules)
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.SrcPrefixOptionalRules)
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.DstPrefixOptionalRules)
	assert.Equal(t, [8]uint64{}, compiled.GlobalCfg.ConditionOptionalRules[0])
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.ConditionOptionalRules[1])
}

func TestCompileOptionalBitmapsPartial(t *testing.T) {
	// Rule with DstPorts but no VLAN, no SrcPorts, no CIDRs
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "tcp", DstPorts: []uint16{80}}, Response: Response{Action: "tcp_reset"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)

	assert.Equal(t, slotBit(0), compiled.GlobalCfg.VlanOptionalRules)
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.SrcPortOptionalRules)
	// DstPorts is set, so NOT optional
	assert.Equal(t, [8]uint64{}, compiled.GlobalCfg.DstPortOptionalRules)
	assert.Equal(t, [8]uint64{}, compiled.GlobalCfg.ConditionOptionalRules[0])
	assert.Equal(t, [8]uint64{}, compiled.GlobalCfg.ConditionOptionalRules[8])
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.ConditionOptionalRules[7])
}

func TestCompileMultipleRulesSamePort(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{DstPorts: []uint16{80}}, Response: Response{Action: "alert"}},
		{RuleID: 2, Match: Match{DstPorts: []uint16{80}}, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)

	// Both rules should be in the port 80 bitmap
	expected := slotBit(0)
	maskOr(&expected, slotBit(1))
	assert.Equal(t, expected, compiled.Indexes.DstPortIndex[80])
}

// --- Runtime tests ---

func TestRuntimeGetEmpty(t *testing.T) {
	rt := NewRuntime()
	rules := rt.GetRuleset()
	assert.Empty(t, rules)
}

func TestRuntimeDryRunDoesNotChangeState(t *testing.T) {
	rt := NewRuntime()

	// Dry-run via Compile (no map writing)
	internalRules := []Rule{
		{RuleID: 1, Response: Response{Action: "alert"}},
	}
	_, err := Compile(internalRules, "pass")
	require.NoError(t, err)

	// State should still be empty
	rules := rt.GetRuleset()
	assert.Empty(t, rules)
}
