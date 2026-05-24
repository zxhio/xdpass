package ruleset

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"xdpass/internal/dataplane/abi"
)

func validARPReplyParams() map[string]any {
	return map[string]any{
		"hardware_addr": "02:00:00:00:00:20",
		"sender_ipv4":   "192.0.2.10",
	}
}

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
	assert.Contains(t, ve.Detail, "4096")
}

func TestValidateExactlyMaxRuleSlots(t *testing.T) {
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

func TestCompatTCPResetWithoutProtocol(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Response: Response{Action: "tcp_reset"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "protocol tcp")
}

func TestCompatTCPSynAckWithTCPSYN(t *testing.T) {
	syn := true
	rules := []Rule{
		{
			RuleID: 1,
			Match:  Match{Protocol: "tcp", TCP: &TCPMatch{Flags: &TCPFlags{SYN: &syn}}},
			Response: Response{
				Action: "tcp_syn_ack",
				Params: map[string]any{"tcp_seq": uint32(1)},
			},
		},
	}
	assert.NoError(t, Validate(rules))
}

func TestCompatTCPSynAckWithoutSYN(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "tcp"}, Response: Response{Action: "tcp_syn_ack"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "tcp.flags.syn")
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

func TestCompatICMPEchoReplyWithoutType(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "icmp"}, Response: Response{Action: "icmp_echo_reply"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "icmp.type")
}

func TestCompatARPReplyWithARPRequest(t *testing.T) {
	rules := []Rule{
		{
			RuleID: 1,
			Match:  Match{Protocol: "arp", ARP: &ARPMatch{Op: "request"}},
			Response: Response{
				Action: "arp_reply",
				Params: validARPReplyParams(),
			},
		},
	}
	assert.NoError(t, Validate(rules))
}

func TestCompatARPReplyWithARPReply(t *testing.T) {
	rules := []Rule{
		{
			RuleID: 1,
			Match:  Match{Protocol: "arp", ARP: &ARPMatch{Op: "reply"}},
			Response: Response{
				Action: "arp_reply",
				Params: validARPReplyParams(),
			},
		},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "arp.op")
}

func TestCompatARPReplyWithoutRequestOp(t *testing.T) {
	rules := []Rule{
		{
			RuleID: 1,
			Match:  Match{Protocol: "arp"},
			Response: Response{
				Action: "arp_reply",
				Params: validARPReplyParams(),
			},
		},
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

func TestCompatDNSRefusedWithoutPort53(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "udp"}, Response: Response{Action: "dns_refused"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "dst_ports")
}

func TestCompatUDPEchoReplyWithoutProtocol(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Response: Response{Action: "udp_echo_reply"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "protocol udp")
}

func TestCompatICMPPortUnreachableRequiresUDP(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "tcp"}, Response: Response{Action: "icmp_port_unreachable"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "protocol udp")
}

func TestCompatICMPHostUnreachableRequiresIPProtocol(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Response: Response{Action: "icmp_host_unreachable"}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "protocol tcp, udp, or icmp")
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

// --- Response params tests ---

func TestValidateRejectsParamsForNoParamActions(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Response: Response{Action: "alert", Params: map[string]any{"unused": true}}},
	}
	err := Validate(rules)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, ve.Detail, "must be empty")
}

func TestValidateTCPSynAckParams(t *testing.T) {
	syn := true
	baseRule := Rule{
		RuleID: 1,
		Match:  Match{Protocol: "tcp", TCP: &TCPMatch{Flags: &TCPFlags{SYN: &syn}}},
		Response: Response{
			Action: "tcp_syn_ack",
		},
	}

	t.Run("valid omitted", func(t *testing.T) {
		assert.NoError(t, Validate([]Rule{baseRule}))
	})

	t.Run("valid uint32", func(t *testing.T) {
		rule := baseRule
		rule.Response.Params = map[string]any{"tcp_seq": uint32(123)}
		assert.NoError(t, Validate([]Rule{rule}))
	})

	t.Run("invalid type", func(t *testing.T) {
		rule := baseRule
		rule.Response.Params = map[string]any{"tcp_seq": "123"}
		err := Validate([]Rule{rule})
		var ve *ValidationError
		require.ErrorAs(t, err, &ve)
		assert.Contains(t, ve.Detail, "tcp_seq")
	})
}

func TestValidateDNSRefusedParams(t *testing.T) {
	baseRule := Rule{
		RuleID: 1,
		Match:  Match{Protocol: "udp", DstPorts: []uint16{53}},
		Response: Response{
			Action: "dns_refused",
		},
	}

	t.Run("valid omitted", func(t *testing.T) {
		assert.NoError(t, Validate([]Rule{baseRule}))
	})

	t.Run("valid refused", func(t *testing.T) {
		rule := baseRule
		rule.Response.Params = map[string]any{"rcode": "refused"}
		assert.NoError(t, Validate([]Rule{rule}))
	})

	t.Run("invalid rcode", func(t *testing.T) {
		rule := baseRule
		rule.Response.Params = map[string]any{"rcode": "noerror"}
		err := Validate([]Rule{rule})
		var ve *ValidationError
		require.ErrorAs(t, err, &ve)
		assert.Contains(t, ve.Detail, "rcode")
	})
}

func TestValidateDNSSinkholeParams(t *testing.T) {
	baseRule := Rule{
		RuleID: 1,
		Match:  Match{Protocol: "udp", DstPorts: []uint16{53}},
		Response: Response{
			Action: "dns_sinkhole",
		},
	}

	t.Run("valid ipv4", func(t *testing.T) {
		rule := baseRule
		rule.Response.Params = map[string]any{
			"family":     "ipv4",
			"answers_v4": []any{"192.0.2.10"},
			"ttl":        float64(60),
		}
		assert.NoError(t, Validate([]Rule{rule}))
	})

	t.Run("valid dual stack", func(t *testing.T) {
		rule := baseRule
		rule.Response.Params = map[string]any{
			"family":     "dual_stack",
			"answers_v4": []string{"192.0.2.10"},
			"answers_v6": []string{"2001:db8::10"},
			"ttl":        uint32(60),
		}
		assert.NoError(t, Validate([]Rule{rule}))
	})

	tests := []struct {
		name     string
		params   map[string]any
		contains string
	}{
		{
			name:     "missing family",
			params:   map[string]any{"answers_v4": []any{"192.0.2.10"}, "ttl": float64(60)},
			contains: "family",
		},
		{
			name:     "missing ttl",
			params:   map[string]any{"family": "ipv4", "answers_v4": []any{"192.0.2.10"}},
			contains: "ttl",
		},
		{
			name:     "ttl zero",
			params:   map[string]any{"family": "ipv4", "answers_v4": []any{"192.0.2.10"}, "ttl": float64(0)},
			contains: "ttl",
		},
		{
			name:     "invalid family",
			params:   map[string]any{"family": "ipv10", "answers_v4": []any{"192.0.2.10"}, "ttl": float64(60)},
			contains: "family",
		},
		{
			name:     "missing answers",
			params:   map[string]any{"family": "ipv4", "ttl": float64(60)},
			contains: "answers_v4",
		},
		{
			name:     "invalid ipv4",
			params:   map[string]any{"family": "ipv4", "answers_v4": []any{"2001:db8::10"}, "ttl": float64(60)},
			contains: "answers_v4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := baseRule
			rule.Response.Params = tt.params
			err := Validate([]Rule{rule})
			var ve *ValidationError
			require.ErrorAs(t, err, &ve)
			assert.Contains(t, ve.Detail, tt.contains)
		})
	}
}

func TestValidateARPReplyParams(t *testing.T) {
	baseRule := Rule{
		RuleID: 1,
		Match:  Match{Protocol: "arp", ARP: &ARPMatch{Op: "request"}},
		Response: Response{
			Action: "arp_reply",
		},
	}

	t.Run("valid", func(t *testing.T) {
		rule := baseRule
		rule.Response.Params = validARPReplyParams()
		assert.NoError(t, Validate([]Rule{rule}))
	})

	tests := []struct {
		name     string
		params   map[string]any
		contains string
	}{
		{
			name:     "missing hardware address",
			params:   map[string]any{"sender_ipv4": "192.0.2.10"},
			contains: "hardware_addr",
		},
		{
			name:     "invalid hardware address",
			params:   map[string]any{"hardware_addr": "invalid", "sender_ipv4": "192.0.2.10"},
			contains: "hardware_addr",
		},
		{
			name:     "missing sender ipv4",
			params:   map[string]any{"hardware_addr": "02:00:00:00:00:20"},
			contains: "sender_ipv4",
		},
		{
			name:     "invalid sender ipv4",
			params:   map[string]any{"hardware_addr": "02:00:00:00:00:20", "sender_ipv4": "2001:db8::10"},
			contains: "sender_ipv4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := baseRule
			rule.Response.Params = tt.params
			err := Validate([]Rule{rule})
			var ve *ValidationError
			require.ErrorAs(t, err, &ve)
			assert.Contains(t, ve.Detail, tt.contains)
		})
	}
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

func TestCompileCIDRLPMIndexMergesDuplicatePrefixes(t *testing.T) {
	rules := []Rule{
		{RuleID: 1, Priority: 10, Match: Match{DstCIDRs: []string{"10.0.1.5/32"}}, Response: Response{Action: "alert"}},
		{RuleID: 2, Priority: 20, Match: Match{DstCIDRs: []string{"10.0.1.5/32"}}, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)

	require.Len(t, compiled.Indexes.DstPrefixLPM, 1)
	expected := slotBit(0)
	maskOr(&expected, slotBit(1))
	assert.Equal(t, expected, compiled.Indexes.DstPrefixLPM[0].Mask)
}

func TestCompileWildcardBitmaps(t *testing.T) {
	// Rule with no VLAN, no ports, no CIDRs -> all wildcard
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "tcp"}, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)

	assert.Equal(t, slotBit(0), compiled.GlobalCfg.VlanWildcardRules)
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.SrcPortWildcardRules)
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.DstPortWildcardRules)
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.SrcPrefixWildcardRules)
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.DstPrefixWildcardRules)
	assert.Equal(t, RuleMask{}, compiled.GlobalCfg.ConditionWildcardRules[0])
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.ConditionWildcardRules[1])
}

func TestCompileWildcardBitmapsPartial(t *testing.T) {
	// Rule with DstPorts but no VLAN, no SrcPorts, no CIDRs
	rules := []Rule{
		{RuleID: 1, Match: Match{Protocol: "tcp", DstPorts: []uint16{80}}, Response: Response{Action: "tcp_reset"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)

	assert.Equal(t, slotBit(0), compiled.GlobalCfg.VlanWildcardRules)
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.SrcPortWildcardRules)
	// DstPorts is set, so NOT wildcard
	assert.Equal(t, RuleMask{}, compiled.GlobalCfg.DstPortWildcardRules)
	assert.Equal(t, RuleMask{}, compiled.GlobalCfg.ConditionWildcardRules[0])
	assert.Equal(t, RuleMask{}, compiled.GlobalCfg.ConditionWildcardRules[8])
	assert.Equal(t, slotBit(0), compiled.GlobalCfg.ConditionWildcardRules[7])
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
