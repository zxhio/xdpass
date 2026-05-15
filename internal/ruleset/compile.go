package ruleset

import (
	"encoding/binary"
	"net"
	"sort"
)

// Compile validates and compiles a ruleset into BPF-ready structures.
func Compile(rules []Rule, ingressVerdict string) (*CompiledRuleset, error) {
	if err := Validate(rules); err != nil {
		return nil, err
	}

	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].RuleID < sorted[j].RuleID
	})

	compiled := &CompiledRuleset{
		Rules:    make([]CompiledRule, len(sorted)),
		Indexes: IndexData{
			SrcPortIndex: make(map[uint16][8]uint64),
			DstPortIndex: make(map[uint16][8]uint64),
			VlanIndex:    make(map[uint16][8]uint64),
		},
	}

	if ingressVerdict == "drop" {
		compiled.GlobalCfg.IngressVerdict = 1
	}

	for i, rule := range sorted {
		slot := uint32(i)
		bit := slotBit(slot)

		requiredMask := compileRequiredMask(rule.Match)
		actionCode, _ := ActionToCode(rule.Response.Action)

		compiled.Rules[i] = CompiledRule{
			Slot:   slot,
			RuleID: rule.RuleID,
			Meta: RuleMetaData{
				RuleID:       rule.RuleID,
				RequiredMask: requiredMask,
				Action:       actionCode,
				Flags:        0,
			},
		}

		maskOr(&compiled.GlobalCfg.AllActiveRules, bit)

		compileIndexes(rule, slot, bit, compiled)
		compileOptionalBitmaps(rule, slot, bit, compiled)
	}

	return compiled, nil
}

// slotBit returns the 512-bit mask with the bit for the given slot set.
func slotBit(slot uint32) [8]uint64 {
	var mask [8]uint64
	group := slot / 64
	bit := slot % 64
	mask[group] = 1 << bit
	return mask
}

func maskOr(dst *[8]uint64, src [8]uint64) {
	for i := range dst {
		dst[i] |= src[i]
	}
}

// compileRequiredMask computes the required_mask for a rule's match conditions.
func compileRequiredMask(m Match) uint32 {
	var mask uint32

	if m.Protocol != "" {
		switch m.Protocol {
		case "tcp":
			mask |= CondProtoTCP
		case "udp":
			mask |= CondProtoUDP
		case "icmp":
			mask |= CondProtoICMP
		case "arp":
			mask |= CondProtoARP
		}
	}

	if len(m.VLANS) > 0 {
		mask |= CondVLAN
	}
	if len(m.SrcCIDRs) > 0 {
		mask |= CondSrcPrefix
	}
	if len(m.DstCIDRs) > 0 {
		mask |= CondDstPrefix
	}
	if len(m.SrcPorts) > 0 {
		mask |= CondSrcPort
	}
	if len(m.DstPorts) > 0 {
		mask |= CondDstPort
	}

	if m.TCPFlags != nil {
		if m.TCPFlags.SYN != nil && *m.TCPFlags.SYN {
			mask |= CondTCPSyn
		}
		if m.TCPFlags.ACK != nil && *m.TCPFlags.ACK {
			mask |= CondTCPAck
		}
		if m.TCPFlags.RST != nil && *m.TCPFlags.RST {
			mask |= CondTCPRst
		}
		if m.TCPFlags.FIN != nil && *m.TCPFlags.FIN {
			mask |= CondTCPFin
		}
		if m.TCPFlags.PSH != nil && *m.TCPFlags.PSH {
			mask |= CondTCPPsh
		}
	}

	if m.ICMPType != "" {
		switch m.ICMPType {
		case "echo_request":
			mask |= CondICMPEchoRequest
		case "echo_reply":
			mask |= CondICMPEchoReply
		}
	}

	if m.ARPOP != "" {
		switch m.ARPOP {
		case "request":
			mask |= CondARPRequest
		case "reply":
			mask |= CondARPReply
		}
	}

	if m.HasL4Payload != nil && *m.HasL4Payload {
		mask |= CondL4Payload
	}

	return mask
}

// compileIndexes populates inverted indexes for a rule.
func compileIndexes(rule Rule, _ uint32, bit [8]uint64, compiled *CompiledRuleset) {
	for _, port := range rule.Match.SrcPorts {
		existing := compiled.Indexes.SrcPortIndex[port]
		maskOr(&existing, bit)
		compiled.Indexes.SrcPortIndex[port] = existing
	}
	for _, port := range rule.Match.DstPorts {
		existing := compiled.Indexes.DstPortIndex[port]
		maskOr(&existing, bit)
		compiled.Indexes.DstPortIndex[port] = existing
	}
	for _, vlan := range rule.Match.VLANS {
		existing := compiled.Indexes.VlanIndex[vlan]
		maskOr(&existing, bit)
		compiled.Indexes.VlanIndex[vlan] = existing
	}
	for _, cidr := range rule.Match.SrcCIDRs {
		entries := compileCIDR(cidr, bit)
		compiled.Indexes.SrcPrefixLPM = append(compiled.Indexes.SrcPrefixLPM, entries...)
	}
	for _, cidr := range rule.Match.DstCIDRs {
		entries := compileCIDR(cidr, bit)
		compiled.Indexes.DstPrefixLPM = append(compiled.Indexes.DstPrefixLPM, entries...)
	}
}

// compileCIDR converts a CIDR string to LPM entries with the given bit mask.
func compileCIDR(cidr string, bit [8]uint64) []LPMEntry {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return nil
	}
	prefixLen, _ := ipNet.Mask.Size()
	addr := binary.BigEndian.Uint32(ip.To4())
	return []LPMEntry{{
		Prefixlen: uint32(prefixLen),
		Addr:      addr,
		Mask:      bit,
	}}
}

// compileOptionalBitmaps populates optional bitmaps for rules missing condition fields.
func compileOptionalBitmaps(rule Rule, _ uint32, bit [8]uint64, compiled *CompiledRuleset) {
	if len(rule.Match.VLANS) == 0 {
		maskOr(&compiled.GlobalCfg.VlanOptionalRules, bit)
	}
	if len(rule.Match.SrcPorts) == 0 {
		maskOr(&compiled.GlobalCfg.SrcPortOptionalRules, bit)
	}
	if len(rule.Match.DstPorts) == 0 {
		maskOr(&compiled.GlobalCfg.DstPortOptionalRules, bit)
	}
	if len(rule.Match.SrcCIDRs) == 0 {
		maskOr(&compiled.GlobalCfg.SrcPrefixOptionalRules, bit)
	}
	if len(rule.Match.DstCIDRs) == 0 {
		maskOr(&compiled.GlobalCfg.DstPrefixOptionalRules, bit)
	}
	requiredMask := compileRequiredMask(rule.Match)
	for cond := range compiled.GlobalCfg.ConditionOptionalRules {
		if requiredMask&(1<<cond) == 0 {
			maskOr(&compiled.GlobalCfg.ConditionOptionalRules[cond], bit)
		}
	}
}
