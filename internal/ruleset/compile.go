package ruleset

import (
	"encoding/binary"
	"net"
	"sort"

	"xdpass/internal/dataplane/abi"
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
		Rules: make([]CompiledRule, len(sorted)),
		Indexes: IndexData{
			SrcPortIndex: make(map[uint16]RuleMask),
			DstPortIndex: make(map[uint16]RuleMask),
			VlanIndex:    make(map[uint16]RuleMask),
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
		compileWildcardBitmaps(rule, slot, bit, compiled)
	}

	return compiled, nil
}

// slotBit returns the rule mask with the bit for the given slot set.
func slotBit(slot uint32) RuleMask {
	var mask RuleMask
	group := slot / 64
	bit := slot % 64
	mask[group] = 1 << bit
	return mask
}

func maskOr(dst *RuleMask, src RuleMask) {
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
			mask |= abi.CondProtoTCP
		case "udp":
			mask |= abi.CondProtoUDP
		case "icmp":
			mask |= abi.CondProtoICMP
		case "arp":
			mask |= abi.CondProtoARP
		}
	}

	if len(m.VLANS) > 0 {
		mask |= abi.CondVLAN
	}
	if len(m.SrcCIDRs) > 0 {
		mask |= abi.CondSrcPrefix
	}
	if len(m.DstCIDRs) > 0 {
		mask |= abi.CondDstPrefix
	}
	if len(m.SrcPorts) > 0 {
		mask |= abi.CondSrcPort
	}
	if len(m.DstPorts) > 0 {
		mask |= abi.CondDstPort
	}

	if m.TCP != nil && m.TCP.Flags != nil {
		mask = addFlagCondition(mask, m.TCP.Flags.SYN, abi.CondTCPSyn)
		mask = addFlagCondition(mask, m.TCP.Flags.ACK, abi.CondTCPAck)
		mask = addFlagCondition(mask, m.TCP.Flags.RST, abi.CondTCPRst)
		mask = addFlagCondition(mask, m.TCP.Flags.FIN, abi.CondTCPFin)
		mask = addFlagCondition(mask, m.TCP.Flags.PSH, abi.CondTCPPsh)
	}

	if m.ICMP != nil {
		switch m.ICMP.Type {
		case "echo_request":
			mask |= abi.CondICMPEchoRequest
		}
	}

	if m.ARP != nil {
		switch m.ARP.Op {
		case "request":
			mask |= abi.CondARPRequest
		}
	}

	return mask
}

func addFlagCondition(mask uint32, enabled *bool, condition uint32) uint32 {
	if enabled != nil && *enabled {
		return mask | condition
	}
	return mask
}

// compileIndexes populates inverted indexes for a rule.
func compileIndexes(rule Rule, _ uint32, bit RuleMask, compiled *CompiledRuleset) {
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
		compiled.Indexes.SrcPrefixLPM = mergeLPMEntries(compiled.Indexes.SrcPrefixLPM, entries)
	}
	for _, cidr := range rule.Match.DstCIDRs {
		entries := compileCIDR(cidr, bit)
		compiled.Indexes.DstPrefixLPM = mergeLPMEntries(compiled.Indexes.DstPrefixLPM, entries)
	}
}

// compileCIDR converts a CIDR string to LPM entries with the given bit mask.
func compileCIDR(cidr string, bit RuleMask) []LPMEntry {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil || ipNet.IP.To4() == nil {
		return nil
	}
	prefixLen, _ := ipNet.Mask.Size()
	return []LPMEntry{{
		Prefixlen: uint32(prefixLen),
		Addr:      ipv4LPMAddr(ipNet.IP),
		Mask:      bit,
	}}
}

func mergeLPMEntries(existing []LPMEntry, entries []LPMEntry) []LPMEntry {
	for _, entry := range entries {
		merged := false
		for i := range existing {
			if existing[i].Prefixlen == entry.Prefixlen && existing[i].Addr == entry.Addr {
				maskOr(&existing[i].Mask, entry.Mask)
				merged = true
				break
			}
		}
		if !merged {
			existing = append(existing, entry)
		}
	}
	return existing
}

// ipv4LPMAddr returns the uint32 value whose little-endian in-memory bytes
// match the IPv4 network-order bytes used by BPF LPM trie lookup.
func ipv4LPMAddr(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip.To4())
}

// compileWildcardBitmaps populates wildcard bitmaps for rules missing condition fields.
func compileWildcardBitmaps(rule Rule, _ uint32, bit RuleMask, compiled *CompiledRuleset) {
	if len(rule.Match.VLANS) == 0 {
		maskOr(&compiled.GlobalCfg.VlanWildcardRules, bit)
	}
	if len(rule.Match.SrcPorts) == 0 {
		maskOr(&compiled.GlobalCfg.SrcPortWildcardRules, bit)
	}
	if len(rule.Match.DstPorts) == 0 {
		maskOr(&compiled.GlobalCfg.DstPortWildcardRules, bit)
	}
	if len(rule.Match.SrcCIDRs) == 0 {
		maskOr(&compiled.GlobalCfg.SrcPrefixWildcardRules, bit)
	}
	if len(rule.Match.DstCIDRs) == 0 {
		maskOr(&compiled.GlobalCfg.DstPrefixWildcardRules, bit)
	}
	requiredMask := compileRequiredMask(rule.Match)
	for cond := range compiled.GlobalCfg.ConditionWildcardRules {
		if requiredMask&(1<<cond) == 0 {
			maskOr(&compiled.GlobalCfg.ConditionWildcardRules[cond], bit)
		}
	}
}
