// Package ruleset implements ruleset validation, compilation, and BPF map writing.
package ruleset

import "xdpass/internal/dataplane/abi"

// Rule is the internal representation of a ruleset rule.
type Rule struct {
	RuleID   uint32
	Priority uint32
	Match    Match
	Response Response
}

// Match holds rule match conditions.
// Empty/nil fields are wildcards.
type Match struct {
	Protocol string // tcp, udp, icmp, arp, or empty
	VLANS    []uint16
	SrcCIDRs []string
	DstCIDRs []string
	SrcPorts []uint16
	DstPorts []uint16
	TCP      *TCPMatch
	ICMP     *ICMPMatch
	ARP      *ARPMatch
}

// TCPMatch holds TCP-specific match conditions.
type TCPMatch struct {
	Flags *TCPFlags
}

// TCPFlags holds TCP flag match conditions.
type TCPFlags struct {
	SYN *bool
	ACK *bool
	RST *bool
	FIN *bool
	PSH *bool
}

// ICMPMatch holds ICMP-specific match conditions.
type ICMPMatch struct {
	Type string // echo_request
}

// ARPMatch holds ARP-specific match conditions.
type ARPMatch struct {
	Op string // request
}

// Response holds rule response action.
type Response struct {
	Action string
	Params map[string]any
}

// CompiledRuleset is the result of compiling a ruleset for BPF maps.
type CompiledRuleset struct {
	Rules     []CompiledRule
	GlobalCfg GlobalCfgData
	Indexes   IndexData
}

// CompiledRule is a single compiled rule ready for BPF.
type CompiledRule struct {
	Slot   uint32
	RuleID uint32
	Meta   RuleMetaData
}

// RuleMetaData is the BPF rule_meta equivalent.
type RuleMetaData struct {
	RuleID       uint32
	RequiredMask uint32
	Action       uint16
	Flags        uint8
}

// RuleMask is the userspace equivalent of BPF mask_t.
type RuleMask [abi.RuleGroups]uint64

// GlobalCfgData holds the compiled global_cfg map data.
type GlobalCfgData struct {
	AllActiveRules         RuleMask
	VlanWildcardRules      RuleMask
	SrcPortWildcardRules   RuleMask
	DstPortWildcardRules   RuleMask
	SrcPrefixWildcardRules RuleMask
	DstPrefixWildcardRules RuleMask
	ConditionWildcardRules [abi.ConditionBits]RuleMask
	IngressVerdict         uint32
}

// IndexData holds all compiled inverted indexes.
type IndexData struct {
	SrcPortIndex map[uint16]RuleMask
	DstPortIndex map[uint16]RuleMask
	VlanIndex    map[uint16]RuleMask
	SrcPrefixLPM []LPMEntry
	DstPrefixLPM []LPMEntry
}

// LPMEntry is a single LPM trie entry.
type LPMEntry struct {
	Prefixlen uint32
	Addr      uint32
	Mask      RuleMask
}
