package ruleset

import (
	"fmt"
	"net"
)

// Condition bits, aligned with BPF ABI.
const (
	CondProtoTCP        uint32 = 1 << 0
	CondProtoUDP        uint32 = 1 << 1
	CondProtoICMP       uint32 = 1 << 2
	CondProtoARP        uint32 = 1 << 3
	CondVLAN            uint32 = 1 << 4
	CondSrcPrefix       uint32 = 1 << 5
	CondDstPrefix       uint32 = 1 << 6
	CondSrcPort         uint32 = 1 << 7
	CondDstPort         uint32 = 1 << 8
	CondTCPSyn          uint32 = 1 << 9
	CondTCPAck          uint32 = 1 << 10
	CondTCPRst          uint32 = 1 << 11
	CondTCPFin          uint32 = 1 << 12
	CondTCPPsh          uint32 = 1 << 13
	CondICMPEchoRequest uint32 = 1 << 14
	CondICMPEchoReply   uint32 = 1 << 15
	CondARPRequest      uint32 = 1 << 16
	CondARPReply        uint32 = 1 << 17
	CondL4Payload       uint32 = 1 << 18
)

// Action codes, aligned with BPF ABI.
const (
	ActionNone                uint16 = 0
	ActionAlert               uint16 = 1
	ActionTCPReset            uint16 = 2
	ActionICMPEchoReply       uint16 = 3
	ActionARPReply            uint16 = 4
	ActionTCPSynAck           uint16 = 5
	ActionICMPPortUnreachable uint16 = 6
	ActionUDPEchoReply        uint16 = 7
	ActionDNSRefused          uint16 = 8
	ActionICMPHostUnreachable uint16 = 9
	ActionICMPAdminProhibited uint16 = 10
	ActionDNSSinkhole         uint16 = 11
)

const maxRuleSlots = 512

var validProtocols = map[string]bool{
	"tcp": true, "udp": true, "icmp": true, "arp": true,
}

var validICMPTypes = map[string]bool{
	"echo_request": true, "echo_reply": true,
}

var validARPOps = map[string]bool{
	"request": true, "reply": true,
}

var actionCodeMap = map[string]uint16{
	"none":                  ActionNone,
	"alert":                 ActionAlert,
	"tcp_reset":             ActionTCPReset,
	"icmp_echo_reply":       ActionICMPEchoReply,
	"arp_reply":             ActionARPReply,
	"tcp_syn_ack":           ActionTCPSynAck,
	"icmp_port_unreachable": ActionICMPPortUnreachable,
	"udp_echo_reply":        ActionUDPEchoReply,
	"dns_refused":           ActionDNSRefused,
	"icmp_host_unreachable": ActionICMPHostUnreachable,
	"icmp_admin_prohibited": ActionICMPAdminProhibited,
	"dns_sinkhole":          ActionDNSSinkhole,
}

// ValidationError is a validation error with a detail message.
type ValidationError struct {
	Detail string
}

func (e *ValidationError) Error() string {
	return e.Detail
}

// Validate checks a ruleset for correctness.
func Validate(rules []Rule) error {
	if len(rules) > maxRuleSlots {
		return &ValidationError{Detail: fmt.Sprintf("ruleset exceeds maximum of %d rules", maxRuleSlots)}
	}

	seen := make(map[uint32]bool, len(rules))
	for i, rule := range rules {
		if err := validateRule(rule, seen); err != nil {
			return &ValidationError{Detail: fmt.Sprintf("rule[%d] (rule_id=%d): %s", i, rule.RuleID, err.Error())}
		}
	}
	return nil
}

func validateRule(rule Rule, seen map[uint32]bool) error {
	if rule.RuleID == 0 {
		return fmt.Errorf("rule_id must be greater than 0")
	}
	if seen[rule.RuleID] {
		return fmt.Errorf("duplicate rule_id: %d", rule.RuleID)
	}
	seen[rule.RuleID] = true

	if err := validateMatch(rule.Match); err != nil {
		return err
	}
	if err := validateResponse(rule.Response); err != nil {
		return err
	}
	if err := validateCompatibility(rule.Match, rule.Response); err != nil {
		return err
	}
	return nil
}

func validateMatch(m Match) error {
	if m.Protocol != "" && !validProtocols[m.Protocol] {
		return fmt.Errorf("invalid protocol: %s", m.Protocol)
	}
	if m.ICMPType != "" && !validICMPTypes[m.ICMPType] {
		return fmt.Errorf("invalid icmp_type: %s", m.ICMPType)
	}
	if m.ARPOP != "" && !validARPOps[m.ARPOP] {
		return fmt.Errorf("invalid arp_op: %s", m.ARPOP)
	}
	for _, cidr := range m.SrcCIDRs {
		if err := validateCIDR(cidr); err != nil {
			return fmt.Errorf("invalid src_cidr %q: %w", cidr, err)
		}
	}
	for _, cidr := range m.DstCIDRs {
		if err := validateCIDR(cidr); err != nil {
			return fmt.Errorf("invalid dst_cidr %q: %w", cidr, err)
		}
	}
	return nil
}

func validateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}
	return nil
}

func validateResponse(r Response) error {
	if r.Action == "" {
		return fmt.Errorf("response.action is required")
	}
	if _, ok := actionCodeMap[r.Action]; !ok {
		return fmt.Errorf("invalid action: %s", r.Action)
	}
	return nil
}

// validateCompatibility checks match/action compatibility per spec.
func validateCompatibility(m Match, r Response) error {
	switch r.Action {
	case "tcp_reset", "tcp_syn_ack":
		if m.Protocol != "" && m.Protocol != "tcp" {
			return fmt.Errorf("action %s requires protocol tcp", r.Action)
		}
	case "icmp_echo_reply":
		if m.Protocol != "" && m.Protocol != "icmp" {
			return fmt.Errorf("action icmp_echo_reply requires protocol icmp")
		}
		if m.ICMPType != "" && m.ICMPType != "echo_request" {
			return fmt.Errorf("action icmp_echo_reply requires icmp_type echo_request")
		}
	case "icmp_port_unreachable":
		// Primarily for UDP, but no strict protocol requirement.
	case "icmp_host_unreachable", "icmp_admin_prohibited":
		// Compatible with IPv4 TCP/UDP/ICMP.
	case "udp_echo_reply":
		if m.Protocol != "" && m.Protocol != "udp" {
			return fmt.Errorf("action udp_echo_reply requires protocol udp")
		}
	case "dns_refused", "dns_sinkhole":
		if m.Protocol != "" && m.Protocol != "udp" {
			return fmt.Errorf("action %s requires protocol udp", r.Action)
		}
	case "arp_reply":
		if m.Protocol != "" && m.Protocol != "arp" {
			return fmt.Errorf("action arp_reply requires protocol arp")
		}
		if m.ARPOP != "" && m.ARPOP != "request" {
			return fmt.Errorf("action arp_reply requires arp_op request")
		}
	case "none", "alert":
		// No protocol requirements.
	}
	return nil
}

// ActionToCode converts an action name to its BPF action code.
func ActionToCode(action string) (uint16, bool) {
	code, ok := actionCodeMap[action]
	return code, ok
}
