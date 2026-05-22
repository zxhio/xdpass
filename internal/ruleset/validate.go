package ruleset

import (
	"fmt"
	"net"

	"xdpass/internal/dataplane/abi"
)

var validProtocols = map[string]bool{
	"tcp": true, "udp": true, "icmp": true, "arp": true,
}

var validICMPTypes = map[string]bool{
	"echo_request": true,
}

var validARPOps = map[string]bool{
	"request": true,
}

var actionCodeMap = map[string]uint16{
	"none":                  abi.ActionNone,
	"alert":                 abi.ActionAlert,
	"tcp_reset":             abi.ActionTCPReset,
	"icmp_echo_reply":       abi.ActionICMPEchoReply,
	"arp_reply":             abi.ActionARPReply,
	"tcp_syn_ack":           abi.ActionTCPSynAck,
	"icmp_port_unreachable": abi.ActionICMPPortUnreachable,
	"udp_echo_reply":        abi.ActionUDPEchoReply,
	"dns_refused":           abi.ActionDNSRefused,
	"icmp_host_unreachable": abi.ActionICMPHostUnreachable,
	"icmp_admin_prohibited": abi.ActionICMPAdminProhibited,
	"dns_sinkhole":          abi.ActionDNSSinkhole,
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
	if len(rules) > abi.MaxRuleSlots {
		return &ValidationError{Detail: fmt.Sprintf("ruleset exceeds maximum of %d rules", abi.MaxRuleSlots)}
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
	if m.TCP != nil {
		if m.Protocol != "" && m.Protocol != "tcp" {
			return fmt.Errorf("tcp match requires protocol tcp")
		}
		if err := validateTCPFlags(m.TCP.Flags); err != nil {
			return err
		}
	}
	if m.ICMP != nil {
		if m.Protocol != "" && m.Protocol != "icmp" {
			return fmt.Errorf("icmp match requires protocol icmp")
		}
		if m.ICMP.Type != "" && !validICMPTypes[m.ICMP.Type] {
			return fmt.Errorf("invalid icmp.type: %s", m.ICMP.Type)
		}
	}
	if m.ARP != nil {
		if m.Protocol != "" && m.Protocol != "arp" {
			return fmt.Errorf("arp match requires protocol arp")
		}
		if m.ARP.Op != "" && !validARPOps[m.ARP.Op] {
			return fmt.Errorf("invalid arp.op: %s", m.ARP.Op)
		}
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

func validateTCPFlags(flags *TCPFlags) error {
	if flags == nil {
		return nil
	}
	for _, flag := range []struct {
		name  string
		value *bool
	}{
		{name: "syn", value: flags.SYN},
		{name: "ack", value: flags.ACK},
		{name: "rst", value: flags.RST},
		{name: "fin", value: flags.FIN},
		{name: "psh", value: flags.PSH},
	} {
		if flag.value != nil && !*flag.value {
			return fmt.Errorf("tcp.flags.%s must be true when set", flag.name)
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
		if m.ICMP != nil && m.ICMP.Type != "" && m.ICMP.Type != "echo_request" {
			return fmt.Errorf("action icmp_echo_reply requires icmp.type echo_request")
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
		if m.ARP != nil && m.ARP.Op != "" && m.ARP.Op != "request" {
			return fmt.Errorf("action arp_reply requires arp.op request")
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

// IsUserspaceAction reports whether the action requires userspace XSK processing.
func IsUserspaceAction(action string) bool {
	switch action {
	case "icmp_echo_reply", "arp_reply", "tcp_syn_ack",
		"icmp_port_unreachable", "udp_echo_reply", "dns_refused",
		"icmp_host_unreachable", "icmp_admin_prohibited", "dns_sinkhole":
		return true
	default:
		return false
	}
}
