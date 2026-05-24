package ruleset

import (
	"fmt"
	"math"
	"net"

	"xdpass/internal/dataplane/abi"
)

const maxUint32Value = uint64(^uint32(0))

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
	if err := validateResponseParams(r); err != nil {
		return err
	}
	return nil
}

// validateCompatibility checks match/action compatibility per spec.
func validateCompatibility(m Match, r Response) error {
	switch r.Action {
	case "tcp_reset":
		if m.Protocol != "tcp" {
			return fmt.Errorf("action %s requires protocol tcp", r.Action)
		}
	case "tcp_syn_ack":
		if m.Protocol != "tcp" {
			return fmt.Errorf("action tcp_syn_ack requires protocol tcp")
		}
		if m.TCP == nil || m.TCP.Flags == nil || m.TCP.Flags.SYN == nil || !*m.TCP.Flags.SYN {
			return fmt.Errorf("action tcp_syn_ack requires tcp.flags.syn true")
		}
	case "icmp_echo_reply":
		if m.Protocol != "icmp" {
			return fmt.Errorf("action icmp_echo_reply requires protocol icmp")
		}
		if m.ICMP == nil || m.ICMP.Type != "echo_request" {
			return fmt.Errorf("action icmp_echo_reply requires icmp.type echo_request")
		}
	case "icmp_port_unreachable":
		if m.Protocol != "udp" {
			return fmt.Errorf("action icmp_port_unreachable requires protocol udp")
		}
	case "icmp_host_unreachable", "icmp_admin_prohibited":
		if m.Protocol != "tcp" && m.Protocol != "udp" && m.Protocol != "icmp" {
			return fmt.Errorf("action %s requires protocol tcp, udp, or icmp", r.Action)
		}
	case "udp_echo_reply":
		if m.Protocol != "udp" {
			return fmt.Errorf("action udp_echo_reply requires protocol udp")
		}
	case "dns_refused", "dns_sinkhole":
		if m.Protocol != "udp" {
			return fmt.Errorf("action %s requires protocol udp", r.Action)
		}
		if !containsPort(m.DstPorts, 53) {
			return fmt.Errorf("action %s requires dst_ports to include 53", r.Action)
		}
	case "arp_reply":
		if m.Protocol != "arp" {
			return fmt.Errorf("action arp_reply requires protocol arp")
		}
		if m.ARP == nil || m.ARP.Op != "request" {
			return fmt.Errorf("action arp_reply requires arp.op request")
		}
	case "none", "alert":
		// No protocol requirements.
	}
	return nil
}

func validateResponseParams(r Response) error {
	params := r.Params
	switch r.Action {
	case "none", "alert", "tcp_reset", "icmp_echo_reply",
		"icmp_port_unreachable", "icmp_host_unreachable",
		"icmp_admin_prohibited", "udp_echo_reply":
		if len(params) > 0 {
			return fmt.Errorf("response.params must be empty for action %s", r.Action)
		}
	case "tcp_syn_ack":
		return validateTCPSynAckParams(params)
	case "dns_refused":
		return validateDNSRefusedParams(params)
	case "dns_sinkhole":
		return validateDNSSinkholeParams(params)
	case "arp_reply":
		return validateARPReplyParams(params)
	}
	return nil
}

func validateTCPSynAckParams(params map[string]any) error {
	for key, value := range params {
		switch key {
		case "tcp_seq":
			if _, ok := toUint32(value); !ok {
				return fmt.Errorf("response.params.tcp_seq must be uint32")
			}
		default:
			return fmt.Errorf("unknown response.params.%s for action tcp_syn_ack", key)
		}
	}
	return nil
}

func validateDNSRefusedParams(params map[string]any) error {
	for key, value := range params {
		switch key {
		case "rcode":
			rcode, ok := value.(string)
			if !ok || rcode != "refused" {
				return fmt.Errorf("response.params.rcode must be refused")
			}
		default:
			return fmt.Errorf("unknown response.params.%s for action dns_refused", key)
		}
	}
	return nil
}

func validateDNSSinkholeParams(params map[string]any) error {
	family, err := stringParam(params, "family")
	if err != nil {
		return err
	}
	ttl, ok := toUint32(params["ttl"])
	if !ok || ttl == 0 {
		return fmt.Errorf("response.params.ttl must be uint32 greater than 0")
	}

	for key := range params {
		switch key {
		case "family":
			// Already validated above.
		case "answers_v4", "answers_v6":
			if _, err := stringArrayParam(params, key); err != nil {
				return err
			}
		case "ttl":
			// Already validated above.
		default:
			return fmt.Errorf("unknown response.params.%s for action dns_sinkhole", key)
		}
	}

	switch family {
	case "ipv4":
		if err := validateIPAnswers(params, "answers_v4", true, false); err != nil {
			return err
		}
	case "ipv6":
		if err := validateIPAnswers(params, "answers_v6", true, true); err != nil {
			return err
		}
	case "dual_stack":
		if err := validateIPAnswers(params, "answers_v4", true, false); err != nil {
			return err
		}
		if err := validateIPAnswers(params, "answers_v6", true, true); err != nil {
			return err
		}
	default:
		return fmt.Errorf("response.params.family must be ipv4, ipv6, or dual_stack")
	}
	return nil
}

func validateARPReplyParams(params map[string]any) error {
	for key := range params {
		switch key {
		case "hardware_addr", "sender_ipv4":
		default:
			return fmt.Errorf("unknown response.params.%s for action arp_reply", key)
		}
	}
	if _, err := hardwareAddrParam(params, "hardware_addr"); err != nil {
		return err
	}
	if _, err := ipv4Param(params, "sender_ipv4"); err != nil {
		return err
	}
	return nil
}

func validateIPAnswers(params map[string]any, key string, required bool, ipv6 bool) error {
	answers, err := stringArrayParam(params, key)
	if err != nil {
		if required {
			return err
		}
		return nil
	}
	if required && len(answers) == 0 {
		return fmt.Errorf("response.params.%s must contain at least one address", key)
	}
	for _, answer := range answers {
		ip := net.ParseIP(answer)
		if ip == nil {
			return fmt.Errorf("response.params.%s contains invalid IP address %q", key, answer)
		}
		if ipv6 {
			if ip.To4() != nil || ip.To16() == nil {
				return fmt.Errorf("response.params.%s contains non-IPv6 address %q", key, answer)
			}
		} else if ip.To4() == nil {
			return fmt.Errorf("response.params.%s contains non-IPv4 address %q", key, answer)
		}
	}
	return nil
}

func stringArrayParam(params map[string]any, key string) ([]string, error) {
	value, ok := params[key]
	if !ok {
		return nil, fmt.Errorf("missing required response.params.%s", key)
	}
	switch arr := value.(type) {
	case []string:
		return append([]string(nil), arr...), nil
	case []any:
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("response.params.%s items must be strings", key)
			}
			result = append(result, s)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("response.params.%s must be an array of strings", key)
	}
}

func stringParam(params map[string]any, key string) (string, error) {
	value, ok := params[key]
	if !ok {
		return "", fmt.Errorf("missing required response.params.%s", key)
	}
	s, ok := value.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("response.params.%s must be a string", key)
	}
	return s, nil
}

func hardwareAddrParam(params map[string]any, key string) (net.HardwareAddr, error) {
	value, ok := params[key]
	if !ok {
		return nil, fmt.Errorf("missing required response.params.%s", key)
	}
	switch hw := value.(type) {
	case net.HardwareAddr:
		if len(hw) != 6 {
			return nil, fmt.Errorf("response.params.%s must be a MAC address", key)
		}
		return hw, nil
	case []byte:
		if len(hw) != 6 {
			return nil, fmt.Errorf("response.params.%s must be a MAC address", key)
		}
		return net.HardwareAddr(hw), nil
	case string:
		mac, err := net.ParseMAC(hw)
		if err != nil {
			return nil, fmt.Errorf("response.params.%s must be a MAC address", key)
		}
		if len(mac) != 6 {
			return nil, fmt.Errorf("response.params.%s must be a MAC address", key)
		}
		return mac, nil
	default:
		return nil, fmt.Errorf("response.params.%s must be a MAC address", key)
	}
}

func ipv4Param(params map[string]any, key string) (net.IP, error) {
	value, ok := params[key]
	if !ok {
		return nil, fmt.Errorf("missing required response.params.%s", key)
	}
	switch ip := value.(type) {
	case net.IP:
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("response.params.%s must be an IPv4 address", key)
		}
		return ip4, nil
	case []byte:
		ip4 := net.IP(ip).To4()
		if ip4 == nil {
			return nil, fmt.Errorf("response.params.%s must be an IPv4 address", key)
		}
		return ip4, nil
	case string:
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return nil, fmt.Errorf("response.params.%s must be an IPv4 address", key)
		}
		ip4 := parsed.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("response.params.%s must be an IPv4 address", key)
		}
		return ip4, nil
	default:
		return nil, fmt.Errorf("response.params.%s must be an IPv4 address", key)
	}
}

func toUint32(value any) (uint32, bool) {
	switch n := value.(type) {
	case float64:
		if n < 0 || n > float64(maxUint32Value) || math.Trunc(n) != n {
			return 0, false
		}
		return uint32(n), true
	case int:
		if n < 0 {
			return 0, false
		}
		return uint32(n), uint64(n) <= maxUint32Value
	case int64:
		if n < 0 || uint64(n) > maxUint32Value {
			return 0, false
		}
		return uint32(n), true
	case uint:
		if uint64(n) > maxUint32Value {
			return 0, false
		}
		return uint32(n), true
	case uint32:
		return n, true
	case uint64:
		if n > maxUint32Value {
			return 0, false
		}
		return uint32(n), true
	default:
		return 0, false
	}
}

func containsPort(ports []uint16, want uint16) bool {
	for _, port := range ports {
		if port == want {
			return true
		}
	}
	return false
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
