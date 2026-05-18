// Package events implements BPF ringbuf event decoding and SSE broadcasting.
package events

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// BPF rule_event is 32 bytes, matching the layout in bpf-abi.md.
type bpfRuleEvent struct {
	TimestampNs uint64 // offset 0, 8 bytes
	RuleID      uint32 // offset 8, 4 bytes
	PktConds    uint32 // offset 12, 4 bytes
	SIP         uint32 // offset 16, 4 bytes
	DIP         uint32 // offset 20, 4 bytes
	Action      uint16 // offset 24, 2 bytes
	Sport       uint16 // offset 26, 2 bytes
	Dport       uint16 // offset 28, 2 bytes
	Verdict     uint8  // offset 30, 1 byte
	IPProto     uint8  // offset 31, 1 byte
}

const ruleEventSize = 32

// Event is the decoded event for API response.
type Event struct {
	Timestamp int64  `json:"timestamp"`
	Type      string `json:"type"`
	RuleID    uint32 `json:"rule_id"`
	Action    string `json:"action"`
	Path      string `json:"path,omitempty"`
	Verdict   string `json:"verdict,omitempty"`
	Result    string `json:"result,omitempty"`
	IfIndex   uint32 `json:"ifindex,omitempty"`
	SIP       string `json:"sip,omitempty"`
	DIP       string `json:"dip,omitempty"`
	Sport     uint16 `json:"sport"`
	Dport     uint16 `json:"dport"`
	IPProto   uint8  `json:"ip_proto"`
}

// actionName maps BPF action codes to API action names.
var actionName = map[uint16]string{
	0:  "none",
	1:  "alert",
	2:  "tcp_reset",
	3:  "icmp_echo_reply",
	4:  "arp_reply",
	5:  "tcp_syn_ack",
	6:  "icmp_port_unreachable",
	7:  "udp_echo_reply",
	8:  "dns_refused",
	9:  "icmp_host_unreachable",
	10: "icmp_admin_prohibited",
	11: "dns_sinkhole",
}

// verdictName maps BPF verdict codes to API verdict names.
var verdictName = map[uint8]string{
	0: "observe",
	1: "xdp_tx",
	2: "xsk_redirect",
	3: "redirect_tx",
}

// actionPath maps action codes to their execution path.
var actionPath = map[uint16]string{
	0:  "none",      // none
	1:  "none",      // alert
	2:  "kernel",    // tcp_reset
	3:  "userspace", // icmp_echo_reply
	4:  "userspace", // arp_reply
	5:  "userspace", // tcp_syn_ack
	6:  "userspace", // icmp_port_unreachable
	7:  "userspace", // udp_echo_reply
	8:  "userspace", // dns_refused
	9:  "userspace", // icmp_host_unreachable
	10: "userspace", // icmp_admin_prohibited
	11: "userspace", // dns_sinkhole
}

// DecodeEvent decodes a 32-byte BPF rule_event into an API Event.
// ifIndex is the attachment's ifindex, not present in the BPF event.
// bootTimeOffset is the offset between monotonic and realtime clocks.
func DecodeEvent(raw [ruleEventSize]byte, ifIndex uint32, bootTimeOffset int64) (Event, error) {
	if len(raw) < ruleEventSize {
		return Event{}, fmt.Errorf("event too short: %d bytes", len(raw))
	}

	e := bpfRuleEvent{
		TimestampNs: binary.LittleEndian.Uint64(raw[0:8]),
		RuleID:      binary.LittleEndian.Uint32(raw[8:12]),
		PktConds:    binary.LittleEndian.Uint32(raw[12:16]),
		SIP:         binary.BigEndian.Uint32(raw[16:20]),
		DIP:         binary.BigEndian.Uint32(raw[20:24]),
		Action:      binary.LittleEndian.Uint16(raw[24:26]),
		Sport:       binary.LittleEndian.Uint16(raw[26:28]),
		Dport:       binary.LittleEndian.Uint16(raw[28:30]),
		Verdict:     raw[30],
		IPProto:     raw[31],
	}

	return Event{
		Timestamp: int64(time.Duration(e.TimestampNs)*time.Nanosecond)/int64(time.Second) + bootTimeOffset,
		Type:      "rule_event",
		RuleID:    e.RuleID,
		Action:    actionName[e.Action],
		Path:      actionPath[e.Action],
		Verdict:   verdictName[e.Verdict],
		Result:    deriveResult(e.Action, e.Verdict),
		IfIndex:   ifIndex,
		SIP:       ipv4ToString(e.SIP),
		DIP:       ipv4ToString(e.DIP),
		Sport:     e.Sport,
		Dport:     e.Dport,
		IPProto:   e.IPProto,
	}, nil
}

// deriveResult derives the event result from action and verdict.
// Only "sent" and "failed" are meaningful; "matched" is omitted as low-value.
func deriveResult(action uint16, verdict uint8) string {
	path := actionPath[action]
	switch path {
	case "none":
		return ""
	case "kernel":
		if verdict == 1 || verdict == 3 { // VERDICT_TX or VERDICT_REDIRECT_TX
			return "sent"
		}
		return "failed"
	case "userspace":
		// BPF verdict=xsk_redirect means the packet entered XSK.
		// The actual sent/failed result comes from the userspace response runtime.
		if verdict == 2 { // VERDICT_XSK
			return ""
		}
		return "failed"
	}
	return ""
}

// ipv4ToString converts a uint32 IPv4 address to dotted-decimal string.
// The address is in network byte order (big-endian).
func ipv4ToString(addr uint32) string {
	if addr == 0 {
		return ""
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, addr)
	return ip.String()
}

// BootTimeOffset returns the offset in seconds between monotonic and realtime clocks.
// realtime = monotonic + offset
func BootTimeOffset() int64 {
	var mono unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono)
	wall := time.Now().UnixNano()
	monoNs := mono.Sec*1e9 + int64(mono.Nsec)
	return (wall - monoNs) / int64(time.Second)
}
