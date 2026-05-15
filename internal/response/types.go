// Package response implements userspace response packet construction and sending.
package response

import "errors"

// Action codes from BPF ABI (bpf-abi.md).
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

// XSK metadata from BPF (bpf-abi.md).
type XSKMeta struct {
	RuleID uint32
	Action uint16
}

// Envelope holds a packet received from XSK with its metadata.
type Envelope struct {
	Packet []byte
	Meta   XSKMeta
	IfIndex uint32 // ingress interface index
}

// RuleLookup finds a rule by its ID, returning action string and params.
type RuleLookup interface {
	LookupByRuleID(ruleID uint32) (action string, params map[string]any, ok bool)
}

// Sender sends a constructed response packet.
type Sender interface {
	Send(pkt []byte) error
	Close() error
}

// Builder constructs a response packet from an original packet and rule params.
type Builder interface {
	Build(origPkt []byte, params map[string]any) ([]byte, error)
}

var (
	ErrUnimplementedAction = errors.New("unimplemented action")
	ErrInvalidPacket       = errors.New("invalid packet for action")
)
