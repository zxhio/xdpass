// Package response implements userspace response packet construction and sending.
package response

import "errors"

// XSK metadata from BPF (bpf-abi.md).
type XSKMeta struct {
	RuleID uint32
	Action uint16
}

// Envelope holds a packet received from XSK with its metadata.
type Envelope struct {
	Packet  []byte
	Meta    XSKMeta
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

// TXWriter writes a packet to an XSK TX ring.
type TXWriter interface {
	WriteTX(pkt []byte) error
}

// Builder constructs a response packet from an original packet and rule params.
type Builder interface {
	Build(origPkt []byte, params map[string]any) ([]byte, error)
}

var (
	ErrUnimplementedAction = errors.New("unimplemented action")
	ErrInvalidPacket       = errors.New("invalid packet for action")
)
