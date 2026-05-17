// Package dispatch implements async packet dispatch for matched packets.
package dispatch

// Sender sends a raw L2 frame to a dispatch backend.
type Sender interface {
	Send(pkt []byte) error
	Close() error
}

// Packet holds a raw L2 frame to be dispatched.
type Packet struct {
	Data []byte
}
