package attachment

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// PromiscuousOpenFunc requests promiscuous mode for an interface and returns
// the handle that owns that kernel membership.
type PromiscuousOpenFunc func(ifIndex uint32) (PromiscuousHandle, error)

// PromiscuousHandle releases one agent-owned promiscuous mode request.
type PromiscuousHandle interface {
	Close() error
}

type promiscuousHandle struct {
	fd int
}

func openPromiscuous(ifIndex uint32) (PromiscuousHandle, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("create packet socket: %w", err)
	}

	req := &unix.PacketMreq{
		Ifindex: int32(ifIndex),
		Type:    unix.PACKET_MR_PROMISC,
	}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, req); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("add packet promiscuous membership: %w", err)
	}

	return &promiscuousHandle{fd: fd}, nil
}

func (h *promiscuousHandle) Close() error {
	if h.fd < 0 {
		return nil
	}
	fd := h.fd
	h.fd = -1
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("close packet socket: %w", err)
	}
	return nil
}
