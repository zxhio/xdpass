package response

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// AFPacketSender sends packets via AF_PACKET raw socket.
type AFPacketSender struct {
	fd     int
	ifIndex uint32
}

// NewAFPacketSender creates an AF_PACKET sender bound to the given interface.
func NewAFPacketSender(ifIndex uint32) (*AFPacketSender, error) {
	// ETH_P_ALL = 0x0003
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("create af_packet socket: %w", err)
	}

	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  int(ifIndex),
	}
	if err := unix.Bind(fd, &addr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind af_packet to ifindex %d: %w", ifIndex, err)
	}

	return &AFPacketSender{fd: fd, ifIndex: ifIndex}, nil
}

// Send writes a raw packet to the AF_PACKET socket.
func (s *AFPacketSender) Send(pkt []byte) error {
	_, err := unix.Write(s.fd, pkt)
	if err != nil {
		return fmt.Errorf("af_packet send: %w", err)
	}
	return nil
}

// Close closes the AF_PACKET socket.
func (s *AFPacketSender) Close() error {
	return unix.Close(s.fd)
}

// xskTXSender sends packets via an XSK TX ring (same-port response).
type xskTXSender struct {
	txWriter TXWriter
}

// Send writes a raw packet to the XSK TX ring.
func (s *xskTXSender) Send(pkt []byte) error {
	return s.txWriter.WriteTX(pkt)
}

// Close is a no-op for the XSK TX sender.
func (s *xskTXSender) Close() error { return nil }

// htons converts a 16-bit value from host to network byte order.
func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}

// NewSender creates the appropriate sender based on whether same-port or cross-port.
// samePort: use XSK TX via txWriter if available, else AF_PACKET fallback
// crossPort: use AF_PACKET on the egress interface
func NewSender(samePort bool, txWriter TXWriter, ingressIfIndex, egressIfIndex uint32) (Sender, error) {
	if samePort {
		if txWriter != nil {
			return &xskTXSender{txWriter: txWriter}, nil
		}
		return NewAFPacketSender(ingressIfIndex)
	}
	return NewAFPacketSender(egressIfIndex)
}

// SendWithVLAN sends a packet, optionally stripping the VLAN tag based on vlan_mode.
func SendWithVLAN(sender Sender, pkt []byte, vlanMode string) error {
	if vlanMode == "access" && len(pkt) >= 18 {
		ethType := uint16(pkt[12])<<8 | uint16(pkt[13])
		if ethType == 0x8100 || ethType == 0x88a8 {
			// Strip 4-byte VLAN tag: build new packet without it.
			stripped := make([]byte, len(pkt)-4)
			copy(stripped[:12], pkt[:12])
			// Update ethertype to inner type.
			copy(stripped[12:14], pkt[16:18])
			copy(stripped[14:], pkt[18:])
			pkt = stripped
		}
	}
	return sender.Send(pkt)
}

// InterfaceAddrs returns the MAC address of an interface by ifindex.
func InterfaceMAC(ifIndex uint32) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByIndex(int(ifIndex))
	if err != nil {
		return nil, fmt.Errorf("get interface %d: %w", ifIndex, err)
	}
	return iface.HardwareAddr, nil
}
