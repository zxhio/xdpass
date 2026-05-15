package response

import (
	"encoding/binary"
	"fmt"
	"net"
)

// BuilderFunc is a function that builds a response packet.
type BuilderFunc func(origPkt []byte, params map[string]any) ([]byte, error)

// BuilderForAction returns a builder for the given action, or nil if unimplemented.
func BuilderForAction(action uint16) BuilderFunc {
	switch action {
	case ActionICMPEchoReply:
		return buildICMPEchoReply
	case ActionUDPEchoReply:
		return buildUDPEchoReply
	case ActionARPReply:
		return buildARPReply
	default:
		return nil
	}
}

// buildICMPEchoReply constructs an ICMP echo reply from an echo request.
// Swaps Ethernet MAC, IPv4 src/dst, sets ICMP type to echo reply.
func buildICMPEchoReply(origPkt []byte, _ map[string]any) ([]byte, error) {
	if len(origPkt) < 14+20+8 {
		return nil, fmt.Errorf("%w: icmp echo reply requires at least ethernet+ipv4+icmp header", ErrInvalidPacket)
	}

	// Parse Ethernet header.
	ethType := binary.BigEndian.Uint16(origPkt[12:14])
	ethHdrLen := 14

	// Skip VLAN tag if present.
	if ethType == 0x8100 || ethType == 0x88a8 {
		if len(origPkt) < 18+20+8 {
			return nil, fmt.Errorf("%w: too short for vlan+ipv4+icmp", ErrInvalidPacket)
		}
		ethType = binary.BigEndian.Uint16(origPkt[16:18])
		ethHdrLen = 18
	}

	if ethType != 0x0800 {
		return nil, fmt.Errorf("%w: not IPv4 (ethertype=0x%04x)", ErrInvalidPacket, ethType)
	}

	// Parse IPv4 header.
	ihl := int(origPkt[ethHdrLen]&0x0f) * 4
	if len(origPkt) < ethHdrLen+ihl+8 {
		return nil, fmt.Errorf("%w: too short for ipv4+icmp", ErrInvalidPacket)
	}
	if origPkt[ethHdrLen+9] != 1 { // protocol must be ICMP
		return nil, fmt.Errorf("%w: not ICMP (proto=%d)", ErrInvalidPacket, origPkt[ethHdrLen+9])
	}

	icmpOffset := ethHdrLen + ihl
	icmpType := origPkt[icmpOffset]
	if icmpType != 8 { // echo request
		return nil, fmt.Errorf("%w: not echo request (type=%d)", ErrInvalidPacket, icmpType)
	}

	// Copy the original packet.
	pkt := make([]byte, len(origPkt))
	copy(pkt, origPkt)

	// Swap Ethernet MAC addresses.
	copy(pkt[0:6], origPkt[6:12])
	copy(pkt[6:12], origPkt[0:6])

	// Swap IPv4 src/dst addresses.
	copy(pkt[ethHdrLen+12:ethHdrLen+16], origPkt[ethHdrLen+16:ethHdrLen+20])
	copy(pkt[ethHdrLen+16:ethHdrLen+20], origPkt[ethHdrLen+12:ethHdrLen+16])

	// Set ICMP type to echo reply (0).
	pkt[icmpOffset] = 0

	// Zero ICMP checksum before recalculating.
	pkt[icmpOffset+2] = 0
	pkt[icmpOffset+3] = 0

	// Recalculate ICMP checksum.
	icmpLen := len(pkt) - icmpOffset
	pkt[icmpOffset+2], pkt[icmpOffset+3] = checksum(pkt[icmpOffset : icmpOffset+icmpLen])

	// Recalculate IPv4 checksum.
	recalcIPv4Checksum(pkt, ethHdrLen)

	return pkt, nil
}

// buildUDPEchoReply constructs a UDP echo reply by swapping addresses and ports.
func buildUDPEchoReply(origPkt []byte, _ map[string]any) ([]byte, error) {
	if len(origPkt) < 14+20+8 {
		return nil, fmt.Errorf("%w: udp echo reply requires at least ethernet+ipv4+udp header", ErrInvalidPacket)
	}

	ethType := binary.BigEndian.Uint16(origPkt[12:14])
	ethHdrLen := 14

	if ethType == 0x8100 || ethType == 0x88a8 {
		if len(origPkt) < 18+20+8 {
			return nil, fmt.Errorf("%w: too short for vlan+ipv4+udp", ErrInvalidPacket)
		}
		ethType = binary.BigEndian.Uint16(origPkt[16:18])
		ethHdrLen = 18
	}

	if ethType != 0x0800 {
		return nil, fmt.Errorf("%w: not IPv4 (ethertype=0x%04x)", ErrInvalidPacket, ethType)
	}

	ihl := int(origPkt[ethHdrLen]&0x0f) * 4
	if len(origPkt) < ethHdrLen+ihl+8 {
		return nil, fmt.Errorf("%w: too short for ipv4+udp", ErrInvalidPacket)
	}
	if origPkt[ethHdrLen+9] != 17 { // protocol must be UDP
		return nil, fmt.Errorf("%w: not UDP (proto=%d)", ErrInvalidPacket, origPkt[ethHdrLen+9])
	}

	udpOffset := ethHdrLen + ihl
	udpLen := binary.BigEndian.Uint16(origPkt[udpOffset+4 : udpOffset+6])
	if udpLen < 8 {
		return nil, fmt.Errorf("%w: invalid udp length %d", ErrInvalidPacket, udpLen)
	}
	if int(udpLen) > len(origPkt)-udpOffset {
		return nil, fmt.Errorf("%w: udp length %d exceeds packet", ErrInvalidPacket, udpLen)
	}

	pkt := make([]byte, len(origPkt))
	copy(pkt, origPkt)

	// Swap Ethernet MAC.
	copy(pkt[0:6], origPkt[6:12])
	copy(pkt[6:12], origPkt[0:6])

	// Swap IPv4 src/dst.
	copy(pkt[ethHdrLen+12:ethHdrLen+16], origPkt[ethHdrLen+16:ethHdrLen+20])
	copy(pkt[ethHdrLen+16:ethHdrLen+20], origPkt[ethHdrLen+12:ethHdrLen+16])

	// Swap UDP src/dst ports.
	copy(pkt[udpOffset:udpOffset+2], origPkt[udpOffset+2:udpOffset+4])
	copy(pkt[udpOffset+2:udpOffset+4], origPkt[udpOffset:udpOffset+2])

	// Zero UDP checksum (optional for IPv4 UDP).
	pkt[udpOffset+6] = 0
	pkt[udpOffset+7] = 0

	// Recalculate IPv4 checksum.
	recalcIPv4Checksum(pkt, ethHdrLen)

	return pkt, nil
}

// buildARPReply constructs an ARP reply from an ARP request.
func buildARPReply(origPkt []byte, params map[string]any) ([]byte, error) {
	if len(origPkt) < 14+28 {
		return nil, fmt.Errorf("%w: arp requires at least ethernet+arp header", ErrInvalidPacket)
	}

	ethType := binary.BigEndian.Uint16(origPkt[12:14])
	ethHdrLen := 14

	if ethType == 0x8100 || ethType == 0x88a8 {
		if len(origPkt) < 18+28 {
			return nil, fmt.Errorf("%w: too short for vlan+arp", ErrInvalidPacket)
		}
		ethType = binary.BigEndian.Uint16(origPkt[16:18])
		ethHdrLen = 18
	}

	if ethType != 0x0806 {
		return nil, fmt.Errorf("%w: not ARP (ethertype=0x%04x)", ErrInvalidPacket, ethType)
	}

	arpOffset := ethHdrLen
	// ARP header: hardware_type(2) + proto_type(2) + hw_len(1) + proto_len(1) + op(2)
	arpOp := binary.BigEndian.Uint16(origPkt[arpOffset+6 : arpOffset+8])
	if arpOp != 1 { // must be ARP request
		return nil, fmt.Errorf("%w: not ARP request (op=%d)", ErrInvalidPacket, arpOp)
	}

	hwLen := origPkt[arpOffset+4]
	protoLen := origPkt[arpOffset+5]
	if hwLen != 6 || protoLen != 4 {
		return nil, fmt.Errorf("%w: unsupported hw_len=%d proto_len=%d", ErrInvalidPacket, hwLen, protoLen)
	}

	expectedLen := ethHdrLen + 8 + int(hwLen)*2 + int(protoLen)*2
	if len(origPkt) < expectedLen {
		return nil, fmt.Errorf("%w: arp packet too short", ErrInvalidPacket)
	}

	// Extract sender fields from ARP request.
	senderHW := origPkt[arpOffset+8 : arpOffset+8+6]
	senderProto := origPkt[arpOffset+14 : arpOffset+14+4]

	// Get reply sender fields from params.
	replyHW, err := getMACParam(params, "hardware_addr")
	if err != nil {
		return nil, err
	}
	replyProto, err := getIPv4Param(params, "sender_ipv4")
	if err != nil {
		return nil, err
	}

	pkt := make([]byte, len(origPkt))
	copy(pkt, origPkt)

	// Swap Ethernet MAC for reply.
	copy(pkt[0:6], senderHW)        // dst = original sender
	copy(pkt[6:12], replyHW)        // src = reply sender

	// Set ARP op to reply.
	binary.BigEndian.PutUint16(pkt[arpOffset+6:arpOffset+8], 2)

	// ARP reply: sender = our params, target = original sender.
	copy(pkt[arpOffset+8:arpOffset+14], replyHW)
	copy(pkt[arpOffset+14:arpOffset+18], replyProto)
	copy(pkt[arpOffset+18:arpOffset+24], senderHW)
	copy(pkt[arpOffset+24:arpOffset+28], senderProto)

	return pkt, nil
}

// getMACParam extracts a MAC address from params.
func getMACParam(params map[string]any, key string) (net.HardwareAddr, error) {
	v, ok := params[key]
	if !ok {
		return nil, fmt.Errorf("missing required param: %s", key)
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("param %s must be a string", key)
	}
	mac, err := net.ParseMAC(s)
	if err != nil {
		return nil, fmt.Errorf("param %s: %w", key, err)
	}
	return mac, nil
}

// getIPv4Param extracts an IPv4 address from params.
func getIPv4Param(params map[string]any, key string) (net.IP, error) {
	v, ok := params[key]
	if !ok {
		return nil, fmt.Errorf("missing required param: %s", key)
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("param %s must be a string", key)
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("param %s: invalid IP address %q", key, s)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("param %s: not an IPv4 address", key)
	}
	return ip, nil
}

// checksum calculates the IPv4/ICMP checksum.
func checksum(data []byte) (byte, byte) {
	var sum uint32
	length := len(data)
	i := 0
	for length > 1 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		i += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[i]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	c := ^uint16(sum)
	return byte(c >> 8), byte(c)
}

// recalcIPv4Checksum recalculates the IPv4 header checksum in-place.
func recalcIPv4Checksum(pkt []byte, ethHdrLen int) {
	ihl := int(pkt[ethHdrLen]&0x0f) * 4
	// Zero the checksum field.
	pkt[ethHdrLen+10] = 0
	pkt[ethHdrLen+11] = 0
	// Calculate and set.
	pkt[ethHdrLen+10], pkt[ethHdrLen+11] = checksum(pkt[ethHdrLen : ethHdrLen+ihl])
}
