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
	case ActionTCPSynAck:
		return buildTCPSynAck
	case ActionDNSRefused:
		return buildDNSRefused
	case ActionDNSSinkhole:
		return buildDNSSinkhole
	case ActionICMPPortUnreachable:
		return buildICMPUnreachable(3)
	case ActionICMPHostUnreachable:
		return buildICMPUnreachable(1)
	case ActionICMPAdminProhibited:
		return buildICMPUnreachable(13)
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

// buildICMPUnreachable returns a BuilderFunc that constructs an ICMP destination
// unreachable response with the given code. The ICMP body contains the original
// IPv4 header and the first 8 bytes of the original payload.
func buildICMPUnreachable(code byte) BuilderFunc {
	return func(origPkt []byte, _ map[string]any) ([]byte, error) {
		if len(origPkt) < 14+20 {
			return nil, fmt.Errorf("%w: icmp unreachable requires at least ethernet+ipv4 header", ErrInvalidPacket)
		}

		ethType := binary.BigEndian.Uint16(origPkt[12:14])
		ethHdrLen := 14

		if ethType == 0x8100 || ethType == 0x88a8 {
			if len(origPkt) < 18+20 {
				return nil, fmt.Errorf("%w: too short for vlan+ipv4", ErrInvalidPacket)
			}
			ethType = binary.BigEndian.Uint16(origPkt[16:18])
			ethHdrLen = 18
		}

		if ethType != 0x0800 {
			return nil, fmt.Errorf("%w: not IPv4 (ethertype=0x%04x)", ErrInvalidPacket, ethType)
		}

		ihl := int(origPkt[ethHdrLen]&0x0f) * 4
		if ihl < 20 {
			return nil, fmt.Errorf("%w: IPv4 IHL too small (%d bytes)", ErrInvalidPacket, ihl)
		}
		if len(origPkt) < ethHdrLen+ihl {
			return nil, fmt.Errorf("%w: packet too short for IPv4 header", ErrInvalidPacket)
		}

		payloadLen := len(origPkt) - ethHdrLen - ihl
		bodyCopyLen := ihl
		if payloadLen < 8 {
			bodyCopyLen += payloadLen
		} else {
			bodyCopyLen += 8
		}

		respLen := ethHdrLen + 20 + 8 + bodyCopyLen
		pkt := make([]byte, respLen)

		// Ethernet header: swap MAC addresses.
		copy(pkt[0:6], origPkt[6:12])
		copy(pkt[6:12], origPkt[0:6])
		binary.BigEndian.PutUint16(pkt[12:14], 0x0800)

		// IPv4 header.
		pkt[ethHdrLen] = 0x45 // version=4, ihl=5
		binary.BigEndian.PutUint16(pkt[ethHdrLen+2:ethHdrLen+4], uint16(respLen-ethHdrLen))
		pkt[ethHdrLen+8] = 64                                                    // TTL
		pkt[ethHdrLen+9] = 1                                                     // protocol = ICMP
		copy(pkt[ethHdrLen+12:ethHdrLen+16], origPkt[ethHdrLen+16:ethHdrLen+20]) // src = orig dst
		copy(pkt[ethHdrLen+16:ethHdrLen+20], origPkt[ethHdrLen+12:ethHdrLen+16]) // dst = orig src

		// ICMP header: type=3 (destination unreachable), code, checksum.
		icmpOff := ethHdrLen + 20
		pkt[icmpOff] = 3
		pkt[icmpOff+1] = code
		// unused (4 bytes) = 0

		// ICMP body: original IPv4 header + first 8 bytes of payload.
		copy(pkt[icmpOff+8:], origPkt[ethHdrLen:ethHdrLen+bodyCopyLen])

		// ICMP checksum over entire ICMP message.
		pkt[icmpOff+2] = 0
		pkt[icmpOff+3] = 0
		icmpLen := 8 + bodyCopyLen
		pkt[icmpOff+2], pkt[icmpOff+3] = checksum(pkt[icmpOff : icmpOff+icmpLen])

		// IPv4 checksum.
		recalcIPv4Checksum(pkt, ethHdrLen)

		return pkt, nil
	}
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
	copy(pkt[0:6], senderHW) // dst = original sender
	copy(pkt[6:12], replyHW) // src = reply sender

	// Set ARP op to reply.
	binary.BigEndian.PutUint16(pkt[arpOffset+6:arpOffset+8], 2)

	// ARP reply: sender = our params, target = original sender.
	copy(pkt[arpOffset+8:arpOffset+14], replyHW)
	copy(pkt[arpOffset+14:arpOffset+18], replyProto)
	copy(pkt[arpOffset+18:arpOffset+24], senderHW)
	copy(pkt[arpOffset+24:arpOffset+28], senderProto)

	return pkt, nil
}

// buildTCPSynAck constructs a TCP SYN-ACK from a TCP SYN.
// Swaps Ethernet MAC, IPv4 src/dst, TCP src/dst ports.
// Sets SYN+ACK flags, ACK = original SEQ + 1, SEQ = tcp_seq param or default.
func buildTCPSynAck(origPkt []byte, params map[string]any) ([]byte, error) {
	if len(origPkt) < 14+20+20 {
		return nil, fmt.Errorf("%w: tcp syn-ack requires at least ethernet+ipv4+tcp header", ErrInvalidPacket)
	}

	ethType := binary.BigEndian.Uint16(origPkt[12:14])
	ethHdrLen := 14

	if ethType == 0x8100 || ethType == 0x88a8 {
		if len(origPkt) < 18+20+20 {
			return nil, fmt.Errorf("%w: too short for vlan+ipv4+tcp", ErrInvalidPacket)
		}
		ethType = binary.BigEndian.Uint16(origPkt[16:18])
		ethHdrLen = 18
	}

	if ethType != 0x0800 {
		return nil, fmt.Errorf("%w: not IPv4 (ethertype=0x%04x)", ErrInvalidPacket, ethType)
	}

	ihl := int(origPkt[ethHdrLen]&0x0f) * 4
	if len(origPkt) < ethHdrLen+ihl+20 {
		return nil, fmt.Errorf("%w: too short for ipv4+tcp", ErrInvalidPacket)
	}
	if origPkt[ethHdrLen+9] != 6 { // protocol must be TCP
		return nil, fmt.Errorf("%w: not TCP (proto=%d)", ErrInvalidPacket, origPkt[ethHdrLen+9])
	}

	tcpOffset := ethHdrLen + ihl
	tcpDataOffset := int(origPkt[tcpOffset+12]>>4) * 4
	if len(origPkt) < tcpOffset+tcpDataOffset {
		return nil, fmt.Errorf("%w: tcp header too short", ErrInvalidPacket)
	}

	// Check SYN flag (bit 1 of byte 13).
	flags := origPkt[tcpOffset+13]
	if flags&0x02 == 0 {
		return nil, fmt.Errorf("%w: not SYN (flags=0x%02x)", ErrInvalidPacket, flags)
	}

	pkt := make([]byte, len(origPkt))
	copy(pkt, origPkt)

	// Swap Ethernet MAC.
	copy(pkt[0:6], origPkt[6:12])
	copy(pkt[6:12], origPkt[0:6])

	// Swap IPv4 src/dst.
	copy(pkt[ethHdrLen+12:ethHdrLen+16], origPkt[ethHdrLen+16:ethHdrLen+20])
	copy(pkt[ethHdrLen+16:ethHdrLen+20], origPkt[ethHdrLen+12:ethHdrLen+16])

	// Swap TCP src/dst ports.
	copy(pkt[tcpOffset:tcpOffset+2], origPkt[tcpOffset+2:tcpOffset+4])
	copy(pkt[tcpOffset+2:tcpOffset+4], origPkt[tcpOffset:tcpOffset+2])

	// Set SYN+ACK flags.
	pkt[tcpOffset+13] = 0x12

	// ACK = original SEQ + 1.
	origSeq := binary.BigEndian.Uint32(origPkt[tcpOffset+4 : tcpOffset+8])
	binary.BigEndian.PutUint32(pkt[tcpOffset+8:tcpOffset+12], origSeq+1)

	// SEQ = tcp_seq param or default (0).
	seq := uint32(0)
	if v, ok := params["tcp_seq"]; ok {
		if n, ok := toUint32(v); ok {
			seq = n
		}
	}
	binary.BigEndian.PutUint32(pkt[tcpOffset+4:tcpOffset+8], seq)

	// Zero TCP checksum before recalculating.
	pkt[tcpOffset+16] = 0
	pkt[tcpOffset+17] = 0

	// Recalculate TCP checksum (over pseudo-header + TCP segment).
	tcpLen := len(pkt) - tcpOffset
	pkt[tcpOffset+16], pkt[tcpOffset+17] = tcpChecksum(pkt, ethHdrLen, tcpLen)

	// Recalculate IPv4 checksum.
	recalcIPv4Checksum(pkt, ethHdrLen)

	return pkt, nil
}

// buildDNSRefused constructs a DNS response with rcode=refused from a DNS request.
// Preserves transaction ID and question, returns no answer records.
func buildDNSRefused(origPkt []byte, _ map[string]any) ([]byte, error) {
	resp, err := buildDNSResponse(origPkt)
	if err != nil {
		return nil, err
	}

	// Set response flag (QR=1) and rcode=refused (5).
	// DNS flags: byte 2 of DNS header (after UDP header).
	ethHdrLen := dnsEthHdrLen(origPkt)
	ihl := int(origPkt[ethHdrLen]&0x0f) * 4
	dnsOffset := ethHdrLen + ihl + 8 // eth + ip + udp

	// Flags: QR=1, Opcode=0, AA=0, TC=0, RD=copy, RA=0, Z=0, RCODE=5
	resp[dnsOffset+2] = 0x81 // QR=1, RD=1 (copy from request)
	resp[dnsOffset+3] = 0x85 // RA=0, Z=0, RCODE=5 (refused)

	// Zero answer, authority, additional counts.
	binary.BigEndian.PutUint16(resp[dnsOffset+6:dnsOffset+8], 0)   // ANCOUNT
	binary.BigEndian.PutUint16(resp[dnsOffset+8:dnsOffset+10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(resp[dnsOffset+10:dnsOffset+12], 0) // ARCOUNT

	// Truncate to DNS header + question (no answers).
	questionEnd := dnsFindQuestionEnd(origPkt, dnsOffset)
	resp = resp[:questionEnd]

	// Update UDP length.
	udpLen := questionEnd - ethHdrLen - ihl
	binary.BigEndian.PutUint16(resp[ethHdrLen+ihl+4:ethHdrLen+ihl+6], uint16(udpLen))

	// Update IPv4 total length.
	totalLen := questionEnd - ethHdrLen
	binary.BigEndian.PutUint16(resp[ethHdrLen+2:ethHdrLen+4], uint16(totalLen))

	// Recalculate UDP checksum.
	udpOffset := ethHdrLen + ihl
	resp[udpOffset+6] = 0
	resp[udpOffset+7] = 0
	resp[udpOffset+6], resp[udpOffset+7] = udpChecksum(resp, ethHdrLen, udpLen)

	// Recalculate IPv4 checksum.
	recalcIPv4Checksum(resp, ethHdrLen)

	return resp, nil
}

// buildDNSSinkhole constructs a DNS response with answer records from params.
func buildDNSSinkhole(origPkt []byte, params map[string]any) ([]byte, error) {
	resp, err := buildDNSResponse(origPkt)
	if err != nil {
		return nil, err
	}

	ethHdrLen := dnsEthHdrLen(origPkt)
	ihl := int(origPkt[ethHdrLen]&0x0f) * 4
	dnsOffset := ethHdrLen + ihl + 8

	// Set response flag (QR=1), rcode=0 (no error).
	resp[dnsOffset+2] = 0x81 // QR=1, RD=1
	resp[dnsOffset+3] = 0x80 // RA=0, RCODE=0

	// Parse params.
	family := "ipv4"
	if v, ok := params["family"]; ok {
		if s, ok := v.(string); ok {
			family = s
		}
	}

	ttl := uint32(300)
	if v, ok := params["ttl"]; ok {
		if n, ok := toUint32(v); ok && n > 0 {
			ttl = n
		}
	}

	var answers []dnsAnswer

	if family == "ipv4" || family == "dual_stack" {
		v4s, err := getStringArrayParam(params, "answers_v4")
		if err != nil {
			return nil, err
		}
		for _, s := range v4s {
			ip := net.ParseIP(s).To4()
			if ip == nil {
				return nil, fmt.Errorf("%w: invalid IPv4 address %q", ErrInvalidPacket, s)
			}
			answers = append(answers, dnsAnswer{typ: 1, class: 1, ttl: ttl, data: ip})
		}
	}

	if family == "ipv6" || family == "dual_stack" {
		v6s, err := getStringArrayParam(params, "answers_v6")
		if err != nil {
			return nil, err
		}
		for _, s := range v6s {
			ip := net.ParseIP(s).To16()
			if ip == nil {
				return nil, fmt.Errorf("%w: invalid IPv6 address %q", ErrInvalidPacket, s)
			}
			answers = append(answers, dnsAnswer{typ: 28, class: 1, ttl: ttl, data: ip})
		}
	}

	if len(answers) == 0 {
		return nil, fmt.Errorf("%w: no answers provided for family=%s", ErrInvalidPacket, family)
	}

	// Set ANCOUNT.
	binary.BigEndian.PutUint16(resp[dnsOffset+6:dnsOffset+8], uint16(len(answers)))
	// Zero NSCOUNT and ARCOUNT.
	binary.BigEndian.PutUint16(resp[dnsOffset+8:dnsOffset+10], 0)
	binary.BigEndian.PutUint16(resp[dnsOffset+10:dnsOffset+12], 0)

	// Truncate to question end, then append answer records.
	questionEnd := dnsFindQuestionEnd(origPkt, dnsOffset)
	resp = resp[:questionEnd]

	for _, ans := range answers {
		// Name pointer to offset 0xc00c (start of question name).
		resp = append(resp, 0xc0, 0x0c)
		// Type.
		resp = append(resp, byte(ans.typ>>8), byte(ans.typ))
		// Class.
		resp = append(resp, byte(ans.class>>8), byte(ans.class))
		// TTL.
		resp = append(resp, byte(ans.ttl>>24), byte(ans.ttl>>16), byte(ans.ttl>>8), byte(ans.ttl))
		// RDLENGTH.
		rdlen := uint16(len(ans.data))
		resp = append(resp, byte(rdlen>>8), byte(rdlen))
		// RDATA.
		resp = append(resp, ans.data...)
	}

	// Update UDP length.
	udpLen := len(resp) - ethHdrLen - ihl
	binary.BigEndian.PutUint16(resp[ethHdrLen+ihl+4:ethHdrLen+ihl+6], uint16(udpLen))

	// Update IPv4 total length.
	totalLen := len(resp) - ethHdrLen
	binary.BigEndian.PutUint16(resp[ethHdrLen+2:ethHdrLen+4], uint16(totalLen))

	// Recalculate UDP checksum.
	udpOffset := ethHdrLen + ihl
	resp[udpOffset+6] = 0
	resp[udpOffset+7] = 0
	resp[udpOffset+6], resp[udpOffset+7] = udpChecksum(resp, ethHdrLen, udpLen)

	// Recalculate IPv4 checksum.
	recalcIPv4Checksum(resp, ethHdrLen)

	return resp, nil
}

type dnsAnswer struct {
	typ   uint16 // 1=A, 28=AAAA
	class uint16 // 1=IN
	ttl   uint32
	data  []byte // 4 bytes for IPv4, 16 for IPv6
}

// buildDNSResponse constructs the base DNS response packet (swap MAC/IP/UDP, copy DNS payload).
func buildDNSResponse(origPkt []byte) ([]byte, error) {
	if len(origPkt) < 14+20+8+12 {
		return nil, fmt.Errorf("%w: dns requires at least ethernet+ipv4+udp+dns header", ErrInvalidPacket)
	}

	ethType := binary.BigEndian.Uint16(origPkt[12:14])
	ethHdrLen := 14

	if ethType == 0x8100 || ethType == 0x88a8 {
		if len(origPkt) < 18+20+8+12 {
			return nil, fmt.Errorf("%w: too short for vlan+ipv4+udp+dns", ErrInvalidPacket)
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
	// Verify dst port is 53.
	dstPort := binary.BigEndian.Uint16(origPkt[udpOffset+2 : udpOffset+4])
	if dstPort != 53 {
		return nil, fmt.Errorf("%w: not DNS (dst port=%d)", ErrInvalidPacket, dstPort)
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

	return pkt, nil
}

// dnsEthHdrLen returns the Ethernet header length (accounting for VLAN tag).
func dnsEthHdrLen(origPkt []byte) int {
	ethType := binary.BigEndian.Uint16(origPkt[12:14])
	if ethType == 0x8100 || ethType == 0x88a8 {
		return 18
	}
	return 14
}

// dnsFindQuestionEnd finds the end of the DNS question section.
// DNS name labels are length-prefixed, terminated by 0x00.
// Question also has QTYPE(2) + QCLASS(2) after the name.
func dnsFindQuestionEnd(pkt []byte, dnsOffset int) int {
	i := dnsOffset + 12 // skip DNS header (ID + flags + counts)
	for i < len(pkt) {
		labelLen := int(pkt[i])
		if labelLen == 0 {
			i++ // skip the terminating 0
			break
		}
		if labelLen&0xc0 == 0xc0 {
			// Pointer, skip 2 bytes.
			i += 2
			break
		}
		i += 1 + labelLen
	}
	// QTYPE(2) + QCLASS(2)
	return i + 4
}

// tcpChecksum calculates the TCP checksum over pseudo-header + TCP segment.
func tcpChecksum(pkt []byte, ethHdrLen, tcpLen int) (byte, byte) {
	ihl := int(pkt[ethHdrLen]&0x0f) * 4
	tcpOffset := ethHdrLen + ihl

	// Build pseudo-header on stack: src_ip(4) + dst_ip(4) + zero(1) + proto(1) + tcp_len(2)
	var pseudo [12]byte
	copy(pseudo[0:4], pkt[ethHdrLen+12:ethHdrLen+16])
	copy(pseudo[4:8], pkt[ethHdrLen+16:ethHdrLen+20])
	pseudo[8] = 0
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))

	return checksum(pseudo[:], pkt[tcpOffset:tcpOffset+tcpLen])
}

// udpChecksum calculates the UDP checksum over pseudo-header + UDP segment.
func udpChecksum(pkt []byte, ethHdrLen, udpLen int) (byte, byte) {
	ihl := int(pkt[ethHdrLen]&0x0f) * 4
	udpOffset := ethHdrLen + ihl

	var pseudo [12]byte
	copy(pseudo[0:4], pkt[ethHdrLen+12:ethHdrLen+16])
	copy(pseudo[4:8], pkt[ethHdrLen+16:ethHdrLen+20])
	pseudo[8] = 0
	pseudo[9] = 17 // UDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(udpLen))

	return checksum(pseudo[:], pkt[udpOffset:udpOffset+udpLen])
}

// getStringArrayParam extracts a string array from params.
func getStringArrayParam(params map[string]any, key string) ([]string, error) {
	v, ok := params[key]
	if !ok {
		return nil, fmt.Errorf("missing required param: %s", key)
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("param %s must be an array", key)
	}
	result := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("param %s items must be strings", key)
		}
		result = append(result, s)
	}
	return result, nil
}

// toUint32 converts an any value to uint32.
func toUint32(v any) (uint32, bool) {
	switch n := v.(type) {
	case float64:
		return uint32(n), true
	case int:
		return uint32(n), true
	case int64:
		return uint32(n), true
	case uint32:
		return n, true
	default:
		return 0, false
	}
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

// checksum calculates the internet checksum over one or more byte slices.
func checksum(parts ...[]byte) (byte, byte) {
	var sum uint32
	var pending byte
	var hasPending bool

	for _, data := range parts {
		i := 0
		if hasPending {
			// Combine leftover byte from previous part with first byte of this part.
			sum += uint32(pending)<<8 | uint32(data[0])
			i = 1
			hasPending = false
		}
		for i+2 <= len(data) {
			sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
			i += 2
		}
		if i < len(data) {
			pending = data[i]
			hasPending = true
		}
	}
	if hasPending {
		sum += uint32(pending) << 8
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
