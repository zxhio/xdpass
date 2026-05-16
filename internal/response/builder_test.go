package response

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildICMPEchoReply(t *testing.T) {
	// Build a minimal ICMP echo request packet.
	pkt := buildTestICMPEchoRequest(t)

	builder := BuilderForAction(ActionICMPEchoReply)
	require.NotNil(t, builder)

	reply, err := builder(pkt, nil)
	require.NoError(t, err)

	// Verify Ethernet MAC swap.
	assert.Equal(t, pkt[6:12], reply[0:6]) // dst = original src
	assert.Equal(t, pkt[0:6], reply[6:12]) // src = original dst

	// Verify IPv4 addr swap (src at 26-29, dst at 30-33).
	assert.Equal(t, pkt[30:34], reply[26:30]) // reply src = original dst
	assert.Equal(t, pkt[26:30], reply[30:34]) // reply dst = original src

	// Verify ICMP type changed to echo reply.
	assert.Equal(t, byte(0), reply[34]) // ICMP type = 0 (echo reply)
}

func TestBuildICMPEchoReplyTooShort(t *testing.T) {
	builder := BuilderForAction(ActionICMPEchoReply)
	_, err := builder([]byte{0x00, 0x01}, nil)
	assert.ErrorIs(t, err, ErrInvalidPacket)
}

func TestBuildICMPEchoReplyNotICMP(t *testing.T) {
	pkt := buildTestICMPEchoRequest(t)
	pkt[23] = 6 // Set protocol to TCP

	builder := BuilderForAction(ActionICMPEchoReply)
	_, err := builder(pkt, nil)
	assert.ErrorIs(t, err, ErrInvalidPacket)
}

func TestBuildUDPEchoReply(t *testing.T) {
	pkt := buildTestUDPPacket(t)

	builder := BuilderForAction(ActionUDPEchoReply)
	require.NotNil(t, builder)

	reply, err := builder(pkt, nil)
	require.NoError(t, err)

	// Verify MAC swap.
	assert.Equal(t, pkt[6:12], reply[0:6])
	assert.Equal(t, pkt[0:6], reply[6:12])

	// Verify IPv4 addr swap (src at 26-29, dst at 30-33).
	assert.Equal(t, pkt[30:34], reply[26:30]) // reply src = original dst
	assert.Equal(t, pkt[26:30], reply[30:34]) // reply dst = original src

	// Verify UDP port swap.
	udpOff := 34                                                    // 14 (eth) + 20 (ipv4)
	assert.Equal(t, pkt[udpOff+2:udpOff+4], reply[udpOff:udpOff+2]) // reply sport = original dport
	assert.Equal(t, pkt[udpOff:udpOff+2], reply[udpOff+2:udpOff+4]) // reply dport = original sport
}

func TestBuildARPReply(t *testing.T) {
	pkt := buildTestARPRequest(t)

	builder := BuilderForAction(ActionARPReply)
	require.NotNil(t, builder)

	replyHW := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	replyIP := net.ParseIP("10.0.0.1").To4()

	params := map[string]any{
		"hardware_addr": replyHW.String(),
		"sender_ipv4":   replyIP.String(),
	}

	reply, err := builder(pkt, params)
	require.NoError(t, err)

	// Verify ARP op is reply.
	assert.Equal(t, byte(0), reply[20]) // op high byte
	assert.Equal(t, byte(2), reply[21]) // op = 2 (reply)

	// Verify sender HW = our reply HW.
	assert.Equal(t, replyHW, net.HardwareAddr(reply[22:28]))

	// Verify sender proto = our reply IP.
	assert.Equal(t, replyIP, net.IP(reply[28:32]))
}

func TestBuildARPReplyMissingParams(t *testing.T) {
	pkt := buildTestARPRequest(t)

	builder := BuilderForAction(ActionARPReply)
	_, err := builder(pkt, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing required param")
}

func TestBuildTCPSynAck(t *testing.T) {
	pkt := buildTestTCPSYN(t)

	builder := BuilderForAction(ActionTCPSynAck)
	require.NotNil(t, builder)

	reply, err := builder(pkt, nil)
	require.NoError(t, err)

	// Verify MAC swap.
	assert.Equal(t, pkt[6:12], reply[0:6])
	assert.Equal(t, pkt[0:6], reply[6:12])

	// Verify IPv4 addr swap.
	assert.Equal(t, pkt[30:34], reply[26:30])
	assert.Equal(t, pkt[26:30], reply[30:34])

	// Verify TCP port swap.
	tcpOff := 34
	assert.Equal(t, pkt[tcpOff+2:tcpOff+4], reply[tcpOff:tcpOff+2])
	assert.Equal(t, pkt[tcpOff:tcpOff+2], reply[tcpOff+2:tcpOff+4])

	// Verify SYN+ACK flags.
	assert.Equal(t, byte(0x12), reply[tcpOff+13])

	// Verify ACK = original SEQ + 1.
	assert.Equal(t, byte(0), reply[tcpOff+8])
	assert.Equal(t, byte(0), reply[tcpOff+9])
	assert.Equal(t, byte(0), reply[tcpOff+10])
	assert.Equal(t, byte(1), reply[tcpOff+11]) // SEQ was 0, ACK=1

	// Verify SEQ = 0 (default).
	assert.Equal(t, byte(0), reply[tcpOff+4])
	assert.Equal(t, byte(0), reply[tcpOff+5])
	assert.Equal(t, byte(0), reply[tcpOff+6])
	assert.Equal(t, byte(0), reply[tcpOff+7])
}

func TestBuildTCPSynAckWithSeqParam(t *testing.T) {
	pkt := buildTestTCPSYN(t)

	builder := BuilderForAction(ActionTCPSynAck)
	require.NotNil(t, builder)

	params := map[string]any{"tcp_seq": float64(12345)}
	reply, err := builder(pkt, params)
	require.NoError(t, err)

	tcpOff := 34
	seq := binary.BigEndian.Uint32(reply[tcpOff+4 : tcpOff+8])
	assert.Equal(t, uint32(12345), seq)
}

func TestBuildTCPSynAckNotSYN(t *testing.T) {
	pkt := buildTestTCPSYN(t)
	pkt[34+13] = 0x10 // ACK only, no SYN

	builder := BuilderForAction(ActionTCPSynAck)
	_, err := builder(pkt, nil)
	assert.ErrorIs(t, err, ErrInvalidPacket)
}

func TestBuildDNSRefused(t *testing.T) {
	pkt := buildTestDNSRequest(t)

	builder := BuilderForAction(ActionDNSRefused)
	require.NotNil(t, builder)

	reply, err := builder(pkt, nil)
	require.NoError(t, err)

	// Verify MAC swap.
	assert.Equal(t, pkt[6:12], reply[0:6])
	assert.Equal(t, pkt[0:6], reply[6:12])

	// Verify IPv4 addr swap.
	assert.Equal(t, pkt[30:34], reply[26:30])
	assert.Equal(t, pkt[26:30], reply[30:34])

	// Verify UDP port swap (response sport=53).
	udpOff := 34
	assert.Equal(t, byte(0), reply[udpOff])
	assert.Equal(t, byte(53), reply[udpOff+1]) // sport = 53

	// Verify DNS flags: QR=1, RD=1, RCODE=5.
	dnsOff := udpOff + 8
	assert.Equal(t, byte(0x81), reply[dnsOff+2]) // QR=1, RD=1
	assert.Equal(t, byte(0x85), reply[dnsOff+3]) // RCODE=5 (refused)

	// Verify ANCOUNT=0.
	assert.Equal(t, byte(0), reply[dnsOff+6])
	assert.Equal(t, byte(0), reply[dnsOff+7])
}

func TestBuildDNSSinkhole(t *testing.T) {
	pkt := buildTestDNSRequest(t)

	builder := BuilderForAction(ActionDNSSinkhole)
	require.NotNil(t, builder)

	params := map[string]any{
		"family":     "ipv4",
		"answers_v4": []any{"10.0.0.1"},
		"ttl":        float64(60),
	}

	reply, err := builder(pkt, params)
	require.NoError(t, err)

	// Verify DNS flags: QR=1, RD=1, RCODE=0.
	dnsOff := 34 + 8
	assert.Equal(t, byte(0x81), reply[dnsOff+2])
	assert.Equal(t, byte(0x80), reply[dnsOff+3]) // RCODE=0

	// Verify ANCOUNT=1.
	assert.Equal(t, byte(0), reply[dnsOff+6])
	assert.Equal(t, byte(1), reply[dnsOff+7])

	// Verify answer contains 10.0.0.1.
	// After question end: name pointer (2) + type (2) + class (2) + ttl (4) + rdlen (2) + rdata (4)
	questionEnd := dnsFindQuestionEnd(pkt, 34+8)
	answerOffset := questionEnd
	assert.Equal(t, byte(0xc0), reply[answerOffset])   // name pointer
	assert.Equal(t, byte(0x0c), reply[answerOffset+1]) // offset 12
	assert.Equal(t, byte(0), reply[answerOffset+2])    // type A
	assert.Equal(t, byte(1), reply[answerOffset+3])
	assert.Equal(t, net.ParseIP("10.0.0.1").To4(), net.IP(reply[answerOffset+12:answerOffset+16]))
}

func TestBuildDNSSinkholeNoAnswers(t *testing.T) {
	pkt := buildTestDNSRequest(t)

	builder := BuilderForAction(ActionDNSSinkhole)
	require.NotNil(t, builder)

	params := map[string]any{
		"family": "ipv4",
	}
	_, err := builder(pkt, params)
	assert.Error(t, err)
}

func TestDecodeXSKMeta(t *testing.T) {
	meta := make([]byte, 8)
	binary.LittleEndian.PutUint32(meta[0:4], 1001)
	binary.LittleEndian.PutUint16(meta[4:6], 3) // ICMP_ECHO_REPLY

	m, err := DecodeXSKMeta(meta)
	require.NoError(t, err)
	assert.Equal(t, uint32(1001), m.RuleID)
	assert.Equal(t, uint16(3), m.Action)
}

func TestDecodeXSKMetaTooShort(t *testing.T) {
	_, err := DecodeXSKMeta([]byte{0x01, 0x02})
	assert.Error(t, err)
}

// --- Test helpers ---

func buildTestICMPEchoRequest(t *testing.T) []byte {
	t.Helper()
	// Ethernet (14) + IPv4 (20) + ICMP (8 + payload)
	pkt := make([]byte, 14+20+8+32)

	// Ethernet: dst MAC, src MAC, ethertype
	copy(pkt[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	copy(pkt[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800) // IPv4

	// IPv4 header (starts at offset 14):
	// byte 14: version+ihl, byte 23: protocol
	// bytes 26-29: src IP, bytes 30-33: dst IP
	pkt[14] = 0x45                                     // version=4, ihl=5
	binary.BigEndian.PutUint16(pkt[16:18], 60)         // total length
	copy(pkt[26:30], net.ParseIP("10.0.0.1").To4())    // src IP
	copy(pkt[30:34], net.ParseIP("192.168.1.1").To4()) // dst IP
	pkt[23] = 1                                        // protocol = ICMP

	// ICMP: type=8 (echo request), code=0
	pkt[34] = 8 // echo request
	pkt[35] = 0

	return pkt
}

func buildTestUDPPacket(t *testing.T) []byte {
	t.Helper()
	pkt := make([]byte, 14+20+8+16) // eth+ipv4+udp+payload

	copy(pkt[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	copy(pkt[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)

	pkt[14] = 0x45
	binary.BigEndian.PutUint16(pkt[16:18], 48) // total length
	copy(pkt[26:30], net.ParseIP("10.0.0.1").To4())
	copy(pkt[30:34], net.ParseIP("192.168.1.1").To4())
	pkt[23] = 17 // protocol = UDP

	// UDP: src port, dst port, length
	udpOff := 34
	binary.BigEndian.PutUint16(pkt[udpOff:udpOff+2], 12345) // sport
	binary.BigEndian.PutUint16(pkt[udpOff+2:udpOff+4], 53)  // dport
	binary.BigEndian.PutUint16(pkt[udpOff+4:udpOff+6], 24)  // udp length

	return pkt
}

func buildTestARPRequest(t *testing.T) []byte {
	t.Helper()
	pkt := make([]byte, 14+28) // eth + arp

	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // broadcast
	copy(pkt[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0806) // ARP

	// ARP header
	binary.BigEndian.PutUint16(pkt[14:16], 1)      // hardware type = ethernet
	binary.BigEndian.PutUint16(pkt[16:18], 0x0800) // proto type = IPv4
	pkt[18] = 6                                    // hw len
	pkt[19] = 4                                    // proto len
	binary.BigEndian.PutUint16(pkt[20:22], 1)      // op = request

	// sender HW (bytes 22-27)
	copy(pkt[22:28], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	// sender proto (bytes 28-31)
	copy(pkt[28:32], net.ParseIP("192.168.1.100").To4())
	// target HW (bytes 32-37, zeros in request)
	copy(pkt[32:38], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// target proto (bytes 38-41)
	copy(pkt[38:42], net.ParseIP("10.0.0.1").To4())

	return pkt
}

func buildTestTCPSYN(t *testing.T) []byte {
	t.Helper()
	pkt := make([]byte, 14+20+20) // eth+ipv4+tcp

	copy(pkt[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	copy(pkt[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)

	pkt[14] = 0x45
	binary.BigEndian.PutUint16(pkt[16:18], 40) // total length
	copy(pkt[26:30], net.ParseIP("10.0.0.1").To4())
	copy(pkt[30:34], net.ParseIP("192.168.1.1").To4())
	pkt[23] = 6 // protocol = TCP

	// TCP header (offset 34).
	tcpOff := 34
	binary.BigEndian.PutUint16(pkt[tcpOff:tcpOff+2], 12345) // sport
	binary.BigEndian.PutUint16(pkt[tcpOff+2:tcpOff+4], 80)  // dport
	binary.BigEndian.PutUint32(pkt[tcpOff+4:tcpOff+8], 0)   // seq = 0
	binary.BigEndian.PutUint32(pkt[tcpOff+8:tcpOff+12], 0)  // ack = 0
	pkt[tcpOff+12] = 0x50                                   // data offset = 5 (20 bytes)
	pkt[tcpOff+13] = 0x02                                   // flags = SYN

	return pkt
}

func buildTestDNSRequest(t *testing.T) []byte {
	t.Helper()
	// Ethernet (14) + IPv4 (20) + UDP (8) + DNS header (12) + question
	// Question: \x03www\x04test\x03com\x00 + QTYPE(2) + QCLASS(2)
	question := []byte{
		3, 'w', 'w', 'w',
		4, 't', 'e', 's', 't',
		3, 'c', 'o', 'm',
		0,    // end of name
		0, 1, // QTYPE = A
		0, 1, // QCLASS = IN
	}
	dnsLen := 12 + len(question)
	pkt := make([]byte, 14+20+8+dnsLen)

	copy(pkt[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	copy(pkt[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)

	pkt[14] = 0x45
	binary.BigEndian.PutUint16(pkt[16:18], uint16(20+8+dnsLen))
	copy(pkt[26:30], net.ParseIP("10.0.0.1").To4())
	copy(pkt[30:34], net.ParseIP("192.168.1.1").To4())
	pkt[23] = 17 // protocol = UDP

	udpOff := 34
	binary.BigEndian.PutUint16(pkt[udpOff:udpOff+2], 12345)              // sport
	binary.BigEndian.PutUint16(pkt[udpOff+2:udpOff+4], 53)               // dport
	binary.BigEndian.PutUint16(pkt[udpOff+4:udpOff+6], uint16(8+dnsLen)) // udp length

	// DNS header.
	dnsOff := udpOff + 8
	binary.BigEndian.PutUint16(pkt[dnsOff:dnsOff+2], 0x1234)   // transaction ID
	binary.BigEndian.PutUint16(pkt[dnsOff+2:dnsOff+4], 0x0100) // flags: standard query, RD=1
	binary.BigEndian.PutUint16(pkt[dnsOff+4:dnsOff+6], 1)      // QDCOUNT=1
	// ANCOUNT, NSCOUNT, ARCOUNT are 0.

	copy(pkt[dnsOff+12:], question)

	return pkt
}
