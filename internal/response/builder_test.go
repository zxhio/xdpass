package response

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"xdpass/internal/dataplane/abi"
)

var (
	testSrcMAC = net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	testDstMAC = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	testSrcIP  = net.ParseIP("10.0.0.1").To4()
	testDstIP  = net.ParseIP("192.168.1.1").To4()
)

func TestBuildICMPEchoReply(t *testing.T) {
	// Build a minimal ICMP echo request packet.
	pkt := buildTestICMPEchoRequest(t)

	builder := BuilderForAction(abi.ActionICMPEchoReply)
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
	builder := BuilderForAction(abi.ActionICMPEchoReply)
	_, err := builder([]byte{0x00, 0x01}, nil)
	assert.ErrorIs(t, err, ErrInvalidPacket)
}

func TestBuildICMPEchoReplyNotICMP(t *testing.T) {
	pkt := buildTestICMPEchoRequest(t)
	pkt[23] = 6 // Set protocol to TCP

	builder := BuilderForAction(abi.ActionICMPEchoReply)
	_, err := builder(pkt, nil)
	assert.ErrorIs(t, err, ErrInvalidPacket)
}

func TestBuildUDPEchoReply(t *testing.T) {
	pkt := buildTestUDPPacket(t)

	builder := BuilderForAction(abi.ActionUDPEchoReply)
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

	builder := BuilderForAction(abi.ActionARPReply)
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

	builder := BuilderForAction(abi.ActionARPReply)
	_, err := builder(pkt, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing required param")
}

func TestBuildTCPSynAck(t *testing.T) {
	pkt := buildTestTCPSYN(t)

	builder := BuilderForAction(abi.ActionTCPSynAck)
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

	builder := BuilderForAction(abi.ActionTCPSynAck)
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

	builder := BuilderForAction(abi.ActionTCPSynAck)
	_, err := builder(pkt, nil)
	assert.ErrorIs(t, err, ErrInvalidPacket)
}

func TestBuildDNSRefused(t *testing.T) {
	pkt := buildTestDNSRequest(t)

	builder := BuilderForAction(abi.ActionDNSRefused)
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

	builder := BuilderForAction(abi.ActionDNSSinkhole)
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

	builder := BuilderForAction(abi.ActionDNSSinkhole)
	require.NotNil(t, builder)

	params := map[string]any{
		"family": "ipv4",
	}
	_, err := builder(pkt, params)
	assert.Error(t, err)
}

func TestBuildICMPPortUnreachable(t *testing.T) {
	pkt := buildTestUDPPacket(t)

	builder := BuilderForAction(abi.ActionICMPPortUnreachable)
	require.NotNil(t, builder)

	reply, err := builder(pkt, nil)
	require.NoError(t, err)

	// Verify Ethernet MAC swap.
	assert.Equal(t, pkt[6:12], reply[0:6])
	assert.Equal(t, pkt[0:6], reply[6:12])

	// Verify IPv4 src = original dst, dst = original src.
	assert.Equal(t, pkt[30:34], reply[26:30]) // reply src = orig dst
	assert.Equal(t, pkt[26:30], reply[30:34]) // reply dst = orig src

	// Verify ICMP type=3, code=3.
	icmpOff := 34                              // 14 (eth) + 20 (ipv4)
	assert.Equal(t, byte(3), reply[icmpOff])   // type = destination unreachable
	assert.Equal(t, byte(3), reply[icmpOff+1]) // code = port unreachable

	// Verify ICMP body contains original IPv4 header.
	assert.Equal(t, pkt[14:34], reply[icmpOff+8:icmpOff+28]) // orig IP header (20 bytes)

	// Verify ICMP body contains first 8 bytes of original payload (UDP header).
	assert.Equal(t, pkt[34:42], reply[icmpOff+28:icmpOff+36]) // orig UDP header (8 bytes)

	// Verify IPv4 total length = 20 (IP) + 8 (ICMP hdr) + 20 (orig IP) + 8 (orig payload) = 56.
	ipLen := binary.BigEndian.Uint16(reply[16:18])
	assert.Equal(t, uint16(56), ipLen)
}

func TestBuildICMPHostUnreachable(t *testing.T) {
	pkt := buildTestTCPSYN(t)

	builder := BuilderForAction(abi.ActionICMPHostUnreachable)
	require.NotNil(t, builder)

	reply, err := builder(pkt, nil)
	require.NoError(t, err)

	icmpOff := 34
	assert.Equal(t, byte(3), reply[icmpOff])   // type
	assert.Equal(t, byte(1), reply[icmpOff+1]) // code = host unreachable

	// Verify ICMP body = orig IP header + first 8 bytes of TCP.
	assert.Equal(t, pkt[14:34], reply[icmpOff+8:icmpOff+28])
	assert.Equal(t, pkt[34:42], reply[icmpOff+28:icmpOff+36])
}

func TestBuildICMPAdminProhibited(t *testing.T) {
	pkt := buildTestUDPPacket(t)

	builder := BuilderForAction(abi.ActionICMPAdminProhibited)
	require.NotNil(t, builder)

	reply, err := builder(pkt, nil)
	require.NoError(t, err)

	icmpOff := 34
	assert.Equal(t, byte(3), reply[icmpOff])    // type
	assert.Equal(t, byte(13), reply[icmpOff+1]) // code = admin prohibited
}

func TestBuildICMPUnreachableTooShort(t *testing.T) {
	builder := BuilderForAction(abi.ActionICMPPortUnreachable)
	_, err := builder([]byte{0x00, 0x01}, nil)
	assert.ErrorIs(t, err, ErrInvalidPacket)
}

func TestBuildICMPUnreachableNotIPv4(t *testing.T) {
	pkt := buildTestARPRequest(t) // ARP, not IPv4

	builder := BuilderForAction(abi.ActionICMPPortUnreachable)
	_, err := builder(pkt, nil)
	assert.ErrorIs(t, err, ErrInvalidPacket)
}

func TestBuildICMPUnreachableShortPayload(t *testing.T) {
	// IPv4 packet with less than 8 bytes of payload.
	pkt := make([]byte, 14+20+4) // only 4 bytes of payload
	copy(pkt[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	copy(pkt[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)
	pkt[14] = 0x45
	binary.BigEndian.PutUint16(pkt[16:18], 24)
	pkt[23] = 17 // UDP
	copy(pkt[26:30], net.ParseIP("10.0.0.1").To4())
	copy(pkt[30:34], net.ParseIP("192.168.1.1").To4())

	builder := BuilderForAction(abi.ActionICMPPortUnreachable)
	reply, err := builder(pkt, nil)
	require.NoError(t, err)

	// Body should be 20 (orig IP) + 4 (available payload) = 24 bytes.
	// Total = 14 + 20 + 8 + 24 = 66.
	assert.Equal(t, 66, len(reply))
}

func TestDecodeXSKMeta(t *testing.T) {
	meta := make([]byte, 8)
	binary.LittleEndian.PutUint32(meta[0:4], 1001)
	binary.LittleEndian.PutUint16(meta[4:6], abi.ActionICMPEchoReply)

	m, err := DecodeXSKMeta(meta)
	require.NoError(t, err)
	assert.Equal(t, uint32(1001), m.RuleID)
	assert.Equal(t, abi.ActionICMPEchoReply, m.Action)
}

func TestDecodeXSKMetaTooShort(t *testing.T) {
	_, err := DecodeXSKMeta([]byte{0x01, 0x02})
	assert.Error(t, err)
}

// --- Stage 6: Builder benchmarks ---

func BenchmarkBuildICMPEchoReply(b *testing.B) {
	pkt := buildTestICMPEchoRequestB(b)
	builder := BuilderForAction(abi.ActionICMPEchoReply)
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		builder(pkt, nil)
	}
}

func BenchmarkBuildUDPEchoReply(b *testing.B) {
	pkt := buildTestUDPPacketB(b)
	builder := BuilderForAction(abi.ActionUDPEchoReply)
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		builder(pkt, nil)
	}
}

func BenchmarkBuildARPReply(b *testing.B) {
	pkt := buildTestARPRequestB(b)
	builder := BuilderForAction(abi.ActionARPReply)
	params := map[string]any{
		"hardware_addr": "aa:bb:cc:dd:ee:ff",
		"sender_ipv4":   "10.0.0.1",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		builder(pkt, params)
	}
}

func BenchmarkBuildICMPPortUnreachable(b *testing.B) {
	pkt := buildTestUDPPacketB(b)
	builder := BuilderForAction(abi.ActionICMPPortUnreachable)
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		builder(pkt, nil)
	}
}

func BenchmarkBuildICMPHostUnreachable(b *testing.B) {
	pkt := buildTestTCPSYNB(b)
	builder := BuilderForAction(abi.ActionICMPHostUnreachable)
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		builder(pkt, nil)
	}
}

func BenchmarkBuildICMPAdminProhibited(b *testing.B) {
	pkt := buildTestUDPPacketB(b)
	builder := BuilderForAction(abi.ActionICMPAdminProhibited)
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		builder(pkt, nil)
	}
}

// --- Stage 6: Zero-alloc BuilderIntoFunc benchmarks ---

const benchBufSize = 256

func BenchmarkBuildIntoICMPEchoReply(b *testing.B) {
	pkt := buildTestICMPEchoRequestB(b)
	builder := BuilderIntoForAction(abi.ActionICMPEchoReply)
	out := make([]byte, benchBufSize)
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		builder(pkt, nil, out)
	}
}

func BenchmarkBuildIntoUDPEchoReply(b *testing.B) {
	pkt := buildTestUDPPacketB(b)
	builder := BuilderIntoForAction(abi.ActionUDPEchoReply)
	out := make([]byte, benchBufSize)
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		builder(pkt, nil, out)
	}
}

func BenchmarkBuildIntoARPReply(b *testing.B) {
	pkt := buildTestARPRequestB(b)
	builder := BuilderIntoForAction(abi.ActionARPReply)
	params := map[string]any{
		"hardware_addr": net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		"sender_ipv4":   net.ParseIP("10.0.0.1").To4(),
	}
	out := make([]byte, benchBufSize)
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		builder(pkt, params, out)
	}
}

func BenchmarkBuildIntoICMPPortUnreachable(b *testing.B) {
	pkt := buildTestUDPPacketB(b)
	builder := BuilderIntoForAction(abi.ActionICMPPortUnreachable)
	out := make([]byte, benchBufSize)
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		builder(pkt, nil, out)
	}
}

func BenchmarkBuildIntoICMPHostUnreachable(b *testing.B) {
	pkt := buildTestTCPSYNB(b)
	builder := BuilderIntoForAction(abi.ActionICMPHostUnreachable)
	out := make([]byte, benchBufSize)
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		builder(pkt, nil, out)
	}
}

func BenchmarkBuildIntoICMPAdminProhibited(b *testing.B) {
	pkt := buildTestUDPPacketB(b)
	builder := BuilderIntoForAction(abi.ActionICMPAdminProhibited)
	out := make([]byte, benchBufSize)
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		builder(pkt, nil, out)
	}
}

// --- Benchmark helpers (using testing.B) ---

func buildTestICMPEchoRequestB(b *testing.B) []byte {
	b.Helper()
	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: testSrcIP, DstIP: testDstIP}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0)}
	payload := make([]byte, 32)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, icmp, gopacket.Payload(payload))
	return buf.Bytes()
}

func buildTestUDPPacketB(b *testing.B) []byte {
	b.Helper()
	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: testSrcIP, DstIP: testDstIP}
	udp := &layers.UDP{SrcPort: 12345, DstPort: 53}
	udp.SetNetworkLayerForChecksum(ip)
	payload := make([]byte, 16)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload))
	return buf.Bytes()
}

func buildTestARPRequestB(b *testing.B) []byte {
	b.Helper()
	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1,
		SourceHwAddress:   testSrcMAC,
		SourceProtAddress: net.ParseIP("192.168.1.100").To4(),
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    testDstIP,
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, arp)
	return buf.Bytes()
}

func buildTestTCPSYNB(b *testing.B) []byte {
	b.Helper()
	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: testSrcIP, DstIP: testDstIP}
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 80, SYN: true}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp)
	return buf.Bytes()
}

// --- Test helpers ---

func buildTestICMPEchoRequest(t *testing.T) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: testSrcIP, DstIP: testDstIP}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0)}
	payload := make([]byte, 32)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, icmp, gopacket.Payload(payload))
	return buf.Bytes()
}

func buildTestUDPPacket(t *testing.T) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: testSrcIP, DstIP: testDstIP}
	udp := &layers.UDP{SrcPort: 12345, DstPort: 53}
	udp.SetNetworkLayerForChecksum(ip)
	payload := make([]byte, 16)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload))
	return buf.Bytes()
}

func buildTestARPRequest(t *testing.T) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1, // request
		SourceHwAddress:   testSrcMAC,
		SourceProtAddress: net.ParseIP("192.168.1.100").To4(),
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    testDstIP,
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, arp)
	return buf.Bytes()
}

func buildTestTCPSYN(t *testing.T) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: testSrcIP, DstIP: testDstIP}
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 80, SYN: true}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp)
	return buf.Bytes()
}

func buildTestDNSRequest(t *testing.T) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: testSrcIP, DstIP: testDstIP}
	udp := &layers.UDP{SrcPort: 12345, DstPort: 53}
	udp.SetNetworkLayerForChecksum(ip)
	dnsPayload := []byte{
		0x12, 0x34, // transaction ID
		0x01, 0x00, // flags: standard query, RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		3, 'w', 'w', 'w',
		4, 't', 'e', 's', 't',
		3, 'c', 'o', 'm',
		0,    // end of name
		0, 1, // QTYPE = A
		0, 1, // QCLASS = IN
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(dnsPayload))
	return buf.Bytes()
}
