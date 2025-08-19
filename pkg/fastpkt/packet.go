package fastpkt

import (
	"errors"
	"unsafe"

	"github.com/zxhio/xdpass/pkg/netaddr"
	"github.com/zxhio/xdpass/pkg/netutil"
	"golang.org/x/sys/unix"
)

const (
	SizeofEthernet = int(unsafe.Sizeof(Ethernet{})) // sizeof(struct ethhdr)
	SizeofVLAN     = int(unsafe.Sizeof(VLAN{}))     // sizeof(struct vlan_hdr)
	SizeofIPv4     = int(unsafe.Sizeof(IPv4{}))     // sizeof(struct iphdr)
	SizeofIPv6     = int(unsafe.Sizeof(IPv6{}))     // sizeof(struct ipv6hdr)
	SizeofTCP      = int(unsafe.Sizeof(TCP{}))      // sizeof(struct tcphdr)
	SizeofUDP      = int(unsafe.Sizeof(UDP{}))      // sizeof(struct udphdr)
	SizeofICMP     = int(unsafe.Sizeof(ICMP{}))     // sizeof(struct icmphdr)
	SizeofARP      = int(unsafe.Sizeof(ARP{}))      // sizeof(struct arphdr)
)

var (
	ErrPacketTooShort            = errors.New("packet too short")
	ErrPacketInvalidEthernetType = errors.New("invalid ethernet type")
	ErrPacketInvalidProtocol     = errors.New("invalid protocol")
)

const (
	L7ProtoNone uint8 = iota
	L7ProtoData       // Normal app data
	L7ProtoHTTPReq
	L7ProtoHTTPResp
)

type Packet struct {
	L3Proto uint16
	L4Proto uint16
	L7Proto uint8

	L2Len uint8
	L3Len uint8
	L4Len uint8

	// L3
	SrcIP netaddr.IPv4Addr
	DstIP netaddr.IPv4Addr

	// L4
	SrcPort uint16
	DstPort uint16

	// L7
	LazyHTTP *LazyHTTP

	RxData []byte // Raw data received from the network (read only)
	TxData []byte // Raw data to be sent to the network
}

var emptyPacket = Packet{}

func (pkt *Packet) Clear() {
	*pkt = emptyPacket
}

func (pkt *Packet) DecodeFromData(data []byte) error {
	if len(data) < 14 {
		return ErrPacketTooShort
	}

	pkt.RxData = data
	pkt.L2Len = uint8(SizeofEthernet)

	eth := (*Ethernet)(unsafe.Pointer(&data[0]))
	off := SizeofEthernet

	switch netutil.Ntohs(eth.HwProto) {
	case unix.ETH_P_8021Q:
		return pkt.DecodePacketVLAN(data[off:])
	case unix.ETH_P_ARP:
		return pkt.DecodePacketARP(data[off:])
	case unix.ETH_P_IP:
		return pkt.DecodePacketIPv4(data[off:])
	case unix.ETH_P_IPV6:
		return pkt.DecodePacketIPv6(data[off:])
	default:
		return ErrPacketInvalidEthernetType
	}
}

func (pkt *Packet) DecodePacketVLAN(data []byte) error {
	if len(data) < SizeofVLAN {
		return ErrPacketTooShort
	}

	pkt.L2Len += uint8(SizeofVLAN)

	vlan := (*VLAN)(unsafe.Pointer(&data[0]))
	off := SizeofVLAN

	switch netutil.Ntohs(vlan.EncapsulatedProto) {
	case unix.ETH_P_ARP:
		return pkt.DecodePacketARP(data[off:])
	case unix.ETH_P_IP:
		return pkt.DecodePacketIPv4(data[off:])
	case unix.ETH_P_IPV6:
		return pkt.DecodePacketIPv6(data[off:])
	default:
		return ErrPacketInvalidEthernetType
	}
}

func (pkt *Packet) DecodePacketARP(data []byte) error {
	if len(data) < SizeofARP {
		return ErrPacketTooShort
	}

	arp := (*ARP)(unsafe.Pointer(&data[0]))
	if len(data) < SizeofARP+int(arp.HwAddrLen)*2+int(arp.ProtAddrLen)*2 {
		return ErrPacketTooShort
	}

	data = data[SizeofARP:]
	pkt.L3Proto = unix.ETH_P_ARP
	pkt.L3Len = arp.HwAddrLen*2 + arp.ProtAddrLen*2

	// IPv4
	if arp.ProtAddrLen == 4 {
		pkt.SrcIP = netaddr.NewIPv4AddrFromIP(data[arp.HwAddrLen : arp.HwAddrLen+arp.ProtAddrLen])
		pkt.DstIP = netaddr.NewIPv4AddrFromIP(data[arp.HwAddrLen*2+arp.ProtAddrLen : arp.HwAddrLen*2+arp.ProtAddrLen*2])
	}

	return nil
}

func (pkt *Packet) DecodePacketIPv4(data []byte) error {
	if len(data) < SizeofIPv4 {
		return ErrPacketTooShort
	}

	ip := (*IPv4)(unsafe.Pointer(&data[0]))
	off := ip.HeaderLen()
	pkt.L3Proto = unix.ETH_P_IP
	pkt.SrcIP = netaddr.IPv4Addr(netutil.Ntohl(ip.SrcIP))
	pkt.DstIP = netaddr.IPv4Addr(netutil.Ntohl(ip.DstIP))
	pkt.L3Len = uint8(off)

	switch ip.Protocol {
	case unix.IPPROTO_TCP:
		return pkt.DecodePacketTCP(data[off:])
	case unix.IPPROTO_UDP:
		return pkt.DecodePacketUDP(data[off:])
	case unix.IPPROTO_ICMP:
		return pkt.DecodePacketICMP(data[off:])
	default:
		return ErrPacketInvalidProtocol
	}
}

// TODO: implement
func (pkt *Packet) DecodePacketIPv6([]byte) error {
	return errors.New("not implement")
}

func (pkt *Packet) DecodePacketTCP(data []byte) error {
	if len(data) < SizeofTCP {
		return ErrPacketTooShort
	}

	tcp := (*TCP)(unsafe.Pointer(&data[0]))
	pkt.L4Proto = unix.IPPROTO_TCP
	pkt.SrcPort = netutil.Ntohs(tcp.SrcPort)
	pkt.DstPort = netutil.Ntohs(tcp.DstPort)
	pkt.L4Len = uint8(tcp.HeaderLen())

	if int(pkt.L4Len) < len(data) {
		pkt.DecodePacketL7(data[pkt.L4Len:])
	}
	return nil
}

func (pkt *Packet) DecodePacketL7(data []byte) {
	pkt.L7Proto = L7ProtoData
	if len(data) < 4 {
		return
	}

	// GET / HTTP/1.1
	// HTTP/1.1 200 OK
	headU32 := *(*uint32)(unsafe.Pointer(&data[0]))
	switch headU32 {
	case methodMagicGet,
		methodMagicPost,
		methodMagicPut,
		methodMagicDelete,
		methodMagicHead,
		methodMagicOptions,
		methodMagicPatch,
		methodMagicConnect,
		methodMagicTrace:
		pkt.L7Proto = L7ProtoHTTPReq
	case methodMagicHTTP:
		pkt.L7Proto = L7ProtoHTTPResp
	}
}

func (pkt *Packet) DecodePacketUDP(data []byte) error {
	if len(data) < SizeofUDP {
		return ErrPacketTooShort
	}

	udp := (*UDP)(unsafe.Pointer(&data[0]))
	pkt.L4Proto = unix.IPPROTO_UDP
	pkt.SrcPort = netutil.Ntohs(udp.SrcPort)
	pkt.DstPort = netutil.Ntohs(udp.DstPort)
	pkt.L4Len = uint8(SizeofUDP)
	return nil
}

func (pkt *Packet) DecodePacketICMP(data []byte) error {
	if len(data) < SizeofICMP {
		return ErrPacketTooShort
	}

	pkt.L4Proto = unix.IPPROTO_ICMP
	pkt.SrcPort = 0
	pkt.DstPort = 0
	pkt.L4Len = uint8(SizeofICMP)
	return nil
}

func NewPacket(data []byte) (*Packet, error) {
	pkt := &Packet{}
	return pkt, pkt.DecodeFromData(data)
}
