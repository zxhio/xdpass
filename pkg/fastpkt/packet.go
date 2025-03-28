package fastpkt

import (
	"errors"
	"unsafe"

	"github.com/zxhio/xdpass/pkg/inet"
	"golang.org/x/sys/unix"
)

const (
	SizeofEthernet = int(unsafe.Sizeof(EthHeader{}))  // sizeof(struct ethhdr)
	SizeofVLAN     = int(unsafe.Sizeof(VLANHeader{})) // sizeof(struct vlan_hdr)
	SizeofIPv4     = int(unsafe.Sizeof(IPv4Header{})) // sizeof(struct iphdr)
	SizeofIPv6     = int(unsafe.Sizeof(IPv6Header{})) // sizeof(struct ipv6hdr)
	SizeofTCP      = int(unsafe.Sizeof(TCPHeader{}))  // sizeof(struct tcphdr)
	SizeofUDP      = int(unsafe.Sizeof(UDPHeader{}))  // sizeof(struct udphdr)
	SizeofICMP     = int(unsafe.Sizeof(ICMPHeader{})) // sizeof(struct icmphdr)
	SizeofARP      = int(unsafe.Sizeof(ARPHeader{}))  // sizeof(struct arphdr)
)

var (
	ErrPacketTooShort            = errors.New("packet too short")
	ErrPacketInvalidEthernetType = errors.New("invalid ethernet type")
	ErrPacketInvalidProtocol     = errors.New("invalid protocol")
)

type Packet struct {
	L3Proto uint16
	L4Proto uint16

	// L3
	SrcIP inet.AddrV4
	DstIP inet.AddrV4

	// L4
	SrcPort uint16
	DstPort uint16

	L2Len uint8
	L3Len uint8
	L4Len uint8

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

	eth := (*EthHeader)(unsafe.Pointer(&data[0]))
	off := SizeofEthernet

	switch inet.Ntohs(eth.HwProto) {
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

	vlan := (*VLANHeader)(unsafe.Pointer(&data[0]))
	off := SizeofVLAN

	switch inet.Ntohs(vlan.EncapsulatedProto) {
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

	arp := (*ARPHeader)(unsafe.Pointer(&data[0]))
	if len(data) < SizeofARP+int(arp.HwAddrLen)*2+int(arp.ProtAddrLen)*2 {
		return ErrPacketTooShort
	}

	data = data[SizeofARP:]
	pkt.L3Proto = unix.ETH_P_ARP
	pkt.L3Len = arp.HwAddrLen*2 + arp.ProtAddrLen*2

	// IPv4
	if arp.ProtAddrLen == 4 {
		pkt.SrcIP = inet.NewAddrV4FromIP(data[arp.HwAddrLen : arp.HwAddrLen+arp.ProtAddrLen])
		pkt.DstIP = inet.NewAddrV4FromIP(data[arp.HwAddrLen*2+arp.ProtAddrLen : arp.HwAddrLen*2+arp.ProtAddrLen*2])
	}

	return nil
}

func (pkt *Packet) DecodePacketIPv4(data []byte) error {
	if len(data) < SizeofIPv4 {
		return ErrPacketTooShort
	}

	ip := (*IPv4Header)(unsafe.Pointer(&data[0]))
	off := ip.HeaderLen()
	pkt.L3Proto = unix.ETH_P_IP
	pkt.SrcIP = inet.AddrV4(inet.Ntohl(ip.SrcIP))
	pkt.DstIP = inet.AddrV4(inet.Ntohl(ip.DstIP))
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

	tcp := (*TCPHeader)(unsafe.Pointer(&data[0]))
	pkt.L4Proto = unix.IPPROTO_TCP
	pkt.SrcPort = inet.Ntohs(tcp.SrcPort)
	pkt.DstPort = inet.Ntohs(tcp.DstPort)
	pkt.L4Len = uint8(tcp.HeaderLen())

	return nil
}

func (pkt *Packet) DecodePacketUDP(data []byte) error {
	if len(data) < SizeofUDP {
		return ErrPacketTooShort
	}

	udp := (*UDPHeader)(unsafe.Pointer(&data[0]))
	pkt.L4Proto = unix.IPPROTO_UDP
	pkt.SrcPort = inet.Ntohs(udp.SrcPort)
	pkt.DstPort = inet.Ntohs(udp.DstPort)
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
