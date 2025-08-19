package rule

import (
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netutil"
	"golang.org/x/sys/unix"
)

const (
	ICMPv4TypeEchoRequest = 0x8
	ICMPv4TypeEchoReply   = 0x0
)

type TargetICMPEchoReplySpoof struct{}

func (TargetICMPEchoReplySpoof) TargetType() TargetType {
	return TargetTypeICMPSpoofEchoReply
}

func (TargetICMPEchoReplySpoof) MatchTypes() []MatchType {
	return []MatchType{
		MatchTypeICMP,
		MatchTypeIPv4PrefixSrc,
		MatchTypeIPv4PrefixDst,
		MatchTypeIPv4RangeSrc,
		MatchTypeIPv4RangeDst,
	}
}

func (tgt TargetICMPEchoReplySpoof) Compare(other Target) int {
	return CompareTargetType(tgt, other)
}

func (TargetICMPEchoReplySpoof) Open() error { return nil }

func (TargetICMPEchoReplySpoof) Execute(pkt *fastpkt.Packet) error {
	var (
		rxEther = fastpkt.EthernetPtr(pkt, pkt.RxData)
		rxIPv4  = fastpkt.IPv4Ptr(pkt, pkt.RxData)
		rxICMP  = fastpkt.ICMPPtr(pkt, pkt.RxData)
		builder = fastpkt.NewPacketBuilder(pkt.TxData)
	)

	if rxICMP.Type != ICMPv4TypeEchoRequest {
		return nil
	}

	// Payload
	txPayloadLen := netutil.Ntohs(rxIPv4.Len) - uint16(rxIPv4.HeaderLen()) - uint16(fastpkt.SizeofICMP)
	txPayload := builder.Alloc(int(txPayloadLen))
	copy(txPayload, pkt.RxData[int(pkt.L2Len)+int(pkt.L3Len)+fastpkt.SizeofICMP:])

	// L4
	txICMP := builder.AllocICMP()
	txICMP.Type = ICMPv4TypeEchoReply
	txICMP.Code = 0
	txICMP.ID = rxICMP.ID
	txICMP.Seq = rxICMP.Seq
	txICMP.SetChecksum(txPayloadLen)

	// L3
	txIPv4 := builder.AllocIPv4()
	txIPv4.SetHeaderLen(uint8(fastpkt.SizeofIPv4))
	txIPv4.TOS = 0
	txIPv4.ID = rxIPv4.ID
	txIPv4.FragOff = rxIPv4.FragOff
	txIPv4.TTL = 78
	txIPv4.Protocol = rxIPv4.Protocol
	txIPv4.SrcIP = rxIPv4.DstIP
	txIPv4.DstIP = rxIPv4.SrcIP
	txIPv4.SetChecksum(uint16(fastpkt.SizeofICMP) + txPayloadLen)

	// L2 VLAN
	if netutil.Ntohs(rxEther.HwProto) == unix.ETH_P_8021Q {
		rxVLAN := fastpkt.VLANPtr(pkt, pkt.RxData)
		txVLAN := builder.AllocVLAN()
		txVLAN.ID = rxVLAN.ID
		txVLAN.EncapsulatedProto = rxVLAN.EncapsulatedProto
	}

	// L2 Ethernet
	txEther := builder.AllocEthernet()
	copy(txEther.HwSource[:], rxEther.HwDest[:])
	copy(txEther.HwDest[:], rxEther.HwSource[:])
	txEther.HwProto = rxEther.HwProto

	pkt.TxData = builder.Bytes()
	return nil
}

func (TargetICMPEchoReplySpoof) Close() error { return nil }
