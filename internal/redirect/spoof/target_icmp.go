package spoof

import (
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/inet"
	"golang.org/x/sys/unix"
)

const (
	ICMPv4TypeEchoRequest = 0x8
	ICMPv4TypeEchoReply   = 0x0
)

type TargetICMPEchoReply struct{}

func (TargetICMPEchoReply) TargetType() TargetType {
	return TargetTypeICMPEchoReply
}

func (TargetICMPEchoReply) MatchTypes() []MatchType {
	return []MatchType{
		MatchTypeICMP,
		MatchTypeLPMIPv4Src,
		MatchTypeLPMIPv4Dst,
		MatchTypeIPRangeV4Src,
		MatchTypeIPRangeV4Dst,
	}
}

func (TargetICMPEchoReply) Execute(pkt *fastpkt.Packet) error {
	var (
		rxEther = fastpkt.DataPtrEthHeader(pkt.RxData, 0)
		rxIPv4  = fastpkt.DataPtrIPv4Header(pkt.RxData, int(pkt.L2Len))
		rxICMP  = fastpkt.DataPtrICMPHeader(pkt.RxData, int(pkt.L2Len+pkt.L3Len))
		buf     = fastpkt.NewBuildBuffer(pkt.TxData)
	)

	// if rxICMP.Type != ICMPv4TypeEchoRequest {
	// 	return true, nil
	// }

	// Payload
	txPayloadLen := inet.Ntohs(rxIPv4.Len) - uint16(rxIPv4.HeaderLen()) - uint16(fastpkt.SizeofICMP)
	txPayload := buf.AllocPayload(int(txPayloadLen))
	copy(txPayload, pkt.RxData[int(pkt.L2Len)+int(pkt.L3Len)+fastpkt.SizeofICMP:])

	// L4
	txICMP := buf.AllocICMPHeader()
	txICMP.Type = ICMPv4TypeEchoReply
	txICMP.Code = 0
	txICMP.ID = rxICMP.ID
	txICMP.Seq = rxICMP.Seq
	txICMP.ComputeChecksum(txPayloadLen)

	// L3
	txIPv4 := buf.AllocIPv4Header()
	txIPv4.SetHeaderLen(uint8(fastpkt.SizeofIPv4))
	txIPv4.TOS = 0
	txIPv4.ID = rxIPv4.ID
	txIPv4.FragOff = rxIPv4.FragOff
	txIPv4.TTL = 78
	txIPv4.Protocol = rxIPv4.Protocol
	txIPv4.SrcIP = rxIPv4.DstIP
	txIPv4.DstIP = rxIPv4.SrcIP
	txIPv4.ComputeChecksum(uint16(fastpkt.SizeofICMP) + txPayloadLen)

	// L2 VLAN
	if inet.Ntohs(rxEther.HwProto) == unix.ETH_P_8021Q {
		rxVLAN := fastpkt.DataPtrVLANHeader(pkt.RxData, fastpkt.SizeofEthernet)
		txVLAN := buf.AllocVLANHeader()
		txVLAN.ID = rxVLAN.ID
		txVLAN.EncapsulatedProto = rxVLAN.EncapsulatedProto
	}

	// L2 Ethernet
	txEther := buf.AllocEthHeader()
	txEther.HwSource = rxEther.HwDest
	txEther.HwDest = rxEther.HwSource
	txEther.HwProto = rxEther.HwProto

	pkt.TxData = buf.Bytes()
	return nil
}

func (tgt TargetICMPEchoReply) Equal(other Target) bool {
	return tgt.TargetType() == other.TargetType()
}
