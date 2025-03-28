package spoof

import (
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/inet"
	"golang.org/x/sys/unix"
)

type TargetTCPReset struct{}

func (TargetTCPReset) TargetType() TargetType {
	return TargetTypeTCPReset
}

func (TargetTCPReset) MatchTypes() []MatchType {
	return []MatchType{
		MatchTypeTCP,
		MatchTypeLPMIPv4Src,
		MatchTypeLPMIPv4Dst,
		MatchTypeIPRangeV4Src,
		MatchTypeIPRangeV4Dst,
		MatchTypeMultiPortSrc,
		MatchTypeMultiPortDst,
		MatchTypePortRangeSrc,
		MatchTypePortRangeDst,
	}
}

func (TargetTCPReset) Execute(pkt *fastpkt.Packet) error {
	var (
		rxEther = fastpkt.DataPtrEthHeader(pkt.RxData, 0)
		rxIPv4  = fastpkt.DataPtrIPv4Header(pkt.RxData, int(pkt.L2Len))
		rxTCP   = fastpkt.DataPtrTCPHeader(pkt.RxData, int(pkt.L2Len+pkt.L3Len))
		buf     = fastpkt.NewBuildBuffer(pkt.TxData)
	)

	// L4
	txTCP := buf.AllocTCPHeader()
	txTCP.SrcPort = rxTCP.DstPort
	txTCP.DstPort = rxTCP.SrcPort
	txTCP.AckSeq = inet.Htonl(inet.Ntohl(rxTCP.Seq) + 1)
	txTCP.SetHeaderLen(uint8(fastpkt.SizeofTCP))
	txTCP.Flags.Clear(fastpkt.TCPFlagsMask)
	txTCP.Flags.Set(fastpkt.TCPFlagRST | fastpkt.TCPFlagACK)
	txTCP.Window = rxTCP.Window
	txTCP.Check = rxTCP.Check

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
	txIPv4.ComputeChecksum(uint16(fastpkt.SizeofTCP))
	txTCP.ComputeChecksum(txIPv4.PseudoChecksum(), 0)

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

func (tgt TargetTCPReset) Equal(other Target) bool {
	return tgt.TargetType() == other.TargetType()
}
