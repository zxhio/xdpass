package rule

import (
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netutil"
	"golang.org/x/sys/unix"
)

var targetTCPMatchTypes = []MatchType{
	MatchTypeTCP,
	MatchTypeIPv4PrefixSrc,
	MatchTypeIPv4PrefixDst,
	MatchTypeIPv4RangeSrc,
	MatchTypeIPv4RangeDst,
	MatchTypeMultiPortSrc,
	MatchTypeMultiPortDst,
	MatchTypePortRangeSrc,
	MatchTypePortRangeDst,
}

type TargetTCPSpoofSYNACK struct{}

func (TargetTCPSpoofSYNACK) TargetType() TargetType     { return TargetTypeTCPSpoofSYNACK }
func (TargetTCPSpoofSYNACK) MatchTypes() []MatchType    { return targetTCPMatchTypes }
func (t TargetTCPSpoofSYNACK) Compare(other Target) int { return CompareTargetType(t, other) }
func (TargetTCPSpoofSYNACK) Open() error                { return nil }
func (TargetTCPSpoofSYNACK) OnPacket(pkt *fastpkt.Packet) error {
	makeTCPDataWithFlags(pkt, fastpkt.TCPFlagSYN|fastpkt.TCPFlagACK)
	return nil
}
func (TargetTCPSpoofSYNACK) Close() error { return nil }

type TargetTCPSpoofRSTACK struct{}

func (TargetTCPSpoofRSTACK) TargetType() TargetType     { return TargetTypeTCPSpoofRSTACK }
func (TargetTCPSpoofRSTACK) MatchTypes() []MatchType    { return targetTCPMatchTypes }
func (t TargetTCPSpoofRSTACK) Compare(other Target) int { return CompareTargetType(t, other) }
func (TargetTCPSpoofRSTACK) Open() error                { return nil }
func (TargetTCPSpoofRSTACK) OnPacket(pkt *fastpkt.Packet) error {
	makeTCPDataWithFlags(pkt, fastpkt.TCPFlagRST|fastpkt.TCPFlagACK)
	return nil
}
func (TargetTCPSpoofRSTACK) Close() error { return nil }

type TargetTCPSpoofPSHACK struct{}

func (TargetTCPSpoofPSHACK) TargetType() TargetType     { return TargetTypeTCPSpoofPSHACK }
func (TargetTCPSpoofPSHACK) MatchTypes() []MatchType    { return targetTCPMatchTypes }
func (t TargetTCPSpoofPSHACK) Compare(other Target) int { return CompareTargetType(t, other) }
func (TargetTCPSpoofPSHACK) Open() error                { return nil }
func (TargetTCPSpoofPSHACK) OnPacket(pkt *fastpkt.Packet) error {
	makeTCPDataWithFlags(pkt, fastpkt.TCPFlagPSH|fastpkt.TCPFlagACK)
	return nil
}
func (TargetTCPSpoofPSHACK) Close() error { return nil }

type TargetTCPSpoofFINACK struct{}

func (TargetTCPSpoofFINACK) TargetType() TargetType     { return TargetTypeTCPSpoofFINACK }
func (TargetTCPSpoofFINACK) MatchTypes() []MatchType    { return targetTCPMatchTypes }
func (t TargetTCPSpoofFINACK) Compare(other Target) int { return CompareTargetType(t, other) }
func (TargetTCPSpoofFINACK) Open() error                { return nil }
func (TargetTCPSpoofFINACK) OnPacket(pkt *fastpkt.Packet) error {
	makeTCPDataWithFlags(pkt, fastpkt.TCPFlagFIN|fastpkt.TCPFlagACK)
	return nil
}
func (TargetTCPSpoofFINACK) Close() error { return nil }

type TargetTCPSpoofACK struct{}

func (TargetTCPSpoofACK) TargetType() TargetType     { return TargetTypeTCPSpoofACK }
func (TargetTCPSpoofACK) MatchTypes() []MatchType    { return targetTCPMatchTypes }
func (t TargetTCPSpoofACK) Compare(other Target) int { return CompareTargetType(t, other) }
func (TargetTCPSpoofACK) Open() error                { return nil }
func (TargetTCPSpoofACK) OnPacket(pkt *fastpkt.Packet) error {
	makeTCPDataWithFlags(pkt, fastpkt.TCPFlagACK)
	return nil
}
func (TargetTCPSpoofACK) Close() error { return nil }

func makeTCPDataWithFlags(pkt *fastpkt.Packet, flags fastpkt.TCPFlags) {
	var (
		rxTCP = fastpkt.DataPtrTCPHeader(pkt.RxData, int(pkt.L2Len+pkt.L3Len))
		buf   = fastpkt.NewBuildBuffer(pkt.TxData)
	)

	// L4
	txTCP := buf.AllocTCPHeader()
	txTCP.SrcPort = rxTCP.DstPort
	txTCP.DstPort = rxTCP.SrcPort
	txTCP.Seq = rxTCP.AckSeq
	txTCP.AckSeq = netutil.Htonl(netutil.Ntohl(rxTCP.Seq) + 1)
	txTCP.SetHeaderLen(uint8(fastpkt.SizeofTCP))
	txTCP.Flags.Clear(fastpkt.TCPFlagsMask)
	txTCP.Flags.Set(flags)
	txTCP.Window = rxTCP.Window
	txTCP.Check = rxTCP.Check

	makeL23DataUnderTCP(pkt, &buf, txTCP, 0)

	pkt.TxData = buf.Bytes()
}

func makeL23DataUnderTCP(pkt *fastpkt.Packet, buf *fastpkt.Buffer, txTCP *fastpkt.TCPHeader, l7Len int) {
	var (
		rxEther = fastpkt.DataPtrEthHeader(pkt.RxData, 0)
		rxIPv4  = fastpkt.DataPtrIPv4Header(pkt.RxData, int(pkt.L2Len))
	)

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
	txIPv4.ComputeChecksum(uint16(fastpkt.SizeofTCP) + uint16(l7Len))
	txTCP.ComputeChecksum(txIPv4.PseudoChecksum(), uint16(l7Len))

	// L2 VLAN
	if netutil.Ntohs(rxEther.HwProto) == unix.ETH_P_8021Q {
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
}
