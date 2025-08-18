package rule

import (
	"bytes"

	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netaddr"
	"github.com/zxhio/xdpass/pkg/netutil"
	"golang.org/x/sys/unix"
)

const (
	ARPOperationRequest = 1
	ARPOperationReply   = 2
)

type TargetARPReplySpoof struct {
	HwAddr netaddr.HwAddr `json:"hw_addr"`
}

func (TargetARPReplySpoof) TargetType() TargetType {
	return TargetTypeARPSpoofReply
}

func (TargetARPReplySpoof) MatchTypes() []MatchType {
	return []MatchType{
		MatchTypeARP,
		MatchTypeIPv4PrefixSrc,
		MatchTypeIPv4PrefixDst,
		MatchTypeIPv4RangeSrc,
		MatchTypeIPv4RangeDst,
	}
}

func (tgt TargetARPReplySpoof) Compare(other Target) int {
	if tgt.TargetType() != other.TargetType() {
		return CompareTargetType(tgt, other)
	}
	t := other.(TargetARPReplySpoof)
	return bytes.Compare(tgt.HwAddr[:], t.HwAddr[:])
}

func (TargetARPReplySpoof) Open() error { return nil }

func (tgt TargetARPReplySpoof) Execute(pkt *fastpkt.Packet) error {
	var (
		rxEther   = fastpkt.DataPtrEthHeader(pkt.RxData, 0)
		rxPayload = pkt.RxData[pkt.L2Len+uint8(fastpkt.SizeofARP):]
		rxARP     = fastpkt.DataPtrARPHeader(pkt.RxData, int(pkt.L2Len))
		buf       = fastpkt.NewBuildBuffer(pkt.TxData)
	)

	// // TODO: support IPv6
	if netutil.Ntohs(rxARP.Operation) != ARPOperationRequest || rxARP.ProtAddrLen != 4 {
		return nil
	}

	// L3
	txPayload := buf.AllocPayload(int(rxARP.HwAddrLen*2 + rxARP.ProtAddrLen*2))

	// ARP reply
	// Source hardware address
	copy(txPayload[:rxARP.HwAddrLen], tgt.HwAddr[:])
	// Source protocol address
	copy(txPayload[rxARP.HwAddrLen:rxARP.HwAddrLen+rxARP.ProtAddrLen], rxPayload[rxARP.HwAddrLen*2+rxARP.ProtAddrLen:rxARP.HwAddrLen*2+rxARP.ProtAddrLen*2])
	// Dest hardware address
	copy(txPayload[rxARP.HwAddrLen+rxARP.ProtAddrLen:rxARP.HwAddrLen*2+rxARP.ProtAddrLen], rxPayload[:rxARP.HwAddrLen])
	// Dest protocol address
	copy(txPayload[rxARP.HwAddrLen*2+rxARP.ProtAddrLen:rxARP.HwAddrLen*2+rxARP.ProtAddrLen*2], rxPayload[rxARP.HwAddrLen:rxARP.HwAddrLen+rxARP.ProtAddrLen])

	txARP := buf.AllocARPHeader()
	txARP.HwAddrType = rxARP.HwAddrType
	txARP.ProtAddrType = rxARP.ProtAddrType
	txARP.HwAddrLen = rxARP.HwAddrLen
	txARP.ProtAddrLen = rxARP.ProtAddrLen
	txARP.Operation = netutil.Htons(ARPOperationReply)

	// L2 VLAN
	if netutil.Ntohs(rxEther.HwProto) == unix.ETH_P_8021Q {
		rxVLAN := fastpkt.DataPtrVLANHeader(pkt.RxData, fastpkt.SizeofEthernet)
		txVLAN := buf.AllocVLANHeader()
		txVLAN.ID = rxVLAN.ID
		txVLAN.EncapsulatedProto = rxVLAN.EncapsulatedProto
	}

	// L2 Ethernet
	txEther := buf.AllocEthHeader()
	copy(txEther.HwSource[:], tgt.HwAddr[:])
	copy(txEther.HwDest[:], rxEther.HwSource[:])
	txEther.HwProto = rxEther.HwProto

	pkt.TxData = buf.Bytes()

	return nil
}

func (TargetARPReplySpoof) Close() error { return nil }
