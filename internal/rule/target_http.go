package rule

import (
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netutil"
)

type TargetHTTPRespSpoofNotFound struct{}

func (TargetHTTPRespSpoofNotFound) TargetType() TargetType {
	return TargetTypeHTTPSpoofNotFound
}

func (TargetHTTPRespSpoofNotFound) MatchTypes() []MatchType {
	return []MatchType{
		MatchTypeHTTP,
		MatchTypeIPv4PrefixSrc,
		MatchTypeIPv4PrefixDst,
		MatchTypeIPv4RangeSrc,
		MatchTypeIPv4RangeDst,
		MatchTypeMultiPortSrc,
		MatchTypeMultiPortDst,
		MatchTypePortRangeSrc,
		MatchTypePortRangeDst,
	}
}

func (tgt TargetHTTPRespSpoofNotFound) Compare(other Target) int {
	return CompareTargetType(tgt, other)
}

const notFoundText = `HTTP/1.1 404 Not Found
Content-Type: text/plain; charset=utf-8
Content-Length: 19

404 page not found`

func (TargetHTTPRespSpoofNotFound) Execute(pkt *fastpkt.Packet) error {
	var (
		rxTCP = fastpkt.DataPtrTCPHeader(pkt.RxData, int(pkt.L2Len+pkt.L3Len))
		buf   = fastpkt.NewBuildBuffer(pkt.TxData)
	)

	// L7
	payload := buf.AllocPayload(len(notFoundText))
	copy(payload, string(notFoundText))

	// L4
	txTCP := buf.AllocTCPHeader()
	txTCP.SrcPort = rxTCP.DstPort
	txTCP.DstPort = rxTCP.SrcPort
	txTCP.AckSeq = netutil.Htonl(netutil.Ntohl(rxTCP.Seq) + 1)
	txTCP.SetHeaderLen(uint8(fastpkt.SizeofTCP))
	txTCP.Flags.Clear(fastpkt.TCPFlagsMask)
	txTCP.Flags.Set(fastpkt.TCPFlagPSH | fastpkt.TCPFlagACK)
	txTCP.Window = rxTCP.Window
	txTCP.Check = rxTCP.Check

	makeL23DataUnderTCP(pkt, &buf, txTCP, len(payload))

	pkt.TxData = buf.Bytes()
	return nil
}
