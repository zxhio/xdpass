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

func (TargetHTTPRespSpoofNotFound) Open() error { return nil }

const notFoundText = "HTTP/1.1 404 Not Found\r\n" +
	"Content-Type: text/html\r\n" +
	"Content-Length: 97\r\n" +
	"\r\n" +
	"<html>\n" +
	"<body>\n" +
	"<h1>404 Not Found</h1>\n" +
	"<p>The requested resource was not found.</p>\n" +
	"</body>\n" +
	"</html>"

func (TargetHTTPRespSpoofNotFound) Execute(pkt *fastpkt.Packet) error {
	var (
		rxTCP   = fastpkt.TCPPtr(pkt, pkt.RxData)
		builder = fastpkt.NewPacketBuilder(pkt.TxData)
	)

	// L7
	payload := builder.Alloc(len(notFoundText))
	copy(payload, string(notFoundText))

	// L4
	txTCP := builder.AllocTCP()
	txTCP.SrcPort = rxTCP.DstPort
	txTCP.DstPort = rxTCP.SrcPort
	txTCP.Seq = rxTCP.AckSeq
	txTCP.AckSeq = netutil.Htonl(netutil.Ntohl(rxTCP.Seq) + uint32(len(pkt.RxData)-int(pkt.L2Len+pkt.L3Len+pkt.L4Len)))
	txTCP.SetHeaderLen(uint8(fastpkt.SizeofTCP))
	txTCP.Flags.Clear(fastpkt.TCPFlagsMask)
	txTCP.Flags.Set(fastpkt.TCPFlagPSH | fastpkt.TCPFlagACK)
	txTCP.Window = rxTCP.Window
	txTCP.Check = rxTCP.Check

	makeL23DataUnderTCP(pkt, builder, txTCP, len(payload))

	pkt.TxData = builder.Bytes()
	return nil
}

func (TargetHTTPRespSpoofNotFound) Close() error { return nil }
