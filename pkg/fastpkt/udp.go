package fastpkt

import (
	"unsafe"

	"github.com/zxhio/xdpass/pkg/netutil"
	"golang.org/x/sys/unix"
)

// <linux/udp.h>
//
// struct udphdr {
//     __be16 source;
//     __be16 dest;
//     __be16 len;
//     __sum16 check;
// };

type UDP struct {
	SrcPort uint16
	DstPort uint16
	Length  uint16
	Check   uint16
}

func (udp *UDP) SetChecksum(ipv4 *IPv4, payloadLen uint16) {
	ipPayloadLen := uint16(SizeofUDP) + payloadLen
	ipPseudoChecksum := ipv4.PseudoChecksum(unix.IPPROTO_UDP, ipPayloadLen)
	data := unsafe.Slice((*byte)(unsafe.Pointer(udp)), ipPayloadLen)
	udp.Check = 0
	udp.Check = netutil.Htons(tcpipChecksum(data, ipPseudoChecksum))
}
