package rule

import (
	"bytes"

	"github.com/zxhio/xdpass/pkg/fastpkt"
	"golang.org/x/sys/unix"
)

// Protocol

type MatchARP struct{}

func (m MatchARP) MatchType() MatchType           { return MatchTypeARP }
func (m MatchARP) Match(pkt *fastpkt.Packet) bool { return pkt.L3Proto == unix.ETH_P_ARP }
func (m MatchARP) Compare(other Matcher) int      { return CompareMatcherType(m, other) }

type MatchTCP struct{}

func (m MatchTCP) MatchType() MatchType           { return MatchTypeTCP }
func (m MatchTCP) Match(pkt *fastpkt.Packet) bool { return pkt.L4Proto == unix.IPPROTO_TCP }
func (m MatchTCP) Compare(other Matcher) int      { return CompareMatcherType(m, other) }

type MatchTCPFlags fastpkt.TCPFlags

func (m MatchTCPFlags) MatchType() MatchType      { return MatchTypeTCPFlags }
func (m MatchTCPFlags) Compare(other Matcher) int { return CompareMatcherType(m, other) }
func (m MatchTCPFlags) Match(pkt *fastpkt.Packet) bool {
	if pkt.L4Proto != unix.IPPROTO_TCP {
		return false
	}
	tcp := fastpkt.DataPtrTCPHeader(pkt.RxData, int(pkt.L2Len+pkt.L3Len))
	return tcp.Flags.Has(fastpkt.TCPFlags(m))
}

type MatchUDP struct{}

func (m MatchUDP) MatchType() MatchType           { return MatchTypeUDP }
func (m MatchUDP) Match(pkt *fastpkt.Packet) bool { return pkt.L4Proto == unix.IPPROTO_UDP }
func (m MatchUDP) Compare(other Matcher) int      { return CompareMatcherType(m, other) }

type MatchICMP struct{}

func (m MatchICMP) MatchType() MatchType           { return MatchTypeICMP }
func (m MatchICMP) Match(pkt *fastpkt.Packet) bool { return pkt.L4Proto == unix.IPPROTO_ICMP }
func (m MatchICMP) Compare(other Matcher) int      { return CompareMatcherType(m, other) }

type MatchHTTP struct {
	Method  string `json:"method,omitempty"`
	URI     string `json:"uri,omitempty"`
	Version string `json:"version,omitempty"`
	Host    string `json:"host,omitempty"`
}

func (m MatchHTTP) MatchType() MatchType { return MatchTypeHTTP }

func (m MatchHTTP) Match(pkt *fastpkt.Packet) bool {
	if pkt.L7Proto != fastpkt.L7ProtoHTTPReq {
		return false
	}

	if pkt.LazyHTTP == nil {
		pkt.LazyHTTP = &fastpkt.LazyHTTP{}
		if !pkt.LazyHTTP.Decoded {
			err := pkt.LazyHTTP.DecodeFromPacket(pkt)
			if err != nil {
				return false
			}
		}
	}
	if !pkt.LazyHTTP.Valid {
		return false
	}

	if m.Method != "" && !bytes.Equal(pkt.LazyHTTP.Method, []byte(m.Method)) {
		return false
	}

	if m.URI != "" && !bytes.Equal(pkt.LazyHTTP.URI, []byte(m.URI)) {
		return false
	}

	ver := [3]byte{pkt.LazyHTTP.VersionMajor, '.', pkt.LazyHTTP.VersionMinor}
	if m.Version != "" && !bytes.Equal(ver[:], []byte(m.Version)) {
		return false
	}

	if m.Host != "" && !bytes.Equal(pkt.LazyHTTP.Host, []byte(m.Host)) {
		return false
	}

	return true
}

func (m MatchHTTP) Compare(other Matcher) int { return CompareMatcherType(m, other) }
