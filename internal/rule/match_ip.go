package rule

import (
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

// IPv4 match

// MatchIPv4PrefixSrc e.g. 192.168.10.10/32, 192.168.10.0/24
type MatchIPv4PrefixSrc netaddr.IPv4Prefix

func (MatchIPv4PrefixSrc) MatchType() MatchType {
	return MatchTypeIPv4PrefixSrc
}

func (m MatchIPv4PrefixSrc) Match(pkt *fastpkt.Packet) bool {
	return (netaddr.IPv4Prefix(m)).ContainsAddrV4(pkt.SrcIP)
}

func (m MatchIPv4PrefixSrc) Compare(other Matcher) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatcherType(m, other)
	}
	return (netaddr.IPv4Prefix(m)).Compare(netaddr.IPv4Prefix(other.(MatchIPv4PrefixSrc)))
}

// MatchIPv4PrefixDst e.g. 192.168.10.10/32, 192.168.10.0/24
type MatchIPv4PrefixDst netaddr.IPv4Prefix

func (MatchIPv4PrefixDst) MatchType() MatchType {
	return MatchTypeIPv4PrefixDst
}

func (m MatchIPv4PrefixDst) Match(pkt *fastpkt.Packet) bool {
	return (netaddr.IPv4Prefix(m)).ContainsAddrV4(pkt.DstIP)
}

func (m MatchIPv4PrefixDst) Compare(other Matcher) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatcherType(m, other)
	}
	return (netaddr.IPv4Prefix(m)).Compare(netaddr.IPv4Prefix(other.(MatchIPv4PrefixDst)))
}

type MatchIPv4RangeSrc netaddr.IPv4Range

func (MatchIPv4RangeSrc) MatchType() MatchType {
	return MatchTypeIPv4RangeSrc
}

func (m MatchIPv4RangeSrc) Match(pkt *fastpkt.Packet) bool {
	return netaddr.IPv4Range(m).Contains(pkt.SrcIP)
}

func (m MatchIPv4RangeSrc) Compare(other Matcher) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatcherType(m, other)
	}
	return netaddr.IPv4Range(m).Compare(netaddr.IPv4Range(other.(MatchIPv4RangeSrc)))
}

type MatchIPv4RangeDst netaddr.IPv4Range

func (MatchIPv4RangeDst) MatchType() MatchType {
	return MatchTypeIPv4RangeDst
}

func (m MatchIPv4RangeDst) Match(pkt *fastpkt.Packet) bool {
	return netaddr.IPv4Range(m).Contains(pkt.DstIP)
}

func (m MatchIPv4RangeDst) Compare(other Matcher) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatcherType(m, other)
	}
	return netaddr.IPv4Range(m).Compare(netaddr.IPv4Range(other.(MatchIPv4RangeDst)))
}
