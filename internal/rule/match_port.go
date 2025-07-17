package rule

import (
	"slices"

	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

// Port match

type MatchPortRangeSrc netaddr.PortRange

func (MatchPortRangeSrc) MatchType() MatchType {
	return MatchTypePortRangeSrc
}

func (m MatchPortRangeSrc) Match(pkt *fastpkt.Packet) bool {
	return netaddr.PortRange(m).Contains(pkt.SrcPort)
}

func (m MatchPortRangeSrc) Compare(other Matcher) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatcherType(m, other)
	}
	return netaddr.PortRange(m).Compare(netaddr.PortRange(other.(MatchPortRangeSrc)))
}

type MatchPortRangeDst netaddr.PortRange

func (MatchPortRangeDst) MatchType() MatchType {
	return MatchTypePortRangeDst
}

func (m MatchPortRangeDst) Match(pkt *fastpkt.Packet) bool {
	return netaddr.PortRange(m).Contains(pkt.DstPort)
}

func (m MatchPortRangeDst) Compare(other Matcher) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatcherType(m, other)
	}
	return netaddr.PortRange(m).Compare(netaddr.PortRange(other.(MatchPortRangeDst)))
}

type MatchMultiPortSrc netaddr.MultiPort

func (MatchMultiPortSrc) MatchType() MatchType {
	return MatchTypeMultiPortSrc
}

func (m MatchMultiPortSrc) Match(pkt *fastpkt.Packet) bool {
	return slices.Contains(m, pkt.SrcPort)
}

func (m MatchMultiPortSrc) Compare(other Matcher) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatcherType(m, other)
	}
	return netaddr.MultiPort(m).Compare(netaddr.MultiPort(other.(MatchMultiPortSrc)))
}

type MatchMultiPortDst netaddr.MultiPort

func (MatchMultiPortDst) MatchType() MatchType {
	return MatchTypeMultiPortDst
}

func (m MatchMultiPortDst) Match(pkt *fastpkt.Packet) bool {
	return slices.Contains(m, pkt.DstPort)
}

func (m MatchMultiPortDst) Compare(other Matcher) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatcherType(m, other)
	}
	return netaddr.MultiPort(m).Compare(netaddr.MultiPort(other.(MatchMultiPortDst)))
}
