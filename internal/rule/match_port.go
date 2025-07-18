package rule

import (
	"slices"

	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

// Port match

type MatchPortRangeSrc struct {
	netaddr.PortRange
}

func (MatchPortRangeSrc) MatchType() MatchType {
	return MatchTypePortRangeSrc
}

func (m MatchPortRangeSrc) Match(pkt *fastpkt.Packet) bool {
	return m.PortRange.Contains(pkt.SrcPort)
}

func (m MatchPortRangeSrc) Compare(other Matcher) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatcherType(m, other)
	}
	return m.PortRange.Compare(other.(MatchPortRangeSrc).PortRange)
}

type MatchPortRangeDst struct {
	netaddr.PortRange
}

func (MatchPortRangeDst) MatchType() MatchType {
	return MatchTypePortRangeDst
}

func (m MatchPortRangeDst) Match(pkt *fastpkt.Packet) bool {
	return m.PortRange.Contains(pkt.DstPort)
}

func (m MatchPortRangeDst) Compare(other Matcher) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatcherType(m, other)
	}
	return m.PortRange.Compare(other.(MatchPortRangeDst).PortRange)
}

type MatchMultiPortSrc struct {
	netaddr.MultiPort
}

func (MatchMultiPortSrc) MatchType() MatchType {
	return MatchTypeMultiPortSrc
}

func (m MatchMultiPortSrc) Match(pkt *fastpkt.Packet) bool {
	return slices.Contains(m.MultiPort, pkt.SrcPort)
}

func (m MatchMultiPortSrc) Compare(other Matcher) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatcherType(m, other)
	}
	return m.MultiPort.Compare(other.(MatchMultiPortSrc).MultiPort)
}

type MatchMultiPortDst struct {
	netaddr.MultiPort
}

func (MatchMultiPortDst) MatchType() MatchType {
	return MatchTypeMultiPortDst
}

func (m MatchMultiPortDst) Match(pkt *fastpkt.Packet) bool {
	return slices.Contains(m.MultiPort, pkt.DstPort)
}

func (m MatchMultiPortDst) Compare(other Matcher) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatcherType(m, other)
	}
	return m.MultiPort.Compare(other.(MatchMultiPortDst).MultiPort)
}
