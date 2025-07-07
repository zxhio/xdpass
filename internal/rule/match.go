package rule

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netaddr"
	"golang.org/x/sys/unix"
)

type MatchType int

// Protocol
const (
	MatchTypeARP MatchType = iota + 100
	MatchTypeTCP
	MatchTypeUDP
	MatchTypeICMP
	MatchTypeHTTP
)

// MAC
const (
	MatchTypeSrcMAC MatchType = iota + 200
	MatchTypeDstMAC
)

// IPv4
const (
	MatchTypeIPv4PrefixSrc MatchType = iota + 300
	MatchTypeIPv4PrefixDst
	MatchTypeIPv4RangeSrc
	MatchTypeIPv4RangeDst
)

// Port
const (
	MatchTypeMultiPortSrc MatchType = iota + 400
	MatchTypeMultiPortDst
	MatchTypePortRangeSrc
	MatchTypePortRangeDst
)

var matchTypeToStr = map[MatchType]string{
	MatchTypeARP:           "ARP",
	MatchTypeTCP:           "TCP",
	MatchTypeUDP:           "UDP",
	MatchTypeICMP:          "ICMP",
	MatchTypeHTTP:          "HTTP",
	MatchTypeSrcMAC:        "MatchTypeSrcMAC",
	MatchTypeDstMAC:        "MatchTypeDstMAC",
	MatchTypeIPv4PrefixSrc: "IPv4PrefixSrc",
	MatchTypeIPv4PrefixDst: "IPv4PrefixDst",
	MatchTypeIPv4RangeSrc:  "IPv4RangeSrc",
	MatchTypeIPv4RangeDst:  "IPv4RangeDst",
	MatchTypeMultiPortSrc:  "MultiPortSrc",
	MatchTypeMultiPortDst:  "MultiPortDst",
	MatchTypePortRangeSrc:  "PortRangeSrc",
	MatchTypePortRangeDst:  "PortRangeDst",
}

var protocolMatchTypes = []MatchType{
	MatchTypeARP,
	MatchTypeTCP,
	MatchTypeUDP,
	MatchTypeICMP,
	MatchTypeHTTP,
}

var strToMatchType = make(map[string]MatchType)

func init() {
	for matchType, str := range matchTypeToStr {
		strToMatchType[str] = matchType
	}
}

func (t MatchType) String() string {
	return matchTypeToStr[t]
}

func (t *MatchType) Set(s string) error {
	if matchType, ok := strToMatchType[s]; ok {
		*t = matchType
		return nil
	}
	return fmt.Errorf("invalid match type: %s", s)
}

func (t MatchType) MarshalJSON() ([]byte, error) {
	s := t.String()
	if s == "" {
		return nil, fmt.Errorf("invalid match type: %d", t)
	}
	return json.Marshal(s)
}

func (t *MatchType) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	return t.Set(s)
}

func (t MatchType) Compare(t1 MatchType) int {
	return int(t - t1)
}

func GetProtocolMatchTypes() []MatchType {
	return protocolMatchTypes
}

type Match interface {
	MatchType() MatchType
	Match(*fastpkt.Packet) bool
	Compare(Match) int
}

func CompareMatchType(m1, m2 Match) int {
	return m1.MatchType().Compare(m2.MatchType())
}

// IPv4 match

// MatchIPv4PrefixSrc e.g. 192.168.10.10/32, 192.168.10.0/24
type MatchIPv4PrefixSrc netaddr.IPv4Prefix

func (MatchIPv4PrefixSrc) MatchType() MatchType {
	return MatchTypeIPv4PrefixSrc
}

func (m MatchIPv4PrefixSrc) Match(pkt *fastpkt.Packet) bool {
	return (netaddr.IPv4Prefix(m)).ContainsAddrV4(pkt.SrcIP)
}

func (m MatchIPv4PrefixSrc) Compare(other Match) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatchType(m, other)
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

func (m MatchIPv4PrefixDst) Compare(other Match) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatchType(m, other)
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

func (m MatchIPv4RangeSrc) Compare(other Match) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatchType(m, other)
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

func (m MatchIPv4RangeDst) Compare(other Match) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatchType(m, other)
	}
	return netaddr.IPv4Range(m).Compare(netaddr.IPv4Range(other.(MatchIPv4RangeDst)))
}

// Port match

type MatchPortRangeSrc netaddr.PortRange

func (MatchPortRangeSrc) MatchType() MatchType {
	return MatchTypePortRangeSrc
}

func (m MatchPortRangeSrc) Match(pkt *fastpkt.Packet) bool {
	return netaddr.PortRange(m).Contains(pkt.SrcPort)
}

func (m MatchPortRangeSrc) Compare(other Match) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatchType(m, other)
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

func (m MatchPortRangeDst) Compare(other Match) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatchType(m, other)
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

func (m MatchMultiPortSrc) Compare(other Match) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatchType(m, other)
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

func (m MatchMultiPortDst) Compare(other Match) int {
	if m.MatchType() != other.MatchType() {
		return CompareMatchType(m, other)
	}
	return netaddr.MultiPort(m).Compare(netaddr.MultiPort(other.(MatchMultiPortDst)))
}

// Protocol

type MatchARP struct{}

func (m MatchARP) MatchType() MatchType           { return MatchTypeARP }
func (m MatchARP) Match(pkt *fastpkt.Packet) bool { return pkt.L3Proto == unix.ETH_P_ARP }
func (m MatchARP) Compare(other Match) int        { return CompareMatchType(m, other) }

type MatchTCP struct{}

func (m MatchTCP) MatchType() MatchType           { return MatchTypeTCP }
func (m MatchTCP) Match(pkt *fastpkt.Packet) bool { return pkt.L4Proto == unix.IPPROTO_TCP }
func (m MatchTCP) Compare(other Match) int        { return CompareMatchType(m, other) }

type MatchUDP struct{}

func (m MatchUDP) MatchType() MatchType           { return MatchTypeUDP }
func (m MatchUDP) Match(pkt *fastpkt.Packet) bool { return pkt.L4Proto == unix.IPPROTO_UDP }
func (m MatchUDP) Compare(other Match) int        { return CompareMatchType(m, other) }

type MatchICMP struct{}

func (m MatchICMP) MatchType() MatchType           { return MatchTypeICMP }
func (m MatchICMP) Match(pkt *fastpkt.Packet) bool { return pkt.L4Proto == unix.IPPROTO_ICMP }
func (m MatchICMP) Compare(other Match) int        { return CompareMatchType(m, other) }

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
			pkt.LazyHTTP.DecodeFromPacket(pkt)
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

func (m MatchHTTP) Compare(other Match) int { return CompareMatchType(m, other) }
