package spoof

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/inet"
	"golang.org/x/sys/unix"
)

type MatchType uint16

const (
	MatchTypeARP MatchType = iota + 1
	MatchTypeLPMIPv4Src
	MatchTypeLPMIPv4Dst
	MatchTypeIPRangeV4Src
	MatchTypeIPRangeV4Dst
	MatchTypeMultiPortSrc
	MatchTypeMultiPortDst
	MatchTypePortRangeSrc
	MatchTypePortRangeDst
	MatchTypeTCP
	MatchTypeUDP
	MatchTypeICMP
	MatchTypeHTTP
)

var matchTypeToStr = map[MatchType]string{
	MatchTypeARP:          "arp",
	MatchTypeLPMIPv4Src:   "lpm-ipv4-src",
	MatchTypeLPMIPv4Dst:   "lpm-ipv4-dst",
	MatchTypeIPRangeV4Src: "iprange-v4-src",
	MatchTypeIPRangeV4Dst: "iprange-v4-dst",
	MatchTypeMultiPortSrc: "multiport-src",
	MatchTypeMultiPortDst: "multiport-dst",
	MatchTypePortRangeSrc: "portrange-src",
	MatchTypePortRangeDst: "portrange-dst",
	MatchTypeTCP:          "tcp",
	MatchTypeUDP:          "udp",
	MatchTypeICMP:         "icmp",
	MatchTypeHTTP:         "http",
}

var strToMatchType = make(map[string]MatchType)

func init() {
	for matchType, str := range matchTypeToStr {
		strToMatchType[str] = matchType
	}
}

type Match interface {
	MatchType() MatchType
	Match(*fastpkt.Packet) bool
	Equal(Match) bool
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

type RangeT[T uint16 | uint32 | inet.AddrV4] struct {
	Start T `json:"start,omitempty"`
	End   T `json:"end,omitempty"`
}

func (r RangeT[T]) IsIn(v T) bool {
	return v >= r.Start && v <= r.End
}

func (r RangeT[T]) Equal(other RangeT[T]) bool {
	return r.Start == other.Start && r.End == other.End
}

// IPv4 match

// MatchLPMIPv4Src e.g. 192.168.10.10/32, 192.168.10.0/24
type MatchLPMIPv4Src inet.LPMIPv4

func (MatchLPMIPv4Src) MatchType() MatchType { return MatchTypeLPMIPv4Src }
func (m MatchLPMIPv4Src) Match(pkt *fastpkt.Packet) bool {
	return (inet.LPMIPv4(m)).Match(pkt.SrcIP)
}
func (m MatchLPMIPv4Src) Equal(other Match) bool {
	if m.MatchType() != other.MatchType() {
		return false
	}
	return inet.LPMIPv4(m).Equal(inet.LPMIPv4(other.(MatchLPMIPv4Src)))
}

// MatchLPMIPv4Dst e.g. 192.168.10.10/32, 192.168.10.0/24
type MatchLPMIPv4Dst inet.LPMIPv4

func (MatchLPMIPv4Dst) MatchType() MatchType { return MatchTypeLPMIPv4Dst }
func (m MatchLPMIPv4Dst) Match(pkt *fastpkt.Packet) bool {
	return (inet.LPMIPv4(m)).Match(pkt.DstIP)
}
func (m MatchLPMIPv4Dst) Equal(other Match) bool {
	if m.MatchType() != other.MatchType() {
		return false
	}
	return inet.LPMIPv4(m).Equal(inet.LPMIPv4(other.(MatchLPMIPv4Dst)))
}

// IPRangeV4 e.g. 192.168.10.10-192.168.10.20
type IPRangeV4 RangeT[inet.AddrV4]

func (r IPRangeV4) IsIn(v inet.AddrV4) bool {
	return RangeT[inet.AddrV4](r).IsIn(v)
}

func (r IPRangeV4) Equal(other IPRangeV4) bool {
	return RangeT[inet.AddrV4](r).Equal(RangeT[inet.AddrV4](other))
}

func (IPRangeV4) Type() string {
	return "iprange"
}

func (ir IPRangeV4) String() string {
	if ir.Start == ir.End {
		if ir.Start == 0 {
			return ""
		}
		return ir.Start.String()
	}
	return fmt.Sprintf("%s-%s", ir.Start.String(), ir.End.String())
}

func (ir *IPRangeV4) Set(s string) error {
	var (
		start inet.AddrV4
		end   inet.AddrV4
	)

	fields := strings.Split(s, "-")
	if len(fields) != 1 && len(fields) != 2 {
		return fmt.Errorf("invalid iprange: %s", s)
	}

	if len(fields) >= 1 {
		ip := net.ParseIP(fields[0])
		if ip == nil {
			return fmt.Errorf("invalid start ip: %s", fields[0])
		}
		start = inet.NewAddrV4FromIP(ip)
		end = start

		if len(fields) == 2 {
			ip := net.ParseIP(fields[1])
			if ip == nil {
				return fmt.Errorf("invalid end ip: %s", fields[1])
			}
			end = inet.NewAddrV4FromIP(ip)
		}
	}

	ir.Start = start
	ir.End = end

	return nil
}

type MatchIPRangeV4Src IPRangeV4

func (MatchIPRangeV4Src) MatchType() MatchType             { return MatchTypeIPRangeV4Src }
func (m MatchIPRangeV4Src) Match(pkt *fastpkt.Packet) bool { return IPRangeV4(m).IsIn(pkt.SrcIP) }
func (m MatchIPRangeV4Src) Equal(other Match) bool {
	if m.MatchType() != other.MatchType() {
		return false
	}
	return IPRangeV4(m).Equal(IPRangeV4(other.(MatchIPRangeV4Src)))
}

type MatchIPRangeV4Dst IPRangeV4

func (MatchIPRangeV4Dst) MatchType() MatchType             { return MatchTypeIPRangeV4Dst }
func (m MatchIPRangeV4Dst) Match(pkt *fastpkt.Packet) bool { return IPRangeV4(m).IsIn(pkt.DstIP) }
func (m MatchIPRangeV4Dst) Equal(other Match) bool {
	if m.MatchType() != other.MatchType() {
		return false
	}
	return IPRangeV4(m).Equal(IPRangeV4(other.(MatchIPRangeV4Dst)))
}

// Port match

// PortRange e.g. 80, 80:90, 80-90
type PortRange RangeT[uint16]

func (r PortRange) IsIn(v uint16) bool {
	return RangeT[uint16](r).IsIn(v)
}

func (r PortRange) Equal(other PortRange) bool {
	return RangeT[uint16](r).Equal(RangeT[uint16](other))
}

func (PortRange) Type() string {
	return "portrange"
}

func (pr PortRange) String() string {
	if pr.Start == pr.End {
		return strconv.Itoa(int(pr.Start))
	}
	return fmt.Sprintf("%d:%d", pr.Start, pr.End)
}

func (pr *PortRange) Set(s string) error {
	var (
		fields []string
		start  uint16
		end    uint16
	)

	if strings.IndexByte(s, ':') != -1 {
		fields = strings.Split(s, ":")
	} else if strings.IndexByte(s, '-') != -1 {
		fields = strings.Split(s, "-")
	} else {
		fields = []string{s}
	}
	if len(fields) != 1 && len(fields) != 2 {
		return fmt.Errorf("invalid portrange: %s", s)
	}

	if len(fields) >= 1 {
		port, err := strconv.Atoi(fields[0])
		if err != nil {
			return fmt.Errorf("invalid start port: %s", fields[0])
		}
		start = uint16(port)
		end = start

		if len(fields) == 2 {
			port, err := strconv.Atoi(fields[1])
			if err != nil {
				return fmt.Errorf("invalid end port: %s", fields[1])
			}
			end = uint16(port)
		}
	}

	if start > end {
		return fmt.Errorf("invalid end port: %d, less than start: %d", end, start)
	}
	pr.Start = start
	pr.End = end
	return nil
}

type MatchPortRangeSrc PortRange

func (MatchPortRangeSrc) MatchType() MatchType { return MatchTypePortRangeSrc }
func (m MatchPortRangeSrc) Match(pkt *fastpkt.Packet) bool {
	return PortRange(m).IsIn(pkt.SrcPort)
}
func (m MatchPortRangeSrc) Equal(other Match) bool {
	if m.MatchType() != other.MatchType() {
		return false
	}
	return PortRange(m).Equal(PortRange(other.(MatchPortRangeSrc)))
}

type MatchPortRangeDst PortRange

func (MatchPortRangeDst) MatchType() MatchType { return MatchTypePortRangeDst }
func (m MatchPortRangeDst) Match(pkt *fastpkt.Packet) bool {
	return PortRange(m).IsIn(pkt.DstPort)
}
func (m MatchPortRangeDst) Equal(other Match) bool {
	if m.MatchType() != other.MatchType() {
		return false
	}
	return PortRange(m).Equal(PortRange(other.(MatchPortRangeDst)))
}

// MultiPort e.g. 80,81
type MultiPort []uint16

func (MultiPort) Type() string {
	return "multiport"
}

func (mp MultiPort) String() string {
	s := make([]string, 0, len(mp))
	for _, v := range mp {
		s = append(s, strconv.Itoa(int(v)))
	}
	return strings.Join(s, ",")
}

func (mp *MultiPort) Set(s string) error {
	if strings.TrimSpace(s) == "" {
		*mp = MultiPort{}
		return nil
	}

	ports := []uint16{}
	fields := strings.Split(s, ",")
	for _, field := range fields {
		port, err := strconv.Atoi(field)
		if err != nil {
			return err
		}
		if !slices.Contains(ports, uint16(port)) {
			ports = append(ports, uint16(port))
		}
	}

	*mp = MultiPort(ports)
	return nil
}

func (m MultiPort) Equal(other MultiPort) bool {
	return slices.Compare(m, other) == 0
}

type MatchMultiPortSrc MultiPort

func (MatchMultiPortSrc) MatchType() MatchType             { return MatchTypeMultiPortSrc }
func (m MatchMultiPortSrc) Match(pkt *fastpkt.Packet) bool { return slices.Contains(m, pkt.SrcPort) }
func (m MatchMultiPortSrc) Equal(other Match) bool {
	if m.MatchType() != other.MatchType() {
		return false
	}
	return MultiPort(m).Equal(MultiPort(other.(MatchMultiPortSrc)))
}

type MatchMultiPortDst MultiPort

func (MatchMultiPortDst) MatchType() MatchType             { return MatchTypeMultiPortDst }
func (m MatchMultiPortDst) Match(pkt *fastpkt.Packet) bool { return slices.Contains(m, pkt.DstPort) }
func (m MatchMultiPortDst) Equal(other Match) bool {
	if m.MatchType() != other.MatchType() {
		return false
	}
	return MultiPort(m).Equal(MultiPort(other.(MatchMultiPortDst)))
}

// MatchTCP
type MatchTCP struct {
	SYN bool `json:"syn,omitempty"`
	ACK bool `json:"ack,omitempty"`
	PSH bool `json:"psh,omitempty"`
	FIN bool `json:"fin,omitempty"`
	RST bool `json:"rst,omitempty"`
}

func (MatchTCP) MatchType() MatchType {
	return MatchTypeTCP
}

func (m MatchTCP) Match(pkt *fastpkt.Packet) bool {
	return true
}

func (m MatchTCP) Equal(other Match) bool {
	if m.MatchType() != other.MatchType() {
		return false
	}
	t := other.(MatchTCP)
	return m.SYN == t.SYN && m.ACK == t.ACK && m.PSH == t.PSH && m.FIN == t.FIN && m.RST == t.RST
}

// MatchUDP
type MatchUDP struct{}

func (MatchUDP) MatchType() MatchType {
	return MatchTypeUDP
}

func (m MatchUDP) Match(pkt *fastpkt.Packet) bool {
	return true
}

func (m MatchUDP) Equal(other Match) bool {
	return true
}

// MatchICMP
type MatchICMP struct {
	Type uint8 `json:"type,omitempty"`
}

func (MatchICMP) MatchType() MatchType {
	return MatchTypeICMP
}

func (m MatchICMP) Match(pkt *fastpkt.Packet) bool {
	if pkt.L4Proto != unix.IPPROTO_ICMP {
		return false
	}

	icmp := fastpkt.DataPtrICMPHeader(pkt.RxData, int(pkt.L2Len+pkt.L3Len))
	if m.Type != 0 && icmp.Type != m.Type {
		return false
	}

	return true
}

func (m MatchICMP) Equal(other Match) bool {
	if m.MatchType() != other.MatchType() {
		return false
	}
	i := other.(MatchICMP)
	return m.Type == i.Type
}

// MatchHTTP
type MatchHTTP struct {
	Host    string `json:"host,omitempty"`
	URI     string `json:"uri,omitempty"`
	Method  string `json:"method,omitempty"`
	Version string `json:"version,omitempty"`
}

func (MatchHTTP) MatchType() MatchType {
	return MatchTypeHTTP
}

func (m MatchHTTP) Match(pkt *fastpkt.Packet) bool {
	return false
}

func (m MatchHTTP) Equal(other Match) bool {
	if m.MatchType() != other.MatchType() {
		return false
	}
	h := other.(MatchHTTP)
	return m.Host == h.Host && m.URI == h.URI && m.Method == h.Method && m.Version == h.Version
}

// MatchARP
type MatchARP struct {
	Operation uint16 `json:"operation,omitempty"`
}

func (MatchARP) MatchType() MatchType {
	return MatchTypeARP
}

func (m MatchARP) Match(pkt *fastpkt.Packet) bool {
	arp := fastpkt.DataPtrARPHeader(pkt.RxData, int(pkt.L2Len))
	return pkt.L3Proto == unix.ETH_P_ARP && inet.Ntohs(arp.Operation) == m.Operation
}

func (m MatchARP) Equal(other Match) bool {
	if m.MatchType() != other.MatchType() {
		return false
	}
	a := other.(MatchARP)
	return m.Operation == a.Operation
}

type MatchTypeValue struct {
	MatchType  MatchType `json:"type,omitempty"`
	MatchValue string    `json:"value,omitempty"`
}

func MatchFromTypeValue(tv *MatchTypeValue) (Match, error) {
	switch tv.MatchType {
	case MatchTypeARP:
		return matchFromValue[MatchARP](tv.MatchValue)
	case MatchTypeLPMIPv4Src:
		return matchFromValue[MatchLPMIPv4Src](tv.MatchValue)
	case MatchTypeLPMIPv4Dst:
		return matchFromValue[MatchLPMIPv4Dst](tv.MatchValue)
	case MatchTypeIPRangeV4Src:
		return matchFromValue[MatchIPRangeV4Src](tv.MatchValue)
	case MatchTypeIPRangeV4Dst:
		return matchFromValue[MatchIPRangeV4Dst](tv.MatchValue)
	case MatchTypeMultiPortSrc:
		return matchFromValue[MatchMultiPortSrc](tv.MatchValue)
	case MatchTypeMultiPortDst:
		return matchFromValue[MatchMultiPortDst](tv.MatchValue)
	case MatchTypePortRangeSrc:
		return matchFromValue[MatchPortRangeSrc](tv.MatchValue)
	case MatchTypePortRangeDst:
		return matchFromValue[MatchPortRangeDst](tv.MatchValue)
	case MatchTypeTCP:
		return matchFromValue[MatchTCP](tv.MatchValue)
	case MatchTypeUDP:
		return matchFromValue[MatchUDP](tv.MatchValue)
	case MatchTypeICMP:
		return matchFromValue[MatchICMP](tv.MatchValue)
	case MatchTypeHTTP:
		return matchFromValue[MatchHTTP](tv.MatchValue)
	default:
		return nil, fmt.Errorf("invalid match type: %d", tv.MatchType)
	}
}

func matchFromValue[T Match](v string) (T, error) {
	var m T
	return m, json.Unmarshal([]byte(v), &m)
}
