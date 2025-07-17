package rule

import (
	"encoding/json"
	"fmt"

	"github.com/zxhio/xdpass/pkg/fastpkt"
)

type MatchType int

const (
	// MAC
	MatchTypeSrcMAC MatchType = iota + 1
	MatchTypeDstMAC

	// IPv4
	MatchTypeIPv4PrefixSrc
	MatchTypeIPv4PrefixDst
	MatchTypeIPv4RangeSrc
	MatchTypeIPv4RangeDst

	// Port
	MatchTypeMultiPortSrc
	MatchTypeMultiPortDst
	MatchTypePortRangeSrc
	MatchTypePortRangeDst

	// Protocol
	MatchTypeARP
	MatchTypeUDP
	MatchTypeICMP
	MatchTypeTCP
	MatchTypeTCPFlags
	MatchTypeHTTP
)

var matchTypeToStr = map[MatchType]string{
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
	MatchTypeARP:           "ARP",
	MatchTypeUDP:           "UDP",
	MatchTypeICMP:          "ICMP",
	MatchTypeTCP:           "TCP",
	MatchTypeTCPFlags:      "TCPFlags",
	MatchTypeHTTP:          "HTTP",
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

func CompareMatchType(t1, t2 MatchType) int {
	return int(t1 - t2)
}

func GetProtocolMatchTypes() []MatchType {
	return protocolMatchTypes
}

type Matcher interface {
	MatchType() MatchType
	Match(*fastpkt.Packet) bool
	Compare(Matcher) int
}

func CompareMatcherType(m1, m2 Matcher) int {
	return CompareMatchType(m1.MatchType(), m2.MatchType())
}
