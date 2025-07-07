package rule

import (
	"encoding/json"
	"fmt"

	"github.com/zxhio/xdpass/pkg/fastpkt"
)

const (
	iotaARP = iota*1000 + 1001
	iotaTCP
	iotaICMP
	iotaUDP
	iotaHTTP
)

type TargetType int

// ARP
const (
	TargetTypeARPSpoofReply = iota + iotaARP
)

// ICMP
const (
	TargetTypeICMPSpoofEchoReply = iota + iotaICMP
)

// TCP
const (
	TargetTypeTCPResetHandshake = iota + iotaTCP
	TargetTypeTCPSpoofHandshake
)

// HTTP
const (
	TargetTypeHTTPSpoofNotFound = iota + iotaHTTP
)

var targetTypeToStr = map[TargetType]string{
	TargetTypeARPSpoofReply:      "spoof-arp-reply",
	TargetTypeTCPResetHandshake:  "reset-handshake",
	TargetTypeTCPSpoofHandshake:  "spoof-handshake",
	TargetTypeICMPSpoofEchoReply: "spoof-echo-reply",
	TargetTypeHTTPSpoofNotFound:  "spoof-not-found",
}

var strToTargetType = make(map[string]TargetType)

func init() {
	for targetType, str := range targetTypeToStr {
		strToTargetType[str] = targetType
	}
}

func (t TargetType) String() string {
	return targetTypeToStr[t]
}

func (t *TargetType) Set(s string) error {
	if targetType, ok := strToTargetType[s]; ok {
		*t = targetType
		return nil
	}
	return fmt.Errorf("invalid target type: %s", s)
}

func (t TargetType) MarshalJSON() ([]byte, error) {
	s := t.String()
	if s == "" {
		return nil, fmt.Errorf("invalid target type: %d", t)
	}
	return json.Marshal(s)
}

func (t *TargetType) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	return t.Set(s)
}

func (t TargetType) Compare(t1 TargetType) int {
	return int(t - t1)
}

type Target interface {
	TargetType() TargetType
	MatchTypes() []MatchType
	Execute(pkt *fastpkt.Packet) error
	Compare(other Target) int
}

func CompareTargetType(t1, t2 Target) int {
	return t1.TargetType().Compare(t2.TargetType())
}
