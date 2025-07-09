package rule

import (
	"encoding/json"
	"fmt"

	"github.com/zxhio/xdpass/pkg/fastpkt"
)

type TargetType int

const (
	// Mirror
	TargetTypeMirrorStdout TargetType = iota + 1
	TargetTypeMirrorTap

	// Protocol
	// ARP
	TargetTypeARPSpoofReply

	// ICMP
	TargetTypeICMPSpoofEchoReply

	// TCP
	TargetTypeTCPSpoofSYNACK
	TargetTypeTCPSpoofRSTACK
	TargetTypeTCPSpoofFINACK
	TargetTypeTCPSpoofPSHACK
	TargetTypeTCPSpoofACK

	// HTTP
	TargetTypeHTTPSpoofNotFound
)

var TargetMirrorTypes = []TargetType{
	TargetTypeMirrorStdout,
	TargetTypeMirrorTap,
}

var targetTypeToStr = map[TargetType]string{
	TargetTypeMirrorStdout:       "mirror-stdout",
	TargetTypeMirrorTap:          "mirror-tap",
	TargetTypeARPSpoofReply:      "spoof-arp-reply",
	TargetTypeTCPSpoofSYNACK:     "spoof-syn-ack",
	TargetTypeTCPSpoofRSTACK:     "spoof-rst-ack",
	TargetTypeTCPSpoofFINACK:     "spoof-fin-ack",
	TargetTypeTCPSpoofPSHACK:     "spoof-psh-ack",
	TargetTypeTCPSpoofACK:        "spoof-ack",
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
