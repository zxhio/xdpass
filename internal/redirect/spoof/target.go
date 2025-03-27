package spoof

import (
	"encoding/json"
	"fmt"

	"github.com/zxhio/xdpass/pkg/fastpkt"
)

type TargetType int

const (
	TargetTypeARPReply TargetType = iota + 1
	TargetTypeICMPEchoReply
	TargetTypeTCPReset
)

var targetTypeToStr = map[TargetType]string{
	TargetTypeARPReply:      "arp-reply",
	TargetTypeICMPEchoReply: "icmp-echo-reply",
	TargetTypeTCPReset:      "tcp-reset",
}

var strToTargetType = map[string]TargetType{}

func init() {
	for targetType, str := range targetTypeToStr {
		strToTargetType[str] = targetType
	}
}

type Target interface {
	TargetType() TargetType
	MatchTypes() []MatchType
	Execute(pkt *fastpkt.Packet) error
	Equal(other Target) bool
}

func (t TargetType) String() string {
	return targetTypeToStr[t]
}

func (t *TargetType) Type() string {
	return "target-type"
}

func (t *TargetType) Set(s string) error {
	if targetType, ok := strToTargetType[s]; ok {
		*t = targetType
		return nil
	}
	return fmt.Errorf("invalid match type: %s", s)
}

func (t TargetType) MarshalJSON() ([]byte, error) {
	s := t.String()
	if s == "" {
		return nil, fmt.Errorf("invalid match type: %d", t)
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

type TargetTypeValue struct {
	TargetType  TargetType `json:"type"`
	TargetValue string     `json:"value"`
}

func TargetFromTypeValue(tv *TargetTypeValue) (Target, error) {
	switch tv.TargetType {
	case TargetTypeARPReply:
		return targetFromValue[TargetARPReply](tv.TargetValue)
	case TargetTypeICMPEchoReply:
		return targetFromValue[TargetICMPEchoReply](tv.TargetValue)
	case TargetTypeTCPReset:
		return targetFromValue[TargetTCPReset](tv.TargetValue)
	default:
		return nil, fmt.Errorf("invalid target type: %d", tv.TargetType)
	}
}

func targetFromValue[T Target](v string) (T, error) {
	var t T
	return t, json.Unmarshal([]byte(v), &t)
}
