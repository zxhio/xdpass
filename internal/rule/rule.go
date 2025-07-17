package rule

import (
	"encoding/json"
	"fmt"

	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

type Rule struct {
	ID       int
	Matchers []Matcher
	Target   Target
	Bytes    uint64
	Packets  uint64
}

type matcherWrapper struct {
	Type  MatchType       `json:"type"`
	Value json.RawMessage `json:"value"`
}

type targetWrapper struct {
	Type  TargetType      `json:"type"`
	Value json.RawMessage `json:"value"`
}

type ruleWrapper struct {
	ID       int              `json:"id"`
	Matchers []matcherWrapper `json:"matchers"`
	Target   targetWrapper    `json:"target"`
	Bytes    uint64           `json:"bytes"`
	Packets  uint64           `json:"packets"`
}

func (r *Rule) Match(pkt *fastpkt.Packet) bool {
	for _, m := range r.Matchers {
		if !m.Match(pkt) {
			return false
		}
	}
	return true
}

func (r Rule) MarshalJSON() ([]byte, error) {
	// Match
	wrappedMatchers := make([]matcherWrapper, 0, len(r.Matchers))
	for _, m := range r.Matchers {
		ser, ok := matchTypeToSerializer[m.MatchType()]
		if !ok {
			return nil, fmt.Errorf("unsupported match type: %v", m.MatchType())
		}
		data, err := ser.marshaler(m)
		if err != nil {
			return nil, err
		}
		wrappedMatchers = append(wrappedMatchers, matcherWrapper{Type: m.MatchType(), Value: data})
	}

	// Target
	var wrappedTarget targetWrapper
	if r.Target != nil {
		ser, ok := targetTypeToSerializer[r.Target.TargetType()]
		if !ok {
			return nil, fmt.Errorf("unsupported target type: %v", r.Target.TargetType())
		}
		data, err := ser.marshaler(r.Target)
		if err != nil {
			return nil, err
		}
		wrappedTarget = targetWrapper{Type: r.Target.TargetType(), Value: data}
	}

	return json.Marshal(ruleWrapper{
		ID:       r.ID,
		Matchers: wrappedMatchers,
		Target:   wrappedTarget,
		Bytes:    r.Bytes,
		Packets:  r.Packets,
	})
}

func (r *Rule) UnmarshalJSON(data []byte) error {
	var w ruleWrapper
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	r.ID = w.ID

	// Match
	r.Matchers = make([]Matcher, len(w.Matchers))
	for i, mw := range w.Matchers {
		ser, ok := matchTypeToSerializer[mw.Type]
		if !ok {
			return fmt.Errorf("unsupported match type: %v", mw.Type)
		}
		m, err := ser.unmarshaler(mw.Value)
		if err != nil {
			return err
		}
		r.Matchers[i] = m
	}

	// Target
	ser, ok := targetTypeToSerializer[w.Target.Type]
	if !ok {
		return fmt.Errorf("unsupported target type: %v", w.Target.Type)
	}
	tgt, err := ser.unmarshaler(w.Target.Value)
	if err != nil {
		return err
	}
	r.Target = tgt

	r.Bytes = w.Bytes
	r.Packets = w.Packets
	return nil
}

type serializer[T any] struct {
	marshaler   func(T) ([]byte, error)
	unmarshaler func([]byte) (T, error)
}

var matchTypeToSerializer = map[MatchType]serializer[Matcher]{
	MatchTypeIPv4PrefixSrc: {
		matchTypeMarshal(func(m Matcher) netaddr.IPv4Prefix { return netaddr.IPv4Prefix(m.(MatchIPv4PrefixSrc)) }),
		matchTypeUnmarshal(func(v netaddr.IPv4Prefix) Matcher { return MatchIPv4PrefixSrc(v) }),
	},
	MatchTypeIPv4PrefixDst: {
		matchTypeMarshal(func(m Matcher) netaddr.IPv4Prefix { return netaddr.IPv4Prefix(m.(MatchIPv4PrefixDst)) }),
		matchTypeUnmarshal(func(v netaddr.IPv4Prefix) Matcher { return MatchIPv4PrefixDst(v) }),
	},
	MatchTypeIPv4RangeSrc: {
		matchTypeMarshal(func(m Matcher) netaddr.IPv4Range { return netaddr.IPv4Range(m.(MatchIPv4RangeSrc)) }),
		matchTypeUnmarshal(func(v netaddr.IPv4Range) Matcher { return MatchIPv4RangeSrc(v) }),
	},
	MatchTypeIPv4RangeDst: {
		matchTypeMarshal(func(m Matcher) netaddr.IPv4Range { return netaddr.IPv4Range(m.(MatchIPv4RangeDst)) }),
		matchTypeUnmarshal(func(v netaddr.IPv4Range) Matcher { return MatchIPv4RangeDst(v) }),
	},
	MatchTypeMultiPortSrc: {
		matchTypeMarshal(func(m Matcher) netaddr.MultiPort { return netaddr.MultiPort(m.(MatchMultiPortSrc)) }),
		matchTypeUnmarshal(func(v netaddr.MultiPort) Matcher { return MatchMultiPortSrc(v) }),
	},
	MatchTypeMultiPortDst: {
		matchTypeMarshal(func(m Matcher) netaddr.MultiPort { return netaddr.MultiPort(m.(MatchMultiPortDst)) }),
		matchTypeUnmarshal(func(v netaddr.MultiPort) Matcher { return MatchMultiPortDst(v) }),
	},
	MatchTypePortRangeSrc: {
		matchTypeMarshal(func(m Matcher) netaddr.PortRange { return netaddr.PortRange(m.(MatchPortRangeSrc)) }),
		matchTypeUnmarshal(func(v netaddr.PortRange) Matcher { return MatchPortRangeSrc(v) }),
	},
	MatchTypePortRangeDst: {
		matchTypeMarshal(func(m Matcher) netaddr.PortRange { return netaddr.PortRange(m.(MatchPortRangeDst)) }),
		matchTypeUnmarshal(func(v netaddr.PortRange) Matcher { return MatchPortRangeDst(v) }),
	},
	MatchTypeARP: {
		matchTypeMarshal(func(m Matcher) MatchARP { return m.(MatchARP) }),
		matchTypeUnmarshal(func(v MatchARP) Matcher { return v }),
	},
	MatchTypeTCP: {
		matchTypeMarshal(func(m Matcher) MatchTCP { return m.(MatchTCP) }),
		matchTypeUnmarshal(func(v MatchTCP) Matcher { return v }),
	},
	MatchTypeUDP: {
		matchTypeMarshal(func(m Matcher) MatchUDP { return m.(MatchUDP) }),
		matchTypeUnmarshal(func(v MatchUDP) Matcher { return v }),
	},
	MatchTypeICMP: {
		matchTypeMarshal(func(m Matcher) MatchICMP { return m.(MatchICMP) }),
		matchTypeUnmarshal(func(v MatchICMP) Matcher { return v }),
	},
	MatchTypeHTTP: {
		matchTypeMarshal(func(m Matcher) MatchHTTP { return m.(MatchHTTP) }),
		matchTypeUnmarshal(func(v MatchHTTP) Matcher { return v }),
	},
	MatchTypeTCPFlags: {
		matchTypeMarshal(func(m Matcher) MatchTCPFlags { return m.(MatchTCPFlags) }),
		matchTypeUnmarshal(func(v MatchTCPFlags) Matcher { return v }),
	},
}

func matchTypeMarshal[T any](m2v func(m Matcher) T) func(Matcher) ([]byte, error) {
	return func(m Matcher) ([]byte, error) { return json.Marshal(m2v(m)) }
}

func matchTypeUnmarshal[T any](v2m func(T) Matcher) func([]byte) (Matcher, error) {
	return func(data []byte) (Matcher, error) {
		var v T
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, err
		}
		return v2m(v), nil
	}
}

var targetTypeToSerializer = map[TargetType]serializer[Target]{}

func registerTargetSerializer[T Target](v T) {
	targetTypeToSerializer[v.TargetType()] = serializer[Target]{
		marshaler:   targetTypeMarshal[T](),
		unmarshaler: targetTypeUnmarshal(func(v T) Target { return T(v) }),
	}
}

func targetTypeMarshal[T any]() func(Target) ([]byte, error) {
	return func(t Target) ([]byte, error) { return json.Marshal(t.(T)) }
}

func targetTypeUnmarshal[T any](v2t func(T) Target) func([]byte) (Target, error) {
	return func(data []byte) (Target, error) {
		var v T
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, err
		}
		return v2t(v), nil
	}
}

func init() {
	registerTargetSerializer(MirrorStdout{})
	registerTargetSerializer(&MirrorTap{})
	registerTargetSerializer(TargetARPReplySpoof{})
	registerTargetSerializer(TargetTCPSpoofSYNACK{})
	registerTargetSerializer(TargetTCPSpoofRSTACK{})
	registerTargetSerializer(TargetTCPSpoofPSHACK{})
	registerTargetSerializer(TargetTCPSpoofFINACK{})
	registerTargetSerializer(TargetTCPSpoofACK{})
	registerTargetSerializer(TargetICMPEchoReplySpoof{})
	registerTargetSerializer(TargetHTTPRespSpoofNotFound{})
}
