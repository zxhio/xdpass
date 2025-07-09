package rule

import (
	"encoding/json"
	"fmt"

	"github.com/zxhio/xdpass/pkg/netaddr"
)

type Rule struct {
	ID     int
	Matchs []Match
	Target Target
}

type matchWrapper struct {
	Type  MatchType       `json:"type"`
	Value json.RawMessage `json:"value"`
}

type targetWrapper struct {
	Type  TargetType      `json:"type"`
	Value json.RawMessage `json:"value"`
}

type ruleWrapper struct {
	ID     int            `json:"id"`
	Matchs []matchWrapper `json:"matchs"`
	Target targetWrapper  `json:"target"`
}

func (r Rule) MarshalJSON() ([]byte, error) {
	// Match
	wrappedMatchs := make([]matchWrapper, 0, len(r.Matchs))
	for _, m := range r.Matchs {
		ser, ok := matchTypeToSerializer[m.MatchType()]
		if !ok {
			return nil, fmt.Errorf("unsupported match type: %v", m.MatchType())
		}
		data, err := ser.marshaler(m)
		if err != nil {
			return nil, err
		}
		wrappedMatchs = append(wrappedMatchs, matchWrapper{Type: m.MatchType(), Value: data})
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

	return json.Marshal(ruleWrapper{ID: r.ID, Matchs: wrappedMatchs, Target: wrappedTarget})
}

func (r *Rule) UnmarshalJSON(data []byte) error {
	var w ruleWrapper
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	r.ID = w.ID

	// Match
	r.Matchs = make([]Match, len(w.Matchs))
	for i, mw := range w.Matchs {
		ser, ok := matchTypeToSerializer[mw.Type]
		if !ok {
			return fmt.Errorf("unsupported match type: %v", mw.Type)
		}
		m, err := ser.unmarshaler(mw.Value)
		if err != nil {
			return err
		}
		r.Matchs[i] = m
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

	return nil
}

type serializer[T any] struct {
	marshaler   func(T) ([]byte, error)
	unmarshaler func([]byte) (T, error)
}

var matchTypeToSerializer = map[MatchType]serializer[Match]{
	MatchTypeIPv4PrefixSrc: {
		matchTypeMarshal(func(m Match) netaddr.IPv4Prefix { return netaddr.IPv4Prefix(m.(MatchIPv4PrefixSrc)) }),
		matchTypeUnmarshal(func(v netaddr.IPv4Prefix) Match { return MatchIPv4PrefixSrc(v) }),
	},
	MatchTypeIPv4PrefixDst: {
		matchTypeMarshal(func(m Match) netaddr.IPv4Prefix { return netaddr.IPv4Prefix(m.(MatchIPv4PrefixDst)) }),
		matchTypeUnmarshal(func(v netaddr.IPv4Prefix) Match { return MatchIPv4PrefixDst(v) }),
	},
	MatchTypeIPv4RangeSrc: {
		matchTypeMarshal(func(m Match) netaddr.IPv4Range { return netaddr.IPv4Range(m.(MatchIPv4RangeSrc)) }),
		matchTypeUnmarshal(func(v netaddr.IPv4Range) Match { return MatchIPv4RangeSrc(v) }),
	},
	MatchTypeIPv4RangeDst: {
		matchTypeMarshal(func(m Match) netaddr.IPv4Range { return netaddr.IPv4Range(m.(MatchIPv4RangeDst)) }),
		matchTypeUnmarshal(func(v netaddr.IPv4Range) Match { return MatchIPv4RangeDst(v) }),
	},
	MatchTypeMultiPortSrc: {
		matchTypeMarshal(func(m Match) netaddr.MultiPort { return netaddr.MultiPort(m.(MatchMultiPortSrc)) }),
		matchTypeUnmarshal(func(v netaddr.MultiPort) Match { return MatchMultiPortSrc(v) }),
	},
	MatchTypeMultiPortDst: {
		matchTypeMarshal(func(m Match) netaddr.MultiPort { return netaddr.MultiPort(m.(MatchMultiPortDst)) }),
		matchTypeUnmarshal(func(v netaddr.MultiPort) Match { return MatchMultiPortDst(v) }),
	},
	MatchTypePortRangeSrc: {
		matchTypeMarshal(func(m Match) netaddr.PortRange { return netaddr.PortRange(m.(MatchPortRangeSrc)) }),
		matchTypeUnmarshal(func(v netaddr.PortRange) Match { return MatchPortRangeSrc(v) }),
	},
	MatchTypePortRangeDst: {
		matchTypeMarshal(func(m Match) netaddr.PortRange { return netaddr.PortRange(m.(MatchPortRangeDst)) }),
		matchTypeUnmarshal(func(v netaddr.PortRange) Match { return MatchPortRangeDst(v) }),
	},
	MatchTypeARP: {
		matchTypeMarshal(func(m Match) MatchARP { return m.(MatchARP) }),
		matchTypeUnmarshal(func(v MatchARP) Match { return v }),
	},
	MatchTypeTCP: {
		matchTypeMarshal(func(m Match) MatchTCP { return m.(MatchTCP) }),
		matchTypeUnmarshal(func(v MatchTCP) Match { return v }),
	},
	MatchTypeUDP: {
		matchTypeMarshal(func(m Match) MatchUDP { return m.(MatchUDP) }),
		matchTypeUnmarshal(func(v MatchUDP) Match { return v }),
	},
	MatchTypeICMP: {
		matchTypeMarshal(func(m Match) MatchICMP { return m.(MatchICMP) }),
		matchTypeUnmarshal(func(v MatchICMP) Match { return v }),
	},
	MatchTypeHTTP: {
		matchTypeMarshal(func(m Match) MatchHTTP { return m.(MatchHTTP) }),
		matchTypeUnmarshal(func(v MatchHTTP) Match { return v }),
	},
	MatchTypeTCPFlags: {
		matchTypeMarshal(func(m Match) MatchTCPFlags { return m.(MatchTCPFlags) }),
		matchTypeUnmarshal(func(v MatchTCPFlags) Match { return v }),
	},
}

func matchTypeMarshal[T any](m2v func(m Match) T) func(Match) ([]byte, error) {
	return func(m Match) ([]byte, error) { return json.Marshal(m2v(m)) }
}

func matchTypeUnmarshal[T any](v2m func(T) Match) func([]byte) (Match, error) {
	return func(data []byte) (Match, error) {
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
	registerTargetSerializer(MirrorTap{})
	registerTargetSerializer(TargetARPReplySpoof{})
	registerTargetSerializer(TargetTCPSpoofSYNACK{})
	registerTargetSerializer(TargetTCPSpoofRSTACK{})
	registerTargetSerializer(TargetTCPSpoofPSHACK{})
	registerTargetSerializer(TargetTCPSpoofFINACK{})
	registerTargetSerializer(TargetTCPSpoofACK{})
	registerTargetSerializer(TargetICMPEchoReplySpoof{})
	registerTargetSerializer(TargetHTTPRespSpoofNotFound{})
}
