package rule

import (
	"encoding/json"
	"fmt"

	"github.com/zxhio/xdpass/pkg/fastpkt"
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
	ID       int              `json:"id,omitempty"`
	Matchers []matcherWrapper `json:"matchers"`
	Target   *targetWrapper   `json:"target"`
	Bytes    uint64           `json:"bytes,omitempty"`
	Packets  uint64           `json:"packets,omitempty"`
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
		data, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		wrappedMatchers = append(wrappedMatchers, matcherWrapper{Type: m.MatchType(), Value: data})
	}

	// Target
	var wrappedTarget *targetWrapper
	if r.Target != nil {
		data, err := json.Marshal(r.Target)
		if err != nil {
			return nil, err
		}
		wrappedTarget = &targetWrapper{Type: r.Target.TargetType(), Value: data}
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
		unmarshal, ok := matchTypeToUnmarshaler[mw.Type]
		if !ok {
			return fmt.Errorf("unsupported match type: %v", mw.Type)
		}
		m, err := unmarshal(mw.Value)
		if err != nil {
			return err
		}
		r.Matchers[i] = m
	}

	// Target
	if w.Target != nil {
		unmarshal, ok := targetTypeToUnmarshaler[w.Target.Type]
		if !ok {
			return fmt.Errorf("unsupported target type: %v", w.Target.Type)
		}
		tgt, err := unmarshal(w.Target.Value)
		if err != nil {
			return err
		}
		r.Target = tgt
	}

	r.Bytes = w.Bytes
	r.Packets = w.Packets
	return nil
}

type unmarshaler[T any] func([]byte) (T, error)

func matcherhUnmarshal[T Matcher]() func([]byte) (Matcher, error) {
	return func(data []byte) (Matcher, error) {
		var v T
		err := json.Unmarshal(data, &v)
		return v, err
	}
}

func targethUnmarshal[T Target]() func([]byte) (Target, error) {
	return func(data []byte) (Target, error) {
		var v T
		err := json.Unmarshal(data, &v)
		return v, err
	}
}

var (
	matchTypeToUnmarshaler  map[MatchType]unmarshaler[Matcher]
	targetTypeToUnmarshaler map[TargetType]unmarshaler[Target]
)

func addMatcherUnmarshaler[T Matcher](v T) {
	matchTypeToUnmarshaler[v.MatchType()] = matcherhUnmarshal[T]()
}

func addTargetUnmarshaler[T Target](v T) {
	targetTypeToUnmarshaler[v.TargetType()] = targethUnmarshal[T]()
}

func init() {
	matchTypeToUnmarshaler = make(map[MatchType]unmarshaler[Matcher])
	targetTypeToUnmarshaler = make(map[TargetType]unmarshaler[Target])

	// Matcher
	addMatcherUnmarshaler(MatchIPv4PrefixSrc{})
	addMatcherUnmarshaler(MatchIPv4PrefixDst{})
	addMatcherUnmarshaler(MatchIPv4RangeSrc{})
	addMatcherUnmarshaler(MatchIPv4RangeDst{})
	addMatcherUnmarshaler(MatchMultiPortSrc{})
	addMatcherUnmarshaler(MatchMultiPortDst{})
	addMatcherUnmarshaler(MatchPortRangeSrc{})
	addMatcherUnmarshaler(MatchPortRangeDst{})
	addMatcherUnmarshaler(MatchARP{})
	addMatcherUnmarshaler(MatchTCP{})
	addMatcherUnmarshaler(MatchUDP{})
	addMatcherUnmarshaler(MatchICMP{})
	addMatcherUnmarshaler(MatchHTTP{})
	addMatcherUnmarshaler(MatchTCPFlags(0))

	// Target
	addTargetUnmarshaler(MirrorStdout{})
	addTargetUnmarshaler(&MirrorTap{})
	addTargetUnmarshaler(TargetARPReplySpoof{})
	addTargetUnmarshaler(TargetTCPSpoofSYNACK{})
	addTargetUnmarshaler(TargetTCPSpoofRSTACK{})
	addTargetUnmarshaler(TargetTCPSpoofPSHACK{})
	addTargetUnmarshaler(TargetTCPSpoofFINACK{})
	addTargetUnmarshaler(TargetTCPSpoofACK{})
	addTargetUnmarshaler(TargetICMPEchoReplySpoof{})
	addTargetUnmarshaler(TargetHTTPRespSpoofNotFound{})
}
