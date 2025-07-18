package service

import (
	"slices"
	"sync"

	"github.com/pkg/errors"
	"github.com/zxhio/xdpass/internal/rule"
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/utils"
)

type RuleService struct {
	mu        *sync.RWMutex
	ruleID    int
	rules     []*rule.Rule
	mirrors   []*rule.Rule
	protocols []*rule.Rule
}

func NewRuleService() (*RuleService, error) {
	return &RuleService{
		mu:        &sync.RWMutex{},
		rules:     make([]*rule.Rule, 0, 64),
		mirrors:   make([]*rule.Rule, 0, 32),
		protocols: make([]*rule.Rule, 0, 32),
	}, nil
}

func (s *RuleService) QueryRule(ruleID int) (*rule.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idx := slices.IndexFunc(s.rules, ruleIDMatcher(ruleID))
	if idx == -1 {
		return nil, errors.Errorf("no such rule id: %d", ruleID)
	}
	return s.rules[idx], nil
}

func (s *RuleService) QueryRules(matchers []rule.Matcher, target rule.Target, page, limit int) ([]*rule.Rule, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	validate := func(r *rule.Rule) bool {
		if target != nil && r.Target.Compare(target) != 0 {
			return false
		}
		for _, matcher := range matchers {
			if !slices.ContainsFunc(r.Matchers, func(m rule.Matcher) bool { return matcher.Compare(m) == 0 }) {
				return false
			}
		}
		return true
	}
	data, total := utils.LimitPageSliceFunc(s.rules, page, limit, validate)
	return data, total, nil

}

func (s *RuleService) AddRule(r *rule.Rule) (int, error) {
	err := r.Target.Open()
	if err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.ruleID++
	r.ID = s.ruleID
	s.rules = append(s.rules, r)

	if slices.Contains(rule.TargetMirrorTypes, r.Target.TargetType()) {
		s.mirrors = append(s.mirrors, r)
	} else {
		s.protocols = append(s.protocols, r)
	}
	return r.ID, nil
}

func (s *RuleService) DeleteRule(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := slices.IndexFunc(s.rules, ruleIDMatcher(id))
	if idx == -1 {
		return errors.Errorf("no such rule id: %d", id)
	}
	s.rules[idx].Target.Close()

	s.rules = slices.DeleteFunc(s.rules, ruleIDMatcher(id))
	s.mirrors = slices.DeleteFunc(s.mirrors, ruleIDMatcher(id))
	s.protocols = slices.DeleteFunc(s.protocols, ruleIDMatcher(id))
	return nil
}

func ruleIDMatcher(ruleID int) func(r *rule.Rule) bool {
	return func(r *rule.Rule) bool { return r.ID == ruleID }
}

type PacketHandler interface {
	OnPacket(pkt *fastpkt.Packet)
}

func (s *RuleService) OnPacket(pkt *fastpkt.Packet) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Protocol
	for _, r := range s.protocols {
		if r.Match(pkt) {
			r.Bytes += uint64(len(pkt.RxData))
			r.Packets++
			r.Target.Execute(pkt)
			break
		}
	}

	// Mirror
	for _, r := range s.mirrors {
		if r.Match(pkt) {
			r.Bytes += uint64(len(pkt.RxData))
			r.Packets++
			r.Target.Execute(pkt)
		}
	}
}
