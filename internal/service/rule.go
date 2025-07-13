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

func (s *RuleService) QueryRules(matchTypes []rule.MatchType, page, limit int) ([]*rule.Rule, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	validateMatch := func(r *rule.Rule) bool {
		if len(matchTypes) == 0 {
			return true
		}
		return slices.ContainsFunc(r.Matchs, func(m rule.Match) bool {
			return slices.Contains(matchTypes, m.MatchType())
		})
	}

	data, total := utils.LimitPageSliceFunc(s.rules, page, limit, validateMatch)
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
