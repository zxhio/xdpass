package spoof

import (
	"encoding/json"
	"slices"
)

type RuleData struct {
	ID     uint32           `json:"id"`
	Matchs []MatchTypeValue `json:"matchs"`
	Target TargetTypeValue  `json:"target"`
}

type Rule struct {
	ID     uint32
	Matchs []Match
	Target Target
}

func (rule *Rule) Equal(other *Rule) bool {
	if len(rule.Matchs) != len(other.Matchs) {
		return false
	}

	if slices.CompareFunc(rule.Matchs, other.Matchs, func(l, r Match) int {
		if l.Equal(r) {
			return 0
		}
		return 1
	}) != 0 {
		return false
	}
	return rule.Target.Equal(other.Target)
}

func (rule Rule) String() string {
	data, _ := json.Marshal(rule)
	return string(data)
}

func (rule Rule) MarshalJSON() ([]byte, error) {
	var matchs []MatchTypeValue
	for _, m := range rule.Matchs {
		data, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		matchs = append(matchs, MatchTypeValue{
			MatchType:  m.MatchType(),
			MatchValue: string(data),
		})
	}

	data, err := json.Marshal(rule.Target)
	if err != nil {
		return nil, err
	}
	tgt := TargetTypeValue{
		TargetType:  rule.Target.TargetType(),
		TargetValue: string(data),
	}

	rd := RuleData{ID: rule.ID, Matchs: matchs, Target: tgt}
	return json.Marshal(rd)
}

func (t *Rule) UnmarshalJSON(data []byte) error {
	var rd RuleData
	if err := json.Unmarshal(data, &rd); err != nil {
		return err
	}

	var matchs []Match
	for _, tv := range rd.Matchs {
		m, err := MatchFromTypeValue(&tv)
		if err != nil {
			return err
		}
		matchs = append(matchs, m)
	}

	tgt, err := TargetFromTypeValue(&rd.Target)
	if err != nil {
		return err
	}

	*t = Rule{ID: rd.ID, Matchs: matchs, Target: tgt}
	return nil
}

type RuleSlice []Rule

func (s RuleSlice) Len() int           { return len(s) }
func (s RuleSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s RuleSlice) Less(i, j int) bool { return s[i].ID < s[j].ID }
