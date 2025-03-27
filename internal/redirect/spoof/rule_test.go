package spoof

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zxhio/xdpass/pkg/netutil"
)

func TestRuleEqual(t *testing.T) {
	testCases := []struct {
		r1 Rule
		r2 Rule
		eq bool
	}{
		{
			Rule{
				Matchs: []Match{MatchMultiPortDst{80}},
				Target: TargetTCPReset{},
			},
			Rule{
				Matchs: []Match{MatchMultiPortDst{80}},
				Target: TargetTCPReset{},
			},
			true,
		},
		{
			Rule{
				Matchs: []Match{MatchMultiPortDst{80}},
				Target: TargetTCPReset{},
			},
			Rule{
				Matchs: []Match{MatchMultiPortSrc{80}},
				Target: TargetTCPReset{},
			},
			false,
		},
		{
			Rule{
				Matchs: []Match{MatchMultiPortDst{80}},
				Target: TargetTCPReset{},
			},
			Rule{
				Matchs: []Match{MatchMultiPortDst{8080}},
				Target: TargetTCPReset{},
			},
			false,
		},
		{
			Rule{
				Matchs: []Match{MatchLPMIPv4Src{IP: 123456, PrefixLen: 32}},
				Target: TargetTCPReset{},
			},
			Rule{
				Matchs: []Match{MatchLPMIPv4Src{IP: 123456, PrefixLen: 32}},
				Target: TargetARPReply{},
			},
			false,
		},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.eq, tc.r1.Equal(&tc.r2), tc.r1.String())
	}
}

func TestRuleMarshal(t *testing.T) {
	rule := Rule{
		Matchs: []Match{
			MatchARP{Operation: ARPOperationRequest},
			MatchLPMIPv4Dst{IP: LPMIPv4Uint32(netutil.IPv4ToUint32(net.ParseIP("172.16.23.1"))), PrefixLen: 32},
		},
		Target: TargetARPReply{HwAddr: [6]byte{1, 2, 3, 4, 5, 6}},
	}

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))

	var rule2 Rule
	err = json.Unmarshal(data, &rule2)
	if err != nil {
		t.Fatal(err)
	}
}
