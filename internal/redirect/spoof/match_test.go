package spoof

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zxhio/xdpass/pkg/inet"
)

func TestLPMIPv4(t *testing.T) {
	testCases := []struct {
		str string
		lpm inet.LPMIPv4
	}{
		{"192.168.10.10", inet.LPMIPv4{Addr4: inet.NewAddrV4FromIP(net.ParseIP("192.168.10.10")), PrefixLen: 32}},
		{"192.168.10.10/32", inet.LPMIPv4{Addr4: inet.NewAddrV4FromIP(net.ParseIP("192.168.10.10")), PrefixLen: 32}},
		{"192.168.10.0/24", inet.LPMIPv4{Addr4: inet.NewAddrV4FromIP(net.ParseIP("192.168.10.0")), PrefixLen: 24}},
		{"192.168.0.0/16", inet.LPMIPv4{Addr4: inet.NewAddrV4FromIP(net.ParseIP("192.168.0.0")), PrefixLen: 16}},
		{"192.0.0.0/8", inet.LPMIPv4{Addr4: inet.NewAddrV4FromIP(net.ParseIP("192.0.0.0")), PrefixLen: 8}},
		{"0.0.0.0/0", inet.LPMIPv4{Addr4: inet.NewAddrV4FromIP(net.ParseIP("0.0.0.0")), PrefixLen: 0}},
	}

	for _, tc := range testCases {
		var lpmIPv4 inet.LPMIPv4
		err := lpmIPv4.Set(tc.str)
		if err != nil {
			t.Error(err)
			continue
		}
		assert.Equal(t, tc.lpm, lpmIPv4, tc.str)
	}
}

func TestPortRange(t *testing.T) {
	testCases := []struct {
		str    string
		expect PortRange
		valid  bool
	}{
		{"80", PortRange{Start: 80, End: 80}, true},
		{"80:80", PortRange{Start: 80, End: 80}, true},
		{"80:90", PortRange{Start: 80, End: 90}, true},
		{"80-90", PortRange{Start: 80, End: 90}, true},
		{"90-80", PortRange{}, false},
	}

	for _, tc := range testCases {
		var pr PortRange
		err := pr.Set(tc.str)
		assert.Equal(t, tc.valid, err == nil, tc.str)
		assert.Equal(t, tc.expect, pr, tc.str)
	}
}

func TestMultiPort(t *testing.T) {
	testCases := []struct {
		str    string
		expect MultiPort
	}{
		{"", MultiPort{}},
		{"80", MultiPort{80}},
		{"80,80", MultiPort{80}},
		{"80,8080", MultiPort{80, 8080}},
	}

	for _, tc := range testCases {
		var mp MultiPort
		err := mp.Set(tc.str)
		if err != nil {
			t.Error(err)
			continue
		}
		assert.Equal(t, tc.expect, mp, tc.str)
	}
}
