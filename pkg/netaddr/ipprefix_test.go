package netaddr

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewIPv4PrefixFromCIDR(t *testing.T) {
	testCases := []struct {
		cidr   string
		ip     string
		prefix uint8
	}{
		{"192.168.10.10/32", "192.168.10.10", 32},
		{"192.168.10.0/24", "192.168.10.0", 24},
		{"192.168.0.0/16", "192.168.0.0", 16},
		{"192.0.0.0/8", "192.0.0.0", 8},

		// unstrict cidr
		{"192.168.10.10/24", "192.168.10.0", 24},
		{"192.168.10.10/16", "192.168.0.0", 16},
		{"192.168.10.10/8", "192.0.0.0", 8},
		{"192.168.10.10/0", "0.0.0.0", 0},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s-%s/%d", tc.cidr, tc.ip, tc.prefix), func(t *testing.T) {
			p, err := NewIPv4PrefixFromCIDRStr(tc.cidr)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, tc.ip, p.Addr.String())
			assert.Equal(t, tc.prefix, p.PrefixLen)
			assert.Equal(t, fmt.Sprintf("%s/%d", tc.ip, tc.prefix), p.String())

			p2, err := NewIPv4PrefixFromStr(tc.cidr)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, 0, p.Compare(p2))
		})
	}
}

func TestNewIPv4PrefixFromIP(t *testing.T) {
	testCases := []struct {
		ip    string
		valid bool
	}{
		{"192.168.10.10", true},
		{"192.168.10.1000", false},
	}

	for _, tc := range testCases {
		p, err := NewIPv4PrefixFromIPStr(tc.ip)
		assert.Equal(t, tc.valid, err == nil)
		if tc.valid {
			assert.Equal(t, fmt.Sprintf("%s/32", tc.ip), p.String())
		}

		p2, err := NewIPv4PrefixFromStr(tc.ip)
		assert.Equal(t, tc.valid, err == nil)
		if tc.valid {
			assert.Equal(t, 0, p.Compare(p2))
		}
	}
}
