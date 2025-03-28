package inet

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLPMIPv4FromCIDR(t *testing.T) {
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
		lpm, err := NewLPMIPV4FromCIDRStr(tc.cidr)
		if err != nil {
			t.Error(err)
		}
		assert.Equal(t, tc.ip, lpm.Addr4.String())
		assert.Equal(t, tc.prefix, lpm.PrefixLen)
		assert.Equal(t, fmt.Sprintf("%s/%d", tc.ip, tc.prefix), lpm.String())

		lpm2, err := NewLPMIPV4FromStr(tc.cidr)
		if err != nil {
			t.Error(err)
		}
		assert.True(t, lpm.Equal(lpm2))
	}
}

func TestNewLPMIPv4FromIP(t *testing.T) {
	testCases := []struct {
		ip    string
		valid bool
	}{
		{"192.168.10.10", true},
		{"192.168.10.1000", false},
	}

	for _, tc := range testCases {
		lpm, err := NewLPMIPV4FromIPStr(tc.ip)
		assert.Equal(t, tc.valid, err == nil)
		if tc.valid {
			assert.Equal(t, fmt.Sprintf("%s/32", tc.ip), lpm.String())
		}

		lpm2, err := NewLPMIPV4FromStr(tc.ip)
		assert.Equal(t, tc.valid, err == nil)
		if tc.valid {
			assert.True(t, lpm.Equal(lpm2))
		}
	}
}
