package netaddr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPv4Range(t *testing.T) {
	testCases := []struct {
		v4RangeStr string
		v4Range    IPv4Range
	}{
		{"127.0.0.1-127.0.0.1", IPv4Range{Start: IPv4Addr(127<<24 + 1), End: IPv4Addr(127<<24 + 1)}},
		{"127.0.0.1-127.0.0.2", IPv4Range{Start: IPv4Addr(127<<24 + 1), End: IPv4Addr(127<<24 + 2)}},
	}

	for _, tc := range testCases {
		t.Run(tc.v4RangeStr, func(t *testing.T) {
			var r IPv4Range
			err := r.Set(tc.v4RangeStr)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, tc.v4Range.Compare(r), 0)
		})
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
		t.Run(tc.str, func(t *testing.T) {
			var pr PortRange
			err := pr.Set(tc.str)
			assert.Equal(t, tc.valid, err == nil, tc.str)
			assert.Equal(t, tc.expect, pr, tc.str)
		})
	}
}
