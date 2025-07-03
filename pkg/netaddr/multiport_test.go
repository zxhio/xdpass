package netaddr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
		t.Run(tc.str, func(t *testing.T) {
			var mp MultiPort
			err := mp.Set(tc.str)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, tc.expect, mp)
		})
	}
}
