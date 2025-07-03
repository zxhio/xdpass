package netaddr

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddrV4(t *testing.T) {
	testCases := []struct {
		addrV4  IPv4Addr
		addrStr string
	}{
		{IPv4Addr(127<<24 + 1), "127.0.0.1"},
		{IPv4Addr(192<<24 + 168<<16 + 10<<8 + 10), "192.168.10.10"},
	}

	for _, tc := range testCases {
		t.Run(tc.addrStr, func(t *testing.T) {
			var v4 IPv4Addr
			err := v4.Set(tc.addrStr)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, tc.addrV4, v4)
			assert.Equal(t, tc.addrStr, tc.addrV4.String())
			assert.Equal(t, net.ParseIP(tc.addrStr), tc.addrV4.ToIP())

			// Marshal/Unmarshal
			data, err := json.Marshal(tc.addrV4)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, fmt.Sprintf(`"%s"`, tc.addrStr), string(data))

			err = json.Unmarshal(data, &v4)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, tc.addrV4, v4)
		})
	}
}
