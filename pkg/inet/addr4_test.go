package inet

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddrV4(t *testing.T) {
	testCases := []struct {
		addrV4  AddrV4
		addrStr string
	}{
		{AddrV4(127<<24 + 1), "127.0.0.1"},
		{AddrV4(192<<24 + 168<<16 + 10<<8 + 10), "192.168.10.10"},
	}

	for _, tc := range testCases {
		var v4 AddrV4
		v4.Set(tc.addrStr)
		assert.Equal(t, tc.addrV4, v4, tc.addrStr)

		assert.Equal(t, tc.addrStr, tc.addrV4.String(), tc.addrStr)
		assert.Equal(t, net.ParseIP(tc.addrStr), tc.addrV4.ToIP(), tc.addrStr)

		// Marshal/Unmarshal
		data, err := json.Marshal(tc.addrV4)
		if err != nil {
			t.Error(err)
		}
		assert.Equal(t, fmt.Sprintf(`"%s"`, tc.addrStr), string(data))

		err = json.Unmarshal(data, &v4)
		if err != nil {
			t.Error(err)
		}
		assert.Equal(t, tc.addrV4, v4, tc.addrStr)
	}
}
