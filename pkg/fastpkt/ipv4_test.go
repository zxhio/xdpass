package fastpkt

import (
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/zxhio/xdpass/pkg/netutil"
)

func TestIPv4Checksum(t *testing.T) {
	testCases := []struct {
		headerLen uint8
		options   []layers.IPv4Option
	}{
		{
			headerLen: 20,
		},
		{
			headerLen: 20 + 1 + 3, // option(1) + padding(3)
			options: []layers.IPv4Option{{
				OptionType:   1, // NOP
				OptionLength: 0,
				OptionData:   nil,
			}},
		},
		{
			headerLen: 20 + 1 + 3, // option(1) + padding(3)
			options: []layers.IPv4Option{{
				OptionType:   0, // END
				OptionLength: 0,
				OptionData:   nil,
			}},
		},
		{
			headerLen: 20 + 1 + 7, // option(1) + padding(7)
			options: []layers.IPv4Option{{
				OptionType:   7,                    // Record Route (RR)
				OptionLength: 7,                    // type(1) + length(1) + pointer(1) + IP(4*1)
				OptionData:   []byte{172, 0, 0, 1}, // IP *1
			}},
		},
	}

	for _, testCase := range testCases {
		layerIPv4 := testLayerIPv4
		layerIPv4.Options = testCase.options
		buf, err := serialize(&layerIPv4)
		if err != nil {
			t.Fatal(err)
		}
		checksum := netutil.Htons(layerIPv4.Checksum)

		ip := DataPtr[IPv4](buf, 0)
		ip.SetChecksum(0)
		assert.Equal(t, checksum, ip.Checksum)
	}
}
