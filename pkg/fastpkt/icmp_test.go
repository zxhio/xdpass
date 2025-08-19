package fastpkt

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/zxhio/xdpass/pkg/netutil"
)

func TestICMPChecksum(t *testing.T) {
	testCases := []struct {
		payload []byte
	}{
		{},
		{payload: []byte{0x01, 0x02, 0x03, 0x04}},
		{payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a}},
	}

	layerICMPv4 := &layers.ICMPv4{TypeCode: layers.ICMPv4TypeEchoRequest}
	for _, testCase := range testCases {
		buf, err := serialize(layerICMPv4, gopacket.Payload(testCase.payload))
		if err != nil {
			t.Fatalf("serialize: %v", err)
		}
		checksum := netutil.Htons(layerICMPv4.Checksum)

		icmp := DataPtr[ICMP](buf, 0)
		icmp.SetChecksum(uint16(len(testCase.payload)))
		assert.Equal(t, checksum, icmp.Checksum)
	}
}
