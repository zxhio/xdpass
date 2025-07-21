package fastpkt

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/zxhio/xdpass/pkg/netutil"
)

func setBaseLayersForTCP() {
	testLayerEth.EthernetType = layers.EthernetTypeIPv4
	testLayerIPv4.Protocol = layers.IPProtocolTCP
}

func TestTCPFlags(t *testing.T) {
	setBaseLayersForTCP()

	testCases := []struct {
		want      TCPFlags
		flagSetFn func(l *layers.TCP)
	}{
		{want: TCPFlagFIN, flagSetFn: func(l *layers.TCP) { l.FIN = true }},
		{want: TCPFlagSYN, flagSetFn: func(l *layers.TCP) { l.SYN = true }},
		{want: TCPFlagRST, flagSetFn: func(l *layers.TCP) { l.RST = true }},
		{want: TCPFlagPSH, flagSetFn: func(l *layers.TCP) { l.PSH = true }},
		{want: TCPFlagACK, flagSetFn: func(l *layers.TCP) { l.ACK = true }},
		{want: TCPFlagURG, flagSetFn: func(l *layers.TCP) { l.URG = true }},
		{want: TCPFlagECE, flagSetFn: func(l *layers.TCP) { l.ECE = true }},
		{want: TCPFlagCWR, flagSetFn: func(l *layers.TCP) { l.CWR = true }},
	}

	for _, testCase := range testCases {
		layerTCP := layers.TCP{SrcPort: 4096, DstPort: 65535}
		testCase.flagSetFn(&layerTCP)
		layerTCP.SetNetworkLayerForChecksum(&testLayerIPv4)

		buf, err := serialize(&testLayerIPv4, &layerTCP)
		if err != nil {
			t.Fatal(err)
		}
		tcp := DataPtrTCPHeader(buf, 20)
		assert.True(t, tcp.Flags.Has(testCase.want))
		assert.Equal(t, testCase.want, tcp.Flags)
	}
}

func TestTCPChecksum(t *testing.T) {
	setBaseLayersForTCP()

	testCases := []struct {
		headerLen uint8
		options   []layers.TCPOption
		payload   []byte
	}{
		{
			headerLen: 20,
		},
		{
			headerLen: 20 + 4, // 4(mss)
			options:   []layers.TCPOption{{OptionType: layers.TCPOptionKindMSS, OptionData: []byte{0x05, 0xDC}}},
		},
		{
			headerLen: 20 + 4, // 4(mss)
			options:   []layers.TCPOption{{OptionType: layers.TCPOptionKindMSS, OptionData: []byte{0x05, 0xDC}}},
			payload:   []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
		},
		{
			headerLen: 20 + 10 + 2, // 10(timestamps) + 2(padding)
			options: []layers.TCPOption{{
				OptionType: layers.TCPOptionKindTimestamps,
				OptionData: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			}},
		},
		{
			headerLen: 20 + 10 + 2, // 10(timestamps) + 2(padding)
			options: []layers.TCPOption{{
				OptionType: layers.TCPOptionKindTimestamps,
				OptionData: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			}},
			payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
		},
	}

	layerTCP := layers.TCP{SrcPort: 4096, DstPort: 65535}
	layerTCP.SetNetworkLayerForChecksum(&testLayerIPv4)
	for _, testCase := range testCases {
		layerTCP.Options = testCase.options
		buf, err := serialize(&testLayerIPv4, &layerTCP, gopacket.Payload(testCase.payload))
		if err != nil {
			t.Fatal(err)
		}
		checksum := netutil.Htons(layerTCP.Checksum)

		// Check ComputeChecksum
		tcp := DataPtrTCPHeader(buf, 20)
		tcp.SetChecksum(DataPtrIPv4Header(buf, 0), uint16(len(testCase.payload)))
		assert.Equal(t, checksum, tcp.Check)
	}
}

func TestTCPL7(t *testing.T) {
	testCases := []struct {
		l7Content string
		l7Proto   uint8
	}{
		{"", L7ProtoNone},
		{"[1,2,3]", L7ProtoData},
		{"GET / HTTP/1.1", L7ProtoHTTPReq},
		{"HTTP/1.1 200 OK", L7ProtoHTTPResp},
	}

	layerTCP := layers.TCP{}
	layerTCP.SetNetworkLayerForChecksum(&testLayerIPv4)
	for _, tc := range testCases {
		layerTCP.Payload = gopacket.Payload(tc.l7Content)
		buf, err := serialize(&layerTCP, gopacket.Payload(tc.l7Content))
		if err != nil {
			t.Fatal(err)
		}

		var pkt Packet
		pkt.DecodePacketTCP(buf)
		assert.Equal(t, tc.l7Proto, pkt.L7Proto, tc.l7Content)
	}
}
