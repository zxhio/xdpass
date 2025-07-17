package rule

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

func TestMatchMarshal(t *testing.T) {
	var (
		loAddr     = netaddr.NewIPv4AddrFromIP(net.ParseIP("127.0.0.1"))
		ipv4Prefix = netaddr.IPv4Prefix{Addr: loAddr, PrefixLen: 8}
		ipv4Range  = netaddr.IPv4Range{Start: loAddr, End: loAddr + 1}
		portRage   = netaddr.PortRange{Start: 80, End: 81}
		mulitPort  = netaddr.MultiPort{80, 81}
	)

	testCases := []struct {
		matcher Matcher
		str     string
	}{
		// IPv4
		{matcher: MatchIPv4PrefixSrc(ipv4Prefix), str: `"127.0.0.0/8"`},
		{matcher: MatchIPv4PrefixDst(ipv4Prefix), str: `"127.0.0.0/8"`},
		{matcher: MatchIPv4RangeSrc(ipv4Range), str: `"127.0.0.1-127.0.0.2"`},
		{matcher: MatchIPv4RangeDst(ipv4Range), str: `"127.0.0.1-127.0.0.2"`},

		// Port
		{matcher: MatchPortRangeSrc(portRage), str: `"80:81"`},
		{matcher: MatchPortRangeDst(portRage), str: `"80:81"`},
		{matcher: MatchMultiPortSrc(mulitPort), str: `"80,81"`},
		{matcher: MatchMultiPortDst(mulitPort), str: `"80,81"`},
	}

	for _, tc := range testCases {
		t.Run(tc.matcher.MatchType().String(), func(t *testing.T) {
			ser, ok := matchTypeToSerializer[tc.matcher.MatchType()]
			if !assert.True(t, ok, "no such match type serializer") {
				return
			}

			data, err := ser.marshaler(tc.matcher)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, tc.str, string(data))
		})
	}
}

// 17:49:44.781393 0a:14:8a:58:0e:14 > 6a:10:e9:37:63:ac, ethertype IPv4 (0x0800), length 74: 172.16.23.2.51998 > 172.16.23.1.1024: Flags [S], seq 2155109571, win 64240, options [TCPOption(Unknown(71):)], length 0
var (
	synData = []byte{106, 16, 233, 55, 99, 172, 10, 20, 138, 88, 14, 20, 8, 0, 69, 0, 0, 60, 246, 122, 64, 0, 64, 6, 190, 29, 172, 16, 23, 2, 172, 16, 23, 1, 203, 30, 4, 0, 128, 116, 92, 195, 0, 0, 0, 0, 160, 2, 250, 240, 134, 82, 0, 0, 71, 69, 84, 32, 47, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 72, 111, 115, 116}
	sip     = netaddr.NewIPv4AddrFromIP(net.ParseIP("172.16.23.2"))
	dip     = netaddr.NewIPv4AddrFromIP(net.ParseIP("172.16.23.1"))
	sport   = uint16(51998)
	dport   = uint16(1024)
)

var topPorts = [...]uint16{
	22, 53, 80, 123, 143, 443, 445, 587, 6379, 27017, 3306, 3389,
	5432, 5672, 5900, 6000, 8080, 8443, 9200, 27018,
}

func BenchmarkMatch(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	pkt, err := fastpkt.NewPacket(synData)
	if err != nil {
		b.Fatal(err)
	}

	sip := netaddr.NewIPv4AddrFromIP(net.ParseIP("172.16.23.2"))

	benchCases := []struct {
		matcher Matcher
	}{
		{MatchIPv4PrefixSrc{sip, 32}},
		{MatchIPv4RangeSrc{sip, sip + 100}},
		{MatchMultiPortDst(topPorts[:])},
		{MatchPortRangeDst{1, 1024}},
	}

	for _, bc := range benchCases {
		b.Run(bc.matcher.MatchType().String(), func(b *testing.B) {
			for range b.N {
				bc.matcher.Match(pkt)
			}
		})
	}
}
