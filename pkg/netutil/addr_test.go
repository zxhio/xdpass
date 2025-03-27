package netutil

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPv4PrefixCompare(t *testing.T) {
	testCases := []struct {
		ip     string
		cidr   string
		expect bool
	}{
		{"192.168.10.10", "192.168.10.10/32", true},
		{"192.168.10.10", "192.168.10.10/24", true},
		{"192.168.10.10", "192.168.10.0/24", true},
		{"192.168.10.10", "192.168.0.0/16", true},
		{"192.168.10.10", "192.0.0.0/8", true},
		{"192.168.20.10", "192.168.10.10/32", false},
		{"192.168.20.10", "192.168.10.0/24", false},
	}

	for _, c := range testCases {
		_, ipnet, err := net.ParseCIDR(c.cidr)
		if err != nil {
			t.Fatal(err)
		}
		ones, _ := ipnet.Mask.Size()
		assert.Equal(t, IPv4PrefixCompare(IPv4ToUint32(net.ParseIP(c.ip)), IPv4ToUint32(ipnet.IP), uint8(ones)) == 0, c.expect)
	}
}

func TestIPv4PrefixFromCIDR(t *testing.T) {
	testCases := []struct {
		cidr   string
		ip     string
		prefix uint8
	}{
		{"192.168.10.10/32", "192.168.10.10", 32},
		{"192.168.10.0/24", "192.168.10.0", 24},
		{"192.168.0.0/16", "192.168.0.0", 16},
		{"192.0.0.0/8", "192.0.0.0", 8},

		{"192.168.10.10/24", "192.168.10.0", 24},
		{"192.168.10.10/16", "192.168.0.0", 16},
		{"192.168.10.10/8", "192.0.0.0", 8},
		{"192.168.10.10/0", "0.0.0.0", 0},
	}

	for _, c := range testCases {
		ip, prefix := IPv4PrefixFromCIDR(c.cidr)
		assert.Equal(t, IPv4FromUint32(ip).String(), c.ip)
		assert.Equal(t, prefix, c.prefix)
	}
}
