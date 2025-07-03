package netaddr

import (
	"fmt"
	"net"
	"strings"
)

// IPv4Prefix IPv4Addr longest prefix match
type IPv4Prefix struct {
	Addr      IPv4Addr `json:"addr,omitempty"`
	PrefixLen uint8    `json:"prefix_len,omitempty"`
}

func (p IPv4Prefix) Compare(other IPv4Prefix) int {
	if p.Addr < other.Addr {
		return -1
	}
	if p.Addr > other.Addr {
		return 1
	}
	if p.PrefixLen < other.PrefixLen {
		return -1
	}
	if p.PrefixLen > other.PrefixLen {
		return 1
	}
	return 0
}

func (p IPv4Prefix) ContainsAddrV4(addrV4 IPv4Addr) bool {
	return p.Addr-addrV4&(0xffffffff<<(32-p.PrefixLen)) == 0
}

func (p IPv4Prefix) Type() string {
	return "IPv4Prefix"
}

func (p *IPv4Prefix) Set(s string) error {
	sp, err := NewIPv4PrefixFromStr(s)
	if err != nil {
		return err
	}
	*p = sp
	return nil
}

func (p IPv4Prefix) String() string {
	ipnet := net.IPNet{IP: p.Addr.ToIP(), Mask: net.CIDRMask(int(p.PrefixLen), 32)}
	return ipnet.String()
}

func NewIPv4PrefixFromCIDRStr(cidr string) (IPv4Prefix, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return IPv4Prefix{}, nil
	}
	ones, _ := ipnet.Mask.Size()
	return IPv4Prefix{Addr: NewIPv4AddrFromIP(ipnet.IP), PrefixLen: uint8(ones)}, nil
}

func NewIPv4PrefixFromIP(p net.IP) (IPv4Prefix, error) {
	return IPv4Prefix{Addr: NewIPv4AddrFromIP(p), PrefixLen: 32}, nil
}

func NewIPv4PrefixFromIPStr(ipStr string) (IPv4Prefix, error) {
	p := net.ParseIP(ipStr)
	if p == nil {
		return IPv4Prefix{}, fmt.Errorf("invalid p: %s", ipStr)
	}
	return NewIPv4PrefixFromIP(p)
}

// NewIPv4PrefixFromStr support both ip/cidr
func NewIPv4PrefixFromStr(s string) (IPv4Prefix, error) {
	if strings.IndexByte(s, '/') == -1 {
		return NewIPv4PrefixFromIPStr(s)
	}
	return NewIPv4PrefixFromCIDRStr(s)
}
