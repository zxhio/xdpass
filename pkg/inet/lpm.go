package inet

import (
	"fmt"
	"net"
	"strings"
)

// LPMIPv4 AddrV4 longest prefix match
type LPMIPv4 struct {
	Addr4     AddrV4 `json:"ip,omitempty"`
	PrefixLen uint8  `json:"prefix_len,omitempty"`
}

func (lpm LPMIPv4) Match(addrV4 AddrV4) bool {
	return lpm.CompareAddrV4(addrV4) == 0
}

func (lpm LPMIPv4) Equal(other LPMIPv4) bool {
	return lpm.Addr4 == other.Addr4 && lpm.PrefixLen == other.PrefixLen
}

func (lpm LPMIPv4) CompareAddrV4(v4 AddrV4) int {
	return int(lpm.Addr4 - v4&(0xffffffff<<(32-lpm.PrefixLen)))
}

func (lpm LPMIPv4) Type() string {
	return "lpm_ipv4"
}

func (lpm *LPMIPv4) Set(s string) error {
	nlpm, err := NewLPMIPV4FromStr(s)
	if err != nil {
		return err
	}
	*lpm = nlpm
	return nil
}

func (lpm LPMIPv4) String() string {
	ipnet := net.IPNet{IP: lpm.Addr4.ToIP(), Mask: net.CIDRMask(int(lpm.PrefixLen), 32)}
	return ipnet.String()
}

func NewLPMIPV4FromCIDRStr(cidr string) (LPMIPv4, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return LPMIPv4{}, nil
	}
	ones, _ := ipnet.Mask.Size()
	return LPMIPv4{Addr4: NewAddrV4FromIP(ipnet.IP), PrefixLen: uint8(ones)}, nil
}

func NewLPMAIPV4FromIP(ip net.IP) (LPMIPv4, error) {
	return LPMIPv4{Addr4: NewAddrV4FromIP(ip), PrefixLen: 32}, nil
}

func NewLPMIPV4FromIPStr(ipStr string) (LPMIPv4, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return LPMIPv4{}, fmt.Errorf("invalid ip: %s", ipStr)
	}
	return NewLPMAIPV4FromIP(ip)
}

// NewLPMIPV4FromStr support both ip/cidr
func NewLPMIPV4FromStr(s string) (LPMIPv4, error) {
	if strings.IndexByte(s, '/') == -1 {
		return NewLPMIPV4FromIPStr(s)
	}
	return NewLPMIPV4FromCIDRStr(s)
}
