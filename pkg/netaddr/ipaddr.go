package netaddr

import (
	"fmt"
	"net"
)

// IPv4Addr 32-bit address int value
type IPv4Addr uint32

func (v4 IPv4Addr) ToIP() net.IP {
	return net.IPv4(byte(v4>>24), byte(v4>>16), byte(v4>>8), byte(v4))
}

func (IPv4Addr) Type() string {
	return "IPv4Addr"
}

func (v4 IPv4Addr) String() string {
	return v4.ToIP().String()
}

func (v4 *IPv4Addr) Set(s string) error {
	ip := net.ParseIP(s)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", s)
	}
	*v4 = NewIPv4AddrFromIP(ip)
	return nil
}

func (v4 IPv4Addr) MarshalJSON() ([]byte, error) {
	return marshal(v4)
}

func (v4 *IPv4Addr) UnmarshalJSON(data []byte) error {
	return unmarshal(v4, data)
}

func NewIPv4AddrFromIP(ip net.IP) IPv4Addr {
	ip = ip.To4()
	return IPv4Addr(uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]))
}
