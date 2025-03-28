package inet

import (
	"encoding/json"
	"fmt"
	"net"
)

// AddrV4 32-bit address int value
type AddrV4 uint32

func (v4 AddrV4) ToIP() net.IP {
	return net.IPv4(byte(v4>>24), byte(v4>>16), byte(v4>>8), byte(v4))
}

func (AddrV4) Type() string {
	return "addr_v4"
}

func (v4 AddrV4) String() string {
	return v4.ToIP().String()
}

func (v4 *AddrV4) Set(s string) error {
	ip := net.ParseIP(s)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", s)
	}
	*v4 = NewAddrV4FromIP(ip)
	return nil
}

func (v4 AddrV4) MarshalJSON() ([]byte, error) {
	return json.Marshal(v4.String())
}

func (v4 *AddrV4) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	return v4.Set(s)
}

func NewAddrV4FromIP(ip net.IP) AddrV4 {
	ip = ip.To4()
	return AddrV4(uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]))
}
