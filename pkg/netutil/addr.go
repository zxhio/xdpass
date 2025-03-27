package netutil

import (
	"encoding/json"
	"net"
)

func Ntohs(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

func Ntohl(v uint32) uint32 {
	return (v>>24)&0xff | (v>>8)&0xff00 | (v<<8)&0xff0000 | (v << 24)
}

func Htons(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

func Htonl(v uint32) uint32 {
	return (v>>24)&0xff | (v>>8)&0xff00 | (v<<8)&0xff0000 | (v << 24)
}

func IPv4FromUint32(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func IPv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func IPv4PrefixCompare(ip, cidrIP uint32, cidrPrefix uint8) int {
	return int(IPv4PrefixToUint32(ip, cidrPrefix) - cidrIP)
}

func IPv4PrefixToUint32(ip uint32, prefixLen uint8) uint32 {
	return ip & (0xffffffff << (32 - prefixLen))
}

func IPv4PrefixFromCIDR(cidr string) (uint32, uint8) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0
	}
	ones, _ := ipnet.Mask.Size()
	return IPv4ToUint32(ipnet.IP), uint8(ones)
}

type HwAddr [6]byte

func (HwAddr) Type() string {
	return "hwaddr"
}

func (addr HwAddr) String() string {
	return net.HardwareAddr(addr[:]).String()
}

func (addr *HwAddr) Set(s string) error {
	mac, err := net.ParseMAC(s)
	if err != nil {
		return err
	}
	*addr = HwAddr(mac)
	return nil
}

func (addr HwAddr) MarshalJSON() ([]byte, error) {
	s := addr.String()
	return json.Marshal(s)
}

func (addr *HwAddr) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	return addr.Set(s)
}
