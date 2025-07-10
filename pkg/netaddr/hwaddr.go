package netaddr

import (
	"bytes"
	"net"
)

type HwAddr [6]byte

func (HwAddr) Type() string {
	return "HwAddr"
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

func (addr HwAddr) Compare(other HwAddr) int {
	return bytes.Compare(addr[:], other[:])
}

func (addr HwAddr) MarshalJSON() ([]byte, error) {
	return marshal(addr)
}

func (addr *HwAddr) UnmarshalJSON(data []byte) error {
	return unmarshal(addr, data)
}
