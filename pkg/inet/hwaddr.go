package inet

import (
	"encoding/json"
	"net"
)

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
