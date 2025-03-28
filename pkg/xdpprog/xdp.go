package xdpprog

import (
	"net"

	"github.com/cilium/ebpf"
	"github.com/zxhio/xdpass/pkg/inet"
)

type FirewallMode uint32

const (
	FirewallModeWhitelist FirewallMode = iota
	FirewallModeBlocklist
)

type Objects struct {
	xdpprogObjects
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdpprog xdp.c -- -I../headers

func LoadObjects(opts *ebpf.CollectionOptions) (*Objects, error) {
	var objs Objects
	return &objs, loadXdpprogObjects(&objs.xdpprogObjects, nil)
}

type IPLpmKey xdpprogIpLpmKey

func (key IPLpmKey) ToLPMIPv4() inet.LPMIPv4 {
	return inet.LPMIPv4{Addr4: inet.NewAddrV4FromIP(net.IP(key.Data[:4])), PrefixLen: uint8(key.PrefixLen)}
}

func NewIPLpmKey(lpm inet.LPMIPv4) IPLpmKey {
	key := IPLpmKey{PrefixLen: uint32(lpm.PrefixLen)}
	copy(key.Data[:], lpm.Addr4.ToIP().To4())
	return key
}
