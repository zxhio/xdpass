package xdpprog

import (
	"net"

	"github.com/cilium/ebpf"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

type Objects struct {
	xdpprogObjects
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdpprog xdp.c -- -I../headers

func LoadObjects(opts *ebpf.CollectionOptions) (*Objects, error) {
	var objs Objects
	return &objs, loadXdpprogObjects(&objs.xdpprogObjects, nil)
}

type IPLPMKey xdpprogIpLpmKey

func (key IPLPMKey) ToIPv4Prefix() netaddr.IPv4Prefix {
	return netaddr.IPv4Prefix{Addr: netaddr.NewIPv4AddrFromIP(net.IP(key.Data[:4])), PrefixLen: uint8(key.PrefixLen)}
}

func NewIPLpmKey(p netaddr.IPv4Prefix) IPLPMKey {
	key := IPLPMKey{PrefixLen: uint32(p.PrefixLen)}
	copy(key.Data[:], p.Addr.ToIP().To4())
	return key
}
