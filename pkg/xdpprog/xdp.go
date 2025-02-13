package xdpprog

import (
	"errors"
	"net"
	"strings"

	"github.com/cilium/ebpf"
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

func MakeIPLpmKeyFromIP(ip net.IP) *IPLpmKey {
	var key IPLpmKey
	ip4 := ip.To4()
	if len(ip4) == net.IPv4len {
		key.PrefixLen = 32
		copy(key.Data[:net.IPv4len], ip4)
	} else {
		key.PrefixLen = 128
		copy(key.Data[:net.IPv6len], ip)
	}
	return &key
}

func MakeIPLpmKeyFromStr(s string) (*IPLpmKey, error) {
	if strings.IndexByte(s, '/') == -1 {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, errors.New("invalid ip")
		}
		return MakeIPLpmKeyFromIP(ip), nil
	}

	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	ones, _ := ipnet.Mask.Size()

	key := MakeIPLpmKeyFromIP(ipnet.IP)
	key.PrefixLen = uint32(ones)

	return key, nil
}
