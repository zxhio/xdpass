package bench

import (
	"fmt"
	"net"
	"os"
	"slices"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

type LayerEthernet struct {
	SrcMAC netaddr.HwAddr
	DstMAC netaddr.HwAddr
}

type LayerVLAN struct {
	ID uint16
}

type LayerIPv4 struct {
	SrcIPv4 net.IP
	DstIPv4 net.IP
	TTL     uint8
}

type LayerPorts struct {
	SPort uint16
	DPort uint16
}

type LayerTCP struct {
	LayerPorts
	SYN         bool
	ACK         bool
	PSH         bool
	RST         bool
	FIN         bool
	Seq         uint32
	Payload     string
	PayloadPath string
}

func (tcp *LayerTCP) MakeLayer(layersIPv4 *layers.IPv4) gopacket.SerializableLayer {
	layersIPv4.Protocol = layers.IPProtocolTCP
	layersTCP := &layers.TCP{
		SrcPort: layers.TCPPort(valueOr(tcp.SPort, 54321)),
		DstPort: layers.TCPPort(valueOr(tcp.DPort, 12345)),
		Seq:     valueOr(tcp.Seq, 12345),
		SYN:     tcp.SYN,
		ACK:     tcp.ACK,
		PSH:     tcp.PSH,
		RST:     tcp.RST,
		FIN:     tcp.FIN,
	}
	layersTCP.SetNetworkLayerForChecksum(layersIPv4)
	return layersTCP
}

func (tcp *LayerTCP) MakePayload() (gopacket.Payload, error) {
	if len(tcp.Payload) == 0 && len(tcp.PayloadPath) != 0 {
		data, err := os.ReadFile(tcp.PayloadPath)
		if err != nil {
			return nil, errors.Wrap(err, "os.ReadFile")
		}
		return gopacket.Payload(data[:min(len(data), 1400)]), nil
	}
	return gopacket.Payload(tcp.Payload[:min(len(tcp.Payload), 1400)]), nil
}

type LayerUDP struct {
	LayerPorts
	Payload     string
	PayloadPath string
}

func (udp *LayerUDP) MakeLayer(layersIPv4 *layers.IPv4) gopacket.SerializableLayer {
	layersIPv4.Protocol = layers.IPProtocolUDP
	layersUDP := &layers.UDP{
		SrcPort: layers.UDPPort(valueOr(udp.SPort, 54321)),
		DstPort: layers.UDPPort(valueOr(udp.DPort, 12345)),
	}
	layersUDP.SetNetworkLayerForChecksum(layersIPv4)
	return layersUDP
}

func (udp *LayerUDP) MakePayload() (gopacket.Payload, error) {
	if len(udp.Payload) == 0 && len(udp.PayloadPath) != 0 {
		data, err := os.ReadFile(udp.PayloadPath)
		if err != nil {
			return nil, errors.Wrap(err, "os.ReadFile")
		}
		return gopacket.Payload(data[:min(len(data), 1400)]), nil
	}
	return gopacket.Payload(udp.Payload[:min(len(udp.Payload), 1400)]), nil
}

type LayerICMP struct {
	ID  uint16
	Seq uint16
}

func (icmp4 *LayerICMP) MakeLayer(layersIPv4 *layers.IPv4) gopacket.SerializableLayer {
	layersIPv4.Protocol = layers.IPProtocolICMPv4
	return &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       valueOr(icmp4.ID, 12345),
		Seq:      valueOr(icmp4.Seq, 12345),
	}
}

func (*LayerICMP) MakePayload() (gopacket.Payload, error) {
	return gopacket.Payload{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	}, nil
}

type layerOpts struct {
	ether *LayerEthernet
	vlan  *LayerVLAN
	ipv4  *LayerIPv4
	tcp   *LayerTCP
	udp   *LayerUDP
	icmp  *LayerICMP
}

type LayerOpt func(*layerOpts)

func WithLayerTCP(tcp *LayerTCP) LayerOpt {
	return func(lo *layerOpts) { lo.tcp = tcp }
}

func WithLayerICMP(icmp *LayerICMP) LayerOpt {
	return func(lo *layerOpts) { lo.icmp = icmp }
}

func WithLayerUDP(udp *LayerUDP) LayerOpt {
	return func(lo *layerOpts) { lo.udp = udp }
}

func WithLayerVLAN(vlan *LayerVLAN) LayerOpt {
	return func(lo *layerOpts) {
		if vlan.ID == 0 {
			return
		}
		lo.vlan = vlan
	}
}

type l4Maker interface {
	MakeLayer(*layers.IPv4) gopacket.SerializableLayer
	MakePayload() (gopacket.Payload, error)
}

func MakePacketData(iface *string, ether *LayerEthernet, ipv4 *LayerIPv4, opts ...LayerOpt) ([]byte, error) {
	var o layerOpts
	for _, opt := range opts {
		opt(&o)
	}

	link, sip, err := getLinkAndSIP(*iface, ipv4.DstIPv4)
	if err != nil {
		return nil, err
	}
	if *iface != link.Attrs().Name {
		fmt.Printf("[Interface]: %s → %s\n", *iface, link.Attrs().Name)
		*iface = link.Attrs().Name
	}

	smac, dmac, err := getLinkMacPair(link, ipv4.DstIPv4)
	if err != nil {
		return nil, err
	}
	if ether.SrcMAC.Compare(netaddr.HwAddr{}) == 0 {
		fmt.Printf("[MAC] Source: %s → %s\n", ether.SrcMAC, smac)
		ether.SrcMAC = netaddr.HwAddr(smac)
	}
	if ether.DstMAC.Compare(netaddr.HwAddr{}) == 0 {
		fmt.Printf("[MAC] Destionation: %s → %s\n", ether.DstMAC, dmac)
		ether.DstMAC = netaddr.HwAddr(dmac)
	}

	if ipv4.SrcIPv4 == nil {
		fmt.Printf("[IPv4] Source: %s → %s\n", ipv4.SrcIPv4, sip)
		ipv4.SrcIPv4 = sip
	}
	fmt.Printf("[IPv4] Destionation: %s\n", ipv4.DstIPv4)

	var packetLayers []gopacket.SerializableLayer
	if o.vlan != nil && o.vlan.ID != 0 {
		packetLayers = append(packetLayers,
			&layers.Ethernet{SrcMAC: ether.SrcMAC[:], DstMAC: ether.DstMAC[:], EthernetType: layers.EthernetTypeDot1Q},
			&layers.Dot1Q{VLANIdentifier: o.vlan.ID, Type: layers.EthernetTypeIPv4},
		)
	} else {
		packetLayers = append(packetLayers, &layers.Ethernet{SrcMAC: ether.SrcMAC[:], DstMAC: ether.DstMAC[:], EthernetType: layers.EthernetTypeIPv4})
	}

	layersIPv4 := layers.IPv4{Version: 4, IHL: 5, TTL: ipv4.TTL, SrcIP: ipv4.SrcIPv4, DstIP: ipv4.DstIPv4}

	var l4m l4Maker
	if o.tcp != nil {
		l4m = o.tcp
	} else if o.udp != nil {
		l4m = o.udp
	} else if o.icmp != nil {
		l4m = o.icmp
	} else {
		return nil, fmt.Errorf("less l4 layer")
	}

	layer4 := l4m.MakeLayer(&layersIPv4)
	payload, err := l4m.MakePayload()
	if err != nil {
		return nil, err
	}
	payload = payload[:min(len(payload), link.Attrs().MTU-14-20)]
	packetLayers = append(packetLayers, &layersIPv4, layer4, payload)

	b := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, packetLayers...)
	if err != nil {
		return nil, errors.Wrap(err, "gopacket.SerializeLayers")
	}
	return b.Bytes(), nil
}

func valueOr[T comparable](v T, def T) T {
	var vv T
	return valueExpect(v == vv, def, v)
}

func valueExpect[T any](expect bool, expectV, notExpectV T) T {
	if expect {
		return expectV
	}
	return notExpectV
}

func getLinkAndSIP(iface string, dstIP net.IP) (netlink.Link, net.IP, error) {
	var (
		links []netlink.Link
		err   error
	)

	if iface != "" {
		links = make([]netlink.Link, 1)
		links[0], err = netlink.LinkByName(iface)
	} else {
		links, err = netlink.LinkList()
	}
	if err != nil {
		return nil, nil, errors.New("list link")
	}

	// same subnet
	for _, link := range links {
		sip, err := getLinkSIPBySameSubnet(link, dstIP)
		if err != nil {
			return nil, nil, err
		}
		if sip == nil {
			continue
		}
		return link, sip, nil
	}

	// find by route
	for _, link := range links {
		sip, err := getLinkSIPByDefaultRoute(link, dstIP)
		if err != nil {
			return nil, nil, err
		}
		if sip == nil {
			continue
		}
		return link, sip, nil
	}

	return nil, nil, fmt.Errorf("no such link")
}

func getLinkMacPair(link netlink.Link, dstIP net.IP) (net.HardwareAddr, net.HardwareAddr, error) {
	var dstNeighIP net.IP

	sip, err := getLinkSIPBySameSubnet(link, dstIP)
	if err != nil {
		return nil, nil, err
	}

	// same subnet
	if sip != nil {
		dstNeighIP = dstIP

		// local
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return nil, nil, fmt.Errorf("list link %s addr: %v", link.Attrs().Name, err)
		}
		if slices.ContainsFunc(addrs, func(a netlink.Addr) bool { return a.IP.Equal(dstNeighIP) }) {
			return link.Attrs().HardwareAddr, link.Attrs().HardwareAddr, nil
		}
	} else {
		routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
		if err != nil {
			return nil, nil, fmt.Errorf("list link %s route: %v", link.Attrs().Name, err)
		}

		// default route
		idx := slices.IndexFunc(routes, func(r netlink.Route) bool { return r.Dst.Contains(dstIP) })
		if idx == -1 {
			return nil, nil, fmt.Errorf("no such route for link %s", link.Attrs().Name)
		}
		dstNeighIP = routes[idx].Gw
	}

	neighs, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
	if err != nil {
		return nil, nil, fmt.Errorf("list link %s neigh: %v", link.Attrs().Name, err)
	}
	idx := slices.IndexFunc(neighs, func(n netlink.Neigh) bool { return n.IP.Equal(dstNeighIP) })
	if idx == -1 {
		return nil, nil, fmt.Errorf("link %s no such ip %s neigh", link.Attrs().Name, dstNeighIP)
	}
	return link.Attrs().HardwareAddr, neighs[idx].HardwareAddr, nil
}

func getLinkSIPBySameSubnet(link netlink.Link, ip net.IP) (net.IP, error) {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list link %s addr: %v", link.Attrs().Name, err)
	}

	// same subnet
	addrIdx := slices.IndexFunc(addrs, func(addr netlink.Addr) bool {
		linkIP, _ := netaddr.NewIPv4PrefixFromCIDRStr(addr.IPNet.String())
		return linkIP.ContainsAddrV4(netaddr.NewIPv4AddrFromIP(ip))
	})
	if addrIdx != -1 {
		return addrs[addrIdx].IP, nil
	}
	return nil, nil
}

func getLinkSIPByDefaultRoute(link netlink.Link, ip net.IP) (net.IP, error) {
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list link %s route: %v", link.Attrs().Name, err)
	}

	// default route
	if slices.ContainsFunc(routes, func(r netlink.Route) bool { return r.Dst.Contains(ip) }) {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("list link %s addr: %v", link.Attrs().Name, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("link %s no such addrs", link.Attrs().Name)
		}
		return addrs[0].IP, nil
	}

	return nil, nil
}
