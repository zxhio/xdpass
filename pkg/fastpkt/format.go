package fastpkt

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type formatOpts struct {
	showEthernet bool
	parentLayer  gopacket.Layer
}

type FormatOpt func(*formatOpts)

func WithFormatEthernet() FormatOpt {
	return func(o *formatOpts) { o.showEthernet = true }
}

func WithFormatParentLayer(parent gopacket.Layer) FormatOpt {
	return func(o *formatOpts) { o.parentLayer = parent }
}

type FormatDelimiter string

const (
	FormatDelimiterNone    FormatDelimiter = ""
	FormatDelimiterSpace   FormatDelimiter = " "
	FormatDelimiterComma   FormatDelimiter = ", "
	FormatDelimiterColon   FormatDelimiter = ": "
	FormatDelimiterNewline FormatDelimiter = "\n"
)

type LayerFormatter interface {
	LayerType() gopacket.LayerType
	Format(layer gopacket.Layer, opts ...FormatOpt) (string, FormatDelimiter)
}

var formatters map[gopacket.LayerType]LayerFormatter

func init() {
	formatters = make(map[gopacket.LayerType]LayerFormatter)

	Register(LayerFormatterEthernet{})
	Register(LayerFormatterVLAN{})
	Register(LayerFormatterARP{})
	Register(LayerFormatterIPv4{})
	Register(LayerFormatterIPv6{})
	Register(LayerFormatterICMPv4{})
	Register(LayerFormatterUDP{})
	Register(LayerFormatterTCP{})
	Register(LayerFormatterVXLAN{})
}

func Register(layer LayerFormatter) {
	formatters[layer.LayerType()] = layer
}

func GetLayerFormatter(layerType gopacket.LayerType) (LayerFormatter, bool) {
	formatter, ok := formatters[layerType]
	return formatter, ok
}

// 02:42:6d:09:05:c4 > 02:42:ac:11:00:0a, ethertype IPv4 (0x0800), length 98:
type LayerFormatterEthernet struct{}

func (LayerFormatterEthernet) LayerType() gopacket.LayerType { return layers.LayerTypeEthernet }

func (LayerFormatterEthernet) Format(layer gopacket.Layer, opts ...FormatOpt) (string, FormatDelimiter) {
	var o formatOpts
	for _, opt := range opts {
		opt(&o)
	}

	eth := layer.(*layers.Ethernet)

	if o.showEthernet {
		return fmt.Sprintf("%s > %s, ethertype %s (0x%04x), length %d",
			eth.SrcMAC, eth.DstMAC, eth.EthernetType, int(eth.EthernetType), len(eth.Contents)+len(eth.Payload)), FormatDelimiterColon
	}

	if eth.EthernetType == layers.EthernetTypeIPv4 ||
		eth.EthernetType == layers.EthernetTypeIPv6 ||
		eth.EthernetType == layers.EthernetTypeARP {
		return eth.EthernetType.String(), FormatDelimiterSpace
	}

	// not show anything
	return "", FormatDelimiterNone
}

// vlan 32, p 0, ethertype IPv4 (0x0800)
type LayerFormatterVLAN struct{}

func (LayerFormatterVLAN) LayerType() gopacket.LayerType { return layers.LayerTypeDot1Q }

func (LayerFormatterVLAN) Format(layer gopacket.Layer, opts ...FormatOpt) (string, FormatDelimiter) {
	var o formatOpts
	for _, opt := range opts {
		opt(&o)
	}

	vlan := layer.(*layers.Dot1Q)
	if o.showEthernet {
		return fmt.Sprintf("vlan %d, p %d, ethertype %s (0x%04x)",
			vlan.VLANIdentifier, vlan.Priority, vlan.Type, int(vlan.Type)), FormatDelimiterComma
	}
	return vlan.Type.String(), FormatDelimiterSpace
}

// Request who-has 172.17.0.1 tell 172.17.0.10, length 28
// Reply 172.17.0.1 is-at 02:42:6d:09:05:c4, length 28
type LayerFormatterARP struct{}

func (LayerFormatterARP) LayerType() gopacket.LayerType { return layers.LayerTypeARP }

func (LayerFormatterARP) Format(layer gopacket.Layer, opts ...FormatOpt) (string, FormatDelimiter) {
	arp := layer.(*layers.ARP)
	var s string
	switch arp.Operation {
	case layers.ARPRequest:
		s = fmt.Sprintf("Request who-has %s tell %s, length %d",
			net.IP(arp.DstProtAddress), net.IP(arp.SourceProtAddress), len(arp.Payload)+len(arp.Contents))
	case layers.ARPReply:
		s = fmt.Sprintf("Reply %s is-at %s, length %d",
			net.IP(arp.DstProtAddress), net.HardwareAddr(arp.DstHwAddress), len(arp.Payload)+len(arp.Contents))
	default:
		s = fmt.Sprintf("unknown arp operation %d", arp.Operation)
	}
	return s, FormatDelimiterNone
}

// 172.17.0.1 > 172.17.0.10
// 172.17.0.1.80 > 172.17.0.10.35912
type LayerFormatterIPv4 struct{}

func (LayerFormatterIPv4) LayerType() gopacket.LayerType { return layers.LayerTypeIPv4 }

func (LayerFormatterIPv4) Format(layer gopacket.Layer, opts ...FormatOpt) (string, FormatDelimiter) {
	ipv4 := layer.(*layers.IPv4)
	if ipv4.NextLayerType() == layers.LayerTypeTCP || ipv4.NextLayerType() == layers.LayerTypeUDP {
		// format in next layer with port
		return "", FormatDelimiterNone
	}
	return fmt.Sprintf("%s > %s", ipv4.SrcIP, ipv4.DstIP), FormatDelimiterColon
}

// fe80::782:bca7:c7d3:c551.59807 > ff02::1:3.5355
type LayerFormatterIPv6 struct{}

func (LayerFormatterIPv6) LayerType() gopacket.LayerType { return layers.LayerTypeIPv6 }

func (LayerFormatterIPv6) Format(layer gopacket.Layer, _ ...FormatOpt) (string, FormatDelimiter) {
	ipv6 := layer.(*layers.IPv6)
	if ipv6.NextLayerType() == layers.LayerTypeTCP || ipv6.NextLayerType() == layers.LayerTypeUDP {
		// format in next layer with port
		return "", FormatDelimiterNone
	}
	return fmt.Sprintf("%s > %s", ipv6.SrcIP, ipv6.DstIP), FormatDelimiterColon
}

// ICMP echo request, id 62002, seq 3, length 64
// ICMP echo reply, id 62002, seq 3, length 64
// ICMP 172.17.0.2 udp port 10053 unreachable, length 37
type LayerFormatterICMPv4 struct{}

func (LayerFormatterICMPv4) LayerType() gopacket.LayerType { return layers.LayerTypeICMPv4 }

func (LayerFormatterICMPv4) Format(layer gopacket.Layer, opts ...FormatOpt) (string, FormatDelimiter) {
	icmp := layer.(*layers.ICMPv4)

	b := strings.Builder{}
	b.WriteString("ICMP ")

	// TODO: handle code layers.ICMPv4TypeDestinationUnreachable
	if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
		b.WriteString(fmt.Sprintf("echo request, id %d, seq %d", icmp.Id, icmp.Seq))
	} else if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
		b.WriteString(fmt.Sprintf("echo reply, id %d, seq %d", icmp.Id, icmp.Seq))
	} else {
		b.WriteString(icmp.TypeCode.String())
	}
	b.WriteString(fmt.Sprintf(", length %d", len(icmp.Contents)+len(icmp.Payload)))

	return b.String(), FormatDelimiterNone
}

// UDP, length 3
type LayerFormatterUDP struct{}

func (LayerFormatterUDP) LayerType() gopacket.LayerType { return layers.LayerTypeUDP }

func (LayerFormatterUDP) Format(layer gopacket.Layer, opts ...FormatOpt) (string, FormatDelimiter) {
	udp := layer.(*layers.UDP)
	if udp.NextLayerType() != gopacket.LayerTypePayload {
		return "", FormatDelimiterNone
	}

	var o formatOpts
	for _, opt := range opts {
		opt(&o)
	}

	b := strings.Builder{}
	if o.parentLayer != nil {
		if o.parentLayer.LayerType() == layers.LayerTypeIPv4 {
			ipv4 := o.parentLayer.(*layers.IPv4)
			b.WriteString(fmt.Sprintf("%s.%d > %s.%d: ", ipv4.SrcIP, udp.SrcPort, ipv4.DstIP, udp.DstPort))
		} else if o.parentLayer.LayerType() == layers.LayerTypeIPv6 {
			ipv6 := o.parentLayer.(*layers.IPv6)
			b.WriteString(fmt.Sprintf("%s.%d > %s.%d: ", ipv6.SrcIP, udp.SrcPort, ipv6.DstIP, udp.DstPort))
		}
	}
	b.WriteString(fmt.Sprintf("UDP, length %d", len(udp.Payload)))
	return b.String(), FormatDelimiterNone
}

// VXLAN, flags [I] (0x08), vni 20000
type LayerFormatterVXLAN struct{}

func (LayerFormatterVXLAN) LayerType() gopacket.LayerType { return layers.LayerTypeVXLAN }

func (LayerFormatterVXLAN) Format(layer gopacket.Layer, opts ...FormatOpt) (string, FormatDelimiter) {
	vxlan := layer.(*layers.VXLAN)

	var flags []byte
	if vxlan.ValidIDFlag {
		flags = append(flags, 'I')
	}
	if vxlan.GBPExtension {
		flags = append(flags, 'G')
	}
	if vxlan.GBPDontLearn {
		flags = append(flags, 'D')
	}
	if vxlan.GBPApplied {
		flags = append(flags, 'A')
	}

	s := strings.Builder{}
	s.WriteString("VXLAN")
	if len(flags) > 0 {
		s.WriteString(fmt.Sprintf(", flags [%s] (0x08)", flags))
	}
	s.WriteString(fmt.Sprintf(", vni %d", vxlan.VNI))

	return s.String(), FormatDelimiterNewline
}

// Flags [S], seq 1996870669, win 64240, options [mss 1460,sackOK,TS val 2991051445 ecr 0,nop,wscale 7], length 0
// Flags [S.], seq 1212244906, ack 1996870670, win 65160, options [mss 1460,sackOK,TS val 2190861178 ecr 2991051445,nop,wscale 7], length 0
// Flags [.], ack 1, win 502, options [nop,nop,TS val 2991051445 ecr 2190861178], length 0
// Flags [P.], seq 1:79, ack 1, win 510, options [nop,nop,TS val 2190861180 ecr 2991051445], length 78
// Flags [F.], seq 1, ack 79, win 502, options [nop,nop,TS val 2991052669 ecr 2190861180], length 0
// Flags [R], seq 3542344698, win 0, length 0
type LayerFormatterTCP struct{}

func (LayerFormatterTCP) LayerType() gopacket.LayerType { return layers.LayerTypeTCP }

func (f LayerFormatterTCP) Format(layer gopacket.Layer, opts ...FormatOpt) (string, FormatDelimiter) {
	var o formatOpts
	for _, opt := range opts {
		opt(&o)
	}

	tcp := layer.(*layers.TCP)

	b := strings.Builder{}
	if o.parentLayer != nil {
		if o.parentLayer.LayerType() == layers.LayerTypeIPv4 {
			ipv4 := o.parentLayer.(*layers.IPv4)
			b.WriteString(fmt.Sprintf("%s.%d > %s.%d: ", ipv4.SrcIP, tcp.SrcPort, ipv4.DstIP, tcp.DstPort))
		} else if o.parentLayer.LayerType() == layers.LayerTypeIPv6 {
			ipv6 := o.parentLayer.(*layers.IPv6)
			b.WriteString(fmt.Sprintf("%s.%d > %s.%d: ", ipv6.SrcIP, tcp.SrcPort, ipv6.DstIP, tcp.DstPort))
		}
	}

	b.WriteString(fmt.Sprintf("Flags [%s]", f.formatFlags(tcp)))

	if tcp.SYN {
		b.WriteString(fmt.Sprintf(", seq %d", tcp.Seq))
	}
	if tcp.PSH {
		b.WriteString(fmt.Sprintf(", seq %d:%d", tcp.Seq, tcp.Seq+uint32(len(tcp.Payload))))
	}
	if tcp.FIN {
		b.WriteString(fmt.Sprintf(", seq %d", tcp.Seq))
	}
	if tcp.RST {
		b.WriteString(fmt.Sprintf(", seq %d", tcp.Seq))
	}
	if tcp.ACK {
		b.WriteString(fmt.Sprintf(", ack %d", tcp.Ack))
	}

	b.WriteString(fmt.Sprintf(", win %d", tcp.Window))
	if len(tcp.Options) > 0 {
		b.WriteString(fmt.Sprintf(", options [%s]", strings.Join(f.formatOptions(tcp.Options), ",")))
	}
	b.WriteString(fmt.Sprintf(", length %d", len(tcp.Payload)))

	return b.String(), FormatDelimiterNone
}

func (LayerFormatterTCP) formatFlags(tcp *layers.TCP) string {
	flags := []byte{}
	if tcp.SYN {
		flags = append(flags, 'S')
	}
	if tcp.PSH {
		flags = append(flags, 'P')
	}
	if tcp.FIN {
		flags = append(flags, 'F')
	}
	if tcp.RST {
		flags = append(flags, 'R')
	}
	if tcp.URG {
		flags = append(flags, 'U')
	}
	if tcp.ECE {
		flags = append(flags, 'E')
	}
	if tcp.CWR {
		flags = append(flags, 'W')
	}
	if tcp.ACK {
		flags = append(flags, '.')
	}
	return string(flags)
}

func (LayerFormatterTCP) formatOptions(options []layers.TCPOption) []string {
	var result []string

	// TODO: format all tcp option like tcpdump
	for _, opt := range options {
		switch opt.OptionType {
		case layers.TCPOptionKindNop:
			result = append(result, "nop")
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) >= 2 {
				result = append(result, fmt.Sprintf("mss %d", binary.BigEndian.Uint16(opt.OptionData)))
			}
		case layers.TCPOptionKindSACKPermitted:
			result = append(result, "sackOK")
		case layers.TCPOptionKindWindowScale:
			if len(opt.OptionData) >= 1 {
				result = append(result, fmt.Sprintf("wscale %d", opt.OptionData[0]))
			}
		case layers.TCPOptionKindTimestamps:
			if len(opt.OptionData) == 8 {
				result = append(result, fmt.Sprintf("TS val %d ecr %d",
					binary.BigEndian.Uint32(opt.OptionData[:4]),
					binary.BigEndian.Uint32(opt.OptionData[4:8])))
			}
		default:
			result = append(result, opt.String())
		}
	}
	return result
}

func FormatDumpTime(t time.Time) string {
	return t.Local().Format("15:04:05.000000")
}

func Format(data []byte, opts ...FormatOpt) string {
	var (
		parent gopacket.Layer
		b      strings.Builder
		delim  FormatDelimiter
	)

	b.WriteString(FormatDumpTime(time.Now()))
	b.WriteByte(' ')

	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	for _, layer := range p.Layers() {
		var (
			s string
			d FormatDelimiter
		)

		f, ok := GetLayerFormatter(layer.LayerType())
		if ok {
			s, d = f.Format(layer, append(opts, WithFormatParentLayer(parent))...)
		} else if layer.LayerType() != gopacket.LayerTypePayload {
			s = layer.LayerType().String()
			d = FormatDelimiterComma
		} else {
			continue
		}

		b.WriteString(string(delim))
		b.WriteString(s)
		delim = d
		parent = layer
	}
	return b.String()
}
