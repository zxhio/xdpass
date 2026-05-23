// Package bpftest provides shared BPF test support for integration tests.
package bpftest

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"xdpass/internal/attachment"
	"xdpass/internal/dataplane/abi"
	"xdpass/internal/dataplane/bpfgen"
)

const benchRepeat = 10000

func skipUnlessBPF(tb testing.TB) {
	tb.Helper()
	if os.Getenv("XDPASS_RUN_BPF_TESTS") != "1" {
		tb.Skip("set XDPASS_RUN_BPF_TESTS=1 to load the BPF program")
	}
}

func removeMemlock(tb testing.TB) {
	tb.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		tb.Fatalf("remove memlock: %v", err)
	}
}

func loadObjects(tb testing.TB) *bpfgen.XdpassObjects {
	tb.Helper()

	var objs bpfgen.XdpassObjects
	if err := bpfgen.LoadXdpassObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelBranch | ebpf.LogLevelStats,
			LogSizeStart: 16 * 1024 * 1024,
		},
	}); err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			tb.Fatalf("load xdpass objects: %+v", verifierErr)
		}
		tb.Fatalf("load xdpass objects: %+v", err)
	}

	tb.Cleanup(func() {
		if err := objs.Close(); err != nil {
			tb.Fatalf("close xdpass objects: %v", err)
		}
	})
	return &objs
}

type objectMaps struct {
	objects *bpfgen.XdpassObjects
}

func newObjectMaps(objects *bpfgen.XdpassObjects) *objectMaps {
	return &objectMaps{objects: objects}
}

var _ attachment.MapAccessor = (*objectMaps)(nil)

func (m *objectMaps) RuleIndexMap() *ebpf.Map    { return m.objects.RuleIndexMap }
func (m *objectMaps) GlobalCfgMap() *ebpf.Map    { return m.objects.GlobalCfgMap }
func (m *objectMaps) TxConfigMap() *ebpf.Map     { return m.objects.TxConfigMap }
func (m *objectMaps) SrcPortIndexMap() *ebpf.Map { return m.objects.SrcPortIndexMap }
func (m *objectMaps) DstPortIndexMap() *ebpf.Map { return m.objects.DstPortIndexMap }
func (m *objectMaps) VlanIndexMap() *ebpf.Map    { return m.objects.VlanIndexMap }
func (m *objectMaps) SrcPrefixLpmMap() *ebpf.Map { return m.objects.SrcPrefixLpmMap }
func (m *objectMaps) DstPrefixLpmMap() *ebpf.Map { return m.objects.DstPrefixLpmMap }
func (m *objectMaps) EventRingbufMap() *ebpf.Map { return m.objects.EventRingbuf }
func (m *objectMaps) StatsMap() *ebpf.Map        { return m.objects.StatsMap }
func (m *objectMaps) XsksMap() *ebpf.Map         { return m.objects.XsksMap }

func assertStatsSum(tb testing.TB, objs *bpfgen.XdpassObjects, index uint32, expected uint64) {
	tb.Helper()

	var percpu []uint64
	if err := objs.StatsMap.Lookup(index, &percpu); err != nil {
		tb.Fatalf("lookup stats[%d]: %v", index, err)
	}
	var sum uint64
	for _, v := range percpu {
		sum += v
	}
	if sum != expected {
		tb.Fatalf("stats[%d] = %d, want %d", index, sum, expected)
	}
}

func slotMask(slot uint32) bpfgen.XdpassMaskT {
	var mask bpfgen.XdpassMaskT
	group := slot / abi.RulesPerGroup
	bit := slot % abi.RulesPerGroup
	mask.Bits[group] = 1 << bit
	return mask
}

func emptyGlobalCfg() bpfgen.XdpassGlobalCfg {
	return bpfgen.XdpassGlobalCfg{}
}

func wildcardGlobalCfg(ingressVerdict uint32) bpfgen.XdpassGlobalCfg {
	s0 := slotMask(0)
	cfg := bpfgen.XdpassGlobalCfg{
		AllActiveRules:         s0,
		VlanWildcardRules:      s0,
		SrcPortWildcardRules:   s0,
		DstPortWildcardRules:   s0,
		SrcPrefixWildcardRules: s0,
		DstPrefixWildcardRules: s0,
		IngressVerdict:         ingressVerdict,
	}
	for i := range cfg.ConditionWildcardRules {
		cfg.ConditionWildcardRules[i] = s0
	}
	return cfg
}

func putGlobalCfg(tb testing.TB, objs *bpfgen.XdpassObjects, cfg bpfgen.XdpassGlobalCfg) {
	tb.Helper()
	if err := objs.GlobalCfgMap.Put(uint32(0), cfg); err != nil {
		tb.Fatalf("write global_cfg_map: %v", err)
	}
}

func putRule(tb testing.TB, objs *bpfgen.XdpassObjects, slot uint32, rule bpfgen.XdpassRuleMeta) {
	tb.Helper()
	if err := objs.RuleIndexMap.Put(slot, rule); err != nil {
		tb.Fatalf("write rule_index_map[%d]: %v", slot, err)
	}
}

func putTxConfig(tb testing.TB, objs *bpfgen.XdpassObjects, cfg bpfgen.XdpassTxConfig) {
	tb.Helper()
	if err := objs.TxConfigMap.Put(uint32(0), cfg); err != nil {
		tb.Fatalf("write tx_config_map: %v", err)
	}
}

func tcpPacket() []byte {
	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{192, 168, 1, 1}
	return buildTCPSYN(srcMAC, dstMAC, srcIP, dstIP, 12345, 80)
}

func vlanTCPPacket() []byte {
	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{192, 168, 1, 1}
	return buildVLANTCPSYN(srcMAC, dstMAC, srcIP, dstIP, 12345, 80, 100)
}

func udpPacket() []byte {
	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{192, 168, 1, 1}
	return buildUDPPacket(srcMAC, dstMAC, srcIP, dstIP, 12345, 53)
}

func icmpPacket() []byte {
	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{192, 168, 1, 1}
	return buildICMPEchoRequest(srcMAC, dstMAC, srcIP, dstIP)
}

func arpPacket() []byte {
	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	srcIP := net.IP{192, 168, 1, 100}
	dstIP := net.IP{192, 168, 1, 1}
	return buildARPRequest(srcMAC, srcIP, dstIP)
}

func tcpSeqAck(tb testing.TB, pkt []byte) (uint32, uint32) {
	tb.Helper()

	parsed := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.NoCopy)
	tcpLayer := parsed.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		tb.Fatal("packet should have TCP layer")
	}
	tcp := tcpLayer.(*layers.TCP)
	return tcp.Seq, tcp.Ack
}

func benchmarkMatchRun(b *testing.B, prog *ebpf.Program, pkt []byte) {
	b.Helper()
	b.ReportAllocs()
	for range b.N {
		_, perRun, err := prog.Benchmark(pkt, benchRepeat, b.ResetTimer)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(perRun.Nanoseconds()), "ns/run")
	}
}

func buildTCPSYN(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp)
	return buf.Bytes()
}

func buildVLANTCPSYN(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, vlanID uint16) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeDot1Q,
	}
	vlan := &layers.Dot1Q{
		VLANIdentifier: vlanID,
		Type:           layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, vlan, ip, tcp)
	return buf.Bytes()
}

func buildUDPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(make([]byte, 16)))
	return buf.Bytes()
}

func buildICMPEchoRequest(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0),
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, icmp, gopacket.Payload(make([]byte, 32)))
	return buf.Bytes()
}

func buildARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP,
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    dstIP,
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, arp)
	return buf.Bytes()
}
