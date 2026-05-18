package bpfgen

import (
	"errors"
	"net"
	"os"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"xdpass/internal/attachment"
	"xdpass/internal/dataplane/abi"
	"xdpass/internal/ruleset"
)

func skipUnlessBPF(t *testing.T) {
	t.Helper()
	if os.Getenv("XDPASS_RUN_BPF_TESTS") != "1" {
		t.Skip("set XDPASS_RUN_BPF_TESTS=1 to load the BPF program")
	}
}

func removeMemlock(t *testing.T) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
}

func loadSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	spec, err := LoadXdpass()
	require.NoError(t, err, "LoadXdpass")
	return spec
}

func loadObjects(t *testing.T) *XdpassObjects {
	t.Helper()
	var objs XdpassObjects
	if err := LoadXdpassObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelBranch | ebpf.LogLevelStats,
			LogSizeStart: 16 * 1024 * 1024,
		},
	}); err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			t.Fatalf("load xdpass objects: %+v", verifierErr)
		}
		t.Fatalf("load xdpass objects: %+v", err)
	}
	t.Cleanup(func() {
		if err := objs.Close(); err != nil {
			t.Fatalf("close xdpass objects: %v", err)
		}
	})
	return &objs
}

// --- Test helpers ---

// Shared ABI aliases for tests.
const (
	statIngressPackets             = abi.StatIngressPackets
	statParseOkPackets             = abi.StatParseOkPackets
	statParseErrorPackets          = abi.StatParseErrorPackets
	statMatchHitPackets            = abi.StatMatchHitPackets
	statMatchMissPackets           = abi.StatMatchMissPackets
	statKernelResponsePackets      = abi.StatKernelResponsePackets
	statKernelResponseXdpTxPackets = abi.StatKernelResponseXDPTXPackets
	statKernelResponseRedirectPkts = abi.StatKernelResponseRedirectPkts
	statKernelResponseErrorPackets = abi.StatKernelResponseErrorPackets
	statXskRedirectPackets         = abi.StatXSKRedirectPackets
	statXskRedirectErrorPackets    = abi.StatXSKRedirectErrorPackets
	statEventDroppedPackets        = abi.StatEventDroppedPackets
	statDiagRuleCandidates         = abi.StatDiagRuleCandidates
	statDiagRedirectFailed         = abi.StatDiagRedirectFailed
	statDiagFibLookupFailed        = abi.StatDiagFibLookupFailed
	statDiagXskMetaFailed          = abi.StatDiagXskMetaFailed
	statDiagXskMapRedirectFailed   = abi.StatDiagXskMapRedirectFailed
)

// condition bits from shared ABI.
const (
	condProtoTCP        = abi.CondProtoTCP
	condProtoUDP        = abi.CondProtoUDP
	condProtoICMP       = abi.CondProtoICMP
	condProtoARP        = abi.CondProtoARP
	condVLAN            = abi.CondVLAN
	condSrcPrefix       = abi.CondSrcPrefix
	condDstPrefix       = abi.CondDstPrefix
	condSrcPort         = abi.CondSrcPort
	condDstPort         = abi.CondDstPort
	condTCPSyn          = abi.CondTCPSyn
	condTCPAck          = abi.CondTCPAck
	condTCPRst          = abi.CondTCPRst
	condTCPFin          = abi.CondTCPFin
	condTCPPsh          = abi.CondTCPPsh
	condICMPEchoRequest = abi.CondICMPEchoRequest
	condICMPEchoReply   = abi.CondICMPEchoReply
	condARPRequest      = abi.CondARPRequest
	condARPReply        = abi.CondARPReply
	condL4Payload       = abi.CondL4Payload
)

// action codes from shared ABI.
const (
	actionNone                = abi.ActionNone
	actionAlert               = abi.ActionAlert
	actionTCPReset            = abi.ActionTCPReset
	actionICMPEchoReply       = abi.ActionICMPEchoReply
	actionARPReply            = abi.ActionARPReply
	actionTCPSynAck           = abi.ActionTCPSynAck
	actionICMPPortUnreachable = abi.ActionICMPPortUnreachable
	actionUDPEchoReply        = abi.ActionUDPEchoReply
	actionDNSRefused          = abi.ActionDNSRefused
	actionICMPHostUnreachable = abi.ActionICMPHostUnreachable
	actionICMPAdminProhibited = abi.ActionICMPAdminProhibited
	actionDNSSinkhole         = abi.ActionDNSSinkhole
)

// assertStatsSum reads a PERCPU_ARRAY stat and asserts the sum across CPUs.
func assertStatsSum(t *testing.T, objs *XdpassObjects, index uint32, expected uint64) {
	t.Helper()
	var percpu []uint64
	require.NoError(t, objs.StatsMap.Lookup(index, &percpu))
	var sum uint64
	for _, v := range percpu {
		sum += v
	}
	assert.Equal(t, expected, sum, "stats[%d]", index)
}

// zeroMask returns a zeroed mask_t (no rules active).
func zeroMask() XdpassMaskT {
	return XdpassMaskT{}
}

// slot0Mask returns a mask_t with bit 0 set (slot 0 active).
func slot0Mask() XdpassMaskT {
	return XdpassMaskT{Bits: [8]uint64{1}}
}

// setupGlobalCfg writes a global_cfg to global_cfg_map[0].
func setupGlobalCfg(t *testing.T, objs *XdpassObjects, cfg XdpassGlobalCfg) {
	t.Helper()
	require.NoError(t, objs.GlobalCfgMap.Put(uint32(0), cfg))
}

// emptyGlobalCfg returns a global_cfg with no active rules and ingress_verdict=0 (pass).
func emptyGlobalCfg() XdpassGlobalCfg {
	return XdpassGlobalCfg{}
}

// wildcardGlobalCfg returns a global_cfg with slot 0 active and all optional bits set.
func wildcardGlobalCfg(ingressVerdict uint32) XdpassGlobalCfg {
	s0 := slot0Mask()
	cfg := XdpassGlobalCfg{
		AllActiveRules:         s0,
		VlanOptionalRules:      s0,
		SrcPortOptionalRules:   s0,
		DstPortOptionalRules:   s0,
		SrcPrefixOptionalRules: s0,
		DstPrefixOptionalRules: s0,
		IngressVerdict:         ingressVerdict,
	}
	for i := range cfg.ConditionOptionalRules {
		cfg.ConditionOptionalRules[i] = s0
	}
	return cfg
}

// setupRule writes a rule_meta to rule_index_map[slot].
func setupRule(t *testing.T, objs *XdpassObjects, slot uint32, rule XdpassRuleMeta) {
	t.Helper()
	require.NoError(t, objs.RuleIndexMap.Put(slot, rule))
}

// buildTCPSYN builds a minimal Ethernet + IPv4 + TCP SYN packet using gopacket.
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

// testPacket returns a standard test TCP SYN packet fixture.
func testPacket() []byte {
	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{192, 168, 1, 1}
	return buildTCPSYN(srcMAC, dstMAC, srcIP, dstIP, 12345, 80)
}

// buildVlanTCPSYN builds a VLAN-tagged Ethernet + IPv4 + TCP SYN packet.
func buildVlanTCPSYN(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, vlanID uint16) []byte {
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

// testVlanPacket returns a VLAN-tagged (VLAN 100) test TCP SYN packet fixture.
func testVlanPacket() []byte {
	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{192, 168, 1, 1}
	return buildVlanTCPSYN(srcMAC, dstMAC, srcIP, dstIP, 12345, 80, 100)
}

// buildUDPPacket builds a minimal Ethernet + IPv4 + UDP packet.
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
	payload := make([]byte, 16)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload))
	return buf.Bytes()
}

// buildICMPEchoRequest builds a minimal Ethernet + IPv4 + ICMP echo request packet.
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
		TypeCode: layers.CreateICMPv4TypeCode(8, 0), // echo request
	}
	payload := make([]byte, 32)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, icmp, gopacket.Payload(payload))
	return buf.Bytes()
}

// buildARPRequest builds a minimal Ethernet + ARP request packet.
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
		Operation:         1, // request
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP,
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    dstIP,
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, arp)
	return buf.Bytes()
}

// testUDPPacket returns a standard test UDP packet fixture.
func testUDPPacket() []byte {
	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{192, 168, 1, 1}
	return buildUDPPacket(srcMAC, dstMAC, srcIP, dstIP, 12345, 53)
}

// testICMPPacket returns a standard test ICMP echo request packet fixture.
func testICMPPacket() []byte {
	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{192, 168, 1, 1}
	return buildICMPEchoRequest(srcMAC, dstMAC, srcIP, dstIP)
}

// testARPPacket returns a standard test ARP request packet fixture.
func testARPPacket() []byte {
	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	srcIP := net.IP{192, 168, 1, 100}
	dstIP := net.IP{192, 168, 1, 1}
	return buildARPRequest(srcMAC, srcIP, dstIP)
}

// setupTxConfig writes a tx_config to tx_config_map[0].
func setupTxConfig(t *testing.T, objs *XdpassObjects, cfg XdpassTxConfig) {
	t.Helper()
	require.NoError(t, objs.TxConfigMap.Put(uint32(0), cfg))
}

// objsMapAccessor adapts XdpassMaps to attachment.MapAccessor for ruleset.WriteMaps.
type objsMapAccessor struct {
	maps *XdpassMaps
}

func (o *objsMapAccessor) RuleIndexMap() *ebpf.Map    { return o.maps.RuleIndexMap }
func (o *objsMapAccessor) GlobalCfgMap() *ebpf.Map    { return o.maps.GlobalCfgMap }
func (o *objsMapAccessor) TxConfigMap() *ebpf.Map     { return o.maps.TxConfigMap }
func (o *objsMapAccessor) SrcPortIndexMap() *ebpf.Map { return o.maps.SrcPortIndexMap }
func (o *objsMapAccessor) DstPortIndexMap() *ebpf.Map { return o.maps.DstPortIndexMap }
func (o *objsMapAccessor) VlanIndexMap() *ebpf.Map    { return o.maps.VlanIndexMap }
func (o *objsMapAccessor) SrcPrefixLpmMap() *ebpf.Map { return o.maps.SrcPrefixLpmMap }
func (o *objsMapAccessor) DstPrefixLpmMap() *ebpf.Map { return o.maps.DstPrefixLpmMap }
func (o *objsMapAccessor) EventRingbufMap() *ebpf.Map { return o.maps.EventRingbuf }
func (o *objsMapAccessor) StatsMap() *ebpf.Map        { return o.maps.StatsMap }
func (o *objsMapAccessor) XsksMap() *ebpf.Map         { return o.maps.XsksMap }

var _ attachment.MapAccessor = (*objsMapAccessor)(nil)

// compileAndWrite compiles rules and writes them to BPF maps via the MapAccessor.
func compileAndWrite(t *testing.T, objs *XdpassObjects, rules []ruleset.Rule, ingressVerdict string) {
	t.Helper()
	compiled, err := ruleset.Compile(rules, ingressVerdict)
	require.NoError(t, err, "compile ruleset")
	maps := &objsMapAccessor{maps: &objs.XdpassMaps}
	require.NoError(t, ruleset.WriteMaps(maps, compiled), "write maps")
}

// --- Spec tests ---

func TestXdpassSpecParse(t *testing.T) {
	skipUnlessBPF(t)

	spec := loadSpec(t)

	_, ok := spec.Programs["xdpass_prog"]
	assert.True(t, ok, "program xdpass_prog not found")

	expectedMaps := []string{
		"rule_index_map",
		"global_cfg_map",
		"tx_config_map",
		"src_port_index_map",
		"dst_port_index_map",
		"vlan_index_map",
		"src_prefix_lpm_map",
		"dst_prefix_lpm_map",
		"event_ringbuf",
		"stats_map",
		"xsks_map",
	}
	for _, name := range expectedMaps {
		_, ok := spec.Maps[name]
		assert.True(t, ok, "map %s not found", name)
	}
}

func TestXdpassMapSpecs(t *testing.T) {
	skipUnlessBPF(t)

	spec := loadSpec(t)

	maskTSize := uint32(unsafe.Sizeof(XdpassMaskT{}))

	tests := []struct {
		name       string
		mapType    ebpf.MapType
		keySize    uint32
		valueSize  uint32
		maxEntries uint32
	}{
		{"rule_index_map", ebpf.Array, 4, uint32(unsafe.Sizeof(XdpassRuleMeta{})), 512},
		{"global_cfg_map", ebpf.Array, 4, uint32(unsafe.Sizeof(XdpassGlobalCfg{})), 1},
		{"tx_config_map", ebpf.Array, 4, uint32(unsafe.Sizeof(XdpassTxConfig{})), 1},
		{"src_port_index_map", ebpf.Hash, 2, maskTSize, 4096},
		{"dst_port_index_map", ebpf.Hash, 2, maskTSize, 4096},
		{"vlan_index_map", ebpf.Hash, 2, maskTSize, 4096},
		{"src_prefix_lpm_map", ebpf.LPMTrie, uint32(unsafe.Sizeof(XdpassIpv4LpmKey{})), maskTSize, 4096},
		{"dst_prefix_lpm_map", ebpf.LPMTrie, uint32(unsafe.Sizeof(XdpassIpv4LpmKey{})), maskTSize, 4096},
		{"stats_map", ebpf.PerCPUArray, 4, 8, abi.StatCount},
		{"xsks_map", ebpf.XSKMap, 4, 4, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, ok := spec.Maps[tt.name]
			require.True(t, ok, "map %s not found", tt.name)
			assert.Equal(t, tt.mapType, m.Type, "map %s type", tt.name)
			assert.Equal(t, tt.keySize, m.KeySize, "map %s key size", tt.name)
			assert.Equal(t, tt.valueSize, m.ValueSize, "map %s value size", tt.name)
			assert.Equal(t, tt.maxEntries, m.MaxEntries, "map %s max entries", tt.name)
		})
	}

	t.Run("event_ringbuf", func(t *testing.T) {
		m, ok := spec.Maps["event_ringbuf"]
		require.True(t, ok, "map event_ringbuf not found")
		assert.Equal(t, ebpf.RingBuf, m.Type, "map event_ringbuf type")
		assert.Equal(t, uint32(16*1024*1024), m.MaxEntries, "map event_ringbuf max entries")
	})
}

// --- Program load test ---

func TestXdpassProgramLoad(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	loadObjects(t)
}

// --- Packet path tests ---

func TestEmptyRulesetMissVerdictPass(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)

	// Empty ruleset: no active rules, ingress_verdict=0 (pass).
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	pkt := testPacket()

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS (2) for empty ruleset with ingress_verdict=0")

	// Stats: ingress=1, parse_ok=1, match_miss=1.
	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseOkPackets, 1)
	assertStatsSum(t, objs, statMatchMissPackets, 1)
	assertStatsSum(t, objs, statMatchHitPackets, 0)
}

func TestEmptyRulesetMissVerdictDrop(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)

	// Empty ruleset with ingress_verdict=1 (drop).
	cfg := emptyGlobalCfg()
	cfg.IngressVerdict = 1
	setupGlobalCfg(t, objs, cfg)

	pkt := testPacket()

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), ret, "expected XDP_DROP (1) for empty ruleset with ingress_verdict=1")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseOkPackets, 1)
	assertStatsSum(t, objs, statMatchMissPackets, 1)
	assertStatsSum(t, objs, statMatchHitPackets, 0)
}

func TestTcpResetXdpTx(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)

	// Wildcard rule: slot 0 active, all optional bits set.
	setupGlobalCfg(t, objs, wildcardGlobalCfg(0))

	// Rule: slot 0 = tcp_reset (action code 2).
	setupRule(t, objs, 0, XdpassRuleMeta{
		RuleId:       100,
		RequiredMask: 0x01, // COND_PROTO_TCP
		Action:       2,    // ACTION_TCP_RESET
	})

	pkt := testPacket()

	const xdpTx = 3 // XDP_TX from linux/if_link.h

	ret, out, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(xdpTx), ret, "expected XDP_TX")

	// Parse output packet.
	parsed := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.NoCopy)
	ethLayer := parsed.Layer(layers.LayerTypeEthernet)
	require.NotNil(t, ethLayer, "output should have Ethernet layer")
	eth := ethLayer.(*layers.Ethernet)

	// MAC swapped.
	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	assert.Equal(t, srcMAC.String(), eth.DstMAC.String(), "dst MAC should be original src")
	assert.Equal(t, dstMAC.String(), eth.SrcMAC.String(), "src MAC should be original dst")

	ipLayer := parsed.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "output should have IPv4 layer")
	ip := ipLayer.(*layers.IPv4)

	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{192, 168, 1, 1}
	assert.Equal(t, dstIP.To4().String(), ip.SrcIP.String(), "src IP should be original dst")
	assert.Equal(t, srcIP.To4().String(), ip.DstIP.String(), "dst IP should be original src")
	assert.Equal(t, uint16(40), ip.Length, "IP total length")
	assert.Equal(t, uint8(5), ip.IHL, "IP IHL")

	tcpLayer := parsed.Layer(layers.LayerTypeTCP)
	require.NotNil(t, tcpLayer, "output should have TCP layer")
	tcp := tcpLayer.(*layers.TCP)

	// Ports swapped.
	assert.Equal(t, layers.TCPPort(80), tcp.SrcPort, "src port should be original dst")
	assert.Equal(t, layers.TCPPort(12345), tcp.DstPort, "dst port should be original src")
	assert.True(t, tcp.RST, "RST flag should be set")
	assert.True(t, tcp.ACK, "ACK flag should be set")

	// Stats.
	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseOkPackets, 1)
	assertStatsSum(t, objs, statMatchHitPackets, 1)
	assertStatsSum(t, objs, statKernelResponsePackets, 1)
	assertStatsSum(t, objs, statKernelResponseXdpTxPackets, 1)
	assertStatsSum(t, objs, statKernelResponseErrorPackets, 0)
}

func TestTcpResetRedirectPreserve(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)

	setupGlobalCfg(t, objs, wildcardGlobalCfg(0))
	setupRule(t, objs, 0, XdpassRuleMeta{
		RuleId:       100,
		RequiredMask: 0x01, // COND_PROTO_TCP
		Action:       2,    // ACTION_TCP_RESET
	})

	// tx_config: redirect mode, egress ifindex=1 (lo), vlan_mode=preserve.
	setupTxConfig(t, objs, XdpassTxConfig{
		TcpResetMode:           1, // TX_MODE_REDIRECT
		TcpResetEgressIfindex:  1,
		TcpResetVlanMode:       0, // VLAN_MODE_PRESERVE
		TcpResetFailureVerdict: 1,
	})

	pkt := testPacket()

	const xdpRedirect = 4 // XDP_REDIRECT from linux/if_link.h

	ret, out, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(xdpRedirect), ret, "expected XDP_REDIRECT")

	// Parse output: should be a valid RST packet (VLAN preserved = no VLAN in this case).
	parsed := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.NoCopy)
	ethLayer := parsed.Layer(layers.LayerTypeEthernet)
	require.NotNil(t, ethLayer, "output should have Ethernet layer")
	eth := ethLayer.(*layers.Ethernet)

	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	assert.Equal(t, srcMAC.String(), eth.DstMAC.String(), "dst MAC should be original src")
	assert.Equal(t, dstMAC.String(), eth.SrcMAC.String(), "src MAC should be original dst")

	ipLayer := parsed.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "output should have IPv4 layer")
	ip := ipLayer.(*layers.IPv4)
	assert.Equal(t, uint16(40), ip.Length, "IP total length")

	tcpLayer := parsed.Layer(layers.LayerTypeTCP)
	require.NotNil(t, tcpLayer, "output should have TCP layer")
	tcp := tcpLayer.(*layers.TCP)
	assert.True(t, tcp.RST, "RST flag should be set")
	assert.True(t, tcp.ACK, "ACK flag should be set")

	// Stats: redirect success.
	assertStatsSum(t, objs, statKernelResponsePackets, 1)
	assertStatsSum(t, objs, statKernelResponseRedirectPkts, 1)
	assertStatsSum(t, objs, statKernelResponseXdpTxPackets, 0)
	assertStatsSum(t, objs, statKernelResponseErrorPackets, 0)
}

func TestTcpResetRedirectAccessVlan(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)

	setupGlobalCfg(t, objs, wildcardGlobalCfg(0))
	setupRule(t, objs, 0, XdpassRuleMeta{
		RuleId:       100,
		RequiredMask: 0x01, // COND_PROTO_TCP
		Action:       2,    // ACTION_TCP_RESET
	})

	// tx_config: redirect mode, egress ifindex=1, vlan_mode=access (strip VLAN).
	setupTxConfig(t, objs, XdpassTxConfig{
		TcpResetMode:           1, // TX_MODE_REDIRECT
		TcpResetEgressIfindex:  1,
		TcpResetVlanMode:       1, // VLAN_MODE_ACCESS
		TcpResetFailureVerdict: 1,
	})

	pkt := testVlanPacket() // VLAN 100 tagged

	const xdpRedirect = 4

	ret, out, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(xdpRedirect), ret, "expected XDP_REDIRECT")

	// Parse output: VLAN should be stripped, so it's plain Ethernet.
	parsed := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.NoCopy)
	ethLayer := parsed.Layer(layers.LayerTypeEthernet)
	require.NotNil(t, ethLayer, "output should have Ethernet layer")
	eth := ethLayer.(*layers.Ethernet)

	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	assert.Equal(t, srcMAC.String(), eth.DstMAC.String(), "dst MAC should be original src")
	assert.Equal(t, dstMAC.String(), eth.SrcMAC.String(), "src MAC should be original dst")
	assert.Equal(t, layers.EthernetTypeIPv4, eth.EthernetType, "ethertype should be IPv4 (no VLAN)")

	// Verify no Dot1Q layer in output.
	vlanLayer := parsed.Layer(layers.LayerTypeDot1Q)
	assert.Nil(t, vlanLayer, "VLAN tag should be stripped in access mode")

	ipLayer := parsed.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "output should have IPv4 layer")
	ip := ipLayer.(*layers.IPv4)
	assert.Equal(t, uint16(40), ip.Length, "IP total length")

	tcpLayer := parsed.Layer(layers.LayerTypeTCP)
	require.NotNil(t, tcpLayer, "output should have TCP layer")
	tcp := tcpLayer.(*layers.TCP)
	assert.True(t, tcp.RST, "RST flag should be set")
	assert.True(t, tcp.ACK, "ACK flag should be set")

	// Stats: redirect success.
	assertStatsSum(t, objs, statKernelResponsePackets, 1)
	assertStatsSum(t, objs, statKernelResponseRedirectPkts, 1)
	assertStatsSum(t, objs, statKernelResponseXdpTxPackets, 0)
	assertStatsSum(t, objs, statKernelResponseErrorPackets, 0)
}

func TestTcpResetRedirectNoIfindex(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)

	setupGlobalCfg(t, objs, wildcardGlobalCfg(0))
	setupRule(t, objs, 0, XdpassRuleMeta{
		RuleId:       100,
		RequiredMask: 0x01, // COND_PROTO_TCP
		Action:       2,    // ACTION_TCP_RESET
	})

	// tx_config: redirect mode but egress ifindex=0 (not configured).
	setupTxConfig(t, objs, XdpassTxConfig{
		TcpResetMode:           1, // TX_MODE_REDIRECT
		TcpResetEgressIfindex:  0, // not configured
		TcpResetVlanMode:       0,
		TcpResetFailureVerdict: 1,
	})

	pkt := testPacket()

	const xdpDrop = 1

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(xdpDrop), ret, "expected XDP_DROP for redirect with no egress ifindex")

	// Stats: kernel response counted, error counted, no redirect success.
	assertStatsSum(t, objs, statKernelResponsePackets, 1)
	assertStatsSum(t, objs, statKernelResponseRedirectPkts, 0)
	assertStatsSum(t, objs, statKernelResponseXdpTxPackets, 0)
	assertStatsSum(t, objs, statKernelResponseErrorPackets, 1)
}

// --- Stage 1: ABI layout tests ---

func TestABIStructSizes(t *testing.T) {
	// Verify Go struct sizes match BPF C struct sizes.
	// mask_t: 8 * uint64 = 64 bytes.
	assert.Equal(t, uintptr(64), unsafe.Sizeof(XdpassMaskT{}), "mask_t size")
	// rule_meta: uint32 + uint32 + uint16 + uint8 + pad = 12 bytes.
	assert.Equal(t, uintptr(12), unsafe.Sizeof(XdpassRuleMeta{}), "rule_meta size")
	// tx_config: 4 * uint32 = 16 bytes.
	assert.Equal(t, uintptr(16), unsafe.Sizeof(XdpassTxConfig{}), "tx_config size")
	// ipv4_lpm_key: uint32 + uint32 = 8 bytes.
	assert.Equal(t, uintptr(8), unsafe.Sizeof(XdpassIpv4LpmKey{}), "ipv4_lpm_key size")

	// global_cfg: 6 mask_t + 19 mask_t + uint32 + 4 pad = 25*64 + 4 + 4 = 1608.
	expectedGlobalCfg := uintptr(25*64 + 4 + 4)
	assert.Equal(t, expectedGlobalCfg, unsafe.Sizeof(XdpassGlobalCfg{}), "global_cfg size")
}

// --- Stage 2: Packet parse boundary tests ---

func TestParseShortPacket(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	// Packet shorter than Ethernet header (14 bytes).
	pkt := make([]byte, 10)

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	// Short packet: parse fails, returns miss_verdict (pass=2 for ingress_verdict=0).
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for short packet")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseErrorPackets, 1)
	assertStatsSum(t, objs, statParseOkPackets, 0)
}

func TestParseUnknownEthertype(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	// Ethernet frame with unknown ethertype (0x1234).
	pkt := make([]byte, 64)
	copy(pkt[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x12
	pkt[13] = 0x34

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	// Unknown ethertype: parse fails, returns miss_verdict (pass).
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for unknown ethertype")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseErrorPackets, 1)
	assertStatsSum(t, objs, statParseOkPackets, 0)
}

func TestParseIPv4TCP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	pkt := testPacket()

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseOkPackets, 1)
	assertStatsSum(t, objs, statParseErrorPackets, 0)
	assertStatsSum(t, objs, statMatchMissPackets, 1)
}

func TestParseIPv4UDP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	pkt := testUDPPacket()

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseOkPackets, 1)
	assertStatsSum(t, objs, statParseErrorPackets, 0)
}

func TestParseIPv4ICMP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	pkt := testICMPPacket()

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseOkPackets, 1)
	assertStatsSum(t, objs, statParseErrorPackets, 0)
}

func TestParseARP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	pkt := testARPPacket()

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseOkPackets, 1)
	assertStatsSum(t, objs, statParseErrorPackets, 0)
}

func TestParseVLAN(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	pkt := testVlanPacket() // VLAN 100 tagged TCP SYN

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseOkPackets, 1)
	assertStatsSum(t, objs, statParseErrorPackets, 0)
}

func TestParseMalformedIPv4Short(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	// Ethernet says IPv4 but packet is too short for IPv4 header.
	pkt := make([]byte, 30)
	copy(pkt[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x08 // ethertype = IPv4
	pkt[13] = 0x00
	pkt[14] = 0x45 // version=4, IHL=5

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	// Malformed: parse fails, returns miss_verdict.
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for malformed IPv4")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseErrorPackets, 1)
	assertStatsSum(t, objs, statParseOkPackets, 0)
}

func TestParseMalformedIPv4SmallIHL(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	// IPv4 with IHL < 5 (invalid).
	pkt := make([]byte, 64)
	copy(pkt[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x08
	pkt[13] = 0x00
	pkt[14] = 0x42 // version=4, IHL=2 (invalid, minimum is 5)

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for small IHL")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseErrorPackets, 1)
}

func TestParseMalformedTCPShort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	// IPv4 TCP packet truncated before TCP header.
	// Ethernet(14) + IPv4(20) = 34 bytes minimum, but we cut at 38 (TCP src port only).
	pkt := make([]byte, 38)
	copy(pkt[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x08
	pkt[13] = 0x00
	pkt[14] = 0x45 // version=4, IHL=5
	pkt[23] = 6    // protocol = TCP
	pkt[26] = 10   // src IP
	pkt[30] = 192  // dst IP

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for truncated TCP")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseErrorPackets, 1)
}

func TestParseMalformedUDPShort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	// IPv4 UDP packet truncated before full UDP header.
	pkt := make([]byte, 38) // Ethernet(14) + IPv4(20) + 4 bytes of UDP (need 8)
	copy(pkt[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x08
	pkt[13] = 0x00
	pkt[14] = 0x45
	pkt[23] = 17 // protocol = UDP
	pkt[26] = 10
	pkt[30] = 192

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for truncated UDP")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseErrorPackets, 1)
}

func TestParseMalformedICMPShort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	// IPv4 ICMP packet truncated before ICMP header.
	pkt := make([]byte, 36) // Ethernet(14) + IPv4(20) + 2 bytes of ICMP (need 4+)
	copy(pkt[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x08
	pkt[13] = 0x00
	pkt[14] = 0x45
	pkt[23] = 1 // protocol = ICMP
	pkt[26] = 10
	pkt[30] = 192

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for truncated ICMP")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseErrorPackets, 1)
}

func TestParseMalformedARPShort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	setupGlobalCfg(t, objs, emptyGlobalCfg())

	// ARP packet truncated (too short for full ARP header).
	pkt := make([]byte, 30) // Need at least 14+28=42 for Ethernet+ARP
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x08
	pkt[13] = 0x06 // ethertype = ARP

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for truncated ARP")

	assertStatsSum(t, objs, statIngressPackets, 1)
	assertStatsSum(t, objs, statParseErrorPackets, 1)
}

// --- Stage 3: Ruleset match boundary tests ---

func TestMatchProtocolTCP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "none"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket() // TCP SYN
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for none action")
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchProtocolTCPMiss(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "none"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testUDPPacket() // UDP, not TCP
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for miss")
	assertStatsSum(t, objs, statMatchMissPackets, 1)
	assertStatsSum(t, objs, statMatchHitPackets, 0)
}

func TestMatchProtocolUDP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "udp"}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testUDPPacket()
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for alert action")
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchProtocolICMP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "icmp"}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testICMPPacket()
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS")
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchProtocolARP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "arp"}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testARPPacket()
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS")
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchDstPort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstPorts: []uint16{80}}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket() // dst port 80
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchDstPortMiss(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstPorts: []uint16{443}}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket() // dst port 80, rule wants 443
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchMissPackets, 1)
	assertStatsSum(t, objs, statMatchHitPackets, 0)
}

func TestMatchSrcPort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", SrcPorts: []uint16{12345}}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket() // src port 12345
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchCIDRDstPrefix(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstCIDRs: []string{"192.168.1.0/24"}}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket() // dst 192.168.1.1
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchCIDRDstPrefixMiss(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstCIDRs: []string{"10.0.0.0/8"}}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket() // dst 192.168.1.1, rule wants 10.0.0.0/8
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchMissPackets, 1)
}

func TestMatchCIDRSrcPrefix(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", SrcCIDRs: []string{"10.0.0.0/8"}}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket() // src 10.0.0.1
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchVLAN(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", VLANS: []uint16{100}}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testVlanPacket() // VLAN 100
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchVLANMiss(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", VLANS: []uint16{200}}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testVlanPacket() // VLAN 100, rule wants 200
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchMissPackets, 1)
}

func TestMatchTCPSynFlag(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	synTrue := true
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{
			Protocol: "tcp",
			TCPFlags: &ruleset.TCPFlags{SYN: &synTrue},
		}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket() // TCP SYN
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchTCPSynFlagMiss(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	synTrue := true
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{
			Protocol: "tcp",
			TCPFlags: &ruleset.TCPFlags{SYN: &synTrue},
		}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket()
	pkt[47] = 0x10 // TCP flags: ACK only (offset 14+20+13=47)

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchMissPackets, 1)
}

func TestMatchICMPEchoRequest(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "icmp", ICMPType: "echo_request"}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testICMPPacket()
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchARPRequest(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "arp", ARPOP: "request"}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testARPPacket()
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchPrioritySlotOrder(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	// Two rules both match TCP. Lower priority number = higher priority = earlier slot.
	// Rule 2 (priority 5) goes to slot 0, rule 1 (priority 10) goes to slot 1.
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "none"}},
		{RuleID: 2, Priority: 5, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket()
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchWildcardRule(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	// Wildcard rule: no match conditions, matches everything.
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket()
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchHitPackets, 1)

	pkt = testUDPPacket()
	ret, _, err = objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchHitPackets, 2)
}

func TestMatchOptionalBitmap(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	// Rule: protocol=tcp, dst_port=80. No src_port, no VLAN, no CIDR.
	// Optional bitmaps should allow this rule to match.
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstPorts: []uint16{80}}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket() // TCP, dst port 80, no VLAN
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestMatchWildcardProtocolWithPort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	// Rule with port condition but no protocol: matches any protocol with that port.
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{DstPorts: []uint16{80}}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket() // TCP dst port 80
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

// --- Stage 4: Action path boundary tests ---

func TestActionNoneObserve(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "none"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket()
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	// none action: observe + miss_verdict (pass).
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for none action")
	assertStatsSum(t, objs, statMatchHitPackets, 1)
	assertStatsSum(t, objs, statKernelResponsePackets, 0)
}

func TestActionAlertObserve(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "alert"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket()
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for alert action")
	assertStatsSum(t, objs, statMatchHitPackets, 1)
	assertStatsSum(t, objs, statKernelResponsePackets, 0)
}

func TestActionNoneObserveDrop(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "none"}},
	}
	compileAndWrite(t, objs, rules, "drop")

	pkt := testPacket()
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	// none action with ingress_verdict=drop: observe + miss_verdict (drop).
	assert.Equal(t, uint32(1), ret, "expected XDP_DROP for none action with drop verdict")
	assertStatsSum(t, objs, statMatchHitPackets, 1)
}

func TestActionICMPPortUnreachableXSKRedirect(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "icmp_port_unreachable"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket()
	const xdpDrop = 1

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	// ICMP port unreachable goes through XSK response path. No XSK socket
	// registered, so bpf_redirect_map fails and returns response_failure_verdict
	// (XDP_DROP). Stats go to xsk_redirect error, not kernel_response.
	assert.Equal(t, uint32(xdpDrop), ret, "expected XDP_DROP for ICMP port unreachable XSK redirect failure")
	assertStatsSum(t, objs, statMatchHitPackets, 1)
	assertStatsSum(t, objs, statXskRedirectErrorPackets, 1)
	assertStatsSum(t, objs, statXskRedirectPackets, 0)
	assertStatsSum(t, objs, statKernelResponsePackets, 0)
}

func TestActionICMPHostUnreachableXSKRedirect(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "icmp_host_unreachable"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket()
	const xdpDrop = 1

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(xdpDrop), ret, "expected XDP_DROP for ICMP host unreachable XSK redirect failure")
	assertStatsSum(t, objs, statMatchHitPackets, 1)
	assertStatsSum(t, objs, statXskRedirectErrorPackets, 1)
	assertStatsSum(t, objs, statXskRedirectPackets, 0)
	assertStatsSum(t, objs, statKernelResponsePackets, 0)
}

func TestActionICMPAdminProhibitedXSKRedirect(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "icmp_admin_prohibited"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testPacket()
	const xdpDrop = 1

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(xdpDrop), ret, "expected XDP_DROP for ICMP admin prohibited XSK redirect failure")
	assertStatsSum(t, objs, statMatchHitPackets, 1)
	assertStatsSum(t, objs, statXskRedirectErrorPackets, 1)
	assertStatsSum(t, objs, statXskRedirectPackets, 0)
	assertStatsSum(t, objs, statKernelResponsePackets, 0)
}

func TestActionXSKNoSocket(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	// ICMP echo reply -> XSK response path. No XSK socket registered.
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "icmp"}, Response: ruleset.Response{Action: "icmp_echo_reply"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testICMPPacket()
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	// XSK redirect without socket: bpf_redirect_map returns != XDP_REDIRECT.
	// Falls to response_failure_verdict() = XDP_DROP.
	assert.Equal(t, uint32(1), ret, "expected XDP_DROP for XSK response without socket")
	assertStatsSum(t, objs, statMatchHitPackets, 1)
	assertStatsSum(t, objs, statXskRedirectErrorPackets, 1)
	assertStatsSum(t, objs, statXskRedirectPackets, 0)
}

func TestActionARPReplyXSKNoSocket(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "arp"}, Response: ruleset.Response{Action: "arp_reply"}},
	}
	compileAndWrite(t, objs, rules, "pass")

	pkt := testARPPacket()
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), ret, "expected XDP_DROP")
	assertStatsSum(t, objs, statXskRedirectErrorPackets, 1)
}

func TestActionUnknownFallback(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	// Manually set an unknown action code on a rule.
	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	// Overwrite slot 0 with an unknown action code (99).
	setupRule(t, objs, 0, XdpassRuleMeta{
		RuleId:       1,
		RequiredMask: condProtoTCP,
		Action:       99, // unknown
	})

	pkt := testPacket()
	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	// Unknown action falls through to default -> miss_verdict (pass).
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for unknown action fallback")
}

// --- Stage 5: Match benchmarks ---

// benchmarkSetup holds pre-compiled state for match benchmarks.
type benchmarkSetup struct {
	objs *XdpassObjects
	pkt  []byte
}

func newBenchmarkSetup(b *testing.B, rules []ruleset.Rule, ingressVerdict string, pkt []byte) *benchmarkSetup {
	b.Helper()
	removeMemlockB(b)
	objs := loadObjectsB(b)
	compileAndWriteB(b, objs, rules, ingressVerdict)
	return &benchmarkSetup{objs: objs, pkt: pkt}
}

func removeMemlockB(b *testing.B) {
	b.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatalf("remove memlock: %v", err)
	}
}

func loadObjectsB(b *testing.B) *XdpassObjects {
	b.Helper()
	var objs XdpassObjects
	if err := LoadXdpassObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelBranch | ebpf.LogLevelStats,
			LogSizeStart: 16 * 1024 * 1024,
		},
	}); err != nil {
		b.Fatalf("load xdpass objects: %+v", err)
	}
	b.Cleanup(func() { objs.Close() })
	return &objs
}

func compileAndWriteB(b *testing.B, objs *XdpassObjects, rules []ruleset.Rule, ingressVerdict string) {
	b.Helper()
	compiled, err := ruleset.Compile(rules, ingressVerdict)
	if err != nil {
		b.Fatalf("compile: %v", err)
	}
	maps := &objsMapAccessor{maps: &objs.XdpassMaps}
	if err := ruleset.WriteMaps(maps, compiled); err != nil {
		b.Fatalf("write maps: %v", err)
	}
}

func skipUnlessBPF_b(b *testing.B) {
	b.Helper()
	if os.Getenv("XDPASS_RUN_BPF_TESTS") != "1" {
		b.Skip("set XDPASS_RUN_BPF_TESTS=1 to run BPF benchmarks")
	}
}

const benchRepeat = 10000

// benchmarkMatchRun runs the BPF program benchRepeat times in a single syscall
// via Program.Benchmark() and reports kernel-side ns/run. This isolates BPF
// execution from Go-side syscall and allocation overhead.
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

func BenchmarkMatchEmptyRuleset(b *testing.B) {
	skipUnlessBPF_b(b)
	s := newBenchmarkSetup(b, nil, "pass", testPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatchSingleWildcard(b *testing.B) {
	skipUnlessBPF_b(b)
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{}, Response: ruleset.Response{Action: "none"}},
	}
	s := newBenchmarkSetup(b, rules, "pass", testPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatchDstPortHit(b *testing.B) {
	skipUnlessBPF_b(b)
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstPorts: []uint16{80}}, Response: ruleset.Response{Action: "none"}},
	}
	s := newBenchmarkSetup(b, rules, "pass", testPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatchDstPortMiss(b *testing.B) {
	skipUnlessBPF_b(b)
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstPorts: []uint16{443}}, Response: ruleset.Response{Action: "none"}},
	}
	s := newBenchmarkSetup(b, rules, "pass", testPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatchCIDRHit(b *testing.B) {
	skipUnlessBPF_b(b)
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstCIDRs: []string{"192.168.1.0/24"}}, Response: ruleset.Response{Action: "none"}},
	}
	s := newBenchmarkSetup(b, rules, "pass", testPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatchCIDRMiss(b *testing.B) {
	skipUnlessBPF_b(b)
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstCIDRs: []string{"10.0.0.0/8"}}, Response: ruleset.Response{Action: "none"}},
	}
	s := newBenchmarkSetup(b, rules, "pass", testPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatchMixedRules(b *testing.B) {
	skipUnlessBPF_b(b)
	rules := []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "udp", DstPorts: []uint16{53}}, Response: ruleset.Response{Action: "none"}},
		{RuleID: 2, Priority: 20, Match: ruleset.Match{Protocol: "tcp", DstCIDRs: []string{"10.0.0.0/8"}}, Response: ruleset.Response{Action: "none"}},
		{RuleID: 3, Priority: 30, Match: ruleset.Match{Protocol: "tcp", DstPorts: []uint16{80}}, Response: ruleset.Response{Action: "none"}},
		{RuleID: 4, Priority: 40, Match: ruleset.Match{Protocol: "icmp"}, Response: ruleset.Response{Action: "none"}},
		{RuleID: 5, Priority: 50, Match: ruleset.Match{Protocol: "arp"}, Response: ruleset.Response{Action: "none"}},
	}
	s := newBenchmarkSetup(b, rules, "pass", testPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

// generateRules creates N rules with the last one matching on dst port 80.
func generateRules(n int) []ruleset.Rule {
	rules := make([]ruleset.Rule, n)
	for i := range n - 1 {
		rules[i] = ruleset.Rule{
			RuleID:   uint32(i + 1),
			Priority: uint32((i + 1) * 10),
			Match:    ruleset.Match{Protocol: "tcp", DstPorts: []uint16{uint16(1000 + i)}},
			Response: ruleset.Response{Action: "none"},
		}
	}
	// Last rule matches port 80.
	rules[n-1] = ruleset.Rule{
		RuleID:   uint32(n),
		Priority: uint32(n * 10),
		Match:    ruleset.Match{Protocol: "tcp", DstPorts: []uint16{80}},
		Response: ruleset.Response{Action: "none"},
	}
	return rules
}

func BenchmarkMatch1Rule(b *testing.B) {
	skipUnlessBPF_b(b)
	s := newBenchmarkSetup(b, generateRules(1), "pass", testPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatch10Rules(b *testing.B) {
	skipUnlessBPF_b(b)
	s := newBenchmarkSetup(b, generateRules(10), "pass", testPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatch100Rules(b *testing.B) {
	skipUnlessBPF_b(b)
	s := newBenchmarkSetup(b, generateRules(100), "pass", testPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatch512RulesLateHit(b *testing.B) {
	skipUnlessBPF_b(b)
	s := newBenchmarkSetup(b, generateRules(512), "pass", testPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}

func BenchmarkMatch512RulesMiss(b *testing.B) {
	skipUnlessBPF_b(b)
	rules := make([]ruleset.Rule, 512)
	for i := range 512 {
		rules[i] = ruleset.Rule{
			RuleID:   uint32(i + 1),
			Priority: uint32((i + 1) * 10),
			Match:    ruleset.Match{Protocol: "tcp", DstPorts: []uint16{uint16(1000 + i)}},
			Response: ruleset.Response{Action: "none"},
		}
	}
	s := newBenchmarkSetup(b, rules, "pass", testPacket())
	b.ResetTimer()
	benchmarkMatchRun(b, s.objs.XdpassProg, s.pkt)
}
