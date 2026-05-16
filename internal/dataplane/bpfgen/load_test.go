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

// statsMap indexes from BPF common.h.
const (
	statIngressPackets             = 0
	statParseOkPackets             = 1
	statParseErrorPackets          = 2
	statMatchHitPackets            = 3
	statMatchMissPackets           = 4
	statKernelResponsePackets      = 5
	statKernelResponseXdpTxPackets = 6
	statKernelResponseRedirectPkts = 7
	statKernelResponseErrorPackets = 8
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

// setupTxConfig writes a tx_config to tx_config_map[0].
func setupTxConfig(t *testing.T, objs *XdpassObjects, cfg XdpassTxConfig) {
	t.Helper()
	require.NoError(t, objs.TxConfigMap.Put(uint32(0), cfg))
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
		{"stats_map", ebpf.PerCPUArray, 4, 8, 17},
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
