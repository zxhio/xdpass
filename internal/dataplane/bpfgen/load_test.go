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

func TestXdpassProgramLoad(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	loadObjects(t)
}

func TestTcpResetXdpTx(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)

	// Set up global config: slot 0 active as wildcard rule (all optional bits set).
	slot0 := XdpassMaskT{Bits: [8]uint64{1}}
	cfg := XdpassGlobalCfg{
		AllActiveRules:         slot0,
		VlanOptionalRules:      slot0,
		SrcPortOptionalRules:   slot0,
		DstPortOptionalRules:   slot0,
		SrcPrefixOptionalRules: slot0,
		DstPrefixOptionalRules: slot0,
	}
	for i := range cfg.ConditionOptionalRules {
		cfg.ConditionOptionalRules[i] = slot0
	}
	require.NoError(t, objs.GlobalCfgMap.Put(uint32(0), cfg))

	// Set up rule: slot 0 = tcp_reset (action code 2).
	rule := XdpassRuleMeta{
		RuleId:       100,
		RequiredMask: 0x01, // COND_PROTO_TCP
		Action:       2,    // ACTION_TCP_RESET
	}
	require.NoError(t, objs.RuleIndexMap.Put(uint32(0), rule))

	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{192, 168, 1, 1}
	pkt := buildTCPSYN(srcMAC, dstMAC, srcIP, dstIP, 12345, 80)

	// XDP return codes from linux/if_link.h.
	const xdpTx = 3

	ret, out, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(xdpTx), ret, "expected XDP_TX")

	// Parse output packet.
	parsed := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.NoCopy)
	ethLayer := parsed.Layer(layers.LayerTypeEthernet)
	require.NotNil(t, ethLayer, "output should have Ethernet layer")
	eth := ethLayer.(*layers.Ethernet)

	// MAC swapped.
	assert.Equal(t, srcMAC.String(), eth.DstMAC.String(), "dst MAC should be original src")
	assert.Equal(t, dstMAC.String(), eth.SrcMAC.String(), "src MAC should be original dst")

	ipLayer := parsed.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "output should have IPv4 layer")
	ip := ipLayer.(*layers.IPv4)

	// IP swapped.
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

	// Stats: kernel_response.packets=1, kernel_response.xdp_tx_packets=1.
	assertStatsSum(t, objs, 5, 1) // STAT_KERNEL_RESPONSE_PACKETS
	assertStatsSum(t, objs, 6, 1) // STAT_KERNEL_RESPONSE_XDP_TX_PACKETS
	assertStatsSum(t, objs, 8, 0) // STAT_KERNEL_RESPONSE_ERROR_PACKETS
}
