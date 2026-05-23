package bpftest

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"xdpass/internal/dataplane/abi"
	"xdpass/internal/dataplane/bpfgen"
)

func TestTCPResetXdpTx(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, wildcardGlobalCfg(0))
	putRule(t, objs, 0, bpfgen.XdpassRuleMeta{
		RuleId:       100,
		RequiredMask: abi.CondProtoTCP,
		Action:       abi.ActionTCPReset,
	})

	pkt := tcpPacket()
	ret, out, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(3), ret, "expected XDP_TX")

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

	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{192, 168, 1, 1}
	assert.Equal(t, dstIP.To4().String(), ip.SrcIP.String(), "src IP should be original dst")
	assert.Equal(t, srcIP.To4().String(), ip.DstIP.String(), "dst IP should be original src")
	assert.Equal(t, uint16(40), ip.Length, "IP total length")
	assert.Equal(t, uint8(5), ip.IHL, "IP IHL")

	tcpLayer := parsed.Layer(layers.LayerTypeTCP)
	require.NotNil(t, tcpLayer, "output should have TCP layer")
	tcp := tcpLayer.(*layers.TCP)

	assert.Equal(t, layers.TCPPort(80), tcp.SrcPort, "src port should be original dst")
	assert.Equal(t, layers.TCPPort(12345), tcp.DstPort, "dst port should be original src")
	assert.True(t, tcp.RST, "RST flag should be set")
	assert.True(t, tcp.ACK, "ACK flag should be set")
	origSeq, _ := tcpSeqAck(t, pkt)
	assert.Equal(t, origSeq+1, tcp.Ack, "ACK should advance original SYN seq")
	assert.Equal(t, uint32(0), tcp.Seq, "SEQ should be zero for RST+ACK")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseOkPackets, 1)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
	assertStatsSum(t, objs, abi.StatKernelResponsePackets, 1)
	assertStatsSum(t, objs, abi.StatKernelResponseXDPTXPackets, 1)
	assertStatsSum(t, objs, abi.StatKernelResponseErrorPackets, 0)
}

func TestTCPResetRedirectPreserve(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, wildcardGlobalCfg(0))
	putRule(t, objs, 0, bpfgen.XdpassRuleMeta{
		RuleId:       100,
		RequiredMask: abi.CondProtoTCP,
		Action:       abi.ActionTCPReset,
	})
	putTxConfig(t, objs, bpfgen.XdpassTxConfig{
		TcpResetMode:           1,
		TcpResetEgressIfindex:  1,
		TcpResetVlanMode:       0,
		TcpResetFailureVerdict: 1,
	})

	ret, out, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(4), ret, "expected XDP_REDIRECT")

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

	assertStatsSum(t, objs, abi.StatKernelResponsePackets, 1)
	assertStatsSum(t, objs, abi.StatKernelResponseRedirectPkts, 1)
	assertStatsSum(t, objs, abi.StatKernelResponseXDPTXPackets, 0)
	assertStatsSum(t, objs, abi.StatKernelResponseErrorPackets, 0)
}

func TestTCPResetRedirectAccessVlan(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, wildcardGlobalCfg(0))
	putRule(t, objs, 0, bpfgen.XdpassRuleMeta{
		RuleId:       100,
		RequiredMask: abi.CondProtoTCP,
		Action:       abi.ActionTCPReset,
	})
	putTxConfig(t, objs, bpfgen.XdpassTxConfig{
		TcpResetMode:           1,
		TcpResetEgressIfindex:  1,
		TcpResetVlanMode:       1,
		TcpResetFailureVerdict: 1,
	})

	ret, out, err := objs.XdpassProg.Test(vlanTCPPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(4), ret, "expected XDP_REDIRECT")

	parsed := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.NoCopy)
	ethLayer := parsed.Layer(layers.LayerTypeEthernet)
	require.NotNil(t, ethLayer, "output should have Ethernet layer")
	eth := ethLayer.(*layers.Ethernet)

	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	assert.Equal(t, srcMAC.String(), eth.DstMAC.String(), "dst MAC should be original src")
	assert.Equal(t, dstMAC.String(), eth.SrcMAC.String(), "src MAC should be original dst")
	assert.Equal(t, layers.EthernetTypeIPv4, eth.EthernetType, "ethertype should be IPv4")
	assert.Nil(t, parsed.Layer(layers.LayerTypeDot1Q), "VLAN tag should be stripped")

	ipLayer := parsed.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "output should have IPv4 layer")
	ip := ipLayer.(*layers.IPv4)
	assert.Equal(t, uint16(40), ip.Length, "IP total length")

	tcpLayer := parsed.Layer(layers.LayerTypeTCP)
	require.NotNil(t, tcpLayer, "output should have TCP layer")
	tcp := tcpLayer.(*layers.TCP)
	assert.True(t, tcp.RST, "RST flag should be set")
	assert.True(t, tcp.ACK, "ACK flag should be set")

	assertStatsSum(t, objs, abi.StatKernelResponsePackets, 1)
	assertStatsSum(t, objs, abi.StatKernelResponseRedirectPkts, 1)
	assertStatsSum(t, objs, abi.StatKernelResponseXDPTXPackets, 0)
	assertStatsSum(t, objs, abi.StatKernelResponseErrorPackets, 0)
}

func TestTCPResetRedirectNoIfindex(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, wildcardGlobalCfg(0))
	putRule(t, objs, 0, bpfgen.XdpassRuleMeta{
		RuleId:       100,
		RequiredMask: abi.CondProtoTCP,
		Action:       abi.ActionTCPReset,
	})
	putTxConfig(t, objs, bpfgen.XdpassTxConfig{
		TcpResetMode:           1,
		TcpResetEgressIfindex:  0,
		TcpResetVlanMode:       0,
		TcpResetFailureVerdict: 1,
	})

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(1), ret, "expected XDP_DROP for redirect with no egress ifindex")

	assertStatsSum(t, objs, abi.StatKernelResponsePackets, 1)
	assertStatsSum(t, objs, abi.StatKernelResponseRedirectPkts, 0)
	assertStatsSum(t, objs, abi.StatKernelResponseXDPTXPackets, 0)
	assertStatsSum(t, objs, abi.StatKernelResponseErrorPackets, 1)
}

func TestActionUnknownFallback(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, wildcardGlobalCfg(0))
	putRule(t, objs, 0, bpfgen.XdpassRuleMeta{
		RuleId:       1,
		RequiredMask: abi.CondProtoTCP,
		Action:       99,
	})

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for unknown action fallback")
}
