package bpftest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"xdpass/internal/dataplane/abi"
	"xdpass/internal/dataplane/bpfgen"
	"xdpass/internal/ruleset"
)

func compileAndWrite(t testing.TB, objs *bpfgen.XdpassObjects, rules []ruleset.Rule, ingressVerdict string) {
	t.Helper()

	compiled, err := ruleset.Compile(rules, ingressVerdict)
	if err != nil {
		t.Fatalf("compile ruleset: %v", err)
	}
	if err := ruleset.WriteMaps(newObjectMaps(objs), compiled); err != nil {
		t.Fatalf("write ruleset maps: %v", err)
	}
}

func TestMatchProtocolTCP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "none"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for none action")
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchProtocolTCPMiss(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "none"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(udpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for miss")
	assertStatsSum(t, objs, abi.StatMatchMissPackets, 1)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 0)
}

func TestMatchProtocolUDP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "udp"}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(udpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchProtocolICMP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "icmp"}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(icmpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchProtocolARP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "arp"}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(arpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchDstPort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstPorts: []uint16{80}}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchDstPortMiss(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstPorts: []uint16{443}}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchMissPackets, 1)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 0)
}

func TestMatchSrcPort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", SrcPorts: []uint16{12345}}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchCIDRDstPrefix(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstCIDRs: []string{"192.168.1.0/24"}}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchARPDstPrefix(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "arp", DstCIDRs: []string{"192.168.1.1/32"}}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(arpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchCIDRDstPrefixMiss(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstCIDRs: []string{"10.0.0.0/8"}}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchMissPackets, 1)
}

func TestMatchCIDRSrcPrefix(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", SrcCIDRs: []string{"10.0.0.0/8"}}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchVLAN(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", VLANS: []uint16{100}}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(vlanTCPPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchVLANMiss(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", VLANS: []uint16{200}}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(vlanTCPPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchMissPackets, 1)
}

func TestMatchTCPSynFlag(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	synTrue := true
	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{
			Protocol: "tcp",
			TCP:      &ruleset.TCPMatch{Flags: &ruleset.TCPFlags{SYN: &synTrue}},
		}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchTCPSynFlagMiss(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	synTrue := true
	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{
			Protocol: "tcp",
			TCP:      &ruleset.TCPMatch{Flags: &ruleset.TCPFlags{SYN: &synTrue}},
		}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	pkt := tcpPacket()
	pkt[47] = 0x10

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchMissPackets, 1)
}

func TestMatchICMPEchoRequest(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "icmp", ICMP: &ruleset.ICMPMatch{Type: "echo_request"}}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(icmpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchARPRequest(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "arp", ARP: &ruleset.ARPMatch{Op: "request"}}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(arpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchPrioritySlotOrder(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "none"}},
		{RuleID: 2, Priority: 5, Match: ruleset.Match{Protocol: "tcp"}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchWildcardRule(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)

	ret, _, err = objs.XdpassProg.Test(udpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 2)
}

func TestMatchWildcardBitmap(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{Protocol: "tcp", DstPorts: []uint16{80}}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}

func TestMatchWildcardProtocolWithPort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)
	objs := loadObjects(t)

	compileAndWrite(t, objs, []ruleset.Rule{
		{RuleID: 1, Priority: 10, Match: ruleset.Match{DstPorts: []uint16{80}}, Response: ruleset.Response{Action: "alert"}},
	}, "pass")

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 1)
}
