package bpftest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"xdpass/internal/dataplane/abi"
)

func TestEmptyRulesetMissVerdictPass(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for empty ruleset")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseOkPackets, 1)
	assertStatsSum(t, objs, abi.StatMatchMissPackets, 1)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 0)
}

func TestEmptyRulesetMissVerdictDrop(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	cfg := emptyGlobalCfg()
	cfg.IngressVerdict = 1
	putGlobalCfg(t, objs, cfg)

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(1), ret, "expected XDP_DROP for empty ruleset with drop verdict")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseOkPackets, 1)
	assertStatsSum(t, objs, abi.StatMatchMissPackets, 1)
	assertStatsSum(t, objs, abi.StatMatchHitPackets, 0)
}

func TestParseShortPacket(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	ret, _, err := objs.XdpassProg.Test(make([]byte, 10))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for short packet")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseErrorPackets, 1)
	assertStatsSum(t, objs, abi.StatParseOkPackets, 0)
}

func TestParseUnknownEthertype(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	pkt := make([]byte, 64)
	copy(pkt[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x12
	pkt[13] = 0x34

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for unknown ethertype")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseErrorPackets, 1)
	assertStatsSum(t, objs, abi.StatParseOkPackets, 0)
}

func TestParseIPv4TCP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	ret, _, err := objs.XdpassProg.Test(tcpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseOkPackets, 1)
	assertStatsSum(t, objs, abi.StatParseErrorPackets, 0)
	assertStatsSum(t, objs, abi.StatMatchMissPackets, 1)
}

func TestParseIPv4UDP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	ret, _, err := objs.XdpassProg.Test(udpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseOkPackets, 1)
	assertStatsSum(t, objs, abi.StatParseErrorPackets, 0)
}

func TestParseIPv4ICMP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	ret, _, err := objs.XdpassProg.Test(icmpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseOkPackets, 1)
	assertStatsSum(t, objs, abi.StatParseErrorPackets, 0)
}

func TestParseARP(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	ret, _, err := objs.XdpassProg.Test(arpPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseOkPackets, 1)
	assertStatsSum(t, objs, abi.StatParseErrorPackets, 0)
}

func TestParseVLAN(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	ret, _, err := objs.XdpassProg.Test(vlanTCPPacket())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseOkPackets, 1)
	assertStatsSum(t, objs, abi.StatParseErrorPackets, 0)
}

func TestParseMalformedIPv4Short(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	pkt := make([]byte, 30)
	copy(pkt[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x08
	pkt[13] = 0x00
	pkt[14] = 0x45

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for malformed IPv4")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseErrorPackets, 1)
	assertStatsSum(t, objs, abi.StatParseOkPackets, 0)
}

func TestParseMalformedIPv4SmallIHL(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	pkt := make([]byte, 64)
	copy(pkt[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x08
	pkt[13] = 0x00
	pkt[14] = 0x42

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for small IHL")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseErrorPackets, 1)
}

func TestParseMalformedTCPShort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	pkt := make([]byte, 38)
	copy(pkt[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x08
	pkt[13] = 0x00
	pkt[14] = 0x45
	pkt[23] = 6
	pkt[26] = 10
	pkt[30] = 192

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for truncated TCP")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseErrorPackets, 1)
}

func TestParseMalformedUDPShort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	pkt := make([]byte, 38)
	copy(pkt[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x08
	pkt[13] = 0x00
	pkt[14] = 0x45
	pkt[23] = 17
	pkt[26] = 10
	pkt[30] = 192

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for truncated UDP")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseErrorPackets, 1)
}

func TestParseMalformedICMPShort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	pkt := make([]byte, 36)
	copy(pkt[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x08
	pkt[13] = 0x00
	pkt[14] = 0x45
	pkt[23] = 1
	pkt[26] = 10
	pkt[30] = 192

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for truncated ICMP")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseErrorPackets, 1)
}

func TestParseMalformedARPShort(t *testing.T) {
	skipUnlessBPF(t)
	removeMemlock(t)

	objs := loadObjects(t)
	putGlobalCfg(t, objs, emptyGlobalCfg())

	pkt := make([]byte, 30)
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(pkt[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	pkt[12] = 0x08
	pkt[13] = 0x06

	ret, _, err := objs.XdpassProg.Test(pkt)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "expected XDP_PASS for truncated ARP")

	assertStatsSum(t, objs, abi.StatIngressPackets, 1)
	assertStatsSum(t, objs, abi.StatParseErrorPackets, 1)
}
