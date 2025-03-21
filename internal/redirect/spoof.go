package redirect

import (
	"fmt"
	"net"
	"sync"

	"github.com/kentik/patricia"
	"github.com/kentik/patricia/generics_tree"
	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netutil"
	"golang.org/x/sys/unix"
)

const (
	ARPRequest            = 1
	ARPReply              = 2
	ICMPv4TypeEchoRequest = 0x8
	ICMPv4TypeEchoReply   = 0x0
)

type SpoofHandle struct {
	ifaceName    string
	hwAddr       net.HardwareAddr
	id           uint32
	mu           *sync.RWMutex
	v4RulesIDMap map[protos.SpoofRuleV4]uint32
	v4RetRules   []protos.SpoofRuleV4                      // reuse buffer for return matched rules
	v4DstIPTree  *generics_tree.TreeV4[protos.SpoofRuleV4] // search key is DstIP
}

func NewSpoofHandle(ifaceName string, hwAddr net.HardwareAddr) (*SpoofHandle, error) {
	return &SpoofHandle{
		ifaceName:    ifaceName,
		hwAddr:       hwAddr,
		mu:           &sync.RWMutex{},
		v4RulesIDMap: make(map[protos.SpoofRuleV4]uint32),
		v4RetRules:   make([]protos.SpoofRuleV4, 0, 64),
		v4DstIPTree:  generics_tree.NewTreeV4[protos.SpoofRuleV4](),
	}, nil
}

func (SpoofHandle) RedirectType() protos.RedirectType {
	return protos.RedirectTypeSpoof
}

func (h *SpoofHandle) Close() error {
	return nil
}

func (h *SpoofHandle) GetSpoofRules() []protos.SpoofRule {
	h.mu.RLock()
	defer h.mu.RUnlock()

	rules := make([]protos.SpoofRule, 0, len(h.v4RulesIDMap))
	for rule, id := range h.v4RulesIDMap {
		rules = append(rules, protos.SpoofRule{ID: id, SpoofRuleV4: rule})
	}
	return rules
}

func (h *SpoofHandle) AddSpoofRule(rule protos.SpoofRule) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	_, ok := h.v4RulesIDMap[rule.SpoofRuleV4]
	if ok {
		return fmt.Errorf("duplicate spoof rule")
	}

	h.id++
	h.v4RulesIDMap[rule.SpoofRuleV4] = h.id
	h.v4DstIPTree.Add(patricia.NewIPv4Address(rule.SpoofRuleV4.DstIP, uint(rule.SpoofRuleV4.DstIPPrefixLen)), rule.SpoofRuleV4, nil)
	return nil
}

func treeMatchFn(_, _ protos.SpoofRuleV4) bool { return true }

func (h *SpoofHandle) DelSpoofRule(rule protos.SpoofRule) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	_, ok := h.v4RulesIDMap[rule.SpoofRuleV4]
	if !ok {
		return fmt.Errorf("no matched spoof rule")
	}

	delete(h.v4RulesIDMap, rule.SpoofRuleV4)
	addr := patricia.NewIPv4Address(rule.SpoofRuleV4.DstIP, uint(rule.SpoofRuleV4.DstIPPrefixLen))
	h.v4DstIPTree.Delete(addr, treeMatchFn, rule.SpoofRuleV4)

	return nil
}

func (h *SpoofHandle) HandlePacket(pkt *fastpkt.Packet) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{
			"l3_proto": pkt.L3Proto,
			"l4_proto": pkt.L4Proto,
			"src_ip":   netutil.Uint32ToIPv4(pkt.SrcIP),
			"dst_ip":   netutil.Uint32ToIPv4(pkt.DstIP),
			"src_port": pkt.SrcPort,
			"dst_port": pkt.DstPort,
		}).Debug("Handle packet")
	}

	var err error
	switch pkt.L3Proto {
	case unix.ETH_P_ARP:
		err = h.handlePacketARP(pkt)
	case unix.ETH_P_IP:
		err = h.handlePacketIPv4(pkt)
	case unix.ETH_P_IPV6:
		err = h.handlePacketIPv6(pkt)
	default:
		return
	}
	if err != nil {
		logrus.WithError(err).Error("Handle packet error")
	}
}

func (h *SpoofHandle) handlePacketIPv4(pkt *fastpkt.Packet) error {
	switch pkt.L4Proto {
	case unix.IPPROTO_ICMP:
		return h.handlePacketICMPv4(pkt)
	case unix.IPPROTO_TCP:
		return h.handlePacketTCP(pkt)
	case unix.IPPROTO_UDP:
		return h.handlePacketUDP(pkt)
	default:
		return fastpkt.ErrPacketInvalidProtocol
	}
}

func (h *SpoofHandle) handlePacketIPv6(*fastpkt.Packet) error {
	// TODO: add ipv6 implement
	return nil
}

func (h *SpoofHandle) handlePacketICMPv4(pkt *fastpkt.Packet) error {
	var (
		rxEther = fastpkt.DataPtrEthernet(pkt.RxData, 0)
		rxIPv4  = fastpkt.DataPtrIPv4(pkt.RxData, int(pkt.L2Len))
		rxICMP  = fastpkt.DataPtrICMP(pkt.RxData, int(pkt.L2Len+pkt.L3Len))
		buf     = fastpkt.NewUncheckedBuffer(pkt.TxData)
	)

	if rxICMP.Type != ICMPv4TypeEchoRequest {
		return nil
	}

	h.mu.RLock()
	ok, rules := matchByDstIPKey(h.v4DstIPTree, pkt, h.v4RetRules[:0])
	h.mu.RUnlock()
	if !ok || len(rules) == 0 {
		return nil
	}

	found := false
	for _, rule := range rules {
		if rule.SpoofType == protos.SpoofTypeICMPEchoReply {
			if logrus.GetLevel() >= logrus.DebugLevel {
				logrus.WithField("rule", rule.String()).Debug("Matched rule")
			}
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	// Payload
	txPayloadLen := netutil.Ntohs(rxIPv4.Len) - uint16(rxIPv4.HeaderLen()) - uint16(fastpkt.SizeofICMP)
	txPayload := buf.AllocatePayload(int(txPayloadLen))
	copy(txPayload, pkt.RxData[int(pkt.L2Len)+int(pkt.L3Len)+fastpkt.SizeofICMP:])

	// L4
	txICMP := buf.AllocateICMP()
	txICMP.Type = ICMPv4TypeEchoReply
	txICMP.Code = 0
	txICMP.ID = rxICMP.ID
	txICMP.Seq = rxICMP.Seq
	txICMP.ComputeChecksum(txPayloadLen)

	// L3
	txIPv4 := buf.AllocateIPv4()
	txIPv4.SetHeaderLen(uint8(fastpkt.SizeofIPv4))
	txIPv4.TOS = 0
	txIPv4.ID = rxIPv4.ID
	txIPv4.FragOff = rxIPv4.FragOff
	txIPv4.TTL = 78
	txIPv4.Protocol = rxIPv4.Protocol
	txIPv4.SrcIP = rxIPv4.DstIP
	txIPv4.DstIP = rxIPv4.SrcIP
	txIPv4.ComputeChecksum(uint16(fastpkt.SizeofICMP) + txPayloadLen)

	// L2 VLAN
	if netutil.Ntohs(rxEther.HwProto) == unix.ETH_P_8021Q {
		rxVLAN := fastpkt.DataPtrVLAN(pkt.RxData, fastpkt.SizeofEthernet)
		txVLAN := buf.AllocateVLAN()
		txVLAN.ID = rxVLAN.ID
		txVLAN.EncapsulatedProto = rxVLAN.EncapsulatedProto
	}

	// L2 Ethernet
	txEther := buf.AllocateEthernet()
	txEther.HwSource = rxEther.HwDest
	txEther.HwDest = rxEther.HwSource
	txEther.HwProto = rxEther.HwProto

	pkt.TxData = buf.Bytes()
	return nil
}

func (h *SpoofHandle) handlePacketTCP(pkt *fastpkt.Packet) error {
	h.mu.RLock()
	ok, rules := matchByDstIPKey(h.v4DstIPTree, pkt, h.v4RetRules[:0])
	h.mu.RUnlock()
	if !ok || len(rules) == 0 {
		return nil
	}

	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithField("rules_count", len(rules)).Debug("Matched rules")
		if logrus.GetLevel() >= logrus.TraceLevel {
			for _, rule := range rules {
				logrus.WithField("rule", rule.String()).Trace("Matched rule detail")
			}
		}
	}

	for _, rule := range rules {
		if rule.SpoofType == protos.SpoofTypeTCPReset {
			return h.handlePacketTCPReset(pkt)
		} else if rule.SpoofType == protos.SpoofTypeTCPResetSYN && fastpkt.DataPtrTCP(pkt.RxData, int(pkt.L2Len+pkt.L3Len)).Flags.Has(fastpkt.TCPFlagSYN) {
			return h.handlePacketTCPReset(pkt)
		}
	}
	return nil
}

func (h *SpoofHandle) handlePacketTCPReset(pkt *fastpkt.Packet) error {
	var (
		rxEther = fastpkt.DataPtrEthernet(pkt.RxData, 0)
		rxIPv4  = fastpkt.DataPtrIPv4(pkt.RxData, int(pkt.L2Len))
		rxTCP   = fastpkt.DataPtrTCP(pkt.RxData, int(pkt.L2Len+pkt.L3Len))
		buf     = fastpkt.NewUncheckedBuffer(pkt.TxData)
	)

	// L4
	txTCP := buf.AllocateTCP()
	txTCP.SrcPort = rxTCP.DstPort
	txTCP.DstPort = rxTCP.SrcPort
	txTCP.AckSeq = netutil.Htonl(netutil.Ntohl(rxTCP.Seq) + 1)
	txTCP.SetHeaderLen(uint8(fastpkt.SizeofTCP))
	txTCP.Flags.Clear(fastpkt.TCPFlagsMask)
	txTCP.Flags.Set(fastpkt.TCPFlagRST | fastpkt.TCPFlagACK)
	txTCP.Window = rxTCP.Window
	txTCP.Check = rxTCP.Check

	// L3
	txIPv4 := buf.AllocateIPv4()
	txIPv4.SetHeaderLen(uint8(fastpkt.SizeofIPv4))
	txIPv4.TOS = 0
	txIPv4.ID = rxIPv4.ID
	txIPv4.FragOff = rxIPv4.FragOff
	txIPv4.TTL = 78
	txIPv4.Protocol = rxIPv4.Protocol
	txIPv4.SrcIP = rxIPv4.DstIP
	txIPv4.DstIP = rxIPv4.SrcIP
	txIPv4.ComputeChecksum(uint16(fastpkt.SizeofTCP))
	txTCP.ComputeChecksum(txIPv4.PseudoChecksum(), 0)

	// L2 VLAN
	if netutil.Ntohs(rxEther.HwProto) == unix.ETH_P_8021Q {
		rxVLAN := fastpkt.DataPtrVLAN(pkt.RxData, fastpkt.SizeofEthernet)
		txVLAN := buf.AllocateVLAN()
		txVLAN.ID = rxVLAN.ID
		txVLAN.EncapsulatedProto = rxVLAN.EncapsulatedProto
	}

	// L2 Ethernet
	txEther := buf.AllocateEthernet()
	txEther.HwSource = rxEther.HwDest
	txEther.HwDest = rxEther.HwSource
	txEther.HwProto = rxEther.HwProto

	pkt.TxData = buf.Bytes()
	return nil
}

func (h *SpoofHandle) handlePacketUDP(*fastpkt.Packet) error {
	// TODO: add udp implement
	return nil
}

func (h *SpoofHandle) handlePacketARP(pkt *fastpkt.Packet) error {
	var (
		rxEther   = fastpkt.DataPtrEthernet(pkt.RxData, 0)
		rxPayload = pkt.RxData[pkt.L2Len+uint8(fastpkt.SizeofARP):]
		rxARP     = fastpkt.DataPtrARP(pkt.RxData, int(pkt.L2Len))
		buf       = fastpkt.NewUncheckedBuffer(pkt.TxData)
	)

	// TODO: support IPv6
	if netutil.Ntohs(rxARP.Operation) != ARPRequest || rxARP.ProtAddrLen != 4 {
		return nil
	}

	dstIP := netutil.IPv4ToUint32(rxPayload[rxARP.HwAddrLen*2+rxARP.ProtAddrLen : rxARP.HwAddrLen*2+rxARP.ProtAddrLen*2])
	dstAddr := patricia.NewIPv4Address(dstIP, 32)
	h.mu.RLock()
	ok, rules := h.v4DstIPTree.FindDeepestTagsWithFilterAppend(h.v4RetRules[:0], dstAddr, func(tag protos.SpoofRuleV4) bool { return tag.Proto == unix.ETH_P_ARP })
	h.mu.RUnlock()
	if !ok || len(rules) == 0 {
		return nil
	}

	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithField("rules_count", len(rules)).Debug("Matched rules")
		if logrus.GetLevel() >= logrus.TraceLevel {
			for _, rule := range rules {
				logrus.WithField("rule", rule.String()).Trace("Matched rule detail")
			}
		}
	}

	// L3
	txPayload := buf.AllocatePayload(int(rxARP.HwAddrLen*2 + rxARP.ProtAddrLen*2))

	// ARP reply
	// Source hardware address
	copy(txPayload[:rxARP.HwAddrLen], []byte(h.hwAddr))
	// Source protocol address
	copy(txPayload[rxARP.HwAddrLen:rxARP.HwAddrLen+rxARP.ProtAddrLen], rxPayload[rxARP.HwAddrLen*2+rxARP.ProtAddrLen:rxARP.HwAddrLen*2+rxARP.ProtAddrLen*2])
	// Dest hardware address
	copy(txPayload[rxARP.HwAddrLen+rxARP.ProtAddrLen:rxARP.HwAddrLen*2+rxARP.ProtAddrLen], rxPayload[:rxARP.HwAddrLen])
	// Dest protocol address
	copy(txPayload[rxARP.HwAddrLen*2+rxARP.ProtAddrLen:rxARP.HwAddrLen*2+rxARP.ProtAddrLen*2], rxPayload[rxARP.HwAddrLen:rxARP.HwAddrLen+rxARP.ProtAddrLen])

	txARP := buf.AllocateARP()
	txARP.HwAddrType = rxARP.HwAddrType
	txARP.ProtAddrType = rxARP.ProtAddrType
	txARP.HwAddrLen = rxARP.HwAddrLen
	txARP.ProtAddrLen = rxARP.ProtAddrLen
	txARP.Operation = netutil.Htons(ARPReply)

	// L2 VLAN
	if netutil.Ntohs(rxEther.HwProto) == unix.ETH_P_8021Q {
		rxVLAN := fastpkt.DataPtrVLAN(pkt.RxData, fastpkt.SizeofEthernet)
		txVLAN := buf.AllocateVLAN()
		txVLAN.ID = rxVLAN.ID
		txVLAN.EncapsulatedProto = rxVLAN.EncapsulatedProto
	}

	// L2 Ethernet
	txEther := buf.AllocateEthernet()
	txEther.HwSource = [6]byte(h.hwAddr)
	txEther.HwDest = rxEther.HwSource
	txEther.HwProto = rxEther.HwProto

	pkt.TxData = buf.Bytes()

	return nil
}

func IPv4PrefixToUint32(addr uint32, prefixLen uint) uint32 {
	return addr & (0xFFFFFFFF << (32 - prefixLen))
}

// matchByDstIPKey return true if matched dst ip
func matchByDstIPKey(trie *generics_tree.TreeV4[protos.SpoofRuleV4], pkt *fastpkt.Packet, ret []protos.SpoofRuleV4) (bool, []protos.SpoofRuleV4) {
	dstIP := patricia.NewIPv4Address(pkt.DstIP, 32)
	return trie.FindDeepestTagsWithFilterAppend(ret, dstIP, func(tag protos.SpoofRuleV4) bool {
		if tag.Proto != 0 && tag.Proto != pkt.L4Proto {
			return false
		}
		if tag.SrcPort != 0 && tag.SrcPort != pkt.SrcPort {
			return false
		}
		if tag.DstPort != 0 && tag.DstPort != pkt.DstPort {
			return false
		}
		return IPv4PrefixToUint32(tag.SrcIP, uint(tag.SrcIPPrefixLen)) == IPv4PrefixToUint32(pkt.SrcIP, uint(tag.SrcIPPrefixLen))
	})
}
