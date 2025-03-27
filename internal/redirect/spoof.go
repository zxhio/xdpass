package redirect

import (
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/spoof"
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netutil"
)

const (
	ARPRequest            = 1
	ARPReply              = 2
	ICMPv4TypeEchoRequest = 0x8
	ICMPv4TypeEchoReply   = 0x0
)

type SpoofHandle struct {
	ifaceName string
	hwAddr    net.HardwareAddr
	id        uint32
	mu        *sync.RWMutex
	rules     map[uint32]*spoof.Rule
}

func NewSpoofHandle(ifaceName string, hwAddr net.HardwareAddr) (*SpoofHandle, error) {
	return &SpoofHandle{
		ifaceName: ifaceName,
		hwAddr:    hwAddr,
		mu:        &sync.RWMutex{},
		rules:     make(map[uint32]*spoof.Rule),
	}, nil
}

func (SpoofHandle) RedirectType() protos.RedirectType {
	return protos.RedirectTypeSpoof
}

func (h *SpoofHandle) Close() error {
	return nil
}

func (h *SpoofHandle) GetSpoofRules() []spoof.Rule {
	h.mu.RLock()
	defer h.mu.RUnlock()

	rules := make([]spoof.Rule, 0, len(h.rules))
	for _, rule := range h.rules {
		rules = append(rules, *rule)
	}
	return rules
}

func (h *SpoofHandle) AddSpoofRule(rule spoof.Rule) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, r := range h.rules {
		if r.Equal(&rule) {
			return fmt.Errorf("existed rule")
		}
	}

	h.id++
	rule.ID = h.id
	h.rules[h.id] = &rule
	return nil
}

func (h *SpoofHandle) DelSpoofRule(rule spoof.Rule) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	for id, r := range h.rules {
		if r.Equal(&rule) {
			delete(h.rules, id)
			return nil
		}
	}
	return fmt.Errorf("no such spoof rule")
}

func (h *SpoofHandle) HandlePacket(pkt *fastpkt.Packet) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{
			"l3_proto": pkt.L3Proto,
			"l4_proto": pkt.L4Proto,
			"src_ip":   netutil.IPv4FromUint32(pkt.SrcIP),
			"dst_ip":   netutil.IPv4FromUint32(pkt.DstIP),
			"src_port": pkt.SrcPort,
			"dst_port": pkt.DstPort,
		}).Debug("Handle packet")
	}

	for _, rule := range h.rules {
		matched := true

		for _, m := range rule.Matchs {
			if !m.Match(pkt) {
				matched = false
				break
			}
		}
		if matched {
			if logrus.GetLevel() >= logrus.DebugLevel {
				logrus.WithFields(logrus.Fields{
					"l3_proto":    pkt.L3Proto,
					"l4_proto":    pkt.L4Proto,
					"src_ip":      netutil.IPv4FromUint32(pkt.SrcIP),
					"dst_ip":      netutil.IPv4FromUint32(pkt.DstIP),
					"src_port":    pkt.SrcPort,
					"dst_port":    pkt.DstPort,
					"target_type": rule.Target.TargetType(),
				}).Debug("Handle packet")
			}
			if err := rule.Target.Execute(pkt); err != nil {
				logrus.WithError(err).Error("Handle packet error")
			}
			break
		}
	}
}
