package ruleset

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	"xdpass/internal/attachment"
	"xdpass/internal/dataplane/abi"
)

var conditionLogNames = []struct {
	mask uint32
	name string
}{
	{mask: abi.CondProtoTCP, name: "proto_tcp"},
	{mask: abi.CondProtoUDP, name: "proto_udp"},
	{mask: abi.CondProtoICMP, name: "proto_icmp"},
	{mask: abi.CondProtoARP, name: "proto_arp"},
	{mask: abi.CondVLAN, name: "vlan"},
	{mask: abi.CondSrcPrefix, name: "src_prefix"},
	{mask: abi.CondDstPrefix, name: "dst_prefix"},
	{mask: abi.CondSrcPort, name: "src_port"},
	{mask: abi.CondDstPort, name: "dst_port"},
	{mask: abi.CondTCPSyn, name: "tcp_syn"},
	{mask: abi.CondTCPAck, name: "tcp_ack"},
	{mask: abi.CondTCPRst, name: "tcp_rst"},
	{mask: abi.CondTCPFin, name: "tcp_fin"},
	{mask: abi.CondTCPPsh, name: "tcp_psh"},
	{mask: abi.CondICMPEchoRequest, name: "icmp_echo_request"},
	{mask: abi.CondARPRequest, name: "arp_request"},
}

// WriteMaps writes a compiled ruleset to an attachment's BPF maps.
func WriteMaps(maps attachment.MapAccessor, compiled *CompiledRuleset) error {
	if err := writeRuleIndexMap(maps.RuleIndexMap(), compiled.Rules); err != nil {
		return fmt.Errorf("write rule_index_map: %w", err)
	}
	if err := writeGlobalCfgMap(maps.GlobalCfgMap(), &compiled.GlobalCfg); err != nil {
		return fmt.Errorf("write global_cfg_map: %w", err)
	}
	if err := writePortIndexMap("src_port_index_map", maps.SrcPortIndexMap(), compiled.Indexes.SrcPortIndex); err != nil {
		return fmt.Errorf("write src_port_index_map: %w", err)
	}
	if err := writePortIndexMap("dst_port_index_map", maps.DstPortIndexMap(), compiled.Indexes.DstPortIndex); err != nil {
		return fmt.Errorf("write dst_port_index_map: %w", err)
	}
	if err := writeVlanIndexMap(maps.VlanIndexMap(), compiled.Indexes.VlanIndex); err != nil {
		return fmt.Errorf("write vlan_index_map: %w", err)
	}
	if err := writeLpmMap("src_prefix_lpm_map", maps.SrcPrefixLpmMap(), compiled.Indexes.SrcPrefixLPM); err != nil {
		return fmt.Errorf("write src_prefix_lpm_map: %w", err)
	}
	if err := writeLpmMap("dst_prefix_lpm_map", maps.DstPrefixLpmMap(), compiled.Indexes.DstPrefixLPM); err != nil {
		return fmt.Errorf("write dst_prefix_lpm_map: %w", err)
	}
	return nil
}

// ClearMaps clears all ruleset-related BPF maps for an attachment.
func ClearMaps(maps attachment.MapAccessor) error {
	if err := clearArrayMap(maps.RuleIndexMap(), abi.MaxRuleSlots); err != nil {
		return fmt.Errorf("clear rule_index_map: %w", err)
	}
	if err := clearGlobalCfgMap(maps.GlobalCfgMap()); err != nil {
		return fmt.Errorf("clear global_cfg_map: %w", err)
	}
	if err := clearHashMap("src_port_index_map", maps.SrcPortIndexMap()); err != nil {
		return fmt.Errorf("clear src_port_index_map: %w", err)
	}
	if err := clearHashMap("dst_port_index_map", maps.DstPortIndexMap()); err != nil {
		return fmt.Errorf("clear dst_port_index_map: %w", err)
	}
	if err := clearHashMap("vlan_index_map", maps.VlanIndexMap()); err != nil {
		return fmt.Errorf("clear vlan_index_map: %w", err)
	}
	if err := clearLpmMap("src_prefix_lpm_map", maps.SrcPrefixLpmMap()); err != nil {
		return fmt.Errorf("clear src_prefix_lpm_map: %w", err)
	}
	if err := clearLpmMap("dst_prefix_lpm_map", maps.DstPrefixLpmMap()); err != nil {
		return fmt.Errorf("clear dst_prefix_lpm_map: %w", err)
	}
	return nil
}

// BPF struct layouts matching the generated Go types.

type bpfRuleMeta struct {
	RuleID       uint32
	RequiredMask uint32
	Action       uint16
	Flags        uint8
	_            [1]byte
}

type bpfGlobalCfg struct {
	AllActiveRules         RuleMask
	VlanWildcardRules      RuleMask
	SrcPortWildcardRules   RuleMask
	DstPortWildcardRules   RuleMask
	SrcPrefixWildcardRules RuleMask
	DstPrefixWildcardRules RuleMask
	ConditionWildcardRules [abi.ConditionBits]RuleMask
	IngressVerdict         uint32
	_                      [4]byte
}

type bpfIpv4LpmKey struct {
	Prefixlen uint32
	Addr      uint32
}

func writeRuleIndexMap(m *ebpf.Map, rules []CompiledRule) error {
	zero := bpfRuleMeta{}
	logrus.WithFields(logrus.Fields{
		"map":        "rule_index_map",
		"slot_start": 0,
		"slot_end":   abi.MaxRuleSlots - 1,
		"slots":      abi.MaxRuleSlots,
	}).Debug("Clear BPF rules")
	for i := range abi.MaxRuleSlots {
		if err := m.Put(uint32(i), zero); err != nil {
			return err
		}
	}
	for _, rule := range rules {
		meta := bpfRuleMeta{
			RuleID:       rule.Meta.RuleID,
			RequiredMask: rule.Meta.RequiredMask,
			Action:       rule.Meta.Action,
			Flags:        rule.Meta.Flags,
		}
		logrus.WithFields(logrus.Fields{
			"map":           "rule_index_map",
			"slot":          rule.Slot,
			"rule_id":       meta.RuleID,
			"required_mask": requiredMaskLogValue(meta.RequiredMask),
			"action":        actionLogValue(meta.Action),
			"flags":         meta.Flags,
		}).Debug("Write BPF rule")
		if err := m.Put(rule.Slot, meta); err != nil {
			return err
		}
	}
	return nil
}

func actionLogValue(code uint16) string {
	for name, value := range actionCodeMap {
		if value == code {
			return fmt.Sprintf("%s(%d)", name, code)
		}
	}
	return fmt.Sprintf("unknown(%d)", code)
}

func requiredMaskLogValue(mask uint32) string {
	if mask == 0 {
		return "wildcard(0x0)"
	}
	parts := make([]string, 0, len(conditionLogNames))
	for _, condition := range conditionLogNames {
		if mask&condition.mask != 0 {
			parts = append(parts, condition.name)
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("unknown(0x%x)", mask)
	}
	return fmt.Sprintf("%s(0x%x)", strings.Join(parts, "|"), mask)
}

func writeGlobalCfgMap(m *ebpf.Map, cfg *GlobalCfgData) error {
	val := bpfGlobalCfg{
		AllActiveRules:         cfg.AllActiveRules,
		VlanWildcardRules:      cfg.VlanWildcardRules,
		SrcPortWildcardRules:   cfg.SrcPortWildcardRules,
		DstPortWildcardRules:   cfg.DstPortWildcardRules,
		SrcPrefixWildcardRules: cfg.SrcPrefixWildcardRules,
		DstPrefixWildcardRules: cfg.DstPrefixWildcardRules,
		ConditionWildcardRules: cfg.ConditionWildcardRules,
		IngressVerdict:         cfg.IngressVerdict,
	}
	logBPFGlobalCfg(val)
	return m.Put(uint32(0), val)
}

func logBPFGlobalCfg(cfg bpfGlobalCfg) {
	logGlobalCfgMask("Write BPF active rules", "all_active_rules", cfg.AllActiveRules, true)
	logGlobalCfgMask("Write BPF wildcard rules", "vlan_wildcard_rules", cfg.VlanWildcardRules, false)
	logGlobalCfgMask("Write BPF wildcard rules", "src_port_wildcard_rules", cfg.SrcPortWildcardRules, false)
	logGlobalCfgMask("Write BPF wildcard rules", "dst_port_wildcard_rules", cfg.DstPortWildcardRules, false)
	logGlobalCfgMask("Write BPF wildcard rules", "src_prefix_wildcard_rules", cfg.SrcPrefixWildcardRules, false)
	logGlobalCfgMask("Write BPF wildcard rules", "dst_prefix_wildcard_rules", cfg.DstPrefixWildcardRules, false)

	for i, mask := range cfg.ConditionWildcardRules {
		if maskEmpty(mask) {
			continue
		}
		condition := fmt.Sprintf("condition_%d", i)
		if i < len(conditionLogNames) {
			condition = conditionLogNames[i].name
		}
		logrus.WithFields(logrus.Fields{
			"map":       "global_cfg_map",
			"condition": condition,
			"slots":     maskSlots(mask),
		}).Debug("Write BPF condition wildcard rules")
	}

	logrus.WithFields(logrus.Fields{
		"map":             "global_cfg_map",
		"ingress_verdict": ingressVerdictLogValue(cfg.IngressVerdict),
	}).Debug("Write BPF ingress verdict")
}

func logGlobalCfgMask(message, field string, mask RuleMask, logEmpty bool) {
	if !logEmpty && maskEmpty(mask) {
		return
	}
	logrus.WithFields(logrus.Fields{
		"map":   "global_cfg_map",
		"field": field,
		"slots": maskSlots(mask),
	}).Debug(message)
}

func clearGlobalCfgMap(m *ebpf.Map) error {
	logrus.WithFields(logrus.Fields{
		"map": "global_cfg_map",
		"key": 0,
	}).Debug("Clear BPF config")
	return m.Put(uint32(0), bpfGlobalCfg{})
}

func writePortIndexMap(name string, m *ebpf.Map, index map[uint16]RuleMask) error {
	if err := clearHashMap(name, m); err != nil {
		return fmt.Errorf("clear: %w", err)
	}
	for port, mask := range index {
		logrus.WithFields(logrus.Fields{
			"map":   name,
			"port":  port,
			"slots": maskSlots(mask),
		}).Debug("Write BPF port index")
		if err := m.Put(port, mask); err != nil {
			return err
		}
	}
	return nil
}

func writeVlanIndexMap(m *ebpf.Map, index map[uint16]RuleMask) error {
	if err := clearHashMap("vlan_index_map", m); err != nil {
		return fmt.Errorf("clear: %w", err)
	}
	for vlan, mask := range index {
		logrus.WithFields(logrus.Fields{
			"map":   "vlan_index_map",
			"vlan":  vlan,
			"slots": maskSlots(mask),
		}).Debug("Write BPF VLAN index")
		if err := m.Put(vlan, mask); err != nil {
			return err
		}
	}
	return nil
}

func writeLpmMap(name string, m *ebpf.Map, entries []LPMEntry) error {
	if err := clearLpmMap(name, m); err != nil {
		return fmt.Errorf("clear: %w", err)
	}
	for _, e := range entries {
		key := bpfIpv4LpmKey{Prefixlen: e.Prefixlen, Addr: e.Addr}
		logrus.WithFields(logrus.Fields{
			"map":    name,
			"prefix": ipv4PrefixLogValue(key.Addr, key.Prefixlen),
			"slots":  maskSlots(e.Mask),
		}).Debug("Write BPF LPM index")
		if err := m.Put(key, e.Mask); err != nil {
			return err
		}
	}
	return nil
}

func clearArrayMap(m *ebpf.Map, size int) error {
	zero := bpfRuleMeta{}
	logrus.WithFields(logrus.Fields{
		"map":        "rule_index_map",
		"slot_start": 0,
		"slot_end":   size - 1,
		"slots":      size,
	}).Debug("Clear BPF rules")
	for i := range size {
		if err := m.Put(uint32(i), zero); err != nil {
			return err
		}
	}
	return nil
}

func clearHashMap(name string, m *ebpf.Map) error {
	var keys []uint16
	var key uint16
	var value RuleMask
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		logrus.WithFields(logrus.Fields{
			"map": name,
			"key": k,
		}).Debug("Delete BPF index")
		if err := m.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func clearLpmMap(name string, m *ebpf.Map) error {
	var keys []bpfIpv4LpmKey
	var key bpfIpv4LpmKey
	var value RuleMask
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		logrus.WithFields(logrus.Fields{
			"map":    name,
			"prefix": ipv4PrefixLogValue(k.Addr, k.Prefixlen),
		}).Debug("Delete BPF LPM index")
		if err := m.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func ipv4PrefixLogValue(addr uint32, prefixLen uint32) string {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], addr)
	return fmt.Sprintf("%s/%d", netip.AddrFrom4(bytes), prefixLen)
}

func ingressVerdictLogValue(verdict uint32) string {
	switch verdict {
	case 0:
		return "pass(0)"
	case 1:
		return "drop(1)"
	default:
		return fmt.Sprintf("unknown(%d)", verdict)
	}
}

func maskEmpty(mask RuleMask) bool {
	for _, group := range mask {
		if group != 0 {
			return false
		}
	}
	return true
}

func maskSlots(mask RuleMask) []uint32 {
	count := 0
	for _, group := range mask {
		count += bits.OnesCount64(group)
	}
	slots := make([]uint32, 0, count)
	for group, groupMask := range mask {
		for bit := range 64 {
			if groupMask&(uint64(1)<<bit) != 0 {
				slots = append(slots, uint32(group*64+bit))
			}
		}
	}
	return slots
}
