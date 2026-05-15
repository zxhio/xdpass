package ruleset

import (
	"fmt"

	"github.com/cilium/ebpf"

	"xdpass/internal/attachment"
)

// WriteMaps writes a compiled ruleset to an attachment's BPF maps.
func WriteMaps(maps attachment.MapAccessor, compiled *CompiledRuleset) error {
	if err := writeRuleIndexMap(maps.RuleIndexMap(), compiled.Rules); err != nil {
		return fmt.Errorf("write rule_index_map: %w", err)
	}
	if err := writeGlobalCfgMap(maps.GlobalCfgMap(), &compiled.GlobalCfg); err != nil {
		return fmt.Errorf("write global_cfg_map: %w", err)
	}
	if err := writePortIndexMap(maps.SrcPortIndexMap(), compiled.Indexes.SrcPortIndex); err != nil {
		return fmt.Errorf("write src_port_index_map: %w", err)
	}
	if err := writePortIndexMap(maps.DstPortIndexMap(), compiled.Indexes.DstPortIndex); err != nil {
		return fmt.Errorf("write dst_port_index_map: %w", err)
	}
	if err := writeVlanIndexMap(maps.VlanIndexMap(), compiled.Indexes.VlanIndex); err != nil {
		return fmt.Errorf("write vlan_index_map: %w", err)
	}
	if err := writeLpmMap(maps.SrcPrefixLpmMap(), compiled.Indexes.SrcPrefixLPM); err != nil {
		return fmt.Errorf("write src_prefix_lpm_map: %w", err)
	}
	if err := writeLpmMap(maps.DstPrefixLpmMap(), compiled.Indexes.DstPrefixLPM); err != nil {
		return fmt.Errorf("write dst_prefix_lpm_map: %w", err)
	}
	return nil
}

// ClearMaps clears all ruleset-related BPF maps for an attachment.
func ClearMaps(maps attachment.MapAccessor) error {
	if err := clearArrayMap(maps.RuleIndexMap(), 512); err != nil {
		return fmt.Errorf("clear rule_index_map: %w", err)
	}
	if err := clearGlobalCfgMap(maps.GlobalCfgMap()); err != nil {
		return fmt.Errorf("clear global_cfg_map: %w", err)
	}
	if err := clearHashMap(maps.SrcPortIndexMap()); err != nil {
		return fmt.Errorf("clear src_port_index_map: %w", err)
	}
	if err := clearHashMap(maps.DstPortIndexMap()); err != nil {
		return fmt.Errorf("clear dst_port_index_map: %w", err)
	}
	if err := clearHashMap(maps.VlanIndexMap()); err != nil {
		return fmt.Errorf("clear vlan_index_map: %w", err)
	}
	if err := clearLpmMap(maps.SrcPrefixLpmMap()); err != nil {
		return fmt.Errorf("clear src_prefix_lpm_map: %w", err)
	}
	if err := clearLpmMap(maps.DstPrefixLpmMap()); err != nil {
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
	AllActiveRules         [8]uint64
	VlanOptionalRules      [8]uint64
	SrcPortOptionalRules   [8]uint64
	DstPortOptionalRules   [8]uint64
	SrcPrefixOptionalRules [8]uint64
	DstPrefixOptionalRules [8]uint64
	ConditionOptionalRules [19][8]uint64
	IngressVerdict         uint32
	_                      [4]byte
}

type bpfIpv4LpmKey struct {
	Prefixlen uint32
	Addr      uint32
}

func writeRuleIndexMap(m *ebpf.Map, rules []CompiledRule) error {
	zero := bpfRuleMeta{}
	for i := range 512 {
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
		if err := m.Put(rule.Slot, meta); err != nil {
			return err
		}
	}
	return nil
}

func writeGlobalCfgMap(m *ebpf.Map, cfg *GlobalCfgData) error {
	val := bpfGlobalCfg{
		AllActiveRules:         cfg.AllActiveRules,
		VlanOptionalRules:      cfg.VlanOptionalRules,
		SrcPortOptionalRules:   cfg.SrcPortOptionalRules,
		DstPortOptionalRules:   cfg.DstPortOptionalRules,
		SrcPrefixOptionalRules: cfg.SrcPrefixOptionalRules,
		DstPrefixOptionalRules: cfg.DstPrefixOptionalRules,
		ConditionOptionalRules: cfg.ConditionOptionalRules,
		IngressVerdict:         cfg.IngressVerdict,
	}
	return m.Put(uint32(0), val)
}

func clearGlobalCfgMap(m *ebpf.Map) error {
	return m.Put(uint32(0), bpfGlobalCfg{})
}

func writePortIndexMap(m *ebpf.Map, index map[uint16][8]uint64) error {
	if err := clearHashMap(m); err != nil {
		return fmt.Errorf("clear: %w", err)
	}
	for port, mask := range index {
		if err := m.Put(port, mask); err != nil {
			return err
		}
	}
	return nil
}

func writeVlanIndexMap(m *ebpf.Map, index map[uint16][8]uint64) error {
	if err := clearHashMap(m); err != nil {
		return fmt.Errorf("clear: %w", err)
	}
	for vlan, mask := range index {
		if err := m.Put(vlan, mask); err != nil {
			return err
		}
	}
	return nil
}

func writeLpmMap(m *ebpf.Map, entries []LPMEntry) error {
	if err := clearLpmMap(m); err != nil {
		return fmt.Errorf("clear: %w", err)
	}
	for _, e := range entries {
		key := bpfIpv4LpmKey{Prefixlen: e.Prefixlen, Addr: e.Addr}
		if err := m.Put(key, e.Mask); err != nil {
			return err
		}
	}
	return nil
}

func clearArrayMap(m *ebpf.Map, size int) error {
	zero := bpfRuleMeta{}
	for i := range size {
		if err := m.Put(uint32(i), zero); err != nil {
			return err
		}
	}
	return nil
}

func clearHashMap(m *ebpf.Map) error {
	var keys []uint16
	var key uint16
	iter := m.Iterate()
	for iter.Next(&key, &[8]uint64{}) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err := m.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func clearLpmMap(m *ebpf.Map) error {
	var keys []bpfIpv4LpmKey
	var key bpfIpv4LpmKey
	iter := m.Iterate()
	for iter.Next(&key, &[8]uint64{}) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err := m.Delete(k); err != nil {
			return err
		}
	}
	return nil
}
