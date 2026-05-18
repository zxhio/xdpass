package ruleset

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"xdpass/internal/attachment"
)

// fakeMapAccessor implements attachment.MapAccessor with injectable maps.
type fakeMapAccessor struct {
	ruleIndexMap    *ebpf.Map
	globalCfgMap    *ebpf.Map
	srcPortIndexMap *ebpf.Map
	dstPortIndexMap *ebpf.Map
	vlanIndexMap    *ebpf.Map
	srcPrefixLpmMap *ebpf.Map
	dstPrefixLpmMap *ebpf.Map
	txConfigMap     *ebpf.Map
	eventRingbufMap *ebpf.Map
	statsMap        *ebpf.Map
	xsksMap         *ebpf.Map
}

func (f *fakeMapAccessor) RuleIndexMap() *ebpf.Map    { return f.ruleIndexMap }
func (f *fakeMapAccessor) GlobalCfgMap() *ebpf.Map    { return f.globalCfgMap }
func (f *fakeMapAccessor) TxConfigMap() *ebpf.Map     { return f.txConfigMap }
func (f *fakeMapAccessor) SrcPortIndexMap() *ebpf.Map { return f.srcPortIndexMap }
func (f *fakeMapAccessor) DstPortIndexMap() *ebpf.Map { return f.dstPortIndexMap }
func (f *fakeMapAccessor) VlanIndexMap() *ebpf.Map    { return f.vlanIndexMap }
func (f *fakeMapAccessor) SrcPrefixLpmMap() *ebpf.Map { return f.srcPrefixLpmMap }
func (f *fakeMapAccessor) DstPrefixLpmMap() *ebpf.Map { return f.dstPrefixLpmMap }
func (f *fakeMapAccessor) EventRingbufMap() *ebpf.Map { return f.eventRingbufMap }
func (f *fakeMapAccessor) StatsMap() *ebpf.Map        { return f.statsMap }
func (f *fakeMapAccessor) XsksMap() *ebpf.Map         { return f.xsksMap }

// Ensure fakeMapAccessor implements the interface.
var _ attachment.MapAccessor = (*fakeMapAccessor)(nil)

func newHashMap(t *testing.T, keySize, valueSize uint32) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: 1024,
	})
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	return m
}

func newRuleIndexMap(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  12, // sizeof(bpfRuleMeta): RuleID(4)+RequiredMask(4)+Action(2)+Flags(1)+pad(1)
		MaxEntries: 512,
	})
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	return m
}

func newGlobalCfgMap(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  1608, // sizeof(bpfGlobalCfg): 25*[8]uint64 + uint32 + pad
		MaxEntries: 1,
	})
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	return m
}

func newLPMMap(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  64,
		MaxEntries: 1024,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	return m
}

func newClosedHashMapWithData(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    2,
		ValueSize:  64,
		MaxEntries: 1024,
	})
	require.NoError(t, err)
	// Insert an entry so clearHashMap has something to delete.
	var key uint16 = 80
	var val [8]uint64
	require.NoError(t, m.Put(key, val))
	m.Close()
	return m
}

func TestWriteMapsPropagatesClearError(t *testing.T) {
	ruleMap := newRuleIndexMap(t)
	cfgMap := newGlobalCfgMap(t)
	portMap := newHashMap(t, 2, 64) // key=uint16, value=[8]uint64
	lpmMap := newLPMMap(t)
	closedPortMap := newClosedHashMapWithData(t)

	rules := []Rule{
		{RuleID: 1, Match: Match{DstPorts: []uint16{80}}, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)

	maps := &fakeMapAccessor{
		ruleIndexMap:    ruleMap,
		globalCfgMap:    cfgMap,
		srcPortIndexMap: portMap,
		dstPortIndexMap: closedPortMap,
		vlanIndexMap:    portMap,
		srcPrefixLpmMap: lpmMap,
		dstPrefixLpmMap: lpmMap,
	}

	err = WriteMaps(maps, compiled)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dst_port_index_map")
}

func TestClearMapsPropagatesError(t *testing.T) {
	ruleMap := newRuleIndexMap(t)
	cfgMap := newGlobalCfgMap(t)
	portMap := newHashMap(t, 2, 64)
	lpmMap := newLPMMap(t)
	closedPortMap := newClosedHashMapWithData(t)

	maps := &fakeMapAccessor{
		ruleIndexMap:    ruleMap,
		globalCfgMap:    cfgMap,
		srcPortIndexMap: closedPortMap,
		dstPortIndexMap: portMap,
		vlanIndexMap:    portMap,
		srcPrefixLpmMap: lpmMap,
		dstPrefixLpmMap: lpmMap,
	}

	err := ClearMaps(maps)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "src_port_index_map")
}

func TestWriteMapsSuccess(t *testing.T) {
	ruleMap := newRuleIndexMap(t)
	cfgMap := newGlobalCfgMap(t)
	portMap := newHashMap(t, 2, 64)
	lpmMap := newLPMMap(t)

	rules := []Rule{
		{RuleID: 1, Match: Match{DstPorts: []uint16{80}}, Response: Response{Action: "alert"}},
	}
	compiled, err := Compile(rules, "pass")
	require.NoError(t, err)

	maps := &fakeMapAccessor{
		ruleIndexMap:    ruleMap,
		globalCfgMap:    cfgMap,
		srcPortIndexMap: portMap,
		dstPortIndexMap: portMap,
		vlanIndexMap:    portMap,
		srcPrefixLpmMap: lpmMap,
		dstPrefixLpmMap: lpmMap,
	}

	err = WriteMaps(maps, compiled)
	assert.NoError(t, err)
}

func TestClearMapsSuccess(t *testing.T) {
	ruleMap := newRuleIndexMap(t)
	cfgMap := newGlobalCfgMap(t)
	portMap := newHashMap(t, 2, 64)
	lpmMap := newLPMMap(t)

	maps := &fakeMapAccessor{
		ruleIndexMap:    ruleMap,
		globalCfgMap:    cfgMap,
		srcPortIndexMap: portMap,
		dstPortIndexMap: portMap,
		vlanIndexMap:    portMap,
		srcPrefixLpmMap: lpmMap,
		dstPrefixLpmMap: lpmMap,
	}

	err := ClearMaps(maps)
	assert.NoError(t, err)
}
