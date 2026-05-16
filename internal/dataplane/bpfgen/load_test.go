package bpfgen

import (
	"errors"
	"os"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
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
