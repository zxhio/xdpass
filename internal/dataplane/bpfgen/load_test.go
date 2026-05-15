package bpfgen

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestXdpassProgramLoad(t *testing.T) {
	if os.Getenv("XDPASS_RUN_BPF_TESTS") != "1" {
		t.Skip("set XDPASS_RUN_BPF_TESTS=1 to load the BPF program")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}

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
}
