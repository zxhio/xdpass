package xsk

import (
	"strings"
	"testing"
)

func TestDefaultOptionsValid(t *testing.T) {
	t.Parallel()
	if err := DefaultOptions().Validate(); err != nil {
		t.Fatalf("DefaultOptions().Validate() error = %v", err)
	}
}

func TestOptionsValidateRejectsBadFrameSize(t *testing.T) {
	t.Parallel()
	o := DefaultOptions()
	o.FrameSize = 1500
	err := o.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want frame size error")
	}
	if !strings.Contains(err.Error(), "frame size") {
		t.Fatalf("Validate() error = %q, want frame size", err)
	}
}

func TestOptionsValidateRequiresTXFrameReserve(t *testing.T) {
	t.Parallel()
	o := DefaultOptions()
	o.TXFrameReserve = 0
	err := o.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want reserve error")
	}
	if !strings.Contains(err.Error(), "tx frame reserve") {
		t.Fatalf("Validate() error = %q, want tx frame reserve", err)
	}
}

func TestOptionsValidateRejectsFillPlusReserveExceedsFrameCount(t *testing.T) {
	t.Parallel()
	o := DefaultOptions()
	o.FrameCount = 4096
	o.FillRingSize = 4096
	o.TXFrameReserve = 1
	err := o.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want frame budget error")
	}
	if !strings.Contains(err.Error(), "exceeds frame count") {
		t.Fatalf("Validate() error = %q, want frame budget error", err)
	}
}

func TestOptionsValidateRejectsNonPowerOf2(t *testing.T) {
	t.Parallel()
	o := DefaultOptions()
	o.FrameCount = 100
	err := o.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want power of 2 error")
	}
	if !strings.Contains(err.Error(), "power of 2") {
		t.Fatalf("Validate() error = %q, want power of 2", err)
	}
}
