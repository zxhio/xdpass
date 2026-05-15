// Package xsk implements AF_XDP socket lifecycle for zero-copy packet I/O.
package xsk

import (
	"fmt"
	"math/bits"
)

const (
	xskMetadataHeadroom = 8 // bpf_xdp_adjust_meta reserves 8 bytes before packet

	defaultFrameSize          = 2048
	defaultFrameCount         = 4096
	defaultFillRingSize       = 2048
	defaultCompletionRingSize = 2048
	defaultRXRingSize         = 2048
	defaultTXRingSize         = 2048
	defaultTXFrameReserve     = 256
)

// Options holds configuration for an AF_XDP socket.
type Options struct {
	FrameSize          uint32 // bytes per frame, 2048 or 4096
	FrameCount         uint32 // UMEM frame count, power of 2
	FillRingSize       uint32 // fill ring entry count, power of 2
	CompletionRingSize uint32 // completion ring entry count, power of 2
	RXRingSize         uint32 // RX ring entry count, power of 2
	TXRingSize         uint32 // TX ring entry count, power of 2
	TXFrameReserve     uint32 // frames reserved for TX
}

// DefaultOptions returns Options with sensible defaults.
func DefaultOptions() Options {
	return Options{
		FrameSize:          defaultFrameSize,
		FrameCount:         defaultFrameCount,
		FillRingSize:       defaultFillRingSize,
		CompletionRingSize: defaultCompletionRingSize,
		RXRingSize:         defaultRXRingSize,
		TXRingSize:         defaultTXRingSize,
		TXFrameReserve:     defaultTXFrameReserve,
	}
}

// Validate checks that the configuration values are valid.
func (o Options) Validate() error {
	if o.FrameSize != 2048 && o.FrameSize != 4096 {
		return fmt.Errorf("xsk: invalid frame size %d, must be 2048 or 4096", o.FrameSize)
	}
	if err := checkPowerOf2(o.FrameCount, "frame count"); err != nil {
		return err
	}
	if err := checkPowerOf2(o.FillRingSize, "fill ring size"); err != nil {
		return err
	}
	if err := checkPowerOf2(o.CompletionRingSize, "completion ring size"); err != nil {
		return err
	}
	if err := checkPowerOf2(o.RXRingSize, "rx ring size"); err != nil {
		return err
	}
	if err := checkPowerOf2(o.TXRingSize, "tx ring size"); err != nil {
		return err
	}
	if o.TXFrameReserve == 0 {
		return fmt.Errorf("xsk: tx frame reserve must be greater than 0")
	}
	if o.FillRingSize+o.TXFrameReserve > o.FrameCount {
		return fmt.Errorf("xsk: fill ring size %d plus tx frame reserve %d exceeds frame count %d",
			o.FillRingSize, o.TXFrameReserve, o.FrameCount)
	}
	return nil
}

// umemSize returns the total UMEM region size in bytes.
func (o Options) umemSize() uint64 {
	return uint64(o.FrameCount) * uint64(o.FrameSize)
}

// txFrameStart returns the byte offset where TX frames begin in UMEM.
// RX frames occupy [0, FrameCount-TXFrameReserve), TX frames occupy the rest.
func (o Options) txFrameStart() uint64 {
	return uint64(o.FrameCount-o.TXFrameReserve) * uint64(o.FrameSize)
}

func checkPowerOf2(n uint32, name string) error {
	if n == 0 || bits.OnesCount32(n) != 1 {
		return fmt.Errorf("xsk: invalid %s %d, must be a power of 2", name, n)
	}
	return nil
}
