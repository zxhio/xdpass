package response

import "sync/atomic"

// Stats holds atomic counters for userspace response outcomes.
type Stats struct {
	XSKRXPackets      atomic.Uint64
	Packets           atomic.Uint64
	XSKTXPackets      atomic.Uint64
	AFPacketTXPackets atomic.Uint64
	ErrorPackets      atomic.Uint64
}

// Snapshot returns a copy of the current counters.
func (s *Stats) Snapshot() StatsSnapshot {
	return StatsSnapshot{
		XSKRXPackets:      s.XSKRXPackets.Load(),
		Packets:           s.Packets.Load(),
		XSKTXPackets:      s.XSKTXPackets.Load(),
		AFPacketTXPackets: s.AFPacketTXPackets.Load(),
		ErrorPackets:      s.ErrorPackets.Load(),
	}
}

// StatsSnapshot is a point-in-time copy of userspace response stats.
type StatsSnapshot struct {
	XSKRXPackets      uint64
	Packets           uint64
	XSKTXPackets      uint64
	AFPacketTXPackets uint64
	ErrorPackets      uint64
}
