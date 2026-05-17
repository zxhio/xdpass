package dispatch

import "sync/atomic"

// Stats holds atomic counters for dispatch outcomes.
type Stats struct {
	EnqueuePackets   atomic.Uint64
	Packets          atomic.Uint64
	DroppedPackets   atomic.Uint64
	QueueFullPackets atomic.Uint64
	ErrorPackets     atomic.Uint64
}

// Snapshot returns a point-in-time copy of the counters.
func (s *Stats) Snapshot() StatsSnapshot {
	return StatsSnapshot{
		EnqueuePackets:   s.EnqueuePackets.Load(),
		Packets:          s.Packets.Load(),
		DroppedPackets:   s.DroppedPackets.Load(),
		QueueFullPackets: s.QueueFullPackets.Load(),
		ErrorPackets:     s.ErrorPackets.Load(),
	}
}

// StatsSnapshot is a plain copy of dispatch stats.
type StatsSnapshot struct {
	EnqueuePackets   uint64
	Packets          uint64
	DroppedPackets   uint64
	QueueFullPackets uint64
	ErrorPackets     uint64
}
