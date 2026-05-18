// Package stats implements BPF stats map reading and aggregation.
package stats

import (
	"github.com/cilium/ebpf"

	"xdpass/internal/dataplane/abi"
)

// Response is the stats API response.
type Response struct {
	Ingress           IngressStats           `json:"ingress"`
	Parse             ParseStats             `json:"parse"`
	Match             MatchStats             `json:"match"`
	KernelResponse    KernelResponseStats    `json:"kernel_response"`
	XSKRedirect       XSKRedirectStats       `json:"xsk_redirect"`
	UserspaceResponse UserspaceResponseStats `json:"userspace_response"`
	Dispatch          DispatchStats          `json:"dispatch"`
	Errors            ErrorsStats            `json:"errors"`
}

// DispatchStats holds dispatch counters.
type DispatchStats struct {
	EnqueuePackets   uint64 `json:"enqueue_packets"`
	Packets          uint64 `json:"packets"`
	DroppedPackets   uint64 `json:"dropped_packets"`
	QueueFullPackets uint64 `json:"queue_full_packets"`
	ErrorPackets     uint64 `json:"error_packets"`
}

type IngressStats struct {
	Packets uint64 `json:"packets"`
}

type ParseStats struct {
	OKPackets    uint64 `json:"ok_packets"`
	ErrorPackets uint64 `json:"error_packets"`
}

type MatchStats struct {
	HitPackets  uint64 `json:"hit_packets"`
	MissPackets uint64 `json:"miss_packets"`
}

type KernelResponseStats struct {
	Packets         uint64 `json:"packets"`
	XDPTXPackets    uint64 `json:"xdp_tx_packets"`
	RedirectPackets uint64 `json:"redirect_packets"`
	ErrorPackets    uint64 `json:"error_packets"`
}

type XSKRedirectStats struct {
	Packets      uint64 `json:"packets"`
	ErrorPackets uint64 `json:"error_packets"`
}

type UserspaceResponseStats struct {
	XSKRXPackets      uint64 `json:"xsk_rx_packets"`
	Packets           uint64 `json:"packets"`
	XSKTXPackets      uint64 `json:"xsk_tx_packets"`
	AFPacketTXPackets uint64 `json:"af_packet_tx_packets"`
	ErrorPackets      uint64 `json:"error_packets"`
}

type ErrorsStats struct {
	XDPPackets uint64 `json:"xdp_packets"`
	XSKPackets uint64 `json:"xsk_packets"`
}

// Snapshot reads and aggregates stats from multiple BPF stats maps.
func Snapshot(maps []*ebpf.Map, us *UserspaceResponseStats, ds *DispatchStats) Response {
	var totals [abi.StatCount]uint64
	for _, m := range maps {
		if m == nil {
			continue
		}
		aggregateMap(m, &totals)
	}

	usResp := UserspaceResponseStats{}
	if us != nil {
		usResp = *us
	}

	dsResp := DispatchStats{}
	if ds != nil {
		dsResp = *ds
	}

	return Response{
		Ingress: IngressStats{
			Packets: totals[abi.StatIngressPackets],
		},
		Parse: ParseStats{
			OKPackets:    totals[abi.StatParseOkPackets],
			ErrorPackets: totals[abi.StatParseErrorPackets],
		},
		Match: MatchStats{
			HitPackets:  totals[abi.StatMatchHitPackets],
			MissPackets: totals[abi.StatMatchMissPackets],
		},
		KernelResponse: KernelResponseStats{
			Packets:         totals[abi.StatKernelResponsePackets],
			XDPTXPackets:    totals[abi.StatKernelResponseXDPTXPackets],
			RedirectPackets: totals[abi.StatKernelResponseRedirectPkts],
			ErrorPackets:    totals[abi.StatKernelResponseErrorPackets],
		},
		XSKRedirect: XSKRedirectStats{
			Packets:      totals[abi.StatXSKRedirectPackets],
			ErrorPackets: totals[abi.StatXSKRedirectErrorPackets],
		},
		UserspaceResponse: usResp,
		Dispatch:          dsResp,
		Errors: ErrorsStats{
			XDPPackets: totals[abi.StatKernelResponseErrorPackets] + totals[abi.StatXSKRedirectErrorPackets],
			XSKPackets: usResp.ErrorPackets,
		},
	}
}

// aggregateMap reads a PERCPU_ARRAY stats map and sums values into totals.
func aggregateMap(m *ebpf.Map, totals *[abi.StatCount]uint64) {
	var key uint32
	for i := range abi.StatCount {
		key = uint32(i)
		var perCPU []uint64
		if err := m.Lookup(&key, &perCPU); err != nil {
			continue
		}
		for _, v := range perCPU {
			totals[i] += v
		}
	}
}

// SnapshotFromReaders aggregates stats from attachment StatsReaders.
func SnapshotFromReaders(readers []StatsReader, us *UserspaceResponseStats, ds *DispatchStats) Response {
	var maps []*ebpf.Map
	for _, r := range readers {
		m := r.StatsMap()
		if m != nil {
			maps = append(maps, m)
		}
	}
	return Snapshot(maps, us, ds)
}

// StatsReader provides access to an attachment's BPF stats map.
type StatsReader interface {
	StatsMap() *ebpf.Map
}
