// Package stats implements BPF stats map reading and aggregation.
package stats

import (
	"encoding/binary"

	"github.com/cilium/ebpf"
)

// BPF stats map counter indexes from bpf-abi.md.
const (
	statIngressPackets             = 0
	statParseOkPackets             = 1
	statParseErrorPackets          = 2
	statMatchHitPackets            = 3
	statMatchMissPackets           = 4
	statKernelResponsePackets      = 5
	statKernelResponseXDPTXPackets = 6
	statKernelResponseRedirectPkts = 7
	statKernelResponseErrorPackets = 8
	statXSKRedirectPackets         = 9
	statXSKRedirectErrorPackets    = 10
	statEventDroppedPackets        = 11
	statCount                      = 17
)

// Response is the stats API response.
type Response struct {
	Ingress           IngressStats           `json:"ingress"`
	Parse             ParseStats             `json:"parse"`
	Match             MatchStats             `json:"match"`
	KernelResponse    KernelResponseStats    `json:"kernel_response"`
	XSKRedirect       XSKRedirectStats       `json:"xsk_redirect"`
	UserspaceResponse UserspaceResponseStats `json:"userspace_response"`
	Errors            ErrorsStats            `json:"errors"`
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
func Snapshot(maps []*ebpf.Map, us *UserspaceResponseStats) Response {
	var totals [statCount]uint64
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

	return Response{
		Ingress: IngressStats{
			Packets: totals[statIngressPackets],
		},
		Parse: ParseStats{
			OKPackets:    totals[statParseOkPackets],
			ErrorPackets: totals[statParseErrorPackets],
		},
		Match: MatchStats{
			HitPackets:  totals[statMatchHitPackets],
			MissPackets: totals[statMatchMissPackets],
		},
		KernelResponse: KernelResponseStats{
			Packets:         totals[statKernelResponsePackets],
			XDPTXPackets:    totals[statKernelResponseXDPTXPackets],
			RedirectPackets: totals[statKernelResponseRedirectPkts],
			ErrorPackets:    totals[statKernelResponseErrorPackets],
		},
		XSKRedirect: XSKRedirectStats{
			Packets:      totals[statXSKRedirectPackets],
			ErrorPackets: totals[statXSKRedirectErrorPackets],
		},
		UserspaceResponse: usResp,
		Errors: ErrorsStats{
			XDPPackets: totals[statKernelResponseErrorPackets] + totals[statXSKRedirectErrorPackets],
			XSKPackets: usResp.ErrorPackets,
		},
	}
}

// aggregateMap reads a PERCPU_ARRAY stats map and sums values into totals.
func aggregateMap(m *ebpf.Map, totals *[statCount]uint64) {
	var key uint32
	for i := range statCount {
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

// ZeroResponse returns a zeroed stats response.
func ZeroResponse() Response {
	return Response{}
}

// SnapshotFromReaders aggregates stats from attachment StatsReaders.
func SnapshotFromReaders(readers []StatsReader, us *UserspaceResponseStats) Response {
	var maps []*ebpf.Map
	for _, r := range readers {
		m := r.StatsMap()
		if m != nil {
			maps = append(maps, m)
		}
	}
	return Snapshot(maps, us)
}

// StatsReader provides access to an attachment's BPF stats map.
type StatsReader interface {
	StatsMap() *ebpf.Map
}

// EncodeCounter encodes a uint64 into little-endian bytes (for testing).
func EncodeCounter(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}
