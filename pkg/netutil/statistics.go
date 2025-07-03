package netutil

import "time"

type Statistics struct {
	RxPackets uint64    `json:"rx_packets"`
	TxPackets uint64    `json:"tx_packets"`
	RxBytes   uint64    `json:"rx_bytes"`
	TxBytes   uint64    `json:"tx_bytes"`
	RxIOs     uint64    `json:"rx_ios"` // recv
	TxIOs     uint64    `json:"tx_ios"` // sendto
	RxErrors  uint64    `json:"rx_errors"`
	TxErrors  uint64    `json:"tx_errors"`
	RxDropped uint64    `json:"rx_dropped"`
	TxDropped uint64    `json:"tx_dropped"`
	Timestamp time.Time `json:"timestamp"` // Get statistics time
}

type StatisticsRate struct {
	RxPPS       float64 // Packets Per Second
	TxPPS       float64
	RxBPS       float64 // Bits Per Second
	TxBPS       float64
	RxIOPS      float64 // IOs Per Second
	TxIOPS      float64
	RxErrIOPS   float64 // Errors Per Second
	TxErrIOPS   float64
	RxDroppedPS float64 // Dropped Per Second
	TxDroppedPS float64
}

func (s Statistics) Rate(prev Statistics) StatisticsRate {
	pps := func(prev, curr uint64, period float64) float64 {
		packets := curr - prev
		return float64(packets) / period
	}

	bps := func(prev, curr uint64, period float64) float64 {
		bytes := curr - prev
		return float64(bytes*8) / period
	}

	iops := func(prev, curr uint64, period float64) float64 {
		ios := curr - prev
		return float64(ios) / period
	}

	ioerrps := func(prev, curr uint64, period float64) float64 {
		ioerrs := curr - prev
		return float64(ioerrs) / period
	}

	dps := func(prev, curr uint64, period float64) float64 {
		dropped := curr - prev
		return float64(dropped) / period
	}

	period := float64(s.Timestamp.Sub(prev.Timestamp)) / float64(time.Second)
	if period == 0.0 {
		return StatisticsRate{}
	}
	return StatisticsRate{
		RxPPS:       pps(prev.RxPackets, s.RxPackets, period),
		TxPPS:       pps(prev.TxPackets, s.TxPackets, period),
		RxBPS:       bps(prev.RxBytes, s.RxBytes, period),
		TxBPS:       bps(prev.TxBytes, s.TxBytes, period),
		RxIOPS:      iops(prev.RxIOs, s.RxIOs, period),
		TxIOPS:      iops(prev.TxIOs, s.TxIOs, period),
		RxErrIOPS:   ioerrps(prev.RxErrors, s.RxErrors, period),
		TxErrIOPS:   ioerrps(prev.TxErrors, s.TxErrors, period),
		RxDroppedPS: dps(prev.RxDropped, s.RxDropped, period),
		TxDroppedPS: dps(prev.TxDropped, s.TxDropped, period),
	}
}
