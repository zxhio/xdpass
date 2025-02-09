package main

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
)

type txStatsRecord struct {
	txPackets     int
	txBytes       int
	sendCount     int
	sendFailCount int
}

type txBenchData struct {
	stats     txStatsRecord
	data      []byte
	n         int
	batchSize uint32
	done      *bool
}

type txBenchmark interface {
	benchmarkTx(*txBenchData)
	waitTxDone(*txBenchData)
}

func benchTx(ctx context.Context, opt *benchOpt, data []byte) error {
	done := false
	go func() {
		<-ctx.Done()
		done = true
	}()

	if opt.AffinityCPU != -1 {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		logrus.WithField("cpu", opt.AffinityCPU).Info("Set affinity cpu")
		setAffinityCPU(opt.AffinityCPU)
	}

	bd := txBenchData{data: data, n: opt.BenchNum, done: &done}
	if opt.RateLimit == -1 {
		bd.batchSize = uint32(opt.BatchSize)
	} else {
		bd.batchSize = 1
	}

	if opt.Stats > 0 {
		go dumpTxStatsRecord(&bd.stats, time.Duration(opt.Stats)*time.Second)
	}

	var (
		b   txBenchmark
		err error
	)
	b, err = newXDPTxBenchPool(opt.IfaceName, opt.QueueId)
	if err != nil {
		logrus.WithError(err).Warn("Not use xdp socket")
		b, err = newRawSockTxBench(opt.IfaceName)
		if err != nil {
			return err
		}
	}

	limiter := newRateLimiter(opt.RateLimit, rateLimitPrecisionFrom(opt.RateLimitPrecStr))
	remain := opt.BenchNum
	for opt.BenchNum == -1 || remain > 0 {
		if opt.RateLimit != -1 && !limiter.allow() {
			continue
		}
		b.benchmarkTx(&bd)
		remain -= int(bd.batchSize)
	}
	b.waitTxDone(&bd)

	return nil
}

func setAffinityCPU(cpu int) error {
	var s unix.CPUSet
	s.Zero()
	s.Set(cpu)
	return unix.SchedSetaffinity(0, &s)
}

type rateLimitPrecision int

const (
	rateLimitLow = iota
	rateLimitMid
	rateLimitHigh
)

func rateLimitPrecisionFrom(s string) rateLimitPrecision {
	switch s {
	case "mid":
		return rateLimitMid
	case "high":
		return rateLimitHigh
	default:
		return rateLimitLow
	}
}

type rateLimiter struct {
	rateLimiter rate.Limiter
	limitN      int
	precision   rateLimitPrecision

	nowTs unix.Timespec
}

func newRateLimiter(lim int, perc rateLimitPrecision) *rateLimiter {
	return &rateLimiter{
		rateLimiter: *rate.NewLimiter(rate.Limit(lim), 1),
		limitN:      lim,
		precision:   perc,
	}
}

func (r *rateLimiter) allow() bool {
	if r.limitN == -1 {
		return true
	}

	switch r.precision {
	case rateLimitMid:
		err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &r.nowTs)
		if err == nil {
			r.nowTs = unix.NsecToTimespec(r.nowTs.Nano() + int64(time.Second/time.Duration(opt.RateLimit)))
			err = unix.ClockNanosleep(unix.CLOCK_MONOTONIC, unix.TIMER_ABSTIME, &r.nowTs, nil)
			if err == nil {
				return true
			}
		}
	case rateLimitHigh:
		return r.rateLimiter.Allow()
	}

	time.Sleep(time.Second / time.Duration(opt.RateLimit))
	return true
}

func dumpTxStatsRecord(stats *txStatsRecord, d time.Duration) {
	prev := txStatsRecord{}
	tm := time.Now()
	t := time.NewTicker(d)
	for {
		<-t.C

		period := float64(time.Since(tm)) / float64(time.Second)

		packets := stats.txPackets - prev.txPackets
		pps := float64(packets) / period

		bytes := stats.txBytes - prev.txBytes
		bps := float64(bytes*8) / period

		sends := stats.sendCount - prev.sendCount
		sps := float64(sends*8) / period

		fsends := stats.sendFailCount - prev.sendFailCount
		fsps := float64(fsends*8) / period

		prev = *stats
		tm = time.Now()

		logrus.Infof("Tx: %12d pkts  (%8.0f pps)  %s  %s (%6.0f %6.0f sendto) period:%fs",
			stats.txPackets, pps, bytesWithUnit(stats.txBytes), bpsWithUnit(bps), sps, fsps, period)
	}
}

const unitSize = 10000

func bytesWithUnit(bytes int) string {
	if bytes < unitSize {
		return fmt.Sprintf("%4d Bytes ", bytes)
	} else if bytes < unitSize*1000 {
		return fmt.Sprintf("%4d KBytes", bytes/1000)
	} else if bytes < unitSize*1000*1000 {
		return fmt.Sprintf("%4d MBytes", bytes/1000/1000)
	} else if bytes < unitSize*1000*1000*1000 {
		return fmt.Sprintf("%4d GBytes", bytes/1000/1000/1000)
	} else {
		return fmt.Sprintf("%4d PBytes", bytes/1000/1000/1000/1000)
	}
}

func bpsWithUnit(bits float64) string {
	if bits < unitSize {
		return fmt.Sprintf("%4.0f bits/s ", bits)
	} else if bits < unitSize*1000 {
		return fmt.Sprintf("%4.0f Kbits/s", bits/1000)
	} else if bits < unitSize*1000*1000 {
		return fmt.Sprintf("%4.0f Mbits/s", bits/1000/1000)
	} else if bits < unitSize*1000*1000*1000 {
		return fmt.Sprintf("%4.0f Gbits/s", bits/1000/1000/1000)
	} else {
		return fmt.Sprintf("%4.0f Pbits/s", bits/1000/1000/1000/1000)
	}
}
