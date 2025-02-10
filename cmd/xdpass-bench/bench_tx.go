package main

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
)

type txStats struct {
	txPackets     int
	txBytes       int
	sendCount     int
	sendFailCount int
}

type txBenchmark interface {
	runBatch(*txBenchmarkData)
	wait(*txBenchmarkData)
}

type txBenchmarkData struct {
	stats     *txStats
	data      []byte
	n         int
	batchSize uint32
	done      *bool
}

type txBenchmarkDataGroup struct {
	txBenchmarkData
	core       int
	benchmarks []txBenchmark
}

func runTxBenchmark(ctx context.Context, opt *benchOpt, data []byte) error {
	done := false
	go func() {
		<-ctx.Done()
		done = true
	}()

	var (
		benchmarks []txBenchmark
		err        error
	)

	benchmarks, err = newXDPTxBenchmarks(opt.IfaceName, opt.QueueId)
	if err != nil {
		b, err := newRawSockTxBench(opt.IfaceName)
		if err != nil {
			return err
		}
		benchmarks = append(benchmarks, b)
	}

	var (
		batchSize uint32
		cores     []int
	)
	if opt.RateLimit == -1 {
		batchSize = uint32(opt.BatchSize)
		cores = opt.Cores
	} else {
		batchSize = 1
		cores = opt.Cores[:1]
	}
	// cpu num should not greater than tx queue num
	if len(cores) > len(benchmarks) {
		cores = cores[:len(benchmarks)]
	}

	var groups []*txBenchmarkDataGroup
	for _, c := range cores {
		groups = append(groups, &txBenchmarkDataGroup{
			txBenchmarkData: txBenchmarkData{
				stats:     &txStats{},
				data:      data,
				batchSize: batchSize,
				done:      &done,
			},
			core: c,
		})
	}

	for k, b := range benchmarks {
		groups[k%len(groups)].benchmarks = append(groups[k%len(groups)].benchmarks, b)
	}
	for k := range opt.BenchNum {
		groups[k%len(groups)].n++
	}

	wg := sync.WaitGroup{}
	wg.Add(len(cores))

	var stats []*txStats
	for _, group := range groups {
		stats = append(stats, group.stats)
		go func() {
			defer wg.Done()
			runTxBenchmarkGroup(group)
		}()
	}
	if opt.Stats > 0 {
		go dumpTxStatsRecords(ctx, stats, time.Duration(opt.Stats)*time.Second)
	}

	wg.Wait()

	return nil
}

func runTxBenchmarkGroup(bd *txBenchmarkDataGroup) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	logrus.WithFields(logrus.Fields{"core": bd.core, "benchmarks": len(bd.benchmarks)}).Info("Set affinity cpu")
	setAffinityCPU(bd.core)

	limiter := newRateLimiter(opt.RateLimit, rateLimitPrecisionFrom(opt.RateLimitPrecStr))
	remain := opt.BenchNum

	for idx := 0; opt.BenchNum == -1 || remain > 0; idx++ {
		if opt.RateLimit != -1 && !limiter.allow() {
			continue
		}

		bd.benchmarks[idx%len(bd.benchmarks)].runBatch(&bd.txBenchmarkData)
		remain -= int(bd.batchSize)
	}

	for _, b := range bd.benchmarks {
		b.wait(&bd.txBenchmarkData)
	}
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

func dumpTxStatsRecords(ctx context.Context, stats []*txStats, d time.Duration) {
	prev := txStats{}
	stat := txStats{}
	tm := time.Now()
	t := time.NewTicker(d)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		joinStatsRecord(stats, &stat)

		period := float64(time.Since(tm)) / float64(time.Second)

		packets := stat.txPackets - prev.txPackets
		pps := float64(packets) / period

		bytes := stat.txBytes - prev.txBytes
		bps := float64(bytes*8) / period

		sends := stat.sendCount - prev.sendCount
		sps := float64(sends*8) / period

		fsends := stat.sendFailCount - prev.sendFailCount
		fsps := float64(fsends*8) / period

		prev = stat
		tm = time.Now()

		logrus.Infof("Tx: %12d pkts  (%8.0f pps)  %s  %s (%6.0f %6.0f sendto) period:%fs",
			stat.txPackets, pps, bytesWithUnit(stat.txBytes), bpsWithUnit(bps), sps, fsps, period)
	}
}

func joinStatsRecord(stats []*txStats, stat *txStats) {
	stat.txPackets = 0
	stat.txBytes = 0
	stat.sendCount = 0
	stat.sendFailCount = 0

	for _, s := range stats {
		stat.txPackets += s.txPackets
	}
	for _, s := range stats {
		stat.txBytes += s.txBytes
	}
	for _, s := range stats {
		stat.sendCount += s.sendCount
	}
	for _, s := range stats {
		stat.sendFailCount += s.sendFailCount
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
