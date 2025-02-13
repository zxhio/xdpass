package main

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/stats"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
)

type txBenchmark interface {
	runBatch(*txBenchmarkData)
	wait(*txBenchmarkData)
}

type txBenchmarkData struct {
	stat      *stats.Statistics
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
				stat:      &stats.Statistics{},
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

	var statsList []*stats.Statistics
	for _, group := range groups {
		statsList = append(statsList, group.stat)
		go func() {
			defer wg.Done()
			runTxBenchmarkGroup(group)
		}()
	}
	if opt.Stats > 0 {
		go stats.DumpStatisticsListLoop(ctx, "TX:", statsList, time.Duration(opt.Stats)*time.Second, logrus.Info)
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

		bd.batchSize = min(bd.batchSize, uint32(remain))
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
