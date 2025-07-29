package bench

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/zxhio/xdpass/pkg/humanize"
	"github.com/zxhio/xdpass/pkg/netutil"
	"github.com/zxhio/xdpass/pkg/utils"
	"github.com/zxhio/xdpass/pkg/xdp"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
)

type benchmarkOpts struct {
	total     int
	batch     uint32
	rateLimit int
	statsDur  time.Duration
	cores     []int
	queues    []uint32
	xdpOpts   []xdp.XDPOpt
}

func defaultBenchmarkOpts() benchmarkOpts {
	return benchmarkOpts{
		total:     -1,
		rateLimit: -1,
		cores:     []int{-1},
	}
}

type BenchmarkOpt func(*benchmarkOpts)

func WithBenchmarkN(n int, batch uint32) BenchmarkOpt {
	return func(bo *benchmarkOpts) {
		bo.total = n
		bo.batch = batch
	}
}

func WithBenchmarkRateLimit(rateLimit int) BenchmarkOpt {
	return func(bo *benchmarkOpts) { bo.rateLimit = rateLimit }
}

func WithBenchmarkStatsDur(dur time.Duration) BenchmarkOpt {
	return func(bo *benchmarkOpts) { bo.statsDur = dur }
}

func WithBenchmarkCPUCores(cores []int) BenchmarkOpt {
	return func(bo *benchmarkOpts) { bo.cores = cores }
}

func WithBenchmarkQueues(queues []uint) BenchmarkOpt {
	return func(bo *benchmarkOpts) {
		for _, q := range queues {
			bo.queues = append(bo.queues, uint32(q))
		}
	}
}

func WithBenchmarkXDPBindMode(copy, zeroCopy bool) BenchmarkOpt {
	return func(bo *benchmarkOpts) {
		if copy {
			bo.xdpOpts = append(bo.xdpOpts, xdp.WithCopy())
		} else if zeroCopy {
			bo.xdpOpts = append(bo.xdpOpts, xdp.WithZeroCopy())
		}
	}
}

func Benchmark(ctx context.Context, ifaceName string, data []byte, opts ...BenchmarkOpt) error {
	done := false
	go func() {
		<-ctx.Done()
		done = true
	}()

	o := defaultBenchmarkOpts()
	for _, opt := range opts {
		opt(&o)
	}
	utils.VerbosePrintln("Benchmark total:%d, rate limit:%d, status dur:%v", o.total, o.rateLimit, o.statsDur)

	txData := TxData{
		Batch:   uint32(o.batch),
		Queues:  o.queues,
		Data:    data,
		XDPOpts: append(o.xdpOpts, xdp.WithFrameSize(2048)),
	}
	txList, err := NewTxList(ifaceName, &txData)
	if err != nil {
		return err
	}

	var groups []*benchmarkGroup
	if len(o.cores) == 0 {
		o.cores = []int{-1}
	}
	for i := range min(len(o.cores), len(txList)) {
		groups = append(groups, &benchmarkGroup{core: o.cores[i], TxData: txData})
	}

	// Assign the average txList to txGroups
	for k, tx := range txList {
		groups[k%len(groups)].txList = append(groups[k%len(groups)].txList, tx)
	}

	if o.total == -1 {
		for _, g := range groups {
			g.total = -1
		}
	} else {
		// Simple method to assign the pkts to txGroups
		for k := range o.total {
			groups[k%len(groups)].total++
		}
	}

	wg := sync.WaitGroup{}
	wg.Add(len(groups))

	for _, g := range groups {
		go func() {
			defer wg.Done()
			g.run(&done, o.rateLimit)
		}()
	}

	if o.statsDur != 0 {
		prev := make(map[int]netutil.Statistics)
		statsCtx, cancel := context.WithCancel(ctx)
		defer func() {
			cancel()
			displayStats(txList, prev)
		}()
		go dumpStats(statsCtx, txList, o.statsDur, prev)
	}
	wg.Wait()

	return nil
}

type benchmarkGroup struct {
	total  int
	core   int
	txList []Tx
	TxData
}

func (g *benchmarkGroup) formatTxData() string {
	s := []string{}
	for _, tx := range g.txList {
		s = append(s, fmt.Sprintf("tx(queue:%d fd:%d)", tx.QueueID(), tx.Fd()))
	}
	return strings.Join(s, ",")
}

func (g *benchmarkGroup) run(done *bool, rateLimit int) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if g.core != -1 {
		utils.SetAffinityCPU(g.core)
		utils.VerbosePrintln("Run benchmark %s on core %d", g.formatTxData(), g.core)
	} else {
		utils.VerbosePrintln("Run benchmark %s", g.formatTxData())
	}

	limiter := newRateLimiter(rateLimit)
	remain := g.total
	for idx := 0; (g.total == -1 || remain > 0) && !*done; idx++ {
		if rateLimit != -1 && !limiter.allow() {
			continue
		}
		g.Batch = min(g.Batch, uint32(remain))
		g.txList[idx%len(g.txList)].Transmit(&g.TxData)
		remain -= int(g.Batch)
	}

	for _, tx := range g.txList {
		tx.Close()
	}
}

type rateLimiter struct {
	rateLimiter rate.Limiter
	limit       int
	nowTs       unix.Timespec
}

func newRateLimiter(lim int) *rateLimiter {
	return &rateLimiter{
		rateLimiter: *rate.NewLimiter(rate.Limit(lim), 1),
		limit:       lim,
	}
}

func (r *rateLimiter) allow() bool {
	if r.limit <= 0 {
		return true
	} else if r.limit < 1000 {
		time.Sleep(time.Second / time.Duration(r.limit))
	} else if r.limit < 10000 {
		err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &r.nowTs)
		if err == nil {
			r.nowTs = unix.NsecToTimespec(r.nowTs.Nano() + int64(time.Second/time.Duration(r.limit)))
			err = unix.ClockNanosleep(unix.CLOCK_MONOTONIC, unix.TIMER_ABSTIME, &r.nowTs, nil)
			if err == nil {
				return true
			}
		}
	}
	return r.rateLimiter.Allow()
}

func dumpStats(ctx context.Context, txList []Tx, dur time.Duration, prev map[int]netutil.Statistics) {
	timer := time.NewTicker(dur)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			displayStats(txList, prev)
		}
	}
}

func displayStats(txList []Tx, prev map[int]netutil.Statistics) {
	tbl := tablewriter.NewTable(os.Stdout,
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Borders: tw.BorderNone,
			Settings: tw.Settings{
				Separators: tw.SeparatorsNone,
			},
		})),
		tablewriter.WithRowAlignment(tw.AlignCenter),
	)
	tbl.Header([]string{"queue", "tx_pkts", "tx_pps", "tx_bytes", "tx_bps", "tx_iops", "tx_err_iops"})

	sum := struct {
		netutil.Statistics
		netutil.StatisticsRate
	}{}
	for _, tx := range txList {
		stat := tx.Stats()
		rate := stat.Rate(prev[tx.Fd()])
		prev[tx.Fd()] = stat

		tbl.Append([]string{
			fmt.Sprintf("%d", tx.QueueID()),
			fmt.Sprintf("%d", stat.TxPackets),
			fmt.Sprintf("%.0f", rate.TxPPS),
			humanize.Bytes(int(stat.TxBytes)),
			humanize.BitsRate(int(rate.TxBPS)),
			fmt.Sprintf("%.0f", rate.TxIOPS),
			fmt.Sprintf("%.0f", rate.TxErrIOPS),
		})
		sum.TxPackets += stat.TxPackets
		sum.TxBytes += stat.TxBytes
		sum.TxPPS += rate.TxPPS
		sum.TxBPS += rate.TxBPS
		sum.TxIOPS += rate.TxIOPS
		sum.TxErrIOPS += rate.TxErrIOPS
	}
	tbl.Footer([]string{
		"SUM",
		fmt.Sprintf("%d", sum.TxPackets),
		fmt.Sprintf("%.0f", sum.TxPPS),
		humanize.Bytes(int(sum.TxBytes)),
		humanize.BitsRate(int(sum.TxBPS)),
		fmt.Sprintf("%.0f", sum.TxIOPS),
		fmt.Sprintf("%.0f", sum.TxErrIOPS),
	})
	tbl.Render()
	fmt.Println()
}
