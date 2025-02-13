package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zxhio/xdpass/internal/config"
	"github.com/zxhio/xdpass/internal/handles"
	"github.com/zxhio/xdpass/internal/netq"
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

var (
	verbose bool
	ips     []string
)

func main() {
	var opt netq.RxOpt

	pflag.StringVarP(&opt.IfaceName, "interface", "i", "", "Interface name")
	pflag.IntVarP(&opt.QueueID, "queue-id", "q", 0, "Interface rx queue index")
	pflag.Var(&opt.XDPFlags, "xdp-flags", config.UsageXDPFlagsMode())
	pflag.IntVar(&opt.PollTimewait, "poll", 0, "Poll timeout (us)")
	pflag.StringSliceVar(&ips, "ips", []string{}, "IP/CIDR list")
	pflag.BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	pflag.Parse()

	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGUSR1)
	go func() {
		sig := <-sigCh
		cancel()
		logrus.WithField("sig", sig).Info("Recv signal")
	}()

	rx, err := netq.NewRxDataDispatcher(&opt, []handles.DataProcessor{&handles.LogHandler{}})
	if err != nil {
		logrus.WithError(err).Fatal("Fatal to new packet rx")
	}
	defer rx.Stop()

	for _, s := range ips {
		l := logrus.WithField("ip", s)
		key, err := xdpprog.MakeIPLpmKeyFromStr(s)
		if err != nil {
			l.WithError(err).Error("Fail to make ip lpm key")
			return
		}
		err = rx.AddIPKey(*key)
		if err != nil {
			l.WithError(err).Error("Fail to add ip key")
			return
		}
	}

	err = rx.Run(ctx)
	if err != nil {
		logrus.WithError(err).Fatal("Fatal to serve rx")
	}
}
