package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zxhio/xdpass/internal"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/commands/fwcmd"
	"github.com/zxhio/xdpass/internal/commands/redirectcmd"
	"github.com/zxhio/xdpass/internal/commands/statscmd"
	"github.com/zxhio/xdpass/internal/config"
	"github.com/zxhio/xdpass/pkg/builder"
	"github.com/zxhio/xdpass/pkg/logs"
)

var opt struct {
	version    bool
	config     string
	dumpConfig string
}

func main() {
	pflag.BoolVarP(&opt.version, "version", "V", false, "Prints the build information")
	pflag.StringVarP(&opt.config, "config", "c", "/etc/xdpass/xdpassd.toml", "Config file path")
	pflag.StringVar(&opt.dumpConfig, "dump-config", "", "Dump default config [generic|native]")
	pflag.Parse()

	if opt.version {
		fmt.Println(builder.BuildInfo())
		return
	}

	if opt.dumpConfig != "" {
		if err := dumpConfig(opt.dumpConfig); err != nil {
			logrus.WithField("err", err).Fatal("Fail to dump config")
		}
		return
	}

	cfg, err := config.NewConfig(opt.config)
	if err != nil {
		logrus.WithField("err", err).Fatal("Fail to load config")
	}

	if err := setLogger(&cfg.Log); err != nil {
		logrus.WithField("err", err).Fatal("Fail to set logger")
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

	server, err := commands.NewMessageServer(commands.DefUnixSock, fwcmd.FirewallCommandHandle{}, redirectcmd.RedirectCommandHandle{}, statscmd.StatsCommandHandle{})
	if err != nil {
		logrus.WithField("err", err).Fatal("Fail to create message server")
	}
	defer server.Close()
	go server.Serve(ctx)

	links := make([]*internal.LinkHandle, len(cfg.Interfaces))
	for i, iface := range cfg.Interfaces {
		opts := []internal.LinkHandleOpt{
			internal.WithLinkHandleCores(cfg.Cores),
			internal.WithLinkQueueID(iface.QueueID),
			internal.WithLinkXDPFlags(iface.AttachMode, iface.XDPOpts...),
			internal.WithLinkHandleTimeout(cfg.PollTimeoutMs),
		}
		link, err := internal.NewLinkHandle(iface.Name, opts...)
		if err != nil {
			logrus.WithField("err", err).Fatal("Fail to new link handle")
		}
		links[i] = link
	}

	wg := sync.WaitGroup{}
	wg.Add(len(links))
	for _, link := range links {
		go func(link *internal.LinkHandle) {
			defer wg.Done()
			defer link.Close()
			if err := link.Run(ctx); err != nil {
				logrus.WithField("err", err).Fatal("Fail to run link handle")
			}
		}(link)
	}
	wg.Wait()
}

func dumpConfig(dumpType string) error {
	var data []byte
	var err error
	switch dumpType {
	case "generic":
		data, err = toml.Marshal(config.DefaultConfigGeneric())
	case "native":
		data, err = toml.Marshal(config.DefaultConfigOffload())
	default:
		return fmt.Errorf("invalid dump type: %s", dumpType)
	}
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func setLogger(cfg *config.LogConfig) error {
	opts := []logs.LogOpt{}

	if cfg.Level != "" {
		level, err := logrus.ParseLevel(cfg.Level)
		if err != nil {
			return err
		}
		logrus.SetLevel(level)
	}

	if cfg.CheckPath != "" {
		if cfg.CheckIntervalSec > 0 {
			opts = append(opts, logs.WithLevelCheckPath(cfg.CheckPath, time.Duration(cfg.CheckIntervalSec)*time.Second))
		} else {
			opts = append(opts, logs.WithLevelCheckPath(cfg.CheckPath, config.DefaultCheckIntervalSec*time.Second))
		}
	}

	if cfg.MaxSize > 0 {
		opts = append(opts, logs.WithMaxSize(cfg.MaxSize))
	}
	if cfg.MaxBackups > 0 {
		opts = append(opts, logs.WithMaxBackups(cfg.MaxBackups))
	}
	if cfg.MaxAge > 0 {
		opts = append(opts, logs.WithMaxAge(cfg.MaxAge))
	}
	if cfg.Compress {
		opts = append(opts, logs.WithCompress())
	}

	logpath := cfg.Path
	if logpath == "" {
		logpath = config.DefaultLogPath
	}
	logs.NewDynLoggerWith(logrus.StandardLogger(), logpath, opts...)
	return nil
}
