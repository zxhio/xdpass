package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"xdpass/internal/api"
	"xdpass/internal/attachment"
	"xdpass/internal/config"
	"xdpass/internal/dataplane/bpfgen"
	"xdpass/internal/dispatch"
	"xdpass/internal/events"
	"xdpass/internal/logging"
	"xdpass/internal/response"
	"xdpass/internal/store"
	"xdpass/internal/xsk"
)

const (
	defaultConfigPath = "/etc/xdpass/agent/config.yaml"

	logoAscii = `    |
 \ \| |\ //| // //
      |`

	cliDescription = "XDP/BPF runtime agent for xdpass policy enforcement."
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	pflag.CommandLine.SortFlags = false
	pflag.CommandLine.SetOutput(os.Stdout)
	configPath := pflag.StringP("config", "c", defaultConfigPath, "path to config file")
	showVersion := pflag.BoolP("version", "V", false, "print version")
	pflag.Usage = printHelp
	pflag.Parse()

	if *showVersion {
		printVersion()
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		logrus.WithError(err).Fatal("Fail to load config")
	}

	logOpts, err := logging.NewOptions(cfg.Logging)
	if err != nil {
		logrus.WithError(err).Fatal("Fail to parse logging config")
	}
	logging.Setup(logOpts)

	opts, err := config.NewServerOptions(cfg.Server)
	if err != nil {
		logrus.WithError(err).Fatal("Fail to parse server config")
	}

	attRuntime := attachment.New(
		func() (*ebpf.Collection, error) {
			var objs bpfgen.XdpassObjects
			if err := bpfgen.LoadXdpassObjects(&objs, nil); err != nil {
				return nil, err
			}
			return &ebpf.Collection{
				Programs: map[string]*ebpf.Program{"xdpass_prog": objs.XdpassProg},
				Maps: map[string]*ebpf.Map{
					"rule_index_map":     objs.RuleIndexMap,
					"global_cfg_map":     objs.GlobalCfgMap,
					"tx_config_map":      objs.TxConfigMap,
					"src_port_index_map": objs.SrcPortIndexMap,
					"dst_port_index_map": objs.DstPortIndexMap,
					"vlan_index_map":     objs.VlanIndexMap,
					"src_prefix_lpm_map": objs.SrcPrefixLpmMap,
					"dst_prefix_lpm_map": objs.DstPrefixLpmMap,
					"event_ringbuf":      objs.EventRingbuf,
					"stats_map":          objs.StatsMap,
					"xsks_map":           objs.XsksMap,
				},
			}, nil
		},
		func(prog *ebpf.Program, ifindex int, attachMode string) (link.Link, error) {
			var flags link.XDPAttachFlags
			switch attachMode {
			case "generic":
				flags = link.XDPGenericMode
			case "driver":
				flags = link.XDPDriverMode
			}
			return link.AttachXDP(link.XDPOptions{
				Program:   prog,
				Interface: ifindex,
				Flags:     flags,
			})
		},
	)
	defer attRuntime.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventStream := events.NewStream(ctx)
	defer eventStream.Stop()

	responseRuntime := response.NewRuntime(ctx, &response.RulesetRuleLookup{})
	defer responseRuntime.Stop()

	xskRuntime := xsk.NewRuntime(ctx)
	defer xskRuntime.StopAll()

	dispatchRuntime := dispatch.NewRuntime(ctx)
	defer dispatchRuntime.Stop()

	s := store.New(attRuntime, eventStream, responseRuntime, xskRuntime, dispatchRuntime)
	s.WireXSKCallbacks()
	handler := api.NewRouter(api.RouterDeps{
		Status:      s,
		Attachments: s,
		Ruleset:     s,
		Stats:       s,
		Egress:      s,
		Dispatch:    s,
		Events:      s,
	})

	server := &http.Server{
		Addr:              opts.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logrus.WithField("addr", opts.ListenAddr).Info("Started listener")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logrus.WithField("signal", sig).Info("Received signal")
	case err := <-errCh:
		if err != nil {
			logrus.WithError(err).Fatal("Fail to run HTTP server")
		}
		return
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logrus.WithError(err).Fatal("Fail to shut down HTTP server")
	}
	if err := <-errCh; err != nil {
		logrus.WithError(err).Fatal("Fail to run HTTP server")
	}
}

func printHelp() {
	out := pflag.CommandLine.Output()
	fmt.Fprintln(out, logoAscii)
	fmt.Fprintln(out)
	fmt.Fprintln(out, cliDescription)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  xdpass-agent [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	fmt.Fprint(out, pflag.CommandLine.FlagUsages())
}

func printVersion() {
	out := os.Stdout
	fmt.Fprintf(out, "Version:    %s\n", version)
	fmt.Fprintf(out, "Commit:     %s\n", commit)
	fmt.Fprintf(out, "Build time: %s\n", buildTime)
	fmt.Fprintf(out, "Go version: %s\n", runtime.Version())
}
