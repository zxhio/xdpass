package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"

	"xdpass/internal/api"
	"xdpass/internal/attachment"
	"xdpass/internal/config"
	"xdpass/internal/dataplane/bpfgen"
	"xdpass/internal/events"
	"xdpass/internal/store"
)

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()

	var serverCfg config.ServerConfig
	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			logrus.WithError(err).Fatal("Fail to load config")
		}
		serverCfg = cfg.Server
	}

	opts, err := config.NewServerOptions(serverCfg)
	if err != nil {
		logrus.WithError(err).Fatal("Fail to parse server config")
	}

	attRuntime := attachment.New(
		func() (*ebpf.Collection, error) {
			var objs bpfgen.XdpassObjects
			if err := bpfgen.LoadXdpassObjects(&objs, nil); err != nil {
				return nil, err
			}
			// Return a minimal Collection for the runtime to use.
			return &ebpf.Collection{
				Programs: map[string]*ebpf.Program{"xdpass_prog": objs.XdpassProg},
				Maps:     map[string]*ebpf.Map{},
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

	s := store.New(attRuntime, eventStream)
	handler := api.NewRouter(api.RouterDeps{
		Status:      s,
		Attachments: s,
		Ruleset:     s,
		Stats:       s,
		Egress:      s,
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
