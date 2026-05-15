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

	"github.com/sirupsen/logrus"

	"xdpass/internal/api"
	"xdpass/internal/config"
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

	server := &http.Server{
		Addr:              opts.ListenAddr,
		Handler:           api.NewRouter(),
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logrus.WithError(err).Fatal("Fail to shut down HTTP server")
	}
	if err := <-errCh; err != nil {
		logrus.WithError(err).Fatal("Fail to run HTTP server")
	}
}
