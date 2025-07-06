package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zxhio/xdpass/internal"
	"github.com/zxhio/xdpass/internal/api"
	"github.com/zxhio/xdpass/pkg/builder"
)

var (
	version   bool
	verbose   bool
	ifaceName string
)

func main() {
	pflag.BoolVarP(&version, "version", "V", false, "Print version")
	pflag.BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	pflag.StringVarP(&ifaceName, "interface", "i", "", "Interface name")
	pflag.Parse()

	if version {
		fmt.Println(builder.BuildInfo())
		os.Exit(0)
	}

	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	lis, err := net.Listen("tcp", ":9921")
	if err != nil {
		logrus.WithError(err).Fatal("Fatal to listen")
	}
	defer lis.Close()

	link, err := internal.NewLinkHandle(ifaceName)
	if err != nil {
		logrus.WithError(err).Fatal("Fatal to new link handle")
	}
	defer link.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGUSR1)
	go func() {
		sig := <-sigCh
		cancel()
		lis.Close()
		logrus.WithField("sig", sig).Info("Recv signal")
	}()

	go func() {
		err = link.Run(ctx)
		if err != nil {
			logrus.WithError(err).Fatal("Fatal to run link handle")
		}
	}()

	g := gin.Default()
	api.SetRuleRouter(g, link)
	api.SetIPRouter(g, link)
	g.RunListener(lis)
}
