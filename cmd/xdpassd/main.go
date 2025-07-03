package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zxhio/xdpass/internal"
	"github.com/zxhio/xdpass/internal/api"
	"github.com/zxhio/xdpass/internal/xdpprog"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

var (
	ifaceName string
	verbose   bool
	key       netaddr.IPv4Prefix
)

func main() {
	pflag.StringVarP(&ifaceName, "interface", "i", "", "Interface name")
	pflag.BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	pflag.Var(&key, "filter", "Limit redirect packet with ip")
	pflag.Parse()

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
		// TODO: use API updating lpm key
		err = link.IpLpmTrie.Update(xdpprog.NewIPLpmKey(key), uint8(0), 0)
		if err != nil {
			logrus.WithError(err).Fatal("Fatal to update fw key")
		}

		err = link.Run(ctx)
		if err != nil {
			logrus.WithError(err).Fatal("Fatal to run link handle")
		}
	}()

	g := gin.Default()
	api.SetRuleRouter(g, link)
	g.RunListener(lis)
}
