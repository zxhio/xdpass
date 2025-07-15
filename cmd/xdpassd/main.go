package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zxhio/xdpass/internal/api"
	"github.com/zxhio/xdpass/internal/service"
	"github.com/zxhio/xdpass/pkg/builder"
)

const logoAscii = `
    |               |
 \ \| |\ //| // // \|
      |`

var (
	version bool
	verbose bool
)

func main() {
	pflag.BoolVarP(&version, "version", "V", false, "Print version")
	pflag.BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	pflag.Parse()

	if version {
		fmt.Println(color.HiBlueString(logoAscii))
		fmt.Println(builder.BuildInfo())
		os.Exit(0)
	}

	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
		gin.SetMode(gin.DebugMode)
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		gin.SetMode(gin.ReleaseMode)
		logrus.SetLevel(logrus.InfoLevel)
		logrus.SetOutput(&lumberjack.Logger{
			Filename:   "/var/log/xdpass/xdpassd.log",
			MaxSize:    100,
			MaxBackups: 10,
			MaxAge:     60,
			Compress:   true,
		})
	}

	logrus.WithField("pid", os.Getpid()).Info("///xdpassd start")
	defer logrus.WithField("pid", os.Getpid()).Info("///xdpassd quit")

	lis, err := net.Listen("tcp", ":9921")
	if err != nil {
		logrus.WithError(err).Fatal("Fatal to listen")
	}
	defer lis.Close()
	logrus.WithField("addr", lis.Addr()).Info("Listen on")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGUSR1)
	go func() {
		sig := <-sigCh
		logrus.WithField("sig", sig).Info("Recv signal")
		lis.Close()
	}()

	rule, err := service.NewRuleService()
	if err != nil {
		logrus.WithError(err).Error("Fail to new rule service")
	}
	logrus.Info("New rule service")

	attachment, err := service.NewAttachmentService(rule)
	if err != nil {
		logrus.WithError(err).Error("Fatal to new attachment service")
	}
	logrus.Info("New attachment service")

	g := gin.Default()
	api.SetRuleRouter(g, rule)
	api.SetIPRouter(g, attachment)
	api.SetAttachmentRouter(g, attachment)
	g.RunListener(lis)
}
