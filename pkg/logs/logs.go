package logs

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
)

const (
	DefaultMaxSize    = 100
	DefaultMaxBackups = 3
	DefaultMaxAge     = 30
	DefaultCompress   = true
	DefaultInterval   = time.Second * 30
)

type logOpts struct {
	maxSize            int
	maxBackups         int
	maxAge             int
	compress           bool
	levelCheckPath     string
	levelCheckInterval time.Duration
	formatter          logrus.Formatter
}

func defaultLogOpts() *logOpts {
	return &logOpts{
		maxSize:    DefaultMaxSize,
		maxBackups: DefaultMaxBackups,
		maxAge:     DefaultMaxAge,
		compress:   DefaultCompress,
		formatter:  logrus.StandardLogger().Formatter,
	}
}

type LogOpt func(*logOpts)

func WithMaxSize(size int) LogOpt {
	return func(opts *logOpts) { opts.maxSize = size }
}

func WithMaxBackups(backups int) LogOpt {
	return func(opts *logOpts) { opts.maxBackups = backups }
}

func WithMaxAge(age int) LogOpt {
	return func(opts *logOpts) { opts.maxAge = age }
}

func WithCompress() LogOpt {
	return func(opts *logOpts) { opts.compress = true }
}

func WithLevelCheckPath(path string, interval time.Duration) LogOpt {
	return func(opts *logOpts) {
		opts.levelCheckPath = path
		opts.levelCheckInterval = interval
	}
}

func WithFormatter(formatter logrus.Formatter) LogOpt {
	return func(opts *logOpts) { opts.formatter = formatter }
}

type DynLogger struct {
	opts          *logOpts
	lastCheckTime time.Time
	*logrus.Logger
}

func NewDynLogger(logpath string, opts ...LogOpt) *DynLogger {
	return NewDynLoggerWith(logrus.New(), logpath, opts...)
}

func NewDynLoggerWith(l *logrus.Logger, logpath string, opts ...LogOpt) *DynLogger {
	o := defaultLogOpts()
	for _, opt := range opts {
		opt(o)
	}

	if o.formatter != nil {
		l.SetFormatter(o.formatter)
	}

	l.SetLevel(logrus.GetLevel())
	l.SetOutput(&lumberjack.Logger{
		Filename:   logpath,
		MaxSize:    o.maxSize,
		MaxBackups: o.maxBackups,
		MaxAge:     o.maxAge,
		Compress:   o.compress,
	})

	dynLogger := &DynLogger{opts: o, Logger: l}
	checker.register(logpath, dynLogger)
	return dynLogger
}

func (l *DynLogger) GetCheckPathLevel(t time.Time) logrus.Level {
	if l.opts.levelCheckPath == "" {
		return l.GetLevel()
	}

	if l.lastCheckTime.Add(l.opts.levelCheckInterval).After(t) {
		return l.GetLevel()
	}
	l.lastCheckTime = t

	content, err := os.ReadFile(l.opts.levelCheckPath)
	if err != nil {
		return l.GetLevel()
	}

	level, err := logrus.ParseLevel(strings.TrimSpace(string(content)))
	if err != nil {
		return l.GetLevel()
	}
	return level
}

var checker = newLevelChecker()

type levelChecker struct {
	mu      *sync.Mutex
	loggers map[string]*DynLogger
}

func newLevelChecker() *levelChecker {
	checker := &levelChecker{
		mu:      &sync.Mutex{},
		loggers: make(map[string]*DynLogger),
	}
	go checker.keepChecking()
	return checker
}

func (c *levelChecker) register(name string, logger *DynLogger) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.loggers[name] = logger
	c.check(logger)
}

func (c *levelChecker) keepChecking() {
	t := time.NewTicker(time.Second * 10)
	defer t.Stop()

	for range t.C {
		c.mu.Lock()
		for _, logger := range c.loggers {
			c.check(logger)
		}
		c.mu.Unlock()
	}
}

func (c *levelChecker) check(logger *DynLogger) {
	from := logger.GetLevel()
	to := logger.GetCheckPathLevel(time.Now())
	if from != to {
		logger.WithFields(logrus.Fields{"from": from, "to": to}).Info("Changed level")
		logger.SetLevel(to)
	}
}
