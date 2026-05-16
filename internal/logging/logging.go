package logging

import (
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Config holds the raw logging section from the config file.
type Config struct {
	Level      string `yaml:"level"`
	FilePath   string `yaml:"file_path"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAgeDays int    `yaml:"max_age_days"`
	Compress   *bool  `yaml:"compress"`
}

// Options is the validated and normalized logging configuration.
type Options struct {
	Level      logrus.Level
	FilePath   string
	MaxSizeMB  int
	MaxBackups int
	MaxAgeDays int
	Compress   bool
}

const (
	DefaultLevel      = logrus.InfoLevel
	DefaultMaxSizeMB  = 100
	DefaultMaxBackups = 7
	DefaultMaxAgeDays = 30
	DefaultCompress   = true
)

// NewOptions validates raw logging config and returns normalized Options.
func NewOptions(cfg Config) (Options, error) {
	level := DefaultLevel
	if cfg.Level != "" {
		parsed, err := logrus.ParseLevel(cfg.Level)
		if err != nil {
			return Options{}, err
		}
		level = parsed
	}

	filePath := strings.TrimSpace(cfg.FilePath)

	maxSizeMB := cfg.MaxSizeMB
	if maxSizeMB <= 0 {
		maxSizeMB = DefaultMaxSizeMB
	}

	maxBackups := cfg.MaxBackups
	if maxBackups <= 0 {
		maxBackups = DefaultMaxBackups
	}

	maxAgeDays := cfg.MaxAgeDays
	if maxAgeDays <= 0 {
		maxAgeDays = DefaultMaxAgeDays
	}

	compress := DefaultCompress
	if cfg.Compress != nil {
		compress = *cfg.Compress
	}

	return Options{
		Level:      level,
		FilePath:   filePath,
		MaxSizeMB:  maxSizeMB,
		MaxBackups: maxBackups,
		MaxAgeDays: maxAgeDays,
		Compress:   compress,
	}, nil
}

// Setup configures logrus according to opts.
// If FilePath is empty, logs go to stderr only.
func Setup(opts Options) {
	logrus.SetLevel(opts.Level)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02T15:04:05.000",
	})

	if opts.FilePath == "" {
		return
	}

	logrus.SetOutput(&lumberjack.Logger{
		Filename:   opts.FilePath,
		MaxSize:    opts.MaxSizeMB,
		MaxBackups: opts.MaxBackups,
		MaxAge:     opts.MaxAgeDays,
		Compress:   opts.Compress,
	})
}
