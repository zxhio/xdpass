package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/pkg/logs"
	"github.com/zxhio/xdpass/pkg/xdp"
)

const (
	DefaultLogPath          = "/var/log/xdpass/xdpassd.log"
	DefaultLogLevel         = logrus.InfoLevel
	DefaultCheckPath        = "/etc/xdpass/xdpassd.log.level"
	DefaultCheckIntervalSec = 30
)

type Config struct {
	PollTimeoutMs int               `toml:"poll_timeout_ms"`
	Cores         []int             `toml:"cores"`
	Interfaces    []InterfaceConfig `toml:"interfaces"`
	Log           LogConfig         `toml:"log"`
}

type LogConfig struct {
	Path             string `toml:"path"`
	Level            string `toml:"level"`
	CheckPath        string `toml:"level_check_path"`
	CheckIntervalSec int    `toml:"level_check_interval_sec"`
	MaxSize          int    `toml:"max_size"`
	MaxBackups       int    `toml:"max_backups"`
	MaxAge           int    `toml:"max_age"`
	Compress         bool   `toml:"compress"`
}

type InterfaceConfig struct {
	Name       string            `toml:"name"`
	QueueID    int               `toml:"queue_id"`
	AttachMode xdp.XDPAttachMode `toml:"attach_mode"`

	// Bind flags
	ForceZeroCopy bool `toml:"force_zero_copy,omitempty"`
	ForceCopy     bool `toml:"force_copy,omitempty"`
	NoNeedWakeup  bool `toml:"no_need_wakeup"`

	// Internal
	XDPOpts []xdp.XDPOpt `toml:"-"`
}

var (
	defaultInterfaceConfigOffload = InterfaceConfig{
		Name:          "br1",
		QueueID:       -1,
		AttachMode:    xdp.XDPAttachModeNative,
		ForceZeroCopy: true,
		NoNeedWakeup:  false,
	}

	defaultInterfaceConfigGeneric = InterfaceConfig{
		Name:         "eth0",
		QueueID:      0,
		AttachMode:   xdp.XDPAttachModeGeneric,
		ForceCopy:    true,
		NoNeedWakeup: false,
	}

	defaultLogConfig = LogConfig{
		Path:             DefaultLogPath,
		Level:            DefaultLogLevel.String(),
		CheckPath:        DefaultCheckPath,
		CheckIntervalSec: DefaultCheckIntervalSec,
		MaxSize:          logs.DefaultMaxSize,
		MaxBackups:       logs.DefaultMaxBackups,
		MaxAge:           logs.DefaultMaxAge,
		Compress:         logs.DefaultCompress,
	}
)

func DefaultConfigOffload() *Config {
	return &Config{
		Cores:      []int{0, 2},
		Interfaces: []InterfaceConfig{defaultInterfaceConfigOffload},
		Log:        defaultLogConfig,
	}
}

func DefaultConfigGeneric() *Config {
	return &Config{
		PollTimeoutMs: 10,
		Interfaces:    []InterfaceConfig{defaultInterfaceConfigGeneric},
		Log:           defaultLogConfig,
	}
}

func NewConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	for _, cfg := range cfg.Interfaces {
		if err := validateInterfaceConfig(&cfg); err != nil {
			return nil, err
		}

		if cfg.ForceZeroCopy {
			cfg.XDPOpts = append(cfg.XDPOpts, xdp.WithZeroCopy())
		} else if cfg.ForceCopy {
			cfg.XDPOpts = append(cfg.XDPOpts, xdp.WithCopy())
		}
		if cfg.NoNeedWakeup {
			cfg.XDPOpts = append(cfg.XDPOpts, xdp.WithNoNeedWakeup())
		}
	}

	return &cfg, nil
}

func validateInterfaceConfig(cfg *InterfaceConfig) error {
	if cfg.Name == "" {
		return fmt.Errorf("interface name is required")
	}

	if cfg.ForceZeroCopy && cfg.ForceCopy {
		return fmt.Errorf("only one bind flags is allowed")
	}
	return nil
}
