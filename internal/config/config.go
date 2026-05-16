package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"xdpass/internal/logging"
)

const DefaultListenAddr = "127.0.0.1:9527"

// Config is the raw startup configuration parsed from YAML.
type Config struct {
	Server  ServerConfig   `yaml:"server"`
	Logging logging.Config `yaml:"logging"`
}

// ServerConfig holds the raw server section from the config file.
type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

// ServerOptions is the validated and normalized server configuration.
type ServerOptions struct {
	ListenAddr string
}

// Load reads and parses the config file at path.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// NewServerOptions validates raw server config and returns normalized Options.
func NewServerOptions(cfg ServerConfig) (ServerOptions, error) {
	listenAddr := strings.TrimSpace(cfg.ListenAddr)
	if listenAddr == "" {
		listenAddr = DefaultListenAddr
	}
	return ServerOptions{ListenAddr: listenAddr}, nil
}
