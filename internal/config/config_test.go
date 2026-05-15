package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewServerOptionsDefault(t *testing.T) {
	opts, err := NewServerOptions(ServerConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.ListenAddr != DefaultListenAddr {
		t.Fatalf("listen addr = %q, want %q", opts.ListenAddr, DefaultListenAddr)
	}
}

func TestNewServerOptionsExplicit(t *testing.T) {
	opts, err := NewServerOptions(ServerConfig{ListenAddr: "0.0.0.0:9090"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.ListenAddr != "0.0.0.0:9090" {
		t.Fatalf("listen addr = %q", opts.ListenAddr)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listen_addr: \"0.0.0.0:9090\"\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.ListenAddr != "0.0.0.0:9090" {
		t.Fatalf("listen addr = %q", cfg.Server.ListenAddr)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
}
