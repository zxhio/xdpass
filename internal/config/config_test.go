package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServerOptionsDefault(t *testing.T) {
	opts, err := NewServerOptions(ServerConfig{})
	require.NoError(t, err)
	assert.Equal(t, DefaultListenAddr, opts.ListenAddr)
}

func TestNewServerOptionsExplicit(t *testing.T) {
	opts, err := NewServerOptions(ServerConfig{ListenAddr: "0.0.0.0:9090"})
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:9090", opts.ListenAddr)
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("server:\n  listen_addr: \"0.0.0.0:9090\"\n"), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:9090", cfg.Server.ListenAddr)
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	assert.Error(t, err)
}
