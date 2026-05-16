.PHONY: generate test build clean

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
CGO_ENABLED ?= 0
GOOS ?= linux
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

generate:
	go generate ./internal/dataplane/bpfgen/...

test: generate
	go test ./...

build: generate
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) go build -ldflags "$(LDFLAGS)" -o build/xdpass-agent ./cmd/xdpass-agent

clean:
	rm -rf build/
	rm -f internal/dataplane/bpfgen/xdpass_bpfel.o
