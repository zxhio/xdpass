.PHONY: generate test build pack clean

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
CGO_ENABLED ?= 0
GOOS ?= linux
GOARCH ?= $(shell go env GOARCH)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

generate:
	go generate ./internal/dataplane/bpfgen/...

test: generate
	go test ./...

build: generate
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o build/xdpass-agent ./cmd/xdpass-agent

pack:
	VERSION=$(VERSION) scripts/pack.sh

clean:
	rm -rf build/
	rm -f internal/dataplane/bpfgen/xdpass_bpfel.o
