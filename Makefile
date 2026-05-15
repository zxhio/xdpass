.PHONY: generate test build clean

generate:
	go generate ./internal/dataplane/bpfgen/...

test: generate
	go test ./...

build: generate
	go build -o build/xdpass-agent ./cmd/xdpass-agent

clean:
	rm -rf build/
	rm -f internal/dataplane/bpfgen/xdpass_bpfel.o
