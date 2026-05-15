// Package bpfgen owns BPF binding generation.
package bpfgen

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Werror" Xdpass ../bpf/prog.c -- -I../bpf
