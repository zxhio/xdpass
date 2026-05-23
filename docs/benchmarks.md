# Benchmarks

## 环境

| 项目 | 值 |
|---|---|
| OS | Linux 6.1.0-10-amd64 |
| Go | go1.25.5 linux/amd64 |
| CPU | 12th Gen Intel(R) Core(TM) i7-12700 |

## BPF Match

使用 `Program.Benchmark(pkt, repeat=10000, reset)` 在单次 syscall 内重复执行
BPF 程序，由 kernel 返回每次执行时间（`ns/run`），排除 Go 侧 syscall 和内存
分配开销。

```sh
XDPASS_RUN_BPF_TESTS=1 go test ./internal/dataplane/bpftest -run '^$' -bench 'BenchmarkMatch' -benchmem -count=1
```

| case | rules | ns/run | notes |
|---|---|---|---|
| empty ruleset | 0 | 37 | baseline, no match logic |
| single wildcard | 1 | 96 | all fields wildcard |
| dst port hit | 1 | 99 | indexed port match |
| dst port miss | 1 | 50 | indexed port, no match |
| CIDR hit | 1 | 52 | LPM trie match |
| CIDR miss | 1 | 58 | LPM trie, no match |
| mixed rules | 5 | 102 | protocol + port + CIDR |
| 1 rule | 1 | 108 | scale baseline |
| 10 rules | 10 | 99 | |
| 100 rules | 100 | 98 | |
| 512 rules late hit | 512 | 99 | worst-case, last slot matches |
| 512 rules miss | 512 | 53 | worst-case, no match |

- 空规则集 baseline 37 ns，其余场景 50-108 ns，差距来自 match 逻辑本身。
- hit 和 miss 的差异主要在最终 `rule_index_map` 读取，不在 bitmap 扫描。
- 规则数量从 1 到 512 对 ns/run 几乎无影响，说明 inverted index + bitmap
  过滤有效，不存在逐条扫描的线性开销。

## Response Builder

使用 `BuilderIntoFunc` 将响应包写入 caller-provided buffer，消除 `make([]byte)`
堆分配。benchmark loop 外预分配 output buffer，loop 内不创建临时对象。

```sh
go test ./internal/response -run '^$' -bench 'BenchmarkBuildInto' -benchmem -count=1
```

### BuilderIntoFunc（零分配）

| action | ns/op | B/op | allocs/op |
|---|---|---|---|
| icmp_echo_reply | 32.87 | 0 | 0 |
| udp_echo_reply | 16.33 | 0 | 0 |
| arp_reply | 22.47 | 0 | 0 |
| icmp_port_unreachable | 32.91 | 0 | 0 |
| icmp_host_unreachable | 33.52 | 0 | 0 |
| icmp_admin_prohibited | 33.54 | 0 | 0 |

### BuilderFunc（有分配，对比基线）

| action | ns/op | B/op | allocs/op |
|---|---|---|---|
| icmp_echo_reply | ~122 | 80 | 1 |
| udp_echo_reply | ~94 | 64 | 1 |
| arp_reply | ~168 | 88 | 3 |
| icmp_port_unreachable | ~129 | 80 | 1 |
| icmp_host_unreachable | ~122 | 80 | 1 |
| icmp_admin_prohibited | ~133 | 80 | 1 |

`BuilderFunc` 的分配来自 `make([]byte, len(origPkt))` 复制原始包。
`BuilderIntoFunc` 通过 caller 预分配 buffer 消除分配，ns/op 降低 3-5x。
