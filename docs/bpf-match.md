# BPF Match Flow

## 背景

旧逻辑会按候选 slot 扫描最多 512 条规则，并对每条规则读取 `rule_index_map`
后检查 `required_mask`。规则容量较大时，verifier 在 load/attach 阶段可能处理超过
`1,000,000` 条指令并拒绝加载。

## 当前逻辑

userspace 编译规则时：

- 按 `priority ASC, rule_id ASC` 分配 slot，slot 小的规则优先。
- 写入 `all_active_rules`。
- 为 VLAN、端口、CIDR 写入倒排索引和字段 optional bitmap。
- 基于 `required_mask` 生成 `condition_optional_rules[16]`。

BPF 匹配时：

1. 从 `all_active_rules` 开始得到候选 bitmap。
2. VLAN、源/目的端口、源/目的 CIDR 使用索引过滤候选规则。
3. 索引命中时使用 `indexed | optional`，保留 wildcard 规则。
4. 非 IPv4 包只保留没有 CIDR 条件的规则。
5. 协议、TCP flags、ICMP 类型和 ARP op 使用 `condition_optional_rules` 过滤。
6. 候选 bitmap 非空时，取最低 slot 并读取一次 `rule_index_map`。

BPF 不再逐条扫描候选规则，也不再对每条候选规则执行 `required_mask` 判断。

## Load 测试

BPF load/verifier 问题通过 opt-in 测试提前暴露：

```sh
XDPASS_RUN_BPF_TESTS=1 go test ./internal/dataplane/bpfgen -run TestXdpassProgramLoad -count=1 -v
```

该测试只验证 BPF object 能加载，不覆盖 packet-level 行为用例。
