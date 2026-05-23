# BPF 规则匹配结构图

本文以 `slot` 为核心说明规则如何编译成 BPF maps，以及 packet 如何沿着这些 maps
完成匹配。

## mask_t

`mask_t` 是规则 slot bitmap。每一 bit 对应一个 slot。

```text
mask_t

                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
bits              |  on/off |  on/off |  on/off |   ...   |  on/off |
                  +---------+---------+---------+---------+---------+
```

后文所有 index map value、wildcard bitmap、active bitmap 都用 `mask_t` 表示 slot 集合。

## 核心关系

所有结构都围绕同一条 `slot` 轴关联。

```text
                 high              priority              low
                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
```

`rule_index_map` 保存 slot 到 rule meta 的映射：

```text
rule_index_map

                 high              priority              low
                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
rule meta         | rule 0  | rule 1  | rule 2  |   ...   | rule N  |
                  +---------+---------+---------+---------+---------+
```

其他结构通过 `mask_t` value 关联到同一条 slot 轴：

- index map 本身是 `HASH` 或 `LPM_TRIE`。
- index map 的 value 是 `mask_t`。
- wildcard bitmap 本身也是 `mask_t`。

它们都不保存规则内容，只保存“哪些 slot 还可能匹配”。

## 规则示例

假设有 3 条规则：

```text
+------+----------+------+--------------------+--------+
| rule | priority | slot | match              | action |
+------+----------+------+--------------------+--------+
| 100  | 10       | 0    | TCP, dst_port=80   | alert  |
| 101  | 20       | 1    | TCP                | none   |
| 102  | 30       | 2    | wildcard           | alert  |
+------+----------+------+--------------------+--------+
```

编译后，优先级顺序固化为 slot 顺序：

```text
                 high              priority              low
                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
rule_index_map    | rule100 | rule101 | rule102 |   ...   |   -     |
                  +---------+---------+---------+---------+---------+
```

## Active Bitmap

`all_active_rules` 表示当前启用的所有规则 slot，是匹配起点。

```text
all_active_rules

                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
active            |    1    |    1    |    1    |   ...   |    0    |
                  +---------+---------+---------+---------+---------+
```

## Value Index Maps

index map 表示“某个具体值命中了哪些 slot”。

- `vlan_index_map`、`src_port_index_map`、`dst_port_index_map` 是 `HASH`。
- `src_prefix_lpm_map`、`dst_prefix_lpm_map` 是 `LPM_TRIE`。
- 它们的 value 是 `mask_t`。

当前匹配会按字段依次查这些 index：

```text
packet
  |
  v
vlan_index_map
  |
  v
src_port_index_map
  |
  v
dst_port_index_map
  |
  v
src_prefix_lpm_map
  |
  v
dst_prefix_lpm_map
  |
  v
condition filters
  |
  v
rule_index_map
  |
  v
action
```

示例里只有 rule 100 配了 `dst_port = 80`，所以 `dst_port_index_map` 有一个
key 为 `80` 的 entry。这个 map entry 的 value 是 `mask_t`：

```text
dst_port_index_map

entry
  +-----+---------+
  | key | value   |
  +-----+---------+
  | 80  | mask_t  |
  +-----+---------+
          |
          v
mask_t
  +---------+---------+---------+---------+---------+
  | slot 0  | slot 1  | slot 2  |   ...   |  max-1  |
  +---------+---------+---------+---------+---------+
  |    1    |    0    |    0    |   ...   |    0    |
  +---------+---------+---------+---------+---------+

  slot 0 = 1: rule 100 has dst_port=80
  slot 1 = 0: rule 101 has no dst_port condition
  slot 2 = 0: rule 102 has no dst_port condition
```

它只表达“值命中的规则”，不表达 wildcard。wildcard 规则在
`dst_port_wildcard_rules` 里单独保存。

## Wildcard Bitmaps

wildcard bitmap 表示“某个维度上不约束的 slot 集合”。过滤时，这些 slot 不能因为
这个维度不匹配而被删掉。

当前有两类 wildcard：

```text
field wildcard
  -> 规则没有配置某个字段
  -> 配合 value index 使用

condition wildcard
  -> 规则不要求某个 condition bit
  -> 配合 packet_conds 使用
```

### Field Wildcard

示例里：

- rule 100 配了 `dst_port = 80`，所以它不是 dst port wildcard。
- rule 101 没配 dst port，所以它是 dst port wildcard。
- rule 102 是全 wildcard，所以它也是 dst port wildcard。

```text
dst_port_wildcard_rules

                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
wildcard          |    0    |    1    |    1    |   ...   |    0    |
                  +---------+---------+---------+---------+---------+
```

其他字段也有对应的 field wildcard。它们不是 hash map，而是
`global_cfg_map[0]` 里的 `mask_t` 字段：

```text
field wildcard bitmaps in global_cfg_map[0]

                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
vlan wildcard     |    1    |    1    |    1    |   ...   |    0    |
src port wildcard |    1    |    1    |    1    |   ...   |    0    |
dst port wildcard |    0    |    1    |    1    |   ...   |    0    |
src CIDR wildcard |    1    |    1    |    1    |   ...   |    0    |
dst CIDR wildcard |    1    |    1    |    1    |   ...   |    0    |
                  +---------+---------+---------+---------+---------+
```

对应关系：

```text
slot 0: rule 100 has dst_port=80, no VLAN/src_port/src_CIDR/dst_CIDR
slot 1: rule 101 only requires TCP, so all field dimensions are wildcard
slot 2: rule 102 is wildcard, so all field dimensions are wildcard
```

### Condition Wildcard

字段值过滤之后，还会做 condition 过滤。

`required_mask` 表示规则要求哪些 condition。`condition_wildcard_rules[X]` 表示：
不要求 condition X 的 slot。

示例里：

- rule 100 要求 TCP。
- rule 101 要求 TCP。
- rule 102 不要求 TCP。

```text
condition_wildcard_rules[TCP]

                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
wildcard          |    0    |    0    |    1    |   ...   |    0    |
                  +---------+---------+---------+---------+---------+
```

当 packet 不是 TCP 时：

```text
candidates = candidates AND condition_wildcard_rules[TCP]
```

也就是删掉要求 TCP 的 slot，只保留不关心 TCP 的 slot。

## Value Index 和 Wildcard 的关系

value index 只负责“具体值命中哪些 slot”。field wildcard bitmap 负责保留“不关心这个
字段”的 slot。BPF 每处理一个字段，都会把这两类 slot 合并成这个字段的候选范围。

```text
packet.dport
    |
    v
dst_port_index_map lookup
    |
    +-------------------------+
    |                         |
    v                         v
lookup hit                lookup miss
    |                         |
    v                         v
+------------------+   +------------------+
| indexed mask     |   | wildcard mask    |
| from map value   |   | from global_cfg  |
+------------------+   +------------------+
    |                         |
    v                         |
+------------------+          |
| wildcard mask    |          |
| from global_cfg  |          |
+------------------+          |
    |                         |
    v                         |
+------------------+          |
| indexed | wild   |          |
+------------------+          |
    |                         |
    +------------+------------+
                 |
                 v
        field result mask
                 |
                 v
        candidates &= field result
```

也就是：

```text
保留两类 slot：
  1. 显式要求这个字段，并且值命中的 slot
  2. 没有配置这个字段，因此不关心这个字段的 wildcard slot
```

如果 packet 的目的端口是 `80`，查 `dst_port_index_map[80]` 得到 slot 0。

如果 packet 的目的端口是 `443`，查不到命中 slot，只保留 `dst_port_wildcard_rules`。

## 匹配流程

完整匹配流程：

```text
packet
  |
  v
parse fields
  |
  v
candidates = all_active_rules
  |
  v
candidates &= vlan_index_map[pkt.vlan].value | vlan_wildcard_rules
            or vlan_wildcard_rules on lookup miss
  |
  v
candidates &= src_port_index_map[pkt.sport].value | src_port_wildcard_rules
            or src_port_wildcard_rules on lookup miss
  |
  v
candidates &= dst_port_index_map[pkt.dport].value | dst_port_wildcard_rules
            or dst_port_wildcard_rules on lookup miss
  |
  v
candidates &= src_prefix_lpm_map[pkt.sip].value | src_prefix_wildcard_rules
            or src_prefix_wildcard_rules on lookup miss
  |
  v
candidates &= dst_prefix_lpm_map[pkt.dip].value | dst_prefix_wildcard_rules
            or dst_prefix_wildcard_rules on lookup miss
  |
  v
candidates &= condition_wildcard_rules[X] when packet lacks condition X
  |
  v
lowest slot
  |
  v
rule_index_map[slot]
  |
  v
action
```

## 示例匹配

### Packet 1：TCP 目的端口 80

```text
start

                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
active            |    1    |    1    |    1    |   ...   |    0    |
                  +---------+---------+---------+---------+---------+
```

```text
dst_port = 80

                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
indexed           |    1    |    0    |    0    |   ...   |    0    |
wildcard          |    0    |    1    |    1    |   ...   |    0    |
after dst_port    |    1    |    1    |    1    |   ...   |    0    |
                  +---------+---------+---------+---------+---------+
```

```text
condition: packet is TCP

                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
after condition   |    1    |    1    |    1    |   ...   |    0    |
                  +---------+---------+---------+---------+---------+

lowest slot = 0
rule_index_map[0] = rule 100
action = alert
```

### Packet 2：TCP 目的端口 443

```text
dst_port = 443

                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
indexed           |    0    |    0    |    0    |   ...   |    0    |
wildcard          |    0    |    1    |    1    |   ...   |    0    |
after dst_port    |    0    |    1    |    1    |   ...   |    0    |
                  +---------+---------+---------+---------+---------+

packet is TCP, so condition filter keeps slot 1 and slot 2.

lowest slot = 1
rule_index_map[1] = rule 101
action = none
```

### Packet 3：UDP 目的端口 80

```text
dst_port = 80

                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
indexed           |    1    |    0    |    0    |   ...   |    0    |
wildcard          |    0    |    1    |    1    |   ...   |    0    |
after dst_port    |    1    |    1    |    1    |   ...   |    0    |
                  +---------+---------+---------+---------+---------+
```

```text
packet lacks TCP

                  +---------+---------+---------+---------+---------+
slots             |    0    |    1    |    2    |   ...   |  max-1  |
                  +---------+---------+---------+---------+---------+
TCP wildcard      |    0    |    0    |    1    |   ...   |    0    |
after condition   |    0    |    0    |    1    |   ...   |    0    |
                  +---------+---------+---------+---------+---------+

lowest slot = 2
rule_index_map[2] = rule 102
action = alert
```

## 一句话总结

同一条 `slot` 轴把 `rule_index_map`、各类 index map、wildcard bitmap 和
condition wildcard bitmap 关联起来。BPF 只是在这条 slot 轴上不断过滤候选 bit，
最后选择最小 slot 作为第一命中规则。
