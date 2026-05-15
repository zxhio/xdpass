# agent ruleset

## 定位

`ruleset` 表示 `agent` 当前运行时规则集。

- 由调用方整体下发
- `agent` 不提供单条规则 CRUD
- `agent` 不生成 `rule_id`
- `agent` 只使用 `ruleset` 中已有的 `rule_id`
- 具体 API 路由见 `../agent-api.md`

---

## 资源结构

```json
{
  "rules": [
    {
      "rule_id": 1001,
      "priority": 10,
      "match": {
        "protocol": "tcp",
        "dst_ports": [80, 8080],
        "tcp_flags": {
          "syn": true
        }
      },
      "response": {
        "action": "tcp_reset",
        "params": {}
      }
    }
  ]
}
```

---

## 字段约定

### `rules`

- 必填
- 规则数组
- 只包含需要实际生效的规则
- 不包含 `enabled=false` 的规则
- 最多 `512` 条，对齐 BPF `MAX_RULE_SLOTS`

### `rules[].rule_id`

- 必填
- 类型：`uint32`
- 由调用方生成
- 创建后不可修改
- 删除后不复用
- 用于 `stats` / `events` 关联规则

### `rules[].priority`

- 可选
- 默认值：`0`
- 必须大于等于 `0`
- 数值越小优先级越高
- 多条规则同时命中时，按 `priority ASC, rule_id ASC` 选择第一条

### `rules[].match`

- 可选
- 为空表示匹配所有包
- 字段结构和基础匹配语义见本文件 `Match 字段`
- `agent` 负责校验、编译和加载运行态匹配结构

### `rules[].response`

- 必填
- 字段结构、动作枚举、参数约束和兼容性见本文件 `Response Action`
- `response.action` 由 `agent` 编译为运行态 action code
- 具体执行路径见 `response.md`

### `rules[].response.params`

- 可选
- 动作相关参数
- 不进入 BPF `rule_meta`
- 由需要用户态响应的 action 使用
- 不需要参数的 action 应为空或省略

---

## Match 语义

`agent` 侧负责运行态校验、编译和执行，必须保证：

- 按 `priority ASC, rule_id ASC` 编译规则
- 多条规则同时命中时，选择编译顺序中的第一条
- 未配置字段按 wildcard 处理
- 只支持正向匹配，不支持否定条件

---

## Match 字段

`rules[].match` 支持以下字段。

```json
{
  "protocol": "tcp",
  "vlans": [100],
  "src_cidrs": ["10.0.0.0/8"],
  "dst_cidrs": ["192.168.1.0/24"],
  "src_ports": [1024],
  "dst_ports": [80, 8080],
  "tcp_flags": {
    "syn": true,
    "ack": false
  },
  "icmp_type": "echo_request",
  "arp_op": "request",
  "has_l4_payload": true
}
```

字段：

- `protocol`：可选，枚举 `tcp` / `udp` / `icmp` / `arp`
- `vlans`：可选，VLAN ID 数组
- `src_cidrs`：可选，源 IPv4 CIDR 数组
- `dst_cidrs`：可选，目的 IPv4 CIDR 数组
- `src_ports`：可选，TCP/UDP 源端口数组
- `dst_ports`：可选，TCP/UDP 目的端口数组
- `tcp_flags`：可选，TCP flags 正向匹配条件
- `icmp_type`：可选，枚举 `echo_request` / `echo_reply`
- `arp_op`：可选，枚举 `request` / `reply`
- `has_l4_payload`：可选，要求 L4 payload 长度大于 `0`

基础匹配语义：

- 同一字段多个值是 OR
- 不同字段之间是 AND
- 未配置字段是 wildcard
- 不支持否定条件
- `src_ports` / `dst_ports` 只对 TCP/UDP 有效
- `tcp_flags` 只对 TCP 有效
- `icmp_type` 只对 ICMP 有效
- `arp_op` 只对 ARP 有效

---

## Match / Action 兼容性

`agent` 必须校验 `match` 和 `response.action` 是否兼容。

基础规则：

- `tcp_reset` 和 `tcp_syn_ack` 只兼容 TCP 包。
- `icmp_echo_reply` 只兼容 ICMP echo request。
- `icmp_port_unreachable` 主要用于 UDP 包。
- `icmp_host_unreachable` / `icmp_admin_prohibited` 兼容 IPv4 TCP / UDP / ICMP。
- `udp_echo_reply` 只兼容 UDP 包，并且要求 `has_l4_payload=true`。
- `dns_sinkhole` / `dns_refused` 只兼容 UDP DNS 请求，通常要求 `dst_ports` 包含 `53`。
- `arp_reply` 只兼容 ARP request。
- `none` / `alert` 不要求特定协议。

当规则缺少足够的 `match` 约束导致 action 不能确定执行对象时，`PUT /api/v1/ruleset`
必须返回 `400 validation_failed`。

---

## Response Action

`agent` 负责：

- 校验 `response.action`
- 校验 `match` / `response.action` 是否兼容
- 将 `response.action` 编译为运行态 action code
- 根据 `response.action` 选择 no response、kernel response 或 userspace response 路径
- 将执行结果通过 `events` 和 `stats` 上报

具体执行路径见 `response.md`。

### action 枚举

| `response.action` | 路径 | 说明 |
|---|---|---|
| `none` | `none` | 不构造响应包 |
| `alert` | `none` | 只产生事件 |
| `tcp_reset` | `kernel` | BPF 内核态构造 TCP RST |
| `icmp_port_unreachable` | `kernel` | BPF 内核态构造 ICMP port unreachable |
| `icmp_host_unreachable` | `kernel` | BPF 内核态构造 ICMP host unreachable |
| `icmp_admin_prohibited` | `kernel` | BPF 内核态构造 ICMP administratively prohibited |
| `icmp_echo_reply` | `userspace` | 用户态构造 ICMP echo reply |
| `tcp_syn_ack` | `userspace` | 用户态构造 TCP SYN ACK |
| `udp_echo_reply` | `userspace` | 用户态回显 UDP payload |
| `dns_sinkhole` | `userspace` | 用户态构造 DNS sinkhole 响应 |
| `dns_refused` | `userspace` | 用户态构造 DNS refused 响应 |
| `arp_reply` | `userspace` | 用户态构造 ARP reply |

### action 参数

无参数 action：

- `none`
- `alert`
- `tcp_reset`
- `icmp_echo_reply`
- `icmp_port_unreachable`
- `icmp_host_unreachable`
- `icmp_admin_prohibited`
- `udp_echo_reply`

带参数 action：

- `tcp_syn_ack`：`tcp_seq` 可选，省略时使用默认值
- `dns_refused`：`rcode` 可选，默认 `refused`
- `dns_sinkhole`：`family`、`answers_v4`、`answers_v6`、`ttl`
- `arp_reply`：`hardware_addr`、`sender_ipv4`

参数范围：

- `tcp_seq`：`uint32`
- `rcode`：当前只允许 `refused`
- `family`：`ipv4` / `ipv6` / `dual_stack`
- `answers_v4`：IPv4 地址字符串数组，`family=ipv4` 或 `dual_stack` 时至少 1 个
- `answers_v6`：IPv6 地址字符串数组，`family=ipv6` 或 `dual_stack` 时至少 1 个
- `ttl`：`uint32`，必须大于 `0`
- `hardware_addr`：MAC 地址字符串
- `sender_ipv4`：IPv4 地址字符串

---

## 更新语义

`GET /api/v1/ruleset` 返回当前完整 `ruleset`。

- 未加载 ruleset 时返回空规则集：`{"rules":[]}`
- 返回体不包含 `version`
- 返回体不包含内部编译字段

`PUT /api/v1/ruleset` 用于整体替换当前运行时 `ruleset`。

更新过程必须是原子的：

- 校验 `ruleset`
- 编译运行态结构
- 更新 BPF maps / 用户态索引
- 全部成功后切换到新版本
- 任一步失败时保留旧版本
- 成功后 `GET /api/v1/ruleset` 返回新完整 ruleset

`PUT /api/v1/ruleset?dry_run=true` 只校验，不应用。

`DELETE /api/v1/ruleset` 清空当前运行时规则集。

清空 `ruleset` 不影响以下运行态配置：

- `attachments`
- `response`

进程重启后当前 `ruleset` 丢失，由调用方重新调用 `PUT /api/v1/ruleset` 下发。

---

## 编译约定

- `enabled` 不出现在 agent `ruleset` 中
- `name` 不出现在 agent `ruleset` 中
- `created_at` 不出现在 agent `ruleset` 中
- `updated_at` 不出现在 agent `ruleset` 中
- `version` 暂不出现在 agent `ruleset` 中
- `response.params` 不进入 BPF `rule_meta`
- `agent` 可以将匹配条件编译为索引和 `required_mask`
- 内核事件和统计统一使用 `rule_id`

---

## 运行态字段

BPF `rule_meta` 只包含运行态必要字段。

字段：

```text
rule_id
required_mask
action
flags
```

不进入 BPF `rule_meta` 的字段：

- `priority`
- `name`
- `enabled`
- `response.params`
- `created_at`
- `updated_at`

dataplane 编译语义见 `dataplane.md`。

BPF map、condition bit 和 action code 见 `bpf-abi.md`。

---

## 资源边界

- `ruleset`：当前运行时规则集
- `response`：定义 `response.action` 的运行态执行路径
- `events`：上报规则命中和动作结果
- `stats`：记录当前运行态计数
