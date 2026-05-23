# agent dataplane

`dataplane` 定义 agent 快路径的包处理、规则匹配、action 执行和观测语义。

- Go dataplane loader、ruleset compiler、XDP/BPF 程序和测试必须遵守
- 外部 HTTP API 不直接暴露 BPF map
- API 资源见 `ruleset.md`、`events.md`、`stats.md`、`response.md`
- dataplane 不负责规则 CRUD、规则持久化、历史 stats / events 存储和 downstream 分析服务生命周期
- dispatch 只在 userspace path 中异步分发原始包，不改变 XDP/BPF 处理语义

dataplane 输入：

- 入站镜像包
- 当前编译后的 `ruleset`
- attachment 的 `miss_verdict`
- response egress 默认出口配置
- XSK queue 注册状态

多 attachment 约定：

- 每个 attachment 独立加载 BPF program。
- 每个 attachment 拥有独立 BPF map set。
- `ruleset` 的编译语义在每个 attachment 的 map set 上分别生效。
- `miss_verdict`、`tx_config` 和 `xsks_map` 都按 attachment 隔离。
- `stats` 和 `events` 对外展示时由 agent 聚合或补充 `ifindex`。

dataplane 输出：

- stats counters
- rule events
- XSK 原始包和 metadata
- userspace path 中可被 dispatch runtime 异步分发的原始包

---

## XDP 程序流程

MVP 只定义镜像入口包的快路径处理。

```text
packet
  -> parse supported protocol fields
  -> match compiled ruleset
  -> execute matched action
  -> report stats / events
```

### MVP 协议解析

dataplane 只解析 MVP 需要的协议字段。

- 支持 Ethernet、单层 VLAN、IPv4 TCP / UDP / ICMP、ARP
- parse 成功后提取规则匹配所需字段
- parse failed 时不匹配规则、不构造 response、不产生 rule event，走 `miss_verdict`

### MVP 规则匹配

- userspace 先把 `ruleset` 按优先级编译成 BPF 可消费的结构
- BPF 不判断 `priority`
- BPF 只做候选规则筛选和第一命中选择
- 未命中规则时走 `miss_verdict`

具体编译和匹配约定见 `ruleset 编译语义`。

### MVP action

dataplane 只负责按 action 选择执行路径。

- `none` / `alert`：不构造响应包
- kernel response：BPF 内联构造响应包
- userspace response：原始包进入 XSK，用户态构造响应包

response action 枚举、路径和失败语义见 `response.md`。

stats、events 的外部语义分别见 `stats.md`、`events.md`。

### Dispatch

dispatch 不属于 XDP/BPF action。

- BPF 不为 dispatch 增加 action code。
- BPF 不为 dispatch 修改 map layout 或 XSK metadata。
- kernel response path 不复制或重定向原始包给 dispatch。
- userspace response worker 收到原始包并成功发送 response 后，可异步 enqueue dispatch。
- dispatch 发送失败、queue 满或未启用不改变原始 response result。

dispatch API 和运行态语义见 `dispatch.md`。

---

## miss_verdict

`miss_verdict` 来自 attachment。

- `pass`：返回 `XDP_PASS`
- `drop`：返回 `XDP_DROP`

写入 BPF 时，`miss_verdict` 保持同名字段。

适用场景：

- 未命中任何规则
- parse failed
- action 不支持当前包形态

`miss_verdict` 不和 response egress 配置的 `ifindex` 联动。

- `miss_verdict` 只决定入站包在未响应场景下 pass/drop
- response egress `ifindex` 只决定命中规则后响应包的异口发送出口
- 未命中包不会因为配置了 response egress 出口而 redirect 到 response egress 网口
- 命中规则后的 response 构造、发送、XSK metadata 写入或 redirect 失败，不使用 `miss_verdict`
- MVP 中 response failure verdict 固定为 `drop`
- 本机测试时可将 `miss_verdict=pass`，让未匹配包放行；命中后 response 失败仍会被识别为失败路径并丢弃

---

## response failure verdict

response failure verdict 表示命中规则并进入 response 路径后，response 构造、发送或转入
userspace 失败时对原始包的处置。

MVP 固定为：

- `drop`：返回 `XDP_DROP`

适用场景：

- kernel response 构造失败
- kernel response `XDP_TX` 提交失败
- kernel response redirect 出口解析、帧改写、FIB lookup 或提交失败
- userspace response 的 XSK metadata 写入失败
- userspace response 的 XSK map redirect 失败

约定：

- response failure verdict 不提供 HTTP API 配置。
- response failure verdict 不使用 attachment `miss_verdict`。
- 失败必须递增对应 `stats` 计数。
- 能产生事件时，事件使用对应 `path` 和 `verdict`，并设置 `result=failed`。

---

## ruleset 编译语义

`ruleset` 下发后，agent 将启用规则编译到 dataplane。

### 编译流程

1. 过滤非运行态字段。
2. 按 `priority ASC, rule_id ASC` 排序。
3. 分配 rule slot，最多 `512` 条。
4. 写入 rule metadata。
5. 写入倒排索引。
6. 写入全局配置。
7. 对每个已启用 attachment 的独立 map set 执行同一套更新。
8. 全部成功后切换到新 ruleset。

约定：

- `rule_id` 必须是 `uint32`
- `response.params` 不进入 BPF rule metadata
- wildcard 规则必须进入对应 wildcard bitmap
- 配置了具体字段值的规则必须进入对应索引值的 bitmap
- 任一步或任一 attachment map set 更新失败时保留旧 ruleset

### 规则顺序

- agent 在 userspace 按 `priority ASC, rule_id ASC` 排序
- 排序后的规则写入固定 slot
- slot 0 表示最高优先级规则
- `priority` 不进入 BPF `rule_meta`
- BPF 程序不比较 `priority`

### 匹配语义

- 未配置字段是 wildcard
- 同一字段多个值是 OR
- 不同字段之间是 AND
- 只支持正向匹配
- 不支持否定条件

BPF 运行时匹配：

- BPF 使用索引 maps 得到候选 slot bitmap
- 索引命中时保留字段 wildcard 规则，即使用 `indexed | wildcard`
- BPF 使用 condition wildcard bitmap 过滤非索引条件
- BPF 取候选 bitmap 中 slot 最小的规则
- 多条规则同时满足条件时，slot 最小的规则获胜

`required_mask` 是规则要求的条件类别 bitmask。

- userspace 将规则需要的条件类别编译到 `required_mask`
- BPF 解析包后生成 `pkt_conds`
- 具体值匹配先由索引 maps 完成，例如端口、VLAN、CIDR
- `required_mask` 不保存端口号、CIDR、VLAN ID 等具体值
- BPF 不逐条读取规则执行 `(pkt_conds & required_mask) == required_mask`
- `required_mask` 语义由 userspace 编译出的索引 bitmap、wildcard bitmap 和
  `condition_wildcard_rules` 共同表达
- `tcp.flags`、`icmp.type`、`arp.op` 这类协议子字段会被编译成对应的
  `required_mask` bit 和 `condition_wildcard_rules` 条目，不进入 `rule_meta.flags`

---

## BPF ABI

BPF ABI 是 agent 内部实现契约，见 `bpf-abi.md`。

dataplane 只依赖这些 ABI 能力：

- `ruleset` 编译后的 rule metadata 和索引 maps
- attachment `miss_verdict` 的 BPF 表示
- kernel response TX 配置
- rule event ringbuf
- stats counters
- XSK metadata

dispatch v1 不增加 BPF ABI 能力。

修改 dataplane 包处理语义时，必须同步检查 `bpf-abi.md` 是否需要变更。
