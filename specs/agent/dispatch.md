# agent dispatch

## 定位

`dispatch` 表示命中包转交 downstream 的运行态分发能力。

第一版只覆盖 userspace response path：

- BPF 将 userspace response action 的原始包转入 XSK。
- 用户态 response worker 构造并发送 response。
- response 成功后，原始包异步进入 dispatch queue。
- dispatch worker 通过 `AF_PACKET` 将原始 L2 frame 发到配置的出口网口。

dispatch 只做分发，不做审计、存储、采样或下游协议适配。

具体 API 路由见 `../agent-api.md`。

---

## 资源结构

```json
{
  "enabled": true,
  "configured": true,
  "ifindex": 3,
  "ifname": "eth1",
  "queue_size": 4096
}
```

---

## 字段约定

### `enabled`

- 可写
- 表示是否启用 dispatch
- `false` 时不分发 packet

### `configured`

- 只读
- 表示当前是否已有有效 dispatch 配置
- `DELETE /api/v1/dispatch` 后为 `false`

### `ifindex`

- `PUT /api/v1/dispatch` 时必填
- 必须大于 `0`
- Linux 网卡 `ifindex`
- 表示 AF_PACKET 分发出口网口

### `ifname`

- 可选
- 如果传入，需要校验是否和 `ifindex` 匹配
- 仅用于展示、日志和调试

### `queue_size`

- 可选
- 默认值：`4096`
- 必须大于 `0`
- 表示 dispatch 异步发送队列容量

---

## API 行为

### get

`GET /api/v1/dispatch` 查看当前 dispatch 配置。

- 未配置时返回：
  - `enabled=false`
  - `configured=false`
  - `ifindex=0`
  - `ifname=""`
  - `queue_size=4096`

### put

`PUT /api/v1/dispatch` 整体替换 dispatch 配置。

- 校验 `ifindex`
- 如果传入 `ifname`，必须和 `ifindex` 匹配
- 校验并规范化 `queue_size`
- 成功后返回规范化后的 dispatch 配置
- 返回中 `configured=true`

请求示例：

```json
{
  "enabled": true,
  "ifindex": 3,
  "ifname": "eth1",
  "queue_size": 4096
}
```

### delete

`DELETE /api/v1/dispatch` 删除 dispatch 配置。

- 删除后停止 dispatch worker
- 清空待分发 queue
- 成功时返回 `204`
- 未配置时也返回 `204`

### recovery

- 进程重启后 dispatch 恢复为未配置、未启用。
- 需要启用 dispatch 时，由调用方重新调用 `PUT /api/v1/dispatch` 下发期望配置。

---

## 执行语义

dispatch 只处理 userspace response worker 已收到的原始包。

执行顺序：

```text
XSK RX
  -> userspace response worker
  -> response build/send
  -> dispatch enqueue
  -> dispatch worker
  -> AF_PACKET send original L2 frame
```

约定：

- response 成功后才 enqueue dispatch。
- enqueue 和 AF_PACKET 发送都是异步的。
- dispatch 不影响 response result/event。
- dispatch queue 满时直接丢弃 dispatch packet。
- dispatch disabled、未配置或 sender 不可用时不分发 packet。
- dispatch 失败只影响 dispatch stats。

---

## Packet 语义

- dispatch 发送原始 L2 frame。
- 原始 VLAN tag 必须保留。
- 不重写 Ethernet、IPv4、L4 header。
- 不截断 packet。
- 不生成新的 response packet。

---

## Stats

dispatch stats 见 `stats.md` 的 `dispatch` 字段。

第一版只定义全局 stats：

- `enqueue_packets`
- `packets`
- `dropped_packets`
- `queue_full_packets`
- `error_packets`

不按 rule、attachment 或 backend 拆分。

---

## 不做

- 不提供 per-rule dispatch 开关。
- 不支持 kernel response path dispatch。
- 不支持多 backend。
- 不支持 HTTP、gRPC、Unix socket、pcap file backend。
- 不支持 packet sampling、snaplen、重试或持久队列。
- 不定义 dispatch events。
- 不修改 BPF ABI、map layout、action code 或 XSK metadata。
