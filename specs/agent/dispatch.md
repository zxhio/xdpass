# agent dispatch

## 定位

`dispatch` 表示命中包转交 downstream 的后续能力。

当前暂缓设计，不属于现阶段 `agent` API 合同。

暂缓原因：

- 如果只在用户态做 dispatch，会受限于当前规则匹配和 XSK 收包路径。
- dispatch 与 response 的同包执行顺序、背压、丢包和 stats 口径尚未确定。
- downstream backend、采样、队列和失败语义尚未确定。

---

## 当前约定

- 不提供 `/api/v1/dispatch` 路由。
- 不要求 dataplane 为 dispatch 强制把所有命中包送入 XSK。
- 不定义 dispatch 配置资源。
- 不定义 dispatch stats 为默认 `GET /api/v1/stats` 字段。
- 不定义 dispatch events。
- response 执行路径不依赖 dispatch。

---

## 待确认问题

- dispatch 是否只处理已经进入 XSK 的 userspace response 包，还是要求额外的 dataplane action。
- kernel response action 命中时，是否还需要把原始包复制或重定向给 dispatch。
- dispatch 与 response 的先后关系、失败隔离和背压策略。
- downstream backend 类型：`AF_PACKET`、HTTP、gRPC、Unix socket、pcap file 或其他。
- 是否需要 packet sampling、截断长度、队列策略和 per-rule 开关。
- stats 和 events 是否需要按 rule、attachment 或 downstream 维度拆分。

---

## 后续设计入口

后续重新启用 dispatch 时，需要同时更新：

- `agent-api.md`
- `agent/dataplane.md`
- `agent/ruleset.md`
- `agent/stats.md`
- `agent/events.md`
- `agent/bpf-abi.md`
