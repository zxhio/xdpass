# agent status

## 定位

`status` 表示 `agent` 当前运行态总览。

`health` 只表示进程存活。

具体 API 路由见 `../agent-api.md`。

---

## health

`GET /api/v1/health` 用于进程存活检查。

成功响应：

```json
{
  "status": "ok"
}
```

字段约定：

### `status`

- 固定值：`ok`

---

## status

`GET /api/v1/status` 用于查看 agent 当前运行态总览。

建议结构：

```json
{
  "status": "running",
  "attachments": 1,
  "ruleset_loaded": true,
  "rules": 12,
  "response_egress_configured": true,
  "dispatch_configured": true
}
```

字段约定：

### `status`

- 可选值：`running` / `degraded`
- `running`：主要运行态正常
- `degraded`：进程存活，但部分运行态能力不可用

### `attachments`

- 当前 attachment 数量

### `ruleset_loaded`

- 当前是否已加载非空 ruleset

### `rules`

- 当前运行态 ruleset 中的规则数量

### `response_egress_configured`

- 是否已配置 response egress 默认出口

### `dispatch_configured`

- 是否已配置 dispatch

### `issues`

- 可选
- `degraded` 时包含诊断条目
- `running` 时省略或为空数组

---

## issues 语义

每个 issue 描述一个运行态不一致。存在任何 issue 时 `status=degraded`。

不算 degraded 的情况：

- 未配置 response egress
- 未配置 dispatch
- 未启用 XSK
- 无 SSE 客户端连接
- 未加载 ruleset

### issue codes

| component | code | 条件 |
|---|---|---|
| `attachment` | `attachment_resources_missing` | attachment `enabled=true`，但 BPF resources 不存在 |
| `attachment` | `attachment_link_missing` | attachment `enabled=true`，但 XDP link 不存在 |
| `attachment` | `attachment_map_missing` | attachment `enabled=true`，但必要 BPF map 缺失 |
| `events` | `event_reader_missing` | attachment `enabled=true` 且有 `event_ringbuf`，但 event reader 未运行 |
| `xsk` | `xsk_not_running` | attachment `enabled=true` 且 `xsk.enabled=true`，但 XSK socket 未运行 |
| `response` | `response_worker_missing` | attachment `enabled=true` 且 `xsk.enabled=true`，但 response worker 未运行 |
| `ruleset` | `userspace_action_without_xsk` | 当前 ruleset 包含 userspace response action，但某个 enabled attachment 未启用 XSK |
| `ruleset` | `ruleset_not_applied` | 当前 ruleset loaded，但某个 enabled attachment 未应用当前 ruleset generation |
| `dispatch` | `dispatch_worker_missing` | dispatch 已配置且 enabled，但 dispatch worker 未运行 |
| `dispatch` | `dispatch_sender_missing` | dispatch 已配置且 enabled，但 sender 缺失 |
