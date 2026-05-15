# Modules

## 服务边界

`agent` 是运行态服务。

- 负责 XDP / BPF / XSK / 网卡操作
- 通过 HTTP API 接收调用方下发的运行态配置
- 不负责规则持久化、配置管理、历史统计和 Web 交互

---

## 资源边界

- `ruleset`：agent 当前运行态规则集合，由调用方整体下发
- `stats`：`agent` 提供当前运行态计数，不保存历史统计
- `events`：`agent` 推送运行态事件，不保存历史事件
- `attachments` / `response`：agent 运行态配置

Web 交互不属于 `agent` 职责范围。

---

## 服务文档

- `agent.md`

## API 文档

- `agent-api.md`

## agent 文档

- `agent/config.md`
- `agent/http.md`
- `agent/status.md`
- `agent/attachments.md`
- `agent/ruleset.md`
- `agent/events.md`
- `agent/stats.md`
- `agent/response.md`
- `agent/dispatch.md`：暂缓设计，不属于当前 API 合同
- `agent/runtime-lifecycle.md`
- `agent/dataplane.md`
- `agent/bpf-abi.md`
