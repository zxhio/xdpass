# Spec vs Implementation Diff

本文档记录 `specs/agent/` 与当前 MVP 实现之间的差异和遗留项。

## 已实现

| 模块 | 状态 | 说明 |
|---|---|---|
| HTTP API 骨架 | done | 所有端点已注册，Problem Details 错误格式 |
| Attachments CRUD | done | create/get/list/patch/delete/dry-run |
| Ruleset CRUD | done | get/replace/delete/dry-run，BPF map 写入 |
| BPF dataplane | done | parse→match→apply pipeline，XDP attach/detach |
| Events SSE | done | ringbuf reader + SSE broadcaster |
| Stats 聚合 | done | BPF PERCPU_ARRAY 读取 + userspace stats 合并 |
| Response egress API | done | GET/PUT/DELETE，tx_config_map 同步 |
| XSK metadata 解码 | done | 8-byte xsk_meta (rule_id, action) |
| Response builders | done | icmp_echo_reply, udp_echo_reply, arp_reply |
| TX backends | done | XSK TX (同口, 真实 AF_XDP TX ring), AF_PACKET TX (异口) |
| XSK socket lifecycle | done | AF_XDP socket 创建、UMEM、RX/TX ring、queue bind |
| Response stats/events | done | sent/failed 派生结果 |

## 未实现 / 部分实现

### Response Builders

| Action | 状态 | 说明 |
|---|---|---|
| `icmp_echo_reply` | done | |
| `udp_echo_reply` | done | |
| `arp_reply` | done | |
| `tcp_syn_ack` | **未实现** | `BuilderForAction` 返回 nil |
| `dns_refused` | **未实现** | `BuilderForAction` 返回 nil |
| `dns_sinkhole` | **未实现** | `BuilderForAction` 返回 nil |

Spec 参考：`specs/agent/response.md` 第 275-315 行。

### Kernel Response

- `tcp_reset` 构包走 BPF failure path（固定 XDP_TX 或 drop）。
- 完整 kernel response 构包（checksum、MAC/IP/port 反转）未在 BPF 中实现。

### XSK Runtime

- `response.Runtime` 已接入 store 和 egress 更新。
- **XSK socket 已实现**：`internal/xsk` 包提供真实 AF_XDP socket 创建、UMEM 注册、RX/TX ring 操作。
- attachment lifecycle（Create/PatchEnabled/Delete）已通过回调自动启停 XSK worker。
- XSK 启动失败会回滚 attachment 创建。

### Dispatch

- `specs/agent/dispatch.md` 模块完全未实现。

### Ruleset Writer

- ~~`clearHashMap` 错误被静默丢弃（`writePortIndexMap`、`writeVlanIndexMap`、`writeLpmMap`）。~~ **已修复**：clear 错误现在正确向上传递，`clearHashMap`/`clearLpmMap` 增加了 `iter.Err()` 检测。

## 已知约束

- `attach_mode` MVP 仅覆盖 `generic`。
- XSK socket 创建需要 root 权限和真实网卡（driver mode XDP）。
- 运行态重启即空状态（无持久化）。
- 构建环境可能没有 kernel headers，`vmlinux.h` 预置提交。
