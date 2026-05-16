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
| Response builders | done | icmp_echo_reply, udp_echo_reply, arp_reply, tcp_syn_ack, dns_refused, dns_sinkhole |
| TX backends | done | XSK TX (同口, 真实 AF_XDP TX ring), AF_PACKET TX (异口) |
| XSK socket lifecycle | done | AF_XDP socket 创建、UMEM、RX/TX ring、queue bind |
| attachment ↔ XSK 集成 | done | afterCreate/afterPatch/preDelete 回调自动启停 XSK worker，启动失败回滚 |
| Response stats/events | done | sent/failed 派生结果 |
| response.Runtime 接入 | done | store 和 egress 更新 |
| Ruleset writer 错误传播 | done | clearHashMap/clearLpmMap 增加 iter.Err() 检测 |
| Agent deploy/logging | done | 组件化部署路径、默认配置路径、logrus 文件日志和 lumberjack 轮转 |

Spec 参考：`specs/agent/response.md` 第 275-315 行。

## 未实现 / 部分实现

### Kernel Response

- `tcp_reset` 构包走 BPF failure path（固定 XDP_TX 或 drop）。
- 完整 kernel response 构包（checksum、MAC/IP/port 反转）未在 BPF 中实现。

### Dispatch

- `specs/agent/dispatch.md` 暂缓设计，不属于当前 API 合同，完全未实现。

## 已知约束

- `attach_mode` MVP 仅覆盖 `generic`。
- XSK socket 创建需要 root 权限和真实网卡（driver mode XDP）。
- kernel response 完整构包未实现，当前走 BPF failure path。
- dispatch 模块暂缓设计，未实现。
- root/真实网卡集成测试需要手动环境，不默认执行。
- 运行态重启即空状态（无持久化）。
- 构建环境可能没有 kernel headers，`vmlinux.h` 预置提交。
