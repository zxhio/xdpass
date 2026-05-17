# agent runtime lifecycle

## 定位

`runtime-lifecycle` 定义 `agent` 进程内运行态资源的生命周期和失败回滚约定。

- 运行态只保存在当前进程内
- 进程重启后由调用方重新下发期望状态
- 不做本地持久化恢复

---

## 启动

启动时：

- 读取 `config.md` 定义的启动配置
- 启动 HTTP server
- `attachments` 为空
- `ruleset` 为空
- `response egress` 为默认同口发送
- `dispatch` 为未配置、未启用
- 不主动 attach XDP
- 不主动加载旧 BPF maps
- 不主动拉取外部配置

---

## 运行态资源

`agent` 在内存中维护：

- attachments
- 当前完整 ruleset
- response egress 配置
- dispatch 配置和异步 worker
- 每个 attachment 的 BPF program / map set
- 每个 attachment 的 XSK runtime
- 当前进程内 stats 和 event reader

---

## 更新原则

- 单个资源更新失败时，保留该资源旧状态。
- 涉及运行态操作的更新必须先完成校验，再执行运行态变更。
- 已完成的运行态操作在后续步骤失败时必须回滚。
- API 成功返回后，内存状态必须和实际运行态一致。

---

## attachment 生命周期

create：

- 校验并规范化 attachment
- 加载独立 BPF program / map set
- attach XDP
- 如果 `xsk.enabled=true`，启动 XSK runtime
- 全部成功后写入内存状态

patch enabled：

- `false -> true`：attach XDP，并按配置启动 XSK
- `true -> false`：停止 XSK，卸载 XDP，保留内存配置

delete：

- 停止 XSK
- 卸载 XDP
- 释放 BPF program / map set
- 删除内存状态

---

## ruleset 生命周期

PUT ruleset：

- 校验 ruleset
- 编译运行态结构
- 写入所有 enabled attachment 的独立 map set
- 全部成功后切换当前 ruleset
- 任一步失败时保留旧 ruleset

DELETE ruleset：

- 清空当前 ruleset
- 清空所有 enabled attachment 的规则相关 maps
- 不影响 attachments
- 不影响 response egress

---

## response egress 生命周期

PUT response egress：

- 校验 ifindex / ifname / vlan_mode
- 更新内存配置
- 将 tx config 写入所有 enabled attachment 的独立 map set

DELETE response egress：

- 恢复默认同口发送
- 将默认 tx config 写入所有 enabled attachment

## dispatch 生命周期

PUT dispatch：

- 校验 ifindex / ifname / queue_size
- 创建或替换 AF_PACKET sender
- 创建 bounded dispatch queue
- 启动或更新 dispatch worker
- 成功后切换内存配置
- 任一步失败时保留旧 dispatch 配置和 worker

DELETE dispatch：

- 停止 dispatch worker
- 清空待分发 queue
- 释放 AF_PACKET sender
- 恢复未配置、未启用状态

userspace response worker：

- response 成功后尝试 enqueue dispatch。
- enqueue 不等待 AF_PACKET 发送完成。
- queue 满、dispatch disabled、未配置或 sender 不可用时直接丢弃 dispatch packet 并累加 dispatch dropped stats。
- dispatch 失败不改变 response result/event。

---

## 停止

进程停止时：

- 停止 event readers
- 停止 dispatch worker
- 停止 XSK runtimes
- 卸载 XDP programs
- 释放 BPF resources

停止过程尽力清理，不写入持久化状态。

---

## 资源边界

- 本文件定义运行态生命周期，不定义 HTTP 请求体。
- API 语义见各资源 spec。
- BPF ABI 见 `bpf-abi.md`。
