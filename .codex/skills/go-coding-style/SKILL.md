---
name: go-coding-style
description: Go 代码风格和 code review 规则。
---

# Go 代码风格

本 skill 用于本仓库 Go 风格和 review 规则，不处理更大的抽象设计问题。

规则保持简短。优先写明确代码。

## Imports

* 优先使用包的原始名称。
* `runtime` 可用时，不要写 `goruntime "runtime"` 这类 alias。
* 只有真实命名冲突或已有本地约定时才加 alias。

## Goroutine 启动

- 对已有工作函数，优先写 `go xxx()`。
- 顶层 goroutine 启动要在调用点可见。
- 不要把后台工作藏在立即返回的方法里。
- 阻塞型 owner 可以在内部启动 goroutine，但它必须同时负责 wait、cancel 和 error propagation。
- 所有权、生命周期或抽象设计问题使用 `go-abstraction`。

### 推荐

```go
go svc.Handle(ctx, ev)
```

### 避免

```go
func (s *Service) Handle(ctx context.Context, ev Event) {
    go s.write(ctx, ev)
}
```

## 直接调用

- 能直接调用时优先直接调用。
- 只有真实可替换性或边界隔离需要时才加间接层。
- 不要只为了方便测试而增加 wrapper。
- 如果直接调用不好断言，测试生命周期或结果边界。

## 生命周期所有权

- stop signal 和 blocking wait 要放在清晰边界上。
- 如果 `Close` 只发出停止信号，保持非阻塞。
- 让 `Run` 或其他阻塞 owner 等待 goroutine 并关闭自己拥有的资源。

## Nil 处理

* 除非 nil 是支持状态，否则不要加 nil guard。
* 不支持 nil 的用法可以快速失败。

## Config 和 Options

- `config` 只负责读取和解析原始配置。
- 不要让 runtime component 直接消费 raw config。
- 构造 runtime component 前，先把 raw config 转成经过校验的模块 `Options`。
- 默认值和规范化属于模块 `Options`。
- 运行态检查属于 `Start`、`Run` 或实际 runtime 边界。
- 对 agent，raw config 必须限于启动配置。不要把业务运行态放进 config。

推荐流程：

```text
config.Load()
    ↓
module.NewOptions(cfg.Module)
    ↓
module.NewService(opt)
```

## Tests

- 测稳定行为，不测实现细节。
- 优先测边界，不优先测内部 helper。
- 不要只为了覆盖率加测试。
- 重构时优先更新已有测试，不要大量新增测试。
- 测试保持小而聚焦。

优先测试：

- API 响应格式和错误映射
- config 解析和校验后的 Options
- ruleset 校验、排序、原子 apply 和 rollback
- dataplane / BPF ABI 常量和 packet-path 行为
- 生命周期取消和重要错误传播

避免测试：

- 简单构造函数
- 字段赋值
- 单行 wrapper
- 私有小 helper
- 日志字符串
- 内部调用顺序
- 调用次数 bookkeeping

新增或保留测试前，先问：

> 如果这个测试失败，哪个边界会被破坏？

只有答案是 protocol、ABI、packet-path、rollback、lifecycle 或 error boundary 时才保留。

## 快速检查

- 顶层 goroutine 启动是否在调用点可见？
- 阻塞函数如果内部启动 goroutine，是否也等待它们并拥有生命周期？
- 是否避免了不必要的 wrapper？
- stop signal 和 blocking wait 是否归属于正确方法？
- 是否避免了不支持状态的防御式 nil guard？
- raw config 解析和校验后的 `Options` 是否分离？
- 行为不变时，这个测试是否能经受重构？
