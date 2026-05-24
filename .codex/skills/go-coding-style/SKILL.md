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

- 新增测试不是 checkpoint 的默认产物。
- 如果用户没有明确要求加测试，不要新增测试。
- 如果认为必须新增测试，先停止实现并手动确认；确认前不要写测试。
- 不要只为了覆盖率、流程或提交完整性加测试。
- 不要为了测试给生产代码增加 wrapper、seam、mock hook 或注入点。

硬性测试只默认保留以下范围：

- BPF / dataplane：BPF ABI、map layout、struct size、action code、event code、stats index、packet parse/match/action/verdict/redirect。
- ruleset：validate、action compatibility、compile、bitmap/index、map write/clear、apply 到 BPF map 的正确性。
- response：packet builder、userspace response correctness，以及相关 benchmark 的 correctness 前置。
- 基础库不变量：ring/buffer/cursor/wraparound、binary encode/decode、ABI decode 这类 review 容易漏 off-by-one、endian 或 index 语义的代码。

默认不新增或保留：

- API handler 映射、HTTP CRUD 流程和路由注册测试
- store / attachment / dispatch / event stream 这类流程状态拼装测试
- config/options 默认值和简单字段校验测试
- stats snapshot、DTO 转换和普通响应字段测试
- 简单构造函数
- 字段赋值
- 单行 wrapper
- 私有小 helper
- 日志字符串
- 内部调用顺序
- 调用次数 bookkeeping

保留或新增测试前，先问：

> 这是否属于 BPF/dataplane、ruleset、response correctness 或基础库不变量？

如果答案不是明确的“是”，默认不加测试；如果仍认为必须加，先向用户确认。

## 快速检查

- 顶层 goroutine 启动是否在调用点可见？
- 阻塞函数如果内部启动 goroutine，是否也等待它们并拥有生命周期？
- 是否避免了不必要的 wrapper？
- stop signal 和 blocking wait 是否归属于正确方法？
- 是否避免了不支持状态的防御式 nil guard？
- raw config 解析和校验后的 `Options` 是否分离？
- 行为不变时，这个测试是否能经受重构？
