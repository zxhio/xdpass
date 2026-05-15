---
name: go-abstraction
description: 当塑造 xdpass-agent Go 运行态结构时使用。强调具体 owner、最小接口、小 helper 和对称领域命名。
---

## 何时使用

修改或 review xdpass-agent Go 代码，并遇到这些情况时使用：

- 状态、依赖或生命周期的 owner 不清楚
- 构造函数依赖过多，或可选行为没有清晰模式
- 重复的 collection / store / helper 逻辑
- 类似业务动作有很长的 if/else 或 switch 分支
- type、file、method 或 package 命名不清楚
- 成对概念，例如 rx/tx、read/write、start/stop、kernel/user
- handler、worker、service 或 runtime owner 开始膨胀

## 目标

保持 Go 代码明确、小、容易扩展。

使用：

- 具体 runtime owner 承担状态和生命周期
- 小 helper 处理重复机械逻辑
- 小接口表达真实行为变化
- function type 表达单个 callback
- `Options` struct 表达校验后的构造输入
- 对称命名表达成对 runtime 角色

不要为了显得聪明而抽象。

## 1. 具体 owner

当组件拥有工作流、可变状态、共享依赖或生命周期时，使用具体 root type。

示例：

```go
type AttachmentRuntime struct {
    byIfindex map[int]Attachment
    logger    *logrus.Entry
}
```

规则：

- 从具体 root type 开始。
- 长生命周期状态、共享依赖和生命周期放在这个 type 上。
- 公共生命周期转换使用明确命名，例如 `Start`、`Stop`、`Run`、`Serve`、`Create`、`Destroy`。
- 按 runtime 职责组织 package，不按泛化 layer 组织。
- struct 保持扁平，除非嵌套能表达真实边界。
- 必需依赖放在构造函数参数中。
- 构造配置放进经过校验的 `Options` struct。
- 避免巨大 dependency bag 和隐藏生命周期的 helper。
- 宁可保留少量重复，也不要做虚假抽象。

本项目推荐的 owner 名：

- `AttachmentRuntime`
- `RulesetRuntime`
- `ResponseRuntime`
- `DispatchRuntime`
- `EventStream`
- `StatsSnapshotter`

除非边界真的通用，否则避免这些泛词：

- `Manager`
- `Processor`
- `Helper`
- `Util`

## 2. Helpers 和 generics

先使用普通 helper。只有多个具体类型共享同一种结构或算法时，才使用 generics。

适合场景：

- collection helper
- map/slice 转换
- 小型内存 store 原语
- 重复 parse/validate wrapper，且流程真的完全相同

示例：

```go
func Values[K comparable, V any](m map[K]V) []V {
    out := make([]V, 0, len(m))
    for _, v := range m {
        out = append(out, v)
    }
    return out
}
```

规则：

- generics 只用于消除真实结构性重复。
- 业务概念优先使用具体类型。
- constraint 保持小而明确。
- 不要把业务流程藏进 generic helper。
- 如果调用点更难读，保留具体代码。
- 除非边界非常清楚，否则避免 `Runtime[T]`、`Store[T]`、`Service[T]` 或 `Handler[T]`。

## 3. Strategy interface

当同一个业务动作存在多个实现时，使用 interface。

适合场景：

- rule action 执行
- response action 处理
- event sink 输出
- dispatch backend
- dataplane attach mode
- worker backend

示例：

```go
type ResponseActionHandler interface {
    Execute(ctx context.Context, pkt Packet) error
}

type ResponseDispatcher struct {
    handlers map[Action]ResponseActionHandler
}

func (d *ResponseDispatcher) Dispatch(ctx context.Context, action Action, pkt Packet) error {
    h, ok := d.handlers[action]
    if !ok {
        return fmt.Errorf("unsupported action: %s", action)
    }
    return h.Execute(ctx, pkt)
}
```

规则：

- 如果依赖只是一个动作，优先用 function type，而不是单方法 interface。
- interface 用于稳定扩展点。
- 多个分支做同类动作但实现不同时，优先考虑 strategy dispatch。
- interface 保持小，通常只有一个主要方法。
- 可行时，把 interface 定义在调用方附近。
- 用 registry 或 map dispatch 替代很长的 if/else 或 switch。
- 简单条件保留普通 if。
- 只有一个实现且边界不会增长时，不要引入 interface。

单动作示例：

```go
type FindFn func(key string) (Item, bool)
```

## 4. 对称命名

相关角色使用对称命名。

常见命名轴：

- 方向：Rx / Tx
- 侧：Kernel / User
- 生命周期：Start / Stop、Load / Unload、Attach / Detach
- 数据流：Read / Write、Encode / Decode、Parse / Emit
- 动作：Redirect / Response / Event
- 角色：Reader / Writer / Handler / Dispatcher / Worker

推荐示例：

```go
type XSKRxWorker struct {}
type XSKTxWorker struct {}

type KernelResponseHandler struct {}
type UserResponseHandler struct {}

type ResponseBuilder struct {}
type ResponseSender struct {}
```

文件：

```text
xsk_rx_worker.go
xsk_tx_worker.go
kernel_response_handler.go
user_response_handler.go
response_builder.go
response_sender.go
```

规则：

- 添加或重命名前先选定命名轴。
- 相关类型保持相同词序。
- 两个类型如果成对，名称应该只差一个轴词。
- 同一组内不要混用同义词，例如 Sender / Writer / Emitter。
- 优先使用领域词，不使用 Manager、Processor、Helper、Util 这类模糊词。
- 文件名尽量跟随同一命名组。

## 决策指南

按这个规则判断：

- owner 或生命周期不清楚：从具体 root type 开始。
- 相同结构、不同类型：先用 helper；只有可读性仍好时再考虑 generics。
- 同一个动作、多个实现：考虑 strategy interface。
- 同一概念组、有不同方向或侧：使用对称命名。
- 简单条件或校验：保留普通 if。
- 业务特定流程：优先写明确具体代码。

## Review 输出

当用户要求 review 或计划改动时，输出：

### Summary

一句简短结论。

### Findings

- <重复、分支或命名问题>

### Suggestions

1. <建议的抽象或命名调整>
   Files: `<file>`
   Note: <原因>

### Avoid

- <不应该抽象的内容>

## 规则

- 优先小步增量修改。
- 除非用户要求，否则保持行为不变。
- 没有清晰调用点收益时，不引入抽象。
- 除非两者都必要，否则不要同时引入 generics 和 interface。
- 现有项目风格一致时，保留现有风格。
- 只有当重命名能改善对称性或消除混乱时才重命名。
- 避免不必要的大范围重构。
