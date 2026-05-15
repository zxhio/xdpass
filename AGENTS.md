# AGENTS

本文件只描述本仓库的本地 skill 功能和路由。

## 路由

| Skill | 功能 | 什么时候用 |
|---|---|---|
| `plan-workflow` | 写简短的文件化计划，包含目标、方案、边界情况、风险点和需要确认的地方。 | 用户要求写计划、先规划、拆步骤、checkpoint 或保存计划到文件时。 |
| `rest-api` | 约束 HTTP API 的路由、响应体、状态码、DTO、handler、service interface 和目录组织。 | 设计或实现 HTTP API，修改 router、handler、DTO、错误响应或分页时。 |
| `go-coding-style` | 约束 Go 代码风格、goroutine、生命周期、config/options 和测试边界。 | 编写或 review Go 代码时。 |
| `go-abstraction` | 约束 Go runtime 结构，强调具体 owner、小 helper、最小接口和对称命名。 | 状态 owner 不清楚、结构开始膨胀、命名混乱或需要抽象判断时。 |
| `logging` | 约束 Go 日志写法，使用 logrus 和结构化日志。 | 新增或修改 Go 日志时。 |
| `git-workflow` | 约束安全 Git 操作和 commit message。 | 检查状态、stage、review diff、准备 commit 或写 commit message 时。 |

## 默认规则

- skill 和 `specs/` 冲突时，以 `specs/` 为准。
- 没有命中的 skill 时，按普通仓库任务处理。
