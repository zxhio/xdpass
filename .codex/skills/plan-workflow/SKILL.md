---
name: plan-workflow
description: 当用户要求写计划、按 harness 执行、自动分解任务、checkpoint、人确认后继续、或把执行上下文写入文件时使用。
---

## 何时使用

用户明确要求以下任一行为时使用：

- 文件化计划、先看计划、拆步骤或 checkpoint。
- 按 harness / AI harness / 自动化交付流程执行。
- 自动分解任务，减少人工投入。
- 人确认关键决策后继续实现。
- 把完成上下文、执行记录或 handoff 写入文件。
- `review-workflow` 已确认 findings，需要进入执行阶段。

## 目标

计划文件要短，并且能让人快速判断下一步是否可以执行。默认自动拆分任务，但只记录恢复和确认真正需要的信息。

本 workflow 产出的是交付单，不只是计划：

- 需求和目标
- 自动拆分后的 checkpoint
- 需要用户确认的关键决策
- 边界、风险和停止条件
- 执行进度
- checkpoint 对应提交
- 完成上下文

不要写长篇分析。优先使用 M 档 Lean Harness，只有高风险或长任务才展开详细上下文。

## 任务分档

先根据影响面自动判断任务大小：

- `S`：0-30 分钟、低风险、小范围修改。除非用户要求落文件，否则可以不写计划文件；若写，只写目标、改动、验证和提交。
- `M`：30-120 分钟或需要确认 1-3 个决策。默认档位，创建计划文件，拆 3-6 个 checkpoint。
- `L`：2 小时以上、跨多个模块、涉及 API/BPF ABI/部署/持久化、可能分多次提交或高失败风险。创建详细计划，按 phase/checkpoint 推进，并在每个 checkpoint 回写上下文。

不确定时选 `M`，不要默认升级到 `L`。

## 自动拆分规则

收到需求后自动拆分，不要等待用户要求“拆一下”。

优先按以下顺序拆 checkpoint：

1. 读 spec 和相关代码，确认现有边界。
2. 明确外部合同：API、CLI、配置、事件、stats、BPF ABI 或部署语义。
3. 实现最小骨架：DTO、接口、owner、route、配置结构或测试入口。
4. 实现核心逻辑。
5. 补测试，优先覆盖变化边界。
6. 同步 spec/docs。
7. 运行验证。
8. 准备提交。

每个 checkpoint 应该是可实现、可验证、可提交、可回滚、可 review 的小单元。避免把“实现功能”作为唯一大步骤。

拆分时遵守：

- `M` 档最多 6 个 checkpoint。
- `L` 档按 phase 分组，每个 phase 3-6 个 checkpoint。
- 每个 checkpoint 写一句完成标准或验证方式。
- 每个 checkpoint 要能对应一个聚焦 commit；如果不能独立提交，继续拆小或把原因写入 `Commits`。
- 如果某步需要人类业务判断，把它放入 `Confirm`，不要埋在 `Plan` 里。
- 如果没有确认项，写 `Confirm: None`，并可继续自动执行，除非用户只要求计划。

## Checkpoint 提交规则

默认每完成一个 checkpoint 就自动提交，然后再进入下一个 checkpoint。

执行顺序：

1. 实现当前 checkpoint 的最小改动。
2. 运行该 checkpoint 对应的最小验证；Go 代码改动至少运行 `gofmt` 和相关包测试。
3. 按 `git-workflow` stage 仅属于当前 checkpoint 的文件或 hunk。
4. 检查 `git diff --cached --check` 和 staged diff。
5. 使用 Conventional Commit 创建提交。
6. 在计划文件 `Progress` 或 `Commits` 记录 `<hash> <message>`，再继续下一 checkpoint。

提交边界：

- 一个 checkpoint 一个 commit 是默认行为。
- 不要把无关文件、未确认用户改动、build artifacts 或本地 `.agent/plans/` 文件放入 commit。
- 如果一个文件同时包含多个 checkpoint 的 hunk，必须拆 hunk stage。
- 如果 checkpoint 验证失败，不提交；在 `Progress` 写失败命令、错误摘要和下一步。
- 只有用户明确说“不要提交”“先不提交”“只改不提交”，或当前 checkpoint 不能形成可工作状态时，才允许推迟提交，并要在 `Progress` 写明原因。
- 如果用户要求最终统一提交，这会覆盖本规则；但计划里必须记录这个提交策略。

## 工作流

1. 先读相关文件和 spec，不凭空假设。
2. 判断任务分档：`S` / `M` / `L`。
3. 自动拆分 checkpoint。
4. 写出推荐方案、边界、风险和停止条件。
5. 把需要用户确认的点列成 checkbox，并给出推荐和影响。
6. 创建或更新计划文件。
7. 有未确认 checkbox 时停止，等待用户确认。
8. 用户确认后，将 `Status` 更新为 `In Progress` 并自动实现。
9. 每完成一个 checkpoint，验证、提交并简短回写 `Progress`。
10. 所有 checkpoint 完成后运行最终验证，回写 `Done`，包括改动摘要、验证命令、commit 列表和 open items。

## 文件位置

计划文件优先放在：

```text
.agent/plans/YYYYMMDD-<slug>.md
```

如果用户指定路径，使用用户指定路径。

## 计划模板

默认使用 Lean Harness 模板：

```md
# <title>

Status: Draft | Awaiting Confirmation | In Progress | Verified | Committed | Blocked

Size: S | M | L

Goal:
- <one sentence>

Plan:
- [ ] <checkpoint 1>
- [ ] <checkpoint 2>
- [ ] <checkpoint 3>

Confirm:
- [ ] <decision>
  - Rec: <recommended choice>
  - Impact: <one sentence>

Boundaries:
- Do: <scope>
- Don't: <scope>
- Stop: <condition>

Risk:
- <main risk>

Progress:
- Pending

Commits:
- Pending

Done:
- Pending
```

`S` 档可以使用最小记录：

```md
# <title>

Status: Done

Size: S

Goal:
- <one sentence>

Changed:
- `<file>`: <short summary>

Verify:
- `<command>` passed

Commit:
- `<hash or none>` <message or reason>
```

`L` 档可以在 Lean Harness 基础上增加：

```md
Phases:
- [ ] Phase 1: <goal>
- [ ] Phase 2: <goal>

Context:
- <only durable decisions, blockers, or handoff-critical facts>

Commits:
- <planned split>
```

## 上下文规则

默认不要列“已读取上下文”流水账。只有以下情况才写 `Context`：

- 用户明确给出的背景、约束或偏好。
- 会影响后续恢复的关键事实。
- 已确认的关键决策。
- 当前未完成工作需要 handoff。
- `L` 档任务的 phase 边界和失败原因。

不要把普通代码阅读过程写成上下文。代码和 spec 读取结果应压缩进 `Plan`、`Boundaries`、`Risk` 或 `Done`。

## 确认规则

遇到这些情况必须列入 `Confirm`，并在实现前等待确认：

- API、字段、语义或 BPF ABI 变化
- 持久化、部署行为或运行态恢复语义变化
- 用户没有决定的业务含义
- 文件边界不清楚
- 方案会引入新依赖、新服务或新长期维护成本
- 会改变提交拆分或需要跨多个 commit 发布

确认项最多 3 个。每个确认项必须包含：

- 推荐选择
- 一句话原因或影响

用户确认后，把 checkbox 改为 `[x]`，将 `Status` 改为 `In Progress`，然后继续执行。

## 进度和完成上下文

执行中必须回写同一个计划文件：

- `Progress` 只记录最近的重要 checkpoint，不写完整流水账。
- checkpoint 完成后勾选对应 `Plan` 项，并记录对应 commit。
- 验证失败时写失败命令、错误摘要和下一步。
- 任务结束时必须更新 `Done`。

`Done` 至少包含：

- 完成了什么
- 关键修改文件或区域
- 验证命令和结果
- commit hash/message 列表；如果某个 checkpoint 未提交，写原因
- open items；如果没有，写 `None`

## 输出规则

- 保持短，不写长篇分析。
- 计划是执行辅助，不是产品合同。
- 不要从代码反推产品合同；有 spec 时以 spec 为准。
- 如果没有需要确认的问题，写 `Confirm: None`。
- 如果用户要求继续实现，先确认没有未完成 checkbox。
- 用户要求“自动分解”时，不要只给方案，必须拆 checkpoint。
- 用户要求“自动完成”时，确认项通过后继续实现、自测并回写 `Done`。
