---
name: review-workflow
description: 当用户要求 review、review gate、先审查再确认修复、把 review 结果写入文件、或根据 review findings 进入 harness 执行时使用。
---

## 目标

把 review 和实现分开：

1. 先 review，不改代码。
2. 输出高价值 findings，等待用户确认。
3. 用户确认后，将确认项转成 `plan-workflow` 的 harness 计划。
4. 进入实现、自测、回写上下文和可选提交。

## 何时使用

用户说以下任一表达时使用：

- `review`
- `review-gate`
- `先 review`
- `review 后确认再修`
- `检查当前 diff`
- `根据 review 结果进入 harness`

如果用户只说“修这个 review 结果”，且 finding 已明确，可以直接转入 `plan-workflow`，不用重新完整 review。

## Review 输入

默认 review 当前工作区 diff：

- `git status --short`
- `git diff`

如果用户指定范围，按用户指定范围：

- 某个 commit
- 某个文件
- 某个 plan
- 某段 review finding

## Review 输出

保持 code review 口径，findings 先行：

```md
Findings:
- [P1] `<file>:<line>` <title>
  - Problem: <what is wrong>
  - Impact: <why it matters>
  - Fix: <recommended fix>

Confirm:
- [ ] Fix finding 1
  - Rec: yes
  - Impact: <one sentence>
```

规则：

- 按严重程度排序：`P0` / `P1` / `P2` / `P3`。
- 只列真实 bug、行为回归、合同违背、缺失测试或高风险维护问题。
- 不把普通风格建议放进 findings，除非它会导致实际风险。
- 每条 finding 必须有文件和行号；如果只能定位到区域，使用最接近的行号。
- 如果没有 findings，明确说没有发现阻断问题，并列出剩余测试风险。

## Review 文件

当用户要求落文件，或 findings 需要后续 harness 执行时，写入：

```text
.agent/reviews/YYYYMMDD-<slug>.md
```

使用 `.agent/templates/review.md`，保持短。

## 确认规则

review 阶段不改代码。

等待用户确认后再执行：

- `确认，修全部`
- `修 1`
- `修 1 和 3`
- `只记录，不修`

确认后：

1. 勾选 review 文件里的确认项。
2. 创建或更新 `.agent/plans/YYYYMMDD-<slug>.md`。
3. 在计划中写入被确认的 finding 摘要。
4. 使用 `plan-workflow` 自动拆 checkpoint 并执行。

## 转 Harness

转入 `plan-workflow` 时，计划应保持 Lean Harness：

- `Goal`：修复确认的 finding。
- `Plan`：定位调用链、补修复、补测试、验证。
- `Confirm`：如果修复本身还有 API/BPF ABI/部署/语义决策，再问用户；否则写 `None`。
- `Done`：写修复摘要、验证命令、commit 信息和 open items。

## 停止条件

遇到以下情况停止并确认：

- finding 与 spec 冲突，需要产品语义判断。
- 修复会改变 API、字段、BPF ABI、部署或持久化语义。
- 修复需要新依赖或新长期维护组件。
- 当前 diff 有用户未说明的无关大改，影响 review 判断。

