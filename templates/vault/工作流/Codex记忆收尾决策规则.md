---
memory_type: workflow
track: workflow
project_id: codex-memory-closeout
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
session_id: ""
status: active
sensitivity: normal
verified_at: 2026-06-20
keywords:
  - closeout
  - memory
---

# Codex 记忆收尾决策规则

## 当前有效摘要

普通记忆不设候选池。每次重要任务结束时，由 Agent 判断是否有稳定事实需要直接写入正式目录。

## 写入哪里

- 用户稳定偏好或边界：`用户记忆/`
- 某个项目的当前状态：`项目/`
- 可复用的方法流程：`工作流/`
- 明确取舍和原因：`决策/`
- Agent 解决某类问题的经验：`agent/cases/`
- 可能值得升级成 skill 的流程：`agent/skill-candidates/`

## 不写入什么

- API key、token、cookie、密码。
- 一次性闲聊。
- 未验证猜测。
- 已经写过且没有新增信息的重复内容。

## Agent case 规则

满足下面条件时，可以写入 `agent/cases/`：

- 任务已经完成或失败原因清楚。
- 过程对未来有复用价值。
- 能说清楚触发条件、操作步骤、风险和验证方式。

## Skill 候选规则

满足下面条件时，可以写入 `agent/skill-candidates/`：

- 同类 case 至少复用 3 次。
- 至少有 2 条有效证据。
- 步骤稳定，不依赖某个临时项目。
- 风险可控。

正式升级为 skill 前，需要询问用户。

## 收尾动作

写完记忆后运行：

```bash
python3 scripts/codex_agent_evolution.py --init --scan --report
python3 scripts/codex_memory_index.py --init --scan --report
python3 scripts/codex_memory_check.py
```
