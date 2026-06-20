---
memory_type: directory_index
track: agent
project_id: agent-memory
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
session_id: ""
status: active
sensitivity: normal
verified_at: 2026-06-20
keywords:
  - agent
---

# Agent 记忆

这里保存 Agent 自己的复用经验，不保存用户画像。

## 子目录

- `cases/`：已经验证过、有复用价值的正式 Agent case。
- `case-candidates/`：可能有复用价值，但证据还不够的 case。
- `skill-candidates/`：多次复用后，可能值得升级成 skill 的流程。
- `open-loops.md`：跨文件的未闭环事项。

## 原则

普通项目记忆不进入这里。只有“Agent 下次如何更好地处理类似任务”才进入这里。
