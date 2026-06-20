---
memory_type: routing
track: routing
project_id: codex-memory-index
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
session_id: ""
status: active
sensitivity: normal
verified_at: 2026-06-20
keywords:
  - index
  - routing
---

# Codex 记忆索引

## 读取入口

- 全局规则：`AGENTS.md`
- 用户偏好：`用户记忆/偏好与边界.md`
- 用户画像：`用户记忆/长期画像.md`
- 字段规范：`工作流/Codex记忆字段规范.md`
- 收尾规则：`工作流/Codex记忆收尾决策规则.md`
- SQLite 索引：`工作流/Codex记忆SQLite全库索引设计.md`
- Agent 记忆：`agent/README.md`

## 目录职责

- `用户记忆/`：用户长期偏好、边界、画像。
- `项目/`：一个项目一个文件，记录当前状态、结论、下次优先看。
- `工作流/`：可复用流程、脚本说明、字段规范。
- `决策/`：重要权衡和为什么这么选。
- `agent/`：Agent 自我进化、case、skill 候选、未闭环事项。

## 搜索建议

优先用 SQLite 搜索，再读命中的少量 Markdown：

```bash
python3 scripts/codex_memory_index.py --search "关键词" --limit 5
python3 scripts/codex_memory_index.py --search "关键词" --track project
python3 scripts/codex_memory_index.py --search "关键词" --has-open-loop
```
