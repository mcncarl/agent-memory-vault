---
memory_type: workflow
track: workflow
project_id: codex-memory-scripts
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
session_id: ""
status: active
sensitivity: normal
verified_at: 2026-06-20
keywords:
  - scripts
  - sqlite
---

# Codex 记忆本地脚本

## 当前有效摘要

本模板提供三类本地脚本：

- `codex_memory_index.py`：全库 Markdown 索引和搜索。
- `codex_agent_evolution.py`：Agent case 和 skill 候选状态统计。
- `codex_memory_check.py`：结构、frontmatter、SQLite、泄密风险检查。

## 环境变量

```bash
CODEX_MEMORY_ROOT=/path/to/your/Obsidian/Codex记忆
CODEX_MEMORY_STATE_DB=$HOME/.config/codex-memory/state.sqlite
CODEX_MEMORY_USER_ID=demo-user
CODEX_MEMORY_AGENT_ID=codex
CODEX_MEMORY_APP_ID=codex
```

## 常用命令

```bash
python3 scripts/codex_memory_index.py --init --scan --report
python3 scripts/codex_memory_index.py --search "关键词" --limit 5
python3 scripts/codex_agent_evolution.py --init --scan --report
python3 scripts/codex_memory_check.py
```

## 下次优先看

- 修改目录结构后，先更新字段规范，再跑检查脚本。
