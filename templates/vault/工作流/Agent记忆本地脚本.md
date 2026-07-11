---
memory_type: workflow
track: workflow
project_id: agent-memory-vault-scripts
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

# Agent 记忆本地脚本

## 当前有效摘要

本模板提供三类本地脚本：

- `agent_memory_index.py`：全库 Markdown 索引和搜索。
- `agent_memory_search.py`：统一检索入口，合并 SQLite、可选 Zvec 和手动 rg 结果。
- `agent_memory_closeout.py`：任务结束收尾，负责检查、对账、刷新索引、捎带 audit 和可选 scoped commit。
- `agent_memory_audit.py`：定期体检，发现过期记忆、重复标题、open-loop 噪声和已过时状态。
- `agent_memory_audit_autorun.py`：audit 自动触发器，只在超过设定间隔时运行。
- `agent_memory_doctor.py`：统一体检 Markdown、SQLite、FTS、INDEX、Zvec、验证来源和自动化状态。
- `agent_memory_stop_hook.py`：Stop 事件节流提醒；到期 audit 仍由 7 天闸门决定是否执行。
- `agent_memory_evolution.py`：Agent case 和 skill 候选状态统计。
- `agent_memory_check.py`：结构、frontmatter、SQLite、泄密风险检查。
- `agent_memory_zvec_index.py`：可选 Zvec 语义索引和搜索。
- `agent_memory_retrieval_benchmark.py`：对比 SQLite 和向量检索召回效果。

## 环境变量

```bash
AGENT_MEMORY_ROOT=/path/to/your/agent-memory-vault
AGENT_MEMORY_GIT_ROOT=/path/to/git-root-containing-the-vault
AGENT_MEMORY_CONFIG_ROOT=$HOME/.config/agent-memory
AGENT_MEMORY_STATE_DB=$HOME/.config/agent-memory/state.sqlite
AGENT_MEMORY_USER_ID=demo-user
AGENT_MEMORY_AGENT_ID=codex
AGENT_MEMORY_APP_ID=codex
AGENT_MEMORY_AUDIT_DB=$HOME/.config/agent-memory/audit_decisions.sqlite
AGENT_MEMORY_CLOSEOUT_LOG=$HOME/.config/agent-memory/logs/closeout.jsonl
AGENT_MEMORY_PYTHON=python3
AGENT_MEMORY_ZVEC_PYTHON=python3
AGENT_MEMORY_VECTOR_DIR=$HOME/.config/agent-memory/zvec/memory_chunks_embeddinggemma_768
AGENT_MEMORY_EMBEDDING_MODEL=google/embeddinggemma-300m
```

## 常用命令

```bash
python3 scripts/agent_memory_index.py --init --scan --report
python3 scripts/agent_memory_search.py "关键词" --limit 5
python3 scripts/agent_memory_closeout.py --prewrite "准备写入的记忆摘要"
python3 scripts/agent_memory_closeout.py --dry-run
python3 scripts/agent_memory_closeout.py --commit
python3 scripts/agent_memory_audit.py
python3 scripts/agent_memory_audit_autorun.py --reason manual --json
python3 scripts/agent_memory_doctor.py
python3 scripts/agent_memory_evolution.py --init --scan --report
python3 scripts/agent_memory_check.py
python3 scripts/agent_memory_zvec_index.py --init
python3 scripts/agent_memory_zvec_index.py --scan --prune
python3 scripts/agent_memory_zvec_index.py --report
python3 scripts/agent_memory_zvec_index.py --search "只记得大概意思的问题" --limit 5
python3 scripts/agent_memory_retrieval_benchmark.py --limit 5
```

## 下次优先看

- 修改目录结构后，先更新字段规范，再跑检查脚本。
