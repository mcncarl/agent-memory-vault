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
- `codex_memory_search.py`：统一检索入口，合并 SQLite、可选 Zvec 和手动 rg 结果。
- `codex_memory_closeout.py`：任务结束收尾，负责检查、对账、刷新索引、捎带 audit 和可选 scoped commit。
- `codex_memory_audit.py`：定期体检，发现过期记忆、重复标题、open-loop 噪声和已过时状态。
- `codex_memory_audit_autorun.py`：audit 自动触发器，只在超过设定间隔时运行。
- `codex_agent_evolution.py`：Agent case 和 skill 候选状态统计。
- `codex_memory_check.py`：结构、frontmatter、SQLite、泄密风险检查。
- `codex_memory_zvec_index.py`：可选 Zvec 语义索引和搜索。
- `codex_memory_retrieval_benchmark.py`：对比 SQLite 和向量检索召回效果。

## 环境变量

```bash
CODEX_MEMORY_ROOT=/path/to/your/codex-memory-vault
CODEX_MEMORY_GIT_ROOT=/path/to/git-root-containing-the-vault
CODEX_MEMORY_CONFIG_ROOT=$HOME/.config/codex-memory
CODEX_MEMORY_STATE_DB=$HOME/.config/codex-memory/state.sqlite
CODEX_MEMORY_USER_ID=demo-user
CODEX_MEMORY_AGENT_ID=codex
CODEX_MEMORY_APP_ID=codex
CODEX_MEMORY_AUDIT_DB=$HOME/.config/codex-memory/audit_decisions.sqlite
CODEX_MEMORY_CLOSEOUT_LOG=$HOME/.config/codex-memory/logs/closeout.jsonl
CODEX_MEMORY_PYTHON=python3
CODEX_MEMORY_ZVEC_PYTHON=python3
CODEX_MEMORY_VECTOR_DIR=$HOME/.config/codex-memory/zvec/memory_chunks_embeddinggemma_768
CODEX_MEMORY_EMBEDDING_MODEL=google/embeddinggemma-300m
```

## 常用命令

```bash
python3 scripts/codex_memory_index.py --init --scan --report
python3 scripts/codex_memory_search.py "关键词" --limit 5
python3 scripts/codex_memory_closeout.py --prewrite "准备写入的记忆摘要"
python3 scripts/codex_memory_closeout.py --dry-run
python3 scripts/codex_memory_closeout.py --commit
python3 scripts/codex_memory_audit.py
python3 scripts/codex_memory_audit_autorun.py --reason manual --json
python3 scripts/codex_agent_evolution.py --init --scan --report
python3 scripts/codex_memory_check.py
python3 scripts/codex_memory_zvec_index.py --init
python3 scripts/codex_memory_zvec_index.py --scan
python3 scripts/codex_memory_zvec_index.py --search "只记得大概意思的问题" --limit 5
python3 scripts/codex_memory_retrieval_benchmark.py --limit 5
```

## 下次优先看

- 修改目录结构后，先更新字段规范，再跑检查脚本。
