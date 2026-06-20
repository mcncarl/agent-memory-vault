---
memory_type: workflow
track: workflow
project_id: codex-memory-sqlite-index
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
session_id: ""
status: active
sensitivity: normal
verified_at: 2026-06-20
keywords:
  - sqlite
  - search
  - index
---

# Codex 记忆 SQLite 全库索引设计

## 当前有效摘要

SQLite 索引用于在任务开始时快速找到最相关的 Markdown。它不替代 Markdown，只保存索引、摘要、字段、未闭环事项和搜索日志。

## 数据表

- `memory_docs`：每个 Markdown 文件一行。
- `memory_fts`：全文搜索虚拟表。
- `memory_open_loops`：从文件中抽取的待办、风险和下次优先看。
- `memory_search_log`：搜索记录。
- `memory_files`：Agent case 文件状态。
- `agent_case_state`：按 case_key 汇总的复用状态。
- `reminders`：需要提醒用户确认的事项。

## 搜索策略

1. 先用 SQLite FTS 做全文搜索。
2. 再用 LIKE 兜底，改善中文短词召回。
3. 最后用字段过滤缩小范围。

## 为什么暂时不默认 embedding

embedding 适合语义相似搜索，但会引入额外成本、API key、隐私边界和索引维护。这个模板先把本地 Markdown + SQLite 做稳。以后可以在不改 Markdown 的前提下增加向量库。
