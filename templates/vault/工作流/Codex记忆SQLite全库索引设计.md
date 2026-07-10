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

SQLite 索引用于在任务开始时快速找到最相关的 Markdown。它不替代 Markdown，只保存索引、摘要、字段、未闭环事项和脱敏后的搜索日志元数据。

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
4. 中文查询补充二元/三元片段，避免没有空格时只能整句匹配。
5. `verified_at_source` 区分真实复核与 mtime 回退；`review_after_days` 决定何时进入 audit。

## 和语义检索的关系

SQLite 是主索引，负责路径、字段、FTS、open-loop 和正交过滤。语义检索是可选旁路，适合“只记得意思”的问题。即使启用 Zvec，最终也必须回读 Markdown 原文。
