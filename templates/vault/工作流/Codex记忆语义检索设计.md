---
memory_type: workflow
track: workflow
project_id: codex-memory-semantic-retrieval
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
session_id: ""
status: active
sensitivity: normal
verified_at: 2026-06-21
keywords:
  - semantic retrieval
  - embedding
  - zvec
  - vector search
---

# Codex 记忆语义检索设计

## 当前有效摘要

语义检索是可选旁路，不是事实源。Markdown 保存原文，SQLite 保存路径、字段、FTS 和 open-loop，Embedding 模型把文本变成向量，Zvec 保存向量并做相似度搜索。

## 分工

- Markdown：唯一长期事实源。
- SQLite：关键词搜索、字段过滤、正交检索、状态索引。
- Embedding model：把 Markdown chunk 和查询文本变成向量。
- Zvec：保存向量，返回意思最接近的 chunk 和 Markdown 路径。
- 统一搜索：并行合并 FTS 与 Zvec，统一执行筛选，并丢弃超过距离阈值的无关近邻。

## 什么时候使用

- 明确关键词、项目名、路径、字段时，优先用 SQLite。
- 只记得大概意思、同义表达、跨文件联想时，加用向量检索。
- 任何向量命中都只作为候选，最终答案必须回读 Markdown 原文。

## 常用命令

```bash
python3 scripts/codex_memory_index.py --init --scan --report
python3 scripts/codex_memory_zvec_index.py --init
python3 scripts/codex_memory_zvec_index.py --scan --prune
python3 scripts/codex_memory_zvec_index.py --report
python3 scripts/codex_memory_zvec_index.py --search "只记得大概意思的问题" --limit 5
python3 scripts/codex_memory_retrieval_benchmark.py --limit 5
```

## 成本和隐私

- Zvec 是本地嵌入式向量数据库，不需要单独后台服务。
- Embedding 模型会占用本机磁盘和运行内存；具体取决于模型大小。
- 模型缓存、向量库、SQLite、`.env` 和任何 token 都不要提交到公开仓库。
- “已过时信息/旧方案”等历史段落默认不进入当前事实向量；Markdown 原文仍完整保留。

## 下次优先看

- 如果 SQLite 召回不全，先确认是否已跑 `codex_memory_zvec_index.py --scan`。
- 如果换 embedding 模型，重新跑全量向量索引和 retrieval benchmark。
