---
memory_type: workflow
track: workflow
project_id: agent-memory-vault-semantic-retrieval
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
agent_scope: shared
session_id: ""
status: active
sensitivity: normal
temporal_policy: reviewable
verified_at: 2026-06-21
review_after_days: 180
keywords:
  - semantic retrieval
  - embedding
  - zvec
  - vector search
---

# Agent 记忆语义检索设计

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
memoryctl --actor migration index --init --scan --report
memoryctl --actor migration zvec --init --scan --prune --json
memoryctl --actor migration zvec --report --json
memoryctl --actor codex search "只记得大概意思的问题" --semantic-mode required --limit 5
memoryctl --actor migration retrieval-benchmark --limit 5 --runs 3 --json
```

## 成本和隐私

- Zvec 是本地嵌入式向量数据库，不需要单独后台服务。
- Embedding 模型会占用本机磁盘和运行内存；具体取决于模型大小。
- 模型缓存、向量库、SQLite、`.env` 和任何 token 都不要提交到公开仓库。
- “已过时信息/旧方案”等历史段落默认不进入当前事实向量；Markdown 原文仍完整保留。

## 下次优先看

- 如果 SQLite 召回不全，先用 `memoryctl --actor human doctor --json` 确认派生索引健康；需要重建时由明确的维护操作运行 `doctor --repair-derived`。
- 如果换 embedding 模型，通过 `memoryctl --actor migration` 的 Zvec 维护与 retrieval benchmark 重新建立受管证据。
