---
memory_type: workflow
track: workflow
project_id: agent-memory-vault-fields
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
session_id: ""
status: active
sensitivity: normal
verified_at: 2026-06-20
review_after_days: 180
keywords:
  - fields
  - orthogonal
---

# Agent 记忆字段规范

## 当前有效摘要

每份正式记忆尽量带 frontmatter。字段不是为了人类好看，而是为了让 Agent 可以稳定过滤和检索。

## 推荐字段

```yaml
---
memory_type: project
track: project
project_id: example-project
app_id: codex
user_id: demo-user
agent_id: codex
session_id: ""
status: active
sensitivity: normal
verified_at: 2026-06-20
keywords:
  - example
---
```

## 字段解释

- `memory_type`：这是什么记忆，例如 `project`、`workflow`、`decision`、`user_profile`、`agent_case`。
- `track`：属于哪条大轨道，例如 `project`、`workflow`、`user`、`agent`、`decision`。
- `project_id`：项目或主题标识。
- `app_id`：记忆来自哪个应用或工作区。
- `user_id`：用户标识，公开模板用假名。
- `agent_id`：Agent 标识。
- `session_id`：可选，会话标识。
- `status`：`active`、`deprecated`、`candidate`、`archived`。
- `sensitivity`：`normal`、`private`、`public-template` 等。
- `verified_at`：最近一次确认日期。
- `review_after_days`：建议多久后重新核验。常见默认值：候选 30 天、项目 90 天、工作流 180 天、长期偏好/决策 365 天。
- 索引会额外记录 `verified_at_source`：来自 frontmatter、摘要中的“最近验证”，或仅是文件 mtime 回退。mtime 不能冒充事实已复核。
- `keywords`：搜索关键词。

## 正交过滤

这些字段互相独立，可以组合使用。例如：

```bash
python3 scripts/agent_memory_index.py --search "部署" --track project --project-id example-app
```

这会比只全文搜索更省上下文，也更少误召回。
