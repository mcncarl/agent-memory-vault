# Codex Memory Instructions

这是本地长期记忆库。遇到既有项目、仓库、路径、人物、历史结论、继续上次任务、报告、调研、较长排查时，默认先使用这个记忆库；简单翻译、改一句话、查时间等一次性小任务可以跳过。

读取顺序：

1. 先读本文件。
2. 再读 `INDEX.md`。
3. 根据任务关键词，只读最相关的 1-3 个文件。

不要默认读取整个记忆库。

## 写入规则

重要任务结束前执行 memory closeout：

1. 判断是否有稳定事实需要写入。
2. 普通记忆直接写入正式目录：`用户记忆/`、`项目/`、`工作流/`、`决策/`。
3. Agent 复用经验写入 `agent/cases/` 或 `agent/case-candidates/`。
4. 多次复用、可抽象成流程的经验，写入 `agent/skill-candidates/`，正式升级 skill 前需要用户确认。
5. 写完后运行 SQLite 索引和检查脚本。

## 字段要求

新建或重写正式记忆时，尽量包含下面字段：

```yaml
---
memory_type: project
track: project
project_id: example-app
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
session_id: ""
status: active
sensitivity: normal
verified_at: 2026-06-20
keywords:
  - example
---
```

## 安全边界

- 不要把 API key、token、cookie、密码写入 Markdown。
- 不要把私密原始聊天全文写入公开仓库。
- 不要把 SQLite 数据库提交到 Git。
- 对外分享前必须脱敏。
