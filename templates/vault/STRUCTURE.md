---
memory_type: directory_index
track: routing
project_id: codex-memory-structure
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
session_id: ""
status: active
sensitivity: normal
verified_at: 2026-06-20
keywords:
  - structure
---

# 结构说明

## 用户记忆

保存长期稳定的用户偏好、边界和画像。不要记录短期情绪，也不要记录不稳定猜测。

## 项目

保存项目级事实：当前状态、关键路径、最近结论、下次优先看、风险和未闭环事项。

## 工作流

保存可复用的方法：怎么收尾、怎么建索引、怎么检查泄密、怎么迁移。

## 决策

保存有取舍意义的判断：为什么用 SQLite，为什么暂时不加 embedding，为什么普通记忆不设候选池。

## agent

保存 Agent 自己的经验沉淀。这里记录的是“下次怎么做得更好”，不是用户画像。
