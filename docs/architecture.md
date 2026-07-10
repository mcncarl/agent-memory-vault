# Architecture

## 1. Markdown source of truth

所有长期记忆都先写成 Markdown。这样做的好处是：

- 人可以直接打开、编辑、diff。
- Git 可以追踪变化。
- Obsidian 可以作为可选的可视化入口；不安装 Obsidian 时，它也只是一个普通 Markdown 文件夹。
- 即使 SQLite 坏了，原始记忆也还在。

SQLite 只负责索引，不负责成为唯一事实源。

## 2. Local stack

这套模板的默认本地链路是：

- Markdown：保存正式记忆。
- SQLite：保存文件索引、搜索字段、未闭环事项和 Agent case 状态。
- Git：保存修改记录，支持 scoped commit 和回滚。
- 统一搜索脚本：合并关键词搜索、字段过滤、可选语义召回和手动 rg。
- closeout 脚本：在任务结束时自动检查、对账、刷新索引、写日志，并可选择提交本轮记忆文件。
- audit 脚本：定期发现过期、重复、open-loop 噪声和已过时状态，裁决结果存在本地 SQLite 中。

可选语义检索层是：

- Embedding model：把 Markdown chunk 和查询语句转成向量。
- Zvec：保存向量，并做相似度检索。

向量层不替代 SQLite。SQLite 继续负责路径、字段、FTS、open-loop 和正交过滤；Zvec 只负责“意思相近”的候选召回。

统一搜索会并行查询 SQLite/FTS 与 Zvec，合并去重后再统一执行 `track`、`memory_type`、`project_id`、`status` 等筛选。语义距离超过阈值的结果直接丢弃，因此向量库不会为了凑足数量而返回明显无关的记忆。

## 3. User memory and Agent memory

用户记忆和 Agent 记忆分开：

- `用户记忆/`：用户偏好、边界、长期画像。
- `agent/`：Agent 的可复用案例、失败教训、skill 候选、未闭环事项。

这样不会把“用户是谁”和“Agent 怎么做事”混在一起。

## 4. Orthogonal retrieval

正交检索就是用多个互不冲突的字段过滤记忆。

例如同一条记忆可以同时有：

```yaml
memory_type: project
track: project
user_id: demo-user
agent_id: codex
app_id: codex
project_id: example-app
session_id: ""
status: active
```

以后搜索时可以说：

- 只看某个项目：`--project-id example-app`
- 只看用户记忆：`--track user`
- 只看工作流：`--memory-type workflow`
- 只看有未闭环事项的文件：`--has-open-loop`

它的价值不是让目录更复杂，而是减少 Agent 每次读取无关内容。

## 5. Semantic retrieval sidecar

语义检索适合这些问题：

- 用户只记得大概意思，不记得文件名或关键词。
- 同一件事有多种说法，例如 “closeout”“收尾”“对话结束归档”。
- 记忆库变大后，需要先用本地索引缩小候选文件。

查询建议：

1. 默认使用 `codex_memory_search.py`。
2. 关键词、项目名、路径、字段明确时，SQLite/FTS 会给出稳定结果。
3. 表达模糊时，可以启用 Zvec 做语义候选召回。
4. Zvec 命中的 chunk 只作为候选，最终仍然回读 Markdown 原文。

## 6. Closeout and audit loop

closeout 是每次任务结束后的自动整理员。它不替 Agent 判断“什么值得记”，但会把收尾动作压成稳定流程：

- 自动发现记忆库变更文件。
- 检查是否有敏感内容、结构问题或膨胀文件。
- 对新文件做写入后查重，发现重复时输出 `MERGE_REQUIRED`。
- 刷新 SQLite 和可选 Zvec。
- Zvec 全量扫描会补齐漏项，并清理已删除、重命名或不再合格的旧向量；“已过时信息/旧方案”等历史段落默认不进入当前事实向量。
- 必要时刷新 Agent evolution。
- 检查 audit 是否超过间隔，超过则捎带运行。
- 记录 closeout 日志，并在允许时只提交本轮记忆文件。
- 日志保存 `git_observed_through` 基线；即使其他备份工具先提交，下一次 closeout 也会从 Git 历史找回尚未处理的记忆变更。

audit 是定期体检。它只产出 findings 和裁决记录，不直接改写 Markdown 事实层。这样可以自动发现问题，又保留人工审计边界。

`codex_memory_doctor.py` 是统一体检入口，核对 Markdown、SQLite、FTS、INDEX、Zvec、Git 基线、验证日期来源、日志隐私与自动化新鲜度。默认只读；`--repair-derived` 也只重建可再生索引。

## 7. Self evolution

普通记忆不设候选池，直接进入正式目录。

但 Agent 自我进化保留两类候选：

- `agent/case-candidates/`：某次任务中可能可复用的方法。
- `agent/skill-candidates/`：多次复用后，可能值得沉淀为正式 skill 的流程。

脚本只做统计和提醒，不自动把候选升级为正式 skill。正式升级前应该由用户确认。
