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
- Session claims：在 SQLite 中记录“哪个会话负责哪些 Markdown”，避免两个 Agent 串提交。
- File observations：成功 closeout 后记录文件内容 hash；它证明某一版内容已经完成检查、索引与收尾，不能用全库索引时顺带扫到来冒充。
- Git：保存修改记录，支持 scoped commit 和回滚。
- 统一搜索脚本：合并关键词搜索、字段过滤、可选语义召回和手动 rg。
- closeout 脚本：在任务结束时自动检查、对账、刷新索引、写日志，并可选择提交本轮记忆文件。
- audit 脚本：定期发现过期、重复、open-loop 噪声和已过时状态，裁决结果存在本地 SQLite 中。

可选语义检索层是：

- Embedding model：把 Markdown chunk 和查询语句转成向量。
- Zvec：保存向量，并做相似度检索。

向量层不替代 SQLite。SQLite 继续负责路径、字段、FTS、open-loop 和正交过滤；Zvec 只负责“意思相近”的候选召回。

统一搜索会并行查询 SQLite/FTS 与 Zvec，合并去重后再统一执行 `track`、`memory_type`、`project_id`、`status` 等筛选。语义距离超过阈值的结果直接丢弃，因此向量库不会为了凑足数量而返回明显无关的记忆。

## 3. Shared core and host adapters

Claude Code 与 Codex 共用 Markdown、Git、SQLite、Zvec、closeout 和 audit。每个宿主只保留自己的规则入口与 Hook：Claude 使用 `CLAUDE.md` 导入共享 `AGENTS.md`，Codex 直接读取 `AGENTS.md`。

普通事实默认 `agent_scope: shared`，这个字段决定可见范围；`agent_id` 只记录来源。`created_by` 和 `last_updated_by` 记录来源；closeout 日志另外记录 actor、trigger、session hash 和 run id。不要为每个 Agent 建独立 Git 基线或独立向量库。

并发控制分三层：全局文件锁保证 SQLite/Zvec/Git 操作不会同时执行；`memory_session_claims` 保证每次 closeout 只处理当前会话自己的文件；`memory_file_observations` 以内容 hash 证明别的会话已经处理完某一版文件，使共享 Git 基线可以安全前进。三者不能互相替代。

## 4. User memory and Agent memory

用户记忆和 Agent 记忆分开：

- `用户记忆/`：用户偏好、边界、长期画像。
- `agent/`：Agent 的可复用案例、失败教训、skill 候选、未闭环事项。

这样不会把“用户是谁”和“Agent 怎么做事”混在一起。

## 5. Orthogonal retrieval

正交检索就是用多个互不冲突的字段过滤记忆。

例如同一条记忆可以同时有：

```yaml
memory_type: project
track: project
user_id: demo-user
agent_id: shared
agent_scope: shared
app_id: agent-memory
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

## 6. Semantic retrieval sidecar

语义检索适合这些问题：

- 用户只记得大概意思，不记得文件名或关键词。
- 同一件事有多种说法，例如 “closeout”“收尾”“对话结束归档”。
- 记忆库变大后，需要先用本地索引缩小候选文件。

查询建议：

1. 默认使用 `agent_memory_search.py`。
2. 关键词、项目名、路径、字段明确时，SQLite/FTS 会给出稳定结果。
3. 表达模糊时，可以启用 Zvec 做语义候选召回。
4. Zvec 命中的 chunk 只作为候选，最终仍然回读 Markdown 原文。

## 7. Closeout and audit loop

closeout 是每次任务结束后的自动整理员。它不替 Agent 判断“什么值得记”，但会把收尾动作压成稳定流程：

- 读取当前会话认领的记忆文件，并排除其他会话文件。
- 检查是否有敏感内容、结构问题或膨胀文件。
- 对新文件做写入后查重，发现重复时输出 `MERGE_REQUIRED`。
- 刷新 SQLite 和可选 Zvec。
- Zvec 全量扫描会补齐漏项，并清理已删除、重命名或不再合格的旧向量；“已过时信息/旧方案”等历史段落默认不进入当前事实向量。
- 必要时刷新 Agent evolution。
- 检查 audit 是否超过间隔，超过则捎带运行。
- 记录 closeout 日志，并在允许时只提交本轮记忆文件。
- 日志保存 `git_observed_through` 基线；即使其他备份工具先提交，下一次 closeout 也会从 Git 历史找回尚未处理的记忆变更。

audit 是定期体检。它只产出 findings 和裁决记录，不直接改写 Markdown 事实层。除过期、重复和 open-loop 外，它还读取机器可读不变量，检查当前摘要里的旧路径、退役脚本、错误 scope 和已经漂移的固定计数。

`agent_memory_doctor.py` 是统一体检入口，核对 Markdown、SQLite、FTS、INDEX、Zvec 路径与 hash、Git 基线与远端备份时效、会话认领残留、验证来源、日志隐私、Runtime manifest、模型文件 hash、语义 Python 基础解释器、依赖锁、完全离线语义查询和自动化新鲜度。默认只读；`--repair-derived` 也只重建可再生索引。

## 8. Self evolution

普通记忆不设候选池，直接进入正式目录。

但 Agent 自我进化保留两类候选：

- `agent/case-candidates/`：某次任务中可能可复用的方法。
- `agent/skill-candidates/`：多次复用后，可能值得沉淀为正式 skill 的流程。

脚本只做统计和提醒，不自动把候选升级为正式 skill。正式升级前应该由用户确认。
