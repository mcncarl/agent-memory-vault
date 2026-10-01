---
memory_type: workflow
track: workflow
risk_class: ordinary
project_id: agent-memory-vault-fields
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
agent_scope: shared
session_id: ""
status: active
sensitivity: normal
verified_at: ""
temporal_policy: structural
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
memory_id: "<write read-target 返回的 generated_memory_id>"
memory_type: project
track: project
project_id: example-project
app_id: codex
user_id: demo-user
agent_id: codex
session_id: ""
status: active
sensitivity: normal
risk_class: ordinary
verified_at: ""
temporal_policy: reviewable
review_after_days: 90
keywords:
  - example
---
```

## 字段解释

- `memory_type`：这是什么记忆，例如 `project`、`workflow`、`decision`、`user_profile`、`agent_case`。
- `track`：属于哪条大轨道，例如 `project`、`workflow`、`user`、`agent`、`decision`。
- `project_id`：项目或主题标识。
- `memory_id`：文档的稳定身份，固定为 64 位小写十六进制。ADD 时由 Write Gateway 生成；rename、状态转换和内容更新必须原值保留，禁止按新路径重算。`project_id` 绝不能兼作文档身份。
- `app_id`：记忆来自哪个应用或工作区。
- `user_id`：用户标识，公开模板用假名。
- `agent_id`：Agent 标识。
- `session_id`：可选，会话标识。
- `status`：正式内容使用 `active`、`pending_verification`、`outdated`、`archived`；候选轨道可使用 `candidate`。
- `sensitivity`：`normal`、`private`、`public-template` 等。
- `risk_class`：只允许 `ordinary` 或 `action_sensitive`，不接受其他状态。active 的项目、工作流和决策文档必须显式填写；决策、原子事实、`expiring`、带 `valid_until` 或 `事实-*.md` 等行动敏感内容不能声明为 `ordinary`。
- `verified_at`：最近一次真实核验日期。普通正文日期、摘要日期和文件 mtime 都不能自动升级为已核验。
- `temporal_policy`：必须显式选择 `structural`、`snapshot`、`stable`、`reviewable` 或 `expiring`。`active` 内容不能只依赖系统猜测的复核周期。
- `review_after_days`：建议多久后重新核验。常见默认值：候选 30 天、项目 90 天、工作流 180 天、长期偏好/决策 365 天。
- `valid_until`：明确知道某条内容在哪天后不能直接当当前事实时才填写；过期后仍可检索，但必须实时核验。
- `fact_key`：可变化原子事实的稳定身份，例如 `project.owner`。只有“一条事实一个文件”时使用。
- `valid_from`：这个事实版本从哪一天开始生效，必须是 `YYYY-MM-DD`。
- `supersedes`：新版本明确替代的旧事实文件相对路径列表。系统不从正文措辞或相似度推断作废关系。
- 索引会额外记录 `verified_at_source`：来自 frontmatter、摘要中的“最近验证”，或仅是文件 mtime 回退。mtime 不能冒充事实已复核。
- `keywords`：搜索关键词。

`pending_verification` 默认仍可发现，但只能作为待核验参考，`can_authorize_action=false`。`outdated` 与 `archived` 默认不进入普通结果，只有显式 `--include-inactive` 才作为历史参考返回。Audit 只生成复核任务，不能自行修改事实或状态。状态变化必须通过 Write Gateway v2 的 `operation=status_transition`；允许 `active → pending_verification/outdated/archived`，恢复 active 必须提供新的真实核验日期和证据，Ailu 不允许执行状态转换。

风险门禁使用稳定 reason code：`METADATA_RISK_CLASS_NOT_EXPLICIT`、
`METADATA_RISK_CLASS_INVALID`、`METADATA_RISK_CLASS_DOWNGRADE`。影子期记录
`would_block_count` 和 reason fingerprint，不改变原有结果；正式切换后才执行新的元数据
阻断。明确的路径伪装或风险降级仍会立即成为 reference-only。用当前 Runtime 查看处理路线：

```bash
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl \
  --actor codex explain <reason_code> --json
```

`project_id` 是项目事实边界，不以 `track` 或目录名为准。传入 `--current-project` 后，任何带有非 `global/shared` 项目标识的记忆都只在对应项目返回；显式加 `--cross-project` 才返回其他项目的类比线索，而且这些线索不能授权动作。没有 `project_id` 的内容按未限定共享参考处理；只有明确写成 `global` 或 `shared` 才是全局共享。

搜索结果中的 `time_status: expired` 不等于删除。它表示这条内容仍可解释历史，但必须实时核验，不能直接当当前事实使用。采用同一内容版本后，Agent 必须声明 `adopted`、`reference_only` 或 `rejected`；只有 adopted 且内容过期、逾期或冲突，同时缺少同版本 `live_verified=yes` 时才允许 Stop 阻断。

## 当前事实时间线 v1

当错误旧值会直接影响后续行动时，使用 `项目/_模板-事实记录.md`，并遵守“一条事实一个文件”。同一个 `(app_id, project_id, user_id, agent_scope, fact_key)` 只能有一个当前头节点。新版本必须显式 `supersedes` 当前旧版本，且 `valid_from` 必须向前；未知目标、自引用、跨 scope、多个 successor、多个无关系当前版本都会 fail closed。

SQLite 的 `memory_supersessions` 与 `memory_fact_states` 只是可重建投影。Markdown 仍是真源；canonical retrieve 会核对当前 Markdown 哈希与投影。默认检索排除 `fact_status: superseded`，`--include-superseded` 只用于历史调查；`--as-of` 可恢复指定日期当时的当前版本。后继版本后来到期，也不会让被替代的旧版本自动复活。

## 正交过滤

这些字段互相独立，可以组合使用。例如：

```bash
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl \
  --actor codex search "部署" --current-project example-app --track project
```

这会比只全文搜索更省上下文，也更少误召回。

## 决策结果记录 v1

需要复盘的决策可在正文加入一个 `## 决策—结果记录` 区块。Pilot 阶段一文件一条，
保留中文叙述字段，并增加稳定、可校验的机器字段：

```md
- outcome_schema: decision-outcome/v1
- decision_id: decision-20260701-example
- 决策日期: 2026-07-01
- 决策问题: ...
- 当时选项: ...
- 最终选择: ...
- 预期结果: ...
- 复盘日期: 2026-07-20
- 实际结果: ...
- 副作用: ...
- 当前结论: ...
- 未确定项: ...
- outcome_status: pending | confirmed | mixed | reversed | superseded | unverifiable
- decision_ref: <当时决策的 Git/原文/会话证据>
- evidence_ref: <独立 commit、日志、构建物、现行配置或外部状态>
- 后续使用证据: <这条结论后来是否影响另一任务>
- recorded_at: 2026-07-20
- recorded_by: human | codex | claude
- confidence: high | medium | low
```

`decision_ref` 固定当时目标，不能在复盘时倒改预期；`evidence_ref` 证明结果，和“后来是否
采用”分开。没有独立证据就使用 `unverifiable`，不能拿本文件自己的旧表述反向证明
`confirmed`。报告中的 `corpus_files` 是扫描到的 Markdown 文件数，不是决策总数；真正
决策分母未知时必须明确保留为 unknown。
