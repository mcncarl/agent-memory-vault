# Shared Claude Code and Agent Memory Vault Instructions

这是 Claude Code 与 Codex 可共用的本地长期记忆库。Markdown 是唯一正式事实源；两个 Agent 不各自维护第二套正式事实。

读取顺序：

1. 先读本文件。
2. 再读 `INDEX.md`。
3. 根据任务关键词，只读最相关的 1-3 个文件。

不要默认读取整个记忆库。

## 检索规则

优先使用统一搜索脚本，而不是手工猜该读哪个文件：

```bash
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl \
  --actor codex search "查询词" --semantic-mode auto --limit 5
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl \
  --actor claude search "查询词" --semantic-mode auto --limit 5
```

它会先查 SQLite/FTS；启用语义索引时，也可以并行查 Zvec。Zvec 命中只能当作候选线索，最终回答前必须回读 Markdown 原文。

长文件先用 `retrieve --view outline --file <相对路径>` 查看当前标题树，再用
`retrieve --view section --section-id <id> --expected-sha256 <outline-sha>` 有界读取目标章节；
出现 `STALE_OUTLINE` 必须重新取大纲。不要因为“当前有效摘要”标题存在就默认整节很短。
默认 retrieve 仍只读，但 canonical retrieve 会自动记录所打开内容的 `memory_id` 与当前
内容 hash；不会记录查询正文、excerpt 或原始 session。`--observe` 暂时保留为兼容参数。

`zvec_raw_distance` 与 `zvec_rank_distance` 都保持模型原始距离；词法证据只在 Hybrid RRF
层融合，不能改写向量距离，也不能单独触发写入、更新或合并。

在项目任务中传入 `--current-project <project-id>`。任何带有非 `global/shared` `project_id` 的记忆都默认硬隔离，包括工作流和决策；只有显式加 `--cross-project` 才返回其他项目的类比线索，而且这些结果不能授权动作。没有当前项目上下文时，项目记忆只能以 `scope_status=project_context_unknown`、`analogy_only=true`、`can_authorize_action=false` 返回。没有 `project_id` 的内容按未限定共享参考处理。`valid_until` 已过期的内容仍可召回，但必须实时核验。

默认只发现 `active` 和 `pending_verification`。后者可检索但绝不能授权动作；`outdated`、
`archived` 只有显式 `--include-inactive` 才作为历史参考出现。`--no-zvec` 只是兼容别名，
新调用使用 `--semantic-mode auto|off|required`。

每个回读候选必须按同一内容版本声明为 `adopted`、`reference_only` 或 `rejected`。采用
过期、逾期或冲突内容时，还必须先对相同 content hash 记录 `live_verified=yes`；否则在
影子期只记录违规，正式门禁启用后 Stop 会阻断。声明只写哈希和受控枚举，不写查询或正文。

会变化且一旦用错会影响行动的事实，使用“一条事实一个文件”的事实记录：frontmatter 必须有稳定的 `fact_key` 和 ISO 日期 `valid_from`。新版本必须用 `supersedes` 精确列出旧文件相对路径；没有显式边、出现多个当前头、跨 scope、日期倒退或环时，一律视为冲突，不能按更新时间、相似度或搜索分数猜当前值。默认搜索和 canonical retrieve 不返回已被明确替代的事实；历史查询使用 `--as-of YYYY-MM-DD`。

## 写入规则

所有正式 Markdown 都由 Write Gateway v2（写入网关 v2）保护。`codex`、`claude`、
`ailu` 是唯一自动写入 actor，未知 actor 统一拒绝。不要先直接编辑文件、再补 claim；
claim 只是当前 intent（写入意图）的
审计投影，不授予写权限。

每个文件必须走同一条高层协议：

1. `write read-target` 读取完整当前文件、Git 基线和一次性 `read_token`。
2. 在这份完整正文上生成最终 Markdown；UPDATE 不能用一段新回答覆盖旧文件。
3. `write prepare` 重传最终正文、`read_token`、来源分类、事实类型和证据引用。它只做
   安全检查、对账并获取 path lease（路径租约）与单调递增的 `fencing_token`，不改 Markdown。
4. 只对 `ADD` / `UPDATE` 继续。`NOOP` 不写；`MERGE_REQUIRED` / `ASK_USER` 必须停下确认。
5. `write apply` 必须重传同一个 proposal id、目标、最终正文、raw/canonical hash、
   `fencing_token` 和对这版提案的精确授权引用。Ailu 必须绑定用户确认；Codex/Claude
   可以绑定当前用户任务授权。不能复用另一版提案的确认。
6. apply 通过文件 CAS（比较后交换）写入；随后 closeout 再次验证租约、fence、文件 hash
   与 Git blob，并在一个数据库事务里写 receipt、file observation、完成 claim 和 intent。

请求和响应都必须是 `schema_version: 2`。JSON 只从 stdin 传入；会话只使用宿主自己的
`AGENT_MEMORY_SESSION_ID`（Codex 可由 `CODEX_THREAD_ID` 提供，Claude 由 SessionStart Hook
写入）。基本命令形态：

```bash
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl \
  --actor <codex|claude|ailu> write read-target --json <<'JSON'
{"schema_version":2,"target_relative_path":"项目/example.md","app_id":"example-app","project_id":"example-project"}
JSON

<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl \
  --actor <codex|claude|ailu> write prepare --json <<'JSON'
{"schema_version":2,"summary":"bounded summary","proposal_markdown":"<完整最终 Markdown>","target_relative_path":"项目/example.md","app_id":"example-app","project_id":"example-project","read_token":"<read-target token>","source_class":"user_direct","knowledge_kind":"fact","asserted_by":"user","evidence_ref":"task:message-reference"}
JSON
```

`prepare` 返回的 `proposal_id`、两种 proposal hash 和 `fencing_token` 必须原样进入 apply；
不要手工伪造。放弃尚未应用的提案时调用 `write cancel`，同时传 proposal id 与 fence。
过期或较小的 fence 即使晚到也必须被拒绝，同一路径不能同时存在两个 live lease。

根治理文件 `AGENTS.md`、`README.md`、`STRUCTURE.md` 也走相同网关，但允许无
frontmatter；只允许 `codex` / `claude` 使用 `app_id=agent-memory`、
`project_id=agent-memory-vault` 写入。`INDEX.md` 是机器生成的只读投影，只能由 closeout
在源文件的同一个 Git 事务里刷新；普通 Gateway 或编辑器写入必须返回
`GENERATED_FILE_READ_ONLY`。Ailu 的 `app_id` 固定为 `ailu`，`project_id` 必填，只能是一个
实际项目 ID 或 `global`；`global` 只允许写 `用户记忆/`，Ailu 不得写根治理文件。

Obsidian 或人工已在网关外修改文件时，不得覆盖。可重新 read-target 后对当前版本准备新
提案；也可由 Codex/Claude 在明确用户授权下用 `prepare` 的 `adopt_external: true` 收养
“当前文件的精确字节”。收养要求文件确实偏离 Git HEAD、提案与当前文件完全一致，并仍然
经过 safety、对账、租约、fence、CAS 和 closeout。Ailu 不自动收养外部编辑。

如果返回 `TARGET_WRITE_RECOVERY_REQUIRED`，目标旁可能保留含完整正文的隐藏恢复 sidecar；
保留现场并人工核对，不能自动删除、提交或盲目重试。任何 unresolved closeout incident、
租约/claim 不一致、其他会话的非 live claim、删除状态或内容漂移都必须 fail closed。

正式目录仍是 `用户记忆/`、`项目/`、`工作流/`、`决策/` 与 `agent/`。Agent 复用经验放入
`agent/cases/` 或 `agent/case-candidates/`；可抽象流程放入 `agent/skill-candidates/`，正式
升级 skill 前需要用户确认。apply 正常完成时已执行会话级 closeout；只有重试未完成的
当前会话收尾或人工诊断时才单独运行 `memoryctl --actor <actor> closeout`。

## Audit 规则

audit 用来发现需要复核、合并或忽略的记忆，不直接改写 Markdown 事实层。

```bash
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor human audit --json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor human audit --ignore FINDING_ID --note "保留原因"
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor human doctor --json
```

自动 audit 只有一个 canonical 调度器：每周日 10:30 的 LaunchAgent。Stop 与 closeout
不得另行触发或漂移这条计划。audit findings 应由用户或 Agent 明确裁决，避免报告本身变成新的 open-loop 噪声。

## 字段要求

新建或重写正式记忆时，尽量包含下面字段：

```yaml
---
memory_id: "<write read-target 返回的 generated_memory_id>"
memory_type: project
track: project
project_id: example-app
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
agent_scope: shared
created_by: human | codex | claude
last_updated_by: human | codex | claude
session_id: ""
status: active
sensitivity: normal
risk_class: ordinary
temporal_policy: reviewable
verified_at: ""
review_after_days: 90
valid_until: ""
keywords:
  - example
---
```

`memory_id` 不得手工编造；ADD 时必须把 `write read-target` 回执中的
`generated_memory_id` 原样放入 proposal。`temporal_policy` 必须显式选择；模板中的
`reviewable` 只是普通多事实文档示例，不能替代对内容风险和时效的判断。

`risk_class` 只允许 `ordinary` 或 `action_sensitive`，不接受第三种状态。
active 的项目、工作流和决策文档必须显式声明风险等级。
决策、原子事实、`expiring` 内容、带 `valid_until` 的内容以及 `事实-*.md` 不能用
`ordinary` 降级；它们必须使用 `action_sensitive`，同时提供真实的 `fact_key`、
`valid_from`、`verified_at` 和 Write Gateway `evidence_ref`。不能为了通过门禁编造日期
或到期日。

风险和时态元数据在七天影子期只记录稳定 reason code 与计数；切换到 enforce 后，缺失、
非法或降级声明会阻止记忆授权动作。路径或 scope 已经明确不安全时仍立即 fail closed，
不会因为处于影子期而放宽。遇到 reason code 时使用当前 Runtime 解释，不要照旧资料调用
底层 claim 命令：

```bash
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl \
  --actor codex explain <reason_code> --json
```

上面是普通多事实文档。需要自动识别“旧值已作废”时，不要把多个版本继续堆在同一摘要里；改用 `项目/_模板-事实记录.md`。事实记录还必须包含 `fact_key`、`valid_from`，替代旧版本时包含 `supersedes`，并在 Write Gateway 请求里提供 `evidence_ref`。自然语言中的“现在、作废、替代”不会自动建立替代关系。

## 安全边界

- 不要把 API key、token、cookie、密码写入 Markdown。
- 不要把私密原始聊天全文写入公开仓库。
- 不要把 SQLite 数据库提交到 Git。
- 搜索日志只保存查询哈希、长度、来源和耗时，不保存新的查询原文。
- 对外分享前必须脱敏。
- Claude Code 原生 auto-memory 不应直接指向正式 vault；可停用，或只把它当作非正式草稿层。
