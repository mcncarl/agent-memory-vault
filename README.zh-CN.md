# Agent Memory Vault：Claude Code、Codex 与 Ailu 共享记忆层

[English](./README.md) | **简体中文**

这是一个可由 Claude Code、Codex 与 Ailu 共用的长期记忆库模板。它把普通 Markdown 文件当作唯一长期事实源，用 SQLite 建全库索引，并用路径租约、单调 fencing token、CAS、Git 回执和 closeout 解决同文件并发写入。需要语义检索时，也可以额外启用本地 EmbeddingGemma + Zvec 向量旁路。

这个仓库只包含模板、脚本和假示例，不应该包含你的真实记忆、真实路径、API key、私人项目名或聊天原文。

所有运行入口都使用平台中立命名：配置使用 `AGENT_MEMORY_*`，脚本使用 `agent_memory_*`，统一命令为 `memoryctl`。仓库不提供旧名称兼容脚本或环境变量回退。

## 它解决什么问题

- 让 Claude Code 与 Codex 每次开始重要任务时，读取同一份相关长期记忆。
- 让每次任务结束时，把稳定事实、项目状态、工作流和 Agent 经验沉淀到 Markdown。
- 让 Markdown 仍然是源文件，SQLite 只做索引和搜索，Obsidian 只是可选的查看和编辑方式。
- 可选增加向量检索：只记得大概意思时，用 embedding + Zvec 找到相关 Markdown，再回读原文。
- 把真实信息留在本地私有 vault，模板只提供结构和方法。

## 是否必须安装 Obsidian？

不必须。

这个项目本质上是一个 Markdown 文件夹 + SQLite 索引脚本。你可以直接用 Codex、VS Code 或任意文本编辑器管理它。

如果你想用更舒服的笔记界面查看、编辑和搜索这些 Markdown 文件，可以安装 Obsidian，然后把生成出来的记忆库文件夹作为一个 Obsidian vault 打开。

## 核心结构

```text
templates/vault/
  AGENTS.md              # 两端共享的读取和写入规则
  INDEX.md               # 记忆路由索引
  用户记忆/              # 用户偏好、边界、长期画像
  项目/                  # 项目级状态和结论
  工作流/                # 可复用流程、字段规范、收尾规则
  决策/                  # 权衡和取舍
  agent/                 # Agent case、skill 候选、未闭环事项

scripts/
  bootstrap.py           # 从模板创建本地私有 vault
  agent_memory_index.py  # 全库 SQLite 索引和搜索
  agent_memory_search.py # 统一搜索入口：SQLite + 可选 Zvec + 手动 rg
  agent_memory_retrieve.py
                         # 回读、重验并有界返回正式 Markdown 摘要
  agent_memory_observability.py
                         # 可选的任务级哈希化可观测事件与分源报表
  agent_memory_write.py  # 宿主程序用的 read-target/prepare/apply/cancel/status/list 边界
  agent_memory_migrate.py
                         # state v4 显式 plan/init/apply/verify 与 ready 提交门
  agent_memory_safety.py # 写入前来源、知识类型和敏感内容闸门
  agent_memory_claim.py  # intent 的会话归属投影与原子批量 closeout
  agent_memory_intent.py # 路径租约、fence、审批绑定和不可变回执
  agent_memory_closeout.py
                          # 任务结束收尾：检查、对账、刷新索引、可选提交
  agent_memory_audit.py  # 定期体检：过期、重复、open-loop、裁决记录
  agent_memory_audit_autorun.py
                          # audit 自动触发器：超过间隔才运行
  agent_memory_doctor.py  # 全链路体检：Markdown/SQLite/FTS/Zvec/Git/自动化
  agent_memory_session_hook.py
                          # Claude SessionStart 会话 ID 桥接，防止与外层 Codex 串号
  agent_memory_stop_hook.py
                          # 可选 Stop 自动 closeout；不接管周审计
  install_runtime.py     # 把当前 Git 版本安装为可校验的本机 Runtime
  memoryctl               # Claude/Codex 共用的平台中立命令入口
  agent_memory_zvec_index.py
  agent_memory_retrieval_benchmark.py
  agent_memory_decision_outcomes.py
  agent_memory_evolution.py
  agent_memory_check.py
```

## 快速开始

macOS/Linux 推荐先只读 plan，再显式一次 apply；宿主 Hook 必须明确选择。下面示例明确不安装 Hook：

```bash
python3 scripts/install-posix.py --plan \
  --memory-root "$HOME/agent-memory-vault" --no-host-hooks --json
python3 scripts/install-posix.py --apply \
  --memory-root "$HOME/agent-memory-vault" --no-host-hooks --json
```

`--plan` 始终调用源码 checkout 中的 migrator，并选择一个已经存在的 Python 3.10+
解释器；也可以用 `--python /absolute/python` 显式指定。因此即使正式 v1 Runtime 里根本
没有 `agent_memory_migrate.py`，它仍能只读读取现有 TOML 与 v1 state DB，输出完整迁移
计划和 `disposition_template`。

升级时，按 plan 要求把 `disposition_template` 另存为私有、已审阅 JSON，并传入全新的
`--config-backup`、`--state-backup` 和 `--disposition-file`。要安装生命周期 Hook，就把
`--no-host-hooks` 换成 `--host codex` 和/或 `--host claude`，并提供新的
`--hook-backup-dir`。任一步失败都会保持 Runtime 非 ready。以下长命令只用于需要逐阶段执行
底层原语的维护场景。

入口只接受两种无歧义状态：TOML 与 state DB 都不存在才是 fresh；两者都存在才是
upgrade；只存在其中一个会 fail closed。apply 会在安装 Runtime 或触碰 Vault 之前，先用
源码 migrator 核验全部 blocker 和已审阅 disposition。只有 fresh 会运行 `bootstrap.py`；
upgrade 只读验证现有 memory/git root 与 `AGENTS.md`、`INDEX.md`，绝不向旧 Vault 补模板或
初始化 Git。唯一会治理既有 Markdown 的步骤是首次机器生成 `INDEX.md` 迁移：state/audit
ready 后，要求 Vault 内全部 Markdown clean 且与 HEAD 精确绑定，再通过 closeout capability
建立只含 INDEX 的精确 Git 提交；Vault 外的非 Markdown 脏文件不会被暂存或提交。下面的手工
`bootstrap.py` 序列仅适用于 fresh，不能用于升级：

```bash
git clone https://github.com/mcncarl/agent-memory-vault.git
cd agent-memory-vault
python3 scripts/install_runtime.py --config-root "$HOME/.config/agent-memory"
test ! -e "$HOME/.config/agent-memory/config/agent-memory.toml" && \
  cp config/agent-memory.example.toml "$HOME/.config/agent-memory/config/agent-memory.toml"
# 编辑 TOML 中的 memory_root、git_root、config_root、state_db、python 和身份字段。
python3 "$HOME/.config/agent-memory/scripts/bootstrap.py" \
  --memory-root "$HOME/agent-memory-vault" \
  --config-root "$HOME/.config/agent-memory" \
  --state-db "$HOME/.config/agent-memory/state.sqlite"
"$HOME/.config/agent-memory/scripts/memoryctl" \
  --actor migration migrate init --json
"$HOME/.config/agent-memory/scripts/memoryctl" \
  --actor migration migrate audit-init --json
"$HOME/.config/agent-memory/scripts/memoryctl" \
  --actor migration migrate generated-index-migrate --json
"$HOME/.config/agent-memory/scripts/memoryctl" \
  --actor migration migrate verify --json
python3 "$HOME/.config/agent-memory/scripts/install_host_hooks.py" \
  --host codex --host claude --auto-closeout \
  --backup-dir "$HOME/.config/agent-memory/backups/hooks-v2" --apply --json
"$HOME/.config/agent-memory/scripts/memoryctl" \
  --actor migration migrate verify --publish-ready --require-host-hooks --json
```

`migrate init` 只适用于 state DB 不存在的新装。已有数据库必须先停掉所有 writer，运行
`migrate plan`，再用一个尚不存在的私有路径执行
`migrate apply --backup-path <new-backup.sqlite>`；迁移器不会覆盖备份，也不会替活动的旧
claim/intent 静默选赢家。`verify` 默认只读，只有完成索引、Doctor 与 Hook 检查后运行
`verify --publish-ready` 才提交 Runtime 切换。源码 checkout 没有 v3 state 时同样 fail closed，
不会由普通命令调用 `ensure_schema` 偷偷升级旧库。

`bootstrap.py` 只用于新建私有 Vault，默认初始化独立 Git 仓库并提交模板基线；升级绝不
调用它。只有明确不需要 Git 时才加 `--no-init-git`。模板自带 `.gitignore`，会排除
Obsidian 界面状态。

Windows 10/11 请直接使用 PowerShell 安装器，完整步骤见 [docs/windows.md](docs/windows.md)：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 `
  -MemoryRoot "$HOME\Documents\Agent Memory Vault"
```

正常升级使用上面的 `install-posix.py --plan/--apply`。下面只展示专家恢复所用的底层
Runtime/config 原语；它不包含升级前的 disposition 预检，不能替代产品入口。私人 TOML
不会被覆盖；只要 bundle 发生变化，Runtime 仍会停在 `state_migration_required`：

```bash
python3 scripts/install_runtime.py --config-root "$HOME/.config/agent-memory"
# 新装只用 `cp -n` 创建 TOML；升级绝不覆盖私人配置，改走原子迁移与独占备份。
"$HOME/.config/agent-memory/scripts/memoryctl" --actor migration migrate config-plan --json
"$HOME/.config/agent-memory/scripts/memoryctl" --actor migration migrate config-apply \
  --backup-path "$HOME/.config/agent-memory/backups/agent-memory-before-v2.toml" --json
"$HOME/.config/agent-memory/scripts/install_runtime.py" \
  --config-root "$HOME/.config/agent-memory" --verify --json
```

## Claude Code、Codex 与 Ailu 共用

保持一个 Markdown vault、一个 Git 基线、一个 state SQLite、一个可选 Zvec 和一个 audit 调度器。三个宿主只维护薄适配层：

- Codex 的 `AGENTS.md` 指向 vault 规则。
- Claude Code 的 `CLAUDE.md` 使用 `@/absolute/path/to/AGENTS.md` 导入同一规则。
- Claude Code 原生 auto-memory 不要指向正式 vault；推荐关闭，或只把它当作非正式草稿层。
- 三端通过 `memoryctl --actor codex|claude|ailu` 使用同一检索与 Write Gateway v2。
- 自动写入 actor 只允许 `codex`、`claude`、`ailu`；未知 actor 统一拒绝。

```bash
scripts/memoryctl --actor claude search "项目状态" --limit 5
AGENT_MEMORY_SESSION_ID="host-session-id" \
scripts/memoryctl --actor codex write read-target --json <<'JSON'
{"schema_version":2,"target_relative_path":"项目/example.md","app_id":"example-app","project_id":"example-project"}
JSON
```

自动 writer 不得先编辑 Markdown 再补 claim。claim 只保存 session hash，是 active intent 的归属
投影，不是写权限。真正的排他权来自每个 canonical path 唯一的 live lease；所有权转移都会
拿到更大的 `fencing_token`，旧进程即使晚醒也不能 apply、closeout 或写 completed receipt。
成功 apply 会自动执行会话级 closeout，并将 Git commit、不可变 receipt、file observation、
claim 完成与 intent 终态绑定。其他会话的 live claim 保持隔离；过期、terminal、fenced、
legacy 或 incident 状态一律 fail closed。
宿主可用 `write status/list` 恢复查询当前 actor 与 session 所属任务；查询不改写
SQLite、claim、遥测或 Markdown。已终止的 apply/cancel 重放只返回原始已验证 receipt。

Claude 的 `Stop` 和 `SessionEnd` 使用不同生命周期语义：`Stop` 可以在首次真实失败时请求 Claude 继续处理，但检测到 `stop_hook_active=true` 后不得重复阻断；`SessionEnd` 只做 60 秒内的非阻断兜底，不运行周审计，失败只发本机通知。两类运行分别记录为 `trigger=stop-hook` 与 `trigger=session-end`。对 `codex`/`claude` 执行 `memoryctl closeout` 默认必须具备宿主 session 或显式 `--session-id`，只有明确传入 `--global` 才允许全库维护。

异常退出可能留下旧认领。Stop Hook 不会继续信任超过 24 小时的认领，Doctor 会把它列为警告。清理时先预览，再显式应用；这只把 SQLite 账本状态改为 `expired`，不会删除或改写 Markdown：

```bash
scripts/memoryctl --actor human claims-expire --older-than-hours 24 --json
scripts/memoryctl --actor human claims-expire --older-than-hours 24 --apply --json
```

如果一个正式 Markdown 已经按用户明确指令移入系统垃圾篓、又被外部备份工具提前提交为 Git 删除，可由人工维护显式登记可恢复删除。命令默认只预览；只有 `--apply` 才会写入审计表和 `deleted:<commit>:<prior_sha256>` 观察指纹。它会核对目标当前缺失、删除提交属于当前历史、父提交确实包含并删除该文件，以及垃圾篓副本与删除前 Git blob 完全一致。`evidence-ref` 和垃圾篓绝对路径只保存哈希，不写入正文或输出：

```bash
scripts/memoryctl --actor human observe-deletion \
  --file "/absolute/vault/项目/已删除.md" \
  --trash-path "$HOME/.Trash/已删除.md" \
  --deletion-commit "40-hex-commit" \
  --evidence-ref "current-user-authorization-reference" \
  --confirm-user-authorized --json

# 逐项确认预览后才应用：
scripts/memoryctl --actor human observe-deletion \
  --file "/absolute/vault/项目/已删除.md" \
  --trash-path "$HOME/.Trash/已删除.md" \
  --deletion-commit "40-hex-commit" \
  --evidence-ref "current-user-authorization-reference" \
  --confirm-user-authorized --apply --json
```

如果正文已经由历史会话精确验证并提交，但 closeout 在写入 observation 前中断，后来该 intent 仅因 TTL 到期，可用原始 `intent_id` 恢复已有文件的观察。这个入口不会改正文；它只接受 `user_direct + ALLOW + exact + early_commit` 的完整 intent/receipt 链，要求当前文件等于 `HEAD`，原 proposal commit 仍是该路径最新变更，且目标没有活动 intent、claim 或未提交 Git 状态。命令同样默认预览，`--apply` 才写审计：

```bash
scripts/memoryctl --actor human observe-committed \
  --file "/absolute/vault/用户记忆/偏好与边界.md" \
  --intent-id "32-hex-expired-intent" \
  --evidence-ref "historical-user-authorization-reference" \
  --confirm-user-authorized --json

# 核对预览后应用：
scripts/memoryctl --actor human observe-committed \
  --file "/absolute/vault/用户记忆/偏好与边界.md" \
  --intent-id "32-hex-expired-intent" \
  --evidence-ref "historical-user-authorization-reference" \
  --confirm-user-authorized --apply --json
```

搜索示例：

```bash
scripts/memoryctl --actor codex search "项目 收尾" --limit 5
scripts/memoryctl --actor codex search "偏好" --track user
scripts/memoryctl --actor codex search "复用流程" --memory-type workflow
scripts/memoryctl --actor codex search "部署边界" \
  --current-project example-app --semantic-mode auto
```

默认检索 `active` 与 `pending_verification`；后者始终只可参考，返回
`can_authorize_action=false`。`outdated`、`archived` 只有显式
`--include-inactive` 才出现。未提供当前项目时，项目记忆可以
`scope_status=project_context_unknown`、`analogy_only=true` 被发现，但不能授权动作；
只有 `--cross-project` 才展示其他项目的类比线索。

需要给宿主程序注入正式记忆正文时，不要直接相信 SQLite/Zvec 中的摘要，使用只读
`retrieve` 再次核对当前 Markdown：

```bash
AGENT_MEMORY_SESSION_ID="ailu-session-id" \
scripts/memoryctl --actor ailu retrieve --json <<'JSON'
{"schema_version":2,"query":"当前任务","app_id":"ailu","project_id":"example-project","max_results":5,"max_file_bytes":1048576,"max_total_bytes":4194304,"max_excerpt_bytes":12288}
JSON
```

该命令不回显查询原文，只返回 `query_hash`；索引只负责提供候选，每个候选都要重新
通过 Vault containment/symlink 检查、严格 UTF-8 读取、当前 frontmatter 的
`status`/`agent_scope`/`app_id`/`project_id` 过滤和敏感内容检查。结果包含相对路径、
当前文件 SHA-256、`verified_at`、Git HEAD、策略与实时核验提示，以及优先取自
`## 当前有效摘要` 的有界 excerpt。单文件问题是结构化 warning；Vault 根目录或协议
参数不安全时才整体失败。Ailu 固定要求 `app_id=ailu` 且 `project_id` 必填；它只能是一个
实际项目 ID 或 `global`。`global` 只允许召回 `用户记忆/`，不接受 `shared`、逗号多项目或
新的 unscoped 内容。查询只能从
受控 stdin JSON 进入，不能出现在 argv。读取过程使用 `search --no-log` 等价的只读索引路径，不写
Markdown、SQLite 或搜索日志。

Agent 读取长文时可先取当前标题树，再按节分页读取；section 必须携带 outline 返回的
`source_sha256`，文件变化会返回 `STALE_OUTLINE`，不会把旧章节坐标套到新正文：

```bash
scripts/memoryctl --actor codex retrieve --view outline \
  --file "项目/example.md" --project-id example-app --json
scripts/memoryctl --actor codex retrieve --view section \
  --file "项目/example.md" --project-id example-app \
  --section-id s0002 --expected-sha256 '<outline-sha256>' --json
```

v4 安装默认启用 `[observability]`。搜索和 Stop Hook 只追加 task/memory 单向哈希、
枚举标签与计数；原问题、回答、excerpt、URL、session 原值和自由文本理由不入库。
Canonical Retrieve 会自动记录重新打开的 `memory_id + 当前内容哈希`，不再依赖
`--observe`。工具观察、Agent 自报、人工标注和独立模型标注在报表中分开，不把
“没观察到”自动解释成“没有发生”。

Hybrid v2、“采用旧记忆但未实时核验”的阻断和显式时态/风险元数据门禁，先经过与当前
Runtime manifest、安装时间和生产配置 SHA 共同绑定的七天影子门禁。迁移 actor 先运行
`memoryctl --actor migration shadow start --benchmark-file <runtime>/benchmarks/private-quality.json`，在第一天固定私有数据集
SHA、完整 required-set SHA 与用例数量；随后对同一文件运行完整的三轮生产链路
`memoryctl --actor migration retrieval-benchmark --benchmark-file <runtime>/benchmarks/private-quality.json --runs 3 --attest-success`
和 `memoryctl --actor migration shadow canary`。成功证明禁止搭配 `--case-id`，私有数据集至少包含 5 个
`required_at <= 5` 的 required case，其中必须包含“Codex 每次对话结束怎么自动归档”；
影子开始后替换成更容易通过的数据集会直接被拒绝。
`memoryctl --actor migration shadow status` 只有在满七天、排除 benchmark/canary/synthetic 后至少有一个真实
Search/Retrieve 任务、required case 无回归、元数据 would-block 为零、无降级或隐私泄漏、
无缺失 task 分母且没有连续语义失败或 Worker 崩溃循环时才通过。之后
`memoryctl --actor migration shadow cutover --config-backup <全新私有路径>` 才能以单文件 CAS 同时启用
`ranking_version=hybrid-v2`、`stale_adoption_enforcement=enforce` 和
`metadata_enforcement=enforce`。
直接改配置或传 Search CLI 参数都不能绕过门禁，失败证据与唯一备份会保留。
风险门禁使用 `METADATA_RISK_CLASS_NOT_EXPLICIT`、
`METADATA_RISK_CLASS_INVALID`、`METADATA_RISK_CLASS_DOWNGRADE` 三个稳定 code；
影子证据只保存计数和指纹，不保存正文或查询。

`ailu` 是运行 actor，不是事实断言者。中央入口只允许它调用 `retrieve`、`write` 和
`version`；低级 `prewrite` / `intent` / `claim` / `closeout` / `check` 等全部 fail closed。
`write prepare` 仍必须把 `asserted_by` 明确写成
`user`、`claude`、`codex` 或 `opencode`，不能把应用名冒充信息来源。

### Write Gateway v2 显式写入

`write` 是 `codex`、`claude` 与 `ailu` 共用的唯一自动写入边界。请求/响应必须包含
`schema_version: 2`，JSON 只从 stdin 传入。Ailu 必须生成自己的
`AGENT_MEMORY_SESSION_ID`，不得继承外层 Codex/Claude 会话，也不能把 session 放进 argv。

构造 `UPDATE` 前必须先用 `read-target` 读取目标的完整当前内容，再在这份
全文上编辑或追加。不能把 Agent 新回答直接当成整份目标，否则会丢掉
旧记忆。该读取只接受正式相对 `.md` 路径，使用 containment/symlink、严格
UTF-8 和 2 MiB 限制，并重新验证 active、shared、app/project scope 与 secret；返回
`base_exists`、完整 `content`、两种 base hash、`base_git_head` 和会话/目标绑定的
`read_token`，
不加写锁、不写 state DB/日志/Markdown：

```bash
AGENT_MEMORY_SESSION_ID="host-session-id" \
scripts/memoryctl --actor ailu write read-target --json <<'JSON'
{"schema_version":2,"target_relative_path":"用户记忆/example.md","app_id":"ailu","project_id":"global"}
JSON
```

`prepare` 先做来源安全、查重、目标选择和基线绑定。它会记录不含正文的
安全审计；只有 `ADD`/`UPDATE` 才会创建私有提案元数据。它绝不修改正式
Markdown：

```bash
AGENT_MEMORY_SESSION_ID="host-session-id" \
scripts/memoryctl --actor ailu write prepare --json <<'JSON'
{"schema_version":2,"summary":"durable preference summary","proposal_markdown":"---\nmemory_id: <read-target generated_memory_id>\nmemory_type: user_preference\ntrack: user\napp_id: ailu\nproject_id: global\nagent_scope: shared\nstatus: active\nrisk_class: ordinary\ntemporal_policy: stable\nreview_after_days: 365\n---\n\n# Example\n","target_relative_path":"用户记忆/example.md","app_id":"ailu","project_id":"global","read_token":"<read-target returned 64-hex>","source_class":"user_direct","knowledge_kind":"preference","asserted_by":"user","evidence_ref":"conversation:message-ref"}
JSON
```

active 的项目、工作流和决策必须显式使用 `risk_class: ordinary` 或
`risk_class: action_sensitive`，不接受其他状态。决策、原子事实、
`expiring`、带 `valid_until` 或 `事实-*.md` 的内容不能用 ordinary 降级；它们还必须
提供 `fact_key`、`valid_from`、真实 `verified_at` 与 `evidence_ref`，不能编造到期日。
Codex/Claude 的状态变化也走 Write Gateway v2 的
`operation=status_transition`；Ailu 禁止状态转换。遇到稳定错误码时运行
`memoryctl --actor codex explain <reason_code> --json` 获取当前路线，不要复用旧的底层
claim 指引。

`prepare` 必须回传同一 session、目标、app/project scope 的 `read_token`。它在共享
`closeout.lock` 内重读并比较 `exists`、raw/canonical hash 与 Git HEAD；缺 token 的
`UPDATE` 和 `ADD` 都拒绝。read-target、prepare 与 proposal frontmatter 必须传相同的
`project_id`。Ailu 只接受一个实际项目 ID 或 `global`，且 `global` 只允许 `用户记忆/`。
新 proposal 必须显式写
`status: active`、`agent_scope: shared` 和固定 app id。

返回只允许 `ADD` / `UPDATE` / `NOOP` / `MERGE_REQUIRED`。`prepared` 包含不可变的
`proposal_id`、两种提案 hash、目标、基线和过期时间；`NOOP` 不写，
`MERGE_REQUIRED` 不创建可写提案，两者都不能被 UI 当成可确认写入。

只有用户明确确认后才能调用 `apply`。宿主必须重传同一版正文、prepare
返回的 ID/hash/目标，以及一个不含聊天正文的用户确认引用：

```json
{"schema_version":2,"proposal_id":"<32-hex>","fencing_token":17,"target_relative_path":"用户记忆/example.md","proposal_markdown":"<与 prepare 完全相同的最终 Markdown>","proposal_raw_sha256":"<64-hex>","proposal_canonical_sha256":"<64-hex>","confirmed_by":"user","confirmation_reference":"conversation:confirmed-message-ref"}
```

`apply` 会在同一把共享锁内重新验证会话、目标、基线、ID、hash、live lease 与
`fencing_token`，再按
“claim → 原子条件写入 → 本会话 closeout”完成提交。ADD 用同目录 hard link
做 no-replace 发布；UPDATE 用同文件系统的原子交换先捕获旧目标，再校验被换出的
raw hash。若捕获的不是准备阶段基线，会先独立保留竞态字节并原子换回；任何无法
证明恢复完整的二次竞态都返回 `TARGET_WRITE_RECOVERY_REQUIRED`，保留隐藏 sidecar
供人工恢复，不继续 closeout。当前文件系统不支持安全交换时也 fail closed。
基线漂移、内容变化或查重冲突会结构化失败，不会静默覆盖。如果精确写入后 closeout 失败，文件保持
当前会话的认领状态，必须核对后重试。这种状态调用 `cancel` 会返回
`APPLY_RECOVERY_REQUIRED`，不允许把已改但未收尾的 Markdown 遗留为“已取消”。
apply 完成文件 CAS 后先释放共享锁，再启动会重新取同一锁的 closeout，避免嵌套死锁；
交接间隙仍由 path lease 与 fence 保护。closeout transport 使用独立进程组，超时或宿主
中断时终止整组并确认其不能继续写。

用户放弃未应用的提案时，向 `cancel` 的 stdin 传入
`{"schema_version":2,"proposal_id":"<32-hex>","fencing_token":17}`。取消不修改 Markdown，同一会话重复取消是
幂等的。

根治理文件 `AGENTS.md`、`README.md`、`STRUCTURE.md` 也使用同一网关，但允许无
frontmatter；只允许 Codex/Claude 使用 `app_id=agent-memory`、
`project_id=agent-memory-vault`。`INDEX.md` 是唯一例外：它是覆盖全部受治理 Markdown 的
机器生成只读投影，只能在源文件 closeout 的同一个 Git 事务中更新。人工、编辑器或普通
Gateway 直接写入都会返回 `GENERATED_FILE_READ_ONLY`；Doctor 要求 missing 和 broken 都为
0。Ailu 不得写根治理文件。

若人工或 Obsidian 已在网关外修改文件，自动 writer 不得覆盖。可以重新 read-target 后对
当前版本准备新提案；也可以由 Codex/Claude 在精确用户授权下让 prepare 携带
`adopt_external: true`，且 proposal 必须与当前文件字节完全相同、文件确实偏离 Git HEAD。
adopt 仍经过安全检查、对账、租约、fence、CAS、Git 与 closeout；Ailu 不自动 adopt。

传入 `--current-project` 后，任何带有非 `global/shared` `project_id` 的记忆都受项目硬边界约束，不论它位于项目、工作流还是决策轨道。确实要借鉴别的项目时，必须再加 `--cross-project`，返回项会标成 `analogy_only`，只能参考，不能据此授权执行动作。没有 `project_id` 的内容按未限定共享参考处理；只有明确写成 `global` 或 `shared` 的内容才是全局共享。

有 `valid_until` 的记忆到期后不会从搜索结果里消失。它仍可能解释历史，但会标成 `time_status: expired` 和 `requires_live_verification: true`；凡是当前状态、费用、账号、权限、外部系统等会变化的事实，都要实时核验后再用。

如果旧值与新值冲突会直接影响行动，请使用 `项目/_模板-事实记录.md`，并坚持“一条事实一个文件”。每个版本声明稳定 `fact_key`、`valid_from`；新版本通过 `supersedes` 精确指向旧文件，并在写入请求中提供 `evidence_ref`。系统只接受同 scope、同 key、日期向前且无分叉/环的显式边；不会根据“作废、现在、替代”等正文词语，也不会根据更新时间或相似度自动判旧。默认检索排除已替代版本，`--as-of` 可恢复历史时点；多个未建立关系的当前版本会阻断 canonical retrieve。

任务结束时建议使用统一收尾入口。它会读取当前会话认领账本，同时追踪“上次成功 closeout 观察到的提交”之后的 Git 历史，因此 Obsidian Git 等工具提前自动提交也不会造成漏处理。随后执行结构检查、字面与语义双重对账、SQLite 刷新、可选 Zvec 补漏/清理和 Agent evolution 刷新。周审计由唯一的周日 10:30 LaunchAgent 独立负责；Stop 与 closeout 都不会改变它的节奏。全局锁负责串行化，认领账本负责隔离文件归属，两者解决的是不同问题。人工维护全库时可显式使用 `memoryctl ... closeout --global`。

```bash
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor codex closeout --dry-run
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor codex closeout
```

写入正式记忆前，可以先让脚本做一次对账，判断应该新建、更新旧文件、跳过、还是需要人工合并：

```bash
scripts/memoryctl --actor codex prewrite "准备写入的记忆摘要" \
  --source-class local_verified --knowledge-kind fact \
  --asserted-by codex --evidence-ref "local-check:example"
```

`prewrite` 先过来源与敏感信息闸门，再做查重对账。`--source-class` 说明信息从哪里来，`--knowledge-kind` 说明它是事实、偏好、规则、推断还是假设；`--asserted-by` 记录主张者，`--evidence-ref` 只以哈希进入安全日志。外部不可信内容、Agent 自己推断的权威事实，以及来源不明的内容，不能悄悄升级成正式事实。

`zvec_raw_distance` 始终是模型返回的原始距离，向量层不再混入词面奖励。生产候选由 Zvec、Unicode FTS 与 trigram FTS 经过固定权重 RRF 合并；RRF 只决定召回顺序，不能单独触发 `UPDATE` 或 `MERGE_REQUIRED`。

### 全库写入网关与并发边界

新安装的 canonical 配置是 `[write_gateway] mode="enforce", full_vault=true`。这意味着所有
正式 Markdown 都必须走高层 `read-target → prepare → apply`；旧 `[write_intents]` 只供迁移
兼容，不能再把普通文件当成 direct-edit 旁路。低层 intent/claim CLI 是维护与诊断接口，
尤其不能公开用 `intent finalize --outcome completed` 绕过 Git blob、raw hash 与 fence 校验。

同一路径的 active intent 唯一索引负责排他，`memory_path_fences` 负责跨过期与换主仍严格
单调的 token。apply 在共享锁内做文件 CAS；closeout 在同一锁域内重新检查 exact raw、
canonical、Git blob、live lease 与精确 claim，并以单个 `BEGIN IMMEDIATE` 批量完成 receipt、
observation、claim 和 intent。一个批次任一项失败就全部回滚。DB commit 后若文件又漂移，
系统不能撤销已经形成的 Git/receipt 事实，而是持久写入 unresolved closeout incident；Doctor
与 Stop Hook 在人工解决前 fail closed。

本地 CLI 是强“防误用”边界，不是对同一系统账号下恶意程序的操作系统安全边界。若要阻止
故意绕过 CLI 的写入，需要把 Vault 对 Agent 挂成只读，并由独立账号或 broker 代理写入。

audit 可以手动运行；自动运行只有每周日 10:30 的 canonical LaunchAgent：

```bash
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor human audit --json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor human audit-autorun --reason manual --json
```

当 7 天闸门真正到期时，autorun 会在内容 audit 后顺带运行一次只读 Doctor，把基础设施结果写到 `reports/latest-doctor.json`。因此远端备份滞后、旧会话认领、模型/Python 断链和 Hook 漂移不只靠人工发现；有内容 finding 或 Doctor 变黄时才通知。

全链路健康检查：

```bash
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor human doctor --json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor human doctor --repair-derived  # 只重建派生索引，不改 Markdown
```

Doctor 还会检查语义检索虚拟环境的基础 Python 是否仍存在、会话认领是否卡死，以及记忆 Git 提交是否长期没有推送。默认容忍少量刚生成的本地提交；记忆提交累计到 10 个，或最老一条超过 3 天仍未推送时才报警，避免日常噪声。

可选的 Stop Hook、macOS `launchd` 与 Windows Task Scheduler 周期兜底见 [docs/automation.md](docs/automation.md)。Windows 兼容边界见 [docs/windows-compatibility-audit.md](docs/windows-compatibility-audit.md)。

## 可选：语义检索

SQLite 适合关键词明确的问题；向量检索适合“只记得意思，不记得原词”的问题。这个模板把语义检索做成可选旁路，不替代 Markdown 和 SQLite。

安装可选依赖：

```bash
python3 -m venv "$HOME/.config/agent-memory/.venv"
"$HOME/.config/agent-memory/.venv/bin/python" -m pip install -U pip
"$HOME/.config/agent-memory/.venv/bin/python" -m pip install -r requirements-vector.lock
```

默认 embedding 模型是 `google/embeddinggemma-300m`。首次下载后，生产用法建议把固定 revision 复制或 APFS 克隆到 Runtime 自管目录，配置 `require_local_model = true`、本地 `embedding_model` 路径和 `model_manifest`。这样清理 Hugging Face 通用缓存也不会让语义检索突然失效。模型缓存、自管模型和向量库都只应保存在本地，不要提交到公开仓库。

```bash
memoryctl --actor migration index --init --scan --report
memoryctl --actor migration zvec --init --scan --prune --json
memoryctl --actor migration zvec --report --json
memoryctl --actor codex search "只记得大概意思的问题" --semantic-mode required --limit 5
```

对比 SQLite 和向量检索：

```bash
memoryctl --actor migration retrieval-benchmark --limit 5 --runs 3 --json
```

公开仓库只放假数据 benchmark。真实 vault 的 benchmark 文件应放在 Git 之外；显式传入私有文件时，默认输出只显示 case id、哈希、长度和名次，不打印查询原文、命中正文或绝对路径。只有在本机人工排查且明确接受暴露时，才使用 `--show-private-details`。

对账与来源安全分别使用独立试卷；公开仓库只带六类对账动作和三类安全结果的假样例：

```bash
scripts/memoryctl --actor codex policy-benchmark --kind reconcile --json
scripts/memoryctl --actor codex policy-benchmark --kind safety --json

# 显式传入的文件一律默认当私有数据脱敏输出
scripts/memoryctl --actor codex policy-benchmark \
  --benchmark-file "$HOME/.config/agent-memory/benchmarks/reconcile-real-v1.json" --json
```

## 设计原则

1. Markdown 是事实源，SQLite 是索引。
2. 普通记忆直接进入正式目录，不做无意义候选池。
3. Agent 自我进化单独放在 `agent/`，其中 case 和 skill 候选用于复用经验沉淀。
4. 用正交字段过滤记忆：`user_id`、`agent_id`、`app_id`、`project_id`、`session_id`、`track`、`memory_type`、`status`。
5. 语义检索只作为候选召回层，最终答案必须回读 Markdown 原文。
6. closeout 负责“任务结束后的自动整理”，audit 负责“定期发现要复核、合并或忽略的记忆”，但二者都不自动改写事实层。
7. API key、模型缓存、SQLite、audit 裁决库和向量库只放本地，永远不写进 Markdown 记忆和公开仓库。
8. `verified_at` 必须区分真实复核与文件 mtime 回退；不同记忆类型用 `review_after_days` 设置不同复核周期。
9. 统一搜索会同时合并关键词与语义结果，所有筛选在合并后再次执行，并用距离阈值拒绝“硬凑出来”的无关近邻。
10. audit 通过机器可读不变量检查当前摘要、核心路径、脚本前缀和 scope；实时计数不要长期手写在摘要里。
11. 原始相似度只负责写入判断，排序分只负责候选顺序；两者不能混用。
12. 项目事实默认硬隔离；跨项目内容和过期内容都只能作参考，不能直接授权动作。
13. 高影响文件可启用写入意图，把“批准了哪一版”绑定到目标、会话、提案哈希和最终回执。
14. 面向宿主注入正文时，索引命中只是候选；必须用只读 retrieve 回读当前 Markdown、重验 frontmatter，并只返回有界摘要和内容指纹。

## 致谢

本项目的部分设计思路受 [EverOS](https://github.com/EverMind-AI/EverOS) 启发，详见 [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md)。
