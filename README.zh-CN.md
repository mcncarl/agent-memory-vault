# Agent Memory Vault: Shared Claude Code + Codex

[English](./README.md) | **简体中文**

这是一个可由 Claude Code 与 Codex 共用的长期记忆库模板。它把普通 Markdown 文件当作唯一长期事实源，用 SQLite 建全库索引，并用少量固定字段支持按用户、Agent、项目、应用、会话和记忆类型过滤。需要语义检索时，也可以额外启用本地 EmbeddingGemma + Zvec 向量旁路。

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
  agent_memory_write.py  # 宿主程序用的 read-target/prepare/apply/cancel 边界
  agent_memory_safety.py # 写入前来源、知识类型和敏感内容闸门
  agent_memory_claim.py  # 会话文件认领账本，防止 Claude/Codex 串提交
  agent_memory_intent.py # 受保护文件的写入意图、审批绑定和不可变回执
  agent_memory_closeout.py
                          # 任务结束收尾：检查、对账、刷新索引、审计、可选提交
  agent_memory_audit.py  # 定期体检：过期、重复、open-loop、裁决记录
  agent_memory_audit_autorun.py
                          # audit 自动触发器：超过间隔才运行
  agent_memory_doctor.py  # 全链路体检：Markdown/SQLite/FTS/Zvec/Git/自动化
  agent_memory_session_hook.py
                          # Claude SessionStart 会话 ID 桥接，防止与外层 Codex 串号
  agent_memory_stop_hook.py
                          # 可选 Stop 自动 closeout + 到期 audit
  install_runtime.py     # 把当前 Git 版本安装为可校验的本机 Runtime
  memoryctl               # Claude/Codex 共用的平台中立命令入口
  agent_memory_zvec_index.py
  agent_memory_retrieval_benchmark.py
  agent_memory_decision_outcomes.py
  agent_memory_evolution.py
  agent_memory_check.py
```

## 快速开始

```bash
git clone https://github.com/mcncarl/agent-memory-vault.git
cd agent-memory-vault
cp .env.example .env
```

编辑 `.env`，把 `AGENT_MEMORY_ROOT` 改成你的本地记忆库路径。它可以只是一个普通文件夹；如果你使用 Obsidian，也可以把这个文件夹作为 Obsidian vault 打开。

脚本会安全解析仓库根目录的 `.env`，不依赖 shell 是否把变量 `export` 给子进程。若源码仓库里既没有 `.env`、也没有 Runtime TOML，所有 SQLite、日志和向量等派生状态会落到仓库内已忽略的 `.agent-memory/`，不会误用另一套已安装记忆系统的正式状态库。

```bash
python3 scripts/bootstrap.py --memory-root "$HOME/agent-memory-vault" --write-env
source .env
python3 scripts/agent_memory_evolution.py --init --scan --report
python3 scripts/agent_memory_index.py --init --scan --report
python3 scripts/agent_memory_check.py
python3 scripts/agent_memory_doctor.py
```

`bootstrap.py` 默认初始化独立 Git 仓库并提交一份仅含模板文件的首个基线；如已有 `HEAD` 会保持不动。只有明确不需要 Git 时才加 `--no-init-git`。模板自带 `.gitignore`，会排除 Obsidian 的 `.obsidian/` 界面状态。

Windows 10/11 请直接使用 PowerShell 安装器，完整步骤见 [docs/windows.md](docs/windows.md)：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 `
  -MemoryRoot "$HOME\Documents\Agent Memory Vault"
```

需要让多个 Agent 从固定本机入口调用时，可把 GitHub 仓库作为唯一源码安装到 Runtime；升级时重复运行同一命令即可，私人 TOML 和本机适配器不会被覆盖：

```bash
python3 scripts/install_runtime.py --config-root "$HOME/.config/agent-memory"
cp config/agent-memory.example.toml "$HOME/.config/agent-memory/config/agent-memory.toml"
# 编辑 TOML 中的 memory_root / git_root / state_db
"$HOME/.config/agent-memory/scripts/install_runtime.py" \
  --config-root "$HOME/.config/agent-memory" --verify --json
```

## Claude Code 与 Codex 共用

保持一个 Markdown vault、一个 Git 基线、一个 SQLite、一个 Zvec 和一个 audit 调度器。两个宿主只维护薄适配层：

- Codex 的 `AGENTS.md` 指向 vault 规则。
- Claude Code 的 `CLAUDE.md` 使用 `@/absolute/path/to/AGENTS.md` 导入同一规则。
- Claude Code 原生 auto-memory 不要指向正式 vault；推荐关闭，或只把它当作非正式草稿层。
- 两端通过 `memoryctl --actor codex|claude` 使用同一搜索和 closeout。

```bash
python3 scripts/memoryctl --actor claude search "项目状态" --limit 5
python3 scripts/memoryctl --actor codex prewrite "准备写入的记忆摘要" \
  --source-class user_direct --knowledge-kind fact \
  --asserted-by user --evidence-ref "current-conversation"
python3 scripts/memoryctl --actor codex claim --file "/absolute/path/to/changed-memory.md"
python3 scripts/memoryctl --actor claude closeout
```

写完正式记忆后先 `claim`。认领记录保存在 SQLite，只存 session id 的哈希；Agent 会话内的 closeout 和 Stop Hook 只处理本会话认领的文件，其他会话的脏文件明确排除。成功 closeout 还会记录每个文件的内容 hash，只有具备这份完成证据的历史文件才允许 Git 观察基线跨过。普通事实默认 `agent_scope: shared`；只有宿主特有经验才标为 `codex` 或 `claude`。

当前会话没有 claim、也没有任何待处理正式记忆时，手动 closeout 和 dry-run 都会作为成功的 no-op 退出；如果确实存在无人认领的记忆变更，仍会返回错误并要求先认领，不能用 no-op 绕过归属检查。

Claude 的 `Stop` 和 `SessionEnd` 使用不同生命周期语义：`Stop` 可以在首次真实失败时请求 Claude 继续处理，但检测到 `stop_hook_active=true` 后不得重复阻断；`SessionEnd` 只做 60 秒内的非阻断兜底，不运行周审计，失败只发本机通知。两类运行分别记录为 `trigger=stop-hook` 与 `trigger=session-end`。对 `codex`/`claude` 执行 `memoryctl closeout` 默认必须具备宿主 session 或显式 `--session-id`，只有明确传入 `--global` 才允许全库维护。

异常退出可能留下旧认领。Stop Hook 不会继续信任超过 24 小时的认领，Doctor 会把它列为警告。清理时先预览，再显式应用；这只把 SQLite 账本状态改为 `expired`，不会删除或改写 Markdown：

```bash
python3 scripts/memoryctl --actor human claims-expire --older-than-hours 24 --json
python3 scripts/memoryctl --actor human claims-expire --older-than-hours 24 --apply --json
```

如果一个正式 Markdown 已经按用户明确指令移入系统垃圾篓、又被外部备份工具提前提交为 Git 删除，可由人工维护显式登记可恢复删除。命令默认只预览；只有 `--apply` 才会写入审计表和 `deleted:<commit>:<prior_sha256>` 观察指纹。它会核对目标当前缺失、删除提交属于当前历史、父提交确实包含并删除该文件，以及垃圾篓副本与删除前 Git blob 完全一致。`evidence-ref` 和垃圾篓绝对路径只保存哈希，不写入正文或输出：

```bash
python3 scripts/memoryctl --actor human observe-deletion \
  --file "/absolute/vault/项目/已删除.md" \
  --trash-path "$HOME/.Trash/已删除.md" \
  --deletion-commit "40-hex-commit" \
  --evidence-ref "current-user-authorization-reference" \
  --confirm-user-authorized --json

# 逐项确认预览后才应用：
python3 scripts/memoryctl --actor human observe-deletion \
  --file "/absolute/vault/项目/已删除.md" \
  --trash-path "$HOME/.Trash/已删除.md" \
  --deletion-commit "40-hex-commit" \
  --evidence-ref "current-user-authorization-reference" \
  --confirm-user-authorized --apply --json
```

如果正文已经由历史会话精确验证并提交，但 closeout 在写入 observation 前中断，后来该 intent 仅因 TTL 到期，可用原始 `intent_id` 恢复已有文件的观察。这个入口不会改正文；它只接受 `user_direct + ALLOW + exact + early_commit` 的完整 intent/receipt 链，要求当前文件等于 `HEAD`，原 proposal commit 仍是该路径最新变更，且目标没有活动 intent、claim 或未提交 Git 状态。命令同样默认预览，`--apply` 才写审计：

```bash
python3 scripts/memoryctl --actor human observe-committed \
  --file "/absolute/vault/用户记忆/偏好与边界.md" \
  --intent-id "32-hex-expired-intent" \
  --evidence-ref "historical-user-authorization-reference" \
  --confirm-user-authorized --json

# 核对预览后应用：
python3 scripts/memoryctl --actor human observe-committed \
  --file "/absolute/vault/用户记忆/偏好与边界.md" \
  --intent-id "32-hex-expired-intent" \
  --evidence-ref "historical-user-authorization-reference" \
  --confirm-user-authorized --apply --json
```

搜索示例：

```bash
python3 scripts/agent_memory_search.py "项目 收尾" --limit 5
python3 scripts/agent_memory_search.py "偏好" --track user
python3 scripts/agent_memory_search.py "复用流程" --memory-type workflow
python3 scripts/agent_memory_search.py "部署边界" --current-project example-app
```

需要给宿主程序注入正式记忆正文时，不要直接相信 SQLite/Zvec 中的摘要，使用只读
`retrieve` 再次核对当前 Markdown：

```bash
python3 scripts/memoryctl --actor yichen-content-studio retrieve --json <<'JSON'
{"schema_version":1,"query":"当前任务","app_id":"yichen-content-studio","project_id":"yichen-content-studio","max_results":5,"max_file_bytes":1048576,"max_total_bytes":4194304,"max_excerpt_bytes":12288}
JSON
```

该命令不回显查询原文，只返回 `query_hash`；索引只负责提供候选，每个候选都要重新
通过 Vault containment/symlink 检查、严格 UTF-8 读取、当前 frontmatter 的
`status`/`agent_scope`/`app_id`/`project_id` 过滤和敏感内容检查。结果包含相对路径、
当前文件 SHA-256、`verified_at`、Git HEAD、策略与实时核验提示，以及优先取自
`## 当前有效摘要` 的有界 excerpt。单文件问题是结构化 warning；Vault 根目录或协议
参数不安全时才整体失败。Studio actor 固定要求精确
`app_id=yichen-content-studio`：项目通道传非空 `project_id` 时只接受该精确项目；创作
通道省略 `project_id`，只接受同 app 的 `global` / `shared` / 未限定记忆。查询只能从
受控 stdin JSON 进入，不能出现在 argv。读取过程使用 `search --no-log` 等价的只读索引路径，不写
Markdown、SQLite 或搜索日志。

`yichen-content-studio` 是运行 actor，不是事实断言者。中央入口只允许它调用
`retrieve`、`write` 和 `version`；低级 `prewrite` / `intent` / `claim` / `closeout` /
`check` 等全部 fail closed。高级 `write prepare` 仍必须把 `asserted_by` 明确写成
`user`、`claude`、`codex` 或 `opencode`，不能把应用名冒充信息来源。

### 宿主程序的显式两阶段写入

`write` 是给本地宿主 UI 的高级边界，目前只接受
`--actor yichen-content-studio`。请求 JSON 只能从 stdin 传入；插件要生成自己的
`AGENT_MEMORY_SESSION_ID`，不得继承外层 `CODEX_THREAD_ID` 或 Claude 会话 ID，也不能
用 `--session-id`、等号写法或 argparse 缩写把 session 放进 argv。

构造 `UPDATE` 前必须先用 `read-target` 读取目标的完整当前内容，再在这份
全文上编辑或追加。不能把 Agent 新回答直接当成整份目标，否则会丢掉
旧记忆。该读取只接受正式相对 `.md` 路径，使用 containment/symlink、严格
UTF-8 和 2 MiB 限制，并重新验证 active、shared、app/project scope 与 secret；返回
`base_exists`、完整 `content`、两种 base hash、`base_git_head` 和会话/目标绑定的
`read_token`，
不加写锁、不写 state DB/日志/Markdown：

```bash
AGENT_MEMORY_SESSION_ID="host-session-id" \
python3 scripts/memoryctl --actor yichen-content-studio write read-target --json <<'JSON'
{"schema_version":1,"target_relative_path":"用户记忆/example.md","app_id":"yichen-content-studio"}
JSON
```

`prepare` 先做来源安全、查重、目标选择和基线绑定。它会记录不含正文的
安全审计；只有 `ADD`/`UPDATE` 才会创建私有提案元数据。它绝不修改正式
Markdown：

```bash
AGENT_MEMORY_SESSION_ID="host-session-id" \
python3 scripts/memoryctl --actor yichen-content-studio write prepare --json <<'JSON'
{"schema_version":1,"summary":"durable preference summary","proposal_markdown":"---\nmemory_type: user_preference\ntrack: user\napp_id: yichen-content-studio\nproject_id: global\nagent_scope: shared\nstatus: active\n---\n\n# Example\n","target_relative_path":"用户记忆/example.md","app_id":"yichen-content-studio","read_token":"<read-target returned 64-hex>","source_class":"user_direct","knowledge_kind":"preference","asserted_by":"user","evidence_ref":"conversation:message-ref"}
JSON
```

`prepare` 必须回传同一 session、目标、app/project scope 的 `read_token`。它在全局
Studio 写锁内重读并比较 `exists`、raw/canonical hash 与 Git HEAD；缺 token 的
`UPDATE` 和 `ADD` 都拒绝。项目通道还要在 read-target/prepare 请求和 proposal
frontmatter 中传相同的 `project_id`；创作通道省略请求 `project_id`，proposal 使用
`global` / `shared` 或未限定项目。新 proposal 必须显式写
`status: active`、`agent_scope: shared` 和固定 app id。

返回只允许 `ADD` / `UPDATE` / `NOOP` / `MERGE_REQUIRED`。`prepared` 包含不可变的
`proposal_id`、两种提案 hash、目标、基线和过期时间；`NOOP` 不写，
`MERGE_REQUIRED` 不创建可写提案，两者都不能被 UI 当成可确认写入。

只有用户明确确认后才能调用 `apply`。宿主必须重传同一版正文、prepare
返回的 ID/hash/目标，以及一个不含聊天正文的用户确认引用：

```json
{"schema_version":1,"proposal_id":"<32-hex>","target_relative_path":"用户记忆/example.md","proposal_markdown":"# Example\n","proposal_raw_sha256":"<64-hex>","proposal_canonical_sha256":"<64-hex>","confirmed_by":"user","confirmation_reference":"conversation:confirmed-message-ref"}
```

`apply` 会在同一把全局锁内重新验证会话、目标、基线、ID 和 hash，再按
“claim → 原子条件写入 → 本会话 closeout”完成提交。ADD 用同目录 hard link
做 no-replace 发布；UPDATE 用同文件系统的原子交换先捕获旧目标，再校验被换出的
raw hash。若捕获的不是准备阶段基线，会先独立保留竞态字节并原子换回；任何无法
证明恢复完整的二次竞态都返回 `TARGET_WRITE_RECOVERY_REQUIRED`，保留隐藏 sidecar
供人工恢复，不继续 closeout。当前文件系统不支持安全交换时也 fail closed。
基线漂移、内容变化或查重冲突会结构化失败，不会静默覆盖。如果精确写入后 closeout 失败，文件保持
当前会话的认领状态，必须核对后重试。这种状态调用 `cancel` 会返回
`APPLY_RECOVERY_REQUIRED`，不允许把已改但未收尾的 Markdown 遗留为“已取消”。
closeout transport 使用独立进程组；超时或宿主中断时先 TERM、等待，再 KILL、等待
整组消失，确认孙进程不能继续写后才释放 Studio 全局锁。

用户放弃未应用的提案时，向 `cancel` 的 stdin 传入
`{"schema_version":1,"proposal_id":"<32-hex>"}`。取消不修改 Markdown，同一会话重复取消是
幂等的。

传入 `--current-project` 后，任何带有非 `global/shared` `project_id` 的记忆都受项目硬边界约束，不论它位于项目、工作流还是决策轨道。确实要借鉴别的项目时，必须再加 `--cross-project`，返回项会标成 `analogy_only`，只能参考，不能据此授权执行动作。没有 `project_id` 的内容按未限定共享参考处理；只有明确写成 `global` 或 `shared` 的内容才是全局共享。

有 `valid_until` 的记忆到期后不会从搜索结果里消失。它仍可能解释历史，但会标成 `time_status: expired` 和 `requires_live_verification: true`；凡是当前状态、费用、账号、权限、外部系统等会变化的事实，都要实时核验后再用。

任务结束时建议使用统一收尾脚本。它会读取当前会话认领账本，同时追踪“上次成功 closeout 观察到的提交”之后的 Git 历史，因此 Obsidian Git 等工具提前自动提交也不会造成漏处理。随后执行结构检查、字面与语义双重对账、SQLite 刷新、可选 Zvec 补漏/清理、Agent evolution 刷新，并在 audit 超过间隔时顺手跑一次体检。全局锁负责串行化，认领账本负责隔离文件归属，两者解决的是不同问题。人工维护全库时可显式使用 `memoryctl ... closeout --global`。

```bash
python3 scripts/memoryctl --actor codex closeout --dry-run
python3 scripts/memoryctl --actor codex closeout
```

写入正式记忆前，可以先让脚本做一次对账，判断应该新建、更新旧文件、跳过、还是需要人工合并：

```bash
python3 scripts/memoryctl --actor codex prewrite "准备写入的记忆摘要" \
  --source-class local_verified --knowledge-kind fact \
  --asserted-by codex --evidence-ref "local-check:example"
```

`prewrite` 先过来源与敏感信息闸门，再做查重对账。`--source-class` 说明信息从哪里来，`--knowledge-kind` 说明它是事实、偏好、规则、推断还是假设；`--asserted-by` 记录主张者，`--evidence-ref` 只以哈希进入安全日志。外部不可信内容、Agent 自己推断的权威事实，以及来源不明的内容，不能悄悄升级成正式事实。

相似度的两个数各管一件事：`zvec_raw_distance` 是模型返回的原始距离，只用它做距离阈值和写入对账；`zvec_rank_distance` 是为展示排序加入词面修正后的距离，只决定候选先后。不能拿 rank 值触发 `UPDATE` 或 `MERGE_REQUIRED`。

### 受保护文件的写入意图

高影响文件可以在 TOML 的 `[write_intents]` 中列入 `protected_paths`。`enforcement = "off"` 表示暂不拦截，`"advisory"` 只报告缺少意图，`"enforce"` 则要求先有内容绑定的意图再改文件。升级旧系统时建议从少量精确路径和 `off` 开始，不要一上来保护整个 vault。

标准顺序是“提案在 vault 外 → 创建意图 → 必要时批准 → 先认领再编辑 → closeout 校验并写回执”：

```bash
python3 scripts/memoryctl --actor codex prewrite "准备更新高影响规则" \
  --source-class local_verified --knowledge-kind rule \
  --asserted-by codex --evidence-ref "verified-local-rule" \
  --create-intent \
  --target-file "$AGENT_MEMORY_ROOT/工作流/Agent记忆收尾决策规则.md" \
  --proposal-file "/tmp/agent-memory-proposal.md" --json

# 只有输出要求人工批准时才执行；hash 和批准人必须与该意图绑定
python3 scripts/memoryctl --actor codex intent approve \
  --intent-id "<intent-id>" \
  --target "$AGENT_MEMORY_ROOT/工作流/Agent记忆收尾决策规则.md" \
  --proposal-raw-sha256 "<proposal-raw-sha256>" \
  --proposal-canonical-sha256 "<proposal-canonical-sha256>" \
  --approved-by user \
  --approval-ref "<current-conversation-approval-ref>" --json

# 必须在编辑目标文件之前认领
python3 scripts/memoryctl --actor codex claim \
  --file "$AGENT_MEMORY_ROOT/工作流/Agent记忆收尾决策规则.md" \
  --intent-id "<intent-id>" --json

python3 scripts/memoryctl --actor codex closeout
```

closeout 会核对目标、会话、基础版本和提案内容。完全一致记为 `exact`；只差换行或 Unicode 规范化记为 `format_only`；Markdown 行尾两个空格会产生硬换行，因此算实质内容。实质内容不一致默认只输出 diff 哈希和统计并停下，避免把意外写入的秘密打印到终端；仅在人工排查时显式加 `intent validate --show-private-diff` 才显示有界且经过凭证行脱敏的 diff。若 Obsidian Git 等工具提前提交，只要 Git 版本链连续且提交内容正好匹配提案，系统会恢复这次流程并在回执中标记 `early_commit`。成功或失败都会留下只含哈希、状态和边界元数据的不可变回执。私有 state DB 会保存有字节上限的 canonical proposal snapshot；它不进入回执、搜索索引或 closeout 持久日志。Runtime 私有目录固定为 `700`，state DB、sidecar、配置和持久日志固定为 `600`。

这里的 `approved_by` 与 `approval_ref` 是同一台机器、同一 Agent 信任域里的审批见证，不是独立的密码学用户签名。它能防止误复用旧提案，不能阻止已经控制该本地账号的恶意程序伪造“用户已批准”；需要强对抗保证时，必须由宿主 UI 或独立人工通道签发不可伪造的一次性回执。

来源安全对所有写入都是操作规范，但 Runtime 只对 `protected_paths` 强制验证 intent 与 safety audit。普通项目笔记仍依赖 Agent 遵守“先 prewrite、后 claim/closeout”的流程；这是为了避免把整个 vault 拖进高摩擦审批，不应被描述成对恶意本地程序的强制防线。

audit 可以手动运行，也可以由 closeout 捎带触发：

```bash
python3 scripts/agent_memory_audit.py
python3 scripts/agent_memory_audit_autorun.py --reason manual --json
```

当 7 天闸门真正到期时，autorun 会在内容 audit 后顺带运行一次只读 Doctor，把基础设施结果写到 `reports/latest-doctor.json`。因此远端备份滞后、旧会话认领、模型/Python 断链和 Hook 漂移不只靠人工发现；有内容 finding 或 Doctor 变黄时才通知。

全链路健康检查：

```bash
python3 scripts/agent_memory_doctor.py
python3 scripts/agent_memory_doctor.py --repair-derived  # 只重建派生索引，不改 Markdown
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
python3 scripts/agent_memory_index.py --init --scan --report
"$HOME/.config/agent-memory/.venv/bin/python" scripts/agent_memory_zvec_index.py --init
"$HOME/.config/agent-memory/.venv/bin/python" scripts/agent_memory_zvec_index.py --scan --prune
"$HOME/.config/agent-memory/.venv/bin/python" scripts/agent_memory_zvec_index.py --report
"$HOME/.config/agent-memory/.venv/bin/python" scripts/agent_memory_zvec_index.py --search "只记得大概意思的问题"
```

对比 SQLite 和向量检索：

```bash
"$HOME/.config/agent-memory/.venv/bin/python" scripts/agent_memory_retrieval_benchmark.py --limit 5
```

公开仓库只放假数据 benchmark。真实 vault 的 benchmark 文件应放在 Git 之外；显式传入私有文件时，默认输出只显示 case id、哈希、长度和名次，不打印查询原文、命中正文或绝对路径。只有在本机人工排查且明确接受暴露时，才使用 `--show-private-details`。

对账与来源安全分别使用独立试卷；公开仓库只带六类对账动作和三类安全结果的假样例：

```bash
python3 scripts/memoryctl --actor codex policy-benchmark --kind reconcile --json
python3 scripts/memoryctl --actor codex policy-benchmark --kind safety --json

# 显式传入的文件一律默认当私有数据脱敏输出
python3 scripts/memoryctl --actor codex policy-benchmark \
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
