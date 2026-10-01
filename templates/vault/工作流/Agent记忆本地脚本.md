---
memory_type: workflow
track: workflow
project_id: agent-memory-vault-scripts
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
agent_scope: shared
session_id: ""
status: active
sensitivity: normal
temporal_policy: reviewable
verified_at: 2026-06-20
review_after_days: 180
keywords:
  - scripts
  - sqlite
---

# Agent 记忆本地脚本

## 当前有效摘要

本模板提供以下本地脚本：

- `agent_memory_index.py`：全库 Markdown 索引和搜索。
- `agent_memory_search.py`：统一检索入口，合并 SQLite、可选 Zvec 和手动 rg 结果。
- `agent_memory_retrieve.py`：回读当前 Markdown；支持默认有界摘要、标题大纲和 source-hash 约束的按节分页。
- `agent_memory_observability.py`：可选任务级事件与 30 天分源报表；不保存 prompt、回答或原始 session。
- `agent_memory_shadow.py`：把 Hybrid v2 与旧记忆采用阻断绑定到当前 Runtime manifest 的七天影子门禁；只有 migration actor、三次私有检索基准、隐私安全 canary 和唯一配置备份齐备后才能切换。真实失败不得原地清除；治理修复后只能用绑定当前 head 的 `shadow restart` 追加不可变子 epoch，并重新积累全部门禁证据。
- `agent_memory_safety.py`：在检索和对账前检查来源、知识类型和敏感信息。
- `agent_memory_closeout.py`：任务结束收尾，负责检查、对账、刷新索引和可选 scoped commit；不接管周审计。
- `agent_memory_claim.py`：把当前 live intent 投影为会话 claim，并在单个事务里批量写 receipt、observation 与完成状态。
- `agent_memory_intent.py`：为每个 canonical path 建立唯一 lease、单调 fencing token、内容绑定批准和不可变回执。
- `agent_memory_write.py`：Codex、Claude、Ailu 共用的 `read-target → prepare → apply/cancel` 正式写入网关。
- `agent_memory_migrate.py`：state v4 的只读 plan、fresh init、带不可覆盖备份的 apply、只读 verify 和显式 ready 发布。
- `agent_memory_audit.py`：定期体检，发现过期记忆、重复标题、open-loop 噪声和已过时状态。
- `agent_memory_audit_autorun.py`：自动触发器，只在超过设定间隔时运行内容 audit，并顺带执行只读 Doctor，把基础设施健康报告写入 `latest-doctor.json`。
- `agent_memory_doctor.py`：统一体检 Markdown、SQLite、FTS、INDEX、Zvec、远端备份、会话认领、语义 Python、验证来源和自动化状态。
- `agent_memory_stop_hook.py`：Stop 事件节流提醒或受控 closeout fallback；不运行或重排周审计。
- `agent_memory_evolution.py`：Agent case 和 skill 候选状态统计。
- `agent_memory_check.py`：结构、frontmatter、SQLite、泄密风险检查。
- `agent_memory_zvec_index.py`：可选 Zvec 语义索引和搜索。
- `agent_memory_retrieval_benchmark.py`：对比 SQLite 和向量检索召回效果。
- `agent_memory_decision_outcomes.py`：检查已有决策是否补了结果、复盘日期和证据。

## 环境变量

```bash
AGENT_MEMORY_ROOT=/path/to/your/agent-memory-vault
AGENT_MEMORY_GIT_ROOT=/path/to/git-root-containing-the-vault
AGENT_MEMORY_CONFIG_ROOT=$HOME/.config/agent-memory
AGENT_MEMORY_STATE_DB=$HOME/.config/agent-memory/state.sqlite
AGENT_MEMORY_USER_ID=demo-user
AGENT_MEMORY_AGENT_ID=codex
AGENT_MEMORY_APP_ID=codex
AGENT_MEMORY_AUDIT_DB=$HOME/.config/agent-memory/audit_decisions.sqlite
AGENT_MEMORY_CLOSEOUT_LOG=$HOME/.config/agent-memory/logs/closeout.jsonl
AGENT_MEMORY_PYTHON=python3
AGENT_MEMORY_ZVEC_PYTHON=python3
AGENT_MEMORY_VECTOR_DIR=$HOME/.config/agent-memory/zvec/memory_chunks_embeddinggemma_768
AGENT_MEMORY_EMBEDDING_MODEL=google/embeddinggemma-300m
AGENT_MEMORY_OBSERVABILITY_ENABLED=false
```

## 常用命令

```bash
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor migration index --init --scan --report
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor codex search "关键词" --limit 5
AGENT_MEMORY_SESSION_ID="host-session-id" \
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor codex write read-target --json <<'JSON'
{"schema_version":2,"target_relative_path":"项目/example.md","app_id":"example-app","project_id":"example-project"}
JSON
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor migration migrate verify --json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor human audit --json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor human audit-autorun --reason manual --json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor human doctor --json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor migration check
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor migration zvec --init
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor migration zvec --scan --prune
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor migration zvec --report
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor codex zvec --search "只记得大概意思的问题" --limit 5
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor migration retrieval-benchmark --limit 5
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor migration shadow start --benchmark-file <runtime>/benchmarks/private-quality.json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor migration shadow restart --benchmark-file <runtime>/benchmarks/private-quality.json --supersede-epoch '<current-epoch-attestation-sha256>'
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor migration shadow status --json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor codex decision-outcomes --json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor codex retrieve --view outline --file "项目/example.md" --project-id example-app --json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor codex observe current --json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor codex observe report --days 30 --json
```

## 检索边界

- `zvec_raw_distance` 是模型原始距离，只用于阈值和写入对账；`zvec_rank_distance` 只用于排序。rank 再靠前，也不能单独触发写入。
- 项目任务用 `--current-project <project-id>`；任何带有非 `global/shared` `project_id` 的记忆都默认硬隔离，显式 `--cross-project` 才能看其他项目类比，且不能据此授权动作。
- 没有 `project_id` 的内容按未限定共享参考处理；只有明确标成 `global` 或 `shared` 才是全局共享。检索结果始终不替代当前授权或实时确认。
- `valid_until` 到期的条目仍会召回并标记 `expired`，但必须实时核验。

## 全库正式写入

新安装使用 `[write_gateway] mode="enforce", full_vault=true`。所有正式 Markdown 都走
`read-target → prepare → apply`，不能先直接编辑再补低层 claim。prepare 重传完整最终正文、
read token、来源/知识类型/证据引用，只获取唯一 path lease 与单调 fence，不改文件；apply
重传 exact proposal id、raw/canonical hash、fence 与这版提案的授权引用，再做文件 CAS。
closeout 在同一锁域中重新检查 live lease、fence、raw bytes 与 Git blob，并以一个数据库事务
批量完成 receipt、observation、claim 与 intent；任一项失败则全部回滚。

Ailu 固定 `app_id=ailu`，`project_id` 必须是单个实际项目或 `global`，global 只写
`用户记忆/`，且不能写根治理文件。根 `AGENTS.md`、`README.md`、`STRUCTURE.md` 只允许
Codex/Claude 在 agent-memory governance scope 下通过同一网关写入。`INDEX.md` 是机器生成
只读投影，只能由 closeout 与源文件在同一个 Git 事务里刷新；直接写入返回
`GENERATED_FILE_READ_ONLY`。

人工/Obsidian 外部编辑必须重新 read-target 后 prepare；或由 Codex/Claude 在明确用户授权下
以 `adopt_external: true` 收养“当前文件的精确字节”。ADOPT 仍做 safety、对账、lease/fence、
CAS、Git 与 closeout。post-finalize 漂移会形成 unresolved incident，并全局阻断 Stop/Doctor；
只有同 target 后续 exact ADOPT 可在 finalize 同一事务里自动解除，没有手工裸 resolve。

新装 state 用 `migrate init`；已有库先 `migrate plan`，再用从未存在的私有 backup path 执行
`migrate apply`。`migrate verify` 默认只读；完成索引、Doctor、Hook 检查后才运行
`migrate verify --publish-ready`。任何活跃的未知 actor 都会统一阻断迁移。

真实 benchmark 文件必须留在公开仓库之外。默认报告只显示 id、哈希、长度和名次；不要开启明文详情，除非正在本机人工排查并明确接受暴露。

## 下次优先看

- 修改目录结构后，先更新字段规范，再跑检查脚本。
