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
python3 scripts/memoryctl --actor codex search "查询词" --limit 5
python3 scripts/memoryctl --actor claude search "查询词" --limit 5
```

它会先查 SQLite/FTS；启用语义索引时，也可以并行查 Zvec。Zvec 命中只能当作候选线索，最终回答前必须回读 Markdown 原文。

## 写入规则

正式写入前先做对账，避免重复记忆越写越多：

```bash
python3 scripts/memoryctl --actor <codex|claude> prewrite "准备写入的记忆摘要"
```

对账动作只允许这 6 种：

- `ADD`：新建记忆。
- `UPDATE`：更新已有记忆。
- `NOOP`：不写。
- `MARK_OUTDATED`：旧信息过时，但不删除。
- `MERGE_REQUIRED`：疑似重复或冲突，需要人工合并。
- `ASK_USER`：涉及敏感、删除、费用、账号、凭证或不确定判断时先问用户。

每次新建或修改正式记忆后，立即把文件认领到当前 Agent 会话：

```bash
python3 scripts/memoryctl --actor <codex|claude> claim --file "/absolute/path/to/memory.md"
```

Codex 会自动使用 `CODEX_THREAD_ID`；Claude Code 必须通过 `SessionStart` 运行 `agent_memory_session_hook.py --actor claude`，把官方 Hook payload 的真实 `session_id` 写入 `CLAUDE_ENV_FILE`，供后续 Bash 命令使用。Stop Hook 只处理当前会话认领的文件，其他会话的脏文件会明确排除；成功 closeout 会另存文件内容 hash，只有匹配这份完成指纹的历史内容才视为已处理。

重要任务结束前执行 memory closeout：

```bash
python3 scripts/memoryctl --actor <codex|claude> closeout --dry-run
python3 scripts/memoryctl --actor <codex|claude> closeout
```

在 Agent 会话内，`memoryctl closeout` 会按当前会话的认领账本执行结构检查、写入后对账、SQLite 刷新、可选 Zvec 刷新、Agent evolution 刷新、audit 捎带触发、closeout 日志写入，并只提交本会话认领的文件。只有人工维护时才使用 `--global` 做全库收尾。

如果 closeout 输出 `MERGE_REQUIRED`、`ASK_USER`、删除文件状态、疑似历史脏变更，先停下让用户确认。

普通记忆直接写入正式目录：`用户记忆/`、`项目/`、`工作流/`、`决策/`。Agent 复用经验写入 `agent/cases/` 或 `agent/case-candidates/`。多次复用、可抽象成流程的经验，写入 `agent/skill-candidates/`，正式升级 skill 前需要用户确认。

## Audit 规则

audit 用来发现需要复核、合并或忽略的记忆，不直接改写 Markdown 事实层。

```bash
python3 scripts/agent_memory_audit.py
python3 scripts/agent_memory_audit.py --ignore FINDING_ID --note "保留原因"
python3 scripts/agent_memory_audit_autorun.py --reason closeout --min-interval-days 7
python3 scripts/agent_memory_doctor.py
```

推荐让 closeout 每 7 天捎带检查一次 audit 是否该运行。audit findings 应该由用户或 Agent 明确裁决，避免报告本身变成新的 open-loop 噪声。

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
agent_scope: shared
created_by: human | codex | claude
last_updated_by: human | codex | claude
session_id: ""
status: active
sensitivity: normal
verified_at: 2026-06-20
review_after_days: 90
keywords:
  - example
---
```

## 安全边界

- 不要把 API key、token、cookie、密码写入 Markdown。
- 不要把私密原始聊天全文写入公开仓库。
- 不要把 SQLite 数据库提交到 Git。
- 搜索日志只保存查询哈希、长度、来源和耗时，不保存新的查询原文。
- 对外分享前必须脱敏。
- Claude Code 原生 auto-memory 不应直接指向正式 vault；可停用，或只把它当作非正式草稿层。
