---
memory_type: workflow
track: workflow
project_id: agent-memory-vault-closeout
app_id: {{APP_ID}}
user_id: {{USER_ID}}
agent_id: {{AGENT_ID}}
agent_scope: shared
session_id: ""
status: active
risk_class: ordinary
sensitivity: normal
temporal_policy: reviewable
review_after_days: 180
keywords:
  - closeout
  - memory
  - 对话结束
  - 自动归档
  - 记忆收尾
  - 对话结束归档
---

# Agent 记忆收尾决策规则

## 当前有效摘要

普通记忆不设候选池。“对话结束”“自动归档”“记忆收尾”和“对话结束归档”都指向同一套 closeout 流程。每次重要任务结束时，由 Agent 判断是否有稳定事实需要直接写入正式目录；写入前先对账，写入后用 closeout 自动整理。

- 真实用户表达别名：对话结束、自动归档、记忆收尾、对话结束归档、Codex 每次对话结束怎么自动归档。

## 写入前对账

写入前先运行：

```bash
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl \
  --actor codex prewrite "准备写入的记忆摘要" \
  --source-class user_direct \
  --knowledge-kind fact \
  --asserted-by human \
  --evidence-ref "当前对话或可复核的本地事实"
```

根据结果选择：

- `ADD`：没有相近旧记忆，可以新建。
- `UPDATE`：已有同主题文件，优先更新旧文件。
- `NOOP`：没有长期价值，不写。
- `MARK_OUTDATED`：旧事实过时，在旧文件中标注过时。
- `MERGE_REQUIRED`：疑似重复或冲突，先让用户确认。
- `ASK_USER`：涉及敏感、删除、账号、凭证、费用或高不确定性时先问用户。

## 写入哪里

- 用户稳定偏好或边界：`用户记忆/`
- 某个项目的当前状态：`项目/`
- 可复用的方法流程：`工作流/`
- 明确取舍和原因：`决策/`
- Agent 解决某类问题的经验：`agent/cases/`
- 可能值得升级成 skill 的流程：`agent/skill-candidates/`

## 不写入什么

- API key、token、cookie、密码。
- 一次性闲聊。
- 未验证猜测。
- 已经写过且没有新增信息的重复内容。

## Agent case 规则

满足下面条件时，可以写入 `agent/cases/`：

- 任务已经完成或失败原因清楚。
- 过程对未来有复用价值。
- 能说清楚触发条件、操作步骤、风险和验证方式。

## Skill 候选规则

满足下面条件时，可以写入 `agent/skill-candidates/`：

- 同类 case 至少复用 3 次。
- 至少有 2 条有效证据。
- 步骤稳定，不依赖某个临时项目。
- 风险可控。

正式升级为 skill 前，需要询问用户。

## 收尾动作

写完记忆后优先运行统一 closeout：

```bash
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor codex closeout --dry-run
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor codex closeout
```

它会自动完成：

- Git 自动发现变更文件。
- 检查结构、frontmatter、泄密和变更文件膨胀。
- 对新文件做写入后查重。
- 刷新 SQLite 索引。
- 可选刷新 Zvec 语义索引。
- 必要时刷新 Agent evolution。
- 不运行或重排周审计；周审计始终由周日 10:30 的唯一调度器负责。
- 写入 closeout 日志。
- 只提交本轮处理过的记忆文件。

如果输出 `MERGE_REQUIRED`、`ASK_USER`、删除文件状态或疑似历史脏变更，不要强行提交。

## Audit 体检

audit 负责发现需要复核、合并或忽略的记忆，不直接修改 Markdown。

```bash
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor human audit --json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor human audit --ignore FINDING_ID --note "保留原因" --json
<runtime>/.venv/bin/python -I -S <runtime>/scripts/memoryctl --actor human audit-autorun --reason manual --json
```
