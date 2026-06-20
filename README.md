# Codex Memory Template

这是一个公开安全的 Codex 长期记忆库模板。它把 Obsidian Markdown 当作长期事实源，用 SQLite 建全库索引，并用少量固定字段支持按用户、Agent、项目、应用、会话和记忆类型过滤。

这个仓库只包含模板、脚本和假示例，不应该包含你的真实记忆、真实路径、API key、私人项目名或聊天原文。

## 它解决什么问题

- 让 Codex 每次开始重要任务时，先读最相关的长期记忆。
- 让每次任务结束时，把稳定事实、项目状态、工作流和 Agent 经验沉淀到 Markdown。
- 让 Markdown 仍然是源文件，SQLite 只做索引和搜索，不替代 Obsidian。
- 让公开仓库可以安全分享，真实信息留在本地私有 vault。

## 核心结构

```text
templates/vault/
  AGENTS.md              # Codex 读取和写入规则
  INDEX.md               # 记忆路由索引
  用户记忆/              # 用户偏好、边界、长期画像
  项目/                  # 项目级状态和结论
  工作流/                # 可复用流程、字段规范、收尾规则
  决策/                  # 权衡和取舍
  agent/                 # Agent case、skill 候选、未闭环事项

scripts/
  bootstrap.py           # 从模板创建本地私有 vault
  codex_memory_index.py  # 全库 SQLite 索引和搜索
  codex_agent_evolution.py
  codex_memory_check.py
```

## 快速开始

```bash
git clone https://github.com/your-name/codex-memory-template.git
cd codex-memory-template
cp .env.example .env
```

编辑 `.env`，把 `CODEX_MEMORY_ROOT` 改成你的本地 Obsidian 记忆库路径。

```bash
python3 scripts/bootstrap.py --memory-root "$HOME/obsidian/Codex记忆" --write-env
source .env
python3 scripts/codex_agent_evolution.py --init --scan --report
python3 scripts/codex_memory_index.py --init --scan --report
python3 scripts/codex_memory_check.py
```

搜索示例：

```bash
python3 scripts/codex_memory_index.py --search "项目 收尾" --limit 5
python3 scripts/codex_memory_index.py --search "偏好" --track user
python3 scripts/codex_memory_index.py --search "复用流程" --memory-type workflow
```

## 公开发布前检查

发布到 GitHub 前至少执行：

```bash
python3 scripts/codex_memory_check.py
find . -name "*.sqlite" -o -name ".env" -o -name "*.key"
```

确认仓库里没有：

- 真实 API key、token、cookie、密码。
- 真实用户姓名、账号、手机号、邮箱、身份证、银行卡。
- 私有项目名、客户名、商业合同、聊天原文。
- 你的真实 Obsidian vault 或 SQLite 数据库。

## 设计原则

1. Markdown 是事实源，SQLite 是索引。
2. 普通记忆直接进入正式目录，不做无意义候选池。
3. Agent 自我进化单独放在 `agent/`，其中 case 和 skill 候选用于复用经验沉淀。
4. 用正交字段过滤记忆：`user_id`、`agent_id`、`app_id`、`project_id`、`session_id`、`track`、`memory_type`、`status`。
5. API key 只放本地 `.env`，永远不写进 Markdown 记忆和公开仓库。
