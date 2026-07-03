# Codex Memory Template

这是一个 Codex 长期记忆库模板。它把普通 Markdown 文件当作长期事实源，用 SQLite 建全库索引，并用少量固定字段支持按用户、Agent、项目、应用、会话和记忆类型过滤。需要语义检索时，也可以额外启用本地 EmbeddingGemma + Zvec 向量旁路。

这个仓库只包含模板、脚本和假示例，不应该包含你的真实记忆、真实路径、API key、私人项目名或聊天原文。

## 它解决什么问题

- 让 Codex 每次开始重要任务时，先读最相关的长期记忆。
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
  codex_memory_search.py # 统一搜索入口：SQLite + 可选 Zvec + 手动 rg
  codex_memory_closeout.py
                          # 任务结束收尾：检查、对账、刷新索引、审计、可选提交
  codex_memory_audit.py  # 定期体检：过期、重复、open-loop、裁决记录
  codex_memory_audit_autorun.py
                          # audit 自动触发器：超过间隔才运行
  codex_memory_zvec_index.py
  codex_memory_retrieval_benchmark.py
  codex_agent_evolution.py
  codex_memory_check.py
```

## 快速开始

```bash
git clone https://github.com/mcncarl/codex-memory.git
cd codex-memory
cp .env.example .env
```

编辑 `.env`，把 `CODEX_MEMORY_ROOT` 改成你的本地记忆库路径。它可以只是一个普通文件夹；如果你使用 Obsidian，也可以把这个文件夹作为 Obsidian vault 打开。

```bash
python3 scripts/bootstrap.py --memory-root "$HOME/codex-memory-vault" --write-env
source .env
python3 scripts/codex_agent_evolution.py --init --scan --report
python3 scripts/codex_memory_index.py --init --scan --report
python3 scripts/codex_memory_check.py
```

搜索示例：

```bash
python3 scripts/codex_memory_search.py "项目 收尾" --limit 5
python3 scripts/codex_memory_search.py "偏好" --track user
python3 scripts/codex_memory_search.py "复用流程" --memory-type workflow
```

任务结束时建议使用统一收尾脚本。它会自动发现记忆库里的变更文件，执行结构检查、写入后对账、SQLite 刷新、可选 Zvec 刷新、Agent evolution 刷新，并在 audit 超过间隔时顺手跑一次体检。

```bash
python3 scripts/codex_memory_closeout.py --dry-run
python3 scripts/codex_memory_closeout.py --commit
```

写入正式记忆前，可以先让脚本做一次对账，判断应该新建、更新旧文件、跳过、还是需要人工合并：

```bash
python3 scripts/codex_memory_closeout.py --prewrite "准备写入的记忆摘要"
```

audit 可以手动运行，也可以由 closeout 捎带触发：

```bash
python3 scripts/codex_memory_audit.py
python3 scripts/codex_memory_audit_autorun.py --reason manual --json
```

可选的 Stop hook 提醒和 macOS `launchd` 周期兜底见 [docs/automation.md](docs/automation.md)。

## 可选：语义检索

SQLite 适合关键词明确的问题；向量检索适合“只记得意思，不记得原词”的问题。这个模板把语义检索做成可选旁路，不替代 Markdown 和 SQLite。

安装可选依赖：

```bash
python3 -m venv "$HOME/.config/codex-memory/.venv"
"$HOME/.config/codex-memory/.venv/bin/python" -m pip install -U pip
"$HOME/.config/codex-memory/.venv/bin/python" -m pip install -r requirements-vector.txt
```

默认 embedding 模型是 `google/embeddinggemma-300m`。如果使用 gated 模型，需要先在 Hugging Face 接受模型条款并完成本机登录。模型缓存和向量库都只应保存在本地，不要提交到公开仓库。

```bash
python3 scripts/codex_memory_index.py --init --scan --report
"$HOME/.config/codex-memory/.venv/bin/python" scripts/codex_memory_zvec_index.py --init
"$HOME/.config/codex-memory/.venv/bin/python" scripts/codex_memory_zvec_index.py --scan
"$HOME/.config/codex-memory/.venv/bin/python" scripts/codex_memory_zvec_index.py --search "只记得大概意思的问题"
```

对比 SQLite 和向量检索：

```bash
"$HOME/.config/codex-memory/.venv/bin/python" scripts/codex_memory_retrieval_benchmark.py --limit 5
```

## 设计原则

1. Markdown 是事实源，SQLite 是索引。
2. 普通记忆直接进入正式目录，不做无意义候选池。
3. Agent 自我进化单独放在 `agent/`，其中 case 和 skill 候选用于复用经验沉淀。
4. 用正交字段过滤记忆：`user_id`、`agent_id`、`app_id`、`project_id`、`session_id`、`track`、`memory_type`、`status`。
5. 语义检索只作为候选召回层，最终答案必须回读 Markdown 原文。
6. closeout 负责“任务结束后的自动整理”，audit 负责“定期发现要复核、合并或忽略的记忆”，但二者都不自动改写事实层。
7. API key、模型缓存、SQLite、audit 裁决库和向量库只放本地，永远不写进 Markdown 记忆和公开仓库。

## 致谢

本项目的部分设计思路受 [EverOS](https://github.com/EverMind-AI/EverOS) 启发，详见 [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md)。
