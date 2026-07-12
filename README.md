# Agent Memory Vault: Shared Claude Code + Codex

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
  agent_memory_claim.py  # 会话文件认领账本，防止 Claude/Codex 串提交
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
python3 scripts/memoryctl --actor codex prewrite "准备写入的记忆摘要"
python3 scripts/memoryctl --actor codex claim --file "/absolute/path/to/changed-memory.md"
python3 scripts/memoryctl --actor claude closeout
```

写完正式记忆后先 `claim`。认领记录保存在 SQLite，只存 session id 的哈希；Agent 会话内的 closeout 和 Stop Hook 只处理本会话认领的文件，其他会话的脏文件明确排除。成功 closeout 还会记录每个文件的内容 hash，只有具备这份完成证据的历史文件才允许 Git 观察基线跨过。普通事实默认 `agent_scope: shared`；只有宿主特有经验才标为 `codex` 或 `claude`。

异常退出可能留下旧认领。Stop Hook 不会继续信任超过 24 小时的认领，Doctor 会把它列为警告。清理时先预览，再显式应用；这只把 SQLite 账本状态改为 `expired`，不会删除或改写 Markdown：

```bash
python3 scripts/memoryctl --actor human claims-expire --older-than-hours 24 --json
python3 scripts/memoryctl --actor human claims-expire --older-than-hours 24 --apply --json
```

搜索示例：

```bash
python3 scripts/agent_memory_search.py "项目 收尾" --limit 5
python3 scripts/agent_memory_search.py "偏好" --track user
python3 scripts/agent_memory_search.py "复用流程" --memory-type workflow
```

任务结束时建议使用统一收尾脚本。它会读取当前会话认领账本，同时追踪“上次成功 closeout 观察到的提交”之后的 Git 历史，因此 Obsidian Git 等工具提前自动提交也不会造成漏处理。随后执行结构检查、字面与语义双重对账、SQLite 刷新、可选 Zvec 补漏/清理、Agent evolution 刷新，并在 audit 超过间隔时顺手跑一次体检。全局锁负责串行化，认领账本负责隔离文件归属，两者解决的是不同问题。人工维护全库时可显式使用 `memoryctl ... closeout --global`。

```bash
python3 scripts/memoryctl --actor codex closeout --dry-run
python3 scripts/memoryctl --actor codex closeout
```

写入正式记忆前，可以先让脚本做一次对账，判断应该新建、更新旧文件、跳过、还是需要人工合并：

```bash
python3 scripts/memoryctl --actor codex prewrite "准备写入的记忆摘要"
```

audit 可以手动运行，也可以由 closeout 捎带触发：

```bash
python3 scripts/agent_memory_audit.py
python3 scripts/agent_memory_audit_autorun.py --reason manual --json
```

全链路健康检查：

```bash
python3 scripts/agent_memory_doctor.py
python3 scripts/agent_memory_doctor.py --repair-derived  # 只重建派生索引，不改 Markdown
```

Doctor 还会检查语义检索虚拟环境的基础 Python 是否仍存在、会话认领是否卡死，以及记忆 Git 提交是否长期没有推送。默认容忍少量刚生成的本地提交；记忆提交累计到 10 个，或最老一条超过 3 天仍未推送时才报警，避免日常噪声。

可选的 Stop hook 与 macOS `launchd` 周期兜底见 [docs/automation.md](docs/automation.md)。

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

## 致谢

本项目的部分设计思路受 [EverOS](https://github.com/EverMind-AI/EverOS) 启发，详见 [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md)。
