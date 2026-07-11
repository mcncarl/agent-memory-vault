# Migration Guide

## 平台中立命名

Agent Memory Vault 使用平台中立命名：

- 新环境变量：`AGENT_MEMORY_*`。
- 新脚本：`agent_memory_*`。
- 统一命令：`memoryctl`。
- 默认本地状态目录：`$HOME/.config/agent-memory`。

当前版本只接受上述新名称，不提供旧环境变量回退或转发包装。升级现有安装时，必须同步修改环境变量、Hook、定时任务和自定义脚本；升级完成后执行测试和 `doctor`，确认没有旧入口消费者。

核心脚本应只从这个 Git 仓库维护，再用 `scripts/install_runtime.py` 安装到本机固定 Runtime。`runtime-manifest.json` 记录源码提交和每个核心文件 hash；私人 `agent-memory.toml`、模型、数据库和宿主适配器不会进入公开仓库。

这份指南用于把一个已经在使用的私人 Agent 记忆系统，整理成可复用模板。

## 接入 Claude Code 而不复制 vault

保留现有 Markdown、Git 基线、SQLite、Zvec、closeout 日志和 audit 调度器。新增一个薄的 `~/.claude/CLAUDE.md`，通过绝对路径导入 vault 的 `AGENTS.md`，再让 Claude 使用 `memoryctl --actor claude` 搜索、认领和收尾。

关闭 Claude Code auto-memory，或明确把它限定为非正式草稿；不要把 auto-memory 目录重定向到正式 vault。旧文件缺少 `agent_scope` 时按 `shared` 处理，只有宿主特有 Agent case 才标 `codex` 或 `claude`。

## 1. 不要直接复制真实 vault

真实 vault 里通常会有：

- 私人偏好和边界
- 项目状态
- 客户、合同、账号、路径
- 失败记录和排查细节

模板只应该复刻结构和方法，不应该复刻内容。

## 2. 用模板初始化新的本地 vault

```bash
python3 scripts/bootstrap.py --memory-root "$HOME/agent-memory-vault" --write-env
```

如果目标目录已经存在，脚本默认只补齐缺失文件，不覆盖已有文件。

如果你使用 Obsidian，可以把这个目录作为 Obsidian vault 打开；如果不使用 Obsidian，也可以直接用 Codex、VS Code 或任意文本编辑器管理这些 Markdown 文件。

## 3. 从旧系统迁移时只手动搬“脱敏后的模式”

可以迁移：

- 字段规范
- 目录设计
- 收尾流程
- 搜索规则
- 检查脚本
- closeout/audit 自动化机制

不要迁移：

- 真实项目内容
- 真实用户资料
- API key
- 原始对话
- 私有业务结论

## 4. 建索引并检查

```bash
source .env
python3 scripts/agent_memory_evolution.py --init --scan --report
python3 scripts/agent_memory_index.py --init --scan --report
python3 scripts/agent_memory_closeout.py --dry-run
python3 scripts/agent_memory_check.py
```

检查通过后，就可以开始在本地使用这个模板。
