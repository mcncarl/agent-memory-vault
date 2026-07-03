# Migration Guide

这份指南用于把一个已经在使用的私人 Codex 记忆系统，整理成可复用模板。

## 1. 不要直接复制真实 vault

真实 vault 里通常会有：

- 私人偏好和边界
- 项目状态
- 客户、合同、账号、路径
- 失败记录和排查细节

模板只应该复刻结构和方法，不应该复刻内容。

## 2. 用模板初始化新的本地 vault

```bash
python3 scripts/bootstrap.py --memory-root "$HOME/codex-memory-vault" --write-env
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
python3 scripts/codex_agent_evolution.py --init --scan --report
python3 scripts/codex_memory_index.py --init --scan --report
python3 scripts/codex_memory_closeout.py --dry-run
python3 scripts/codex_memory_check.py
```

检查通过后，就可以开始在本地使用这个模板。
