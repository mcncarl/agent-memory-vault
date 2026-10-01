# Agent Memory Vault

这是一个 Claude Code 与 Codex 可共用的本地记忆库模板。真实使用时，你可以把这个目录当作普通 Markdown 文件夹使用；如果你使用 Obsidian，也可以把它作为 Obsidian vault 打开。

建议读取顺序：

1. `AGENTS.md`
2. `INDEX.md`
3. 根据任务关键词读取最相关的 1-3 个文件

正式记忆位于 `用户记忆/`、`项目/`、`工作流/`、`决策/` 和 `agent/`。所有自动写入均通过
Write Gateway v2 的 `read-target → prepare → apply`，不允许直接编辑后补 claim。
`codex`、`claude`、`ailu` 共用同一套路径租约、单调 fencing token、CAS、Git 回执和
closeout；未知 actor 统一拒绝。人工/Obsidian 外部编辑必须
重新基于当前文件准备提案，或由 Codex/Claude 在明确用户授权下显式 adopt，不能静默覆盖。

首次使用或升级 Runtime 前必须执行显式状态迁移：fresh state 用 `migrate init`；旧库先
`migrate plan`，再用新的私有备份路径执行 `migrate apply`；其后 `migrate verify`，完成
索引、Doctor 和 Hook 检查后再以 `migrate verify --publish-ready` 提交切换。
