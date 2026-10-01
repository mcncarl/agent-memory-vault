# Windows 原生使用指南

支持 Windows 10/11、Python 3.10+ 和 Git。PowerShell 7 优先，也兼容 Windows PowerShell 5.1；Obsidian 可选。

## 安装

在仓库根目录运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 `
  -MemoryRoot "$HOME\Documents\Agent Memory Vault"
```

`Bypass` 只作用于这一个 PowerShell 进程。安装器会检查 Python/Git、创建私有虚拟环境、安装可校验 Runtime、从 Runtime 自带模板初始化 Vault、创建首个 Git 基线，并让 Runtime 保持 `state_migration_required`。随后它显式初始化或迁移 state v4、只读 verify、安装所选 Hook，最后由 `migrate verify --publish-ready` 在同一维护锁内重建并核验派生索引、check/doctor 和 Hook 后提交切换。它不会安装可选的大型向量依赖。

新装生成的 TOML 默认启用 `[write_gateway] mode="enforce", full_vault=true`，writer 协议为 2、state schema 为 4，canonical actors 为 `codex`、`claude`、`ailu`；未知 actor 统一拒绝。

## 新装与升级状态机

- state DB 不存在时，安装器用私有 `O_EXCL` 文件执行 `migrate init`；此时备份明确记为 `not_applicable`，不会制造假备份。
- state DB 与 audit decisions DB 已存在时，分别执行只读 plan，并把 SQLite online backup 写到不同的全新时间戳路径，随后由 installer-only `apply` 迁移；备份文件绝不覆盖。普通 Search/Retrieve/Observe/Audit 不执行 schema DDL。
- 活动 legacy claim、活动 v1 intent、重复 active target、非法路径或迁移期间状态变化都会阻止 apply；安装器不会静默选赢家。
- `migrate verify` 默认不发布 ready。只有 evolution、SQLite/FTS、structure check、Doctor 和所选 Hook/Task 全部成功后，最终 `--publish-ready` 才原子更新 marker。
- 安装中断时 marker 仍非 ready，除 `version`、`migrate`、`doctor` 外的正常命令全部 fail closed；重新运行安装器或从已验证备份恢复。

已有 `agent-memory.toml` 不会被 Runtime 文件安装覆盖。Windows 流程会先运行只读
`migrate config-plan`，再用独占的新备份路径执行原子 `config-apply`；它只新增 canonical
`[write_gateway]` 并关闭旧 `[write_intents]`，其余私有配置保持原字节内容。
不要通过删除 transition marker 或直接运行 index 脚本来绕过迁移。

可选同时安装 Codex Stop Hook 和每周 audit：

```powershell
.\scripts\install-windows.ps1 `
  -MemoryRoot "$HOME\Documents\Agent Memory Vault" `
  -InstallCodexHook -AutoCloseout -InstallAuditTask
```

路径均作为独立参数传递，带空格和中文的路径不需要转换成短路径。

## 日常命令

```powershell
$runtime = Join-Path $env:LOCALAPPDATA 'AgentMemoryVault'
$python = Join-Path $runtime '.venv\Scripts\python.exe'
$memoryctl = Join-Path $runtime 'scripts\memoryctl'
& $python $memoryctl --actor codex search "项目状态" --limit 5
& $python $memoryctl --actor human doctor
```

原生 Windows Runtime 严格只读：支持 `write read-target/status/list`，
`prepare/apply/cancel` 会在读取请求或访问状态库之前返回 `WINDOWS_READ_ONLY`。
需要正式 Markdown 写入时，请在受支持的 POSIX Runtime 中使用
`write read-target → prepare → apply`；不要先直接编辑再补 claim。
claim 是 active intent 的会话归属投影，真正排他权是 canonical path lease 与单调
`fencing_token`。人工或 Obsidian 已改文件时，重新基于当前内容 prepare，或让
Codex/Claude 在明确用户授权下使用 `adopt_external: true`；Ailu 不自动 adopt。

Python 会直接加载 Runtime TOML，PowerShell 不需要模拟 Bash 的 `source .env`。

## Codex Stop Hook

单独安装时运行：

```powershell
.\scripts\install-codex-hook.ps1 -AutoCloseout
```

安装器会保留 `hooks.json` 中其他 Hook，只追加当前 Runtime 的 wrapper，并以原子写和独占备份自动启用 `%USERPROFILE%\.codex\config.toml` 中的 Hooks：

```toml
[features]
hooks = true
```

PowerShell wrapper 从 stdin 原样接收事件 JSON，再通过当前 Runtime 的受管 Python，使用 `-I -S memoryctl --actor codex stop-hook` 进入统一路由。Runtime 核心仍负责 session claim、SQLite/INDEX、去重、closeout 和可选 Git commit。

## Task Scheduler audit

```powershell
.\scripts\audit-task.ps1 install
.\scripts\audit-task.ps1 status
.\scripts\audit-task.ps1 run
```

默认任务名为 `AgentMemoryVaultAudit`，以当前用户和 Limited 权限运行。重复 `install` 会更新同名任务，不会创建副本。`uninstall` 会删除计划任务，只有明确需要移除时才运行。

## Obsidian 与 Doctor

在 Obsidian 中选择“Open folder as vault”并打开 `-MemoryRoot` 目录即可。模板已经忽略 `.obsidian/`，因此界面状态不会污染 Git 或 closeout 变更识别。

```powershell
& $python -I -S (Join-Path $runtime 'scripts\memoryctl') --actor human doctor --json
```

Zvec 未启用时不会在 closeout 中启动，SQLite 搜索仍可正常使用。

## 常见问题

- `running scripts is disabled`：使用上面的单进程 `-ExecutionPolicy Bypass`，不要永久设置 `Unrestricted`。
- `python not found`：安装 Python 3.10+，并启用 `py.exe` 或把 Python 加入 PATH。
- 中文乱码：使用仓库 wrapper；它会为 Python 子进程固定 UTF-8 I/O，Git 输出也按 UTF-8 解码。
- Task Scheduler 不运行：先执行 `status`，再确认用户已登录、Python 与 Runtime 路径仍存在。
- Runtime 脱离源码后不能 bootstrap：重新运行安装器；当前 manifest 会校验 `templates/vault` 是否完整。
- `RUNTIME_TRANSITION_INCOMPLETE`：先运行 `migrate plan --json` 查看阻断；fresh state 才用 `migrate init`，旧库必须使用新的 `--backup-path` 做 apply。完成所有检查后才运行 `migrate verify --publish-ready --json`。
- `ACTIVE_LEGACY_CLAIM`：先确定真实 owner 并显式完成或 expire；不要让 migrator 自动继承旧写权限。
- `writer_protocol_v2` Doctor 失败：现有 TOML 被保留但仍是 v1；手工迁移 `[write_gateway]` 后重跑 Doctor 与最终 publish-ready。
