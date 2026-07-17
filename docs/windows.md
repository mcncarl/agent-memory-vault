# Windows 原生使用指南

支持 Windows 10/11，优先 PowerShell 7，并兼容 Windows PowerShell 5.1。核心功能需要 Python 3.10+ 和 Git；Obsidian 可选。

## 安装

在仓库根目录运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 `
  -MemoryRoot "$HOME\Documents\Agent Memory Vault"
```

`Bypass` 只作用于这一个进程，不会永久降低系统 Execution Policy。安装器会：检查 Python/Git、创建 `.venv`、安装本地 Runtime、初始化 Vault/SQLite/INDEX、运行 check 和 doctor。它不会安装可选的大型向量依赖。

可选同时安装 Codex 自动 closeout 和每周 audit：

```powershell
.\scripts\install-windows.ps1 `
  -MemoryRoot "$HOME\Documents\Agent Memory Vault" `
  -InstallCodexHook -AutoCloseout -InstallAuditTask
```

所有路径均作为独立参数传递，含空格和中文路径无需手工转义成短路径。

## 日常命令

```powershell
$runtime = Join-Path $env:LOCALAPPDATA 'AgentMemoryVault'
$python = Join-Path $runtime '.venv\Scripts\python.exe'
$memoryctl = Join-Path $runtime 'scripts\memoryctl'
& $python $memoryctl --actor codex search "项目状态" --limit 5
& $python $memoryctl --actor codex closeout --dry-run
& $python $memoryctl --actor codex closeout
& $python $memoryctl --actor human doctor
```

Python 会直接加载 Runtime TOML 或仓库 `.env`，PowerShell 不需要模拟 Bash 的 `source .env`。

## Codex Stop Hook

单独安装（保留 `hooks.json` 中其他 Hook）：

```powershell
.\scripts\install-codex-hook.ps1 -AutoCloseout
```

Codex 默认启用 Hooks；如果你曾显式关闭过它，请确认 `%USERPROFILE%\.codex\config.toml` 没有设置 `hooks = false`。首次加载新命令时，Codex 会要求审查和信任该 Hook；在 CLI 中使用 `/hooks` 完成确认。

```toml
[features]
hooks = true
```

PowerShell wrapper 从 stdin 原样接收 Hook JSON，通过当前 Python 运行 `agent_memory_stop_hook.py`。Python 负责加载配置、按 session claim 收尾、更新 SQLite/INDEX、去重和可选 Git commit；失败会写 stderr 并返回非零状态，不会静默吞错。

## Task Scheduler audit

```powershell
.\scripts\audit-task.ps1 install
.\scripts\audit-task.ps1 status
.\scripts\audit-task.ps1 run
.\scripts\audit-task.ps1 uninstall
```

默认任务名为 `AgentMemoryVaultAudit`，以当前用户、Limited 权限、交互登录方式运行。重复 `install` 会更新同名任务，不创建副本。自定义 Runtime 时传入 `-RuntimeRoot` 和 `-Python`。

## Obsidian

在 Obsidian 中选择“Open folder as vault”，打开 `-MemoryRoot` 对应目录即可。Obsidian 不是索引或 closeout 的依赖；Markdown 仍是唯一事实源。

## Doctor

```powershell
& $python (Join-Path $runtime 'scripts\agent_memory_doctor.py')
```

Windows 额外检查 Python、Git、PowerShell、Codex Stop Hook 和 Scheduled Task。Zvec 未启用时是可接受的警告，不影响 SQLite 搜索。

## 常见问题

- `running scripts is disabled`：使用上面的单进程 `-ExecutionPolicy Bypass`，不要设置 `Unrestricted`。
- `python not found`：安装 Python 3.10+ 并启用 `py.exe` 或将 Python 加入 PATH。
- 路径带空格：使用引号并把路径作为单个参数传入；不要手工拼命令字符串。
- 中文乱码：使用仓库 PowerShell wrapper；它会设置 Python UTF-8 I/O，Git 路径也按 UTF-8 解码。
- `.env`：Windows 不需要 dot-source；Python 自动加载。双引号 Windows 路径中的反斜杠也会按字面路径处理。
- Task Scheduler 不运行：先执行 `status`，再确认用户已登录、Python 和 Runtime 路径仍存在。
- Obsidian 看不到索引：先运行 `memoryctl index --init --scan --report`，再打开正确 Vault 目录。
