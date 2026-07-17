# Windows Compatibility Audit

审计基线：`main` 分支，Windows 11、Python 3.11、Windows PowerShell 5.1。结论来自代码检查和本机测试，不根据需求描述推测。

## 已跨平台或可直接运行

- Markdown Vault、字段模型、SQLite/FTS 索引、搜索、claim 账本、结构检查和 bootstrap 主要使用 Python 标准库与 `pathlib`。
- `.env` 已由 `agent_memory_env.py` 在 Python 内部解析，业务脚本不要求 shell 先执行 `source .env`。
- Obsidian 只是打开 Markdown 目录的可选界面，没有运行时耦合。
- Git 调用以参数数组传给 `subprocess`，没有使用 `shell=True`。

## Windows 基线会失败

| 范围 | 代码证据 | Windows 影响 | 修复 |
| --- | --- | --- | --- |
| 全局锁 | closeout、audit autorun、Zvec 直接导入 `fcntl` | 模块导入即失败 | 新增 `agent_memory_lock.py`，Unix 使用 `flock`，Windows 使用 `msvcrt.locking` |
| 命令分发 | `memoryctl` 直接执行无扩展名 shebang 文件 | `WinError 193` | 始终通过当前 `sys.executable` 启动目标脚本 |
| 默认路径 | 多处依赖 `$HOME` | Windows 未设置 `HOME` 时产生错误相对路径 | 统一 `expand_path()`，回退到 `USERPROFILE`/`Path.home()` |
| 中文 Git 路径 | Git 使用 UTF-8，`subprocess(text=True)` 使用系统代码页 | Stop Hook/closeout 丢失或误解中文路径 | Git 输出显式按 UTF-8 解码，内部相对路径统一为 POSIX 表示 |
| SQLite 生命周期 | `with sqlite3.connect()` 不会关闭连接 | Windows 临时库和 Vault 无法删除/移动 | 用 `contextlib.closing` 显式关闭连接 |
| 自动化 | 只有 macOS `launchd` 文档 | Windows 无周期 audit | 新增幂等 Task Scheduler 管理脚本 |
| Stop Hook | 文档命令硬编码 `/bin/zsh`、`source`、`python3` | Codex Hook 无法原生运行 | 新增 PowerShell wrapper 和安全合并安装器 |
| 安装 | 只有 Bash 风格命令 | Windows 无一键入口 | 新增 `install-windows.ps1` |
| 测试 | 两项测试调用 `cp -R`，CI 只跑 Ubuntu | Windows 套件失败且无持续验证 | 改为 `shutil.copytree`，CI 扩展到三系统 |

## 潜在风险但非本次强制启用

- Zvec、Torch、EmbeddingGemma 是可选旁路；锁与路径已跨平台，但具体第三方 wheel 是否支持目标 Windows/Python 组合仍取决于其发布物。
- Windows Task Scheduler 任务采用当前用户、Interactive、Limited 权限；用户未登录时不会运行，这是避免保存密码或要求管理员权限的安全取舍。
- PowerShell 5.1 与 7 均使用同一脚本语法；CI 额外解析所有 `.ps1`，真实任务注册仍需要 Windows 主机。

## 路径与 Shell 结论

- Python 核心不再要求手工拼接 `/`；对外 JSON/索引相对路径统一使用 `as_posix()`，本机绝对路径仍由 `Path` 生成。
- Unix 文档和 shebang 保留；Windows 逻辑隔离在小型 Python 平台适配器和 PowerShell 入口中。
- macOS `launchd` 未删除或改写；Windows Task Scheduler 是并列适配层。
- 未发现 `shell=True`、硬编码真实用户名、API key 或 Token。

## 最小架构

```text
Core Python (Memory / Search / SQLite / Closeout / Audit / Index)
  + agent_memory_env.py   (path/config adapter)
  + agent_memory_lock.py  (process-lock adapter)
  + Unix shebang / macOS launchd
  + Windows PowerShell / Task Scheduler
```

不改变 Memory Markdown 格式、SQLite 数据模型或去重决策规则。
