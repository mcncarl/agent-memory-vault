# Windows Compatibility Audit

本次适配保持 Markdown 格式、SQLite 数据模型、记忆去重规则和 macOS/Linux 路径不变。架构仍然是共享 Python Core，加平台薄适配层。

| 范围 | 原问题 | 当前处理 |
| --- | --- | --- |
| 全局锁 | `fcntl` 在 Windows 无法导入 | `agent_memory_lock.py`：Unix 使用 `flock`，Windows 使用 `msvcrt.locking` |
| 命令分发 | 直接执行无扩展名 shebang 脚本会报 `WinError 193` | Python 子脚本统一由当前/配置的解释器启动 |
| 默认路径 | `$HOME` 可能未设置 | 统一 `expand_path()`，回退 `USERPROFILE` 或 `Path.home()` |
| Git/子进程输出 | 系统代码页可能误解 UTF-8 和中文路径 | Python 子进程设置 UTF-8，文本输出显式 UTF-8 解码 |
| SQLite 生命周期 | `with sqlite3.connect()` 只管事务，不保证立即关闭连接 | 安全连接上下文退出时显式关闭；其他直接连接用 `closing` |
| Runtime 模板 | 安装包脱离源码后不能 bootstrap | Runtime 安装并校验 `templates/vault` |
| 新 Vault Git | 只有 `git init`、没有首个 HEAD | bootstrap 默认只提交模板文件，创建干净初始基线 |
| 语义检索开关 | disabled 路径仍可能调用 Zvec | closeout 在入口处短路，完全不启动 Zvec |
| Obsidian 状态 | `.obsidian/` 会污染 Git 识别 | Vault 模板内置 `.gitignore` |
| 自动化 | 仅有 macOS `launchd` 路径 | Windows 提供 Stop Hook wrapper 与 Task Scheduler 管理脚本 |
| 持续验证 | 托管 CI 会引入外部 runner 依赖 | GitHub Actions 以只读权限和固定 SHA 的官方 actions，在 Ubuntu、macOS、Windows 上运行隔离测试与跨平台静态检查；源码/Runtime/manifest 哈希对账和 Windows 10/11 原生验收仍按需在本地完成 |

## 有意保留的边界

- Windows 文件安全由 ACL 表达，不伪装成 POSIX `0600/0700`；严格模式检查只在 POSIX 平台执行。
- Zvec、Torch 和 EmbeddingGemma 仍是可选旁路。核心适配已跨平台，但第三方 wheel 是否覆盖具体 Windows/Python 组合取决于上游发布物。
- Task Scheduler 使用当前用户、Interactive、Limited 权限，避免保存密码或要求管理员权限；用户未登录时不会运行。
- Obsidian 只是 Markdown 编辑界面，不是索引或 closeout 的运行依赖。

```text
Core Python (Memory / Search / SQLite / Closeout / Audit / Index)
  + agent_memory_env.py   (path/config adapter)
  + agent_memory_lock.py  (process-lock adapter)
  + Unix/macOS entrypoints and launchd
  + Windows PowerShell and Task Scheduler
```
