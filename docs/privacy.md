# Privacy Checklist

这个模板不是你的真实记忆库。真实信息应该留在本地私有 vault 里。

Claude Code 与 Codex 可以读取同一个私有配置源，但真实 Cookie、token 和 API key 仍然不能进入 Markdown vault、CLAUDE.md、AGENTS.md、auto-memory、搜索日志或公开仓库。推荐把私有值放在 Git 之外、权限为 `600` 的结构化文件或系统 Keychain 中，并通过 runner 只向目标子进程注入所需变量；不要让 Agent 打印整个 secrets 文件。

## 永远不要放进模板

- `.env`
- SQLite 数据库：`*.sqlite`、`*.db`
- audit 裁决库：`audit_decisions.sqlite`
- closeout/audit 运行日志：`logs/*.jsonl`
- API key、token、cookie、密码
- Hugging Face token、模型缓存
- Zvec / LanceDB / Qdrant 等派生向量库
- 真实聊天记录
- 私有项目名和客户名
- 合同、报价、账号、手机号、邮箱、身份证、银行卡
- 真实 Obsidian vault 全量内容

## 推荐做法

- 模板只放 `templates/`、`scripts/`、`docs/`、假示例。
- 本地真实记忆库放在另一个不公开的位置。
- `.env.example` 只放变量名和占位符。
- 文档里的路径使用 `/path/to/...` 或 `$HOME/...`。
- 示例项目统一使用 `example-app`、`demo-user` 这类假名。
- closeout/audit 只能公开脚本，不能公开本地运行产物。
- 公开 benchmark 只用假数据；真实检索、对账和安全边界样本放在 Git 之外。
- 私有 benchmark 默认只输出不可逆的 case reference、哈希、长度、名次和汇总指标，不输出原始 case id、查询原文、候选正文或绝对路径。
- `--show-private-details` 只用于本机人工排查；运行前要明确接受终端和日志里出现明文的风险。
- Runtime 私有目录固定为 `700`；state DB、SQLite sidecar、配置文件和持久日志固定为 `600`，每次打开都会拒绝 symlink 并复核权限。
- 普通 CLI 写入意图仅在私有 state DB 中保存有上限的 canonical proposal snapshot；宿主 `write` API 的高级 intent 是下述无 snapshot 例外。内容不一致时默认只返回 diff 哈希和统计；只有显式 `--show-private-diff` 才返回有界且经过凭证行脱敏的 diff。对外 `show`、receipt、搜索索引和 closeout JSONL 不保留 diff 正文。
- Ailu `retrieve` 只从受控 stdin JSON 接收查询，不回显查询原文、候选绝对路径或后端错误正文；只返回 query hash、正式相对路径、内容指纹与有界 excerpt。重新读取时发现已知凭证模式会拒绝整份候选，避免秘密落入宿主日志。
- 可观测性默认关闭。启用后只保存 task/session 的带用途 SHA-256、memory ref、枚举事件、来源分类和数值指标；不保存原问题、回答、excerpt、原始 session、自由文本理由。工具观察、Agent 自报、人工标注和独立模型标注不得混算。
- 可观测事件只追加，不自动清理。任何历史行清理或数据库恢复覆盖都必须另行取得明确授权；关闭功能只停止新事件写入，不 DROP 表或删除旧行。
- 宿主 `write` API 只从 stdin 接收提案，不把正文放进 argv；内部 prewrite/postwrite reconcile query 也通过 stdin 交给 search 子进程。Ailu session 只从私有环境传递，wrapper 拒绝 `--session-id`、等号写法及其 argparse 缩写，子进程 argv 中也没有 session。它创建的高级 intent 不保存 proposal snapshot，只保留 hash、字节/行数、read token 与 scope 边界元数据；候选 excerpt、提案正文、diff 和确认 reference 都不进入持久日志，确认 reference 只存哈希。
- `write read-target` 会把不超过 2 MiB 的完整目标正文返回给调用宿主，因为安全的 UPDATE 必须基于当前全文。该正文只存在进程管道和宿主内存中，不写入 state DB、搜索日志或 closeout 日志；宿主不应把该回执记入调试日志或对话持久化。
- 原子 UPDATE 在目标同目录短暂创建隐藏 proposal 文件；正常成功或已完整恢复的普通竞态会按 hash 核对后清理。若崩溃、二次竞态或恢复结果无法证明完整，系统会返回 `TARGET_WRITE_RECOVERY_REQUIRED` 并保留隐藏 proposal/displaced/recovery sidecar，其中可能含完整提案或被竞态修改的 Markdown。它们留在私有 Vault 中用于人工恢复，不进入 state DB、回执或日志；存在时同一提案后续 apply 会持续 fail closed，不能自动删除或提交这些恢复材料。

## 本地检查命令

```bash
find . -name "*.sqlite" -o -name "*.db" -o -name ".env" -o -name "*.key" -o -name "*.pem" -o -name "zvec" -o -path "*/logs/*.jsonl"
python3 scripts/agent_memory_check.py
```

如果检查结果出现真实 key 或真实路径，先从模板里移除。
