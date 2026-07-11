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

## 本地检查命令

```bash
find . -name "*.sqlite" -o -name "*.db" -o -name ".env" -o -name "*.key" -o -name "*.pem" -o -name "zvec" -o -path "*/logs/*.jsonl"
python3 scripts/codex_memory_check.py
```

如果检查结果出现真实 key 或真实路径，先从模板里移除。
