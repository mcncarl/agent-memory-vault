# Privacy Checklist

这个仓库是模板仓库，不是你的真实记忆库。公开发布前请按下面规则检查。

## 永远不要提交

- `.env`
- SQLite 数据库：`*.sqlite`、`*.db`
- API key、token、cookie、密码
- 真实聊天记录
- 私有项目名和客户名
- 合同、报价、账号、手机号、邮箱、身份证、银行卡
- 真实 Obsidian vault 全量内容

## 推荐做法

- 公开仓库只放 `templates/`、`scripts/`、`docs/`、假示例。
- 本地真实记忆库放在另一个不公开的位置。
- `.env.example` 只放变量名和占位符。
- 文档里的路径使用 `/path/to/...` 或 `$HOME/...`。
- 示例项目统一使用 `example-app`、`demo-user` 这类假名。

## 发布前命令

```bash
find . -name "*.sqlite" -o -name "*.db" -o -name ".env" -o -name "*.key" -o -name "*.pem"
python3 scripts/codex_memory_check.py
```

如果检查结果出现真实 key 或真实路径，先从仓库移除，再发布。
