from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
TEMPLATE = REPO_ROOT / "templates" / "vault"


class CurrentFactInvariantTest(unittest.TestCase):
    def test_audit_detects_and_clears_current_summary_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            vault = tmp / "vault"
            runtime = tmp / "runtime"
            subprocess.run(["cp", "-R", str(TEMPLATE), str(vault)], check=True)
            runtime.joinpath("config").mkdir(parents=True)
            invariants = runtime / "config" / "system-invariants.json"
            invariants.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "system_name": "Agent Memory Vault",
                        "memory_root": str(vault),
                        "runtime_root": str(runtime),
                        "canonical_script_prefix": "agent_memory_",
                        "shared_tracks": ["project", "workflow", "decision", "user", "routing"],
                        "scope_exceptions": [],
                        "forbidden_current_summary_patterns": [
                            {
                                "id": "legacy_compatibility_claim",
                                "pattern": r"agent_memory_\*[^。；\n]{0,32}(?:兼容|compat)",
                                "severity": "medium",
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            config = runtime / "config" / "agent-memory.toml"
            config.write_text(
                "\n".join(
                    [
                        f'memory_root = "{vault}"',
                        f'config_root = "{runtime}"',
                        f'state_db = "{runtime / "state.sqlite"}"',
                        f'audit_db = "{runtime / "audit.sqlite"}"',
                        f'invariants_file = "{invariants}"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["AGENT_MEMORY_CONFIG_FILE"] = str(config)
            target = vault / "项目" / "current-facts.md"
            target.write_text(
                """---
memory_type: project
track: project
agent_scope: shared
status: active
verified_at: 2026-07-11
---
# Current facts

## 当前有效摘要

- Markdown/SQLite/FTS 为 1/1/1，Zvec 为 1/1、1 个事实块。
- 底层 agent_memory_* 脚本继续保留兼容。
""",
                encoding="utf-8",
            )

            def scan() -> None:
                result = subprocess.run(
                    [sys.executable, str(SCRIPTS / "agent_memory_index.py"), "--init", "--scan"],
                    cwd=REPO_ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

            def audit_kinds() -> set[str]:
                result = subprocess.run(
                    [sys.executable, str(SCRIPTS / "agent_memory_audit.py"), "--json", "--limit", "200"],
                    cwd=REPO_ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                return {
                    item["kind"]
                    for item in payload["findings"]
                    if item.get("rel_path") == "项目/current-facts.md"
                }

            scan()
            self.assertIn("current_metric_conflict", audit_kinds())
            self.assertIn("current_summary_invariant", audit_kinds())

            target.write_text(
                target.read_text(encoding="utf-8")
                .replace("- Markdown/SQLite/FTS 为 1/1/1，Zvec 为 1/1、1 个事实块。\n", "- 实时指标由 doctor 读取。\n")
                .replace("- 底层 agent_memory_* 脚本继续保留兼容。\n", "- 公开仓库是唯一核心源码。\n"),
                encoding="utf-8",
            )
            scan()
            self.assertNotIn("current_metric_conflict", audit_kinds())
            self.assertNotIn("current_summary_invariant", audit_kinds())


if __name__ == "__main__":
    unittest.main()
