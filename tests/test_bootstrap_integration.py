from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = REPO_ROOT / "scripts"
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from state_fixture import initialize_full_state


def run(command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


class BootstrapIntegrationTests(unittest.TestCase):
    def test_new_namespace_bootstraps_indexes_and_checks(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            vault = root / "Agent记忆"
            config = root / "config"
            state_db = config / "state.sqlite"

            bootstrap = run(
                [
                    sys.executable,
                    str(SCRIPT_ROOT / "bootstrap.py"),
                    "--memory-root",
                    str(vault),
                ]
            )
            self.assertEqual(bootstrap.returncode, 0, bootstrap.stderr)
            self.assertTrue((vault / ".git" / "HEAD").is_file())
            head = run(["git", "-C", str(vault), "rev-parse", "--verify", "HEAD"])
            self.assertEqual(head.returncode, 0, head.stdout + head.stderr)
            (vault / ".obsidian").mkdir()
            (vault / ".obsidian" / "workspace.json").write_text("{}\n", encoding="utf-8")
            status = run(["git", "-C", str(vault), "status", "--porcelain"])
            self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
            self.assertEqual(status.stdout, "")

            closeout_rules = (
                vault / "工作流" / "Agent记忆收尾决策规则.md"
            ).read_text(encoding="utf-8")
            self.assertIn("risk_class: ordinary\n", closeout_rules)
            self.assertNotIn("verified_at:", closeout_rules)
            self.assertIn(
                "- 真实用户表达别名：对话结束、自动归档、记忆收尾、对话结束归档、"
                "Codex 每次对话结束怎么自动归档。",
                closeout_rules,
            )

            env = os.environ.copy()
            env.update(
                {
                    "AGENT_MEMORY_ROOT": str(vault),
                    "AGENT_MEMORY_GIT_ROOT": str(vault),
                    "AGENT_MEMORY_CONFIG_ROOT": str(config),
                    "AGENT_MEMORY_STATE_DB": str(state_db),
                }
            )
            initialize_full_state(state_db)

            evolution = run(
                [sys.executable, str(SCRIPT_ROOT / "agent_memory_evolution.py"), "--init", "--scan", "--report"],
                env,
            )
            self.assertEqual(evolution.returncode, 0, evolution.stderr)

            index = run(
                [sys.executable, str(SCRIPT_ROOT / "agent_memory_index.py"), "--init", "--scan", "--report"],
                env,
            )
            self.assertEqual(index.returncode, 0, index.stderr)

            check = run(
                [sys.executable, str(SCRIPT_ROOT / "agent_memory_check.py")], env
            )
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
            self.assertIn("agent_memory_check=ok", check.stdout)


if __name__ == "__main__":
    unittest.main()
