from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = REPO_ROOT / "scripts"


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

            env = os.environ.copy()
            env.update(
                {
                    "AGENT_MEMORY_ROOT": str(vault),
                    "AGENT_MEMORY_GIT_ROOT": str(vault),
                    "AGENT_MEMORY_CONFIG_ROOT": str(config),
                    "AGENT_MEMORY_STATE_DB": str(state_db),
                }
            )
            for key in tuple(env):
                if key.startswith("CODEX_MEMORY_"):
                    env.pop(key)

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
