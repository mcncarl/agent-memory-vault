from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = REPO_ROOT / "scripts"


def run(command: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


def memory(title: str, agent_id: str, agent_scope: str = "") -> str:
    scope_line = f"agent_scope: {agent_scope}\n" if agent_scope else ""
    return (
        "---\n"
        "memory_type: workflow\n"
        "track: workflow\n"
        f"agent_id: {agent_id}\n"
        f"{scope_line}"
        "status: active\n"
        "---\n\n"
        f"# {title}\n\n"
        "scopeprobe shared visibility marker\n"
    )


class AgentScopeTests(unittest.TestCase):
    def test_missing_scope_defaults_shared_without_overwriting_agent_id(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            vault = root / "Agent记忆"
            workflow = vault / "工作流"
            workflow.mkdir(parents=True)
            (workflow / "shared.md").write_text(memory("Shared", "codex"), encoding="utf-8")
            (workflow / "codex.md").write_text(memory("Codex", "codex", "codex"), encoding="utf-8")
            (workflow / "claude.md").write_text(memory("Claude", "claude", "claude"), encoding="utf-8")

            state_db = root / "config" / "state.sqlite"
            env = os.environ.copy()
            env.update(
                {
                    "AGENT_MEMORY_ROOT": str(vault),
                    "AGENT_MEMORY_GIT_ROOT": str(root),
                    "AGENT_MEMORY_CONFIG_ROOT": str(root / "config"),
                    "AGENT_MEMORY_STATE_DB": str(state_db),
                }
            )
            indexed = run(
                [sys.executable, str(SCRIPT_ROOT / "agent_memory_index.py"), "--init", "--scan"],
                env,
            )
            self.assertEqual(indexed.returncode, 0, indexed.stdout + indexed.stderr)

            with sqlite3.connect(state_db) as conn:
                row = conn.execute(
                    "SELECT agent_id, agent_scope FROM memory_docs WHERE rel_path='工作流/shared.md'"
                ).fetchone()
            self.assertEqual(row, ("codex", "shared"))

            visible: dict[str, set[str]] = {}
            for actor in ("codex", "claude"):
                result = run(
                    [
                        sys.executable,
                        str(SCRIPT_ROOT / "memoryctl"),
                        "--actor",
                        actor,
                        "search",
                        "scopeprobe",
                        "--limit",
                        "10",
                        "--no-zvec",
                        "--json",
                    ],
                    env,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                payload = json.loads(result.stdout)
                visible[actor] = {str(item["rel_path"]) for item in payload["results"]}

            self.assertEqual(visible["codex"], {"工作流/shared.md", "工作流/codex.md"})
            self.assertEqual(visible["claude"], {"工作流/shared.md", "工作流/claude.md"})


if __name__ == "__main__":
    unittest.main()
