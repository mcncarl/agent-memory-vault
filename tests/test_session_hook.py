from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "agent_memory_session_hook.py"


class ClaudeSessionHookTest(unittest.TestCase):
    def test_session_start_exports_claude_id_and_clears_inherited_codex_id(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            env_file = Path(raw_tmp) / "claude-env.sh"
            env = os.environ.copy()
            env["CLAUDE_ENV_FILE"] = str(env_file)
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "--actor", "claude"],
                input=json.dumps({"session_id": "claude-session-123"}),
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            exported = env_file.read_text(encoding="utf-8")
            self.assertIn("export AGENT_MEMORY_SESSION_ID=claude-session-123", exported)
            self.assertIn("export CLAUDE_SESSION_ID=claude-session-123", exported)
            self.assertIn("unset CODEX_THREAD_ID", exported)


if __name__ == "__main__":
    unittest.main()
