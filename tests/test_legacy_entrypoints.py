from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = REPO_ROOT / "scripts"

LEGACY_NAMES = (
    "codex_agent_evolution.py",
    "codex_memory_audit.py",
    "codex_memory_audit_autorun.py",
    "codex_memory_check.py",
    "codex_memory_closeout.py",
    "codex_memory_doctor.py",
    "codex_memory_index.py",
    "codex_memory_retrieval_benchmark.py",
    "codex_memory_search.py",
    "codex_memory_stop_hook.py",
    "codex_memory_zvec_index.py",
)


class LegacyEntrypointTests(unittest.TestCase):
    def test_all_legacy_entrypoints_forward_help(self) -> None:
        for name in LEGACY_NAMES:
            with self.subTest(name=name):
                completed = subprocess.run(
                    [sys.executable, str(SCRIPT_ROOT / name), "--help"],
                    text=True,
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("usage:", completed.stdout.lower())


if __name__ == "__main__":
    unittest.main()
