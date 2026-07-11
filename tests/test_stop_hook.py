from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))


def load_stop_hook():
    path = REPO_ROOT / "scripts" / "agent_memory_stop_hook.py"
    spec = importlib.util.spec_from_file_location("test_stop_hook_module", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


class StopHookProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_stop_hook()

    def test_claude_failure_blocks_with_json(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(self.module, "notify"),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.module.report_failure(
                "claude", {"status": "error", "error": "synthetic failure"}
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(returncode, 0)
        self.assertEqual(payload["decision"], "block")
        self.assertIn("synthetic failure", payload["reason"])
        self.assertEqual(stderr.getvalue(), "")

    def test_codex_failure_requests_continuation(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(self.module, "notify"),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.module.report_failure(
                "codex", {"status": "error", "error": "synthetic failure"}
            )

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Continue this turn", stderr.getvalue())
        self.assertIn("synthetic failure", stderr.getvalue())


class StopHookGitBaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_stop_hook()
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.vault = self.root / "Agent记忆"
        self.vault.mkdir()
        git(self.root, "init", "-q")
        git(self.root, "config", "user.name", "Agent Memory Test")
        git(self.root, "config", "user.email", "test@example.invalid")
        self.note = self.vault / "AGENTS.md"
        self.note.write_text("# Agent Memory\n", encoding="utf-8")
        git(self.root, "add", "Agent记忆/AGENTS.md")
        git(self.root, "commit", "-qm", "baseline")
        self.baseline = git(self.root, "rev-parse", "HEAD")
        self.log_path = self.root / "closeout.jsonl"
        self.module.GIT_ROOT = self.root
        self.module.VAULT_ROOT = self.vault
        self.module.LOG_PATH = self.log_path

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_dirty_markdown_is_detected_under_renamed_vault(self) -> None:
        self.note.write_text("# Agent Memory\n\nChanged.\n", encoding="utf-8")
        self.assertEqual(self.module.dirty_paths(), [self.note.resolve()])

    def test_external_commit_after_observed_baseline_is_recovered(self) -> None:
        self.note.write_text("# Agent Memory\n\nCommitted externally.\n", encoding="utf-8")
        git(self.root, "add", "Agent记忆/AGENTS.md")
        git(self.root, "commit", "-qm", "external commit")
        self.log_path.write_text(
            json.dumps({"git_observed_through": self.baseline}) + "\n",
            encoding="utf-8",
        )

        self.assertEqual(self.module.historical_paths(), [self.note.resolve()])


if __name__ == "__main__":
    unittest.main()
