from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))


def load_closeout():
    path = SCRIPTS_ROOT / "agent_memory_closeout.py"
    spec = importlib.util.spec_from_file_location("test_closeout_module", path)
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


class CloseoutRenameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_closeout()
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.old_vault = self.root / "MemoryBeforeRename"
        self.new_vault = self.root / "Agent记忆"
        self.old_vault.mkdir()
        git(self.root, "init", "-q")
        git(self.root, "config", "user.name", "Agent Memory Test")
        git(self.root, "config", "user.email", "test@example.invalid")
        (self.old_vault / "existing.md").write_text("# Existing\n", encoding="utf-8")
        git(self.root, "add", "MemoryBeforeRename/existing.md")
        git(self.root, "commit", "-qm", "baseline")
        self.baseline = git(self.root, "rev-parse", "HEAD")
        self.module.REPO_ROOT = self.root
        self.module.VAULT_ROOT = self.new_vault

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def migrate_without_commit(self) -> None:
        git(self.root, "mv", "MemoryBeforeRename", "Agent记忆")
        (self.new_vault / "new.md").write_text("# New\n", encoding="utf-8")
        git(self.root, "add", "Agent记忆/new.md")

    def assert_rename_and_add(self, entries) -> None:
        by_name = {entry.path.name: entry for entry in entries}
        self.assertEqual(set(by_name), {"existing.md", "new.md"})
        self.assertTrue(by_name["existing.md"].status.startswith("R"))
        self.assertEqual(
            by_name["existing.md"].previous_repo_path,
            "MemoryBeforeRename/existing.md",
        )
        self.assertFalse(by_name["existing.md"].is_new)
        self.assertTrue(by_name["new.md"].is_new)

    def test_dirty_root_rename_is_not_treated_as_new_memory(self) -> None:
        self.migrate_without_commit()
        entries, warnings = self.module.git_status_entries()
        self.assertEqual(warnings, [])
        self.assert_rename_and_add(entries)

    def test_committed_root_rename_is_not_treated_as_new_memory(self) -> None:
        self.migrate_without_commit()
        git(self.root, "commit", "-qm", "rename vault")
        head = git(self.root, "rev-parse", "HEAD")
        entries, warnings = self.module.git_history_entries(self.baseline, head)
        self.assertEqual(warnings, [])
        self.assert_rename_and_add(entries)


if __name__ == "__main__":
    unittest.main()
