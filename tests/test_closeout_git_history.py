from __future__ import annotations

import importlib.util
import hashlib
import sqlite3
from contextlib import closing
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


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


class CloseoutReconcileStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_closeout()
        self.tempdir = tempfile.TemporaryDirectory()
        self.vault = Path(self.tempdir.name).resolve() / "AgentMemory"
        (self.vault / "项目").mkdir(parents=True)
        self.module.VAULT_ROOT = self.vault

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_archived_history_does_not_block_active_fact_reconcile(self) -> None:
        archived = self.vault / "项目" / "history.md"
        archived.write_text(
            "---\nmemory_type: project_history\nstatus: archived\n---\n\n# History\n",
            encoding="utf-8",
        )
        entry = self.module.GitEntry(
            status="A",
            repo_path="AgentMemory/项目/history.md",
            path=archived,
        )
        args = Namespace(reconcile_all=False, limit=8, no_zvec=False)
        with mock.patch.object(
            self.module,
            "search_memory",
            side_effect=AssertionError("archived history must not enter duplicate search"),
        ):
            findings, warnings = self.module.postwrite_reconcile([entry], args)

        self.assertEqual(findings, [])
        self.assertEqual(warnings, [])

    def test_frontmatter_boilerplate_is_not_used_as_fallback_summary(self) -> None:
        note = self.vault / "项目" / "new-project.md"
        note.write_text(
            "---\n"
            "memory_type: project\n"
            "track: project\n"
            "app_id: agent-memory\n"
            "agent_scope: shared\n"
            "status: active\n"
            "---\n\n"
            "# Unique Project\n\n"
            "unique_project_marker_20260712\n",
            encoding="utf-8",
        )

        query = self.module.reconcile_query_for_file(note)
        self.assertIn("unique_project_marker_20260712", query)
        self.assertNotIn("memory_type", query)
        self.assertNotIn("agent_scope", query)

    def test_postwrite_ignores_navigation_and_template_candidates(self) -> None:
        note = self.vault / "项目" / "new-project.md"
        note.write_text("# Unique Project\n\nunique_project_marker_20260712\n", encoding="utf-8")
        entry = self.module.GitEntry(
            status="A",
            repo_path="AgentMemory/项目/new-project.md",
            path=note,
        )
        rows = [
            {
                "path": str(self.vault / "INDEX.md"),
                "rel_path": "INDEX.md",
                "title": "Agent Memory Index",
                "memory_type": "directory_index",
                "summary": "Unique Project unique_project_marker_20260712",
                "hit": "Unique Project unique_project_marker_20260712",
                "sources": ["sqlite"],
            }
        ]
        args = Namespace(
            reconcile_all=False,
            limit=8,
            no_zvec=True,
            merge_threshold=0.42,
            merge_coverage_threshold=0.35,
            semantic_merge_threshold=0.32,
        )
        with mock.patch.object(self.module, "search_memory", return_value=(rows, [])):
            findings, warnings = self.module.postwrite_reconcile([entry], args)

        self.assertEqual(findings, [])
        self.assertEqual(warnings, [])

    def test_history_requires_a_matching_closeout_observation(self) -> None:
        note = self.vault / "项目" / "observed.md"
        note.write_text("# Observed\n", encoding="utf-8")
        entry = self.module.GitEntry(
            status="M",
            repo_path="AgentMemory/项目/observed.md",
            path=note,
        )
        self.module.STATE_DB = self.vault.parent / "state.sqlite"
        with closing(sqlite3.connect(self.module.STATE_DB)) as conn, conn:
            conn.execute(
                "CREATE TABLE memory_file_observations (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL)"
            )

        self.assertEqual(self.module.unobserved_history_entries([entry]), [entry])

        digest = hashlib.sha256(note.read_bytes()).hexdigest()
        with closing(sqlite3.connect(self.module.STATE_DB)) as conn, conn:
            conn.execute(
                "INSERT INTO memory_file_observations(path, sha256) VALUES (?, ?)",
                (str(note), digest),
            )
        self.assertEqual(self.module.unobserved_history_entries([entry]), [])

        note.write_text("# Observed\n\nChanged.\n", encoding="utf-8")
        self.assertEqual(self.module.unobserved_history_entries([entry]), [entry])

if __name__ == "__main__":
    unittest.main()
