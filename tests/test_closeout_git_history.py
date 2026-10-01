from __future__ import annotations

import contextlib
import importlib.util
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from state_fixture import initialize_full_state


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


class CloseoutObservedHeadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_closeout()
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.module.LOG_PATH = self.root / "closeout.jsonl"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_explicit_empty_observed_through_never_falls_back_to_same_row_head(self) -> None:
        head = "a" * 40
        self.module.LOG_PATH.write_text(
            json.dumps(
                {
                    "status": "ok",
                    "git_observed_through": "",
                    "git_head_after": head,
                    "commit": head,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual(self.module.last_observed_git_head(), "")

    def test_newer_empty_baseline_preserves_older_explicit_observed_head(self) -> None:
        older = "b" * 40
        newer = "c" * 40
        self.module.LOG_PATH.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "status": "ok",
                            "git_observed_through": older,
                            "git_head_after": older,
                        }
                    ),
                    json.dumps(
                        {
                            "status": "ok",
                            "git_observed_through": "",
                            "git_head_after": newer,
                            "commit": newer,
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual(self.module.last_observed_git_head(), older)

    def test_sha256_length_observed_head_is_accepted(self) -> None:
        sha256_head = "d" * 64
        self.module.LOG_PATH.write_text(
            json.dumps(
                {
                    "status": "ok",
                    "git_observed_through": sha256_head,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual(self.module.last_observed_git_head(), sha256_head)


@unittest.skipIf(os.name == "nt", "POSIX execute bits are not available")
class CloseoutSnapshotModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_closeout()
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.vault = self.root / "AgentMemory"
        (self.vault / "项目").mkdir(parents=True)
        self.note = self.vault / "项目" / "Mode.md"
        self.note.write_text("# Mode\n", encoding="utf-8")
        git(self.root, "init", "-q")
        git(self.root, "config", "user.name", "Snapshot Mode Test")
        git(self.root, "config", "user.email", "snapshot-mode@example.invalid")
        self.module.REPO_ROOT = self.root
        self.module.VAULT_ROOT = self.vault

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_snapshot_rejects_execute_bits_and_never_normalizes_worktree_mode(self) -> None:
        digest = hashlib.sha256(self.note.read_bytes()).hexdigest()
        self.note.chmod(0o755)
        snapshots, error = self.module._snapshot_commit_files(
            [self.note],
            {self.note.resolve(): digest},
        )
        self.assertEqual(snapshots, [])
        self.assertEqual(error["detail"], "GOVERNED_MARKDOWN_MODE_INVALID")
        self.assertEqual(self.note.lstat().st_mode & 0o777, 0o755)

        self.note.chmod(0o644)
        snapshots, error = self.module._snapshot_commit_files(
            [self.note],
            {self.note.resolve(): digest},
        )
        self.assertIsNone(error)
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0].mode, "100644")

    def test_missing_legacy_claim_preserves_deletion_semantics_but_intent_fails(self) -> None:
        missing = self.vault / "项目" / "Deleted.md"
        raw_session = "legacy-deletion-session"
        legacy = {
            "actor": "human",
            "session_hash": self.module.session_hash(raw_session),
            "path": str(missing),
            "rel_path": "项目/Deleted.md",
            "intent_id": "",
            "claim_kind": "legacy",
            "fencing_token": 0,
        }
        checked = self.module.assert_current_claim_leases(
            [legacy],
            actor="human",
            raw_session_id=raw_session,
            stage="deletion_test",
        )
        self.assertEqual(checked[0]["lease_state"], "legacy_allowed")

        intent_bound = {
            **legacy,
            "actor": "codex",
            "session_hash": self.module.session_hash("intent-session"),
            "intent_id": "intent-missing-target",
            "claim_kind": "intent",
            "fencing_token": 1,
        }
        with self.assertRaises(self.module.write_intent.IntentError) as raised:
            self.module.assert_current_claim_leases(
                [intent_bound],
                actor="codex",
                raw_session_id="intent-session",
                stage="intent_test",
            )
        self.assertEqual(
            raised.exception.reason_code,
            "GOVERNED_MARKDOWN_MODE_INVALID",
        )


class CloseoutRenameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_closeout()
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.old_vault = self.root / "MemoryBeforeRename"
        self.new_vault = self.root / "Agent记忆"
        (self.old_vault / "项目").mkdir(parents=True)
        git(self.root, "init", "-q")
        git(self.root, "config", "user.name", "Agent Memory Test")
        git(self.root, "config", "user.email", "test@example.invalid")
        (self.old_vault / "项目" / "existing.md").write_text("# Existing\n", encoding="utf-8")
        git(self.root, "add", "MemoryBeforeRename/项目/existing.md")
        git(self.root, "commit", "-qm", "baseline")
        self.baseline = git(self.root, "rev-parse", "HEAD")
        self.module.REPO_ROOT = self.root
        self.module.VAULT_ROOT = self.new_vault

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def migrate_without_commit(self) -> None:
        git(self.root, "mv", "MemoryBeforeRename", "Agent记忆")
        (self.new_vault / "项目" / "new.md").write_text("# New\n", encoding="utf-8")
        git(self.root, "add", "Agent记忆/项目/new.md")

    def assert_rename_and_add(self, entries) -> None:
        by_name = {entry.path.name: entry for entry in entries}
        self.assertEqual(set(by_name), {"existing.md", "new.md"})
        self.assertTrue(by_name["existing.md"].status.startswith("R"))
        self.assertEqual(
            by_name["existing.md"].previous_repo_path,
            "MemoryBeforeRename/项目/existing.md",
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


class CloseoutHistoryCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_closeout()
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.vault = self.root / "AgentMemory"
        (self.vault / "项目").mkdir(parents=True)
        self.note = self.vault / "项目" / "note.md"
        self.metadata = self.vault / ".DS_Store"
        self.note.write_text("# Note\n", encoding="utf-8")
        self.metadata.write_bytes(b"metadata-v1")
        git(self.root, "init", "-q")
        git(self.root, "config", "user.name", "Agent Memory Test")
        git(self.root, "config", "user.email", "test@example.invalid")
        git(self.root, "add", "AgentMemory")
        git(self.root, "commit", "-qm", "baseline")
        self.baseline = git(self.root, "rev-parse", "HEAD")
        self.module.REPO_ROOT = self.root
        self.module.VAULT_ROOT = self.vault

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_history_ignores_tracked_non_markdown_metadata(self) -> None:
        self.note.write_text("# Note\n\nChanged.\n", encoding="utf-8")
        self.metadata.write_bytes(b"metadata-v2")
        git(self.root, "add", "AgentMemory")
        git(self.root, "commit", "-qm", "external backup")
        head = git(self.root, "rev-parse", "HEAD")

        entries, warnings = self.module.git_history_entries(self.baseline, head)

        self.assertEqual(warnings, [])
        self.assertEqual([entry.repo_path for entry in entries], ["AgentMemory/项目/note.md"])

    def test_dirty_status_ignores_tracked_non_markdown_metadata(self) -> None:
        self.note.write_text("# Note\n\nChanged.\n", encoding="utf-8")
        self.metadata.write_bytes(b"metadata-v2")

        entries, warnings = self.module.git_status_entries()

        self.assertEqual(warnings, [])
        self.assertEqual([entry.repo_path for entry in entries], ["AgentMemory/项目/note.md"])

    def _record_deleted_observation(
        self,
        path: Path,
        deletion_commit: str,
        prior_sha256: str,
        *,
        actor: str = "human",
        trash_sha256: str | None = None,
        evidence_ref_sha256: str | None = None,
    ) -> None:
        sentinel = f"deleted:{deletion_commit}:{prior_sha256}"
        trash_digest = trash_sha256 or prior_sha256
        evidence_digest = evidence_ref_sha256 or ("e" * 64)
        with contextlib.closing(sqlite3.connect(self.module.STATE_DB)) as conn, conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS memory_file_observations "
                "(path TEXT PRIMARY KEY, sha256 TEXT NOT NULL)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_deletion_observations (
                  observation_id TEXT PRIMARY KEY,
                  path TEXT NOT NULL,
                  rel_path TEXT NOT NULL,
                  sentinel TEXT NOT NULL,
                  actor TEXT NOT NULL,
                  user_authorized INTEGER NOT NULL,
                  deletion_commit TEXT NOT NULL,
                  parent_commit TEXT NOT NULL,
                  prior_sha256 TEXT NOT NULL,
                  trash_sha256 TEXT NOT NULL,
                  trash_path_sha256 TEXT NOT NULL,
                  evidence_ref_sha256 TEXT NOT NULL,
                  evidence_ref_length INTEGER NOT NULL,
                  observed_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "INSERT OR REPLACE INTO memory_file_observations(path, sha256) VALUES (?, ?)",
                (str(path), sentinel),
            )
            conn.execute(
                "INSERT INTO memory_deletion_observations "
                "(observation_id, path, rel_path, sentinel, actor, user_authorized, "
                "deletion_commit, parent_commit, prior_sha256, trash_sha256, "
                "trash_path_sha256, evidence_ref_sha256, evidence_ref_length, observed_at) "
                "VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 12, ?)",
                (
                    hashlib.sha256(str(path).encode("utf-8")).hexdigest(),
                    str(path),
                    path.relative_to(self.vault).as_posix(),
                    sentinel,
                    actor,
                    deletion_commit,
                    "a" * 40,
                    prior_sha256,
                    trash_digest,
                    "b" * 64,
                    evidence_digest,
                    "2026-08-02T00:00:00+00:00",
                ),
            )

    def test_history_accepts_audited_deletion_observation_for_latest_path_change(self) -> None:
        deleted = self.vault / "项目" / "deleted.md"
        content = b"# Deleted\n"
        deleted.write_bytes(content)
        git(self.root, "add", "AgentMemory/项目/deleted.md")
        git(self.root, "commit", "-qm", "add note that will be deleted")
        trash = self.root / ".Trash"
        trash.mkdir()
        deleted.replace(trash / "deleted.md")
        git(self.root, "add", "-u", "AgentMemory/项目/deleted.md")
        git(self.root, "commit", "-qm", "authorized deletion")
        deletion_commit = git(self.root, "rev-parse", "HEAD")
        prior_sha256 = hashlib.sha256(content).hexdigest()
        self.module.STATE_DB = self.root / "state.sqlite"
        self._record_deleted_observation(deleted, deletion_commit, prior_sha256)
        entry = self.module.GitEntry(
            status="D",
            repo_path="AgentMemory/项目/deleted.md",
            path=deleted,
        )

        self.assertEqual(self.module.unobserved_history_entries([entry]), [])

    def test_old_deletion_observation_does_not_authorize_a_later_redelete(self) -> None:
        deleted = self.vault / "项目" / "redeleted.md"
        content = b"# Re-deleted\n"
        deleted.write_bytes(content)
        git(self.root, "add", "AgentMemory/项目/redeleted.md")
        git(self.root, "commit", "-qm", "add redelete note")
        trash = self.root / ".Trash"
        trash.mkdir()
        first_trash = trash / "redeleted-first.md"
        deleted.replace(first_trash)
        git(self.root, "add", "-u", "AgentMemory/项目/redeleted.md")
        git(self.root, "commit", "-qm", "first authorized deletion")
        first_deletion = git(self.root, "rev-parse", "HEAD")
        prior_sha256 = hashlib.sha256(content).hexdigest()
        self.module.STATE_DB = self.root / "state.sqlite"
        self._record_deleted_observation(deleted, first_deletion, prior_sha256)

        deleted.write_bytes(content)
        git(self.root, "add", "AgentMemory/项目/redeleted.md")
        git(self.root, "commit", "-qm", "restore note")
        deleted.replace(trash / "redeleted-second.md")
        git(self.root, "add", "-u", "AgentMemory/项目/redeleted.md")
        git(self.root, "commit", "-qm", "later deletion")
        entry = self.module.GitEntry(
            status="D",
            repo_path="AgentMemory/项目/redeleted.md",
            path=deleted,
        )

        self.assertEqual(self.module.unobserved_history_entries([entry]), [entry])

    def test_history_rejects_wrong_actor_trash_hash_or_evidence_hash(self) -> None:
        deleted = self.vault / "项目" / "invalid-audit.md"
        content = b"# Invalid audit\n"
        deleted.write_bytes(content)
        git(self.root, "add", "AgentMemory/项目/invalid-audit.md")
        git(self.root, "commit", "-qm", "add invalid audit note")
        trash = self.root / ".Trash"
        trash.mkdir()
        deleted.replace(trash / "invalid-audit.md")
        git(self.root, "add", "-u", "AgentMemory/项目/invalid-audit.md")
        git(self.root, "commit", "-qm", "delete invalid audit note")
        deletion_commit = git(self.root, "rev-parse", "HEAD")
        prior_sha256 = hashlib.sha256(content).hexdigest()
        self.module.STATE_DB = self.root / "state.sqlite"
        entry = self.module.GitEntry(
            status="D",
            repo_path="AgentMemory/项目/invalid-audit.md",
            path=deleted,
        )

        self._record_deleted_observation(
            deleted,
            deletion_commit,
            prior_sha256,
            actor="migration",
        )
        self.assertEqual(self.module.unobserved_history_entries([entry]), [entry])

        with contextlib.closing(sqlite3.connect(self.module.STATE_DB)) as conn, conn:
            conn.execute(
                "UPDATE memory_deletion_observations SET actor='human', trash_sha256=?",
                ("c" * 64,),
            )
        self.assertEqual(self.module.unobserved_history_entries([entry]), [entry])

        with contextlib.closing(sqlite3.connect(self.module.STATE_DB)) as conn, conn:
            conn.execute(
                "UPDATE memory_deletion_observations "
                "SET trash_sha256=prior_sha256, evidence_ref_sha256=''"
            )
        self.assertEqual(self.module.unobserved_history_entries([entry]), [entry])


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

    def test_project_track_infers_current_project_for_postwrite_search(self) -> None:
        project_note = self.vault / "项目" / "project-a.md"
        project_note.write_text(
            "---\n"
            "memory_type: project\n"
            "track: project\n"
            "project_id: project-a\n"
            "status: active\n"
            "---\n\n"
            "# Project A\n\nA scoped deployment rule.\n",
            encoding="utf-8",
        )
        entry = self.module.GitEntry(
            status="A",
            repo_path="AgentMemory/项目/project-a.md",
            path=project_note,
        )
        args = Namespace(reconcile_all=False, limit=8, no_zvec=True, current_project="")
        with mock.patch.object(
            self.module,
            "search_memory",
            return_value=([], [], {"sqlite": {"status": "ok"}}),
        ) as search:
            findings, warnings = self.module.postwrite_reconcile([entry], args)

        self.assertEqual(findings, [])
        self.assertEqual(warnings, [])
        self.assertEqual(search.call_args.kwargs["current_project"], "project-a")

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
        with mock.patch.object(
            self.module,
            "search_memory",
            return_value=(rows, [], {"sqlite": {"status": "ok"}}),
        ):
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
        with contextlib.closing(sqlite3.connect(self.module.STATE_DB)) as conn, conn:
            conn.execute(
                "CREATE TABLE memory_file_observations (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL)"
            )

        self.assertEqual(self.module.unobserved_history_entries([entry]), [entry])

        digest = hashlib.sha256(note.read_bytes()).hexdigest()
        with contextlib.closing(sqlite3.connect(self.module.STATE_DB)) as conn, conn:
            conn.execute(
                "INSERT INTO memory_file_observations(path, sha256) VALUES (?, ?)",
                (str(note), digest),
            )
        self.assertEqual(self.module.unobserved_history_entries([entry]), [])

        note.write_text("# Observed\n\nChanged.\n", encoding="utf-8")
        self.assertEqual(self.module.unobserved_history_entries([entry]), [entry])


class CloseoutCommitSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_closeout()
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.vault = self.root / "Agent记忆"
        self.vault.mkdir()
        self.note = self.vault / "AGENTS.md"
        self.note.write_text("# Rules\n\nOriginal.\n", encoding="utf-8")
        self.index = self.vault / "INDEX.md"
        self.index.write_text(
            "<!-- agent-memory-generated-index:v1 -->\n# Generated Index\n\nOriginal.\n",
            encoding="utf-8",
        )
        git(self.root, "init", "-q")
        git(self.root, "config", "user.name", "Snapshot Test")
        git(self.root, "config", "user.email", "snapshot@example.invalid")
        git(self.root, "add", "Agent记忆")
        git(self.root, "commit", "-qm", "baseline")
        self.baseline = git(self.root, "rev-parse", "HEAD")
        self.module.REPO_ROOT = self.root
        self.module.VAULT_ROOT = self.vault
        self.module.CONFIG_ROOT = self.root / "runtime"
        self.module.STATE_DB = self.module.CONFIG_ROOT / "state.sqlite"
        self.module.LOG_PATH = self.module.CONFIG_ROOT / "logs" / "closeout.jsonl"
        initialize_full_state(self.module.STATE_DB)
        self.args = Namespace(commit=True, dry_run=False, message="snapshot commit", actor="codex")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def bind_generated_transaction(self, binding: dict[str, str], digest: str) -> None:
        with sqlite3.connect(self.module.STATE_DB) as conn:
            changed = conn.execute(
                "UPDATE generated_index_closeout_transactions "
                "SET status='generated_bound', consumer_pid=?, generated_sha256=? "
                "WHERE transaction_id=? AND status='registered'",
                (os.getpid(), digest, binding["transaction_id"]),
            ).rowcount
            self.assertEqual(changed, 1)

    def prepare_generated_index_sync_crash(self, transaction_id: str):
        snapshot = self.module.capture_generated_index_snapshot()
        binding = self.module.generated_index_transaction_binding(
            transaction_id=transaction_id,
            actor="migration",
            raw_session_id="",
            git_head=self.baseline,
            index_base_sha256=snapshot.raw_sha256,
            full_vault_inputs_sha256=self.module.full_vault_input_projection_sha256(),
            lease_checkpoints=[],
        )
        self.module._register_generated_index_closeout_transaction(
            transaction_binding=binding,
        )
        generated = (
            "<!-- agent-memory-generated-index:v1 -->\n"
            "# Generated Index\n\n"
            "- [Rules](AGENTS.md)\n"
        ).encode("utf-8")
        self.index.write_bytes(generated)
        digest = hashlib.sha256(generated).hexdigest()
        self.bind_generated_transaction(binding, digest)
        args = Namespace(
            commit=True,
            dry_run=False,
            message="crash after update-ref",
            actor="migration",
        )
        with mock.patch.object(
            self.module,
            "_sync_real_index",
            return_value={"ok": False, "stage": "injected_crash"},
        ):
            committed = self.module.commit_files(
                [self.index],
                args,
                expected_raw_sha256={self.index: digest},
                expected_head=self.baseline,
                expected_full_vault_inputs_sha256=binding["full_vault_inputs_sha256"],
            )
        with sqlite3.connect(self.module.STATE_DB) as conn:
            conn.execute(
                "UPDATE generated_index_closeout_transactions "
                "SET issuer_pid=999999, issued_at_epoch=0, expires_at_epoch=0 "
                "WHERE transaction_id=?",
                (binding["transaction_id"],),
            )
            conn.commit()
        return binding, digest, committed["commit"]

    def prepare_multi_path_index_sync_crash(self, *, stage_unrelated: bool = False):
        note_bytes = b"# Rules\n\nApproved ordinary target.\n"
        index_bytes = (
            b"<!-- agent-memory-generated-index:v1 -->\n"
            b"# Generated Index\n\nApproved generated target.\n"
        )
        self.note.write_bytes(note_bytes)
        self.index.write_bytes(index_bytes)
        unrelated = self.root / ".ailu" / "conversation-writer.json"
        unrelated_stage = ""
        if stage_unrelated:
            unrelated.parent.mkdir()
            unrelated.write_bytes(b'{"owner":"external-v1"}\n')
            git(self.root, "add", ".ailu/conversation-writer.json")
            unrelated_stage = git(
                self.root,
                "ls-files",
                "--stage",
                "--",
                ".ailu/conversation-writer.json",
            )
        with mock.patch.object(
            self.module,
            "_sync_real_index",
            return_value={"ok": False, "stage": "injected_crash"},
        ):
            committed = self.module.commit_files(
                [self.note, self.index],
                self.args,
                expected_raw_sha256={
                    self.note: hashlib.sha256(note_bytes).hexdigest(),
                    self.index: hashlib.sha256(index_bytes).hexdigest(),
                },
                expected_head=self.baseline,
            )
        self.assertEqual(committed["stage"], "injected_crash", committed)
        self.assertRegex(str(committed.get("commit", "")), r"^[0-9a-f]{40,64}$")
        return committed["commit"], unrelated, unrelated_stage

    def prepare_pending_index_sync_before_head_publish(self):
        approved = b"# Rules\n\nApproved before HEAD publish.\n"
        self.note.write_bytes(approved)
        git(self.root, "add", "Agent记忆/AGENTS.md")
        git(self.root, "commit", "-qm", "target object")
        target_head = git(self.root, "rev-parse", "HEAD")
        git(self.root, "reset", "--mixed", self.baseline)
        snapshots, failure = self.module._snapshot_commit_files(
            [self.note],
            {self.note: hashlib.sha256(approved).hexdigest()},
        )
        self.assertIsNone(failure)
        deadline = (
            self.module.time.monotonic()
            + self.module.GIT_INDEX_SYNC_DEADLINE_SECONDS
        )
        transaction = self.module._prepare_real_index_sync(
            snapshots,
            expected_head=self.baseline,
            target_head=target_head,
            deadline=deadline,
        )
        held = self.module._hold_prepared_index_lock_before_head_cas(
            transaction,
            expected_head=self.baseline,
            deadline=deadline,
        )
        return transaction, held, target_head

    def initial_index_args(self) -> Namespace:
        return Namespace(
            actor="migration",
            trigger="migration",
            commit=True,
            dry_run=False,
            message="initial generated index migration",
        )

    @staticmethod
    def initial_index_capability() -> dict[str, object]:
        return {"token": "t" * 64, "issuer_pid": os.getpid()}

    def test_real_index_sync_waits_for_transient_unknown_lock_without_touching_it(self) -> None:
        approved = b"# Rules\n\nApproved.\n"
        self.note.write_bytes(approved)
        lock = self.root / ".git" / "index.lock"
        user_bytes = b"other-git-process\n"
        lock.write_bytes(user_bytes)

        def external_git_releases_lock(_interval):
            self.assertEqual(lock.read_bytes(), user_bytes)
            self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)
            lock.unlink()

        # Patch this module's retry clock, not the process-wide time module:
        # subprocess.wait also sleeps and must not release a Git lock for us.
        with mock.patch.object(self.module, "time", mock.Mock(wraps=time)) as clock:
            clock.sleep.side_effect = external_git_releases_lock
            result = self.module.commit_files(
                [self.note],
                self.args,
                expected_raw_sha256={self.note: hashlib.sha256(approved).hexdigest()},
                expected_head=self.baseline,
            )

        self.assertTrue(result["ok"], result)
        clock.sleep.assert_called_once()
        self.assertFalse(lock.exists())
        self.assertEqual(git(self.root, "status", "--porcelain", "--", "Agent记忆/AGENTS.md"), "")

    def test_real_index_sync_preserves_persistent_unknown_lock_and_fails_closed(self) -> None:
        approved = b"# Rules\n\nApproved.\n"
        self.note.write_bytes(approved)
        lock = self.root / ".git" / "index.lock"
        user_bytes = b"other-git-process\n"
        lock.write_bytes(user_bytes)
        # Exercise persistent-lock rejection, not host speed while preparing
        # the index. Keep the real overall deadline; skip only fixture retries.
        with mock.patch.object(self.module, "GIT_INDEX_LOCK_RETRY_SECONDS", 0.0):
            result = self.module.commit_files(
                [self.note],
                self.args,
                expected_raw_sha256={self.note: hashlib.sha256(approved).hexdigest()},
                expected_head=self.baseline,
            )

        self.assertFalse(result["ok"])
        self.assertEqual(result["stage"], "index_sync_lock")
        self.assertEqual(result["detail"], "GIT_INDEX_LOCKED")
        self.assertEqual(lock.read_bytes(), user_bytes)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)

    def test_real_index_sync_never_follows_unknown_symlinked_lock(self) -> None:
        approved = b"# Rules\n\nApproved.\n"
        self.note.write_bytes(approved)
        lock = self.root / ".git" / "index.lock"
        outside = self.root / "user-owned-lock-target"
        user_bytes = b"preserve-me\n"
        outside.write_bytes(user_bytes)
        lock.symlink_to(outside)
        result = self.module.commit_files(
            [self.note],
            self.args,
            expected_raw_sha256={self.note: hashlib.sha256(approved).hexdigest()},
            expected_head=self.baseline,
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["stage"], "index_sync_lock")
        self.assertEqual(result["detail"], "GIT_INDEX_LOCK_UNSAFE")
        self.assertTrue(lock.is_symlink())
        self.assertEqual(outside.read_bytes(), user_bytes)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)

    def test_real_index_sync_rejects_same_path_third_state_before_head_update(self) -> None:
        approved = b"# Rules\n\nApproved.\n"
        self.note.write_bytes(b"# Rules\n\nThird-party staged bytes.\n")
        git(self.root, "add", "Agent记忆/AGENTS.md")
        staged_before = git(self.root, "ls-files", "--stage", "--", "Agent记忆/AGENTS.md")
        self.note.write_bytes(approved)

        result = self.module.commit_files(
            [self.note],
            self.args,
            expected_raw_sha256={self.note: hashlib.sha256(approved).hexdigest()},
            expected_head=self.baseline,
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["stage"], "index_sync_prepare")
        self.assertEqual(result["detail"], "GIT_INDEX_OWNED_PATH_DRIFT")
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)
        self.assertEqual(
            git(self.root, "ls-files", "--stage", "--", "Agent记忆/AGENTS.md"),
            staged_before,
        )

    def test_pre_cas_unrelated_index_flag_drift_is_preserved_and_rejected(self) -> None:
        unrelated = self.root / "unrelated.txt"
        unrelated.write_text("tracked\n", encoding="utf-8")
        git(self.root, "add", "unrelated.txt")
        git(self.root, "commit", "-qm", "tracked unrelated")
        self.baseline = git(self.root, "rev-parse", "HEAD")
        approved = b"# Rules\n\nApproved with index flag race.\n"
        self.note.write_bytes(approved)
        real_prepare = self.module._prepare_real_index_sync

        def prepare_then_change_flag(*args, **kwargs):
            transaction = real_prepare(*args, **kwargs)
            git(self.root, "update-index", "--skip-worktree", "unrelated.txt")
            return transaction

        with mock.patch.object(
            self.module,
            "_prepare_real_index_sync",
            side_effect=prepare_then_change_flag,
        ):
            result = self.module.commit_files(
                [self.note],
                self.args,
                expected_raw_sha256={
                    self.note: hashlib.sha256(approved).hexdigest()
                },
                expected_head=self.baseline,
            )

        self.assertFalse(result["ok"], result)
        self.assertEqual(result["stage"], "index_sync_lock")
        self.assertEqual(result["detail"], "GIT_INDEX_UNRELATED_STAGED_DRIFT")
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)
        self.assertTrue(git(self.root, "ls-files", "-v", "unrelated.txt").startswith("S "))
        self.assertFalse((self.root / ".git" / "index.lock").exists())

    def test_recovery_releases_own_pre_cas_lock_when_head_is_still_base(self) -> None:
        transaction, _held, _target_head = (
            self.prepare_pending_index_sync_before_head_publish()
        )
        lock = self.root / ".git" / "index.lock"
        self.assertTrue(
            self.module._same_regular_inode(
                lock,
                Path(transaction["candidate_path"]),
            )
        )

        recovered = self.module.recover_closeout_index_transactions()

        self.assertTrue(recovered["ok"], recovered)
        self.assertEqual(recovered["aborted"], 1)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)
        self.assertFalse(lock.exists())
        self.assertTrue(Path(transaction["outcome_path"]).is_file())
        self.assertTrue(
            any(
                path.name.endswith(".released-index-lock")
                for path in Path(transaction["manifest_path"]).parent.iterdir()
            )
        )

    def test_recovery_releases_exact_owned_lock_when_manifest_load_fails(self) -> None:
        transaction, _held, _target_head = (
            self.prepare_pending_index_sync_before_head_publish()
        )
        manifest_path = Path(transaction["manifest_path"])
        candidate_path = Path(transaction["candidate_path"])
        lock = self.root / ".git" / "index.lock"
        manifest_path.write_text("{\"corrupt\":true}\n", encoding="utf-8")
        self.assertTrue(self.module._same_regular_inode(lock, candidate_path))

        recovered = self.module.recover_closeout_index_transactions()

        self.assertFalse(recovered["ok"], recovered)
        self.assertEqual(recovered["detail"], "GIT_INDEX_RECOVERY_MANIFEST_INVALID")
        self.assertFalse(lock.exists())
        evidence = [
            path
            for path in manifest_path.parent.iterdir()
            if path.name.endswith(".released-index-lock")
        ]
        self.assertEqual(len(evidence), 1)
        self.assertTrue(
            self.module._same_regular_inode(evidence[0], candidate_path)
        )

    def test_partial_terminal_outcome_releases_only_exact_owned_lock(self) -> None:
        transaction, _held, _target_head = (
            self.prepare_pending_index_sync_before_head_publish()
        )
        outcome_path = Path(transaction["outcome_path"])
        candidate_path = Path(transaction["candidate_path"])
        lock = self.root / ".git" / "index.lock"
        partial = b'{"schema_version":1'
        self.module._write_private_file_exclusive(outcome_path, partial)
        self.module._fsync_directory(outcome_path.parent)
        self.assertTrue(self.module._same_regular_inode(lock, candidate_path))

        recovered = self.module.recover_closeout_index_transactions()

        self.assertFalse(recovered["ok"], recovered)
        self.assertFalse(lock.exists())
        self.assertEqual(outcome_path.read_bytes(), partial)
        evidence = [
            path
            for path in outcome_path.parent.iterdir()
            if path.name.endswith(".released-index-lock")
        ]
        self.assertEqual(len(evidence), 1)
        self.assertTrue(self.module._same_regular_inode(evidence[0], candidate_path))

    def test_outcome_publish_failure_never_creates_partial_final_path(self) -> None:
        transaction, held, _target_head = (
            self.prepare_pending_index_sync_before_head_publish()
        )
        outcome_path = Path(transaction["outcome_path"])
        real_link = self.module.os.link

        def fail_only_final_outcome_link(source, target, *args, **kwargs):
            if Path(target) == outcome_path:
                raise OSError("injected crash before atomic outcome publish")
            return real_link(source, target, *args, **kwargs)

        try:
            with mock.patch.object(
                self.module.os,
                "link",
                side_effect=fail_only_final_outcome_link,
            ):
                with self.assertRaises(OSError):
                    self.module._record_index_sync_outcome(
                        transaction,
                        "aborted_before_head_publish",
                        compact_candidate=False,
                    )
            self.assertFalse(outcome_path.exists())
            candidates = list(
                outcome_path.parent.glob(
                    f".{outcome_path.name}.*.outcome-candidate"
                )
            )
            self.assertEqual(len(candidates), 1)
            payload = self.module._read_private_json(candidates[0])
            self.assertEqual(
                payload["transaction_id"],
                transaction["manifest"]["transaction_id"],
            )
        finally:
            self.module._release_held_index_lock(held)
        self.assertFalse((self.root / ".git" / "index.lock").exists())

    def test_manifest_publish_failure_never_creates_partial_final_path(self) -> None:
        approved = b"# Rules\n\nApproved manifest publish crash.\n"
        self.note.write_bytes(approved)
        real_link = self.module.os.link

        def fail_only_final_manifest_link(source, target, *args, **kwargs):
            if Path(target).name.endswith(".manifest.json"):
                raise OSError("injected crash before atomic manifest publish")
            return real_link(source, target, *args, **kwargs)

        with mock.patch.object(
            self.module.os,
            "link",
            side_effect=fail_only_final_manifest_link,
        ):
            result = self.module.commit_files(
                [self.note],
                self.args,
                expected_raw_sha256={
                    self.note: hashlib.sha256(approved).hexdigest()
                },
                expected_head=self.baseline,
            )

        self.assertFalse(result["ok"], result)
        self.assertEqual(result["stage"], "index_sync_prepare")
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)
        recovery_root = self.root / ".git" / "agent-memory-closeout-recovery"
        self.assertEqual(list(recovery_root.glob("[0-9a-f]*.manifest.json")), [])
        candidates = list(
            recovery_root.glob(".*.manifest.json.*.outcome-candidate")
        )
        self.assertEqual(len(candidates), 1)
        payload = self.module._read_private_json(candidates[0])
        self.assertRegex(payload["transaction_id"], r"^[0-9a-f]{32}$")
        self.assertFalse((self.root / ".git" / "index.lock").exists())

    def test_pre_cas_operation_drift_releases_only_owned_lock(self) -> None:
        approved = b"# Rules\n\nApproved.\n"
        self.note.write_bytes(approved)
        real_hold = self.module._hold_prepared_index_lock_before_head_cas

        def hold_then_start_merge(*args, **kwargs):
            held = real_hold(*args, **kwargs)
            (self.root / ".git" / "MERGE_HEAD").write_text(
                f"{self.baseline}\n",
                encoding="ascii",
            )
            return held

        with mock.patch.object(
            self.module,
            "_hold_prepared_index_lock_before_head_cas",
            side_effect=hold_then_start_merge,
        ):
            result = self.module.commit_files(
                [self.note],
                self.args,
                expected_raw_sha256={
                    self.note: hashlib.sha256(approved).hexdigest()
                },
                expected_head=self.baseline,
            )

        self.assertFalse(result["ok"], result)
        self.assertEqual(result["stage"], "git_operation_head_cas")
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)
        self.assertFalse((self.root / ".git" / "index.lock").exists())
        recovery_root = self.root / ".git" / "agent-memory-closeout-recovery"
        self.assertTrue(
            any(path.name.endswith(".released-index-lock") for path in recovery_root.iterdir())
        )

    def test_ambiguous_update_ref_success_is_read_back_and_completed(self) -> None:
        approved = b"# Rules\n\nApproved ambiguous update-ref.\n"
        self.note.write_bytes(approved)
        real_run_command = self.module.run_command

        def publish_then_report_timeout(command, *args, **kwargs):
            result = real_run_command(command, *args, **kwargs)
            if "update-ref" in command and "HEAD" in command:
                return {**result, "ok": False, "returncode": 124, "detail": "timeout"}
            return result

        with mock.patch.object(
            self.module,
            "run_command",
            side_effect=publish_then_report_timeout,
        ):
            result = self.module.commit_files(
                [self.note],
                self.args,
                expected_raw_sha256={
                    self.note: hashlib.sha256(approved).hexdigest()
                },
                expected_head=self.baseline,
            )

        self.assertTrue(result["ok"], result)
        self.assertNotEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)
        self.assertEqual(
            git(self.root, "status", "--porcelain", "--", "Agent记忆/AGENTS.md"),
            "",
        )
        self.assertFalse((self.root / ".git" / "index.lock").exists())

    def test_initial_generated_index_migration_rejects_dirty_memory_before_capability(self) -> None:
        self.note.write_text("# Rules\n\nUncommitted user work.\n", encoding="utf-8")
        with mock.patch.object(
            self.module,
            "recover_generated_index_transactions",
            return_value={"ok": True, "recovered": 0, "detail": "none"},
        ), mock.patch.object(
            self.module,
            "assert_runtime_maintenance_capability",
            return_value={"maintenance_capability": True},
        ), mock.patch.object(
            self.module,
            "_register_generated_index_closeout_transaction",
        ) as register:
            payload = self.module.run_initial_generated_index_migration(
                self.initial_index_args(),
                maintenance_capability=self.initial_index_capability(),
            )
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["status"], "blocked")
        self.assertEqual(
            payload["reason_code"],
            "GENERATED_INDEX_MIGRATION_DIRTY_MEMORY",
        )
        register.assert_not_called()
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)

    def test_initial_generated_index_plan_rejects_dirty_markdown_without_mutation(self) -> None:
        self.note.write_text("# Rules\n\nUncommitted plan input.\n", encoding="utf-8")
        head_before = git(self.root, "rev-parse", "HEAD")
        git_index_before = hashlib.sha256((self.root / ".git" / "index").read_bytes()).hexdigest()

        payload = self.module.plan_initial_generated_index_migration()

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["status"], "blocked")
        self.assertEqual(payload["reason_code"], "GENERATED_INDEX_MIGRATION_DIRTY_MEMORY")
        self.assertIn("Agent记忆/AGENTS.md", payload["dirty_markdown"])
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), head_before)
        self.assertEqual(
            hashlib.sha256((self.root / ".git" / "index").read_bytes()).hexdigest(),
            git_index_before,
        )

    def test_initial_generated_index_plan_reports_open_recovery_before_mutation(self) -> None:
        snapshot = self.module.capture_generated_index_snapshot()
        binding = self.module.generated_index_transaction_binding(
            transaction_id="b" * 32,
            actor="migration",
            raw_session_id="",
            git_head=self.baseline,
            index_base_sha256=snapshot.raw_sha256,
            full_vault_inputs_sha256=self.module.full_vault_input_projection_sha256(),
            lease_checkpoints=[],
        )
        self.module._register_generated_index_closeout_transaction(
            transaction_binding=binding,
        )
        head_before = git(self.root, "rev-parse", "HEAD")
        index_before = hashlib.sha256((self.root / ".git" / "index").read_bytes()).hexdigest()

        payload = self.module.plan_initial_generated_index_migration()

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["reason_code"], "GENERATED_INDEX_RECOVERY_REQUIRED")
        self.assertEqual(payload["generated_index_recovery"]["pending"], 1)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), head_before)
        self.assertEqual(
            hashlib.sha256((self.root / ".git" / "index").read_bytes()).hexdigest(),
            index_before,
        )

    def test_generated_commit_rejects_non_markdown_merge_in_progress(self) -> None:
        outside = self.root / "unrelated.json"
        outside.write_text('{"version": 1}\n', encoding="utf-8")
        git(self.root, "add", "unrelated.json")
        git(self.root, "commit", "-qm", "add unrelated file")
        self.baseline = git(self.root, "rev-parse", "HEAD")
        outside.write_text('{"version": 2}\n', encoding="utf-8")
        git(self.root, "add", "unrelated.json")
        (self.root / ".git" / "MERGE_HEAD").write_text(
            f"{self.baseline}\n",
            encoding="ascii",
        )
        generated = b"<!-- agent-memory-generated-index:v1 -->\n# Generated Index\n\nBlocked.\n"
        self.index.write_bytes(generated)
        index_before = hashlib.sha256((self.root / ".git" / "index").read_bytes()).hexdigest()

        result = self.module.commit_files(
            [self.index],
            self.initial_index_args(),
            expected_raw_sha256={self.index: hashlib.sha256(generated).hexdigest()},
            expected_head=self.baseline,
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["stage"], "git_operation_precommit")
        self.assertEqual(result["detail"], "GENERATED_INDEX_GIT_OPERATION_IN_PROGRESS")
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)
        self.assertEqual(
            hashlib.sha256((self.root / ".git" / "index").read_bytes()).hexdigest(),
            index_before,
        )
        self.assertEqual(git(self.root, "diff", "--cached", "--name-only"), "unrelated.json")
        self.assertEqual(self.index.read_bytes(), generated)

    def test_initial_generated_index_migration_rejects_markdown_outside_legacy_routes(self) -> None:
        notes = self.vault / "notes"
        notes.mkdir()
        untracked = notes / "user-draft.md"
        untracked.write_text("# Untracked user draft\n", encoding="utf-8")
        with mock.patch.object(
            self.module,
            "recover_generated_index_transactions",
            return_value={"ok": True, "recovered": 0, "detail": "none"},
        ), mock.patch.object(
            self.module,
            "assert_runtime_maintenance_capability",
            return_value={"maintenance_capability": True},
        ), mock.patch.object(
            self.module,
            "_register_generated_index_closeout_transaction",
        ) as register:
            payload = self.module.run_initial_generated_index_migration(
                self.initial_index_args(),
                maintenance_capability=self.initial_index_capability(),
            )
        self.assertFalse(payload["ok"])
        self.assertEqual(
            payload["reason_code"],
            "GENERATED_INDEX_MIGRATION_DIRTY_MEMORY",
        )
        self.assertIn("Agent记忆/notes/user-draft.md", payload["changed_files"])
        register.assert_not_called()

    def test_initial_generated_index_migration_uses_bound_exact_git_commit(self) -> None:
        generated = (
            "<!-- agent-memory-generated-index:v1 -->\n"
            "# Generated Index\n\n"
            "- [Rules](AGENTS.md)\n"
        )

        def generate(_args, *, transaction_binding, maintenance_environment=None):
            self.assertEqual(
                maintenance_environment,
                {
                    "AGENT_MEMORY_MIGRATION_CAPABILITY": "t" * 64,
                    "AGENT_MEMORY_MIGRATION_ISSUER_PID": str(os.getpid()),
                },
            )
            self.index.write_text(generated, encoding="utf-8")
            digest = hashlib.sha256(generated.encode("utf-8")).hexdigest()
            self.bind_generated_transaction(transaction_binding, digest)
            return {
                "ok": True,
                "detail": "ok",
                "generated_index": {
                    "changed": True,
                    "path": str(self.index),
                    "sha256": digest,
                },
            }

        with mock.patch.object(
            self.module,
            "recover_generated_index_transactions",
            return_value={"ok": True, "recovered": 0, "detail": "none"},
        ), mock.patch.object(
            self.module,
            "assert_runtime_maintenance_capability",
            return_value={"maintenance_capability": True},
        ), mock.patch.object(self.module, "run_index", side_effect=generate):
            payload = self.module.run_initial_generated_index_migration(
                self.initial_index_args(),
                maintenance_capability=self.initial_index_capability(),
            )

        self.assertTrue(payload["ok"], payload)
        commit = payload["commit"]
        self.assertRegex(commit, r"^[0-9a-f]{40,64}$")
        self.assertNotEqual(commit, self.baseline)
        self.assertEqual(
            git(self.root, "show", f"{commit}:Agent记忆/INDEX.md"),
            generated.strip(),
        )
        self.assertEqual(
            git(self.root, "show", f"{commit}:Agent记忆/AGENTS.md"),
            "# Rules\n\nOriginal.",
        )

    def test_initial_generated_index_migration_resumes_after_clean_exact_commit(self) -> None:
        generated = (
            "<!-- agent-memory-generated-index:v1 -->\n"
            "# Generated Index\n\n"
            "- [Rules](AGENTS.md)\n"
        ).encode("utf-8")
        digest = hashlib.sha256(generated).hexdigest()

        def generate(_args, *, transaction_binding, maintenance_environment=None):
            changed = self.index.read_bytes() != generated
            if changed:
                self.index.write_bytes(generated)
            self.bind_generated_transaction(transaction_binding, digest)
            return {
                "ok": True,
                "detail": "ok",
                "generated_index": {
                    "changed": changed,
                    "path": str(self.index),
                    "sha256": digest,
                },
            }

        with mock.patch.object(
            self.module,
            "recover_generated_index_transactions",
            return_value={"ok": True, "recovered": 0, "detail": "none"},
        ), mock.patch.object(
            self.module,
            "assert_runtime_maintenance_capability",
            return_value={"maintenance_capability": True},
        ), mock.patch.object(self.module, "run_index", side_effect=generate):
            first = self.module.run_initial_generated_index_migration(
                self.initial_index_args(),
                maintenance_capability=self.initial_index_capability(),
            )
            second = self.module.run_initial_generated_index_migration(
                self.initial_index_args(),
                maintenance_capability=self.initial_index_capability(),
            )

        self.assertTrue(first["ok"], first)
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["commit"], "skipped")
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), first["commit"])
        self.assertEqual(git(self.root, "status", "--porcelain", "--", "Agent记忆"), "")

    def test_initial_generated_index_migration_preserves_unrelated_staged_json(self) -> None:
        unrelated = self.root / ".ailu" / "conversation-writer.json"
        unrelated.parent.mkdir()
        unrelated_bytes = b'{"owner":"user"}\n'
        unrelated.write_bytes(unrelated_bytes)
        git(self.root, "add", ".ailu/conversation-writer.json")
        staged_before = git(self.root, "ls-files", "--stage", "--", ".ailu/conversation-writer.json")
        generated = (
            "<!-- agent-memory-generated-index:v1 -->\n"
            "# Generated Index\n\n"
            "- [Rules](AGENTS.md)\n"
        )

        def generate(_args, *, transaction_binding, maintenance_environment=None):
            self.index.write_text(generated, encoding="utf-8")
            digest = hashlib.sha256(generated.encode("utf-8")).hexdigest()
            self.bind_generated_transaction(transaction_binding, digest)
            return {
                "ok": True,
                "detail": "ok",
                "generated_index": {
                    "changed": True,
                    "path": str(self.index),
                    "sha256": digest,
                },
            }

        with mock.patch.object(
            self.module,
            "recover_generated_index_transactions",
            return_value={"ok": True, "recovered": 0, "detail": "none"},
        ), mock.patch.object(
            self.module,
            "assert_runtime_maintenance_capability",
            return_value={"maintenance_capability": True},
        ), mock.patch.object(self.module, "run_index", side_effect=generate):
            payload = self.module.run_initial_generated_index_migration(
                self.initial_index_args(),
                maintenance_capability=self.initial_index_capability(),
            )

        self.assertTrue(payload["ok"], payload)
        self.assertEqual(unrelated.read_bytes(), unrelated_bytes)
        self.assertEqual(
            git(self.root, "ls-files", "--stage", "--", ".ailu/conversation-writer.json"),
            staged_before,
        )
        self.assertEqual(
            git(self.root, "diff", "--cached", "--name-only", "--", ".ailu/conversation-writer.json"),
            ".ailu/conversation-writer.json",
        )
        committed_unrelated = subprocess.run(
            ["git", "-C", str(self.root), "cat-file", "-e", f"{payload['commit']}:.ailu/conversation-writer.json"],
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(committed_unrelated.returncode, 0)

    def test_generated_index_recovery_repairs_update_ref_before_index_sync_crash(self) -> None:
        binding, _digest, crash_head = self.prepare_generated_index_sync_crash(
            "9" * 32
        )
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), crash_head)
        self.assertNotEqual(git(self.root, "status", "--porcelain", "--", "Agent记忆/INDEX.md"), "")

        recovered = self.module.recover_generated_index_transactions()

        self.assertTrue(recovered["ok"], recovered)
        self.assertEqual(recovered["committed"], 1)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), crash_head)
        self.assertEqual(
            git(self.root, "status", "--porcelain", "--", "Agent记忆/INDEX.md"),
            "",
        )
        with sqlite3.connect(self.module.STATE_DB) as conn:
            status = conn.execute(
                "SELECT status FROM generated_index_closeout_transactions WHERE transaction_id=?",
                (binding["transaction_id"],),
            ).fetchone()[0]
        self.assertEqual(status, "consumed")

        # The recovered INDEX is our own committed artifact, not an external
        # edit.  Losing this observation used to block every later closeout.
        entry = self.module.GitEntry(
            status="M", repo_path="Agent记忆/INDEX.md", path=self.index,
        )
        self.assertEqual(self.module.unobserved_history_entries([entry]), [])

    def test_consumed_generated_index_repairs_missing_completion_observation(self) -> None:
        binding, digest, crash_head = self.prepare_generated_index_sync_crash("a" * 32)
        recovered = self.module.recover_generated_index_transactions()
        self.assertTrue(recovered["ok"], recovered)
        # Simulate a pre-fix runtime which consumed the durable transaction
        # but died before publishing its completion observation.
        with sqlite3.connect(self.module.STATE_DB) as conn:
            conn.execute("DELETE FROM memory_file_observations WHERE rel_path='INDEX.md'")
        git(self.root, "commit", "--allow-empty", "-qm", "unrelated later commit")
        repaired = self.module.recover_generated_index_transactions()
        self.assertTrue(repaired["ok"], repaired)
        with sqlite3.connect(self.module.STATE_DB) as conn:
            observed = conn.execute(
                "SELECT sha256, git_commit FROM memory_file_observations WHERE rel_path='INDEX.md'"
            ).fetchone()
        self.assertEqual(observed, (digest, crash_head))
        self.assertEqual(self.module.recover_generated_index_transactions()["recovered"], 0)

    def test_consumed_index_proof_does_not_bless_later_manual_edit(self) -> None:
        self.prepare_generated_index_sync_crash("b" * 32)
        self.assertTrue(self.module.recover_generated_index_transactions()["ok"])
        changed = b"# Unapproved external INDEX change\n"
        self.index.write_bytes(changed)
        git(self.root, "add", "Agent记忆/INDEX.md")
        git(self.root, "commit", "-qm", "external index edit")
        self.module.recover_generated_index_transactions()
        entry = self.module.GitEntry(
            status="M", repo_path="Agent记忆/INDEX.md", path=self.index,
        )
        self.assertEqual(self.module.unobserved_history_entries([entry]), [entry])
        self.assertEqual(self.index.read_bytes(), changed)

    def test_atomic_batch_recovery_repairs_ordinary_target_and_index_together(self) -> None:
        crash_head, unrelated, unrelated_stage = self.prepare_multi_path_index_sync_crash(
            stage_unrelated=True
        )

        recovered = self.module.recover_closeout_index_transactions()

        self.assertTrue(recovered["ok"], recovered)
        self.assertEqual(recovered["completed"], 1)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), crash_head)
        self.assertEqual(
            git(self.root, "status", "--porcelain", "--", "Agent记忆/AGENTS.md", "Agent记忆/INDEX.md"),
            "",
        )
        self.assertEqual(
            git(self.root, "ls-files", "--stage", "--", ".ailu/conversation-writer.json"),
            unrelated_stage,
        )
        self.assertEqual(unrelated.read_bytes(), b'{"owner":"external-v1"}\n')

    def test_atomic_batch_recovery_accepts_only_exact_base_new_mixed_residue(self) -> None:
        crash_head, _unrelated, _stage = self.prepare_multi_path_index_sync_crash()
        repo_path = "Agent记忆/AGENTS.md"
        mode, oid = self.module._git_tree_entry(crash_head, repo_path)
        git(self.root, "update-index", "--add", "--cacheinfo", mode, oid, repo_path)

        recovered = self.module.recover_closeout_index_transactions()

        self.assertTrue(recovered["ok"], recovered)
        self.assertEqual(
            git(self.root, "status", "--porcelain", "--", "Agent记忆/AGENTS.md", "Agent记忆/INDEX.md"),
            "",
        )

    def test_atomic_batch_recovery_rejects_owned_third_state_without_partial_update(self) -> None:
        _crash_head, _unrelated, _stage = self.prepare_multi_path_index_sync_crash()
        self.note.write_bytes(b"# Rules\n\nThird staged state.\n")
        git(self.root, "add", "Agent记忆/AGENTS.md")
        self.note.write_bytes(b"# Rules\n\nApproved ordinary target.\n")
        index_before = hashlib.sha256((self.root / ".git" / "index").read_bytes()).hexdigest()
        staged_before = git(self.root, "ls-files", "--stage", "--", "Agent记忆/AGENTS.md")

        recovered = self.module.recover_closeout_index_transactions()

        self.assertFalse(recovered["ok"], recovered)
        self.assertEqual(recovered["detail"], "GIT_INDEX_OWNED_PATH_DRIFT")
        self.assertEqual(hashlib.sha256((self.root / ".git" / "index").read_bytes()).hexdigest(), index_before)
        self.assertEqual(git(self.root, "ls-files", "--stage", "--", "Agent记忆/AGENTS.md"), staged_before)

    def test_atomic_batch_recovery_rejects_head_and_unrelated_staged_drift(self) -> None:
        crash_head, unrelated, _stage = self.prepare_multi_path_index_sync_crash(
            stage_unrelated=True
        )
        unrelated.write_bytes(b'{"owner":"external-v2"}\n')
        git(self.root, "add", ".ailu/conversation-writer.json")
        staged_before = git(self.root, "ls-files", "--stage", "--", ".ailu/conversation-writer.json")
        tree = git(self.root, "rev-parse", f"{crash_head}^{{tree}}")
        drift_head = git(self.root, "commit-tree", tree, "-p", crash_head, "-m", "external head drift")
        git(self.root, "update-ref", "HEAD", drift_head, crash_head)
        index_before = hashlib.sha256((self.root / ".git" / "index").read_bytes()).hexdigest()

        recovered = self.module.recover_closeout_index_transactions()

        self.assertFalse(recovered["ok"], recovered)
        self.assertEqual(recovered["detail"], "GIT_INDEX_HEAD_DRIFT")
        self.assertEqual(hashlib.sha256((self.root / ".git" / "index").read_bytes()).hexdigest(), index_before)
        self.assertEqual(git(self.root, "ls-files", "--stage", "--", ".ailu/conversation-writer.json"), staged_before)

    def test_atomic_batch_recovery_never_overwrites_unrelated_staged_drift(self) -> None:
        _crash_head, unrelated, _stage = self.prepare_multi_path_index_sync_crash(
            stage_unrelated=True
        )
        unrelated.write_bytes(b'{"owner":"external-v2"}\n')
        git(self.root, "add", ".ailu/conversation-writer.json")
        staged_before = git(self.root, "ls-files", "--stage", "--", ".ailu/conversation-writer.json")
        index_before = hashlib.sha256((self.root / ".git" / "index").read_bytes()).hexdigest()

        recovered = self.module.recover_closeout_index_transactions()

        self.assertFalse(recovered["ok"], recovered)
        self.assertEqual(recovered["detail"], "GIT_INDEX_UNRELATED_STAGED_DRIFT")
        self.assertEqual(hashlib.sha256((self.root / ".git" / "index").read_bytes()).hexdigest(), index_before)
        self.assertEqual(git(self.root, "ls-files", "--stage", "--", ".ailu/conversation-writer.json"), staged_before)

    def test_atomic_batch_recovery_blocks_owned_worktree_drift_without_index_write(self) -> None:
        _crash_head, _unrelated, _stage = self.prepare_multi_path_index_sync_crash()
        raced = b"# Rules\n\nUser changed this after the proposal.\n"
        self.note.write_bytes(raced)
        git_index = self.root / ".git" / "index"
        index_before = git_index.read_bytes()

        recovered = self.module.recover_closeout_index_transactions()

        self.assertFalse(recovered["ok"], recovered)
        self.assertEqual(recovered["detail"], "GIT_INDEX_OWNED_WORKTREE_DRIFT")
        self.assertEqual(git_index.read_bytes(), index_before)
        self.assertEqual(self.note.read_bytes(), raced)
        self.assertFalse((self.root / ".git" / "index.lock").exists())

    def test_safe_descendant_completion_is_zero_index_write(self) -> None:
        crash_head, unrelated, _stage = self.prepare_multi_path_index_sync_crash()
        git(self.root, "reset", "--mixed", crash_head)
        unrelated.parent.mkdir(exist_ok=True)
        unrelated.write_bytes(b'{"owner":"external-descendant"}\n')
        git(self.root, "add", ".ailu/conversation-writer.json")
        git(self.root, "commit", "-qm", "unrelated external descendant")
        descendant = git(self.root, "rev-parse", "HEAD")
        self.assertNotEqual(descendant, crash_head)
        git_index = self.root / ".git" / "index"
        index_before = git_index.read_bytes()

        recovered = self.module.recover_closeout_index_transactions()

        self.assertTrue(recovered["ok"], recovered)
        self.assertEqual(recovered["completed"], 1)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), descendant)
        self.assertEqual(git_index.read_bytes(), index_before)
        self.assertFalse((self.root / ".git" / "index.lock").exists())

    def test_descendant_that_changes_owned_tree_is_rejected_without_index_write(self) -> None:
        crash_head, _unrelated, _stage = self.prepare_multi_path_index_sync_crash()
        git(self.root, "reset", "--mixed", crash_head)
        self.note.write_bytes(b"# Rules\n\nExternal owned descendant.\n")
        git(self.root, "add", "Agent记忆/AGENTS.md")
        git(self.root, "commit", "-qm", "owned external descendant")
        git_index = self.root / ".git" / "index"
        index_before = git_index.read_bytes()

        recovered = self.module.recover_closeout_index_transactions()

        self.assertFalse(recovered["ok"], recovered)
        self.assertEqual(recovered["detail"], "GIT_INDEX_HEAD_DRIFT")
        self.assertEqual(git_index.read_bytes(), index_before)

    def test_descendant_with_mixed_owned_index_is_rejected_without_index_write(self) -> None:
        crash_head, _unrelated, _stage = self.prepare_multi_path_index_sync_crash()
        tree = git(self.root, "rev-parse", f"{crash_head}^{{tree}}")
        descendant = git(
            self.root,
            "commit-tree",
            tree,
            "-p",
            crash_head,
            "-m",
            "same-tree descendant",
        )
        git(self.root, "update-ref", "HEAD", descendant, crash_head)
        git_index = self.root / ".git" / "index"
        index_before = git_index.read_bytes()

        recovered = self.module.recover_closeout_index_transactions()

        self.assertFalse(recovered["ok"], recovered)
        self.assertEqual(recovered["detail"], "GIT_INDEX_HEAD_DRIFT")
        self.assertEqual(git_index.read_bytes(), index_before)
        self.assertFalse((self.root / ".git" / "index.lock").exists())

    def test_failed_commit_step_keeps_durable_generated_index_recoverable(self) -> None:
        binding, digest, crash_head = self.prepare_generated_index_sync_crash(
            "b" * 32
        )

        finalized = self.module.resolve_generated_index_transaction(
            transaction_binding=binding,
            index_step={"ok": True},
            snapshot=None,
            commit_step={
                "ok": False,
                "stage": "index_sync",
                "commit": crash_head,
            },
            git_head_before=self.baseline,
        )

        self.assertFalse(finalized["ok"], finalized)
        self.assertEqual(
            finalized["detail"],
            "GENERATED_INDEX_COMMIT_RECOVERY_REQUIRED",
        )
        with sqlite3.connect(self.module.STATE_DB) as conn:
            status = conn.execute(
                "SELECT status FROM generated_index_closeout_transactions "
                "WHERE transaction_id=?",
                (binding["transaction_id"],),
            ).fetchone()[0]
        self.assertEqual(status, "generated_bound")

        recovered = self.module.recover_generated_index_transactions()

        self.assertTrue(recovered["ok"], recovered)
        self.assertEqual(recovered["committed"], 1)
        self.assertEqual(
            hashlib.sha256(self.index.read_bytes()).hexdigest(),
            digest,
        )
        with sqlite3.connect(self.module.STATE_DB) as conn:
            status = conn.execute(
                "SELECT status FROM generated_index_closeout_transactions "
                "WHERE transaction_id=?",
                (binding["transaction_id"],),
            ).fetchone()[0]
        self.assertEqual(status, "consumed")

    def test_expired_governance_repair_consumes_or_reads_back_only_the_exact_task_transaction(self) -> None:
        raw_session_id = "repair-session"
        intent_id = "1" * 32
        fencing_token = 7
        target = "AGENTS.md"
        review_sha256 = "7" * 64
        proposal_sha256 = hashlib.sha256(self.note.read_bytes()).hexdigest()
        checkpoint = [{
            "stage": "before_checks",
            "path": target,
            "intent_id": intent_id,
            "fencing_token": fencing_token,
            "lease_state": "live",
        }]
        snapshot = self.module.capture_generated_index_snapshot()
        binding = self.module.generated_index_transaction_binding(
            transaction_id="d" * 32,
            actor="codex",
            raw_session_id=raw_session_id,
            git_head=self.baseline,
            index_base_sha256=snapshot.raw_sha256,
            full_vault_inputs_sha256=(
                self.module.full_vault_input_projection_sha256()
            ),
            lease_checkpoints=checkpoint,
        )
        self.module._register_generated_index_closeout_transaction(
            transaction_binding=binding,
        )
        now = int(time.time())
        with sqlite3.connect(self.module.STATE_DB) as conn:
            conn.execute(
                "UPDATE generated_index_closeout_transactions SET "
                "status='generated_bound', issuer_pid=999991, "
                "consumer_pid=999992, issued_at_epoch=?, expires_at_epoch=?, "
                "claimed_at_epoch=?, generated_sha256=? WHERE transaction_id=?",
                (
                    now - 19,
                    now - 11,
                    now - 18,
                    snapshot.raw_sha256,
                    binding["transaction_id"],
                ),
            )
            conn.execute(
                "INSERT INTO memory_session_claims ("
                "session_hash, actor, path, rel_path, status, claimed_at, "
                "updated_at, completed_at, intent_id, target_key, "
                "fencing_token, claim_kind"
                ") VALUES (?, 'codex', ?, ?, 'active', ?, ?, NULL, ?, ?, ?, 'intent')",
                (
                    self.module.session_hash(raw_session_id),
                    str(self.note.resolve()),
                    target,
                    "2026-08-25T00:00:00+00:00",
                    "2026-08-25T00:00:00+00:00",
                    intent_id,
                    target.casefold(),
                    fencing_token,
                ),
            )
            conn.commit()
        stored = {
            "intent_id": intent_id,
            "actor": "codex",
            "session_hash": self.module.session_hash(raw_session_id),
            "target_rel_path": target,
            "target_key": target.casefold(),
            "fencing_token": fencing_token,
            "status": "validated",
            "base_exists": 1,
            "base_raw_sha256": proposal_sha256,
            "base_canonical_sha256": proposal_sha256,
            "read_token": "6" * 64,
            "scope_app_id": "agent-memory",
            "scope_project_id": "agent-memory-vault",
            "reason_code": (
                self.module.write_intent.EXPIRED_VALIDATED_RECOVERY_REASON
            ),
            "proposal_raw_sha256": proposal_sha256,
            "proposal_canonical_sha256": proposal_sha256,
            "proposal_size_bytes": len(self.note.read_bytes()),
            "final_raw_sha256": proposal_sha256,
            "final_canonical_sha256": proposal_sha256,
            "base_git_head": self.baseline,
            "validated_git_head": self.baseline,
            "early_commit": 0,
            "proposal_commit": "",
            "evidence_ref_sha256": hashlib.sha256(
                f"content-migration-review:{review_sha256}".encode("utf-8")
            ).hexdigest(),
            "operation": "governance_migration",
            "reconcile_action": "UPDATE",
            "target_status": "",
            "transition_reason_sha256": "",
            "validation_mode": "exact",
            "validated_at": "2026-08-25T00:00:00+00:00",
            "bound_base_raw_sha256": proposal_sha256,
            "claim_ref_sha256": "5" * 64,
            "approval_required": 1,
            "source_class": "user_direct",
            "knowledge_kind": "rule",
            "asserted_by": "user",
            "updated_at": self.module.dt.datetime.fromtimestamp(
                now - 20,
                tz=self.module.dt.timezone.utc,
            ).replace(microsecond=0).isoformat(),
            "expires_at": self.module.dt.datetime.fromtimestamp(
                now - 10,
                tz=self.module.dt.timezone.utc,
            ).replace(microsecond=0).isoformat(),
        }
        call = {
            "actor": "codex",
            "raw_session_id": raw_session_id,
            "intent_id": intent_id,
            "target_relative_path": target,
            "fencing_token": fencing_token,
            "review_sha256": review_sha256,
            "base_raw_sha256": proposal_sha256,
            "base_canonical_sha256": proposal_sha256,
            "read_token": "6" * 64,
            "scope_app_id": "agent-memory",
            "scope_project_id": "agent-memory-vault",
            "proposal_raw_sha256": proposal_sha256,
            "proposal_canonical_sha256": proposal_sha256,
            "proposal_size_bytes": len(self.note.read_bytes()),
            "base_git_head": self.baseline,
            "validated_git_head": self.baseline,
            "early_commit": False,
            "proposal_commit": "",
        }
        with mock.patch.object(
            self.module.write_intent,
            "VAULT_ROOT",
            self.vault,
        ), mock.patch.object(
            self.module.write_intent,
            "GIT_ROOT",
            self.root,
        ), mock.patch.object(
            self.module.write_intent,
            "STATE_DB",
            self.module.STATE_DB,
        ), mock.patch.object(
            self.module.write_intent,
            "show_intent",
            return_value={"intent": stored, "receipt": None},
        ), mock.patch.object(
            self.module.write_intent,
            "assert_current_lease",
            return_value=stored,
        ), mock.patch.object(
            self.module.write_intent,
            "has_valid_confirmation_capability_approval",
            return_value=True,
        ):
            with mock.patch.object(
                self.module,
                "current_git_head",
                side_effect=[
                    (self.baseline, []),
                    ("f" * 40, []),
                ],
            ), self.assertRaises(
                self.module.GeneratedIndexCapabilityError
            ) as concurrent_drift:
                self.module.recover_expired_governance_generated_index_transaction(
                    **call
                )
            self.assertEqual(
                str(concurrent_drift.exception),
                "EXPIRED_VALIDATED_RECOVERY_INDEX_CONCURRENT_DRIFT",
            )
            with sqlite3.connect(self.module.STATE_DB) as conn:
                self.assertEqual(
                    conn.execute(
                        "SELECT status FROM generated_index_closeout_transactions "
                        "WHERE transaction_id=?",
                        (binding["transaction_id"],),
                    ).fetchone()[0],
                    "consumed",
                )
            first = (
                self.module.recover_expired_governance_generated_index_transaction(
                    **call
                )
            )
            consumed_at = None
            with sqlite3.connect(self.module.STATE_DB) as conn:
                consumed_at = conn.execute(
                    "SELECT consumed_at_epoch FROM "
                    "generated_index_closeout_transactions WHERE transaction_id=?",
                    (binding["transaction_id"],),
                ).fetchone()[0]
            second = (
                self.module.recover_expired_governance_generated_index_transaction(
                    **call
                )
            )
            with sqlite3.connect(self.module.STATE_DB) as conn:
                repeated_consumed_at = conn.execute(
                    "SELECT consumed_at_epoch FROM "
                    "generated_index_closeout_transactions WHERE transaction_id=?",
                    (binding["transaction_id"],),
                ).fetchone()[0]

            lock_state = {"held": False}

            @contextlib.contextmanager
            def tracked_closeout_lock(_timeout: float):
                self.assertFalse(lock_state["held"])
                lock_state["held"] = True
                try:
                    yield
                finally:
                    lock_state["held"] = False

            def publish_repair(evidence: dict[str, str]):
                self.assertTrue(lock_state["held"])
                self.assertEqual(evidence, first)
                return {
                    "intent_id": intent_id,
                    "fencing_token": fencing_token,
                    "status": "validated",
                    "reason_code": (
                        self.module.write_intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON
                    ),
                }

            with mock.patch.object(
                self.module,
                "closeout_lock",
                side_effect=tracked_closeout_lock,
            ):
                published = self.module.recover_expired_governance_generated_index_transaction(
                    **call,
                    publish_repair=publish_repair,
                )
            self.assertFalse(lock_state["held"])
            self.assertEqual(published["evidence"], first)
            self.assertEqual(
                published["repair_intent"]["reason_code"],
                self.module.write_intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON,
            )

            foreign_binding = self.module.generated_index_transaction_binding(
                transaction_id="e" * 32,
                actor="migration",
                raw_session_id="",
                git_head=self.baseline,
                index_base_sha256=snapshot.raw_sha256,
                full_vault_inputs_sha256=(
                    self.module.full_vault_input_projection_sha256()
                ),
                lease_checkpoints=[],
            )
            self.module._register_generated_index_closeout_transaction(
                transaction_binding=foreign_binding,
            )
            with self.assertRaises(
                self.module.GeneratedIndexCapabilityError
            ) as foreign_open:
                self.module.recover_expired_governance_generated_index_transaction(
                    **call
                )
            self.assertEqual(
                str(foreign_open.exception),
                "EXPIRED_VALIDATED_RECOVERY_INDEX_OTHER_TRANSACTION_OPEN",
            )
            self.module.mark_generated_index_transaction_outcome(
                self.module.STATE_DB,
                foreign_binding,
                outcome="rolled_back",
            )

            lock_path = self.root / ".git" / "index.lock"
            lock_path.write_bytes(b"unknown-lock")
            with self.assertRaises(
                self.module.GeneratedIndexCapabilityError
            ) as unknown_lock:
                self.module.recover_expired_governance_generated_index_transaction(
                    **call
                )
            self.assertEqual(
                str(unknown_lock.exception),
                "EXPIRED_VALIDATED_RECOVERY_INDEX_PROJECTION_DRIFT",
            )
            lock_path.rename(self.root / ".git" / "test-index-lock-used")

            recovery_root = (
                self.root
                / ".git"
                / self.module.GIT_INDEX_SYNC_RECOVERY_DIRECTORY
            )
            recovery_root.mkdir(mode=0o700)
            pending_manifest = recovery_root / ("f" * 32 + ".manifest.json")
            pending_manifest.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(
                self.module.GeneratedIndexCapabilityError
            ) as pending_git_index:
                self.module.recover_expired_governance_generated_index_transaction(
                    **call
                )
            self.assertEqual(
                str(pending_git_index.exception),
                "EXPIRED_VALIDATED_RECOVERY_INDEX_PROJECTION_DRIFT",
            )
            pending_manifest.rename(recovery_root / "pending-manifest-used")

            self.index.write_bytes(snapshot.raw + b"drift\n")
            with self.assertRaises(
                self.module.GeneratedIndexCapabilityError
            ) as index_drift:
                self.module.recover_expired_governance_generated_index_transaction(
                    **call
                )
            self.assertEqual(
                str(index_drift.exception),
                "EXPIRED_VALIDATED_RECOVERY_INDEX_PROJECTION_DRIFT",
            )
            self.index.write_bytes(snapshot.raw)

            git(self.root, "commit", "--allow-empty", "-qm", "foreign head drift")
            with self.assertRaises(
                self.module.GeneratedIndexCapabilityError
            ) as head_drift:
                self.module.recover_expired_governance_generated_index_transaction(
                    **call
                )
            self.assertEqual(
                str(head_drift.exception),
                "EXPIRED_VALIDATED_RECOVERY_INDEX_PROJECTION_DRIFT",
            )

            current_head = git(self.root, "rev-parse", "HEAD")
            self.assertNotEqual(binding["git_head"], current_head)
            current_projection = self.module.full_vault_input_projection_sha256()
            exact_binding = self.module.generated_index_transaction_binding(
                transaction_id="8" * 32,
                actor="codex",
                raw_session_id=raw_session_id,
                git_head=current_head,
                index_base_sha256=snapshot.raw_sha256,
                full_vault_inputs_sha256=current_projection,
                lease_checkpoints=checkpoint,
            )
            self.module._register_generated_index_closeout_transaction(
                transaction_binding=exact_binding,
            )
            with sqlite3.connect(self.module.STATE_DB) as conn:
                conn.execute(
                    "UPDATE generated_index_closeout_transactions SET "
                    "status='consumed', issuer_pid=999995, consumer_pid=999996, "
                    "issued_at_epoch=?, expires_at_epoch=?, claimed_at_epoch=?, "
                    "consumed_at_epoch=?, generated_sha256=?, "
                    "closeout_git_commit=? WHERE transaction_id=?",
                    (
                        now - 19,
                        now - 11,
                        now - 18,
                        now - 10,
                        snapshot.raw_sha256,
                        current_head,
                        exact_binding["transaction_id"],
                    ),
                )
                conn.execute(
                    "UPDATE generated_index_closeout_transactions SET "
                    "closeout_git_commit=? WHERE transaction_id=?",
                    (current_head, binding["transaction_id"]),
                )
                conn.commit()
                historical_before = conn.execute(
                    "SELECT * FROM generated_index_closeout_transactions "
                    "WHERE transaction_id=?",
                    (binding["transaction_id"],),
                ).fetchone()
                self.assertEqual(
                    conn.execute(
                        "SELECT git_head, closeout_git_commit FROM "
                        "generated_index_closeout_transactions "
                        "WHERE transaction_id=?",
                        (binding["transaction_id"],),
                    ).fetchone(),
                    (binding["git_head"], current_head),
                )
                exact_before = conn.execute(
                    "SELECT * FROM generated_index_closeout_transactions "
                    "WHERE transaction_id=?",
                    (exact_binding["transaction_id"],),
                ).fetchone()

            recovered_current = (
                self.module.recover_expired_governance_generated_index_transaction(
                    **call
                )
            )
            self.assertEqual(
                recovered_current["transaction_id"],
                exact_binding["transaction_id"],
            )
            with sqlite3.connect(self.module.STATE_DB) as conn:
                self.assertEqual(
                    conn.execute(
                        "SELECT * FROM generated_index_closeout_transactions "
                        "WHERE transaction_id=?",
                        (binding["transaction_id"],),
                    ).fetchone(),
                    historical_before,
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT * FROM generated_index_closeout_transactions "
                        "WHERE transaction_id=?",
                        (exact_binding["transaction_id"],),
                    ).fetchone(),
                    exact_before,
                )

            malformed_binding = self.module.generated_index_transaction_binding(
                transaction_id="9" * 32,
                actor="codex",
                raw_session_id=raw_session_id,
                git_head=current_head,
                index_base_sha256=snapshot.raw_sha256,
                full_vault_inputs_sha256=current_projection,
                lease_checkpoints=checkpoint,
            )
            self.module._register_generated_index_closeout_transaction(
                transaction_binding=malformed_binding,
            )
            with sqlite3.connect(self.module.STATE_DB) as conn:
                conn.execute(
                    "UPDATE generated_index_closeout_transactions SET "
                    "status='consumed', issuer_pid=999997, consumer_pid=999998, "
                    "issued_at_epoch=?, expires_at_epoch=?, claimed_at_epoch=?, "
                    "consumed_at_epoch=?, generated_sha256=?, "
                    "closeout_git_commit=?, vault_root_sha256=? "
                    "WHERE transaction_id=?",
                    (
                        now - 19,
                        now - 11,
                        now - 18,
                        now - 10,
                        snapshot.raw_sha256,
                        current_head,
                        "0" * 64,
                        malformed_binding["transaction_id"],
                    ),
                )
                conn.commit()
                malformed_before = {
                    item["transaction_id"]: conn.execute(
                        "SELECT * FROM generated_index_closeout_transactions "
                        "WHERE transaction_id=?",
                        (item["transaction_id"],),
                    ).fetchone()
                    for item in (binding, exact_binding, malformed_binding)
                }
            with self.assertRaises(
                self.module.GeneratedIndexCapabilityError
            ) as malformed_projection:
                self.module.recover_expired_governance_generated_index_transaction(
                    **call
                )
            self.assertEqual(
                str(malformed_projection.exception),
                "EXPIRED_VALIDATED_RECOVERY_INDEX_TRANSACTION_INVALID",
            )
            with sqlite3.connect(self.module.STATE_DB) as conn:
                for item in (binding, exact_binding, malformed_binding):
                    self.assertEqual(
                        conn.execute(
                            "SELECT * FROM generated_index_closeout_transactions "
                            "WHERE transaction_id=?",
                            (item["transaction_id"],),
                        ).fetchone(),
                        malformed_before[item["transaction_id"]],
                    )
                conn.execute(
                    "UPDATE generated_index_closeout_transactions SET "
                    "vault_root_sha256=? WHERE transaction_id=?",
                    (
                        malformed_binding["vault_root_sha256"],
                        malformed_binding["transaction_id"],
                    ),
                )
                conn.commit()
                exact_before = {
                    item["transaction_id"]: conn.execute(
                        "SELECT * FROM generated_index_closeout_transactions "
                        "WHERE transaction_id=?",
                        (item["transaction_id"],),
                    ).fetchone()
                    for item in (exact_binding, malformed_binding)
                }
            with self.assertRaises(
                self.module.GeneratedIndexCapabilityError
            ) as duplicate_projection:
                self.module.recover_expired_governance_generated_index_transaction(
                    **call
                )
            self.assertEqual(
                str(duplicate_projection.exception),
                "EXPIRED_VALIDATED_RECOVERY_INDEX_TRANSACTION_AMBIGUOUS",
            )
            with sqlite3.connect(self.module.STATE_DB) as conn:
                self.assertEqual(
                    conn.execute(
                        "SELECT * FROM generated_index_closeout_transactions "
                        "WHERE transaction_id=?",
                        (binding["transaction_id"],),
                    ).fetchone(),
                    historical_before,
                )
                for item in (exact_binding, malformed_binding):
                    self.assertEqual(
                        conn.execute(
                            "SELECT * FROM generated_index_closeout_transactions "
                            "WHERE transaction_id=?",
                            (item["transaction_id"],),
                        ).fetchone(),
                        exact_before[item["transaction_id"]],
                    )

        self.assertEqual(first, second)
        self.assertEqual(first["status"], "consumed")
        self.assertEqual(first["transaction_id"], binding["transaction_id"])
        self.assertEqual(consumed_at, repeated_consumed_at)

    def test_generated_index_recovery_preserves_staged_mode_change(self) -> None:
        _binding, _digest, _head = self.prepare_generated_index_sync_crash("8" * 32)
        git(self.root, "update-index", "--chmod=+x", "Agent记忆/INDEX.md")
        before = git(self.root, "ls-files", "--stage", "--", "Agent记忆/INDEX.md")

        recovered = self.module.recover_generated_index_transactions()

        self.assertFalse(recovered["ok"], recovered)
        after = git(self.root, "ls-files", "--stage", "--", "Agent记忆/INDEX.md")
        self.assertEqual(after, before)
        self.assertTrue(after.startswith("100755 "))

    def test_generated_index_recovery_does_not_touch_index_during_git_operation(self) -> None:
        _binding, _digest, crash_head = self.prepare_generated_index_sync_crash("a" * 32)
        merge_head = self.root / ".git" / "MERGE_HEAD"
        merge_head.write_text(f"{self.baseline}\n", encoding="ascii")
        git_index = self.root / ".git" / "index"
        index_before = hashlib.sha256(git_index.read_bytes()).hexdigest()

        recovered = self.module.recover_generated_index_transactions()

        self.assertFalse(recovered["ok"], recovered)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), crash_head)
        self.assertEqual(hashlib.sha256(git_index.read_bytes()).hexdigest(), index_before)
        self.assertTrue(merge_head.is_file())

    def test_generated_index_recovery_preserves_existing_git_index_lock(self) -> None:
        self.prepare_generated_index_sync_crash("7" * 32)
        lock = self.root / ".git" / "index.lock"
        user_bytes = b"user-owned-concurrent-git-lock\n"
        lock.write_bytes(user_bytes)

        recovered = self.module.recover_generated_index_transactions()

        self.assertFalse(recovered["ok"], recovered)
        self.assertEqual(lock.read_bytes(), user_bytes)

    def test_generated_index_recovery_rejects_symlinked_git_index_without_touching_target(self) -> None:
        self.prepare_generated_index_sync_crash("6" * 32)
        git_index = self.root / ".git" / "index"
        preserved_index = self.root / ".git" / "index.user-preserved"
        os.replace(git_index, preserved_index)
        outside_directory = self.root / "user-data"
        outside_directory.mkdir()
        outside_index = outside_directory / "private.bin"
        outside_bytes = b"user-owned-index-target\n"
        outside_index.write_bytes(outside_bytes)
        git_index.symlink_to(outside_index)

        recovered = self.module.recover_generated_index_transactions()

        self.assertFalse(recovered["ok"], recovered)
        self.assertEqual(outside_index.read_bytes(), outside_bytes)
        self.assertFalse((outside_directory / "index.lock").exists())
        self.assertFalse((outside_directory / "agent-memory-recovery").exists())
        self.assertTrue(preserved_index.is_file())

    def test_generated_index_recovery_resumes_after_durable_proposal_link(self) -> None:
        self.prepare_generated_index_sync_crash("5" * 32)
        real_link = self.module.os.link

        def interrupt_standard_lock_link(source, target, *args, **kwargs):
            if Path(target).name == "index.lock":
                raise OSError("injected kill before standard lock link")
            return real_link(source, target, *args, **kwargs)

        with mock.patch.object(
            self.module.os,
            "link",
            side_effect=interrupt_standard_lock_link,
        ):
            interrupted = self.module.recover_generated_index_transactions()
        self.assertFalse(interrupted["ok"], interrupted)
        self.assertFalse((self.root / ".git" / "index.lock").exists())

        recovered = self.module.recover_generated_index_transactions()

        self.assertTrue(recovered["ok"], recovered)
        self.assertEqual(git(self.root, "status", "--porcelain", "--", "Agent记忆/INDEX.md"), "")

    def test_generated_index_recovery_resumes_from_own_standard_lock(self) -> None:
        self.prepare_generated_index_sync_crash("4" * 32)
        real_replace = self.module.os.replace

        def interrupt_index_replace(source, target, *args, **kwargs):
            if Path(source).name == "index.lock" and Path(target).name == "index":
                raise OSError("injected kill before index replace")
            return real_replace(source, target, *args, **kwargs)

        with mock.patch.object(self.module.os, "replace", side_effect=interrupt_index_replace):
            interrupted = self.module.recover_generated_index_transactions()
        self.assertFalse(interrupted["ok"], interrupted)
        self.assertFalse((self.root / ".git" / "index.lock").exists())
        self.assertTrue(
            any(
                path.name.endswith(".released-index-lock")
                for path in (
                    self.root / ".git" / "agent-memory-closeout-recovery"
                ).iterdir()
            )
        )

        recovered = self.module.recover_generated_index_transactions()

        self.assertTrue(recovered["ok"], recovered)
        self.assertFalse((self.root / ".git" / "index.lock").exists())
        self.assertEqual(git(self.root, "status", "--porcelain", "--", "Agent记忆/INDEX.md"), "")

    def test_generated_index_recovery_resumes_after_index_replace_before_fsync(self) -> None:
        self.prepare_generated_index_sync_crash("3" * 32)
        real_fsync_directory = self.module._fsync_directory

        def interrupt_git_index_fsync(path):
            if Path(path) == self.root / ".git":
                raise OSError("injected kill after index replace")
            return real_fsync_directory(path)

        with mock.patch.object(
            self.module,
            "_fsync_directory",
            side_effect=interrupt_git_index_fsync,
        ):
            interrupted = self.module.recover_generated_index_transactions()
        self.assertFalse(interrupted["ok"], interrupted)

        recovered = self.module.recover_generated_index_transactions()

        self.assertTrue(recovered["ok"], recovered)
        self.assertEqual(git(self.root, "status", "--porcelain", "--", "Agent记忆/INDEX.md"), "")

    def test_validated_content_changed_before_snapshot_is_not_committed(self) -> None:
        expected_content = b"# Rules\n\nApproved.\n"
        expected_hash = hashlib.sha256(expected_content).hexdigest()
        self.note.write_bytes(b"# Rules\n\nRaced.\n")
        result = self.module.commit_files(
            [self.note],
            self.args,
            expected_raw_sha256={self.note: expected_hash},
            expected_head=self.baseline,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["stage"], "validated_snapshot_verify")
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)

    def test_worktree_race_after_snapshot_cannot_change_commit_blob(self) -> None:
        approved = b"# Rules\n\nApproved.\n"
        raced = "# Rules\n\nRaced after snapshot.\n"
        self.note.write_bytes(approved)
        expected_hash = hashlib.sha256(approved).hexdigest()
        original_builder = self.module._build_isolated_commit

        def race_then_commit(
            snapshots,
            *,
            expected_head,
            message,
            expected_full_vault_inputs_sha256="",
        ):
            self.note.write_text(raced, encoding="utf-8")
            return original_builder(
                snapshots,
                expected_head=expected_head,
                message=message,
                expected_full_vault_inputs_sha256=expected_full_vault_inputs_sha256,
            )

        with mock.patch.object(self.module, "_build_isolated_commit", side_effect=race_then_commit):
            result = self.module.commit_files(
                [self.note],
                self.args,
                expected_raw_sha256={self.note: expected_hash},
                expected_head=self.baseline,
            )
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["stage"], "index_sync_lock")
        self.assertEqual(result["detail"], "GIT_INDEX_OWNED_WORKTREE_DRIFT")
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)
        self.assertEqual(str(result.get("commit", "")), "")
        self.assertEqual(self.note.read_text(encoding="utf-8"), raced)
        self.assertFalse((self.root / ".git" / "index.lock").exists())

    def test_full_closeout_rejects_ordinary_file_changed_after_check(self) -> None:
        checked = "# Rules\n\nChecked ordinary content.\n"
        raced = "# Rules\n\nChanged after check.\n"
        self.note.write_text(checked, encoding="utf-8")
        argv = [
            "agent_memory_closeout.py",
            "--actor",
            "human",
            "--commit",
            "--commit-warnings",
            "--skip-zvec",
            "--skip-audit",
            "--no-zvec",
            "--json",
        ]
        with mock.patch.object(sys, "argv", argv):
            args = self.module.parse_args()

        def check_then_race(_files, _args):
            self.note.write_text(raced, encoding="utf-8")
            return {"ok": True, "advisories": [], "detail": "ok"}

        gate = {
            "ok": True,
            "enabled": True,
            "requested_mode": "enforce",
            "mode": "enforce",
            "blocking": False,
            "matched": [],
            "violations": [],
        }
        ok_step = {"ok": True, "skipped": True, "detail": "test"}
        with (
            mock.patch.object(self.module, "run_check", side_effect=check_then_race),
            mock.patch.object(self.module, "postwrite_reconcile", return_value=([], [])),
            mock.patch.object(self.module, "run_index", return_value=ok_step),
            mock.patch.object(self.module, "temporal_graph_health", return_value=ok_step),
            mock.patch.object(self.module, "run_zvec", return_value=ok_step),
            mock.patch.object(self.module, "run_agent_evolution", return_value=ok_step),
            mock.patch.object(self.module, "run_audit_autorun", return_value=ok_step),
            mock.patch.object(self.module, "append_log"),
            mock.patch.object(
                self.module.write_intent,
                "enforce_protected_changes",
                return_value=gate,
            ),
        ):
            payload = self.module.run_closeout(args)

        self.assertEqual(payload["status"], "error")
        self.assertEqual(
            payload["steps"]["commit"]["detail"],
            "CONTENT_CHANGED_AFTER_CHECK",
        )
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)

    def test_generated_index_is_committed_with_the_same_closeout_snapshot(self) -> None:
        self.note.write_text("# Rules\n\nUpdated with generated index.\n", encoding="utf-8")
        index_path = self.vault / "INDEX.md"
        generated = "<!-- agent-memory-generated-index:v1 -->\n# Generated Index\n"

        argv = [
            "agent_memory_closeout.py",
            "--actor",
            "human",
            "--commit",
            "--commit-warnings",
            "--skip-zvec",
            "--skip-audit",
            "--no-zvec",
            "--json",
        ]
        with mock.patch.object(sys, "argv", argv):
            args = self.module.parse_args()

        def generate_index(_args, *, transaction_binding):
            self.assertEqual(transaction_binding["transaction_id"], mock.ANY)
            index_path.write_text(generated, encoding="utf-8")
            digest = hashlib.sha256(generated.encode("utf-8")).hexdigest()
            self.bind_generated_transaction(transaction_binding, digest)
            return {
                "ok": True,
                "detail": "ok",
                "generated_index": {
                    "changed": True,
                    "path": str(index_path),
                    "sha256": digest,
                },
            }

        gate = {
            "ok": True,
            "enabled": True,
            "requested_mode": "enforce",
            "mode": "enforce",
            "blocking": False,
            "matched": [],
            "violations": [],
        }
        ok_step = {"ok": True, "skipped": True, "detail": "test"}
        with (
            mock.patch.object(
                self.module,
                "run_check",
                return_value={"ok": True, "advisories": [], "detail": "ok"},
            ),
            mock.patch.object(self.module, "postwrite_reconcile", return_value=([], [])),
            mock.patch.object(self.module, "run_index", side_effect=generate_index),
            mock.patch.object(self.module, "temporal_graph_health", return_value=ok_step),
            mock.patch.object(self.module, "run_zvec", return_value=ok_step),
            mock.patch.object(self.module, "run_agent_evolution", return_value=ok_step),
            mock.patch.object(self.module, "run_audit_autorun", return_value=ok_step),
            mock.patch.object(self.module, "record_file_observations", return_value=2),
            mock.patch.object(self.module, "append_log"),
            mock.patch.object(
                self.module.write_intent,
                "enforce_protected_changes",
                return_value=gate,
            ),
        ):
            payload = self.module.run_closeout(args)

        self.assertEqual(payload["status"], "ok", payload)
        commit = str(payload["commit"])
        self.assertRegex(commit, r"^[0-9a-f]{40}$")
        self.assertEqual(
            git(self.root, "show", f"{commit}:Agent记忆/AGENTS.md"),
            "# Rules\n\nUpdated with generated index.",
        )
        self.assertEqual(
            git(self.root, "show", f"{commit}:Agent记忆/INDEX.md"),
            generated.strip(),
        )
        self.assertIn("INDEX.md", payload["processed_files"])

    def test_direct_generated_index_edit_is_read_only_and_preserved(self) -> None:
        direct = (
            "<!-- agent-memory-generated-index:v1 -->\n"
            "# Direct edit that closeout must not bless\n"
        )
        self.index.write_text(direct, encoding="utf-8")
        argv = [
            "agent_memory_closeout.py",
            "--actor",
            "human",
            "--commit",
            "--json",
        ]
        with mock.patch.object(sys, "argv", argv):
            args = self.module.parse_args()
        with (
            mock.patch.object(self.module, "run_index") as run_index,
            mock.patch.object(self.module, "append_log"),
        ):
            payload = self.module.run_closeout(args)
        self.assertEqual(payload["status"], "error", payload)
        self.assertEqual(payload["ownership_error"], "GENERATED_FILE_READ_ONLY")
        self.assertEqual(self.index.read_text(encoding="utf-8"), direct)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)
        run_index.assert_not_called()

    def test_generated_index_is_restored_when_a_later_step_fails(self) -> None:
        self.note.write_text("# Rules\n\nUpdated but not committed.\n", encoding="utf-8")
        original_index = self.index.read_bytes()
        generated = "<!-- agent-memory-generated-index:v1 -->\n# Generated Index\n\nChanged.\n"

        argv = [
            "agent_memory_closeout.py",
            "--actor",
            "human",
            "--commit",
            "--commit-warnings",
            "--skip-audit",
            "--no-zvec",
            "--json",
        ]
        with mock.patch.object(sys, "argv", argv):
            args = self.module.parse_args()

        def generate_index(_args, *, transaction_binding):
            self.assertEqual(transaction_binding["transaction_id"], mock.ANY)
            self.index.write_text(generated, encoding="utf-8")
            digest = hashlib.sha256(generated.encode("utf-8")).hexdigest()
            self.bind_generated_transaction(transaction_binding, digest)
            return {
                "ok": True,
                "detail": "ok",
                "generated_index": {
                    "changed": True,
                    "path": str(self.index),
                    "sha256": digest,
                },
            }

        gate = {
            "ok": True,
            "mode": "enforce",
            "blocking": False,
            "matched": [],
            "violations": [],
        }
        ok_step = {"ok": True, "skipped": True, "detail": "test"}
        with (
            mock.patch.object(
                self.module,
                "run_check",
                return_value={"ok": True, "advisories": [], "detail": "ok"},
            ),
            mock.patch.object(self.module, "postwrite_reconcile", return_value=([], [])),
            mock.patch.object(self.module, "run_index", side_effect=generate_index),
            mock.patch.object(self.module, "temporal_graph_health", return_value=ok_step),
            mock.patch.object(
                self.module,
                "run_zvec",
                return_value={"ok": False, "skipped": False, "detail": "synthetic_failure"},
            ),
            mock.patch.object(self.module, "run_agent_evolution", return_value=ok_step),
            mock.patch.object(self.module, "run_audit_autorun", return_value=ok_step),
            mock.patch.object(
                self.module,
                "rescan_after_generated_index_restore",
                return_value={"ok": True, "detail": "test"},
            ),
            mock.patch.object(self.module, "append_log"),
            mock.patch.object(
                self.module.write_intent,
                "enforce_protected_changes",
                return_value=gate,
            ),
        ):
            payload = self.module.run_closeout(args)

        self.assertEqual(payload["status"], "error", payload)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)
        self.assertEqual(self.index.read_bytes(), original_index)
        self.assertNotIn("INDEX.md", payload["processed_files"])
        self.assertEqual(
            payload["steps"]["generated_index_transaction"]["detail"],
            "restored_precloseout_bytes",
        )

    def test_clean_unselected_markdown_race_blocks_commit_and_preserves_edit(self) -> None:
        other = self.vault / "STRUCTURE.md"
        other.write_text("# Stable\n", encoding="utf-8")
        git(self.root, "add", "Agent记忆/STRUCTURE.md")
        git(self.root, "commit", "-qm", "add stable structure")
        self.baseline = git(self.root, "rev-parse", "HEAD")
        self.note.write_text("# Rules\n\nSelected update.\n", encoding="utf-8")
        original_index = self.index.read_bytes()
        generated = "<!-- agent-memory-generated-index:v1 -->\n# Generated Index\n\nRace test.\n"

        argv = [
            "agent_memory_closeout.py",
            "--actor",
            "human",
            "--commit",
            "--commit-warnings",
            "--skip-audit",
            "--no-zvec",
            "--json",
        ]
        with mock.patch.object(sys, "argv", argv):
            args = self.module.parse_args()

        def generate_index(_args, *, transaction_binding):
            self.index.write_text(generated, encoding="utf-8")
            digest = hashlib.sha256(generated.encode("utf-8")).hexdigest()
            self.bind_generated_transaction(transaction_binding, digest)
            return {
                "ok": True,
                "detail": "ok",
                "generated_index": {
                    "changed": True,
                    "path": str(self.index),
                    "sha256": digest,
                },
            }

        def race_during_zvec(_files, _args):
            other.write_text("# Concurrent edit\n", encoding="utf-8")
            return {"ok": True, "skipped": False, "detail": "race"}

        gate = {
            "ok": True,
            "mode": "enforce",
            "blocking": False,
            "matched": [],
            "violations": [],
        }
        ok_step = {"ok": True, "skipped": True, "detail": "test"}
        with (
            mock.patch.object(
                self.module,
                "run_check",
                return_value={"ok": True, "advisories": [], "detail": "ok"},
            ),
            mock.patch.object(self.module, "postwrite_reconcile", return_value=([], [])),
            mock.patch.object(self.module, "run_index", side_effect=generate_index),
            mock.patch.object(self.module, "temporal_graph_health", return_value=ok_step),
            mock.patch.object(self.module, "run_zvec", side_effect=race_during_zvec),
            mock.patch.object(self.module, "run_agent_evolution", return_value=ok_step),
            mock.patch.object(self.module, "run_audit_autorun", return_value=ok_step),
            mock.patch.object(
                self.module,
                "rescan_after_generated_index_restore",
                return_value={"ok": True, "detail": "test"},
            ),
            mock.patch.object(self.module, "append_log"),
            mock.patch.object(
                self.module.write_intent,
                "enforce_protected_changes",
                return_value=gate,
            ),
        ):
            payload = self.module.run_closeout(args)

        self.assertEqual(payload["status"], "error", payload)
        self.assertEqual(payload["steps"]["commit"]["detail"], "GENERATED_INDEX_INPUT_CHANGED")
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.baseline)
        self.assertEqual(self.index.read_bytes(), original_index)
        self.assertEqual(other.read_text(encoding="utf-8"), "# Concurrent edit\n")

    def test_claimed_only_blocks_index_generation_when_another_session_is_dirty(self) -> None:
        other = self.vault / "STRUCTURE.md"
        other.write_text("# Other session\n", encoding="utf-8")
        self.note.write_text("# Rules\n\nCurrent session.\n", encoding="utf-8")
        current_row = {"path": str(self.note), "rel_path": "AGENTS.md", "intent_id": ""}
        other_row = {"path": str(other), "rel_path": "STRUCTURE.md", "intent_id": ""}

        argv = [
            "agent_memory_closeout.py",
            "--actor",
            "human",
            "--claimed-only",
            "--session-id",
            "session-a",
            "--commit",
            "--json",
        ]
        with mock.patch.object(sys, "argv", argv):
            args = self.module.parse_args()
        gate = {
            "ok": True,
            "mode": "enforce",
            "blocking": False,
            "matched": [],
            "violations": [],
        }
        with (
            mock.patch.object(self.module, "active_claim_rows", return_value=[current_row]),
            mock.patch.object(
                self.module,
                "all_active_claim_rows",
                return_value=[current_row, other_row],
            ),
            mock.patch.object(self.module, "run_index") as run_index,
            mock.patch.object(self.module, "append_log"),
            mock.patch.object(
                self.module.write_intent,
                "enforce_protected_changes",
                return_value=gate,
            ),
        ):
            payload = self.module.run_closeout(args)

        self.assertEqual(payload["status"], "error", payload)
        self.assertEqual(
            payload["ownership_error"],
            "GENERATED_INDEX_OTHER_SESSION_DIRTY",
        )
        self.assertEqual(payload["commit"], "skipped")
        run_index.assert_not_called()

if __name__ == "__main__":
    unittest.main()
