from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_claim as claim
from agent_memory_claim import parse_deleted_observation


def git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return completed.stdout.strip()


class DeletionObservationCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.git_root = self.root / "git"
        self.vault = self.git_root / "AgentMemory"
        self.target = self.vault / "项目" / "deleted-note.md"
        self.trash_dir = self.root / ".Trash"
        self.trash_file = self.trash_dir / "deleted-note.md"
        self.runtime = self.root / "runtime"
        self.state_db = self.runtime / "state.sqlite"
        self.content = b"# Deleted note\n\nRecoverable content.\n"

        self.target.parent.mkdir(parents=True)
        self.trash_dir.mkdir()
        self.runtime.mkdir()
        self.target.write_bytes(self.content)
        git(self.git_root, "init", "-q", "--initial-branch=main")
        git(self.git_root, "config", "user.name", "Deletion Observation Test")
        git(self.git_root, "config", "user.email", "test@example.invalid")
        git(self.git_root, "add", "AgentMemory")
        git(self.git_root, "commit", "-qm", "baseline")
        self.baseline_commit = git(self.git_root, "rev-parse", "HEAD")

        helper = self.git_root / "unrelated.txt"
        helper.write_text("unrelated\n", encoding="utf-8")
        git(self.git_root, "add", "unrelated.txt")
        git(self.git_root, "commit", "-qm", "unrelated ancestor")
        self.non_deletion_commit = git(self.git_root, "rev-parse", "HEAD")

        self.target.replace(self.trash_file)
        git(self.git_root, "add", "-u", "--", "AgentMemory/项目/deleted-note.md")
        git(self.git_root, "commit", "-qm", "authorized deletion")
        self.deletion_commit = git(self.git_root, "rev-parse", "HEAD")

        config_path = self.runtime / "agent-memory.toml"
        config_path.write_text(
            "\n".join(
                (
                    f"memory_root = {json.dumps(str(self.vault), ensure_ascii=False)}",
                    f"git_root = {json.dumps(str(self.git_root), ensure_ascii=False)}",
                    f"config_root = {json.dumps(str(self.runtime), ensure_ascii=False)}",
                    f"state_db = {json.dumps(str(self.state_db), ensure_ascii=False)}",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        self.env = os.environ.copy()
        self.env["AGENT_MEMORY_CONFIG_FILE"] = str(config_path)
        self.env["HOME"] = str(self.root)
        self.env["USERPROFILE"] = str(self.root)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def observe(
        self,
        *,
        commit: str | None = None,
        trash_file: Path | None = None,
        authorized: bool = True,
        apply: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(SCRIPTS / "memoryctl"),
            "--actor",
            "human",
            "observe-deletion",
            "--file",
            str(self.target),
            "--trash-path",
            str(trash_file or self.trash_file),
            "--deletion-commit",
            commit or self.deletion_commit,
            "--evidence-ref",
            "current-user-turn-explicit-delete",
            "--json",
        ]
        if authorized:
            command.append("--confirm-user-authorized")
        if apply:
            command.append("--apply")
        return subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_preview_then_apply_records_audited_tombstone_without_restoring_file(self) -> None:
        preview = self.observe()
        self.assertEqual(preview.returncode, 0, preview.stderr + preview.stdout)
        preview_payload = json.loads(preview.stdout)
        self.assertTrue(preview_payload["preview"])
        self.assertEqual(preview_payload["applied"], 0)
        self.assertFalse(self.state_db.exists(), "preview must not create or modify the state database")

        applied = self.observe(apply=True)
        self.assertEqual(applied.returncode, 0, applied.stderr + applied.stdout)
        payload = json.loads(applied.stdout)
        self.assertFalse(payload["preview"])
        self.assertEqual(payload["applied"], 1)
        self.assertFalse(self.target.exists())
        self.assertEqual(self.trash_file.read_bytes(), self.content)
        self.assertNotIn(str(self.trash_file), applied.stdout)
        self.assertNotIn("current-user-turn-explicit-delete", applied.stdout)

        prior_sha256 = hashlib.sha256(self.content).hexdigest()
        expected_sentinel = f"deleted:{self.deletion_commit}:{prior_sha256}"
        self.assertEqual(parse_deleted_observation(expected_sentinel), (self.deletion_commit, prior_sha256))
        self.assertIsNone(parse_deleted_observation(f"deleted:{self.deletion_commit}:bad"))
        with contextlib.closing(sqlite3.connect(self.state_db)) as conn, conn:
            audit = conn.execute(
                """
                SELECT actor, user_authorized, deletion_commit, prior_sha256,
                       trash_sha256, trash_path_sha256, evidence_ref_sha256
                FROM memory_deletion_observations
                """
            ).fetchone()
            observed = conn.execute(
                "SELECT sha256, actor, session_hash FROM memory_file_observations"
            ).fetchone()
        self.assertEqual(audit[0:4], ("human", 1, self.deletion_commit, prior_sha256))
        self.assertEqual(audit[4], prior_sha256)
        self.assertEqual(audit[5], hashlib.sha256(str(self.trash_file).encode("utf-8")).hexdigest())
        self.assertEqual(
            audit[6],
            hashlib.sha256(b"current-user-turn-explicit-delete").hexdigest(),
        )
        self.assertEqual(observed, (expected_sentinel, "human", ""))

        repeated = self.observe(apply=True)
        self.assertEqual(repeated.returncode, 0, repeated.stderr + repeated.stdout)
        self.assertEqual(json.loads(repeated.stdout)["applied"], 0)
        with contextlib.closing(sqlite3.connect(self.state_db)) as conn, conn:
            count = conn.execute("SELECT COUNT(*) FROM memory_deletion_observations").fetchone()[0]
        self.assertEqual(count, 1)

    def test_missing_explicit_authorization_is_rejected_without_writes(self) -> None:
        completed = self.observe(authorized=False, apply=True)
        self.assertEqual(completed.returncode, 2, completed.stderr + completed.stdout)
        self.assertIn("explicit user authorization", json.loads(completed.stdout)["error"])
        self.assertFalse(self.state_db.exists())

    def test_trash_hash_mismatch_is_rejected_without_writes(self) -> None:
        self.trash_file.write_text("different content\n", encoding="utf-8")
        completed = self.observe(apply=True)
        self.assertEqual(completed.returncode, 2, completed.stderr + completed.stdout)
        self.assertIn("does not match", json.loads(completed.stdout)["error"])
        self.assertFalse(self.state_db.exists())

    def test_trash_symlink_is_rejected_without_writes(self) -> None:
        trash_link = self.trash_dir / "deleted-note-link.md"
        trash_link.symlink_to(self.trash_file)
        completed = self.observe(trash_file=trash_link, apply=True)
        self.assertEqual(completed.returncode, 2, completed.stderr + completed.stdout)
        self.assertIn("regular file", json.loads(completed.stdout)["error"])
        self.assertFalse(self.state_db.exists())

    def test_lookalike_trash_component_is_rejected_without_writes(self) -> None:
        lookalike = self.root / "ordinary" / ".Trash"
        lookalike.mkdir(parents=True)
        fake_trash = lookalike / "deleted-note.md"
        shutil.copy2(self.trash_file, fake_trash)
        completed = self.observe(trash_file=fake_trash, apply=True)
        self.assertEqual(completed.returncode, 2, completed.stderr + completed.stdout)
        self.assertIn("recognized Trash", json.loads(completed.stdout)["error"])
        self.assertFalse(self.state_db.exists())

    def test_staged_readd_with_missing_worktree_file_is_rejected(self) -> None:
        self.target.write_bytes(self.content)
        git(self.git_root, "add", "AgentMemory/项目/deleted-note.md")
        self.target.replace(self.trash_dir / "staged-readd.md")
        completed = self.observe(apply=True)
        self.assertEqual(completed.returncode, 2, completed.stderr + completed.stdout)
        self.assertIn("uncommitted Git index or worktree", json.loads(completed.stdout)["error"])
        self.assertFalse(self.state_db.exists())

    def test_apply_revalidates_trash_after_preview(self) -> None:
        patches = (
            mock.patch.object(claim, "VAULT_ROOT", self.vault),
            mock.patch.object(claim, "GIT_ROOT", self.git_root),
            mock.patch.object(claim, "STATE_DB", self.state_db),
            mock.patch.object(claim, "CONFIG_ROOT", self.runtime),
            mock.patch.object(
                claim,
                "DELETION_OBSERVATION_LOCK",
                self.runtime / "locks" / "closeout.lock",
            ),
            mock.patch.dict(
                os.environ,
                {"HOME": str(self.root), "USERPROFILE": str(self.root)},
            ),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            observation = claim.validate_deletion_observation(
                actor="human",
                target_file=str(self.target),
                trash_file=str(self.trash_file),
                deletion_commit=self.deletion_commit,
                evidence_ref="current-user-turn-explicit-delete",
                user_authorized=True,
            )
            self.trash_file.write_text("changed after preview\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not match"):
                claim.apply_deletion_observation(
                    observation,
                    actor="human",
                    target_file=str(self.target),
                    trash_file=str(self.trash_file),
                    deletion_commit=self.deletion_commit,
                    evidence_ref="current-user-turn-explicit-delete",
                    user_authorized=True,
                )
        self.assertFalse(self.state_db.exists())

    def test_non_ancestor_deletion_commit_is_rejected(self) -> None:
        side_trash = self.trash_dir / "side-deleted-note.md"
        shutil.copy2(self.trash_file, side_trash)
        git(self.git_root, "checkout", "-q", "-b", "side", self.baseline_commit)
        self.target.replace(side_trash)
        git(self.git_root, "add", "-u", "--", "AgentMemory/项目/deleted-note.md")
        git(self.git_root, "commit", "-qm", "side deletion")
        side_commit = git(self.git_root, "rev-parse", "HEAD")
        git(self.git_root, "checkout", "-q", "main")

        completed = self.observe(commit=side_commit, trash_file=side_trash, apply=True)
        self.assertEqual(completed.returncode, 2, completed.stderr + completed.stdout)
        self.assertIn("not an ancestor", json.loads(completed.stdout)["error"])
        self.assertFalse(self.state_db.exists())

    def test_ancestor_commit_that_did_not_delete_target_is_rejected(self) -> None:
        completed = self.observe(commit=self.non_deletion_commit, apply=True)
        self.assertEqual(completed.returncode, 2, completed.stderr + completed.stdout)
        error = json.loads(completed.stdout)["error"]
        self.assertTrue("still contains" in error or "did not delete" in error)
        self.assertFalse(self.state_db.exists())


if __name__ == "__main__":
    unittest.main()
