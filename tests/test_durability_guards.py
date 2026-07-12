from __future__ import annotations

import datetime as dt
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_claim as claim
import agent_memory_doctor as doctor


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise AssertionError(result.stderr or result.stdout)
    return result.stdout.strip()


class DurabilityGuardTests(unittest.TestCase):
    def test_derived_repair_uses_configured_semantic_python(self) -> None:
        configured_python = Path("/configured/vector/python")
        with mock.patch.object(doctor, "SEMANTIC_ENABLED", True), mock.patch.object(
            doctor, "ZVEC_PYTHON", configured_python
        ), mock.patch.object(
            doctor,
            "run",
            side_effect=[
                {"ok": True, "detail": "sqlite rebuilt"},
                {"ok": True, "detail": "zvec rebuilt"},
            ],
        ) as run_mock:
            actions = doctor.repair_derived()
        self.assertEqual([item["action"] for item in actions], ["rebuild_sqlite_fts", "rebuild_zvec"])
        vector_command = run_mock.call_args_list[1].args[0]
        self.assertEqual(vector_command[0], str(configured_python))
        self.assertTrue(vector_command[1].endswith("agent_memory_zvec_index.py"))

    def test_semantic_python_detects_missing_interpreter(self) -> None:
        with mock.patch.object(doctor, "ZVEC_PYTHON", Path("/definitely/missing/python")):
            ok, detail = doctor.verify_semantic_python_runtime()
        self.assertFalse(ok)
        self.assertEqual(detail["error"], "python_missing_or_broken_symlink")

    def test_semantic_python_accepts_live_base_interpreter(self) -> None:
        with mock.patch.object(doctor, "ZVEC_PYTHON", Path(sys.executable)):
            ok, detail = doctor.verify_semantic_python_runtime()
        self.assertTrue(ok, detail)
        self.assertTrue(detail["base_exists"])

    def test_remote_backup_warns_when_memory_commit_ages_out(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp).resolve()
            remote = tmp / "remote.git"
            work = tmp / "work"
            subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
            subprocess.run(["git", "init", "-q", "--initial-branch=main", str(work)], check=True)
            git(work, "config", "user.name", "Agent Memory Test")
            git(work, "config", "user.email", "test@example.invalid")
            memory_root = work / "AgentMemory"
            memory_root.mkdir()
            note = memory_root / "note.md"
            note.write_text("baseline\n", encoding="utf-8")
            git(work, "add", "AgentMemory/note.md")
            git(work, "commit", "-qm", "baseline")
            git(work, "remote", "add", "origin", str(remote))
            git(work, "push", "-qu", "origin", "main")

            with mock.patch.object(doctor, "GIT_ROOT", work):
                healthy, detail = doctor.git_remote_backup_health("AgentMemory")
            self.assertTrue(healthy, detail)
            self.assertEqual(detail["ahead_memory"], 0)

            note.write_text("local memory change\n", encoding="utf-8")
            git(work, "add", "AgentMemory/note.md")
            git(work, "commit", "-qm", "local memory")
            future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=4)
            with mock.patch.object(doctor, "GIT_ROOT", work):
                healthy, detail = doctor.git_remote_backup_health("AgentMemory", now=future)
            self.assertFalse(healthy)
            self.assertEqual(detail["ahead_memory"], 1)
            self.assertGreaterEqual(detail["oldest_unpushed_age_days"], 3)

    def test_doctor_reports_stale_claim_without_exposing_session_id(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            CREATE TABLE memory_session_claims (
              session_hash TEXT NOT NULL,
              actor TEXT NOT NULL,
              path TEXT NOT NULL,
              rel_path TEXT NOT NULL,
              status TEXT NOT NULL,
              claimed_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              completed_at TEXT
            )
            """
        )
        now = dt.datetime(2026, 7, 12, tzinfo=dt.timezone.utc)
        conn.executemany(
            "INSERT INTO memory_session_claims VALUES (?, ?, ?, ?, 'active', ?, ?, NULL)",
            [
                ("fresh-session", "codex", "/fresh.md", "fresh.md", now.isoformat(), now.isoformat()),
                (
                    "stale-session",
                    "claude",
                    "/stale.md",
                    "stale.md",
                    (now - dt.timedelta(days=2)).isoformat(),
                    (now - dt.timedelta(days=2)).isoformat(),
                ),
            ],
        )
        healthy, detail = doctor.session_claim_hygiene(conn, now=now)
        conn.close()
        self.assertFalse(healthy)
        self.assertEqual(detail["active"], 2)
        self.assertEqual(detail["stale"][0]["rel_path"], "stale.md")
        self.assertNotIn("session_hash", detail["stale"][0])

    def test_precommit_dirty_baseline_is_only_allowed_when_explicit(self) -> None:
        strict = doctor.memory_git_baseline_result(1, True, allow_dirty_memory=False)
        closeout = doctor.memory_git_baseline_result(1, True, allow_dirty_memory=True)
        self.assertEqual(strict[0], "warn")
        self.assertEqual(closeout[0], "pass")
        self.assertFalse(strict[2]["allowed_precommit"])
        self.assertTrue(closeout[2]["allowed_precommit"])

    def test_stale_claim_preview_and_expiry_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp).resolve()
            vault = tmp / "AgentMemory"
            vault.mkdir()
            note = vault / "note.md"
            note.write_text("memory\n", encoding="utf-8")
            state_db = tmp / "state.sqlite"
            with mock.patch.object(claim, "VAULT_ROOT", vault), mock.patch.object(claim, "STATE_DB", state_db):
                claim.claim_paths("codex", "old-session", [str(note)])
                with sqlite3.connect(state_db) as conn:
                    conn.execute(
                        "UPDATE memory_session_claims SET updated_at='2000-01-01T00:00:00+00:00'"
                    )
                    conn.commit()
                self.assertEqual(claim.all_active_claim_rows(max_age_hours=24), [])
                rows, applied = claim.expire_stale_claims(24, apply=False)
                self.assertEqual((len(rows), applied), (1, 0))
                with sqlite3.connect(state_db) as conn:
                    conn.execute(
                        "UPDATE memory_session_claims SET updated_at=?",
                        (claim.utc_now(),),
                    )
                    conn.commit()
                with mock.patch.object(claim, "stale_active_claim_rows", return_value=rows):
                    _, applied = claim.expire_stale_claims(24, apply=True)
                self.assertEqual(applied, 0)
                with sqlite3.connect(state_db) as conn:
                    conn.execute(
                        "UPDATE memory_session_claims SET updated_at='2000-01-01T00:00:00+00:00'"
                    )
                    conn.commit()
                rows, applied = claim.expire_stale_claims(24, apply=True)
                self.assertEqual((len(rows), applied), (1, 1))
                with sqlite3.connect(state_db) as conn:
                    status = conn.execute("SELECT status FROM memory_session_claims").fetchone()[0]
                self.assertEqual(status, "expired")


if __name__ == "__main__":
    unittest.main()
