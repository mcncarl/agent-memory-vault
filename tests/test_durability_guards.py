from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import shlex
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
import agent_memory_closeout as closeout
import agent_memory_doctor as doctor
import agent_memory_intent as write_intent
from tests.state_fixture import initialize_full_state


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
    def test_doctor_accepts_terminal_outer_install_transaction(self) -> None:
        reader = mock.Mock()
        reader.install_orchestration_health.return_value = {
            "healthy": True,
            "status": "terminal",
            "reason_code": "",
        }
        with (
            mock.patch.object(doctor, "_load_install_posix_module", return_value=reader),
            mock.patch.dict(
                doctor.os.environ,
                {
                    "AGENT_MEMORY_INSTALL_TRANSACTION_ID": "",
                    "AGENT_MEMORY_INSTALL_INPUT_SHA256": "",
                },
            ),
        ):
            result = doctor.install_orchestration_doctor_check()
        self.assertEqual(result["status"], "pass")
        reader.install_orchestration_health.assert_called_once_with(
            doctor.CONFIG_ROOT,
            active_transaction_id="",
            active_input_sha256="",
        )

    def test_doctor_allows_only_exactly_bound_active_install_transaction(self) -> None:
        reader = mock.Mock()
        transaction_id = "a" * 32
        input_sha256 = "b" * 64
        reader.install_orchestration_health.return_value = {
            "healthy": True,
            "status": "active",
            "transaction_id": transaction_id,
            "input_sha256": input_sha256,
            "reason_code": "",
        }
        with (
            mock.patch.object(doctor, "_load_install_posix_module", return_value=reader),
            mock.patch.dict(
                doctor.os.environ,
                {
                    "AGENT_MEMORY_INSTALL_TRANSACTION_ID": transaction_id,
                    "AGENT_MEMORY_INSTALL_INPUT_SHA256": input_sha256,
                },
            ),
        ):
            result = doctor.install_orchestration_doctor_check()
        self.assertEqual(result["status"], "pass")
        reader.install_orchestration_health.assert_called_once_with(
            doctor.CONFIG_ROOT,
            active_transaction_id=transaction_id,
            active_input_sha256=input_sha256,
        )

    def test_doctor_rejects_terminal_journal_when_active_binding_is_supplied(self) -> None:
        reader = mock.Mock()
        reader.install_orchestration_health.return_value = {
            "healthy": True,
            "status": "terminal",
            "transaction_id": "a" * 32,
            "input_sha256": "b" * 64,
            "reason_code": "",
        }
        with (
            mock.patch.object(doctor, "_load_install_posix_module", return_value=reader),
            mock.patch.dict(
                doctor.os.environ,
                {
                    "AGENT_MEMORY_INSTALL_TRANSACTION_ID": "a" * 32,
                    "AGENT_MEMORY_INSTALL_INPUT_SHA256": "b" * 64,
                },
            ),
        ):
            result = doctor.install_orchestration_doctor_check()

        self.assertEqual(result["status"], "fail")
        self.assertFalse(result["detail"]["binding_matches"])
        self.assertEqual(
            result["detail"]["reason_code"],
            "INSTALL_ACTIVE_BINDING_MISMATCH",
        )

    def test_doctor_rejects_partial_active_install_binding_without_reading_journal(self) -> None:
        reader = mock.Mock()
        with (
            mock.patch.object(doctor, "_load_install_posix_module", return_value=reader),
            mock.patch.dict(
                doctor.os.environ,
                {
                    "AGENT_MEMORY_INSTALL_TRANSACTION_ID": "a" * 32,
                    "AGENT_MEMORY_INSTALL_INPUT_SHA256": "",
                },
            ),
        ):
            result = doctor.install_orchestration_doctor_check()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(
            result["detail"]["reason_code"],
            "INSTALL_ACTIVE_BINDING_INVALID",
        )
        reader.install_orchestration_health.assert_not_called()

    def test_doctor_rejects_interrupted_outer_install_transaction(self) -> None:
        reader = mock.Mock()
        reader.install_orchestration_health.return_value = {
            "healthy": False,
            "status": "interrupted",
            "reason_code": "INSTALL_TRANSACTION_INTERRUPTED",
        }
        with (
            mock.patch.object(doctor, "_load_install_posix_module", return_value=reader),
            mock.patch.dict(
                doctor.os.environ,
                {
                    "AGENT_MEMORY_INSTALL_TRANSACTION_ID": "",
                    "AGENT_MEMORY_INSTALL_INPUT_SHA256": "",
                },
            ),
        ):
            result = doctor.install_orchestration_doctor_check()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["detail"]["status"], "interrupted")

    def test_doctor_json_exposes_installer_ok_contract(self) -> None:
        args = mock.Mock(json=True, repair_derived=False, allow_dirty_memory=False)
        with (
            mock.patch.object(doctor, "parse_args", return_value=args),
            mock.patch.object(doctor, "assert_runtime_ready", return_value={"ready": True}),
            mock.patch.object(
                doctor,
                "collect_checks",
                return_value=[
                    {"name": "runtime", "status": "pass", "message": "ok"},
                    {"name": "advisory", "status": "warn", "message": "review"},
                ],
            ),
            contextlib.redirect_stdout(io.StringIO()) as stdout,
        ):
            returncode = doctor.main()
        payload = json.loads(stdout.getvalue())
        self.assertEqual(returncode, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "warning")

    def test_doctor_rejects_blocking_session_end_hook(self) -> None:
        broken = {
            "Stop": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": shlex.join([
                                str(doctor.PYTHON), "-I", "-S", str(doctor.SCRIPT_ROOT / "memoryctl"),
                                "--actor", "claude", "stop-hook", "--protocol", "claude",
                                "--event", "stop-hook", "--auto-closeout", "--timeout", "300",
                            ]),
                            "timeout": 320,
                        }
                    ]
                }
            ],
            "SessionEnd": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": shlex.join([
                                str(doctor.PYTHON), "-I", "-S", str(doctor.SCRIPT_ROOT / "memoryctl"),
                                "--actor", "claude", "stop-hook", "--protocol", "codex",
                                "--event", "session-end", "--auto-closeout", "--timeout", "45",
                            ]),
                            "timeout": 60,
                        }
                    ]
                }
            ],
            "SessionStart": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": shlex.join([
                                str(doctor.PYTHON), "-I", "-S", str(doctor.SCRIPT_ROOT / "memoryctl"),
                                "--actor", "claude", "session-hook",
                            ]),
                            "timeout": 10,
                        }
                    ]
                }
            ],
        }
        healthy, detail = doctor.claude_hook_semantics(broken)
        self.assertFalse(healthy)
        self.assertTrue(detail["stop_scoped_and_blocking"])
        self.assertFalse(detail["session_end_non_blocking"])

    def test_doctor_accepts_nonblocking_session_end_hook(self) -> None:
        hooks = {
            "Stop": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": shlex.join([
                                str(doctor.PYTHON), "-I", "-S", str(doctor.SCRIPT_ROOT / "memoryctl"),
                                "--actor", "claude", "stop-hook", "--protocol", "claude",
                                "--event", "stop-hook", "--auto-closeout", "--timeout", "300",
                            ]),
                            "timeout": 320,
                        }
                    ]
                }
            ],
            "SessionEnd": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": shlex.join([
                                str(doctor.PYTHON), "-I", "-S", str(doctor.SCRIPT_ROOT / "memoryctl"),
                                "--actor", "claude", "stop-hook", "--protocol", "claude",
                                "--event", "session-end", "--auto-closeout", "--non-blocking",
                                "--timeout", "45",
                            ]),
                            "timeout": 60,
                        }
                    ]
                }
            ],
            "SessionStart": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": shlex.join([
                                str(doctor.PYTHON), "-I", "-S", str(doctor.SCRIPT_ROOT / "memoryctl"),
                                "--actor", "claude", "session-hook",
                            ]),
                            "timeout": 10,
                        }
                    ]
                }
            ],
        }
        healthy, detail = doctor.claude_hook_semantics(hooks)
        self.assertTrue(healthy, detail)
        hooks["Stop"][0]["hooks"][0]["command"] += " --non-blocking"
        healthy, detail = doctor.claude_hook_semantics(hooks)
        self.assertFalse(healthy)
        self.assertFalse(detail["stop_scoped_and_blocking"])

    def test_doctor_accepts_canonical_memoryctl_hooks_structurally(self) -> None:
        python = str(doctor.PYTHON)
        memoryctl = str(doctor.SCRIPT_ROOT / "memoryctl")

        def canonical(actor: str, command_name: str, *forwarded: str) -> str:
            return shlex.join(
                [python, "-I", "-S", memoryctl, "--actor", actor, command_name, *forwarded]
            )

        claude_hooks = {
            "Stop": [{"hooks": [{
                "type": "command",
                "command": canonical(
                    "claude", "stop-hook", "--protocol", "claude", "--event", "stop-hook",
                    "--auto-closeout", "--timeout", "300",
                ),
                "timeout": 320,
            }]}],
            "SessionEnd": [{"hooks": [{
                "type": "command",
                "command": canonical(
                    "claude", "stop-hook", "--protocol", "claude", "--event", "session-end",
                    "--auto-closeout", "--non-blocking", "--timeout", "45",
                ),
                "timeout": 60,
            }]}],
            "SessionStart": [{"hooks": [{
                "type": "command",
                "command": canonical("claude", "session-hook"),
                "timeout": 10,
            }]}],
        }
        healthy, detail = doctor.claude_hook_semantics(claude_hooks)
        self.assertTrue(healthy, detail)
        self.assertEqual(detail["managed_stop_count"], 1)

        codex_hooks = {"Stop": [{"hooks": [{
            "type": "command",
            "command": canonical(
                "codex", "stop-hook", "--protocol", "codex", "--event", "stop-hook",
                "--auto-closeout", "--timeout", "300",
            ),
            "timeout": 320,
        }]}]}
        healthy, detail = doctor.codex_hook_semantics(codex_hooks)
        self.assertTrue(healthy, detail)
        self.assertEqual(detail["canonical_count"], 1)
        codex_hooks["Stop"][0]["hooks"][0]["command"] = (
            shlex.join([
                str(doctor.SCRIPT_ROOT / "agent_memory_stop_hook.py"),
                "--actor", "codex", "--protocol", "codex", "--event", "stop-hook",
                "--auto-closeout", "--timeout", "300",
            ])
        )
        healthy, detail = doctor.codex_hook_semantics(codex_hooks)
        self.assertFalse(healthy, detail)
        self.assertEqual(detail["legacy_count"], 1)
        self.assertEqual(detail["canonical_count"], 0)

    def test_doctor_rejects_duplicate_or_inexact_managed_routes(self) -> None:
        exact = {
            "type": "command",
            "command": shlex.join([
                str(doctor.PYTHON), "-I", "-S", str(doctor.SCRIPT_ROOT / "memoryctl"),
                "--actor", "codex", "stop-hook", "--protocol", "codex", "--event",
                "stop-hook", "--auto-closeout", "--timeout", "300",
            ]),
            "timeout": 320,
        }
        hooks = {"Stop": [{"hooks": [exact, dict(exact)]}]}
        healthy, detail = doctor.codex_hook_semantics(hooks)
        self.assertFalse(healthy)
        self.assertEqual(detail["managed_stop_count"], 2)

        hooks["Stop"][0]["hooks"] = [dict(exact)]
        hooks["Stop"][0]["hooks"][0]["command"] += " --unexpected"
        healthy, detail = doctor.codex_hook_semantics(hooks)
        self.assertFalse(healthy)
        self.assertEqual(detail["managed_stop_count"], 1)

        hooks["Stop"][0]["hooks"] = [{
            "type": "command",
            "command": (
                "echo agent_memory_stop_hook.py --actor codex --protocol codex "
                "--event stop-hook --auto-closeout --timeout 300"
            ),
            "timeout": 320,
        }]
        healthy, detail = doctor.codex_hook_semantics(hooks)
        self.assertFalse(healthy)
        self.assertEqual(detail["managed_stop_count"], 1)

    def test_doctor_reports_unobserved_closeout_history(self) -> None:
        pending = closeout.GitEntry(
            status="M",
            repo_path="AgentMemory/项目/pending.md",
            path=Path("/tmp/AgentMemory/项目/pending.md"),
        )
        with (
            mock.patch.object(closeout, "last_observed_git_head", return_value="a" * 40),
            mock.patch.object(closeout, "current_git_head", return_value=("b" * 40, [])),
            mock.patch.object(closeout, "git_history_entries", return_value=([pending], [])),
            mock.patch.object(closeout, "unobserved_history_entries", return_value=[pending]),
            mock.patch.object(closeout, "relative_to_vault", return_value="项目/pending.md"),
        ):
            healthy, detail = doctor.closeout_observation_health()

        self.assertFalse(healthy)
        self.assertEqual(detail["pending_count"], 1)
        self.assertEqual(detail["pending_existing"], ["项目/pending.md"])
        self.assertEqual(detail["pending_deleted"], [])

    def test_doctor_accepts_fully_observed_closeout_history(self) -> None:
        with (
            mock.patch.object(closeout, "last_observed_git_head", return_value="a" * 40),
            mock.patch.object(closeout, "current_git_head", return_value=("b" * 40, [])),
            mock.patch.object(closeout, "git_history_entries", return_value=([], [])),
            mock.patch.object(closeout, "unobserved_history_entries", return_value=[]),
        ):
            healthy, detail = doctor.closeout_observation_health()

        self.assertTrue(healthy)
        self.assertEqual(detail["pending_count"], 0)

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

    def test_doctor_validates_observability_task_classes_and_hash_arrays(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE memory_use_events("
            "task_id TEXT, task_class TEXT, memory_ids_json TEXT)"
        )
        valid_hash = "a" * 64
        conn.executemany(
            "INSERT INTO memory_use_events VALUES (?, ?, ?)",
            [
                (valid_hash, "coding", json.dumps(["b" * 64])),
                ("raw-private-task", "freeform-private-class", "not-json"),
                (valid_hash, "research", json.dumps(["not-a-hash", 42])),
            ],
        )
        detail = doctor.observability_event_hygiene(conn)
        conn.close()
        self.assertEqual(
            detail,
            {
                "invalid_task_refs": 1,
                "invalid_task_classes": 1,
                "invalid_memory_id_payloads": 1,
                "invalid_memory_refs": 2,
            },
        )
        self.assertNotIn("raw-private-task", str(detail))

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
            with (
                mock.patch.object(claim, "VAULT_ROOT", vault),
                mock.patch.object(claim, "STATE_DB", state_db),
                mock.patch.object(
                    claim,
                    "assert_runtime_ready",
                    return_value={"ready": True},
                ),
                mock.patch.object(write_intent, "VAULT_ROOT", vault),
            ):
                initialize_full_state(state_db)
                claim.claim_paths("codex", "old-session", [str(note)])
                with contextlib.closing(sqlite3.connect(state_db)) as conn, conn:
                    conn.execute(
                        "UPDATE memory_session_claims SET updated_at='2000-01-01T00:00:00+00:00'"
                    )
                    conn.commit()
                self.assertEqual(claim.all_active_claim_rows(max_age_hours=24), [])
                self.assertEqual(
                    claim.active_claim_rows("old-session", "codex", max_age_hours=24),
                    [],
                )
                rows, applied = claim.expire_stale_claims(24, apply=False)
                self.assertEqual((len(rows), applied), (1, 0))
                with contextlib.closing(sqlite3.connect(state_db)) as conn, conn:
                    conn.execute(
                        "UPDATE memory_session_claims SET updated_at=?",
                        (claim.utc_now(),),
                    )
                    conn.commit()
                with mock.patch.object(claim, "stale_active_claim_rows", return_value=rows):
                    _, applied = claim.expire_stale_claims(24, apply=True)
                self.assertEqual(applied, 0)
                with contextlib.closing(sqlite3.connect(state_db)) as conn, conn:
                    conn.execute(
                        "UPDATE memory_session_claims SET updated_at='2000-01-01T00:00:00+00:00'"
                    )
                    conn.commit()
                rows, applied = claim.expire_stale_claims(24, apply=True)
                self.assertEqual((len(rows), applied), (1, 1))
                with contextlib.closing(sqlite3.connect(state_db)) as conn, conn:
                    status = conn.execute("SELECT status FROM memory_session_claims").fetchone()[0]
                self.assertEqual(status, "expired")


if __name__ == "__main__":
    unittest.main()
