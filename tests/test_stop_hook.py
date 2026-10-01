from __future__ import annotations

import contextlib
import gc
import hashlib
import importlib.util
import io
import json
import sqlite3
import subprocess
import sys
import tempfile
import types
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
        # Loading this fresh module releases the previous test's module graph.
        # Collect it before any test redirects stderr so unrelated late
        # ResourceWarnings cannot be mistaken for Stop Hook protocol output.
        # Warnings remain enabled and any stderr emitted by the code under test
        # is still captured and asserted normally.
        gc.collect()
        self.runtime_ready = mock.patch.object(
            self.module,
            "assert_runtime_ready",
            return_value={"ready": True},
        )
        self.runtime_ready.start()
        self.addCleanup(self.runtime_ready.stop)
        self.no_stale_adoptions = mock.patch.object(
            self.module.observability,
            "adopted_stale_without_verification",
            return_value=0,
        )
        self.no_stale_adoptions.start()
        self.addCleanup(self.no_stale_adoptions.stop)
        self.task_completed = mock.patch.object(
            self.module.observability,
            "record_task_completed",
        )
        self.task_completed.start()
        self.addCleanup(self.task_completed.stop)

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

    def test_session_end_failure_is_notification_only(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(self.module, "notify") as notified,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.module.report_failure(
                "claude",
                {"status": "error", "error": "synthetic session-end failure"},
                non_blocking=True,
            )

        self.assertEqual(returncode, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        notified.assert_called_once()

    def test_session_end_closeout_is_attributed_and_skips_audit(self) -> None:
        completed = subprocess.CompletedProcess(
            [],
            0,
            stdout=json.dumps({"status": "ok"}),
            stderr="",
        )
        with mock.patch.object(self.module.subprocess, "run", return_value=completed) as invoked:
            result = self.module.run_closeout(
                {"session_id": "claude-session-end"},
                "claude",
                55,
                "session-end",
            )

        self.assertEqual(result["status"], "ok")
        command = invoked.call_args.args[0]
        self.assertEqual(command[command.index("--trigger") + 1], "session-end")
        self.assertIn("--skip-audit", command)

    def test_reentered_stop_does_not_block_again(self) -> None:
        args = types.SimpleNamespace(
            actor="claude",
            protocol="claude",
            event="stop-hook",
            non_blocking=False,
            auto_closeout=True,
            timeout=300,
        )
        stdout = io.StringIO()
        with (
            mock.patch.object(self.module, "parse_args", return_value=args),
            mock.patch.object(
                self.module,
                "read_payload",
                return_value={"session_id": "claude-reentry", "stop_hook_active": True},
            ),
            mock.patch.object(self.module, "pending_paths", return_value=[Path("/tmp/pending.md")]),
            mock.patch.object(self.module, "active_claim_lease_rows", return_value=[]),
            mock.patch.object(self.module, "all_active_claim_lease_rows", return_value=[]),
            mock.patch.object(self.module, "notify") as notified,
            contextlib.redirect_stdout(stdout),
        ):
            returncode = self.module.main()

        self.assertEqual(returncode, 0)
        self.assertEqual(stdout.getvalue(), "")
        notified.assert_called_once()

    def test_first_stop_still_blocks_real_unclaimed_change(self) -> None:
        args = types.SimpleNamespace(
            actor="claude",
            protocol="claude",
            event="stop-hook",
            non_blocking=False,
            auto_closeout=True,
            timeout=300,
        )
        stdout = io.StringIO()
        with (
            mock.patch.object(self.module, "parse_args", return_value=args),
            mock.patch.object(
                self.module,
                "read_payload",
                return_value={"session_id": "claude-first-stop", "stop_hook_active": False},
            ),
            mock.patch.object(self.module, "pending_paths", return_value=[Path("/tmp/pending.md")]),
            mock.patch.object(self.module, "active_claim_lease_rows", return_value=[]),
            mock.patch.object(self.module, "all_active_claim_lease_rows", return_value=[]),
            mock.patch.object(self.module, "notify"),
            contextlib.redirect_stdout(stdout),
        ):
            returncode = self.module.main()

        payload = json.loads(stdout.getvalue())
        self.assertEqual(returncode, 0)
        self.assertEqual(payload["decision"], "block")
        self.assertIn("no live intent-backed claim", payload["reason"])

    def test_clean_session_end_does_not_start_weekly_audit(self) -> None:
        args = types.SimpleNamespace(
            actor="claude",
            protocol="claude",
            event="session-end",
            non_blocking=True,
            auto_closeout=True,
            timeout=55,
        )
        with (
            mock.patch.object(self.module, "parse_args", return_value=args),
            mock.patch.object(self.module, "read_payload", return_value={"session_id": "clean-end"}),
            mock.patch.object(self.module, "pending_paths", return_value=[]),
            mock.patch.object(self.module, "active_claim_lease_rows", return_value=[]),
            mock.patch.object(self.module.observability, "record_task_seen") as task_seen,
            mock.patch.object(self.module, "run_due_audit") as audit,
        ):
            returncode = self.module.main()

        self.assertEqual(returncode, 0)
        task_seen.assert_called_once_with("clean-end", "claude")
        audit.assert_not_called()

    def test_enforced_stale_adoption_blocks_clean_stop_until_live_verified(self) -> None:
        args = types.SimpleNamespace(
            actor="claude",
            protocol="claude",
            event="stop-hook",
            non_blocking=False,
            auto_closeout=True,
            timeout=55,
        )
        stdout = io.StringIO()
        with (
            mock.patch.object(self.module, "parse_args", return_value=args),
            mock.patch.object(self.module, "read_payload", return_value={"session_id": "stale-task"}),
            mock.patch.object(self.module, "pending_paths", return_value=[]),
            mock.patch.object(self.module, "active_claim_lease_rows", return_value=[]),
            mock.patch.object(self.module, "env_value", return_value="enforce"),
            mock.patch.object(self.module.shadow_gate, "cutover_active", return_value=True),
            mock.patch.object(
                self.module.observability,
                "adopted_stale_without_verification",
                return_value=1,
            ),
            mock.patch.object(self.module.observability, "record_task_completed") as completed,
            mock.patch.object(self.module, "notify"),
            mock.patch.object(self.module, "run_due_audit"),
            contextlib.redirect_stdout(stdout),
        ):
            returncode = self.module.main()

        decision = json.loads(stdout.getvalue())
        self.assertEqual(returncode, 0)
        self.assertEqual(decision["decision"], "block")
        self.assertIn("live verification", decision["reason"])
        completed.assert_not_called()

    def test_config_enforce_without_cutover_attestation_cannot_activate_gate(self) -> None:
        with (
            mock.patch.object(self.module, "env_value", return_value="enforce"),
            mock.patch.object(self.module.shadow_gate, "cutover_active", return_value=False),
            mock.patch.object(
                self.module.observability,
                "adopted_stale_without_verification",
                return_value=1,
            ),
            mock.patch.object(self.module.observability, "record_task_completed") as completed,
        ):
            returncode = self.module.finish_success(
                actor="codex",
                raw_session_id="unattested-enforce",
                protocol="codex",
                payload={},
                event="stop-hook",
                non_blocking=False,
            )

        self.assertEqual(returncode, 0)
        completed.assert_called_once()

    def test_shadow_stale_adoption_records_but_does_not_block(self) -> None:
        args = types.SimpleNamespace(
            actor="codex",
            protocol="codex",
            event="stop-hook",
            non_blocking=False,
            auto_closeout=True,
            timeout=55,
        )
        with (
            mock.patch.object(self.module, "parse_args", return_value=args),
            mock.patch.object(self.module, "read_payload", return_value={"session_id": "shadow-task"}),
            mock.patch.object(self.module, "pending_paths", return_value=[]),
            mock.patch.object(self.module, "active_claim_lease_rows", return_value=[]),
            mock.patch.object(self.module, "env_value", return_value="shadow"),
            mock.patch.object(
                self.module.observability,
                "adopted_stale_without_verification",
                return_value=1,
            ),
            mock.patch.object(self.module.observability, "record_task_completed") as completed,
            mock.patch.object(self.module, "run_due_audit"),
        ):
            returncode = self.module.main()

        self.assertEqual(returncode, 0)
        completed.assert_called_once_with("shadow-task", "codex", value="success")

    def test_enforced_observability_failure_blocks_and_never_records_success(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(self.module, "env_value", return_value="enforce"),
            mock.patch.object(self.module.shadow_gate, "cutover_active", return_value=True),
            mock.patch.object(
                self.module.observability,
                "adopted_stale_without_verification",
                side_effect=sqlite3.OperationalError("database is locked"),
            ),
            mock.patch.object(self.module.observability, "record_task_completed") as completed,
            mock.patch.object(self.module, "notify"),
            contextlib.redirect_stdout(stdout),
        ):
            returncode = self.module.finish_success(
                actor="claude",
                raw_session_id="ledger-failure",
                protocol="claude",
                payload={},
                event="stop-hook",
                non_blocking=False,
            )
        self.assertEqual(returncode, 0)
        decision = json.loads(stdout.getvalue())
        self.assertEqual(decision["decision"], "block")
        self.assertIn("OBSERVABILITY_LEDGER_UNAVAILABLE", decision["reason"])
        completed.assert_called_once_with("ledger-failure", "claude", value="failure")
        self.assertNotIn(mock.call("ledger-failure", "claude", value="success"), completed.mock_calls)

    def test_shadow_observability_failure_is_explicit_degraded_but_nonblocking(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(self.module, "env_value", return_value="shadow"),
            mock.patch.object(
                self.module.observability,
                "adopted_stale_without_verification",
                side_effect=sqlite3.DatabaseError("malformed"),
            ),
            mock.patch.object(self.module.observability, "record_task_completed") as completed,
            mock.patch.object(self.module, "notify"),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.module.finish_success(
                actor="codex",
                raw_session_id="shadow-ledger-failure",
                protocol="codex",
                payload={},
                event="stop-hook",
                non_blocking=False,
            )
        self.assertEqual(returncode, 0)
        self.assertIn("OBSERVABILITY_LEDGER_UNAVAILABLE", stderr.getvalue())
        completed.assert_called_once_with("shadow-ledger-failure", "codex", value="failure")

    def test_enforced_missing_task_identity_blocks_instead_of_recording_success(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(self.module, "env_value", return_value="enforce"),
            mock.patch.object(self.module.shadow_gate, "cutover_active", return_value=True),
            mock.patch.object(
                self.module.observability,
                "adopted_stale_without_verification",
                side_effect=self.module.observability.ObservabilityLedgerUnavailable(
                    "OBSERVABILITY_TASK_ID_UNAVAILABLE"
                ),
            ),
            mock.patch.object(self.module.observability, "record_task_completed") as completed,
            contextlib.redirect_stdout(stdout),
        ):
            returncode = self.module.finish_success(
                actor="claude",
                raw_session_id="",
                protocol="claude",
                payload={},
                event="stop-hook",
                non_blocking=False,
            )
        self.assertEqual(returncode, 0)
        self.assertEqual(json.loads(stdout.getvalue())["decision"], "block")
        self.assertNotIn(mock.call("", "claude", value="success"), completed.mock_calls)

    def test_missing_session_is_quiet_when_all_changes_belong_to_other_session(self) -> None:
        pending = Path("/tmp/other-session.md").resolve()
        args = types.SimpleNamespace(
            actor="claude",
            protocol="claude",
            event="stop-hook",
            non_blocking=False,
            auto_closeout=True,
            timeout=300,
        )
        stdout = io.StringIO()
        with (
            mock.patch.object(self.module, "parse_args", return_value=args),
            mock.patch.object(self.module, "read_payload", return_value={}),
            mock.patch.object(self.module, "pending_paths", return_value=[pending]),
            mock.patch.object(self.module, "active_claim_lease_rows", return_value=[]),
            mock.patch.object(
                self.module,
                "all_active_claim_lease_rows",
                return_value=[{"path": str(pending), "lease_state": "live"}],
            ),
            mock.patch.object(self.module, "run_due_audit") as audit,
            contextlib.redirect_stdout(stdout),
        ):
            returncode = self.module.main()

        self.assertEqual(returncode, 0)
        self.assertEqual(stdout.getvalue(), "")
        audit.assert_not_called()

    def test_live_intent_lease_is_required_for_automatic_closeout(self) -> None:
        pending = Path("/tmp/legacy-claim.md").resolve()
        args = types.SimpleNamespace(
            actor="codex",
            protocol="codex",
            event="stop-hook",
            non_blocking=False,
            auto_closeout=True,
            timeout=300,
        )
        stderr = io.StringIO()
        legacy = {"path": str(pending), "rel_path": "项目/legacy.md", "lease_state": "legacy"}
        with (
            mock.patch.object(self.module, "parse_args", return_value=args),
            mock.patch.object(self.module, "read_payload", return_value={"session_id": "codex-session"}),
            mock.patch.object(self.module, "pending_paths", return_value=[pending]),
            mock.patch.object(self.module, "active_claim_lease_rows", return_value=[legacy]),
            mock.patch.object(self.module, "all_active_claim_lease_rows", return_value=[legacy]),
            mock.patch.object(self.module, "run_closeout") as closeout,
            mock.patch.object(self.module, "notify"),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.module.main()

        self.assertEqual(returncode, 2)
        self.assertIn("states=legacy", stderr.getvalue())
        closeout.assert_not_called()

    def test_current_live_intent_lease_starts_closeout(self) -> None:
        pending = Path("/tmp/live-claim.md").resolve()
        args = types.SimpleNamespace(
            actor="codex",
            protocol="codex",
            event="stop-hook",
            non_blocking=False,
            auto_closeout=True,
            timeout=300,
        )
        live = {"path": str(pending), "rel_path": "项目/live.md", "lease_state": "live"}
        with (
            mock.patch.object(self.module, "parse_args", return_value=args),
            mock.patch.object(self.module, "read_payload", return_value={"session_id": "codex-session"}),
            mock.patch.object(self.module, "pending_paths", return_value=[pending]),
            mock.patch.object(self.module, "active_claim_lease_rows", return_value=[live]),
            mock.patch.object(self.module, "all_active_claim_lease_rows", return_value=[live]),
            mock.patch.object(self.module, "run_closeout", return_value={"status": "ok"}) as closeout,
        ):
            returncode = self.module.main()

        self.assertEqual(returncode, 0)
        closeout.assert_called_once()

    def test_terminal_intent_with_active_claim_blocks_even_when_clean(self) -> None:
        args = types.SimpleNamespace(
            actor="claude",
            protocol="claude",
            event="stop-hook",
            non_blocking=False,
            auto_closeout=True,
            timeout=300,
        )
        terminal = {
            "path": "/tmp/terminal-claim.md",
            "rel_path": "项目/terminal.md",
            "lease_state": "intent_terminal",
        }
        stdout = io.StringIO()
        with (
            mock.patch.object(self.module, "parse_args", return_value=args),
            mock.patch.object(self.module, "read_payload", return_value={"session_id": "claude-session"}),
            mock.patch.object(self.module, "pending_paths", return_value=[]),
            mock.patch.object(self.module, "active_claim_lease_rows", return_value=[terminal]),
            mock.patch.object(self.module, "run_closeout") as closeout,
            mock.patch.object(self.module, "notify"),
            contextlib.redirect_stdout(stdout),
        ):
            returncode = self.module.main()

        decision = json.loads(stdout.getvalue())
        self.assertEqual(returncode, 0)
        self.assertEqual(decision["decision"], "block")
        self.assertIn("terminal intent", decision["reason"])
        closeout.assert_not_called()


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
        self.module.STATE_DB = self.root / "state.sqlite"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_dirty_markdown_is_detected_under_renamed_vault(self) -> None:
        self.note.write_text("# Agent Memory\n\nChanged.\n", encoding="utf-8")
        self.assertEqual(self.module.dirty_paths(), [self.note.resolve()])

    def test_missing_markdown_path_is_not_silently_dropped(self) -> None:
        missing = self.vault / "missing.md"
        self.assertEqual(
            self.module.normalize_path("Agent记忆/missing.md"),
            missing.resolve(),
        )
        self.assertEqual(self.module.unobserved_paths([missing]), [missing])

    def test_external_commit_after_observed_baseline_is_recovered(self) -> None:
        self.note.write_text("# Agent Memory\n\nCommitted externally.\n", encoding="utf-8")
        git(self.root, "add", "Agent记忆/AGENTS.md")
        git(self.root, "commit", "-qm", "external commit")
        self.log_path.write_text(
            json.dumps({"git_observed_through": self.baseline}) + "\n",
            encoding="utf-8",
        )

        self.assertEqual(self.module.historical_paths(), [self.note.resolve()])

    def test_pending_paths_ignores_content_with_matching_closeout_observation(self) -> None:
        self.note.write_text("# Agent Memory\n\nCommitted externally.\n", encoding="utf-8")
        git(self.root, "add", "Agent记忆/AGENTS.md")
        git(self.root, "commit", "-qm", "external commit")
        self.log_path.write_text(
            json.dumps({"git_observed_through": self.baseline}) + "\n",
            encoding="utf-8",
        )
        digest = hashlib.sha256(self.note.read_bytes()).hexdigest()
        with contextlib.closing(sqlite3.connect(self.module.STATE_DB)) as conn, conn:
            conn.execute("CREATE TABLE memory_file_observations (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL)")
            conn.execute(
                "INSERT INTO memory_file_observations(path, sha256) VALUES (?, ?)",
                (str(self.note), digest),
            )

        self.assertEqual(self.module.historical_paths(), [self.note.resolve()])
        self.assertEqual(self.module.pending_paths(), [])

        self.note.write_text("# Agent Memory\n\nChanged again.\n", encoding="utf-8")
        self.assertEqual(self.module.pending_paths(), [self.note.resolve()])


if __name__ == "__main__":
    unittest.main()
