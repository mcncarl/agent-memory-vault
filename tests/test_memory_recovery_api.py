from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
for entry in (REPO_ROOT / "scripts", REPO_ROOT / "tests"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import install_runtime
from test_studio_memory_write import AiluWriteSandbox, run


CLAIM_RELEASE_FAILURE_HELPER = r"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "scripts"))
import agent_memory_write as memory_write

memory_write.ACTOR = "ailu"

def fail_claim_release(*_args, **_kwargs):
    raise OSError("simulated claim projection failure")

memory_write.memory_claim.complete_claim_paths = fail_claim_release
request = json.load(sys.stdin)
try:
    with memory_write.writer_lock(10):
        result = memory_write.cancel(
            request,
            raw_session_id=memory_write._raw_session_id(),
        )
except memory_write.MemoryWriteError as exc:
    print(json.dumps({"ok": False, "reason_code": exc.reason_code}))
    raise SystemExit(2)
else:
    print(json.dumps(result, separators=(",", ":")))
"""


class MemoryRecoveryApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.box = AiluWriteSandbox()

    def tearDown(self) -> None:
        self.box.close()

    def _prepare(
        self,
        token: str,
        target: str,
        *,
        session: str,
    ) -> tuple[dict[str, object], dict[str, object]]:
        request: dict[str, object] = {
            "schema_version": 2,
            "summary": token,
            "proposal_markdown": self.box.add_proposal(token),
            "target_relative_path": target,
            "source_class": "user_direct",
            "knowledge_kind": "rule",
            "asserted_by": "user",
            "evidence_ref": f"conversation:{token}",
            "current_project": "ailu",
            "app_id": "ailu",
            "project_id": "ailu",
        }
        read_process, read = self.box.write(
            "read-target",
            {
                "schema_version": 2,
                "target_relative_path": target,
                "app_id": "ailu",
                "project_id": "ailu",
            },
            session=session,
        )
        self.assertEqual(
            read_process.returncode,
            0,
            read_process.stderr + read_process.stdout,
        )
        request["read_token"] = read["read_token"]
        generated_memory_id = str(read.get("generated_memory_id", ""))
        if generated_memory_id:
            request["proposal_markdown"] = str(request["proposal_markdown"]).replace(
                "---\n",
                f"---\nmemory_id: {generated_memory_id}\n",
                1,
            )
        process, prepared = self.box.write("prepare", request, session=session)
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        return request, prepared

    @staticmethod
    def _apply_request(
        request: dict[str, object],
        prepared: dict[str, object],
        *,
        confirmation: str,
    ) -> dict[str, object]:
        return {
            "schema_version": 2,
            "proposal_id": prepared["proposal_id"],
            "fencing_token": prepared["fencing_token"],
            "target_relative_path": request["target_relative_path"],
            "proposal_markdown": request["proposal_markdown"],
            "proposal_raw_sha256": prepared["proposal_raw_sha256"],
            "proposal_canonical_sha256": prepared["proposal_canonical_sha256"],
            "confirmed_by": "user",
            "confirmation_reference": confirmation,
        }

    def _state_hashes(self) -> dict[str, str]:
        return {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.box.runtime.glob("state.sqlite*")
        }

    def test_status_and_list_are_session_scoped_and_physically_read_only(self) -> None:
        session = "ailu-recovery-session"
        _, prepared = self._prepare(
            "recoverystatus94731",
            "项目/RecoveryStatus.md",
            session=session,
        )
        before = self._state_hashes()

        status_process, status_payload = self.box.write(
            "status",
            {"schema_version": 2, "proposal_id": prepared["proposal_id"]},
            session=session,
            extra_env={"AGENT_MEMORY_OBSERVABILITY_ENABLED": "true"},
        )
        list_process, list_payload = self.box.write(
            "list",
            {"schema_version": 2, "limit": 20},
            session=session,
            extra_env={"AGENT_MEMORY_OBSERVABILITY_ENABLED": "true"},
        )
        wrong_process, wrong_payload = self.box.write(
            "status",
            {"schema_version": 2, "proposal_id": prepared["proposal_id"]},
            session="another-ailu-session",
            extra_env={"AGENT_MEMORY_OBSERVABILITY_ENABLED": "true"},
        )
        other_process, other_payload = self.box.write(
            "list",
            {"schema_version": 2, "limit": 20},
            session="another-ailu-session",
            extra_env={"AGENT_MEMORY_OBSERVABILITY_ENABLED": "true"},
        )

        self.assertEqual(status_process.returncode, 0, status_process.stderr)
        self.assertEqual(status_payload["intent_status"], "pending")
        self.assertEqual(status_payload["target_state"], "base")
        self.assertEqual(status_payload["recovery_action"], "manual_continue_or_cancel")
        self.assertEqual(list_process.returncode, 0, list_process.stderr)
        self.assertEqual(
            [item["proposal_id"] for item in list_payload["items"]],
            [prepared["proposal_id"]],
        )
        self.assertEqual(wrong_process.returncode, 2)
        self.assertEqual(wrong_payload["reason_code"], "INTENT_SESSION_MISMATCH")
        self.assertEqual(other_process.returncode, 0, other_process.stderr)
        self.assertEqual(other_payload["items"], [])
        self.assertEqual(self._state_hashes(), before)

    def test_completed_apply_and_cancel_replay_the_original_receipts(self) -> None:
        completed_session = "ailu-completed-recovery"
        completed_target = "项目/CompletedRecovery.md"
        request, prepared = self._prepare(
            "completedrecovery94731",
            completed_target,
            session=completed_session,
        )
        apply_request = self._apply_request(
            request,
            prepared,
            confirmation="conversation:completed-recovery",
        )
        first_process, first = self.box.write(
            "apply",
            apply_request,
            session=completed_session,
        )
        self.assertEqual(first_process.returncode, 0, first_process.stderr + first_process.stdout)
        self.assertEqual(first["receipt"]["outcome"], "completed")

        (self.box.vault / completed_target).write_text(
            self.box.add_proposal("later-legitimate-edit-94731"),
            encoding="utf-8",
        )
        completed_wal = sqlite3.connect(self.box.state_db)
        try:
            completed_wal.execute("PRAGMA journal_mode=WAL")
            completed_wal.execute(
                "CREATE TABLE IF NOT EXISTS terminal_replay_wal_probe(value TEXT)"
            )
            completed_wal.execute(
                "INSERT INTO terminal_replay_wal_probe(value) VALUES ('completed')"
            )
            completed_wal.commit()
            self.assertGreater(
                (self.box.runtime / "state.sqlite-wal").stat().st_size,
                0,
            )
            replay_process, replay = self.box.write(
                "apply",
                apply_request,
                session=completed_session,
            )
        finally:
            completed_wal.close()
        self.assertEqual(replay_process.returncode, 0, replay_process.stderr + replay_process.stdout)
        self.assertTrue(replay["idempotent"])
        self.assertEqual(replay["receipt"], first["receipt"])

        status_process, status = self.box.write(
            "status",
            {"schema_version": 2, "proposal_id": prepared["proposal_id"]},
            session=completed_session,
        )
        self.assertEqual(status_process.returncode, 0, status_process.stderr)
        self.assertEqual(status["intent_status"], "completed")
        self.assertEqual(status["target_state"], "other")
        self.assertEqual(status["recovery_action"], "mark_succeeded")
        self.assertTrue(status["receipt_verified"])
        self.assertTrue(status["receipt"]["git_blob_verified"])

        cancelled_session = "ailu-cancelled-recovery"
        cancel_request, cancel_prepared = self._prepare(
            "cancelledrecovery94731",
            "项目/CancelledRecovery.md",
            session=cancelled_session,
        )
        cancellation = {
            "schema_version": 2,
            "proposal_id": cancel_prepared["proposal_id"],
            "fencing_token": cancel_prepared["fencing_token"],
        }
        cancel_process, cancelled = self.box.write(
            "cancel",
            cancellation,
            session=cancelled_session,
        )
        cancelled_wal = sqlite3.connect(self.box.state_db)
        try:
            cancelled_wal.execute("PRAGMA journal_mode=WAL")
            cancelled_wal.execute(
                "INSERT INTO terminal_replay_wal_probe(value) VALUES ('cancelled')"
            )
            cancelled_wal.commit()
            self.assertGreater(
                (self.box.runtime / "state.sqlite-wal").stat().st_size,
                0,
            )
            repeated_process, repeated = self.box.write(
                "cancel",
                cancellation,
                session=cancelled_session,
            )
        finally:
            cancelled_wal.close()
        self.assertEqual(cancel_process.returncode, 0, cancel_process.stderr + cancel_process.stdout)
        self.assertEqual(repeated_process.returncode, 0, repeated_process.stderr + repeated_process.stdout)
        self.assertFalse(cancelled["idempotent"])
        self.assertTrue(repeated["idempotent"])
        self.assertEqual(repeated["receipt"], cancelled["receipt"])

        cancelled_apply_process, cancelled_apply = self.box.write(
            "apply",
            self._apply_request(
                cancel_request,
                cancel_prepared,
                confirmation="conversation:cancelled-recovery",
            ),
            session=cancelled_session,
        )
        self.assertEqual(cancelled_apply_process.returncode, 2)
        self.assertEqual(cancelled_apply["status"], "cancelled")
        self.assertEqual(cancelled_apply["receipt"], cancelled["receipt"])

    def test_cancel_receipt_survives_claim_projection_failure_and_replay(self) -> None:
        session = "ailu-cancel-claim-failure"
        _, prepared = self._prepare(
            "cancelclaimfailure94731",
            "项目/CancelClaimFailure.md",
            session=session,
        )
        cancellation = {
            "schema_version": 2,
            "proposal_id": prepared["proposal_id"],
            "fencing_token": prepared["fencing_token"],
        }

        results: list[dict[str, object]] = []
        for _ in range(2):
            process = run(
                [sys.executable, "-c", CLAIM_RELEASE_FAILURE_HELPER],
                cwd=REPO_ROOT,
                env=self.box.env(session),
                input_text=json.dumps(cancellation),
            )
            self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
            results.append(json.loads(process.stdout))

        first, replay = results
        self.assertFalse(first["idempotent"])
        self.assertTrue(replay["idempotent"])
        self.assertTrue(first["claim_release_pending"])
        self.assertTrue(replay["claim_release_pending"])
        self.assertEqual(first["claim_release_reason_code"], "CLAIM_RELEASE_FAILED")
        self.assertEqual(replay["claim_release_reason_code"], "CLAIM_RELEASE_FAILED")
        self.assertEqual(first["receipt"], replay["receipt"])
        self.assertEqual(first["receipt"]["outcome"], "cancelled")

    def test_status_rejects_a_tampered_terminal_receipt(self) -> None:
        session = "ailu-tampered-receipt"
        request, prepared = self._prepare(
            "tamperedreceipt94731",
            "项目/TamperedReceipt.md",
            session=session,
        )
        process, _ = self.box.write(
            "apply",
            self._apply_request(
                request,
                prepared,
                confirmation="conversation:tampered-receipt",
            ),
            session=session,
        )
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        with sqlite3.connect(self.box.state_db) as connection:
            connection.execute(
                "UPDATE memory_write_receipts SET fencing_token=fencing_token+1 "
                "WHERE intent_id=?",
                (prepared["proposal_id"],),
            )
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()

        status_process, status = self.box.write(
            "status",
            {"schema_version": 2, "proposal_id": prepared["proposal_id"]},
            session=session,
        )
        self.assertEqual(status_process.returncode, 2)
        self.assertEqual(status["reason_code"], "RECEIPT_INTEGRITY_INVALID")

    @unittest.skipIf(os.name == "nt", "WAL sidecar preservation is POSIX-tested")
    def test_status_fails_closed_on_active_wal_without_changing_sidecars(self) -> None:
        session = "ailu-active-wal"
        _, prepared = self._prepare(
            "activewal94731",
            "项目/ActiveWal.md",
            session=session,
        )
        connection = sqlite3.connect(self.box.state_db)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS recovery_wal_probe(value TEXT)"
            )
            connection.execute(
                "INSERT INTO recovery_wal_probe(value) VALUES ('probe')"
            )
            connection.commit()
            before = self._state_hashes()
            self.assertGreater(
                (self.box.runtime / "state.sqlite-wal").stat().st_size,
                0,
            )

            process, payload = self.box.write(
                "status",
                {"schema_version": 2, "proposal_id": prepared["proposal_id"]},
                session=session,
            )
            self.assertEqual(process.returncode, 2)
            self.assertEqual(payload["reason_code"], "RUNTIME_TRANSITION_INCOMPLETE")
            self.assertEqual(self._state_hashes(), before)
        finally:
            connection.close()

    def test_list_supports_status_filter_and_stable_cursor(self) -> None:
        session = "ailu-list-pagination"
        prepared_ids: list[str] = []
        for index in range(3):
            _, prepared = self._prepare(
                f"pagination{index}94731",
                f"项目/Pagination{index}.md",
                session=session,
            )
            prepared_ids.append(str(prepared["proposal_id"]))

        first_process, first = self.box.write(
            "list",
            {"schema_version": 2, "statuses": ["pending"], "limit": 2},
            session=session,
        )
        second_process, second = self.box.write(
            "list",
            {
                "schema_version": 2,
                "statuses": ["pending"],
                "limit": 2,
                "cursor": first["next_cursor"],
            },
            session=session,
        )
        self.assertEqual(first_process.returncode, 0, first_process.stderr)
        self.assertEqual(second_process.returncode, 0, second_process.stderr)
        seen = [item["proposal_id"] for item in first["items"] + second["items"]]
        self.assertEqual(len(seen), 3)
        self.assertEqual(set(seen), set(prepared_ids))
        self.assertTrue(first["next_cursor"])
        self.assertEqual(second["next_cursor"], "")

    def test_validated_written_proposal_reports_resume_closeout(self) -> None:
        session = "ailu-resume-closeout"
        request, prepared = self._prepare(
            "resumecloseout94731",
            "项目/ResumeCloseout.md",
            session=session,
        )
        failed_process, failed = self.box.write(
            "apply",
            self._apply_request(
                request,
                prepared,
                confirmation="conversation:resume-closeout",
            ),
            session=session,
            extra_env={"AGENT_MEMORY_PYTHON": str(self.box.root / "missing-python")},
        )
        self.assertEqual(failed_process.returncode, 2)
        self.assertEqual(failed["reason_code"], "CLOSEOUT_FAILED")

        status_process, status = self.box.write(
            "status",
            {"schema_version": 2, "proposal_id": prepared["proposal_id"]},
            session=session,
        )
        self.assertEqual(status_process.returncode, 0, status_process.stderr)
        self.assertEqual(status["intent_status"], "validated")
        self.assertEqual(status["target_state"], "final")
        self.assertEqual(status["recovery_action"], "resume_closeout")

    def test_manifest_declares_ailu_runtime_2_1_capabilities(self) -> None:
        manifest = install_runtime.expected_manifest(self.box.runtime)
        self.assertEqual(manifest["release_version"], "2.1.0")
        self.assertEqual(manifest["state_schema_required"], 4)
        self.assertEqual(
            manifest["capabilities"]["write_gateway"],
            install_runtime.WRITE_GATEWAY_CAPABILITIES,
        )


if __name__ == "__main__":
    unittest.main()
