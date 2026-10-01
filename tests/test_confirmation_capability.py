from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_confirmation_capability as capability
import agent_memory_intent as intent


def binding() -> dict[str, object]:
    return {
        "subject_actor": "codex",
        "raw_task_id": "task-123",
        "raw_session_id": "session-456",
        "proposal_id": "a" * 32,
        "proposal_raw_sha256": "b" * 64,
        "proposal_canonical_sha256": "c" * 64,
        "target_relative_path": "项目/Alpha.md",
        "target_key": "d" * 64,
        "operation": "status_transition",
        "reconcile_action": "UPDATE",
        "fencing_token": 7,
    }


class ConfirmationCapabilityTests(unittest.TestCase):
    def issue(self, root: Path, **overrides: object) -> dict[str, object]:
        values = binding()
        values.update(overrides)
        return capability.issue_confirmation_capability(
            root,
            issuer_actor="human",
            confirmation_reference="manual-review:event-123",
            **values,
        )

    def consume(self, root: Path, issued: dict[str, object], **overrides: object):
        values = binding()
        values.update(overrides)
        return capability.consume_confirmation_capability(
            root,
            capability_path=str(issued["path"]),
            token=str(issued["token"]),
            **values,
        )

    @staticmethod
    def approved_intent(
        consumed: object,
        *,
        status: str = "validated",
    ) -> dict[str, object]:
        values = binding()
        approval_ref = capability.approval_reference(consumed)
        stored: dict[str, object] = {
            "intent_id": values["proposal_id"],
            "status": status,
            "writer_protocol_version": 2,
            "actor": values["subject_actor"],
            "session_hash": capability.session_hash(
                str(values["raw_session_id"])
            ),
            "base_raw_sha256": "0" * 64,
            "base_git_head": "1" * 40,
            "proposal_raw_sha256": values["proposal_raw_sha256"],
            "proposal_canonical_sha256": values[
                "proposal_canonical_sha256"
            ],
            "target_rel_path": values["target_relative_path"],
            "target_key": values["target_key"],
            "operation": values["operation"],
            "reconcile_action": values["reconcile_action"],
            "fencing_token": values["fencing_token"],
            "reason_code": "WRITE_COMPLETED" if status == "completed" else "",
            "validation_mode": "exact",
            "final_raw_sha256": values["proposal_raw_sha256"],
            "final_canonical_sha256": values[
                "proposal_canonical_sha256"
            ],
            "validated_git_head": "2" * 40,
            "early_commit": 0,
            "proposal_commit": "",
            "source_class": "first_party_user",
            "knowledge_kind": "observation",
            "asserted_by": "user",
            "safety_decision": "ALLOW",
            "safety_reason_code": "SOURCE_ALLOWED",
            "safety_input_sha256": "3" * 64,
            "safety_input_length": 123,
            "evidence_ref_sha256": "4" * 64,
            "target_status": "pending_verification",
            "transition_reason_sha256": "5" * 64,
            "validated_at": "2026-08-25T00:00:01+00:00",
            "updated_at": "2026-08-25T00:00:02+00:00",
            "approved_at": "2026-08-25T00:00:00+00:00",
            "approved_by": intent.HUMAN_CONFIRMATION_CAPABILITY_APPROVER,
            "approval_proposal_raw_sha256": values[
                "proposal_raw_sha256"
            ],
            "approval_proposal_canonical_sha256": values[
                "proposal_canonical_sha256"
            ],
            "approval_ref_sha256": hashlib.sha256(
                approval_ref.encode("utf-8")
            ).hexdigest(),
        }
        stored["approval_binding_sha256"] = intent._stored_approval_binding(
            stored
        )
        return stored

    @staticmethod
    def completed_receipt(stored: dict[str, object]) -> dict[str, object]:
        asserted_by = str(stored["asserted_by"])
        return {
            "receipt_id": hashlib.sha256(
                f"write-receipt:{stored['intent_id']}".encode("utf-8")
            ).hexdigest()[:32],
            "intent_id": stored["intent_id"],
            "writer_protocol_version": stored["writer_protocol_version"],
            "actor": stored["actor"],
            "session_hash": stored["session_hash"],
            "target_rel_path": stored["target_rel_path"],
            "target_key": stored["target_key"],
            "fencing_token": stored["fencing_token"],
            "outcome": "completed",
            "reason_code": stored["reason_code"],
            "validation_mode": stored["validation_mode"],
            "base_raw_sha256": stored["base_raw_sha256"],
            "proposal_raw_sha256": stored["proposal_raw_sha256"],
            "proposal_canonical_sha256": stored[
                "proposal_canonical_sha256"
            ],
            "final_raw_sha256": stored["final_raw_sha256"],
            "final_canonical_sha256": stored["final_canonical_sha256"],
            "base_git_head": stored["base_git_head"],
            "validated_git_head": stored["validated_git_head"],
            "git_commit": "6" * 40,
            "early_commit": stored["early_commit"],
            "proposal_commit": stored["proposal_commit"],
            "approval_binding_sha256": stored[
                "approval_binding_sha256"
            ],
            "approval_ref_sha256": stored["approval_ref_sha256"],
            "source_class": stored["source_class"],
            "knowledge_kind": stored["knowledge_kind"],
            "asserted_by_sha256": hashlib.sha256(
                asserted_by.encode("utf-8")
            ).hexdigest(),
            "safety_decision": stored["safety_decision"],
            "safety_reason_code": stored["safety_reason_code"],
            "safety_input_sha256": stored["safety_input_sha256"],
            "safety_input_length": stored["safety_input_length"],
            "evidence_ref_sha256": stored["evidence_ref_sha256"],
            "operation": stored["operation"],
            "target_status": stored["target_status"],
            "transition_reason_sha256": stored[
                "transition_reason_sha256"
            ],
            "detail_code": "",
            "created_at": stored["updated_at"],
        }

    def test_only_explicit_human_issuer_can_mint(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(capability.ConfirmationCapabilityError) as caught:
                capability.issue_confirmation_capability(
                    Path(raw),
                    issuer_actor="codex",
                    confirmation_reference="self-declared",
                    **binding(),
                )
            self.assertEqual(caught.exception.reason_code, "CONFIRMATION_CAPABILITY_ISSUER_FORBIDDEN")

    def test_each_proposal_can_mint_only_one_capability(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            issued = self.issue(root)
            self.assertTrue(Path(str(issued["path"])).is_file())
            with self.assertRaises(capability.ConfirmationCapabilityError) as caught:
                self.issue(root)
            self.assertEqual(
                caught.exception.reason_code,
                "CONFIRMATION_CAPABILITY_ALREADY_ISSUED",
            )

    def test_reviewed_content_update_can_use_exact_one_shot_capability(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            issued = self.issue(root, operation="content_update")
            consumed = self.consume(root, issued, operation="content_update")
            expected = binding()
            expected["operation"] = "content_update"
            self.assertTrue(capability.attests_to(consumed, **expected))

    def test_journal_is_private_and_contains_neither_bearer_token_nor_raw_reference(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            issued = self.issue(Path(raw))
            path = Path(str(issued["path"]))
            payload_text = path.read_text(encoding="utf-8")
            payload = json.loads(payload_text)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertNotIn(str(issued["token"]), payload_text)
            self.assertNotIn("manual-review:event-123", payload_text)
            self.assertRegex(payload["token_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(payload["confirmation_reference_sha256"], r"^[0-9a-f]{64}$")

    def test_consumption_is_bound_to_every_security_field(self) -> None:
        mismatches = {
            "subject_actor": "claude",
            "raw_task_id": "another-task",
            "raw_session_id": "another-session",
            "proposal_id": "e" * 32,
            "proposal_raw_sha256": "e" * 64,
            "proposal_canonical_sha256": "e" * 64,
            "target_relative_path": "项目/Beta.md",
            "target_key": "e" * 64,
            "operation": "governance_migration",
            "reconcile_action": "ADOPT",
            "fencing_token": 8,
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            issued = self.issue(root)
            for key, changed in mismatches.items():
                with self.subTest(field=key), self.assertRaises(
                    capability.ConfirmationCapabilityError
                ) as caught:
                    self.consume(root, issued, **{key: changed})
                self.assertEqual(caught.exception.reason_code, "CONFIRMATION_CAPABILITY_INVALID")
            consumed = self.consume(root, issued)
            self.assertTrue(capability.attests_to(consumed, **binding()))
            self.assertEqual(
                capability.approval_reference(consumed),
                (
                    f"human-confirmation-capability:{issued['capability_id']}:"
                    "confirmation-reference-sha256:"
                    + hashlib.sha256(
                        b"manual-review:event-123"
                    ).hexdigest()
                ),
            )

    def test_wrong_token_does_not_consume_and_second_valid_use_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            issued = self.issue(root)
            with self.assertRaises(capability.ConfirmationCapabilityError) as caught:
                capability.consume_confirmation_capability(
                    root,
                    capability_path=str(issued["path"]),
                    token="wrong-token",
                    **binding(),
                )
            self.assertEqual(caught.exception.reason_code, "CONFIRMATION_CAPABILITY_INVALID")
            self.consume(root, issued)
            with self.assertRaises(capability.ConfirmationCapabilityError) as caught:
                self.consume(root, issued)
            self.assertEqual(caught.exception.reason_code, "CONFIRMATION_CAPABILITY_ALREADY_CONSUMED")

    def test_exact_consumption_can_recover_only_the_preapproval_crash_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            issued = self.issue(root)
            first = self.consume(root, issued)
            recovered = capability.consume_confirmation_capability(
                root,
                capability_path=str(issued["path"]),
                token=str(issued["token"]),
                allow_idempotent_recovery=True,
                **binding(),
            )
            self.assertTrue(capability.attests_to(first, **binding()))
            self.assertTrue(capability.attests_to(recovered, **binding()))
            for changed in (
                {"proposal_id": "e" * 32},
                {"fencing_token": 8},
                {"raw_session_id": "another-session"},
            ):
                with self.subTest(changed=changed), self.assertRaises(
                    capability.ConfirmationCapabilityError
                ) as caught:
                    values = binding()
                    values.update(changed)
                    capability.consume_confirmation_capability(
                        root,
                        capability_path=str(issued["path"]),
                        token=str(issued["token"]),
                        allow_idempotent_recovery=True,
                        **values,
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "CONFIRMATION_CAPABILITY_INVALID",
                )

    def test_receipt_before_journal_crash_is_exactly_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            issued = self.issue(root)
            journal = Path(str(issued["path"]))
            issued_bytes = journal.read_bytes()
            self.consume(root, issued)
            # This recreates the durable ordering window: receipt fsynced, but
            # the mutable journal had not yet reached status=consumed.
            journal.write_bytes(issued_bytes)
            if os.name != "nt":
                journal.chmod(0o600)
            recovered = capability.consume_confirmation_capability(
                root,
                capability_path=str(issued["path"]),
                token=str(issued["token"]),
                allow_idempotent_recovery=True,
                **binding(),
            )
            self.assertTrue(capability.attests_to(recovered, **binding()))
            self.assertEqual(
                json.loads(journal.read_text(encoding="utf-8"))["status"],
                "consumed",
            )

    def test_recovery_rejects_a_tampered_monotonic_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            issued = self.issue(root)
            self.consume(root, issued)
            receipt = root / capability.CONSUMPTION_LEDGER_DIRECTORY / (
                capability.CONSUMPTION_RECEIPT_PREFIX
                + str(issued["capability_id"])
                + ".json"
            )
            payload = json.loads(receipt.read_text(encoding="utf-8"))
            payload["binding_sha256"] = "f" * 64
            receipt.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            if os.name != "nt":
                receipt.chmod(0o600)
            with self.assertRaises(capability.ConfirmationCapabilityError) as caught:
                capability.consume_confirmation_capability(
                    root,
                    capability_path=str(issued["path"]),
                    token=str(issued["token"]),
                    allow_idempotent_recovery=True,
                    **binding(),
                )
            self.assertEqual(
                caught.exception.reason_code,
                "CONFIRMATION_CAPABILITY_INVALID",
            )

    def test_restoring_issued_journal_cannot_rewind_consumption(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            issued = self.issue(root)
            journal = Path(str(issued["path"]))
            issued_bytes = journal.read_bytes()
            self.consume(root, issued)
            receipt = root / capability.CONSUMPTION_LEDGER_DIRECTORY / (
                capability.CONSUMPTION_RECEIPT_PREFIX
                + str(issued["capability_id"])
                + ".json"
            )
            self.assertTrue(receipt.is_file())
            self.assertNotEqual(receipt.parent, journal.parent)
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            journal.write_bytes(issued_bytes)
            if os.name != "nt":
                journal.chmod(0o600)
            with self.assertRaises(capability.ConfirmationCapabilityError) as caught:
                self.consume(root, issued)
            self.assertEqual(
                caught.exception.reason_code,
                "CONFIRMATION_CAPABILITY_ALREADY_CONSUMED",
            )

    def test_journal_binding_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            issued = self.issue(root)
            path = Path(str(issued["path"]))
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["fencing_token"] = 8
            path.write_text(
                json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            if os.name != "nt":
                os.chmod(path, 0o600)
            with self.assertRaises(capability.ConfirmationCapabilityError) as caught:
                self.consume(root, issued, fencing_token=8)
            self.assertEqual(caught.exception.reason_code, "CONFIRMATION_CAPABILITY_INVALID")

    def test_concurrent_consumers_get_exactly_one_success(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            issued = self.issue(root)

            def attempt() -> str:
                try:
                    self.consume(root, issued)
                    return "ok"
                except capability.ConfirmationCapabilityError as exc:
                    return exc.reason_code

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(lambda _value: attempt(), range(2)))
            self.assertEqual(outcomes.count("ok"), 1)
            self.assertEqual(outcomes.count("CONFIRMATION_CAPABILITY_ALREADY_CONSUMED"), 1)

    def test_expired_capability_fails_closed_without_becoming_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            issued = self.issue(root, ttl_seconds=1)
            payload = json.loads(Path(str(issued["path"])).read_text(encoding="utf-8"))
            with self.assertRaises(capability.ConfirmationCapabilityError) as caught:
                capability.consume_confirmation_capability(
                    root,
                    capability_path=str(issued["path"]),
                    token=str(issued["token"]),
                    now_epoch=int(payload["expires_at_epoch"]) + 1,
                    **binding(),
                )
            self.assertEqual(caught.exception.reason_code, "CONFIRMATION_CAPABILITY_EXPIRED")
            current = json.loads(Path(str(issued["path"])).read_text(encoding="utf-8"))
            self.assertEqual(current["status"], "issued")

    def test_expired_handoff_cannot_recover_an_unconsumed_capability(self) -> None:
        pending = {
            "intent_id": "a" * 32,
            "status": "pending",
            "actor": "codex",
            "session_hash": capability.session_hash("session-456"),
            "proposal_raw_sha256": "b" * 64,
            "proposal_canonical_sha256": "c" * 64,
            "target_rel_path": "项目/Alpha.md",
            "target_key": "d" * 64,
            "operation": "status_transition",
            "reconcile_action": "UPDATE",
            "fencing_token": 7,
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with mock.patch.object(
                intent,
                "show_intent",
                return_value={"intent": pending, "receipt": None},
            ), mock.patch.object(capability.time, "time", return_value=1_000):
                public = capability.issue_for_intent_handoff(
                    root,
                    issuer_actor="human",
                    subject_actor="codex",
                    raw_task_id="task-123",
                    raw_session_id="session-456",
                    proposal_id="a" * 32,
                    confirmation_reference="manual-review:event-123",
                    ttl_seconds=1,
                )
            with mock.patch.object(capability.time, "time", return_value=1_002):
                with self.assertRaises(
                    capability.ConfirmationCapabilityError
                ) as expired:
                    capability.read_confirmation_handoff(
                        root,
                        handoff_path=str(public["handoff_path"]),
                    )
                self.assertEqual(
                    expired.exception.reason_code,
                    "CONFIRMATION_HANDOFF_EXPIRED",
                )
                with self.assertRaises(
                    capability.ConfirmationCapabilityError
                ) as recovery:
                    capability.recover_consumed_confirmation_handoff(
                        root,
                        handoff_path=str(public["handoff_path"]),
                        subject_actor="codex",
                        raw_task_id="task-123",
                        raw_session_id="session-456",
                    )
            self.assertEqual(
                recovery.exception.reason_code,
                "CONFIRMATION_CAPABILITY_NOT_CONSUMED",
            )
            journal = json.loads(
                Path(str(public["capability_path"])).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(journal["status"], "issued")

    def test_expired_consumed_handoff_recovers_only_exact_durable_intent(self) -> None:
        pending = {
            "intent_id": "a" * 32,
            "status": "pending",
            "actor": "codex",
            "session_hash": capability.session_hash("session-456"),
            "proposal_raw_sha256": "b" * 64,
            "proposal_canonical_sha256": "c" * 64,
            "target_rel_path": "项目/Alpha.md",
            "target_key": "d" * 64,
            "operation": "status_transition",
            "reconcile_action": "UPDATE",
            "fencing_token": 7,
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with mock.patch.object(
                intent,
                "show_intent",
                return_value={"intent": pending, "receipt": None},
            ), mock.patch.object(capability.time, "time", return_value=1_000):
                public = capability.issue_for_intent_handoff(
                    root,
                    issuer_actor="human",
                    subject_actor="codex",
                    raw_task_id="task-123",
                    raw_session_id="session-456",
                    proposal_id="a" * 32,
                    confirmation_reference="manual-review:event-123",
                    ttl_seconds=1,
                )
                private = capability.read_confirmation_handoff(
                    root,
                    handoff_path=str(public["handoff_path"]),
                )
                issued_capability_bytes = Path(
                    str(private["capability_path"])
                ).read_bytes()
                consumed = capability.consume_confirmation_capability(
                    root,
                    capability_path=str(private["capability_path"]),
                    token=str(private["token"]),
                    **binding(),
                )
                # Recreate the earlier half of the same crash window too: the
                # immutable receipt reached disk but the capability journal did
                # not yet advance from issued to consumed.
                Path(str(private["capability_path"])).write_bytes(
                    issued_capability_bytes
                )
                if os.name != "nt":
                    Path(str(private["capability_path"])).chmod(0o600)

            # Crash window: the monotonic consumption receipt exists, but the
            # writer has not yet committed its atomic approval transaction.
            with mock.patch.object(
                intent,
                "show_intent",
                return_value={"intent": pending, "receipt": None},
            ), mock.patch.object(
                capability.time,
                "time",
                return_value=1_002,
            ):
                recovered_pending = (
                    capability.recover_consumed_confirmation_handoff(
                        root,
                        handoff_path=str(public["handoff_path"]),
                        subject_actor="codex",
                        raw_task_id="task-123",
                        raw_session_id="session-456",
                    )
                )
            self.assertTrue(recovered_pending["consumed_recovery"])
            self.assertEqual(recovered_pending["intent_status"], "pending")
            self.assertEqual(recovered_pending["token"], private["token"])
            self.assertEqual(
                json.loads(
                    Path(str(private["capability_path"])).read_text(
                        encoding="utf-8"
                    )
                )["status"],
                "consumed",
            )

            for durable_status in (
                "approved",
                "bound",
                "validated",
                "completed",
            ):
                approved = self.approved_intent(
                    consumed,
                    status=durable_status,
                )
                completed_receipt = (
                    self.completed_receipt(approved)
                    if durable_status == "completed"
                    else None
                )
                with self.subTest(
                    durable_status=durable_status
                ), mock.patch.object(
                    intent,
                    "show_intent",
                    return_value={
                        "intent": approved,
                        "receipt": completed_receipt,
                    },
                ), mock.patch.object(
                    capability.time,
                    "time",
                    return_value=1_002,
                ):
                    recovered = (
                        capability.recover_consumed_confirmation_handoff(
                            root,
                            handoff_path=str(public["handoff_path"]),
                            subject_actor="codex",
                            raw_task_id="task-123",
                            raw_session_id="session-456",
                        )
                    )
                self.assertTrue(recovered["consumed_recovery"])
                self.assertEqual(
                    recovered["intent_status"],
                    durable_status,
                )
                self.assertEqual(recovered["token"], private["token"])

            approved = self.approved_intent(consumed)

            mismatches = (
                {"subject_actor": "claude"},
                {"raw_task_id": "another-task"},
                {"raw_session_id": "another-session"},
            )
            for changed in mismatches:
                arguments = {
                    "subject_actor": "codex",
                    "raw_task_id": "task-123",
                    "raw_session_id": "session-456",
                    **changed,
                }
                with self.subTest(changed=changed), mock.patch.object(
                    intent,
                    "show_intent",
                    return_value={"intent": approved, "receipt": None},
                ), mock.patch.object(
                    capability.time,
                    "time",
                    return_value=1_002,
                ), self.assertRaises(
                    capability.ConfirmationCapabilityError
                ) as caught:
                    capability.recover_consumed_confirmation_handoff(
                        root,
                        handoff_path=str(public["handoff_path"]),
                        **arguments,
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
                )

            for field, changed in (
                ("proposal_raw_sha256", "e" * 64),
                ("target_rel_path", "项目/Beta.md"),
                ("operation", "governance_migration"),
                ("fencing_token", 8),
            ):
                drifted = dict(approved)
                drifted[field] = changed
                with self.subTest(intent_field=field), mock.patch.object(
                    intent,
                    "show_intent",
                    return_value={"intent": drifted, "receipt": None},
                ), mock.patch.object(
                    capability.time,
                    "time",
                    return_value=1_002,
                ), self.assertRaises(
                    capability.ConfirmationCapabilityError
                ) as caught:
                    capability.recover_consumed_confirmation_handoff(
                        root,
                        handoff_path=str(public["handoff_path"]),
                        subject_actor="codex",
                        raw_task_id="task-123",
                        raw_session_id="session-456",
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
                )

            pending_with_partial_approval = dict(pending)
            pending_with_partial_approval["approved_by"] = "user"
            with mock.patch.object(
                intent,
                "show_intent",
                return_value={
                    "intent": pending_with_partial_approval,
                    "receipt": None,
                },
            ), mock.patch.object(
                capability.time,
                "time",
                return_value=1_002,
            ), self.assertRaises(
                capability.ConfirmationCapabilityError
            ) as partial_approval:
                capability.recover_consumed_confirmation_handoff(
                    root,
                    handoff_path=str(public["handoff_path"]),
                    subject_actor="codex",
                    raw_task_id="task-123",
                    raw_session_id="session-456",
                )
            self.assertEqual(
                partial_approval.exception.reason_code,
                "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
            )

            with mock.patch.object(
                intent,
                "show_intent",
                return_value={
                    "intent": pending,
                    "receipt": {"outcome": "failed"},
                },
            ), mock.patch.object(
                capability.time,
                "time",
                return_value=1_002,
            ), self.assertRaises(
                capability.ConfirmationCapabilityError
            ) as pending_terminal_receipt:
                capability.recover_consumed_confirmation_handoff(
                    root,
                    handoff_path=str(public["handoff_path"]),
                    subject_actor="codex",
                    raw_task_id="task-123",
                    raw_session_id="session-456",
                )
            self.assertEqual(
                pending_terminal_receipt.exception.reason_code,
                "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
            )

            for active_status in ("approved", "bound", "validated"):
                active = self.approved_intent(
                    consumed,
                    status=active_status,
                )
                with self.subTest(
                    active_status_with_terminal_receipt=active_status
                ), mock.patch.object(
                    intent,
                    "show_intent",
                    return_value={
                        "intent": active,
                        "receipt": {"outcome": "expired"},
                    },
                ), mock.patch.object(
                    capability.time,
                    "time",
                    return_value=1_002,
                ), self.assertRaises(
                    capability.ConfirmationCapabilityError
                ) as terminal_receipt:
                    capability.recover_consumed_confirmation_handoff(
                        root,
                        handoff_path=str(public["handoff_path"]),
                        subject_actor="codex",
                        raw_task_id="task-123",
                        raw_session_id="session-456",
                    )
                self.assertEqual(
                    terminal_receipt.exception.reason_code,
                    "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
                )

            completed = self.approved_intent(consumed, status="completed")
            complete_receipt = self.completed_receipt(completed)
            # detail_code is caller-selected audit metadata and has no durable
            # twin on the intent; every derivable receipt field is exact-bound.
            for field in complete_receipt.keys() - {"detail_code"}:
                tampered = dict(complete_receipt)
                current = tampered[field]
                tampered[field] = (
                    999 if isinstance(current, int) else "tampered"
                )
                with self.subTest(
                    completed_receipt_field=field
                ), mock.patch.object(
                    intent,
                    "show_intent",
                    return_value={"intent": completed, "receipt": tampered},
                ), mock.patch.object(
                    capability.time,
                    "time",
                    return_value=1_002,
                ), self.assertRaises(
                    capability.ConfirmationCapabilityError
                ) as completed_receipt_error:
                    capability.recover_consumed_confirmation_handoff(
                        root,
                        handoff_path=str(public["handoff_path"]),
                        subject_actor="codex",
                        raw_task_id="task-123",
                        raw_session_id="session-456",
                    )
                self.assertEqual(
                    completed_receipt_error.exception.reason_code,
                    "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
                )

            receipt_path = (
                root
                / capability.CONSUMPTION_LEDGER_DIRECTORY
                / (
                    capability.CONSUMPTION_RECEIPT_PREFIX
                    + str(public["capability_id"])
                    + ".json"
                )
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["binding_sha256"] = "f" * 64
            receipt_path.write_text(
                json.dumps(receipt, sort_keys=True, separators=(",", ":"))
                + "\n",
                encoding="utf-8",
            )
            if os.name != "nt":
                receipt_path.chmod(0o600)
            with mock.patch.object(
                intent,
                "show_intent",
                return_value={"intent": approved, "receipt": None},
            ), mock.patch.object(
                capability.time,
                "time",
                return_value=1_002,
            ), self.assertRaises(
                capability.ConfirmationCapabilityError
            ) as receipt_error:
                capability.recover_consumed_confirmation_handoff(
                    root,
                    handoff_path=str(public["handoff_path"]),
                    subject_actor="codex",
                    raw_task_id="task-123",
                    raw_session_id="session-456",
                )
            self.assertEqual(
                receipt_error.exception.reason_code,
                "CONFIRMATION_CAPABILITY_INVALID",
            )

    def test_issue_for_intent_derives_mutation_fields_instead_of_trusting_host_copy(self) -> None:
        stored = {
            "intent_id": "a" * 32,
            "status": "pending",
            "actor": "codex",
            "session_hash": capability.session_hash("session-456"),
            "proposal_raw_sha256": "b" * 64,
            "proposal_canonical_sha256": "c" * 64,
            "target_rel_path": "项目/Alpha.md",
            "target_key": "d" * 64,
            "operation": "status_transition",
            "reconcile_action": "UPDATE",
            "fencing_token": 7,
        }
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(
            intent, "show_intent", return_value={"intent": stored, "receipt": None}
        ):
            issued = capability.issue_for_intent(
                Path(raw),
                issuer_actor="human",
                subject_actor="codex",
                raw_task_id="task-123",
                raw_session_id="session-456",
                proposal_id="a" * 32,
                confirmation_reference="manual-review:event-123",
            )
            consumed = self.consume(Path(raw), issued)
            self.assertTrue(capability.attests_to(consumed, **binding()))

    def test_stdin_issuer_handoff_never_returns_token_and_scrubs_after_use(self) -> None:
        stored = {
            "intent_id": "a" * 32,
            "status": "pending",
            "actor": "codex",
            "session_hash": capability.session_hash("session-456"),
            "proposal_raw_sha256": "b" * 64,
            "proposal_canonical_sha256": "c" * 64,
            "target_rel_path": "项目/Alpha.md",
            "target_key": "d" * 64,
            "operation": "governance_migration",
            "reconcile_action": "UPDATE",
            "fencing_token": 7,
        }
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(
            intent, "show_intent", return_value={"intent": stored, "receipt": None}
        ):
            root = Path(raw)
            public = capability.issue_for_intent_handoff(
                root,
                issuer_actor="human",
                subject_actor="codex",
                raw_task_id="task-123",
                raw_session_id="session-456",
                proposal_id="a" * 32,
                confirmation_reference="manual-review:event-123",
            )
            self.assertNotIn("token", public)
            handoff_path = Path(str(public["handoff_path"]))
            raw_handoff = handoff_path.read_text(encoding="utf-8")
            self.assertIn('"token":', raw_handoff)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(handoff_path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(handoff_path.parent.stat().st_mode), 0o700)
            private = capability.read_confirmation_handoff(
                root,
                handoff_path=str(handoff_path),
            )
            self.assertIn("token", private)
            expected = binding()
            expected["operation"] = "governance_migration"
            consumed = capability.consume_confirmation_capability(
                root,
                capability_path=str(private["capability_path"]),
                token=str(private["token"]),
                **expected,
            )
            self.assertEqual(consumed.capability_id, public["capability_id"])
            capability.mark_confirmation_handoff_consumed(
                root,
                handoff_path=str(handoff_path),
                capability_id=str(public["capability_id"]),
            )
            scrubbed = handoff_path.read_text(encoding="utf-8")
            self.assertNotIn('"token":', scrubbed)
            self.assertIn('"status":"consumed"', scrubbed)

    def test_handoff_rejects_symlink_permissions_and_binding_tamper(self) -> None:
        stored = {
            "intent_id": "a" * 32,
            "status": "pending",
            "actor": "codex",
            "session_hash": capability.session_hash("session-456"),
            "proposal_raw_sha256": "b" * 64,
            "proposal_canonical_sha256": "c" * 64,
            "target_rel_path": "项目/Alpha.md",
            "target_key": "d" * 64,
            "operation": "governance_migration",
            "reconcile_action": "UPDATE",
            "fencing_token": 7,
        }
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(
            intent, "show_intent", return_value={"intent": stored, "receipt": None}
        ):
            root = Path(raw)
            public = capability.issue_for_intent_handoff(
                root,
                issuer_actor="human",
                subject_actor="codex",
                raw_task_id="task-123",
                raw_session_id="session-456",
                proposal_id="a" * 32,
                confirmation_reference="manual-review:event-123",
            )
            handoff = Path(str(public["handoff_path"]))
            original = handoff.read_bytes()

            if os.name != "nt":
                handoff.chmod(0o644)
                with self.assertRaises(capability.ConfirmationCapabilityError):
                    capability.read_confirmation_handoff(
                        root,
                        handoff_path=str(handoff),
                    )
                handoff.chmod(0o600)

            payload = json.loads(original)
            payload["proposal_id"] = "e" * 32
            handoff.write_text(
                json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            if os.name != "nt":
                handoff.chmod(0o600)
            with self.assertRaises(capability.ConfirmationCapabilityError):
                capability.read_confirmation_handoff(
                    root,
                    handoff_path=str(handoff),
                )

            handoff.write_bytes(original)
            if os.name != "nt":
                handoff.chmod(0o600)
                alias = handoff.parent / (
                    capability.HANDOFF_PREFIX + "f" * 32 + ".json"
                )
                alias.symlink_to(handoff)
                with self.assertRaises(capability.ConfirmationCapabilityError):
                    capability.read_confirmation_handoff(
                        root,
                        handoff_path=str(alias),
                    )

    def test_handoff_creation_is_create_once_and_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            issued = self.issue(root, operation="governance_migration")
            handoff_root = capability._secure_handoff_directory(root)
            handoff = handoff_root / (
                capability.HANDOFF_PREFIX
                + str(issued["capability_id"])
                + ".json"
            )
            sentinel = b"existing-private-handoff\n"
            descriptor = os.open(
                handoff,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(sentinel)
            if os.name != "nt":
                handoff.chmod(0o600)

            with mock.patch.object(
                capability,
                "issue_for_intent",
                return_value=issued,
            ), self.assertRaises(capability.ConfirmationCapabilityError) as caught:
                capability.issue_for_intent_handoff(
                    root,
                    issuer_actor="human",
                    subject_actor="codex",
                    raw_task_id="task-123",
                    raw_session_id="session-456",
                    proposal_id="a" * 32,
                    confirmation_reference="manual-review:event-123",
                )
            self.assertEqual(
                caught.exception.reason_code,
                "CONFIRMATION_HANDOFF_ALREADY_EXISTS",
            )
            self.assertEqual(handoff.read_bytes(), sentinel)

    def test_cli_stdout_contains_only_public_handoff_summary(self) -> None:
        stored = {
            "intent_id": "a" * 32,
            "status": "pending",
            "actor": "codex",
            "session_hash": capability.session_hash("session-456"),
            "proposal_raw_sha256": "b" * 64,
            "proposal_canonical_sha256": "c" * 64,
            "target_rel_path": "项目/Alpha.md",
            "target_key": "d" * 64,
            "operation": "governance_migration",
            "reconcile_action": "UPDATE",
            "fencing_token": 7,
        }
        request = {
            "subject_actor": "codex",
            "task_id": "task-123",
            "session_id": "session-456",
            "proposal_id": "a" * 32,
            "confirmation_reference": "manual-review:event-123",
        }
        stdin = io.TextIOWrapper(
            io.BytesIO((json.dumps(request) + "\n").encode("utf-8")),
            encoding="utf-8",
        )
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(
            capability, "assert_runtime_ready"
        ), mock.patch.object(
            capability, "expand_path", return_value=Path(raw)
        ), mock.patch.object(
            intent, "show_intent", return_value={"intent": stored, "receipt": None}
        ), mock.patch.object(sys, "stdin", stdin):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    capability.main(
                        ["--issuer-actor", "human", "--json", "issue"]
                    ),
                    0,
                )
            payload = json.loads(output.getvalue())
            self.assertTrue(payload["ok"])
            self.assertNotIn("token", payload)
            self.assertNotIn("manual-review:event-123", output.getvalue())
            self.assertTrue(Path(payload["handoff_path"]).is_file())

    def test_symlink_capability_path_is_rejected(self) -> None:
        if os.name == "nt":
            self.skipTest("symlink creation is privilege-dependent on Windows")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            issued = self.issue(root)
            link = Path(str(issued["path"])).parent / "human-confirmation-link.json"
            link.symlink_to(Path(str(issued["path"])))
            with self.assertRaises(capability.ConfirmationCapabilityError):
                capability.consume_confirmation_capability(
                    root,
                    capability_path=str(link),
                    token=str(issued["token"]),
                    **binding(),
                )


if __name__ == "__main__":
    unittest.main()
