from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import agent_memory_intent as intent
import agent_memory_write as writer


class WriterHostScopeTests(unittest.TestCase):
    @staticmethod
    def markdown(*, actor: str, agent_scope: str) -> str:
        app_id = "ailu" if actor == "ailu" else "agent-memory"
        project_id = "ailu" if actor == "ailu" else "agent-memory-vault"
        return (
            "---\n"
            "memory_type: workflow\n"
            "track: workflow\n"
            f"project_id: {project_id}\n"
            f"app_id: {app_id}\n"
            f"agent_scope: {agent_scope}\n"
            "status: active\n"
            "---\n\n"
            "# Scope probe\n"
        )

    def validate(self, *, actor: str, agent_scope: str, explicit: bool) -> dict[str, object]:
        app_id = "ailu" if actor == "ailu" else "agent-memory"
        project_id = "ailu" if actor == "ailu" else "agent-memory-vault"
        path = intent.VAULT_ROOT / "工作流" / "ScopeProbe.md"
        with mock.patch.object(writer, "ACTOR", actor):
            return writer._validate_writer_markdown(
                self.markdown(actor=actor, agent_scope=agent_scope),
                path=path,
                app_id=app_id,
                project_id=project_id,
                require_explicit_write_scope=explicit,
            )

    def test_shared_scope_is_readable_and_writable_by_every_supported_actor(self) -> None:
        for actor in ("codex", "claude", "ailu"):
            for explicit in (False, True):
                with self.subTest(actor=actor, explicit=explicit):
                    metadata = self.validate(actor=actor, agent_scope="shared", explicit=explicit)
                    self.assertEqual(metadata["agent_scope"], "shared")

    def test_codex_and_claude_can_read_and_write_their_own_host_scope(self) -> None:
        for actor in ("codex", "claude"):
            for explicit in (False, True):
                with self.subTest(actor=actor, explicit=explicit):
                    metadata = self.validate(actor=actor, agent_scope=actor, explicit=explicit)
                    self.assertEqual(metadata["agent_scope"], actor)

    def test_codex_and_claude_cannot_read_or_write_the_other_host_scope(self) -> None:
        for actor, other_scope in (("codex", "claude"), ("claude", "codex")):
            for explicit in (False, True):
                with self.subTest(actor=actor, other_scope=other_scope, explicit=explicit):
                    with self.assertRaises(writer.MemoryWriteError) as raised:
                        self.validate(actor=actor, agent_scope=other_scope, explicit=explicit)
                    self.assertEqual(raised.exception.reason_code, "AGENT_SCOPE_MISMATCH")

    def test_governance_operation_string_cannot_bypass_cross_host_read_scope(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw).resolve()
            relative_path = "工作流/ClaudePrivate.md"
            path = vault / relative_path
            path.parent.mkdir(parents=True)
            memory_id = writer.memory_index.memory_identity(relative_path, {})[0]
            path.write_text(
                "---\n"
                f"memory_id: {memory_id}\n"
                "memory_type: workflow\n"
                "track: workflow\n"
                "project_id: agent-memory-vault\n"
                "app_id: agent-memory\n"
                "agent_scope: claude\n"
                "status: active\n"
                "temporal_policy: reviewable\n"
                "review_after_days: 90\n"
                "risk_class: ordinary\n"
                "---\n\n"
                "# Already governed Claude memory\n",
                encoding="utf-8",
            )
            target = intent.CanonicalTarget(
                path=path,
                rel_path=relative_path,
                target_key="b" * 64,
            )
            request = {
                "target_relative_path": target.rel_path,
                "app_id": "agent-memory",
                "project_id": "agent-memory-vault",
                "operation": "governance_migration",
            }
            with mock.patch.object(writer, "ACTOR", "codex"), mock.patch.object(
                writer.write_intent,
                "VAULT_ROOT",
                vault,
            ), mock.patch.object(
                writer.memory_index,
                "VAULT_ROOT",
                vault,
            ), mock.patch.object(
                writer,
                "_formal_target",
                return_value=target,
            ), mock.patch.object(
                writer.write_intent,
                "current_git_head",
                return_value="c" * 40,
            ):
                with self.assertRaises(writer.MemoryWriteError) as raised:
                    writer.read_target(request, raw_session_id="scope-session")
                with self.assertRaises(writer.MemoryWriteError) as prepare_blocked:
                    writer.prepare(
                        {
                            **request,
                            "proposal_markdown": path.read_text(encoding="utf-8"),
                            "read_token": "d" * 64,
                            "summary": "governance scope replay",
                            "source_class": "user_direct",
                            "knowledge_kind": "fact",
                            "asserted_by": "human",
                            "evidence_ref": "current reviewed migration",
                        },
                        raw_session_id="scope-session",
                    )
        self.assertEqual(raised.exception.reason_code, "AGENT_SCOPE_MISMATCH")
        self.assertEqual(
            prepare_blocked.exception.reason_code,
            "AGENT_SCOPE_MISMATCH",
        )

    def test_governance_apply_replay_cannot_bypass_host_or_ailu_scope(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw).resolve()
            relative_path = "工作流/ClaudePrivate.md"
            path = vault / relative_path
            path.parent.mkdir(parents=True)
            memory_id = writer.memory_index.memory_identity(relative_path, {})[0]
            proposal = (
                "---\n"
                f"memory_id: {memory_id}\n"
                "memory_type: workflow\n"
                "track: workflow\n"
                "project_id: agent-memory-vault\n"
                "app_id: agent-memory\n"
                "agent_scope: claude\n"
                "status: active\n"
                "temporal_policy: reviewable\n"
                "review_after_days: 90\n"
                "risk_class: ordinary\n"
                "---\n\n"
                "# Already governed Claude memory\n"
            )
            path.write_text(proposal, encoding="utf-8")
            digest = intent.content_hashes(proposal.encode("utf-8"))
            target = intent.CanonicalTarget(
                path=path,
                rel_path=relative_path,
                target_key="e" * 64,
            )
            proposal_id = "f" * 32
            stored_intent = {
                "intent_id": proposal_id,
                "fencing_token": 7,
                "reconcile_action": "UPDATE",
                "operation": "governance_migration",
                "status": "bound",
                "target_key": target.target_key,
                "proposal_raw_sha256": digest.raw_sha256,
                "proposal_canonical_sha256": digest.canonical_sha256,
            }
            apply_request = {
                "proposal_id": proposal_id,
                "fencing_token": 7,
                "target_relative_path": relative_path,
                "proposal_markdown": proposal,
                "proposal_raw_sha256": digest.raw_sha256,
                "proposal_canonical_sha256": digest.canonical_sha256,
            }
            common_patches = (
                mock.patch.object(writer.write_intent, "VAULT_ROOT", vault),
                mock.patch.object(writer.memory_index, "VAULT_ROOT", vault),
                mock.patch.object(writer, "_formal_target", return_value=target),
                mock.patch.object(writer, "_authorized_intent", return_value=stored_intent),
                mock.patch.object(
                    writer,
                    "_intent_scope_binding",
                    return_value=("agent-memory", "agent-memory-vault"),
                ),
            )
            with common_patches[0], common_patches[1], common_patches[2], common_patches[3], common_patches[4]:
                with mock.patch.object(writer, "ACTOR", "codex"):
                    with self.assertRaises(writer.MemoryWriteError) as codex_blocked:
                        writer._apply_locked(
                            apply_request,
                            raw_session_id="scope-session",
                        )

            ailu_relative_path = "工作流/AiluShared.md"
            ailu_path = vault / ailu_relative_path
            ailu_memory_id = writer.memory_index.memory_identity(
                ailu_relative_path,
                {},
            )[0]
            ailu_target = intent.CanonicalTarget(
                path=ailu_path,
                rel_path=ailu_relative_path,
                target_key="a" * 64,
            )
            for operation, status in (
                ("governance_migration", "active"),
                ("status_transition", "pending_verification"),
            ):
                with self.subTest(actor="ailu", operation=operation):
                    ailu_proposal = (
                        "---\n"
                        f"memory_id: {ailu_memory_id}\n"
                        "memory_type: workflow\n"
                        "track: workflow\n"
                        "project_id: ailu\n"
                        "app_id: ailu\n"
                        "agent_scope: shared\n"
                        f"status: {status}\n"
                        "temporal_policy: reviewable\n"
                        "review_after_days: 90\n"
                        "risk_class: ordinary\n"
                        "---\n\n"
                        "# Ailu shared memory\n"
                    )
                    ailu_path.write_text(ailu_proposal, encoding="utf-8")
                    ailu_digest = intent.content_hashes(
                        ailu_proposal.encode("utf-8")
                    )
                    ailu_intent = {
                        "intent_id": proposal_id,
                        "fencing_token": 7,
                        "reconcile_action": "UPDATE",
                        "operation": operation,
                        "target_status": (
                            "pending_verification"
                            if operation == "status_transition"
                            else ""
                        ),
                        "status": "bound",
                        "target_key": ailu_target.target_key,
                        "scope_app_id": "ailu",
                        "scope_project_id": "ailu",
                        "proposal_raw_sha256": ailu_digest.raw_sha256,
                        "proposal_canonical_sha256": (
                            ailu_digest.canonical_sha256
                        ),
                    }
                    ailu_apply_request = {
                        "proposal_id": proposal_id,
                        "fencing_token": 7,
                        "target_relative_path": ailu_relative_path,
                        "proposal_markdown": ailu_proposal,
                        "proposal_raw_sha256": ailu_digest.raw_sha256,
                        "proposal_canonical_sha256": (
                            ailu_digest.canonical_sha256
                        ),
                    }
                    with mock.patch.object(
                        writer,
                        "ACTOR",
                        "ailu",
                    ), mock.patch.object(
                        writer,
                        "_formal_target",
                        return_value=ailu_target,
                    ), mock.patch.object(
                        writer,
                        "_authorized_intent",
                        return_value=ailu_intent,
                    ), mock.patch.object(
                        writer,
                        "_intent_scope_binding",
                        wraps=writer._intent_scope_binding,
                    ) as scope_binding:
                        with self.assertRaises(
                            writer.MemoryWriteError
                        ) as ailu_blocked:
                            writer._apply_locked(
                                ailu_apply_request,
                                raw_session_id="scope-session",
                            )
                    self.assertEqual(
                        ailu_blocked.exception.reason_code,
                        "STATUS_TRANSITION_FORBIDDEN",
                    )
                    scope_binding.assert_not_called()
            codex_proposal = proposal.replace(
                "agent_scope: claude",
                "agent_scope: codex",
            )
            codex_digest = intent.content_hashes(codex_proposal.encode("utf-8"))
            codex_intent = {
                **stored_intent,
                "proposal_raw_sha256": codex_digest.raw_sha256,
                "proposal_canonical_sha256": codex_digest.canonical_sha256,
            }
            codex_apply_request = {
                **apply_request,
                "proposal_markdown": codex_proposal,
                "proposal_raw_sha256": codex_digest.raw_sha256,
                "proposal_canonical_sha256": codex_digest.canonical_sha256,
            }
            with mock.patch.object(
                writer.write_intent,
                "VAULT_ROOT",
                vault,
            ), mock.patch.object(
                writer.memory_index,
                "VAULT_ROOT",
                vault,
            ), mock.patch.object(
                writer,
                "_formal_target",
                return_value=target,
            ), mock.patch.object(
                writer,
                "_authorized_intent",
                return_value=codex_intent,
            ), mock.patch.object(
                writer,
                "_intent_scope_binding",
                return_value=("agent-memory", "agent-memory-vault"),
            ), mock.patch.object(writer, "ACTOR", "claude"):
                with self.assertRaises(writer.MemoryWriteError) as claude_blocked:
                    writer._apply_locked(
                        codex_apply_request,
                        raw_session_id="scope-session",
                    )
        self.assertEqual(
            codex_blocked.exception.reason_code,
            "AGENT_SCOPE_MISMATCH",
        )
        self.assertEqual(
            claude_blocked.exception.reason_code,
            "AGENT_SCOPE_MISMATCH",
        )

    def test_ailu_remains_confined_to_shared_scope(self) -> None:
        for forbidden_scope in ("ailu", "codex", "claude"):
            for explicit in (False, True):
                with self.subTest(forbidden_scope=forbidden_scope, explicit=explicit):
                    with self.assertRaises(writer.MemoryWriteError) as raised:
                        self.validate(actor="ailu", agent_scope=forbidden_scope, explicit=explicit)
                    self.assertEqual(raised.exception.reason_code, "AGENT_SCOPE_MISMATCH")

    def test_reconciliation_search_includes_shared_and_self_only_for_host_actors(self) -> None:
        self.assertEqual(writer._reconciliation_agent_scope("codex"), "codex")
        self.assertEqual(writer._reconciliation_agent_scope("claude"), "claude")
        self.assertEqual(writer._reconciliation_agent_scope("ailu"), "shared")

    def test_completed_non_sensitive_apply_needs_no_new_confirmation_but_pending_does(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "项目" / "Risk.md"
            path.parent.mkdir()
            proposal = "---\nstatus: active\n---\n# Risk\n"
            path.write_text(proposal, encoding="utf-8")
            digest = intent.content_hashes(proposal.encode("utf-8"))
            target = intent.CanonicalTarget(
                path=path,
                rel_path="项目/Risk.md",
                target_key="项目/risk.md",
            )
            stored = {
                "intent_id": "a" * 32,
                "fencing_token": 7,
                "reconcile_action": "UPDATE",
                "operation": "content_update",
                "status": "completed",
                "target_rel_path": target.rel_path,
                "target_key": target.target_key,
                "proposal_raw_sha256": digest.raw_sha256,
                "proposal_canonical_sha256": digest.canonical_sha256,
                "final_raw_sha256": digest.raw_sha256,
                "base_git_head": "1" * 40,
            }
            receipt = {
                "receipt_id": "b" * 32,
                "outcome": "completed",
                "git_commit": "2" * 40,
                "created_at": "2026-08-25T00:00:00+00:00",
            }
            request = {
                "proposal_id": stored["intent_id"],
                "fencing_token": 7,
                "target_relative_path": target.rel_path,
                "proposal_markdown": proposal,
                "proposal_raw_sha256": digest.raw_sha256,
                "proposal_canonical_sha256": digest.canonical_sha256,
            }
            with mock.patch.object(writer, "ACTOR", "codex"), mock.patch.object(
                writer,
                "_authorized_intent",
                return_value=stored,
            ), mock.patch.object(
                writer,
                "_formal_target",
                return_value=target,
            ), mock.patch.object(
                writer,
                "_intent_scope_binding",
                return_value=("agent-memory", "risk"),
            ), mock.patch.object(
                writer,
                "_validate_writer_markdown",
            ), mock.patch.object(
                writer,
                "_validate_write_temporal_gate",
            ), mock.patch.object(
                writer,
                "_has_conditional_recovery_sidecar",
                return_value=False,
            ), mock.patch.object(
                writer.write_intent,
                "git_target_digest_at_commit",
                return_value=(True, digest),
            ), mock.patch.object(
                writer,
                "_content_update_status",
            ), mock.patch.object(
                writer.write_intent,
                "show_intent",
                return_value={"intent": stored, "receipt": receipt},
            ), mock.patch.object(
                writer.write_intent,
                "verify_terminal_receipt",
            ), mock.patch.object(
                writer,
                "_target_digest",
                return_value=(True, digest),
            ):
                recovered = writer._apply_locked(
                    request,
                    raw_session_id="risk-session",
                )
            self.assertFalse(recovered["closeout_required"])
            self.assertTrue(recovered["payload"]["idempotent"])

            pending = {**stored, "status": "pending"}
            with mock.patch.object(writer, "ACTOR", "codex"), mock.patch.object(
                writer,
                "_authorized_intent",
                return_value=pending,
            ), mock.patch.object(writer, "_formal_target") as formal_target:
                with self.assertRaises(writer.MemoryWriteError) as blocked:
                    writer._apply_locked(request, raw_session_id="risk-session")
            self.assertEqual(
                blocked.exception.reason_code,
                "USER_CONFIRMATION_REQUIRED",
            )
            formal_target.assert_not_called()

    def test_legacy_sha_target_key_compatibility_is_terminal_and_path_exact(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "项目" / "Legacy.md"
            path.parent.mkdir()
            proposal = "---\nstatus: active\n---\n# Legacy\n"
            path.write_text(proposal, encoding="utf-8")
            digest = intent.content_hashes(proposal.encode("utf-8"))
            target = intent.CanonicalTarget(
                path=path,
                rel_path="项目/Legacy.md",
                target_key="项目/legacy.md",
            )
            stored = {
                "intent_id": "a" * 32,
                "fencing_token": 7,
                "reconcile_action": "UPDATE",
                "operation": "content_update",
                "status": "completed",
                "target_rel_path": target.rel_path,
                "target_key": "f" * 64,
                "proposal_raw_sha256": digest.raw_sha256,
                "proposal_canonical_sha256": digest.canonical_sha256,
                "final_raw_sha256": digest.raw_sha256,
                "base_git_head": "1" * 40,
                "base_exists": 1,
                "base_raw_sha256": digest.raw_sha256,
                "base_canonical_sha256": digest.canonical_sha256,
                "scope_app_id": "agent-memory",
                "scope_project_id": "legacy",
            }
            legacy_target = intent.CanonicalTarget(
                path=target.path,
                rel_path=target.rel_path,
                target_key=stored["target_key"],
            )
            with mock.patch.object(writer, "ACTOR", "codex"):
                stored["read_token"] = writer._read_token(
                    legacy_target,
                    app_id="agent-memory",
                    project_id="legacy",
                    exists=True,
                    digest=digest,
                    git_head=stored["base_git_head"],
                    raw_session_id="legacy-session",
                )
            receipt = {
                "receipt_id": "b" * 32,
                "outcome": "completed",
                "git_commit": "2" * 40,
                "created_at": "2026-08-25T00:00:00+00:00",
            }
            request = {
                "proposal_id": stored["intent_id"],
                "fencing_token": 7,
                "target_relative_path": target.rel_path,
                "proposal_markdown": proposal,
                "proposal_raw_sha256": digest.raw_sha256,
                "proposal_canonical_sha256": digest.canonical_sha256,
            }

            def invoke(intent_row, apply_request):
                with mock.patch.object(writer, "ACTOR", "codex"), mock.patch.object(
                    writer,
                    "_authorized_intent",
                    return_value=intent_row,
                ), mock.patch.object(
                    writer,
                    "_formal_target",
                    return_value=target,
                ), mock.patch.object(
                    writer,
                    "_validate_writer_markdown",
                ), mock.patch.object(
                    writer,
                    "_validate_write_temporal_gate",
                ), mock.patch.object(
                    writer,
                    "_has_conditional_recovery_sidecar",
                    return_value=False,
                ), mock.patch.object(
                    writer.write_intent,
                    "git_target_digest_at_commit",
                    return_value=(True, digest),
                ), mock.patch.object(
                    writer,
                    "_content_update_status",
                ), mock.patch.object(
                    writer.write_intent,
                    "show_intent",
                    return_value={"intent": intent_row, "receipt": receipt},
                ), mock.patch.object(
                    writer.write_intent,
                    "verify_terminal_receipt",
                ), mock.patch.object(
                    writer,
                    "_target_digest",
                    return_value=(True, digest),
                ):
                    return writer._apply_locked(
                        apply_request,
                        raw_session_id="legacy-session",
                    )

            recovered = invoke(stored, request)
            self.assertTrue(recovered["payload"]["idempotent"])

            confirmed = {
                **request,
                "confirmed_by": "codex",
                "confirmation_reference": "existing-host-confirmation",
            }
            with self.assertRaises(writer.MemoryWriteError) as active_blocked:
                invoke({**stored, "status": "pending"}, confirmed)
            self.assertEqual(
                active_blocked.exception.reason_code,
                "APPROVAL_TARGET_MISMATCH",
            )

            with self.assertRaises(writer.MemoryWriteError) as path_blocked:
                invoke(
                    {**stored, "target_rel_path": "项目/Other.md"},
                    request,
                )
            self.assertEqual(
                path_blocked.exception.reason_code,
                "APPROVAL_TARGET_MISMATCH",
            )


if __name__ == "__main__":
    unittest.main()
