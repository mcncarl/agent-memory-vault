from __future__ import annotations

import contextlib
import datetime as dt
import json
import sqlite3
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_audit as audit
import agent_memory_claim as memory_claim
import agent_memory_confirmation_capability as confirmation_capability
import agent_memory_index as memory_index
import agent_memory_migrate as migrate
import agent_memory_observability as observability
import agent_memory_write as memory_write
from tests.state_fixture import initialize_full_state


MEMORY_ID = "a" * 64


def markdown(status: str, *, verified_at: str = "2026-08-24", body: str = "Current fact.\n") -> str:
    return (
        "---\n"
        f"memory_id: {MEMORY_ID}\n"
        f"status: {status}\n"
        "agent_scope: shared\n"
        "app_id: agent-memory\n"
        "project_id: alpha\n"
        "temporal_policy: reviewable\n"
        f"verified_at: {verified_at}\n"
        "---\n"
        "# Fact\n\n"
        f"{body}"
    )


class GovernanceV4Tests(unittest.TestCase):
    def test_index_frontmatter_parser_rejects_duplicate_governance_scalars(self) -> None:
        base = (
            "---\nmemory_type: workflow\ntrack: workflow\nstatus: active\n"
            "risk_class: action_sensitive\ntemporal_policy: expiring\n"
            "review_after_days: 30\n---\n# Rule\n"
        )
        for key, second in (
            ("risk_class", "ordinary"),
            ("temporal_policy", "reviewable"),
            ("fact_key", "workflow.other"),
            ("verified_at", "2026-08-25"),
            ("project_id", "other-project"),
        ):
            if f"{key}:" in base:
                duplicate = base.replace(
                    f"{key}: ",
                    f"{key}: {second}\n{key}: ",
                    1,
                )
            else:
                duplicate = base.replace(
                    "review_after_days: 30\n",
                    f"review_after_days: 30\n{key}: first\n{key}: {second}\n",
                )
            with self.subTest(key=key), self.assertRaisesRegex(
                ValueError, "FRONTMATTER_DUPLICATE_KEY"
            ):
                memory_index.parse_frontmatter(duplicate)

    def test_explicit_session_is_stable_confirmation_task_binding(self) -> None:
        with mock.patch.dict(
            memory_write.os.environ,
            {
                "AGENT_MEMORY_SESSION_ID": "session-stable",
                "AGENT_MEMORY_TASK_ID": "ephemeral-wrapper-nonce",
            },
            clear=False,
        ), mock.patch.object(
            memory_write.memory_observability,
            "current_raw_task_id",
            return_value="ephemeral-wrapper-nonce",
        ):
            self.assertEqual(
                memory_write._confirmation_raw_task_id("session-stable"),
                "session-stable",
            )

    def test_content_update_status_is_invariant_and_add_is_active_only(self) -> None:
        self.assertEqual(
            memory_write._content_update_status(
                base_text=markdown("pending_verification"),
                proposal_text=markdown(
                    "pending_verification",
                    body="Reviewed notes without reactivation.\n",
                ),
                base_exists=True,
            ),
            "pending_verification",
        )
        self.assertEqual(
            memory_write._content_update_status(
                base_text="",
                proposal_text=markdown("active"),
                base_exists=False,
            ),
            "active",
        )
        for base, proposal, exists in (
            (markdown("active"), markdown("pending_verification"), True),
            (markdown("pending_verification"), markdown("active"), True),
            (markdown("outdated"), markdown("outdated"), True),
            ("", markdown("pending_verification"), False),
        ):
            with self.subTest(exists=exists, proposal=proposal[:80]), self.assertRaises(
                memory_write.MemoryWriteError
            ) as caught:
                memory_write._content_update_status(
                    base_text=base,
                    proposal_text=proposal,
                    base_exists=exists,
                )
            self.assertEqual(caught.exception.reason_code, "STATUS_TRANSITION_FORBIDDEN")

    def test_prepare_blocks_content_update_status_bypass_for_every_writer(self) -> None:
        base = markdown("active")
        proposal = markdown("pending_verification")
        base_digest = memory_write.write_intent.content_hashes(base.encode("utf-8"))
        target = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/Alpha.md"),
            rel_path="项目/Alpha.md",
            target_key="d" * 64,
        )
        request = {
            "schema_version": 2,
            "target_relative_path": target.rel_path,
            "proposal_markdown": proposal,
            "read_token": "e" * 64,
            "app_id": "agent-memory",
            "project_id": "alpha",
        }
        previous_actor = memory_write.ACTOR
        try:
            for actor in ("codex", "claude", "ailu"):
                memory_write.ACTOR = actor
                with self.subTest(actor=actor), mock.patch.object(
                    memory_write, "_formal_target", return_value=target
                ), mock.patch.object(
                    memory_write, "_scope_request", return_value=("agent-memory", "alpha")
                ), mock.patch.object(
                    memory_write, "_validate_writer_markdown", return_value={}
                ), mock.patch.object(
                    memory_write,
                    "_target_snapshot",
                    return_value=(True, base_digest, "f" * 40, "e" * 64),
                ), self.assertRaises(memory_write.MemoryWriteError) as caught:
                    memory_write.prepare(request, raw_session_id="session-1")
                self.assertEqual(
                    caught.exception.reason_code,
                    "STATUS_TRANSITION_FORBIDDEN",
                )
        finally:
            memory_write.ACTOR = previous_actor

    def test_apply_recovery_rechecks_status_against_immutable_git_base(self) -> None:
        base = markdown("active")
        proposal = markdown("pending_verification")
        base_digest = memory_write.write_intent.content_hashes(base.encode("utf-8"))
        proposal_digest = memory_write.write_intent.content_hashes(proposal.encode("utf-8"))
        target = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/Alpha.md"),
            rel_path="项目/Alpha.md",
            target_key="d" * 64,
        )
        stored = {
            "intent_id": "b" * 32,
            "fencing_token": 9,
            "reconcile_action": "UPDATE",
            "operation": "content_update",
            "status": "bound",
            "target_key": target.target_key,
            "target_rel_path": target.rel_path,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "base_git_head": "f" * 40,
        }
        request = {
            "schema_version": 2,
            "proposal_id": "b" * 32,
            "fencing_token": 9,
            "target_relative_path": target.rel_path,
            "proposal_markdown": proposal,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "confirmed_by": "user",
            "confirmation_reference": "task:approved",
        }
        previous_actor = memory_write.ACTOR
        try:
            for actor in ("codex", "claude", "ailu"):
                memory_write.ACTOR = actor
                with self.subTest(actor=actor), mock.patch.object(
                    memory_write, "_authorized_intent", return_value=stored
                ), mock.patch.object(
                    memory_write, "_formal_target", return_value=target
                ), mock.patch.object(
                    memory_write, "_intent_scope_binding", return_value=("agent-memory", "alpha")
                ), mock.patch.object(
                    memory_write, "_validate_writer_markdown", return_value={}
                ), mock.patch.object(
                    memory_write, "_validate_write_temporal_gate"
                ), mock.patch.object(
                    memory_write, "_has_conditional_recovery_sidecar", return_value=False
                ), mock.patch.object(
                    memory_write.write_intent,
                    "git_target_digest_at_commit",
                    return_value=(True, base_digest),
                ), self.assertRaises(memory_write.MemoryWriteError) as caught:
                    memory_write._apply_locked(request, raw_session_id="session-1")
                self.assertEqual(
                    caught.exception.reason_code,
                    "STATUS_TRANSITION_FORBIDDEN",
                )
        finally:
            memory_write.ACTOR = previous_actor

    def test_prepare_adopt_cannot_hide_status_change_in_dirty_worktree(self) -> None:
        base = markdown("active")
        proposal = markdown("pending_verification")
        base_digest = memory_write.write_intent.content_hashes(base.encode("utf-8"))
        proposal_digest = memory_write.write_intent.content_hashes(proposal.encode("utf-8"))
        target = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/Alpha.md"),
            rel_path="项目/Alpha.md",
            target_key="d" * 64,
        )
        request = {
            "schema_version": 2,
            "target_relative_path": target.rel_path,
            "proposal_markdown": proposal,
            "read_token": "e" * 64,
            "app_id": "agent-memory",
            "project_id": "alpha",
            "adopt_external": True,
        }
        with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
            memory_write, "_formal_target", return_value=target
        ), mock.patch.object(
            memory_write, "_scope_request", return_value=("agent-memory", "alpha")
        ), mock.patch.object(
            memory_write, "_validate_writer_markdown", return_value={}
        ), mock.patch.object(
            memory_write,
            "_target_snapshot",
            return_value=(True, proposal_digest, "f" * 40, "e" * 64),
        ), mock.patch.object(
            memory_write.write_intent,
            "git_target_digest_at_commit",
            return_value=(True, base_digest),
        ), self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write.prepare(request, raw_session_id="session-1")
        self.assertEqual(caught.exception.reason_code, "STATUS_TRANSITION_FORBIDDEN")

    def test_global_user_scope_requires_an_exact_governed_operation(self) -> None:
        user_target = SimpleNamespace(
            rel_path="用户记忆/Profile.md",
            path=memory_write.write_intent.VAULT_ROOT / "用户记忆" / "Profile.md",
        )
        project_target = SimpleNamespace(
            rel_path="项目/Profile.md",
            path=memory_write.write_intent.VAULT_ROOT / "项目" / "Profile.md",
        )
        payload = {"app_id": "agent-memory", "project_id": "global"}
        with mock.patch.object(memory_write, "ACTOR", "codex"):
            for operation in ("", "content_update"):
                with self.subTest(operation=operation), self.assertRaises(
                    memory_write.MemoryWriteError
                ):
                    memory_write._scope_request(
                        payload,
                        target=user_target,
                        governed_operation=operation,
                    )
            for operation in ("governance_migration", "status_transition"):
                with self.subTest(operation=operation):
                    self.assertEqual(
                        memory_write._scope_request(
                            payload,
                            target=user_target,
                            governed_operation=operation,
                        ),
                        ("agent-memory", "global"),
                    )
            with self.assertRaises(memory_write.MemoryWriteError):
                memory_write._scope_request(
                    payload,
                    target=project_target,
                    governed_operation="governance_migration",
                )

    def test_audit_dates_require_an_exact_iso_date(self) -> None:
        self.assertEqual(audit.parse_date("2099-01-01"), __import__("datetime").date(2099, 1, 1))
        self.assertIsNone(audit.parse_date("2099-01-01junk"))
        self.assertIsNone(audit.parse_date("2099-01-01T00:00:00Z"))

    def test_status_transition_is_metadata_only_and_preserves_memory_id(self) -> None:
        result = memory_write._validate_status_transition(
            base_text=markdown("active"),
            proposal_text=markdown("pending_verification"),
            target_status="pending_verification",
            evidence_ref="",
        )
        self.assertEqual(result["from_status"], "active")
        with self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write._validate_status_transition(
                base_text=markdown("active"),
                proposal_text=markdown("pending_verification", body="Changed fact.\n"),
                target_status="pending_verification",
                evidence_ref="",
            )
        self.assertEqual(caught.exception.reason_code, "STATUS_TRANSITION_INVALID")
        with self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write._validate_status_transition(
                base_text=markdown("active", verified_at="2026-08-01"),
                proposal_text=markdown("outdated", verified_at="2026-08-24"),
                target_status="outdated",
                evidence_ref="",
            )
        self.assertEqual(caught.exception.reason_code, "STATUS_TRANSITION_INVALID")

    def test_reactivation_requires_fresh_explicit_verification_and_evidence(self) -> None:
        with self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write._validate_status_transition(
                base_text=markdown("pending_verification", verified_at="2026-01-01"),
                proposal_text=markdown("active", verified_at="2026-08-24"),
                target_status="active",
                evidence_ref="",
            )
        self.assertEqual(caught.exception.reason_code, "STATUS_REACTIVATION_EVIDENCE_REQUIRED")
        result = memory_write._validate_status_transition(
            base_text=markdown("pending_verification", verified_at="2026-01-01"),
            proposal_text=markdown("active", verified_at="2026-08-24"),
            target_status="active",
            evidence_ref="evidence-1",
        )
        self.assertEqual(result["target_status"], "active")
        for invalid_verified_at in ("2026-01-01", "2026-08-24T00:00:00Z", "2999-01-01"):
            with self.subTest(verified_at=invalid_verified_at):
                with self.assertRaises(memory_write.MemoryWriteError) as caught:
                    memory_write._validate_status_transition(
                        base_text=markdown("pending_verification", verified_at="2026-01-01"),
                        proposal_text=markdown("active", verified_at=invalid_verified_at),
                        target_status="active",
                        evidence_ref="new-live-evidence",
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "STATUS_REACTIVATION_EVIDENCE_REQUIRED",
                )

    def test_write_temporal_gate_requires_explicit_policy_and_atomic_sensitive_facts(self) -> None:
        ordinary = (
            "---\nmemory_type: project\ntrack: project\nstatus: active\n"
            "risk_class: ordinary\ntemporal_policy: reviewable\nreview_after_days: 90\n---\n# Project\n"
        )
        memory_write._validate_write_temporal_gate(
            proposal_text=ordinary,
            knowledge_kind="rule",
            evidence_ref="",
            operation="content_update",
        )
        duplicate_downgrades = (
            ordinary.replace(
                "risk_class: ordinary",
                "risk_class: action_sensitive\nrisk_class: ordinary",
            ),
            ordinary.replace(
                "temporal_policy: reviewable",
                "temporal_policy: expiring\ntemporal_policy: reviewable",
            ),
            ordinary.replace(
                "status: active",
                "status: pending_verification",
            ).replace(
                "risk_class: ordinary",
                "risk_class: action_sensitive\nrisk_class: ordinary",
            ),
        )
        for duplicate in duplicate_downgrades:
            with self.subTest(duplicate=duplicate[:160]), self.assertRaises(
                memory_write.MemoryWriteError
            ) as caught:
                memory_write._validate_write_temporal_gate(
                    proposal_text=duplicate,
                    knowledge_kind="rule",
                    evidence_ref="",
                    operation="content_update",
                )
            self.assertEqual(
                caught.exception.reason_code,
                "FRONTMATTER_DUPLICATE_KEY",
            )
        with self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write._validate_write_temporal_gate(
                proposal_text=ordinary.replace("temporal_policy: reviewable\n", ""),
                knowledge_kind="rule",
                evidence_ref="",
                operation="content_update",
            )
        self.assertEqual(caught.exception.reason_code, "TEMPORAL_POLICY_REQUIRED")
        with self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write._validate_write_temporal_gate(
                proposal_text=ordinary.replace("review_after_days: 90\n", ""),
                knowledge_kind="rule",
                evidence_ref="",
                operation="content_update",
            )
        self.assertEqual(caught.exception.reason_code, "REVIEW_POLICY_REQUIRED")
        with self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write._validate_write_temporal_gate(
                proposal_text=ordinary,
                knowledge_kind="fact",
                evidence_ref="live-evidence",
                operation="content_update",
            )
        self.assertEqual(caught.exception.reason_code, "PATH_POLICY_DOWNGRADE_FORBIDDEN")

        sensitive_without_fact = ordinary.replace(
            "risk_class: ordinary", "risk_class: action_sensitive"
        )
        for caller_kind in ("rule", "preference", "inference"):
            with self.subTest(knowledge_kind=caller_kind):
                with self.assertRaises(memory_write.MemoryWriteError) as caught:
                    memory_write._validate_write_temporal_gate(
                        proposal_text=sensitive_without_fact,
                        knowledge_kind=caller_kind,
                        evidence_ref="live-evidence",
                        operation="content_update",
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "ACTION_SENSITIVE_FACT_REQUIRED",
                )

        for unscoped_track in ("user", "agent"):
            sensitive_unscoped = sensitive_without_fact.replace(
                "memory_type: project\ntrack: project",
                f"memory_type: {unscoped_track}\ntrack: {unscoped_track}",
            )
            with self.subTest(track=unscoped_track), self.assertRaises(
                memory_write.MemoryWriteError
            ) as caught:
                memory_write._validate_write_temporal_gate(
                    proposal_text=sensitive_unscoped,
                    knowledge_kind="preference",
                    evidence_ref="live-evidence",
                    operation="content_update",
                )
            self.assertEqual(
                caught.exception.reason_code,
                "ACTION_SENSITIVE_FACT_REQUIRED",
            )

        atomic = ordinary.replace(
            "risk_class: ordinary",
            "risk_class: action_sensitive",
        ).replace(
            "review_after_days: 90\n",
            "review_after_days: 90\nfact_key: project.owner\n"
            "valid_from: 2026-08-01\nvalid_until: \"\"\nverified_at: 2026-08-24\n",
        )
        memory_write._validate_write_temporal_gate(
            proposal_text=atomic,
            knowledge_kind="fact",
            evidence_ref="live-evidence",
            operation="content_update",
        )
        for non_fact_kind in ("rule", "preference", "inference"):
            with self.subTest(complete_atomic_kind=non_fact_kind), self.assertRaises(
                memory_write.MemoryWriteError
            ) as caught:
                memory_write._validate_write_temporal_gate(
                    proposal_text=atomic,
                    knowledge_kind=non_fact_kind,
                    evidence_ref="live-evidence",
                    operation="content_update",
                )
            self.assertEqual(
                caught.exception.reason_code,
                "ACTION_SENSITIVE_FACT_REQUIRED",
            )
        with self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write._validate_write_temporal_gate(
                proposal_text=atomic.replace("temporal_policy: reviewable", "temporal_policy: expiring"),
                knowledge_kind="fact",
                evidence_ref="live-evidence",
                operation="content_update",
            )
        self.assertEqual(caught.exception.reason_code, "ACTION_SENSITIVE_FACT_REQUIRED")

        today = dt.date.today()
        expiring = (
            atomic.replace("temporal_policy: reviewable", "temporal_policy: expiring")
            .replace("valid_from: 2026-08-01", f"valid_from: {(today - dt.timedelta(days=2)).isoformat()}")
            .replace("verified_at: 2026-08-24", f"verified_at: {today.isoformat()}")
            .replace('valid_until: ""', f"valid_until: {(today + dt.timedelta(days=1)).isoformat()}")
        )
        memory_write._validate_write_temporal_gate(
            proposal_text=expiring,
            knowledge_kind="fact",
            evidence_ref="live-evidence",
            operation="content_update",
        )
        memory_write._validate_write_temporal_gate(
            proposal_text=expiring.replace(
                (today + dt.timedelta(days=1)).isoformat(),
                today.isoformat(),
            ),
            knowledge_kind="fact",
            evidence_ref="live-evidence",
            operation="content_update",
        )
        with self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write._validate_write_temporal_gate(
                proposal_text=expiring.replace(
                    (today + dt.timedelta(days=1)).isoformat(),
                    (today - dt.timedelta(days=1)).isoformat(),
                ),
                knowledge_kind="fact",
                evidence_ref="live-evidence",
                operation="content_update",
            )
        self.assertEqual(caught.exception.reason_code, "ACTION_SENSITIVE_FACT_REQUIRED")
        with self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write._validate_write_temporal_gate(
                proposal_text=expiring.replace(
                    (today + dt.timedelta(days=1)).isoformat(),
                    "2026-02-30",
                ),
                knowledge_kind="fact",
                evidence_ref="live-evidence",
                operation="content_update",
            )
        self.assertEqual(caught.exception.reason_code, "ACTION_SENSITIVE_FACT_REQUIRED")

    def test_user_and_agent_tracks_cannot_hide_fact_or_temporal_conflicts(self) -> None:
        today = dt.date.today().isoformat()
        for track, memory_type, target in (
            ("user", "user_profile", "用户记忆/Fact.md"),
            ("agent", "agent_note", "agent/Fact.md"),
        ):
            ordinary = (
                f"---\nmemory_type: {memory_type}\ntrack: {track}\nstatus: active\n"
                "risk_class: ordinary\ntemporal_policy: reviewable\n"
                "review_after_days: 90\n---\n# Ordinary\n"
            )
            with self.subTest(track=track, signal="caller-fact"), self.assertRaises(
                memory_write.MemoryWriteError
            ) as caught:
                memory_write._validate_write_temporal_gate(
                    proposal_text=ordinary,
                    knowledge_kind="fact",
                    evidence_ref="live-evidence",
                    operation="content_update",
                    target_relative_path=target,
                )
            self.assertEqual(
                caught.exception.reason_code,
                "PATH_POLICY_DOWNGRADE_FORBIDDEN",
            )

            atomic = (
                f"---\nmemory_type: fact\ntrack: {track}\nstatus: active\n"
                "risk_class: action_sensitive\ntemporal_policy: reviewable\n"
                "review_after_days: 90\nfact_key: cross.track.fact\n"
                f"valid_from: {today}\nverified_at: {today}\n"
                "valid_until: \"\"\n---\n# Atomic fact\n"
            )
            memory_write._validate_write_temporal_gate(
                proposal_text=atomic,
                knowledge_kind="fact",
                evidence_ref="live-evidence",
                operation="content_update",
                target_relative_path=target,
            )
            with self.subTest(track=track, signal="structural-fact"), self.assertRaises(
                memory_write.MemoryWriteError
            ) as caught:
                memory_write._validate_write_temporal_gate(
                    proposal_text=atomic.replace(
                        "temporal_policy: reviewable",
                        "temporal_policy: structural",
                    ),
                    knowledge_kind="fact",
                    evidence_ref="live-evidence",
                    operation="content_update",
                    target_relative_path=target,
                )
            self.assertEqual(
                caught.exception.reason_code,
                "TEMPORAL_METADATA_INVALID",
            )

            structural_with_date = ordinary.replace(
                "temporal_policy: reviewable",
                "temporal_policy: structural",
            ).replace(
                "review_after_days: 90\n",
                f"review_after_days: 90\nverified_at: {today}\n",
            )
            with self.subTest(track=track, signal="structural-date"), self.assertRaises(
                memory_write.MemoryWriteError
            ) as caught:
                memory_write._validate_write_temporal_gate(
                    proposal_text=structural_with_date,
                    knowledge_kind="rule",
                    evidence_ref="",
                    operation="content_update",
                    target_relative_path=target,
                )
            self.assertEqual(
                caught.exception.reason_code,
                "TEMPORAL_METADATA_INVALID",
            )

            with self.subTest(track=track, signal="active-snapshot"), self.assertRaises(
                memory_write.MemoryWriteError
            ) as caught:
                memory_write._validate_write_temporal_gate(
                    proposal_text=ordinary.replace(
                        "temporal_policy: reviewable",
                        "temporal_policy: snapshot",
                    ),
                    knowledge_kind="rule",
                    evidence_ref="",
                    operation="content_update",
                    target_relative_path=target,
                )
            self.assertEqual(
                caught.exception.reason_code,
                "TEMPORAL_METADATA_INVALID",
            )

    def test_any_action_sensitive_valid_until_rejects_past_across_tracks_and_policies(self) -> None:
        today = dt.date.today()
        valid_from = (today - dt.timedelta(days=2)).isoformat()
        future = (today + dt.timedelta(days=1)).isoformat()
        for track, target in (
            ("project", "项目/事实-expiry.md"),
            ("user", "用户记忆/事实-expiry.md"),
            ("agent", "agent/事实-expiry.md"),
        ):
            for policy in ("stable", "reviewable", "expiring"):
                base = (
                    f"---\nmemory_type: fact\ntrack: {track}\nstatus: active\n"
                    "risk_class: action_sensitive\n"
                    f"temporal_policy: {policy}\nreview_after_days: 90\n"
                    f"fact_key: {track}.expiry\nvalid_from: {valid_from}\n"
                    f"verified_at: {today.isoformat()}\nvalid_until: {future}\n"
                    "---\n# Expiring fact\n"
                )
                for label, valid_until in (
                    ("future", future),
                    ("today", today.isoformat()),
                ):
                    with self.subTest(
                        track=track,
                        policy=policy,
                        boundary=label,
                    ):
                        memory_write._validate_write_temporal_gate(
                            proposal_text=base.replace(
                                f"valid_until: {future}",
                                f"valid_until: {valid_until}",
                            ),
                            knowledge_kind="fact",
                            evidence_ref="live-evidence",
                            operation="content_update",
                            target_relative_path=target,
                        )
                with self.subTest(
                    track=track,
                    policy=policy,
                    boundary="past",
                ), self.assertRaises(memory_write.MemoryWriteError) as caught:
                    memory_write._validate_write_temporal_gate(
                        proposal_text=base.replace(
                            f"valid_until: {future}",
                            "valid_until: "
                            f"{(today - dt.timedelta(days=1)).isoformat()}",
                        ),
                        knowledge_kind="fact",
                        evidence_ref="live-evidence",
                        operation="content_update",
                        target_relative_path=target,
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "ACTION_SENSITIVE_FACT_REQUIRED",
                )

    def test_action_sensitive_review_boundary_matches_doctor_across_tracks_and_policies(self) -> None:
        today = dt.date.today()
        review_days = 30
        due_today = (today - dt.timedelta(days=review_days)).isoformat()
        overdue = (today - dt.timedelta(days=review_days + 1)).isoformat()
        valid_from = (today - dt.timedelta(days=review_days + 10)).isoformat()
        valid_until = (today + dt.timedelta(days=10)).isoformat()
        for track, target in (
            ("project", "项目/事实-review.md"),
            ("user", "用户记忆/事实-review.md"),
            ("agent", "agent/事实-review.md"),
        ):
            for policy in ("stable", "reviewable", "expiring"):
                base = (
                    f"---\nmemory_type: fact\ntrack: {track}\nstatus: active\n"
                    "risk_class: action_sensitive\n"
                    f"temporal_policy: {policy}\nreview_after_days: {review_days}\n"
                    f"fact_key: {track}.review\nvalid_from: {valid_from}\n"
                    f"verified_at: {due_today}\nvalid_until: {valid_until}\n"
                    "---\n# Review-bound fact\n"
                )
                with self.subTest(
                    track=track,
                    policy=policy,
                    boundary="due-today",
                ):
                    memory_write._validate_write_temporal_gate(
                        proposal_text=base,
                        knowledge_kind="fact",
                        evidence_ref="live-evidence",
                        operation="content_update",
                        target_relative_path=target,
                    )
                with self.subTest(
                    track=track,
                    policy=policy,
                    boundary="overdue",
                ), self.assertRaises(memory_write.MemoryWriteError) as caught:
                    memory_write._validate_write_temporal_gate(
                        proposal_text=base.replace(
                            f"verified_at: {due_today}",
                            f"verified_at: {overdue}",
                        ),
                        knowledge_kind="fact",
                        evidence_ref="live-evidence",
                        operation="content_update",
                        target_relative_path=target,
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "ACTION_SENSITIVE_FACT_REQUIRED",
                )

    def test_root_governance_content_remains_writable_through_gateway(self) -> None:
        memory_write._validate_write_temporal_gate(
            proposal_text="# Agent Memory governance\n\nUpdated rule.\n",
            knowledge_kind="rule",
            evidence_ref="user-approved-plan",
            operation="content_update",
            governance_target=True,
        )

    def test_canonical_path_floor_rejects_frontmatter_downgrade_but_allows_real_structural_rule(self) -> None:
        masquerade = (
            "---\nmemory_type: governance\ntrack: misc\nstatus: active\n"
            "risk_class: ordinary\ntemporal_policy: structural\n"
            "review_after_days: 180\n---\n# Pretend governance\n"
        )
        for target in ("项目/x.md", "工作流/x.md", "决策/x.md"):
            with self.subTest(target=target), self.assertRaises(
                memory_write.MemoryWriteError
            ) as caught:
                memory_write._validate_write_temporal_gate(
                    proposal_text=masquerade,
                    knowledge_kind="rule",
                    evidence_ref="",
                    operation="content_update",
                    target_relative_path=target,
                )
            self.assertEqual(
                caught.exception.reason_code,
                "PATH_POLICY_DOWNGRADE_FORBIDDEN",
            )

        structural_rule = masquerade.replace(
            "memory_type: governance\ntrack: misc",
            "memory_type: workflow\ntrack: workflow",
        )
        memory_write._validate_write_temporal_gate(
            proposal_text=structural_rule,
            knowledge_kind="rule",
            evidence_ref="",
            operation="content_update",
            target_relative_path="工作流/字段规范.md",
        )
        with self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write._validate_write_temporal_gate(
                proposal_text=structural_rule.replace(
                    "review_after_days: 180\n",
                    "review_after_days: 180\nfact_key: workflow.owner\n"
                    "valid_from: 2026-08-01\nverified_at: 2026-08-24\n",
                ),
                knowledge_kind="rule",
                evidence_ref="live-evidence",
                operation="content_update",
                target_relative_path="工作流/字段规范.md",
            )
        self.assertEqual(
            caught.exception.reason_code,
            "PATH_POLICY_DOWNGRADE_FORBIDDEN",
        )

    def test_apply_replays_temporal_gate_from_intent_bound_metadata(self) -> None:
        proposal = (
            f"---\nmemory_id: {MEMORY_ID}\nmemory_type: project\ntrack: project\n"
            "status: active\nagent_scope: shared\napp_id: agent-memory\n"
            "project_id: alpha\nrisk_class: ordinary\ntemporal_policy: structural\n"
            "review_after_days: 90\n---\n# Ordinary-looking rule\n"
        )
        digest = memory_write.write_intent.content_hashes(proposal.encode("utf-8"))
        target = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/Alpha.md"),
            rel_path="项目/Alpha.md",
            target_key="d" * 64,
        )
        stored = {
            "intent_id": "b" * 32,
            "fencing_token": 9,
            "reconcile_action": "UPDATE",
            "operation": "content_update",
            "status": "pending",
            "target_key": target.target_key,
            "target_rel_path": target.rel_path,
            "proposal_raw_sha256": digest.raw_sha256,
            "proposal_canonical_sha256": digest.canonical_sha256,
            # This is the immutable prepare-time classification. Apply has no
            # request field that may replace it with a lower-risk label.
            "knowledge_kind": "fact",
            "evidence_ref_sha256": "e" * 64,
        }
        request = {
            "schema_version": 2,
            "proposal_id": "b" * 32,
            "fencing_token": 9,
            "target_relative_path": target.rel_path,
            "proposal_markdown": proposal,
            "proposal_raw_sha256": digest.raw_sha256,
            "proposal_canonical_sha256": digest.canonical_sha256,
            "confirmed_by": "user",
            "confirmation_reference": "task:confirmed",
        }
        with mock.patch.object(
            memory_write, "_authorized_intent", return_value=stored
        ), mock.patch.object(
            memory_write, "_formal_target", return_value=target
        ), mock.patch.object(
            memory_write, "_intent_scope_binding", return_value=("agent-memory", "alpha")
        ), mock.patch.object(
            memory_write, "_validate_writer_markdown", return_value={}
        ), self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write._apply_locked(request, raw_session_id="session-1")
        self.assertEqual(
            caught.exception.reason_code,
            "PATH_POLICY_DOWNGRADE_FORBIDDEN",
        )

    def test_governance_migration_adds_only_deterministic_memory_id_and_policy(self) -> None:
        rel_path = "项目/Alpha.md"
        expected = memory_index.memory_identity(rel_path, {})[0]
        base = (
            "---\nstatus: active\nagent_scope: shared\napp_id: agent-memory\n"
            "project_id: alpha\n---\n# Alpha\n\nBody.\n"
        )
        proposal = memory_write._governance_v4_proposal(
            rel_path=rel_path,
            base_text=base,
        )
        self.assertEqual(
            memory_write._validate_governance_migration(
                rel_path=rel_path,
                base_text=base,
                proposal_text=proposal,
            ),
            expected,
        )
        with self.assertRaises(memory_write.MemoryWriteError):
            memory_write._validate_governance_migration(
                rel_path=rel_path,
                base_text=base,
                proposal_text=proposal.replace("Body.", "Changed."),
            )
        with self.assertRaises(memory_write.MemoryWriteError):
            memory_write._validate_governance_migration(
                rel_path=rel_path,
                base_text=base,
                proposal_text=proposal.replace(
                    "status: active\nagent_scope: shared\n",
                    "agent_scope: shared\nstatus: active\n",
                ),
            )

    def test_governance_migration_preserves_crlf_bytes(self) -> None:
        rel_path = "项目/Windows.md"
        base = (
            "---\r\nstatus: active\r\nagent_scope: shared\r\n"
            "app_id: agent-memory\r\nproject_id: windows\r\n---\r\n"
            "# Windows\r\n\r\nBody.\r\n"
        )
        proposal = memory_write._governance_v4_proposal(
            rel_path=rel_path,
            base_text=base,
        )
        self.assertNotIn("\n", proposal.replace("\r\n", ""))
        self.assertEqual(
            memory_write._validate_governance_migration(
                rel_path=rel_path,
                base_text=base,
                proposal_text=proposal,
            ),
            memory_index.memory_identity(rel_path, {})[0],
        )

    def test_governance_migration_can_fill_policy_for_existing_identity_only(self) -> None:
        rel_path = "工作流/Closeout.md"
        existing_id = "b" * 64
        base = (
            f"---\nmemory_id: {existing_id}\nstatus: active\nagent_scope: shared\n"
            "app_id: agent-memory\nproject_id: closeout\nrisk_class: ordinary\n"
            "---\n# Closeout\n\nBody. 2026-08-24 is provenance only.\n"
        )
        proposal = memory_write._governance_v4_proposal(
            rel_path=rel_path,
            base_text=base,
        )
        self.assertIn(f"memory_id: {existing_id}\n", proposal)
        self.assertIn("temporal_policy: reviewable\n", proposal)
        self.assertIn("review_after_days: 180\n", proposal)
        self.assertNotIn("verified_at:", proposal)
        self.assertEqual(
            memory_write._validate_governance_migration(
                rel_path=rel_path,
                base_text=base,
                proposal_text=proposal,
            ),
            existing_id,
        )
        with self.assertRaises(memory_write.MemoryWriteError):
            memory_write._validate_governance_migration(
                rel_path=rel_path,
                base_text=base,
                proposal_text=proposal.replace(
                    "risk_class: ordinary", "risk_class: action_sensitive"
                ),
            )

    def test_superseded_fact_governance_prepare_persists_and_apply_recovers_from_intent(self) -> None:
        """Exercise the historical-fact exception through the durable gateway.

        The first apply is interrupted after the exact proposal bytes reach the
        target.  Its retry must recover from the persisted bound intent and
        consumed confirmation capability, without preparing a second intent or
        weakening ordinary ``content_update`` temporal validation.
        """

        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            vault = root / "vault"
            config_root = root / "runtime"
            state_db = config_root / "state.sqlite"
            target_path = vault / "项目" / "owner-v1.md"
            successor_path = vault / "项目" / "owner-v2.md"
            target_path.parent.mkdir(parents=True)
            config_root.mkdir(parents=True)
            base = (
                "---\n"
                "memory_type: project\n"
                "track: project\n"
                "app_id: agent-memory\n"
                "project_id: project-a\n"
                "user_id: demo-user\n"
                "agent_scope: shared\n"
                "status: active\n"
                "fact_key: project.owner\n"
                "valid_from: 2026-07-01\n"
                "verified_at: 2026-07-02\n"
                "---\n\n"
                "# Owner v1\n\n## 当前有效摘要\n\nAlice\n"
            )
            successor = (
                "---\n"
                "memory_type: project\n"
                "track: project\n"
                "app_id: agent-memory\n"
                "project_id: project-a\n"
                "user_id: demo-user\n"
                "agent_scope: shared\n"
                "status: active\n"
                "fact_key: project.owner\n"
                "valid_from: 2026-08-01\n"
                "verified_at: 2026-08-02\n"
                "supersedes: [项目/owner-v1.md]\n"
                "temporal_policy: reviewable\n"
                "review_after_days: 180\n"
                "---\n\n"
                "# Owner v2\n\n## 当前有效摘要\n\nBob\n"
            )
            target_path.write_text(base, encoding="utf-8")
            successor_path.write_text(successor, encoding="utf-8")
            initialize_full_state(state_db)

            raw_session_id = "governance-historical-session"
            raw_task_id = raw_session_id
            git_head = "f" * 40
            target = memory_write.write_intent.CanonicalTarget(
                path=target_path,
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )

            with contextlib.ExitStack() as stack:
                for owner, name, value in (
                    (memory_write, "ACTOR", "codex"),
                    (memory_write, "CONFIG_ROOT", config_root),
                    (memory_write.write_intent, "VAULT_ROOT", vault),
                    (memory_write.write_intent, "GIT_ROOT", root),
                    (memory_write.write_intent, "STATE_DB", state_db),
                    (memory_index, "VAULT_ROOT", vault),
                    (memory_claim, "VAULT_ROOT", vault),
                    (memory_claim, "STATE_DB", state_db),
                ):
                    stack.enter_context(mock.patch.object(owner, name, value))
                stack.enter_context(
                    mock.patch.object(
                        memory_write.write_intent,
                        "assert_runtime_ready",
                        return_value={"ready": True},
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        memory_claim,
                        "assert_runtime_ready",
                        return_value={"ready": True},
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        memory_write.write_intent,
                        "current_git_head",
                        return_value=git_head,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        memory_write.write_intent,
                        "_git_blob",
                        return_value=base.encode("utf-8"),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        memory_write.write_intent,
                        "_git_path_matches_worktree",
                        return_value=True,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        memory_write.write_intent,
                        "git_version_chain",
                        return_value={"ok": True, "reason_code": "", "versions": []},
                    )
                )
                stack.enter_context(
                    mock.patch.object(memory_write, "_formal_target", return_value=target)
                )
                stack.enter_context(
                    mock.patch.object(
                        memory_write.memory_closeout,
                        "search_memory",
                        return_value=([], [], {"sqlite": {"status": "ok"}}),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        memory_write.memory_closeout,
                        "prewrite_recommendation",
                        return_value=("NOOP", None, {}),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        memory_write.memory_observability,
                        "current_raw_task_id",
                        return_value=raw_task_id,
                    )
                )

                proposal = memory_write._governance_v4_proposal(
                    rel_path=target.rel_path,
                    base_text=base,
                )
                read = memory_write.read_target(
                    {
                        "target_relative_path": target.rel_path,
                        "app_id": "agent-memory",
                        "project_id": "project-a",
                        "operation": "governance_migration",
                    },
                    raw_session_id=raw_session_id,
                )
                common_prepare = {
                    "schema_version": 2,
                    "target_relative_path": target.rel_path,
                    "proposal_markdown": proposal,
                    "read_token": read["read_token"],
                    "app_id": "agent-memory",
                    "project_id": "project-a",
                    "summary": "Add deterministic governance metadata to a superseded fact.",
                    "source_class": "user_direct",
                    "knowledge_kind": "fact",
                    "asserted_by": "user",
                    "evidence_ref": "task:historical-governance-regression",
                }

                with self.assertRaises(memory_write.MemoryWriteError) as ordinary:
                    memory_write._validate_temporal_transition(
                        selected_target=target,
                        base_text=base,
                        proposal_text=proposal,
                        operation="content_update",
                    )
                self.assertEqual(ordinary.exception.reason_code, "TEMPORAL_RELATION_INVALID")
                with self.assertRaises(memory_write.MemoryWriteError):
                    memory_write.prepare(
                        {**common_prepare, "operation": "content_update"},
                        raw_session_id=raw_session_id,
                    )
                with sqlite3.connect(state_db) as connection:
                    self.assertEqual(
                        connection.execute("SELECT COUNT(*) FROM memory_write_intents").fetchone()[0],
                        0,
                    )

                prepared = memory_write.prepare(
                    {**common_prepare, "operation": "governance_migration"},
                    raw_session_id=raw_session_id,
                )
                self.assertEqual(prepared["status"], "prepared")
                self.assertTrue(prepared["confirmation_capability_required"])
                shown = memory_write.write_intent.show_intent(prepared["proposal_id"])
                self.assertEqual(shown["intent"]["operation"], "governance_migration")
                self.assertEqual(shown["intent"]["status"], "pending")
                self.assertEqual(shown["intent"]["target_rel_path"], target.rel_path)

                issued = confirmation_capability.issue_confirmation_capability(
                    config_root,
                    issuer_actor="human",
                    subject_actor="codex",
                    raw_task_id=raw_task_id,
                    raw_session_id=raw_session_id,
                    proposal_id=prepared["proposal_id"],
                    proposal_raw_sha256=prepared["proposal_raw_sha256"],
                    proposal_canonical_sha256=prepared["proposal_canonical_sha256"],
                    target_relative_path=target.rel_path,
                    target_key=target.target_key,
                    operation="governance_migration",
                    reconcile_action="UPDATE",
                    fencing_token=prepared["fencing_token"],
                    confirmation_reference="task:historical-governance-regression",
                )
                apply_request = {
                    "schema_version": 2,
                    "proposal_id": prepared["proposal_id"],
                    "fencing_token": prepared["fencing_token"],
                    "target_relative_path": target.rel_path,
                    "proposal_markdown": proposal,
                    "proposal_raw_sha256": prepared["proposal_raw_sha256"],
                    "proposal_canonical_sha256": prepared["proposal_canonical_sha256"],
                    "confirmation_capability_path": issued["path"],
                    "confirmation_capability_token": issued["token"],
                }

                atomic_write = memory_write._atomic_conditional_write

                def write_then_interrupt(*args: object, **kwargs: object) -> None:
                    atomic_write(*args, **kwargs)
                    raise memory_write.MemoryWriteError(
                        "TEST_INTERRUPTED_AFTER_WRITE",
                        "simulated process interruption after the durable target write",
                        retryable=True,
                    )

                with mock.patch.object(
                    memory_write,
                    "_atomic_conditional_write",
                    side_effect=write_then_interrupt,
                ) as interrupted_write, self.assertRaises(
                    memory_write.MemoryWriteError
                ) as interrupted:
                    memory_write._apply_locked(
                        apply_request,
                        raw_session_id=raw_session_id,
                    )
                self.assertEqual(
                    interrupted.exception.reason_code,
                    "TEST_INTERRUPTED_AFTER_WRITE",
                )
                self.assertEqual(interrupted_write.call_count, 1)
                self.assertEqual(target_path.read_text(encoding="utf-8"), proposal)
                after_interrupt = memory_write.write_intent.show_intent(prepared["proposal_id"])
                self.assertEqual(after_interrupt["intent"]["status"], "bound")
                self.assertTrue(
                    memory_write.write_intent.has_valid_confirmation_capability_approval(
                        after_interrupt["intent"]
                    )
                )

                recovered = memory_write._apply_locked(
                    apply_request,
                    raw_session_id=raw_session_id,
                )
                self.assertTrue(recovered["closeout_required"])
                self.assertTrue(recovered["proposal_already_written"])
                final = memory_write.write_intent.show_intent(prepared["proposal_id"])
                self.assertEqual(final["intent"]["status"], "validated")
                capability_journal = json.loads(
                    Path(str(issued["path"])).read_text(encoding="utf-8")
                )
                self.assertEqual(capability_journal["status"], "consumed")

    def test_governance_supporting_document_exception_is_narrow(self) -> None:
        readme = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/vault/agent/README.md"),
            rel_path="agent/README.md",
            target_key="a" * 64,
        )
        template = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/vault/工作流/_模板流程.md"),
            rel_path="工作流/_模板流程.md",
            target_key="b" * 64,
        )
        archived = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/vault/agent/archive/README.md"),
            rel_path="agent/archive/README.md",
            target_key="c" * 64,
        )
        archived_body = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/vault/agent/archive/old.md"),
            rel_path="agent/archive/old.md",
            target_key="1" * 64,
        )
        ordinary = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/vault/项目/Alpha.md"),
            rel_path="项目/Alpha.md",
            target_key="d" * 64,
        )
        previous_actor = memory_write.ACTOR
        try:
            for actor in ("codex", "claude"):
                memory_write.ACTOR = actor
                with self.subTest(actor=actor):
                    self.assertTrue(
                        memory_write._allow_supporting_document(
                            readme,
                            operation="governance_migration",
                        )
                    )
            for actor, operation, target in (
                ("ailu", "governance_migration", readme),
                ("codex", "content_update", readme),
                ("codex", "status_transition", readme),
                ("codex", "governance_migration", template),
                ("codex", "governance_migration", archived),
                ("codex", "governance_migration", archived_body),
                ("codex", "governance_migration", ordinary),
            ):
                memory_write.ACTOR = actor
                with self.subTest(actor=actor, operation=operation, target=target.rel_path):
                    self.assertFalse(
                        memory_write._allow_supporting_document(
                            target,
                            operation=operation,
                        )
                    )
        finally:
            memory_write.ACTOR = previous_actor

    def test_formal_target_globally_rejects_archive_and_template_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw).resolve()
            for relative in (
                Path("agent/archive"),
                Path("工作流"),
                Path("项目"),
            ):
                (vault / relative).mkdir(parents=True, exist_ok=True)
            with mock.patch.object(memory_write.write_intent, "VAULT_ROOT", vault):
                for relative in (
                    "agent/archive/old.md",
                    "工作流/_模板-流程.md",
                    "工作流/_模板流程.md",
                ):
                    with self.subTest(relative=relative), self.assertRaises(
                        memory_write.MemoryWriteError
                    ) as blocked:
                        memory_write._formal_target(relative)
                    self.assertEqual(blocked.exception.reason_code, "TARGET_NOT_FORMAL_MEMORY")
                allowed = memory_write._formal_target("项目/Alpha.md")
                self.assertEqual(allowed.rel_path, "项目/Alpha.md")

    def test_governance_migration_rejects_non_readme_archive_at_every_entry(self) -> None:
        target = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/vault/agent/archive/old.md"),
            rel_path="agent/archive/old.md",
            target_key="1" * 64,
        )
        base = (
            "---\nstatus: archived\nagent_scope: shared\napp_id: agent-memory\n"
            "project_id: archive\n---\n# Old\n"
        )
        proposal = memory_write._governance_v4_proposal(
            rel_path=target.rel_path,
            base_text=base,
        )
        digest = memory_write.write_intent.content_hashes(proposal.encode("utf-8"))
        read_request = {
            "target_relative_path": target.rel_path,
            "app_id": "agent-memory",
            "project_id": "archive",
            "operation": "governance_migration",
        }
        with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
            memory_write, "_formal_target", return_value=target
        ):
            with self.assertRaises(memory_write.MemoryWriteError) as read_blocked:
                memory_write.read_target(read_request, raw_session_id="session-1")
            self.assertEqual(
                read_blocked.exception.reason_code,
                "GOVERNANCE_MIGRATION_TARGET_INVALID",
            )
            with self.assertRaises(memory_write.MemoryWriteError) as prepare_blocked:
                memory_write.prepare(
                    {
                        **read_request,
                        "proposal_markdown": proposal,
                    },
                    raw_session_id="session-1",
                )
            self.assertEqual(
                prepare_blocked.exception.reason_code,
                "GOVERNANCE_MIGRATION_TARGET_INVALID",
            )

            stored = {
                "intent_id": "b" * 32,
                "fencing_token": 9,
                "reconcile_action": "UPDATE",
                "operation": "governance_migration",
                "status": "bound",
                "target_key": target.target_key,
                "proposal_raw_sha256": digest.raw_sha256,
                "proposal_canonical_sha256": digest.canonical_sha256,
            }
            with mock.patch.object(
                memory_write, "_authorized_intent", return_value=stored
            ), self.assertRaises(memory_write.MemoryWriteError) as apply_blocked:
                memory_write._apply_locked(
                    {
                        "proposal_id": "b" * 32,
                        "fencing_token": 9,
                        "target_relative_path": target.rel_path,
                        "proposal_markdown": proposal,
                        "proposal_raw_sha256": digest.raw_sha256,
                        "proposal_canonical_sha256": digest.canonical_sha256,
                    },
                    raw_session_id="session-1",
                )
            self.assertEqual(
                apply_blocked.exception.reason_code,
                "GOVERNANCE_MIGRATION_TARGET_INVALID",
            )
            with self.assertRaises(memory_write.MemoryWriteError) as validator_blocked:
                memory_write._validate_governance_migration(
                    rel_path=target.rel_path,
                    base_text=base,
                    proposal_text=proposal,
                )
            self.assertEqual(
                validator_blocked.exception.reason_code,
                "GOVERNANCE_MIGRATION_TARGET_INVALID",
            )

    def test_candidate_status_is_accepted_only_by_governance_migration(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw).resolve()
            target = vault / "agent" / "case-candidates" / "ready.md"
            target.parent.mkdir(parents=True)
            proposal = (
                f"---\nmemory_id: {'a' * 64}\nstatus: candidate\n"
                "agent_scope: shared\napp_id: agent-memory\nproject_id: agent-cases\n"
                "temporal_policy: reviewable\nreview_after_days: 30\n---\n# Candidate\n"
            )
            target.write_text(proposal, encoding="utf-8")
            canonical = memory_write.write_intent.CanonicalTarget(
                path=target,
                rel_path="agent/case-candidates/ready.md",
                target_key="f" * 64,
            )
            with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
                memory_write.write_intent, "VAULT_ROOT", vault
            ), mock.patch.object(memory_index, "VAULT_ROOT", vault):
                with self.assertRaises(memory_write.MemoryWriteError) as ordinary:
                    memory_write._validate_writer_markdown(
                        proposal,
                        path=target,
                        app_id="agent-memory",
                        project_id="agent-cases",
                        require_explicit_write_scope=True,
                    )
                self.assertEqual(ordinary.exception.reason_code, "STATUS_NOT_ACTIVE")
                metadata = memory_write._validate_writer_markdown(
                    proposal,
                    path=target,
                    app_id="agent-memory",
                    project_id="agent-cases",
                    require_explicit_write_scope=True,
                    allowed_statuses=memory_index.GOVERNANCE_MIGRATION_STATUSES,
                )
                with mock.patch.object(
                    memory_write, "_formal_target", return_value=canonical
                ), mock.patch.object(
                    memory_write.write_intent,
                    "current_git_head",
                    return_value="f" * 40,
                ):
                    read = memory_write.read_target(
                        {
                            "target_relative_path": canonical.rel_path,
                            "app_id": "agent-memory",
                            "project_id": "agent-cases",
                            "operation": "governance_migration",
                        },
                        raw_session_id="session-1",
                    )
                    self.assertEqual(read["status"], "found")
                    with self.assertRaises(memory_write.MemoryWriteError) as normal_read:
                        memory_write.read_target(
                            {
                                "target_relative_path": canonical.rel_path,
                                "app_id": "agent-memory",
                                "project_id": "agent-cases",
                            },
                            raw_session_id="session-1",
                        )
                    self.assertEqual(normal_read.exception.reason_code, "STATUS_NOT_ACTIVE")
            with mock.patch.object(memory_write, "ACTOR", "ailu"), mock.patch.object(
                memory_write, "_formal_target", return_value=canonical
            ), self.assertRaises(memory_write.MemoryWriteError) as ailu_read:
                memory_write.read_target(
                    {
                        "target_relative_path": canonical.rel_path,
                        "app_id": "agent-memory",
                        "project_id": "agent-cases",
                        "operation": "governance_migration",
                    },
                    raw_session_id="session-1",
                )
            self.assertEqual(ailu_read.exception.reason_code, "STATUS_TRANSITION_FORBIDDEN")
        self.assertEqual(metadata["status"], "candidate")

    def test_governance_supporting_read_and_prepare_use_the_same_exception(self) -> None:
        base = (
            "---\nstatus: active\nagent_scope: shared\napp_id: agent-memory\n"
            "project_id: agent-memory\n---\n# Agent memory\n"
        )
        proposal = memory_write._governance_v4_proposal(
            rel_path="agent/README.md",
            base_text=base,
        )
        base_digest = memory_write.write_intent.content_hashes(base.encode("utf-8"))
        target = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/vault/agent/README.md"),
            rel_path="agent/README.md",
            target_key="e" * 64,
        )
        read_request = {
            "target_relative_path": target.rel_path,
            "app_id": "agent-memory",
            "project_id": "agent-memory",
            "operation": "governance_migration",
        }
        with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
            memory_write, "_formal_target", return_value=target
        ), mock.patch.object(
            memory_write,
            "_target_snapshot",
            return_value=(True, base_digest, "f" * 40, "1" * 64),
        ) as snapshot:
            memory_write.read_target(read_request, raw_session_id="session-1")
        self.assertTrue(snapshot.call_args.kwargs["allow_supporting_document"])

        prepare_request = {
            **read_request,
            "proposal_markdown": proposal,
            "read_token": "1" * 64,
            "summary": "Add deterministic governance metadata to directory index.",
            "source_class": "local_verified",
            "knowledge_kind": "rule",
            "asserted_by": "codex",
        }
        validator = mock.Mock(return_value={})
        with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
            memory_write, "_formal_target", return_value=target
        ), mock.patch.object(
            memory_write, "_scope_request", return_value=("agent-memory", "agent-memory")
        ), mock.patch.object(
            memory_write, "_validate_writer_markdown", validator
        ), mock.patch.object(
            memory_write,
            "_target_snapshot",
            return_value=(True, base_digest, "f" * 40, "1" * 64),
        ) as prepare_snapshot, mock.patch.object(
            memory_write, "_validate_governance_migration"
        ), mock.patch.object(
            memory_write, "_validate_write_temporal_gate"
        ), mock.patch.object(
            memory_write,
            "_validate_temporal_transition",
            side_effect=memory_write.MemoryWriteError("TEST_STOP", "stop"),
        ), self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write.prepare(prepare_request, raw_session_id="session-1")
        self.assertEqual(caught.exception.reason_code, "TEST_STOP")
        self.assertTrue(validator.call_args.kwargs["allow_supporting_document"])
        self.assertTrue(prepare_snapshot.call_args.kwargs["allow_supporting_document"])

    def test_governance_supporting_apply_rechecks_proposal_and_current_content(self) -> None:
        base = (
            "---\nstatus: active\nagent_scope: shared\napp_id: agent-memory\n"
            "project_id: agent-memory\n---\n# Agent memory\n"
        )
        proposal = memory_write._governance_v4_proposal(
            rel_path="agent/README.md",
            base_text=base,
        )
        base_digest = memory_write.write_intent.content_hashes(base.encode("utf-8"))
        proposal_digest = memory_write.write_intent.content_hashes(proposal.encode("utf-8"))
        target = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/vault/agent/README.md"),
            rel_path="agent/README.md",
            target_key="e" * 64,
        )
        stored = {
            "intent_id": "b" * 32,
            "fencing_token": 9,
            "reconcile_action": "UPDATE",
            "operation": "governance_migration",
            "status": "bound",
            "target_key": target.target_key,
            "target_rel_path": target.rel_path,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "base_exists": 1,
            "base_raw_sha256": base_digest.raw_sha256,
            "base_canonical_sha256": base_digest.canonical_sha256,
            "base_git_head": "f" * 40,
            "knowledge_kind": "rule",
            "evidence_ref_sha256": "",
        }
        request = {
            "proposal_id": "b" * 32,
            "fencing_token": 9,
            "target_relative_path": target.rel_path,
            "proposal_markdown": proposal,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
        }
        validator = mock.Mock(
            side_effect=(
                {},
                memory_write.MemoryWriteError("TEST_STOP", "stop after current validation"),
            )
        )
        with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
            memory_write, "_authorized_intent", return_value=stored
        ), mock.patch.object(
            memory_write, "_formal_target", return_value=target
        ), mock.patch.object(
            memory_write, "_intent_scope_binding", return_value=("agent-memory", "agent-memory")
        ), mock.patch.object(
            memory_write, "_validate_writer_markdown", validator
        ), mock.patch.object(
            memory_write, "_validate_write_temporal_gate"
        ), mock.patch.object(
            memory_write, "_has_conditional_recovery_sidecar", return_value=False
        ), mock.patch.object(
            memory_write.write_intent,
            "show_intent",
            return_value={"intent": stored, "receipt": None},
        ), mock.patch.object(
            memory_write.write_intent, "assert_current_lease"
        ), mock.patch.object(
            memory_write.write_intent,
            "has_valid_confirmation_capability_approval",
            return_value=True,
        ), mock.patch.object(
            memory_write, "_claim_matches", return_value=True
        ), mock.patch.object(
            memory_write, "_target_digest", return_value=(True, base_digest)
        ), self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write._apply_locked(request, raw_session_id="session-1")
        self.assertEqual(caught.exception.reason_code, "TEST_STOP")
        self.assertEqual(validator.call_count, 2)
        self.assertTrue(validator.call_args_list[0].kwargs["allow_supporting_document"])
        self.assertTrue(validator.call_args_list[1].kwargs["allow_supporting_document"])

    def test_existing_legacy_read_returns_path_bound_expected_memory_id(self) -> None:
        text = (
            "---\nstatus: active\nagent_scope: shared\napp_id: agent-memory\n"
            "project_id: alpha\n---\n# Alpha\n"
        )
        digest = memory_write.write_intent.content_hashes(text.encode("utf-8"))
        target = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/Alpha.md"),
            rel_path="项目/Alpha.md",
            target_key="c" * 64,
        )
        previous_actor = memory_write.ACTOR
        memory_write.ACTOR = "codex"
        try:
            with mock.patch.object(memory_write, "_formal_target", return_value=target), mock.patch.object(
                memory_write, "_scope_request", return_value=("agent-memory", "alpha")
            ), mock.patch.object(
                memory_write,
                "_target_snapshot",
                return_value=(True, digest, "d" * 40, "e" * 64),
            ):
                result = memory_write.read_target(
                    {
                        "target_relative_path": "项目/Alpha.md",
                        "app_id": "agent-memory",
                        "project_id": "alpha",
                    },
                    raw_session_id="session-1",
                )
        finally:
            memory_write.ACTOR = previous_actor
        self.assertEqual(
            result["expected_memory_id"],
            memory_index.memory_identity("项目/Alpha.md", {})[0],
        )
        self.assertNotIn("generated_memory_id", result)

    def test_risk_followup_requires_review_for_unclassified_ordinary_content(self) -> None:
        ordinary = (
            f"---\nmemory_id: {'d' * 64}\nmemory_type: project\ntrack: project\n"
            "status: active\nagent_scope: shared\napp_id: agent-memory\n"
            "project_id: alpha\ntemporal_policy: reviewable\n"
            "review_after_days: 90\n---\n# Alpha\n\nBody.\n"
        )
        ordinary_recommendation = memory_write._risk_v4_recommendation(
            rel_path="项目/Alpha.md",
            base_text=ordinary,
        )
        self.assertEqual(ordinary_recommendation["operation"], "manual_review")
        self.assertEqual(ordinary_recommendation["recommended"], "")
        with self.assertRaises(memory_write.MemoryWriteError) as caught:
            memory_write._risk_v4_proposal(
                rel_path="项目/Alpha.md",
                base_text=ordinary,
            )
        self.assertEqual(caught.exception.reason_code, "RISK_CLASS_REQUIRED")

        explicit_fact_signal = ordinary.replace(
            "review_after_days: 90\n",
            "review_after_days: 90\nfact_key: project.owner\n",
        )
        signaled = memory_write._risk_v4_recommendation(
            rel_path="项目/Alpha.md",
            base_text=explicit_fact_signal,
        )
        self.assertEqual(signaled["recommended"], "action_sensitive")
        self.assertIn(signaled["operation"], {"content_update", "status_transition"})

        sensitive = ordinary.replace(
            "memory_type: project\ntrack: project",
            "memory_type: decision\ntrack: decision",
        )
        sensitive_recommendation = memory_write._risk_v4_recommendation(
            rel_path="决策/Alpha.md",
            base_text=sensitive,
        )
        self.assertEqual(sensitive_recommendation["operation"], "status_transition")
        quarantined = memory_write._risk_v4_proposal(
            rel_path="决策/Alpha.md",
            base_text=sensitive,
        )
        self.assertIn("status: pending_verification\n", quarantined)
        self.assertIn("risk_class: action_sensitive\n", quarantined)
        with self.assertRaises(memory_write.MemoryWriteError) as completed:
            memory_write._risk_v4_recommendation(
                rel_path="决策/Alpha.md",
                base_text=quarantined,
            )
        self.assertEqual(
            completed.exception.reason_code,
            "GOVERNANCE_MIGRATION_NOT_REQUIRED",
        )

        explicit_downgrade = sensitive.replace(
            "review_after_days: 90\n",
            "review_after_days: 90\nrisk_class: ordinary\n",
        )
        downgrade = memory_write._risk_v4_recommendation(
            rel_path="决策/Alpha.md",
            base_text=explicit_downgrade,
        )
        self.assertEqual(downgrade["operation"], "manual_review")
        self.assertEqual(downgrade["recommended"], "action_sensitive")

    def test_status_and_governance_operations_always_require_user_confirmation(self) -> None:
        self.assertTrue(memory_write._requires_user_confirmation("UPDATE", "status_transition"))
        self.assertTrue(memory_write._requires_user_confirmation("UPDATE", "governance_migration"))
        self.assertTrue(memory_write._requires_user_confirmation("ADOPT", "content_update"))
        self.assertFalse(memory_write._requires_user_confirmation("UPDATE", "content_update"))

    def test_sensitive_apply_cannot_forge_confirmation_in_its_own_json(self) -> None:
        proposal = markdown("pending_verification")
        digest = memory_write.write_intent.content_hashes(proposal.encode("utf-8"))
        request = {
            "schema_version": 2,
            "proposal_id": "b" * 32,
            "fencing_token": 9,
            "target_relative_path": "项目/Alpha.md",
            "proposal_markdown": proposal,
            "proposal_raw_sha256": digest.raw_sha256,
            "proposal_canonical_sha256": digest.canonical_sha256,
            "confirmed_by": "user",
            "confirmation_reference": "self-declared-user-confirmation",
        }
        previous_actor = memory_write.ACTOR
        memory_write.ACTOR = "codex"
        try:
            cases = (
                ("UPDATE", "status_transition"),
                ("UPDATE", "governance_migration"),
                ("ADOPT", "content_update"),
                ("MIGRATE_LEGACY_SCOPE", "content_update"),
            )
            for action, operation in cases:
                with self.subTest(action=action, operation=operation), mock.patch.object(
                    memory_write,
                    "_authorized_intent",
                    return_value={
                        "intent_id": "b" * 32,
                        "fencing_token": 9,
                        "reconcile_action": action,
                        "operation": operation,
                        "status": "pending",
                    },
                ), self.assertRaises(memory_write.MemoryWriteError) as caught:
                    memory_write._apply_locked(request, raw_session_id="session-1")
                self.assertEqual(caught.exception.reason_code, "CONFIRMATION_CAPABILITY_REQUIRED")
        finally:
            memory_write.ACTOR = previous_actor

    def test_low_level_intent_approval_rejects_sensitive_self_declaration(self) -> None:
        write_intent = memory_write.write_intent
        raw_session_id = "session-1"
        stored = {
            "intent_id": "b" * 32,
            "actor": "codex",
            "session_hash": write_intent.session_hash(raw_session_id),
            "status": "pending",
            "target_key": "d" * 64,
            "target_rel_path": "项目/Alpha.md",
            "proposal_raw_sha256": "e" * 64,
            "proposal_canonical_sha256": "f" * 64,
            "reconcile_action": "ADOPT",
            "operation": "content_update",
            "fencing_token": 3,
        }
        connection = mock.MagicMock()
        context = mock.MagicMock()
        context.__enter__.return_value = connection
        context.__exit__.return_value = False
        canonical = write_intent.CanonicalTarget(
            path=Path("/private/Alpha.md"),
            rel_path="项目/Alpha.md",
            target_key="d" * 64,
        )
        with mock.patch.object(write_intent, "connect", return_value=context), mock.patch.object(
            write_intent, "_fetch_intent", return_value=stored
        ), mock.patch.object(write_intent, "canonical_target", return_value=canonical), self.assertRaises(
            write_intent.IntentError
        ) as caught:
            write_intent.approve_intent(
                "b" * 32,
                actor="codex",
                raw_session_id=raw_session_id,
                raw_task_id="task-1",
                target=canonical.path,
                proposal_raw_sha256="e" * 64,
                proposal_canonical_sha256="f" * 64,
                approved_by="user",
                approval_ref="same-request-json",
            )
        self.assertEqual(caught.exception.reason_code, "CONFIRMATION_CAPABILITY_REQUIRED")

    def test_sensitive_apply_consumes_capability_and_derives_system_approval(self) -> None:
        proposal = markdown("pending_verification")
        digest = memory_write.write_intent.content_hashes(proposal.encode("utf-8"))
        raw_session_id = "session-456"
        target = memory_write.write_intent.CanonicalTarget(
            path=Path("/private/Alpha.md"),
            rel_path="项目/Alpha.md",
            target_key="d" * 64,
        )
        stored = {
            "intent_id": "b" * 32,
            "actor": "codex",
            "session_hash": memory_write.write_intent.session_hash(raw_session_id),
            "fencing_token": 9,
            "reconcile_action": "UPDATE",
            "operation": "status_transition",
            "target_status": "pending_verification",
            "status": "pending",
            "target_key": target.target_key,
            "target_rel_path": target.rel_path,
            "proposal_raw_sha256": digest.raw_sha256,
            "proposal_canonical_sha256": digest.canonical_sha256,
        }
        with tempfile.TemporaryDirectory() as raw:
            config_root = Path(raw)
            issued = confirmation_capability.issue_confirmation_capability(
                config_root,
                issuer_actor="human",
                subject_actor="codex",
                raw_task_id="task-123",
                raw_session_id=raw_session_id,
                proposal_id="b" * 32,
                proposal_raw_sha256=digest.raw_sha256,
                proposal_canonical_sha256=digest.canonical_sha256,
                target_relative_path=target.rel_path,
                target_key=target.target_key,
                operation="status_transition",
                reconcile_action="UPDATE",
                fencing_token=9,
                confirmation_reference="manual-review:event-123",
            )
            request = {
                "schema_version": 2,
                "proposal_id": "b" * 32,
                "fencing_token": 9,
                "target_relative_path": target.rel_path,
                "proposal_markdown": proposal,
                "proposal_raw_sha256": digest.raw_sha256,
                "proposal_canonical_sha256": digest.canonical_sha256,
                "confirmation_capability_path": issued["path"],
                "confirmation_capability_token": issued["token"],
            }
            previous_actor = memory_write.ACTOR
            previous_config_root = memory_write.CONFIG_ROOT
            memory_write.ACTOR = "codex"
            memory_write.CONFIG_ROOT = config_root
            approval = mock.Mock(
                side_effect=memory_write.write_intent.IntentError("TEST_STOP", "stop after approval boundary")
            )
            try:
                with mock.patch.object(memory_write, "_authorized_intent", return_value=stored), mock.patch.object(
                    memory_write, "_formal_target", return_value=target
                ), mock.patch.object(
                    memory_write, "_intent_scope_binding", return_value=("agent-memory", "alpha")
                ), mock.patch.object(
                    memory_write, "_validate_writer_markdown", return_value={}
                ), mock.patch.object(
                    memory_write, "_has_conditional_recovery_sidecar", return_value=False
                ), mock.patch.object(
                    memory_write.write_intent, "show_intent", return_value={"intent": stored, "receipt": None}
                ), mock.patch.object(
                    memory_write.write_intent, "assert_current_lease"
                ), mock.patch.object(
                    memory_write.write_intent, "approve_intent", approval
                ), mock.patch.object(
                    memory_write.memory_observability, "current_raw_task_id", return_value="task-123"
                ):
                    # First invocation consumes the capability and then
                    # simulates a crash before the intent approval commits.
                    # The exact retry must recover that consumption instead of
                    # stranding the pending intent.
                    for attempt in ("first", "recovery"):
                        with self.subTest(attempt=attempt), self.assertRaises(
                            memory_write.MemoryWriteError
                        ) as caught:
                            memory_write._apply_locked(
                                request,
                                raw_session_id=raw_session_id,
                            )
                        self.assertEqual(caught.exception.reason_code, "TEST_STOP")
            finally:
                memory_write.ACTOR = previous_actor
                memory_write.CONFIG_ROOT = previous_config_root
            self.assertEqual(approval.call_count, 2)
            approval_kwargs = approval.call_args.kwargs
            self.assertEqual(
                approval_kwargs["approved_by"],
                memory_write.write_intent.HUMAN_CONFIRMATION_CAPABILITY_APPROVER,
            )
            self.assertRegex(
                approval_kwargs["approval_ref"],
                (
                    r"^human-confirmation-capability:[0-9a-f]{32}:"
                    r"confirmation-reference-sha256:[0-9a-f]{64}$"
                ),
            )
            self.assertIsNotNone(approval_kwargs["confirmation_capability"])
            journal = json.loads(Path(str(issued["path"])).read_text(encoding="utf-8"))
            self.assertEqual(journal["status"], "consumed")

    def test_document_date_does_not_become_verification_and_dual_fts_are_populated(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            note = root / "Fact.md"
            note.write_text(
                "---\nstatus: active\ntemporal_policy: stable\n---\n"
                "# Fact\n\nCurrent as of 2026-08-24.\n",
                encoding="utf-8",
            )
            previous_root = memory_index.VAULT_ROOT
            memory_index.VAULT_ROOT = root
            try:
                with contextlib.closing(sqlite3.connect(":memory:")) as conn:
                    conn.row_factory = sqlite3.Row
                    memory_index.init_db(conn)
                    memory_index.scan(conn)
                    row = conn.execute(
                        "SELECT verified_at, verified_at_source, document_date, memory_id FROM memory_docs"
                    ).fetchone()
                    self.assertEqual(row["verified_at"], "")
                    self.assertEqual(row["verified_at_source"], "document_date_unverified")
                    self.assertEqual(row["document_date"], "2026-08-24")
                    self.assertEqual(len(row["memory_id"]), 64)
                    for table in ("memory_fts", "memory_fts_unicode", "memory_fts_trigram"):
                        self.assertEqual(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 1)
            finally:
                memory_index.VAULT_ROOT = previous_root

    def test_audit_reports_path_metadata_and_risk_floor_downgrades(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            target = vault / "工作流" / "masquerade.md"
            target.parent.mkdir()
            target.write_text(
                "---\nmemory_type: governance\ntrack: misc\nstatus: active\n"
                "risk_class: ordinary\ntemporal_policy: structural\n"
                "review_after_days: 180\n---\n# Masquerade\n",
                encoding="utf-8",
            )
            with contextlib.closing(sqlite3.connect(":memory:")) as conn:
                conn.row_factory = sqlite3.Row
                memory_index.init_db(conn)
                with mock.patch.object(memory_index, "VAULT_ROOT", vault):
                    doc, _ = memory_index.load_doc(target, "2026-08-24T00:00:00+00:00")
                memory_index.upsert_doc(conn, doc)
                findings: list[audit.Finding] = []
                with mock.patch.object(audit, "VAULT_ROOT", vault):
                    audit.add_temporal_policy_findings(conn, findings)
            downgrade = [
                item for item in findings if item.kind == "path_policy_downgrade"
            ]
            self.assertEqual(len(downgrade), 1)
            self.assertEqual(
                set(downgrade[0].detail["reason_codes"]),
                {"PATH_TRACK_DOWNGRADE", "PATH_MEMORY_TYPE_DOWNGRADE"},
            )

    def test_audit_decision_hides_only_the_same_occurrence(self) -> None:
        finding = audit.Finding(
            id="stable",
            kind="expired",
            severity="high",
            rel_path="Fact.md",
            title="Fact",
            message="expired",
            detail={"valid_until": "2026-08-01"},
        )
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root) / "audit.sqlite"
            with contextlib.closing(sqlite3.connect(database)) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute(
                    "CREATE TABLE audit_decisions(finding_id TEXT, decision TEXT, "
                    "occurrence_fingerprint TEXT, snooze_until TEXT)"
                )
                conn.execute(
                    "INSERT INTO audit_decisions VALUES(?, 'resolved', ?, '')",
                    (finding.id, finding.occurrence_fingerprint),
                )
                row = conn.execute("SELECT * FROM audit_decisions").fetchone()
                self.assertTrue(audit.decision_hides(row, finding))
                recurrent = audit.Finding(
                    **{**finding.__dict__, "detail": {"valid_until": "2026-09-01"}}
                )
                self.assertFalse(audit.decision_hides(row, recurrent))

    def test_observability_v2_binds_adoption_to_content_version(self) -> None:
        with contextlib.closing(sqlite3.connect(":memory:")) as conn:
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
            observability.ensure_schema(conn)
            event_id = observability._insert_event(
                conn,
                actor="codex",
                task_id="b" * 64,
                event_type="adoption_declared",
                source="agent_declared",
                value="adopted",
                memory_versions=[
                    {
                        "memory_id": MEMORY_ID,
                        "content_sha256": "c" * 64,
                        "policy_state": "expired",
                        "requires_live_verification": True,
                    }
                ],
            )
            row = conn.execute(
                "SELECT content_sha256, requires_live_verification FROM memory_use_events WHERE event_id=?",
                (event_id,),
            ).fetchone()
            self.assertEqual(row["content_sha256"], "c" * 64)
            self.assertEqual(row["requires_live_verification"], 1)

    def test_legacy_search_privacy_migration_runs_after_backup_boundary(self) -> None:
        with contextlib.closing(sqlite3.connect(":memory:")) as conn:
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
            conn.execute(
                "INSERT INTO memory_search_log(query,result_count,used_paths,created_at) "
                "VALUES('raw private query', 1, '项目/Secret.md', '2026-08-24T00:00:00+00:00')"
            )
            result = migrate._redact_legacy_search_rows(conn)
            row = conn.execute(
                "SELECT query, query_sha256, used_paths FROM memory_search_log"
            ).fetchone()
            self.assertEqual(result["query_rows_redacted"], 1)
            self.assertRegex(row["query"], r"^\[redacted:[0-9a-f]{12}\]$")
            self.assertEqual(len(row["query_sha256"]), 64)
            self.assertEqual(row["used_paths"], "")

    def test_shadow_search_fields_are_controlled_and_reported(self) -> None:
        with contextlib.closing(sqlite3.connect(":memory:")) as conn:
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
            observability.ensure_schema(conn)
            observability.record_search(
                conn,
                query="never persist this query",
                rel_paths=["项目/Alpha.md"],
                sources=["sqlite"],
                duration_ms=1,
                search_status="success",
                ranking_mode="shadow",
                v1_result_fingerprint="1" * 64,
                v2_result_fingerprint="2" * 64,
                required_case_regression_count=1,
                worker_status="restarted",
                worker_restart_count=1,
            )
            row = conn.execute("SELECT * FROM memory_search_log").fetchone()
            self.assertEqual(row["query"], "")
            self.assertEqual(row["used_paths"], "")
            self.assertEqual(row["ranking_mode"], "shadow")
            report = observability.build_report(conn, days=7)
            shadow = report["cross_metrics"]["shadow_7d"]
            self.assertEqual(shadow["required_regressions"], 1)
            self.assertEqual(shadow["privacy_violation"], 0)
            self.assertEqual(shadow["worker_restarts"], 1)

    def test_stale_adoption_canary_is_version_bound_and_clearable(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            state = Path(raw_root).resolve() / "state.sqlite"
            with contextlib.closing(sqlite3.connect(state)) as conn:
                conn.row_factory = sqlite3.Row
                memory_index.init_db(conn)
                observability.ensure_schema(conn)
                task_id = observability.task_ref("synthetic-canary", "codex")
                version = {
                    "memory_id": MEMORY_ID,
                    "content_sha256": "d" * 64,
                    "policy_state": "expired",
                    "requires_live_verification": True,
                }
                observability._insert_event(
                    conn,
                    actor="codex",
                    task_id=task_id,
                    event_type="adoption_declared",
                    source="agent_declared",
                    value="adopted",
                    memory_versions=[version],
                )
                conn.commit()
            state.chmod(0o600)
            with (
                mock.patch.object(observability, "STATE_DB", state),
                mock.patch.object(observability, "assert_runtime_ready", return_value={"ready": True}),
            ):
                self.assertEqual(
                    observability.adopted_stale_without_verification(
                        "codex", "synthetic-canary"
                    ),
                    1,
                )
                with observability.connect() as conn:
                    observability._insert_event(
                        conn,
                        actor="codex",
                        task_id=observability.task_ref("synthetic-canary", "codex"),
                        event_type="adoption_declared",
                        source="agent_declared",
                        value="reference_only",
                        memory_versions=[version],
                    )
                self.assertEqual(
                    observability.adopted_stale_without_verification(
                        "codex", "synthetic-canary"
                    ),
                    0,
                )


if __name__ == "__main__":
    unittest.main()
