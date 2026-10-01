from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import io
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_content_migrate as content_migrate
import agent_memory_confirmation_capability as confirmation_capability
import agent_memory_doctor as memory_doctor
import agent_memory_index as memory_index
import agent_memory_intent as intent
import agent_memory_write as write_gateway


def query_item(target: str = "项目/example.md", *, automatable: bool = True) -> dict[str, object]:
    return {
        "target_relative_path": target,
        "issues": {"app_id": "missing"},
        "migrate_action": "MIGRATE_LEGACY_SCOPE",
        "migrate_legacy_scope": True,
        "legacy_scope_app_id": "agent-memory",
        "requested_app_id": "agent-memory",
        "requested_project_id": Path(target).stem.casefold(),
        "automatable": automatable,
        "manual_review_reasons": [] if automatable else ["app_id"],
    }


def doctor(items: list[dict[str, object]], *, unsafe: list[str] | None = None, fail: int = 1) -> dict[str, object]:
    unsafe = unsafe or []
    automatic = sum(item["automatable"] is True for item in items)
    manual = len(items) - automatic + len(unsafe)
    return {
        "status": "error" if fail else "warning",
        "summary": {"pass": 1, "warn": 0, "fail": fail},
        "checks": [{
            "name": "legacy_scope_documents",
            "status": "fail" if items or unsafe else "pass",
            "detail": {
                "policy": "full_vault_explicit_scope_v1",
                "migration_query_schema_version": 1,
                "legacy_scope_documents": len(items) + len(unsafe),
                "automatable_documents": automatic,
                "manual_review_documents": manual,
                "unsafe_documents": unsafe,
                "migration_query": items,
            },
        }],
    }


def safe_risk_record(target: str) -> dict[str, object]:
    return {
        "target_relative_path": target,
        "risk_recommendation": {
            "source_status": "active",
            "current": "action_sensitive",
            "automatable_now": True,
            "automatable_after_governance": True,
            "manual_review_required": False,
            "recommended": "action_sensitive",
            "reason_codes": ["ACTION_SENSITIVE_ATOMIC_GAP"],
            "followup_operation": "status_transition",
            "target_status": "pending_verification",
        },
    }


def temporal_coverage_check(uncovered: list[str]) -> dict[str, object]:
    return {
        "name": "temporal_fact_coverage",
        "status": "fail",
        "message": (
            f"{len(uncovered)} active action-sensitive document(s) lack "
            "a complete atomic fact tuple or durable evidence provenance."
        ),
        "detail": {
            "action_sensitive_documents": sorted(uncovered),
            "uncovered": sorted(uncovered),
            "gap_details": [
                {
                    "rel_path": target,
                    "missing_or_invalid": ["evidence_provenance"],
                    "evidence_provenance": {
                        "present": False,
                        "source": "write_gateway_v2_receipt",
                        "reason_code": "CURRENT_CONTENT_EVIDENCE_RECEIPT_MISSING",
                        "current_content_bound": False,
                        "checked_receipts": 1,
                    },
                }
                for target in sorted(uncovered)
            ],
            "structural_and_routing_excluded": True,
            "coverage_is_per_document": True,
            "coverage_requires": [
                "non_structural_temporal_policy",
                "fact_key",
                "valid_from",
                "frontmatter_verified_at",
                "current_content_write_gateway_evidence",
            ],
            "fact_records": len(uncovered),
            "migration_is_explicit_only": True,
        },
    }


def governance_doctor_with_temporal_failure(
    uncovered: list[str],
) -> dict[str, object]:
    return {
        "status": "error",
        "summary": {"pass": 1, "warn": 1, "fail": 1},
        "checks": [
            {
                "name": "governance_metadata_v4",
                "status": "warn",
                "message": "Governance migration remains.",
                "detail": {},
            },
            temporal_coverage_check(uncovered),
        ],
    }


def governance_doctor_with_missing_fact_key(
    target: str,
) -> dict[str, object]:
    payload = governance_doctor_with_temporal_failure([target])
    detail = payload["checks"][1]["detail"]
    detail["fact_records"] = 0
    detail["gap_details"][0]["missing_or_invalid"] = ["fact_key"]
    detail["gap_details"][0]["evidence_provenance"] = {
        "present": True,
        "source": "write_gateway_v2_receipt",
        "reason_code": "",
        "current_content_bound": True,
        "checked_receipts": 1,
    }
    return payload


def review_for(items: list[dict[str, object]]) -> dict[str, object]:
    query_doc = doctor(items)
    binding = content_migrate.normalize_doctor_query(query_doc, require_all_automatable=True)
    review_items = []
    for item in binding["migration_query"]:
        review_items.append({
            "target_relative_path": item["target_relative_path"],
            "requested_app_id": item["requested_app_id"],
            "requested_project_id": item["requested_project_id"],
            "legacy_scope_app_id": item["legacy_scope_app_id"],
            "read_token": "1" * 64,
            "base_raw_sha256": "2" * 64,
            "base_canonical_sha256": "3" * 64,
            "base_git_head": "4" * 40,
            "proposal_raw_sha256": "5" * 64,
            "proposal_canonical_sha256": "6" * 64,
            "proposal_size_bytes": 100,
        })
    return {
        "schema_version": 1,
        "kind": content_migrate.REVIEW_KIND,
        "created_at": "2026-08-12T00:00:00+00:00",
        "actor": "codex",
        "initial_git_head": "4" * 40,
        "doctor_binding": binding,
        "items": review_items,
        "review_status": "pending_user_confirmation",
    }


def progress_header() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": content_migrate.PROGRESS_KIND,
        "event": "header",
        "review_sha256": "7" * 64,
        "actor": "codex",
        "created_at": "2026-08-12T00:00:00+00:00",
    }


def prepared_event(target: str = "项目/example.md", *, head: str = "4" * 40) -> dict[str, object]:
    return {
        "schema_version": 1,
        "event": "prepared",
        "time": "2026-08-12T00:00:01+00:00",
        "target_relative_path": target,
        "proposal_id": "a" * 32,
        "fencing_token": 7,
        "base_git_head": head,
    }


def completed_event(target: str = "项目/example.md", *, commit: str = "8" * 40) -> dict[str, object]:
    return {
        "schema_version": 1,
        "event": "completed",
        "time": "2026-08-12T00:00:02+00:00",
        "target_relative_path": target,
        "proposal_id": "a" * 32,
        "fencing_token": 7,
        "git_commit": commit,
        "receipt_id": "b" * 32,
    }


class ContentMigrationTests(unittest.TestCase):
    @staticmethod
    def governance_scope_payload(
        vault: Path,
        scopes: dict[str, str],
    ) -> tuple[dict[str, object], dict[str, str]]:
        sources: dict[str, str] = {}
        for index, (name, agent_scope) in enumerate(scopes.items(), 1):
            rel_path = f"项目/{name}.md"
            text = (
                "---\nstatus: active\n"
                f"agent_scope: {agent_scope}\n"
                "app_id: agent-memory\n"
                f"project_id: lane-{index}\n"
                "---\n"
                f"# {name}\n"
            )
            target = vault / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            sources[rel_path] = text
        with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
            memory_index, "VAULT_ROOT", vault
        ):
            detail = memory_doctor.governance_metadata_migration_health()
        return {
            "status": "warning",
            "summary": {"pass": 1, "warn": 1, "fail": 0},
            "checks": [{
                "name": "governance_metadata_v4",
                "status": "warn",
                "detail": detail,
            }],
        }, sources

    @staticmethod
    def governance_risk_payload(
        vault: Path,
        *,
        missing_governance: bool = False,
    ) -> dict[str, object]:
        target = vault / "项目" / "Ailu事实-插件ID.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        review_line = "" if missing_governance else "review_after_days: 90\n"
        target.write_text(
            "---\n"
            f"memory_id: {'a' * 64}\n"
            "status: active\n"
            "agent_scope: shared\n"
            "app_id: agent-memory\n"
            "project_id: ailu-plugin-id\n"
            "temporal_policy: stable\n"
            f"{review_line}"
            "risk_class: action_sensitive\n"
            "fact_key: ailu.plugin_id\n"
            "valid_from: 2026-08-25\n"
            "verified_at: 2026-08-25\n"
            "---\n# Ailu plugin id\n",
            encoding="utf-8",
        )
        with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
            memory_index, "VAULT_ROOT", vault
        ):
            detail = memory_doctor.governance_metadata_migration_health()
        rel_path = "项目/Ailu事实-插件ID.md"
        return {
            "status": "error",
            "summary": {"pass": 0, "warn": 1, "fail": 1},
            "checks": [
                {
                    "name": "governance_metadata_v4",
                    "status": "warn",
                    "message": "Governance migration remains.",
                    "detail": detail,
                },
                temporal_coverage_check([rel_path]),
            ],
        }

    def test_preflight_governance_debt_accepts_only_exact_safe_automatic_temporal_target(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            payload = self.governance_risk_payload(Path(raw))
        debt = content_migrate.preflight_governance_migration_debt(payload)
        self.assertEqual(debt["safe_automatic_governance_documents"], 1)
        self.assertEqual(debt["governance_metadata_automatic_documents"], 0)
        self.assertEqual(debt["governance_risk_automatic_documents"], 1)
        self.assertEqual(debt["temporal_failure_documents"], 1)
        serialized = json.dumps(debt, ensure_ascii=False)
        self.assertNotIn("Ailu事实", serialized)
        self.assertNotIn("项目/", serialized)

        manual = json.loads(json.dumps(payload))
        detail = manual["checks"][0]["detail"]
        for record in [
            *detail["documents"],
            *detail["risk_migration_query"],
            *detail["manual_review_queue"],
        ]:
            recommendation = record["risk_recommendation"]
            recommendation["automatable_now"] = False
            recommendation["automatable_after_governance"] = False
            recommendation["manual_review_required"] = True
        detail["risk_automatable_documents"] = 0
        detail["risk_manual_review_documents"] = 1
        detail["risk_migration_query_sha256"] = content_migrate.canonical_sha256(
            detail["risk_migration_query"]
        )
        with self.assertRaises(content_migrate.ContentMigrationError) as blocked:
            content_migrate.preflight_governance_migration_debt(manual)
        self.assertEqual(
            blocked.exception.reason_code,
            "DOCTOR_TEMPORAL_FACT_COVERAGE_NOT_AUTOMATABLE",
        )

    def test_preflight_governance_debt_rejects_unsafe_and_malformed_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            payload = self.governance_risk_payload(Path(raw))
        unsafe = json.loads(json.dumps(payload))
        detail = unsafe["checks"][0]["detail"]
        detail["unsafe_documents"] = ["项目/Ailu事实-插件ID.md"]
        detail["governed_documents"] += 1
        detail["manual_review_documents"] += 1
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate.preflight_governance_migration_debt(unsafe)

        malformed = json.loads(json.dumps(payload))
        malformed["checks"][0]["detail"]["risk_automatable_documents"] = True
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate.preflight_governance_migration_debt(malformed)

        unsafe_automatic = json.loads(json.dumps(payload))
        detail = unsafe_automatic["checks"][0]["detail"]
        for record in [
            *detail["documents"],
            *detail["risk_migration_query"],
            *detail["manual_review_queue"],
        ]:
            record["risk_recommendation"]["followup_operation"] = "none"
            record["risk_recommendation"]["target_status"] = ""
        detail["risk_migration_query_sha256"] = content_migrate.canonical_sha256(
            detail["risk_migration_query"]
        )
        with self.assertRaises(content_migrate.ContentMigrationError) as unsafe_auto:
            content_migrate.preflight_governance_migration_debt(
                unsafe_automatic
            )
        self.assertEqual(
            unsafe_auto.exception.reason_code,
            "RISK_AUTOMATION_CLASSIFICATION_UNSAFE",
        )

        unresolved = json.loads(json.dumps(payload))
        detail = unresolved["checks"][0]["detail"]
        for record in [
            *detail["documents"],
            *detail["risk_migration_query"],
            *detail["manual_review_queue"],
        ]:
            recommendation = record["risk_recommendation"]
            recommendation["automatable_now"] = False
            recommendation["automatable_after_governance"] = False
            recommendation["manual_review_required"] = False
        detail["risk_automatable_documents"] = 0
        detail["risk_migration_query_sha256"] = content_migrate.canonical_sha256(
            detail["risk_migration_query"]
        )
        with self.assertRaises(content_migrate.ContentMigrationError) as dangling:
            content_migrate.preflight_governance_migration_debt(unresolved)
        self.assertEqual(
            dangling.exception.reason_code,
            "RISK_AUTOMATION_CLASSIFICATION_UNRESOLVED",
        )

    def test_preflight_governance_debt_keeps_manual_only_warning_non_authorizing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            payload, _sources = self.governance_scope_payload(
                Path(raw),
                {"Manual": "private"},
            )
        payload["checks"].append({
            "name": "temporal_fact_coverage",
            "status": "pass",
            "message": "No automatic temporal failure.",
            "detail": {},
        })
        debt = content_migrate.preflight_governance_migration_debt(payload)
        self.assertEqual(debt["safe_automatic_governance_documents"], 0)
        self.assertGreater(debt["governance_manual_review_documents"], 0)
        self.assertEqual(debt["temporal_failure_documents"], 0)

    def test_preflight_governance_debt_enforces_strict_risk_tri_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            after_governance = self.governance_risk_payload(
                Path(raw),
                missing_governance=True,
            )
        after_governance["checks"][1] = {
            "name": "temporal_fact_coverage",
            "status": "pass",
            "message": "Governance must run before risk automation.",
            "detail": {},
        }
        valid = content_migrate.preflight_governance_migration_debt(
            after_governance
        )
        self.assertEqual(valid["governance_metadata_automatic_documents"], 1)
        self.assertEqual(valid["governance_risk_automatic_documents"], 0)

        def recommendations(detail: dict[str, object]):
            return [
                record["risk_recommendation"]
                for record in [
                    *detail["documents"],
                    *detail["migration_query"],
                    *detail["risk_migration_query"],
                    *detail["manual_review_queue"],
                ]
            ]

        unknown_operation = json.loads(json.dumps(after_governance))
        detail = unknown_operation["checks"][0]["detail"]
        for recommendation in recommendations(detail):
            recommendation["followup_operation"] = "none"
            recommendation["target_status"] = ""
        detail["migration_query_sha256"] = content_migrate.canonical_sha256(
            detail["migration_query"]
        )
        detail["risk_migration_query_sha256"] = content_migrate.canonical_sha256(
            detail["risk_migration_query"]
        )
        with self.assertRaises(content_migrate.ContentMigrationError) as unknown:
            content_migrate.preflight_governance_migration_debt(
                unknown_operation
            )
        self.assertEqual(
            unknown.exception.reason_code,
            "RISK_AUTOMATION_CLASSIFICATION_UNRESOLVED",
        )

        with tempfile.TemporaryDirectory() as raw:
            nonmetadata = self.governance_risk_payload(Path(raw))
        nonmetadata["checks"][1] = {
            "name": "temporal_fact_coverage",
            "status": "pass",
            "message": "No current temporal automation.",
            "detail": {},
        }
        detail = nonmetadata["checks"][0]["detail"]
        for recommendation in recommendations(detail):
            recommendation["automatable_now"] = False
        detail["risk_automatable_documents"] = 0
        detail["risk_migration_query_sha256"] = content_migrate.canonical_sha256(
            detail["risk_migration_query"]
        )
        with self.assertRaises(content_migrate.ContentMigrationError) as outside:
            content_migrate.preflight_governance_migration_debt(nonmetadata)
        self.assertEqual(
            outside.exception.reason_code,
            "RISK_AUTOMATION_CLASSIFICATION_UNRESOLVED",
        )

        after_and_manual = json.loads(json.dumps(after_governance))
        detail = after_and_manual["checks"][0]["detail"]
        for recommendation in recommendations(detail):
            recommendation["manual_review_required"] = True
        detail["risk_manual_review_documents"] = 1
        detail["migration_query_sha256"] = content_migrate.canonical_sha256(
            detail["migration_query"]
        )
        detail["risk_migration_query_sha256"] = content_migrate.canonical_sha256(
            detail["risk_migration_query"]
        )
        with self.assertRaises(content_migrate.ContentMigrationError) as mixed:
            content_migrate.preflight_governance_migration_debt(
                after_and_manual
            )
        self.assertEqual(
            mixed.exception.reason_code,
            "RISK_AUTOMATION_CLASSIFICATION_UNRESOLVED",
        )

    def test_governance_v4_supporting_readme_uses_the_writer_operation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw)
            target = vault / "agent" / "README.md"
            target.parent.mkdir()
            target.write_text(
                "---\nstatus: active\nagent_scope: shared\napp_id: agent-memory\n"
                "project_id: agent-memory\n---\n# Agent memory\n",
                encoding="utf-8",
            )
            template_dir = vault / "工作流"
            template_dir.mkdir()
            for name in ("_模板-流程.md", "_模板流程.md"):
                (template_dir / name).write_text("# Template\n", encoding="utf-8")
            archived = vault / "agent" / "archive" / "README.md"
            archived.parent.mkdir()
            archived.write_text("# Archived index\n", encoding="utf-8")
            candidate = vault / "agent" / "case-candidates" / "ready.md"
            candidate.parent.mkdir()
            candidate.write_text(
                "---\nstatus: candidate\nagent_scope: shared\napp_id: agent-memory\n"
                "project_id: agent-cases\n---\n# Candidate\n",
                encoding="utf-8",
            )
            missing_status = vault / "agent" / "cases" / "missing-status.md"
            missing_status.parent.mkdir()
            missing_status.write_text(
                "---\nagent_scope: shared\napp_id: agent-memory\n"
                "project_id: agent-cases\n---\n# Missing status\n",
                encoding="utf-8",
            )
            with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
                memory_index, "VAULT_ROOT", vault
            ):
                detail = memory_doctor.governance_metadata_migration_health()
        self.assertEqual(detail["migration_candidate_documents"], 3)
        self.assertEqual(detail["automatable_documents"], 2)
        by_path = {
            item["target_relative_path"]: item
            for item in detail["migration_query"]
        }
        self.assertTrue(by_path["agent/case-candidates/ready.md"]["automatable"])
        self.assertFalse(by_path["agent/cases/missing-status.md"]["automatable"])
        self.assertIn(
            "STATUS_REVIEW_REQUIRED",
            by_path["agent/cases/missing-status.md"]["manual_review_reasons"],
        )
        record = by_path["agent/README.md"]
        self.assertEqual(record["target_relative_path"], "agent/README.md")
        self.assertEqual(
            content_migrate.migration_read_request(
                record,
                mode=content_migrate.GOVERNANCE_V4_MODE,
            ),
            {
                "schema_version": 2,
                "target_relative_path": "agent/README.md",
                "app_id": "agent-memory",
                "project_id": "agent-memory",
                "operation": "governance_migration",
            },
        )

    def test_governance_v4_query_keeps_automatic_metadata_and_manual_review_together(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw)
            target = vault / "项目" / "Alpha.md"
            target.parent.mkdir()
            target.write_text(
                "---\nstatus: active\nagent_scope: shared\napp_id: agent-memory\n"
                "project_id: alpha\n---\n# Alpha\n\nSnapshot 2026-08-01.\n",
                encoding="utf-8",
            )
            with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
                memory_index, "VAULT_ROOT", vault
            ):
                detail = memory_doctor.governance_metadata_migration_health()
        self.assertEqual(detail["migration_candidate_documents"], 1)
        self.assertEqual(detail["automatable_documents"], 1)
        record = detail["migration_query"][0]
        self.assertEqual(
            set(record["candidate_metadata"]),
            {"memory_id", "temporal_policy", "review_after_days"},
        )
        self.assertTrue(record["document_date_unverified"])
        self.assertTrue(record["active_unverified"])
        self.assertTrue(record["manual_review_required"])
        self.assertFalse(
            record["verification_basis"]["document_date_is_verification"]
        )
        self.assertEqual(
            record["risk_recommendation"]["recommended"], ""
        )
        payload = {
            "status": "warning",
            "summary": {"pass": 1, "warn": 1, "fail": 0},
            "checks": [{
                "name": "governance_metadata_v4",
                "status": "warn",
                "detail": detail,
            }],
        }
        normalized = content_migrate.normalize_governance_doctor_query(payload)
        self.assertEqual(normalized["automatable_documents"], 1)

    def test_doctor_binds_normalized_agent_scope_and_keeps_invalid_manual(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            payload, _sources = self.governance_scope_payload(
                Path(raw),
                {
                    "Shared": "ＳＨＡＲＥＤ",
                    "Codex": "CoDeX",
                    "Claude": "CLAUDE",
                    "Missing": "",
                    "Invalid": "Private",
                },
            )
        detail = payload["checks"][0]["detail"]
        records = {
            item["target_relative_path"]: item
            for item in detail["documents"]
        }
        self.assertEqual(
            records["项目/Shared.md"]["requested_agent_scope"],
            "shared",
        )
        self.assertEqual(
            records["项目/Codex.md"]["requested_agent_scope"],
            "codex",
        )
        self.assertEqual(
            records["项目/Claude.md"]["requested_agent_scope"],
            "claude",
        )
        for target, expected_scope in (
            ("项目/Missing.md", ""),
            ("项目/Invalid.md", "private"),
        ):
            record = records[target]
            self.assertEqual(record["requested_agent_scope"], expected_scope)
            self.assertFalse(record["automatable"])
            self.assertIn("SCOPE_REVIEW_REQUIRED", record["manual_review_reasons"])

        complete = content_migrate.normalize_governance_doctor_query(payload)
        self.assertEqual(len(complete["documents"]), 5)
        missing_binding = json.loads(json.dumps(payload))
        missing_detail = missing_binding["checks"][0]["detail"]
        missing_detail["migration_query"][0].pop("requested_agent_scope")
        missing_detail["migration_query_sha256"] = content_migrate.canonical_sha256(
            missing_detail["migration_query"]
        )
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate.normalize_governance_doctor_query(missing_binding)
        _full, codex_lane = content_migrate.normalize_and_project_query_for_actor(
            payload,
            mode=content_migrate.GOVERNANCE_V4_MODE,
            actor="codex",
        )
        _full, claude_lane = content_migrate.normalize_and_project_query_for_actor(
            payload,
            mode=content_migrate.GOVERNANCE_V4_MODE,
            actor="claude",
        )
        self.assertEqual(
            {
                item["requested_agent_scope"]
                for item in codex_lane["documents"]
            },
            {"shared", "codex"},
        )
        self.assertEqual(
            {
                item["requested_agent_scope"]
                for item in claude_lane["documents"]
            },
            {"claude"},
        )
        self.assertEqual(codex_lane["unassigned_manual_review_count"], 2)
        self.assertEqual(claude_lane["unassigned_manual_review_count"], 2)
        self.assertNotIn(
            "项目/Invalid.md",
            {
                item["target_relative_path"]
                for item in [
                    *codex_lane["documents"],
                    *claude_lane["documents"],
                ]
            },
        )
        _full, codex_risk_lane = (
            content_migrate.normalize_and_project_query_for_actor(
                payload,
                mode=content_migrate.RISK_V4_MODE,
                actor="codex",
            )
        )
        _full, claude_risk_lane = (
            content_migrate.normalize_and_project_query_for_actor(
                payload,
                mode=content_migrate.RISK_V4_MODE,
                actor="claude",
            )
        )
        self.assertTrue(all(
            item["requested_agent_scope"] in {"shared", "codex"}
            for item in codex_risk_lane["migration_query"]
        ))
        self.assertTrue(all(
            item["requested_agent_scope"] == "claude"
            for item in claude_risk_lane["migration_query"]
        ))
        self.assertEqual(codex_risk_lane["unassigned_manual_review_count"], 2)
        self.assertEqual(claude_risk_lane["unassigned_manual_review_count"], 2)
        with self.assertRaises(content_migrate.ContentMigrationError) as ailu:
            content_migrate.normalize_and_project_query_for_actor(
                payload,
                mode=content_migrate.GOVERNANCE_V4_MODE,
                actor="ailu",
            )
        self.assertEqual(ailu.exception.reason_code, "ACTOR_FORBIDDEN")

    def test_governance_review_is_owner_lane_only_for_both_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            payload, sources = self.governance_scope_payload(
                Path(raw),
                {"Shared": "shared", "Codex": "codex", "Claude": "claude"},
            )
        complete = content_migrate.normalize_governance_doctor_query(payload)
        records = {
            item["target_relative_path"]: item
            for item in complete["migration_query"]
        }

        class LaneClient:
            def __init__(self, actor: str) -> None:
                self.actor = actor
                self.read_targets: list[str] = []

            def doctor(self):
                return payload

            def write(self, action, request):
                self.assert_lane(request["target_relative_path"])
                if action != "read-target":
                    raise AssertionError(action)
                target = request["target_relative_path"]
                self.read_targets.append(target)
                record = records[target]
                digest = intent.content_hashes(sources[target].encode("utf-8"))
                return {
                    "ok": True,
                    "status": "found",
                    "exists": True,
                    "scope_migration": False,
                    "target_relative_path": target,
                    "app_id": record["requested_app_id"],
                    "project_id": record["requested_project_id"],
                    "content": sources[target],
                    "read_token": "1" * 64,
                    "base_raw_sha256": digest.raw_sha256,
                    "base_canonical_sha256": digest.canonical_sha256,
                    "base_git_head": "2" * 40,
                    "expected_memory_id": record["candidate_metadata"]["memory_id"],
                }

            def assert_lane(self, target: str) -> None:
                scope = records[target]["requested_agent_scope"]
                expected = "codex" if scope in {"shared", "codex"} else "claude"
                if expected != self.actor:
                    raise AssertionError((self.actor, target, scope))

        codex_client = LaneClient("codex")
        codex_review = content_migrate.build_review(
            codex_client,
            mode=content_migrate.GOVERNANCE_V4_MODE,
        )
        claude_client = LaneClient("claude")
        claude_review = content_migrate.build_review(
            claude_client,
            mode=content_migrate.GOVERNANCE_V4_MODE,
        )
        self.assertEqual(
            set(codex_client.read_targets),
            {"项目/Shared.md", "项目/Codex.md"},
        )
        self.assertEqual(claude_client.read_targets, ["项目/Claude.md"])
        self.assertEqual(
            {
                item["requested_agent_scope"]
                for item in codex_review["items"]
            },
            {"shared", "codex"},
        )
        self.assertEqual(
            [item["requested_agent_scope"] for item in claude_review["items"]],
            ["claude"],
        )
        self.assertEqual(
            content_migrate.validate_review(codex_review),
            codex_review,
        )
        self.assertEqual(
            content_migrate.validate_review(claude_review),
            claude_review,
        )
        self.assertNotEqual(
            codex_review["doctor_binding"]["migration_query"],
            complete["migration_query"],
        )
        self.assertRegex(
            codex_review["doctor_binding"]["complete_doctor_binding_sha256"],
            r"^[0-9a-f]{64}$",
        )

        with tempfile.TemporaryDirectory() as changed_raw:
            changed_payload, _changed_sources = self.governance_scope_payload(
                Path(changed_raw),
                {
                    "Shared": "shared",
                    "Codex": "codex",
                    "ClaudeChanged": "claude",
                },
            )
        _changed_full, changed_codex_lane = (
            content_migrate.normalize_and_project_query_for_actor(
                changed_payload,
                mode=content_migrate.GOVERNANCE_V4_MODE,
                actor="codex",
            )
        )
        self.assertEqual(
            content_migrate.compare_current_query(
                codex_review,
                codex_review["doctor_binding"],
            ),
            set(),
        )
        with self.assertRaises(content_migrate.ContentMigrationError) as drift:
            content_migrate.compare_current_query(
                codex_review,
                changed_codex_lane,
            )
        self.assertEqual(
            drift.exception.reason_code,
            "MIGRATION_COMPLETE_BINDING_CHANGED",
        )
        shrunk_lane = json.loads(json.dumps(changed_codex_lane))
        removed = shrunk_lane["migration_query"].pop(0)
        shrunk_lane["migration_query_sha256"] = content_migrate.canonical_sha256(
            shrunk_lane["migration_query"]
        )
        self.assertEqual(
            content_migrate.compare_current_query(codex_review, shrunk_lane),
            {removed["target_relative_path"]},
        )

        changed_unassigned = json.loads(json.dumps(
            codex_review["doctor_binding"]
        ))
        changed_unassigned["unassigned_manual_review_count"] += 1
        with self.assertRaises(content_migrate.ContentMigrationError) as debt:
            content_migrate.compare_current_query(
                codex_review,
                changed_unassigned,
            )
        self.assertEqual(
            debt.exception.reason_code,
            "MIGRATION_UNASSIGNED_MANUAL_CHANGED",
        )

        tampered_count = json.loads(json.dumps(codex_review))
        tampered_count["manual_review_count"] += 1
        with self.assertRaises(content_migrate.ContentMigrationError) as count:
            content_migrate.validate_review(tampered_count)
        self.assertEqual(
            count.exception.reason_code,
            "REVIEW_MANUAL_COUNT_INVALID",
        )

        tampered = json.loads(json.dumps(codex_review))
        tampered["doctor_binding"] = claude_review["doctor_binding"]
        tampered["items"] = claude_review["items"]
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate.validate_review(tampered)

    def test_current_query_and_final_empty_are_evaluated_per_owner_lane(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            payload, _sources = self.governance_scope_payload(
                Path(raw),
                {"Claude": "claude"},
            )

            class CodexEmptyLaneClient:
                actor = "codex"

                def doctor(self):
                    return payload

                def write(self, action, request):
                    raise AssertionError((action, request))

            client = CodexEmptyLaneClient()
            review = content_migrate.build_review(
                client,
                mode=content_migrate.GOVERNANCE_V4_MODE,
            )
            self.assertEqual(review["items"], [])
            self.assertEqual(review["doctor_binding"]["migration_query"], [])
            progress = Path(raw) / "lane-progress.jsonl"
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256=content_migrate.canonical_sha256(review),
                progress_path=progress,
                allow_apply=False,
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["final_governance_automatable_documents"], 0)

    def test_unassigned_manual_and_unsafe_debt_never_false_green_or_leak_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw)
            self.governance_scope_payload(vault, {"Private": "Private"})
            unsafe_target = vault / "项目" / "Unreadable.md"
            unsafe_target.write_bytes(b"\xff")
            with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
                memory_index, "VAULT_ROOT", vault
            ):
                detail = memory_doctor.governance_metadata_migration_health()
            payload = {
                "status": "warning",
                "summary": {"pass": 1, "warn": 1, "fail": 0},
                "checks": [{
                    "name": "governance_metadata_v4",
                    "status": "warn",
                    "detail": detail,
                }],
            }
            self.assertEqual(detail["manual_review_documents"], 2)
            self.assertEqual(detail["unsafe_documents"], ["项目/Unreadable.md"])

            class EmptyOwnerLaneClient:
                def __init__(self, actor: str) -> None:
                    self.actor = actor

                def doctor(self):
                    return payload

                def write(self, action, request):
                    raise AssertionError((action, request))

            for actor in ("codex", "claude"):
                for mode in (
                    content_migrate.GOVERNANCE_V4_MODE,
                    content_migrate.RISK_V4_MODE,
                ):
                    with self.subTest(actor=actor, mode=mode):
                        client = EmptyOwnerLaneClient(actor)
                        review = content_migrate.build_review(client, mode=mode)
                        self.assertEqual(review["items"], [])
                        self.assertEqual(
                            review["doctor_binding"]["migration_query"],
                            [],
                        )
                        self.assertEqual(
                            review["unassigned_manual_review_count"],
                            2,
                        )
                        self.assertEqual(review["manual_review_count"], 2)
                        serialized = json.dumps(review, ensure_ascii=False)
                        self.assertNotIn("项目/Private.md", serialized)
                        self.assertNotIn("项目/Unreadable.md", serialized)
                        self.assertEqual(
                            content_migrate.validate_review(review),
                            review,
                        )
                        result = content_migrate.run_apply(
                            client,
                            review,
                            review_sha256=content_migrate.canonical_sha256(review),
                            progress_path=(
                                vault / f"{actor}-{mode}-progress.jsonl"
                            ),
                            allow_apply=False,
                        )
                        self.assertTrue(result["ok"])
                        self.assertEqual(
                            result["status"],
                            "complete_with_manual_review",
                        )
                        self.assertEqual(
                            result["final_manual_review_documents"],
                            2,
                        )
                        self.assertEqual(
                            result["final_unassigned_manual_review_count"],
                            2,
                        )

    def test_risk_v4_missing_ordinary_classification_remains_manual(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw)
            target = vault / "项目" / "Alpha.md"
            target.parent.mkdir()
            target.write_text(
                f"---\nmemory_id: {'a' * 64}\nmemory_type: project\ntrack: project\n"
                "status: active\nagent_scope: shared\napp_id: agent-memory\n"
                "project_id: alpha\ntemporal_policy: reviewable\n"
                "review_after_days: 90\n---\n# Alpha\n",
                encoding="utf-8",
            )
            with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
                memory_index, "VAULT_ROOT", vault
            ):
                detail = memory_doctor.governance_metadata_migration_health()
        self.assertEqual(detail["migration_candidate_documents"], 0)
        self.assertEqual(detail["risk_candidate_documents"], 1)
        self.assertEqual(detail["risk_automatable_documents"], 0)
        self.assertEqual(detail["risk_manual_review_documents"], 1)
        recommendation = detail["risk_migration_query"][0]["risk_recommendation"]
        self.assertEqual(recommendation["recommended"], "")
        self.assertFalse(recommendation["automatable_now"])
        self.assertTrue(recommendation["manual_review_required"])
        payload = {
            "status": "warning",
            "summary": {"pass": 1, "warn": 1, "fail": 0},
            "checks": [{
                "name": "governance_metadata_v4",
                "status": "warn",
                "detail": detail,
            }],
        }
        normalized = content_migrate.normalize_query_for_mode(
            payload,
            mode=content_migrate.RISK_V4_MODE,
        )
        self.assertEqual(normalized["automatable_documents"], 0)
        self.assertEqual(
            normalized["migration_query"][0]["target_relative_path"],
            "项目/Alpha.md",
        )

        class ManualOnlyClient:
            actor = "codex"

            def doctor(self):
                return payload

            def write(self, action, request):
                raise AssertionError((action, request))

        review = content_migrate.build_review(
            ManualOnlyClient(),
            mode=content_migrate.RISK_V4_MODE,
        )
        self.assertEqual(review["items"], [])
        self.assertEqual(
            content_migrate.validate_review(review)["items"],
            [],
        )

    def test_risk_v4_rejects_legacy_doctor_auto_ordinary_classification(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw)
            target = vault / "项目" / "Alpha.md"
            target.parent.mkdir()
            target.write_text(
                f"---\nmemory_id: {'a' * 64}\nmemory_type: project\ntrack: project\n"
                "status: active\nagent_scope: shared\napp_id: agent-memory\n"
                "project_id: alpha\ntemporal_policy: reviewable\n"
                "review_after_days: 90\nverified_at: 2026-08-25\n---\n# Alpha\n",
                encoding="utf-8",
            )
            with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
                memory_index, "VAULT_ROOT", vault
            ):
                detail = memory_doctor.governance_metadata_migration_health()
        record = detail["documents"][0]
        recommendation = record["risk_recommendation"]
        recommendation.update({
            "recommended": "ordinary",
            "followup_operation": "content_update",
            "target_status": "",
            "automatable_after_governance": True,
            "automatable_now": True,
            "manual_review_required": False,
        })
        record["manual_review_required"] = False
        record["manual_review_reasons"] = []
        detail["manual_review_documents"] = 0
        detail["manual_review_queue"] = []
        detail["risk_automatable_documents"] = 1
        detail["risk_manual_review_documents"] = 0
        detail["risk_migration_query"] = [record]
        detail["risk_migration_query_sha256"] = content_migrate.canonical_sha256(
            detail["risk_migration_query"]
        )
        payload = {
            "status": "warning",
            "summary": {"pass": 1, "warn": 1, "fail": 0},
            "checks": [{
                "name": "governance_metadata_v4",
                "status": "warn",
                "detail": detail,
            }],
        }
        with self.assertRaises(content_migrate.ContentMigrationError) as caught:
            content_migrate.normalize_query_for_mode(
                payload,
                mode=content_migrate.RISK_V4_MODE,
            )
        self.assertEqual(
            caught.exception.reason_code,
            "RISK_AUTOMATION_CLASSIFICATION_UNSAFE",
        )
        self.assertEqual(caught.exception.target_relative_path, "")
        self.assertNotIn("项目/Alpha.md", str(caught.exception))

    def test_governance_partial_metadata_review_binds_existing_memory_id(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw)
            target = vault / "工作流" / "Closeout.md"
            target.parent.mkdir()
            existing_id = "a" * 64
            base = (
                f"---\nmemory_id: {existing_id}\nmemory_type: workflow\n"
                "track: workflow\nstatus: active\nagent_scope: shared\n"
                "app_id: agent-memory\nproject_id: closeout\nrisk_class: ordinary\n"
                "---\n# Closeout\n"
            )
            target.write_text(base, encoding="utf-8")
            base_digest = intent.content_hashes(base.encode("utf-8"))
            with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
                memory_index, "VAULT_ROOT", vault
            ):
                detail = memory_doctor.governance_metadata_migration_health()
                payload = {
                    "status": "warning",
                    "summary": {"pass": 1, "warn": 1, "fail": 0},
                    "checks": [{
                        "name": "governance_metadata_v4",
                        "status": "warn",
                        "detail": detail,
                    }],
                }

                class FakeClient:
                    actor = "codex"

                    def doctor(self):
                        return payload

                    def write(self, action, request):
                        if action != "read-target":
                            raise AssertionError(action)
                        return {
                            "ok": True,
                            "status": "found",
                            "exists": True,
                            "scope_migration": False,
                            "target_relative_path": "工作流/Closeout.md",
                            "app_id": "agent-memory",
                            "project_id": "closeout",
                            "content": base,
                            "read_token": "1" * 64,
                            "base_raw_sha256": base_digest.raw_sha256,
                            "base_canonical_sha256": base_digest.canonical_sha256,
                            "base_git_head": "2" * 40,
                            "expected_memory_id": existing_id,
                        }

                review = content_migrate.build_review(
                    FakeClient(),
                    mode=content_migrate.GOVERNANCE_V4_MODE,
                )
                validated = content_migrate.validate_review(review)
            self.assertEqual(
                validated["items"][0]["expected_memory_id"],
                existing_id,
            )
            self.assertNotIn(
                "memory_id",
                validated["items"][0]["candidate_metadata"],
            )

    def test_doctor_scope_and_path_floor_match_gateway_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw)
            user = vault / "用户记忆" / "Profile.md"
            project = vault / "项目" / "Alpha.md"
            user.parent.mkdir()
            project.parent.mkdir()
            common = (
                f"memory_id: {'a' * 64}\nstatus: active\nagent_scope: shared\n"
                "app_id: agent-memory\ntemporal_policy: reviewable\n"
                "review_after_days: 90\nverified_at: 2026-08-24\n"
            )
            user.write_text(
                "---\n" + common + "memory_type: user_profile\ntrack: user\n"
                "project_id: global\n---\n# Profile\n",
                encoding="utf-8",
            )
            project.write_text(
                "---\n" + common.replace("a" * 64, "b" * 64)
                + "memory_type: user\ntrack: user\nproject_id: alpha\n"
                "---\n# Alpha\n",
                encoding="utf-8",
            )
            with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
                memory_index, "VAULT_ROOT", vault
            ):
                detail = memory_doctor.governance_metadata_migration_health()
        records = {
            item["target_relative_path"]: item for item in detail["documents"]
        }
        self.assertNotIn(
            "SCOPE_REVIEW_REQUIRED",
            records["用户记忆/Profile.md"]["manual_review_reasons"],
        )
        self.assertIn(
            "PATH_POLICY_DOWNGRADE_FORBIDDEN",
            records["项目/Alpha.md"]["manual_review_reasons"],
        )
        self.assertFalse(records["项目/Alpha.md"]["automatable"])

    def test_action_sensitive_unverified_atomic_gap_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw)
            target = vault / "项目" / "Sensitive.md"
            target.parent.mkdir()
            base = (
                f"---\nmemory_id: {'a' * 64}\nmemory_type: project\ntrack: project\n"
                "status: active\nagent_scope: shared\napp_id: agent-memory\n"
                "project_id: sensitive\nrisk_class: action_sensitive\n"
                "temporal_policy: reviewable\nreview_after_days: 90\n"
                "---\n# Sensitive\n"
            )
            target.write_text(base, encoding="utf-8")
            with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
                memory_index, "VAULT_ROOT", vault
            ):
                detail = memory_doctor.governance_metadata_migration_health()
        recommendation = detail["risk_migration_query"][0]["risk_recommendation"]
        self.assertEqual(recommendation["followup_operation"], "status_transition")
        self.assertEqual(recommendation["target_status"], "pending_verification")
        self.assertTrue(recommendation["automatable_now"])
        self.assertIn("ACTION_SENSITIVE_ATOMIC_GAP", recommendation["reason_codes"])
        payload = {
            "status": "warning",
            "summary": {"pass": 1, "warn": 1, "fail": 0},
            "checks": [{
                "name": "governance_metadata_v4",
                "status": "warn",
                "detail": detail,
            }],
        }
        base_digest = intent.content_hashes(base.encode("utf-8"))

        class FakeClient:
            actor = "codex"
            session_id = "session-1"

            def doctor(self):
                return payload

            def write(self, action, request):
                if action != "read-target":
                    raise AssertionError(action)
                return {
                    "ok": True,
                    "status": "found",
                    "exists": True,
                    "scope_migration": False,
                    "target_relative_path": "项目/Sensitive.md",
                    "app_id": "agent-memory",
                    "project_id": "sensitive",
                    "content": base,
                    "read_token": "1" * 64,
                    "base_raw_sha256": base_digest.raw_sha256,
                    "base_canonical_sha256": base_digest.canonical_sha256,
                    "base_git_head": "2" * 40,
                }

        review = content_migrate.build_review(
            FakeClient(),
            mode=content_migrate.RISK_V4_MODE,
        )
        self.assertEqual(len(review["items"]), 1)
        queued = review["items"][0]
        self.assertEqual(queued["migration_operation"], "status_transition")
        self.assertEqual(queued["target_status"], "pending_verification")
        self.assertEqual(queued["confirmation_mode"], "capability")

    def test_risk_automation_matches_writer_statuses_and_quarantine_is_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw)
            project = vault / "项目"
            project.mkdir()
            status_paths: dict[str, Path] = {}
            for index, status in enumerate(
                ("active", "pending_verification", "outdated", "archived", "candidate"),
                start=1,
            ):
                target = project / f"事实-{status}.md"
                status_paths[status] = target
                target.write_text(
                    f"---\nmemory_id: {index:064x}\nmemory_type: fact\n"
                    f"track: project\nstatus: {status}\nagent_scope: shared\n"
                    "app_id: agent-memory\nproject_id: status-matrix\n"
                    "temporal_policy: reviewable\nreview_after_days: 90\n"
                    "fact_key: project.status\nvalid_from: 2026-08-01\n"
                    "verified_at: 2026-08-01\n---\n# Status\n\nBody stays fixed.\n",
                    encoding="utf-8",
                )
            with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
                memory_index, "VAULT_ROOT", vault
            ):
                detail = memory_doctor.governance_metadata_migration_health()
                records = {
                    item["risk_recommendation"]["source_status"]: item
                    for item in detail["risk_migration_query"]
                }

                self.assertEqual(detail["risk_automatable_documents"], 2)
                self.assertEqual(
                    records["active"]["risk_recommendation"]["followup_operation"],
                    "status_transition",
                )
                self.assertEqual(
                    records["pending_verification"]["risk_recommendation"]["followup_operation"],
                    "content_update",
                )
                for status in ("active", "pending_verification"):
                    recommendation = records[status]["risk_recommendation"]
                    self.assertTrue(recommendation["automatable_now"])
                    self.assertTrue(
                        content_migrate._risk_recommendation_is_safe_automatic(
                            recommendation
                        )
                    )
                for status in ("outdated", "archived", "candidate"):
                    recommendation = records[status]["risk_recommendation"]
                    self.assertFalse(recommendation["automatable_now"])
                    self.assertTrue(recommendation["manual_review_required"])
                    self.assertFalse(
                        content_migrate._risk_recommendation_is_safe_automatic(
                            recommendation
                        )
                    )

                active_text = status_paths["active"].read_text(encoding="utf-8")
                with self.assertRaises(content_migrate.ContentMigrationError) as drifted:
                    content_migrate._proposal(
                        records["active"],
                        active_text.replace("status: active", "status: outdated"),
                        actor="codex",
                        mode=content_migrate.RISK_V4_MODE,
                    )
                self.assertEqual(
                    drifted.exception.reason_code,
                    "PROPOSAL_GENERATION_FAILED",
                )
                quarantined, _digest = content_migrate._proposal(
                    records["active"],
                    active_text,
                    actor="codex",
                    mode=content_migrate.RISK_V4_MODE,
                )
                self.assertIn("status: pending_verification\n", quarantined)
                self.assertIn("risk_class: action_sensitive\n", quarantined)
                self.assertIn("Body stays fixed.", quarantined)
                status_paths["active"].write_text(quarantined, encoding="utf-8")

                pending_text = status_paths["pending_verification"].read_text(
                    encoding="utf-8"
                )
                completed, _digest = content_migrate._proposal(
                    records["pending_verification"],
                    pending_text,
                    actor="codex",
                    mode=content_migrate.RISK_V4_MODE,
                )
                self.assertIn("status: pending_verification\n", completed)
                self.assertIn("risk_class: action_sensitive\n", completed)
                self.assertIn("Body stays fixed.", completed)

                fresh = memory_doctor.governance_metadata_migration_health()

            fresh_targets = {
                item["target_relative_path"]
                for item in fresh["risk_migration_query"]
            }
            self.assertNotIn("项目/事实-active.md", fresh_targets)

            forged = json.loads(json.dumps(detail))
            forged_target = "项目/事实-outdated.md"
            for collection_name in (
                "documents",
                "risk_migration_query",
                "manual_review_queue",
            ):
                for item in forged[collection_name]:
                    if item["target_relative_path"] == forged_target:
                        item["risk_recommendation"].update({
                            "automatable_after_governance": True,
                            "automatable_now": True,
                            "manual_review_required": False,
                        })
            forged["risk_automatable_documents"] += 1
            forged["risk_manual_review_documents"] -= 1
            forged["risk_migration_query_sha256"] = (
                content_migrate.canonical_sha256(forged["risk_migration_query"])
            )
            forged_payload = {
                "status": "warning",
                "summary": {"pass": 1, "warn": 1, "fail": 0},
                "checks": [{
                    "name": "governance_metadata_v4",
                    "status": "warn",
                    "detail": forged,
                }],
            }
            with self.assertRaises(content_migrate.ContentMigrationError) as unsafe:
                content_migrate.normalize_query_for_mode(
                    forged_payload,
                    mode=content_migrate.RISK_V4_MODE,
                )
            self.assertEqual(
                unsafe.exception.reason_code,
                "RISK_AUTOMATION_CLASSIFICATION_UNSAFE",
            )

            null_status = json.loads(json.dumps(detail))
            null_target = "项目/事实-pending_verification.md"
            for collection_name in (
                "documents",
                "risk_migration_query",
                "manual_review_queue",
            ):
                for item in null_status[collection_name]:
                    if item["target_relative_path"] == null_target:
                        item["risk_recommendation"]["target_status"] = None
            null_status["risk_migration_query_sha256"] = (
                content_migrate.canonical_sha256(
                    null_status["risk_migration_query"]
                )
            )
            null_payload = {
                "status": "warning",
                "summary": {"pass": 1, "warn": 1, "fail": 0},
                "checks": [{
                    "name": "governance_metadata_v4",
                    "status": "warn",
                    "detail": null_status,
                }],
            }
            with self.assertRaises(content_migrate.ContentMigrationError) as invalid:
                content_migrate.normalize_query_for_mode(
                    null_payload,
                    mode=content_migrate.RISK_V4_MODE,
                )
            self.assertEqual(
                invalid.exception.reason_code,
                "MIGRATION_QUERY_INVALID",
            )

    def test_missing_or_blank_status_never_authorizes_risk_automation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw)
            project = vault / "项目"
            project.mkdir()
            for index, status_line in enumerate(("", "status:   \n"), start=1):
                (project / f"事实-status-{index}.md").write_text(
                    f"---\nmemory_id: {index:064x}\nmemory_type: fact\n"
                    "track: project\n"
                    f"{status_line}"
                    "agent_scope: shared\napp_id: agent-memory\n"
                    "project_id: missing-status\nrisk_class: \n"
                    "temporal_policy: reviewable\nreview_after_days: 90\n"
                    "fact_key: project.status\nvalid_from: 2026-08-01\n"
                    "verified_at: 2026-08-01\n---\n# Missing status\n",
                    encoding="utf-8",
                )
            with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
                memory_index, "VAULT_ROOT", vault
            ):
                detail = memory_doctor.governance_metadata_migration_health()

            self.assertEqual(detail["risk_candidate_documents"], 2)
            self.assertEqual(detail["risk_automatable_documents"], 0)
            self.assertEqual(detail["risk_manual_review_documents"], 2)
            for record in detail["risk_migration_query"]:
                recommendation = record["risk_recommendation"]
                self.assertEqual(recommendation["source_status"], "")
                self.assertFalse(recommendation["automatable_after_governance"])
                self.assertFalse(recommendation["automatable_now"])
                self.assertTrue(recommendation["manual_review_required"])
                self.assertIn(
                    "STATUS_REVIEW_REQUIRED",
                    record["manual_review_reasons"],
                )
                self.assertFalse(
                    content_migrate._risk_recommendation_is_safe_automatic(
                        recommendation
                    )
                )

            payload = {
                "status": "warning",
                "summary": {"pass": 1, "warn": 1, "fail": 0},
                "checks": [{
                    "name": "governance_metadata_v4",
                    "status": "warn",
                    "detail": detail,
                }],
            }
            normalized = content_migrate.normalize_query_for_mode(
                payload,
                mode=content_migrate.RISK_V4_MODE,
            )
            self.assertEqual(normalized["automatable_documents"], 0)

            class ManualClient:
                actor = "codex"

                def doctor(self):
                    return payload

                def write(self, action, request):
                    raise AssertionError((action, request))

            review = content_migrate.build_review(
                ManualClient(),
                mode=content_migrate.RISK_V4_MODE,
            )
            self.assertEqual(review["items"], [])

    def test_risk_status_transition_replans_to_complete_without_followup_update(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            vault = root / "vault"
            relative_targets = (
                "项目/事实-a-owner.md",
                "项目/事实-b-owner.md",
            )
            targets = {relative: vault / relative for relative in relative_targets}
            for index, relative in enumerate(relative_targets, start=1):
                target = targets[relative]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    f"---\nmemory_id: {index:064x}\nmemory_type: fact\n"
                    "track: project\nstatus: active\nagent_scope: shared\n"
                    "app_id: agent-memory\nproject_id: owner\n"
                    "temporal_policy: reviewable\nreview_after_days: 90\n"
                    f"fact_key: project.owner.{index}\nvalid_from: 2026-08-01\n"
                    "verified_at: 2026-08-01\n---\n# Owner\n\n"
                    f"Immutable body {index}.\n",
                    encoding="utf-8",
                )

            class LiveDoctorGateway:
                actor = "codex"
                session_id = "risk-atomic-session"

                def __init__(self) -> None:
                    self.head = "2" * 40
                    self.prepared: dict[str, object] = {}
                    self.commit_index = 2
                    self.prepare_targets: list[str] = []
                    self.apply_targets: list[str] = []

                def doctor(self):
                    detail = memory_doctor.governance_metadata_migration_health()
                    debt = bool(
                        detail["migration_candidate_documents"]
                        or detail["risk_candidate_documents"]
                        or detail["manual_review_documents"]
                    )
                    return {
                        "status": "warning" if debt else "ok",
                        "summary": {"pass": 1, "warn": int(debt), "fail": 0},
                        "checks": [{
                            "name": "governance_metadata_v4",
                            "status": "warn" if debt else "pass",
                            "detail": detail,
                        }],
                    }

                def write(self, action, request):
                    relative = str(request["target_relative_path"])
                    if relative not in targets:
                        raise AssertionError(relative)
                    target = targets[relative]
                    current = target.read_text(encoding="utf-8")
                    current_digest = intent.content_hashes(current.encode("utf-8"))
                    if action == "read-target":
                        return {
                            "ok": True,
                            "status": "found",
                            "exists": True,
                            "scope_migration": False,
                            "target_relative_path": relative,
                            "app_id": "agent-memory",
                            "project_id": "owner",
                            "content": current,
                            "read_token": "1" * 64,
                            "base_raw_sha256": current_digest.raw_sha256,
                            "base_canonical_sha256": current_digest.canonical_sha256,
                            "base_git_head": self.head,
                        }
                    if action == "prepare":
                        if (
                            request.get("operation") != "status_transition"
                            or request.get("target_status")
                            != "pending_verification"
                        ):
                            raise AssertionError("atomic transition was not bound")
                        self.prepare_targets.append(relative)
                        proposal = str(request["proposal_markdown"])
                        proposal_digest = intent.content_hashes(proposal.encode("utf-8"))
                        proposal_id = hashlib.sha256(
                            relative.encode("utf-8")
                        ).hexdigest()[:32]
                        self.prepared = {
                            "target": relative,
                            "proposal": proposal,
                            "raw": proposal_digest.raw_sha256,
                            "canonical": proposal_digest.canonical_sha256,
                            "proposal_id": proposal_id,
                        }
                        return {
                            "ok": True,
                            "status": "prepared",
                            "recommended_action": "UPDATE",
                            "target_relative_path": relative,
                            "scope_migration": False,
                            "confirmation_required": True,
                            "proposal_id": proposal_id,
                            "fencing_token": 7,
                            "base_raw_sha256": current_digest.raw_sha256,
                            "base_canonical_sha256": current_digest.canonical_sha256,
                            "base_git_head": self.head,
                            "proposal_raw_sha256": proposal_digest.raw_sha256,
                            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
                            "proposal_size_bytes": proposal_digest.size_bytes,
                        }
                    if action != "apply":
                        raise AssertionError(action)
                    if self.prepared.get("target") != relative:
                        raise AssertionError("apply target escaped prepared proposal")
                    self.assert_atomic_apply(request)
                    target.write_text(str(self.prepared["proposal"]), encoding="utf-8")
                    self.apply_targets.append(relative)
                    self.commit_index += 1
                    self.head = f"{self.commit_index:x}" * 40
                    return {
                        "ok": True,
                        "status": "applied",
                        "recommended_action": "UPDATE",
                        "target_relative_path": relative,
                        "scope_migration": False,
                        "proposal_id": self.prepared["proposal_id"],
                        "fencing_token": 7,
                        "proposal_raw_sha256": self.prepared["raw"],
                        "proposal_canonical_sha256": self.prepared["canonical"],
                        "git_commit": self.head,
                        "receipt_id": hashlib.sha256(
                            f"receipt:{relative}".encode("utf-8")
                        ).hexdigest()[:32],
                        "idempotent": False,
                    }

                def assert_atomic_apply(self, request) -> None:
                    proposal = str(request["proposal_markdown"])
                    if "status: pending_verification\n" not in proposal:
                        raise AssertionError("status was not quarantined")
                    if "risk_class: action_sensitive\n" not in proposal:
                        raise AssertionError("risk class was not filled atomically")
                    if "Immutable body " not in proposal:
                        raise AssertionError("body changed")

            client = LiveDoctorGateway()
            with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
                memory_index, "VAULT_ROOT", vault
            ):
                review = content_migrate.build_review(
                    client,
                    mode=content_migrate.RISK_V4_MODE,
                )
                self.assertEqual(
                    [item["target_relative_path"] for item in review["items"]],
                    list(relative_targets),
                )
                review_sha = content_migrate.canonical_sha256(review)
                progress = root / "first.progress.jsonl"
                prepared = content_migrate.run_apply(
                    client,
                    review,
                    review_sha256=review_sha,
                    progress_path=progress,
                    allow_apply=False,
                )
                self.assertEqual(prepared["status"], "confirmation_required")
                with mock.patch.object(
                    content_migrate,
                    "_assert_prepared_base_git_projection",
                ):
                    applied = content_migrate.run_apply(
                        client,
                        review,
                        review_sha256=review_sha,
                        progress_path=progress,
                        confirmation_capability_path=(
                            "/private/exact-capability.json"
                        ),
                        confirmation_capability_token="exact-token",
                    )
                self.assertEqual(applied["status"], "replan_required", applied)
                self.assertEqual(
                    applied["reason_code"],
                    "RISK_FOLLOWUP_REPLAN_REQUIRED",
                )
                self.assertEqual(
                    applied["transitioned_target_relative_path"],
                    relative_targets[0],
                )
                self.assertEqual(client.prepare_targets, [relative_targets[0]])
                self.assertEqual(client.apply_targets, [relative_targets[0]])
                untouched = targets[relative_targets[1]].read_text(encoding="utf-8")
                self.assertIn("status: active\n", untouched)
                self.assertNotIn("risk_class:", untouched)

                fresh_review = content_migrate.build_review(
                    client,
                    mode=content_migrate.RISK_V4_MODE,
                )
                self.assertEqual(
                    [
                        item["target_relative_path"]
                        for item in fresh_review["items"]
                    ],
                    [relative_targets[1]],
                )
                second_sha = content_migrate.canonical_sha256(fresh_review)
                second_progress = root / "second.progress.jsonl"
                second_prepared = content_migrate.run_apply(
                    client,
                    fresh_review,
                    review_sha256=second_sha,
                    progress_path=second_progress,
                    allow_apply=False,
                )
                self.assertEqual(
                    second_prepared["status"],
                    "confirmation_required",
                )
                with mock.patch.object(
                    content_migrate,
                    "_assert_prepared_base_git_projection",
                ):
                    second_applied = content_migrate.run_apply(
                        client,
                        fresh_review,
                        review_sha256=second_sha,
                        progress_path=second_progress,
                        confirmation_capability_path=(
                            "/private/second-exact-capability.json"
                        ),
                        confirmation_capability_token="second-exact-token",
                    )
                self.assertEqual(second_applied["status"], "replan_required")
                self.assertEqual(
                    client.apply_targets,
                    list(relative_targets),
                )

                final_review = content_migrate.build_review(
                    client,
                    mode=content_migrate.RISK_V4_MODE,
                )
                self.assertEqual(final_review["items"], [])
                self.assertEqual(
                    final_review["doctor_binding"]["migration_query"],
                    [],
                )
                completed = content_migrate.run_apply(
                    client,
                    final_review,
                    review_sha256=content_migrate.canonical_sha256(final_review),
                    progress_path=root / "fresh.progress.jsonl",
                )
            self.assertTrue(completed["ok"])
            self.assertIn(completed["status"], {"complete", "complete_with_manual_review"})
            for target in targets.values():
                final_text = target.read_text(encoding="utf-8")
                self.assertIn("status: pending_verification\n", final_text)
                self.assertIn("risk_class: action_sensitive\n", final_text)

    def test_structural_action_sensitive_fact_cannot_bypass_full_tuple_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw)
            target = vault / "项目" / "事实-owner.md"
            target.parent.mkdir()
            base = (
                f"---\nmemory_id: {'a' * 64}\nmemory_type: project\ntrack: project\n"
                "status: active\nagent_scope: shared\napp_id: agent-memory\n"
                "project_id: owner\nrisk_class: action_sensitive\n"
                "temporal_policy: structural\nreview_after_days: 90\n"
                "fact_key: project.owner\n---\n# Owner\n\n"
                "## 当前有效摘要\n\n- Current 2026-08-01.\n"
            )
            target.write_text(base, encoding="utf-8")
            with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
                memory_index, "VAULT_ROOT", vault
            ):
                detail = memory_doctor.governance_metadata_migration_health()

        self.assertEqual(detail["migration_candidate_documents"], 0)
        self.assertEqual(detail["risk_candidate_documents"], 1)
        record = detail["risk_migration_query"][0]
        self.assertEqual(
            set(record["atomic_fact_gap_fields"]),
            {"temporal_policy", "valid_from", "verified_at", "evidence_provenance"},
        )
        self.assertFalse(record["durable_evidence_provenance"]["present"])
        self.assertEqual(
            record["verification_basis"]["source"],
            "document_date_unverified",
        )
        self.assertEqual(record["verification_basis"]["verified_at"], "")
        recommendation = record["risk_recommendation"]
        self.assertEqual(recommendation["followup_operation"], "status_transition")
        self.assertEqual(recommendation["target_status"], "pending_verification")
        self.assertTrue(recommendation["automatable_now"])
        self.assertIn("ACTION_SENSITIVE_ATOMIC_GAP", recommendation["reason_codes"])

        proposal, _digest = content_migrate._proposal(
            record,
            base,
            actor="codex",
            mode=content_migrate.RISK_V4_MODE,
        )
        self.assertIn("status: pending_verification\n", proposal)
        self.assertNotIn("verified_at:", proposal)
        self.assertIn("Current 2026-08-01.", proposal)

        payload = {
            "status": "warning",
            "summary": {"pass": 1, "warn": 1, "fail": 0},
            "checks": [{
                "name": "governance_metadata_v4",
                "status": "warn",
                "detail": detail,
            }],
        }
        base_digest = intent.content_hashes(base.encode("utf-8"))

        class FakeClient:
            actor = "codex"

            def doctor(self):
                return payload

            def write(self, action, request):
                if action != "read-target":
                    raise AssertionError(action)
                return {
                    "ok": True,
                    "status": "found",
                    "exists": True,
                    "scope_migration": False,
                    "target_relative_path": "项目/事实-owner.md",
                    "app_id": "agent-memory",
                    "project_id": "owner",
                    "content": base,
                    "read_token": "1" * 64,
                    "base_raw_sha256": base_digest.raw_sha256,
                    "base_canonical_sha256": base_digest.canonical_sha256,
                    "base_git_head": "2" * 40,
                }

        review = content_migrate.build_review(
            FakeClient(),
            mode=content_migrate.RISK_V4_MODE,
        )
        self.assertEqual(len(review["items"]), 1)
        self.assertEqual(review["items"][0]["migration_operation"], "status_transition")

    def test_risk_v4_quarantines_complete_expired_and_overdue_facts_without_gap_fields(self) -> None:
        today = dt.date.today()
        cases = {
            "项目/事实-expired.md": {
                "memory_id": "a" * 64,
                "policy": "expiring",
                "review_days": 90,
                "valid_from": (today - dt.timedelta(days=10)).isoformat(),
                "verified_at": today.isoformat(),
                "valid_until": (today - dt.timedelta(days=1)).isoformat(),
                "reason": "ACTION_SENSITIVE_EXPIRED",
            },
            "项目/事实-overdue.md": {
                "memory_id": "b" * 64,
                "policy": "reviewable",
                "review_days": 30,
                "valid_from": (today - dt.timedelta(days=120)).isoformat(),
                "verified_at": (today - dt.timedelta(days=120)).isoformat(),
                "valid_until": "",
                "reason": "ACTION_SENSITIVE_REVIEW_OVERDUE",
            },
        }
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw)
            source: dict[str, str] = {}
            digests: dict[str, intent.ContentDigest] = {}
            with contextlib.closing(sqlite3.connect(":memory:")) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute(
                    """
                    CREATE TABLE memory_write_receipts(
                      writer_protocol_version INTEGER,
                      target_rel_path TEXT,
                      outcome TEXT,
                      final_raw_sha256 TEXT,
                      git_commit TEXT,
                      source_class TEXT,
                      knowledge_kind TEXT,
                      asserted_by_sha256 TEXT,
                      safety_decision TEXT,
                      evidence_ref_sha256 TEXT,
                      created_at TEXT
                    )
                    """
                )
                for index, (rel_path, case) in enumerate(cases.items(), 1):
                    target = vault / rel_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    valid_until = (
                        f"valid_until: {case['valid_until']}\n"
                        if case["valid_until"]
                        else "valid_until: \"\"\n"
                    )
                    text = (
                        f"---\nmemory_id: {case['memory_id']}\n"
                        "memory_type: project\ntrack: project\nstatus: active\n"
                        "agent_scope: shared\napp_id: agent-memory\n"
                        "project_id: temporal\nrisk_class: action_sensitive\n"
                        f"temporal_policy: {case['policy']}\n"
                        f"review_after_days: {case['review_days']}\n"
                        f"fact_key: project.temporal.{index}\n"
                        f"valid_from: {case['valid_from']}\n"
                        f"{valid_until}verified_at: {case['verified_at']}\n"
                        "---\n# Temporal fact\n"
                    )
                    target.write_text(text, encoding="utf-8")
                    source[rel_path] = text
                    digest = intent.content_hashes(text.encode("utf-8"))
                    digests[rel_path] = digest
                    conn.execute(
                        "INSERT INTO memory_write_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            2,
                            rel_path,
                            "completed",
                            digest.raw_sha256,
                            "c" * 40,
                            "user_direct",
                            "fact",
                            "d" * 64,
                            "ALLOW",
                            "e" * 64,
                            "2026-08-25T00:00:00+00:00",
                        ),
                    )
                with mock.patch.object(
                    memory_doctor, "VAULT_ROOT", vault
                ), mock.patch.object(memory_index, "VAULT_ROOT", vault):
                    detail = memory_doctor.governance_metadata_migration_health(conn)

            records = {
                item["target_relative_path"]: item
                for item in detail["risk_migration_query"]
            }
            self.assertEqual(set(records), set(cases))
            for rel_path, case in cases.items():
                record = records[rel_path]
                self.assertEqual(record["atomic_fact_gap_fields"], [])
                recommendation = record["risk_recommendation"]
                self.assertEqual(
                    recommendation["reason_codes"],
                    [case["reason"]],
                )
                self.assertEqual(
                    recommendation["followup_operation"],
                    "status_transition",
                )
                self.assertTrue(recommendation["automatable_now"])
                proposal, _digest = content_migrate._proposal(
                    record,
                    source[rel_path],
                    actor="codex",
                    mode=content_migrate.RISK_V4_MODE,
                )
                self.assertIn("status: pending_verification\n", proposal)
                prepared = content_migrate._prepare_request(
                    record,
                    {"read_token": "1" * 64},
                    proposal,
                    "2" * 64,
                    mode=content_migrate.RISK_V4_MODE,
                )
                self.assertEqual(prepared["knowledge_kind"], "fact")
                self.assertEqual(prepared["operation"], "status_transition")
                self.assertEqual(prepared["target_status"], "pending_verification")

            payload = {
                "status": "warning",
                "summary": {"pass": 1, "warn": 1, "fail": 0},
                "checks": [{
                    "name": "governance_metadata_v4",
                    "status": "warn",
                    "detail": detail,
                }],
            }

            class FakeClient:
                actor = "codex"

                def doctor(self):
                    return payload

                def write(self, action, request):
                    if action != "read-target":
                        raise AssertionError(action)
                    rel_path = request["target_relative_path"]
                    digest = digests[rel_path]
                    return {
                        "ok": True,
                        "status": "found",
                        "exists": True,
                        "scope_migration": False,
                        "target_relative_path": rel_path,
                        "app_id": "agent-memory",
                        "project_id": "temporal",
                        "content": source[rel_path],
                        "read_token": "1" * 64,
                        "base_raw_sha256": digest.raw_sha256,
                        "base_canonical_sha256": digest.canonical_sha256,
                        "base_git_head": "2" * 40,
                    }

            review = content_migrate.build_review(
                FakeClient(),
                mode=content_migrate.RISK_V4_MODE,
            )
            self.assertEqual(len(review["items"]), 2)
            self.assertTrue(all(
                item["migration_operation"] == "status_transition"
                and item["target_status"] == "pending_verification"
                for item in review["items"]
            ))

    def test_json_review_parser_rejects_duplicate_keys_and_nonfinite_numbers(self) -> None:
        for payload in ('{"actor":"codex","actor":"claude"}', '{"value":NaN}'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                content_migrate.strict_json_loads(payload)

    def test_query_normalization_binds_every_scope_field(self) -> None:
        item = query_item()
        normalized = content_migrate.normalize_doctor_query(doctor([item]), require_all_automatable=True)
        self.assertEqual(normalized["automatable_documents"], 1)
        self.assertEqual(normalized["migration_query"][0]["requested_project_id"], "example")
        self.assertEqual(
            normalized["migration_query_sha256"],
            content_migrate.canonical_sha256(normalized["migration_query"]),
        )
        changed = json.loads(json.dumps(normalized["migration_query"]))
        changed[0]["requested_app_id"] = "codex"
        self.assertNotEqual(content_migrate.canonical_sha256(changed), normalized["migration_query_sha256"])

    def test_query_rejects_nonautomatable_unsafe_and_duplicate_targets(self) -> None:
        cases = (
            doctor([query_item(automatable=False)]),
            doctor([query_item()], unsafe=["项目/unsafe.md"]),
            doctor([query_item(), query_item()]),
        )
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(content_migrate.ContentMigrationError):
                content_migrate.normalize_doctor_query(payload, require_all_automatable=True)

    def test_doctor_allows_only_the_scope_migration_failure(self) -> None:
        payload = doctor([query_item()])
        binding = content_migrate.normalize_doctor_query(payload, require_all_automatable=True)
        content_migrate.assert_doctor_migration_safe(payload, binding)
        payload["checks"].append({"name": "runtime_integrity", "status": "fail"})
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate.assert_doctor_migration_safe(payload, binding)

    def test_governance_allows_live_temporal_gap_owned_by_automatic_risk_lane(self) -> None:
        target = "项目/Ailu事实-插件ID.md"
        payload = governance_doctor_with_temporal_failure([target])
        binding = {
            "migration_candidate_documents": 0,
            "risk_candidate_documents": 1,
            "migration_query": [],
            "risk_migration_query": [safe_risk_record(target)],
            # The metadata assessment may still require manual review while an
            # independent safe risk quarantine remains automatic.
            "manual_review_queue": [{"target_relative_path": target}],
            "unsafe_documents": [],
        }
        content_migrate.assert_doctor_migration_safe(
            payload,
            binding,
            mode=content_migrate.GOVERNANCE_V4_MODE,
        )

    def test_missing_fact_key_with_zero_fact_records_is_migration_scoped(self) -> None:
        target = "项目/Ailu事实-插件ID.md"
        payload = governance_doctor_with_missing_fact_key(target)
        binding = {
            "migration_candidate_documents": 0,
            "risk_candidate_documents": 1,
            "migration_query": [],
            "risk_migration_query": [safe_risk_record(target)],
            "manual_review_queue": [{"target_relative_path": target}],
            "unsafe_documents": [],
        }
        for mode in (
            content_migrate.GOVERNANCE_V4_MODE,
            content_migrate.RISK_V4_MODE,
        ):
            with self.subTest(mode=mode):
                content_migrate.assert_doctor_migration_safe(
                    payload,
                    binding,
                    mode=mode,
                )

    def test_governance_rejects_mixed_or_manual_only_temporal_gaps(self) -> None:
        target = "项目/Ailu事实-插件ID.md"
        outsider = "项目/Outside.md"
        safe_binding = {
            "migration_candidate_documents": 0,
            "risk_candidate_documents": 1,
            "migration_query": [],
            "risk_migration_query": [safe_risk_record(target)],
            "manual_review_queue": [],
            "unsafe_documents": [],
        }
        mixed = governance_doctor_with_temporal_failure([target, outsider])
        with self.assertRaises(content_migrate.ContentMigrationError) as caught:
            content_migrate.assert_doctor_migration_safe(
                mixed,
                safe_binding,
                mode=content_migrate.GOVERNANCE_V4_MODE,
            )
        self.assertEqual(caught.exception.reason_code, "DOCTOR_UNRELATED_FAILURE")

        manual_only = governance_doctor_with_temporal_failure([target])
        manual_binding = {
            **safe_binding,
            "risk_candidate_documents": 0,
            "risk_migration_query": [{
                "target_relative_path": target,
                "risk_recommendation": {
                    **safe_risk_record(target)["risk_recommendation"],
                    "automatable_now": False,
                    "manual_review_required": True,
                },
            }],
            "manual_review_queue": [{"target_relative_path": target}],
        }
        with self.assertRaises(content_migrate.ContentMigrationError) as manual:
            content_migrate.assert_doctor_migration_safe(
                manual_only,
                manual_binding,
                mode=content_migrate.GOVERNANCE_V4_MODE,
            )
        self.assertEqual(manual.exception.reason_code, "DOCTOR_UNRELATED_FAILURE")

        unsafe_binding = {
            **safe_binding,
            "unsafe_documents": [target],
        }
        with self.assertRaises(content_migrate.ContentMigrationError) as unsafe:
            content_migrate.assert_doctor_migration_safe(
                manual_only,
                unsafe_binding,
                mode=content_migrate.GOVERNANCE_V4_MODE,
            )
        self.assertEqual(unsafe.exception.reason_code, "DOCTOR_UNRELATED_FAILURE")

    def test_temporal_failure_detail_must_be_complete_and_canonical(self) -> None:
        target = "项目/Ailu事实-插件ID.md"
        binding = {
            "migration_candidate_documents": 1,
            "risk_candidate_documents": 0,
            "migration_query": [{
                "target_relative_path": target,
                "automatable": True,
            }],
            "risk_migration_query": [],
            "manual_review_queue": [],
            "unsafe_documents": [],
        }
        valid = governance_doctor_with_temporal_failure([target])
        content_migrate.assert_doctor_migration_safe(
            valid,
            binding,
            mode=content_migrate.GOVERNANCE_V4_MODE,
        )
        malformed_checks = []
        missing_detail = json.loads(json.dumps(valid))
        missing_detail["checks"][1].pop("detail")
        malformed_checks.append(missing_detail)
        empty_uncovered = json.loads(json.dumps(valid))
        empty_uncovered["checks"][1]["detail"]["uncovered"] = []
        empty_uncovered["checks"][1]["detail"]["gap_details"] = []
        malformed_checks.append(empty_uncovered)
        missing_gap = json.loads(json.dumps(valid))
        missing_gap["checks"][1]["detail"]["gap_details"] = []
        malformed_checks.append(missing_gap)
        extra_field = json.loads(json.dumps(valid))
        extra_field["checks"][1]["detail"]["unexpected"] = True
        malformed_checks.append(extra_field)
        for invalid_fact_records in (-1, True, "0"):
            malformed_fact_records = json.loads(json.dumps(valid))
            malformed_fact_records["checks"][1]["detail"][
                "fact_records"
            ] = invalid_fact_records
            malformed_checks.append(malformed_fact_records)
        for payload in malformed_checks:
            with self.subTest(payload=payload), self.assertRaises(
                content_migrate.ContentMigrationError
            ) as caught:
                content_migrate.assert_doctor_migration_safe(
                    payload,
                    binding,
                    mode=content_migrate.GOVERNANCE_V4_MODE,
                )
            self.assertEqual(
                caught.exception.reason_code,
                "DOCTOR_UNRELATED_FAILURE",
            )

    def test_risk_mode_allows_only_safe_automatic_temporal_followup(self) -> None:
        target = "项目/Ailu事实-插件ID.md"
        payload = governance_doctor_with_temporal_failure([target])
        safe_binding = {
            "migration_candidate_documents": 0,
            "risk_candidate_documents": 1,
            "migration_query": [safe_risk_record(target)],
            "risk_migration_query": [safe_risk_record(target)],
            "manual_review_queue": [],
            "unsafe_documents": [],
        }
        content_migrate.assert_doctor_migration_safe(
            payload,
            safe_binding,
            mode=content_migrate.RISK_V4_MODE,
        )

        unsafe_record = safe_risk_record(target)
        unsafe_record["risk_recommendation"] = {
            **unsafe_record["risk_recommendation"],
            "reason_codes": ["UNSUPPORTED_RISK_REASON"],
        }
        unsafe_binding = {
            **safe_binding,
            "migration_query": [unsafe_record],
            "risk_migration_query": [unsafe_record],
        }
        with self.assertRaises(content_migrate.ContentMigrationError) as caught:
            content_migrate.assert_doctor_migration_safe(
                payload,
                unsafe_binding,
                mode=content_migrate.RISK_V4_MODE,
            )
        self.assertEqual(caught.exception.reason_code, "DOCTOR_UNRELATED_FAILURE")

    def test_governance_final_temporal_failure_requires_risk_followup(self) -> None:
        target = "项目/Ailu事实-插件ID.md"
        complete_binding = {
            "migration_candidate_documents": 0,
            "risk_candidate_documents": 1,
            "migration_query": [],
            "risk_migration_query": [safe_risk_record(target)],
            "manual_review_queue": [{"target_relative_path": target}],
            "manual_review_documents": 1,
            "unassigned_manual_review_count": 0,
            "unsafe_documents": [],
        }
        projected_binding = {
            **complete_binding,
            "migration_query": [],
            "automatable_documents": 0,
        }
        review = {
            "mode": content_migrate.GOVERNANCE_V4_MODE,
            "initial_git_head": "",
            "doctor_binding": projected_binding,
            "items": [],
        }
        for drifted_envelope in (False, True):
            with self.subTest(drifted_envelope=drifted_envelope):
                payload = governance_doctor_with_missing_fact_key(target)
                if drifted_envelope:
                    # Reproduce a drifted Doctor envelope: final readiness must
                    # inspect checks instead of trusting aggregate fields.
                    payload["status"] = "warning"
                    payload["summary"]["fail"] = 0
                client = mock.Mock(actor="codex")
                client.doctor.return_value = payload
                with mock.patch.object(
                    content_migrate,
                    "normalize_and_project_query_for_actor",
                    return_value=(complete_binding, projected_binding),
                ), mock.patch.object(
                    content_migrate,
                    "compare_current_query",
                    return_value=set(),
                ), mock.patch.object(
                    content_migrate,
                    "load_progress",
                    return_value=[progress_header()],
                ):
                    result = content_migrate._run_apply(
                        client,
                        review,
                        review_sha256="7" * 64,
                        progress_path=mock.Mock(),
                    )
                self.assertFalse(result["ok"])
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(
                    result["reason_code"],
                    "FINAL_GOVERNANCE_MIGRATION_INCOMPLETE",
                )
                self.assertEqual(client.doctor.call_count, 2)

    def test_review_validation_rejects_scope_or_hash_tampering(self) -> None:
        review = review_for([query_item()])
        self.assertEqual(content_migrate.validate_review(review)["actor"], "codex")
        for key, value in (("requested_app_id", "other"), ("proposal_raw_sha256", "x" * 64)):
            changed = json.loads(json.dumps(review))
            changed["items"][0][key] = value
            with self.subTest(key=key), self.assertRaises(content_migrate.ContentMigrationError):
                content_migrate.validate_review(changed)

        changed = json.loads(json.dumps(review))
        changed["initial_git_head"] = "9" * 40
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate.validate_review(changed)

    def test_review_validation_rejects_rehashed_query_or_duplicate_items(self) -> None:
        review = review_for([query_item("项目/a.md"), query_item("项目/b.md")])
        changed = json.loads(json.dumps(review))
        changed["doctor_binding"]["migration_query"][0]["requested_project_id"] = "tampered"
        changed["doctor_binding"]["migration_query_sha256"] = content_migrate.canonical_sha256(
            changed["doctor_binding"]["migration_query"]
        )
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate.validate_review(changed)

        changed = json.loads(json.dumps(review))
        changed["items"][1] = json.loads(json.dumps(changed["items"][0]))
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate.validate_review(changed)

    def test_current_query_may_only_shrink_without_scope_change(self) -> None:
        first, second = query_item("项目/a.md"), query_item("项目/b.md")
        review = review_for([first, second])
        current = content_migrate.normalize_doctor_query(doctor([second]), require_all_automatable=True)
        self.assertEqual(content_migrate.compare_current_query(review, current), {"项目/a.md"})
        changed = query_item("项目/b.md")
        changed["requested_project_id"] = "other"
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate.compare_current_query(
                review,
                content_migrate.normalize_doctor_query(doctor([changed]), require_all_automatable=True),
            )

    def test_read_and_prepare_payloads_use_only_explicit_query_scope(self) -> None:
        record = query_item()
        read = content_migrate.migration_read_request(record)
        self.assertEqual(read, {
            "schema_version": 2,
            "target_relative_path": "项目/example.md",
            "app_id": "agent-memory",
            "project_id": "example",
            "migrate_legacy_scope": True,
            "legacy_scope_app_id": "agent-memory",
        })
        prepared = content_migrate._prepare_request(
            record,
            {"read_token": "1" * 64},
            "proposal",
            "2" * 64,
        )
        self.assertEqual(prepared["read_token"], "1" * 64)
        self.assertEqual(prepared["proposal_markdown"], "proposal")
        self.assertTrue(prepared["migrate_legacy_scope"])

    def test_progress_state_requires_prepared_before_completed(self) -> None:
        review = review_for([query_item()])
        header = progress_header()
        prepared = prepared_event()
        completed = completed_event()
        state = content_migrate.progress_state([header, prepared, completed], review)
        self.assertEqual(state["项目/example.md"]["event"], "completed")
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate.progress_state([header, completed], review)

    def test_progress_state_is_a_completed_prefix_plus_one_prepared_item(self) -> None:
        review = review_for([query_item("项目/a.md"), query_item("项目/b.md")])
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate.progress_state(
                [progress_header(), prepared_event("项目/b.md")],
                review,
            )
        first_prepared = prepared_event("项目/a.md")
        first_completed = completed_event("项目/a.md", commit="8" * 40)
        second_prepared = prepared_event("项目/b.md", head="8" * 40)
        state = content_migrate.progress_state(
            [progress_header(), first_prepared, first_completed, second_prepared],
            review,
        )
        self.assertEqual(state["项目/b.md"]["event"], "prepared")
        changed = json.loads(json.dumps(second_prepared))
        changed["base_git_head"] = "9" * 40
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate.progress_state(
                [progress_header(), first_prepared, first_completed, changed],
                review,
            )

    def test_append_progress_partial_candidate_never_corrupts_journal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            if sys.platform != "win32":
                root.chmod(0o700)
            progress = root / "review.progress.jsonl"
            original = (
                content_migrate.canonical_bytes(progress_header()) + b"\n"
            )
            content_migrate.write_private_exclusive(progress, original)

            def partial_then_crash(candidate, payload):
                candidate.write_bytes(payload[: max(1, len(payload) // 2)])
                if sys.platform != "win32":
                    candidate.chmod(0o600)
                raise OSError("simulated partial candidate write")

            with mock.patch.object(
                content_migrate,
                "_write_progress_candidate",
                side_effect=partial_then_crash,
            ), self.assertRaises(
                content_migrate.ContentMigrationError
            ) as crashed:
                content_migrate.append_progress(
                    progress,
                    prepared_event(),
                )
            self.assertEqual(
                crashed.exception.reason_code,
                "PROGRESS_APPEND_FAILED",
            )
            self.assertEqual(progress.read_bytes(), original)
            self.assertEqual(
                content_migrate.load_progress(
                    progress,
                    review_sha256="7" * 64,
                    actor="codex",
                ),
                [progress_header()],
            )

            partial_tail = original + b'{"event":"prepared"'
            progress.write_bytes(partial_tail)
            if sys.platform != "win32":
                progress.chmod(0o600)
            with self.assertRaises(
                content_migrate.ContentMigrationError
            ) as invalid:
                content_migrate.append_progress(
                    progress,
                    prepared_event(),
                )
            self.assertEqual(invalid.exception.reason_code, "PROGRESS_INVALID")
            self.assertEqual(progress.read_bytes(), partial_tail)

    def test_append_progress_fails_closed_on_inode_or_byte_cas_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            if sys.platform != "win32":
                root.chmod(0o700)
            progress = root / "review.progress.jsonl"
            original = (
                content_migrate.canonical_bytes(progress_header()) + b"\n"
            )
            drifted = (
                original
                + content_migrate.canonical_bytes(prepared_event())
                + b"\n"
            )
            content_migrate.write_private_exclusive(progress, original)
            write_candidate = content_migrate._write_progress_candidate

            def stage_then_drift(candidate, payload):
                write_candidate(candidate, payload)
                progress.write_bytes(drifted)
                if sys.platform != "win32":
                    progress.chmod(0o600)

            with mock.patch.object(
                content_migrate,
                "_write_progress_candidate",
                side_effect=stage_then_drift,
            ), self.assertRaises(
                content_migrate.ContentMigrationError
            ) as changed:
                content_migrate.append_progress(
                    progress,
                    prepared_event(),
                )
            self.assertEqual(changed.exception.reason_code, "PROGRESS_CHANGED")
            self.assertEqual(progress.read_bytes(), drifted)

    def test_progress_directory_fsync_is_skipped_on_windows(self) -> None:
        path = Path("progress-parent")
        with mock.patch.object(content_migrate.os, "name", "nt"), mock.patch.object(
            content_migrate.os,
            "open",
            side_effect=AssertionError("must not open a directory on Windows"),
        ):
            content_migrate._fsync_progress_directory(path)

    def test_append_progress_post_publish_fsync_failure_is_complete_and_resumable(self) -> None:
        review = review_for([query_item()])
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            if sys.platform != "win32":
                root.chmod(0o700)
            progress = root / "review.progress.jsonl"
            initial_events = [progress_header(), prepared_event()]
            original = b"".join(
                content_migrate.canonical_bytes(event) + b"\n"
                for event in initial_events
            )
            content_migrate.write_private_exclusive(progress, original)
            with mock.patch.object(
                content_migrate,
                "_fsync_progress_directory",
                side_effect=OSError("simulated directory fsync crash"),
            ), self.assertRaises(
                content_migrate.ContentMigrationError
            ) as crashed:
                content_migrate.append_progress(
                    progress,
                    completed_event(),
                )
            self.assertEqual(
                crashed.exception.reason_code,
                "PROGRESS_APPEND_FAILED",
            )
            self.assertTrue(progress.read_bytes().endswith(b"\n"))
            recovered_events = content_migrate.load_progress(
                progress,
                review_sha256="7" * 64,
                actor="codex",
            )
            recovered_state = content_migrate.progress_state(
                recovered_events,
                review,
            )
            self.assertEqual(
                recovered_state["项目/example.md"]["event"],
                "completed",
            )

    def test_plan_builds_review_from_memoryctl_only_and_rechecks_doctor(self) -> None:
        item = query_item()
        base = "---\nstatus: active\nagent_scope: shared\n---\n# Body\n"
        base_digest = intent.content_hashes(base.encode())

        class FakeClient:
            actor = "codex"
            calls: list[str] = []

            def doctor(self):
                self.calls.append("doctor")
                return doctor([item])

            def write(self, action, request):
                self.calls.append(action)
                self.assert_request = request
                return {
                    "ok": True, "status": "found", "exists": True,
                    "scope_migration": True,
                    "target_relative_path": "项目/example.md",
                    "app_id": "agent-memory", "project_id": "example",
                    "content": base,
                    "read_token": "1" * 64,
                    "base_raw_sha256": base_digest.raw_sha256,
                    "base_canonical_sha256": base_digest.canonical_sha256,
                    "base_git_head": "2" * 40,
                }

        client = FakeClient()
        review = content_migrate.build_review(client)
        self.assertEqual(client.calls, ["doctor", "read-target", "doctor"])
        self.assertEqual(len(review["items"]), 1)
        self.assertEqual(review["initial_git_head"], "2" * 40)

    def test_apply_cli_requires_review_file_but_cannot_self_declare_user_confirmation(self) -> None:
        with self.assertRaises(SystemExit):
            content_migrate.parse_args(["apply"])
        with self.assertRaises(SystemExit):
            content_migrate.parse_args([
                "apply", "--review-file", "/private/review.json", "--confirmed-by", "codex",
            ])
        parsed = content_migrate.parse_args([
            "apply", "--review-file", "/private/review.json",
        ])
        self.assertEqual(parsed.review_file, "/private/review.json")
        self.assertFalse(hasattr(parsed, "confirmed_by"))

    def test_memoryctl_children_do_not_inherit_confirmation_bearer_environment(self) -> None:
        completed = mock.Mock(returncode=0, stdout='{"ok":true}', stderr="")
        client = content_migrate.MemoryctlClient(actor="codex", session_id="session-1")
        with mock.patch.dict(
            content_migrate.os.environ,
            {
                content_migrate.CONFIRMATION_CAPABILITY_PATH_ENV: "/private/capability.json",
                content_migrate.CONFIRMATION_CAPABILITY_TOKEN_ENV: "secret-token",
            },
        ), mock.patch.object(content_migrate.subprocess, "run", return_value=completed) as invoked:
            payload = client._call(["doctor", "--json"])
        self.assertTrue(payload["ok"])
        child_environment = invoked.call_args.kwargs["env"]
        self.assertNotIn(content_migrate.CONFIRMATION_CAPABILITY_PATH_ENV, child_environment)
        self.assertNotIn(content_migrate.CONFIRMATION_CAPABILITY_TOKEN_ENV, child_environment)
        self.assertEqual(child_environment["AGENT_MEMORY_TASK_ID"], "session-1")

    def test_explicit_session_human_issuer_to_risk_apply_binding_e2e(self) -> None:
        session_id = "session-1"
        batch_confirmation = (
            "task:user-approved-agent-memory-vault-full-repair-2026-08-24"
        )
        proposal_id = "a" * 32
        proposal_raw_sha256 = "b" * 64
        proposal_canonical_sha256 = "c" * 64
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config_root = root / "config"
            vault = root / "vault"
            target = vault / "项目" / "Alpha.md"
            target.parent.mkdir(parents=True)
            target.write_text("---\nstatus: active\n---\n# Alpha\n", encoding="utf-8")
            with mock.patch.object(intent, "VAULT_ROOT", vault), mock.patch.object(
                write_gateway, "CONFIG_ROOT", config_root
            ):
                canonical = intent.canonical_target("项目/Alpha.md")
                stored = {
                    "intent_id": proposal_id,
                    "status": "pending",
                    "actor": "codex",
                    "session_hash": confirmation_capability.session_hash(session_id),
                    "proposal_raw_sha256": proposal_raw_sha256,
                    "proposal_canonical_sha256": proposal_canonical_sha256,
                    "target_rel_path": canonical.rel_path,
                    "target_key": canonical.target_key,
                    "operation": "content_update",
                    "reconcile_action": "UPDATE",
                    "fencing_token": 7,
                }
                with mock.patch.object(
                    intent,
                    "show_intent",
                    return_value={"intent": stored, "receipt": None},
                ):
                    public = confirmation_capability.issue_for_intent_handoff(
                        config_root,
                        issuer_actor="human",
                        subject_actor="codex",
                        raw_task_id=session_id,
                        raw_session_id=session_id,
                        proposal_id=proposal_id,
                        confirmation_reference=batch_confirmation,
                    )
                private = confirmation_capability.read_confirmation_handoff(
                    config_root,
                    handoff_path=str(public["handoff_path"]),
                )
                item = {
                    "target_relative_path": canonical.rel_path,
                    "proposal_raw_sha256": proposal_raw_sha256,
                    "proposal_canonical_sha256": proposal_canonical_sha256,
                }
                phase = {"proposal_id": proposal_id, "fencing_token": 7}
                client = content_migrate.MemoryctlClient(
                    actor="codex",
                    session_id=session_id,
                )
                approval_reference = (
                    content_migrate._consume_risk_content_update_confirmation(
                        client,
                        item=item,
                        phase=phase,
                        capability_path=str(private["capability_path"]),
                        capability_token=str(private["token"]),
                    )
                )
                apply_request = content_migrate._apply_request(
                    item,
                    phase,
                    "proposal",
                    confirmed_by="user",
                    confirmation_reference=approval_reference,
                )

            expected_reference_hash = hashlib.sha256(
                batch_confirmation.encode("utf-8")
            ).hexdigest()
            journal = json.loads(
                Path(str(public["capability_path"])).read_text(encoding="utf-8")
            )
            self.assertEqual(journal["status"], "consumed")
            self.assertEqual(
                journal["confirmation_reference_sha256"],
                expected_reference_hash,
            )
            self.assertEqual(apply_request["confirmed_by"], "user")
            self.assertIn(expected_reference_hash, apply_request["confirmation_reference"])
            self.assertNotIn(batch_confirmation, apply_request["confirmation_reference"])
            self.assertNotIn("confirmation_capability_path", apply_request)
            self.assertNotIn("confirmation_capability_token", apply_request)
            self.assertNotIn(str(private["token"]), json.dumps(apply_request))

    def test_prepare_cli_never_enables_apply_phase(self) -> None:
        review = {"mode": content_migrate.RISK_V4_MODE}
        raw = b"{}\n"
        output_buffer = io.StringIO()
        with mock.patch.object(
            content_migrate,
            "_load_review_for_cli",
            return_value=(review, raw, Path("/private/review.json")),
        ), mock.patch.object(content_migrate, "MemoryctlClient"), mock.patch.object(
            content_migrate,
            "run_apply",
            return_value={"ok": False, "status": "confirmation_required"},
        ) as run, contextlib.redirect_stdout(output_buffer):
            output = content_migrate.main(
                [
                    "--session-id", "session-1", "--json", "prepare",
                    "--review-file", "/private/review.json",
                ]
            )
        self.assertEqual(output, 2)
        self.assertFalse(run.call_args.kwargs["allow_apply"])

    def test_completed_recovery_replan_scrubs_handoff_in_outer_cli(self) -> None:
        review = review_for([query_item()])
        raw = b"{}\n"
        token = "consumed-secret-token"
        handoff = {
            "status": "issued",
            "token": token,
            "capability_path": "/private/capability.json",
            "handoff_path": "/private/handoff.json",
            "capability_id": "c" * 32,
            "consumed_recovery": True,
            "intent_status": "completed",
        }
        recovered = {
            "schema_version": 1,
            "ok": False,
            "status": "replan_required",
            "reason_code": "COMPLETED_RECOVERY_REPLAN_REQUIRED",
            "items": [{
                "target_relative_path": "项目/example.md",
                "status": "applied",
                "idempotent": True,
            }],
        }
        output_buffer = io.StringIO()
        with mock.patch.object(
            content_migrate,
            "_load_review_for_cli",
            return_value=(review, raw, Path("/private/review.json")),
        ), mock.patch.object(
            content_migrate,
            "_read_apply_request",
            return_value={
                "schema_version": 1,
                "confirmation_handoff_path": handoff["handoff_path"],
            },
        ), mock.patch.object(
            content_migrate,
            "_read_confirmation_handoff_for_apply",
            return_value=handoff,
        ), mock.patch.object(
            content_migrate,
            "MemoryctlClient",
        ), mock.patch.object(
            content_migrate,
            "run_apply",
            return_value=recovered,
        ) as run, mock.patch.object(
            confirmation_capability,
            "mark_confirmation_handoff_consumed",
        ) as scrubbed, contextlib.redirect_stdout(output_buffer):
            return_code = content_migrate.main([
                "--session-id",
                "session-1",
                "--json",
                "apply",
                "--review-file",
                "/private/review.json",
            ])

        self.assertEqual(return_code, 2)
        self.assertEqual(run.call_args.kwargs["confirmation_handoff"], handoff)
        scrubbed.assert_called_once_with(
            write_gateway.CONFIG_ROOT,
            handoff_path=handoff["handoff_path"],
            capability_id=handoff["capability_id"],
        )
        self.assertNotIn(token, output_buffer.getvalue())

    def test_apply_request_binds_review_proposal_intent_and_fence(self) -> None:
        item = review_for([query_item()])["items"][0]
        request = content_migrate._apply_request(
            item,
            {"proposal_id": "a" * 32, "fencing_token": 7},
            "proposal",
            confirmation_capability_path="/private/capability.json",
            confirmation_capability_token="secret-token",
        )
        self.assertEqual(request["proposal_id"], "a" * 32)
        self.assertEqual(request["fencing_token"], 7)
        self.assertEqual(request["proposal_raw_sha256"], "5" * 64)
        self.assertNotIn("confirmed_by", request)
        self.assertNotIn("confirmation_reference", request)
        self.assertEqual(request["confirmation_capability_path"], "/private/capability.json")
        self.assertEqual(request["confirmation_capability_token"], "secret-token")
        with self.assertRaises(content_migrate.ContentMigrationError) as caught:
            content_migrate._apply_request(
                item,
                {"proposal_id": "a" * 32, "fencing_token": 7},
                "proposal",
                confirmation_capability_path="/private/capability.json",
            )
        self.assertEqual(caught.exception.reason_code, "CONFIRMATION_CAPABILITY_INVALID")

    def test_prepare_and_apply_responses_bind_all_gateway_evidence(self) -> None:
        item = review_for([query_item()])["items"][0]
        read = {
            "base_raw_sha256": item["base_raw_sha256"],
            "base_canonical_sha256": item["base_canonical_sha256"],
            "base_git_head": item["base_git_head"],
        }
        prepared = {
            "status": "prepared",
            "recommended_action": "MIGRATE_LEGACY_SCOPE",
            "target_relative_path": item["target_relative_path"],
            "scope_migration": True,
            "confirmation_required": True,
            "proposal_id": "a" * 32,
            "fencing_token": 7,
            "base_raw_sha256": item["base_raw_sha256"],
            "base_canonical_sha256": item["base_canonical_sha256"],
            "base_git_head": item["base_git_head"],
            "proposal_raw_sha256": item["proposal_raw_sha256"],
            "proposal_canonical_sha256": item["proposal_canonical_sha256"],
            "proposal_size_bytes": item["proposal_size_bytes"],
        }
        phase = content_migrate._validated_prepared_phase(prepared, item=item, read=read)
        applied = {
            "status": "applied",
            "recommended_action": "MIGRATE_LEGACY_SCOPE",
            "target_relative_path": item["target_relative_path"],
            "scope_migration": True,
            "proposal_id": "a" * 32,
            "fencing_token": 7,
            "proposal_raw_sha256": item["proposal_raw_sha256"],
            "proposal_canonical_sha256": item["proposal_canonical_sha256"],
            "git_commit": "8" * 40,
            "receipt_id": "b" * 32,
            "idempotent": False,
        }
        completed = content_migrate._validated_apply_response(applied, item=item, phase=phase)
        self.assertEqual(completed["git_commit"], "8" * 40)
        changed = dict(applied, proposal_id="c" * 32)
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate._validated_apply_response(changed, item=item, phase=phase)

    def test_interrupted_apply_resumes_same_intent_idempotently(self) -> None:
        record = query_item()
        base = "---\nstatus: active\nagent_scope: shared\n---\n# Body\n"
        proposal, proposal_digest = content_migrate._proposal(record, base, actor="codex")
        base_digest = intent.content_hashes(base.encode())
        review = review_for([record])
        review["items"][0].update({
            "base_raw_sha256": base_digest.raw_sha256,
            "base_canonical_sha256": base_digest.canonical_sha256,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "proposal_size_bytes": proposal_digest.size_bytes,
        })
        review = content_migrate.validate_review(review)
        prepared = prepared_event()
        commit = "8" * 40

        class FakeClient:
            actor = "codex"
            session_id = "session-1"

            def __init__(self):
                self.doctor_calls = 0
                self.actions = []

            def doctor(self):
                self.doctor_calls += 1
                return doctor([], fail=0)

            def write(self, action, request):
                self.actions.append(action)
                if action == "read-target":
                    return {
                        "ok": True, "status": "found", "exists": True,
                        "scope_migration": True,
                        "target_relative_path": "项目/example.md",
                        "app_id": "agent-memory", "project_id": "example",
                        "content": proposal,
                        "read_token": "1" * 64,
                        "base_raw_sha256": proposal_digest.raw_sha256,
                        "base_canonical_sha256": proposal_digest.canonical_sha256,
                        "base_git_head": commit,
                    }
                return {
                    "status": "applied",
                    "recommended_action": "MIGRATE_LEGACY_SCOPE",
                    "target_relative_path": "项目/example.md",
                    "scope_migration": True,
                    "proposal_id": "a" * 32,
                    "fencing_token": 7,
                    "proposal_raw_sha256": proposal_digest.raw_sha256,
                    "proposal_canonical_sha256": proposal_digest.canonical_sha256,
                    "git_commit": commit,
                    "receipt_id": "b" * 32,
                    "idempotent": True,
                }

        item = review["items"][0]
        recovered_handoff = {
            "status": "issued",
            "token": "already-consumed-one-shot-token",
            "capability_path": "/private/capability.json",
            "handoff_path": "/private/handoff.json",
            "capability_id": "c" * 32,
            "consumed_recovery": True,
            "intent_status": "validated",
            "subject_actor": "codex",
            "task_hash": confirmation_capability.task_hash(
                "session-1",
                "codex",
            ),
            "session_hash": confirmation_capability.session_hash("session-1"),
            "proposal_id": "a" * 32,
            "proposal_raw_sha256": item["proposal_raw_sha256"],
            "proposal_canonical_sha256": item[
                "proposal_canonical_sha256"
            ],
            "target_relative_path": "项目/example.md",
            "target_key": "项目/example.md".casefold(),
            "operation": "content_update",
            "reconcile_action": "MIGRATE_LEGACY_SCOPE",
            "fencing_token": 7,
        }
        appended = []
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header(), prepared],
        ), mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.canonical_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            side_effect=[
                (True, base_digest),
                (True, proposal_digest),
            ],
        ), mock.patch.object(
            intent,
            "git_version_chain",
            return_value={
                "ok": True,
                "reason_code": "",
                "versions": [{
                    "commit": commit,
                    "exists": True,
                    "raw_sha256": proposal_digest.raw_sha256,
                    "canonical_sha256": proposal_digest.canonical_sha256,
                }],
            },
        ):
            result = content_migrate.run_apply(
                FakeClient(),
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path=str(
                    recovered_handoff["capability_path"]
                ),
                confirmation_capability_token=str(recovered_handoff["token"]),
                confirmation_handoff=recovered_handoff,
                append=lambda _path, event: appended.append(event),
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["items"][0]["status"], "applied")
        self.assertTrue(result["items"][0]["idempotent"])
        self.assertEqual([event["event"] for event in appended], ["completed"])

    def _completed_recovery_fixture(
        self,
        *,
        idempotent: bool = True,
        post_read_content: str | None = None,
        current_head: str = "9" * 40,
        receipt_commit: str = "8" * 40,
    ):
        record = query_item()
        base = "---\nstatus: active\nagent_scope: shared\n---\n# Body\n"
        proposal, proposal_digest = content_migrate._proposal(
            record,
            base,
            actor="codex",
        )
        base_digest = intent.content_hashes(base.encode())
        review = review_for([record])
        review["items"][0].update({
            "base_raw_sha256": base_digest.raw_sha256,
            "base_canonical_sha256": base_digest.canonical_sha256,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "proposal_size_bytes": proposal_digest.size_bytes,
        })
        review = content_migrate.validate_review(review)
        item = review["items"][0]

        class FakeClient:
            actor = "codex"
            session_id = "session-1"

            def __init__(self):
                self.actions: list[str] = []
                self.apply_requests: list[dict[str, object]] = []
                self.read_count = 0

            def doctor(self):
                return doctor([], fail=0)

            def write(self, action, request):
                self.actions.append(action)
                if action == "read-target":
                    self.read_count += 1
                    content = (
                        proposal
                        if self.read_count == 1 or post_read_content is None
                        else post_read_content
                    )
                    digest = intent.content_hashes(content.encode("utf-8"))
                    return {
                        "ok": True,
                        "status": "found",
                        "exists": True,
                        "scope_migration": True,
                        "target_relative_path": "项目/example.md",
                        "app_id": "agent-memory",
                        "project_id": "example",
                        "content": content,
                        "read_token": "1" * 64,
                        "base_raw_sha256": digest.raw_sha256,
                        "base_canonical_sha256": digest.canonical_sha256,
                        "base_git_head": current_head,
                    }
                if action != "apply":
                    raise AssertionError(action)
                self.apply_requests.append(dict(request))
                return {
                    "status": "applied",
                    "recommended_action": "MIGRATE_LEGACY_SCOPE",
                    "target_relative_path": "项目/example.md",
                    "scope_migration": True,
                    "proposal_id": "a" * 32,
                    "fencing_token": 7,
                    "proposal_raw_sha256": proposal_digest.raw_sha256,
                    "proposal_canonical_sha256": (
                        proposal_digest.canonical_sha256
                    ),
                    "git_commit": receipt_commit,
                    "receipt_id": "b" * 32,
                    "idempotent": idempotent,
                }

        handoff = {
            "status": "issued",
            "token": "already-consumed-one-shot-token",
            "capability_path": "/private/capability.json",
            "handoff_path": "/private/handoff.json",
            "capability_id": "c" * 32,
            "consumed_recovery": True,
            "intent_status": "completed",
            "subject_actor": "codex",
            "task_hash": confirmation_capability.task_hash(
                "session-1",
                "codex",
            ),
            "session_hash": confirmation_capability.session_hash("session-1"),
            "proposal_id": "a" * 32,
            "proposal_raw_sha256": item["proposal_raw_sha256"],
            "proposal_canonical_sha256": item[
                "proposal_canonical_sha256"
            ],
            "target_relative_path": "项目/example.md",
            "target_key": "项目/example.md".casefold(),
            "operation": "content_update",
            "reconcile_action": "MIGRATE_LEGACY_SCOPE",
            "fencing_token": 7,
        }
        return (
            review,
            prepared_event(),
            handoff,
            FakeClient(),
            base,
            proposal_digest,
        )

    def test_completed_intent_recovery_appends_then_requires_replan(self) -> None:
        review, prepared, handoff, client, _base, proposal_digest = (
            self._completed_recovery_fixture()
        )
        appended = []
        canonical_target = mock.sentinel.canonical_target
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header(), prepared],
        ), mock.patch.object(
            content_migrate,
            "_assert_prepared_early_commit_git_projection",
        ), mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ) as ancestor, mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=canonical_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            return_value=(True, proposal_digest),
        ) as commit_digest, mock.patch.object(
            intent,
            "git_version_chain",
            return_value={"ok": True, "reason_code": "", "versions": []},
        ):
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path=str(
                    handoff["capability_path"]
                ),
                confirmation_capability_token=str(handoff["token"]),
                confirmation_handoff=handoff,
                append=lambda _path, event: appended.append(event),
            )

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "replan_required")
        self.assertEqual(
            result["reason_code"],
            "COMPLETED_RECOVERY_REPLAN_REQUIRED",
        )
        self.assertEqual(
            result["recovered_target_relative_path"],
            "项目/example.md",
        )
        self.assertEqual(result["items"][0]["status"], "applied")
        self.assertTrue(result["items"][0]["idempotent"])
        self.assertEqual([event["event"] for event in appended], ["completed"])
        self.assertEqual(client.actions, ["read-target", "apply", "read-target"])
        self.assertNotIn(
            "confirmation_capability_path",
            client.apply_requests[0],
        )
        self.assertNotIn(
            "confirmation_capability_token",
            client.apply_requests[0],
        )
        ancestor.assert_called_once_with("8" * 40, "9" * 40)
        self.assertEqual(
            commit_digest.call_args_list,
            [
                mock.call("8" * 40, canonical_target),
                mock.call("9" * 40, canonical_target),
            ],
        )

    def test_risk_v4_completed_recovery_reaches_real_writer_without_new_confirmation(self) -> None:
        review, prepared, handoff, _client, base, proposal_digest = (
            self._completed_recovery_fixture()
        )
        proposal, _ = content_migrate._proposal(
            query_item(),
            base,
            actor="codex",
        )
        review["mode"] = content_migrate.RISK_V4_MODE
        record = review["doctor_binding"]["migration_query"][0]
        record["requested_agent_scope"] = "shared"
        record["risk_recommendation"] = {
            "source_status": "active",
            "current": "",
            "recommended": "action_sensitive",
            "reason_codes": ["METADATA_RISK_CLASS_NOT_EXPLICIT"],
            "followup_operation": "content_update",
            "target_status": "",
            "automatable_after_governance": True,
            "automatable_now": True,
            "manual_review_required": False,
        }
        item = review["items"][0]
        item.update({
            "migration_operation": "content_update",
            "recommended_risk_class": "action_sensitive",
            "target_status": "",
            "confirmation_mode": "capability",
            "manual_review_required": False,
            "manual_review_reasons": ["METADATA_RISK_CLASS_NOT_EXPLICIT"],
        })
        handoff.update({
            "operation": "content_update",
            "reconcile_action": "UPDATE",
        })

        with tempfile.TemporaryDirectory() as raw:
            target_path = Path(raw) / "项目" / "example.md"
            target_path.parent.mkdir()
            target_path.write_text(proposal, encoding="utf-8")
            canonical_target = intent.CanonicalTarget(
                path=target_path,
                rel_path="项目/example.md",
                target_key="项目/example.md".casefold(),
            )
            stored_intent = {
                "intent_id": "a" * 32,
                "fencing_token": 7,
                "reconcile_action": "UPDATE",
                "operation": "content_update",
                "status": "completed",
                "target_rel_path": canonical_target.rel_path,
                "target_key": canonical_target.target_key,
                "proposal_raw_sha256": proposal_digest.raw_sha256,
                "proposal_canonical_sha256": (
                    proposal_digest.canonical_sha256
                ),
                "final_raw_sha256": proposal_digest.raw_sha256,
                "base_git_head": "4" * 40,
            }
            receipt = {
                "receipt_id": "b" * 32,
                "outcome": "completed",
                "git_commit": "8" * 40,
                "created_at": "2026-08-25T00:00:00+00:00",
            }

            class RiskWriterClient:
                actor = "codex"
                session_id = "session-1"

                def __init__(self):
                    self.apply_request = None

                def doctor(self):
                    return {"status": "warning", "summary": {"fail": 0}}

                def write(self, action, request):
                    if action == "read-target":
                        return {
                            "ok": True,
                            "status": "found",
                            "exists": True,
                            "scope_migration": False,
                            "target_relative_path": "项目/example.md",
                            "app_id": "agent-memory",
                            "project_id": "example",
                            "content": proposal,
                            "read_token": "1" * 64,
                            "base_raw_sha256": proposal_digest.raw_sha256,
                            "base_canonical_sha256": (
                                proposal_digest.canonical_sha256
                            ),
                            "base_git_head": "9" * 40,
                        }
                    if action != "apply":
                        raise AssertionError(action)
                    self.apply_request = dict(request)
                    return write_gateway._apply_locked(
                        request,
                        raw_session_id=self.session_id,
                    )["payload"]

            client = RiskWriterClient()
            appended = []
            with mock.patch.object(
                content_migrate,
                "progress_transaction_lock",
                return_value=contextlib.nullcontext(),
            ), mock.patch.object(
                content_migrate,
                "load_progress",
                return_value=[progress_header(), prepared],
            ), mock.patch.object(
                content_migrate,
                "normalize_and_project_query_for_actor",
                return_value=({}, {}),
            ), mock.patch.object(
                content_migrate,
                "assert_doctor_migration_safe",
            ), mock.patch.object(
                content_migrate,
                "compare_current_query",
                return_value={"项目/example.md"},
            ), mock.patch.object(
                content_migrate,
                "_assert_prepared_early_commit_git_projection",
            ), mock.patch.object(
                write_gateway,
                "ACTOR",
                "codex",
            ), mock.patch.object(
                write_gateway,
                "_authorized_intent",
                return_value=stored_intent,
            ), mock.patch.object(
                write_gateway,
                "_formal_target",
                return_value=canonical_target,
            ), mock.patch.object(
                write_gateway,
                "_intent_scope_binding",
                return_value=("agent-memory", "example"),
            ), mock.patch.object(
                write_gateway,
                "_validate_writer_markdown",
            ), mock.patch.object(
                write_gateway,
                "_validate_write_temporal_gate",
            ), mock.patch.object(
                write_gateway,
                "_has_conditional_recovery_sidecar",
                return_value=False,
            ), mock.patch.object(
                intent,
                "git_target_digest_at_commit",
                return_value=(True, proposal_digest),
            ), mock.patch.object(
                write_gateway,
                "_content_update_status",
            ), mock.patch.multiple(
                intent,
                show_intent=mock.Mock(
                    return_value={"intent": stored_intent, "receipt": receipt}
                ),
                verify_terminal_receipt=mock.Mock(
                    return_value={"verified": True, "git_blob_verified": True}
                ),
            ), mock.patch.object(
                write_gateway,
                "_target_digest",
                return_value=(True, proposal_digest),
            ), mock.patch.object(
                intent,
                "_git_is_ancestor",
                return_value=True,
            ), mock.patch.object(
                intent,
                "git_version_chain",
                return_value={"ok": True, "reason_code": "", "versions": []},
            ):
                result = content_migrate.run_apply(
                    client,
                    review,
                    review_sha256="7" * 64,
                    progress_path=mock.Mock(),
                    confirmation_capability_path=str(
                        handoff["capability_path"]
                    ),
                    confirmation_capability_token=str(handoff["token"]),
                    confirmation_handoff=handoff,
                    append=lambda _path, event: appended.append(event),
                )

        self.assertEqual(result["status"], "replan_required")
        self.assertEqual(len(appended), 1)
        self.assertNotIn("confirmed_by", client.apply_request)
        self.assertNotIn("confirmation_reference", client.apply_request)
        self.assertNotIn("confirmation_capability_path", client.apply_request)
        self.assertNotIn("confirmation_capability_token", client.apply_request)

    def test_completed_intent_recovery_rejects_non_idempotent_or_target_drift(self) -> None:
        cases = (
            (False, None, "COMPLETED_RECOVERY_RESPONSE_INVALID"),
            (
                True,
                "---\nstatus: active\nagent_scope: shared\n---\n# Changed\n",
                "COMPLETED_RECOVERY_TARGET_DRIFT",
            ),
        )
        for idempotent, post_content, reason_code in cases:
            with self.subTest(reason_code=reason_code):
                review, prepared, handoff, client, _base, _proposal_digest = (
                    self._completed_recovery_fixture(
                        idempotent=idempotent,
                        post_read_content=post_content,
                    )
                )
                appended = []
                progress_path = mock.Mock()
                progress_path.exists.return_value = True
                with mock.patch.object(
                    content_migrate,
                    "progress_transaction_lock",
                    return_value=contextlib.nullcontext(),
                ), mock.patch.object(
                    content_migrate,
                    "load_progress",
                    return_value=[progress_header(), prepared],
                ), mock.patch.object(
                    content_migrate,
                    "_assert_prepared_early_commit_git_projection",
                ), mock.patch.object(
                    intent,
                    "_git_is_ancestor",
                ) as ancestor:
                    result = content_migrate.run_apply(
                        client,
                        review,
                        review_sha256="7" * 64,
                        progress_path=progress_path,
                        confirmation_capability_path=str(
                            handoff["capability_path"]
                        ),
                        confirmation_capability_token=str(handoff["token"]),
                        confirmation_handoff=handoff,
                        append=lambda _path, event: appended.append(event),
                    )
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["reason_code"], reason_code)
                self.assertEqual(appended, [])
                ancestor.assert_not_called()

    def test_completed_intent_recovery_rejects_sibling_or_rewritten_history(self) -> None:
        review, prepared, handoff, client, _base, _proposal_digest = (
            self._completed_recovery_fixture()
        )
        appended = []
        progress_path = mock.Mock()
        progress_path.exists.return_value = True
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header(), prepared],
        ), mock.patch.object(
            content_migrate,
            "_assert_prepared_early_commit_git_projection",
        ), mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=False,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
        ) as commit_digest:
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=progress_path,
                confirmation_capability_path=str(
                    handoff["capability_path"]
                ),
                confirmation_capability_token=str(handoff["token"]),
                confirmation_handoff=handoff,
                append=lambda _path, event: appended.append(event),
            )
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["reason_code"],
            "COMPLETED_RECOVERY_GIT_DIVERGED",
        )
        self.assertEqual(appended, [])
        commit_digest.assert_not_called()

    def test_completed_intent_recovery_rejects_receipt_commit_content_mismatch(self) -> None:
        review, prepared, handoff, client, base, _proposal_digest = (
            self._completed_recovery_fixture()
        )
        appended = []
        progress_path = mock.Mock()
        progress_path.exists.return_value = True
        base_digest = intent.content_hashes(base.encode("utf-8"))
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header(), prepared],
        ), mock.patch.object(
            content_migrate,
            "_assert_prepared_early_commit_git_projection",
        ), mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.canonical_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            return_value=(True, base_digest),
        ), mock.patch.object(
            intent,
            "git_version_chain",
            return_value={"ok": True, "reason_code": "", "versions": []},
        ):
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=progress_path,
                confirmation_capability_path=str(
                    handoff["capability_path"]
                ),
                confirmation_capability_token=str(handoff["token"]),
                confirmation_handoff=handoff,
                append=lambda _path, event: appended.append(event),
            )
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["reason_code"],
            "COMPLETED_RECOVERY_COMMIT_CONTENT_MISMATCH",
        )
        self.assertEqual(appended, [])

    def test_completed_recovery_rejects_target_changing_descendant_even_if_worktree_matches(self) -> None:
        review, prepared, handoff, client, base, proposal_digest = (
            self._completed_recovery_fixture()
        )
        base_digest = intent.content_hashes(base.encode("utf-8"))
        progress_path = mock.Mock()
        progress_path.exists.return_value = True
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header(), prepared],
        ), mock.patch.object(
            content_migrate,
            "_assert_prepared_early_commit_git_projection",
        ), mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.canonical_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            side_effect=[(True, proposal_digest), (True, base_digest)],
        ), mock.patch.object(
            intent,
            "git_version_chain",
            return_value={"ok": True, "reason_code": "", "versions": []},
        ):
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=progress_path,
                confirmation_capability_path=str(
                    handoff["capability_path"]
                ),
                confirmation_capability_token=str(handoff["token"]),
                confirmation_handoff=handoff,
            )
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["reason_code"],
            "COMPLETED_RECOVERY_CURRENT_COMMIT_CONTENT_MISMATCH",
        )

    def test_completed_recovery_rejects_changed_then_reverted_target_history(self) -> None:
        review, prepared, handoff, client, base, proposal_digest = (
            self._completed_recovery_fixture()
        )
        base_digest = intent.content_hashes(base.encode("utf-8"))
        progress_path = mock.Mock()
        progress_path.exists.return_value = True
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header(), prepared],
        ), mock.patch.object(
            content_migrate,
            "_assert_prepared_early_commit_git_projection",
        ), mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.canonical_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            return_value=(True, proposal_digest),
        ), mock.patch.object(
            intent,
            "git_version_chain",
            return_value={
                "ok": True,
                "reason_code": "",
                "versions": [{
                    "commit": "a" * 40,
                    "exists": True,
                    "raw_sha256": base_digest.raw_sha256,
                    "canonical_sha256": base_digest.canonical_sha256,
                }],
            },
        ):
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=progress_path,
                confirmation_capability_path=str(
                    handoff["capability_path"]
                ),
                confirmation_capability_token=str(handoff["token"]),
                confirmation_handoff=handoff,
            )
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["reason_code"],
            "COMPLETED_RECOVERY_TARGET_HISTORY_CHANGED",
        )

    def test_completed_recovery_exact_receipt_head_still_requires_replan(self) -> None:
        review, prepared, handoff, client, _base, proposal_digest = (
            self._completed_recovery_fixture(current_head="8" * 40)
        )
        appended = []
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header(), prepared],
        ), mock.patch.object(
            content_migrate,
            "_assert_prepared_early_commit_git_projection",
        ), mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.canonical_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            return_value=(True, proposal_digest),
        ) as commit_digest, mock.patch.object(
            intent,
            "git_version_chain",
            return_value={"ok": True, "reason_code": "", "versions": []},
        ):
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path=str(
                    handoff["capability_path"]
                ),
                confirmation_capability_token=str(handoff["token"]),
                confirmation_handoff=handoff,
                append=lambda _path, event: appended.append(event),
            )
        self.assertEqual(result["status"], "replan_required")
        self.assertEqual(len(appended), 1)
        commit_digest.assert_called_once_with(
            "8" * 40,
            mock.sentinel.canonical_target,
        )

    def test_completed_intent_recovery_retries_after_progress_append_crash(self) -> None:
        review, prepared, handoff, client, _base, proposal_digest = (
            self._completed_recovery_fixture()
        )
        events = [progress_header(), prepared]
        attempts = 0
        progress_path = mock.Mock()
        progress_path.exists.return_value = True

        def flaky_append(_path, event):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise content_migrate.ContentMigrationError(
                    "PROGRESS_APPEND_FAILED",
                    "progress",
                    "项目/example.md",
                )
            events.append(event)

        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            side_effect=lambda *_args, **_kwargs: list(events),
        ), mock.patch.object(
            content_migrate,
            "_assert_prepared_early_commit_git_projection",
        ), mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.canonical_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            return_value=(True, proposal_digest),
        ), mock.patch.object(
            intent,
            "git_version_chain",
            return_value={"ok": True, "reason_code": "", "versions": []},
        ):
            first = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=progress_path,
                confirmation_capability_path=str(
                    handoff["capability_path"]
                ),
                confirmation_capability_token=str(handoff["token"]),
                confirmation_handoff=handoff,
                append=flaky_append,
            )
            second = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=progress_path,
                confirmation_capability_path=str(
                    handoff["capability_path"]
                ),
                confirmation_capability_token=str(handoff["token"]),
                confirmation_handoff=handoff,
                append=flaky_append,
            )

        self.assertEqual(first["status"], "blocked")
        self.assertEqual(first["reason_code"], "PROGRESS_APPEND_FAILED")
        self.assertEqual(second["status"], "replan_required")
        self.assertEqual(attempts, 2)
        self.assertEqual(
            [event["event"] for event in events],
            ["header", "prepared", "completed"],
        )
        self.assertEqual(client.actions.count("apply"), 2)

    def test_consumed_expiry_recovery_is_bound_to_exact_prepared_review(self) -> None:
        review = review_for([query_item("项目/a.md")])
        client = mock.Mock(actor="codex", session_id="session-1")
        item = review["items"][0]
        events = [
            progress_header(),
            prepared_event("项目/a.md"),
        ]
        handoff = {
            "status": "issued",
            "token": "already-consumed-one-shot-token",
            "capability_path": "/private/capability.json",
            "handoff_path": "/private/handoff.json",
            "capability_id": "c" * 32,
            "consumed_recovery": True,
            "intent_status": "validated",
            "subject_actor": "codex",
            "task_hash": confirmation_capability.task_hash(
                "session-1",
                "codex",
            ),
            "session_hash": confirmation_capability.session_hash("session-1"),
            "proposal_id": "a" * 32,
            "proposal_raw_sha256": item["proposal_raw_sha256"],
            "proposal_canonical_sha256": item[
                "proposal_canonical_sha256"
            ],
            "target_relative_path": "项目/a.md",
            "target_key": "项目/a.md".casefold(),
            "operation": "content_update",
            "reconcile_action": "MIGRATE_LEGACY_SCOPE",
            "fencing_token": 7,
        }
        resumed = {"schema_version": 1, "ok": True, "status": "complete"}
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=events,
        ), mock.patch.object(
            content_migrate,
            "_recover_completed_confirmation_handoff",
            return_value=False,
        ), mock.patch.object(
            content_migrate,
            "_run_apply_with_structured_failure",
            return_value=resumed,
        ) as run:
            self.assertEqual(
                content_migrate.run_apply(
                    client,
                    review,
                    review_sha256="7" * 64,
                    progress_path=mock.Mock(),
                    confirmation_capability_path=str(
                        handoff["capability_path"]
                    ),
                    confirmation_capability_token=str(handoff["token"]),
                    confirmation_handoff=handoff,
                ),
                resumed,
            )
        self.assertEqual(
            run.call_args.kwargs["confirmation_capability_token"],
            handoff["token"],
        )

        pending_handoff = dict(handoff, intent_status="pending")
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=events,
        ), mock.patch.object(
            content_migrate,
            "_recover_completed_confirmation_handoff",
            return_value=False,
        ), mock.patch.object(
            content_migrate,
            "_run_apply_with_structured_failure",
            return_value=resumed,
        ) as pending_run:
            self.assertEqual(
                content_migrate.run_apply(
                    client,
                    review,
                    review_sha256="7" * 64,
                    progress_path=mock.Mock(),
                    confirmation_capability_path=str(
                        pending_handoff["capability_path"]
                    ),
                    confirmation_capability_token=str(
                        pending_handoff["token"]
                    ),
                    confirmation_handoff=pending_handoff,
                ),
                resumed,
            )
        self.assertEqual(
            pending_run.call_args.kwargs["confirmation_capability_path"],
            pending_handoff["capability_path"],
        )

        completed_events = [
            progress_header(),
            prepared_event("项目/a.md"),
            completed_event("项目/a.md", commit="8" * 40),
        ]
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=completed_events,
        ), mock.patch.object(
            content_migrate,
            "_run_apply_with_structured_failure",
        ) as pending_completed_run, self.assertRaises(
            content_migrate.ContentMigrationError
        ) as pending_completed:
            content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path=str(
                    pending_handoff["capability_path"]
                ),
                confirmation_capability_token=str(pending_handoff["token"]),
                confirmation_handoff=pending_handoff,
            )
        self.assertEqual(
            pending_completed.exception.reason_code,
            "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
        )
        pending_completed_run.assert_not_called()

        for key, changed in (
            ("subject_actor", "claude"),
            ("task_hash", "e" * 64),
            ("session_hash", "e" * 16),
            ("proposal_id", "d" * 32),
            ("proposal_raw_sha256", "e" * 64),
            ("proposal_canonical_sha256", "e" * 64),
            ("target_relative_path", "项目/b.md"),
            ("operation", "governance_migration"),
            ("reconcile_action", "UPDATE"),
            ("fencing_token", 8),
        ):
            drifted = dict(handoff)
            drifted[key] = changed
            with self.subTest(binding=key), mock.patch.object(
                content_migrate,
                "progress_transaction_lock",
                return_value=contextlib.nullcontext(),
            ), mock.patch.object(
                content_migrate,
                "load_progress",
                return_value=events,
            ), mock.patch.object(
                content_migrate,
                "_run_apply_with_structured_failure",
            ) as blocked, self.assertRaises(
                content_migrate.ContentMigrationError
            ) as caught:
                content_migrate.run_apply(
                    client,
                    review,
                    review_sha256="7" * 64,
                    progress_path=mock.Mock(),
                    confirmation_capability_path=str(
                        handoff["capability_path"]
                    ),
                    confirmation_capability_token=str(handoff["token"]),
                    confirmation_handoff=drifted,
                )
            self.assertEqual(
                caught.exception.reason_code,
                "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
            )
            blocked.assert_not_called()

    def test_handoff_reader_falls_back_only_for_consumed_expiry(self) -> None:
        client = mock.Mock(actor="codex", session_id="session-1")
        recovered = {
            "status": "issued",
            "consumed_recovery": True,
            "token": "already-consumed-token",
        }
        with mock.patch.object(
            confirmation_capability,
            "read_confirmation_handoff",
            side_effect=confirmation_capability.ConfirmationCapabilityError(
                "CONFIRMATION_HANDOFF_EXPIRED"
            ),
        ), mock.patch.object(
            confirmation_capability,
            "recover_consumed_confirmation_handoff",
            return_value=recovered,
        ) as recovery:
            self.assertEqual(
                content_migrate._read_confirmation_handoff_for_apply(
                    client,
                    handoff_path="/private/expired-handoff.json",
                ),
                recovered,
            )
        recovery.assert_called_once_with(
            write_gateway.CONFIG_ROOT,
            handoff_path="/private/expired-handoff.json",
            subject_actor="codex",
            raw_task_id="session-1",
            raw_session_id="session-1",
        )

        with mock.patch.object(
            confirmation_capability,
            "read_confirmation_handoff",
            side_effect=confirmation_capability.ConfirmationCapabilityError(
                "CONFIRMATION_HANDOFF_INVALID"
            ),
        ), mock.patch.object(
            confirmation_capability,
            "recover_consumed_confirmation_handoff",
        ) as forbidden_recovery, self.assertRaises(
            confirmation_capability.ConfirmationCapabilityError
        ) as caught:
            content_migrate._read_confirmation_handoff_for_apply(
                client,
                handoff_path="/private/tampered-handoff.json",
            )
        self.assertEqual(
            caught.exception.reason_code,
            "CONFIRMATION_HANDOFF_INVALID",
        )
        forbidden_recovery.assert_not_called()

    def test_batch_apply_consumes_at_most_one_confirmation_capability(self) -> None:
        records = [query_item("项目/a.md"), query_item("项目/b.md")]
        base = "---\nstatus: active\nagent_scope: shared\n---\n# Body\n"
        base_digest = intent.content_hashes(base.encode())
        review = review_for(records)
        for record, item in zip(records, review["items"]):
            _proposal, proposal_digest = content_migrate._proposal(record, base, actor="codex")
            item.update({
                "base_raw_sha256": base_digest.raw_sha256,
                "base_canonical_sha256": base_digest.canonical_sha256,
                "proposal_raw_sha256": proposal_digest.raw_sha256,
                "proposal_canonical_sha256": proposal_digest.canonical_sha256,
                "proposal_size_bytes": proposal_digest.size_bytes,
            })
        review = content_migrate.validate_review(review)
        first_item = review["items"][0]

        class FakeClient:
            actor = "codex"

            def __init__(self):
                self.actions = []
                self.apply_requests = []

            def doctor(self):
                return doctor(records)

            def write(self, action, request):
                self.actions.append(action)
                self.assert_first_target(request)
                if action == "read-target":
                    return {
                        "ok": True,
                        "status": "found",
                        "exists": True,
                        "scope_migration": True,
                        "target_relative_path": "项目/a.md",
                        "app_id": "agent-memory",
                        "project_id": "a",
                        "content": base,
                        "read_token": "1" * 64,
                        "base_raw_sha256": base_digest.raw_sha256,
                        "base_canonical_sha256": base_digest.canonical_sha256,
                        "base_git_head": "4" * 40,
                    }
                if action == "prepare":
                    return {
                        "status": "prepared",
                        "recommended_action": "MIGRATE_LEGACY_SCOPE",
                        "target_relative_path": "项目/a.md",
                        "scope_migration": True,
                        "confirmation_required": True,
                        "proposal_id": "a" * 32,
                        "fencing_token": 7,
                        "base_raw_sha256": base_digest.raw_sha256,
                        "base_canonical_sha256": base_digest.canonical_sha256,
                        "base_git_head": "4" * 40,
                        "proposal_raw_sha256": first_item["proposal_raw_sha256"],
                        "proposal_canonical_sha256": first_item["proposal_canonical_sha256"],
                        "proposal_size_bytes": first_item["proposal_size_bytes"],
                    }
                self.apply_requests.append(dict(request))
                return {
                    "status": "applied",
                    "recommended_action": "MIGRATE_LEGACY_SCOPE",
                    "target_relative_path": "项目/a.md",
                    "scope_migration": True,
                    "proposal_id": "a" * 32,
                    "fencing_token": 7,
                    "proposal_raw_sha256": first_item["proposal_raw_sha256"],
                    "proposal_canonical_sha256": first_item["proposal_canonical_sha256"],
                    "git_commit": "8" * 40,
                    "receipt_id": "b" * 32,
                    "idempotent": False,
                }

            @staticmethod
            def assert_first_target(request):
                if request["target_relative_path"] != "项目/a.md":
                    raise AssertionError("second target must not receive the first capability")

        client = FakeClient()
        first_appended = []
        with mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header()],
        ):
            prepared_result = content_migrate._run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                append=lambda _path, event: first_appended.append(event),
            )

        self.assertFalse(prepared_result["ok"])
        self.assertEqual(prepared_result["status"], "confirmation_required")
        self.assertEqual(prepared_result["proposal_id"], "a" * 32)
        self.assertEqual(client.actions, ["read-target", "prepare"])
        self.assertEqual([event["event"] for event in first_appended], ["prepared"])

        second_appended = []
        with mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header(), first_appended[0]],
        ), mock.patch.object(
            content_migrate,
            "_assert_prepared_base_git_projection",
        ):
            result = content_migrate._run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path="/private/capability.json",
                confirmation_capability_token="one-shot-token",
                append=lambda _path, event: second_appended.append(event),
            )

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "next_confirmation_required")
        self.assertEqual(result["reason_code"], "NEXT_CONFIRMATION_REQUIRED")
        self.assertEqual(result["next_target_relative_path"], "项目/b.md")
        self.assertEqual(client.actions, ["read-target", "prepare", "read-target", "apply"])
        self.assertEqual(len(client.apply_requests), 1)
        self.assertEqual(
            client.apply_requests[0]["confirmation_capability_token"],
            "one-shot-token",
        )
        self.assertEqual(
            [event["event"] for event in second_appended],
            ["completed"],
        )
        self.assertEqual(
            [item["status"] for item in result["items"]],
            ["applied", "next_confirmation_required"],
        )

    def test_unrelated_descendant_advances_head_before_next_prepare(self) -> None:
        records = [query_item("项目/a.md"), query_item("项目/b.md")]
        base = "---\nstatus: active\nagent_scope: shared\n---\n# Body\n"
        base_digest = intent.content_hashes(base.encode())
        review = review_for(records)
        proposals = {}
        for record, item in zip(records, review["items"]):
            proposal, proposal_digest = content_migrate._proposal(
                record,
                base,
                actor="codex",
            )
            proposals[record["target_relative_path"]] = proposal
            item.update({
                "base_raw_sha256": base_digest.raw_sha256,
                "base_canonical_sha256": base_digest.canonical_sha256,
                "proposal_raw_sha256": proposal_digest.raw_sha256,
                "proposal_canonical_sha256": proposal_digest.canonical_sha256,
                "proposal_size_bytes": proposal_digest.size_bytes,
            })
        review = content_migrate.validate_review(review)
        receipt_head = "8" * 40
        unrelated_head = "9" * 40
        events = [
            progress_header(),
            prepared_event("项目/a.md"),
            completed_event("项目/a.md", commit=receipt_head),
        ]
        pending_item = review["items"][1]

        class FakeClient:
            actor = "codex"

            def __init__(self):
                self.actions = []

            def doctor(self):
                return doctor([records[1]])

            def write(self, action, request):
                self.actions.append((action, request["target_relative_path"]))
                target = request["target_relative_path"]
                if action == "read-target":
                    content = proposals[target] if target == "项目/a.md" else base
                    digest = intent.content_hashes(content.encode())
                    return {
                        "ok": True,
                        "status": "found",
                        "exists": True,
                        "scope_migration": True,
                        "target_relative_path": target,
                        "app_id": "agent-memory",
                        "project_id": Path(target).stem.casefold(),
                        "content": content,
                        "read_token": "1" * 64,
                        "base_raw_sha256": digest.raw_sha256,
                        "base_canonical_sha256": digest.canonical_sha256,
                        "base_git_head": unrelated_head,
                    }
                if action != "prepare" or target != "项目/b.md":
                    raise AssertionError((action, target))
                return {
                    "status": "prepared",
                    "recommended_action": "MIGRATE_LEGACY_SCOPE",
                    "target_relative_path": target,
                    "scope_migration": True,
                    "confirmation_required": True,
                    "proposal_id": "c" * 32,
                    "fencing_token": 8,
                    "base_raw_sha256": base_digest.raw_sha256,
                    "base_canonical_sha256": base_digest.canonical_sha256,
                    "base_git_head": unrelated_head,
                    "proposal_raw_sha256": pending_item["proposal_raw_sha256"],
                    "proposal_canonical_sha256": (
                        pending_item["proposal_canonical_sha256"]
                    ),
                    "proposal_size_bytes": pending_item["proposal_size_bytes"],
                }

        appended = []
        with mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=events,
        ), mock.patch.object(
            content_migrate,
            "_assert_completed_progress_git_projection",
        ) as completed_projection, mock.patch.object(
            content_migrate,
            "_assert_pending_target_safe_head_advance",
        ) as safe_advance:
            result = content_migrate._run_apply(
                FakeClient(),
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                append=lambda _path, event: appended.append(event),
            )

        self.assertEqual(result["status"], "confirmation_required")
        self.assertEqual(result["next_target_relative_path"], "项目/b.md")
        self.assertEqual(len(appended), 1)
        self.assertEqual(appended[0]["base_git_head"], unrelated_head)
        self.assertEqual(appended[0]["advanced_from_git_head"], receipt_head)
        completed_projection.assert_called_once_with(
            target="项目/a.md",
            item=review["items"][0],
            receipt_commit=receipt_head,
            current_head=unrelated_head,
        )
        safe_advance.assert_called_once()
        self.assertEqual(
            safe_advance.call_args.kwargs["allowed_head"],
            receipt_head,
        )
        self.assertEqual(
            safe_advance.call_args.kwargs["current_head"],
            unrelated_head,
        )
        resumed = content_migrate.progress_state(
            [*events, appended[0]],
            review,
        )
        self.assertEqual(resumed["项目/b.md"]["event"], "prepared")
        wrong_ancestor = dict(
            appended[0],
            advanced_from_git_head="f" * 40,
        )
        with self.assertRaises(content_migrate.ContentMigrationError):
            content_migrate.progress_state(
                [*events, wrong_ancestor],
                review,
            )

    def test_safe_head_advance_allows_unchanged_completed_and_pending_targets(self) -> None:
        completed_item, pending_item = review_for([
            query_item("项目/a.md"),
            query_item("项目/b.md"),
        ])["items"]
        completed_phase = completed_event("项目/a.md", commit="8" * 40)
        completed_digest = intent.ContentDigest(
            raw_sha256=str(completed_item["proposal_raw_sha256"]),
            canonical_sha256=str(completed_item["proposal_canonical_sha256"]),
            size_bytes=0,
            text="",
        )
        pending_digest = intent.ContentDigest(
            raw_sha256=str(pending_item["base_raw_sha256"]),
            canonical_sha256=str(pending_item["base_canonical_sha256"]),
            size_bytes=0,
            text="",
        )
        completed_target = mock.sentinel.completed_target
        pending_target = mock.sentinel.pending_target

        def target_for(rel_path):
            return completed_target if rel_path == "项目/a.md" else pending_target

        def digest_for(_commit, target):
            return (
                (True, completed_digest)
                if target is completed_target
                else (True, pending_digest)
            )

        with mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            side_effect=target_for,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            side_effect=digest_for,
        ), mock.patch.object(
            intent,
            "git_version_chain",
            return_value={"ok": True, "reason_code": "", "versions": []},
        ) as version_chain:
            content_migrate._assert_pending_target_safe_head_advance(
                target="项目/b.md",
                item=pending_item,
                allowed_head="8" * 40,
                current_head="9" * 40,
                completed=[(completed_item, completed_phase)],
            )
        self.assertEqual(version_chain.call_count, 2)

    def test_safe_head_advance_reuses_same_head_completed_attestations(self) -> None:
        completed_item, pending_item = review_for([
            query_item("项目/a.md"),
            query_item("项目/b.md"),
        ])["items"]
        current_head = "9" * 40
        with mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            content_migrate,
            "_assert_completed_progress_git_projection",
        ) as completed_projection, mock.patch.object(
            content_migrate,
            "_assert_git_target_projection",
        ) as pending_projection:
            content_migrate._assert_pending_target_safe_head_advance(
                target="项目/b.md",
                item=pending_item,
                allowed_head="8" * 40,
                current_head=current_head,
                completed=[(
                    completed_item,
                    completed_event("项目/a.md", commit="8" * 40),
                )],
                verified_completed_heads={"项目/a.md": current_head},
            )
        completed_projection.assert_not_called()
        pending_projection.assert_called_once()

    def test_safe_head_advance_rejects_pending_target_changed_then_reverted(self) -> None:
        item = review_for([query_item()])["items"][0]
        base_digest = intent.ContentDigest(
            raw_sha256=str(item["base_raw_sha256"]),
            canonical_sha256=str(item["base_canonical_sha256"]),
            size_bytes=0,
            text="",
        )
        changed_digest = intent.ContentDigest(
            raw_sha256="a" * 64,
            canonical_sha256="b" * 64,
            size_bytes=0,
            text="",
        )
        with mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.pending_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            return_value=(True, base_digest),
        ), mock.patch.object(
            intent,
            "git_version_chain",
            return_value={
                "ok": True,
                "reason_code": "",
                "versions": [{
                    "commit": "5" * 40,
                    "exists": True,
                    "raw_sha256": changed_digest.raw_sha256,
                    "canonical_sha256": changed_digest.canonical_sha256,
                }],
            },
        ), self.assertRaises(content_migrate.ContentMigrationError) as caught:
            content_migrate._assert_pending_target_safe_head_advance(
                target="项目/example.md",
                item=item,
                allowed_head="4" * 40,
                current_head="9" * 40,
                completed=[],
            )
        self.assertEqual(caught.exception.reason_code, "PENDING_TARGET_HISTORY_CHANGED")

    def test_completed_progress_rejects_changed_target_history(self) -> None:
        item = review_for([query_item()])["items"][0]
        proposal_digest = intent.ContentDigest(
            raw_sha256=str(item["proposal_raw_sha256"]),
            canonical_sha256=str(item["proposal_canonical_sha256"]),
            size_bytes=0,
            text="",
        )
        changed_digest = intent.ContentDigest(
            raw_sha256="a" * 64,
            canonical_sha256="b" * 64,
            size_bytes=0,
            text="",
        )
        with mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.completed_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            return_value=(True, proposal_digest),
        ), mock.patch.object(
            intent,
            "git_version_chain",
            return_value={
                "ok": True,
                "reason_code": "",
                "versions": [{
                    "commit": "9" * 40,
                    "exists": True,
                    "raw_sha256": changed_digest.raw_sha256,
                    "canonical_sha256": changed_digest.canonical_sha256,
                }],
            },
        ), self.assertRaises(content_migrate.ContentMigrationError) as caught:
            content_migrate._assert_completed_progress_git_projection(
                target="项目/example.md",
                item=item,
                receipt_commit="8" * 40,
                current_head="9" * 40,
            )
        self.assertEqual(
            caught.exception.reason_code,
            "COMPLETED_PROGRESS_TARGET_HISTORY_CHANGED",
        )

    def test_safe_head_advance_rejects_sibling_history(self) -> None:
        item = review_for([query_item()])["items"][0]
        with mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=False,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
        ) as forbidden_target, self.assertRaises(
            content_migrate.ContentMigrationError
        ) as caught:
            content_migrate._assert_pending_target_safe_head_advance(
                target="项目/example.md",
                item=item,
                allowed_head="4" * 40,
                current_head="9" * 40,
                completed=[],
            )
        self.assertEqual(caught.exception.reason_code, "HEAD_ADVANCE_GIT_DIVERGED")
        forbidden_target.assert_not_called()

    def test_safe_head_advance_rejects_head_worktree_projection_mismatch(self) -> None:
        item = review_for([query_item()])["items"][0]
        base_digest = intent.ContentDigest(
            raw_sha256=str(item["base_raw_sha256"]),
            canonical_sha256=str(item["base_canonical_sha256"]),
            size_bytes=0,
            text="",
        )
        changed_digest = intent.ContentDigest(
            raw_sha256="a" * 64,
            canonical_sha256="b" * 64,
            size_bytes=0,
            text="",
        )
        with mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.pending_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            side_effect=[(True, base_digest), (True, changed_digest)],
        ), mock.patch.object(
            intent,
            "git_version_chain",
            return_value={"ok": True, "reason_code": "", "versions": []},
        ), self.assertRaises(content_migrate.ContentMigrationError) as caught:
            content_migrate._assert_pending_target_safe_head_advance(
                target="项目/example.md",
                item=item,
                allowed_head="4" * 40,
                current_head="9" * 40,
                completed=[],
            )
        self.assertEqual(
            caught.exception.reason_code,
            "PENDING_CURRENT_COMMIT_CONTENT_MISMATCH",
        )

    def test_prepared_proposal_allows_exact_head_atomic_write_crash_window(self) -> None:
        item = review_for([query_item()])["items"][0]
        base_digest = intent.ContentDigest(
            raw_sha256=str(item["base_raw_sha256"]),
            canonical_sha256=str(item["base_canonical_sha256"]),
            size_bytes=0,
            text="",
        )
        prepared_head = "4" * 40
        with mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.prepared_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            return_value=(True, base_digest),
        ) as commit_digest, mock.patch.object(
            intent,
            "git_version_chain",
            return_value={"ok": True, "reason_code": "", "versions": []},
        ):
            content_migrate._assert_prepared_early_commit_git_projection(
                target="项目/example.md",
                item=item,
                prepared_head=prepared_head,
                current_head=prepared_head,
                completed=[],
                allow_uncommitted_worktree=True,
            )
        commit_digest.assert_called_once_with(
            prepared_head,
            mock.sentinel.prepared_target,
        )

    def test_prepared_proposal_allows_monotonic_committed_early_write(self) -> None:
        item = review_for([query_item()])["items"][0]
        base_digest = intent.ContentDigest(
            raw_sha256=str(item["base_raw_sha256"]),
            canonical_sha256=str(item["base_canonical_sha256"]),
            size_bytes=0,
            text="",
        )
        proposal_digest = intent.ContentDigest(
            raw_sha256=str(item["proposal_raw_sha256"]),
            canonical_sha256=str(item["proposal_canonical_sha256"]),
            size_bytes=0,
            text="",
        )
        with mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.prepared_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            side_effect=[(True, base_digest), (True, proposal_digest)],
        ), mock.patch.object(
            intent,
            "git_version_chain",
            return_value={
                "ok": True,
                "reason_code": "",
                "versions": [{
                    "commit": "9" * 40,
                    "exists": True,
                    "raw_sha256": proposal_digest.raw_sha256,
                    "canonical_sha256": proposal_digest.canonical_sha256,
                }],
            },
        ):
            content_migrate._assert_prepared_early_commit_git_projection(
                target="项目/example.md",
                item=item,
                prepared_head="4" * 40,
                current_head="9" * 40,
                completed=[],
            )

    def test_prepared_proposal_rejects_sibling_or_nonmonotonic_history(self) -> None:
        item = review_for([query_item()])["items"][0]
        base_digest = intent.ContentDigest(
            raw_sha256=str(item["base_raw_sha256"]),
            canonical_sha256=str(item["base_canonical_sha256"]),
            size_bytes=0,
            text="",
        )
        proposal_digest = intent.ContentDigest(
            raw_sha256=str(item["proposal_raw_sha256"]),
            canonical_sha256=str(item["proposal_canonical_sha256"]),
            size_bytes=0,
            text="",
        )
        with mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=False,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
        ) as forbidden_target, self.assertRaises(
            content_migrate.ContentMigrationError
        ) as sibling:
            content_migrate._assert_prepared_early_commit_git_projection(
                target="项目/example.md",
                item=item,
                prepared_head="4" * 40,
                current_head="9" * 40,
                completed=[],
            )
        self.assertEqual(sibling.exception.reason_code, "PREPARED_GIT_HEAD_DRIFT")
        forbidden_target.assert_not_called()

        with mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.prepared_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            side_effect=[(True, base_digest), (True, proposal_digest)],
        ), mock.patch.object(
            intent,
            "git_version_chain",
            return_value={
                "ok": True,
                "reason_code": "",
                "versions": [
                    {
                        "commit": "7" * 40,
                        "exists": True,
                        "raw_sha256": proposal_digest.raw_sha256,
                        "canonical_sha256": proposal_digest.canonical_sha256,
                    },
                    {
                        "commit": "8" * 40,
                        "exists": True,
                        "raw_sha256": base_digest.raw_sha256,
                        "canonical_sha256": base_digest.canonical_sha256,
                    },
                    {
                        "commit": "9" * 40,
                        "exists": True,
                        "raw_sha256": proposal_digest.raw_sha256,
                        "canonical_sha256": proposal_digest.canonical_sha256,
                    },
                ],
            },
        ), self.assertRaises(content_migrate.ContentMigrationError) as history:
            content_migrate._assert_prepared_early_commit_git_projection(
                target="项目/example.md",
                item=item,
                prepared_head="4" * 40,
                current_head="9" * 40,
                completed=[],
            )
        self.assertEqual(
            history.exception.reason_code,
            "PREPARED_TARGET_HISTORY_CHANGED",
        )

    def test_prepared_proposal_head_worktree_mismatch_blocks_before_apply(self) -> None:
        record = query_item()
        base = "---\nstatus: active\nagent_scope: shared\n---\n# Body\n"
        proposal, proposal_digest = content_migrate._proposal(
            record,
            base,
            actor="codex",
        )
        base_digest = intent.content_hashes(base.encode())
        review = review_for([record])
        review["items"][0].update({
            "base_raw_sha256": base_digest.raw_sha256,
            "base_canonical_sha256": base_digest.canonical_sha256,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "proposal_size_bytes": proposal_digest.size_bytes,
        })
        review = content_migrate.validate_review(review)
        prepared = prepared_event()

        class FakeClient:
            actor = "codex"

            def __init__(self):
                self.actions = []

            def doctor(self):
                return doctor([], fail=0)

            def write(self, action, request):
                self.actions.append(action)
                if action != "read-target":
                    raise AssertionError("apply must not be called")
                return {
                    "ok": True,
                    "status": "found",
                    "exists": True,
                    "scope_migration": True,
                    "target_relative_path": "项目/example.md",
                    "app_id": "agent-memory",
                    "project_id": "example",
                    "content": proposal,
                    "read_token": "1" * 64,
                    "base_raw_sha256": proposal_digest.raw_sha256,
                    "base_canonical_sha256": proposal_digest.canonical_sha256,
                    "base_git_head": "9" * 40,
                }

        client = FakeClient()
        with mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header(), prepared],
        ), mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.prepared_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            return_value=(True, base_digest),
        ), mock.patch.object(
            intent,
            "git_version_chain",
            return_value={"ok": True, "reason_code": "", "versions": []},
        ), self.assertRaises(content_migrate.ContentMigrationError) as caught:
            content_migrate._run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path="/private/capability.json",
                confirmation_capability_token="one-shot-token",
            )
        self.assertEqual(
            caught.exception.reason_code,
            "PREPARED_CURRENT_COMMIT_CONTENT_MISMATCH",
        )
        self.assertEqual(client.actions, ["read-target"])

    def test_prepared_proposal_exact_head_crash_retries_apply_and_commits(self) -> None:
        record = query_item()
        base = "---\nstatus: active\nagent_scope: shared\n---\n# Body\n"
        proposal, proposal_digest = content_migrate._proposal(
            record,
            base,
            actor="codex",
        )
        base_digest = intent.content_hashes(base.encode())
        review = review_for([record])
        review["items"][0].update({
            "base_raw_sha256": base_digest.raw_sha256,
            "base_canonical_sha256": base_digest.canonical_sha256,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "proposal_size_bytes": proposal_digest.size_bytes,
        })
        review = content_migrate.validate_review(review)
        prepared = prepared_event()
        receipt_head = "8" * 40

        class FakeClient:
            actor = "codex"

            def __init__(self):
                self.actions = []

            def doctor(self):
                return doctor([], fail=0)

            def write(self, action, request):
                self.actions.append(action)
                if action == "read-target":
                    return {
                        "ok": True,
                        "status": "found",
                        "exists": True,
                        "scope_migration": True,
                        "target_relative_path": "项目/example.md",
                        "app_id": "agent-memory",
                        "project_id": "example",
                        "content": proposal,
                        "read_token": "1" * 64,
                        "base_raw_sha256": proposal_digest.raw_sha256,
                        "base_canonical_sha256": proposal_digest.canonical_sha256,
                        "base_git_head": "4" * 40,
                    }
                if action != "apply":
                    raise AssertionError(action)
                return {
                    "status": "applied",
                    "recommended_action": "MIGRATE_LEGACY_SCOPE",
                    "target_relative_path": "项目/example.md",
                    "scope_migration": True,
                    "proposal_id": "a" * 32,
                    "fencing_token": 7,
                    "proposal_raw_sha256": proposal_digest.raw_sha256,
                    "proposal_canonical_sha256": proposal_digest.canonical_sha256,
                    "git_commit": receipt_head,
                    "receipt_id": "b" * 32,
                    "idempotent": False,
                }

        client = FakeClient()
        appended = []
        proposal_version = {
            "commit": receipt_head,
            "exists": True,
            "raw_sha256": proposal_digest.raw_sha256,
            "canonical_sha256": proposal_digest.canonical_sha256,
        }
        with mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header(), prepared],
        ), mock.patch.object(
            intent,
            "_git_is_ancestor",
            return_value=True,
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.sentinel.prepared_target,
        ), mock.patch.object(
            intent,
            "git_target_digest_at_commit",
            side_effect=[
                (True, base_digest),
                (True, base_digest),
                (True, proposal_digest),
            ],
        ), mock.patch.object(
            intent,
            "git_version_chain",
            side_effect=[
                {"ok": True, "reason_code": "", "versions": []},
                {
                    "ok": True,
                    "reason_code": "",
                    "versions": [proposal_version],
                },
            ],
        ):
            result = content_migrate._run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path="/private/capability.json",
                confirmation_capability_token="one-shot-token",
                append=lambda _path, event: appended.append(event),
            )
        self.assertTrue(result["ok"])
        self.assertEqual(client.actions, ["read-target", "apply"])
        self.assertEqual([event["event"] for event in appended], ["completed"])

    def test_new_completed_live_head_reprojects_every_prior_target(self) -> None:
        records = [query_item("项目/a.md"), query_item("项目/b.md")]
        base = "---\nstatus: active\nagent_scope: shared\n---\n# Body\n"
        base_digest = intent.content_hashes(base.encode())
        review = review_for(records)
        proposals = {}
        proposal_digests = {}
        for record, item in zip(records, review["items"]):
            proposal, proposal_digest = content_migrate._proposal(
                record,
                base,
                actor="codex",
            )
            target = str(record["target_relative_path"])
            proposals[target] = proposal
            proposal_digests[target] = proposal_digest
            item.update({
                "base_raw_sha256": base_digest.raw_sha256,
                "base_canonical_sha256": base_digest.canonical_sha256,
                "proposal_raw_sha256": proposal_digest.raw_sha256,
                "proposal_canonical_sha256": proposal_digest.canonical_sha256,
                "proposal_size_bytes": proposal_digest.size_bytes,
            })
        review = content_migrate.validate_review(review)
        events = [
            progress_header(),
            prepared_event("项目/a.md"),
            completed_event("项目/a.md", commit="6" * 40),
            prepared_event("项目/b.md", head="6" * 40),
            completed_event("项目/b.md", commit="7" * 40),
        ]

        class FakeClient:
            actor = "codex"

            def __init__(self):
                self.doctor_calls = 0

            def doctor(self):
                self.doctor_calls += 1
                return doctor([], fail=0)

            def write(self, action, request):
                if action != "read-target":
                    raise AssertionError(action)
                target = request["target_relative_path"]
                digest = proposal_digests[target]
                return {
                    "ok": True,
                    "status": "found",
                    "exists": True,
                    "scope_migration": True,
                    "target_relative_path": target,
                    "app_id": "agent-memory",
                    "project_id": Path(target).stem.casefold(),
                    "content": proposals[target],
                    "read_token": "1" * 64,
                    "base_raw_sha256": digest.raw_sha256,
                    "base_canonical_sha256": digest.canonical_sha256,
                    "base_git_head": (
                        "8" * 40 if target == "项目/a.md" else "9" * 40
                    ),
                }

        projection_calls = []

        def record_projection(**kwargs):
            projection_calls.append((
                kwargs["target"],
                kwargs["current_head"],
            ))

        client = FakeClient()
        with mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=events,
        ), mock.patch.object(
            content_migrate,
            "_assert_completed_progress_git_projection",
            side_effect=record_projection,
        ):
            result = content_migrate._run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
            )
        self.assertTrue(result["ok"])
        self.assertEqual(
            projection_calls,
            [
                ("项目/a.md", "8" * 40),
                ("项目/a.md", "9" * 40),
                ("项目/b.md", "9" * 40),
            ],
        )

        def reject_prior_drift(**kwargs):
            if (
                kwargs["target"] == "项目/a.md"
                and kwargs["current_head"] == "9" * 40
            ):
                raise content_migrate.ContentMigrationError(
                    "COMPLETED_TARGET_DRIFT", "resume", "项目/a.md"
                )

        blocked_client = FakeClient()
        with mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=events,
        ), mock.patch.object(
            content_migrate,
            "_assert_completed_progress_git_projection",
            side_effect=reject_prior_drift,
        ), self.assertRaises(content_migrate.ContentMigrationError) as blocked:
            content_migrate._run_apply(
                blocked_client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
            )
        self.assertEqual(blocked.exception.reason_code, "COMPLETED_TARGET_DRIFT")
        self.assertEqual(blocked_client.doctor_calls, 1)

    def test_capability_cannot_be_forwarded_before_next_intent_is_prepared(self) -> None:
        record = query_item("项目/a.md")
        base = "---\nstatus: active\nagent_scope: shared\n---\n# Body\n"
        base_digest = intent.content_hashes(base.encode())
        review = review_for([record])
        _proposal, proposal_digest = content_migrate._proposal(record, base, actor="codex")
        review["items"][0].update({
            "base_raw_sha256": base_digest.raw_sha256,
            "base_canonical_sha256": base_digest.canonical_sha256,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "proposal_size_bytes": proposal_digest.size_bytes,
        })
        review = content_migrate.validate_review(review)
        client = mock.Mock(actor="codex")
        client.doctor.return_value = doctor([record])
        client.write.return_value = {
            "ok": True, "status": "found", "exists": True,
            "scope_migration": True, "target_relative_path": "项目/a.md",
            "app_id": "agent-memory", "project_id": "a", "content": base,
            "read_token": "1" * 64,
            "base_raw_sha256": base_digest.raw_sha256,
            "base_canonical_sha256": base_digest.canonical_sha256,
            "base_git_head": "4" * 40,
        }
        with mock.patch.object(
            content_migrate, "load_progress", return_value=[progress_header()]
        ), self.assertRaises(content_migrate.ContentMigrationError) as caught:
            content_migrate._run_apply(
                client, review, review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path="/private/old-capability.json",
                confirmation_capability_token="old-one-shot-token",
            )
        self.assertEqual(
            caught.exception.reason_code, "CONFIRMATION_CAPABILITY_PREMATURE"
        )
        self.assertEqual(
            [call.args[0] for call in client.write.call_args_list], ["read-target"]
        )

    def test_completed_progress_scrubs_exact_orphan_handoff_before_next_target(self) -> None:
        review = review_for([query_item("项目/a.md"), query_item("项目/b.md")])
        client = mock.Mock(actor="codex", session_id="session-1")
        events = [
            progress_header(),
            prepared_event("项目/a.md"),
            completed_event("项目/a.md", commit="8" * 40),
        ]
        first_item = review["items"][0]
        handoff = {
            "status": "issued",
            "token": "orphan-one-shot-token",
            "handoff_path": "/private/orphan-handoff.json",
            "capability_id": "c" * 32,
            "subject_actor": "codex",
            "task_hash": confirmation_capability.task_hash(
                "session-1",
                "codex",
            ),
            "session_hash": confirmation_capability.session_hash("session-1"),
            "proposal_id": "a" * 32,
            "proposal_raw_sha256": first_item["proposal_raw_sha256"],
            "proposal_canonical_sha256": first_item[
                "proposal_canonical_sha256"
            ],
            "target_relative_path": "项目/a.md",
            "target_key": "项目/a.md".casefold(),
            "operation": "content_update",
            "reconcile_action": "MIGRATE_LEGACY_SCOPE",
            "fencing_token": 7,
        }
        resumed = {
            "schema_version": 1,
            "ok": False,
            "status": "confirmation_required",
            "next_target_relative_path": "项目/b.md",
        }
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=events,
        ), mock.patch.object(
            confirmation_capability,
            "mark_confirmation_handoff_consumed",
        ) as scrubbed, mock.patch.object(
            content_migrate,
            "_run_apply_with_structured_failure",
            return_value=resumed,
        ) as run:
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path="/private/capability.json",
                confirmation_capability_token="orphan-one-shot-token",
                confirmation_handoff=handoff,
            )

        self.assertEqual(result, resumed)
        scrubbed.assert_called_once_with(
            write_gateway.CONFIG_ROOT,
            handoff_path="/private/orphan-handoff.json",
            capability_id="c" * 32,
        )
        self.assertEqual(run.call_args.kwargs["confirmation_capability_path"], "")
        self.assertEqual(run.call_args.kwargs["confirmation_capability_token"], "")
        self.assertEqual(handoff["status"], "consumed")
        self.assertNotIn("token", handoff)

    def test_completed_progress_does_not_scrub_mismatched_handoff(self) -> None:
        review = review_for([query_item("项目/a.md"), query_item("项目/b.md")])
        client = mock.Mock(actor="codex", session_id="session-1")
        events = [
            progress_header(),
            prepared_event("项目/a.md"),
            completed_event("项目/a.md", commit="8" * 40),
        ]
        first_item = review["items"][0]
        handoff = {
            "status": "issued",
            "token": "mismatched-one-shot-token",
            "handoff_path": "/private/mismatched-handoff.json",
            "capability_id": "c" * 32,
            "subject_actor": "codex",
            "task_hash": confirmation_capability.task_hash(
                "session-1",
                "codex",
            ),
            "session_hash": confirmation_capability.session_hash("session-1"),
            # Every other field matches, but the proposal identity does not.
            "proposal_id": "d" * 32,
            "proposal_raw_sha256": first_item["proposal_raw_sha256"],
            "proposal_canonical_sha256": first_item[
                "proposal_canonical_sha256"
            ],
            "target_relative_path": "项目/a.md",
            "target_key": "项目/a.md".casefold(),
            "operation": "content_update",
            "reconcile_action": "MIGRATE_LEGACY_SCOPE",
            "fencing_token": 7,
        }
        blocked = {
            "schema_version": 1,
            "ok": False,
            "status": "blocked",
            "reason_code": "CONFIRMATION_CAPABILITY_PREMATURE",
        }
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=events,
        ), mock.patch.object(
            confirmation_capability,
            "mark_confirmation_handoff_consumed",
        ) as scrubbed, mock.patch.object(
            content_migrate,
            "_run_apply_with_structured_failure",
            return_value=blocked,
        ) as run:
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path="/private/capability.json",
                confirmation_capability_token="mismatched-one-shot-token",
                confirmation_handoff=handoff,
            )

        self.assertEqual(result, blocked)
        scrubbed.assert_not_called()
        self.assertEqual(
            run.call_args.kwargs["confirmation_capability_path"],
            "/private/capability.json",
        )
        self.assertEqual(
            run.call_args.kwargs["confirmation_capability_token"],
            "mismatched-one-shot-token",
        )
        self.assertEqual(handoff["status"], "issued")
        self.assertIn("token", handoff)

    def test_completed_handoff_recovery_accepts_preupgrade_sha_target_key(self) -> None:
        review = review_for([query_item("项目/a.md"), query_item("项目/b.md")])
        client = mock.Mock(actor="codex", session_id="session-1")
        item = review["items"][0]
        state = {
            "项目/a.md": completed_event("项目/a.md", commit="8" * 40),
        }
        handoff = {
            "status": "issued",
            "token": "orphan-one-shot-token",
            "subject_actor": "codex",
            "task_hash": confirmation_capability.task_hash("session-1", "codex"),
            "session_hash": confirmation_capability.session_hash("session-1"),
            "proposal_id": "a" * 32,
            "proposal_raw_sha256": item["proposal_raw_sha256"],
            "proposal_canonical_sha256": item["proposal_canonical_sha256"],
            "target_relative_path": "项目/a.md",
            "target_key": "f" * 64,
            "operation": "content_update",
            "reconcile_action": "MIGRATE_LEGACY_SCOPE",
            "fencing_token": 7,
        }

        self.assertEqual(
            content_migrate._completed_handoff_target(
                client, review, state, handoff
            ),
            "项目/a.md",
        )
        handoff["proposal_id"] = "d" * 32
        self.assertEqual(
            content_migrate._completed_handoff_target(
                client, review, state, handoff
            ),
            "",
        )

    def test_progress_transaction_lock_rejects_concurrent_state_machine(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            if sys.platform != "win32":
                root.chmod(0o700)
            progress = root / "review.progress.jsonl"
            entered = threading.Event()
            release = threading.Event()
            failures: list[BaseException] = []

            def hold_lock() -> None:
                try:
                    with content_migrate.progress_transaction_lock(progress):
                        entered.set()
                        release.wait(timeout=5)
                except BaseException as exc:  # pragma: no cover - assertion reports it.
                    failures.append(exc)

            holder = threading.Thread(target=hold_lock)
            holder.start()
            self.assertTrue(entered.wait(timeout=5))
            try:
                with self.assertRaises(content_migrate.ContentMigrationError) as caught:
                    with content_migrate.progress_transaction_lock(progress):
                        pass
                self.assertEqual(caught.exception.reason_code, "MIGRATION_ALREADY_RUNNING")
            finally:
                release.set()
                holder.join(timeout=5)
            self.assertFalse(holder.is_alive())
            self.assertEqual(failures, [])
            lock_path = content_migrate._progress_lock_path(progress)
            self.assertTrue(lock_path.is_file())
            if sys.platform != "win32":
                self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)

    def test_blocked_apply_returns_structured_result_for_every_item(self) -> None:
        review = review_for([query_item("项目/a.md"), query_item("项目/b.md")])
        progress_path = mock.Mock()
        progress_path.exists.return_value = False
        progress_path.is_symlink.return_value = False
        progress_path.__str__ = mock.Mock(return_value="/private/review.progress.jsonl")
        client = mock.Mock(actor="codex")
        failure = content_migrate.ContentMigrationError("TARGET_BASE_DRIFT", "apply-preflight", "项目/a.md")
        with mock.patch.object(content_migrate, "_run_apply", side_effect=failure), mock.patch.object(
            content_migrate, "progress_transaction_lock", return_value=contextlib.nullcontext()
        ):
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=progress_path,
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["items"][0]["status"], "blocked")
        self.assertEqual(result["items"][1]["status"], "not_attempted")

    def test_expired_validated_governance_recovery_ignores_only_unrelated_drift_and_stops(self) -> None:
        targets = ("项目/a.md", "项目/b.md")
        review = review_for([query_item(target) for target in targets])
        review["mode"] = content_migrate.GOVERNANCE_V4_MODE
        review["doctor_binding"].update({
            "owner_lane_policy": content_migrate.GOVERNANCE_OWNER_LANE_POLICY,
            "owner_actor": "codex",
        })
        proposal = "---\nstatus: active\nagent_scope: shared\n---\n# Migrated\n"
        proposal_digest = intent.content_hashes(proposal.encode("utf-8"))
        first = review["items"][0]
        first.update({
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "proposal_size_bytes": proposal_digest.size_bytes,
        })
        phase = prepared_event(targets[0])
        events = [progress_header(), phase]
        handoff = {
            "status": "issued",
            "token": "already-consumed-token",
            "capability_path": "/private/capability.json",
            "handoff_path": "/private/handoff.json",
            "capability_id": "c" * 32,
            "consumed_recovery": True,
            "intent_status": "validated",
            "intent_expires_at": "2026-01-01T00:00:00+00:00",
            "intent_reason_code": "",
            "subject_actor": "codex",
            "task_hash": confirmation_capability.task_hash(
                "session-1", "codex"
            ),
            "session_hash": confirmation_capability.session_hash(
                "session-1"
            ),
            "proposal_id": phase["proposal_id"],
            "proposal_raw_sha256": first["proposal_raw_sha256"],
            "proposal_canonical_sha256": first[
                "proposal_canonical_sha256"
            ],
            "target_relative_path": targets[0],
            "target_key": targets[0].casefold(),
            "operation": "governance_migration",
            "reconcile_action": "UPDATE",
            "fencing_token": phase["fencing_token"],
        }
        current = {
            "owner_lane_policy": content_migrate.GOVERNANCE_OWNER_LANE_POLICY,
            "owner_actor": "codex",
            # The other reviewed row drifted and a new row appeared. Neither
            # may be treated as authorization to process another target.
            "migration_query": [
                {"target_relative_path": targets[1], "changed": True},
                {"target_relative_path": "项目/new.md", "changed": True},
            ],
        }

        class Client:
            actor = "codex"
            session_id = "session-1"

            def __init__(self) -> None:
                self.actions: list[tuple[str, dict[str, object]]] = []

            def doctor(self):
                return {"status": "warning"}

            def write(self, action, request):
                self.actions.append((action, dict(request)))
                if action == "read-target":
                    return {
                        "ok": True,
                        "status": "found",
                        "exists": True,
                        "scope_migration": False,
                        "target_relative_path": targets[0],
                        "app_id": first["requested_app_id"],
                        "project_id": first["requested_project_id"],
                        "content": proposal,
                        "read_token": "1" * 64,
                        "base_raw_sha256": proposal_digest.raw_sha256,
                        "base_canonical_sha256": (
                            proposal_digest.canonical_sha256
                        ),
                        "base_git_head": "8" * 40,
                        "expected_memory_id": "",
                    }
                if action == "apply":
                    return {
                        "status": "applied",
                        "recommended_action": "UPDATE",
                        "target_relative_path": targets[0],
                        "scope_migration": False,
                        "proposal_id": phase["proposal_id"],
                        "fencing_token": phase["fencing_token"],
                        "proposal_raw_sha256": first[
                            "proposal_raw_sha256"
                        ],
                        "proposal_canonical_sha256": first[
                            "proposal_canonical_sha256"
                        ],
                        "git_commit": "8" * 40,
                        "receipt_id": "b" * 32,
                        "idempotent": True,
                    }
                raise AssertionError(action)

        client = Client()
        stored = {
            "status": "validated",
            "reason_code": "",
            "expires_at": handoff["intent_expires_at"],
            "validated_git_head": phase["base_git_head"],
            "evidence_ref_sha256": "e" * 64,
            "early_commit": 0,
            "proposal_commit": "",
        }
        recovered = {
            **stored,
            "reason_code": intent.EXPIRED_VALIDATED_RECOVERY_REASON,
        }
        appended: list[dict[str, object]] = []
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=events,
        ), mock.patch.object(
            content_migrate,
            "normalize_and_project_query_for_actor",
            return_value=({}, current),
        ), mock.patch.object(
            content_migrate,
            "assert_doctor_migration_safe",
        ), mock.patch.object(
            content_migrate,
            "compare_current_query",
            side_effect=AssertionError("scope-wide CAS must be bypassed only here"),
        ), mock.patch.object(
            content_migrate,
            "_governance_recovery_intent_snapshot",
            return_value=stored,
        ), mock.patch.object(
            content_migrate,
            "_assert_governance_recovery_git_projection",
        ), mock.patch.object(
            intent,
            "recover_expired_validated_lease",
            return_value=recovered,
        ) as lease_recovery, mock.patch.object(
            content_migrate,
            "_assert_completed_recovery_git_projection",
        ):
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path=handoff["capability_path"],
                confirmation_capability_token=handoff["token"],
                confirmation_handoff=handoff,
                append=lambda _path, event: appended.append(event),
            )

        self.assertEqual(result["status"], "replan_required")
        self.assertEqual(
            result["reason_code"],
            "EXPIRED_VALIDATED_RECOVERY_REPLAN_REQUIRED",
        )
        self.assertEqual(result["items"][0]["status"], "applied")
        self.assertEqual(result["items"][1]["status"], "not_attempted")
        self.assertEqual([event["event"] for event in appended], ["completed"])
        self.assertEqual(
            [action for action, _request in client.actions],
            ["read-target", "apply", "read-target"],
        )
        apply_request = client.actions[1][1]
        self.assertNotIn("confirmation_capability_path", apply_request)
        self.assertNotIn("confirmation_capability_token", apply_request)
        lease_recovery.assert_called_once()

    def test_elapsed_first_recovery_consumes_exact_generated_index_before_doctor_and_opens_one_repair_window(self) -> None:
        targets = ("项目/a.md", "项目/b.md")
        review = review_for([query_item(target) for target in targets])
        review["mode"] = content_migrate.GOVERNANCE_V4_MODE
        review["doctor_binding"].update({
            "owner_lane_policy": content_migrate.GOVERNANCE_OWNER_LANE_POLICY,
            "owner_actor": "codex",
        })
        proposal = "---\nstatus: active\nagent_scope: shared\n---\n# Migrated\n"
        proposal_digest = intent.content_hashes(proposal.encode("utf-8"))
        item = review["items"][0]
        item.update({
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "proposal_size_bytes": proposal_digest.size_bytes,
        })
        phase = prepared_event(targets[0])
        handoff = {
            "status": "issued",
            "token": "already-consumed-token",
            "capability_path": "/private/capability.json",
            "handoff_path": "/private/handoff.json",
            "capability_id": "c" * 32,
            "consumed_recovery": True,
            "intent_status": "validated",
            "intent_expires_at": "2000-01-01T00:10:00+00:00",
            "intent_reason_code": intent.EXPIRED_VALIDATED_RECOVERY_REASON,
            "subject_actor": "codex",
            "task_hash": confirmation_capability.task_hash("session-1", "codex"),
            "session_hash": confirmation_capability.session_hash("session-1"),
            "proposal_id": phase["proposal_id"],
            "proposal_raw_sha256": item["proposal_raw_sha256"],
            "proposal_canonical_sha256": item["proposal_canonical_sha256"],
            "target_relative_path": targets[0],
            "target_key": targets[0].casefold(),
            "operation": "governance_migration",
            "reconcile_action": "UPDATE",
            "fencing_token": phase["fencing_token"],
        }
        call_order: list[str] = []

        class Client:
            actor = "codex"
            session_id = "session-1"

            def doctor(self):
                call_order.append("doctor")
                return {"status": "warning"}

            def write(self, action, request):
                call_order.append(action)
                if action == "read-target":
                    return {
                        "ok": True,
                        "status": "found",
                        "exists": True,
                        "scope_migration": False,
                        "target_relative_path": targets[0],
                        "app_id": item["requested_app_id"],
                        "project_id": item["requested_project_id"],
                        "content": proposal,
                        "read_token": "1" * 64,
                        "base_raw_sha256": proposal_digest.raw_sha256,
                        "base_canonical_sha256": proposal_digest.canonical_sha256,
                        "base_git_head": "8" * 40,
                        "expected_memory_id": "",
                    }
                if action == "apply":
                    return {
                        "status": "applied",
                        "recommended_action": "UPDATE",
                        "target_relative_path": targets[0],
                        "scope_migration": False,
                        "proposal_id": phase["proposal_id"],
                        "fencing_token": phase["fencing_token"],
                        "proposal_raw_sha256": item["proposal_raw_sha256"],
                        "proposal_canonical_sha256": item["proposal_canonical_sha256"],
                        "git_commit": "8" * 40,
                        "receipt_id": "b" * 32,
                        "idempotent": True,
                    }
                raise AssertionError(action)

        stored = {
            "status": "validated",
            "reason_code": intent.EXPIRED_VALIDATED_RECOVERY_REASON,
            "expires_at": handoff["intent_expires_at"],
            "validated_git_head": phase["base_git_head"],
            "evidence_ref_sha256": "e" * 64,
            "early_commit": 0,
            "proposal_commit": "",
        }
        generated_recovery = {
            "transaction_id": "d" * 32,
            "git_head": "8" * 40,
            "index_base_sha256": "a" * 64,
            "generated_sha256": "a" * 64,
            "closeout_git_commit": "8" * 40,
            "lease_fences_sha256": "f" * 64,
            "status": "consumed",
        }
        repaired = {
            **stored,
            "intent_id": phase["proposal_id"],
            "fencing_token": phase["fencing_token"],
            "reason_code": intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON,
            "expires_at": "2099-01-01T00:05:00+00:00",
        }
        appended: list[dict[str, object]] = []

        def recover_generated(**kwargs):
            call_order.append("generated-index-recovery")
            publisher = kwargs.get("publish_repair")
            if publisher is not None:
                return {
                    "evidence": generated_recovery,
                    "repair_intent": publisher(generated_recovery),
                }
            return generated_recovery

        def recover_lease(*_args, **kwargs):
            call_order.append("repair-lease")
            self.assertEqual(kwargs["generated_index_recovery"], generated_recovery)
            return repaired

        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header(), phase],
        ), mock.patch.object(
            content_migrate,
            "normalize_and_project_query_for_actor",
            return_value=(
                {},
                {
                    "owner_lane_policy": content_migrate.GOVERNANCE_OWNER_LANE_POLICY,
                    "owner_actor": "codex",
                    "migration_query": [],
                },
            ),
        ), mock.patch.object(
            content_migrate,
            "assert_doctor_migration_safe",
        ), mock.patch.object(
            content_migrate,
            "_governance_recovery_intent_snapshot",
            return_value=stored,
        ), mock.patch.object(
            content_migrate,
            "_assert_governance_recovery_git_projection",
        ), mock.patch.object(
            content_migrate.memory_closeout,
            "recover_expired_governance_generated_index_transaction",
            side_effect=recover_generated,
        ) as generated, mock.patch.object(
            intent,
            "recover_expired_validated_lease",
            side_effect=recover_lease,
        ) as lease_recovery, mock.patch.object(
            content_migrate,
            "_assert_completed_recovery_git_projection",
        ):
            result = content_migrate.run_apply(
                Client(),
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path=handoff["capability_path"],
                confirmation_capability_token=handoff["token"],
                confirmation_handoff=handoff,
                append=lambda _path, event: appended.append(event),
            )

        self.assertEqual(result["status"], "replan_required")
        self.assertEqual(result["items"][0]["status"], "applied")
        self.assertEqual(result["items"][1]["status"], "not_attempted")
        self.assertLess(
            call_order.index("generated-index-recovery"),
            call_order.index("doctor"),
        )
        self.assertLess(call_order.index("doctor"), call_order.index("repair-lease"))
        self.assertEqual(generated.call_count, 2)
        self.assertIsNone(generated.call_args_list[0].kwargs["publish_repair"])
        self.assertTrue(
            callable(generated.call_args_list[1].kwargs["publish_repair"])
        )
        lease_recovery.assert_called_once()
        self.assertEqual([event["event"] for event in appended], ["completed"])

    def test_elapsed_repair_window_rejects_before_generated_index_helper(self) -> None:
        review = review_for([query_item("项目/a.md"), query_item("项目/b.md")])
        review["mode"] = content_migrate.GOVERNANCE_V4_MODE
        phase = prepared_event("项目/a.md")
        item = review["items"][0]
        handoff = {
            "status": "issued",
            "token": "already-consumed-token",
            "consumed_recovery": True,
            "intent_status": "validated",
            "intent_expires_at": "2000-01-01T00:05:00+00:00",
            "intent_reason_code": intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON,
            "subject_actor": "codex",
            "task_hash": confirmation_capability.task_hash("session-1", "codex"),
            "session_hash": confirmation_capability.session_hash("session-1"),
            "proposal_id": phase["proposal_id"],
            "proposal_raw_sha256": item["proposal_raw_sha256"],
            "proposal_canonical_sha256": item["proposal_canonical_sha256"],
            "target_relative_path": "项目/a.md",
            "target_key": "项目/a.md".casefold(),
            "operation": "governance_migration",
            "reconcile_action": "UPDATE",
            "fencing_token": phase["fencing_token"],
        }
        client = mock.Mock(actor="codex", session_id="session-1")
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header(), phase],
        ), mock.patch.object(
            content_migrate.memory_closeout,
            "recover_expired_governance_generated_index_transaction",
        ) as generated:
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_handoff=handoff,
            )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["reason_code"],
            "EXPIRED_VALIDATED_RECOVERY_REPAIR_WINDOW_ELAPSED",
        )
        generated.assert_not_called()
        client.doctor.assert_not_called()
        client.write.assert_not_called()

    def test_expired_validated_terminal_retry_scrubs_and_never_processes_next_item(self) -> None:
        targets = ("项目/a.md", "项目/b.md")
        review = review_for([query_item(target) for target in targets])
        review["mode"] = content_migrate.GOVERNANCE_V4_MODE
        phase = prepared_event(targets[0])
        terminal = completed_event(targets[0])
        events = [progress_header(), phase, terminal]
        first = review["items"][0]
        handoff = {
            "status": "issued",
            "token": "already-consumed-token",
            "capability_path": "/private/capability.json",
            "handoff_path": "/private/handoff.json",
            "capability_id": "c" * 32,
            "consumed_recovery": True,
            "intent_status": "completed",
            "intent_reason_code": (
                intent.EXPIRED_VALIDATED_RECOVERY_COMPLETED_REASON
            ),
            "subject_actor": "codex",
            "task_hash": confirmation_capability.task_hash(
                "session-1", "codex"
            ),
            "session_hash": confirmation_capability.session_hash(
                "session-1"
            ),
            "proposal_id": phase["proposal_id"],
            "proposal_raw_sha256": first["proposal_raw_sha256"],
            "proposal_canonical_sha256": first[
                "proposal_canonical_sha256"
            ],
            "target_relative_path": targets[0],
            "target_key": targets[0].casefold(),
            "operation": "governance_migration",
            "reconcile_action": "UPDATE",
            "fencing_token": phase["fencing_token"],
        }
        client = mock.Mock(actor="codex", session_id="session-1")

        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=events,
        ), mock.patch.object(
            confirmation_capability,
            "mark_confirmation_handoff_consumed",
        ) as scrub, mock.patch.object(
            content_migrate,
            "_run_apply_with_structured_failure",
        ) as ordinary_apply:
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path=handoff["capability_path"],
                confirmation_capability_token=handoff["token"],
                confirmation_handoff=handoff,
            )

        self.assertEqual(result["status"], "replan_required")
        self.assertEqual(
            result["reason_code"],
            "EXPIRED_VALIDATED_RECOVERY_REPLAN_REQUIRED",
        )
        self.assertEqual(result["items"][0]["status"], "already_applied")
        self.assertTrue(result["items"][0]["idempotent"])
        self.assertEqual(result["items"][1]["status"], "not_attempted")
        self.assertEqual(
            result["recovered_target_relative_path"], targets[0]
        )
        scrub.assert_called_once_with(
            write_gateway.CONFIG_ROOT,
            handoff_path="/private/handoff.json",
            capability_id="c" * 32,
        )
        ordinary_apply.assert_not_called()
        client.doctor.assert_not_called()
        client.write.assert_not_called()
        self.assertEqual(handoff["status"], "consumed")
        self.assertNotIn("token", handoff)

    def test_expired_validated_recovery_requires_target_disappearance_before_lease_mutation(self) -> None:
        review = review_for([query_item("项目/a.md")])
        review["mode"] = content_migrate.GOVERNANCE_V4_MODE
        review["doctor_binding"].update({
            "owner_lane_policy": content_migrate.GOVERNANCE_OWNER_LANE_POLICY,
            "owner_actor": "codex",
        })
        item = review["items"][0]
        phase = prepared_event("项目/a.md")
        handoff = {
            "status": "issued",
            "token": "already-consumed-token",
            "capability_path": "/private/capability.json",
            "capability_id": "c" * 32,
            "consumed_recovery": True,
            "intent_status": "validated",
            "intent_expires_at": "2026-01-01T00:00:00+00:00",
            "intent_reason_code": "",
            "subject_actor": "codex",
            "task_hash": confirmation_capability.task_hash(
                "session-1", "codex"
            ),
            "session_hash": confirmation_capability.session_hash(
                "session-1"
            ),
            "proposal_id": phase["proposal_id"],
            "proposal_raw_sha256": item["proposal_raw_sha256"],
            "proposal_canonical_sha256": item[
                "proposal_canonical_sha256"
            ],
            "target_relative_path": "项目/a.md",
            "target_key": "项目/a.md".casefold(),
            "operation": "governance_migration",
            "reconcile_action": "UPDATE",
            "fencing_token": phase["fencing_token"],
        }
        client = mock.Mock(actor="codex", session_id="session-1")
        client.doctor.return_value = {"status": "warning"}
        current = {
            "owner_lane_policy": content_migrate.GOVERNANCE_OWNER_LANE_POLICY,
            "owner_actor": "codex",
            "migration_query": [{"target_relative_path": "项目/a.md"}],
        }
        with mock.patch.object(
            content_migrate,
            "progress_transaction_lock",
            return_value=contextlib.nullcontext(),
        ), mock.patch.object(
            content_migrate,
            "load_progress",
            return_value=[progress_header(), phase],
        ), mock.patch.object(
            content_migrate,
            "normalize_and_project_query_for_actor",
            return_value=({}, current),
        ), mock.patch.object(
            content_migrate,
            "assert_doctor_migration_safe",
        ), mock.patch.object(
            intent,
            "recover_expired_validated_lease",
        ) as lease_recovery:
            result = content_migrate.run_apply(
                client,
                review,
                review_sha256="7" * 64,
                progress_path=mock.Mock(),
                confirmation_capability_path=handoff["capability_path"],
                confirmation_capability_token=handoff["token"],
                confirmation_handoff=handoff,
            )
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["reason_code"],
            "EXPIRED_VALIDATED_RECOVERY_TARGET_NOT_DISAPPEARED",
        )
        lease_recovery.assert_not_called()
        client.write.assert_not_called()

    def test_expired_validated_recovery_rejects_any_existing_receipt(self) -> None:
        item = review_for([query_item("项目/a.md")])["items"][0]
        phase = prepared_event("项目/a.md")
        client = mock.Mock(actor="codex", session_id="session-1")
        handoff = {
            "intent_expires_at": "2026-01-01T00:00:00+00:00",
            "intent_reason_code": "",
        }
        with mock.patch.object(
            intent,
            "show_intent",
            return_value={
                "intent": {"status": "validated"},
                "receipt": {"outcome": "expired"},
            },
        ), mock.patch.object(
            write_gateway,
            "_formal_target",
            return_value=mock.Mock(target_key="项目/a.md".casefold()),
        ), self.assertRaises(content_migrate.ContentMigrationError) as caught:
            content_migrate._governance_recovery_intent_snapshot(
                client,
                review_sha256="7" * 64,
                item=item,
                phase=phase,
                handoff=handoff,
            )
        self.assertEqual(
            caught.exception.reason_code,
            "EXPIRED_VALIDATED_RECOVERY_RECEIPT_CONFLICT",
        )

    def test_expired_validated_recovery_git_projection_is_mode_and_history_strict(self) -> None:
        def invoke(case: str) -> str:
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                vault = root / "vault"
                target = vault / "项目" / "a.md"
                target.parent.mkdir(parents=True)
                subprocess = content_migrate.subprocess

                def git(*args: str) -> str:
                    completed = subprocess.run(
                        ["git", "-C", str(root), *args],
                        text=True,
                        encoding="utf-8",
                        capture_output=True,
                        check=True,
                    )
                    return completed.stdout.strip()

                git("init", "-q")
                git("config", "user.name", "Recovery Test")
                git("config", "user.email", "recovery@example.invalid")
                base = "---\nstatus: active\n---\n# Base\n"
                proposal = "---\nstatus: active\nagent_scope: shared\n---\n# Base\n"
                target.write_text(base, encoding="utf-8")
                git("add", "vault/项目/a.md")
                git("commit", "-qm", "base")
                base_head = git("rev-parse", "HEAD")
                base_digest = intent.content_hashes(base.encode("utf-8"))
                proposal_digest = intent.content_hashes(
                    proposal.encode("utf-8")
                )
                target.write_text(proposal, encoding="utf-8")

                if case == "base_only":
                    current_head = base_head
                else:
                    git("add", "vault/项目/a.md")
                    git("commit", "-qm", "proposal")
                    current_head = git("rev-parse", "HEAD")
                    if case == "dirty_third_state":
                        target.write_text("third state\n", encoding="utf-8")
                    elif case == "worktree_executable":
                        target.chmod(0o755)
                    elif case == "worktree_symlink":
                        other = target.with_name("other.md")
                        other.write_text(proposal, encoding="utf-8")
                        target.unlink()
                        target.symlink_to(other.name)
                    elif case == "git_executable_history":
                        git("update-index", "--chmod=+x", "vault/项目/a.md")
                        git("commit", "-qm", "executable mode")
                        current_head = git("rev-parse", "HEAD")
                        target.chmod(0o644)
                        git("config", "core.filemode", "false")
                    elif case == "symlink_history":
                        target.unlink()
                        target.symlink_to("a.md")
                        git("add", "vault/项目/a.md")
                        git("commit", "-qm", "symlink mode")
                        target.unlink()
                        target.write_text(proposal, encoding="utf-8")
                        git("add", "vault/项目/a.md")
                        git("commit", "-qm", "restore regular")
                        current_head = git("rev-parse", "HEAD")
                    elif case == "rename_history":
                        git("mv", "vault/项目/a.md", "vault/项目/temp.md")
                        git("commit", "-qm", "rename away")
                        git("mv", "vault/项目/temp.md", "vault/项目/a.md")
                        git("commit", "-qm", "rename back")
                        current_head = git("rev-parse", "HEAD")

                item = {
                    "target_relative_path": "项目/a.md",
                    "base_git_head": base_head,
                    "base_raw_sha256": base_digest.raw_sha256,
                    "base_canonical_sha256": base_digest.canonical_sha256,
                    "proposal_raw_sha256": proposal_digest.raw_sha256,
                    "proposal_canonical_sha256": (
                        proposal_digest.canonical_sha256
                    ),
                }
                phase = {
                    "base_git_head": base_head,
                    "proposal_id": "a" * 32,
                    "fencing_token": 7,
                }
                stored = {
                    "validated_git_head": base_head,
                    "early_commit": 0,
                    "proposal_commit": "",
                }
                with mock.patch.object(intent, "VAULT_ROOT", vault), mock.patch.object(
                    intent, "GIT_ROOT", root
                ):
                    try:
                        content_migrate._assert_governance_recovery_git_projection(
                            target="项目/a.md",
                            item=item,
                            phase=phase,
                            stored=stored,
                            current_head=current_head,
                        )
                    except content_migrate.ContentMigrationError as exc:
                        return exc.reason_code
                return "ok"

        self.assertEqual(invoke("success"), "ok")
        blocked = {
            "base_only": "EXPIRED_VALIDATED_RECOVERY_COMMIT_CONTENT_MISMATCH",
            "dirty_third_state": "EXPIRED_VALIDATED_RECOVERY_TARGET_DRIFT",
            "worktree_executable": "EXPIRED_VALIDATED_RECOVERY_WORKTREE_UNSAFE",
            "worktree_symlink": "EXPIRED_VALIDATED_RECOVERY_GIT_PROJECTION_UNAVAILABLE",
            "git_executable_history": "EXPIRED_VALIDATED_RECOVERY_COMMIT_CONTENT_MISMATCH",
            "symlink_history": "EXPIRED_VALIDATED_RECOVERY_TARGET_HISTORY_CHANGED",
            "rename_history": "EXPIRED_VALIDATED_RECOVERY_TARGET_HISTORY_CHANGED",
        }
        for case, reason in blocked.items():
            with self.subTest(case=case):
                self.assertEqual(invoke(case), reason)


if __name__ == "__main__":
    unittest.main()
