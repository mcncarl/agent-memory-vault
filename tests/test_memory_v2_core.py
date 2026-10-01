from __future__ import annotations

import datetime as dt
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import agent_memory_claim as claim
import agent_memory_content_migrate as content_migrate
import agent_memory_doctor as memory_doctor
import agent_memory_env as memory_env
import agent_memory_host_automation as host_automation
import agent_memory_intent as intent
import agent_memory_index as memory_index
import agent_memory_migrate as migrate
import agent_memory_stop_hook as stop_hook
import agent_memory_write as writer
import agent_memory_state as memory_state
import install_host_hooks as host_hooks
import install_runtime as runtime_install


def load_posix_installer():
    path = SCRIPTS_ROOT / "install-posix.py"
    loader = importlib.machinery.SourceFileLoader("test_install_posix_module", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def doctor_payload(
    *,
    legacy_scope_documents: int = 0,
) -> dict[str, object]:
    required = legacy_scope_documents > 0
    scope_status = "warn" if legacy_scope_documents else "pass"
    legacy_items = [
        {
            "target_relative_path": f"项目/legacy-{index}.md",
            "issues": {"app_id": "missing"},
            "migrate_action": "MIGRATE_LEGACY_SCOPE",
            "migrate_legacy_scope": True,
            "legacy_scope_app_id": "agent-memory",
            "requested_app_id": "agent-memory",
            "requested_project_id": f"legacy-{index}",
            "automatable": True,
            "manual_review_reasons": [],
        }
        for index in range(legacy_scope_documents)
    ]
    empty_hash = hashlib.sha256(b"[]").hexdigest()
    return {
        "ok": True,
        "status": "warning" if required else "ok",
        "checks": [
            {
                "name": "legacy_scope_documents",
                "status": scope_status,
                "detail": {
                    "policy": "full_vault_explicit_scope_v1",
                    "migration_query_schema_version": 1,
                    "legacy_scope_documents": legacy_scope_documents,
                    "automatable_documents": legacy_scope_documents,
                    "manual_review_documents": 0,
                    "unsafe_documents": [],
                    "migration_query": legacy_items,
                    **({"bootstrap_advisory": True} if legacy_scope_documents else {}),
                },
            },
            {
                "name": "governance_metadata_v4",
                "status": "pass",
                "detail": {
                    "policy": "governance_metadata_v4",
                    "migration_query_schema_version": 4,
                    "governed_documents": 0,
                    "migration_candidate_documents": 0,
                    "automatable_documents": 0,
                    "manual_review_documents": 0,
                    "risk_candidate_documents": 0,
                    "risk_automatable_documents": 0,
                    "risk_manual_review_documents": 0,
                    "clean_documents": 0,
                    "unsafe_documents": [],
                    "documents": [],
                    "migration_query": [],
                    "manual_review_queue": [],
                    "risk_migration_query": [],
                    "migration_query_sha256": empty_hash,
                    "risk_migration_query_sha256": empty_hash,
                    "ordinary_document_dates_never_verify": True,
                },
            },
            {
                "name": "temporal_fact_coverage",
                "status": "pass",
                "message": "Atomic fact coverage is complete.",
                "detail": {},
            },
        ],
        "summary": {
            "pass": 2 + int(not legacy_scope_documents),
            "warn": int(bool(legacy_scope_documents)),
            "fail": 0,
        },
    }


def published_result(
    *,
    legacy_scope_documents: int = 0,
) -> dict[str, object]:
    content_debt = migrate._validate_preflight_doctor_payload(
        doctor_payload(legacy_scope_documents=legacy_scope_documents)
    )
    return {
        "ok": True,
        "preflight_attestation": {
            **content_debt,
        },
    }


def safe_governance_doctor_payload(
    vault: Path,
    *,
    legacy_scope_documents: int = 0,
) -> dict[str, object]:
    target = vault / "项目" / "Ailu事实-插件ID.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "---\n"
        f"memory_id: {'a' * 64}\n"
        "status: active\nagent_scope: shared\napp_id: agent-memory\n"
        "project_id: ailu-plugin-id\ntemporal_policy: stable\n"
        "review_after_days: 90\nrisk_class: action_sensitive\n"
        "fact_key: ailu.plugin_id\nvalid_from: 2026-08-25\n"
        "verified_at: 2026-08-25\n---\n# Ailu plugin id\n",
        encoding="utf-8",
    )
    with mock.patch.object(memory_doctor, "VAULT_ROOT", vault), mock.patch.object(
        memory_index, "VAULT_ROOT", vault
    ):
        governance = memory_doctor.governance_metadata_migration_health()
    payload = doctor_payload(legacy_scope_documents=legacy_scope_documents)
    payload["checks"][1] = {
        "name": "governance_metadata_v4",
        "status": "warn",
        "message": "Governance migration remains.",
        "detail": governance,
    }
    rel_path = "项目/Ailu事实-插件ID.md"
    payload["checks"][2] = {
        "name": "temporal_fact_coverage",
        "status": "fail",
        "message": "One automatic atomic fact gap remains.",
        "detail": {
            "action_sensitive_documents": [rel_path],
            "uncovered": [rel_path],
            "gap_details": [{
                "rel_path": rel_path,
                "missing_or_invalid": ["evidence_provenance"],
                "evidence_provenance": {
                    "present": False,
                    "source": "write_gateway_v2_receipt",
                    "reason_code": "CURRENT_CONTENT_EVIDENCE_RECEIPT_MISSING",
                    "current_content_bound": False,
                    "checked_receipts": 1,
                },
            }],
            "structural_and_routing_excluded": True,
            "coverage_is_per_document": True,
            "coverage_requires": [
                "non_structural_temporal_policy",
                "fact_key",
                "valid_from",
                "frontmatter_verified_at",
                "current_content_write_gateway_evidence",
            ],
            "fact_records": 1,
            "migration_is_explicit_only": True,
        },
    }
    payload["summary"] = {
        "pass": int(not legacy_scope_documents),
        "warn": 1 + int(bool(legacy_scope_documents)),
        "fail": 1,
    }
    payload["status"] = "error"
    payload["ok"] = False
    return payload


class MemoryV2CoreTests(unittest.TestCase):
    def connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        claim.ensure_schema(conn)
        memory_state.install_search_log_privacy_guards(conn)
        conn.commit()
        return conn

    def insert_intent(
        self,
        conn: sqlite3.Connection,
        *,
        intent_id: str,
        target_key: str,
        fencing_token: int,
        status: str = "bound",
        expires_at: str = "2099-01-01T00:00:00+00:00",
    ) -> None:
        empty = hashlib.sha256(b"").hexdigest()
        now = "2026-08-12T00:00:00+00:00"
        values = {
            "intent_id": intent_id,
            "schema_version": intent.STATE_SCHEMA_VERSION,
            "writer_protocol_version": intent.WRITER_PROTOCOL_VERSION,
            "actor": "codex",
            "session_hash": intent.session_hash("session-v2"),
            "target_rel_path": "AGENTS.md",
            "target_key": target_key,
            "fencing_token": fencing_token,
            "base_exists": 1,
            "base_raw_sha256": empty,
            "base_canonical_sha256": empty,
            "base_git_head": "0" * 40,
            "proposal_raw_sha256": empty,
            "proposal_canonical_sha256": empty,
            "proposal_size_bytes": 0,
            "proposal_path_sha256": empty,
            "status": status,
            "created_at": now,
            "updated_at": now,
            "expires_at": expires_at,
        }
        columns = ", ".join(values)
        placeholders = ", ".join("?" for _ in values)
        conn.execute(
            f"INSERT INTO memory_write_intents ({columns}) VALUES ({placeholders})",
            tuple(values.values()),
        )

    def test_fences_are_monotonic_and_expiry_releases_claim_projection(self) -> None:
        with self.connection() as conn:
            first = intent._allocate_fencing_token(conn, "agents.md")
            self.assertEqual(first, 1)
            self.insert_intent(
                conn,
                intent_id="intent-old",
                target_key="agents.md",
                fencing_token=first,
                expires_at="2000-01-01T00:00:00+00:00",
            )
            conn.execute(
                "INSERT INTO memory_session_claims ("
                "session_hash, actor, path, rel_path, status, claimed_at, updated_at, "
                "intent_id, target_key, fencing_token, claim_kind"
                ") VALUES (?, 'codex', ?, 'AGENTS.md', 'active', ?, ?, ?, ?, ?, 'intent')",
                (
                    intent.session_hash("session-v2"),
                    str(intent.VAULT_ROOT / "AGENTS.md"),
                    "2026-08-12T00:00:00+00:00",
                    "2026-08-12T00:00:00+00:00",
                    "intent-old",
                    "agents.md",
                    first,
                ),
            )
            changed = intent._expire_active_rows(
                conn,
                current=dt.datetime(2026, 8, 12, tzinfo=dt.timezone.utc),
                target_key="agents.md",
            )
            self.assertEqual(changed, 1)
            self.assertEqual(
                conn.execute("SELECT status FROM memory_session_claims").fetchone()[0],
                "expired",
            )
            self.assertEqual(
                conn.execute("SELECT outcome FROM memory_write_receipts").fetchone()[0],
                "expired",
            )

            second = intent._allocate_fencing_token(conn, "agents.md")
            self.assertEqual(second, 2)
            self.insert_intent(
                conn,
                intent_id="intent-new",
                target_key="agents.md",
                fencing_token=second,
            )
            conn.execute(
                "INSERT INTO memory_session_claims ("
                "session_hash, actor, path, rel_path, status, claimed_at, updated_at, "
                "intent_id, target_key, fencing_token, claim_kind"
                ") VALUES (?, 'codex', ?, 'AGENTS.md', 'active', ?, ?, ?, ?, ?, 'intent')",
                (
                    intent.session_hash("session-new"),
                    str(intent.VAULT_ROOT / "AGENTS.md"),
                    "2026-08-12T01:00:00+00:00",
                    "2026-08-12T01:00:00+00:00",
                    "intent-new",
                    "agents.md",
                    second,
                ),
            )
            self.assertEqual(
                conn.execute(
                    "SELECT fencing_token FROM memory_session_claims WHERE status='active'"
                ).fetchone()[0],
                2,
            )

    def test_state_schema_four_and_writer_protocol_two_are_distinct(self) -> None:
        with self.connection() as conn:
            meta = dict(conn.execute("SELECT key, value FROM meta"))
            self.assertEqual(meta["agent_memory_state_schema_version"], "4")
            self.assertEqual(meta["agent_memory_writer_protocol_version"], "2")
            self.assertIn(
                "fencing_token",
                {row[1] for row in conn.execute("PRAGMA table_info(memory_file_observations)")},
            )
            self.assertIn(
                "resolved_at",
                {row[1] for row in conn.execute("PRAGMA table_info(memory_closeout_incidents)")},
            )

    def test_verify_does_not_publish_without_explicit_commit_gate(self) -> None:
        with self.connection() as conn:
            report = migrate.verify(conn)
            self.assertTrue(report["ok"])
            self.assertFalse(report["runtime_transition"]["ready"])

            report = migrate.verify(conn, publish_ready=True)
            self.assertFalse(report["ok"])
            self.assertEqual(
                report["runtime_transition"]["reason_code"],
                "STRONG_PREFLIGHT_REQUIRED",
            )

    def test_validated_raw_drift_terminalizes_intent_and_claim_in_one_transaction(self) -> None:
        with self.connection() as conn:
            class NonClosingConnection:
                def __init__(self, wrapped: sqlite3.Connection) -> None:
                    self.wrapped = wrapped

                def __getattr__(self, name: str):
                    return getattr(self.wrapped, name)

                def __enter__(self):
                    self.wrapped.__enter__()
                    return self

                def __exit__(self, *args):
                    return self.wrapped.__exit__(*args)

                def close(self) -> None:
                    pass

            fence = intent._allocate_fencing_token(conn, "agents.md")
            self.insert_intent(
                conn,
                intent_id="intent-drift",
                target_key="agents.md",
                fencing_token=fence,
                status="validated",
            )
            expected = intent.content_hashes(b"expected\n")
            observed = intent.content_hashes(b"observed\r\n")
            conn.execute(
                "UPDATE memory_write_intents SET final_raw_sha256=?, final_canonical_sha256=?, "
                "validation_mode='exact' WHERE intent_id='intent-drift'",
                (expected.raw_sha256, expected.canonical_sha256),
            )
            conn.execute(
                "INSERT INTO memory_session_claims ("
                "session_hash, actor, path, rel_path, status, claimed_at, updated_at, "
                "intent_id, target_key, fencing_token, claim_kind"
                ") VALUES (?, 'codex', ?, 'AGENTS.md', 'active', ?, ?, ?, ?, ?, 'intent')",
                (
                    intent.session_hash("session-v2"),
                    str(intent.VAULT_ROOT / "AGENTS.md"),
                    "2026-08-12T00:00:00+00:00",
                    "2026-08-12T00:00:00+00:00",
                    "intent-drift",
                    "agents.md",
                    fence,
                ),
            )
            conn.commit()
            proxy = NonClosingConnection(conn)
            with mock.patch.object(intent, "connect", return_value=proxy), mock.patch.object(
                intent,
                "_read_target",
                return_value=(True, observed),
            ):
                result = intent.validate_closeout(
                    "intent-drift",
                    actor="codex",
                    raw_session_id="session-v2",
                )
            self.assertFalse(result["ok"])
            self.assertEqual(result["reason_code"], "VALIDATED_CONTENT_CHANGED")
            row = conn.execute(
                "SELECT i.status, r.outcome, r.final_raw_sha256, c.status AS claim_status "
                "FROM memory_write_intents i "
                "JOIN memory_write_receipts r ON r.intent_id=i.intent_id "
                "JOIN memory_session_claims c ON c.intent_id=i.intent_id "
                "WHERE i.intent_id='intent-drift'"
            ).fetchone()
            self.assertEqual(row["status"], "failed")
            self.assertEqual(row["outcome"], "failed")
            self.assertEqual(row["final_raw_sha256"], expected.raw_sha256)
            self.assertEqual(row["claim_status"], "expired")

    def test_exact_adopt_finalize_is_the_only_incident_resolution_path(self) -> None:
        with self.connection() as conn:
            class NonClosingConnection:
                def __init__(self, wrapped: sqlite3.Connection) -> None:
                    self.wrapped = wrapped

                def __getattr__(self, name: str):
                    return getattr(self.wrapped, name)

                def __enter__(self):
                    self.wrapped.__enter__()
                    return self

                def __exit__(self, *args):
                    return self.wrapped.__exit__(*args)

                def close(self) -> None:
                    pass

            proxy = NonClosingConnection(conn)
            final = intent.content_hashes(b"adopted exact bytes\n")
            target_path = intent.VAULT_ROOT / "AGENTS.md"
            fence = intent._allocate_fencing_token(conn, "agents.md")
            self.insert_intent(
                conn,
                intent_id="intent-adopt",
                target_key="agents.md",
                fencing_token=fence,
                status="validated",
            )
            conn.execute(
                "UPDATE memory_write_intents SET final_raw_sha256=?, final_canonical_sha256=?, "
                "validation_mode='exact', reconcile_action='ADOPT' WHERE intent_id='intent-adopt'",
                (final.raw_sha256, final.canonical_sha256),
            )
            conn.execute(
                "INSERT INTO memory_session_claims ("
                "session_hash, actor, path, rel_path, status, claimed_at, updated_at, "
                "intent_id, target_key, fencing_token, claim_kind"
                ") VALUES (?, 'codex', ?, 'AGENTS.md', 'active', ?, ?, ?, ?, ?, 'intent')",
                (
                    intent.session_hash("session-v2"),
                    str(target_path.resolve()),
                    "2026-08-12T00:00:00+00:00",
                    "2026-08-12T00:00:00+00:00",
                    "intent-adopt",
                    "agents.md",
                    fence,
                ),
            )
            conn.execute(
                "INSERT INTO memory_closeout_incidents ("
                "incident_id, intent_id, target_key, rel_path, expected_sha256, observed_sha256, "
                "git_commit, reason_code, detected_at"
                ") VALUES ('incident-old', 'intent-old', 'agents.md', 'AGENTS.md', ?, ?, ?, "
                "'POST_FINALIZE_CONTENT_DRIFT', '2026-08-12T00:00:00+00:00')",
                ("0" * 64, final.raw_sha256, "0" * 40),
            )
            conn.commit()
            self.assertEqual(len(stop_hook.unresolved_closeout_incidents(conn)), 1)
            with mock.patch.object(claim, "connect", return_value=proxy), mock.patch.object(
                claim,
                "_observed_file_sha256",
                return_value=final.raw_sha256,
            ), mock.patch.object(
                intent,
                "_resolve_git_commit",
                return_value="1" * 40,
            ), mock.patch.object(
                intent,
                "_git_blob",
                return_value=b"adopted exact bytes\n",
            ), mock.patch.object(
                intent,
                "_repo_rel_path",
                return_value="AGENTS.md",
            ), mock.patch.object(Path, "is_file", return_value=True):
                result = claim.finalize_closeout_batch(
                    [{
                        "intent_id": "intent-adopt",
                        "fencing_token": fence,
                        "target": "AGENTS.md",
                        "rel_path": "AGENTS.md",
                        "file_sha256": final.raw_sha256,
                        "git_commit": "1" * 40,
                    }],
                    actor="codex",
                    raw_session_id="session-v2",
                )
            self.assertTrue(result["ok"])
            self.assertEqual(result["resolved_incidents"], 1)
            self.assertEqual(stop_hook.unresolved_closeout_incidents(conn), [])
            incident = conn.execute(
                "SELECT resolved_at, resolution_intent_id, resolution_git_commit "
                "FROM memory_closeout_incidents WHERE incident_id='incident-old'"
            ).fetchone()
            self.assertTrue(incident["resolved_at"])
            self.assertEqual(incident["resolution_intent_id"], "intent-adopt")
            self.assertEqual(incident["resolution_git_commit"], "1" * 40)

    def test_migrator_blocks_active_legacy_claim(self) -> None:
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO memory_session_claims ("
                "session_hash, actor, path, rel_path, status, claimed_at, updated_at"
                ") VALUES ('legacy-session', 'codex', ?, 'AGENTS.md', 'active', ?, ?)",
                (
                    str(intent.VAULT_ROOT / "AGENTS.md"),
                    "2026-08-12T00:00:00+00:00",
                    "2026-08-12T00:00:00+00:00",
                ),
            )
            report = migrate.inspect(conn)
            self.assertIn("ACTIVE_LEGACY_CLAIM", report["blockers"])

    def test_migrator_blocks_terminal_intent_active_claim_for_explicit_disposition(self) -> None:
        with self.connection() as conn:
            fence = intent._allocate_fencing_token(conn, "agents.md")
            self.insert_intent(
                conn,
                intent_id="intent-terminal",
                target_key="agents.md",
                fencing_token=fence,
                status="completed",
            )
            conn.execute(
                "INSERT INTO memory_session_claims ("
                "session_hash, actor, path, rel_path, status, claimed_at, updated_at, "
                "intent_id, target_key, fencing_token, claim_kind"
                ") VALUES (?, 'codex', ?, 'AGENTS.md', 'active', ?, ?, ?, ?, ?, 'intent')",
                (
                    intent.session_hash("session-v2"),
                    str(intent.VAULT_ROOT / "AGENTS.md"),
                    "2026-08-12T00:00:00+00:00",
                    "2026-08-12T00:00:00+00:00",
                    "intent-terminal",
                    "agents.md",
                    fence,
                ),
            )
            report = migrate.inspect(conn)
            self.assertIn("TERMINAL_INTENT_ACTIVE_CLAIM", report["blockers"])
            self.assertEqual(len(report["terminal_intent_active_claims"]), 1)

    def test_terminal_claim_disposition_requires_exact_cas_and_commit_chain(self) -> None:
        with self.connection() as conn:
            class NonClosingConnection:
                def __init__(self, wrapped: sqlite3.Connection) -> None:
                    self.wrapped = wrapped
                def __getattr__(self, name: str):
                    return getattr(self.wrapped, name)
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    return False
                def close(self) -> None:
                    pass

            raw = b"terminal committed bytes\n"
            final = intent.content_hashes(raw)
            fence = intent._allocate_fencing_token(conn, "agents.md")
            self.insert_intent(conn, intent_id="intent-dispose", target_key="agents.md", fencing_token=fence, status="completed")
            conn.execute(
                "UPDATE memory_write_intents SET final_raw_sha256=?, final_canonical_sha256=? WHERE intent_id='intent-dispose'",
                (final.raw_sha256, final.canonical_sha256),
            )
            updated = "2026-08-12T00:00:00+00:00"
            hashed = intent.session_hash("session-v2")
            target = str(intent.VAULT_ROOT / "AGENTS.md")
            conn.execute(
                "INSERT INTO memory_session_claims (session_hash,actor,path,rel_path,status,claimed_at,updated_at,intent_id,target_key,fencing_token,claim_kind) "
                "VALUES (?,'codex',?,'AGENTS.md','active',?,?,?,'agents.md',?,'intent')",
                (hashed, target, updated, updated, "intent-dispose", fence),
            )
            conn.execute(
                "INSERT INTO memory_write_receipts (receipt_id,intent_id,writer_protocol_version,actor,session_hash,target_rel_path,target_key,fencing_token,outcome,reason_code,base_raw_sha256,proposal_raw_sha256,proposal_canonical_sha256,final_raw_sha256,final_canonical_sha256,base_git_head,git_commit,created_at) "
                "VALUES ('receipt-dispose','intent-dispose',2,'codex',?,'AGENTS.md','agents.md',?,'completed','WRITE_COMPLETED',?,?,?,?,?,?,?,?)",
                (hashed, fence, "0"*64, "0"*64, "0"*64, final.raw_sha256, final.canonical_sha256, "0"*40, "1"*40, updated),
            )
            conn.commit()
            report = migrate.inspect(conn)
            document = report["disposition_template"]
            with mock.patch.object(intent, "_resolve_git_commit", return_value="1" * 40), mock.patch.object(
                intent, "_git_blob", return_value=raw
            ), mock.patch.object(intent, "_repo_rel_path", return_value="AGENTS.md"):
                preview = migrate._validate_disposition_document(conn, report, document)
                self.assertEqual(len(preview), 1)
                conn.execute("BEGIN IMMEDIATE")
                applied = migrate._apply_dispositions(conn, preview)
                conn.commit()
            self.assertEqual(applied, 1)
            self.assertEqual(conn.execute("SELECT status FROM memory_session_claims").fetchone()[0], "completed")

    def test_disposition_preview_rejects_uncovered_live_unsupported_actor(self) -> None:
        with self.connection() as conn:
            fence = intent._allocate_fencing_token(conn, "agents.md")
            self.insert_intent(
                conn,
                intent_id="intent-live-unsupported-actor",
                target_key="agents.md",
                fencing_token=fence,
            )
            conn.execute(
                "UPDATE memory_write_intents SET actor=? WHERE intent_id=?",
                ("retired-client", "intent-live-unsupported-actor"),
            )
            conn.execute(
                "INSERT INTO memory_session_claims ("
                "session_hash, actor, path, rel_path, status, claimed_at, updated_at, "
                "intent_id, target_key, fencing_token, claim_kind"
                ") VALUES (?, ?, ?, 'AGENTS.md', 'active', ?, ?, ?, 'agents.md', ?, 'intent')",
                (
                    intent.session_hash("session-v2"),
                    "retired-client",
                    str(intent.VAULT_ROOT / "AGENTS.md"),
                    "2026-08-12T00:00:00+00:00",
                    "2026-08-12T00:00:00+00:00",
                    "intent-live-unsupported-actor",
                    fence,
                ),
            )
            report = migrate.preview_dispositions(conn, None)
            self.assertFalse(report["ok"])
            self.assertEqual(report["reason_code"], "UNHANDLED_MIGRATION_BLOCKERS")
            self.assertEqual(report["blockers"], ["UNSUPPORTED_ACTIVE_ACTOR"])

    def test_doctor_counts_unknown_active_actors_generically(self) -> None:
        import agent_memory_doctor as doctor

        with self.connection() as conn:
            fence = intent._allocate_fencing_token(conn, "agents.md")
            self.insert_intent(
                conn,
                intent_id="intent-live-unsupported-doctor",
                target_key="agents.md",
                fencing_token=fence,
            )
            conn.execute(
                "UPDATE memory_write_intents SET actor=? WHERE intent_id=?",
                ("retired-client", "intent-live-unsupported-doctor"),
            )
            conn.execute(
                "INSERT INTO memory_session_claims ("
                "session_hash, actor, path, rel_path, status, claimed_at, updated_at, "
                "intent_id, target_key, fencing_token, claim_kind"
                ") VALUES (?, ?, ?, 'AGENTS.md', 'active', ?, ?, ?, 'agents.md', ?, 'intent')",
                (
                    intent.session_hash("session-v2"),
                    "retired-client",
                    str(intent.VAULT_ROOT / "AGENTS.md"),
                    "2026-08-12T00:00:00+00:00",
                    "2026-08-12T00:00:00+00:00",
                    "intent-live-unsupported-doctor",
                    fence,
                ),
            )
            with mock.patch.object(doctor, "load_config", return_value={
                "write_gateway": {
                    "writer_protocol_version": 2,
                    "state_schema_required": 3,
                    "canonical_actors": ["codex", "claude", "ailu"],
                },
            }):
                healthy, detail = doctor.writer_protocol_health(conn)
        self.assertFalse(healthy)
        self.assertEqual(detail["unsupported_active_actors"], 2)

    def test_failed_terminal_intent_disposition_expires_claim_projection(self) -> None:
        with self.connection() as conn:
            fence = intent._allocate_fencing_token(conn, "agents.md")
            self.insert_intent(
                conn,
                intent_id="intent-failed-dispose",
                target_key="agents.md",
                fencing_token=fence,
                status="failed",
            )
            updated = "2026-08-12T00:00:00+00:00"
            hashed = intent.session_hash("session-v2")
            target = str(intent.VAULT_ROOT / "AGENTS.md")
            conn.execute(
                "INSERT INTO memory_session_claims (session_hash,actor,path,rel_path,status,claimed_at,updated_at,intent_id,target_key,fencing_token,claim_kind) "
                "VALUES (?,'codex',?,'AGENTS.md','active',?,?,?,'agents.md',?,'intent')",
                (hashed, target, updated, updated, "intent-failed-dispose", fence),
            )
            conn.execute(
                "INSERT INTO memory_write_receipts (receipt_id,intent_id,writer_protocol_version,actor,session_hash,target_rel_path,target_key,fencing_token,outcome,reason_code,base_raw_sha256,proposal_raw_sha256,proposal_canonical_sha256,final_raw_sha256,final_canonical_sha256,base_git_head,git_commit,created_at) "
                "VALUES ('receipt-failed-dispose','intent-failed-dispose',2,'codex',?,'AGENTS.md','agents.md',?,'failed','WRITE_FAILED',?,?,?,?,?,?,?,?)",
                (hashed, fence, "0"*64, "0"*64, "0"*64, "0"*64, "0"*64, "0"*40, "", updated),
            )
            conn.commit()
            report = migrate.inspect(conn)
            decisions = migrate._validate_disposition_document(
                conn,
                report,
                report["disposition_template"],
            )
            conn.execute("BEGIN IMMEDIATE")
            self.assertEqual(migrate._apply_dispositions(conn, decisions), 1)
            conn.commit()
            self.assertEqual(
                conn.execute("SELECT status FROM memory_session_claims").fetchone()[0],
                "expired",
            )

    def test_terminal_disposition_rejects_claim_bound_to_a_different_path(self) -> None:
        with self.connection() as conn:
            raw = b"terminal committed bytes\n"
            final = intent.content_hashes(raw)
            fence = intent._allocate_fencing_token(conn, "agents.md")
            self.insert_intent(
                conn,
                intent_id="intent-wrong-path",
                target_key="agents.md",
                fencing_token=fence,
                status="completed",
            )
            conn.execute(
                "UPDATE memory_write_intents SET final_raw_sha256=?, final_canonical_sha256=? "
                "WHERE intent_id='intent-wrong-path'",
                (final.raw_sha256, final.canonical_sha256),
            )
            updated = "2026-08-12T00:00:00+00:00"
            hashed = intent.session_hash("session-v2")
            conn.execute(
                "INSERT INTO memory_session_claims (session_hash,actor,path,rel_path,status,claimed_at,updated_at,intent_id,target_key,fencing_token,claim_kind) "
                "VALUES (?,'codex',?,'INDEX.md','active',?,?,?,'index.md',?,'intent')",
                (hashed, str(intent.VAULT_ROOT / "INDEX.md"), updated, updated, "intent-wrong-path", fence),
            )
            conn.execute(
                "INSERT INTO memory_write_receipts (receipt_id,intent_id,writer_protocol_version,actor,session_hash,target_rel_path,target_key,fencing_token,outcome,reason_code,base_raw_sha256,proposal_raw_sha256,proposal_canonical_sha256,final_raw_sha256,final_canonical_sha256,base_git_head,git_commit,created_at) "
                "VALUES ('receipt-wrong-path','intent-wrong-path',2,'codex',?,'AGENTS.md','agents.md',?,'completed','WRITE_COMPLETED',?,?,?,?,?,?,?,?)",
                (hashed, fence, "0"*64, "0"*64, "0"*64, final.raw_sha256, final.canonical_sha256, "0"*40, "1"*40, updated),
            )
            conn.commit()
            report = migrate.inspect(conn)
            with self.assertRaisesRegex(ValueError, "DISPOSITION_TARGET_BINDING_MISMATCH"):
                migrate._validate_disposition_document(
                    conn,
                    report,
                    report["disposition_template"],
                )

    def test_full_vault_includes_top_level_governance_files(self) -> None:
        previous = intent.FULL_VAULT_GATEWAY
        intent.FULL_VAULT_GATEWAY = True
        try:
            self.assertTrue(intent.is_protected_target("AGENTS.md"))
            self.assertTrue(intent.is_protected_target("项目/_模板-项目.md"))
        finally:
            intent.FULL_VAULT_GATEWAY = previous

    def test_writer_governance_profile_and_actor_authorization(self) -> None:
        previous_actor = writer.ACTOR
        writer.ACTOR = "codex"
        try:
            target = writer._formal_target("AGENTS.md")
            self.assertEqual(
                writer._scope_request(
                    {"app_id": "agent-memory", "project_id": "agent-memory-vault"},
                    target=target,
                ),
                ("agent-memory", "agent-memory-vault"),
            )
            metadata = writer._validate_writer_markdown(
                "# Governance\n",
                path=target.path,
                app_id="agent-memory",
                project_id="agent-memory-vault",
                require_explicit_write_scope=True,
            )
            self.assertEqual(metadata["memory_type"], "governance")
            proposal = "# Governance\n"
            digest = intent.content_hashes(proposal.encode("utf-8"))
            parsed = writer._validate_apply_request({
                "schema_version": 2,
                "proposal_id": "a" * 32,
                "fencing_token": 1,
                "target_relative_path": "AGENTS.md",
                "proposal_markdown": proposal,
                "proposal_raw_sha256": digest.raw_sha256,
                "proposal_canonical_sha256": digest.canonical_sha256,
                "confirmed_by": "codex",
                "confirmation_reference": "task:exact-proposal-v2",
            })
            self.assertEqual(parsed[5], "codex")
            writer.ACTOR = "ailu"
            with self.assertRaises(writer.MemoryWriteError):
                writer._validate_apply_request({
                    "schema_version": 2,
                    "proposal_id": "a" * 32,
                    "fencing_token": 1,
                    "target_relative_path": "AGENTS.md",
                    "proposal_markdown": proposal,
                    "proposal_raw_sha256": digest.raw_sha256,
                    "proposal_canonical_sha256": digest.canonical_sha256,
                    "confirmed_by": "codex",
                    "confirmation_reference": "task:exact-proposal-v2",
                })
        finally:
            writer.ACTOR = previous_actor

    def test_config_python_migration_only_changes_top_level_runtime(self) -> None:
        original = (
            'python = "/usr/bin/python3"\n'
            'memory_root = "/vault"\n'
            "\n[semantic_retrieval]\n"
            'python = "/semantic/python"\n'
        )
        migrated, changed = migrate._migrate_top_level_python(
            original,
            Path("/managed/.venv/bin/python"),
        )
        self.assertTrue(changed)
        self.assertIn('python = "/managed/.venv/bin/python"', migrated)
        self.assertIn('python = "/semantic/python"', migrated)

    def test_host_hook_merge_removes_only_managed_duplicates(self) -> None:
        hooks = {
            "Stop": [{
                "hooks": [
                    {"type": "command", "command": "python agent_memory_stop_hook.py --old"},
                    {"type": "command", "command": "keep-unrelated"},
                    {"type": "command", "command": "python agent_memory_stop_hook.py --duplicate"},
                ]
            }]
        }
        replacement = {"type": "command", "command": "managed-v2", "timeout": 320}
        self.assertEqual(
            host_hooks.merge_event(
                hooks,
                "Stop",
                script_name="agent_memory_stop_hook.py",
                entry=replacement,
            ),
            "updated",
        )
        self.assertEqual(
            hooks["Stop"][0]["hooks"],
            [replacement, {"type": "command", "command": "keep-unrelated"}],
        )
        # A second upgrade sees the canonical memoryctl route structurally and
        # reconciles it in place instead of appending another Stop hook.
        canonical = {
            "type": "command",
            "command": host_hooks.command(
                Path("/private/runtime/.venv/bin/python"),
                "agent_memory_stop_hook.py",
                "--actor", "codex", "--protocol", "codex", "--event", "stop-hook",
                "--auto-closeout", "--timeout", "300",
            ),
            "timeout": 320,
        }
        host_hooks.merge_event(
            hooks,
            "Stop",
            script_name="agent_memory_stop_hook.py",
            entry=canonical,
        )
        host_hooks.merge_event(
            hooks,
            "Stop",
            script_name="agent_memory_stop_hook.py",
            entry=dict(canonical),
        )
        managed = [
            item for group in hooks["Stop"] for item in group["hooks"]
            if host_hooks._managed_event_route(
                item.get("command", ""),
                script_name="agent_memory_stop_hook.py",
            )
        ]
        self.assertEqual(managed, [canonical])

    def test_explicit_no_host_hooks_attestation_remains_ready(self) -> None:
        result = memory_env.managed_host_hook_integrity({
            "preflight_attestation": {
                "host_hooks": {"policy": "explicitly_disabled", "verified": True}
            }
        })
        self.assertTrue(result["ok"])

    def test_required_codex_hook_attestation_ignores_unrelated_config_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            codex = home / ".codex"
            codex.mkdir()
            hooks = codex / "hooks.json"
            hooks.write_text('{"hooks":{"Stop":[]}}\n', encoding="utf-8")
            original_config = 'service_tier = "default"\n[features]\nhooks = true\n'
            config = codex / "config.toml"
            config.write_text(original_config, encoding="utf-8")
            marker = {
                "preflight_attestation": {
                    "host_hooks": {
                        "policy": "required",
                        "verified": True,
                        "hosts": ["codex"],
                        # Deliberately model the currently installed legacy
                        # marker so the safe Runtime upgrade restores service
                        # without weakening the dedicated Hook digest.
                        "codex": {
                            "hooks_sha256": hashlib.sha256(hooks.read_bytes()).hexdigest(),
                            "config_sha256": hashlib.sha256(original_config.encode()).hexdigest(),
                        },
                    }
                }
            }
            config.write_text(
                'model = "gpt-5.6-sol"\nservice_tier = "priority"\n'
                'model_reasoning_effort = "max"\n[features]\nhooks = true\n',
                encoding="utf-8",
            )
            with mock.patch.object(memory_env.Path, "home", return_value=home):
                result = memory_env.managed_host_hook_integrity(marker)
        self.assertTrue(result["ok"])
        self.assertEqual(result["mismatched_count"], 0)

    def test_required_codex_hook_attestation_fails_closed_on_hook_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            codex = home / ".codex"
            codex.mkdir()
            hooks = codex / "hooks.json"
            hooks.write_text('{"hooks":{"Stop":[]}}\n', encoding="utf-8")
            expected_hooks = hashlib.sha256(hooks.read_bytes()).hexdigest()
            (codex / "config.toml").write_text("[features]\nhooks = true\n", encoding="utf-8")
            marker = {
                "preflight_attestation": {
                    "host_hooks": {
                        "policy": "required",
                        "verified": True,
                        "hosts": ["codex"],
                        "codex": {
                            "hooks_sha256": expected_hooks,
                            "config_hooks_enabled": True,
                        },
                    }
                }
            }
            hooks.write_text('{"hooks":{"Stop":[{"hooks":[]}]}}\n', encoding="utf-8")
            with mock.patch.object(memory_env.Path, "home", return_value=home):
                result = memory_env.managed_host_hook_integrity(marker)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason_code"], "HOST_HOOK_ATTESTATION_MISMATCH")

    def test_required_codex_hook_attestation_fails_closed_when_hooks_are_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            codex = home / ".codex"
            codex.mkdir()
            hooks = codex / "hooks.json"
            hooks.write_text('{"hooks":{"Stop":[]}}\n', encoding="utf-8")
            (codex / "config.toml").write_text("[features]\nhooks = false\n", encoding="utf-8")
            marker = {
                "preflight_attestation": {
                    "host_hooks": {
                        "policy": "required",
                        "verified": True,
                        "hosts": ["codex"],
                        "codex": {
                            "hooks_sha256": hashlib.sha256(hooks.read_bytes()).hexdigest(),
                            "config_hooks_enabled": True,
                        },
                    }
                }
            }
            with mock.patch.object(memory_env.Path, "home", return_value=home):
                result = memory_env.managed_host_hook_integrity(marker)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason_code"], "HOST_HOOK_ATTESTATION_MISMATCH")

    def test_required_claude_attestation_binds_routes_not_unrelated_settings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            runtime = home / "runtime"
            python = runtime / ".venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            (runtime / "scripts").mkdir(parents=True)
            python.write_text("python\n", encoding="utf-8")
            (runtime / "scripts" / "memoryctl").write_text("memoryctl\n", encoding="utf-8")
            hooks: dict[str, object] = {}
            for event, spec in host_automation.claude_hook_specs().items():
                hooks[event] = [{"hooks": [{
                    "type": "command",
                    "command": host_automation.canonical_hook_command(python, runtime, spec),
                    "timeout": spec.timeout,
                }]}]
            classification = host_automation.classify_claude_hooks(
                hooks,
                runtime_python=python,
                runtime_root=runtime,
            )
            claude = home / ".claude"
            claude.mkdir()
            settings = claude / "settings.json"
            settings.write_text(
                json.dumps({"model": "old", "permissions": {"allow": ["Read"]}, "hooks": hooks}),
                encoding="utf-8",
            )
            marker = {
                "preflight_attestation": {
                    "host_hooks": {
                        "policy": "required",
                        "verified": True,
                        "hosts": ["claude"],
                        "claude": {
                            "settings_sha256": "0" * 64,
                            "classification": classification["events"],
                        },
                    }
                }
            }
            # Unrelated model/permission changes are outside the Hook route
            # contract and must not take the Runtime offline.
            settings.write_text(
                json.dumps({"model": "new", "permissions": {"deny": ["Write"]}, "hooks": hooks}),
                encoding="utf-8",
            )
            with (
                mock.patch.object(memory_env.Path, "home", return_value=home),
                mock.patch.object(memory_env, "RUNTIME_ROOT", runtime),
            ):
                healthy = memory_env.managed_host_hook_integrity(marker)
            self.assertTrue(healthy["ok"], healthy)
            self.assertEqual(healthy["mismatched_count"], 0)

            hooks["Stop"][0]["hooks"][0]["disabled"] = True  # type: ignore[index]
            settings.write_text(json.dumps({"model": "new", "hooks": hooks}), encoding="utf-8")
            with (
                mock.patch.object(memory_env.Path, "home", return_value=home),
                mock.patch.object(memory_env, "RUNTIME_ROOT", runtime),
            ):
                drifted = memory_env.managed_host_hook_integrity(marker)
            self.assertFalse(drifted["ok"])
            self.assertEqual(drifted["reason_code"], "HOST_HOOK_ATTESTATION_MISMATCH")

    def test_runtime_python_identity_allows_only_darwin_persistent_device_renumbering(self) -> None:
        def signed(value: dict[str, object]) -> dict[str, object]:
            result = json.loads(json.dumps(value))
            result.pop("attestation_sha256", None)
            result["attestation_sha256"] = hashlib.sha256(
                json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            return result

        identity = signed({
            "schema_version": 1,
            "launcher": "/runtime/.venv/bin/python",
            "launcher_chain": [{
                "path": ".venv/bin/python",
                "kind": "symlink",
                "link_target": "python3.12",
                "link_sha256": "d" * 64,
                "identity": {"device": 1, "inode": 2, "mode": 0o777, "size": 10, "mtime_ns": 4},
            }],
            "resolved_path": "/opt/python3.12",
            "resolved_sha256": "a" * 64,
            "resolved_identity": {"device": 1, "inode": 3, "mode": 0o755, "size": 20, "mtime_ns": 5},
            "version": [3, 12, 13],
            "implementation": "CPython",
            "probe_executable": "/runtime/.venv/bin/python",
            "base_prefix": "/runtime/.venv",
        })
        self.assertTrue(memory_state.runtime_python_attestation_matches(identity, dict(identity)))
        renumbered = json.loads(json.dumps(identity))
        renumbered["launcher_chain"][0]["identity"]["device"] = 9
        renumbered["resolved_identity"]["device"] = 9
        renumbered = signed(renumbered)
        self.assertTrue(memory_state.runtime_python_attestation_matches(
            identity, renumbered, platform="darwin"
        ))
        self.assertTrue(memory_state.runtime_python_static_attestation_matches(
            identity, renumbered, platform="darwin"
        ))
        self.assertFalse(memory_state.runtime_python_attestation_matches(
            identity, renumbered, platform="linux"
        ))
        wrong_inode = json.loads(json.dumps(renumbered))
        wrong_inode["resolved_identity"]["inode"] = 99
        wrong_inode = signed(wrong_inode)
        self.assertFalse(memory_state.runtime_python_attestation_matches(
            identity, wrong_inode, platform="darwin"
        ))
        drifted_hash = dict(identity)
        drifted_hash["resolved_sha256"] = "c" * 64
        drifted_hash = signed(drifted_hash)
        self.assertFalse(memory_state.runtime_python_attestation_matches(identity, drifted_hash))
        invalid_digest = dict(identity)
        invalid_digest["attestation_sha256"] = "0" * 64
        self.assertFalse(memory_state.runtime_python_attestation_matches(identity, invalid_digest))

    def test_runtime_python_probe_is_always_isolated_and_no_site(self) -> None:
        static = {
            "launcher": "/private/runtime/.venv/bin/python",
            "launcher_chain": [],
            "resolved_path": "/private/runtime/.venv/bin/python",
            "resolved_sha256": "a" * 64,
            "resolved_identity": {"device": 1, "inode": 2, "mode": 0o755, "size": 3, "mtime_ns": 4},
        }
        completed = mock.Mock(
            returncode=0,
            stdout=json.dumps({
                "version": [3, 12, 0],
                "implementation": "CPython",
                "executable": static["launcher"],
                "base_prefix": "/private/runtime/.venv",
            }),
        )
        with mock.patch.object(
            memory_state,
            "_python_launcher_identity",
            side_effect=[static, static],
        ), mock.patch.object(memory_state.subprocess, "run", return_value=completed) as invoked:
            memory_state.runtime_python_attestation(
                Path("/private/runtime"),
                Path(static["launcher"]),
            )
        self.assertEqual(invoked.call_args.args[0][1:4], ["-I", "-S", "-c"])

    def test_vector_preflight_uses_only_managed_venv_site_packages(self) -> None:
        default = migrate._isolated_runtime_script(
            "/runtime/.venv/bin/python",
            Path("/runtime/scripts/agent_memory_index.py"),
            "--scan",
        )
        vector = migrate._isolated_runtime_script(
            "/runtime/.venv/bin/python",
            Path("/runtime/scripts/agent_memory_zvec_index.py"),
            "--scan",
            load_site_packages=True,
        )
        self.assertEqual(default[1:3], ["-I", "-S"])
        self.assertEqual(vector[1], "-I")
        self.assertNotIn("-S", vector)
        self.assertIn("-c", vector)

    def test_managed_config_integrity_binds_attested_python_identity(self) -> None:
        runtime_root = memory_env.RUNTIME_ROOT
        python_path = runtime_root / ".venv" / "bin" / "python"
        text = (
            f'memory_root = "/vault"\n'
            f'git_root = "/git"\n'
            f'state_db = "/runtime/state.sqlite"\n'
            f'config_root = {json.dumps(str(runtime_root))}\n'
            f'python = {json.dumps(str(python_path))}\n'
            "[write_gateway]\n"
            'mode = "enforce"\n'
            "writer_protocol_version = 2\n"
            "state_schema_required = 4\n"
            'canonical_actors = ["codex", "claude", "ailu"]\n'
            "path_fencing = true\n"
            "claims_are_projection = true\n"
            "full_vault = true\n"
        )
        raw = text.encode("utf-8")
        identity = {
            "schema_version": 1,
            "launcher": str(python_path),
            "launcher_chain": [],
            "resolved_path": str(python_path),
            "resolved_sha256": "a" * 64,
            "resolved_identity": {
                "device": 1, "inode": 2, "mode": 0o755, "size": 3, "mtime_ns": 4,
            },
            "version": [3, 12, 0],
            "implementation": "CPython",
            "probe_executable": str(python_path),
            "base_prefix": str(runtime_root / ".venv"),
        }
        identity["attestation_sha256"] = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        marker = {
            "preflight_attestation": {
                "config_sha256": hashlib.sha256(raw).hexdigest(),
                "memory_root": "/vault",
                "git_root": "/git",
                "state_db": "/runtime/state.sqlite",
                "config_root": str(runtime_root),
                "runtime_python": identity,
            }
        }
        metadata = mock.Mock(st_mode=stat.S_IFREG | 0o600)
        environment = {
            "AGENT_MEMORY_ROOT": "/vault",
            "AGENT_MEMORY_GIT_ROOT": "/git",
            "AGENT_MEMORY_STATE_DB": "/runtime/state.sqlite",
            "AGENT_MEMORY_CONFIG_ROOT": str(runtime_root),
        }
        with mock.patch.dict(memory_env.os.environ, environment, clear=True), mock.patch.object(
            memory_env,
            "secure_read_bytes_and_stat_beneath",
            return_value=(raw, metadata),
        ), mock.patch.object(
            memory_env,
            "runtime_python_attestation",
            return_value=dict(identity),
        ), mock.patch.object(
            memory_env.sys,
            "executable",
            str(python_path),
        ):
            self.assertTrue(memory_env.managed_config_integrity(marker)["ok"])
        drifted = dict(identity)
        drifted["resolved_sha256"] = "b" * 64
        drifted.pop("attestation_sha256")
        drifted["attestation_sha256"] = hashlib.sha256(
            json.dumps(drifted, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        with mock.patch.dict(memory_env.os.environ, environment, clear=True), mock.patch.object(
            memory_env,
            "secure_read_bytes_and_stat_beneath",
            return_value=(raw, metadata),
        ), mock.patch.object(
            memory_env,
            "runtime_python_attestation",
            return_value=drifted,
        ), mock.patch.object(
            memory_env.sys,
            "executable",
            str(python_path),
        ):
            result = memory_env.managed_config_integrity(marker)
        self.assertFalse(result["ok"])
        self.assertFalse(result["runtime_python_ok"])

        with mock.patch.dict(memory_env.os.environ, environment, clear=True), mock.patch.object(
            memory_env,
            "secure_read_bytes_and_stat_beneath",
            return_value=(raw, metadata),
        ), mock.patch.object(
            memory_env,
            "runtime_python_attestation",
            return_value=dict(identity),
        ), mock.patch.object(
            memory_env.sys,
            "executable",
            "/usr/local/bin/python3",
        ):
            wrong_launcher = memory_env.managed_config_integrity(marker)
        self.assertFalse(wrong_launcher["ok"])
        self.assertFalse(wrong_launcher["current_runtime_launcher_ok"])

    def test_managed_runtime_integrity_fails_closed_when_containment_helper_rejects(self) -> None:
        manifest = {
            "files": {"memoryctl": "a" * 64},
            "support_files": {"requirements-vector.lock": "b" * 64},
            "template_files": {"templates/vault/AGENTS.md": "c" * 64},
        }
        manifest["bundle_sha256"] = hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        with mock.patch.object(
            memory_env,
            "_managed_read_optional",
            return_value=json.dumps(manifest).encode("utf-8"),
        ), mock.patch.object(
            memory_env,
            "secure_sha256_beneath",
            side_effect=memory_state.StateSecurityError("intermediate symlink"),
        ):
            result = memory_env.managed_runtime_integrity()
        self.assertFalse(result["ok"])
        self.assertEqual(result["mismatched_count"], 3)

    def test_strong_publish_rechecks_index_and_sqlite_at_terminal_boundary(self) -> None:
        class FakeConnection:
            def execute(self, sql: str):
                value = "ok" if "quick_check" in sql else 7
                return mock.Mock(fetchone=mock.Mock(return_value=(value,)))
            def close(self) -> None:
                pass

        manifest = {
            "manifest_sha256": "a" * 64,
            "bundle_sha256": "b" * 64,
            "files_verified": 30,
            "install_id": "1" * 64,
            "runtime_anchor_sha256": "2" * 64,
        }
        identity = {"schema_version": 1, "attestation_sha256": "c" * 64}
        config = {
            "sha256": "d" * 64,
            "memory_root": "/vault",
            "git_root": "/vault",
            "state_db": "/runtime/state.sqlite",
            "config_root": str(migrate.RUNTIME_ROOT),
            "python": "/runtime/.venv/bin/python",
            "runtime_python": identity,
            "semantic_enabled": True,
            "semantic_mode": "required",
        }
        state = {"ok": True, "quick_check": "ok"}
        command_payloads = [
            {"payload": {}},
            {"payload": {}},
            {"payload": {"ok": True, "status": "ok"}},
            {"payload": {"ok": True, "status": "ok"}},
            {"payload": doctor_payload()},
        ]
        index_health = mock.Mock(return_value={"doc_count": 4, "fts_count": 4})
        with mock.patch.object(migrate, "_runtime_manifest_health", return_value=manifest), mock.patch.object(
            migrate, "_runtime_config_health", return_value=config
        ), mock.patch.object(
            migrate, "verify_audit", return_value={"ok": True, "status": "verified"}
        ), mock.patch.object(migrate, "connect", return_value=FakeConnection()), mock.patch.object(
            migrate, "verify", return_value=state
        ), mock.patch.object(migrate, "_issue_preflight_capability", return_value=("x" * 64, {})), mock.patch.object(
            migrate, "_run_preflight_command", side_effect=command_payloads
        ) as run_preflight, mock.patch.object(
            migrate,
            "_run_generated_index_migration_locked",
            return_value={"payload": {"ok": True, "status": "ok"}},
        ), mock.patch.object(migrate, "_host_hook_health", return_value={"verified": True}), mock.patch.object(
            migrate, "_publish_scheduler_health", return_value={"healthy": True, "structural_only": True}
        ), mock.patch.object(
            migrate, "_index_health", index_health
        ), mock.patch.object(
            migrate, "_publish_runtime_ready", return_value={"ready": True}
        ) as publish:
            result = migrate.publish_ready_preflight(no_host_hooks=True, required_hosts=())
        self.assertTrue(result["runtime_transition"]["ready"])
        self.assertFalse(result["preflight_attestation"]["content_migration_required"])
        self.assertEqual(result["preflight_attestation"]["legacy_scope_documents"], 0)
        self.assertEqual(index_health.call_count, 3)
        zvec_command = run_preflight.call_args_list[2].args[0]
        self.assertIn("--init", zvec_command)
        self.assertLess(zvec_command.index("--init"), zvec_command.index("--scan"))
        doctor_call = run_preflight.call_args_list[-1]
        self.assertEqual(doctor_call.kwargs["accepted_returncodes"], (0, 2))
        self.assertTrue(doctor_call.kwargs["doctor_process_contract"])
        for call in run_preflight.call_args_list[:-1]:
            self.assertNotIn("accepted_returncodes", call.kwargs)
        publish.assert_called_once()

    def test_ready_runtime_can_issue_fresh_preflight_capability(self) -> None:
        marker = {
            "phase": "ready",
            "bundle_sha256": "b" * 64,
            "install_id": "1" * 64,
            "runtime_anchor_sha256": "2" * 64,
        }
        with mock.patch.object(
            migrate, "_runtime_json_object", return_value=marker
        ), mock.patch.object(migrate, "_atomic_transition") as publish:
            token, capability = migrate._issue_preflight_capability(
                {"bundle_sha256": "b" * 64}
            )
        self.assertGreaterEqual(len(token), 32)
        self.assertEqual(capability["phase"], "preflight")
        self.assertEqual(capability["bundle_sha256"], "b" * 64)
        publish.assert_called_once_with(capability)

    def test_user_direct_exact_textual_noop_is_promoted_to_update(self) -> None:
        promoted = writer._promote_user_direct_exact_noop(
            action="NOOP",
            recommended_target_key="项目/example.md",
            selected_target_key="项目/example.md",
            candidate_target_keys={"项目/example.md"},
            target_exists=True,
            target_canonical_sha256="a" * 64,
            proposal_canonical_sha256="b" * 64,
            source_class="user_direct",
            asserted_by="user",
        )
        self.assertEqual(promoted, "UPDATE")
        self.assertEqual(
            writer._promote_user_direct_exact_noop(
                action="NOOP",
                recommended_target_key="项目/other.md",
                selected_target_key="项目/example.md",
                candidate_target_keys={"项目/example.md", "项目/other.md"},
                target_exists=True,
                target_canonical_sha256="a" * 64,
                proposal_canonical_sha256="b" * 64,
                source_class="user_direct",
                asserted_by="user",
            ),
            "NOOP",
        )
        self.assertEqual(
            writer._promote_user_direct_exact_noop(
                action="MERGE_REQUIRED",
                recommended_target_key="",
                selected_target_key="项目/example.md",
                candidate_target_keys={"项目/example.md"},
                target_exists=True,
                target_canonical_sha256="a" * 64,
                proposal_canonical_sha256="b" * 64,
                source_class="user_direct",
                asserted_by="user",
            ),
            "UPDATE",
        )
        self.assertEqual(
            writer._promote_user_direct_exact_noop(
                action="MERGE_REQUIRED",
                recommended_target_key="",
                selected_target_key="项目/example.md",
                candidate_target_keys={"项目/example.md", "项目/other.md"},
                target_exists=True,
                target_canonical_sha256="a" * 64,
                proposal_canonical_sha256="b" * 64,
                source_class="user_direct",
                asserted_by="user",
            ),
            "MERGE_REQUIRED",
        )

    def test_strong_publish_refuses_terminal_markdown_index_drift(self) -> None:
        class FakeConnection:
            def execute(self, sql: str):
                value = "ok" if "quick_check" in sql else 7
                return mock.Mock(fetchone=mock.Mock(return_value=(value,)))
            def close(self) -> None:
                pass

        manifest = {
            "manifest_sha256": "a" * 64, "bundle_sha256": "b" * 64,
            "files_verified": 30, "install_id": "1" * 64,
            "runtime_anchor_sha256": "2" * 64,
        }
        config = {
            "sha256": "d" * 64, "memory_root": "/vault", "git_root": "/vault",
            "state_db": "/runtime/state.sqlite", "config_root": str(migrate.RUNTIME_ROOT),
            "python": "/runtime/.venv/bin/python",
            "runtime_python": {"schema_version": 1, "attestation_sha256": "c" * 64},
        }
        commands = [
            {"payload": {}}, {"payload": {}},
            {"payload": {"ok": True, "status": "ok"}}, {"payload": doctor_payload()},
        ]
        with mock.patch.object(migrate, "_runtime_manifest_health", return_value=manifest), mock.patch.object(
            migrate, "_runtime_config_health", return_value=config
        ), mock.patch.object(
            migrate, "verify_audit", return_value={"ok": True, "status": "verified"}
        ), mock.patch.object(migrate, "connect", return_value=FakeConnection()), mock.patch.object(
            migrate, "verify", return_value={"ok": True, "quick_check": "ok"}
        ), mock.patch.object(migrate, "_issue_preflight_capability", return_value=("x" * 64, {})), mock.patch.object(
            migrate, "_run_preflight_command", side_effect=commands
        ), mock.patch.object(
            migrate,
            "_run_generated_index_migration_locked",
            return_value={"payload": {"ok": True, "status": "ok"}},
        ), mock.patch.object(migrate, "_host_hook_health", return_value={"verified": True}), mock.patch.object(
            migrate, "_publish_scheduler_health", return_value={"healthy": True, "structural_only": True}
        ), mock.patch.object(
            migrate,
            "_index_health",
            side_effect=[
                {"doc_count": 4, "fts_count": 4},
                {"doc_count": 4, "fts_count": 4},
                {"doc_count": 5, "fts_count": 4},
            ],
        ), mock.patch.object(migrate, "_publish_runtime_ready") as publish:
            with self.assertRaisesRegex(ValueError, "PREFLIGHT_TERMINAL_INPUT_DRIFT"):
                migrate.publish_ready_preflight(no_host_hooks=True, required_hosts=())
        publish.assert_not_called()

    def test_strong_hook_attestation_accepts_only_isolated_memoryctl_route(self) -> None:
        python = Path("/private/runtime/.venv/bin/python")
        required = (
            "--actor", "codex", "--protocol", "codex", "--event", "stop-hook",
            "--auto-closeout", "--timeout", "300",
        )
        command = host_hooks.command(
            python,
            "agent_memory_stop_hook.py",
            *required,
        )
        entry = {"type": "command", "command": command, "timeout": 320}
        self.assertTrue(
            migrate._command_matches(
                entry,
                python=python,
                script=migrate.RUNTIME_ROOT / "scripts" / "agent_memory_stop_hook.py",
                required=required,
                forbidden=("--non-blocking",),
                max_timeout=360,
            )
        )
        entry["command"] = command.replace(" -I -S ", " ")
        self.assertFalse(
            migrate._command_matches(
                entry,
                python=python,
                script=migrate.RUNTIME_ROOT / "scripts" / "agent_memory_stop_hook.py",
                required=required,
                forbidden=("--non-blocking",),
                max_timeout=360,
            )
        )
        exact = {"type": "command", "command": command, "timeout": 320}
        duplicate = dict(exact)
        self.assertFalse(
            migrate._single_exact_managed_hook(
                [exact, duplicate],
                command_name="stop-hook",
                matches=lambda item: migrate._command_matches(
                    item,
                    python=python,
                    script=migrate.RUNTIME_ROOT / "scripts" / "agent_memory_stop_hook.py",
                    required=required,
                    forbidden=("--non-blocking",),
                    expected_timeout=320,
                ),
            )
        )
        extra = dict(exact)
        extra["command"] += " --unexpected"
        self.assertFalse(
            migrate._command_matches(
                extra,
                python=python,
                script=migrate.RUNTIME_ROOT / "scripts" / "agent_memory_stop_hook.py",
                required=required,
                forbidden=("--non-blocking",),
                expected_timeout=320,
            )
        )

    def test_automatic_writers_cannot_use_low_level_mutating_clis(self) -> None:
        for actor in ("codex", "claude", "ailu"):
            with self.subTest(actor=actor), self.assertRaisesRegex(
                intent.IntentError,
                "must mutate memory through write",
            ):
                intent.enforce_low_level_cli_policy(actor, "create")
            with self.subTest(actor=actor), self.assertRaisesRegex(
                ValueError,
                "LOW_LEVEL_GATEWAY_MUTATION_FORBIDDEN",
            ):
                claim.enforce_low_level_cli_policy(actor, "claim")
            intent.enforce_low_level_cli_policy(actor, "show")
            claim.enforce_low_level_cli_policy(actor, "list")

    def test_posix_installer_fresh_config_uses_v2_template_and_managed_paths(self) -> None:
        module = load_posix_installer()
        args = mock.Mock(
            memory_root="/private/vault",
            git_root="/private/vault",
            user_id="user",
            agent_id="shared",
            app_id="agent-memory",
        )
        paths = {
            "config_root": Path("/private/runtime"),
            "state": Path("/private/runtime/state.sqlite"),
        }
        text = module.fresh_config_text(args, paths, Path("/private/runtime/.venv/bin/python"))
        prefix = text.split("[semantic_retrieval]", 1)[0]
        self.assertIn('memory_root = "/private/vault"', prefix)
        self.assertIn('python = "/private/runtime/.venv/bin/python"', prefix)
        self.assertIn('[write_gateway]', text)
        self.assertIn('canonical_actors = ["codex", "claude", "ailu"]', text)
        parsed = migrate._load_toml_text(text)
        semantic = parsed["semantic_retrieval"]
        self.assertEqual(parsed["shadow"]["state_dir"], "/private/runtime/shadow")
        self.assertEqual(
            semantic["vector_dir"],
            "/private/runtime/zvec/memory_chunks_embeddinggemma_768",
        )
        self.assertEqual(semantic["python"], "/private/runtime/.venv/bin/python")
        self.assertEqual(semantic["lock_path"], "/private/runtime/locks/zvec.lock")
        self.assertEqual(
            semantic["model_manifest"],
            "/private/runtime/models/embeddinggemma-300m/model-manifest.json",
        )
        self.assertEqual(
            semantic["dependency_lock"],
            "/private/runtime/requirements-vector.lock",
        )
        self.assertEqual(
            semantic["embedding_worker_socket"],
            "/private/runtime/run/embedding.sock",
        )

    def test_config_plan_removes_only_obsolete_write_gateway_actor_key(self) -> None:
        original = (
            'memory_root = "/vault"\r\n'
            '# preserve this comment\r\n'
            '[write_gateway] # preserve this header comment\r\n'
            'mode = "enforce"\r\n'
            'legacy_actor = "retired-client" # remove this assignment only\r\n'
            'writer_protocol_version = 2\r\n'
            'state_schema_required = 4\r\n'
            'canonical_actors = ["codex", "claude", "ailu"]\r\n'
            'path_fencing = true\r\n'
            'claims_are_projection = true\r\n'
            'full_vault = true\r\n'
            'custom_gateway_key = "preserve"\r\n'
            '\r\n[unrelated]\r\n'
            'legacy_actor = "preserve-outside-write-gateway"\r\n'
        )
        expected = original.replace(
            'legacy_actor = "retired-client" # remove this assignment only\r\n',
            '',
            1,
        )
        with mock.patch.object(
            migrate,
            "_assert_no_config_migration_recovery",
        ), mock.patch.object(
            migrate,
            "_config_migration_operation_id",
            return_value="1" * 64,
        ), mock.patch.object(
            migrate,
            "_secure_config_bytes",
            return_value=(original.encode("utf-8"), mock.Mock()),
        ), mock.patch.object(
            migrate,
            "_managed_runtime_python",
            return_value=None,
        ):
            result = migrate.config_migration_plan()
        self.assertTrue(result["changed"])
        self.assertEqual(result["status"], "migration_required")
        self.assertEqual(
            result["operations"],
            [
                "REMOVE_WRITE_GATEWAY_LEGACY_ACTOR",
                "ADD_HOST_V4_DEFAULTS",
                "ADD_OBSERVABILITY_V4_DEFAULTS",
                "ADD_SHADOW_V4_DEFAULTS",
                "ADD_SEMANTIC_RETRIEVAL_V4_DEFAULTS",
            ],
        )
        self.assertTrue(result["_migrated_text"].startswith(expected))
        parsed = migrate._load_toml_text(result["_migrated_text"])
        self.assertNotIn("legacy_actor", parsed["write_gateway"])
        self.assertEqual(parsed["write_gateway"]["custom_gateway_key"], "preserve")
        self.assertEqual(parsed["unrelated"]["legacy_actor"], "preserve-outside-write-gateway")
        self.assertEqual(parsed["shadow"]["status"], "observing")
        self.assertTrue(str(parsed["shadow"]["state_dir"]).endswith("/shadow"))
        self.assertEqual(parsed["semantic_retrieval"]["candidate_pool_min"], 64)
        self.assertEqual(parsed["semantic_retrieval"]["candidate_pool_scope_min"], 128)
        self.assertEqual(parsed["semantic_retrieval"]["zvec_lock_timeout_seconds"], 2)
        self.assertEqual(parsed["semantic_retrieval"]["embedding_worker_idle_seconds"], 600)
        self.assertIn("vector_dir", parsed["semantic_retrieval"])
        self.assertIn("lock_path", parsed["semantic_retrieval"])

    def test_config_plan_is_noop_after_obsolete_gateway_key_removal(self) -> None:
        original = (
            '[write_gateway]\n'
            'mode = "enforce"\n'
            'writer_protocol_version = 2\n'
            'state_schema_required = 4\n'
            'canonical_actors = ["codex", "claude", "ailu"]\n'
            'path_fencing = true\n'
            'claims_are_projection = true\n'
            'full_vault = true\n'
        )
        with mock.patch.object(
            migrate,
            "_assert_no_config_migration_recovery",
        ), mock.patch.object(
            migrate,
            "_config_migration_operation_id",
            return_value="3" * 64,
        ), mock.patch.object(
            migrate,
            "_secure_config_bytes",
            return_value=(original.encode("utf-8"), mock.Mock()),
        ), mock.patch.object(
            migrate,
            "_managed_runtime_python",
            return_value=None,
        ):
            result = migrate.config_migration_plan()
        self.assertTrue(result["changed"])
        self.assertEqual(result["status"], "migration_required")
        self.assertEqual(
            result["operations"],
            [
                "ADD_HOST_V4_DEFAULTS",
                "ADD_OBSERVABILITY_V4_DEFAULTS",
                "ADD_SHADOW_V4_DEFAULTS",
                "ADD_SEMANTIC_RETRIEVAL_V4_DEFAULTS",
            ],
        )
        self.assertTrue(result["_migrated_text"].startswith(original))

    def test_config_plan_upgrades_gateway_state_three_to_four(self) -> None:
        original = (
            '[write_gateway]\n'
            'mode = "enforce"\n'
            'writer_protocol_version = 2\n'
            'state_schema_required = 3\n'
            'canonical_actors = ["codex", "claude", "ailu"]\n'
            'path_fencing = true\n'
            'claims_are_projection = true\n'
            'full_vault = true\n'
        )
        with mock.patch.object(
            migrate,
            "_assert_no_config_migration_recovery",
        ), mock.patch.object(
            migrate,
            "_config_migration_operation_id",
            return_value="4" * 64,
        ), mock.patch.object(
            migrate,
            "_secure_config_bytes",
            return_value=(original.encode("utf-8"), mock.Mock()),
        ), mock.patch.object(
            migrate,
            "_managed_runtime_python",
            return_value=None,
        ):
            result = migrate.config_migration_plan()
        self.assertTrue(result["changed"])
        self.assertEqual(
            result["operations"],
            [
                "UPGRADE_WRITE_GATEWAY_STATE_SCHEMA_V4",
                "ADD_HOST_V4_DEFAULTS",
                "ADD_OBSERVABILITY_V4_DEFAULTS",
                "ADD_SHADOW_V4_DEFAULTS",
                "ADD_SEMANTIC_RETRIEVAL_V4_DEFAULTS",
            ],
        )
        self.assertIn("state_schema_required = 4", result["_migrated_text"])

    def test_config_plan_fills_shadow_and_semantic_wiring_without_overwriting_private_values(self) -> None:
        original = (
            'config_root = "/private/custom-runtime"\n'
            '[write_gateway]\n'
            'mode = "enforce"\nwriter_protocol_version = 2\nstate_schema_required = 4\n'
            'canonical_actors = ["codex", "claude", "ailu"]\n'
            'path_fencing = true\nclaims_are_projection = true\nfull_vault = true\n'
            '[semantic_retrieval]\n'
            'candidate_pool_min = 91\n'
            'embedding_worker_idle_seconds = 777\n'
            '[shadow]\n'
            'state_dir = "/private/custom-runtime/custom-shadow"\n'
        )
        with mock.patch.object(
            migrate, "_assert_no_config_migration_recovery"
        ), mock.patch.object(
            migrate, "_config_migration_operation_id", return_value="8" * 64
        ), mock.patch.object(
            migrate, "_secure_config_bytes", return_value=(original.encode("utf-8"), mock.Mock())
        ), mock.patch.object(
            migrate, "_managed_runtime_python", return_value=None
        ):
            result = migrate.config_migration_plan()

        parsed = migrate._load_toml_text(result["_migrated_text"])
        self.assertEqual(parsed["semantic_retrieval"]["candidate_pool_min"], 91)
        self.assertEqual(parsed["semantic_retrieval"]["embedding_worker_idle_seconds"], 777)
        self.assertEqual(parsed["shadow"]["state_dir"], "/private/custom-runtime/custom-shadow")
        for key in (
            "candidate_pool_factor", "candidate_pool_scope_min", "candidate_pool_max",
            "zvec_lock_timeout_seconds", "zvec_max_distance", "embedding_worker_socket",
            "embedding_worker_cold_timeout_seconds", "embedding_worker_warm_timeout_seconds",
        ):
            self.assertIn(key, parsed["semantic_retrieval"])
        for key in (
            "status", "shadow_started_at", "runtime_installed_at", "manifest_sha256",
            "cutover_evidence_sha256", "cutover_evidence_file", "cutover_from_config_sha256",
            "cutover_config_backup", "cutover_at",
        ):
            self.assertIn(key, parsed["shadow"])

    def test_config_plan_fails_closed_on_recovery_artifact_and_large_config(self) -> None:
        valid = (
            '[write_gateway]\n'
            'mode = "enforce"\n'
            'writer_protocol_version = 2\n'
            'state_schema_required = 4\n'
            'canonical_actors = ["codex", "claude", "ailu"]\n'
            'path_fencing = true\n'
            'claims_are_projection = true\n'
            'full_vault = true\n'
        )
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            config = root / "agent-memory.toml"
            config.write_text(valid, encoding="utf-8")
            target_id = hashlib.sha256(config.name.encode("utf-8")).hexdigest()[:24]
            recovery = root / (
                f".agent-memory-config-cas-{target_id}-"
                f"{'1' * 64}.recovery"
            )
            recovery.write_bytes(b"preserved")
            with mock.patch.object(migrate, "config_path", return_value=config), mock.patch.object(
                migrate, "_config_security_root", return_value=root
            ), self.assertRaisesRegex(ValueError, "CONFIG_MIGRATION_RECOVERY_REQUIRED"):
                migrate.config_migration_plan()
            self.assertEqual(config.read_text(encoding="utf-8"), valid)
            self.assertEqual(recovery.read_bytes(), b"preserved")

        with tempfile.TemporaryFile() as oversized_handle:
            oversized_handle.truncate(migrate.MAX_RUNTIME_CONFIG_BYTES + 1)
            opened = mock.MagicMock()
            opened.__enter__.return_value = oversized_handle
            with mock.patch.object(
                migrate,
                "_config_security_root",
                return_value=Path("/private"),
            ), mock.patch.object(
                migrate,
                "secure_open_regular_beneath",
                return_value=opened,
            ), self.assertRaisesRegex(ValueError, "RUNTIME_CONFIG_TOO_LARGE"):
                migrate._secure_config_bytes(Path("/private/agent-memory.toml"))

    def test_config_migration_operation_identity_is_stable_and_content_bound(self) -> None:
        path = Path("/private/runtime/config/agent-memory.toml")
        with mock.patch.object(
            migrate,
            "_config_security_root",
            return_value=Path("/private/runtime"),
        ):
            first = migrate._config_migration_operation_id(
                path,
                before_sha256="1" * 64,
                after_sha256="2" * 64,
            )
            repeated = migrate._config_migration_operation_id(
                path,
                before_sha256="1" * 64,
                after_sha256="2" * 64,
            )
            changed = migrate._config_migration_operation_id(
                path,
                before_sha256="1" * 64,
                after_sha256="3" * 64,
            )
        self.assertEqual(first, repeated)
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first, changed)

    @unittest.skipUnless(memory_state.POSIX_PERMISSION_MODEL, "POSIX pinned-dir regression")
    def test_config_cas_cannot_escape_a_pinned_parent_after_symlink_swap(self) -> None:
        original = b"original-config\n"
        migrated = b"canonical-config\n"
        with tempfile.TemporaryDirectory() as raw_root:
            base = Path(raw_root).resolve()
            root = base / "runtime"
            config_dir = root / "config"
            outside = base / "outside"
            displaced_dir = root / "displaced-config"
            config_dir.mkdir(parents=True)
            outside.mkdir()
            target = config_dir / "agent-memory.toml"
            outside_target = outside / target.name
            target.write_bytes(original)
            outside_target.write_bytes(b"outside-sentinel\n")
            real_capture = memory_state._conditional_capture

            def swap_parent_then_capture(
                parent_fd: int | None,
                parent: Path,
                *,
                target: str,
                proposal: str,
                displaced: str,
            ) -> str:
                self.assertIsNotNone(parent_fd)
                config_dir.rename(displaced_dir)
                config_dir.symlink_to(outside, target_is_directory=True)
                return real_capture(
                    parent_fd,
                    parent,
                    target=target,
                    proposal=proposal,
                    displaced=displaced,
                )

            with mock.patch.object(
                memory_state,
                "_conditional_capture",
                side_effect=swap_parent_then_capture,
            ):
                memory_state.secure_conditional_write_bytes_beneath(
                    root,
                    Path("config") / target.name,
                    migrated,
                    expected_sha256=hashlib.sha256(original).hexdigest(),
                    expected_size=len(original),
                    operation_id="4" * 64,
                    namespace="config",
                    max_capture_bytes=1024,
                )
            self.assertEqual(outside_target.read_bytes(), b"outside-sentinel\n")
            self.assertEqual((displaced_dir / target.name).read_bytes(), migrated)
            self.assertEqual(list(displaced_dir.glob(".agent-memory-config-cas-*")), [])

    def test_uncertain_config_recovery_blocks_plan_with_stable_artifacts(self) -> None:
        original = (
            '[write_gateway]\n'
            'mode = "enforce"\n'
            'legacy_actor = "retired-client"\n'
            'writer_protocol_version = 2\n'
            'state_schema_required = 4\n'
            'canonical_actors = ["codex", "claude", "ailu"]\n'
            'path_fencing = true\n'
            'claims_are_projection = true\n'
            'full_vault = true\n'
        )
        migrated = original.replace('legacy_actor = "retired-client"\n', '', 1)
        raced = original + '\n[concurrent]\nvalue = "preserve-me"\n'
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            config_dir = root / "config"
            backup_dir = root / "backups"
            config_dir.mkdir()
            backup_dir.mkdir(mode=0o700)
            config = config_dir / "agent-memory.toml"
            backup = backup_dir / "before.toml"
            config.write_text(original, encoding="utf-8")
            config.chmod(0o600)
            with mock.patch.object(migrate, "config_path", return_value=config), mock.patch.object(
                migrate, "_config_security_root", return_value=config_dir
            ), mock.patch.object(migrate, "_managed_runtime_python", return_value=None):
                migrated = migrate.config_migration_plan()["_migrated_text"]
            real_capture = memory_state._conditional_capture

            def inject_race(
                parent_fd: int | None,
                parent: Path,
                *,
                target: str,
                proposal: str,
                displaced: str,
            ) -> str:
                if parent_fd is not None:
                    descriptor = os.open(target, os.O_WRONLY | os.O_TRUNC, dir_fd=parent_fd)
                    with os.fdopen(descriptor, "wb", closefd=True) as handle:
                        handle.write(raced.encode("utf-8"))
                        handle.flush()
                        os.fsync(handle.fileno())
                else:
                    (parent / target).write_text(raced, encoding="utf-8")
                return real_capture(
                    parent_fd,
                    parent,
                    target=target,
                    proposal=proposal,
                    displaced=displaced,
                )

            with mock.patch.object(migrate, "config_path", return_value=config), mock.patch.object(
                migrate, "_config_security_root", return_value=config_dir
            ), mock.patch.object(
                migrate, "_managed_runtime_python", return_value=None
            ), mock.patch.object(
                memory_state, "_conditional_capture", side_effect=inject_race
            ), mock.patch.object(
                memory_state, "_conditional_restore", side_effect=OSError("injected")
            ), self.assertRaisesRegex(ValueError, "CONFIG_MIGRATION_RECOVERY_REQUIRED"):
                migrate.apply_config_migration(backup_path=backup)

            with mock.patch.object(migrate, "_config_security_root", return_value=config_dir):
                operation_id = migrate._config_migration_operation_id(
                    config,
                    before_sha256=hashlib.sha256(original.encode("utf-8")).hexdigest(),
                    after_sha256=hashlib.sha256(migrated.encode("utf-8")).hexdigest(),
                )
            artifacts = list(config_dir.glob(".agent-memory-config-cas-*"))
            self.assertTrue(artifacts)
            self.assertTrue(all(operation_id in path.name for path in artifacts))
            self.assertEqual(backup.read_text(encoding="utf-8"), original)
            with mock.patch.object(migrate, "config_path", return_value=config), mock.patch.object(
                migrate, "_config_security_root", return_value=config_dir
            ), self.assertRaisesRegex(ValueError, "CONFIG_MIGRATION_RECOVERY_REQUIRED"):
                migrate.config_migration_plan()
            self.assertEqual({path.name for path in artifacts}, {path.name for path in config_dir.glob(".agent-memory-config-cas-*")})

    def test_config_apply_preserves_a_concurrent_edit_and_original_backup(self) -> None:
        original = (
            '[write_gateway]\n'
            'mode = "enforce"\n'
            'legacy_actor = "retired-client"\n'
            'writer_protocol_version = 2\n'
            'state_schema_required = 4\n'
            'canonical_actors = ["codex", "claude", "ailu"]\n'
            'path_fencing = true\n'
            'claims_are_projection = true\n'
            'full_vault = true\n'
        )
        migrated = original.replace('legacy_actor = "retired-client"\n', '', 1)
        raced = original + '\n[concurrent]\nvalue = "preserve-me"\n'
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            config_dir = root / "config"
            backup_dir = root / "backups"
            evidence_dir = root / "evidence"
            config_dir.mkdir()
            backup_dir.mkdir(mode=0o700)
            evidence_dir.mkdir()
            config = config_dir / "agent-memory.toml"
            backup = backup_dir / "before.toml"
            sentinels = {
                evidence_dir / "state.sqlite": b"state-sentinel",
                evidence_dir / "receipt.json": b"receipt-sentinel",
                evidence_dir / "closeout.jsonl": b"log-sentinel\n",
            }
            for path, content in sentinels.items():
                path.write_bytes(content)
            config.write_text(original, encoding="utf-8")
            config.chmod(0o600)
            real_fsync = os.fsync
            fsynced_directories: list[tuple[int, int]] = []

            def recording_fsync(descriptor: int) -> None:
                metadata = os.fstat(descriptor)
                if stat.S_ISDIR(metadata.st_mode):
                    fsynced_directories.append((metadata.st_dev, metadata.st_ino))
                real_fsync(descriptor)

            def config_health() -> dict[str, str]:
                return {"sha256": hashlib.sha256(config.read_bytes()).hexdigest()}

            with mock.patch.object(migrate, "config_path", return_value=config), mock.patch.object(
                migrate, "_config_security_root", return_value=config_dir
            ), mock.patch.object(
                migrate, "_managed_runtime_python", return_value=None
            ), mock.patch.object(
                migrate, "_runtime_config_health", side_effect=config_health
            ) as health, mock.patch.object(
                migrate.os, "fsync", side_effect=recording_fsync
            ):
                applied = migrate.apply_config_migration(backup_path=backup)

            self.assertEqual(applied["status"], "applied")
            self.assertEqual(
                applied["operations"],
                [
                    "REMOVE_WRITE_GATEWAY_LEGACY_ACTOR",
                    "ADD_HOST_V4_DEFAULTS",
                    "ADD_OBSERVABILITY_V4_DEFAULTS",
                    "ADD_SHADOW_V4_DEFAULTS",
                    "ADD_SEMANTIC_RETRIEVAL_V4_DEFAULTS",
                ],
            )
            health.assert_called_once_with()
            self.assertTrue(config.read_text(encoding="utf-8").startswith(migrated))
            self.assertEqual(backup.read_text(encoding="utf-8"), original)
            if memory_state.POSIX_PERMISSION_MODEL:
                backup_parent = backup_dir.stat()
                self.assertIn(
                    (backup_parent.st_dev, backup_parent.st_ino),
                    fsynced_directories,
                )
            for path, content in sentinels.items():
                self.assertEqual(path.read_bytes(), content)
            self.assertEqual(list(config_dir.glob(".agent-memory-config-cas-*")), [])

            race_backup = backup_dir / "before-race.toml"
            config.write_text(original, encoding="utf-8")
            config.chmod(0o600)
            capture = memory_state._conditional_capture

            def inject_race(
                parent_fd: int | None,
                parent: Path,
                *,
                target: str,
                proposal: str,
                displaced: str,
            ) -> str:
                if parent_fd is not None:
                    descriptor = os.open(
                        target,
                        os.O_WRONLY | os.O_TRUNC,
                        dir_fd=parent_fd,
                    )
                    with os.fdopen(descriptor, "wb", closefd=True) as handle:
                        handle.write(raced.encode("utf-8"))
                        handle.flush()
                        os.fsync(handle.fileno())
                else:
                    (parent / target).write_text(raced, encoding="utf-8")
                return capture(
                    parent_fd,
                    parent,
                    target=target,
                    proposal=proposal,
                    displaced=displaced,
                )

            with mock.patch.object(migrate, "config_path", return_value=config), mock.patch.object(
                migrate, "_config_security_root", return_value=config_dir
            ), mock.patch.object(
                migrate, "_managed_runtime_python", return_value=None
            ), mock.patch.object(
                memory_state, "_conditional_capture", side_effect=inject_race
            ), self.assertRaisesRegex(ValueError, "CONFIG_CHANGED_BEFORE_REPLACE"):
                migrate.apply_config_migration(backup_path=race_backup)

            self.assertEqual(config.read_text(encoding="utf-8"), raced)
            self.assertEqual(race_backup.read_text(encoding="utf-8"), original)
            for path, content in sentinels.items():
                self.assertEqual(path.read_bytes(), content)
            self.assertEqual(list(config_dir.glob(".agent-memory-config-cas-*")), [])

            wrong_sha_backup = backup_dir / "before-wrong-sha.toml"
            config.write_text(original, encoding="utf-8")
            config.chmod(0o600)
            with mock.patch.object(migrate, "config_path", return_value=config), mock.patch.object(
                migrate, "_config_security_root", return_value=config_dir
            ), mock.patch.object(
                migrate, "_managed_runtime_python", return_value=None
            ), mock.patch.object(
                migrate, "_runtime_config_health", return_value={"sha256": "0" * 64}
            ) as wrong_health, self.assertRaisesRegex(
                ValueError,
                "CONFIG_MIGRATION_VERIFY_FAILED",
            ):
                migrate.apply_config_migration(backup_path=wrong_sha_backup)
            wrong_health.assert_called_once_with()
            self.assertEqual(wrong_sha_backup.read_text(encoding="utf-8"), original)
            self.assertTrue(config.read_text(encoding="utf-8").startswith(migrated))
            for path, content in sentinels.items():
                self.assertEqual(path.read_bytes(), content)

    def test_content_migrator_is_manifested_and_doctor_required(self) -> None:
        self.assertIn("agent_memory_content_migrate.py", runtime_install.CORE_FILES)
        doctor_source = (SCRIPTS_ROOT / "agent_memory_doctor.py").read_text(encoding="utf-8")
        self.assertIn('"agent_memory_content_migrate.py"', doctor_source)

    def test_posix_installer_requires_an_explicit_host_policy(self) -> None:
        module = load_posix_installer()
        with self.assertRaisesRegex(module.PosixInstallError, "HOST_HOOK_POLICY_REQUIRED"):
            module.host_policy(mock.Mock(host=[], no_host_hooks=False))
        hooks, publish = module.host_policy(mock.Mock(host=["codex", "codex"], no_host_hooks=False))
        self.assertEqual(hooks, ["--host", "codex"])
        self.assertEqual(publish, ["--require-host-hook", "codex"])

    def test_preflight_scope_count_is_structured_and_strict(self) -> None:
        ready = migrate._validate_preflight_doctor_payload(doctor_payload())
        self.assertEqual(ready["legacy_scope_documents"], 0)
        self.assertEqual(ready["safe_automatic_governance_documents"], 0)
        self.assertFalse(ready["content_migration_required"])
        continuation = migrate._validate_preflight_doctor_payload(
            doctor_payload(legacy_scope_documents=5)
        )
        self.assertEqual(continuation["legacy_scope_documents"], 5)
        self.assertEqual(
            continuation["content_migration"]["reason_codes"],
            ["LEGACY_SCOPE_AUTOMATIC"],
        )
        self.assertTrue(continuation["content_migration_required"])
        invalid_scope = doctor_payload(legacy_scope_documents=1)
        invalid_scope["checks"][0]["detail"]["legacy_scope_documents"] = True
        with self.assertRaisesRegex(ValueError, "PREFLIGHT_DOCTOR_SCOPE_CHECK_INVALID"):
            migrate._validate_preflight_doctor_payload(invalid_scope)

    def test_preflight_accepts_exact_safe_governance_temporal_and_mixed_legacy_debt(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            payload = safe_governance_doctor_payload(Path(raw))
            result = migrate._validate_preflight_doctor_payload(payload)
        self.assertTrue(result["content_migration_required"])
        self.assertEqual(result["legacy_scope_documents"], 0)
        self.assertEqual(result["safe_automatic_governance_documents"], 1)
        self.assertEqual(
            result["content_migration"]["reason_codes"],
            ["RISK_V4_AUTOMATIC"],
        )

        with tempfile.TemporaryDirectory() as raw:
            mixed = safe_governance_doctor_payload(
                Path(raw),
                legacy_scope_documents=2,
            )
            mixed_result = migrate._validate_preflight_doctor_payload(mixed)
        self.assertEqual(mixed_result["legacy_scope_documents"], 2)
        self.assertEqual(mixed_result["safe_automatic_governance_documents"], 1)
        self.assertEqual(
            mixed_result["content_migration"]["reason_codes"],
            ["LEGACY_SCOPE_AUTOMATIC", "RISK_V4_AUTOMATIC"],
        )
        final_mixed = json.loads(json.dumps(mixed))
        final_mixed["checks"][0]["status"] = "fail"
        final_mixed["checks"][0]["detail"]["bootstrap_advisory"] = False
        final_mixed["summary"] = {"pass": 0, "warn": 1, "fail": 2}
        self.assertEqual(
            migrate.validate_final_doctor_content_debt(
                final_mixed,
                mixed_result,
            )["content_migration"],
            mixed_result["content_migration"],
        )

    def test_preflight_fails_closed_on_manual_unrelated_and_forged_doctor_failures(self) -> None:
        manual_only = doctor_payload()
        manual_only["checks"][1]["status"] = "fail"
        manual_only["summary"] = {"pass": 2, "warn": 0, "fail": 1}
        manual_only["status"] = "error"
        manual_only["ok"] = False
        with self.assertRaises(ValueError):
            migrate._validate_preflight_doctor_payload(manual_only)

        unrelated = doctor_payload()
        unrelated["checks"].append({
            "name": "runtime_manifest",
            "status": "fail",
            "detail": {},
        })
        unrelated["summary"] = {"pass": 3, "warn": 0, "fail": 1}
        unrelated["status"] = "error"
        unrelated["ok"] = False
        with self.assertRaisesRegex(ValueError, "PREFLIGHT_DOCTOR_FAILED"):
            migrate._validate_preflight_doctor_payload(unrelated)

        forged_summary = doctor_payload()
        forged_summary["summary"]["fail"] = 1
        with self.assertRaisesRegex(ValueError, "PREFLIGHT_DOCTOR_JSON_INVALID"):
            migrate._validate_preflight_doctor_payload(forged_summary)
        for invalid_summary in (
            {"pass": True, "warn": 0, "fail": 0},
            {"pass": 3, "warn": 0, "fail": 0, "extra": 0},
            {"pass": 3, "warn": 0, "fail": -1},
        ):
            invalid_envelope = doctor_payload()
            invalid_envelope["summary"] = invalid_summary
            with self.assertRaisesRegex(
                ValueError,
                "PREFLIGHT_DOCTOR_PROCESS_CONTRACT_INVALID",
            ):
                migrate._validate_preflight_doctor_payload(invalid_envelope)

    def test_final_doctor_revalidation_blocks_automatic_debt_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            preflight = safe_governance_doctor_payload(Path(raw))
        debt = migrate._validate_preflight_doctor_payload(preflight)
        attestation = dict(debt)
        observed = migrate.validate_final_doctor_content_debt(
            preflight,
            attestation,
        )
        self.assertEqual(observed["content_migration"], debt["content_migration"])

        drifted = json.loads(json.dumps(preflight))
        drifted["checks"][2]["detail"]["gap_details"][0][
            "evidence_provenance"
        ]["checked_receipts"] = 2
        with self.assertRaisesRegex(
            ValueError,
            "PREFLIGHT_FINAL_CONTENT_DEBT_DRIFT",
        ):
            migrate.validate_final_doctor_content_debt(drifted, attestation)

    def test_preflight_command_allows_rc2_only_when_explicitly_requested(self) -> None:
        completed = SimpleNamespace(
            returncode=2,
            stdout=json.dumps({
                "ok": False,
                "status": "error",
                "summary": {"pass": 1, "warn": 0, "fail": 1},
            }),
        )
        with mock.patch.object(migrate.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(ValueError, "PREFLIGHT_AGENT_MEMORY_DOCTOR_FAILED"):
                migrate._run_preflight_command(
                    ["python", "/runtime/agent_memory_doctor.py"],
                    token="x" * 64,
                    expect_json=True,
                )
            accepted = migrate._run_preflight_command(
                ["python", "/runtime/agent_memory_doctor.py"],
                token="x" * 64,
                expect_json=True,
                accepted_returncodes=(0, 2),
                doctor_process_contract=True,
            )
        self.assertEqual(accepted["returncode"], 2)
        non_json = SimpleNamespace(returncode=2, stdout="not-json")
        with mock.patch.object(migrate.subprocess, "run", return_value=non_json):
            with self.assertRaisesRegex(ValueError, "PREFLIGHT_JSON_INVALID"):
                migrate._run_preflight_command(
                    ["python", "/runtime/agent_memory_doctor.py"],
                    token="x" * 64,
                    expect_json=True,
                    accepted_returncodes=(0, 2),
                    doctor_process_contract=True,
                )

        for returncode, envelope in (
            (2, {"ok": True, "status": "warning", "summary": {"pass": 1, "warn": 1, "fail": 0}}),
            (0, {"ok": False, "status": "error", "summary": {"pass": 1, "warn": 0, "fail": 1}}),
        ):
            mismatch = SimpleNamespace(
                returncode=returncode,
                stdout=json.dumps(envelope),
            )
            with mock.patch.object(migrate.subprocess, "run", return_value=mismatch):
                with self.assertRaisesRegex(
                    ValueError,
                    "PREFLIGHT_DOCTOR_PROCESS_CONTRACT_INVALID",
                ):
                    migrate._run_preflight_command(
                        ["python", "/runtime/agent_memory_doctor.py"],
                        token="x" * 64,
                        expect_json=True,
                        accepted_returncodes=(0, 2),
                        doctor_process_contract=True,
                    )

    def test_posix_installer_reports_content_migration_continuation(self) -> None:
        module = load_posix_installer()
        ready = module.publication_outcome(published_result())
        self.assertEqual(ready["status"], "ready")
        self.assertTrue(ready["installation_complete"])
        continuation = module.publication_outcome(
            published_result(legacy_scope_documents=7)
        )
        self.assertEqual(continuation["status"], "runtime_ready_content_migration_required")
        self.assertFalse(continuation["installation_complete"])
        self.assertTrue(continuation["continuation"]["required"])
        self.assertEqual(continuation["legacy_scope_documents"], 7)
        self.assertEqual(
            continuation["continuation"]["reason_codes"],
            ["LEGACY_SCOPE_AUTOMATIC"],
        )
        self.assertEqual(
            continuation["continuation"]["next_action"],
            "RUN_CONTENT_MIGRATE_THEN_RERUN_INSTALLER_STRONG_PUBLISH",
        )
        self.assertIn("content-migrate", continuation["continuation"]["instructions"])
        windows = (SCRIPTS_ROOT / "install-windows.ps1").read_text(encoding="utf-8")
        self.assertIn("RUN_CONTENT_MIGRATE_THEN_RERUN_INSTALLER_STRONG_PUBLISH", windows)
        invalid = published_result(legacy_scope_documents=7)
        invalid["preflight_attestation"]["content_migration_required"] = False
        with self.assertRaisesRegex(module.PosixInstallError, "CONTENT_MIGRATION_ATTESTATION_INVALID"):
            module.publication_outcome(invalid)
        forged_counts = published_result()
        forged_counts["preflight_attestation"]["content_migration"][
            "safe_automatic_governance_documents"
        ] = 1
        with self.assertRaisesRegex(
            module.PosixInstallError,
            "CONTENT_MIGRATION_ATTESTATION_INVALID",
        ):
            module.publication_outcome(forged_counts)
        forged_reasons = published_result(legacy_scope_documents=1)
        forged_reasons["preflight_attestation"]["content_migration"][
            "reason_codes"
        ] = []
        with self.assertRaisesRegex(
            module.PosixInstallError,
            "CONTENT_MIGRATION_ATTESTATION_INVALID",
        ):
            module.publication_outcome(forged_reasons)
        self.assertIn("safe_automatic_governance_documents", windows)
        self.assertIn("AUTOMATIC_CONTENT_MIGRATION_REMAINS", windows)
        self.assertIn("$rawReasons -is [System.Array]", windows)
        self.assertIn("Get-Utf8Sha256Hex $canonicalFingerprintPayload", windows)
        self.assertIn(
            "automatic_migration_fingerprint_sha256 -ne $computedAutomaticFingerprint",
            windows,
        )
        self.assertEqual(
            content_migrate.canonical_bytes({
                "schema_version": 1,
                "legacy_binding_sha256": "a" * 64,
                "governance_automatic_migration_fingerprint_sha256": "b" * 64,
            }).decode("utf-8"),
            '{"governance_automatic_migration_fingerprint_sha256":"'
            + "b" * 64
            + '","legacy_binding_sha256":"'
            + "a" * 64
            + '","schema_version":1}',
        )

    def test_doctor_scope_parser_keeps_non_active_status_distinct_from_missing_scope(self) -> None:
        import agent_memory_doctor as doctor

        active, duplicates, state = doctor._explicit_frontmatter(
            "---\nstatus: active\napp_id: agent-memory\nproject_id: example\nagent_scope: shared\n---\nbody\n"
        )
        self.assertEqual(state, "present")
        self.assertFalse(duplicates)
        self.assertEqual(active["status"], "active")
        eof_frontmatter, _, eof_state = doctor._explicit_frontmatter(
            "---\nstatus: active\napp_id: agent-memory\nproject_id: example\nagent_scope: shared\n---"
        )
        self.assertEqual(eof_state, "present")
        self.assertEqual(eof_frontmatter["project_id"], "example")
        archived, _, _ = doctor._explicit_frontmatter(
            "---\nstatus: archived\n---\nhistory\n"
        )
        self.assertIn(archived["status"], doctor.NON_ACTIVE_SCOPE_STATUSES)
        pending, pending_duplicates, pending_state = doctor._explicit_frontmatter(
            "---\nstatus: pending_verification\n---\nneeds review\n"
        )
        self.assertIn(pending["status"], doctor.NON_ACTIVE_SCOPE_STATUSES)
        self.assertEqual(
            doctor._scope_status_policy(
                Path("项目/pending.md"),
                pending,
                pending_duplicates,
                pending_state,
            ),
            ("excluded", "pending_verification"),
        )
        self.assertLessEqual(
            doctor.memory_index.GOVERNANCE_MIGRATION_STATUSES - {"active"},
            doctor.NON_ACTIVE_SCOPE_STATUSES,
        )
        missing, _, state = doctor._explicit_frontmatter("# Legacy active body\n")
        self.assertEqual(missing, {})
        self.assertEqual(state, "missing")

    def test_doctor_scope_health_excludes_pending_verification_but_keeps_active_debt(self) -> None:
        import agent_memory_doctor as doctor

        with tempfile.TemporaryDirectory() as raw_root:
            vault_root = Path(raw_root)
            project_root = vault_root / "项目"
            project_root.mkdir()
            (project_root / "pending.md").write_text(
                "---\nstatus: pending_verification\n---\nneeds review\n",
                encoding="utf-8",
            )
            (project_root / "active.md").write_text(
                "---\nstatus: active\n---\ncurrent body\n",
                encoding="utf-8",
            )

            with mock.patch.object(doctor, "VAULT_ROOT", vault_root):
                result = doctor.legacy_scope_documents_health()

        self.assertEqual(result["scanned_body_documents"], 2)
        self.assertEqual(result["active_body_documents"], 1)
        self.assertEqual(result["legacy_scope_documents"], 1)
        self.assertEqual(result["excluded_non_active_documents"], 1)
        self.assertEqual(result["excluded_by_status"], {"pending_verification": 1})
        self.assertEqual(
            [item["target_relative_path"] for item in result["migration_query"]],
            ["项目/active.md"],
        )

    def test_doctor_duplicate_status_and_scope_scalar_grammar_fail_closed(self) -> None:
        import agent_memory_doctor as doctor

        for text in (
            "---\nstatus: active\nstatus: archived\n---\nbody\n",
            "---\nstatus: archived\nstatus: active\n---\nbody\n",
        ):
            metadata, duplicates, state = doctor._explicit_frontmatter(text)
            policy, _ = doctor._scope_status_policy(Path("项目/example.md"), metadata, duplicates, state)
            self.assertEqual(policy, "manual")
        self.assertEqual(doctor._scope_value_issue("app_id", "", Path("项目/x.md")), "missing")
        for value in ("one,two", "one|two", "[]", "{}", "bad\x00value", "bad\nvalue"):
            with self.subTest(value=repr(value)):
                self.assertEqual(
                    doctor._scope_value_issue("app_id", value, Path("项目/x.md")),
                    "invalid",
                )
        self.assertEqual(
            doctor._scope_value_issue("project_id", "shared", Path("项目/x.md")),
            "invalid",
        )
        self.assertEqual(
            doctor._scope_value_issue("project_id", "global", Path("项目/x.md")),
            "invalid",
        )
        self.assertEqual(
            doctor._scope_value_issue("project_id", "global", Path("用户记忆/x.md")),
            "",
        )

    def test_public_template_has_zero_scope_debt_after_bootstrap_substitution(self) -> None:
        import agent_memory_doctor as doctor

        template_root = REPO_ROOT / "templates" / "vault"
        original_read_text = Path.read_text

        def rendered_read_text(path: Path, *args, **kwargs) -> str:
            return original_read_text(path, *args, **kwargs).replace("{{APP_ID}}", "agent-memory")

        with mock.patch.object(doctor, "VAULT_ROOT", template_root), mock.patch.object(
            Path, "read_text", rendered_read_text
        ):
            result = doctor.legacy_scope_documents_health()
        self.assertEqual(result["legacy_scope_documents"], 0, result["migration_query"])
        self.assertEqual(result["manual_review_documents"], 0)

    def test_windows_installer_does_not_claim_completion_with_scope_debt(self) -> None:
        text = (SCRIPTS_ROOT / "install-windows.ps1").read_text(encoding="utf-8")
        self.assertIn("runtime_ready_content_migration_required", text)
        self.assertIn("installation_complete = $false", text)
        self.assertNotIn("Windows installation complete", text)
        self.assertIn("PARTIAL_INSTALL_AMBIGUOUS", text)
        self.assertNotIn("$stateExistedBeforeInstall", text)
        bootstrap = text.index("'vault bootstrap'")
        fresh_guard = text.rfind("if ($installationMode -eq 'fresh')", 0, bootstrap)
        self.assertGreaterEqual(fresh_guard, 0)
        self.assertLess(text.index("$installationMode = if ($existingConfig)"), text.index("runtime installation"))
        self.assertNotIn("'virtual environment creation'", text)
        self.assertIn("Assert-ExternalSourcePython $python.Source", text)
        self.assertIn("install_runtime owns the fixed target venv", text)

    def test_only_canonical_ailu_app_id_is_accepted(self) -> None:
        self.assertEqual(
            writer.WRITABLE_ACTIONS,
            {"ADD", "UPDATE", "ADOPT", "MIGRATE_LEGACY_SCOPE"},
        )
        with mock.patch.object(writer, "ACTOR", "ailu"):
            with self.assertRaises(writer.MemoryWriteError) as raised:
                writer._scope_request({"app_id": "retired-app", "project_id": "global"})
        self.assertEqual(raised.exception.reason_code, "APP_ID_UNSUPPORTED")

    def test_closeout_session_transport_is_actor_specific(self) -> None:
        class FakeProcess:
            pid = 4321
            returncode = 0

            def communicate(self, timeout=None):
                return (json.dumps({"status": "ok"}), "")

            def poll(self):
                return 0

        for actor in ("codex", "claude", "ailu"):
            with self.subTest(actor=actor), mock.patch.object(writer, "ACTOR", actor), mock.patch.object(
                writer.subprocess, "Popen", return_value=FakeProcess()
            ) as popen, mock.patch.object(writer, "_posix_process_group_may_exist", return_value=False):
                writer._run_closeout(raw_session_id=f"{actor}-session", timeout_seconds=5)
            command = popen.call_args.args[0]
            environment = popen.call_args.kwargs["env"]
            self.assertEqual(environment["AGENT_MEMORY_SESSION_ID"], f"{actor}-session")
            self.assertEqual(environment["MEMORY_ACTOR"], actor)
            if actor == "ailu":
                self.assertNotIn("--session-id", command)
            else:
                index = command.index("--session-id")
                self.assertEqual(command[index + 1], f"{actor}-session")

    def test_root_governance_reconcile_is_path_unique_without_relaxing_nonroot(self) -> None:
        base = {
            "target_canonical_sha256": "a" * 64,
            "proposal_canonical_sha256": "b" * 64,
            "fallback_action": "MERGE_REQUIRED",
            "fallback_recommended_path": "项目/Agent Memory Vault模板仓库.md",
        }
        self.assertEqual(
            writer._structurally_unique_recommendation(
                target_relative_path="INDEX.md", target_exists=True, **base
            ),
            ("UPDATE", "INDEX.md"),
        )
        self.assertEqual(
            writer._structurally_unique_recommendation(
                target_relative_path="INDEX.md", target_exists=False, **base
            ),
            ("ADD", "INDEX.md"),
        )
        self.assertEqual(
            writer._structurally_unique_recommendation(
                target_relative_path="INDEX.md",
                target_exists=True,
                **{**base, "proposal_canonical_sha256": "a" * 64},
            ),
            ("NOOP", "INDEX.md"),
        )
        self.assertEqual(
            writer._structurally_unique_recommendation(
                target_relative_path="工作流/Agent记忆本地脚本.md", target_exists=True, **base
            ),
            ("MERGE_REQUIRED", "项目/Agent Memory Vault模板仓库.md"),
        )

    def test_legacy_scope_migration_is_metadata_only_and_crlf_safe(self) -> None:
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)):
                base = newline.join((
                    "---",
                    "memory_type: workflow",
                    "track: workflow",
                    "agent_scope: shared",
                    "status: active",
                    "---",
                    "",
                    "# 旧正文",
                    "正文中的 retired-client 字样不得随 scope 迁移改变。",
                    "",
                ))
                expected = base.replace(
                    f"status: active{newline}---",
                    f"status: active{newline}app_id: agent-memory{newline}project_id: agent-memory-vault{newline}---",
                )
                generated = writer._legacy_scope_proposal(
                    actor="codex",
                    target_relative_path="工作流/Agent记忆本地脚本.md",
                    requested_app_id="agent-memory",
                    requested_project_id="agent-memory-vault",
                    legacy_scope_app_id="agent-memory",
                    base_text=base,
                )
                self.assertEqual(generated, expected)
                writer._validate_legacy_scope_migration(
                    actor="claude",
                    target_relative_path="工作流/Agent记忆本地脚本.md",
                    requested_app_id="agent-memory",
                    requested_project_id="agent-memory-vault",
                    legacy_scope_app_id="agent-memory",
                    base_text=base,
                    proposal_text=expected,
                )
                with self.assertRaises(writer.MemoryWriteError) as raised:
                    writer._validate_legacy_scope_migration(
                        actor="claude",
                        target_relative_path="工作流/Agent记忆本地脚本.md",
                        requested_app_id="agent-memory",
                        requested_project_id="agent-memory-vault",
                        legacy_scope_app_id="agent-memory",
                        base_text=base,
                        proposal_text=expected + "正文也改了",
                    )
                self.assertEqual(raised.exception.reason_code, "LEGACY_SCOPE_MIGRATION_FORBIDDEN")

    def test_legacy_scope_migration_wraps_frontmatterless_body_without_changing_it(self) -> None:
        body = "# 原始标题\r\n\r\n原始正文逐字节保留。\r\n"
        proposal = writer._legacy_scope_proposal(
            actor="codex",
            target_relative_path="项目/旧项目.md",
            requested_app_id="agent-memory",
            requested_project_id="legacy-project",
            legacy_scope_app_id="agent-memory",
            base_text=body,
        )
        expected_header = (
            "---\r\n"
            "memory_type: project\r\n"
            "track: project\r\n"
            "project_id: legacy-project\r\n"
            "app_id: agent-memory\r\n"
            "agent_scope: shared\r\n"
            "status: active\r\n"
            "---\r\n\r\n"
        )
        self.assertEqual(proposal, expected_header + body)
        self.assertTrue(proposal.endswith(body))
        self.assertNotIn("verified_at:", proposal)

    def test_legacy_scope_migration_rejects_conflicts_private_and_wrong_boundaries(self) -> None:
        base = (
            "---\n"
            "memory_type: project\n"
            "track: project\n"
            "agent_scope: shared\n"
            "status: active\n"
            "---\n\n# 正文\n"
        )
        defaults = {
            "actor": "codex",
            "target_relative_path": "项目/旧项目.md",
            "requested_app_id": "agent-memory",
            "requested_project_id": "legacy-project",
            "legacy_scope_app_id": "agent-memory",
            "base_text": base,
        }
        cases = (
            {"actor": "ailu"},
            {"target_relative_path": "INDEX.md"},
            {"target_relative_path": "其他/旧项目.md"},
            {"requested_app_id": "ailu"},
            {"requested_project_id": ""},
            {"requested_project_id": "global"},
            {"legacy_scope_app_id": "other"},
            {"base_text": base.replace("agent_scope: shared", "agent_scope: private")},
            {"base_text": base.replace("status: active", "status: archived")},
            {"base_text": base.replace("status: active", "app_id: other\nstatus: active")},
            {"base_text": base.replace("status: active", "app_id: agent-memory, other\nstatus: active")},
            {"base_text": base.replace("status: active", "project_id: other-project\nstatus: active")},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides), self.assertRaises(writer.MemoryWriteError) as raised:
                writer._legacy_scope_proposal(**{**defaults, **overrides})
            self.assertEqual(raised.exception.reason_code, "LEGACY_SCOPE_MIGRATION_FORBIDDEN")

    def test_legacy_scope_prepare_rejects_stale_read_token_before_migration(self) -> None:
        base = (
            "---\n"
            "memory_type: workflow\n"
            "track: workflow\n"
            "agent_scope: shared\n"
            "status: active\n"
            "---\n\n# 正文\n"
        )
        proposal = writer._legacy_scope_proposal(
            actor="codex",
            target_relative_path="工作流/旧流程.md",
            requested_app_id="agent-memory",
            requested_project_id="agent-memory-vault",
            legacy_scope_app_id="agent-memory",
            base_text=base,
        )
        target = SimpleNamespace(rel_path="工作流/旧流程.md", path=Path("/vault/工作流/旧流程.md"))
        snapshot = (True, intent.content_hashes(base.encode("utf-8")), "1" * 40, "a" * 64)
        request = {
            "proposal_markdown": proposal,
            "target_relative_path": target.rel_path,
            "app_id": "agent-memory",
            "project_id": "agent-memory-vault",
            "read_token": "b" * 64,
            "migrate_legacy_scope": True,
            "legacy_scope_app_id": "agent-memory",
        }
        with mock.patch.object(writer, "ACTOR", "codex"), mock.patch.object(
            writer, "_formal_target", return_value=target
        ), mock.patch.object(
            writer, "_scope_request", return_value=("agent-memory", "agent-memory-vault")
        ), mock.patch.object(writer, "_target_snapshot", return_value=snapshot):
            with self.assertRaises(writer.MemoryWriteError) as raised:
                writer.prepare(request, raw_session_id="codex-session")
        self.assertEqual(raised.exception.reason_code, "STALE_READ_TOKEN")

    def test_legacy_scope_action_is_explicitly_writable_and_user_confirmed(self) -> None:
        self.assertIn("MIGRATE_LEGACY_SCOPE", writer.WRITABLE_ACTIONS)
        source = (SCRIPTS_ROOT / "agent_memory_write.py").read_text(encoding="utf-8")
        self.assertIn('{"ADOPT", "MIGRATE_LEGACY_SCOPE"}', source)
        self.assertIn('"scope_migration": action == "MIGRATE_LEGACY_SCOPE"', source)

    def test_legacy_scope_prepare_uses_exact_target_despite_semantic_merge_candidate(self) -> None:
        base = (
            "---\n"
            "memory_type: workflow\n"
            "track: workflow\n"
            "agent_scope: shared\n"
            "status: active\n"
            "---\n\n# 正文\n"
        )
        proposal = writer._legacy_scope_proposal(
            actor="codex",
            target_relative_path="工作流/旧流程.md",
            requested_app_id="agent-memory",
            requested_project_id="agent-memory-vault",
            legacy_scope_app_id="agent-memory",
            base_text=base,
        )
        target = SimpleNamespace(
            rel_path="工作流/旧流程.md",
            path=writer.write_intent.VAULT_ROOT / "工作流" / "旧流程.md",
            target_key="target-key",
        )
        base_digest = intent.content_hashes(base.encode("utf-8"))
        snapshot = (True, base_digest, "1" * 40, "a" * 64)
        request = {
            "proposal_markdown": proposal,
            "target_relative_path": target.rel_path,
            "app_id": "agent-memory",
            "project_id": "agent-memory-vault",
            "read_token": "a" * 64,
            "migrate_legacy_scope": True,
            "legacy_scope_app_id": "agent-memory",
            "summary": "旧流程 scope 元数据迁移",
            "source_class": "user_direct",
            "knowledge_kind": "fact",
            "asserted_by": "user",
            "evidence_ref": "task:test",
        }
        created = {
            "intent_id": "f" * 32,
            "fencing_token": 9,
            "base_exists": 1,
            "base_raw_sha256": base_digest.raw_sha256,
            "base_canonical_sha256": base_digest.canonical_sha256,
            "base_git_head": "1" * 40,
            "expires_at": "2099-01-01T00:00:00+00:00",
        }
        with mock.patch.object(writer, "ACTOR", "codex"), mock.patch.object(
            writer, "_formal_target", return_value=target
        ), mock.patch.object(
            writer, "_scope_request", return_value=("agent-memory", "agent-memory-vault")
        ), mock.patch.object(writer, "_target_snapshot", return_value=snapshot), mock.patch.object(
            writer.memory_safety, "assess_source", return_value={"decision": "ALLOW", "evidence_ref_sha256": "e" * 64}
        ), mock.patch.object(writer, "_record_prepare_safety"), mock.patch.object(
            writer.memory_closeout, "search_memory", return_value=([], [], {"sqlite": {"status": "ok"}})
        ), mock.patch.object(
            writer.memory_closeout, "prewrite_recommendation", return_value=("MERGE_REQUIRED", None, {})
        ), mock.patch.object(writer.write_intent, "create_intent", return_value=created):
            result = writer.prepare(request, raw_session_id="codex-session")
        self.assertEqual(result["status"], "prepared")
        self.assertEqual(result["recommended_action"], "MIGRATE_LEGACY_SCOPE")
        self.assertEqual(result["target_relative_path"], target.rel_path)
        self.assertTrue(result["scope_migration"])

    def test_legacy_scope_preserves_existing_canonical_app_and_global_project(self) -> None:
        base = (
            "---\r\n"
            "memory_type: user_profile\r\n"
            "track: user\r\n"
            "app_id: codex\r\n"
            "project_id: global\r\n"
            "status: active\r\n"
            "---\r\n\r\n# 用户正文\r\n"
        )
        proposal = writer._legacy_scope_proposal(
            actor="codex",
            target_relative_path="用户记忆/长期画像.md",
            requested_app_id="codex",
            requested_project_id="global",
            legacy_scope_app_id="codex",
            base_text=base,
        )
        self.assertEqual(
            proposal,
            base.replace("status: active\r\n---", "status: active\r\nagent_scope: shared\r\n---"),
        )
        self.assertEqual(proposal.count("app_id: codex"), 1)
        self.assertEqual(proposal.count("project_id: global"), 1)

    def test_legacy_scope_adds_only_missing_active_scope_fields_in_fixed_order(self) -> None:
        base = "---\nmemory_type: project\ntrack: project\n---\n\n# 正文\n"
        proposal = writer._legacy_scope_proposal(
            actor="claude",
            target_relative_path="项目/wx_channel.md",
            requested_app_id="codex",
            requested_project_id="wx_channel",
            legacy_scope_app_id="codex",
            base_text=base,
        )
        expected_fields = (
            "status: active\n"
            "agent_scope: shared\n"
            "app_id: codex\n"
            "project_id: wx_channel\n"
        )
        self.assertIn(f"track: project\n{expected_fields}---\n\n# 正文\n", proposal)
        self.assertTrue(proposal.endswith("\n# 正文\n"))

    def test_legacy_scope_fills_explicit_empty_app_and_project_scalars_in_place(self) -> None:
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)):
                base = newline.join((
                    "---",
                    "memory_type: project",
                    "track: project",
                    "status: active",
                    "agent_scope: shared",
                    "app_id:   ",
                    "project_id:\t",
                    "---",
                    "",
                    "# 正文 app_id: 不应改",
                    "",
                ))
                proposal = writer._legacy_scope_proposal(
                    actor="codex",
                    target_relative_path="项目/旧项目.md",
                    requested_app_id="agent-memory",
                    requested_project_id="legacy-project",
                    legacy_scope_app_id="agent-memory",
                    base_text=base,
                )
                expected = base.replace("app_id:   ", "app_id: agent-memory").replace(
                    "project_id:\t", "project_id: legacy-project"
                )
                self.assertEqual(proposal, expected)
                self.assertEqual(proposal.count("app_id:"), 2)  # one metadata key plus body text
                self.assertEqual(proposal.count("project_id:"), 1)
                writer._validate_legacy_scope_migration(
                    actor="claude",
                    target_relative_path="项目/旧项目.md",
                    requested_app_id="agent-memory",
                    requested_project_id="legacy-project",
                    legacy_scope_app_id="agent-memory",
                    base_text=base,
                    proposal_text=proposal,
                )

    def test_legacy_scope_allows_supporting_readme_only_inside_migration_validation(self) -> None:
        body = "# Agent cases\n"
        proposal = writer._legacy_scope_proposal(
            actor="codex",
            target_relative_path="agent/cases/README.md",
            requested_app_id="agent-memory",
            requested_project_id="agent-cases",
            legacy_scope_app_id="agent-memory",
            base_text=body,
        )
        path = writer.write_intent.VAULT_ROOT / "agent" / "cases" / "README.md"
        with mock.patch.object(writer, "ACTOR", "codex"):
            with self.assertRaises(writer.MemoryWriteError) as ordinary:
                writer._validate_writer_markdown(
                    proposal,
                    path=path,
                    app_id="agent-memory",
                    project_id="agent-cases",
                    require_explicit_write_scope=True,
                )
            self.assertEqual(ordinary.exception.reason_code, "SUPPORTING_DOCUMENT_EXCLUDED")
            metadata = writer._validate_writer_markdown(
                proposal,
                path=path,
                app_id="agent-memory",
                project_id="agent-cases",
                require_explicit_write_scope=True,
                allow_supporting_document=True,
            )
        self.assertEqual(metadata["memory_type"], "directory_index")

    def test_legacy_scope_global_project_is_narrowly_available_for_user_memory(self) -> None:
        target = SimpleNamespace(
            rel_path="用户记忆/长期画像.md",
            path=writer.write_intent.VAULT_ROOT / "用户记忆" / "长期画像.md",
            target_key="user-profile-target",
        )
        payload = {
            "app_id": "Codex",
            "project_id": "global",
            "legacy_scope_app_id": "codex",
        }
        with mock.patch.object(writer, "ACTOR", "codex"):
            self.assertEqual(
                writer._scope_request(payload, target=target, legacy_scope_migration=True),
                ("codex", "global"),
            )
            with self.assertRaises(writer.MemoryWriteError):
                writer._scope_request(payload, target=target)
            with self.assertRaises(writer.MemoryWriteError):
                writer._scope_request(
                    payload,
                    target=SimpleNamespace(rel_path="项目/长期画像.md", path=writer.write_intent.VAULT_ROOT / "项目" / "长期画像.md"),
                    legacy_scope_migration=True,
                )

    def test_legacy_scope_rejects_candidate_archive_duplicate_and_multi_value_metadata(self) -> None:
        base = "---\nstatus: active\nagent_scope: shared\n---\n\n# 正文\n"
        defaults = {
            "actor": "codex",
            "target_relative_path": "项目/旧项目.md",
            "requested_app_id": "agent-memory",
            "requested_project_id": "legacy-project",
            "legacy_scope_app_id": "agent-memory",
            "base_text": base,
        }
        cases = (
            {"target_relative_path": "agent/case-candidates/旧项目.md"},
            {"target_relative_path": "项目/archive/旧项目.md"},
            {"target_relative_path": "工作流/_模板-流程.md"},
            {"target_relative_path": "工作流/_模板流程.md"},
            {"base_text": base.replace("status: active", "status: candidate")},
            {"base_text": base.replace("status: active", "status: active\nstatus: active")},
            {"base_text": base.replace("status: active", "app_id:\napp_id:\nstatus: active")},
            {"base_text": base.replace("status: active", "project_id: []\nstatus: active")},
            {"base_text": base.replace("status: active", "app_id: {}\nstatus: active")},
            {"base_text": base.replace("status: active", "app_id: agent-memory, codex\nstatus: active")},
            {"requested_app_id": "agent-memory,codex"},
            {"requested_project_id": "one,two"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides), self.assertRaises(writer.MemoryWriteError) as raised:
                writer._legacy_scope_proposal(**{**defaults, **overrides})
            self.assertEqual(raised.exception.reason_code, "LEGACY_SCOPE_MIGRATION_FORBIDDEN")

    def test_legacy_scope_intent_binding_accepts_exact_global_scope_and_token(self) -> None:
        target = SimpleNamespace(
            rel_path="用户记忆/长期画像.md",
            path=writer.write_intent.VAULT_ROOT / "用户记忆" / "长期画像.md",
            target_key="user-profile-intent-target",
        )
        base = intent.content_hashes(b"legacy")
        raw_session_id = "codex-scope-session"
        with mock.patch.object(writer, "ACTOR", "codex"):
            token = writer._read_token(
                target,
                app_id="codex",
                project_id="global",
                exists=True,
                digest=base,
                git_head="1" * 40,
                raw_session_id=raw_session_id,
            )
            bound = writer._intent_scope_binding(
                {
                    "reconcile_action": "MIGRATE_LEGACY_SCOPE",
                    "scope_app_id": "codex",
                    "scope_project_id": "global",
                    "read_token": token,
                    "base_exists": 1,
                    "base_raw_sha256": base.raw_sha256,
                    "base_canonical_sha256": base.canonical_sha256,
                    "base_git_head": "1" * 40,
                },
                target=target,
                raw_session_id=raw_session_id,
            )
        self.assertEqual(bound, ("codex", "global"))

    def test_legacy_scope_read_target_returns_canonical_scope_and_bound_token(self) -> None:
        target = SimpleNamespace(
            rel_path="用户记忆/长期画像.md",
            path=writer.write_intent.VAULT_ROOT / "用户记忆" / "长期画像.md",
            target_key="read-target-key",
        )
        digest = intent.content_hashes(b"legacy body")
        request = {
            "target_relative_path": target.rel_path,
            "app_id": "Codex",
            "project_id": "global",
            "migrate_legacy_scope": True,
            "legacy_scope_app_id": "codex",
        }
        with mock.patch.object(writer, "ACTOR", "codex"), mock.patch.object(
            writer, "_formal_target", return_value=target
        ), mock.patch.object(
            writer,
            "_target_snapshot",
            return_value=(True, digest, "1" * 40, "a" * 64),
        ) as snapshot:
            result = writer.read_target(request, raw_session_id="codex-read-session")
        self.assertEqual(result["app_id"], "codex")
        self.assertEqual(result["project_id"], "global")
        self.assertTrue(result["scope_migration"])
        self.assertEqual(result["read_token"], "a" * 64)
        self.assertTrue(snapshot.call_args.kwargs["allow_supporting_document"])

    def test_posix_installer_rejects_partial_config_state_combinations(self) -> None:
        module = load_posix_installer()
        self.assertEqual(module.installation_mode(config_exists=False, state_exists=False), "fresh")
        self.assertEqual(module.installation_mode(config_exists=True, state_exists=True), "upgrade")
        for config_exists, state_exists in ((True, False), (False, True)):
            with self.subTest(config_exists=config_exists, state_exists=state_exists), self.assertRaisesRegex(
                module.PosixInstallError,
                "PARTIAL_INSTALL_AMBIGUOUS",
            ):
                module.installation_mode(
                    config_exists=config_exists,
                    state_exists=state_exists,
                )

    def test_posix_source_python_never_probes_target_venv(self) -> None:
        module = load_posix_installer()
        target = Path("/private/runtime/.venv/bin/python")
        args = mock.Mock(python=str(target))
        paths = {"config_root": Path("/private/runtime")}
        with mock.patch.object(module.subprocess, "run") as invoked, self.assertRaisesRegex(
            module.PosixInstallError,
            "SOURCE_PYTHON_TARGET_VENV_FORBIDDEN",
        ):
            module.select_supported_python(args, paths)
        invoked.assert_not_called()

    def test_posix_source_python_rejects_parent_directory_alias_into_target_venv(self) -> None:
        module = load_posix_installer()
        target = Path("/real/runtime")
        candidate = Path("/alias/runtime/.venv/bin/python")

        def fake_lstat(path: Path):
            mode = stat.S_IFLNK if str(path) == "/alias" else stat.S_IFDIR
            return SimpleNamespace(st_mode=mode)

        with mock.patch.object(Path, "lstat", fake_lstat), mock.patch.object(
            module.os,
            "readlink",
            return_value="/real",
        ):
            self.assertTrue(module._candidate_enters_target_venv(candidate, target))

    def test_windows_source_python_walks_parent_reparse_components(self) -> None:
        text = (SCRIPTS_ROOT / "install-windows.ps1").read_text(encoding="utf-8")
        self.assertIn("function Resolve-SourcePathComponents", text)
        self.assertIn("for ($index = 0; $index -lt $parts.Count; $index++)", text)
        self.assertIn("$target = Resolve-SourcePathComponents $venvRoot", text)
        self.assertIn("$current = Resolve-SourcePathComponents $Path", text)
        self.assertLess(
            text.index("Assert-ExternalSourcePython $python.Source"),
            text.index("$version = & $python.Source"),
        )

    def test_source_config_plan_only_derives_target_launcher_without_probe(self) -> None:
        with mock.patch.object(migrate, "runtime_python_attestation") as probe, mock.patch.object(
            migrate, "assert_no_symlink_beneath"
        ):
            result = migrate._managed_runtime_python(Path("/private/runtime"))
        expected = (
            Path("/private/runtime/.venv/Scripts/python.exe")
            if os.name == "nt"
            else Path("/private/runtime/.venv/bin/python")
        )
        self.assertEqual(result, expected)
        probe.assert_not_called()

    def test_runtime_verify_never_probes_target_before_static_ready_auth(self) -> None:
        manifest = {
            "schema_version": 2, "runtime_api_version": 2,
            "writer_protocol_version": 2, "state_schema_required": 3,
            "canonical_actors": ["codex", "claude", "ailu"],
            "files": {"memoryctl": "a" * 64}, "support_files": {}, "template_files": {},
            "bundle_sha256": "b" * 64, "install_id": "1" * 64,
            "runtime_anchor_sha256": "2" * 64,
        }
        transition = {
            "phase": "ready", "bundle_sha256": "b" * 64,
            "install_id": "1" * 64, "runtime_anchor_sha256": "2" * 64,
        }

        def read(_root, relative):
            return json.dumps(
                manifest if Path(relative).name == "runtime-manifest.json" else transition
            ).encode("utf-8")

        with mock.patch.object(runtime_install, "secure_read_bytes_beneath", side_effect=read), mock.patch.object(
            runtime_install, "_authenticated_existing_runtime_python",
            side_effect=memory_state.StateSecurityError("blocked"),
        ), mock.patch.object(runtime_install, "runtime_python_attestation") as probe, mock.patch.object(
            runtime_install.subprocess, "run"
        ) as child:
            result = runtime_install.verify(Path("/private/runtime"))
        self.assertFalse(result["runtime_python"]["ok"])
        probe.assert_not_called()
        child.assert_not_called()

    def test_authenticated_runtime_python_replacement_blocks_before_subprocess(self) -> None:
        launcher = "/private/runtime/.venv/bin/python"
        static_a = {
            "launcher": launcher,
            "launcher_chain": [{
                "path": ".venv/bin/python",
                "kind": "regular",
                "identity": {"device": 1, "inode": 2, "mode": 0o755, "size": 3, "mtime_ns": 4},
            }],
            "resolved_path": launcher,
            "resolved_sha256": "a" * 64,
            "resolved_identity": {
                "device": 1,
                "inode": 2,
                "mode": 0o755,
                "size": 3,
                "mtime_ns": 4,
            },
        }
        expected = {
            "schema_version": 1,
            **static_a,
            "version": [3, 12, 0],
            "implementation": "CPython",
            "probe_executable": launcher,
            "base_prefix": "/private/runtime/.venv",
        }
        expected["attestation_sha256"] = hashlib.sha256(
            json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        renumbered = json.loads(json.dumps(static_a))
        renumbered["launcher_chain"][0]["identity"]["device"] = 9
        renumbered["resolved_identity"]["device"] = 9
        with mock.patch.object(runtime_install.sys, "platform", "darwin"):
            runtime_install._validated_attested_python(expected, renumbered)
        with mock.patch.object(runtime_install.sys, "platform", "linux"), self.assertRaisesRegex(
            memory_state.StateSecurityError,
            "pre-exec identity mismatch",
        ):
            runtime_install._validated_attested_python(expected, renumbered)
        static_b = {
            **static_a,
            "resolved_sha256": "b" * 64,
            "resolved_identity": {**static_a["resolved_identity"], "inode": 9},
        }
        with mock.patch.object(
            runtime_install,
            "_python_launcher_identity",
            side_effect=[static_a, static_b],
        ), mock.patch.object(runtime_install.subprocess, "run") as invoked, self.assertRaisesRegex(
            memory_state.StateSecurityError,
            "pre-exec identity mismatch",
        ):
            runtime_install._attest_authenticated_runtime_python(
                Path("/private/runtime"),
                Path(launcher),
                expected,
            )
        invoked.assert_not_called()

    def test_legacy_venv_is_preserved_before_trusted_recreation(self) -> None:
        config_root = Path("/private/runtime")
        launcher = runtime_install.managed_python_path(config_root)
        completed = mock.Mock(returncode=0)
        with mock.patch.object(runtime_install.sys, "version_info", (3, 12, 0)), mock.patch.object(
            Path, "exists", return_value=True
        ), mock.patch.object(
            Path, "is_symlink", return_value=False
        ), mock.patch.object(
            runtime_install, "assert_no_symlink_beneath"
        ), mock.patch.object(
            runtime_install, "_authenticated_existing_runtime_python",
            side_effect=memory_state.StateSecurityError("legacy"),
        ), mock.patch.object(
            runtime_install, "_recoverably_move_untrusted_venv",
            return_value=Path("/private/runtime/backups/untrusted-venv-1"),
        ) as preserve, mock.patch.object(
            runtime_install, "ensure_private_directory"
        ), mock.patch.object(
            runtime_install.subprocess, "run", return_value=completed
        ) as create, mock.patch.object(
            Path, "is_file", return_value=True
        ), mock.patch.object(
            runtime_install, "runtime_python_attestation", return_value={"schema_version": 1}
        ):
            python, _, recovered = runtime_install.ensure_managed_python(config_root)
        self.assertEqual(python, launcher)
        self.assertEqual(recovered, Path("/private/runtime/backups/untrusted-venv-1"))
        preserve.assert_called_once()
        self.assertEqual(create.call_args.args[0][:3], [sys.executable, "-m", "venv"])

    def test_posix_source_plan_uses_checkout_migrator_and_explicit_environment(self) -> None:
        module = load_posix_installer()
        paths = {
            "config_root": Path("/private/runtime"),
            "config": Path("/private/runtime/config/agent-memory.toml"),
        }
        with mock.patch.dict(
            module.os.environ,
            {
                "AGENT_MEMORY_ROOT": "/wrong/vault",
                "AGENT_MEMORY_STATE_DB": "/wrong/state.sqlite",
                "UNRELATED": "preserved",
            },
            clear=True,
        ):
            environment = module.source_environment(paths, config_exists=True)
        self.assertNotIn("AGENT_MEMORY_ROOT", environment)
        self.assertNotIn("AGENT_MEMORY_STATE_DB", environment)
        self.assertEqual(environment["AGENT_MEMORY_CONFIG_ROOT"], "/private/runtime")
        self.assertEqual(
            environment["AGENT_MEMORY_CONFIG_FILE"],
            "/private/runtime/config/agent-memory.toml",
        )
        self.assertEqual(environment["UNRELATED"], "preserved")
        with mock.patch.object(
            module,
            "run_json",
            return_value={"ok": False, "status": "blocked", "stage": "plan", "plan": {"blockers": []}},
        ) as run:
            result = module.source_state_plan(Path("/opt/python3.12"), environment)
        command = run.call_args.args[0]
        self.assertEqual(command[0], "/opt/python3.12")
        self.assertEqual(Path(command[1]), module.SOURCE_SCRIPTS / "agent_memory_migrate.py")
        self.assertEqual(command[2:4], ["plan", "--json"])
        self.assertEqual(result["status"], "blocked")

    def test_posix_upgrade_plan_surfaces_obsolete_gateway_key_removal(self) -> None:
        module = load_posix_installer()
        args = mock.Mock(host=[], no_host_hooks=True)
        paths = {
            "config_root": Path("/private/runtime"),
            "config": Path("/private/runtime/config/agent-memory.toml"),
            "state": Path("/private/runtime/state.sqlite"),
        }
        discovered = {
            "mode": "upgrade",
            "config_exists": True,
            "state_exists": True,
            "configured": {
                "memory_root": Path("/private/vault"),
                "git_root": Path("/private/vault"),
                "state_db": Path("/private/runtime/state.sqlite"),
            },
            "environment": {"AGENT_MEMORY_CONFIG_ROOT": "/private/runtime"},
            "vault": {"ok": True, "mutation": "none"},
        }
        config_plan = {
            "ok": True,
            "changed": True,
            "operations": ["REMOVE_WRITE_GATEWAY_LEGACY_ACTOR"],
        }
        with mock.patch.object(module, "private_paths", return_value=paths), mock.patch.object(
            module, "host_policy", return_value=([], ["--no-host-hooks"])
        ), mock.patch.object(
            module, "select_supported_python", return_value=Path("/opt/python3.12")
        ), mock.patch.object(
            module, "discover_installation", return_value=discovered
        ), mock.patch.object(
            module, "run_json", return_value={"ok": True, "status": "planned"}
        ), mock.patch.object(
            module,
            "source_generated_index_plan",
            return_value={"ok": True, "status": "ready", "blocking": False},
        ), mock.patch.object(
            module, "source_config_plan", return_value=config_plan
        ), mock.patch.object(
            module, "source_state_plan", return_value={"ok": True, "plan": {"blockers": []}}
        ), mock.patch.object(
            module,
            "source_audit_plan",
            return_value={"ok": True, "stage": "audit-plan", "status": "initialization_required", "exists": False},
        ):
            result = module.plan(args)
        self.assertEqual(result["config_plan"], config_plan)
        self.assertEqual(
            result["config_plan"]["operations"],
            ["REMOVE_WRITE_GATEWAY_LEGACY_ACTOR"],
        )
        windows = (SCRIPTS_ROOT / "install-windows.ps1").read_text(encoding="utf-8")
        windows_plan = "Memory-MigrateArgs -Arguments @('config-plan', '--json')"
        windows_apply = (
            "Memory-MigrateArgs -Arguments @('config-apply', '--backup-path', "
            "$configBackupPath, '--json')"
        )
        self.assertIn(windows_plan, windows)
        self.assertIn(windows_apply, windows)
        self.assertLess(windows.index(windows_plan), windows.index(windows_apply))

    def test_posix_apply_validates_reviewed_blockers_before_runtime_or_vault_write(self) -> None:
        module = load_posix_installer()
        args = mock.Mock(
            host=[], no_host_hooks=True,
            config_backup="/private/config-before.toml",
            state_backup="/private/state-before.sqlite",
            audit_backup="/private/audit-before.sqlite",
            disposition_file="", hook_backup_dir="",
            launchagent_backup_dir="/private/launchagent-backups/upgrade-1",
            memory_root="/private/vault", git_root="/private/vault",
            state_db="/private/runtime/state.sqlite",
        )
        paths = {
            "config_root": Path("/private/runtime"),
            "config": Path("/private/runtime/config/agent-memory.toml"),
            "state": Path("/private/runtime/state.sqlite"),
            "audit": Path("/private/runtime/audit_decisions.sqlite"),
            "config_backup": Path("/private/config-before.toml"),
            "state_backup": Path("/private/state-before.sqlite"),
            "audit_backup": Path("/private/audit-before.sqlite"),
            "hook_backup_dir": Path(),
            "launchagent_backup_dir": Path("/private/launchagent-backups/upgrade-1"),
            "disposition": Path(),
        }
        discovered = {
            "mode": "upgrade", "config_exists": True, "state_exists": True,
            "configured": {
                "memory_root": Path("/private/vault"),
                "git_root": Path("/private/vault"),
                "state_db": Path("/private/runtime/state.sqlite"),
            },
            "environment": {},
            "vault": {"ok": True, "mutation": "none"},
        }
        with mock.patch.object(module, "private_paths", return_value=paths), mock.patch.object(
            module, "select_supported_python", return_value=Path("/opt/python3.12")
        ), mock.patch.object(module, "discover_installation", return_value=discovered), mock.patch.object(
            module, "source_config_plan", return_value={"ok": True}
        ), mock.patch.object(
            module,
            "source_state_plan",
            return_value={"ok": False, "plan": {"blockers": ["ACTIVE_LEGACY_CLAIM"]}},
        ), mock.patch.object(
            module,
            "verify_reviewed_dispositions",
            side_effect=module.PosixInstallError("DISPOSITION_FILE_REQUIRED", "disposition-verify"),
        ), mock.patch.object(module, "run_json") as run, mock.patch.object(module, "run_plain") as plain:
            with self.assertRaisesRegex(module.PosixInstallError, "DISPOSITION_FILE_REQUIRED"):
                module.apply(args)
        run.assert_not_called()
        plain.assert_not_called()

    def test_posix_apply_rejects_non_disposition_blocker_before_runtime_install(self) -> None:
        module = load_posix_installer()
        args = mock.Mock(
            host=[], no_host_hooks=True,
            config_backup="/private/config-before.toml",
            state_backup="/private/state-before.sqlite",
            disposition_file="/private/reviewed.json", hook_backup_dir="",
            memory_root="/private/vault", git_root="/private/vault",
            state_db="/private/runtime/state.sqlite",
        )
        paths = {
            "config_root": Path("/private/runtime"),
            "config": Path("/private/runtime/config/agent-memory.toml"),
            "state": Path("/private/runtime/state.sqlite"),
            "config_backup": Path("/private/config-before.toml"),
            "state_backup": Path("/private/state-before.sqlite"),
            "hook_backup_dir": Path(),
            "disposition": Path("/private/reviewed.json"),
        }
        discovered = {
            "mode": "upgrade", "config_exists": True, "state_exists": True,
            "configured": {}, "environment": {},
            "vault": {"ok": True, "mutation": "none"},
        }
        with mock.patch.object(module, "private_paths", return_value=paths), mock.patch.object(
            module, "select_supported_python", return_value=Path("/opt/python3.12")
        ), mock.patch.object(module, "discover_installation", return_value=discovered), mock.patch.object(
            module, "source_config_plan", return_value={"ok": True}
        ), mock.patch.object(
            module,
            "source_state_plan",
            return_value={"ok": False, "plan": {"blockers": ["DUPLICATE_ACTIVE_TARGET"]}},
        ), mock.patch.object(
            module,
            "verify_reviewed_dispositions",
            side_effect=module.PosixInstallError("UNHANDLED_MIGRATION_BLOCKERS", "disposition-verify"),
        ), mock.patch.object(module, "run_json") as run, mock.patch.object(module, "run_plain") as plain:
            with self.assertRaisesRegex(module.PosixInstallError, "UNHANDLED_MIGRATION_BLOCKERS"):
                module.apply(args)
        run.assert_not_called()
        plain.assert_not_called()

    def test_posix_upgrade_never_bootstraps_existing_vault(self) -> None:
        module = load_posix_installer()
        args = mock.Mock(
            host=[], no_host_hooks=True,
            config_backup="/private/config-before.toml",
            state_backup="/private/state-before.sqlite",
            audit_backup="/private/audit-before.sqlite",
            disposition_file="", hook_backup_dir="",
            launchagent_backup_dir="/private/launchagent-backups/upgrade-2",
            memory_root="/private/vault", git_root="/private/vault",
            state_db="/private/runtime/state.sqlite",
        )
        paths = {
            "config_root": Path("/private/runtime"),
            "config": Path("/private/runtime/config/agent-memory.toml"),
            "state": Path("/private/runtime/state.sqlite"),
            "audit": Path("/private/runtime/audit_decisions.sqlite"),
            "config_backup": Path("/private/config-before.toml"),
            "state_backup": Path("/private/state-before.sqlite"),
            "audit_backup": Path("/private/audit-before.sqlite"),
            "hook_backup_dir": Path(),
            "launchagent_backup_dir": Path("/private/launchagent-backups/upgrade-2"),
            "disposition": Path(),
        }
        configured = {
            "memory_root": Path("/private/vault"),
            "git_root": Path("/private/vault"),
            "state_db": Path("/private/runtime/state.sqlite"),
            "audit_db": Path("/private/runtime/audit_decisions.sqlite"),
        }
        discovered = {
            "mode": "upgrade", "config_exists": True, "state_exists": True,
            "configured": configured, "environment": {},
            "vault": {"ok": True, "mutation": "none"},
        }

        def child_result(*_args, **kwargs):
            if kwargs["stage"] == "publish-ready":
                return published_result()
            if kwargs["stage"] == "audit-launchagent-deferred":
                return {
                    "ok": True,
                    "transaction_journal": "/private/launchagent-backups/upgrade-2/audit-launchagent-transaction.jsonl",
                }
            if kwargs["stage"] == "config-plan":
                return {
                    "ok": True,
                    "changed": True,
                    "operations": ["REMOVE_WRITE_GATEWAY_LEGACY_ACTOR"],
                }
            return {"ok": True, "changed": False, "stage": kwargs["stage"]}

        with mock.patch.object(module, "private_paths", return_value=paths), mock.patch.object(
            module, "select_supported_python", return_value=Path("/opt/python3.12")
        ), mock.patch.object(module, "discover_installation", return_value=discovered), mock.patch.object(
            module, "source_config_plan", return_value={"ok": True, "changed": False}
        ), mock.patch.object(
            module, "source_state_plan", return_value={"ok": True, "plan": {"blockers": []}}
        ), mock.patch.object(
            module,
            "source_audit_plan",
            return_value={"ok": True, "stage": "audit-plan", "status": "ready", "exists": True},
        ), mock.patch.object(
            module,
            "prepare_private_backup_parents",
            return_value={"ok": True, "private_parents": []},
        ), mock.patch.object(module, "configured_paths", return_value=configured), mock.patch.object(
            module, "run_json", side_effect=child_result
        ), mock.patch.object(module, "run_plain") as plain, mock.patch.object(
            module, "create_fresh_config"
        ) as create_config:
            result = module.apply(args)
        self.assertTrue(result["ok"])
        self.assertEqual(result["mode"], "upgrade")
        stages = [item["stage"] for item in result["stages"]]
        self.assertIn("vault-upgrade", stages)
        self.assertIn("config-apply", stages)
        self.assertIn("audit-apply", stages)
        self.assertNotIn("bootstrap", stages)
        plain.assert_not_called()
        create_config.assert_not_called()

    def test_posix_fresh_install_is_the_only_path_that_bootstraps(self) -> None:
        module = load_posix_installer()
        args = mock.Mock(
            host=[], no_host_hooks=True,
            config_backup="", state_backup="", disposition_file="", hook_backup_dir="",
            launchagent_backup_dir="/private/launchagent-backups/fresh-1",
            memory_root="/private/new-vault", git_root="/private/new-vault",
            state_db="/private/runtime/state.sqlite",
            user_id="user", agent_id="shared", app_id="agent-memory",
        )
        paths = {
            "config_root": Path("/private/runtime"),
            "config": Path("/private/runtime/config/agent-memory.toml"),
            "state": Path("/private/runtime/state.sqlite"),
            "config_backup": Path(), "state_backup": Path(),
            "hook_backup_dir": Path(),
            "launchagent_backup_dir": Path("/private/launchagent-backups/fresh-1"),
            "disposition": Path(),
        }
        configured = {
            "memory_root": Path("/private/new-vault"),
            "git_root": Path("/private/new-vault"),
            "state_db": Path("/private/runtime/state.sqlite"),
        }
        discovered = {
            "mode": "fresh", "config_exists": False, "state_exists": False,
            "configured": None, "environment": {},
            "vault": {"ok": True, "mutation": "bootstrap-on-apply"},
        }

        def child_result(*_args, **kwargs):
            if kwargs["stage"] == "publish-ready":
                return published_result()
            if kwargs["stage"] == "audit-launchagent-deferred":
                return {
                    "ok": True,
                    "transaction_journal": "/private/launchagent-backups/fresh-1/audit-launchagent-transaction.jsonl",
                }
            return {"ok": True, "stage": kwargs["stage"]}

        with mock.patch.object(module, "private_paths", return_value=paths), mock.patch.object(
            module, "select_supported_python", return_value=Path("/opt/python3.12")
        ), mock.patch.object(module, "discover_installation", return_value=discovered), mock.patch.object(
            module,
            "prepare_private_backup_parents",
            return_value={"ok": True, "private_parents": []},
        ), mock.patch.object(
            module, "configured_paths", return_value=configured
        ), mock.patch.object(module, "run_json", side_effect=child_result), mock.patch.object(
            module, "run_plain", return_value={"ok": True}
        ) as plain, mock.patch.object(module, "create_fresh_config") as create_config:
            result = module.apply(args)
        self.assertTrue(result["ok"])
        self.assertEqual(result["mode"], "fresh")
        self.assertIn("bootstrap", [item["stage"] for item in result["stages"]])
        plain.assert_called_once()
        create_config.assert_called_once()


if __name__ == "__main__":
    unittest.main()
