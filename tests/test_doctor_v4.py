from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_doctor as doctor
import agent_memory_audit as memory_audit
import agent_memory_index as memory_index
import agent_memory_intent as memory_intent
import agent_memory_observability as observability
import agent_memory_migrate as migrate


class DoctorV4ReadOnlyGatesTests(unittest.TestCase):
    def test_shadow_without_current_version_start_is_visible_but_reads_remain_available(self) -> None:
        with (
            mock.patch.object(doctor, "SEMANTIC_CONFIG", {"ranking_version": "hybrid-v2-shadow"}),
            mock.patch("agent_memory_shadow.shadow_status", return_value={
                "ok": False, "status": "not_started", "gate_failures": ["SHADOW_NOT_STARTED"],
            }),
        ):
            result = doctor.shadow_lifecycle_doctor_check()
        self.assertEqual(result["status"], "warn")
        self.assertEqual(result["detail"]["next_action"], "shadow start")
        self.assertFalse(result["detail"]["production_acceptance_complete"])

    def test_shadow_regression_is_not_reported_as_just_waiting(self) -> None:
        with (
            mock.patch.object(doctor, "SEMANTIC_CONFIG", {"ranking_version": "hybrid-v2-shadow"}),
            mock.patch("agent_memory_shadow.shadow_status", return_value={
                "ok": False, "status": "observing",
                "gate_failures": ["SHADOW_MINIMUM_DURATION_NOT_MET", "SHADOW_REQUIRED_CASE_REGRESSION"],
            }),
        ):
            result = doctor.shadow_lifecycle_doctor_check()
        self.assertEqual(result["status"], "fail")

    def test_legacy_ranking_does_not_require_shadow(self) -> None:
        with mock.patch.object(doctor, "SEMANTIC_CONFIG", {"ranking_version": "hybrid-v1"}):
            self.assertEqual(doctor.shadow_lifecycle_doctor_check()["status"], "pass")

    def _note(self, title: str, project_id: str) -> str:
        return (
            "---\n"
            "memory_type: routing\n"
            "track: routing\n"
            f"project_id: {project_id}\n"
            "app_id: agent-memory\n"
            "user_id: test\n"
            "agent_id: shared\n"
            "agent_scope: shared\n"
            "status: active\n"
            "sensitivity: normal\n"
            "temporal_policy: structural\n"
            "review_after_days: 3650\n"
            "---\n"
            f"# {title}\n\nBody.\n"
        )

    def test_dual_fts_requires_exact_markdown_projection_not_only_path_counts(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root).resolve()
            (vault / "A.md").write_text(self._note("A", "a"), encoding="utf-8")
            (vault / "INDEX.md").write_text(self._note("Index", "index"), encoding="utf-8")
            with (
                mock.patch.object(memory_index, "VAULT_ROOT", vault),
                mock.patch.object(doctor, "VAULT_ROOT", vault),
                contextlib.closing(sqlite3.connect(":memory:")) as conn,
            ):
                conn.row_factory = sqlite3.Row
                memory_index.init_db(conn)
                memory_index.scan(conn)
                (vault / "INDEX.md").write_text(
                    memory_index.generated_index_markdown(conn), encoding="utf-8"
                )
                memory_index.scan(conn)
                actual = sorted(vault.rglob("*.md"))
                actual_by_path = {str(path.resolve()): path for path in actual}
                docs = conn.execute("SELECT * FROM memory_docs").fetchall()
                db_by_path = {str(row["path"]): row for row in docs}

                healthy, detail = doctor.fts_exact_parity_health(
                    conn, actual_by_path, db_by_path
                )
                self.assertTrue(healthy, detail)
                self.assertTrue(detail["table_projection_digests_match"])

                conn.execute(
                    "UPDATE memory_fts_trigram SET summary='tampered' WHERE path=?",
                    (str((vault / "A.md").resolve()),),
                )
                healthy, detail = doctor.fts_exact_parity_health(
                    conn, actual_by_path, db_by_path
                )
                self.assertFalse(healthy)
                self.assertEqual(
                    detail["tables"]["memory_fts_trigram"]["content_hash_mismatch"],
                    ["A.md"],
                )
                self.assertFalse(detail["table_projection_digests_match"])

    def test_generated_index_is_exact_and_never_lists_itself(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root).resolve()
            (vault / "A.md").write_text(self._note("A", "a"), encoding="utf-8")
            (vault / "INDEX.md").write_text(self._note("Index", "index"), encoding="utf-8")
            with (
                mock.patch.object(memory_index, "VAULT_ROOT", vault),
                mock.patch.object(doctor, "VAULT_ROOT", vault),
                contextlib.closing(sqlite3.connect(":memory:")) as conn,
            ):
                conn.row_factory = sqlite3.Row
                memory_index.init_db(conn)
                memory_index.scan(conn)
                generated = memory_index.generated_index_markdown(conn)
                (vault / "INDEX.md").write_text(generated, encoding="utf-8")
                memory_index.scan(conn)
                healthy, detail = doctor.generated_index_health(
                    conn, {"A.md", "INDEX.md"}
                )
                self.assertTrue(healthy, detail)
                self.assertEqual(detail["missing"], [])
                self.assertEqual(detail["broken"], [])
                self.assertEqual(detail["self_references"], 0)

                (vault / "INDEX.md").write_text(
                    generated + "- `INDEX.md`: forbidden self reference\n",
                    encoding="utf-8",
                )
                healthy, detail = doctor.generated_index_health(
                    conn, {"A.md", "INDEX.md"}
                )
                self.assertFalse(healthy)
                self.assertEqual(detail["self_references"], 1)
                self.assertFalse(detail["generated_exact"])

    def test_generated_index_parity_ignores_markdown_paths_inside_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root).resolve()
            note = self._note("A", "a").replace(
                "memory_type: routing\n",
                'summary: "See `/private/archive/Legacy.md`, `A.md`, and `Short.md`."\n'
                "memory_type: routing\n",
            )
            (vault / "A.md").write_text(note, encoding="utf-8")
            (vault / "INDEX.md").write_text(self._note("Index", "index"), encoding="utf-8")
            with (
                mock.patch.object(memory_index, "VAULT_ROOT", vault),
                mock.patch.object(doctor, "VAULT_ROOT", vault),
                contextlib.closing(sqlite3.connect(":memory:")) as conn,
            ):
                conn.row_factory = sqlite3.Row
                memory_index.init_db(conn)
                memory_index.scan(conn)
                generated = memory_index.generated_index_markdown(conn)
                self.assertIn("`/private/archive/Legacy.md`", generated)
                self.assertIn("`A.md`", generated)
                (vault / "INDEX.md").write_text(generated, encoding="utf-8")
                memory_index.scan(conn)

                healthy, detail = doctor.generated_index_health(
                    conn, {"A.md", "INDEX.md"}
                )

            self.assertTrue(healthy, detail)
            self.assertEqual(detail["listed"], 1)
            self.assertEqual(detail["missing"], [])
            self.assertEqual(detail["broken"], [])
            self.assertEqual(detail["duplicates"], [])

    def test_generated_index_navigation_parser_requires_canonical_leading_path(self) -> None:
        text = (
            memory_index.GENERATED_INDEX_MARKER
            + "\n# Index\n\n"
            + "- `项目/A.md`: A (workflow)\n"
            + "- `/private/Bad.md`: ignored absolute entry\n"
            + "- `项目/../Bad.md`: ignored traversal entry\n"
            + "Summary mentions `Summary.md` and `项目/A.md`.\n"
        )
        self.assertEqual(
            memory_index.generated_index_navigation_references(text),
            ["项目/A.md"],
        )

    def test_legacy_index_keeps_broad_reference_safety_checks(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root).resolve()
            (vault / "A.md").write_text(self._note("A", "a"), encoding="utf-8")
            (vault / "INDEX.md").write_text(
                "# Legacy index\n\nSee `A.md` and stale `Missing.md`.\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(memory_index, "VAULT_ROOT", vault),
                mock.patch.object(doctor, "VAULT_ROOT", vault),
                contextlib.closing(sqlite3.connect(":memory:")) as conn,
            ):
                conn.row_factory = sqlite3.Row
                memory_index.init_db(conn)
                memory_index.scan(conn)
                healthy, detail = doctor.generated_index_health(
                    conn, {"A.md", "INDEX.md"}
                )

            self.assertFalse(healthy)
            self.assertFalse(detail["generated_marker"])
            self.assertEqual(detail["listed"], 2)
            self.assertEqual(detail["missing"], [])
            self.assertEqual(detail["broken"], ["Missing.md"])

    def test_observability_hygiene_rejects_free_text_but_never_echoes_it(self) -> None:
        with contextlib.closing(sqlite3.connect(":memory:")) as conn:
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
            observability._insert_event(
                conn,
                actor="codex",
                task_id="a" * 64,
                event_type="task_seen",
                source="tool_observed",
                value="seen",
            )
            conn.execute(
                """
                INSERT INTO memory_search_log(
                  query,result_count,used_paths,query_sha256,created_at,actor,task_id,
                  event_source,returned_memory_ids_json,ranking_mode,worker_status,
                  worker_restart_count,v1_result_fingerprint,v2_result_fingerprint
                ) VALUES(?,1,'',?,?,?,?,'tool_observed',?,'shadow','not_used',0,'','')
                """,
                (
                    "[redacted:0123456789ab]",
                    "b" * 64,
                    "2026-08-24T00:00:00+00:00",
                    "codex",
                    "a" * 64,
                    "[]",
                ),
            )
            self.assertFalse(any(doctor.observability_event_hygiene(conn).values()))
            self.assertFalse(any(doctor.search_observability_hygiene(conn).values()))

            conn.execute(
                "UPDATE memory_use_events SET reason_code='https://secret.example/path'"
            )
            conn.execute(
                "UPDATE memory_search_log SET query='private raw query', used_paths='/private/path'"
            )
            event_detail = doctor.observability_event_hygiene(conn)
            search_detail = doctor.search_observability_hygiene(conn)
            self.assertEqual(event_detail["invalid_reason_or_confidence"], 1)
            self.assertEqual(search_detail["raw_query_rows"], 1)
            self.assertEqual(search_detail["raw_path_rows"], 1)
            self.assertNotIn("secret.example", str(event_detail))
            self.assertNotIn("private raw query", str(search_detail))

    def test_audit_schema_check_is_read_only_and_fails_old_schema(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            audit_db = Path(raw_root) / "audit.sqlite"
            with contextlib.closing(sqlite3.connect(audit_db)) as conn:
                conn.execute(
                    "CREATE TABLE audit_decisions(finding_id TEXT, decision TEXT)"
                )
                conn.commit()
            before = audit_db.read_bytes()
            with mock.patch.object(migrate, "AUDIT_DB", audit_db):
                check = doctor.audit_schema_doctor_check()
            self.assertEqual(check["status"], "fail")
            self.assertEqual(
                check["detail"]["reason_code"],
                "AUDIT_SCHEMA_MIGRATION_REQUIRED",
            )
            with contextlib.closing(sqlite3.connect(audit_db)) as conn:
                tables = {
                    str(row[0])
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                columns = {
                    str(row[1])
                    for row in conn.execute("PRAGMA table_info(audit_decisions)")
                }
            self.assertEqual(tables, {"audit_decisions"})
            self.assertEqual(columns, {"finding_id", "decision"})
            self.assertEqual(audit_db.read_bytes(), before)

    def test_semantic_model_manifest_requires_exact_nonempty_revision_binding(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            model = root / "model"
            model.mkdir()
            artifact = model / "config.json"
            artifact.write_bytes(b"{}\n")
            revision = "57c266a740f537b4dc058e1b0cda161fd15afa75"
            manifest = root / "model-manifest.json"
            manifest.write_text(
                json.dumps({
                    "root": str(model),
                    "revision": revision,
                    "files": {
                        "config.json": {
                            "size": artifact.stat().st_size,
                            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        }
                    },
                }),
                encoding="utf-8",
            )
            with (
                mock.patch.object(doctor, "MODEL_MANIFEST", manifest),
                mock.patch.object(doctor, "MODEL_REVISION", revision),
            ):
                healthy, detail = doctor.verify_model_manifest()
            self.assertTrue(healthy, detail)
            self.assertTrue(detail["revision_format_ok"])

            for invalid_revision in ("", "main", "0" * 40):
                with (
                    mock.patch.object(doctor, "MODEL_MANIFEST", manifest),
                    mock.patch.object(doctor, "MODEL_REVISION", invalid_revision),
                ):
                    healthy, detail = doctor.verify_model_manifest()
                self.assertFalse(healthy, detail)

    def test_semantic_offline_probe_preserves_preflight_capability_for_child(self) -> None:
        capability = "a" * 64
        issuer = "4242"

        def successful_probe(
            command: list[str],
            timeout: int,
            environment: dict[str, str],
        ) -> dict[str, object]:
            self.assertEqual(environment["AGENT_MEMORY_MIGRATION_CAPABILITY"], capability)
            self.assertEqual(environment["AGENT_MEMORY_MIGRATION_ISSUER_PID"], issuer)
            return {
                "ok": True,
                "returncode": 0,
                "stdout": json.dumps({"results": [{"relative_path": "A.md"}]}),
                "detail": "",
            }

        with (
            mock.patch.dict(
                os.environ,
                {
                    "AGENT_MEMORY_MIGRATION_CAPABILITY": capability,
                    "AGENT_MEMORY_MIGRATION_ISSUER_PID": issuer,
                },
            ),
            mock.patch.object(
                doctor,
                "assert_runtime_ready",
                return_value={"phase": "preflight", "maintenance_capability": True},
            ),
            mock.patch.object(doctor, "run", side_effect=successful_probe),
        ):
            healthy, detail = doctor.offline_semantic_probe()
        self.assertTrue(healthy, detail)
        self.assertTrue(detail["maintenance_capability"])
        self.assertEqual(detail["reason_code"], "")

    def test_semantic_offline_probe_reports_transition_reason_instead_of_empty_error(self) -> None:
        blocked = {
            "ok": False,
            "returncode": 2,
            "stdout": json.dumps(
                {
                    "status": "error",
                    "reason_code": "RUNTIME_TRANSITION_INCOMPLETE",
                }
            ),
            "detail": "",
        }
        with (
            mock.patch.object(
                doctor,
                "assert_runtime_ready",
                return_value={"phase": "preflight", "maintenance_capability": True},
            ),
            mock.patch.object(doctor, "run", return_value=blocked),
        ):
            healthy, detail = doctor.offline_semantic_probe()
        self.assertFalse(healthy)
        self.assertEqual(detail["returncode"], 2)
        self.assertEqual(detail["reason_code"], "RUNTIME_TRANSITION_INCOMPLETE")
        self.assertEqual(detail["error"], "RUNTIME_TRANSITION_INCOMPLETE")

    def test_semantic_offline_probe_does_not_spawn_without_zvec_authorization(self) -> None:
        with (
            mock.patch.object(
                doctor,
                "assert_runtime_ready",
                side_effect=doctor.RuntimeTransitionError("closed"),
            ),
            mock.patch.object(doctor, "run") as invoked,
        ):
            healthy, detail = doctor.offline_semantic_probe()
        self.assertFalse(healthy)
        self.assertEqual(detail["reason_code"], "RUNTIME_TRANSITION_INCOMPLETE")
        invoked.assert_not_called()

    def test_atomic_coverage_is_per_document_and_excludes_structural_routing(self) -> None:
        base = {
            "status": "active",
            "memory_type": "project",
            "temporal_policy": "reviewable",
            "fact_key": "",
            "valid_from": "",
            "valid_until": "",
        }
        detail = doctor.action_sensitive_atomic_coverage(
            [
                {**base, "rel_path": "项目/普通项目摘要.md"},
                {
                    **base,
                    "rel_path": "项目/事实-缺键.md",
                    "valid_from": "2026-08-24",
                },
                {
                    **base,
                    "rel_path": "项目/事实-完整.md",
                    "valid_from": "2026-08-24",
                    "fact_key": "alpha.owner",
                },
                {
                    **base,
                    "rel_path": "工作流/结构规则.md",
                    "memory_type": "routing",
                    "temporal_policy": "structural",
                    "valid_from": "2026-08-24",
                },
                {
                    **base,
                    "rel_path": "决策/_模板-决策.md",
                    "memory_type": "template",
                    "temporal_policy": "structural",
                    "risk_class": "action_sensitive",
                },
            ]
        )
        self.assertEqual(
            detail["action_sensitive_documents"],
            ["项目/事实-完整.md", "项目/事实-缺键.md"],
        )
        self.assertEqual(
            detail["uncovered"],
            ["项目/事实-完整.md", "项目/事实-缺键.md"],
        )
        gaps = {
            item["rel_path"]: set(item["missing_or_invalid"])
            for item in detail["gap_details"]
        }
        self.assertEqual(
            gaps["项目/事实-完整.md"],
            {"verified_at", "evidence_provenance"},
        )
        self.assertTrue(
            {"fact_key", "verified_at", "evidence_provenance"}.issubset(
                gaps["项目/事实-缺键.md"]
            )
        )

    def test_durable_fact_evidence_requires_exact_current_v2_fact_receipt(self) -> None:
        raw_sha256 = hashlib.sha256(b"current bytes\n").hexdigest()
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
            conn.execute(
                "INSERT INTO memory_write_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    2,
                    "项目/事实-owner.md",
                    "completed",
                    raw_sha256,
                    "a" * 40,
                    "user_direct",
                    "fact",
                    "b" * 64,
                    "ALLOW",
                    "c" * 64,
                    "2026-08-25T00:00:00+00:00",
                ),
            )
            current = doctor._durable_fact_evidence_provenance(
                conn,
                rel_path="项目/事实-owner.md",
                raw_sha256=raw_sha256,
            )
            audit_current = memory_audit._durable_fact_evidence_provenance(
                conn,
                rel_path="项目/事实-owner.md",
                raw_sha256=raw_sha256,
            )
            changed = doctor._durable_fact_evidence_provenance(
                conn,
                rel_path="项目/事实-owner.md",
                raw_sha256="d" * 64,
            )
            conn.execute(
                "UPDATE memory_write_receipts SET knowledge_kind='rule'"
            )
            wrong_kind = doctor._durable_fact_evidence_provenance(
                conn,
                rel_path="项目/事实-owner.md",
                raw_sha256=raw_sha256,
            )
            audit_wrong_kind = memory_audit._durable_fact_evidence_provenance(
                conn,
                rel_path="项目/事实-owner.md",
                raw_sha256=raw_sha256,
            )
        self.assertTrue(current["present"])
        self.assertTrue(current["current_content_bound"])
        self.assertTrue(audit_current["present"])
        self.assertFalse(changed["present"])
        self.assertEqual(
            changed["reason_code"],
            "CURRENT_CONTENT_EVIDENCE_RECEIPT_MISSING",
        )
        self.assertFalse(wrong_kind["present"])
        self.assertFalse(audit_wrong_kind["present"])
        self.assertEqual(
            wrong_kind["reason_code"],
            "CURRENT_CONTENT_EVIDENCE_RECEIPT_MISSING",
        )

    def test_complete_atomic_tuple_with_current_receipt_has_no_risk_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root).resolve()
            target = vault / "项目" / "事实-owner.md"
            target.parent.mkdir()
            verified = dt.date.today().isoformat()
            text = (
                "---\n"
                f"memory_id: {'a' * 64}\n"
                "memory_type: project\ntrack: project\n"
                "app_id: agent-memory\nproject_id: owner\nagent_scope: shared\n"
                "status: active\nrisk_class: action_sensitive\n"
                "temporal_policy: reviewable\nreview_after_days: 90\n"
                f"fact_key: project.owner\nvalid_from: {verified}\n"
                f"verified_at: {verified}\n"
                "---\n# Owner\n"
            )
            target.write_text(text, encoding="utf-8")
            raw_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
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
                conn.execute(
                    "INSERT INTO memory_write_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        2,
                        "项目/事实-owner.md",
                        "completed",
                        raw_sha256,
                        "a" * 40,
                        "user_direct",
                        "fact",
                        "b" * 64,
                        "ALLOW",
                        "c" * 64,
                        "2026-08-25T00:00:00+00:00",
                    ),
                )
                with (
                    mock.patch.object(doctor, "VAULT_ROOT", vault),
                    mock.patch.object(memory_index, "VAULT_ROOT", vault),
                ):
                    report = doctor.governance_metadata_migration_health(conn)

        record = report["documents"][0]
        self.assertFalse(record["atomic_fact_gap"])
        self.assertEqual(record["atomic_fact_gap_fields"], [])
        self.assertTrue(record["durable_evidence_provenance"]["present"])
        self.assertEqual(record["risk_recommendation"]["reason_codes"], [])
        self.assertEqual(report["risk_candidate_documents"], 0)

    def test_missing_risk_class_is_never_auto_classified_as_ordinary(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root).resolve()
            workflow = vault / "工作流"
            workflow.mkdir()
            (workflow / "待判断.md").write_text(
                "---\n"
                f"memory_id: {'a' * 64}\n"
                "memory_type: workflow\n"
                "track: workflow\n"
                "project_id: agent-memory\n"
                "app_id: agent-memory\n"
                "agent_scope: shared\n"
                "status: active\n"
                "sensitivity: normal\n"
                "temporal_policy: reviewable\n"
                "review_after_days: 90\n"
                f"verified_at: {dt.date.today().isoformat()}\n"
                "---\n"
                "# 待判断\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(doctor, "VAULT_ROOT", vault),
                mock.patch.object(memory_index, "VAULT_ROOT", vault),
            ):
                report = doctor.governance_metadata_migration_health()

        self.assertEqual(report["risk_candidate_documents"], 1)
        recommendation = report["documents"][0]["risk_recommendation"]
        self.assertEqual(recommendation["recommended"], "")
        self.assertFalse(recommendation["automatable_after_governance"])
        self.assertFalse(recommendation["automatable_now"])
        self.assertTrue(recommendation["manual_review_required"])

    def test_old_v3_state_fails_structured_and_stops_before_v4_queries(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            vault = root / "vault"
            vault.mkdir()
            state_db = root / "state.sqlite"
            audit_db = root / "audit.sqlite"
            with contextlib.closing(sqlite3.connect(state_db)) as conn:
                conn.executescript(
                    """
                    CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO meta(key,value)
                    VALUES('agent_memory_state_schema_version','3');
                    CREATE TABLE memory_docs(
                      path TEXT PRIMARY KEY,
                      rel_path TEXT NOT NULL,
                      sha256 TEXT NOT NULL,
                      memory_type TEXT NOT NULL,
                      status TEXT NOT NULL,
                      sensitivity TEXT NOT NULL,
                      verified_at_source TEXT NOT NULL,
                      line_count INTEGER NOT NULL,
                      size_bytes INTEGER NOT NULL,
                      fact_key TEXT NOT NULL,
                      track TEXT NOT NULL
                    );
                    """
                )
                conn.commit()
            state_db.chmod(0o600)
            before = state_db.read_bytes()
            with (
                mock.patch.object(doctor, "STATE_DB", state_db),
                mock.patch.object(doctor, "VAULT_ROOT", vault),
                mock.patch.object(migrate, "AUDIT_DB", audit_db),
            ):
                checks = doctor.collect_checks()
            by_name = {str(item["name"]): item for item in checks}
            self.assertEqual(by_name["state_schema"]["status"], "fail")
            self.assertEqual(
                by_name["state_schema"]["detail"]["reason_code"],
                "STATE_SCHEMA_MIGRATION_REQUIRED",
            )
            self.assertNotIn("markdown_sqlite_parity", by_name)
            self.assertNotIn("writer_protocol_v2", by_name)
            self.assertEqual(state_db.read_bytes(), before)

    def test_required_runtime_files_cover_all_new_v4_entrypoints(self) -> None:
        self.assertTrue(
            {
                "agent_memory_embedding_worker.py",
                "agent_memory_explain.py",
                "agent_memory_shadow.py",
                "agent_memory_retrieval_benchmark.py",
            }.issubset(set(doctor.REQUIRED_RUNTIME_FILES))
        )

    def test_doctor_rejects_consumed_index_with_mismatched_commit_projection(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            repo = root / "repo"
            vault = repo / "vault"
            vault.mkdir(parents=True)
            index = vault / "INDEX.md"
            rules = vault / "AGENTS.md"
            base = b"# Base\n"
            generated = b"# Generated\n"
            index.write_bytes(base)
            rules.write_text("# Bound rules\n", encoding="utf-8")

            def git(*args: str) -> str:
                completed = __import__("subprocess").run(
                    ["git", "-C", str(repo), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return completed.stdout.strip()

            git("init", "-q")
            git("config", "user.name", "Doctor Test")
            git("config", "user.email", "doctor@example.invalid")
            git("add", "vault")
            git("commit", "-qm", "base")
            base_head = git("rev-parse", "HEAD")
            index.write_bytes(generated)
            rules.write_text("# Unbound changed rules\n", encoding="utf-8")
            git("add", "vault")
            git("commit", "-qm", "invalid projection")
            generated_commit = git("rev-parse", "HEAD")

            state_db = root / "state.sqlite"
            with sqlite3.connect(state_db) as conn:
                memory_intent.ensure_schema(conn)
                conn.execute(
                    """
                    INSERT INTO generated_index_closeout_transactions(
                      transaction_id, actor, task_sha256, vault_root_sha256,
                      git_head, index_base_sha256, full_vault_inputs_sha256,
                      lease_fences_sha256, capability_sha256, issuer_pid,
                      consumer_pid, status, issued_at_epoch, expires_at_epoch,
                      claimed_at_epoch, consumed_at_epoch, generated_sha256,
                      closeout_git_commit
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        "1" * 32,
                        "test",
                        "2" * 64,
                        hashlib.sha256(str(vault.resolve()).encode("utf-8")).hexdigest(),
                        base_head,
                        hashlib.sha256(base).hexdigest(),
                        "5" * 64,
                        "6" * 64,
                        "7" * 64,
                        123,
                        456,
                        "consumed",
                        1,
                        2,
                        1,
                        2,
                        hashlib.sha256(generated).hexdigest(),
                        generated_commit,
                    ),
                )
                conn.commit()
                config = {
                    "write_gateway": {
                        "writer_protocol_version": doctor.WRITER_PROTOCOL_REQUIRED,
                        "state_schema_required": doctor.STATE_SCHEMA_REQUIRED,
                        "canonical_actors": list(doctor.CANONICAL_WRITER_ACTORS),
                    }
                }
                with (
                    mock.patch.object(doctor, "GIT_ROOT", repo),
                    mock.patch.object(doctor, "VAULT_ROOT", vault),
                    mock.patch.object(doctor, "load_config", return_value=config),
                ):
                    healthy, detail = doctor.writer_protocol_health(conn)
            self.assertFalse(healthy, detail)
            self.assertEqual(
                detail["invalid_consumed_generated_index_transactions"],
                1,
            )


if __name__ == "__main__":
    unittest.main()
