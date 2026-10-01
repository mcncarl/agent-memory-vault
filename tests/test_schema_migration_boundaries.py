from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import agent_memory_audit as audit
import agent_memory_claim as claim
import agent_memory_evolution as evolution
import agent_memory_index as memory_index
import agent_memory_intent as intent
import agent_memory_migrate as migrate
import agent_memory_observability as observability
import agent_memory_search as search
import agent_memory_safety as safety
import agent_memory_zvec_index as zvec_index
from agent_memory_state import (
    OBSERVABILITY_EVENT_CONTROL_TRIGGER_INSERT,
    OBSERVABILITY_EVENT_CONTROL_TRIGGER_UPDATE,
    SEARCH_LOG_CONTROL_REASON_CODE,
    SEARCH_LOG_CONTROL_TRIGGER_INSERT,
    SEARCH_LOG_CONTROL_TRIGGER_UPDATE,
    SEARCH_LOG_PRIVACY_REASON_CODE,
    SEARCH_LOG_PRIVACY_TRIGGER_INSERT,
    SEARCH_LOG_PRIVACY_TRIGGER_UPDATE,
)
from tests.state_fixture import initialize_full_state


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AuditMigrationBoundaryTests(unittest.TestCase):
    def test_installer_migrates_legacy_audit_with_exclusive_online_backup(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            database = root / "audit.sqlite"
            backup = root / "audit-before.sqlite"
            with sqlite3.connect(database) as conn:
                conn.execute(
                    "CREATE TABLE audit_decisions("
                    "finding_id TEXT PRIMARY KEY, decision TEXT NOT NULL, note TEXT DEFAULT '', "
                    "snooze_until TEXT DEFAULT '', decided_at TEXT NOT NULL)"
                )
                conn.execute(
                    "INSERT INTO audit_decisions VALUES('f1','resolved','','','2026-08-01')"
                )
            with mock.patch.object(migrate, "AUDIT_DB", database):
                result = migrate.apply_audit_migration(backup_path=backup)
                verified = migrate.verify_audit()
            self.assertTrue(result["ok"])
            self.assertTrue(verified["ok"])
            self.assertEqual(oct(backup.stat().st_mode & 0o777), "0o600")
            with sqlite3.connect(backup) as conn:
                self.assertNotIn(
                    "occurrence_fingerprint",
                    {str(row[1]) for row in conn.execute("PRAGMA table_info(audit_decisions)")},
                )
            with sqlite3.connect(database) as conn:
                self.assertEqual(
                    conn.execute(
                        "SELECT value FROM meta WHERE key='agent_memory_audit_schema_version'"
                    ).fetchone()[0],
                    str(audit.AUDIT_SCHEMA_VERSION),
                )
                self.assertIsNotNone(
                    conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' "
                        "AND name='audit_finding_occurrences'"
                    ).fetchone()
                )
            with mock.patch.object(migrate, "AUDIT_DB", database):
                with self.assertRaisesRegex(ValueError, "BACKUP_PATH_EXISTS"):
                    migrate.apply_audit_migration(backup_path=backup)

    def test_ordinary_audit_rejects_legacy_schema_without_ddl(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "audit.sqlite"
            with sqlite3.connect(database) as conn:
                conn.execute(
                    "CREATE TABLE audit_decisions(finding_id TEXT PRIMARY KEY, decision TEXT NOT NULL)"
                )
            before = file_sha256(database)
            with mock.patch.object(audit, "AUDIT_DB", database):
                with self.assertRaisesRegex(
                    audit.AuditSchemaMigrationRequired,
                    audit.AUDIT_SCHEMA_REASON_CODE,
                ):
                    audit.connect_audit(read_only=True)
            self.assertEqual(file_sha256(database), before)

    def test_recurring_expiry_gets_new_occurrence_each_week(self) -> None:
        finding = audit.Finding(
            id="stable-expiry",
            kind="memory_expired",
            severity="high",
            rel_path="Fact.md",
            title="Fact",
            message="expired",
            detail={"valid_until": "2026-08-01", "status": "active"},
        )
        with sqlite3.connect(":memory:") as conn:
            conn.row_factory = sqlite3.Row
            migrate._ensure_audit_schema(conn)
            conn.commit()
            audit.reconcile_occurrences(conn, [finding], cycle="2026-W34")
            first = finding.occurrence_fingerprint
            conn.execute(
                "INSERT INTO audit_decisions VALUES(?,?,?,?,?,?)",
                (finding.id, "resolved", first, "", "", "2026-08-24T00:00:00+00:00"),
            )
            conn.commit()
            decision = audit.load_decisions(conn)[finding.id]
            self.assertTrue(audit.decision_hides(decision, finding))
            next_week = audit.Finding(**{**finding.__dict__, "occurrence_token": ""})
            audit.reconcile_occurrences(conn, [next_week], cycle="2026-W35")
            self.assertNotEqual(next_week.occurrence_fingerprint, first)
            self.assertFalse(audit.decision_hides(decision, next_week))

    def test_disappeared_finding_reappears_as_new_occurrence(self) -> None:
        finding = audit.Finding(
            id="stable",
            kind="active_unverified",
            severity="medium",
            rel_path="Fact.md",
            title="Fact",
            message="missing",
            detail={"temporal_policy": "reviewable"},
        )
        with sqlite3.connect(":memory:") as conn:
            conn.row_factory = sqlite3.Row
            migrate._ensure_audit_schema(conn)
            conn.commit()
            audit.reconcile_occurrences(conn, [finding], cycle="2026-W34")
            first = finding.occurrence_fingerprint
            audit.reconcile_occurrences(conn, [], cycle="2026-W34")
            reappeared = audit.Finding(**{**finding.__dict__, "occurrence_token": ""})
            audit.reconcile_occurrences(conn, [reappeared], cycle="2026-W34")
            self.assertNotEqual(reappeared.occurrence_fingerprint, first)


class OrdinaryCommandSchemaBoundaryTests(unittest.TestCase):
    @staticmethod
    def _schema_snapshot(database: Path) -> tuple[tuple[object, ...], ...]:
        with sqlite3.connect(database) as conn:
            return tuple(
                conn.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name")
            )

    def test_claim_list_and_expiry_preview_require_migration_without_ddl(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "state.sqlite"
            with sqlite3.connect(database) as conn:
                conn.execute("CREATE TABLE legacy(value TEXT)")
            before = self._schema_snapshot(database)
            with (
                mock.patch.object(claim, "STATE_DB", database),
                mock.patch.object(claim, "assert_runtime_ready", return_value={"ready": True}),
            ):
                for operation in (
                    lambda: claim.active_claim_rows("session", "codex"),
                    claim.all_active_claim_rows,
                    lambda: claim.expire_stale_claims(24, apply=False),
                ):
                    with self.subTest(operation=operation):
                        with self.assertRaises(intent.IntentError) as raised:
                            operation()
                        self.assertEqual(
                            raised.exception.reason_code,
                            intent.STATE_SCHEMA_REASON_CODE,
                        )
            self.assertEqual(self._schema_snapshot(database), before)

    def test_index_and_evolution_init_are_verify_only_without_installer_capability(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            for module, args in (
                (
                    memory_index,
                    SimpleNamespace(
                        init=True,
                        scan=False,
                        report=False,
                        search=None,
                        gen_index_candidate=False,
                        sync_generated_index=False,
                    ),
                ),
                (evolution, SimpleNamespace(init=True, scan=False, report=False)),
            ):
                database = root / f"{module.__name__}.sqlite"
                with sqlite3.connect(database) as conn:
                    conn.execute("CREATE TABLE legacy(value TEXT)")
                before = self._schema_snapshot(database)
                output = io.StringIO()
                with (
                    mock.patch.object(module, "STATE_DB", database),
                    mock.patch.object(module, "parse_args", return_value=args),
                    mock.patch.object(module, "assert_runtime_ready", return_value={"ready": True}),
                    contextlib.redirect_stdout(output),
                ):
                    self.assertEqual(module.main(), 2)
                self.assertIn(intent.STATE_SCHEMA_REASON_CODE, output.getvalue())
                self.assertEqual(self._schema_snapshot(database), before)

    def test_claim_and_intent_reads_do_not_create_a_missing_database(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "missing-state.sqlite"
            with (
                mock.patch.object(claim, "STATE_DB", database),
                mock.patch.object(intent, "STATE_DB", database),
            ):
                for operation in (
                    claim.all_active_claim_rows,
                    lambda: intent.show_intent("0" * 32),
                    claim.connect,
                    intent.connect,
                ):
                    with self.subTest(operation=operation), mock.patch.object(
                        claim if operation is claim.connect else intent,
                        "assert_runtime_ready",
                        return_value={"ready": True},
                    ):
                        with self.assertRaises(intent.IntentError) as raised:
                            operation()
                        self.assertEqual(
                            raised.exception.reason_code,
                            intent.STATE_SCHEMA_REASON_CODE,
                        )
                        self.assertFalse(database.exists())

    def test_intent_and_claim_writes_never_repair_partial_v4_schema(self) -> None:
        mutations = (
            (
                "missing_intent_column",
                "ALTER TABLE memory_write_intents DROP COLUMN approval_proposal_raw_sha256",
                intent,
            ),
            (
                "missing_claim_index",
                "DROP INDEX idx_memory_session_claims_active_target",
                claim,
            ),
            (
                "missing_privacy_trigger",
                f"DROP TRIGGER {SEARCH_LOG_PRIVACY_TRIGGER_INSERT}",
                intent,
            ),
        )
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            for name, mutation, module in mutations:
                with self.subTest(name=name):
                    database = root / f"{name}.sqlite"
                    initialize_full_state(database)
                    with sqlite3.connect(database) as conn:
                        conn.execute(mutation)
                        conn.commit()
                    before_bytes = database.read_bytes()
                    with (
                        mock.patch.object(module, "STATE_DB", database),
                        mock.patch.object(module, "assert_runtime_ready", return_value={"ready": True}),
                    ):
                        with self.assertRaises(intent.IntentError) as raised:
                            module.connect()
                        self.assertEqual(
                            raised.exception.reason_code,
                            intent.STATE_SCHEMA_REASON_CODE,
                        )
                    self.assertEqual(database.read_bytes(), before_bytes)

    def test_safety_audit_never_creates_or_repairs_state_schema(self) -> None:
        assessment = safety.assess_source(
            "bounded input",
            source_class="user_direct",
            knowledge_kind="rule",
        )
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            missing = root / "missing.sqlite"
            with self.assertRaisesRegex(sqlite3.OperationalError, "STATE_SCHEMA_MIGRATION_REQUIRED"):
                safety.record_assessment(
                    missing,
                    assessment,
                    run_id="missing",
                    actor="codex",
                    session_hash="",
                    trigger="test",
                )
            self.assertFalse(missing.exists())

            partial = root / "partial.sqlite"
            with sqlite3.connect(partial) as conn:
                conn.execute("CREATE TABLE memory_safety_log(id INTEGER PRIMARY KEY)")
                conn.commit()
            before = partial.read_bytes()
            with self.assertRaisesRegex(sqlite3.OperationalError, "STATE_SCHEMA_MIGRATION_REQUIRED"):
                safety.record_assessment(
                    partial,
                    assessment,
                    run_id="partial",
                    actor="codex",
                    session_hash="",
                    trigger="test",
                )
            self.assertEqual(partial.read_bytes(), before)

    def test_claim_list_cli_returns_stable_migration_reason_without_ddl(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "state.sqlite"
            with sqlite3.connect(database) as conn:
                conn.execute("CREATE TABLE legacy(value TEXT)")
            before = self._schema_snapshot(database)
            args = SimpleNamespace(
                actor="human",
                session_id="",
                json=True,
                action="list-all",
            )
            output = io.StringIO()
            with (
                mock.patch.object(claim, "STATE_DB", database),
                mock.patch.object(claim, "parse_args", return_value=args),
                mock.patch.object(claim, "assert_runtime_ready", return_value={"ready": True}),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(claim.main(), 2)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["reason_code"], intent.STATE_SCHEMA_REASON_CODE)
            self.assertTrue(payload["degraded"])
            self.assertEqual(self._schema_snapshot(database), before)

    def test_intent_show_and_expiry_preview_require_migration_without_ddl(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "state.sqlite"
            with sqlite3.connect(database) as conn:
                conn.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            before = self._schema_snapshot(database)
            with mock.patch.object(intent, "STATE_DB", database):
                for operation in (
                    lambda: intent.show_intent("0" * 32),
                    lambda: intent.expire_intents(apply=False),
                ):
                    with self.subTest(operation=operation):
                        with self.assertRaises(intent.IntentError) as raised:
                            operation()
                        self.assertEqual(
                            raised.exception.reason_code,
                            intent.STATE_SCHEMA_REASON_CODE,
                        )
            self.assertEqual(self._schema_snapshot(database), before)

    def test_intent_show_cli_returns_stable_migration_reason_without_ddl(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "state.sqlite"
            with sqlite3.connect(database) as conn:
                conn.execute("CREATE TABLE legacy(value TEXT)")
            before = self._schema_snapshot(database)
            args = SimpleNamespace(
                actor="codex",
                session_id="",
                json=True,
                action="show",
                intent_id="0" * 32,
            )
            output = io.StringIO()
            with (
                mock.patch.object(intent, "STATE_DB", database),
                mock.patch.object(intent, "parse_args", return_value=args),
                mock.patch.object(intent, "assert_runtime_ready", return_value={"ready": True}),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(intent.main(), 2)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["reason_code"], intent.STATE_SCHEMA_REASON_CODE)
            self.assertTrue(payload["degraded"])
            self.assertEqual(self._schema_snapshot(database), before)

    def test_fresh_installer_state_has_database_privacy_guards(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "state.sqlite"
            with mock.patch.object(migrate, "STATE_DB", database):
                result = migrate.initialize_state()
            self.assertTrue(result["ok"])
            self.assertTrue(result["report"]["search_log_privacy"]["ready"])
            with sqlite3.connect(database) as conn:
                triggers = {
                    str(row[0])
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertTrue(
                {
                    SEARCH_LOG_PRIVACY_TRIGGER_INSERT,
                    SEARCH_LOG_PRIVACY_TRIGGER_UPDATE,
                    SEARCH_LOG_CONTROL_TRIGGER_INSERT,
                    SEARCH_LOG_CONTROL_TRIGGER_UPDATE,
                    OBSERVABILITY_EVENT_CONTROL_TRIGGER_INSERT,
                    OBSERVABILITY_EVENT_CONTROL_TRIGGER_UPDATE,
                }.issubset(triggers)
            )

    def test_fresh_installer_state_passes_claim_schema_gate(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "state.sqlite"
            with mock.patch.object(migrate, "STATE_DB", database):
                self.assertTrue(migrate.initialize_state()["ok"])
            with contextlib.closing(sqlite3.connect(database)) as conn:
                tables = {
                    str(row[0])
                    for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                claim.assert_schema_ready(conn)
            self.assertTrue(
                {"memory_deletion_observations", "memory_committed_observations"}.issubset(tables)
            )

    def test_installer_migrates_legacy_search_rows_then_installs_guards(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            database = root / "state.sqlite"
            backup = root / "state-before.sqlite"
            with sqlite3.connect(database) as conn:
                conn.row_factory = sqlite3.Row
                intent.ensure_schema(conn)
                conn.execute(
                    "INSERT INTO memory_search_log(query,result_count,used_paths,created_at) "
                    "VALUES('private legacy query',1,'项目/Secret.md','2026-08-24T00:00:00+00:00')"
                )
                conn.commit()
                before = migrate.inspect(conn)
                self.assertIn("guard_version", before["missing_privacy_guards"])
                result = migrate.apply_migration(conn, backup_path=backup)
                verified = migrate.verify(conn)
                row = conn.execute(
                    "SELECT query,query_sha256,used_paths FROM memory_search_log"
                ).fetchone()
            self.assertTrue(result["ok"])
            self.assertTrue(verified["ok"])
            self.assertEqual(str(row[0]), "")
            self.assertEqual(len(str(row[1])), 64)
            self.assertEqual(str(row[2]), "")
            self.assertTrue(backup.exists())

    def test_installer_backfills_legacy_task_denominator_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            database = root / "state.sqlite"
            first_backup = root / "state-before-first.sqlite"
            second_backup = root / "state-before-second.sqlite"
            task_id = "a" * 64
            memory_id = "b" * 64
            with sqlite3.connect(database) as conn:
                conn.row_factory = sqlite3.Row
                intent.ensure_schema(conn)
                for event_id, event_type, memory_ids, created_at in (
                    (
                        "legacy-opened-objective",
                        "opened_original",
                        json.dumps([memory_id]),
                        "2026-08-01T00:00:00+00:00",
                    ),
                    (
                        "legacy-search-objective",
                        "search",
                        "[]",
                        "2026-08-24T00:00:00+00:00",
                    ),
                ):
                    conn.execute(
                        """
                        INSERT INTO memory_use_events(
                          event_id,actor,task_id,runtime_version,event_type,source,
                          memory_ids_json,value,created_at
                        ) VALUES(?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            event_id, "codex", task_id, "legacy-runtime", event_type,
                            "tool_observed", memory_ids, "yes" if event_type == "opened_original" else "success",
                            created_at,
                        ),
                    )
                conn.execute(
                    """
                    INSERT INTO memory_search_log(
                      query,result_count,used_paths,query_sha256,query_length,
                      sources,duration_ms,created_at,search_id,actor,task_id,
                      runtime_version,event_source,returned_memory_ids_json,search_status
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        "", 0, "", "c" * 64, 1, "sqlite", 1,
                        "2026-08-24T00:00:00+00:00",
                        "11111111-1111-1111-1111-111111111111", "codex", task_id,
                        "legacy-runtime", "tool_observed", "[]", "success",
                    ),
                )
                conn.commit()

                first = migrate.apply_migration(conn, backup_path=first_backup)
                seen = conn.execute(
                    "SELECT created_at FROM memory_use_events WHERE actor=? AND task_id=? "
                    "AND event_type='task_seen' AND source='tool_observed'",
                    ("codex", task_id),
                ).fetchall()
                report = observability.build_report(
                    conn,
                    since="2026-08-20T00:00:00+00:00",
                )
                second = migrate.apply_migration(conn, backup_path=second_backup)

            self.assertTrue(first["ok"])
            self.assertEqual(first["observability_task_seen_backfill"]["inserted"], 1)
            self.assertEqual(first["observability_task_seen_backfill"]["remaining_pairs"], 0)
            self.assertEqual([str(row[0]) for row in seen], ["2026-08-01T00:00:00+00:00"])
            self.assertEqual(report["tool_observed"]["tasks_without_hook_denominator"], 0)
            self.assertEqual(report["cross_metrics"]["chain_health"]["orphan_event_tasks"], 0)
            self.assertEqual(report["cross_metrics"]["shadow_7d"]["missing_denominator"], 0)
            self.assertTrue(second["ok"])
            self.assertEqual(second["observability_task_seen_backfill"]["inserted"], 0)
            self.assertEqual(second["observability_task_seen_backfill"]["remaining_pairs"], 0)

    def test_guardless_v4_is_migration_required_and_direct_sql_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "state.sqlite"
            with sqlite3.connect(database) as conn:
                conn.row_factory = sqlite3.Row
                intent.ensure_schema(conn)
                report = migrate.inspect(conn)
                verified = migrate.verify(conn)
            self.assertEqual(report["state_schema_version"], intent.STATE_SCHEMA_VERSION)
            self.assertFalse(report["search_log_privacy"]["ready"])
            self.assertEqual(verified["status"], "migration_required")
            self.assertEqual(verified["reason_code"], intent.STATE_SCHEMA_REASON_CODE)

            guarded_database = Path(raw_root).resolve() / "guarded-state.sqlite"
            with mock.patch.object(migrate, "STATE_DB", guarded_database):
                self.assertTrue(migrate.initialize_state()["ok"])
            with sqlite3.connect(guarded_database) as conn:
                with self.assertRaisesRegex(sqlite3.IntegrityError, SEARCH_LOG_PRIVACY_REASON_CODE):
                    conn.execute(
                        "INSERT INTO memory_search_log(query,result_count,used_paths,sources,search_status,created_at) "
                        "VALUES('raw private query',0,'','none','success','now')"
                    )
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM memory_search_log").fetchone()[0], 0)
                with self.assertRaisesRegex(sqlite3.IntegrityError, SEARCH_LOG_PRIVACY_REASON_CODE):
                    conn.execute(
                        "INSERT INTO memory_search_log(query,result_count,used_paths,sources,search_status,created_at) "
                        "VALUES('[redacted:abcdef012345]',0,'','none','success','now')"
                    )
                conn.execute(
                    "INSERT INTO memory_search_log(query,result_count,used_paths,sources,search_status,created_at) "
                    "VALUES('',0,'','none','success','2026-08-24T00:00:00+00:00')"
                )
                with self.assertRaisesRegex(sqlite3.IntegrityError, SEARCH_LOG_CONTROL_REASON_CODE):
                    conn.execute(
                        "UPDATE memory_search_log SET sources='https://private.example'"
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, SEARCH_LOG_PRIVACY_REASON_CODE):
                    conn.execute("UPDATE memory_search_log SET used_paths='/private/path'")
                row = conn.execute("SELECT query,used_paths,sources,search_status FROM memory_search_log").fetchone()
            self.assertEqual(tuple(row), ("", "", "none", "success"))

    def test_search_missing_v4_schema_is_degraded_without_ddl(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "state.sqlite"
            with sqlite3.connect(database) as conn:
                conn.execute("CREATE TABLE legacy(value TEXT)")
            with sqlite3.connect(database) as conn:
                before = tuple(conn.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name"))
            args = SimpleNamespace(query="memory", no_log=False)
            with (
                mock.patch.object(search, "STATE_DB", database),
                mock.patch.object(search, "assert_runtime_ready", return_value={"ready": True}),
            ):
                rows, warnings = search.sqlite_search(args)
            self.assertEqual(rows, [])
            self.assertIn("STATE_SCHEMA_MIGRATION_REQUIRED", " ".join(warnings))
            with sqlite3.connect(database) as conn:
                after = tuple(conn.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name"))
            self.assertEqual(after, before)

    def test_observe_missing_v4_schema_rejects_without_ddl(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "state.sqlite"
            with sqlite3.connect(database) as conn:
                conn.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            with sqlite3.connect(database) as conn:
                before = tuple(conn.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name"))
            with (
                mock.patch.object(observability, "STATE_DB", database),
                mock.patch.object(observability, "assert_runtime_ready", return_value={"ready": True}),
            ):
                with contextlib.closing(observability.connect()) as conn:
                    with self.assertRaisesRegex(sqlite3.OperationalError, "STATE_SCHEMA_MIGRATION_REQUIRED"):
                        observability.assert_schema_ready(conn)
            with sqlite3.connect(database) as conn:
                after = tuple(conn.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name"))
            self.assertEqual(after, before)

    def test_zvec_query_schema_gate_does_not_create_vector_tables(self) -> None:
        with contextlib.closing(sqlite3.connect(":memory:")) as conn:
            conn.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            before = tuple(
                conn.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name")
            )
            with self.assertRaisesRegex(sqlite3.OperationalError, "STATE_SCHEMA_MIGRATION_REQUIRED"):
                zvec_index.assert_schema_ready(conn)
            after = tuple(
                conn.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name")
            )
        self.assertEqual(after, before)

    def test_atomic_fact_coverage_is_per_document(self) -> None:
        with contextlib.closing(sqlite3.connect(":memory:")) as conn:
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
            for index, (rel_path, fact_key, valid_from) in enumerate(
                (
                    ("Project-Fact-Missing.md", "", "2026-08-24"),
                    ("Workflow-Ordinary-Reviewable.md", "", ""),
                    ("Decision-Fact-With-Key.md", "decision:one", "2026-08-24"),
                ),
                1,
            ):
                conn.execute(
                    "INSERT INTO memory_docs("
                    "path,rel_path,memory_id,sha256,title,memory_type,track,status,"
                    "temporal_policy,fact_key,valid_from,mtime,size_bytes,line_count,indexed_at"
                    ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        f"/vault/{rel_path}", rel_path, f"m{index}", f"s{index}", rel_path,
                        ("project", "workflow", "decision")[index - 1], "project", "active",
                        "reviewable", fact_key, valid_from, 1.0, 1, 1,
                        "2026-08-24T00:00:00+00:00",
                    ),
                )
            findings: list[audit.Finding] = []
            audit.add_temporal_policy_findings(conn, findings)
        atomic = [item for item in findings if item.kind == "atomic_fact_coverage"]
        self.assertEqual(
            [item.rel_path for item in atomic],
            ["Decision-Fact-With-Key.md", "Project-Fact-Missing.md"],
        )
        by_path = {item.rel_path: item for item in atomic}
        self.assertEqual(
            set(by_path["Decision-Fact-With-Key.md"].detail["missing_or_invalid"]),
            {"verified_at", "evidence_provenance"},
        )
        self.assertTrue(
            {"fact_key", "verified_at", "evidence_provenance"}.issubset(
                set(by_path["Project-Fact-Missing.md"].detail["missing_or_invalid"])
            )
        )

    def test_audit_flags_structural_action_sensitive_tuple_and_evidence_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root).resolve()
            target = vault / "项目" / "事实-结构绕过.md"
            target.parent.mkdir()
            target.write_text(
                "---\n"
                f"memory_id: {'a' * 64}\n"
                "memory_type: project\ntrack: project\n"
                "app_id: agent-memory\nproject_id: alpha\nagent_scope: shared\n"
                "status: active\nrisk_class: action_sensitive\n"
                "temporal_policy: structural\nreview_after_days: 90\n"
                "fact_key: project.owner\n"
                "---\n# Owner\n\n## 当前有效摘要\n\n- Current 2026-08-01.\n",
                encoding="utf-8",
            )
            with contextlib.closing(sqlite3.connect(":memory:")) as conn:
                conn.row_factory = sqlite3.Row
                memory_index.init_db(conn)
                with mock.patch.object(memory_index, "VAULT_ROOT", vault):
                    doc, _loops = memory_index.load_doc(
                        target,
                        "2026-08-25T00:00:00+00:00",
                    )
                memory_index.upsert_doc(conn, doc)
                findings: list[audit.Finding] = []
                with mock.patch.object(audit, "VAULT_ROOT", vault):
                    audit.add_temporal_policy_findings(conn, findings)

        atomic = [item for item in findings if item.kind == "atomic_fact_coverage"]
        self.assertEqual(len(atomic), 1)
        self.assertEqual(
            set(atomic[0].detail["missing_or_invalid"]),
            {"temporal_policy", "valid_from", "verified_at", "evidence_provenance"},
        )
        self.assertFalse(atomic[0].detail["document_date_is_verification"])
        conflicts = [
            item for item in findings if item.kind == "temporal_policy_conflict"
        ]
        self.assertEqual(len(conflicts), 1)
        self.assertIn(
            "ACTION_SENSITIVE_STRUCTURAL_POLICY",
            conflicts[0].detail["reason_codes"],
        )


if __name__ == "__main__":
    unittest.main()
