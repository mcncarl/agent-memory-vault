from __future__ import annotations

import contextlib
import io
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

import agent_memory_observability as observability
import agent_memory_state as memory_state


def legacy_database(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE memory_search_log(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          query TEXT NOT NULL,
          result_count INTEGER NOT NULL,
          used_paths TEXT,
          query_sha256 TEXT,
          query_length INTEGER,
          sources TEXT,
          duration_ms INTEGER,
          created_at TEXT NOT NULL
        );
        """
    )
    return conn


class MemoryObservabilityTests(unittest.TestCase):
    def test_version_reducer_is_ordered_and_exact_across_content_versions(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp).resolve() / "state.sqlite"
            task_raw = "ordered-version-reducer"
            task_id = observability.task_ref(task_raw, "codex")
            memory_id = "a" * 64
            version_a = "1" * 64
            version_b = "2" * 64
            version_c = "3" * 64

            def version(content_sha256: str) -> dict[str, object]:
                return {
                    "memory_id": memory_id,
                    "content_sha256": content_sha256,
                    "policy_state": "expired",
                    "requires_live_verification": True,
                }

            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                conn.execute(
                    "INSERT INTO meta(key,value) VALUES('observability_enabled_at','2026-08-01T00:00:00+00:00')"
                )
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="task_seen", source="tool_observed", value="seen",
                )
                for content_sha256 in (version_a, version_b, version_c):
                    observability._insert_event(
                        conn, actor="codex", task_id=task_id,
                        event_type="source_opened", source="tool_observed", value="yes",
                        memory_versions=[version(content_sha256)],
                    )
                    observability._insert_event(
                        conn, actor="codex", task_id=task_id,
                        event_type="adoption_declared", source="agent_declared", value="adopted",
                        memory_versions=[version(content_sha256)],
                    )
                # A later no must undo A's earlier yes.
                for value in ("yes", "no"):
                    observability._insert_event(
                        conn, actor="codex", task_id=task_id,
                        event_type="live_verified", source="agent_declared", value=value,
                        memory_versions=[version(version_a)],
                    )
                # B is independent and ends verified.
                for value in ("no", "yes"):
                    observability._insert_event(
                        conn, actor="codex", task_id=task_id,
                        event_type="live_verified", source="agent_declared", value=value,
                        memory_versions=[version(version_b)],
                    )
                # A later exact reference-only declaration clears only C.
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="adoption_declared", source="agent_declared",
                    value="reference_only", memory_versions=[version(version_c)],
                )
                # A hashless non-adoption decision is allowed for a returned
                # candidate, but it cannot mutate an exact content-version
                # state.  The public declaration API separately proves that
                # the opaque ID was objectively returned in this task.
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="adoption_declared", source="agent_declared",
                    value="rejected", memory_ids=[memory_id],
                )
                # Re-adopt A and B to exercise stable last-write ordering.
                for content_sha256 in (version_a, version_b):
                    observability._insert_event(
                        conn, actor="codex", task_id=task_id,
                        event_type="adoption_declared", source="agent_declared", value="adopted",
                        memory_versions=[version(content_sha256)],
                    )
                conn.commit()
                rows = conn.execute(
                    "SELECT actor,task_id,event_type,source,value,memory_ids_json,memory_versions_json "
                    "FROM memory_use_events ORDER BY id"
                ).fetchall()
                reduced = observability.reduce_versioned_events(rows)
                report = observability.build_report(conn, since="2026-08-01")

            self.assertEqual(reduced[("codex", task_id, memory_id, version_a)]["live_verified"], "no")
            self.assertEqual(reduced[("codex", task_id, memory_id, version_b)]["live_verified"], "yes")
            self.assertEqual(reduced[("codex", task_id, memory_id, version_c)]["adoption"], "reference_only")
            self.assertEqual(
                report["cross_metrics"]["chain_health"]["adopted_stale_without_live_verification"],
                1,
            )
            state.chmod(0o600)
            with (
                mock.patch.object(observability, "STATE_DB", state),
                mock.patch.object(observability, "assert_runtime_ready", return_value={"ready": True}),
            ):
                self.assertEqual(
                    observability.adopted_stale_without_verification("codex", task_raw),
                    1,
                )

    def test_search_enums_and_storage_guards_reject_covert_text_channels(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp).resolve() / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                with self.assertRaisesRegex(ValueError, "search_source_unsupported"):
                    observability.record_search(
                        conn, query="q", rel_paths=[], sources=["https://private.example"],
                        duration_ms=1, search_status="success",
                    )
                with self.assertRaisesRegex(ValueError, "search_status_unsupported"):
                    observability.record_search(
                        conn, query="q", rel_paths=[], sources=["sqlite"],
                        duration_ms=1, search_status="private prose",
                    )
                memory_state.install_search_log_privacy_guards(conn)
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    memory_state.SEARCH_LOG_PRIVACY_REASON_CODE,
                ):
                    conn.execute(
                        "INSERT INTO memory_search_log(query,result_count,used_paths,sources,search_status,created_at) "
                        "VALUES('[redacted:0123456789ab]',0,'','none','success','now')"
                    )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    memory_state.SEARCH_LOG_CONTROL_REASON_CODE,
                ):
                    conn.execute(
                        "INSERT INTO memory_search_log(query,result_count,used_paths,sources,search_status,created_at) "
                        "VALUES('',0,'','https://private.example','success','now')"
                    )

    def test_application_and_database_guards_reject_raw_identifiers_and_json_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp).resolve() / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                with self.assertRaisesRegex(ValueError, "unsupported_actor"):
                    observability._insert_event(
                        conn, actor="private actor prose", task_id="a" * 64,
                        event_type="task_seen", source="tool_observed", value="seen",
                    )
                with self.assertRaisesRegex(ValueError, "task_id_must_be_sha256"):
                    observability._insert_event(
                        conn, actor="codex", task_id="raw-session-id",
                        event_type="task_seen", source="tool_observed", value="seen",
                    )
                with self.assertRaisesRegex(ValueError, "event_id_invalid"):
                    observability._insert_event(
                        conn, actor="codex", task_id="a" * 64,
                        event_type="task_seen", source="tool_observed", value="seen",
                        event_id="https://private.example/session",
                    )
                with self.assertRaisesRegex(ValueError, "result_count_invalid"):
                    observability._insert_event(
                        conn, actor="codex", task_id="a" * 64,
                        event_type="task_seen", source="tool_observed", value="seen",
                        result_count=-1,
                    )

                memory_state.install_search_log_privacy_guards(conn)
                timestamp = "2026-08-24T00:00:00+00:00"
                with mock.patch.dict(
                    os.environ,
                    {"AGENT_MEMORY_OBSERVABILITY_ENABLED": "false"},
                    clear=False,
                ):
                    observability.record_search(
                        conn,
                        query="not persisted",
                        rel_paths=[],
                        sources=["sqlite"],
                        duration_ms=1,
                        search_status="success",
                    )
                observability._insert_event(
                    conn, actor="codex", task_id="c" * 64,
                    event_type="task_seen", source="tool_observed", value="seen",
                )
                conn.execute(
                    "INSERT INTO memory_search_log(query,result_count,used_paths,sources,search_status,created_at) "
                    "VALUES('',0,'','none','success',?)",
                    (timestamp,),
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    memory_state.SEARCH_LOG_CONTROL_REASON_CODE,
                ):
                    conn.execute(
                        "UPDATE memory_search_log SET query_sha256='raw private question'"
                    )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    memory_state.SEARCH_LOG_CONTROL_REASON_CODE,
                ):
                    conn.execute(
                        "UPDATE memory_search_log SET returned_memory_ids_json='[\"https://private.example\"]'"
                    )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    memory_state.OBSERVABILITY_EVENT_CONTROL_REASON_CODE,
                ):
                    conn.execute(
                        """
                        INSERT INTO memory_use_events(
                          event_id,actor,task_id,runtime_version,event_type,source,
                          memory_ids_json,memory_versions_json,value,created_at
                        ) VALUES(?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            "event-private-body", "codex", "b" * 64, "test-runtime",
                            "task_seen", "tool_observed", '["https://private.example"]',
                            "[]", "seen", timestamp,
                        ),
                    )

    def test_report_flags_redacted_placeholders_and_invalid_search_enums(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp).resolve() / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                conn.execute(
                    "INSERT INTO meta(key,value) VALUES('observability_enabled_at','2026-08-01T00:00:00+00:00')"
                )
                conn.execute(
                    "INSERT INTO memory_search_log(query,result_count,used_paths,sources,search_status,created_at) "
                    "VALUES('[redacted:0123456789ab]',0,'','private-source','private-status',?)",
                    (observability.utc_now(),),
                )
                report = observability.build_report(conn, since="2026-08-01")
            shadow = report["cross_metrics"]["shadow_7d"]
            self.assertEqual(shadow["privacy_violation"], 1)
            self.assertEqual(shadow["invalid_source_rows"], 1)
            self.assertEqual(shadow["invalid_search_status_rows"], 1)
            self.assertNotIn("private-source", str(report))

    def test_stale_check_does_not_shift_policy_across_legacy_hashless_versions(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp).resolve() / "state.sqlite"
            task_raw = "mixed-version-task"
            task_id = observability.task_ref(task_raw, "codex")
            legacy_id = "1" * 64
            current_id = "2" * 64
            current_sha = "3" * 64
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                observability._insert_event(
                    conn,
                    actor="codex",
                    task_id=task_id,
                    event_type="opened_original",
                    source="tool_observed",
                    value="yes",
                    memory_versions=[
                        {
                            "memory_id": legacy_id,
                            "content_sha256": "",
                            "policy_state": "expired",
                            "requires_live_verification": True,
                        },
                        {
                            "memory_id": current_id,
                            "content_sha256": current_sha,
                            "policy_state": "current",
                            "requires_live_verification": False,
                        },
                    ],
                )
                observability._insert_event(
                    conn,
                    actor="codex",
                    task_id=task_id,
                    event_type="adoption_declared",
                    source="agent_declared",
                    value="adopted",
                    memory_versions=[{
                        "memory_id": current_id,
                        "content_sha256": current_sha,
                        "policy_state": "current",
                        "requires_live_verification": False,
                    }],
                )
                conn.commit()
            state.chmod(0o600)
            with (
                mock.patch.object(observability, "STATE_DB", state),
                mock.patch.object(observability, "assert_runtime_ready", return_value={"ready": True}),
            ):
                self.assertEqual(
                    observability.adopted_stale_without_verification("codex", task_raw),
                    0,
                )

    def test_adoption_uses_objective_source_opened_policy_and_rejects_unopened_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp).resolve() / "state.sqlite"
            task_raw = "objective-adoption-task"
            task_id = observability.task_ref(task_raw, "codex")
            memory_id = "a" * 64
            content_sha = "b" * 64
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                observability._insert_event(
                    conn,
                    actor="codex",
                    task_id=task_id,
                    event_type="source_opened",
                    source="tool_observed",
                    value="yes",
                    memory_versions=[{
                        "memory_id": memory_id,
                        "content_sha256": content_sha,
                        "policy_state": "expired",
                        "requires_live_verification": True,
                    }],
                )
                conn.commit()
            state.chmod(0o600)
            with (
                mock.patch.object(observability, "STATE_DB", state),
                mock.patch.object(observability, "assert_runtime_ready", return_value={"ready": True}),
                mock.patch.dict(os.environ, {"AGENT_MEMORY_OBSERVABILITY_ENABLED": "true"}),
            ):
                observability.record_declared_event(
                    actor="codex",
                    task_id=task_id,
                    event_type="adoption_declared",
                    source="agent_declared",
                    value="adopted",
                    memory_versions=[{
                        "memory_id": memory_id,
                        "content_sha256": content_sha,
                        "policy_state": "unknown",
                        "requires_live_verification": False,
                    }],
                )
                self.assertEqual(
                    observability.adopted_stale_without_verification("codex", task_raw),
                    1,
                )
                with self.assertRaisesRegex(ValueError, "declared_version_not_source_opened"):
                    observability.record_declared_event(
                        actor="codex",
                        task_id=task_id,
                        event_type="adoption_declared",
                        source="agent_declared",
                        value="adopted",
                        memory_versions=[{
                            "memory_id": "c" * 64,
                            "content_sha256": "d" * 64,
                            "policy_state": "current",
                            "requires_live_verification": False,
                        }],
                    )

    def test_additive_migration_is_idempotent_and_preserves_legacy_rows(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                conn.execute(
                    "INSERT INTO memory_search_log(query,result_count,created_at) VALUES (?,?,?)",
                    ("[redacted:legacy]", 2, "2026-08-01T00:00:00+00:00"),
                )
                observability.ensure_schema(conn)
                observability.ensure_schema(conn)
                conn.commit()
                row = conn.execute("SELECT * FROM memory_search_log").fetchone()
                version = conn.execute(
                    "SELECT value FROM meta WHERE key='memory_observability_schema_version'"
                ).fetchone()[0]
                tables = {
                    item[0] for item in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
            self.assertEqual(row["query"], "[redacted:legacy]")
            self.assertEqual(row["result_count"], 2)
            self.assertIsNone(row["actor"])
            self.assertIsNone(row["task_id"])
            self.assertEqual(version, observability.SCHEMA_VERSION)
            self.assertIn("memory_use_events", tables)

    def test_report_on_uninitialized_runtime_does_not_create_partial_database(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "missing-state.sqlite"
            stdout = io.StringIO()
            with (
                mock.patch.object(observability, "STATE_DB", state),
                mock.patch.object(
                    observability,
                    "assert_runtime_ready",
                    return_value={"ready": True},
                ),
                mock.patch.object(sys, "argv", ["observe", "--json", "report"]),
                contextlib.redirect_stdout(stdout),
            ):
                returncode = observability.main()
            payload = json.loads(stdout.getvalue())
        self.assertEqual(returncode, 2)
        self.assertEqual(payload["error"], "observability_not_initialized")
        self.assertFalse(state.exists())

    def test_schema_refuses_an_uninitialized_existing_database_without_partial_tables(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "blank.sqlite"
            with contextlib.closing(sqlite3.connect(state)) as conn:
                with self.assertRaisesRegex(sqlite3.OperationalError, "observability_requires_initialized"):
                    observability.ensure_schema(conn)
                tables = {
                    row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
        self.assertNotIn("memory_use_events", tables)

    def test_search_records_only_hashes_and_controlled_task_event(self) -> None:
        raw_query = "private question that must never be stored"
        raw_task = "private-session-4a57c8f2"
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn, mock.patch.dict(
                os.environ,
                {
                    "AGENT_MEMORY_OBSERVABILITY_ENABLED": "true",
                    "MEMORY_ACTOR": "codex",
                    "AGENT_MEMORY_TASK_ID": raw_task,
                },
                clear=False,
            ):
                observability.ensure_schema(conn)
                search_id = observability.record_search(
                    conn,
                    query=raw_query,
                    rel_paths=["项目/Alpha.md"],
                    sources=["sqlite", "zvec"],
                    duration_ms=17,
                    search_status="success",
                    required_live_verification_count=1,
                    metadata_gate_mode="shadow",
                    metadata_would_block_count=1,
                    metadata_reason_fingerprint="a" * 64,
                )
                conn.commit()
                search = conn.execute("SELECT * FROM memory_search_log").fetchone()
                events = conn.execute(
                    "SELECT event_type,source,value,task_id,memory_ids_json,required_live_verification_count "
                    "FROM memory_use_events ORDER BY id"
                ).fetchall()
            database_bytes = state.read_bytes()

        self.assertEqual(search["search_id"], search_id)
        self.assertEqual(search["actor"], "codex")
        self.assertEqual(len(search["task_id"]), 64)
        self.assertEqual(search["event_source"], "tool_observed")
        self.assertEqual(search["search_status"], "success")
        self.assertEqual(search["metadata_gate_mode"], "shadow")
        self.assertEqual(search["metadata_would_block_count"], 1)
        self.assertEqual(search["metadata_reason_fingerprint"], "a" * 64)
        self.assertNotIn(raw_query.encode(), database_bytes)
        self.assertNotIn(raw_task.encode(), database_bytes)
        self.assertEqual(
            [row["event_type"] for row in events],
            ["task_seen", "search_completed"],
        )
        self.assertEqual(events[1]["source"], "tool_observed")
        self.assertEqual(events[1]["required_live_verification_count"], 1)
        self.assertEqual(
            json.loads(events[1]["memory_ids_json"]),
            [observability.memory_ref("项目/Alpha.md")],
        )

    def test_benchmark_search_is_synthetic_and_never_enters_task_ledger(self) -> None:
        raw_query = "private benchmark query"
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn, mock.patch.dict(
                os.environ,
                {
                    "AGENT_MEMORY_OBSERVABILITY_ENABLED": "true",
                    "MEMORY_ACTOR": "codex",
                    "AGENT_MEMORY_TASK_ID": "real-codex-task",
                },
                clear=False,
            ):
                observability.ensure_schema(conn)
                observability.record_benchmark_search(
                    conn,
                    query=raw_query,
                    rel_paths=["工作流/benchmark.md"],
                    memory_ids=["a" * 64],
                    duration_ms=9,
                    search_status="success",
                    v1_result_fingerprint="b" * 64,
                    v2_result_fingerprint="c" * 64,
                    required_case_regression_count=0,
                    worker_status="reused",
                    worker_restart_count=0,
                )
                conn.commit()
                row = conn.execute(
                    "SELECT actor,task_id,sources,query,used_paths FROM memory_search_log"
                ).fetchone()
                event_count = int(
                    conn.execute("SELECT COUNT(*) FROM memory_use_events").fetchone()[0]
                )
                report = observability.build_report(conn, since="2026-01-01")
            database_bytes = state.read_bytes()

        self.assertEqual(row["actor"], "test")
        self.assertRegex(str(row["task_id"]), r"^[0-9a-f]{64}$")
        self.assertEqual(row["sources"], "hybrid_benchmark")
        self.assertEqual(row["query"], "")
        self.assertEqual(row["used_paths"], "")
        self.assertEqual(event_count, 0)
        self.assertEqual(report["tool_observed"]["task_denominator"], 0)
        self.assertEqual(report["cross_metrics"]["shadow_7d"]["missing_denominator"], 0)
        self.assertNotIn(raw_query.encode(), database_bytes)

    def test_search_rejects_inconsistent_metadata_gate_projection(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                base = {
                    "query": "redacted",
                    "rel_paths": [],
                    "sources": ["sqlite"],
                    "duration_ms": 1,
                    "search_status": "success",
                }
                with self.assertRaisesRegex(ValueError, "metadata_gate_mode_unsupported"):
                    observability.record_search(conn, **base, metadata_gate_mode="disabled")
                with self.assertRaisesRegex(ValueError, "metadata_would_block_count_invalid"):
                    observability.record_search(conn, **base, metadata_would_block_count=-1)
                with self.assertRaisesRegex(ValueError, "metadata_reason_fingerprint_required"):
                    observability.record_search(conn, **base, metadata_would_block_count=1)
                with self.assertRaisesRegex(ValueError, "metadata_reason_fingerprint_without_block"):
                    observability.record_search(
                        conn,
                        **base,
                        metadata_would_block_count=0,
                        metadata_reason_fingerprint="b" * 64,
                    )

    def test_disabled_mode_keeps_legacy_search_log_without_task_event(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn, mock.patch.dict(
                os.environ,
                {
                    "AGENT_MEMORY_OBSERVABILITY_ENABLED": "false",
                    "MEMORY_ACTOR": "codex",
                    "AGENT_MEMORY_TASK_ID": "must-not-be-used",
                },
                clear=False,
            ):
                observability.ensure_schema(conn)
                observability.record_search(
                    conn,
                    query="still redacted",
                    rel_paths=[],
                    sources=["sqlite"],
                    duration_ms=1,
                    search_status="success",
                )
                conn.commit()
                search = conn.execute("SELECT actor,task_id FROM memory_search_log").fetchone()
                event_count = conn.execute("SELECT COUNT(*) FROM memory_use_events").fetchone()[0]
        self.assertIsNone(search["actor"])
        self.assertIsNone(search["task_id"])
        self.assertEqual(event_count, 0)

    def test_declared_api_cannot_forge_tool_observation_or_free_text(self) -> None:
        with self.assertRaisesRegex(ValueError, "tool_observed_cannot_be_declared"):
            observability.record_declared_event(
                actor="codex",
                task_id="a" * 64,
                event_type="search",
                source="tool_observed",
                value="success",
            )
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                with self.assertRaisesRegex(ValueError, "unsupported_reason_code"):
                    observability._insert_event(
                        conn,
                        actor="codex",
                        task_id="a" * 64,
                        event_type="adoption",
                        source="agent_declared",
                        value="adopted",
                        reason_code="arbitrary private prose",
                    )
                with self.assertRaisesRegex(ValueError, "memory_id_required:adoption"):
                    observability._insert_event(
                        conn,
                        actor="codex",
                        task_id="a" * 64,
                        event_type="adoption",
                        source="agent_declared",
                        value="adopted",
                    )

    def test_reference_or_rejection_requires_observed_candidate_and_sanitizes_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            task_id = "1" * 64
            memory_id = "2" * 64
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                observability._insert_event(
                    conn,
                    actor="codex",
                    task_id=task_id,
                    event_type="task_seen",
                    source="tool_observed",
                    value="seen",
                )
                observability._insert_event(
                    conn,
                    actor="codex",
                    task_id=task_id,
                    event_type="search_completed",
                    source="tool_observed",
                    value="success",
                    memory_ids=[memory_id],
                )
                conn.commit()
            state.chmod(0o600)
            with (
                mock.patch.object(observability, "STATE_DB", state),
                mock.patch.object(observability, "assert_runtime_ready", return_value={"ready": True}),
                mock.patch.dict(os.environ, {"AGENT_MEMORY_OBSERVABILITY_ENABLED": "true"}),
            ):
                reference_id = observability.record_declared_event(
                    actor="codex",
                    task_id=task_id,
                    event_type="adoption_declared",
                    source="agent_declared",
                    value="reference_only",
                    memory_versions=[{
                        "memory_id": memory_id,
                        "content_sha256": "3" * 64,
                        "policy_state": "current",
                        "requires_live_verification": False,
                    }],
                )
                event_id = observability.record_declared_event(
                    actor="codex",
                    task_id=task_id,
                    event_type="adoption_declared",
                    source="agent_declared",
                    value="rejected",
                    memory_ids=[memory_id],
                )
                with self.assertRaisesRegex(ValueError, "declared_candidate_not_observed"):
                    observability.record_declared_event(
                        actor="codex",
                        task_id=task_id,
                        event_type="adoption_declared",
                        source="agent_declared",
                        value="rejected",
                        memory_ids=["4" * 64],
                    )
            with sqlite3.connect(state) as conn:
                rows = conn.execute(
                    "SELECT memory_ids_json,memory_versions_json FROM memory_use_events "
                    "WHERE event_id IN (?,?) ORDER BY id",
                    (reference_id, event_id),
                ).fetchall()
            self.assertEqual([json.loads(row[0]) for row in rows], [[memory_id], [memory_id]])
            reference_version = json.loads(rows[0][1])[0]
            self.assertEqual(reference_version["content_sha256"], "3" * 64)
            self.assertEqual(reference_version["policy_state"], "unknown")
            self.assertTrue(reference_version["requires_live_verification"])
            self.assertEqual(json.loads(rows[1][1]), [])

    def test_completed_tasks_require_disposition_for_every_returned_or_opened_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                conn.execute(
                    "UPDATE meta SET value='2026-01-01T00:00:00+00:00' "
                    "WHERE key='disposition_tracking_enabled_at'"
                )
                returned_a, returned_b, opened, resolved = (
                    "1" * 64,
                    "2" * 64,
                    "3" * 64,
                    "4" * 64,
                )
                tasks = [f"{index:x}" * 64 for index in range(10, 14)]

                for task_id in tasks:
                    observability._insert_event(
                        conn, actor="codex", task_id=task_id,
                        event_type="task_seen", source="tool_observed", value="seen",
                    )

                observability._insert_event(
                    conn, actor="codex", task_id=tasks[0],
                    event_type="search_completed", source="tool_observed", value="success",
                    memory_ids=[returned_a, returned_b],
                )
                observability._insert_event(
                    conn, actor="codex", task_id=tasks[0],
                    event_type="adoption_declared", source="agent_declared",
                    value="rejected", memory_ids=[returned_a],
                )
                observability._insert_event(
                    conn, actor="codex", task_id=tasks[0],
                    event_type="task_completed", source="tool_observed", value="success",
                )

                observability._insert_event(
                    conn, actor="codex", task_id=tasks[1],
                    event_type="source_opened", source="tool_observed", value="yes",
                    memory_versions=[{
                        "memory_id": opened,
                        "content_sha256": "5" * 64,
                        "policy_state": "current",
                        "requires_live_verification": False,
                    }],
                )
                observability._insert_event(
                    conn, actor="codex", task_id=tasks[1],
                    event_type="task_completed", source="tool_observed", value="success",
                )

                observability._insert_event(
                    conn, actor="codex", task_id=tasks[2],
                    event_type="search_completed", source="tool_observed", value="success",
                    memory_ids=[resolved],
                )
                observability._insert_event(
                    conn, actor="codex", task_id=tasks[2],
                    event_type="adoption_declared", source="agent_declared",
                    value="reference_only", memory_ids=[resolved],
                )
                observability._insert_event(
                    conn, actor="codex", task_id=tasks[2],
                    event_type="task_completed", source="tool_observed", value="success",
                )

                # An in-flight task is not declared incomplete yet.
                observability._insert_event(
                    conn, actor="codex", task_id=tasks[3],
                    event_type="search_completed", source="tool_observed", value="success",
                    memory_ids=["6" * 64],
                )
                conn.commit()
                report = observability.build_report(conn, since="2026-01-01")

            chain = report["cross_metrics"]["chain_health"]
            self.assertEqual(chain["returned_without_disposition"], 1)
            self.assertEqual(chain["opened_without_disposition"], 1)
            self.assertEqual(chain["tasks_with_missing_disposition"], 2)

    def test_disposition_and_completion_do_not_carry_into_a_later_task_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                conn.execute(
                    "UPDATE meta SET value='2026-01-01T00:00:00+00:00' "
                    "WHERE key='disposition_tracking_enabled_at'"
                )
                task_id = "a" * 64
                memory_id = "b" * 64
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="task_seen", source="tool_observed", value="seen",
                )
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="search_completed", source="tool_observed", value="success",
                    memory_ids=[memory_id],
                )
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="adoption_declared", source="agent_declared",
                    value="reference_only", memory_ids=[memory_id],
                )
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="task_completed", source="tool_observed", value="success",
                )
                resolved = observability.build_report(conn, since="2026-01-01")

                # A later candidate return starts a fresh cycle. The old
                # completion must not judge it and the old disposition must
                # not cover it.
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="search_completed", source="tool_observed", value="success",
                    memory_ids=[memory_id],
                )
                in_flight = observability.build_report(conn, since="2026-01-01")
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="task_completed", source="tool_observed", value="failure",
                )
                failed_cycle = observability.build_report(conn, since="2026-01-01")
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="task_completed", source="tool_observed", value="success",
                )
                missing = observability.build_report(conn, since="2026-01-01")
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="adoption_declared", source="agent_declared",
                    value="rejected", memory_ids=[memory_id],
                )
                repaired = observability.build_report(conn, since="2026-01-01")

            def returned_gap(report: dict[str, object]) -> int:
                return int(
                    report["cross_metrics"]["chain_health"]["returned_without_disposition"]  # type: ignore[index]
                )

            self.assertEqual(returned_gap(resolved), 0)
            self.assertEqual(returned_gap(in_flight), 0)
            self.assertEqual(returned_gap(failed_cycle), 0)
            self.assertEqual(returned_gap(missing), 1)
            self.assertEqual(returned_gap(repaired), 0)

    def test_declared_success_is_not_a_stop_completion_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                conn.execute(
                    "UPDATE meta SET value='2026-01-01T00:00:00+00:00' "
                    "WHERE key='disposition_tracking_enabled_at'"
                )
                task_id = "d" * 64
                memory_id = "e" * 64
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="task_seen", source="tool_observed", value="seen",
                )
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="search_completed", source="tool_observed", value="success",
                    memory_ids=[memory_id],
                )
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="task_completed", source="agent_declared", value="success",
                )
                declared = observability.build_report(conn, since="2026-01-01")
                observability._insert_event(
                    conn, actor="codex", task_id=task_id,
                    event_type="task_completed", source="tool_observed", value="success",
                )
                stopped = observability.build_report(conn, since="2026-01-01")

        self.assertEqual(
            declared["cross_metrics"]["chain_health"]["returned_without_disposition"],
            0,
        )
        self.assertEqual(
            stopped["cross_metrics"]["chain_health"]["returned_without_disposition"],
            1,
        )

    def test_task_completion_is_idempotent_per_event_high_watermark(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                conn.commit()
            state.chmod(0o600)
            with (
                mock.patch.object(observability, "STATE_DB", state),
                mock.patch.object(observability, "assert_runtime_ready", return_value={"ready": True}),
                mock.patch.dict(os.environ, {"AGENT_MEMORY_OBSERVABILITY_ENABLED": "true"}),
            ):
                first = observability.record_task_completed("same-host-session", "codex")
                second = observability.record_task_completed("same-host-session", "codex")

                with observability.connect() as conn:
                    task_id = observability.task_ref("same-host-session", "codex")
                    observability._insert_event(
                        conn, actor="codex", task_id=task_id,
                        event_type="search_completed", source="tool_observed", value="success",
                        memory_ids=["c" * 64],
                    )
                third = observability.record_task_completed("same-host-session", "codex")

            self.assertTrue(first)
            self.assertTrue(second)
            self.assertEqual(first, second)
            self.assertNotEqual(first, third)
            with sqlite3.connect(state) as conn:
                count = conn.execute(
                    "SELECT COUNT(*) FROM memory_use_events WHERE event_type='task_completed'"
                ).fetchone()[0]
            self.assertEqual(count, 2)

    def test_stale_adoption_check_requires_task_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                conn.commit()
            state.chmod(0o600)
            with (
                mock.patch.object(observability, "STATE_DB", state),
                mock.patch.object(observability, "assert_runtime_ready", return_value={"ready": True}),
            ):
                with self.assertRaisesRegex(
                    observability.ObservabilityLedgerUnavailable,
                    "OBSERVABILITY_TASK_ID_UNAVAILABLE",
                ):
                    observability.adopted_stale_without_verification("codex", "")

    def test_report_separates_objective_self_human_and_model_sources(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn, mock.patch.dict(
                os.environ,
                {"AGENT_MEMORY_OBSERVABILITY_ENABLED": "true"},
                clear=False,
            ):
                observability.ensure_schema(conn)
                conn.execute(
                    "INSERT INTO meta(key,value) VALUES('observability_enabled_at','2026-08-01T00:00:00+00:00')"
                )
                task_a, task_b = "a" * 64, "b" * 64
                observability._insert_event(
                    conn, actor="codex", task_id=task_a, event_type="task_seen",
                    source="tool_observed", value="seen",
                )
                observability._insert_event(
                    conn, actor="codex", task_id=task_a, event_type="search",
                    source="tool_observed", value="success",
                )
                observability._insert_event(
                    conn, actor="codex", task_id=task_b, event_type="task_seen",
                    source="tool_observed", value="seen",
                )
                observability._insert_event(
                    conn, actor="codex", task_id=task_a, event_type="applicability_self",
                    source="agent_declared", value="yes", task_class="existing_project",
                )
                observability._insert_event(
                    conn, actor="codex", task_id=task_a, event_type="applicability_independent",
                    source="human_declared", value="yes", task_class="existing_project",
                )
                observability._insert_event(
                    conn, actor="codex", task_id=task_a, event_type="applicability_independent",
                    source="human_declared", value="no", task_class="existing_project",
                )
                observability._insert_event(
                    conn, actor="codex", task_id=task_b, event_type="applicability_independent",
                    source="independent_model", value="no", task_class="one_off",
                )
                conn.commit()
                report = observability.build_report(conn, since="2026-08-01")

        self.assertEqual(report["tool_observed"]["task_denominator"], 2)
        self.assertEqual(report["tool_observed"]["searched_tasks"], 1)
        self.assertEqual(report["tool_observed"]["not_searched_tasks"], 1)
        self.assertEqual(report["applicability"]["independent_task_denominator"], 2)
        self.assertEqual(report["applicability"]["human"], {"no": 1})
        self.assertEqual(report["applicability"]["independent_model"], {"no": 1})
        self.assertEqual(report["applicability"]["agent_self"], {"yes": 1})
        self.assertEqual(
            report["applicability"]["independent_by_task_class"],
            {"existing_project": {"no": 1}, "one_off": {"no": 1}},
        )
        self.assertEqual(
            report["applicability"]["self_independent_agreement"]["human_declared"],
            {"compared": 1, "agreed": 0, "rate": 0.0},
        )
        self.assertFalse(report["interpretation"]["sources_combined"])

    def test_report_cross_metrics_use_explicit_source_specific_denominators(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                conn.execute(
                    "INSERT INTO meta(key,value) VALUES('observability_enabled_at','2026-08-01T00:00:00+00:00')"
                )
                tasks = [f"{index:x}" * 64 for index in range(1, 8)]
                task_1, task_2, task_3, task_4, task_5, task_6, task_7 = tasks
                memory_id = "f" * 64

                for task_id in (task_1, task_2, task_3, task_4, task_6):
                    observability._insert_event(
                        conn,
                        actor="codex",
                        task_id=task_id,
                        event_type="task_seen",
                        source="tool_observed",
                        value="seen",
                    )
                for task_id, required_count in (
                    (task_1, 2),
                    (task_3, 1),
                    (task_6, 0),
                    (task_7, 3),
                ):
                    observability._insert_event(
                        conn,
                        actor="codex",
                        task_id=task_id,
                        event_type="search",
                        source="tool_observed",
                        value="success",
                        required_live_verification_count=required_count,
                    )
                for task_id in (task_1, task_4):
                    observability._insert_event(
                        conn,
                        actor="codex",
                        task_id=task_id,
                        event_type="opened_original",
                        source="tool_observed",
                        value="yes",
                        memory_ids=[memory_id],
                    )

                for task_id, value in (
                    (task_1, "yes"),
                    (task_2, "yes"),
                    (task_3, "yes"),
                    (task_4, "yes"),
                    (task_5, "no"),
                ):
                    observability._insert_event(
                        conn,
                        actor="codex",
                        task_id=task_id,
                        event_type="applicability_independent",
                        source="human_declared",
                        value=value,
                        task_class="existing_project",
                    )
                for task_id, value in (
                    (task_1, "yes"),
                    (task_2, "no"),
                    (task_3, "yes"),
                    (task_5, "yes"),
                ):
                    observability._insert_event(
                        conn,
                        actor="codex",
                        task_id=task_id,
                        event_type="applicability_independent",
                        source="independent_model",
                        value=value,
                        task_class="existing_project",
                    )

                for source, task_id, value in (
                    ("agent_declared", task_1, "yes"),
                    ("agent_declared", task_3, "no"),
                    ("human_declared", task_3, "yes"),
                    ("independent_model", task_1, "no"),
                    ("independent_model", task_7, "yes"),
                ):
                    observability._insert_event(
                        conn,
                        actor="codex",
                        task_id=task_id,
                        event_type="live_verified",
                        source=source,
                        value=value,
                        memory_versions=[{
                            "memory_id": memory_id,
                            "content_sha256": task_id,
                            "policy_state": "current",
                            "requires_live_verification": True,
                        }],
                    )
                conn.commit()
                report = observability.build_report(conn, since="2026-08-01")

        applicable = report["cross_metrics"]["applicable_yes"]
        self.assertEqual(
            applicable["by_source"]["human_declared"],
            {
                "denominator": 4,
                "not_searched": 2,
                "not_opened": 2,
                "neither_search_nor_open": 1,
                "searched_not_opened": 1,
                "direct_open_without_search": 1,
                "rate": {
                    "not_searched": 0.5,
                    "not_opened": 0.5,
                    "neither_search_nor_open": 0.25,
                    "searched_not_opened": 0.25,
                    "direct_open_without_search": 0.25,
                },
            },
        )
        self.assertEqual(
            applicable["by_source"]["independent_model"],
            {
                "denominator": 2,
                "not_searched": 0,
                "not_opened": 1,
                "neither_search_nor_open": 0,
                "searched_not_opened": 1,
                "direct_open_without_search": 0,
                "rate": {
                    "not_searched": 0.0,
                    "not_opened": 0.5,
                    "neither_search_nor_open": 0.0,
                    "searched_not_opened": 0.5,
                    "direct_open_without_search": 0.0,
                },
            },
        )
        self.assertEqual(
            applicable["labels_without_task_seen"],
            {
                "human_declared": {"total": 1, "by_value": {"no": 1}},
                "independent_model": {"total": 1, "by_value": {"yes": 1}},
            },
        )
        self.assertEqual(
            applicable["source_conflicts"],
            {"both_labeled": 4, "conflicting": 2, "with_task_seen": 1, "without_task_seen": 1},
        )

        verification = report["cross_metrics"]["time_sensitive_live_verification"]
        self.assertEqual(verification["denominator"], 3)
        for source in ("agent_declared", "human_declared", "independent_model"):
            self.assertEqual(
                verification["by_source"][source],
                {
                    "yes_verification": 1,
                    "no_yes_event": 2,
                    "yes_verification_rate": 1 / 3,
                    "no_yes_event_rate": 2 / 3,
                },
            )
        self.assertEqual(verification["no_yes_event_meaning"], "unknown_or_not_verified")
        self.assertNotIn(task_1, str(report["cross_metrics"]))

    def test_task_seen_is_idempotent_and_best_effort(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                conn.commit()
            os.chmod(state, 0o600)
            with (
                mock.patch.object(observability, "STATE_DB", state),
                mock.patch.object(
                    observability,
                    "assert_runtime_ready",
                    return_value={"ready": True},
                ),
                mock.patch.dict(
                    os.environ,
                    {"AGENT_MEMORY_OBSERVABILITY_ENABLED": "true"},
                    clear=False,
                ),
            ):
                first = observability.record_task_seen("same-private-task", "codex")
                second = observability.record_task_seen("same-private-task", "codex")
                with mock.patch.object(
                    observability,
                    "utc_now",
                    return_value="2026-09-10T00:00:00+00:00",
                ):
                    later = observability.record_task_seen("same-private-task", "codex")
            with contextlib.closing(sqlite3.connect(state)) as conn:
                count = conn.execute(
                    "SELECT COUNT(*) FROM memory_use_events WHERE event_type='task_seen'"
                ).fetchone()[0]
        self.assertEqual(first, second)
        self.assertEqual(first, later)
        self.assertEqual(count, 1)

    def test_independent_label_requires_observed_task_and_labeler_reference(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(legacy_database(state)) as conn:
                observability.ensure_schema(conn)
                observed_task = "a" * 64
                observability._insert_event(
                    conn,
                    actor="codex",
                    task_id=observed_task,
                    event_type="task_seen",
                    source="tool_observed",
                    value="seen",
                )
                conn.commit()
            os.chmod(state, 0o600)
            with (
                mock.patch.object(observability, "STATE_DB", state),
                mock.patch.object(
                    observability,
                    "assert_runtime_ready",
                    return_value={"ready": True},
                ),
                mock.patch.dict(
                    os.environ,
                    {"AGENT_MEMORY_OBSERVABILITY_ENABLED": "true"},
                    clear=False,
                ),
            ):
                with self.assertRaisesRegex(ValueError, "labeler_ref_required"):
                    observability.record_declared_event(
                        actor="codex",
                        task_id=observed_task,
                        event_type="applicability_independent",
                        source="independent_model",
                        value="yes",
                    )
                with self.assertRaisesRegex(ValueError, "labeled_task_not_observed"):
                    observability.record_declared_event(
                        actor="codex",
                        task_id="b" * 64,
                        event_type="applicability_independent",
                        source="independent_model",
                        value="yes",
                        labeler_ref="review-run-1",
                    )
                event_id = observability.record_declared_event(
                    actor="codex",
                    task_id=observed_task,
                    event_type="applicability_independent",
                    source="independent_model",
                    value="yes",
                    labeler_ref="review-run-1",
                )
        self.assertTrue(event_id)


if __name__ == "__main__":
    unittest.main()
