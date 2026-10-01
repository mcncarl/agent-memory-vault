from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
import subprocess
import sys
import sqlite3
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_search as search
import agent_memory_index as memory_index
from tests.state_fixture import initialize_full_state


def args(**overrides: object) -> Namespace:
    values: dict[str, object] = {
        "agent_scope": "",
        "track": "",
        "memory_type": "",
        "user_id": "",
        "agent_id": "",
        "app_id": "",
        "session_id": "",
        "project_id": "",
        "current_project": "",
        "cross_project": False,
        "status": "",
        "include_inactive": False,
        "has_open_loop": False,
        "include_supporting": False,
        "as_of": "",
        "no_log": False,
    }
    values.update(overrides)
    return Namespace(**values)


class SearchBoundaryTests(unittest.TestCase):
    def test_generated_routing_index_is_supporting_only_by_default(self) -> None:
        result = search.SearchResult(
            path="/vault/INDEX.md",
            rel_path="INDEX.md",
            status="active",
            memory_type="routing",
        )
        self.assertFalse(search.result_matches_filters(result, args()))
        self.assertTrue(
            search.result_matches_filters(result, args(include_supporting=True))
        )
        self.assertTrue(
            search.result_matches_filters(result, args(memory_type="routing"))
        )

    def test_runtime_actor_forces_scope_and_rejects_conflicting_cli_scope(self) -> None:
        shared = search.SearchResult(
            path="/vault/shared.md",
            rel_path="工作流/shared.md",
            status="active",
            memory_type="workflow",
            agent_scope="shared",
        )
        codex = search.SearchResult(
            path="/vault/codex.md",
            rel_path="工作流/codex.md",
            status="active",
            memory_type="workflow",
            agent_scope="codex",
        )
        claude = search.SearchResult(
            path="/vault/claude.md",
            rel_path="工作流/claude.md",
            status="active",
            memory_type="workflow",
            agent_scope="claude",
        )
        namespace = args(
            query="scopeprobe",
            limit=10,
            ranking_version="hybrid-v1",
            semantic_mode="off",
            no_zvec=True,
            force_rg=False,
            no_log=True,
        )
        with (
            mock.patch.dict(os.environ, {"MEMORY_ACTOR": "codex"}),
            mock.patch.object(search, "index_projection_health", return_value={"status": "ok"}),
            mock.patch.object(
                search,
                "legacy_sqlite_search",
                return_value=([shared, codex, claude], []),
            ),
        ):
            rows, _warnings, failed = search.run_search(namespace)
        self.assertFalse(failed)
        self.assertEqual(namespace.agent_scope, "codex")
        self.assertEqual(
            {row.rel_path for row in rows},
            {"工作流/shared.md", "工作流/codex.md"},
        )

        conflict = args(agent_scope="claude")
        with mock.patch.dict(os.environ, {"MEMORY_ACTOR": "codex"}):
            with self.assertRaises(search.SearchProtocolError) as caught:
                search.enforce_runtime_actor_scope(conflict)
        self.assertEqual(caught.exception.reason_code, search.SEARCH_ACTOR_SCOPE_CONFLICT)

    def test_raw_ailu_search_and_actor_conflict_fail_before_query_disclosure(self) -> None:
        namespace = args(
            query="private-query-must-not-leak",
            json=True,
            redact_legacy_logs=False,
            agent_scope="claude",
        )
        output = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"MEMORY_ACTOR": "codex"}),
            mock.patch.object(search, "parse_args", return_value=namespace),
            mock.patch.object(search, "assert_runtime_ready", return_value={"ready": True}),
            mock.patch.object(search, "run_search") as backend,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(search.main(), 2)
        backend.assert_not_called()
        serialized = output.getvalue()
        self.assertNotIn("private-query", serialized)
        self.assertEqual(
            json.loads(serialized)["reason_code"],
            search.SEARCH_ACTOR_SCOPE_CONFLICT,
        )

        raw_ailu = args(agent_scope="")
        with mock.patch.dict(os.environ, {"MEMORY_ACTOR": "ailu"}):
            with self.assertRaises(search.SearchProtocolError) as caught:
                search.enforce_runtime_actor_scope(raw_ailu)
        self.assertEqual(caught.exception.reason_code, search.AILU_SEARCH_DISABLED)

    def test_hybrid_v2_fuses_backends_by_stable_memory_id(self) -> None:
        memory_id = "a" * 64
        lexical = search.SearchResult(
            path="/vault/new.md",
            rel_path="工作流/new.md",
            status="active",
            memory_id_value=memory_id,
            memory_id_source_value="frontmatter",
            sources={"unicode_fts"},
            score=0.2,
        )
        stale_vector = search.SearchResult(
            path="/vault/old.md",
            rel_path="工作流/old.md",
            status="active",
            memory_id_value=memory_id,
            memory_id_source_value="frontmatter",
            sources={"zvec"},
            score=0.4,
        )
        rows = search.merge_results([[lexical], [stale_vector]], search.RANKING_VERSION)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].memory_id, memory_id)
        self.assertEqual(rows[0].rel_path, "工作流/new.md")
        self.assertEqual(rows[0].sources, {"unicode_fts", "zvec"})
        self.assertAlmostEqual(rows[0].score, 0.6)

    def test_shadow_returns_only_checkpoint_lane_and_records_v2_order(self) -> None:
        first_id, second_id = "1" * 64, "2" * 64
        checkpoint = [
            search.SearchResult(
                path="/vault/first.md", rel_path="工作流/first.md",
                status="active", memory_type="workflow", memory_id_value=first_id,
                sources={"sqlite"}, legacy_score=2.0,
            ),
            search.SearchResult(
                path="/vault/second.md", rel_path="工作流/second.md",
                status="active", memory_type="workflow", memory_id_value=second_id,
                sources={"sqlite"}, legacy_score=1.0,
            ),
        ]
        v2 = [
            search.SearchResult(
                path="/vault/second.md", rel_path="工作流/second.md",
                status="active", memory_type="workflow", memory_id_value=second_id,
                sources={"unicode_fts"}, score=0.2,
            ),
            search.SearchResult(
                path="/vault/first.md", rel_path="工作流/first.md",
                status="active", memory_type="workflow", memory_id_value=first_id,
                sources={"unicode_fts"}, score=0.1,
            ),
        ]
        namespace = args(
            query="fixture",
            limit=2,
            ranking_version="hybrid-v2-shadow",
            semantic_mode="off",
            no_zvec=True,
            force_rg=False,
            no_log=True,
        )
        with (
            mock.patch.object(search, "index_projection_health", return_value={"status": "ok"}),
            mock.patch.object(search, "legacy_sqlite_search", return_value=(checkpoint, [])),
            mock.patch.object(search, "sqlite_search", return_value=(v2, [])),
        ):
            rows, _warnings, failed = search.run_search(namespace)
        self.assertFalse(failed)
        self.assertEqual([row.memory_id for row in rows], [first_id, second_id])
        self.assertEqual(namespace._v1_result_memory_ids, [first_id, second_id])
        self.assertEqual(namespace._shadow_result_memory_ids, [second_id, first_id])
        self.assertTrue(all(row.sources == {"sqlite"} for row in rows))

    def test_checkpoint_fixed_corpus_has_golden_order(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            vault = Path(raw_tmp).resolve()
            workflow = vault / "工作流"
            workflow.mkdir()
            corpus = (
                ("自动归档.md", "自动归档", "自动归档 对话结束 记忆收尾"),
                ("body-only.md", "普通流程", "自动归档"),
                ("unrelated.md", "普通参考", "其他内容"),
            )
            conn = sqlite3.connect(":memory:")
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
            with mock.patch.object(memory_index, "VAULT_ROOT", vault):
                for index, (name, title, body) in enumerate(corpus, 1):
                    target = workflow / name
                    target.write_text(
                        "---\nmemory_type: workflow\ntrack: workflow\n"
                        "status: active\nagent_scope: shared\n---\n"
                        f"# {title}\n\n{body}\n",
                        encoding="utf-8",
                    )
                    doc, _ = memory_index.load_doc(
                        target, f"2026-08-25T00:00:0{index}+00:00"
                    )
                    memory_index.upsert_doc(conn, doc)
                    memory_index.insert_fts(conn, doc)
            rows = search.readonly_checkpoint_search(conn, "自动归档", 5)
            conn.close()
        self.assertEqual(
            [str(row["rel_path"]) for row in rows],
            ["工作流/自动归档.md", "工作流/body-only.md"],
        )

    def test_fts_match_error_is_a_failed_backend_not_an_empty_success(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state_db = Path(raw_tmp) / "state.sqlite"
            with contextlib.closing(sqlite3.connect(state_db)) as conn:
                conn.row_factory = sqlite3.Row
                memory_index.init_db(conn)
                with (
                    mock.patch.object(search, "STATE_DB", state_db),
                    mock.patch.object(search, "connect", return_value=conn),
                    mock.patch.object(memory_index, "fts_query", return_value='"unterminated'),
                ):
                    namespace = args(query="fixture", limit=5)
                    rows, warnings = search.sqlite_search(namespace)
        self.assertEqual(rows, [])
        self.assertEqual(namespace._unicode_fts_status, "failed")
        self.assertIn("unicode_fts search failed", " ".join(warnings))

    def test_shadow_log_persists_only_fingerprints_and_controlled_worker_state(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        memory_index.init_db(conn)
        first = "1" * 64
        second = "2" * 64
        row = search.SearchResult(
            path="/vault/工作流/example.md",
            rel_path="工作流/example.md",
            status="active",
            memory_id_value=second,
            memory_id_source_value="frontmatter",
        )
        with mock.patch.object(search, "connect", return_value=conn):
            search.log_search(
                "private query must not be stored",
                [row],
                12,
                "success",
                ranking_mode="hybrid-v2-shadow",
                v1_result_memory_ids=[first],
                v2_result_memory_ids=[second],
                worker_status="reused",
                worker_restart_count=0,
            )
        stored = conn.execute(
            "SELECT query,used_paths,ranking_mode,v1_result_fingerprint,"
            "v2_result_fingerprint,worker_status,worker_restart_count,returned_memory_ids_json "
            "FROM memory_search_log"
        ).fetchone()
        self.assertEqual(stored["query"], "")
        self.assertEqual(stored["used_paths"], "")
        self.assertEqual(stored["ranking_mode"], "shadow")
        self.assertEqual(
            stored["v1_result_fingerprint"],
            __import__("hashlib").sha256(first.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(
            stored["v2_result_fingerprint"],
            __import__("hashlib").sha256(second.encode("utf-8")).hexdigest(),
        )
        self.assertEqual((stored["worker_status"], stored["worker_restart_count"]), ("reused", 0))
        self.assertEqual(json.loads(stored["returned_memory_ids_json"]), [second])
        conn.close()

    def test_redaction_ignores_new_empty_query_rows(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        memory_index.init_db(conn)
        conn.execute(
            "INSERT INTO memory_search_log(query,result_count,created_at) VALUES ('',0,'now')"
        )
        conn.execute(
            "INSERT INTO memory_search_log(query,result_count,created_at) VALUES ('legacy private',0,'then')"
        )
        conn.commit()
        with mock.patch.object(search, "connect", return_value=conn):
            payload = search.redact_legacy_search_logs()
        self.assertEqual(payload, {"redacted": 1, "remaining_raw": 0})
        queries = [str(row[0]) for row in conn.execute("SELECT query FROM memory_search_log ORDER BY id")]
        self.assertEqual(queries[0], "")
        self.assertTrue(queries[1].startswith("[redacted:"))
        conn.close()

    def test_search_never_authorizes_before_canonical_read(self) -> None:
        result = search.SearchResult(
            path="/vault/工作流/current.md",
            rel_path="工作流/current.md",
            status="active",
            project_id="global",
            verified_at_source="structural",
            fact_status="not_fact",
        )
        search.annotate_result_policy(result, args())
        self.assertFalse(result.can_authorize_action)
        self.assertTrue(result.canonical_read_required)
        self.assertTrue(result.to_dict()["canonical_read_required"])
        result.scope_status = "project_context_unknown"
        result.project_id = "other-project"
        search.annotate_result_policy(result, args())
        self.assertFalse(result.can_authorize_action)

    def test_non_today_as_of_is_always_historical_analogy(self) -> None:
        result = search.SearchResult(
            path="/vault/工作流/current.md",
            rel_path="工作流/current.md",
            memory_type="workflow",
            track="workflow",
            status="active",
            project_id="global",
            verified_at_source="structural",
            fact_status="not_fact",
        )
        historical_date = (dt.date.today() - dt.timedelta(days=1)).isoformat()
        search.annotate_result_policy(result, args(as_of=historical_date))
        self.assertEqual(result.as_of_status, "historical")
        self.assertTrue(result.analogy_only)
        self.assertTrue(result.requires_live_verification)
        self.assertFalse(result.legacy_authorizable)
        self.assertFalse(result.can_authorize_action)
        self.assertIn("historical_as_of_reference_only", result.policy_warnings)

    def test_search_metadata_gate_only_projects_legacy_authorizable_rows(self) -> None:
        incomplete = search.SearchResult(
            path="/vault/工作流/incomplete.md",
            rel_path="工作流/incomplete.md",
            status="active",
            project_id="global",
            verified_at_source="structural",
            fact_status="not_fact",
            memory_type="workflow",
        )
        inactive = search.SearchResult(
            path="/vault/工作流/inactive.md",
            rel_path="工作流/inactive.md",
            status="pending_verification",
            project_id="global",
            verified_at_source="structural",
            fact_status="not_fact",
            memory_type="workflow",
        )
        search.annotate_result_policy(incomplete, args())
        search.annotate_result_policy(inactive, args())
        self.assertTrue(incomplete.legacy_authorizable)
        self.assertEqual(
            set(incomplete.metadata_gate_reasons),
            {
                "METADATA_MEMORY_ID_NOT_EXPLICIT",
                "METADATA_TEMPORAL_POLICY_NOT_EXPLICIT",
                "METADATA_REVIEW_POLICY_NOT_EXPLICIT",
                "METADATA_RISK_CLASS_NOT_EXPLICIT",
            },
        )
        self.assertFalse(inactive.legacy_authorizable)
        self.assertEqual(inactive.metadata_gate_reasons, ())
        projection = {
            "configured_mode": "shadow",
            "effective_mode": "shadow",
            "would_block_count": 1,
            "reason_codes": sorted(incomplete.metadata_gate_reasons),
            "reason_fingerprint": "a" * 64,
            "enforced": False,
        }
        with mock.patch.object(
            search.shadow_gate,
            "metadata_gate_projection",
            return_value=projection,
        ) as projected:
            self.assertEqual(search.apply_metadata_gate([incomplete, inactive]), projection)
        projected.assert_called_once_with([incomplete.metadata_gate_reasons])
        self.assertIn("metadata_gate_would_block", incomplete.policy_warnings)
        self.assertNotIn("metadata_gate_would_block", inactive.policy_warnings)
        self.assertFalse(incomplete.can_authorize_action)

    def test_search_risk_metadata_round_trips_and_downgrade_is_observed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            vault = Path(raw_tmp)
            target = vault / "项目" / "事实-owner.md"
            target.parent.mkdir()
            target.write_text(
                "---\nmemory_id: " + "a" * 64 + "\n"
                "memory_type: fact\ntrack: project\nproject_id: global\nstatus: active\n"
                "risk_class: ordinary\ntemporal_policy: reviewable\nreview_after_days: 90\n"
                "verification_mode: structural\nfact_key: project.owner\nvalid_from: 2026-08-01\n"
                "---\n# Owner\n",
                encoding="utf-8",
            )
            with mock.patch.object(memory_index, "VAULT_ROOT", vault):
                doc, _ = memory_index.load_doc(target, "2026-08-24T00:00:00+00:00")
            conn = sqlite3.connect(":memory:")
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
            memory_index.upsert_doc(conn, doc)
            row = conn.execute(
                "SELECT d.*, '' AS hit FROM memory_docs d WHERE rel_path=?",
                ("项目/事实-owner.md",),
            ).fetchone()
            result = search.row_to_result(row, 1, "owner")
            search.annotate_result_policy(result, args())
            conn.close()

        self.assertEqual(result.risk_class, "ordinary")
        self.assertEqual(result.risk_class_source, "frontmatter")
        self.assertIn("RISK_CLASS_DOWNGRADE", result.path_policy_reason_codes)
        self.assertTrue(result.metadata_gate_evaluated)
        self.assertEqual(
            result.metadata_gate_reasons,
            ("METADATA_RISK_CLASS_DOWNGRADE",),
        )
        self.assertFalse(result.legacy_authorizable)
        self.assertFalse(result.can_authorize_action)
        self.assertEqual(result.to_dict()["risk_class"], "ordinary")

        projection = {
            "configured_mode": "shadow",
            "effective_mode": "shadow",
            "would_block_count": 1,
            "reason_codes": ["METADATA_RISK_CLASS_DOWNGRADE"],
            "reason_fingerprint": "a" * 64,
            "enforced": False,
        }
        with mock.patch.object(
            search.shadow_gate,
            "metadata_gate_projection",
            return_value=projection,
        ) as projected:
            self.assertEqual(search.apply_metadata_gate([result]), projection)
        projected.assert_called_once_with([("METADATA_RISK_CLASS_DOWNGRADE",)])
        self.assertIn("metadata_gate_would_block", result.policy_warnings)

    def test_pending_verification_remains_discoverable_but_never_authorizes(self) -> None:
        result = search.SearchResult(
            path="/vault/项目/pending.md",
            rel_path="项目/pending.md",
            status="pending_verification",
            memory_type="project",
            track="project",
            project_id="global",
            risk_class="ordinary",
            risk_class_source="frontmatter",
            memory_id_value="a" * 64,
            memory_id_source_value="frontmatter",
            temporal_policy="reviewable",
            temporal_policy_source="frontmatter",
            review_after_days=90,
            review_after_source="frontmatter",
            verified_at_source="structural",
            fact_status="not_fact",
        )
        search.annotate_result_policy(result, args())
        self.assertTrue(search.result_matches_filters(result, args()))
        self.assertFalse(result.legacy_authorizable)
        self.assertFalse(result.metadata_gate_evaluated)
        self.assertEqual(result.metadata_gate_reasons, ())
        self.assertFalse(result.can_authorize_action)

    def test_invalid_risk_class_is_observed_without_becoming_a_downgrade(self) -> None:
        result = search.SearchResult(
            path="/vault/项目/example.md",
            rel_path="项目/example.md",
            status="active",
            memory_type="project",
            track="project",
            project_id="global",
            risk_class="legacy_sensitive",
            risk_class_source="frontmatter",
            memory_id_value="a" * 64,
            memory_id_source_value="frontmatter",
            temporal_policy="reviewable",
            temporal_policy_source="frontmatter",
            review_after_days=90,
            review_after_source="frontmatter",
            verified_at_source="structural",
            fact_status="not_fact",
        )
        search.annotate_result_policy(result, args())
        self.assertIn("RISK_CLASS_INVALID", result.path_policy_reason_codes)
        self.assertNotIn("RISK_CLASS_DOWNGRADE", result.path_policy_reason_codes)
        self.assertEqual(
            result.metadata_gate_reasons,
            ("METADATA_RISK_CLASS_INVALID",),
        )
        self.assertTrue(result.metadata_gate_evaluated)
        self.assertFalse(result.legacy_authorizable)
        self.assertFalse(result.can_authorize_action)

    def test_missing_risk_columns_require_explicit_index_migration_without_alter(self) -> None:
        conn = sqlite3.connect(":memory:")
        memory_index.init_db(conn)
        conn.execute("ALTER TABLE memory_docs DROP COLUMN risk_class_source")
        conn.execute("ALTER TABLE memory_docs DROP COLUMN risk_class")
        before = tuple(
            str(row[1]) for row in conn.execute("PRAGMA table_info(memory_docs)")
        )
        with self.assertRaisesRegex(
            sqlite3.OperationalError,
            "STATE_SCHEMA_MIGRATION_REQUIRED",
        ):
            memory_index.assert_schema_ready(conn)
        after = tuple(
            str(row[1]) for row in conn.execute("PRAGMA table_info(memory_docs)")
        )
        conn.close()
        self.assertEqual(after, before)
        self.assertNotIn("risk_class", after)
        self.assertNotIn("risk_class_source", after)

    def test_valid_until_round_trips_through_index_schema(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            vault = Path(raw_tmp)
            target = vault / "项目" / "example.md"
            target.parent.mkdir()
            target.write_text(
                "---\nmemory_type: project\ntrack: project\nproject_id: example\nstatus: active\n"
                "verified_at: 2026-06-01\nvalid_until: 2026-08-01\nreview_after_days: 30\n"
                "---\n# Example\n",
                encoding="utf-8",
            )
            with mock.patch.object(memory_index, "VAULT_ROOT", vault):
                doc, _ = memory_index.load_doc(target, "2026-07-19T00:00:00+00:00")
            conn = sqlite3.connect(":memory:")
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
            memory_index.upsert_doc(conn, doc)
            row = conn.execute(
                "SELECT d.*, '' AS hit FROM memory_docs d WHERE rel_path=?",
                ("项目/example.md",),
            ).fetchone()
            result = search.row_to_result(row, 1, "Example")
            search.annotate_result_policy(result, args())
            conn.close()
        self.assertEqual(result.valid_until, "2026-08-01")
        self.assertEqual(result.review_after_days, 30)
        self.assertEqual(result.review_status, "overdue")
        self.assertEqual(result.review_due_at, "2026-07-01")
        self.assertIn(search.REVIEW_OVERDUE_WARNING, result.policy_warnings)

    def test_expired_result_is_warned_but_keeps_score(self) -> None:
        result = search.SearchResult(
            path="/vault/工作流/time-bound.md",
            rel_path="工作流/time-bound.md",
            track="workflow",
            memory_type="workflow",
            status="active",
            valid_until="2026-07-18",
            score=3.25,
        )
        search.annotate_result_policy(result, args())
        self.assertEqual(result.score, 3.25)
        self.assertEqual(result.time_status, "expired")
        self.assertIn("expired_memory_reference_only", result.policy_warnings)
        self.assertTrue(result.requires_live_verification)
        self.assertFalse(result.can_authorize_action)

    def test_malformed_iso_date_cannot_borrow_a_valid_prefix(self) -> None:
        self.assertIsNone(search.parsed_date("2099-01-01junk"))
        result = search.SearchResult(
            path="/vault/工作流/malformed.md",
            rel_path="工作流/malformed.md",
            status="active",
            project_id="global",
            valid_until="2099-01-01junk",
            verified_at_source="structural",
            fact_status="not_fact",
        )
        search.annotate_result_policy(result, args())
        self.assertEqual(result.time_status, "invalid")
        self.assertIn("invalid_valid_until", result.policy_warnings)
        self.assertTrue(result.requires_live_verification)
        self.assertFalse(result.can_authorize_action)

    def test_inactive_policy_never_mixes_candidates_or_legacy_pseudo_states(self) -> None:
        allowed_default = {"active", "pending_verification"}
        allowed_history = allowed_default | {"outdated", "archived"}
        for status in (
            "active",
            "pending_verification",
            "outdated",
            "archived",
            "candidate",
            "stale",
            "deprecated",
        ):
            result = search.SearchResult(
                path=f"/vault/项目/{status}.md",
                rel_path=f"项目/{status}.md",
                status=status,
            )
            with self.subTest(status=status, include_inactive=False):
                self.assertEqual(
                    search.result_matches_filters(result, args()),
                    status in allowed_default,
                )
            with self.subTest(status=status, include_inactive=True):
                self.assertEqual(
                    search.result_matches_filters(result, args(include_inactive=True)),
                    status in allowed_history,
                )
            with self.subTest(status=status, explicit=True):
                self.assertEqual(
                    search.result_matches_filters(
                        result,
                        args(status=status, include_inactive=True),
                    ),
                    status in allowed_history,
                )

    def test_include_inactive_is_sufficient_for_outdated_fact_history(self) -> None:
        for fact_status in ("superseded", "historical"):
            inactive = search.SearchResult(
                path=f"/vault/项目/{fact_status}.md",
                rel_path=f"项目/{fact_status}.md",
                status="outdated",
                fact_status=fact_status,
            )
            active = search.SearchResult(
                path=f"/vault/项目/active-{fact_status}.md",
                rel_path=f"项目/active-{fact_status}.md",
                status="active",
                fact_status=fact_status,
            )
            candidate = search.SearchResult(
                path=f"/vault/项目/candidate-{fact_status}.md",
                rel_path=f"项目/candidate-{fact_status}.md",
                status="candidate",
                fact_status=fact_status,
            )
            with self.subTest(fact_status=fact_status):
                self.assertFalse(search.result_matches_filters(inactive, args()))
                self.assertTrue(
                    search.result_matches_filters(
                        inactive,
                        args(include_inactive=True),
                    )
                )
                self.assertFalse(
                    search.result_matches_filters(
                        active,
                        args(include_inactive=True),
                    )
                )
                self.assertTrue(
                    search.result_matches_filters(
                        active,
                        args(include_superseded=True),
                    )
                )
                self.assertFalse(
                    search.result_matches_filters(
                        candidate,
                        args(include_inactive=True, include_superseded=True),
                    )
                )
                search.annotate_result_policy(inactive, args(include_inactive=True))
                self.assertFalse(inactive.can_authorize_action)
                self.assertTrue(inactive.canonical_read_required)

    def test_review_overdue_is_separate_from_expiry_and_keeps_score(self) -> None:
        result = search.SearchResult(
            path="/vault/工作流/reviewable.md",
            rel_path="工作流/reviewable.md",
            track="workflow",
            memory_type="workflow",
            status="active",
            verified_at="2026-06-18",
            verified_at_source="frontmatter",
            review_after_days=30,
            score=4.5,
        )
        search.annotate_result_policy(result, args())
        self.assertEqual(result.score, 4.5)
        self.assertEqual(result.time_status, "unspecified")
        self.assertEqual(result.review_status, "overdue")
        self.assertEqual(result.review_due_at, "2026-07-18")
        self.assertEqual(result.policy_warnings, [search.REVIEW_OVERDUE_WARNING])
        self.assertTrue(result.requires_live_verification)

    def test_valid_until_expiry_keeps_priority_when_review_is_also_overdue(self) -> None:
        result = search.SearchResult(
            path="/vault/项目/time-bound.md",
            rel_path="项目/time-bound.md",
            status="active",
            valid_until="2026-07-18",
            verified_at="2026-06-18",
            verified_at_source="frontmatter",
            review_after_days=30,
        )
        search.annotate_result_policy(result, args())
        self.assertEqual(result.time_status, "expired")
        self.assertEqual(result.review_status, "overdue")
        self.assertEqual(
            result.policy_warnings,
            ["expired_memory_reference_only", search.REVIEW_OVERDUE_WARNING],
        )

    def test_review_boundary_and_non_reviewable_sources_are_deterministic(self) -> None:
        today = dt.date.today()
        due_today = search.SearchResult(
            path="/vault/项目/due.md",
            rel_path="项目/due.md",
            status="active",
            verified_at=(today - dt.timedelta(days=30)).isoformat(),
            verified_at_source="frontmatter",
            review_after_days=30,
        )
        search.annotate_result_policy(due_today, args())
        self.assertEqual(due_today.review_status, "due_today")
        self.assertEqual(due_today.review_due_at, today.isoformat())
        self.assertFalse(due_today.requires_live_verification)

        for source in ("structural", "snapshot"):
            with self.subTest(source=source):
                result = search.SearchResult(
                    path=f"/vault/{source}.md",
                    rel_path=f"{source}.md",
                    status="active",
                    verified_at_source=source,
                    review_after_days=1,
                )
                search.annotate_result_policy(result, args())
                self.assertEqual(result.review_status, "not_applicable")
                self.assertNotIn(search.REVIEW_OVERDUE_WARNING, result.policy_warnings)
                self.assertFalse(result.requires_live_verification)

        missing = search.SearchResult(
            path="/vault/项目/unverified.md",
            rel_path="项目/unverified.md",
            status="active",
            verified_at="",
            verified_at_source="needs_review",
            review_after_days=1,
        )
        search.annotate_result_policy(missing, args())
        self.assertEqual(missing.review_status, "unverified")
        self.assertEqual(missing.review_due_at, "")
        self.assertEqual(missing.policy_warnings, ["verification_needed"])
        self.assertNotIn(search.REVIEW_OVERDUE_WARNING, missing.policy_warnings)

    def test_other_project_is_excluded_by_default(self) -> None:
        result = search.SearchResult(
            path="/vault/项目/b.md",
            rel_path="项目/b.md",
            track="project",
            memory_type="project",
            project_id="project-b",
            status="active",
        )
        self.assertFalse(search.result_matches_filters(result, args(current_project="project-a")))

    def test_cross_project_mode_labels_reference(self) -> None:
        result = search.SearchResult(
            path="/vault/项目/b.md",
            rel_path="项目/b.md",
            track="project",
            memory_type="project",
            project_id="project-b",
            status="active",
        )
        boundary_args = args(current_project="project-a", cross_project=True)
        self.assertTrue(search.result_matches_filters(result, boundary_args))
        search.annotate_result_policy(result, boundary_args)
        self.assertEqual(result.scope_status, "cross_project_reference")
        self.assertIn("cross_project_reference_only", result.policy_warnings)
        self.assertFalse(result.can_authorize_action)
        self.assertTrue(result.analogy_only)

    def test_project_mode_oversamples_before_filtering(self) -> None:
        self.assertEqual(search.backend_candidate_limit(Namespace(limit=5, current_project="a")), 128)
        self.assertEqual(search.backend_candidate_limit(Namespace(limit=5, current_project="")), 80)

    def test_all_post_backend_scope_filters_oversample_before_filtering(self) -> None:
        for field in (
            "project_id",
            "agent_scope",
            "track",
            "memory_type",
            "user_id",
            "agent_id",
            "app_id",
            "session_id",
            "status",
        ):
            with self.subTest(field=field):
                self.assertEqual(
                    search.backend_candidate_limit(Namespace(limit=5, **{field: "selected"})),
                    128,
                )
        self.assertEqual(
            search.backend_candidate_limit(Namespace(limit=5, has_open_loop=True)),
            128,
        )

    def test_project_id_matching_is_exact_not_substring(self) -> None:
        self.assertFalse(search.project_matches("foo", "foobar"))
        self.assertTrue(search.project_matches("ＦＯＯ", "foo, shared-project"))

        exact = search.SearchResult(
            path="/vault/项目/foo.md",
            rel_path="项目/foo.md",
            track="project",
            project_id="foo",
            status="active",
        )
        prefixed = search.SearchResult(
            path="/vault/项目/foobar.md",
            rel_path="项目/foobar.md",
            track="project",
            project_id="foobar",
            status="active",
        )
        self.assertTrue(search.result_matches_filters(exact, args(project_id="ＦＯＯ")))
        self.assertFalse(search.result_matches_filters(prefixed, args(project_id="foo")))

    def test_project_tagged_workflow_and_decision_use_the_hard_boundary(self) -> None:
        project_workflow = search.SearchResult(
            path="/vault/工作流/b.md",
            rel_path="工作流/b.md",
            track="workflow",
            memory_type="workflow",
            project_id="project-b",
            status="active",
        )
        global_workflow = search.SearchResult(
            path="/vault/工作流/global.md",
            rel_path="工作流/global.md",
            track="workflow",
            memory_type="workflow",
            project_id="global",
            status="active",
        )
        current_workflow = search.SearchResult(
            path="/vault/工作流/a.md",
            rel_path="工作流/a.md",
            track="workflow",
            memory_type="workflow",
            project_id="project-a",
            status="active",
        )
        tagged_decision = search.SearchResult(
            path="/vault/决策/b.md",
            rel_path="决策/b.md",
            track="decision",
            memory_type="decision",
            project_id="project-b",
            status="active",
        )
        unscoped_workflow = search.SearchResult(
            path="/vault/工作流/unscoped.md",
            rel_path="工作流/unscoped.md",
            track="workflow",
            memory_type="workflow",
            project_id="",
            status="active",
        )
        mixed_global_project = search.SearchResult(
            path="/vault/工作流/mixed.md",
            rel_path="工作流/mixed.md",
            track="workflow",
            memory_type="workflow",
            project_id="global, project-b",
            status="active",
        )
        boundary_args = args(current_project="project-a")
        self.assertFalse(search.result_matches_filters(project_workflow, boundary_args))
        self.assertTrue(search.result_matches_filters(global_workflow, boundary_args))
        self.assertTrue(search.result_matches_filters(current_workflow, boundary_args))
        self.assertFalse(search.result_matches_filters(tagged_decision, boundary_args))
        self.assertTrue(search.result_matches_filters(unscoped_workflow, boundary_args))
        self.assertFalse(search.result_matches_filters(mixed_global_project, boundary_args))
        search.annotate_result_policy(project_workflow, boundary_args)
        search.annotate_result_policy(current_workflow, boundary_args)
        search.annotate_result_policy(global_workflow, boundary_args)
        search.annotate_result_policy(unscoped_workflow, boundary_args)
        self.assertEqual(project_workflow.scope_status, "cross_project_reference")
        self.assertEqual(current_workflow.scope_status, "current_project")
        self.assertEqual(global_workflow.scope_status, "global_shared")
        self.assertEqual(unscoped_workflow.scope_status, "unscoped_shared_reference")
        self.assertTrue(project_workflow.analogy_only)
        self.assertFalse(project_workflow.can_authorize_action)
        self.assertFalse(current_workflow.can_authorize_action)
        self.assertFalse(global_workflow.can_authorize_action)

    def test_cross_project_mode_applies_to_non_project_tracks(self) -> None:
        result = search.SearchResult(
            path="/vault/决策/b.md",
            rel_path="决策/b.md",
            track="decision",
            memory_type="decision",
            project_id="project-b",
            status="active",
        )
        boundary_args = args(current_project="project-a", cross_project=True)
        self.assertTrue(search.result_matches_filters(result, boundary_args))
        search.annotate_result_policy(result, boundary_args)
        self.assertEqual(result.scope_status, "cross_project_reference")
        self.assertTrue(result.analogy_only)
        self.assertFalse(result.can_authorize_action)

    def test_cli_exact_scope_and_no_log_are_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp).resolve()
            vault = tmp / "vault"
            state_db = tmp / "state.sqlite"
            vault.mkdir()
            specifications = [
                ("项目/a.md", "project", "project", "project-a"),
                ("项目/alpha.md", "project", "project", "project-alpha"),
                ("工作流/a.md", "workflow", "workflow", "project-a"),
                ("工作流/b.md", "workflow", "workflow", "project-b"),
                ("决策/b.md", "decision", "decision", "project-b"),
                ("工作流/global.md", "workflow", "workflow", "global"),
                ("决策/shared.md", "decision", "decision", "shared"),
                ("工作流/mixed.md", "workflow", "workflow", "global, project-b"),
            ]
            initialize_full_state(state_db)
            conn = sqlite3.connect(state_db)
            conn.row_factory = sqlite3.Row
            with mock.patch.object(memory_index, "VAULT_ROOT", vault):
                for rel_path, memory_type, track, project_id in specifications:
                    target = vault / rel_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if "," in project_id:
                        project_field = "project_id:\n" + "\n".join(
                            f"  - {item.strip()}" for item in project_id.split(",")
                        )
                    else:
                        project_field = f"project_id: {project_id}"
                    target.write_text(
                        "---\n"
                        f"memory_type: {memory_type}\n"
                        f"track: {track}\n"
                        f"{project_field}\n"
                        "status: active\n"
                        "---\n"
                        f"# {target.stem} scopeprobe\n\n"
                        "scopeprobe common searchable text\n",
                        encoding="utf-8",
                    )
                    doc, _ = memory_index.load_doc(target, "2026-07-19T00:00:00+00:00")
                    memory_index.upsert_doc(conn, doc)
                    memory_index.insert_fts(conn, doc)
            conn.commit()
            conn.close()

            config = tmp / "agent-memory.toml"
            config.write_text(
                f"memory_root = {json.dumps(str(vault), ensure_ascii=False)}\n"
                f"state_db = {json.dumps(str(state_db), ensure_ascii=False)}\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["AGENT_MEMORY_CONFIG_FILE"] = str(config)
            env["AGENT_MEMORY_ROOT"] = str(vault)
            env["AGENT_MEMORY_GIT_ROOT"] = str(vault)
            env["AGENT_MEMORY_STATE_DB"] = str(state_db)
            command = [
                sys.executable,
                str(SCRIPTS / "agent_memory_search.py"),
                "scopeprobe",
                "--limit",
                "20",
                "--no-zvec",
                "--no-log",
                "--json",
            ]

            before_bytes = state_db.read_bytes()
            with contextlib.closing(sqlite3.connect(state_db)) as before_conn, before_conn:
                before_rows = {
                    table: before_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("memory_docs", "memory_fts", "memory_search_log", "meta")
                }

            current = subprocess.run(
                [*command, "--current-project", "project-a"],
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(current.returncode, 0, current.stdout + current.stderr)
            current_payload = json.loads(current.stdout)
            current_paths = {row["rel_path"] for row in current_payload["results"]}
            self.assertIn("项目/a.md", current_paths, current_payload)
            self.assertIn("工作流/a.md", current_paths)
            self.assertIn("工作流/global.md", current_paths)
            self.assertIn("决策/shared.md", current_paths)
            self.assertNotIn("项目/alpha.md", current_paths)
            self.assertNotIn("工作流/b.md", current_paths)
            self.assertNotIn("决策/b.md", current_paths)
            self.assertNotIn("工作流/mixed.md", current_paths)
            self.assertTrue(all(row["can_authorize_action"] is False for row in current_payload["results"]))

            cross = subprocess.run(
                [*command, "--current-project", "project-a", "--cross-project"],
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(cross.returncode, 0, cross.stdout + cross.stderr)
            cross_payload = json.loads(cross.stdout)
            cross_by_path = {row["rel_path"]: row for row in cross_payload["results"]}
            self.assertTrue(cross_by_path["工作流/b.md"]["analogy_only"])
            self.assertTrue(cross_by_path["决策/b.md"]["analogy_only"])
            self.assertFalse(cross_by_path["工作流/global.md"]["analogy_only"])
            self.assertFalse(cross_by_path["决策/shared.md"]["analogy_only"])

            exact = subprocess.run(
                [*command, "--project-id", "project-a"],
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(exact.returncode, 0, exact.stdout + exact.stderr)
            exact_payload = json.loads(exact.stdout)
            self.assertIn("project-a", {row["project_id"] for row in exact_payload["results"]})
            self.assertIn("global", {row["project_id"] for row in exact_payload["results"]})
            self.assertNotIn("项目/alpha.md", {row["rel_path"] for row in exact_payload["results"]})

            with contextlib.closing(sqlite3.connect(state_db)) as after_conn, after_conn:
                after_rows = {
                    table: after_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("memory_docs", "memory_fts", "memory_search_log", "meta")
                }
            self.assertEqual(after_rows, before_rows)
            self.assertEqual(state_db.read_bytes(), before_bytes)

    def test_cli_refuses_an_older_state_without_silent_migration(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            state_db = tmp / "legacy.sqlite"
            with contextlib.closing(sqlite3.connect(state_db)) as conn, conn:
                conn.execute("CREATE TABLE legacy_marker(value TEXT NOT NULL)")
                conn.execute("INSERT INTO legacy_marker(value) VALUES ('unchanged')")
            config = tmp / "agent-memory.toml"
            config.write_text(
                f"memory_root = {json.dumps(str(tmp), ensure_ascii=False)}\n"
                f"state_db = {json.dumps(str(state_db), ensure_ascii=False)}\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["AGENT_MEMORY_CONFIG_FILE"] = str(config)
            env["AGENT_MEMORY_ROOT"] = str(tmp)
            env["AGENT_MEMORY_GIT_ROOT"] = str(tmp)
            env["AGENT_MEMORY_STATE_DB"] = str(state_db)
            before_bytes = state_db.read_bytes()
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "agent_memory_search.py"),
                    "scopeprobe",
                    "--no-zvec",
                    "--no-log",
                    "--json",
                ],
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["reason_code"], "RUNTIME_TRANSITION_INCOMPLETE")
            with contextlib.closing(sqlite3.connect(state_db)) as conn, conn:
                tables = {
                    row[0]
                    for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                marker = conn.execute("SELECT value FROM legacy_marker").fetchone()[0]
            self.assertEqual(tables, {"legacy_marker"})
            self.assertEqual(marker, "unchanged")
            self.assertEqual(state_db.read_bytes(), before_bytes)

    def test_run_search_distinguishes_total_failure_from_backend_degradation(self) -> None:
        health = mock.patch.object(search, "index_projection_health", return_value={"status": "ok"})
        health.start()
        self.addCleanup(health.stop)
        search_args = args(
            query="healthcheck",
            limit=5,
            ranking_version=search.RANKING_VERSION,
            _shadow_benchmark_bypass=True,
            no_zvec=False,
            force_rg=False,
            no_log=True,
            zvec_timeout=5,
            zvec_max_distance=0.8,
            rg_timeout=5,
        )
        with (
            mock.patch.object(search, "sqlite_search", return_value=([], ["sqlite failed"])),
            mock.patch.object(search, "zvec_search", return_value=([], ["zvec failed"])),
        ):
            rows, warnings, all_failed = search.run_search(search_args)
        self.assertEqual(rows, [])
        self.assertTrue(all_failed)
        self.assertCountEqual(warnings, ["sqlite failed", "zvec failed"])
        self.assertEqual(search_args._backend_status["unicode_fts"], "failed")
        self.assertEqual(search_args._backend_status["zvec"], "failed")

        with (
            mock.patch.object(search, "sqlite_search", return_value=([], ["sqlite failed"])),
            mock.patch.object(search, "zvec_search", return_value=([], [])),
        ):
            rows, warnings, all_failed = search.run_search(search_args)
        self.assertEqual(rows, [])
        self.assertFalse(all_failed)
        self.assertEqual(warnings, ["sqlite failed"])
        self.assertEqual(search_args._backend_status["unicode_fts"], "failed")
        self.assertEqual(search_args._backend_status["zvec"], "ok")
        self.assertTrue(search_args._degraded)

    def test_required_semantic_failure_is_a_stable_hard_failure(self) -> None:
        lexical = search.SearchResult(
            path="/vault/工作流/lexical.md",
            rel_path="工作流/lexical.md",
            status="active",
            sources={"unicode_fts"},
        )
        search_args = args(
            query="healthcheck",
            limit=5,
            ranking_version=search.RANKING_VERSION,
            _shadow_benchmark_bypass=True,
            no_zvec=False,
            semantic_mode="required",
            force_rg=False,
            no_log=True,
        )
        with (
            mock.patch.object(search, "index_projection_health", return_value={"status": "ok"}),
            mock.patch.object(search, "sqlite_search", return_value=([lexical], [])),
            mock.patch.object(search, "zvec_search", return_value=([], ["zvec failed"])),
        ):
            rows, _warnings, all_failed = search.run_search(search_args)
        self.assertFalse(all_failed)
        self.assertEqual([row.rel_path for row in rows], ["工作流/lexical.md"])
        self.assertTrue(search_args._hard_failure)
        self.assertTrue(search_args._degraded)
        self.assertEqual(
            search_args._failure_reason_code,
            search.RETRIEVAL_BACKEND_REQUIRED_UNAVAILABLE,
        )

    def test_hybrid_v2_excludes_rg_and_row_version_matches_effective_version(self) -> None:
        rg = search.SearchResult(
            path="/vault/rg.md",
            rel_path="工作流/rg.md",
            status="active",
            sources={"rg"},
            score=99,
            legacy_score=99,
        )
        lexical = search.SearchResult(
            path="/vault/fts.md",
            rel_path="工作流/fts.md",
            status="active",
            sources={"unicode_fts"},
            score=0.1,
            legacy_score=0.1,
        )
        self.assertEqual(
            [row.rel_path for row in search.merge_results([[rg], [lexical]], search.RANKING_VERSION)],
            ["工作流/fts.md"],
        )
        search_args = args(
            query="healthcheck",
            limit=5,
            no_zvec=True,
            semantic_mode="off",
            ranking_version="hybrid-v1",
            force_rg=False,
            no_log=True,
        )
        with (
            mock.patch.object(search, "index_projection_health", return_value={"status": "ok"}),
            mock.patch.object(search, "legacy_sqlite_search", return_value=([lexical], [])),
        ):
            rows, _warnings, _all_failed = search.run_search(search_args)
        self.assertEqual(rows[0].to_dict()["ranking_version"], "hybrid-v1")
        self.assertEqual(search_args._effective_ranking_version, "hybrid-v1")

        production = search.SearchResult(
            path="/vault/fts-production.md",
            rel_path="工作流/fts-production.md",
            status="active",
            sources={"unicode_fts"},
            verified_at_source="structural",
        )
        production_args = args(
            query="healthcheck",
            limit=5,
            no_zvec=True,
            semantic_mode="off",
            ranking_version=search.RANKING_VERSION,
            force_rg=True,
            no_log=True,
            _shadow_benchmark_bypass=True,
        )
        with (
            mock.patch.object(search, "index_projection_health", return_value={"status": "ok"}),
            mock.patch.object(search, "sqlite_search", return_value=([production], [])),
            mock.patch.object(search, "rg_search", return_value=([rg], [])) as rg_backend,
        ):
            rows, _warnings, all_failed = search.run_search(production_args)
        self.assertFalse(all_failed)
        rg_backend.assert_not_called()
        self.assertEqual([row.rel_path for row in rows], ["工作流/fts-production.md"])
        self.assertEqual(rows[0].sources, {"unicode_fts"})
        self.assertEqual(rows[0].to_dict()["ranking_version"], search.RANKING_VERSION)

    def test_shadow_control_lane_never_falls_through_to_rg(self) -> None:
        health = mock.patch.object(search, "index_projection_health", return_value={"status": "ok"})
        health.start()
        self.addCleanup(health.stop)
        rg = search.SearchResult(
            path="/vault/rg.md",
            rel_path="工作流/rg.md",
            status="active",
            sources={"rg"},
            verified_at_source="structural",
        )
        search_args = args(
            query="healthcheck",
            limit=5,
            no_zvec=True,
            semantic_mode="off",
            ranking_version="hybrid-v1",
            force_rg=True,
            no_log=True,
        )

        def failed_checkpoint(namespace: Namespace):
            namespace._legacy_sqlite_status = "failed"
            return [], ["lexical unavailable"]

        with (
            mock.patch.object(search, "legacy_sqlite_search", side_effect=failed_checkpoint),
            mock.patch.object(search, "rg_search", return_value=([rg], [])) as rg_backend,
        ):
            rows, warnings, all_failed = search.run_search(search_args)
        rg_backend.assert_not_called()
        self.assertTrue(all_failed)
        self.assertEqual(warnings, ["lexical unavailable"])
        self.assertEqual(rows, [])

    def test_main_returns_nonzero_only_for_total_backend_failure_without_results(self) -> None:
        cli_args = args(
            query="healthcheck",
            json=True,
            redact_legacy_logs=False,
        )
        output = io.StringIO()
        with (
            mock.patch.object(search, "parse_args", return_value=cli_args),
            mock.patch.object(search, "assert_runtime_ready", return_value={"ready": True}),
            mock.patch.object(search, "run_search", return_value=([], ["all failed"], True)),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(search.main(), 2)
        failed_payload = json.loads(output.getvalue())
        self.assertEqual(failed_payload["warnings"], ["all failed"])
        self.assertFalse(failed_payload["ok"])
        self.assertEqual(
            failed_payload["error"]["code"],
            search.RETRIEVAL_BACKENDS_UNAVAILABLE,
        )
        self.assertEqual(failed_payload["results"], [])
        self.assertTrue(failed_payload["degraded"])

        output = io.StringIO()
        with (
            mock.patch.object(search, "parse_args", return_value=cli_args),
            mock.patch.object(search, "assert_runtime_ready", return_value={"ready": True}),
            mock.patch.object(search, "run_search", return_value=([], ["sqlite degraded"], False)),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(search.main(), 0)

    def test_main_maps_orchestrator_exception_to_structured_backend_failure(self) -> None:
        for semantic_mode, expected in (
            ("auto", search.RETRIEVAL_BACKENDS_UNAVAILABLE),
            ("required", search.RETRIEVAL_BACKEND_REQUIRED_UNAVAILABLE),
        ):
            cli_args = args(
                query="healthcheck",
                json=True,
                redact_legacy_logs=False,
                semantic_mode=semantic_mode,
            )
            output = io.StringIO()
            with (
                self.subTest(semantic_mode=semantic_mode),
                mock.patch.object(search, "parse_args", return_value=cli_args),
                mock.patch.object(search, "assert_runtime_ready", return_value={"ready": True}),
                mock.patch.object(
                    search,
                    "run_search",
                    side_effect=RuntimeError("private backend detail"),
                ),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(search.main(), 2)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["error"]["code"], expected)
            self.assertEqual(payload["results"], [])
            self.assertNotIn("private backend detail", output.getvalue())


if __name__ == "__main__":
    unittest.main()
