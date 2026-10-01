from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from argparse import Namespace
from contextlib import closing
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_closeout as closeout
from tests.state_fixture import initialize_full_state


def prewrite_args(text: str, *, create_intent: bool = False) -> Namespace:
    return Namespace(
        prewrite=text,
        source_class="user_direct",
        knowledge_kind="fact",
        asserted_by="user",
        evidence_ref="",
        actor="codex",
        trigger="test",
        session_id="session-1",
        limit=8,
        no_zvec=True,
        current_project="",
        proposal_file="",
        target_file="",
        create_intent=create_intent,
    )


class ReconcileHealthTests(unittest.TestCase):
    def test_search_failure_keeps_machine_readable_backend_health(self) -> None:
        warning = "sqlite index missing"
        result = {
            "ok": False,
            "returncode": 2,
            "stdout": json.dumps(
                {
                    "results": [],
                    "warnings": [warning],
                    "backend_status": {
                        "sqlite": {
                            "status": "error",
                            "results": 0,
                            "warnings": [warning],
                        }
                    },
                }
            ),
            "stderr": "",
        }
        with mock.patch.object(closeout, "run_command", return_value=result):
            rows, warnings, backend_status = closeout.search_memory("ordinary query")

        self.assertEqual(rows, [])
        self.assertEqual(warnings, [warning])
        self.assertEqual(backend_status["sqlite"]["status"], "error")

    def test_hybrid_lane_status_requires_the_lexical_lanes_behind_the_ranking(self) -> None:
        def search_result(payload: dict[str, object], *, ok: bool = True) -> dict[str, object]:
            return {
                "ok": ok,
                "returncode": 0 if ok else 2,
                "stdout": json.dumps(payload),
                "stderr": "",
            }

        lanes = {
            "legacy_sqlite": "ok",
            "unicode_fts": "disabled",
            "trigram_fts": "disabled",
            "zvec": "disabled",
            "rg": "disabled",
        }
        cases = (
            ("checkpoint healthy", {"ranking_version": "hybrid-v1", "backend_status": lanes}, True, "ok"),
            (
                "checkpoint lane failed",
                {"ranking_version": "hybrid-v1", "backend_status": {**lanes, "legacy_sqlite": "failed"}},
                True,
                "error",
            ),
            (
                "hybrid semantic lane is advisory",
                {
                    "ranking_version": "hybrid-v2",
                    "backend_status": {
                        **lanes,
                        "legacy_sqlite": "disabled",
                        "unicode_fts": "ok",
                        "trigram_fts": "ok",
                        "zvec": "failed",
                    },
                },
                True,
                "ok",
            ),
            (
                "hybrid lexical lane failed",
                {
                    "ranking_version": "hybrid-v2",
                    "backend_status": {
                        **lanes,
                        "legacy_sqlite": "disabled",
                        "unicode_fts": "ok",
                        "trigram_fts": "failed",
                    },
                },
                True,
                "error",
            ),
            (
                "contract failure payload",
                {"ok": False, "ranking_version": "hybrid-v1", "backend_status": lanes},
                False,
                "error",
            ),
        )
        for name, payload, process_ok, expected in cases:
            with self.subTest(name):
                with mock.patch.object(
                    closeout,
                    "run_command",
                    return_value=search_result({"results": [], "warnings": [], **payload}, ok=process_ok),
                ):
                    _rows, warnings, backend_status = closeout.search_memory("ordinary query")
                self.assertEqual(backend_status["sqlite"]["status"], expected)
                if not process_ok:
                    self.assertTrue(warnings)

    def test_ailu_candidate_lane_reports_lexical_health(self) -> None:
        import agent_memory_retrieve as memory_retrieve

        for lane_status, expected in (("ok", "ok"), ("failed", "error")):
            with self.subTest(lane_status=lane_status):
                namespace = Namespace(
                    _backend_status={"legacy_sqlite": lane_status, "zvec": "disabled"},
                    _effective_ranking_version="hybrid-v1",
                )
                with (
                    mock.patch.object(
                        memory_retrieve,
                        "validate_ailu_scope_request",
                        return_value=("ailu", "example-project"),
                    ),
                    mock.patch.object(
                        memory_retrieve,
                        "_run_candidate_search",
                        return_value=([], [], namespace),
                    ),
                ):
                    rows, _warnings, backend_status = closeout.search_memory(
                        "ordinary query",
                        app_id="ailu",
                        project_id="example-project",
                        canonical_actor="ailu",
                    )
                self.assertEqual(rows, [])
                self.assertEqual(backend_status["sqlite"]["status"], expected)

    def test_unhealthy_sqlite_blocks_prewrite_and_intent_creation(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            state_db = Path(raw_tmp) / "state.sqlite"
            initialize_full_state(state_db)
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(
                    closeout,
                    "search_memory",
                    return_value=(
                        [],
                        ["sqlite index missing"],
                        {"sqlite": {"status": "error"}},
                    ),
                ),
                mock.patch.object(closeout.write_intent, "create_intent") as create_intent,
            ):
                payload = closeout.run_prewrite(
                    prewrite_args("A durable local workflow fact.", create_intent=True)
                )
            with closing(sqlite3.connect(state_db)) as connection:
                audit_rows = connection.execute("SELECT COUNT(*) FROM memory_safety_log").fetchone()[0]

        create_intent.assert_not_called()
        self.assertEqual(audit_rows, 1)
        self.assertEqual(payload["status"], "blocked")
        self.assertIsNone(payload["recommended_action"])
        self.assertEqual(
            payload["recommendation_unavailable_reason"],
            "RECONCILE_SEARCH_UNHEALTHY",
        )
        self.assertEqual(payload["reconcile"]["status"], "blocked")

    def test_long_prewrite_uses_bounded_query_but_keeps_full_input(self) -> None:
        captured: list[str] = []

        def healthy_search(query: str, **_kwargs):
            captured.append(query)
            return [], [], {"sqlite": {"status": "ok"}}

        text = "Cross-platform image workflow keeps verified output records. " * 600
        with tempfile.TemporaryDirectory() as raw_tmp:
            state_db = Path(raw_tmp) / "state.sqlite"
            initialize_full_state(state_db)
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "search_memory", side_effect=healthy_search),
            ):
                payload = closeout.run_prewrite(prewrite_args(text))

        self.assertEqual(payload["input_length"], len(text))
        self.assertEqual(payload["recommended_action"], "ADD")
        self.assertEqual(len(captured), 1)
        self.assertLessEqual(len(captured[0]), closeout.RECONCILE_QUERY_MAX_CHARS)
        self.assertLess(len(captured[0]), len(text))

    def test_specific_title_matches_without_promoting_generic_titles(self) -> None:
        specific = {
            "title": "Cross-platform image converter",
            "rel_path": "项目/cross-platform-image-converter.md",
            "summary": "Technical validation is in progress.",
            "hit": "",
        }
        text = (
            "Cross-platform image converter supports batch work, metadata retention, "
            "retries, validation, and maintenance records."
        )
        action, _, metrics = closeout.prewrite_recommendation(text, [specific])
        self.assertEqual(action, "UPDATE")
        self.assertTrue(metrics["title_match"])

        generic = {
            "title": "工作流程",
            "rel_path": "工作流程.md",
            "summary": "",
            "hit": "",
        }
        action, _, metrics = closeout.prewrite_recommendation(
            "工作流程只是部署文档中的普通术语，正文讨论备份、责任人与事故恢复。",
            [generic],
        )
        self.assertEqual(action, "ADD")
        self.assertFalse(metrics["title_match"])

        single_word = {
            "title": "Deployment",
            "rel_path": "deployment.md",
            "summary": "",
            "hit": "",
        }
        action, _, metrics = closeout.prewrite_recommendation(
            "Deployment is one ordinary word in this unrelated recovery guide.",
            [single_word],
        )
        self.assertEqual(action, "ADD")
        self.assertFalse(metrics["title_match"])

    def test_postwrite_search_failure_is_a_blocking_finding(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            vault = Path(raw_tmp) / "vault"
            note = vault / "项目" / "new.md"
            note.parent.mkdir(parents=True)
            note.write_text("# New memory\n\nA durable fact.\n", encoding="utf-8")
            entry = closeout.GitEntry("A", "vault/项目/new.md", note)
            args = Namespace(
                reconcile_all=False,
                limit=8,
                no_zvec=True,
                current_project="",
                dry_run=False,
                merge_threshold=0.42,
                merge_coverage_threshold=0.35,
                semantic_merge_threshold=0.32,
            )
            with (
                mock.patch.object(closeout, "VAULT_ROOT", vault),
                mock.patch.object(
                    closeout,
                    "search_memory",
                    return_value=(
                        [],
                        ["sqlite index missing"],
                        {"sqlite": {"status": "error"}},
                    ),
                ),
            ):
                findings, warnings = closeout.postwrite_reconcile([entry], args)

        self.assertEqual(warnings, ["sqlite index missing"])
        self.assertEqual(findings[0]["reason"], "reconcile_search_unhealthy")
        self.assertEqual(findings[0]["action"], "ASK_USER")


if __name__ == "__main__":
    unittest.main()
