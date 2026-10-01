from __future__ import annotations

import datetime as dt
import hashlib
import sqlite3
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_index as memory_index
import agent_memory_closeout as memory_closeout
import agent_memory_retrieve as memory_retrieve
import agent_memory_search as memory_search
import agent_memory_write as memory_write
import agent_memory_intent as write_intent


def row(
    rel_path: str,
    *,
    fact_key: str = "project.owner",
    valid_from: str,
    supersedes: str = "",
    project_id: str = "project-a",
    valid_until: str = "",
    status: str = "active",
) -> dict[str, str]:
    return {
        "rel_path": rel_path,
        "sha256": rel_path,
        "memory_type": "project",
        "status": status,
        "fact_key": fact_key,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "supersedes": supersedes,
        "app_id": "agent-memory",
        "project_id": project_id,
        "user_id": "demo-user",
        "agent_scope": "shared",
    }


def markdown(
    title: str,
    *,
    fact_key: str,
    valid_from: str,
    supersedes: str = "",
    body: str = "value",
    valid_until: str = "",
    verified_at: str = "",
    project_id: str = "project-a",
    status: str = "active",
    extra_frontmatter: str = "",
) -> str:
    relation = f"supersedes: [{supersedes}]\n" if supersedes else ""
    validity_end = f"valid_until: {valid_until}\n" if valid_until else ""
    extra = f"{extra_frontmatter.rstrip()}\n" if extra_frontmatter.strip() else ""
    return (
        "---\n"
        "memory_type: project\n"
        "track: project\n"
        "app_id: agent-memory\n"
        f"project_id: {project_id}\n"
        "user_id: demo-user\n"
        "agent_scope: shared\n"
        f"status: {status}\n"
        f"fact_key: {fact_key}\n"
        f"valid_from: {valid_from}\n"
        f"{validity_end}"
        f"verified_at: {verified_at or valid_from}\n"
        f"{relation}"
        f"{extra}"
        "---\n\n"
        f"# {title}\n\n## 当前有效摘要\n\n{body}\n"
    )


def mixed_newline_markdown(
    title: str,
    *,
    body: str,
    extra_frontmatter: str = "",
    closing_fence: str = "---",
) -> str:
    extra = f"{extra_frontmatter}\n" if extra_frontmatter else ""
    closing = f"{closing_fence}\r\n" if closing_fence else ""
    return (
        "---\r\n"
        "memory_type: project\n"
        "track: project\r\n"
        "app_id: agent-memory\n"
        "project_id: project-a\r\n"
        "user_id: demo-user\n"
        "agent_scope: shared\r\n"
        "status: active\n"
        "fact_key: project.owner\r\n"
        "valid_from: 2026-07-01\n"
        "verified_at: 2026-07-01\n"
        f"{extra}"
        f"{closing}"
        "\r\n"
        f"# {title}\r\n\r\n## 当前有效摘要\n\n{body}\r\n"
    )


class TemporalProjectionTests(unittest.TestCase):
    def test_explicit_fact_postwrite_ignores_legacy_context_but_not_other_facts(self) -> None:
        source = {"ailu.plugin-id"}
        self.assertTrue(
            memory_closeout.legacy_context_candidate_for_explicit_fact(
                source,
                {"rel_path": "项目/Ailu.md", "fact_key": ""},
            )
        )
        self.assertFalse(
            memory_closeout.legacy_context_candidate_for_explicit_fact(
                source,
                {"rel_path": "项目/same-slot.md", "fact_key": "ailu.plugin-id"},
            )
        )
        self.assertTrue(
            memory_closeout.legacy_context_candidate_for_explicit_fact(
                source,
                {"rel_path": "项目/other-fact.md", "fact_key": "ailu.version"},
            )
        )
        self.assertFalse(
            memory_closeout.legacy_context_candidate_for_explicit_fact(
                set(),
                {"rel_path": "项目/Ailu.md", "fact_key": ""},
            )
        )

    def test_explicit_forward_edge_has_one_current_head(self) -> None:
        relations, states = memory_index.build_temporal_projection(
            [
                row("项目/owner-v1.md", valid_from="2026-07-01"),
                row(
                    "项目/owner-v2.md",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                ),
            ],
            "2026-08-12T00:00:00+00:00",
        )
        self.assertEqual(relations[0]["relation_status"], "effective")
        by_path = {state["rel_path"]: state for state in states}
        self.assertEqual(by_path["项目/owner-v1.md"]["fact_status"], "superseded")
        self.assertEqual(by_path["项目/owner-v1.md"]["superseded_by"], "项目/owner-v2.md")
        self.assertEqual(by_path["项目/owner-v2.md"]["fact_status"], "current")

    def test_governed_non_active_successor_preserves_lineage_without_a_current_head(self) -> None:
        for status in ("pending_verification", "outdated", "archived"):
            with self.subTest(status=status):
                relations, states = memory_index.build_temporal_projection(
                    [
                        row("项目/owner-v1.md", valid_from="2026-07-01"),
                        row(
                            "项目/owner-v2.md",
                            valid_from="2026-08-01",
                            supersedes="项目/owner-v1.md",
                            status=status,
                        ),
                    ],
                    "2026-08-12T00:00:00+00:00",
                )
                self.assertEqual(relations[0]["relation_status"], "effective")
                by_path = {state["rel_path"]: state for state in states}
                self.assertEqual(by_path["项目/owner-v1.md"]["fact_status"], "superseded")
                self.assertEqual(by_path["项目/owner-v2.md"]["fact_status"], "historical")
                self.assertEqual({state["current_rel_path"] for state in states}, {""})

    def test_all_pending_lineage_stays_effective_but_candidate_source_is_invalid(self) -> None:
        relations, states = memory_index.build_temporal_projection(
            [
                row(
                    "项目/owner-v1.md",
                    valid_from="2026-07-01",
                    status="pending_verification",
                ),
                row(
                    "项目/owner-v2.md",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                    status="pending_verification",
                ),
            ],
            "2026-08-12T00:00:00+00:00",
        )
        self.assertEqual(relations[0]["relation_status"], "effective")
        by_path = {state["rel_path"]: state for state in states}
        self.assertEqual(by_path["项目/owner-v1.md"]["fact_status"], "superseded")
        self.assertEqual(by_path["项目/owner-v2.md"]["fact_status"], "historical")
        self.assertEqual({state["current_rel_path"] for state in states}, {""})

        candidate_relations, _ = memory_index.build_temporal_projection(
            [
                row("项目/owner-v1.md", valid_from="2026-07-01"),
                row(
                    "项目/owner-v2.md",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                    status="candidate",
                ),
            ],
            "2026-08-12T00:00:00+00:00",
        )
        self.assertEqual(candidate_relations[0]["relation_status"], "invalid")
        self.assertEqual(candidate_relations[0]["reason_code"], "SOURCE_NOT_CURRENT")

    def test_two_unrelated_heads_fail_closed_as_conflict(self) -> None:
        _, states = memory_index.build_temporal_projection(
            [
                row("项目/owner-v1.md", valid_from="2026-07-01"),
                row("项目/owner-v2.md", valid_from="2026-08-01"),
            ],
            "2026-08-12T00:00:00+00:00",
        )
        self.assertEqual({state["fact_status"] for state in states}, {"conflict"})

    def test_cross_scope_and_backward_edges_never_take_effect(self) -> None:
        relations, _ = memory_index.build_temporal_projection(
            [
                row("项目/a.md", valid_from="2026-08-01", project_id="project-a"),
                row(
                    "项目/b.md",
                    valid_from="2026-07-01",
                    supersedes="项目/a.md",
                    project_id="project-b",
                ),
            ],
            "2026-08-12T00:00:00+00:00",
        )
        self.assertEqual(relations[0]["relation_status"], "invalid")
        self.assertEqual(relations[0]["reason_code"], "FACT_SCOPE_MISMATCH")

        backward, _ = memory_index.build_temporal_projection(
            [
                row("项目/a.md", valid_from="2026-08-01"),
                row(
                    "项目/b.md",
                    valid_from="2026-07-01",
                    supersedes="项目/a.md",
                ),
            ],
            "2026-08-12T00:00:00+00:00",
        )
        self.assertEqual(backward[0]["relation_status"], "invalid")
        self.assertEqual(backward[0]["reason_code"], "VALID_FROM_NOT_FORWARD")

    def test_fork_and_cycle_declarations_remain_fail_closed(self) -> None:
        forked, _ = memory_index.build_temporal_projection(
            [
                row("项目/owner-v1.md", valid_from="2026-06-01"),
                row(
                    "项目/owner-v2.md",
                    valid_from="2026-07-01",
                    supersedes="项目/owner-v1.md",
                    status="pending_verification",
                ),
                row(
                    "项目/owner-v3.md",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                    status="outdated",
                ),
            ],
            "2026-08-12T00:00:00+00:00",
        )
        self.assertEqual(
            {relation["reason_code"] for relation in forked},
            {"MULTIPLE_SUCCESSORS"},
        )

        cycle, cycle_states = memory_index.build_temporal_projection(
            [
                row(
                    "项目/owner-v1.md",
                    valid_from="2026-07-01",
                    supersedes="项目/owner-v2.md",
                    status="pending_verification",
                ),
                row(
                    "项目/owner-v2.md",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                    status="outdated",
                ),
            ],
            "2026-08-12T00:00:00+00:00",
        )
        self.assertIn("VALID_FROM_NOT_FORWARD", {relation["reason_code"] for relation in cycle})
        self.assertEqual({state["fact_status"] for state in cycle_states}, {"invalid_relation"})
        self.assertEqual({state["current_rel_path"] for state in cycle_states}, {""})

    def test_fact_metadata_requires_explicit_key_and_iso_start(self) -> None:
        missing = memory_index.fact_metadata({"supersedes": ["项目/old.md"]})
        invalid = memory_index.fact_metadata({"fact_key": "owner key", "valid_from": "08/01/2026"})
        self.assertIn("FACT_KEY_REQUIRED", missing["errors"])
        self.assertIn("FACT_KEY_INVALID", invalid["errors"])
        self.assertIn("DATE_INVALID", invalid["errors"])


class TemporalSearchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        memory_index.init_db(self.conn)
        indexed_at = "2026-08-12T00:00:00+00:00"
        rows = [
            row("项目/owner-v1.md", valid_from="2026-07-01"),
            row(
                "项目/owner-v2.md",
                valid_from="2026-08-01",
                valid_until="2026-08-05",
                supersedes="项目/owner-v1.md",
            ),
        ]
        relations, states = memory_index.build_temporal_projection(rows, indexed_at)
        for item in rows:
            self.conn.execute(
                """
                INSERT INTO memory_docs(
                  path, rel_path, sha256, title, memory_type, track, project_id,
                  app_id, user_id, agent_id, agent_scope, session_id, status,
                  sensitivity, verified_at, verified_at_source, fact_key,
                  valid_from, valid_until, review_after_days, supersedes, mtime,
                  size_bytes, line_count, summary, next_hint, stale_info,
                  has_open_loop, open_loop_count, indexed_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "/vault/" + item["rel_path"], item["rel_path"], item["sha256"],
                    item["rel_path"], "project", "project", item["project_id"],
                    item["app_id"], item["user_id"], "shared", item["agent_scope"],
                    "", item["status"], "normal", item["valid_from"], "frontmatter",
                    item["fact_key"], item["valid_from"], item["valid_until"], 90,
                    item["supersedes"], 0.0, 1, 1, "", "", "", 0, 0, indexed_at,
                ),
            )
        self.conn.executemany(
            """
            INSERT INTO memory_supersessions(
              source_rel_path,target_rel_path,source_fact_key,target_fact_key,
              source_valid_from,target_valid_from,effective_from,source_status,
              target_status,relation_status,reason_code,indexed_at
            ) VALUES (
              :source_rel_path,:target_rel_path,:source_fact_key,:target_fact_key,
              :source_valid_from,:target_valid_from,:effective_from,:source_status,
              :target_status,:relation_status,:reason_code,:indexed_at
            )
            """,
            relations,
        )
        self.conn.executemany(
            """
            INSERT INTO memory_fact_states(
              rel_path,fact_key,fact_status,current_rel_path,superseded_by,
              effective_from,reason_code,indexed_at
            ) VALUES (
              :rel_path,:fact_key,:fact_status,:current_rel_path,:superseded_by,
              :effective_from,:reason_code,:indexed_at
            )
            """,
            states,
        )

    def tearDown(self) -> None:
        self.conn.close()

    def result(self, rel_path: str) -> memory_search.SearchResult:
        row_value = self.conn.execute(
            "SELECT d.*, '' AS hit FROM memory_docs d WHERE rel_path=?",
            (rel_path,),
        ).fetchone()
        return memory_search.row_to_result(row_value, 1, "owner")

    @staticmethod
    def search_args(*, include_inactive: bool = False, include_superseded: bool = False) -> Namespace:
        return Namespace(
            agent_scope="",
            track="",
            memory_type="",
            user_id="",
            agent_id="",
            app_id="",
            session_id="",
            project_id="",
            current_project="project-a",
            cross_project=False,
            status="",
            include_inactive=include_inactive,
            include_superseded=include_superseded,
            has_open_loop=False,
            include_supporting=False,
            as_of="",
        )

    def rebuild_with_statuses(self, old_status: str, new_status: str) -> None:
        self.conn.execute(
            "UPDATE memory_docs SET status=? WHERE rel_path='项目/owner-v1.md'",
            (old_status,),
        )
        self.conn.execute(
            "UPDATE memory_docs SET status=? WHERE rel_path='项目/owner-v2.md'",
            (new_status,),
        )
        self.conn.execute("DELETE FROM memory_supersessions")
        self.conn.execute("DELETE FROM memory_fact_states")
        memory_index._rebuild_supersessions(
            self.conn,
            "2026-08-12T00:00:01+00:00",
        )
        self.conn.commit()

    def test_as_of_before_edge_returns_old_and_hides_future_successor(self) -> None:
        old = self.result("项目/owner-v1.md")
        new = self.result("项目/owner-v2.md")
        memory_search.annotate_temporal_from_db(old, self.conn, memory_search.parsed_date("2026-07-15"))
        memory_search.annotate_temporal_from_db(new, self.conn, memory_search.parsed_date("2026-07-15"))
        self.assertEqual(old.fact_status, "current")
        self.assertEqual(new.fact_status, "not_yet_valid")

    def test_expired_successor_does_not_resurrect_predecessor(self) -> None:
        old = self.result("项目/owner-v1.md")
        new = self.result("项目/owner-v2.md")
        as_of = memory_search.parsed_date("2026-08-12")
        memory_search.annotate_temporal_from_db(old, self.conn, as_of)
        memory_search.annotate_temporal_from_db(new, self.conn, as_of)
        self.assertEqual(old.fact_status, "superseded")
        self.assertEqual(new.fact_status, "expired")

    def test_default_filter_excludes_superseded_but_history_flag_allows_it(self) -> None:
        old = self.result("项目/owner-v1.md")
        memory_search.annotate_temporal_from_db(old, self.conn, memory_search.parsed_date("2026-08-12"))
        base = dict(
            agent_scope="", track="", memory_type="", user_id="", agent_id="",
            app_id="", session_id="", project_id="", current_project="",
            cross_project=False, status="", include_inactive=False,
            has_open_loop=False, include_supporting=False,
        )
        self.assertFalse(memory_search.result_matches_filters(old, Namespace(**base, include_superseded=False)))
        self.assertTrue(memory_search.result_matches_filters(old, Namespace(**base, include_superseded=True)))

    def test_search_pending_successor_suppresses_old_active_without_current_authority(self) -> None:
        self.rebuild_with_statuses("active", "pending_verification")
        old = self.result("项目/owner-v1.md")
        new = self.result("项目/owner-v2.md")
        as_of = memory_search.parsed_date("2026-08-12")
        memory_search.annotate_temporal_from_db(old, self.conn, as_of)
        memory_search.annotate_temporal_from_db(new, self.conn, as_of)

        self.assertEqual(old.fact_status, "superseded")
        self.assertEqual(new.fact_status, "historical")
        self.assertEqual(old.current_fact_path, "")
        self.assertEqual(new.current_fact_path, "")
        self.assertFalse(memory_search.result_matches_filters(old, self.search_args()))
        self.assertTrue(memory_search.result_matches_filters(new, self.search_args()))
        memory_search.annotate_result_policy(new, self.search_args())
        self.assertFalse(new.legacy_authorizable)
        self.assertFalse(new.can_authorize_action)

    def test_search_all_pending_returns_latest_by_default_and_history_on_request(self) -> None:
        self.rebuild_with_statuses("pending_verification", "pending_verification")
        old = self.result("项目/owner-v1.md")
        new = self.result("项目/owner-v2.md")
        as_of = memory_search.parsed_date("2026-08-12")
        memory_search.annotate_temporal_from_db(old, self.conn, as_of)
        memory_search.annotate_temporal_from_db(new, self.conn, as_of)

        self.assertEqual(old.fact_status, "superseded")
        self.assertEqual(new.fact_status, "historical")
        self.assertEqual({old.current_fact_path, new.current_fact_path}, {""})
        self.assertFalse(memory_search.result_matches_filters(old, self.search_args()))
        self.assertTrue(memory_search.result_matches_filters(new, self.search_args()))
        self.assertTrue(
            memory_search.result_matches_filters(
                old,
                self.search_args(include_superseded=True),
            )
        )
        for result, args in (
            (old, self.search_args(include_superseded=True)),
            (new, self.search_args()),
        ):
            memory_search.annotate_result_policy(result, args)
            self.assertFalse(result.legacy_authorizable)
            self.assertFalse(result.can_authorize_action)

    def test_search_outdated_and_archived_lineage_requires_include_inactive(self) -> None:
        for successor_status in ("outdated", "archived"):
            with self.subTest(status=successor_status):
                self.rebuild_with_statuses("active", successor_status)
                old = self.result("项目/owner-v1.md")
                successor = self.result("项目/owner-v2.md")
                as_of = memory_search.parsed_date("2026-08-12")
                memory_search.annotate_temporal_from_db(old, self.conn, as_of)
                memory_search.annotate_temporal_from_db(successor, self.conn, as_of)

                self.assertEqual(old.fact_status, "superseded")
                self.assertEqual(successor.fact_status, "historical")
                self.assertEqual({old.current_fact_path, successor.current_fact_path}, {""})
                self.assertFalse(
                    memory_search.result_matches_filters(successor, self.search_args())
                )
                self.assertTrue(
                    memory_search.result_matches_filters(
                        successor,
                        self.search_args(include_inactive=True),
                    )
                )
                self.assertFalse(
                    memory_search.result_matches_filters(
                        old,
                        self.search_args(include_inactive=True),
                    )
                )


class TemporalWriteGateTests(unittest.TestCase):
    def test_prepare_validates_status_before_temporal_projection_and_binds_result(self) -> None:
        base_text = markdown(
            "Owner",
            fact_key="project.owner",
            valid_from="2026-07-01",
            body="Alice",
        )
        proposal_text = markdown(
            "Owner",
            fact_key="project.owner",
            valid_from="2026-07-01",
            status="pending_verification",
            body="Alice",
            extra_frontmatter="risk_class: action_sensitive",
        )
        base_digest = write_intent.content_hashes(base_text.encode("utf-8"))
        selected = write_intent.CanonicalTarget(
            path=Path("/private/owner-v1.md"),
            rel_path="项目/owner-v1.md",
            target_key="项目/owner-v1.md".casefold(),
        )

        def stop_after_transition(**kwargs: object) -> dict[str, object]:
            self.assertEqual(
                kwargs["validated_status_transition"],
                {"from_status": "active", "target_status": "pending_verification"},
            )
            raise memory_write.MemoryWriteError("TEST_STOP", "stop after temporal binding")

        request = {
            "schema_version": 2,
            "target_relative_path": selected.rel_path,
            "proposal_markdown": proposal_text,
            "read_token": "e" * 64,
            "app_id": "agent-memory",
            "project_id": "project-a",
            "operation": "status_transition",
            "target_status": "pending_verification",
            "transition_reason": "needs verification",
            "summary": "Quarantine an unverified fact.",
            "source_class": "local_verified",
            "knowledge_kind": "fact",
            "asserted_by": "codex",
            "evidence_ref": "task:status-transition",
        }
        with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
            memory_write, "_formal_target", return_value=selected
        ), mock.patch.object(
            memory_write, "_scope_request", return_value=("agent-memory", "project-a")
        ), mock.patch.object(
            memory_write, "_validate_writer_markdown", return_value={}
        ), mock.patch.object(
            memory_write,
            "_target_snapshot",
            return_value=(True, base_digest, "f" * 40, "e" * 64),
        ), mock.patch.object(
            memory_write.write_intent,
            "git_target_digest_at_commit",
            return_value=(True, base_digest),
        ), mock.patch.object(
            memory_write, "_validate_write_temporal_gate"
        ), mock.patch.object(
            memory_write,
            "_validate_temporal_transition",
            side_effect=stop_after_transition,
        ), self.assertRaises(memory_write.MemoryWriteError) as stopped:
            memory_write.prepare(request, raw_session_id="session-1")
        self.assertEqual(stopped.exception.reason_code, "TEST_STOP")

    def test_atomic_quarantine_may_only_add_missing_risk_class(self) -> None:
        for risk_line in ("", "risk_class:   "):
            with self.subTest(risk_line=risk_line or "missing"):
                base_text = markdown(
                    "Owner",
                    fact_key="project.owner",
                    valid_from="2026-07-01",
                    body="Alice",
                    extra_frontmatter=risk_line,
                )
                proposal_text = memory_write._frontmatter_scalar_replacement(
                    base_text,
                    key="status",
                    value="pending_verification",
                    allow_insert=False,
                )
                proposal_text = memory_write._frontmatter_scalar_replacement(
                    proposal_text,
                    key="risk_class",
                    value="action_sensitive",
                    allow_insert=not bool(risk_line),
                )
                self.assertEqual(
                    memory_write._validate_status_transition(
                        base_text=base_text,
                        proposal_text=proposal_text,
                        target_status="pending_verification",
                        evidence_ref="task:quarantine",
                    ),
                    {
                        "from_status": "active",
                        "target_status": "pending_verification",
                    },
                )

                drifts = {
                    "body": proposal_text.replace("Alice", "Mallory"),
                    "scope": proposal_text.replace("project-a", "project-b"),
                    "date": proposal_text.replace("2026-07-01", "2026-07-02", 1),
                    "relation": proposal_text.replace(
                        "verified_at: 2026-07-01\n",
                        "verified_at: 2026-07-01\nsupersedes: [项目/owner-v0.md]\n",
                    ),
                    "verified_at": proposal_text.replace(
                        "verified_at: 2026-07-01",
                        "verified_at: 2026-07-02",
                    ),
                    "risk_value": proposal_text.replace(
                        "risk_class: action_sensitive",
                        "risk_class: ordinary",
                    ),
                    "extra_frontmatter": proposal_text.replace(
                        "risk_class: action_sensitive\n",
                        "risk_class: action_sensitive\nsensitivity: private\n",
                    ),
                }
                for case, drifted in drifts.items():
                    with self.subTest(risk_line=risk_line or "missing", drift=case):
                        with self.assertRaises(memory_write.MemoryWriteError):
                            memory_write._validate_status_transition(
                                base_text=base_text,
                                proposal_text=drifted,
                                target_status="pending_verification",
                                evidence_ref="task:quarantine",
                            )

        ordinary_base = markdown(
            "Owner",
            fact_key="project.owner",
            valid_from="2026-07-01",
            body="Alice",
            extra_frontmatter="risk_class: ordinary",
        )
        ordinary_proposal = memory_write._frontmatter_scalar_replacement(
            ordinary_base,
            key="status",
            value="pending_verification",
            allow_insert=False,
        ).replace("risk_class: ordinary", "risk_class: action_sensitive")
        with self.assertRaises(memory_write.MemoryWriteError) as ordinary:
            memory_write._validate_status_transition(
                base_text=ordinary_base,
                proposal_text=ordinary_proposal,
                target_status="pending_verification",
                evidence_ref="task:quarantine",
            )
        self.assertEqual(ordinary.exception.reason_code, "STATUS_TRANSITION_INVALID")

    def test_prepare_status_transition_uses_live_base_for_existing_risk(self) -> None:
        head_text = markdown(
            "Owner",
            fact_key="project.owner",
            valid_from="2026-07-01",
            body="Committed Alice",
            extra_frontmatter="risk_class: action_sensitive",
        )
        live_text = head_text.replace("Committed Alice", "Dirty live Alice")
        malicious_proposal = memory_write._frontmatter_scalar_replacement(
            head_text,
            key="status",
            value="pending_verification",
            allow_insert=False,
        )
        live_proposal = memory_write._frontmatter_scalar_replacement(
            live_text,
            key="status",
            value="pending_verification",
            allow_insert=False,
        )
        live_digest = write_intent.content_hashes(live_text.encode("utf-8"))
        head_digest = write_intent.content_hashes(head_text.encode("utf-8"))
        selected = write_intent.CanonicalTarget(
            path=Path("/private/owner-v1.md"),
            rel_path="项目/owner-v1.md",
            target_key="项目/owner-v1.md".casefold(),
        )

        def request(proposal_text: str) -> dict[str, object]:
            return {
                "schema_version": 2,
                "target_relative_path": selected.rel_path,
                "proposal_markdown": proposal_text,
                "read_token": "e" * 64,
                "app_id": "agent-memory",
                "project_id": "project-a",
                "operation": "status_transition",
                "target_status": "pending_verification",
                "transition_reason": "needs verification",
                "summary": "Quarantine an unverified fact.",
                "source_class": "local_verified",
                "knowledge_kind": "fact",
                "asserted_by": "codex",
                "evidence_ref": "task:status-transition",
            }

        common = (
            mock.patch.object(memory_write, "ACTOR", "codex"),
            mock.patch.object(memory_write, "_formal_target", return_value=selected),
            mock.patch.object(
                memory_write,
                "_scope_request",
                return_value=("agent-memory", "project-a"),
            ),
            mock.patch.object(memory_write, "_validate_writer_markdown", return_value={}),
            mock.patch.object(
                memory_write,
                "_target_snapshot",
                return_value=(True, live_digest, "f" * 40, "e" * 64),
            ),
            mock.patch.object(memory_write, "_validate_write_temporal_gate"),
        )
        with common[0], common[1], common[2], common[3], common[4], common[5], mock.patch.object(
            memory_write.write_intent,
            "git_target_digest_at_commit",
            return_value=(True, head_digest),
        ) as git_base, self.assertRaises(memory_write.MemoryWriteError) as malicious:
            memory_write.prepare(request(malicious_proposal), raw_session_id="session-1")
        self.assertEqual(malicious.exception.reason_code, "STATUS_TRANSITION_INVALID")
        git_base.assert_not_called()

        def stop_after_live_validation(**kwargs: object) -> dict[str, object]:
            self.assertEqual(kwargs["base_text"], live_text)
            self.assertEqual(
                kwargs["validated_status_transition"],
                {"from_status": "active", "target_status": "pending_verification"},
            )
            raise memory_write.MemoryWriteError("TEST_STOP", "live base checked")

        common = (
            mock.patch.object(memory_write, "ACTOR", "codex"),
            mock.patch.object(memory_write, "_formal_target", return_value=selected),
            mock.patch.object(
                memory_write,
                "_scope_request",
                return_value=("agent-memory", "project-a"),
            ),
            mock.patch.object(memory_write, "_validate_writer_markdown", return_value={}),
            mock.patch.object(
                memory_write,
                "_target_snapshot",
                return_value=(True, live_digest, "f" * 40, "e" * 64),
            ),
            mock.patch.object(memory_write, "_validate_write_temporal_gate"),
        )
        with common[0], common[1], common[2], common[3], common[4], common[5], mock.patch.object(
            memory_write.write_intent,
            "git_target_digest_at_commit",
            return_value=(True, head_digest),
        ) as git_base, mock.patch.object(
            memory_write,
            "_validate_temporal_transition",
            side_effect=stop_after_live_validation,
        ), self.assertRaises(memory_write.MemoryWriteError) as valid:
            memory_write.prepare(request(live_proposal), raw_session_id="session-1")
        self.assertEqual(valid.exception.reason_code, "TEST_STOP")
        git_base.assert_not_called()

    def test_prepare_atomic_risk_quarantine_uses_live_crlf_representation(self) -> None:
        head_text = markdown(
            "Owner",
            fact_key="project.owner",
            valid_from="2026-07-01",
            body="Committed Alice",
        )
        live_text = head_text.replace("\n", "\r\n")
        proposal_text = memory_write._frontmatter_scalar_replacement(
            live_text,
            key="status",
            value="pending_verification",
            allow_insert=False,
        )
        proposal_text = memory_write._frontmatter_scalar_replacement(
            proposal_text,
            key="risk_class",
            value="action_sensitive",
            allow_insert=True,
        )
        live_digest = write_intent.content_hashes(live_text.encode("utf-8"))
        head_digest = write_intent.content_hashes(head_text.encode("utf-8"))
        selected = write_intent.CanonicalTarget(
            path=Path("/private/owner-v1.md"),
            rel_path="项目/owner-v1.md",
            target_key="项目/owner-v1.md".casefold(),
        )
        request = {
            "schema_version": 2,
            "target_relative_path": selected.rel_path,
            "proposal_markdown": proposal_text,
            "read_token": "e" * 64,
            "app_id": "agent-memory",
            "project_id": "project-a",
            "operation": "status_transition",
            "target_status": "pending_verification",
            "transition_reason": "needs verification",
            "summary": "Quarantine an unverified fact.",
            "source_class": "local_verified",
            "knowledge_kind": "fact",
            "asserted_by": "codex",
            "evidence_ref": "task:status-transition",
        }

        def stop_after_live_validation(**kwargs: object) -> dict[str, object]:
            self.assertEqual(kwargs["base_text"], live_text)
            self.assertEqual(kwargs["proposal_text"], proposal_text)
            raise memory_write.MemoryWriteError("TEST_STOP", "CRLF live base checked")

        with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
            memory_write, "_formal_target", return_value=selected
        ), mock.patch.object(
            memory_write,
            "_scope_request",
            return_value=("agent-memory", "project-a"),
        ), mock.patch.object(
            memory_write, "_validate_writer_markdown", return_value={}
        ), mock.patch.object(
            memory_write,
            "_target_snapshot",
            return_value=(True, live_digest, "f" * 40, "e" * 64),
        ), mock.patch.object(
            memory_write.write_intent,
            "git_target_digest_at_commit",
            return_value=(True, head_digest),
        ) as git_base, mock.patch.object(
            memory_write, "_validate_write_temporal_gate"
        ), mock.patch.object(
            memory_write,
            "_validate_temporal_transition",
            side_effect=stop_after_live_validation,
        ), self.assertRaises(memory_write.MemoryWriteError) as stopped:
            memory_write.prepare(request, raw_session_id="session-1")
        self.assertEqual(stopped.exception.reason_code, "TEST_STOP")
        git_base.assert_not_called()

    def test_prepare_risk_only_content_update_uses_exact_live_base(self) -> None:
        base_text = markdown(
            "Owner",
            fact_key="project.owner",
            valid_from="2026-07-01",
            status="pending_verification",
            body="Alice",
        )
        proposal_text = memory_write._frontmatter_scalar_replacement(
            base_text,
            key="risk_class",
            value="action_sensitive",
            allow_insert=True,
        )
        base_digest = write_intent.content_hashes(base_text.encode("utf-8"))
        selected = write_intent.CanonicalTarget(
            path=Path("/private/owner-v1.md"),
            rel_path="项目/owner-v1.md",
            target_key="项目/owner-v1.md".casefold(),
        )
        request = {
            "schema_version": 2,
            "target_relative_path": selected.rel_path,
            "proposal_markdown": proposal_text,
            "read_token": "e" * 64,
            "app_id": "agent-memory",
            "project_id": "project-a",
            "operation": "content_update",
            "summary": "Classify one quarantined fact.",
            "source_class": "local_verified",
            "knowledge_kind": "fact",
            "asserted_by": "codex",
            "evidence_ref": "task:risk-classification",
        }

        def stop_after_revalidation(**kwargs: object) -> dict[str, object]:
            self.assertEqual(kwargs["base_text"], base_text)
            raise memory_write.MemoryWriteError("TEST_STOP", "immutable base checked")

        with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
            memory_write, "_formal_target", return_value=selected
        ), mock.patch.object(
            memory_write, "_scope_request", return_value=("agent-memory", "project-a")
        ), mock.patch.object(
            memory_write, "_validate_writer_markdown", return_value={}
        ), mock.patch.object(
            memory_write,
            "_target_snapshot",
            return_value=(True, base_digest, "f" * 40, "e" * 64),
        ), mock.patch.object(
            memory_write.write_intent,
            "git_target_digest_at_commit",
            return_value=(True, base_digest),
        ) as git_base, mock.patch.object(
            memory_write, "_validate_write_temporal_gate"
        ), mock.patch.object(
            memory_write,
            "_validate_temporal_transition",
            side_effect=stop_after_revalidation,
        ), self.assertRaises(memory_write.MemoryWriteError) as stopped:
            memory_write.prepare(request, raw_session_id="session-1")
        self.assertEqual(stopped.exception.reason_code, "TEST_STOP")
        git_base.assert_not_called()

    def test_prepare_untracked_active_adopt_accepts_absent_git_blob(self) -> None:
        proposal_text = markdown(
            "Owner",
            fact_key="project.owner",
            valid_from="2026-07-01",
            body="Externally created Alice",
        )
        proposal_digest = write_intent.content_hashes(proposal_text.encode("utf-8"))
        empty_digest = write_intent.content_hashes(b"")
        selected = write_intent.CanonicalTarget(
            path=Path("/private/owner-v1.md"),
            rel_path="项目/owner-v1.md",
            target_key="项目/owner-v1.md".casefold(),
        )
        request = {
            "schema_version": 2,
            "target_relative_path": selected.rel_path,
            "proposal_markdown": proposal_text,
            "read_token": "e" * 64,
            "app_id": "agent-memory",
            "project_id": "project-a",
            "operation": "content_update",
            "adopt_external": True,
            "summary": "Adopt one externally created active fact.",
            "source_class": "local_verified",
            "knowledge_kind": "fact",
            "asserted_by": "codex",
            "evidence_ref": "task:adopt-untracked",
        }

        def stop_at_dirty_check(*args: object, **kwargs: object) -> bool:
            raise memory_write.MemoryWriteError("TEST_STOP", "untracked adopt reached")

        with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
            memory_write, "_formal_target", return_value=selected
        ), mock.patch.object(
            memory_write,
            "_scope_request",
            return_value=("agent-memory", "project-a"),
        ), mock.patch.object(
            memory_write, "_validate_writer_markdown", return_value={}
        ), mock.patch.object(
            memory_write,
            "_target_snapshot",
            return_value=(True, proposal_digest, "f" * 40, "e" * 64),
        ), mock.patch.object(
            memory_write.write_intent,
            "git_target_digest_at_commit",
            return_value=(False, empty_digest),
        ) as git_base, mock.patch.object(
            memory_write, "_validate_write_temporal_gate"
        ), mock.patch.object(
            memory_write,
            "_validate_temporal_transition",
            return_value={
                "enabled": False,
                "fact_key": "",
                "supersedes": [],
                "fact_status": "",
            },
        ), mock.patch.object(
            memory_write,
            "_external_dirty_against_head",
            side_effect=stop_at_dirty_check,
        ) as dirty_check, self.assertRaises(memory_write.MemoryWriteError) as stopped:
            memory_write.prepare(request, raw_session_id="session-1")
        self.assertEqual(stopped.exception.reason_code, "TEST_STOP")
        git_base.assert_called_once_with("f" * 40, selected)
        dirty_check.assert_called_once_with(selected, proposal_digest, "f" * 40)

    def test_prepare_tracked_crlf_risk_only_adopt_uses_canonical_policy(self) -> None:
        git_text = markdown(
            "Owner",
            fact_key="project.owner",
            valid_from="2026-07-01",
            status="pending_verification",
            body="Alice",
        )
        live_base = git_text.replace("\n", "\r\n")
        proposal_text = memory_write._frontmatter_scalar_replacement(
            live_base,
            key="risk_class",
            value="action_sensitive",
            allow_insert=True,
        )
        git_digest = write_intent.content_hashes(git_text.encode("utf-8"))
        proposal_digest = write_intent.content_hashes(proposal_text.encode("utf-8"))
        selected = write_intent.CanonicalTarget(
            path=Path("/private/owner-v1.md"),
            rel_path="项目/owner-v1.md",
            target_key="项目/owner-v1.md".casefold(),
        )
        request = {
            "schema_version": 2,
            "target_relative_path": selected.rel_path,
            "proposal_markdown": proposal_text,
            "read_token": "e" * 64,
            "app_id": "agent-memory",
            "project_id": "project-a",
            "operation": "content_update",
            "adopt_external": True,
            "summary": "Adopt one externally classified pending fact.",
            "source_class": "local_verified",
            "knowledge_kind": "fact",
            "asserted_by": "codex",
            "evidence_ref": "task:adopt-risk-only",
        }

        def stop_after_canonical_policy(**kwargs: object) -> dict[str, object]:
            self.assertEqual(
                kwargs["base_text"],
                write_intent.canonicalize_text(git_text),
            )
            self.assertEqual(
                kwargs["proposal_text"],
                write_intent.canonicalize_text(proposal_text),
            )
            raise memory_write.MemoryWriteError("TEST_STOP", "canonical policy checked")

        with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
            memory_write, "_formal_target", return_value=selected
        ), mock.patch.object(
            memory_write,
            "_scope_request",
            return_value=("agent-memory", "project-a"),
        ), mock.patch.object(
            memory_write, "_validate_writer_markdown", return_value={}
        ), mock.patch.object(
            memory_write,
            "_target_snapshot",
            return_value=(True, proposal_digest, "f" * 40, "e" * 64),
        ), mock.patch.object(
            memory_write.write_intent,
            "git_target_digest_at_commit",
            return_value=(True, git_digest),
        ), mock.patch.object(
            memory_write, "_validate_write_temporal_gate"
        ), mock.patch.object(
            memory_write,
            "_validate_temporal_transition",
            side_effect=stop_after_canonical_policy,
        ), self.assertRaises(memory_write.MemoryWriteError) as stopped:
            memory_write.prepare(request, raw_session_id="session-1")
        self.assertEqual(stopped.exception.reason_code, "TEST_STOP")

    def test_apply_risk_only_content_update_revalidates_git_base_for_both_paths(self) -> None:
        git_base_text = markdown(
            "Owner",
            fact_key="project.owner",
            valid_from="2026-07-01",
            status="pending_verification",
            body="Alice",
        )
        base_text = git_base_text.replace("\n", "\r\n")
        proposal_text = memory_write._frontmatter_scalar_replacement(
            base_text,
            key="risk_class",
            value="action_sensitive",
            allow_insert=True,
        )
        git_base_digest = write_intent.content_hashes(
            git_base_text.encode("utf-8")
        )
        base_digest = write_intent.content_hashes(base_text.encode("utf-8"))
        proposal_digest = write_intent.content_hashes(proposal_text.encode("utf-8"))
        selected = write_intent.CanonicalTarget(
            path=Path("/private/owner-v1.md"),
            rel_path="项目/owner-v1.md",
            target_key="项目/owner-v1.md".casefold(),
        )
        confirmation_ref = "task:risk-classification"
        stored = {
            "intent_id": "c" * 32,
            "fencing_token": 10,
            "reconcile_action": "UPDATE",
            "operation": "content_update",
            "target_status": "",
            "status": "bound",
            "target_key": selected.target_key,
            "target_rel_path": selected.rel_path,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "base_exists": 1,
            "base_raw_sha256": base_digest.raw_sha256,
            "base_canonical_sha256": base_digest.canonical_sha256,
            "base_git_head": "f" * 40,
            "knowledge_kind": "fact",
            "evidence_ref_sha256": "e" * 64,
            "approved_by": "codex",
            "approval_ref_sha256": hashlib.sha256(
                confirmation_ref.encode("utf-8")
            ).hexdigest(),
            "approval_proposal_raw_sha256": proposal_digest.raw_sha256,
            "approval_proposal_canonical_sha256": proposal_digest.canonical_sha256,
        }
        request = {
            "schema_version": 2,
            "proposal_id": "c" * 32,
            "fencing_token": 10,
            "target_relative_path": selected.rel_path,
            "proposal_markdown": proposal_text,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "confirmed_by": "codex",
            "confirmation_reference": confirmation_ref,
        }

        for case, current_digest, current_head in (
            ("base_matches", base_digest, "f" * 40),
            ("proposal_already_written", proposal_digest, "a" * 40),
        ):
            with self.subTest(case=case):
                def stop_after_revalidation(**kwargs: object) -> dict[str, object]:
                    self.assertEqual(
                        kwargs["base_text"],
                        (
                            base_text
                            if case == "base_matches"
                            else write_intent.canonicalize_text(git_base_text)
                        ),
                    )
                    self.assertEqual(
                        kwargs["proposal_text"],
                        (
                            proposal_text
                            if case == "base_matches"
                            else write_intent.canonicalize_text(proposal_text)
                        ),
                    )
                    raise memory_write.MemoryWriteError("TEST_STOP", "immutable base checked")

                with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
                    memory_write, "_authorized_intent", return_value=stored
                ), mock.patch.object(
                    memory_write, "_formal_target", return_value=selected
                ), mock.patch.object(
                    memory_write,
                    "_intent_scope_binding",
                    return_value=("agent-memory", "project-a"),
                ), mock.patch.object(
                    memory_write, "_validate_writer_markdown", return_value={}
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
                    memory_write, "_claim_matches", return_value=True
                ), mock.patch.object(
                    memory_write, "_target_digest", return_value=(True, current_digest)
                ), mock.patch.object(
                    memory_write.write_intent,
                    "current_git_head",
                    return_value=current_head,
                ), mock.patch.object(
                    memory_write.write_intent,
                    "git_target_digest_at_commit",
                    return_value=(True, git_base_digest),
                ) as git_base, mock.patch.object(
                    memory_write,
                    "_validate_temporal_transition",
                    side_effect=stop_after_revalidation,
                ), self.assertRaises(memory_write.MemoryWriteError) as stopped:
                    memory_write._apply_locked(request, raw_session_id="session-1")
                self.assertEqual(stopped.exception.reason_code, "TEST_STOP")
                self.assertEqual(git_base.call_count, 1)

        with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
            memory_write, "_authorized_intent", return_value=stored
        ), mock.patch.object(
            memory_write, "_formal_target", return_value=selected
        ), mock.patch.object(
            memory_write,
            "_intent_scope_binding",
            return_value=("agent-memory", "project-a"),
        ), mock.patch.object(
            memory_write, "_validate_writer_markdown", return_value={}
        ), mock.patch.object(
            memory_write, "_validate_write_temporal_gate"
        ), mock.patch.object(
            memory_write, "_has_conditional_recovery_sidecar", return_value=False
        ), mock.patch.object(
            memory_write.write_intent,
            "git_target_digest_at_commit",
            return_value=(False, write_intent.content_hashes(b"")),
        ), self.assertRaises(memory_write.MemoryWriteError) as missing:
            memory_write._apply_locked(request, raw_session_id="session-1")
        self.assertEqual(missing.exception.reason_code, "INTENT_BINDING_INVALID")

    def test_apply_tracked_risk_only_adopt_keeps_live_intent_base(self) -> None:
        git_text = markdown(
            "Owner",
            fact_key="project.owner",
            valid_from="2026-07-01",
            status="pending_verification",
            body="Alice",
        )
        live_base = git_text.replace("\n", "\r\n")
        proposal_text = memory_write._frontmatter_scalar_replacement(
            live_base,
            key="risk_class",
            value="action_sensitive",
            allow_insert=True,
        )
        git_digest = write_intent.content_hashes(git_text.encode("utf-8"))
        proposal_digest = write_intent.content_hashes(proposal_text.encode("utf-8"))
        selected = write_intent.CanonicalTarget(
            path=Path("/private/owner-v1.md"),
            rel_path="项目/owner-v1.md",
            target_key="项目/owner-v1.md".casefold(),
        )
        stored = {
            "intent_id": "d" * 32,
            "fencing_token": 11,
            "reconcile_action": "ADOPT",
            "operation": "content_update",
            "target_status": "",
            "status": "bound",
            "target_key": selected.target_key,
            "target_rel_path": selected.rel_path,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            # ADOPT binds the live external proposal, not its prior Git blob.
            "base_exists": 1,
            "base_raw_sha256": proposal_digest.raw_sha256,
            "base_canonical_sha256": proposal_digest.canonical_sha256,
            "base_git_head": "f" * 40,
            "knowledge_kind": "fact",
            "evidence_ref_sha256": "e" * 64,
        }
        request = {
            "schema_version": 2,
            "proposal_id": "d" * 32,
            "fencing_token": 11,
            "target_relative_path": selected.rel_path,
            "proposal_markdown": proposal_text,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
        }

        def stop_after_policy_revalidation(**kwargs: object) -> dict[str, object]:
            self.assertEqual(
                kwargs["base_text"],
                write_intent.canonicalize_text(git_text),
            )
            self.assertEqual(
                kwargs["proposal_text"],
                write_intent.canonicalize_text(proposal_text),
            )
            raise memory_write.MemoryWriteError("TEST_STOP", "adopt policy base checked")

        with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
            memory_write, "_authorized_intent", return_value=stored
        ), mock.patch.object(
            memory_write, "_formal_target", return_value=selected
        ), mock.patch.object(
            memory_write,
            "_intent_scope_binding",
            return_value=("agent-memory", "project-a"),
        ), mock.patch.object(
            memory_write, "_validate_writer_markdown", return_value={}
        ), mock.patch.object(
            memory_write, "_validate_write_temporal_gate"
        ), mock.patch.object(
            memory_write, "_has_conditional_recovery_sidecar", return_value=False
        ), mock.patch.object(
            memory_write.write_intent,
            "git_target_digest_at_commit",
            return_value=(True, git_digest),
        ) as git_base, mock.patch.object(
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
            memory_write, "_target_digest", return_value=(True, proposal_digest)
        ), mock.patch.object(
            memory_write.write_intent,
            "current_git_head",
            return_value="f" * 40,
        ), mock.patch.object(
            memory_write,
            "_validate_temporal_transition",
            side_effect=stop_after_policy_revalidation,
        ), self.assertRaises(memory_write.MemoryWriteError) as stopped:
            memory_write._apply_locked(request, raw_session_id="session-1")
        self.assertEqual(stopped.exception.reason_code, "TEST_STOP")
        self.assertEqual(git_base.call_count, 1)

    def test_apply_status_transition_revalidates_git_base_for_both_recovery_paths(self) -> None:
        git_base_text = markdown(
            "Owner",
            fact_key="project.owner",
            valid_from="2026-07-01",
            body="Alice",
        )
        base_text = git_base_text.replace("\n", "\r\n")
        proposal_text = memory_write._frontmatter_scalar_replacement(
            base_text,
            key="status",
            value="pending_verification",
            allow_insert=False,
        )
        proposal_text = memory_write._frontmatter_scalar_replacement(
            proposal_text,
            key="risk_class",
            value="action_sensitive",
            allow_insert=True,
        )
        git_base_digest = write_intent.content_hashes(
            git_base_text.encode("utf-8")
        )
        base_digest = write_intent.content_hashes(base_text.encode("utf-8"))
        proposal_digest = write_intent.content_hashes(proposal_text.encode("utf-8"))
        selected = write_intent.CanonicalTarget(
            path=Path("/private/owner-v1.md"),
            rel_path="项目/owner-v1.md",
            target_key="项目/owner-v1.md".casefold(),
        )
        stored = {
            "intent_id": "b" * 32,
            "fencing_token": 9,
            "reconcile_action": "UPDATE",
            "operation": "status_transition",
            "target_status": "pending_verification",
            "status": "bound",
            "target_key": selected.target_key,
            "target_rel_path": selected.rel_path,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "base_exists": 1,
            "base_raw_sha256": base_digest.raw_sha256,
            "base_canonical_sha256": base_digest.canonical_sha256,
            "base_git_head": "f" * 40,
            "knowledge_kind": "fact",
            "evidence_ref_sha256": "e" * 64,
        }
        request = {
            "schema_version": 2,
            "proposal_id": "b" * 32,
            "fencing_token": 9,
            "target_relative_path": selected.rel_path,
            "proposal_markdown": proposal_text,
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
        }

        for case, current_digest, current_head in (
            ("base_matches", base_digest, "f" * 40),
            ("proposal_already_written", proposal_digest, "a" * 40),
        ):
            with self.subTest(case=case):
                def stop_after_revalidation(**kwargs: object) -> dict[str, object]:
                    self.assertEqual(
                        kwargs["base_text"],
                        (
                            base_text
                            if case == "base_matches"
                            else write_intent.canonicalize_text(git_base_text)
                        ),
                    )
                    self.assertEqual(
                        kwargs["proposal_text"],
                        (
                            proposal_text
                            if case == "base_matches"
                            else write_intent.canonicalize_text(proposal_text)
                        ),
                    )
                    self.assertEqual(
                        kwargs["validated_status_transition"],
                        {"from_status": "active", "target_status": "pending_verification"},
                    )
                    raise memory_write.MemoryWriteError(
                        "TEST_STOP",
                        "stop after recovery validation",
                    )

                with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
                    memory_write, "_authorized_intent", return_value=stored
                ), mock.patch.object(
                    memory_write, "_formal_target", return_value=selected
                ), mock.patch.object(
                    memory_write,
                    "_intent_scope_binding",
                    return_value=("agent-memory", "project-a"),
                ), mock.patch.object(
                    memory_write, "_validate_writer_markdown", return_value={}
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
                    memory_write, "_target_digest", return_value=(True, current_digest)
                ), mock.patch.object(
                    memory_write.write_intent,
                    "current_git_head",
                    return_value=current_head,
                ), mock.patch.object(
                    memory_write.write_intent,
                    "git_target_digest_at_commit",
                    return_value=(True, git_base_digest),
                ) as git_base, mock.patch.object(
                    memory_write,
                    "_validate_temporal_transition",
                    side_effect=stop_after_revalidation,
                ), self.assertRaises(memory_write.MemoryWriteError) as stopped:
                    memory_write._apply_locked(request, raw_session_id="session-1")
                self.assertEqual(stopped.exception.reason_code, "TEST_STOP")
                self.assertEqual(
                    git_base.call_count,
                    0 if case == "base_matches" else 1,
                )

    def test_apply_status_transition_rejects_head_proposal_over_dirty_live_base(self) -> None:
        head_text = markdown(
            "Owner",
            fact_key="project.owner",
            valid_from="2026-07-01",
            body="Committed Alice",
            extra_frontmatter="risk_class: action_sensitive",
        )
        live_text = head_text.replace("Committed Alice", "Dirty live Alice")
        malicious_proposal = memory_write._frontmatter_scalar_replacement(
            head_text,
            key="status",
            value="pending_verification",
            allow_insert=False,
        )
        live_proposal = memory_write._frontmatter_scalar_replacement(
            live_text,
            key="status",
            value="pending_verification",
            allow_insert=False,
        )
        head_digest = write_intent.content_hashes(head_text.encode("utf-8"))
        live_digest = write_intent.content_hashes(live_text.encode("utf-8"))
        selected = write_intent.CanonicalTarget(
            path=Path("/private/owner-v1.md"),
            rel_path="项目/owner-v1.md",
            target_key="项目/owner-v1.md".casefold(),
        )

        for case, proposal_text, expected_reason in (
            ("head_based", malicious_proposal, "STATUS_TRANSITION_INVALID"),
            ("live_based", live_proposal, "TEST_STOP"),
        ):
            with self.subTest(case=case):
                proposal_digest = write_intent.content_hashes(
                    proposal_text.encode("utf-8")
                )
                stored = {
                    "intent_id": "e" * 32,
                    "fencing_token": 12,
                    "reconcile_action": "UPDATE",
                    "operation": "status_transition",
                    "target_status": "pending_verification",
                    "status": "bound",
                    "target_key": selected.target_key,
                    "target_rel_path": selected.rel_path,
                    "proposal_raw_sha256": proposal_digest.raw_sha256,
                    "proposal_canonical_sha256": proposal_digest.canonical_sha256,
                    "base_exists": 1,
                    "base_raw_sha256": live_digest.raw_sha256,
                    "base_canonical_sha256": live_digest.canonical_sha256,
                    "base_git_head": "f" * 40,
                    "knowledge_kind": "fact",
                    "evidence_ref_sha256": "e" * 64,
                }
                request = {
                    "schema_version": 2,
                    "proposal_id": "e" * 32,
                    "fencing_token": 12,
                    "target_relative_path": selected.rel_path,
                    "proposal_markdown": proposal_text,
                    "proposal_raw_sha256": proposal_digest.raw_sha256,
                    "proposal_canonical_sha256": proposal_digest.canonical_sha256,
                }

                def stop_after_live_validation(**kwargs: object) -> dict[str, object]:
                    self.assertEqual(kwargs["base_text"], live_text)
                    self.assertEqual(kwargs["proposal_text"], live_proposal)
                    raise memory_write.MemoryWriteError("TEST_STOP", "live base checked")

                with mock.patch.object(memory_write, "ACTOR", "codex"), mock.patch.object(
                    memory_write, "_authorized_intent", return_value=stored
                ), mock.patch.object(
                    memory_write, "_formal_target", return_value=selected
                ), mock.patch.object(
                    memory_write,
                    "_intent_scope_binding",
                    return_value=("agent-memory", "project-a"),
                ), mock.patch.object(
                    memory_write, "_validate_writer_markdown", return_value={}
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
                    memory_write, "_target_digest", return_value=(True, live_digest)
                ), mock.patch.object(
                    memory_write.write_intent,
                    "current_git_head",
                    return_value="f" * 40,
                ), mock.patch.object(
                    memory_write.write_intent,
                    "git_target_digest_at_commit",
                    return_value=(True, head_digest),
                ) as git_base, mock.patch.object(
                    memory_write,
                    "_validate_temporal_transition",
                    side_effect=stop_after_live_validation,
                ), mock.patch.object(
                    memory_write, "_atomic_conditional_write"
                ) as write_target, self.assertRaises(
                    memory_write.MemoryWriteError
                ) as stopped:
                    memory_write._apply_locked(request, raw_session_id="session-1")
                self.assertEqual(stopped.exception.reason_code, expected_reason)
                git_base.assert_not_called()
                write_target.assert_not_called()

    def test_metadata_only_fact_deactivation_becomes_historical(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v1.md",
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                for base_status, status in (
                    ("active", "pending_verification"),
                    ("active", "outdated"),
                    ("active", "archived"),
                    ("pending_verification", "outdated"),
                    ("pending_verification", "archived"),
                    ("outdated", "archived"),
                ):
                    with self.subTest(base_status=base_status, status=status):
                        base_text = markdown(
                            "Owner",
                            fact_key="project.owner",
                            valid_from="2026-07-01",
                            status=base_status,
                            body="Alice",
                        )
                        proposal_text = markdown(
                            "Owner",
                            fact_key="project.owner",
                            valid_from="2026-07-01",
                            status=status,
                            body="Alice",
                        )
                        transition = memory_write._validate_status_transition(
                            base_text=base_text,
                            proposal_text=proposal_text,
                            target_status=status,
                            evidence_ref="",
                        )
                        result = memory_write._validate_temporal_transition(
                            selected_target=selected,
                            base_text=base_text,
                            proposal_text=proposal_text,
                            operation="status_transition",
                            validated_status_transition=transition,
                        )
                        self.assertEqual(result["fact_status"], "historical")

    def test_deactivated_successor_keeps_predecessor_superseded_and_no_current(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            predecessor = vault / "项目" / "owner-v1.md"
            predecessor.write_text(
                markdown(
                    "Owner v1",
                    fact_key="project.owner",
                    valid_from="2026-07-01",
                    body="Alice",
                ),
                encoding="utf-8",
            )
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v2.md",
                rel_path="项目/owner-v2.md",
                target_key="项目/owner-v2.md".casefold(),
            )
            base_text = markdown(
                "Owner v2",
                fact_key="project.owner",
                valid_from="2026-08-01",
                supersedes="项目/owner-v1.md",
                body="Bob",
            )
            proposal_text = markdown(
                "Owner v2",
                fact_key="project.owner",
                valid_from="2026-08-01",
                supersedes="项目/owner-v1.md",
                status="pending_verification",
                body="Bob",
            )
            transition = memory_write._validate_status_transition(
                base_text=base_text,
                proposal_text=proposal_text,
                target_status="pending_verification",
                evidence_ref="",
            )
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                result = memory_write._validate_temporal_transition(
                    selected_target=selected,
                    base_text=base_text,
                    proposal_text=proposal_text,
                    operation="status_transition",
                    validated_status_transition=transition,
                )
            self.assertEqual(result["fact_status"], "historical")

    def test_historical_content_update_and_old_fact_reactivation_remain_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v1.md",
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )
            pending = markdown(
                "Owner v1",
                fact_key="project.owner",
                valid_from="2026-07-01",
                status="pending_verification",
                body="Alice",
            )
            (vault / "项目" / "owner-v2.md").write_text(
                markdown(
                    "Owner v2",
                    fact_key="project.owner",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                    body="Bob",
                ),
                encoding="utf-8",
            )
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                with self.assertRaises(memory_write.MemoryWriteError) as historical_update:
                    memory_write._validate_temporal_transition(
                        selected_target=selected,
                        base_text=pending,
                        proposal_text=pending,
                        operation="content_update",
                    )
                self.assertEqual(
                    historical_update.exception.reason_code,
                    "TEMPORAL_RELATION_INVALID",
                )

                reactivated = markdown(
                    "Owner v1",
                    fact_key="project.owner",
                    valid_from="2026-07-01",
                    verified_at="2026-08-26",
                    status="active",
                    body="Alice",
                )
                transition = memory_write._validate_status_transition(
                    base_text=pending,
                    proposal_text=reactivated,
                    target_status="active",
                    evidence_ref="task:live-verification",
                )
                with self.assertRaises(memory_write.MemoryWriteError) as old_fact:
                    memory_write._validate_temporal_transition(
                        selected_target=selected,
                        base_text=pending,
                        proposal_text=reactivated,
                        operation="status_transition",
                        validated_status_transition=transition,
                    )
                self.assertEqual(old_fact.exception.reason_code, "TEMPORAL_RELATION_INVALID")

    def test_pending_fact_allows_only_exact_risk_upgrade_latest_or_superseded(self) -> None:
        for case, risk_line, with_successor, expected_status in (
            ("latest_missing", "", False, "historical"),
            ("superseded_blank", "risk_class:   ", True, "superseded"),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw_root:
                vault = Path(raw_root)
                (vault / "项目").mkdir()
                selected = write_intent.CanonicalTarget(
                    path=vault / "项目" / "owner-v1.md",
                    rel_path="项目/owner-v1.md",
                    target_key="项目/owner-v1.md".casefold(),
                )
                base_text = markdown(
                    "Owner v1",
                    fact_key="project.owner",
                    valid_from="2026-07-01",
                    status="pending_verification",
                    body="Alice",
                    extra_frontmatter=risk_line,
                )
                proposal_text = memory_write._frontmatter_scalar_replacement(
                    base_text,
                    key="risk_class",
                    value="action_sensitive",
                    allow_insert=not bool(risk_line),
                )
                if with_successor:
                    (vault / "项目" / "owner-v2.md").write_text(
                        markdown(
                            "Owner v2",
                            fact_key="project.owner",
                            valid_from="2026-08-01",
                            supersedes="项目/owner-v1.md",
                            status="pending_verification",
                            body="Bob",
                            extra_frontmatter="risk_class: action_sensitive",
                        ),
                        encoding="utf-8",
                    )
                with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                    result = memory_write._validate_temporal_transition(
                        selected_target=selected,
                        base_text=base_text,
                        proposal_text=proposal_text,
                        operation="content_update",
                    )
                self.assertEqual(result["fact_status"], expected_status)

    def test_pending_fact_risk_only_update_rejects_every_other_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v1.md",
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )
            predecessor = vault / "项目" / "owner-v0.md"
            predecessor.write_text(
                markdown(
                    "Owner v0",
                    fact_key="project.owner",
                    valid_from="2026-06-01",
                    status="pending_verification",
                    body="Before Alice",
                    extra_frontmatter="risk_class: action_sensitive",
                ),
                encoding="utf-8",
            )
            base_text = markdown(
                "Owner v1",
                fact_key="project.owner",
                valid_from="2026-07-01",
                supersedes="项目/owner-v0.md",
                valid_until="2026-12-31",
                verified_at="2026-07-02",
                status="pending_verification",
                body="Alice",
            )
            exact = memory_write._frontmatter_scalar_replacement(
                base_text,
                key="risk_class",
                value="action_sensitive",
                allow_insert=True,
            )
            drifts = {
                "body": exact.replace("Alice", "Mallory"),
                "status": exact.replace(
                    "status: pending_verification",
                    "status: outdated",
                ),
                "scope": exact.replace("project-a", "project-b"),
                "valid_from": exact.replace("valid_from: 2026-07-01", "valid_from: 2026-07-03"),
                "valid_until": exact.replace("valid_until: 2026-12-31", "valid_until: 2027-01-01"),
                "relation": exact.replace(
                    "supersedes: [项目/owner-v0.md]",
                    "supersedes: []",
                ),
                "verified_at": exact.replace(
                    "verified_at: 2026-07-02",
                    "verified_at: 2026-07-03",
                ),
                "risk_value": exact.replace(
                    "risk_class: action_sensitive",
                    "risk_class: ordinary",
                ),
                "extra_frontmatter": exact.replace(
                    "risk_class: action_sensitive\n",
                    "risk_class: action_sensitive\nsensitivity: private\n",
                ),
            }
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                for case, proposal_text in drifts.items():
                    with self.subTest(case=case):
                        with self.assertRaises(memory_write.MemoryWriteError):
                            memory_write._content_update_status(
                                base_text=base_text,
                                proposal_text=proposal_text,
                                base_exists=True,
                            )
                            memory_write._validate_temporal_transition(
                                selected_target=selected,
                                base_text=base_text,
                                proposal_text=proposal_text,
                                operation="content_update",
                            )

            ordinary_base = base_text.replace(
                "status: pending_verification\n",
                "status: pending_verification\nrisk_class: ordinary\n",
            )
            ordinary_proposal = ordinary_base.replace(
                "risk_class: ordinary",
                "risk_class: action_sensitive",
            )
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                with self.assertRaises(memory_write.MemoryWriteError) as ordinary:
                    memory_write._validate_temporal_transition(
                        selected_target=selected,
                        base_text=ordinary_base,
                        proposal_text=ordinary_proposal,
                        operation="content_update",
                    )
            self.assertEqual(ordinary.exception.reason_code, "TEMPORAL_RELATION_INVALID")

    def test_new_fact_must_explicitly_supersede_existing_head(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            old = vault / "项目" / "owner-v1.md"
            old.write_text(
                markdown("Old", fact_key="project.owner", valid_from="2026-07-01", body="Alice"),
                encoding="utf-8",
            )
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v2.md",
                rel_path="项目/owner-v2.md",
                target_key="项目/owner-v2.md".casefold(),
            )
            no_edge = markdown("New", fact_key="project.owner", valid_from="2026-08-01", body="Bob")
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                with self.assertRaises(memory_write.MemoryWriteError) as caught:
                    memory_write._validate_temporal_transition(
                        selected_target=selected,
                        base_text="",
                        proposal_text=no_edge,
                    )
                self.assertEqual(caught.exception.reason_code, "TEMPORAL_RELATION_INVALID")

                valid = markdown(
                    "New",
                    fact_key="project.owner",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                    body="Bob",
                )
                result = memory_write._validate_temporal_transition(
                    selected_target=selected,
                    base_text="",
                    proposal_text=valid,
                )
            self.assertTrue(result["enabled"])
            self.assertEqual(result["fact_status"], "current")

    def test_existing_fact_body_cannot_be_changed_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v1.md",
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )
            base_text = markdown(
                "Owner",
                fact_key="project.owner",
                valid_from="2026-07-01",
                body="Alice",
            )
            proposal_text = markdown(
                "Owner",
                fact_key="project.owner",
                valid_from="2026-07-01",
                body="Bob",
            )
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                with self.assertRaises(memory_write.MemoryWriteError) as caught:
                    memory_write._validate_temporal_transition(
                        selected_target=selected,
                        base_text=base_text,
                        proposal_text=proposal_text,
                    )
            self.assertEqual(caught.exception.reason_code, "FACT_VALUE_CHANGE_FORBIDDEN")

    def test_current_fact_mixed_newlines_reject_body_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v1.md",
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )
            base_text = mixed_newline_markdown("Owner", body="Alice")
            proposal_text = mixed_newline_markdown("Owner", body="Mallory")
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                with self.assertRaises(memory_write.MemoryWriteError) as caught:
                    memory_write._validate_temporal_transition(
                        selected_target=selected,
                        base_text=base_text,
                        proposal_text=proposal_text,
                    )
            self.assertEqual(caught.exception.reason_code, "FACT_VALUE_CHANGE_FORBIDDEN")

    def test_current_fact_mixed_newlines_preserve_identical_raw_body(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v1.md",
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )
            base_text = mixed_newline_markdown("Owner", body="Alice")
            proposal_text = mixed_newline_markdown(
                "Owner",
                body="Alice",
                extra_frontmatter="temporal_policy: snapshot",
            )
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                result = memory_write._validate_temporal_transition(
                    selected_target=selected,
                    base_text=base_text,
                    proposal_text=proposal_text,
                )
            self.assertEqual(result["fact_status"], "current")

    def test_temporal_fact_missing_or_malformed_closing_fence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v1.md",
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )
            base_text = mixed_newline_markdown("Owner", body="Alice")
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                for case, closing_fence in (
                    ("missing", ""),
                    ("malformed", "--- trailing text"),
                ):
                    with self.subTest(case=case):
                        proposal_text = mixed_newline_markdown(
                            "Owner",
                            body="Mallory",
                            closing_fence=closing_fence,
                        )
                        with self.assertRaises(memory_write.MemoryWriteError) as caught:
                            memory_write._validate_temporal_transition(
                                selected_target=selected,
                                base_text=base_text,
                                proposal_text=proposal_text,
                            )
                        self.assertEqual(caught.exception.reason_code, "FRONTMATTER_INVALID")

    def test_superseded_fact_allows_metadata_only_governance_preservation(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v1.md",
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )
            base_text = markdown(
                "Owner v1",
                fact_key="project.owner",
                valid_from="2026-07-01",
                valid_until="2026-12-31",
                verified_at="2026-07-02",
                body="Alice",
            )
            proposal_text = markdown(
                "Owner v1",
                fact_key="project.owner",
                valid_from="2026-07-01",
                valid_until="2026-12-31",
                verified_at="2026-07-02",
                body="Alice",
                extra_frontmatter=(
                    "memory_id: 018f2dd8-60d1-7bd4-84db-49e6b8262a1a\n"
                    "temporal_policy: snapshot"
                ),
            )
            (vault / "项目" / "owner-v2.md").write_text(
                markdown(
                    "Owner v2",
                    fact_key="project.owner",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                    body="Bob",
                ),
                encoding="utf-8",
            )
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                result = memory_write._validate_temporal_transition(
                    selected_target=selected,
                    base_text=base_text,
                    proposal_text=proposal_text,
                    operation="governance_migration",
                )
            self.assertTrue(result["enabled"])
            self.assertEqual(result["fact_status"], "superseded")

    def test_superseded_metadata_preservation_is_disabled_for_ordinary_operations(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v1.md",
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )
            base_text = markdown(
                "Owner v1",
                fact_key="project.owner",
                valid_from="2026-07-01",
                body="Alice",
            )
            proposal_text = markdown(
                "Owner v1",
                fact_key="project.owner",
                valid_from="2026-07-01",
                body="Alice",
                extra_frontmatter="temporal_policy: snapshot",
            )
            (vault / "项目" / "owner-v2.md").write_text(
                markdown(
                    "Owner v2",
                    fact_key="project.owner",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                    body="Bob",
                ),
                encoding="utf-8",
            )
            call = {
                "selected_target": selected,
                "base_text": base_text,
                "proposal_text": proposal_text,
            }
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                with self.assertRaises(memory_write.MemoryWriteError) as default_caught:
                    memory_write._validate_temporal_transition(**call)
                self.assertEqual(
                    default_caught.exception.reason_code,
                    "TEMPORAL_RELATION_INVALID",
                )
                for operation in ("content_update", "status_transition"):
                    with self.subTest(operation=operation):
                        with self.assertRaises(memory_write.MemoryWriteError) as caught:
                            memory_write._validate_temporal_transition(
                                **call,
                                operation=operation,
                            )
                        self.assertEqual(
                            caught.exception.reason_code,
                            "TEMPORAL_RELATION_INVALID",
                        )

    def test_superseded_crlf_fact_allows_exact_governance_metadata_transform(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v1.md",
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )
            base_text = markdown(
                "Owner v1",
                fact_key="project.owner",
                valid_from="2026-07-01",
                body="Alice\nSecond line",
            ).replace("\n", "\r\n")
            proposal_text = markdown(
                "Owner v1",
                fact_key="project.owner",
                valid_from="2026-07-01",
                body="Alice\nSecond line",
                extra_frontmatter=(
                    "memory_id: 018f2dd8-60d1-7bd4-84db-49e6b8262a1a\n"
                    "temporal_policy: snapshot"
                ),
            ).replace("\n", "\r\n")
            successor = markdown(
                "Owner v2",
                fact_key="project.owner",
                valid_from="2026-08-01",
                supersedes="项目/owner-v1.md",
                body="Bob",
            ).replace("\n", "\r\n")
            (vault / "项目" / "owner-v2.md").write_text(successor, encoding="utf-8")
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                result = memory_write._validate_temporal_transition(
                    selected_target=selected,
                    base_text=base_text,
                    proposal_text=proposal_text,
                    operation="governance_migration",
                )
            self.assertEqual(result["fact_status"], "superseded")

    def test_superseded_crlf_fact_rejects_body_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v1.md",
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )
            base_text = markdown(
                "Owner v1",
                fact_key="project.owner",
                valid_from="2026-07-01",
                body="Alice\nSecond line",
            ).replace("\n", "\r\n")
            proposal_text = markdown(
                "Owner v1",
                fact_key="project.owner",
                valid_from="2026-07-01",
                body="Mallory\nSecond line",
                extra_frontmatter="temporal_policy: snapshot",
            ).replace("\n", "\r\n")
            (vault / "项目" / "owner-v2.md").write_text(
                markdown(
                    "Owner v2",
                    fact_key="project.owner",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                    body="Bob",
                ).replace("\n", "\r\n"),
                encoding="utf-8",
            )
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                with self.assertRaises(memory_write.MemoryWriteError) as caught:
                    memory_write._validate_temporal_transition(
                        selected_target=selected,
                        base_text=base_text,
                        proposal_text=proposal_text,
                        operation="governance_migration",
                    )
            self.assertEqual(caught.exception.reason_code, "FACT_VALUE_CHANGE_FORBIDDEN")

    def test_superseded_metadata_preservation_rejects_semantic_or_scope_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v1.md",
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )
            base_text = markdown(
                "Owner v1",
                fact_key="project.owner",
                valid_from="2026-07-01",
                valid_until="2026-12-31",
                verified_at="2026-07-02",
                body="Alice",
            )
            (vault / "项目" / "owner-v2.md").write_text(
                markdown(
                    "Owner v2",
                    fact_key="project.owner",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                    body="Bob",
                ),
                encoding="utf-8",
            )
            proposals = {
                "valid_until": markdown(
                    "Owner v1",
                    fact_key="project.owner",
                    valid_from="2026-07-01",
                    valid_until="2027-01-31",
                    verified_at="2026-07-02",
                    body="Alice",
                ),
                "verified_at": markdown(
                    "Owner v1",
                    fact_key="project.owner",
                    valid_from="2026-07-01",
                    valid_until="2026-12-31",
                    verified_at="2026-07-03",
                    body="Alice",
                ),
                "scope": markdown(
                    "Owner v1",
                    fact_key="project.owner",
                    valid_from="2026-07-01",
                    valid_until="2026-12-31",
                    verified_at="2026-07-02",
                    project_id="project-b",
                    body="Alice",
                ),
                "value": markdown(
                    "Owner v1",
                    fact_key="project.owner",
                    valid_from="2026-07-01",
                    valid_until="2026-12-31",
                    verified_at="2026-07-02",
                    body="Mallory",
                ),
                "status": markdown(
                    "Owner v1",
                    fact_key="project.owner",
                    valid_from="2026-07-01",
                    valid_until="2026-12-31",
                    verified_at="2026-07-02",
                    status="pending_verification",
                    body="Alice",
                ),
            }
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                for case, proposal_text in proposals.items():
                    with self.subTest(case=case):
                        with self.assertRaises(memory_write.MemoryWriteError):
                            memory_write._validate_temporal_transition(
                                selected_target=selected,
                                base_text=base_text,
                                proposal_text=proposal_text,
                                operation="governance_migration",
                            )

    def test_superseded_metadata_preservation_rejects_relation_addition_and_removal(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root)
            (vault / "项目").mkdir()
            selected = write_intent.CanonicalTarget(
                path=vault / "项目" / "owner-v1.md",
                rel_path="项目/owner-v1.md",
                target_key="项目/owner-v1.md".casefold(),
            )
            predecessor = vault / "项目" / "owner-v0.md"
            predecessor.write_text(
                markdown(
                    "Owner v0",
                    fact_key="project.owner",
                    valid_from="2026-06-01",
                    status="archived",
                    body="Before Alice",
                ),
                encoding="utf-8",
            )
            (vault / "项目" / "owner-v2.md").write_text(
                markdown(
                    "Owner v2",
                    fact_key="project.owner",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                    body="Bob",
                ),
                encoding="utf-8",
            )
            without_edge = markdown(
                "Owner v1",
                fact_key="project.owner",
                valid_from="2026-07-01",
                body="Alice",
            )
            with_edge = markdown(
                "Owner v1",
                fact_key="project.owner",
                valid_from="2026-07-01",
                supersedes="项目/owner-v0.md",
                body="Alice",
            )
            with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                for case, base_text, proposal_text in (
                    ("add", without_edge, with_edge),
                    ("remove", with_edge, without_edge),
                ):
                    with self.subTest(case=case):
                        with self.assertRaises(memory_write.MemoryWriteError):
                            memory_write._validate_temporal_transition(
                                selected_target=selected,
                                base_text=base_text,
                                proposal_text=proposal_text,
                                operation="governance_migration",
                            )

    def test_superseded_metadata_preservation_rejects_conflict_and_invalid_relation(self) -> None:
        for case in ("conflict", "invalid"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw_root:
                vault = Path(raw_root)
                (vault / "项目").mkdir()
                selected = write_intent.CanonicalTarget(
                    path=vault / "项目" / "owner-v1.md",
                    rel_path="项目/owner-v1.md",
                    target_key="项目/owner-v1.md".casefold(),
                )
                base_text = markdown(
                    "Owner v1",
                    fact_key="project.owner",
                    valid_from="2026-07-01",
                    body="Alice",
                )
                proposal_text = markdown(
                    "Owner v1",
                    fact_key="project.owner",
                    valid_from="2026-07-01",
                    body="Alice",
                    extra_frontmatter="temporal_policy: snapshot",
                )
                successor_project = "project-b" if case == "invalid" else "project-a"
                (vault / "项目" / "owner-v2.md").write_text(
                    markdown(
                        "Owner v2",
                        fact_key="project.owner",
                        valid_from="2026-08-01",
                        supersedes="项目/owner-v1.md",
                        project_id=successor_project,
                        body="Bob",
                    ),
                    encoding="utf-8",
                )
                if case == "conflict":
                    (vault / "项目" / "owner-other.md").write_text(
                        markdown(
                            "Owner other",
                            fact_key="project.owner",
                            valid_from="2026-07-15",
                            body="Carol",
                        ),
                        encoding="utf-8",
                    )
                with mock.patch.object(write_intent, "VAULT_ROOT", vault):
                    with self.assertRaises(memory_write.MemoryWriteError) as caught:
                        memory_write._validate_temporal_transition(
                            selected_target=selected,
                            base_text=base_text,
                            proposal_text=proposal_text,
                            operation="governance_migration",
                        )
                self.assertEqual(caught.exception.reason_code, "TEMPORAL_RELATION_INVALID")

    def test_natural_language_does_not_create_a_supersession_edge(self) -> None:
        meta = memory_index.fact_metadata(
            {"fact_key": "project.owner", "valid_from": "2026-08-01"}
        )
        self.assertEqual(meta["supersedes"], [])


class TemporalRetrieveTests(unittest.TestCase):
    def retrieve_lineage_scenario(
        self,
        *,
        old_status: str,
        new_status: str,
        include_inactive: bool = False,
    ) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            vault = root / "vault"
            state_db = root / "state.sqlite"
            (vault / "项目").mkdir(parents=True)
            old = vault / "项目" / "owner-v1.md"
            new = vault / "项目" / "owner-v2.md"
            old.write_text(
                markdown(
                    "Old",
                    fact_key="project.owner",
                    valid_from="2026-07-01",
                    status=old_status,
                    body="Alice retrievalprobe",
                ),
                encoding="utf-8",
            )
            new.write_text(
                markdown(
                    "New",
                    fact_key="project.owner",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                    status=new_status,
                    body="Bob retrievalprobe",
                ),
                encoding="utf-8",
            )
            conn = sqlite3.connect(state_db)
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
            indexed_at = "2026-08-26T00:00:00+00:00"
            with mock.patch.object(memory_index, "VAULT_ROOT", vault):
                for path in (old, new):
                    doc, loops = memory_index.load_doc(path, indexed_at)
                    memory_index.upsert_doc(conn, doc)
                    memory_index.insert_fts(conn, doc)
                    self.assertEqual(loops, [])
                memory_index._rebuild_supersessions(conn, indexed_at)
            conn.commit()
            conn.close()
            state_db.chmod(0o600)
            candidates = [
                memory_retrieve.Candidate(str(old), "项目/owner-v1.md", 1),
                memory_retrieve.Candidate(str(new), "项目/owner-v2.md", 2),
            ]
            with mock.patch.object(memory_retrieve, "VAULT_ROOT", vault), mock.patch.object(
                memory_retrieve, "GIT_ROOT", vault
            ), mock.patch.object(memory_index, "VAULT_ROOT", vault), mock.patch.object(
                write_intent, "VAULT_ROOT", vault
            ), mock.patch.object(memory_search, "STATE_DB", state_db), mock.patch.object(
                memory_search, "assert_runtime_ready", return_value=None
            ), mock.patch.object(
                memory_retrieve, "current_git_head", return_value=("a" * 40, None)
            ):
                return memory_retrieve.retrieve(
                    actor="codex",
                    app_id="agent-memory",
                    project_id="project-a",
                    query="retrievalprobe",
                    max_results=5,
                    max_file_bytes=128_000,
                    max_total_bytes=256_000,
                    max_excerpt_bytes=8_000,
                    candidates=candidates,
                    as_of=dt.date.today().isoformat(),
                    include_inactive=include_inactive,
                    _observation_capability=memory_retrieve._SYNTHETIC_BENCHMARK_CAPABILITY,
                )

    def test_canonical_retrieve_never_resurrects_old_fact_behind_pending_successor(self) -> None:
        payload = self.retrieve_lineage_scenario(
            old_status="active",
            new_status="pending_verification",
        )
        self.assertEqual(
            [item["relative_path"] for item in payload["results"]],
            ["项目/owner-v2.md"],
            payload,
        )
        item = payload["results"][0]
        self.assertEqual(item["fact_status"], "historical")
        self.assertEqual(item["current_fact_path"], "")
        self.assertFalse(item["can_authorize_action"])
        self.assertIn("inactive_or_historical_memory", item["policy"]["warnings"])
        self.assertTrue(
            any(
                warning.get("relative_path") == "项目/owner-v1.md"
                and warning.get("reason") == "FACT_SUPERSEDED"
                for warning in payload["warnings"]
            )
        )

    def test_canonical_retrieve_all_pending_returns_only_latest_non_authorizing_fact(self) -> None:
        payload = self.retrieve_lineage_scenario(
            old_status="pending_verification",
            new_status="pending_verification",
        )
        self.assertEqual(
            [item["relative_path"] for item in payload["results"]],
            ["项目/owner-v2.md"],
            payload,
        )
        item = payload["results"][0]
        self.assertEqual(item["fact_status"], "historical")
        self.assertEqual(item["current_fact_path"], "")
        self.assertFalse(item["can_authorize_action"])
        self.assertTrue(
            any(
                warning.get("relative_path") == "项目/owner-v1.md"
                and warning.get("reason") == "FACT_SUPERSEDED"
                for warning in payload["warnings"]
            )
        )

    def test_canonical_retrieve_outdated_and_archived_lineage_requires_include_inactive(self) -> None:
        for successor_status in ("outdated", "archived"):
            with self.subTest(status=successor_status):
                default = self.retrieve_lineage_scenario(
                    old_status="active",
                    new_status=successor_status,
                )
                self.assertEqual(default["results"], [], default)
                history = self.retrieve_lineage_scenario(
                    old_status="active",
                    new_status=successor_status,
                    include_inactive=True,
                )
                self.assertEqual(
                    [item["relative_path"] for item in history["results"]],
                    ["项目/owner-v2.md"],
                    history,
                )
                item = history["results"][0]
                self.assertEqual(item["fact_status"], "historical")
                self.assertEqual(item["current_fact_path"], "")
                self.assertFalse(item["can_authorize_action"])

    def test_canonical_retrieve_rejects_superseded_fact_and_supports_as_of(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            vault = root / "vault"
            state_db = root / "state.sqlite"
            (vault / "项目").mkdir(parents=True)
            old = vault / "项目" / "owner-v1.md"
            new = vault / "项目" / "owner-v2.md"
            old.write_text(
                markdown("Old", fact_key="project.owner", valid_from="2026-07-01", body="Alice retrievalprobe"),
                encoding="utf-8",
            )
            new.write_text(
                markdown(
                    "New",
                    fact_key="project.owner",
                    valid_from="2026-08-01",
                    supersedes="项目/owner-v1.md",
                    body="Bob retrievalprobe",
                ),
                encoding="utf-8",
            )
            conn = sqlite3.connect(state_db)
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
            indexed_at = "2026-08-12T00:00:00+00:00"
            with mock.patch.object(memory_index, "VAULT_ROOT", vault):
                for path in (old, new):
                    doc, loops = memory_index.load_doc(path, indexed_at)
                    memory_index.upsert_doc(conn, doc)
                    memory_index.insert_fts(conn, doc)
                    self.assertEqual(loops, [])
                memory_index._rebuild_supersessions(conn, indexed_at)
            conn.commit()
            conn.close()
            state_db.chmod(0o600)
            candidates = [
                memory_retrieve.Candidate(str(old), "项目/owner-v1.md", 1),
                memory_retrieve.Candidate(str(new), "项目/owner-v2.md", 2),
            ]
            with mock.patch.object(memory_index, "VAULT_ROOT", vault):
                parsed_metadata = memory_retrieve._metadata_for(
                    new,
                    memory_retrieve._frontmatter_text(new.read_text(encoding="utf-8")),
                )
            self.assertEqual(parsed_metadata["fact_key"], "project.owner")
            patches = (
                mock.patch.object(memory_retrieve, "VAULT_ROOT", vault),
                mock.patch.object(memory_retrieve, "GIT_ROOT", vault),
                mock.patch.object(memory_index, "VAULT_ROOT", vault),
                mock.patch.object(write_intent, "VAULT_ROOT", vault),
                mock.patch.object(memory_search, "STATE_DB", state_db),
                mock.patch.object(memory_search, "assert_runtime_ready", return_value=None),
                mock.patch.object(memory_retrieve, "current_git_head", return_value=("a" * 40, None)),
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                current = memory_retrieve.retrieve(
                    actor="codex",
                    app_id="agent-memory",
                    project_id="project-a",
                    query="retrievalprobe",
                    max_results=5,
                    max_file_bytes=128_000,
                    max_total_bytes=256_000,
                    max_excerpt_bytes=8_000,
                    candidates=candidates,
                    as_of="2026-08-12",
                )
                historical = memory_retrieve.retrieve(
                    actor="codex",
                    app_id="agent-memory",
                    project_id="project-a",
                    query="retrievalprobe",
                    max_results=5,
                    max_file_bytes=128_000,
                    max_total_bytes=256_000,
                    max_excerpt_bytes=8_000,
                    candidates=candidates,
                    as_of="2026-07-15",
                )
                discovered_historical = memory_retrieve.retrieve(
                    actor="codex",
                    app_id="agent-memory",
                    project_id="project-a",
                    query="retrievalprobe",
                    max_results=5,
                    max_file_bytes=128_000,
                    max_total_bytes=256_000,
                    max_excerpt_bytes=8_000,
                    as_of="2026-07-15",
                )
            self.assertEqual(
                [item["relative_path"] for item in current["results"]],
                ["项目/owner-v2.md"],
                current,
            )
            self.assertEqual(current["results"][0]["fact_status"], "current")
            self.assertTrue(any(item.get("reason") == "FACT_SUPERSEDED" for item in current["warnings"]))
            self.assertEqual([item["relative_path"] for item in historical["results"]], ["项目/owner-v1.md"])
            self.assertEqual(historical["results"][0]["fact_status"], "current")
            self.assertEqual(
                [item["relative_path"] for item in discovered_historical["results"]],
                ["项目/owner-v1.md"],
                discovered_historical,
            )


if __name__ == "__main__":
    unittest.main()
