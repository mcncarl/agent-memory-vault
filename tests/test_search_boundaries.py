from __future__ import annotations

import contextlib
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
        "as_of": "2026-07-19",
        "no_log": False,
    }
    values.update(overrides)
    return Namespace(**values)


class SearchBoundaryTests(unittest.TestCase):
    def test_valid_until_round_trips_through_index_schema(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            vault = Path(raw_tmp)
            target = vault / "项目" / "example.md"
            target.parent.mkdir()
            target.write_text(
                "---\nmemory_type: project\ntrack: project\nproject_id: example\nstatus: active\nvalid_until: 2026-08-01\n---\n# Example\n",
                encoding="utf-8",
            )
            with mock.patch.object(memory_index, "VAULT_ROOT", vault):
                doc, _ = memory_index.load_doc(target, "2026-07-19T00:00:00+00:00")
            conn = sqlite3.connect(":memory:")
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
            memory_index.upsert_doc(conn, doc)
            stored = conn.execute("SELECT valid_until FROM memory_docs WHERE rel_path=?", ("项目/example.md",)).fetchone()[0]
            conn.close()
        self.assertEqual(stored, "2026-08-01")

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
        self.assertEqual(search.backend_candidate_limit(Namespace(limit=5, current_project="a")), 40)
        self.assertEqual(search.backend_candidate_limit(Namespace(limit=5, current_project="")), 10)

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
            tmp = Path(raw_tmp)
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
            conn = sqlite3.connect(state_db)
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
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
            self.assertEqual(
                {row["project_id"] for row in exact_payload["results"]},
                {"project-a"},
            )
            self.assertNotIn("项目/alpha.md", {row["rel_path"] for row in exact_payload["results"]})

            with contextlib.closing(sqlite3.connect(state_db)) as after_conn, after_conn:
                after_rows = {
                    table: after_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("memory_docs", "memory_fts", "memory_search_log", "meta")
                }
            self.assertEqual(after_rows, before_rows)
            self.assertEqual(state_db.read_bytes(), before_bytes)

    def test_cli_no_log_does_not_migrate_an_older_schema_and_reports_failure(self) -> None:
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
            self.assertEqual(payload["results"], [])
            self.assertTrue(any("sqlite search failed" in warning for warning in payload["warnings"]))
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
        search_args = args(
            query="healthcheck",
            limit=5,
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

        with (
            mock.patch.object(search, "sqlite_search", return_value=([], ["sqlite failed"])),
            mock.patch.object(search, "zvec_search", return_value=([], [])),
        ):
            rows, warnings, all_failed = search.run_search(search_args)
        self.assertEqual(rows, [])
        self.assertFalse(all_failed)
        self.assertEqual(warnings, ["sqlite failed"])

    def test_main_returns_nonzero_only_for_total_backend_failure_without_results(self) -> None:
        cli_args = args(
            query="healthcheck",
            json=True,
            redact_legacy_logs=False,
        )
        output = io.StringIO()
        with (
            mock.patch.object(search, "parse_args", return_value=cli_args),
            mock.patch.object(search, "run_search", return_value=([], ["all failed"], True)),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(search.main(), 2)
        self.assertEqual(json.loads(output.getvalue())["warnings"], ["all failed"])

        output = io.StringIO()
        with (
            mock.patch.object(search, "parse_args", return_value=cli_args),
            mock.patch.object(search, "run_search", return_value=([], ["sqlite degraded"], False)),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(search.main(), 0)


if __name__ == "__main__":
    unittest.main()
