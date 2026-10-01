from __future__ import annotations

import subprocess
import sys
import unittest
from argparse import Namespace
from contextlib import contextmanager
from pathlib import Path
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import agent_memory_search as search
import agent_memory_zvec_index as zvec_index


class SearchPythonTests(unittest.TestCase):
    def test_hybrid_v2_uses_exact_weighted_rrf_formula(self) -> None:
        self.assertEqual(search.RRF_K, 20)
        self.assertEqual(
            {
                backend: search.RRF_WEIGHTS[backend]
                for backend in ("zvec", "unicode_fts", "trigram_fts")
            },
            {
                "zvec": 0.55,
                "unicode_fts": 0.25,
                "trigram_fts": 0.20,
            },
        )

        row = {
            "path": "/vault/workflow.md",
            "rel_path": "workflow.md",
            "title": "Workflow",
            "memory_type": "workflow",
            "track": "workflow",
            "project_id": "shared",
            "status": "active",
            "risk_class": "ordinary",
            "risk_class_source": "frontmatter",
            "verified_at": "",
            "verified_at_source": "structural",
            "fact_key": "",
            "valid_from": "",
            "valid_until": "",
            "supersedes": "",
            "temporal_policy": "structural",
            "temporal_policy_source": "frontmatter",
            "review_after_days": 0,
            "review_after_source": "frontmatter",
            "user_id": "",
            "agent_id": "shared",
            "agent_scope": "shared",
            "app_id": "agent-memory",
            "session_id": "",
            "memory_id": "a" * 64,
            "memory_id_source": "frontmatter",
            "has_open_loop": 0,
            "summary": "Workflow summary",
            "hit": "Workflow hit",
        }
        rank = 3
        for backend in ("unicode_fts", "trigram_fts"):
            with self.subTest(backend=backend):
                result = search.row_to_result(row, rank, "workflow", backend)
                self.assertEqual(
                    result.score,
                    search.RRF_WEIGHTS[backend] / (20 + rank),
                )

        args = Namespace(
            no_zvec=False,
            no_log=True,
            query="workflow",
            limit=3,
            zvec_timeout=5,
            zvec_max_distance=0.8,
            as_of="",
        )
        completed = subprocess.CompletedProcess(
            [],
            0,
            stdout=(
                '{"embedding":{"worker_status":"reused"},"results":['
                '{"path":"/vault/workflow.md","rel_path":"workflow.md",'
                '"memory_id":"' + ("a" * 64) + '","raw_distance":0.2}]}'
            ),
            stderr="",
        )

        @contextmanager
        def fake_connection(*_args: object, **_kwargs: object):
            yield object()

        with (
            mock.patch.object(search.subprocess, "run", return_value=completed),
            mock.patch.object(search, "connect", side_effect=fake_connection),
            mock.patch.object(search, "enrich_from_db", side_effect=lambda result, _conn: result),
            mock.patch.object(
                search,
                "annotate_temporal_from_db",
                side_effect=lambda result, _conn, _as_of: result,
            ),
        ):
            vector_results, warnings = search.zvec_search(args)

        self.assertEqual(warnings, [])
        self.assertEqual(len(vector_results), 1)
        self.assertEqual(
            vector_results[0].score,
            search.RRF_WEIGHTS["zvec"] / (20 + 1),
        )

    def test_zvec_search_uses_configured_python(self) -> None:
        args = Namespace(
            no_zvec=False,
            query="semantic query",
            limit=3,
            zvec_timeout=5,
            zvec_max_distance=0.8,
        )
        completed = subprocess.CompletedProcess([], 0, stdout='{"results": []}', stderr="")
        with mock.patch.object(search, "ZVEC_PYTHON", "/custom/vector/python"):
            with mock.patch.object(search.subprocess, "run", return_value=completed) as run:
                results, warnings = search.zvec_search(args)

        self.assertEqual(results, [])
        self.assertEqual(warnings, [])
        self.assertEqual(run.call_args.args[0][0], "/custom/vector/python")
        self.assertEqual(run.call_args.args[0][1], str(search.ZVEC_SCRIPT))

    def test_zvec_cli_does_not_hold_collection_lock_across_worker_start(self) -> None:
        args = Namespace(
            init=False,
            scan=False,
            prune=False,
            report=False,
            changed_file=[],
            search="healthcheck",
            lock_timeout=7.0,
            json=False,
        )
        calls: list[tuple[bool, float]] = []

        @contextmanager
        def recorded_lock(*, exclusive: bool, timeout: float):
            calls.append((exclusive, timeout))
            yield

        with (
            mock.patch.object(zvec_index, "parse_args", return_value=args),
            mock.patch.object(
                zvec_index,
                "assert_runtime_ready",
                return_value={"ready": True},
            ),
            mock.patch.object(zvec_index, "zvec_lock", side_effect=recorded_lock),
            mock.patch.object(zvec_index, "run_locked", return_value=0) as run_locked,
        ):
            self.assertEqual(zvec_index.main(), 0)

        # run_locked owns the narrow collection critical sections.  main must
        # not wrap Worker startup/query embedding in one outer lock.
        self.assertEqual(calls, [])
        run_locked.assert_called_once_with(args)


if __name__ == "__main__":
    unittest.main()
