from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import agent_memory_search as search


class SearchPythonTests(unittest.TestCase):
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

    def test_run_search_reports_primary_backend_failure(self) -> None:
        args = Namespace(
            no_zvec=True,
            force_rg=False,
            query="ordinary query",
            limit=5,
        )
        warning = "sqlite index missing: <state-index>"
        with mock.patch.object(search, "sqlite_search", return_value=([], [warning])), \
             mock.patch.object(search, "log_search"):
            rows, warnings, backend_status = search.run_search(args)

        self.assertEqual(rows, [])
        self.assertEqual(warnings, [warning])
        self.assertEqual(backend_status["sqlite"]["status"], "error")
        self.assertEqual(backend_status["zvec"]["status"], "skipped")
        self.assertEqual(backend_status["rg"]["status"], "skipped")

    def test_main_returns_nonzero_when_sqlite_is_unhealthy(self) -> None:
        args = Namespace(
            redact_legacy_logs=False,
            json=True,
            query="ordinary query",
        )
        backend_status = {
            "sqlite": {"status": "error", "results": 0, "warnings": ["missing"]},
            "zvec": {"status": "skipped", "results": 0, "warnings": []},
            "rg": {"status": "skipped", "results": 0, "warnings": []},
        }
        output = io.StringIO()
        with mock.patch.object(search, "parse_args", return_value=args), \
             mock.patch.object(search, "run_search", return_value=([], ["missing"], backend_status)), \
             contextlib.redirect_stdout(output):
            returncode = search.main()

        self.assertEqual(returncode, 2)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["backend_status"]["sqlite"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
