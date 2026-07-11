from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
