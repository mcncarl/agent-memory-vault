from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"


class SearchLogRedactionTest(unittest.TestCase):
    def test_legacy_query_text_is_replaced_with_hash_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            state_db = tmp / "state.sqlite"
            config = tmp / "agent-memory.toml"
            config.write_text(
                f'memory_root = "{(REPO_ROOT / "templates" / "vault").as_posix()}"\n'
                f'state_db = "{state_db.as_posix()}"\n',
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["AGENT_MEMORY_CONFIG_FILE"] = str(config)
            initialized = subprocess.run(
                [sys.executable, str(SCRIPTS / "agent_memory_index.py"), "--init"],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            with closing(sqlite3.connect(state_db)) as conn, conn:
                conn.execute(
                    "INSERT INTO memory_search_log(query,result_count,created_at) VALUES (?,?,?)",
                    ("private legacy query", 0, "2026-07-11T00:00:00+00:00"),
                )
            redacted = subprocess.run(
                [sys.executable, str(SCRIPTS / "agent_memory_search.py"), "--redact-legacy-logs", "--json"],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(redacted.returncode, 0, redacted.stderr)
            self.assertEqual(json.loads(redacted.stdout), {"redacted": 1, "remaining_raw": 0})
            with closing(sqlite3.connect(state_db)) as conn, conn:
                query, digest, length = conn.execute(
                    "SELECT query, query_sha256, query_length FROM memory_search_log"
                ).fetchone()
            self.assertTrue(query.startswith("[redacted:"))
            self.assertEqual(len(digest), 64)
            self.assertEqual(length, len("private legacy query"))
            self.assertNotIn("private legacy query", query)


if __name__ == "__main__":
    unittest.main()
