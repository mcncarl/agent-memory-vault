from __future__ import annotations

import contextlib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from tests.state_fixture import initialize_full_state
import agent_memory_migrate as memory_migrate
from agent_memory_state import (
    SEARCH_LOG_CONTROL_TRIGGER_INSERT,
    SEARCH_LOG_CONTROL_TRIGGER_UPDATE,
    SEARCH_LOG_PRIVACY_TRIGGER_INSERT,
    SEARCH_LOG_PRIVACY_TRIGGER_UPDATE,
    install_search_log_privacy_guards,
)


class SearchLogRedactionTest(unittest.TestCase):
    def test_legacy_query_text_is_replaced_with_hash_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp).resolve()
            state_db = tmp / "state.sqlite"
            initialize_full_state(state_db)
            with contextlib.closing(sqlite3.connect(state_db)) as conn, conn:
                conn.row_factory = sqlite3.Row
                for trigger in (
                    SEARCH_LOG_PRIVACY_TRIGGER_INSERT,
                    SEARCH_LOG_PRIVACY_TRIGGER_UPDATE,
                    SEARCH_LOG_CONTROL_TRIGGER_INSERT,
                    SEARCH_LOG_CONTROL_TRIGGER_UPDATE,
                ):
                    conn.execute(f"DROP TRIGGER {trigger}")
                conn.execute(
                    "INSERT INTO memory_search_log(query,result_count,created_at) VALUES (?,?,?)",
                    ("private legacy query", 0, "2026-07-11T00:00:00+00:00"),
                )
                redacted = memory_migrate._redact_legacy_search_rows(conn)
                install_search_log_privacy_guards(conn)
            self.assertEqual(redacted["query_rows_redacted"], 1)
            self.assertEqual(redacted["path_rows_cleared"], 0)
            with contextlib.closing(sqlite3.connect(state_db)) as conn, conn:
                query, digest, length = conn.execute(
                    "SELECT query, query_sha256, query_length FROM memory_search_log"
                ).fetchone()
            self.assertEqual(query, "")
            self.assertEqual(len(digest), 64)
            self.assertEqual(length, len("private legacy query"))
            self.assertNotIn("private legacy query", query)


if __name__ == "__main__":
    unittest.main()
