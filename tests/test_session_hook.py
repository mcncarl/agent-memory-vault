from __future__ import annotations

import contextlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import agent_memory_observability as observability
import agent_memory_session_hook as session_hook


class ClaudeSessionHookTest(unittest.TestCase):
    def test_session_start_records_one_idempotent_task_seen_event(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            state = root / "state.sqlite"
            env_file = root / "claude-env.sh"
            with contextlib.closing(sqlite3.connect(state)) as conn:
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
                observability.ensure_schema(conn)
                conn.commit()
            os.chmod(state, 0o600)

            payload = json.dumps({"session_id": "same-claude-session"})
            with (
                mock.patch.object(observability, "STATE_DB", state),
                mock.patch.object(
                    observability,
                    "assert_runtime_ready",
                    return_value={"ready": True},
                ),
                mock.patch.object(
                    session_hook,
                    "assert_runtime_ready",
                    return_value={"ready": True},
                ),
                mock.patch.object(
                    session_hook,
                    "parse_args",
                    return_value=Namespace(actor="claude"),
                ),
                mock.patch.dict(
                    os.environ,
                    {
                        "AGENT_MEMORY_OBSERVABILITY_ENABLED": "true",
                        "CLAUDE_ENV_FILE": str(env_file),
                    },
                    clear=False,
                ),
            ):
                for _ in range(2):
                    with mock.patch.object(session_hook.sys, "stdin", io.StringIO(payload)):
                        self.assertEqual(session_hook.main(), 0)

            with contextlib.closing(sqlite3.connect(state)) as conn:
                rows = conn.execute(
                    """
                    SELECT actor, task_id, event_type, source, value
                    FROM memory_use_events
                    WHERE event_type='task_seen'
                    """
                ).fetchall()
            self.assertEqual(
                rows,
                [
                    (
                        "claude",
                        observability.task_ref("same-claude-session", "claude"),
                        "task_seen",
                        "tool_observed",
                        "seen",
                    )
                ],
            )

    def test_session_start_exports_claude_id_and_clears_inherited_codex_id(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            env_file = Path(raw_tmp) / "claude-env.sh"
            with (
                mock.patch.object(
                    session_hook,
                    "assert_runtime_ready",
                    return_value={"ready": True},
                ),
                mock.patch.object(
                    session_hook,
                    "parse_args",
                    return_value=Namespace(actor="claude"),
                ),
                mock.patch.object(session_hook, "record_task_seen") as task_seen,
                mock.patch.object(
                    session_hook.sys,
                    "stdin",
                    io.StringIO(json.dumps({"session_id": "claude-session-123"})),
                ),
                mock.patch.dict(
                    os.environ,
                    {"CLAUDE_ENV_FILE": str(env_file)},
                    clear=False,
                ),
            ):
                self.assertEqual(session_hook.main(), 0)
            task_seen.assert_called_once_with("claude-session-123", "claude")
            exported = env_file.read_text(encoding="utf-8")
            self.assertIn("export AGENT_MEMORY_SESSION_ID=claude-session-123", exported)
            self.assertIn("export CLAUDE_SESSION_ID=claude-session-123", exported)
            self.assertIn("unset CODEX_THREAD_ID", exported)


if __name__ == "__main__":
    unittest.main()
