from __future__ import annotations

import contextlib
import os
import json
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MEMORYCTL = ROOT / "scripts" / "memoryctl"
if str(MEMORYCTL.parent) not in sys.path:
    sys.path.insert(0, str(MEMORYCTL.parent))

import agent_memory_observability as observability
from state_fixture import initialize_full_state


class MemoryctlTaskSeenTests(unittest.TestCase):
    @staticmethod
    def sessionless_environment() -> dict[str, str]:
        environment = os.environ.copy()
        for key in (
            "AGENT_MEMORY_TASK_ID",
            "AGENT_MEMORY_SESSION_ID",
            "CODEX_THREAD_ID",
            "CLAUDE_SESSION_ID",
            "CLAUDE_CODE_SESSION_ID",
            "MEMORY_ACTOR",
        ):
            environment.pop(key, None)
        environment.update(
            {
                "AGENT_MEMORY_CONFIG_FILE": os.environ["AGENT_MEMORY_TEST_CONFIG_FILE"],
                "AGENT_MEMORY_ROOT": os.environ["AGENT_MEMORY_TEST_ROOT"],
                "AGENT_MEMORY_GIT_ROOT": os.environ["AGENT_MEMORY_TEST_ROOT"],
                "AGENT_MEMORY_STATE_DB": os.environ["AGENT_MEMORY_TEST_STATE_DB"],
            }
        )
        return environment

    def test_first_task_call_is_idempotently_observed(self) -> None:
        self.assertEqual(
            os.environ.get("AGENT_MEMORY_TEST_ISOLATED"),
            "1",
            "run tests through scripts/run_tests_isolated.py",
        )
        state_db = Path(os.environ["AGENT_MEMORY_TEST_STATE_DB"])
        test_root = os.environ["AGENT_MEMORY_TEST_ROOT"]
        child_env = os.environ.copy()
        child_env.update(
            {
                "AGENT_MEMORY_CONFIG_FILE": os.environ["AGENT_MEMORY_TEST_CONFIG_FILE"],
                "AGENT_MEMORY_ROOT": test_root,
                "AGENT_MEMORY_GIT_ROOT": test_root,
                "AGENT_MEMORY_STATE_DB": str(state_db),
                "AGENT_MEMORY_SESSION_ID": "memoryctl-task-seen-fixture",
            }
        )
        for _ in range(2):
            completed = subprocess.run(
                [str(MEMORYCTL), "observe", "current", "--json"],
                cwd=ROOT,
                env=child_env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertTrue(payload.get("enabled"), payload)
            self.assertTrue(payload.get("task_available"), payload)
        diagnostic = subprocess.run(
            [str(MEMORYCTL), "observe", "outcome", "--value", "success", "--json"],
            cwd=ROOT,
            env=child_env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(diagnostic.returncode, 0, diagnostic.stdout + diagnostic.stderr)
        task_id = observability.task_ref("memoryctl-task-seen-fixture", "codex")
        with contextlib.closing(sqlite3.connect(state_db)) as connection:
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM memory_use_events "
                    "WHERE event_type='task_seen' AND source='tool_observed' "
                    "AND actor='codex' AND task_id=?",
                    (task_id,),
                ).fetchone()[0]
            )
        self.assertEqual(count, 1)

    def test_sessionless_human_and_migration_searches_get_complete_denominators(self) -> None:
        self.assertEqual(os.environ.get("AGENT_MEMORY_TEST_ISOLATED"), "1")
        source_config = Path(os.environ["AGENT_MEMORY_TEST_CONFIG_FILE"])
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary).resolve()
            state_db = private_root / "state.sqlite"
            config = private_root / "agent-memory.toml"
            initialize_full_state(state_db)
            config_text = source_config.read_text(encoding="utf-8")
            config_text, count = re.subn(
                r'(?m)^state_db\s*=\s*[^\r\n]+$',
                f'state_db = "{state_db.as_posix()}"',
                config_text,
                count=1,
            )
            self.assertEqual(count, 1)
            config.write_text(config_text, encoding="utf-8")
            if os.name == "posix":
                state_db.chmod(0o600)
                config.chmod(0o600)
            child_env = self.sessionless_environment()
            child_env["AGENT_MEMORY_CONFIG_FILE"] = str(config)
            child_env["AGENT_MEMORY_STATE_DB"] = str(state_db)
            for actor in ("human", "migration"):
                completed = subprocess.run(
                    [
                        str(MEMORYCTL),
                        "--actor",
                        actor,
                        "search",
                        "sessionless denominator fixture",
                        "--semantic-mode",
                        "off",
                        "--json",
                    ],
                    cwd=ROOT,
                    env=child_env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

            with contextlib.closing(sqlite3.connect(state_db)) as connection:
                connection.row_factory = sqlite3.Row
                rows = connection.execute(
                    "SELECT actor, task_id, query, used_paths FROM memory_search_log "
                    "WHERE actor IN ('human','migration') ORDER BY id DESC LIMIT 2"
                ).fetchall()
                self.assertEqual({str(row["actor"]) for row in rows}, {"human", "migration"})
                for row in rows:
                    actor = str(row["actor"])
                    task_id = str(row["task_id"] or "")
                    self.assertRegex(task_id, r"^[0-9a-f]{64}$")
                    self.assertEqual(str(row["query"] or ""), "")
                    self.assertEqual(str(row["used_paths"] or ""), "")
                    event_types = {
                        str(event[0])
                        for event in connection.execute(
                            "SELECT event_type FROM memory_use_events "
                            "WHERE actor=? AND task_id=?",
                            (actor, task_id),
                        )
                    }
                    self.assertIn("task_seen", event_types)
                    self.assertIn("search_completed", event_types)


if __name__ == "__main__":
    unittest.main()
