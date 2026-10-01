from __future__ import annotations

import contextlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS_PATH = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_PATH) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_PATH))

from agent_memory_claim import session_value
from agent_memory_stop_hook import session_key
from tests.state_fixture import initialize_full_state


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
TEMPLATE = REPO_ROOT / "templates" / "vault"


def run(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout, check=False)


class ActorSessionIsolationTest(unittest.TestCase):
    def test_actor_specific_environment_wins_over_inherited_other_host(self) -> None:
        env = {
            "CODEX_THREAD_ID": "codex-thread",
            "CLAUDE_SESSION_ID": "claude-session",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(session_value(actor="codex"), "codex-thread")
            self.assertEqual(session_value(actor="claude"), "claude-session")
            self.assertEqual(session_key({}, "codex"), "codex-thread")
            self.assertEqual(session_key({}, "claude"), "claude-session")

    def test_claude_never_falls_back_to_inherited_codex_thread(self) -> None:
        with mock.patch.dict(os.environ, {"CODEX_THREAD_ID": "outer-codex-thread"}, clear=True):
            self.assertEqual(session_value(actor="claude"), "")
            self.assertEqual(session_key({}, "claude"), "")


class SessionClaimConcurrencyTest(unittest.TestCase):
    def test_two_dirty_sessions_fail_closed_before_generated_index_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp).resolve()
            git_root = tmp / "git"
            vault = git_root / "AgentMemory"
            runtime = tmp / "runtime"
            git_root.mkdir(parents=True)
            shutil.copytree(TEMPLATE, vault)
            subprocess.run(["git", "init", "-q", str(git_root)], check=True)
            subprocess.run(["git", "-C", str(git_root), "config", "user.name", "Agent Memory Test"], check=True)
            subprocess.run(["git", "-C", str(git_root), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(git_root), "add", "AgentMemory"], check=True)
            subprocess.run(["git", "-C", str(git_root), "commit", "-qm", "baseline"], check=True)

            config_dir = runtime / "config"
            config_dir.mkdir(parents=True)
            config_path = config_dir / "agent-memory.toml"
            config_path.write_text(
                "\n".join(
                    [
                        f"memory_root = {json.dumps(str(vault), ensure_ascii=False)}",
                        f"git_root = {json.dumps(str(git_root), ensure_ascii=False)}",
                        f"config_root = {json.dumps(str(runtime), ensure_ascii=False)}",
                        f"state_db = {json.dumps(str(runtime / 'state.sqlite'), ensure_ascii=False)}",
                        f"closeout_log = {json.dumps(str(runtime / 'logs' / 'closeout.jsonl'), ensure_ascii=False)}",
                        f"audit_run_log = {json.dumps(str(runtime / 'logs' / 'audit_runs.jsonl'), ensure_ascii=False)}",
                        f"python = {json.dumps(sys.executable)}",
                        "",
                        "[semantic_retrieval]",
                        "enabled = false",
                        f"python = {json.dumps(sys.executable)}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["AGENT_MEMORY_CONFIG_FILE"] = str(config_path)
            initialize_full_state(runtime / "state.sqlite")

            evolved = run(
                [sys.executable, str(SCRIPTS / "agent_memory_evolution.py"), "--init", "--scan"],
                cwd=REPO_ROOT,
                env=env,
            )
            self.assertEqual(evolved.returncode, 0, evolved.stderr)
            indexed = run(
                [sys.executable, str(SCRIPTS / "agent_memory_index.py"), "--init", "--scan"],
                cwd=REPO_ROOT,
                env=env,
            )
            self.assertEqual(indexed.returncode, 0, indexed.stderr)

            codex_file = vault / "项目" / "_模板-项目.md"
            claude_file = vault / "工作流" / "Agent记忆收尾决策规则.md"
            codex_file.write_text(codex_file.read_text(encoding="utf-8") + "\nCodex session change.\n", encoding="utf-8")
            claude_file.write_text(claude_file.read_text(encoding="utf-8") + "\nClaude session change.\n", encoding="utf-8")

            for actor, session_id, path in (
                ("human", "human-session-1", codex_file),
                ("migration", "migration-session-1", claude_file),
            ):
                claimed = run(
                    [
                        sys.executable,
                        str(SCRIPTS / "agent_memory_claim.py"),
                        "--actor",
                        actor,
                        "--session-id",
                        session_id,
                        "--json",
                        "claim",
                        "--file",
                        str(path),
                    ],
                    cwd=REPO_ROOT,
                    env=env,
                )
                self.assertEqual(claimed.returncode, 0, claimed.stderr)
                self.assertEqual(json.loads(claimed.stdout)["count"], 1)

            listed = run(
                [
                    str(SCRIPTS / "memoryctl"),
                    "--actor",
                    "migration",
                    "claims",
                    "--session-id",
                    "migration-session-1",
                    "--json",
                ],
                cwd=REPO_ROOT,
                env=env,
            )
            self.assertEqual(listed.returncode, 0, listed.stderr)
            self.assertEqual(json.loads(listed.stdout)["count"], 1)

            precheck = run(
                [sys.executable, str(SCRIPTS / "agent_memory_check.py"), "--json"],
                cwd=REPO_ROOT,
                env=env,
            )
            self.assertEqual(precheck.returncode, 0, precheck.stderr + precheck.stdout)

            def closeout_command(actor: str, session_id: str) -> list[str]:
                return [
                    sys.executable,
                    str(SCRIPTS / "agent_memory_closeout.py"),
                    "--actor",
                    actor,
                    "--session-id",
                    session_id,
                    "--claimed-only",
                    "--commit",
                    "--skip-zvec",
                    "--no-zvec",
                    "--skip-audit",
                    "--trigger",
                    "test",
                    "--lock-timeout",
                    "30",
                    "--json",
                ]

            first = subprocess.Popen(
                closeout_command("human", "human-session-1"),
                cwd=REPO_ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            second = subprocess.Popen(
                closeout_command("migration", "migration-session-1"),
                cwd=REPO_ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            first_stdout, first_stderr = first.communicate(timeout=120)
            second_stdout, second_stderr = second.communicate(timeout=120)
            self.assertEqual(first.returncode, 2, first_stderr + first_stdout)
            self.assertEqual(second.returncode, 2, second_stderr + second_stdout)

            payloads = [json.loads(first_stdout), json.loads(second_stdout)]
            by_actor = {payload["actor"]: payload for payload in payloads}
            self.assertEqual(by_actor["human"]["processed_files"], ["项目/_模板-项目.md"])
            self.assertEqual(by_actor["migration"]["processed_files"], ["工作流/Agent记忆收尾决策规则.md"])
            for payload in payloads:
                self.assertEqual(payload["status"], "error")
                self.assertEqual(payload["ownership_error"], "GENERATED_INDEX_OTHER_SESSION_DIRTY")
                self.assertEqual(payload["commit"], "skipped")

            with contextlib.closing(sqlite3.connect(runtime / "state.sqlite")) as conn, conn:
                active = conn.execute(
                    "SELECT COUNT(*) FROM memory_session_claims WHERE status='active'"
                ).fetchone()[0]
                completed = conn.execute(
                    "SELECT COUNT(*) FROM memory_session_claims WHERE status='completed'"
                ).fetchone()[0]
                observations = conn.execute(
                    "SELECT COUNT(*) FROM memory_file_observations"
                ).fetchone()[0]
            self.assertEqual(active, 2)
            self.assertEqual(completed, 0)
            self.assertEqual(observations, 0)


if __name__ == "__main__":
    unittest.main()
