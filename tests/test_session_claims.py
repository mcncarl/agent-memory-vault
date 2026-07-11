from __future__ import annotations

import json
import os
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
            self.assertNotEqual(session_key({}, "claude"), "outer-codex-thread")


class SessionClaimConcurrencyTest(unittest.TestCase):
    def test_two_sessions_commit_only_their_claimed_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            git_root = tmp / "git"
            vault = git_root / "AgentMemory"
            runtime = tmp / "runtime"
            git_root.mkdir(parents=True)
            subprocess.run(["cp", "-R", str(TEMPLATE), str(vault)], check=True)
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
                        f'memory_root = "{vault}"',
                        f'git_root = "{git_root}"',
                        f'config_root = "{runtime}"',
                        f'state_db = "{runtime / "state.sqlite"}"',
                        f'closeout_log = "{runtime / "logs" / "closeout.jsonl"}"',
                        f'audit_run_log = "{runtime / "logs" / "audit_runs.jsonl"}"',
                        'python = "' + sys.executable + '"',
                        "",
                        "[semantic_retrieval]",
                        "enabled = false",
                        'python = "' + sys.executable + '"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["AGENT_MEMORY_CONFIG_FILE"] = str(config_path)

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
                ("codex", "codex-session-1", codex_file),
                ("claude", "claude-session-1", claude_file),
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
                    "claude",
                    "claims",
                    "--session-id",
                    "claude-session-1",
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
                closeout_command("codex", "codex-session-1"),
                cwd=REPO_ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            second = subprocess.Popen(
                closeout_command("claude", "claude-session-1"),
                cwd=REPO_ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            first_stdout, first_stderr = first.communicate(timeout=120)
            second_stdout, second_stderr = second.communicate(timeout=120)
            self.assertEqual(first.returncode, 0, first_stderr + first_stdout)
            self.assertEqual(second.returncode, 0, second_stderr + second_stdout)

            payloads = [json.loads(first_stdout), json.loads(second_stdout)]
            by_actor = {payload["actor"]: payload for payload in payloads}
            self.assertEqual(by_actor["codex"]["processed_files"], ["项目/_模板-项目.md"])
            self.assertEqual(by_actor["claude"]["processed_files"], ["工作流/Agent记忆收尾决策规则.md"])
            self.assertNotIn("工作流/Agent记忆收尾决策规则.md", by_actor["codex"]["processed_files"])
            self.assertNotIn("项目/_模板-项目.md", by_actor["claude"]["processed_files"])

            changed_commits = run(
                ["git", "-C", str(git_root), "log", "-2", "--format=%H"],
                cwd=REPO_ROOT,
                env=env,
            )
            commits = [line for line in changed_commits.stdout.splitlines() if line]
            self.assertEqual(len(commits), 2)
            committed_paths = []
            for commit in commits:
                shown = run(
                    ["git", "-C", str(git_root), "-c", "core.quotepath=false", "show", "--pretty=", "--name-only", commit],
                    cwd=REPO_ROOT,
                    env=env,
                )
                paths = [line for line in shown.stdout.splitlines() if line]
                self.assertEqual(len(paths), 1)
                committed_paths.extend(paths)
            self.assertEqual(
                set(committed_paths),
                {"AgentMemory/项目/_模板-项目.md", "AgentMemory/工作流/Agent记忆收尾决策规则.md"},
            )

            with sqlite3.connect(runtime / "state.sqlite") as conn:
                active = conn.execute(
                    "SELECT COUNT(*) FROM memory_session_claims WHERE status='active'"
                ).fetchone()[0]
                completed = conn.execute(
                    "SELECT COUNT(*) FROM memory_session_claims WHERE status='completed'"
                ).fetchone()[0]
                observations = conn.execute(
                    "SELECT COUNT(*) FROM memory_file_observations"
                ).fetchone()[0]
            self.assertEqual(active, 0)
            self.assertEqual(completed, 2)
            self.assertEqual(observations, 2)


if __name__ == "__main__":
    unittest.main()
