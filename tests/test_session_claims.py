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
    def test_two_sessions_commit_only_their_claimed_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
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
                    sys.executable,
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
            self.assertEqual(active, 0)
            self.assertEqual(completed, 2)
            self.assertEqual(observations, 2)

            clean_noop_command = closeout_command("claude", "claude-clean-noop")
            clean_noop_command[clean_noop_command.index("--commit")] = "--dry-run"
            clean_noop = run(
                clean_noop_command,
                cwd=REPO_ROOT,
                env=env,
            )
            self.assertEqual(clean_noop.returncode, 0, clean_noop.stderr + clean_noop.stdout)
            clean_payload = json.loads(clean_noop.stdout)
            self.assertEqual(clean_payload["status"], "ok")
            self.assertEqual(clean_payload["ownership_error"], "")
            self.assertEqual(clean_payload["processed_files"], [])
            self.assertIn("dry_run: no index refresh", "\n".join(clean_payload["info"]))

            codex_file.write_text(
                codex_file.read_text(encoding="utf-8") + "\nOther session owned change.\n",
                encoding="utf-8",
            )
            other_claim = run(
                [
                    sys.executable,
                    str(SCRIPTS / "agent_memory_claim.py"),
                    "--actor",
                    "codex",
                    "--session-id",
                    "codex-other-session",
                    "--json",
                    "claim",
                    "--file",
                    str(codex_file),
                ],
                cwd=REPO_ROOT,
                env=env,
            )
            self.assertEqual(other_claim.returncode, 0, other_claim.stderr)

            other_owned_command = closeout_command("claude", "claude-with-no-claim")
            other_owned_command[other_owned_command.index("--commit")] = "--dry-run"
            other_owned = run(other_owned_command, cwd=REPO_ROOT, env=env)
            self.assertEqual(other_owned.returncode, 0, other_owned.stderr + other_owned.stdout)
            other_payload = json.loads(other_owned.stdout)
            self.assertEqual(other_payload["status"], "ok")
            self.assertEqual(other_payload["ownership_error"], "")
            self.assertEqual(other_payload["unclaimed_files"], [])
            self.assertEqual(
                other_payload["other_session_files"],
                ["AgentMemory/项目/_模板-项目.md"],
            )

            other_closeout = run(
                closeout_command("codex", "codex-other-session"),
                cwd=REPO_ROOT,
                env=env,
            )
            self.assertEqual(
                other_closeout.returncode,
                0,
                other_closeout.stderr + other_closeout.stdout,
            )

            codex_file.write_text(
                codex_file.read_text(encoding="utf-8") + "\nUnclaimed change.\n",
                encoding="utf-8",
            )
            dirty_no_claim_command = closeout_command("claude", "claude-dirty-no-claim")
            dirty_no_claim_command[dirty_no_claim_command.index("--commit")] = "--dry-run"
            dirty_without_claim = run(
                dirty_no_claim_command,
                cwd=REPO_ROOT,
                env=env,
            )
            self.assertEqual(
                dirty_without_claim.returncode,
                2,
                dirty_without_claim.stderr + dirty_without_claim.stdout,
            )
            dirty_payload = json.loads(dirty_without_claim.stdout)
            self.assertEqual(dirty_payload["status"], "error")
            self.assertIn("no active memory claims", dirty_payload["ownership_error"])


if __name__ == "__main__":
    unittest.main()
