from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
MEMORYCTL = SCRIPTS / "memoryctl"
INSTALLER = SCRIPTS / "install_runtime.py"

RACED_APPLY_HELPER = r"""
import contextlib
import json
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path.cwd() / "scripts"))
import agent_memory_write as studio_write

request = json.load(sys.stdin)
concurrent_markdown = request.pop("_concurrent_markdown")
secondary_markdown = request.pop("_secondary_markdown", "")
original_capture = studio_write._atomic_capture_target
original_restore = studio_write._atomic_restore_target

def raced_capture(proposal_path, target_path, displaced_path):
    target_path.write_text(concurrent_markdown, encoding="utf-8")
    return original_capture(proposal_path, target_path, displaced_path)

def raced_restore(captured_path, target_path, proposal_path):
    target_path.write_text(secondary_markdown, encoding="utf-8")
    return original_restore(captured_path, target_path, proposal_path)

try:
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(studio_write, "_atomic_capture_target", side_effect=raced_capture))
        if secondary_markdown:
            stack.enter_context(mock.patch.object(studio_write, "_atomic_restore_target", side_effect=raced_restore))
        with studio_write.studio_write_lock(10):
            result = studio_write.apply(
                request,
                raw_session_id=studio_write._raw_session_id(),
                closeout_timeout=90,
            )
except studio_write.StudioWriteError as exc:
    print(json.dumps({"ok": False, "reason_code": exc.reason_code}, separators=(",", ":")))
    raise SystemExit(2)
else:
    print(json.dumps(result, separators=(",", ":")))
"""


def run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    input_text: str = "",
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        input=input_text,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        capture_output=True,
        timeout=20,
        check=True,
    )
    return completed.stdout.strip()


def toml_string(value: str | Path) -> str:
    return json.dumps(str(value), ensure_ascii=False)


class StudioWriteSandbox:
    def __init__(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.git_root = self.root / "repo"
        self.vault = self.git_root / "AgentMemory"
        self.runtime = self.root / "runtime"
        self.state_db = self.runtime / "state.sqlite"
        self.config = self.runtime / "config" / "agent-memory.toml"
        self.git_root.mkdir(parents=True)
        self.runtime.mkdir(parents=True)
        self._create_minimal_vault()
        self._init_git()
        self._write_config()
        self.base_env = os.environ.copy()
        self.base_env["AGENT_MEMORY_CONFIG_FILE"] = str(self.config)
        for key in (
            "AGENT_MEMORY_SESSION_ID",
            "AGENT_MEMORY_PYTHON",
            "CODEX_THREAD_ID",
            "CLAUDE_SESSION_ID",
            "CLAUDE_CODE_SESSION_ID",
        ):
            self.base_env.pop(key, None)
        self._initialize_state()

    def close(self) -> None:
        self.tempdir.cleanup()

    def _memory_text(self, title: str, body: str, *, project: bool = False) -> str:
        memory_type = "project" if project else "workflow"
        track = memory_type
        project_fields = (
            "project_id: yichen-content-studio\n"
            "app_id: yichen-content-studio\n"
            if project
            else ""
        )
        return (
            "---\n"
            f"memory_type: {memory_type}\n"
            f"track: {track}\n"
            f"{project_fields}"
            "agent_scope: shared\n"
            "created_by: human\n"
            "last_updated_by: human\n"
            "status: active\n"
            "sensitivity: normal\n"
            "verified_at: 2026-08-09\n"
            "review_after_days: 90\n"
            "---\n\n"
            f"# {title}\n\n"
            "## 当前有效摘要\n\n"
            f"{body}\n"
        )

    def _create_minimal_vault(self) -> None:
        for path in (
            self.vault / "用户记忆",
            self.vault / "项目",
            self.vault / "工作流",
            self.vault / "决策",
            self.vault / "agent" / "case-candidates",
            self.vault / "agent" / "cases",
            self.vault / "agent" / "skill-candidates",
        ):
            path.mkdir(parents=True, exist_ok=True)
        plain_files = {
            self.vault / "AGENTS.md": "# Test Agent Memory\n",
            self.vault / "INDEX.md": "# Test Index\n",
            self.vault / "用户记忆" / "README.md": "# User Memory\n",
            self.vault / "agent" / "case-candidates" / "README.md": "# Candidates\n",
            self.vault / "agent" / "cases" / "README.md": "# Cases\n",
            self.vault / "agent" / "skill-candidates" / "README.md": "# Skills\n",
        }
        for path, text in plain_files.items():
            path.write_text(text, encoding="utf-8")
        typed_files = {
            self.vault / "用户记忆" / "偏好与边界.md": "user_preference",
            self.vault / "用户记忆" / "长期画像.md": "user_profile",
            self.vault / "agent" / "case-candidates" / "_模板-AgentCase候选.md": "agent_case_candidate",
            self.vault / "agent" / "cases" / "_模板-AgentCase正式记忆.md": "agent_case",
            self.vault / "agent" / "skill-candidates" / "_模板-Skill候选.md": "skill_candidate",
        }
        for path, memory_type in typed_files.items():
            path.write_text(
                f"---\nmemory_type: {memory_type}\nstatus: active\n---\n\n# {path.stem}\n",
                encoding="utf-8",
            )
        (self.vault / "工作流" / "Agent记忆字段规范.md").write_text(
            self._memory_text("Field schema", "Baseline schema."),
            encoding="utf-8",
        )
        (self.vault / "项目" / "Existing.md").write_text(
            self._memory_text(
                "Existing noopprobe94731",
                "Stable noop fact noopprobe94731.",
                project=True,
            ),
            encoding="utf-8",
        )

    def _init_git(self) -> None:
        git(self.git_root, "init", "-q")
        git(self.git_root, "config", "user.name", "Studio Write E2E")
        git(self.git_root, "config", "user.email", "studio-write@example.invalid")
        git(self.git_root, "add", "AgentMemory")
        git(self.git_root, "commit", "-qm", "baseline")

    def _write_config(self) -> None:
        self.config.parent.mkdir(parents=True, exist_ok=True)
        self.config.write_text(
            "\n".join(
                [
                    f"memory_root = {toml_string(self.vault)}",
                    f"git_root = {toml_string(self.git_root)}",
                    f"config_root = {toml_string(self.runtime)}",
                    f"state_db = {toml_string(self.state_db)}",
                    f"closeout_log = {toml_string(self.runtime / 'logs' / 'closeout.jsonl')}",
                    f"audit_run_log = {toml_string(self.runtime / 'logs' / 'audit_runs.jsonl')}",
                    f"python = {toml_string(sys.executable)}",
                    "",
                    "[semantic_retrieval]",
                    "enabled = false",
                    f"python = {toml_string(sys.executable)}",
                    "",
                    "[write_intents]",
                    "enabled = true",
                    'enforcement = "enforce"',
                    "ttl_hours = 24",
                    "max_proposal_bytes = 1048576",
                    "max_target_bytes = 1048576",
                    'protected_paths = ["项目/*.md", "工作流/*.md"]',
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        if os.name != "nt":
            self.config.chmod(0o600)

    def _initialize_state(self) -> None:
        for script in ("agent_memory_evolution.py", "agent_memory_index.py"):
            completed = run(
                [sys.executable, str(SCRIPTS / script), "--init", "--scan"],
                cwd=REPO_ROOT,
                env=self.base_env,
            )
            if completed.returncode != 0:
                raise AssertionError(completed.stderr + completed.stdout)

    def env(self, session: str) -> dict[str, str]:
        payload = self.base_env.copy()
        payload["AGENT_MEMORY_SESSION_ID"] = session
        payload["CODEX_THREAD_ID"] = "outer-codex-thread-must-not-be-used"
        return payload

    def write(
        self,
        action: str,
        request: dict[str, object],
        *,
        session: str,
        extra_env: dict[str, str] | None = None,
        memoryctl: Path = MEMORYCTL,
        closeout_timeout: float = 90,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        environment = self.env(session)
        if extra_env:
            environment.update(extra_env)
        completed = run(
            [
                sys.executable,
                str(memoryctl),
                "--actor",
                "yichen-content-studio",
                "write",
                action,
                "--json",
                "--lock-timeout",
                "10",
                "--closeout-timeout",
                str(closeout_timeout),
            ],
            cwd=REPO_ROOT,
            env=environment,
            input_text=json.dumps(request, ensure_ascii=False),
        )
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"non-json output (rc={completed.returncode}):\n"
                f"stdout={completed.stdout}\nstderr={completed.stderr}"
            ) from exc
        if not isinstance(payload, dict):
            raise AssertionError(f"expected JSON object, got {payload!r}")
        return completed, payload

    def add_proposal(self, token: str) -> str:
        return self._memory_text(
            token,
            f"{token}.",
            project=True,
        )


class StudioMemoryWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.box = StudioWriteSandbox()

    def tearDown(self) -> None:
        self.box.close()

    def prepare_request(self, token: str, target: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "summary": token,
            "proposal_markdown": self.box.add_proposal(token),
            "target_relative_path": target,
            "source_class": "user_direct",
            "knowledge_kind": "fact",
            "asserted_by": "user",
            "evidence_ref": f"conversation:{token}",
            "current_project": "yichen-content-studio",
            "app_id": "yichen-content-studio",
            "project_id": "yichen-content-studio",
        }

    def bind_read_token(
        self,
        request: dict[str, object],
        *,
        session: str,
    ) -> dict[str, object]:
        target = str(request["target_relative_path"])
        read_request: dict[str, object] = {
            "schema_version": 1,
            "target_relative_path": target,
            "app_id": request.get("app_id", "yichen-content-studio"),
        }
        if request.get("project_id"):
            read_request["project_id"] = request["project_id"]
        process, payload = self.box.write(
            "read-target",
            read_request,
            session=session,
        )
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        request["read_token"] = payload["read_token"]
        return request

    def prepare_existing_update(
        self,
        *,
        session: str,
        marker: str,
    ) -> tuple[str, dict[str, object], dict[str, object]]:
        target_rel = "项目/Existing.md"
        request: dict[str, object] = {
            "schema_version": 1,
            "summary": f"Stable noop fact noopprobe94731 {marker}",
            "proposal_markdown": self.box._memory_text(
                "Existing noopprobe94731",
                f"Stable noop fact noopprobe94731 plus {marker} durable version.",
                project=True,
            ),
            "target_relative_path": target_rel,
            "source_class": "user_direct",
            "knowledge_kind": "fact",
            "asserted_by": "user",
            "evidence_ref": f"conversation:{marker}",
            "current_project": "yichen-content-studio",
            "app_id": "yichen-content-studio",
            "project_id": "yichen-content-studio",
        }
        self.bind_read_token(request, session=session)
        prepared_process, prepared = self.box.write("prepare", request, session=session)
        self.assertEqual(
            prepared_process.returncode,
            0,
            prepared_process.stderr + prepared_process.stdout,
        )
        self.assertEqual(prepared["status"], "prepared")
        self.assertEqual(prepared["recommended_action"], "UPDATE")
        return target_rel, request, prepared

    def raced_apply(
        self,
        *,
        session: str,
        target_rel: str,
        request: dict[str, object],
        prepared: dict[str, object],
        concurrent_markdown: str,
        secondary_markdown: str = "",
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        apply_request = {
            "schema_version": 1,
            "proposal_id": prepared["proposal_id"],
            "target_relative_path": target_rel,
            "proposal_markdown": request["proposal_markdown"],
            "proposal_raw_sha256": prepared["proposal_raw_sha256"],
            "proposal_canonical_sha256": prepared["proposal_canonical_sha256"],
            "confirmed_by": "user",
            "confirmation_reference": "conversation:atomic-cas-confirmed",
            "_concurrent_markdown": concurrent_markdown,
        }
        if secondary_markdown:
            apply_request["_secondary_markdown"] = secondary_markdown
        completed = run(
            [sys.executable, "-c", RACED_APPLY_HELPER],
            cwd=REPO_ROOT,
            env=self.box.env(session),
            input_text=json.dumps(apply_request, ensure_ascii=False),
        )
        return completed, json.loads(completed.stdout)

    def test_installed_runtime_prepare_and_apply_end_to_end(self) -> None:
        installed = run(
            [
                sys.executable,
                str(INSTALLER),
                "--config-root",
                str(self.box.runtime),
                "--json",
            ],
            cwd=REPO_ROOT,
            env=self.box.base_env,
        )
        self.assertEqual(installed.returncode, 0, installed.stderr + installed.stdout)
        installed_memoryctl = self.box.runtime / "scripts" / "memoryctl"
        session = "content-studio-installed-runtime"
        token = "installedruntimewrite94731"
        target_rel = "项目/InstalledRuntimeWrite.md"
        request = self.prepare_request(token, target_rel)
        self.bind_read_token(request, session=session)

        prepared_process, prepared = self.box.write(
            "prepare",
            request,
            session=session,
            memoryctl=installed_memoryctl,
        )
        self.assertEqual(
            prepared_process.returncode,
            0,
            prepared_process.stderr + prepared_process.stdout,
        )
        apply_request = {
            "schema_version": 1,
            "proposal_id": prepared["proposal_id"],
            "target_relative_path": target_rel,
            "proposal_markdown": request["proposal_markdown"],
            "proposal_raw_sha256": prepared["proposal_raw_sha256"],
            "proposal_canonical_sha256": prepared["proposal_canonical_sha256"],
            "confirmed_by": "user",
            "confirmation_reference": "conversation:installed-runtime-confirmed",
        }
        applied_process, applied = self.box.write(
            "apply",
            apply_request,
            session=session,
            memoryctl=installed_memoryctl,
        )

        self.assertEqual(
            applied_process.returncode,
            0,
            applied_process.stderr + applied_process.stdout,
        )
        self.assertEqual(applied["status"], "applied")
        self.assertEqual(
            (self.box.vault / target_rel).read_text(encoding="utf-8"),
            request["proposal_markdown"],
        )
        self.assertEqual(git(self.box.git_root, "status", "--porcelain"), "")

    def test_wrapper_rejects_session_equals_before_starting_write_child(self) -> None:
        private_marker = "argv-session-private-marker-94731"
        completed = run(
            [
                sys.executable,
                str(MEMORYCTL),
                "--actor",
                "yichen-content-studio",
                "write",
                "read-target",
                "--json",
                f"--session-id={private_marker}",
            ],
            cwd=REPO_ROOT,
            env=self.box.base_env,
            input_text=json.dumps(
                {
                    "schema_version": 1,
                    "target_relative_path": "项目/Existing.md",
                    "app_id": "yichen-content-studio",
                    "project_id": "yichen-content-studio",
                }
            ),
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertNotIn(private_marker, completed.stderr)
        self.assertIn("environment only", completed.stderr)

    def test_read_target_returns_exact_content_without_touching_runtime_state(self) -> None:
        session = "content-studio-read-session"
        existing = self.box.vault / "项目" / "Existing.md"
        expected_bytes = existing.read_bytes()
        expected = expected_bytes.decode("utf-8")
        state_before = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.box.runtime.glob("state.sqlite*")
        }

        found_process, found = self.box.write(
            "read-target",
            {
                "schema_version": 1,
                "target_relative_path": "项目/Existing.md",
                "app_id": "yichen-content-studio",
                "project_id": "yichen-content-studio",
            },
            session=session,
        )
        missing_process, missing = self.box.write(
            "read-target",
            {
                "schema_version": 1,
                "target_relative_path": "项目/NewMemory.md",
                "app_id": "yichen-content-studio",
                "project_id": "yichen-content-studio",
            },
            session=session,
        )

        self.assertEqual(found_process.returncode, 0, found_process.stderr + found_process.stdout)
        self.assertEqual(found["status"], "found")
        self.assertTrue(found["exists"])
        self.assertEqual(found["content"], expected)
        self.assertEqual(found["raw_sha256"], hashlib.sha256(expected_bytes).hexdigest())
        self.assertEqual(found["git_head"], git(self.box.git_root, "rev-parse", "HEAD"))
        self.assertEqual(missing_process.returncode, 0, missing_process.stderr + missing_process.stdout)
        self.assertEqual(missing["status"], "missing")
        self.assertFalse(missing["exists"])
        self.assertEqual(missing["content"], "")
        state_after = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.box.runtime.glob("state.sqlite*")
        }
        self.assertEqual(state_after, state_before)
        self.assertFalse((self.box.runtime / "locks" / "content-studio-write.lock").exists())

    def test_read_target_blocks_unsafe_invalid_and_oversized_content(self) -> None:
        session = "content-studio-read-safety"
        invalid = self.box.vault / "项目" / "Invalid.md"
        invalid.write_bytes(b"# invalid\n\xff\n")
        oversized = self.box.vault / "项目" / "Oversized.md"
        oversized.write_bytes(b"x" * (2 * 1024 * 1024 + 1))

        outside_process, outside = self.box.write(
            "read-target",
            {
                "schema_version": 1,
                "target_relative_path": "../outside.md",
                "app_id": "yichen-content-studio",
                "project_id": "yichen-content-studio",
            },
            session=session,
        )
        invalid_process, invalid_result = self.box.write(
            "read-target",
            {
                "schema_version": 1,
                "target_relative_path": "项目/Invalid.md",
                "app_id": "yichen-content-studio",
                "project_id": "yichen-content-studio",
            },
            session=session,
        )
        oversized_process, oversized_result = self.box.write(
            "read-target",
            {
                "schema_version": 1,
                "target_relative_path": "项目/Oversized.md",
                "app_id": "yichen-content-studio",
                "project_id": "yichen-content-studio",
            },
            session=session,
        )

        self.assertEqual(outside_process.returncode, 2)
        self.assertEqual(outside["reason_code"], "PATH_OUTSIDE_BOUNDARY")
        self.assertEqual(invalid_process.returncode, 2)
        self.assertEqual(invalid_result["reason_code"], "CONTENT_NOT_UTF8")
        self.assertEqual(oversized_process.returncode, 2)
        self.assertEqual(oversized_result["reason_code"], "TARGET_TOO_LARGE")
        self.assertNotIn("invalid", invalid_process.stdout.casefold())

    def test_prepare_is_read_only_and_apply_commits_exact_confirmed_proposal(self) -> None:
        session = "content-studio-session-one"
        token = "newwritebody94731"
        target_rel = "项目/StudioWrite.md"
        target = self.box.vault / target_rel
        request = self.prepare_request(token, target_rel)
        self.bind_read_token(request, session=session)

        prepared_process, prepared = self.box.write("prepare", request, session=session)
        self.assertEqual(prepared_process.returncode, 0, prepared_process.stderr + prepared_process.stdout)
        self.assertEqual(prepared["status"], "prepared")
        self.assertEqual(prepared["recommended_action"], "ADD")
        self.assertFalse(target.exists())
        self.assertEqual(git(self.box.git_root, "status", "--porcelain"), "")
        proposal_id = str(prepared["proposal_id"])
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            intent = conn.execute(
                "SELECT proposal_canonical_snapshot, approval_required, reconcile_action, "
                "actor, session_hash, asserted_by FROM memory_write_intents WHERE intent_id=?",
                (proposal_id,),
            ).fetchone()
        self.assertEqual(intent[0], "")
        self.assertEqual(intent[1:4], (1, "ADD", "yichen-content-studio"))
        self.assertEqual(intent[4], hashlib.sha256(session.encode()).hexdigest()[:16])
        self.assertEqual(intent[5], "user")
        for state_path in self.box.runtime.glob("state.sqlite*"):
            self.assertNotIn(token.encode(), state_path.read_bytes())

        apply_request = {
            "schema_version": 1,
            "proposal_id": proposal_id,
            "target_relative_path": target_rel,
            "proposal_markdown": request["proposal_markdown"],
            "proposal_raw_sha256": prepared["proposal_raw_sha256"],
            "proposal_canonical_sha256": prepared["proposal_canonical_sha256"],
            "confirmed_by": "user",
            "confirmation_reference": "conversation:turn-1",
        }
        applied_process, applied = self.box.write("apply", apply_request, session=session)
        self.assertEqual(applied_process.returncode, 0, applied_process.stderr + applied_process.stdout)
        self.assertEqual(applied["status"], "applied")
        self.assertFalse(applied["idempotent"])
        self.assertEqual(target.read_text(encoding="utf-8"), request["proposal_markdown"])
        self.assertEqual(git(self.box.git_root, "status", "--porcelain"), "")
        self.assertEqual(
            git(self.box.git_root, "log", "-1", "--format=%H", "--", f"AgentMemory/{target_rel}"),
            applied["git_commit"],
        )
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            stored = conn.execute(
                "SELECT i.status, r.outcome, r.approval_ref_sha256 "
                "FROM memory_write_intents i JOIN memory_write_receipts r USING(intent_id) "
                "WHERE i.intent_id=?",
                (proposal_id,),
            ).fetchone()
        self.assertEqual(stored[0:2], ("completed", "completed"))
        self.assertEqual(
            stored[2],
            hashlib.sha256(b"conversation:turn-1").hexdigest(),
        )

        commit_before = git(self.box.git_root, "rev-parse", "HEAD")
        repeated_process, repeated = self.box.write("apply", apply_request, session=session)
        self.assertEqual(repeated_process.returncode, 0, repeated_process.stderr + repeated_process.stdout)
        self.assertTrue(repeated["idempotent"])
        self.assertEqual(git(self.box.git_root, "rev-parse", "HEAD"), commit_before)

    def test_hash_or_session_mismatch_cannot_write_and_cancel_is_terminal(self) -> None:
        session = "content-studio-session-two"
        target_rel = "项目/CancelMe.md"
        request = self.prepare_request("cancelprobe94731", target_rel)
        self.bind_read_token(request, session=session)
        prepared_process, prepared = self.box.write("prepare", request, session=session)
        self.assertEqual(prepared_process.returncode, 0, prepared_process.stderr + prepared_process.stdout)
        apply_request = {
            "schema_version": 1,
            "proposal_id": prepared["proposal_id"],
            "target_relative_path": target_rel,
            "proposal_markdown": request["proposal_markdown"],
            "proposal_raw_sha256": "0" * 64,
            "proposal_canonical_sha256": prepared["proposal_canonical_sha256"],
            "confirmed_by": "user",
            "confirmation_reference": "conversation:turn-2",
        }
        mismatched_process, mismatched = self.box.write("apply", apply_request, session=session)
        self.assertEqual(mismatched_process.returncode, 2)
        self.assertEqual(mismatched["reason_code"], "PROPOSAL_HASH_MISMATCH")
        self.assertFalse((self.box.vault / target_rel).exists())

        wrong_session_process, wrong_session = self.box.write(
            "cancel",
            {"schema_version": 1, "proposal_id": prepared["proposal_id"]},
            session="another-content-studio-session",
        )
        self.assertEqual(wrong_session_process.returncode, 2)
        self.assertEqual(wrong_session["reason_code"], "INTENT_SESSION_MISMATCH")

        cancelled_process, cancelled = self.box.write(
            "cancel",
            {"schema_version": 1, "proposal_id": prepared["proposal_id"]},
            session=session,
        )
        self.assertEqual(cancelled_process.returncode, 0, cancelled_process.stderr + cancelled_process.stdout)
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertFalse((self.box.vault / target_rel).exists())

        apply_request["proposal_raw_sha256"] = prepared["proposal_raw_sha256"]
        after_cancel_process, after_cancel = self.box.write("apply", apply_request, session=session)
        self.assertEqual(after_cancel_process.returncode, 2)
        self.assertEqual(after_cancel["reason_code"], "INTENT_NOT_APPLICABLE")
        self.assertFalse((self.box.vault / target_rel).exists())

    def test_cancel_cannot_abandon_content_after_apply_has_started(self) -> None:
        session = "content-studio-apply-recovery"
        target_rel = "项目/Recovery.md"
        request = self.prepare_request("applyrecovery94731", target_rel)
        self.bind_read_token(request, session=session)
        prepared_process, prepared = self.box.write("prepare", request, session=session)
        self.assertEqual(prepared_process.returncode, 0, prepared_process.stderr + prepared_process.stdout)
        apply_request = {
            "schema_version": 1,
            "proposal_id": prepared["proposal_id"],
            "target_relative_path": target_rel,
            "proposal_markdown": request["proposal_markdown"],
            "proposal_raw_sha256": prepared["proposal_raw_sha256"],
            "proposal_canonical_sha256": prepared["proposal_canonical_sha256"],
            "confirmed_by": "user",
            "confirmation_reference": "conversation:recovery-confirmed",
        }

        failed_process, failed = self.box.write(
            "apply",
            apply_request,
            session=session,
            extra_env={"AGENT_MEMORY_PYTHON": str(self.box.root / "missing-python")},
        )

        self.assertEqual(failed_process.returncode, 2)
        self.assertEqual(failed["reason_code"], "CLOSEOUT_FAILED")
        target = self.box.vault / target_rel
        self.assertEqual(target.read_text(encoding="utf-8"), request["proposal_markdown"])
        cancel_process, cancel_result = self.box.write(
            "cancel",
            {"schema_version": 1, "proposal_id": prepared["proposal_id"]},
            session=session,
        )
        self.assertEqual(cancel_process.returncode, 2)
        self.assertEqual(cancel_result["reason_code"], "APPLY_RECOVERY_REQUIRED")
        self.assertEqual(target.read_text(encoding="utf-8"), request["proposal_markdown"])

        recovered_process, recovered = self.box.write("apply", apply_request, session=session)
        self.assertEqual(recovered_process.returncode, 0, recovered_process.stderr + recovered_process.stdout)
        self.assertEqual(recovered["status"], "applied")
        self.assertTrue(recovered["idempotent"])
        self.assertEqual(git(self.box.git_root, "status", "--porcelain"), "")

    def test_update_uses_recommended_target_and_never_overwrites_a_changed_base(self) -> None:
        session = "content-studio-session-update"
        target_rel = "项目/Existing.md"
        target = self.box.vault / target_rel
        proposal = self.box._memory_text(
            "Existing noopprobe94731",
            "Stable noop fact noopprobe94731 plus durable update marker.",
            project=True,
        )
        request = {
            "schema_version": 1,
            "summary": "Stable noop fact noopprobe94731 updated",
            "proposal_markdown": proposal,
            "source_class": "user_direct",
            "knowledge_kind": "fact",
            "asserted_by": "user",
            "evidence_ref": "conversation:update-probe",
            "current_project": "yichen-content-studio",
            "target_relative_path": target_rel,
            "app_id": "yichen-content-studio",
            "project_id": "yichen-content-studio",
        }
        self.bind_read_token(request, session=session)

        prepared_process, prepared = self.box.write("prepare", request, session=session)
        self.assertEqual(prepared_process.returncode, 0, prepared_process.stderr + prepared_process.stdout)
        self.assertEqual(prepared["status"], "prepared")
        self.assertEqual(prepared["recommended_action"], "UPDATE")
        self.assertEqual(prepared["target_relative_path"], target_rel)

        changed_base = target.read_text(encoding="utf-8") + "\nExternally changed after prepare.\n"
        target.write_text(changed_base, encoding="utf-8")
        git(self.box.git_root, "add", f"AgentMemory/{target_rel}")
        git(self.box.git_root, "commit", "-qm", "external baseline drift")
        apply_request = {
            "schema_version": 1,
            "proposal_id": prepared["proposal_id"],
            "target_relative_path": target_rel,
            "proposal_markdown": proposal,
            "proposal_raw_sha256": prepared["proposal_raw_sha256"],
            "proposal_canonical_sha256": prepared["proposal_canonical_sha256"],
            "confirmed_by": "user",
            "confirmation_reference": "conversation:update-confirmed",
        }

        applied_process, blocked = self.box.write("apply", apply_request, session=session)

        self.assertEqual(applied_process.returncode, 2)
        self.assertEqual(blocked["reason_code"], "STALE_BASE")
        self.assertEqual(target.read_text(encoding="utf-8"), changed_base)
        self.assertNotEqual(target.read_text(encoding="utf-8"), proposal)

    def test_noop_merge_and_source_block_never_create_writable_proposals(self) -> None:
        session = "content-studio-session-three"
        existing_text = (self.box.vault / "项目" / "Existing.md").read_text(encoding="utf-8")
        base_request = {
            "schema_version": 1,
            "summary": "Stable noop fact noopprobe94731",
            "proposal_markdown": existing_text,
            "target_relative_path": "项目/Existing.md",
            "source_class": "user_direct",
            "knowledge_kind": "fact",
            "asserted_by": "user",
            "evidence_ref": "conversation:noop",
            "current_project": "yichen-content-studio",
            "app_id": "yichen-content-studio",
            "project_id": "yichen-content-studio",
        }
        self.bind_read_token(base_request, session=session)
        noop_process, noop = self.box.write("prepare", base_request, session=session)
        self.assertEqual(noop_process.returncode, 0, noop_process.stderr + noop_process.stdout)
        self.assertEqual(noop["status"], "noop")
        self.assertEqual(noop["recommended_action"], "NOOP")
        self.assertNotIn("proposal_id", noop)

        merge_request = dict(base_request)
        merge_request["target_relative_path"] = "项目/Different.md"
        self.bind_read_token(merge_request, session=session)
        merge_process, merge = self.box.write("prepare", merge_request, session=session)
        self.assertEqual(merge_process.returncode, 0, merge_process.stderr + merge_process.stdout)
        self.assertEqual(merge["status"], "merge_required")
        self.assertEqual(merge["recommended_action"], "MERGE_REQUIRED")
        self.assertNotIn("proposal_id", merge)

        secret = "sk-" + ("S" * 28)
        blocked_request = self.prepare_request("secretprobe94731", "项目/Secret.md")
        self.bind_read_token(blocked_request, session=session)
        blocked_request["proposal_markdown"] = str(blocked_request["proposal_markdown"]) + secret
        blocked_process, blocked = self.box.write("prepare", blocked_request, session=session)
        self.assertEqual(blocked_process.returncode, 2)
        self.assertEqual(blocked["reason_code"], "SECRET_MATERIAL")
        self.assertNotIn(secret, blocked_process.stdout)
        self.assertFalse((self.box.vault / "项目" / "Secret.md").exists())

        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            intent_count = conn.execute("SELECT COUNT(*) FROM memory_write_intents").fetchone()[0]
        self.assertEqual(intent_count, 0)
        self.assertEqual(git(self.box.git_root, "status", "--porcelain"), "")

    def test_scope_guard_blocks_missing_app_other_app_project_agent_and_secret(self) -> None:
        session = "content-studio-scope-guard"
        marker = "private-scope-marker-94731"
        other_app = self.box.vault / "项目" / "OtherApp.md"
        other_app.write_text(
            self.box._memory_text("Other app", marker, project=True).replace(
                "app_id: yichen-content-studio",
                "app_id: other-app",
            ),
            encoding="utf-8",
        )
        codex_only = self.box.vault / "项目" / "CodexOnly.md"
        codex_only.write_text(
            self.box._memory_text("Codex only", marker, project=True).replace(
                "agent_scope: shared",
                "agent_scope: codex",
            ),
            encoding="utf-8",
        )
        other_project = self.box.vault / "项目" / "OtherProject.md"
        other_project.write_text(
            self.box._memory_text("Other project", marker, project=True).replace(
                "project_id: yichen-content-studio",
                "project_id: other-project",
            ),
            encoding="utf-8",
        )
        secret_value = "sk-" + "Z" * 32
        blocked_target = self.box.vault / "项目" / "SecretTarget.md"
        blocked_target.write_text(
            self.box._memory_text("Secret", secret_value, project=True),
            encoding="utf-8",
        )

        cases = (
            ({"schema_version": 1, "target_relative_path": "项目/Existing.md"}, "APP_ID_REQUIRED"),
            (
                {
                    "schema_version": 1,
                    "target_relative_path": "项目/OtherApp.md",
                    "app_id": "yichen-content-studio",
                    "project_id": "yichen-content-studio",
                },
                "APP_ID_MISMATCH",
            ),
            (
                {
                    "schema_version": 1,
                    "target_relative_path": "项目/CodexOnly.md",
                    "app_id": "yichen-content-studio",
                    "project_id": "yichen-content-studio",
                },
                "AGENT_SCOPE_MISMATCH",
            ),
            (
                {
                    "schema_version": 1,
                    "target_relative_path": "项目/OtherProject.md",
                    "app_id": "yichen-content-studio",
                    "project_id": "yichen-content-studio",
                },
                "PROJECT_SCOPE_MISMATCH",
            ),
            (
                {
                    "schema_version": 1,
                    "target_relative_path": "项目/SecretTarget.md",
                    "app_id": "yichen-content-studio",
                    "project_id": "yichen-content-studio",
                },
                "SECRET_MATERIAL",
            ),
            (
                {
                    "schema_version": 1,
                    "target_relative_path": "项目/Existing.md",
                    "app_id": "yichen-content-studio",
                },
                "PROJECT_SCOPE_MISMATCH",
            ),
        )
        for request, reason in cases:
            with self.subTest(reason=reason):
                process, payload = self.box.write("read-target", request, session=session)
                self.assertEqual(process.returncode, 2)
                self.assertEqual(payload["reason_code"], reason)
                self.assertNotIn(marker, process.stdout)
                self.assertNotIn(secret_value, process.stdout)

    def test_prepare_requires_fresh_read_token_and_explicit_shared_frontmatter(self) -> None:
        session = "content-studio-required-read-token"
        target_rel = "项目/TokenRequired.md"
        request = self.prepare_request("tokenrequired94731", target_rel)

        missing_process, missing = self.box.write("prepare", request, session=session)
        self.assertEqual(missing_process.returncode, 2)
        self.assertEqual(missing["reason_code"], "READ_TOKEN_REQUIRED")

        self.bind_read_token(request, session=session)
        request["proposal_markdown"] = str(request["proposal_markdown"]).replace(
            "agent_scope: shared",
            "agent_scope: codex",
        )
        scoped_process, scoped = self.box.write("prepare", request, session=session)
        self.assertEqual(scoped_process.returncode, 2)
        self.assertEqual(scoped["reason_code"], "AGENT_SCOPE_MISMATCH")
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM memory_write_intents").fetchone()[0],
                0,
            )

    def test_update_read_token_cas_preserves_a_newer_completed_write(self) -> None:
        target_rel = "项目/Existing.md"
        target = self.box.vault / target_rel
        scope = {
            "schema_version": 1,
            "target_relative_path": target_rel,
            "app_id": "yichen-content-studio",
            "project_id": "yichen-content-studio",
        }
        a_read_process, a_read = self.box.write(
            "read-target",
            scope,
            session="studio-reader-a",
        )
        self.assertEqual(a_read_process.returncode, 0, a_read_process.stderr + a_read_process.stdout)

        b_request = {
            "schema_version": 1,
            "summary": "Stable noop fact noopprobe94731 updated by B",
            "proposal_markdown": self.box._memory_text(
                "Existing noopprobe94731",
                "Stable noop fact noopprobe94731 plus B durable version.",
                project=True,
            ),
            "target_relative_path": target_rel,
            "source_class": "user_direct",
            "knowledge_kind": "fact",
            "asserted_by": "user",
            "evidence_ref": "conversation:writer-b",
            "current_project": "yichen-content-studio",
            "app_id": "yichen-content-studio",
            "project_id": "yichen-content-studio",
        }
        self.bind_read_token(b_request, session="studio-writer-b")
        prepared_process, prepared = self.box.write(
            "prepare",
            b_request,
            session="studio-writer-b",
        )
        self.assertEqual(prepared_process.returncode, 0, prepared_process.stderr + prepared_process.stdout)
        apply_request = {
            "schema_version": 1,
            "proposal_id": prepared["proposal_id"],
            "target_relative_path": target_rel,
            "proposal_markdown": b_request["proposal_markdown"],
            "proposal_raw_sha256": prepared["proposal_raw_sha256"],
            "proposal_canonical_sha256": prepared["proposal_canonical_sha256"],
            "confirmed_by": "user",
            "confirmation_reference": "conversation:writer-b-confirmed",
        }
        applied_process, _ = self.box.write("apply", apply_request, session="studio-writer-b")
        self.assertEqual(applied_process.returncode, 0, applied_process.stderr + applied_process.stdout)
        b_content = target.read_text(encoding="utf-8")

        a_request = dict(b_request)
        a_request.update(
            {
                "summary": "Stable noop fact noopprobe94731 stale A update",
                "proposal_markdown": self.box._memory_text(
                    "Existing noopprobe94731",
                    "Stable noop fact noopprobe94731 plus stale A version.",
                    project=True,
                ),
                "read_token": a_read["read_token"],
                "evidence_ref": "conversation:reader-a",
            }
        )
        stale_process, stale = self.box.write("prepare", a_request, session="studio-reader-a")
        self.assertEqual(stale_process.returncode, 2)
        self.assertEqual(stale["reason_code"], "STALE_READ_TOKEN")
        self.assertEqual(target.read_text(encoding="utf-8"), b_content)

    def test_add_missing_read_token_cannot_claim_a_path_created_by_another_write(self) -> None:
        target_rel = "项目/AddRace.md"
        scope = {
            "schema_version": 1,
            "target_relative_path": target_rel,
            "app_id": "yichen-content-studio",
            "project_id": "yichen-content-studio",
        }
        a_read_process, a_read = self.box.write("read-target", scope, session="add-reader-a")
        self.assertEqual(a_read_process.returncode, 0, a_read_process.stderr + a_read_process.stdout)
        self.assertFalse(a_read["base_exists"])

        b_request = self.prepare_request("addraceb94731", target_rel)
        self.bind_read_token(b_request, session="add-writer-b")
        prepared_process, prepared = self.box.write("prepare", b_request, session="add-writer-b")
        self.assertEqual(prepared_process.returncode, 0, prepared_process.stderr + prepared_process.stdout)
        applied_process, _ = self.box.write(
            "apply",
            {
                "schema_version": 1,
                "proposal_id": prepared["proposal_id"],
                "target_relative_path": target_rel,
                "proposal_markdown": b_request["proposal_markdown"],
                "proposal_raw_sha256": prepared["proposal_raw_sha256"],
                "proposal_canonical_sha256": prepared["proposal_canonical_sha256"],
                "confirmed_by": "user",
                "confirmation_reference": "conversation:add-writer-b-confirmed",
            },
            session="add-writer-b",
        )
        self.assertEqual(applied_process.returncode, 0, applied_process.stderr + applied_process.stdout)
        b_content = (self.box.vault / target_rel).read_text(encoding="utf-8")

        a_request = self.prepare_request("addracea94731", target_rel)
        a_request["read_token"] = a_read["read_token"]
        stale_process, stale = self.box.write("prepare", a_request, session="add-reader-a")
        self.assertEqual(stale_process.returncode, 2)
        self.assertEqual(stale["reason_code"], "STALE_READ_TOKEN")
        self.assertEqual((self.box.vault / target_rel).read_text(encoding="utf-8"), b_content)

    def test_atomic_update_cas_restores_uncommitted_edit_created_after_precheck(self) -> None:
        session = "studio-atomic-cas-race"
        target_rel, request, prepared = self.prepare_existing_update(
            session=session,
            marker="atomiccas94731",
        )
        target = self.box.vault / target_rel
        concurrent_marker = "CONCURRENT_UNCOMMITTED_FACT_MUST_SURVIVE_94731"
        concurrent = target.read_text(encoding="utf-8") + f"\n{concurrent_marker}\n"

        completed, payload = self.raced_apply(
            session=session,
            target_rel=target_rel,
            request=request,
            prepared=prepared,
            concurrent_markdown=concurrent,
        )

        self.assertEqual(completed.returncode, 2, completed.stderr + completed.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["reason_code"], "TARGET_CHANGED_AFTER_CLAIM")
        self.assertEqual(target.read_text(encoding="utf-8"), concurrent)
        self.assertIn(concurrent_marker, target.read_text(encoding="utf-8"))
        self.assertNotEqual(target.read_text(encoding="utf-8"), request["proposal_markdown"])
        self.assertEqual(list(target.parent.glob(".agent-memory-studio-*")), [])
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            intent_status = conn.execute(
                "SELECT status FROM memory_write_intents WHERE intent_id=?",
                (prepared["proposal_id"],),
            ).fetchone()[0]
            active_claims = conn.execute(
                "SELECT COUNT(*) FROM memory_session_claims WHERE intent_id=? AND status='active'",
                (prepared["proposal_id"],),
            ).fetchone()[0]
        self.assertEqual(intent_status, "failed")
        self.assertEqual(active_claims, 0)

    def test_secondary_update_race_preserves_both_displaced_versions(self) -> None:
        session = "studio-atomic-cas-secondary-race"
        target_rel, request, prepared = self.prepare_existing_update(
            session=session,
            marker="secondarycas94731",
        )
        target = self.box.vault / target_rel
        first_marker = "FIRST_CONCURRENT_FACT_94731"
        second_marker = "SECOND_CONCURRENT_FACT_94731"
        original = target.read_text(encoding="utf-8")
        first = original + f"\n{first_marker}\n"
        second = original + f"\n{second_marker}\n"

        completed, payload = self.raced_apply(
            session=session,
            target_rel=target_rel,
            request=request,
            prepared=prepared,
            concurrent_markdown=first,
            secondary_markdown=second,
        )

        self.assertEqual(completed.returncode, 2, completed.stderr + completed.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["reason_code"], "TARGET_WRITE_RECOVERY_REQUIRED")
        preserved_texts = [target.read_text(encoding="utf-8")]
        for sidecar in target.parent.glob(".agent-memory-studio-*"):
            preserved_texts.append(sidecar.read_text(encoding="utf-8"))
        combined = "\n".join(preserved_texts)
        self.assertIn(first_marker, combined)
        self.assertIn(second_marker, combined)
        self.assertGreaterEqual(len(preserved_texts), 3)

    @unittest.skipIf(os.name == "nt", "POSIX process-group semantics are validated on macOS/Linux")
    def test_closeout_timeout_kills_grandchild_before_releasing_studio_lock(self) -> None:
        first_session = "studio-timeout-first"
        second_session = "studio-timeout-second"
        first_target = "项目/TimeoutFirst.md"
        second_target = "项目/TimeoutSecond.md"
        first_request = self.prepare_request("timeoutfirst94731", first_target)
        second_request = self.prepare_request("timeoutsecond94731", second_target)
        self.bind_read_token(first_request, session=first_session)
        self.bind_read_token(second_request, session=second_session)
        first_prepared_process, first_prepared = self.box.write(
            "prepare",
            first_request,
            session=first_session,
        )
        second_prepared_process, second_prepared = self.box.write(
            "prepare",
            second_request,
            session=second_session,
        )
        self.assertEqual(
            first_prepared_process.returncode,
            0,
            first_prepared_process.stderr + first_prepared_process.stdout,
        )
        self.assertEqual(
            second_prepared_process.returncode,
            0,
            second_prepared_process.stderr + second_prepared_process.stdout,
        )

        marker = self.box.root / "grandchild-marker.log"
        overlap_marker = self.box.root / "grandchild-overlap.log"
        fake_python = self.box.root / "fake-closeout-python"
        fake_python.write_text(
            "#!/usr/bin/env python3\n"
            "import os, subprocess, sys, time\n"
            "marker = os.environ['STUDIO_GRANDCHILD_MARKER']\n"
            "code = (\"import os,sqlite3,time\\n\"\n"
            "        \"p=os.environ['STUDIO_GRANDCHILD_MARKER']\\n\"\n"
            "        \"db=os.environ['STUDIO_STATE_DB']\\n\"\n"
            "        \"proposal=os.environ['STUDIO_SECOND_PROPOSAL_ID']\\n\"\n"
            "        \"overlap=os.environ['STUDIO_OVERLAP_MARKER']\\n\"\n"
            "        \"while True:\\n\"\n"
            "        \"  try:\\n\"\n"
            "        \"    with sqlite3.connect(db,timeout=0.05) as c:\\n\"\n"
            "        \"      row=c.execute('select status from memory_write_intents where intent_id=?',(proposal,)).fetchone()\\n\"\n"
            "        \"    if row and row[0]=='cancelled':\\n\"\n"
            "        \"      with open(overlap,'a',encoding='utf-8') as h: h.write('overlap'); h.flush()\\n\"\n"
            "        \"  except sqlite3.Error:\\n\"\n"
            "        \"    pass\\n\"\n"
            "        \"  with open(p,'a',encoding='utf-8') as h: h.write('tick'); h.flush()\\n\"\n"
            "        \"  time.sleep(0.02)\\n\")\n"
            "subprocess.Popen([sys.executable, '-c', code], env=os.environ.copy(),\n"
            "                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "time.sleep(60)\n",
            encoding="utf-8",
        )
        fake_python.chmod(0o700)
        apply_request = {
            "schema_version": 1,
            "proposal_id": first_prepared["proposal_id"],
            "target_relative_path": first_target,
            "proposal_markdown": first_request["proposal_markdown"],
            "proposal_raw_sha256": first_prepared["proposal_raw_sha256"],
            "proposal_canonical_sha256": first_prepared["proposal_canonical_sha256"],
            "confirmed_by": "user",
            "confirmation_reference": "conversation:timeout-confirmed",
        }
        cancel_request = {
            "schema_version": 1,
            "proposal_id": second_prepared["proposal_id"],
        }
        environment = {
            "AGENT_MEMORY_PYTHON": str(fake_python),
            "STUDIO_GRANDCHILD_MARKER": str(marker),
            "STUDIO_OVERLAP_MARKER": str(overlap_marker),
            "STUDIO_STATE_DB": str(self.box.state_db),
            "STUDIO_SECOND_PROPOSAL_ID": second_prepared["proposal_id"],
        }

        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(
                self.box.write,
                "apply",
                apply_request,
                session=first_session,
                extra_env=environment,
                closeout_timeout=1,
            )
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(marker.exists(), "fake closeout grandchild never started")
            second_future = executor.submit(
                self.box.write,
                "cancel",
                cancel_request,
                session=second_session,
            )
            first_process, first_payload = first_future.result(timeout=20)
            second_process, second_payload = second_future.result(timeout=20)

        self.assertEqual(first_process.returncode, 2)
        self.assertEqual(first_payload["reason_code"], "CLOSEOUT_TIMEOUT")
        self.assertEqual(second_process.returncode, 0, second_process.stderr + second_process.stdout)
        self.assertEqual(second_payload["status"], "cancelled")
        self.assertFalse(
            overlap_marker.exists(),
            "a second studio write acquired the lock while the timed-out process group was alive",
        )
        size_after_unlock = marker.stat().st_size
        time.sleep(0.4)
        self.assertEqual(marker.stat().st_size, size_after_unlock)


if __name__ == "__main__":
    unittest.main()
