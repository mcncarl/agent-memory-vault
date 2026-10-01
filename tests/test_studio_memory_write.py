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
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from state_fixture import initialize_full_state
import agent_memory_closeout as memory_closeout
from agent_memory_generated_index_capability import (
    CAPABILITY_BINDING_ENV as GENERATED_INDEX_CAPABILITY_BINDING_ENV,
    CAPABILITY_PATH_ENV as GENERATED_INDEX_CAPABILITY_PATH_ENV,
    CAPABILITY_TOKEN_ENV as GENERATED_INDEX_CAPABILITY_TOKEN_ENV,
    commit_generated_index_transaction,
    issue_generated_index_capability,
)

MEMORYCTL = SCRIPTS / "memoryctl"
INSTALLER = SCRIPTS / "install_runtime.py"

RACED_APPLY_HELPER = r"""
import contextlib
import json
import os
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path.cwd() / "scripts"))
import agent_memory_write as memory_write

request = json.load(sys.stdin)
concurrent_markdown = request.pop("_concurrent_markdown")
secondary_markdown = request.pop("_secondary_markdown", "")
if os.environ.get("AILU_FAIL_CLAIM_RELEASE") == "1":
    def fail_claim_release(*_args, **_kwargs):
        raise OSError("simulated claim projection failure")
    memory_write.memory_claim.complete_claim_paths = fail_claim_release
original_capture = memory_write._atomic_capture_target
original_restore = memory_write._atomic_restore_target

def raced_capture(proposal_path, target_path, displaced_path):
    target_path.write_text(concurrent_markdown, encoding="utf-8")
    return original_capture(proposal_path, target_path, displaced_path)

def raced_restore(captured_path, target_path, proposal_path):
    target_path.write_text(secondary_markdown, encoding="utf-8")
    return original_restore(captured_path, target_path, proposal_path)

try:
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(memory_write, "_atomic_capture_target", side_effect=raced_capture))
        if secondary_markdown:
            stack.enter_context(mock.patch.object(memory_write, "_atomic_restore_target", side_effect=raced_restore))
        result = memory_write.apply(
            request,
            raw_session_id=memory_write._raw_session_id(),
            closeout_timeout=90,
        )
except memory_write.MemoryWriteError as exc:
    print(json.dumps({"ok": False, "reason_code": exc.reason_code}, separators=(",", ":")))
    raise SystemExit(2)
else:
    print(json.dumps(result, separators=(",", ":")))
    raise SystemExit(0 if result.get("ok") else 2)
"""


TIMEOUT_APPLY_HELPER = r"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "scripts"))
import agent_memory_write as memory_write

memory_write.ACTOR = "ailu"
memory_write.CLOSEOUT_SCRIPT = Path(os.environ["AILU_FAKE_CLOSEOUT_SCRIPT"])
if os.environ.get("AILU_FORCE_KILLPG_PERMISSION_ERROR") == "1":
    def denied_killpg(group_id, sig):
        raise PermissionError("simulated Darwin killpg EPERM")
    memory_write.os.killpg = denied_killpg
request = json.load(sys.stdin)
try:
    result = memory_write.apply(
        request,
        raw_session_id=memory_write._raw_session_id(),
        closeout_timeout=1,
    )
except memory_write.MemoryWriteError as exc:
    print(json.dumps({"ok": False, "reason_code": exc.reason_code}, separators=(",", ":")))
    raise SystemExit(2)
else:
    print(json.dumps(result, separators=(",", ":")))
"""


APPLY_LOCKED_ONLY_HELPER = r"""
import contextlib
import json
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path.cwd() / "scripts"))
import agent_memory_write as memory_write

request = json.load(sys.stdin)
skip_validation = bool(request.pop("_skip_validation", False))
try:
    with contextlib.ExitStack() as stack:
        if skip_validation:
            stack.enter_context(
                mock.patch.object(
                    memory_write.write_intent,
                    "validate_closeout",
                    return_value={"ok": True, "mutated": False},
                )
            )
        with memory_write.writer_lock(10):
            result = memory_write._apply_locked(
                request,
                raw_session_id=memory_write._raw_session_id(),
            )
except memory_write.MemoryWriteError as exc:
    print(json.dumps({"ok": False, "reason_code": exc.reason_code}))
    raise SystemExit(2)
else:
    print(json.dumps({
        "ok": True,
        "closeout_required": bool(result.get("closeout_required")),
        "proposal_already_written": bool(result.get("proposal_already_written")),
    }))
"""


COMMITTED_HISTORY_PROOF_HELPER = r"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "scripts"))
import agent_memory_closeout as closeout

request = json.load(sys.stdin)
rows = closeout.all_active_claim_rows(read_only=True)
if request.get("claim_fence_delta"):
    for row in rows:
        if row.get("rel_path") == request.get("claim_rel_path"):
            row["fencing_token"] = str(
                int(row.get("fencing_token") or 0)
                + int(request["claim_fence_delta"])
            )
entry = closeout.GitEntry(
    status=str(request.get("status", "A")),
    repo_path=str(request["repo_path"]),
    path=(closeout.REPO_ROOT / str(request["repo_path"])).resolve(),
    previous_repo_path=str(request.get("previous_repo_path", "")),
)
result = closeout._other_session_committed_history_is_exact_validated(
    entry,
    claim_rows=rows,
    current_head=closeout.current_git_head()[0],
    dirty_repo_paths=set(request.get("dirty_repo_paths", [])),
)
print(json.dumps({"ok": bool(result)}))
"""


VALIDATE_INTENT_ONLY_HELPER = r"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "scripts"))
import agent_memory_intent as write_intent

request = json.load(sys.stdin)
try:
    result = write_intent.validate_closeout(
        str(request["proposal_id"]),
        actor="ailu",
        raw_session_id=os.environ["AGENT_MEMORY_SESSION_ID"],
        target=str(request["target_relative_path"]),
        mutate=True,
    )
except write_intent.IntentError as exc:
    print(json.dumps({"ok": False, "reason_code": exc.reason_code}))
    raise SystemExit(2)
else:
    print(json.dumps(result))
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


class AiluWriteSandbox:
    def __init__(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.git_root = self.root / "repo"
        self.vault = self.git_root / "AgentMemory"
        self.runtime = self.root / "runtime"
        self.test_home = self.root / "test-home"
        self.state_db = self.runtime / "state.sqlite"
        self.config = self.runtime / "config" / "agent-memory.toml"
        self.git_root.mkdir(parents=True)
        self.runtime.mkdir(parents=True)
        self.test_home.mkdir(parents=True)
        self._create_minimal_vault()
        self._init_git()
        self._write_config()
        self.base_env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("AGENT_MEMORY_")
            and key
            not in {
                "MEMORY_ACTOR",
                "CODEX_THREAD_ID",
                "CLAUDE_SESSION_ID",
                "CLAUDE_CODE_SESSION_ID",
            }
        }
        self.base_env["HOME"] = str(self.test_home)
        self.base_env["USERPROFILE"] = str(self.test_home)
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
            "project_id: ailu\n"
            "app_id: ailu\n"
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
            "risk_class: ordinary\n"
            "temporal_policy: reviewable\n"
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
        git(self.git_root, "config", "user.name", "Ailu Write E2E")
        git(self.git_root, "config", "user.email", "ailu-write@example.invalid")
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
                    "[write_gateway]",
                    'mode = "enforce"',
                    "writer_protocol_version = 2",
                    "state_schema_required = 4",
                    'canonical_actors = ["codex", "claude", "ailu"]',
                    "path_fencing = true",
                    "claims_are_projection = true",
                    "full_vault = true",
                    "ttl_hours = 24",
                    "max_proposal_bytes = 1048576",
                    "max_target_bytes = 1048576",
                    "",
                    "[write_intents]",
                    "enabled = false",
                    'enforcement = "off"',
                    "protected_paths = []",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        if os.name != "nt":
            self.config.chmod(0o600)

    def _initialize_state(self) -> None:
        initialize_full_state(self.state_db)
        audit_initialized = run(
            [
                sys.executable,
                str(SCRIPTS / "agent_memory_migrate.py"),
                "audit-init",
                "--json",
            ],
            cwd=REPO_ROOT,
            env=self.base_env,
        )
        if audit_initialized.returncode != 0:
            raise AssertionError(audit_initialized.stderr + audit_initialized.stdout)
        scanned = run(
            [
                sys.executable,
                str(SCRIPTS / "agent_memory_index.py"),
                "--scan",
            ],
            cwd=REPO_ROOT,
            env=self.base_env,
        )
        if scanned.returncode != 0:
            raise AssertionError(scanned.stderr + scanned.stdout)
        checked_projection = sorted(
            (
                path.resolve().relative_to(self.vault).as_posix(),
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            for path in self.vault.rglob("*.md")
            if path.is_file() and path.resolve() != (self.vault / "INDEX.md").resolve()
        )
        canonical_projection = lambda value: hashlib.sha256(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        transaction_binding = {
            "transaction_id": hashlib.sha256(
                f"studio-index-fixture:{self.root}".encode("utf-8")
            ).hexdigest()[:32],
            "actor": "test",
            "task_sha256": hashlib.sha256(b"studio-index-fixture").hexdigest(),
            "vault_root_sha256": hashlib.sha256(str(self.vault).encode("utf-8")).hexdigest(),
            "git_head": git(self.git_root, "rev-parse", "HEAD"),
            "index_base_sha256": hashlib.sha256((self.vault / "INDEX.md").read_bytes()).hexdigest(),
            "full_vault_inputs_sha256": canonical_projection(checked_projection),
            "lease_fences_sha256": canonical_projection([]),
        }
        previous_closeout_state_db = memory_closeout.STATE_DB
        memory_closeout.STATE_DB = self.state_db
        try:
            memory_closeout._register_generated_index_closeout_transaction(
                transaction_binding=transaction_binding,
            )
        finally:
            memory_closeout.STATE_DB = previous_closeout_state_db
        capability = issue_generated_index_capability(
            self.runtime,
            state_db=self.state_db,
            transaction_binding=transaction_binding,
            issuer_pid=os.getpid(),
        )
        index_env = self.base_env.copy()
        index_env[GENERATED_INDEX_CAPABILITY_PATH_ENV] = capability["path"]
        index_env[GENERATED_INDEX_CAPABILITY_TOKEN_ENV] = capability["token"]
        index_env[GENERATED_INDEX_CAPABILITY_BINDING_ENV] = json.dumps(
            transaction_binding,
            sort_keys=True,
            separators=(",", ":"),
        )
        completed = run(
            [
                sys.executable,
                str(SCRIPTS / "agent_memory_index.py"),
                "--sync-generated-index",
            ],
            cwd=REPO_ROOT,
            env=index_env,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr + completed.stdout)
        if git(self.git_root, "status", "--porcelain", "--", "AgentMemory/INDEX.md"):
            git(self.git_root, "add", "--", "AgentMemory/INDEX.md")
            git(self.git_root, "commit", "-qm", "synchronize generated index fixture")
        commit_generated_index_transaction(
            self.state_db,
            transaction_binding,
            generated_sha256=hashlib.sha256(
                (self.vault / "INDEX.md").read_bytes()
            ).hexdigest(),
            closeout_git_commit=git(self.git_root, "rev-parse", "HEAD"),
        )

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
                "-I",
                "-S",
                str(memoryctl),
                "--actor",
                "ailu",
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

    def apply_locked_only(
        self,
        request: dict[str, object],
        *,
        session: str,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        completed = run(
            [sys.executable, "-c", APPLY_LOCKED_ONLY_HELPER],
            cwd=REPO_ROOT,
            env=self.env(session),
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

    def committed_history_proof(
        self,
        request: dict[str, object],
        *,
        session: str,
    ) -> bool:
        completed = run(
            [sys.executable, "-c", COMMITTED_HISTORY_PROOF_HELPER],
            cwd=REPO_ROOT,
            env=self.env(session),
            input_text=json.dumps(request, ensure_ascii=False),
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr + completed.stdout)
        payload = json.loads(completed.stdout)
        return bool(payload["ok"])

    def validate_intent_only(
        self,
        request: dict[str, object],
        *,
        session: str,
    ) -> dict[str, object]:
        completed = run(
            [sys.executable, "-c", VALIDATE_INTENT_ONLY_HELPER],
            cwd=REPO_ROOT,
            env=self.env(session),
            input_text=json.dumps(request, ensure_ascii=False),
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr + completed.stdout)
        payload = json.loads(completed.stdout)
        if not isinstance(payload, dict):
            raise AssertionError(f"expected JSON object, got {payload!r}")
        return payload

    def closeout_claimed_only(
        self,
        *,
        session: str,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        completed = run(
            [
                sys.executable,
                str(SCRIPTS / "agent_memory_closeout.py"),
                "--actor",
                "ailu",
                "--claimed-only",
                "--commit",
                "--json",
                "--trigger",
                "manual",
                "--skip-audit",
                "--lock-timeout",
                "30",
            ],
            cwd=REPO_ROOT,
            env=self.env(session),
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


class AiluMemoryWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.box = AiluWriteSandbox()

    def tearDown(self) -> None:
        self.box.close()

    def prepare_request(self, token: str, target: str) -> dict[str, object]:
        return {
            "schema_version": 2,
            "summary": token,
            "proposal_markdown": self.box.add_proposal(token),
            "target_relative_path": target,
            "source_class": "user_direct",
            "knowledge_kind": "rule",
            "asserted_by": "user",
            "evidence_ref": f"conversation:{token}",
            "current_project": "ailu",
            "app_id": "ailu",
            "project_id": "ailu",
        }

    def bind_read_token(
        self,
        request: dict[str, object],
        *,
        session: str,
    ) -> dict[str, object]:
        target = str(request["target_relative_path"])
        read_request: dict[str, object] = {
            "schema_version": 2,
            "target_relative_path": target,
            "app_id": request.get("app_id", "ailu"),
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
        generated_memory_id = str(payload.get("generated_memory_id", "")).strip()
        if generated_memory_id:
            proposal = str(request["proposal_markdown"])
            self.assertTrue(proposal.startswith("---\n"))
            request["proposal_markdown"] = proposal.replace(
                "---\n",
                f"---\nmemory_id: {generated_memory_id}\n",
                1,
            )
        return request

    def prepare_existing_update(
        self,
        *,
        session: str,
        marker: str,
    ) -> tuple[str, dict[str, object], dict[str, object]]:
        target_rel = "项目/Existing.md"
        request: dict[str, object] = {
            "schema_version": 2,
            "summary": f"Stable noop fact noopprobe94731 {marker}",
            "proposal_markdown": self.box._memory_text(
                "Existing noopprobe94731",
                f"Stable noop fact noopprobe94731 plus {marker} durable version.",
                project=True,
            ),
            "target_relative_path": target_rel,
            "source_class": "user_direct",
            "knowledge_kind": "rule",
            "asserted_by": "user",
            "evidence_ref": f"conversation:{marker}",
            "current_project": "ailu",
            "app_id": "ailu",
            "project_id": "ailu",
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

    def prepare_locked_add(
        self,
        *,
        session: str,
        target_rel: str,
        token: str,
        skip_validation: bool = False,
    ) -> tuple[dict[str, object], dict[str, object]]:
        request = self.prepare_request(token, target_rel)
        self.bind_read_token(request, session=session)
        prepared_process, prepared = self.box.write(
            "prepare",
            request,
            session=session,
        )
        self.assertEqual(
            prepared_process.returncode,
            0,
            prepared_process.stderr + prepared_process.stdout,
        )
        apply_request = {
            "schema_version": 2,
            "proposal_id": prepared["proposal_id"],
            "fencing_token": prepared["fencing_token"],
            "target_relative_path": target_rel,
            "proposal_markdown": request["proposal_markdown"],
            "proposal_raw_sha256": prepared["proposal_raw_sha256"],
            "proposal_canonical_sha256": prepared["proposal_canonical_sha256"],
            "confirmed_by": "user",
            "confirmation_reference": f"conversation:{token}",
        }
        helper_request = dict(apply_request)
        if skip_validation:
            helper_request["_skip_validation"] = True
        locked_process, locked = self.box.apply_locked_only(
            helper_request,
            session=session,
        )
        self.assertEqual(
            locked_process.returncode,
            0,
            locked_process.stderr + locked_process.stdout,
        )
        self.assertTrue(locked["closeout_required"])
        return apply_request, prepared

    def raced_apply(
        self,
        *,
        session: str,
        target_rel: str,
        request: dict[str, object],
        prepared: dict[str, object],
        concurrent_markdown: str,
        secondary_markdown: str = "",
        fail_claim_release: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        apply_request = {
            "schema_version": 2,
            "proposal_id": prepared["proposal_id"],
            "fencing_token": prepared["fencing_token"],
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
        environment = self.box.env(session)
        if fail_claim_release:
            environment["AILU_FAIL_CLAIM_RELEASE"] = "1"
        completed = run(
            [sys.executable, "-c", RACED_APPLY_HELPER],
            cwd=REPO_ROOT,
            env=environment,
            input_text=json.dumps(apply_request, ensure_ascii=False),
        )
        return completed, json.loads(completed.stdout)

    def test_prepare_fails_closed_on_canonical_path_frontmatter_downgrade(self) -> None:
        session = "path-floor-session"
        request = self.prepare_request("pathfloorprobe", "项目/path-floor.md")
        proposal = str(request["proposal_markdown"])
        request["proposal_markdown"] = proposal.replace(
            "memory_type: project\ntrack: project",
            "memory_type: governance\ntrack: misc",
        ).replace("temporal_policy: reviewable", "temporal_policy: structural")
        self.bind_read_token(request, session=session)
        completed, payload = self.box.write("prepare", request, session=session)
        self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
        self.assertEqual(payload["reason_code"], "PATH_POLICY_DOWNGRADE_FORBIDDEN")

    @unittest.skipIf(
        sys.version_info < (3, 10),
        "the managed Runtime installer requires Python 3.10 or newer",
    )
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
        managed_python = self.box.runtime / ".venv" / "bin" / "python"
        # ``install_runtime.py`` installs the immutable bundle only. The POSIX
        # installer normally performs this reviewed private-config migration
        # before publish-ready verification; reproduce that boundary here.
        config_text = self.box.config.read_text(encoding="utf-8")
        config_text = config_text.replace(
            f"python = {toml_string(sys.executable)}",
            f"python = {toml_string(managed_python)}",
        )
        self.box.config.write_text(config_text, encoding="utf-8")
        self.box.config.chmod(0o600)
        scheduler = run(
            [
                str(installed_memoryctl),
                "--actor",
                "migration",
                "install-audit-launchagent",
                "--apply",
                "--runtime-root",
                str(self.box.runtime),
                "--python",
                str(managed_python),
                "--backup-dir",
                str(self.box.root / "launchagent-backup"),
                "--defer-load",
                "--json",
            ],
            cwd=self.box.runtime,
            env=self.box.base_env,
        )
        self.assertEqual(scheduler.returncode, 0, scheduler.stderr + scheduler.stdout)
        published = run(
            [
                str(installed_memoryctl),
                "--actor", "migration", "migrate", "verify",
                "--publish-ready", "--no-host-hooks", "--json",
            ],
            cwd=self.box.runtime,
            env=self.box.base_env,
        )
        self.assertEqual(published.returncode, 0, published.stderr + published.stdout)
        session = "ailu-installed-runtime"
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
            "schema_version": 2,
            "proposal_id": prepared["proposal_id"],
            "fencing_token": prepared["fencing_token"],
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
                "-I",
                "-S",
                str(MEMORYCTL),
                "--actor",
                "ailu",
                "write",
                "read-target",
                "--json",
                f"--session-id={private_marker}",
            ],
            cwd=REPO_ROOT,
            env=self.box.base_env,
            input_text=json.dumps(
                {
                    "schema_version": 2,
                    "target_relative_path": "项目/Existing.md",
                    "app_id": "ailu",
                    "project_id": "ailu",
                }
            ),
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertNotIn(private_marker, completed.stderr)
        self.assertIn("environment only", completed.stderr)

    def test_read_target_returns_exact_content_without_touching_runtime_state(self) -> None:
        session = "ailu-read-session"
        existing = self.box.vault / "项目" / "Existing.md"
        expected_bytes = existing.read_bytes()
        expected = expected_bytes.decode("utf-8")
        state_before = hashlib.sha256(self.box.state_db.read_bytes()).hexdigest()

        found_process, found = self.box.write(
            "read-target",
            {
                "schema_version": 2,
                "target_relative_path": "项目/Existing.md",
                "app_id": "ailu",
                "project_id": "ailu",
            },
            session=session,
        )
        missing_process, missing = self.box.write(
            "read-target",
            {
                "schema_version": 2,
                "target_relative_path": "项目/NewMemory.md",
                "app_id": "ailu",
                "project_id": "ailu",
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
        state_after = hashlib.sha256(self.box.state_db.read_bytes()).hexdigest()
        self.assertEqual(state_after, state_before)
        wal = self.box.state_db.with_name(self.box.state_db.name + "-wal")
        self.assertFalse(wal.is_file() and wal.stat().st_size)
        self.assertFalse((self.box.runtime / "locks" / "memory-write.lock").exists())

    def test_read_target_blocks_unsafe_invalid_and_oversized_content(self) -> None:
        session = "ailu-read-safety"
        invalid = self.box.vault / "项目" / "Invalid.md"
        invalid.write_bytes(b"# invalid\n\xff\n")
        oversized = self.box.vault / "项目" / "Oversized.md"
        oversized.write_bytes(b"x" * (2 * 1024 * 1024 + 1))

        outside_process, outside = self.box.write(
            "read-target",
            {
                "schema_version": 2,
                "target_relative_path": "../outside.md",
                "app_id": "ailu",
                "project_id": "ailu",
            },
            session=session,
        )
        invalid_process, invalid_result = self.box.write(
            "read-target",
            {
                "schema_version": 2,
                "target_relative_path": "项目/Invalid.md",
                "app_id": "ailu",
                "project_id": "ailu",
            },
            session=session,
        )
        oversized_process, oversized_result = self.box.write(
            "read-target",
            {
                "schema_version": 2,
                "target_relative_path": "项目/Oversized.md",
                "app_id": "ailu",
                "project_id": "ailu",
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
        session = "ailu-session-one"
        token = "newwritebody94731"
        target_rel = "项目/AiluWrite.md"
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
        self.assertEqual(intent[1:4], (1, "ADD", "ailu"))
        self.assertEqual(intent[4], hashlib.sha256(session.encode()).hexdigest()[:16])
        self.assertEqual(intent[5], "user")
        for state_path in self.box.runtime.glob("state.sqlite*"):
            self.assertNotIn(token.encode(), state_path.read_bytes())

        apply_request = {
            "schema_version": 2,
            "proposal_id": proposal_id,
            "fencing_token": prepared["fencing_token"],
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

    def test_two_sessions_recover_exact_committed_proposals_without_absorbing_ailu_state(self) -> None:
        """Committed-clean validated peers must not deadlock claimed-only recovery.

        The semantic worker is represented by a private executable that records
        only its argv.  SQLite, both FTS indexes, generated INDEX, Git history,
        receipts, and claims use the real temporary Runtime and repository.
        """

        zvec_marker = self.box.root / "zvec-routes.jsonl"
        fake_python = self.box.root / "fake-zvec-python"
        fake_python.write_text(
            f"#!{sys.executable}\n"
            "import json,sys\n"
            f"with open({str(zvec_marker)!r}, 'a', encoding='utf-8') as handle:\n"
            "    handle.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "print(json.dumps({'ok': True}))\n",
            encoding="utf-8",
        )
        fake_python.chmod(0o700)
        semantic_before = (
            "[semantic_retrieval]\n"
            "enabled = false\n"
            f"python = {toml_string(sys.executable)}"
        )
        semantic_after = (
            "[semantic_retrieval]\n"
            "enabled = true\n"
            f"python = {toml_string(fake_python)}\n"
            "run_vector_index_after_closeout = true"
        )
        config_text = self.box.config.read_text(encoding="utf-8")
        self.assertIn(semantic_before, config_text)
        self.box.config.write_text(
            config_text.replace(semantic_before, semantic_after, 1),
            encoding="utf-8",
        )

        sessions = ("ailu-recovery-a", "ailu-recovery-b")
        targets = ("项目/CommittedA.md", "项目/CommittedB.md")
        prepared_items: list[tuple[str, str, dict[str, object], dict[str, object]]] = []
        for session, target_rel, token in zip(
            sessions,
            targets,
            ("committedrecoverya94731", "committedrecoveryb94731"),
            strict=True,
        ):
            request = self.prepare_request(token, target_rel)
            self.bind_read_token(request, session=session)
            prepared_process, prepared = self.box.write(
                "prepare",
                request,
                session=session,
            )
            self.assertEqual(
                prepared_process.returncode,
                0,
                prepared_process.stderr + prepared_process.stdout,
            )
            apply_request = {
                "schema_version": 2,
                "proposal_id": prepared["proposal_id"],
                "fencing_token": prepared["fencing_token"],
                "target_relative_path": target_rel,
                "proposal_markdown": request["proposal_markdown"],
                "proposal_raw_sha256": prepared["proposal_raw_sha256"],
                "proposal_canonical_sha256": prepared[
                    "proposal_canonical_sha256"
                ],
                "confirmed_by": "user",
                "confirmation_reference": f"conversation:{token}",
            }
            locked_process, locked = self.box.apply_locked_only(
                apply_request,
                session=session,
            )
            self.assertEqual(
                locked_process.returncode,
                0,
                locked_process.stderr + locked_process.stdout,
            )
            self.assertTrue(locked["closeout_required"])
            self.assertFalse(locked["proposal_already_written"])
            prepared_items.append((session, target_rel, apply_request, prepared))

        initial_head = git(self.box.git_root, "rev-parse", "HEAD")
        closeout_log = self.box.runtime / "logs" / "closeout.jsonl"
        closeout_log.parent.mkdir(parents=True, exist_ok=True)
        closeout_log.write_text(
            json.dumps(
                {
                    "status": "ok",
                    "git_observed_through": initial_head,
                    "git_head_after": initial_head,
                }
            )
            + "\n",
            encoding="utf-8",
        )

        ailu_state = self.box.git_root / ".ailu" / "conversation-writer.json"
        obsidian_state = self.box.git_root / ".obsidian" / "workspace.json"
        ailu_state.parent.mkdir(parents=True)
        obsidian_state.parent.mkdir(parents=True)
        ailu_state.write_text('{"version":1}\n', encoding="utf-8")
        obsidian_state.write_text('{"layout":1}\n', encoding="utf-8")

        target_a = self.box.vault / targets[0]
        target_b = self.box.vault / targets[1]
        before_a = target_a.read_bytes()
        before_b = target_b.read_bytes()
        git(
            self.box.git_root,
            "add",
            f"AgentMemory/{targets[0]}",
            ".ailu/conversation-writer.json",
        )
        git(self.box.git_root, "commit", "-qm", "external backup a")
        proposal_commit_a = git(self.box.git_root, "rev-parse", "HEAD")
        git(
            self.box.git_root,
            "add",
            f"AgentMemory/{targets[1]}",
            ".obsidian/workspace.json",
        )
        git(self.box.git_root, "commit", "-qm", "external backup b")
        proposal_commit_b = git(self.box.git_root, "rev-parse", "HEAD")
        validations = [
            self.box.validate_intent_only(item[2], session=item[0])
            for item in prepared_items
        ]
        self.assertTrue(all(validation["ok"] for validation in validations))
        self.assertTrue(all(validation["early_commit"] for validation in validations))
        self.assertEqual(
            [validation["proposal_commit"] for validation in validations],
            [proposal_commit_a, proposal_commit_b],
        )

        repo_path_b = f"AgentMemory/{targets[1]}"
        self.assertTrue(
            self.box.committed_history_proof(
                {"repo_path": repo_path_b},
                session=sessions[0],
            )
        )
        self.assertFalse(
            self.box.committed_history_proof(
                {
                    "repo_path": repo_path_b,
                    "claim_rel_path": targets[1],
                    "claim_fence_delta": 1,
                },
                session=sessions[0],
            )
        )
        self.assertFalse(
            self.box.committed_history_proof(
                {"repo_path": repo_path_b.replace("AgentMemory", "agentmemory", 1)},
                session=sessions[0],
            )
        )
        self.assertFalse(
            self.box.committed_history_proof(
                {"repo_path": "AgentMemory/项目/Cafe\u0301.md"},
                session=sessions[0],
            )
        )
        self.assertFalse(
            self.box.committed_history_proof(
                {
                    "repo_path": repo_path_b,
                    "status": "R100",
                    "previous_repo_path": "AgentMemory/项目/UnapprovedOld.md",
                },
                session=sessions[0],
            )
        )
        alias = self.box.vault / "项目" / "CommittedAlias.md"
        alias.symlink_to(target_b.name)
        try:
            self.assertFalse(
                self.box.committed_history_proof(
                    {"repo_path": "AgentMemory/项目/CommittedAlias.md"},
                    session=sessions[0],
                )
            )
        finally:
            alias.unlink()

        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO memory_file_observations (
                  path, rel_path, sha256, actor, session_hash, intent_id,
                  fencing_token, git_commit, observed_at
                ) VALUES (?, ?, ?, ?, ?, '', 0, ?, ?)
                """,
                (
                    str(target_b.resolve()),
                    targets[1],
                    hashlib.sha256(target_b.read_bytes()).hexdigest(),
                    "codex",
                    "stale-observation",
                    proposal_commit_b,
                    "2026-08-25T00:00:00+00:00",
                ),
            )
        ailu_state.write_text('{"version":2,"dirty":true}\n', encoding="utf-8")
        dirty_ailu = ailu_state.read_bytes()
        stat_a = target_a.stat()
        stat_b = target_b.stat()

        first_process, first = self.box.write(
            "apply",
            prepared_items[0][2],
            session=sessions[0],
        )
        self.assertEqual(
            first_process.returncode,
            0,
            first_process.stderr + first_process.stdout,
        )
        self.assertEqual(first["status"], "applied")
        self.assertTrue(first["idempotent"])
        self.assertEqual(first["git_commit"], proposal_commit_a)
        self.assertEqual(target_a.read_bytes(), before_a)
        self.assertEqual(target_b.read_bytes(), before_b)
        self.assertEqual(target_a.stat().st_ino, stat_a.st_ino)
        self.assertEqual(target_a.stat().st_mtime_ns, stat_a.st_mtime_ns)
        self.assertEqual(target_b.stat().st_ino, stat_b.st_ino)
        self.assertEqual(target_b.stat().st_mtime_ns, stat_b.st_mtime_ns)
        self.assertEqual(ailu_state.read_bytes(), dirty_ailu)
        self.assertEqual(
            git(
                self.box.git_root,
                "diff",
                "--cached",
                "--name-only",
                "--",
                ".ailu/conversation-writer.json",
            ),
            "",
        )
        first_closeout = json.loads(closeout_log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(first_closeout["git_previous_observed_head"], initial_head)
        self.assertEqual(first_closeout["git_observed_through"], initial_head)
        self.assertTrue(
            any("deferred 1 exact committed file" in item for item in first_closeout["info"])
        )
        self.assertTrue(
            any("held Git observation baseline for 1" in item for item in first_closeout["info"])
        )

        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn:
            for target_rel in targets:
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM memory_docs WHERE rel_path=?",
                        (target_rel,),
                    ).fetchone()[0],
                    1,
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM memory_fts_unicode WHERE rel_path=?",
                        (target_rel,),
                    ).fetchone()[0],
                    1,
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM memory_fts_trigram WHERE rel_path=?",
                        (target_rel,),
                    ).fetchone()[0],
                    1,
                )
            first_receipt = conn.execute(
                "SELECT outcome, git_commit FROM memory_write_receipts "
                "WHERE intent_id=?",
                (prepared_items[0][3]["proposal_id"],),
            ).fetchone()
            second_receipts = conn.execute(
                "SELECT COUNT(*) FROM memory_write_receipts WHERE intent_id=?",
                (prepared_items[1][3]["proposal_id"],),
            ).fetchone()[0]
            active_claims = conn.execute(
                "SELECT rel_path FROM memory_session_claims WHERE status='active'"
            ).fetchall()
        self.assertEqual(first_receipt, ("completed", proposal_commit_a))
        self.assertEqual(second_receipts, 0)
        self.assertEqual(active_claims, [(targets[1],)])
        generated_index = (self.box.vault / "INDEX.md").read_text(encoding="utf-8")
        self.assertIn(targets[0], generated_index)
        self.assertIn(targets[1], generated_index)

        routes_after_first = [
            json.loads(line)
            for line in zvec_marker.read_text(encoding="utf-8").splitlines()
        ]
        routed_calls_after_first = [
            route for route in routes_after_first if "--changed-file" in route
        ]
        self.assertEqual(len(routed_calls_after_first), 1)
        self.assertIn("--search-stdin", routes_after_first[-1])
        self.assertLess(
            routes_after_first.index(routed_calls_after_first[0]),
            len(routes_after_first) - 1,
            "postwrite reconcile must read the newly refreshed vector index",
        )
        self.assertIn(str(target_a), routed_calls_after_first[0])
        self.assertNotIn(str(target_b), routed_calls_after_first[0])
        self.assertFalse(
            any(".ailu" in value for value in routed_calls_after_first[0])
        )

        second_process, second = self.box.write(
            "apply",
            prepared_items[1][2],
            session=sessions[1],
        )
        self.assertEqual(
            second_process.returncode,
            0,
            second_process.stderr + second_process.stdout,
        )
        self.assertEqual(second["status"], "applied")
        self.assertTrue(second["idempotent"])
        self.assertEqual(second["git_commit"], proposal_commit_b)
        self.assertEqual(target_a.read_bytes(), before_a)
        self.assertEqual(target_b.read_bytes(), before_b)
        self.assertEqual(ailu_state.read_bytes(), dirty_ailu)
        routes = [
            json.loads(line)
            for line in zvec_marker.read_text(encoding="utf-8").splitlines()
        ]
        routed_calls = [route for route in routes if "--changed-file" in route]
        self.assertEqual(len(routed_calls), 2)
        self.assertIn(str(target_b), routed_calls[1])
        self.assertFalse(any(".ailu" in value for route in routes for value in route))

        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn:
            receipts = conn.execute(
                "SELECT intent_id, outcome, git_commit FROM memory_write_receipts "
                "WHERE intent_id IN (?, ?) ORDER BY intent_id",
                (
                    prepared_items[0][3]["proposal_id"],
                    prepared_items[1][3]["proposal_id"],
                ),
            ).fetchall()
            remaining_claims = conn.execute(
                "SELECT COUNT(*) FROM memory_session_claims WHERE status='active'"
            ).fetchone()[0]
        self.assertEqual(len(receipts), 2)
        self.assertEqual({row[1] for row in receipts}, {"completed"})
        self.assertEqual({row[2] for row in receipts}, {proposal_commit_a, proposal_commit_b})
        self.assertEqual(remaining_claims, 0)
        self.assertIn(".ailu/conversation-writer.json", git(self.box.git_root, "status", "--porcelain"))
        commit_before = git(self.box.git_root, "rev-parse", "HEAD")
        repeated_process, repeated = self.box.write(
            "apply",
            prepared_items[1][2],
            session=sessions[1],
        )
        self.assertEqual(
            repeated_process.returncode,
            0,
            repeated_process.stderr + repeated_process.stdout,
        )
        self.assertTrue(repeated["idempotent"])
        self.assertEqual(git(self.box.git_root, "rev-parse", "HEAD"), commit_before)

    def test_empty_observation_baseline_is_held_by_unseen_foreign_active_claim(self) -> None:
        sessions = ("ailu-empty-baseline-a", "ailu-empty-baseline-b")
        targets = ("项目/EmptyBaselineA.md", "项目/EmptyBaselineB.md")
        items = [
            (
                session,
                target,
                *self.prepare_locked_add(
                    session=session,
                    target_rel=target,
                    token=f"emptybaseline{index}94731",
                ),
            )
            for index, (session, target) in enumerate(
                zip(sessions, targets, strict=True),
                start=1,
            )
        ]
        for index, (_, target, _, _) in enumerate(items, start=1):
            git(self.box.git_root, "add", f"AgentMemory/{target}")
            git(self.box.git_root, "commit", "-qm", f"external empty baseline {index}")
        for session, _, apply_request, _ in items:
            validation = self.box.validate_intent_only(
                apply_request,
                session=session,
            )
            self.assertTrue(validation["ok"])
            self.assertTrue(validation["early_commit"])

        closeout_log = self.box.runtime / "logs" / "closeout.jsonl"
        self.assertFalse(closeout_log.exists())
        process, payload = self.box.write(
            "apply",
            items[0][2],
            session=sessions[0],
        )
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        self.assertTrue(payload["idempotent"])
        closeout = json.loads(closeout_log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(closeout["git_previous_observed_head"], "")
        self.assertEqual(closeout["git_observed_through"], "")
        self.assertTrue(
            any("held Git observation baseline for 1" in item for item in closeout["info"])
        )
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn:
            second_receipt = conn.execute(
                "SELECT COUNT(*) FROM memory_write_receipts WHERE intent_id=?",
                (items[1][3]["proposal_id"],),
            ).fetchone()[0]
            second_claim = conn.execute(
                "SELECT COUNT(*) FROM memory_session_claims "
                "WHERE rel_path=? AND status='active'",
                (targets[1],),
            ).fetchone()[0]
        self.assertEqual(second_receipt, 0)
        self.assertEqual(second_claim, 1)

    def test_validated_then_external_commit_allows_unrelated_descendant(self) -> None:
        session = "ailu-validated-before-commit"
        target_rel = "项目/ValidatedBeforeCommit.md"
        apply_request, prepared = self.prepare_locked_add(
            session=session,
            target_rel=target_rel,
            token="validatedbeforecommit94731",
        )
        validation = self.box.validate_intent_only(
            apply_request,
            session=session,
        )
        self.assertTrue(validation["ok"])
        self.assertFalse(validation["early_commit"])

        target = self.box.vault / target_rel
        before = target.read_bytes()
        before_stat = target.stat()
        git(self.box.git_root, "add", f"AgentMemory/{target_rel}")
        git(self.box.git_root, "commit", "-qm", "external proposal after validation")
        proposal_commit = git(self.box.git_root, "rev-parse", "HEAD")
        unrelated = self.box.git_root / "unrelated.txt"
        unrelated.write_text("unrelated descendant\n", encoding="utf-8")
        git(self.box.git_root, "add", "unrelated.txt")
        git(self.box.git_root, "commit", "-qm", "unrelated descendant")

        process, payload = self.box.write("apply", apply_request, session=session)
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        self.assertTrue(payload["idempotent"])
        self.assertEqual(payload["git_commit"], proposal_commit)
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(target.stat().st_ino, before_stat.st_ino)
        self.assertEqual(target.stat().st_mtime_ns, before_stat.st_mtime_ns)
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn:
            row = conn.execute(
                "SELECT early_commit, proposal_commit, status FROM memory_write_intents "
                "WHERE intent_id=?",
                (prepared["proposal_id"],),
            ).fetchone()
        self.assertEqual(row, (1, proposal_commit, "completed"))

    def test_prevalidation_raw_variant_in_full_history_blocks_exact_retry(self) -> None:
        session = "ailu-prevalidation-raw-history"
        target_rel = "项目/PrevalidationRawHistory.md"
        apply_request, prepared = self.prepare_locked_add(
            session=session,
            target_rel=target_rel,
            token="prevalidationrawhistory94731",
            skip_validation=True,
        )
        target = self.box.vault / target_rel
        final_bytes = target.read_bytes()
        raw_variant = final_bytes.replace(b"\n", b"\r\n")
        self.assertNotEqual(hashlib.sha256(raw_variant).digest(), hashlib.sha256(final_bytes).digest())
        self.assertEqual(
            memory_closeout.write_intent.content_hashes(
                raw_variant,
                max_bytes=1024 * 1024,
            ).canonical_sha256,
            memory_closeout.write_intent.content_hashes(
                final_bytes,
                max_bytes=1024 * 1024,
            ).canonical_sha256,
        )
        repo_path = f"AgentMemory/{target_rel}"
        target.write_bytes(raw_variant)
        git(self.box.git_root, "add", repo_path)
        git(self.box.git_root, "commit", "-qm", "canonical-only intermediate version")
        target.write_bytes(final_bytes)
        git(self.box.git_root, "add", repo_path)
        git(self.box.git_root, "commit", "-qm", "restore exact final version")
        validation = self.box.validate_intent_only(apply_request, session=session)
        self.assertTrue(validation["ok"])
        self.assertEqual(validation["validation_mode"], "exact")
        self.assertTrue(validation["early_commit"])

        process, payload = self.box.write("apply", apply_request, session=session)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(payload["reason_code"], "CLOSEOUT_FAILED")
        closeout_log = self.box.runtime / "logs" / "closeout.jsonl"
        closeout = json.loads(closeout_log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(closeout["intent_error"], "STALE_BASE")
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn:
            receipts = conn.execute(
                "SELECT COUNT(*) FROM memory_write_receipts WHERE intent_id=?",
                (prepared["proposal_id"],),
            ).fetchone()[0]
        self.assertEqual(receipts, 0)

    def test_format_only_validated_paths_support_ordinary_and_early_closeout(self) -> None:
        cases = (
            ("ordinary", False),
            ("early", True),
        )
        for label, commit_before_validation in cases:
            with self.subTest(label=label):
                session = f"ailu-format-only-{label}"
                target_rel = f"项目/FormatOnly{label.title()}.md"
                apply_request, prepared = self.prepare_locked_add(
                    session=session,
                    target_rel=target_rel,
                    token=f"formatonly{label}94731",
                    skip_validation=True,
                )
                target = self.box.vault / target_rel
                formatted_bytes = target.read_bytes().replace(b"\n", b"\r\n")
                target.write_bytes(formatted_bytes)
                proposal_commit = ""
                if commit_before_validation:
                    git(self.box.git_root, "add", f"AgentMemory/{target_rel}")
                    git(self.box.git_root, "commit", "-qm", f"format-only {label}")
                    proposal_commit = git(self.box.git_root, "rev-parse", "HEAD")
                validation = self.box.validate_intent_only(
                    apply_request,
                    session=session,
                )
                self.assertTrue(validation["ok"], validation)
                self.assertEqual(validation["validation_mode"], "format_only")
                self.assertEqual(validation["early_commit"], commit_before_validation)

                process, payload = self.box.closeout_claimed_only(session=session)
                self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
                self.assertEqual(payload["status"], "ok")
                with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn:
                    row = conn.execute(
                        "SELECT i.status, i.validation_mode, r.outcome, r.git_commit "
                        "FROM memory_write_intents i "
                        "JOIN memory_write_receipts r USING(intent_id) "
                        "WHERE i.intent_id=?",
                        (prepared["proposal_id"],),
                    ).fetchone()
                self.assertEqual(row[0:3], ("completed", "format_only", "completed"))
                self.assertEqual(target.read_bytes(), formatted_bytes)
                if commit_before_validation:
                    self.assertEqual(row[3], proposal_commit)
                else:
                    self.assertEqual(
                        git(
                            self.box.git_root,
                            "rev-parse",
                            f"{row[3]}:AgentMemory/{target_rel}",
                        ),
                        git(self.box.git_root, "hash-object", str(target)),
                    )

    def test_intermediate_non_regular_git_mode_blocks_validated_recovery(self) -> None:
        session = "ailu-mode-drift"
        target_rel = "项目/ModeDrift.md"
        apply_request, prepared = self.prepare_locked_add(
            session=session,
            target_rel=target_rel,
            token="modedrift94731",
        )
        repo_path = f"AgentMemory/{target_rel}"
        git(self.box.git_root, "add", repo_path)
        git(self.box.git_root, "commit", "-qm", "external regular proposal")
        validation = self.box.validate_intent_only(apply_request, session=session)
        self.assertTrue(validation["ok"])
        self.assertTrue(validation["early_commit"])
        tree_record = git(self.box.git_root, "ls-tree", "HEAD", "--", repo_path)
        blob_oid = tree_record.split()[2]
        git(self.box.git_root, "update-index", "--cacheinfo", f"120000,{blob_oid},{repo_path}")
        git(self.box.git_root, "commit", "-qm", "intermediate symlink mode")
        git(self.box.git_root, "update-index", "--cacheinfo", f"100644,{blob_oid},{repo_path}")
        git(self.box.git_root, "commit", "-qm", "restore regular mode")
        self.assertEqual(git(self.box.git_root, "status", "--porcelain", "--", repo_path), "")

        process, payload = self.box.write("apply", apply_request, session=session)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(payload["reason_code"], "CLOSEOUT_FAILED")
        closeout_log = self.box.runtime / "logs" / "closeout.jsonl"
        closeout = json.loads(closeout_log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(closeout["intent_error"], "STALE_BASE")
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn:
            receipts = conn.execute(
                "SELECT COUNT(*) FROM memory_write_receipts WHERE intent_id=?",
                (prepared["proposal_id"],),
            ).fetchone()[0]
        self.assertEqual(receipts, 0)

    @unittest.skipIf(os.name == "nt", "POSIX execute bits are not available")
    def test_non_early_executable_markdown_fails_without_commit_or_receipt(self) -> None:
        session = "ailu-executable-markdown"
        target_rel = "项目/ExecutableMarkdown.md"
        apply_request, prepared = self.prepare_locked_add(
            session=session,
            target_rel=target_rel,
            token="executablemarkdown94731",
        )
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn:
            early_commit = conn.execute(
                "SELECT early_commit FROM memory_write_intents WHERE intent_id=?",
                (prepared["proposal_id"],),
            ).fetchone()[0]
        self.assertEqual(early_commit, 0)
        target = self.box.vault / target_rel
        target.chmod(0o755)
        self.assertTrue(target.lstat().st_mode & 0o111)
        head_before = git(self.box.git_root, "rev-parse", "HEAD")

        process, payload = self.box.write("apply", apply_request, session=session)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(payload["reason_code"], "CLOSEOUT_FAILED")
        self.assertEqual(git(self.box.git_root, "rev-parse", "HEAD"), head_before)
        self.assertTrue(target.lstat().st_mode & 0o111)
        closeout_log = self.box.runtime / "logs" / "closeout.jsonl"
        closeout = json.loads(closeout_log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(
            closeout["intent_error"],
            "GOVERNED_MARKDOWN_MODE_INVALID",
        )
        self.assertEqual(closeout["commit"], "skipped")
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn:
            receipt_count = conn.execute(
                "SELECT COUNT(*) FROM memory_write_receipts WHERE intent_id=?",
                (prepared["proposal_id"],),
            ).fetchone()[0]
            active_claim = conn.execute(
                "SELECT COUNT(*) FROM memory_session_claims "
                "WHERE rel_path=? AND status='active'",
                (target_rel,),
            ).fetchone()[0]
        self.assertEqual(receipt_count, 0)
        self.assertEqual(active_claim, 1)

    def test_validated_head_on_sibling_branch_fails_closed_with_exact_live_bytes(self) -> None:
        session = "ailu-diverged-history"
        target_rel = "项目/DivergedHistory.md"
        initial_head = git(self.box.git_root, "rev-parse", "HEAD")
        apply_request, prepared = self.prepare_locked_add(
            session=session,
            target_rel=target_rel,
            token="divergedhistory94731",
        )
        target = self.box.vault / target_rel
        proposal_bytes = target.read_bytes()
        repo_path = f"AgentMemory/{target_rel}"
        git(self.box.git_root, "add", repo_path)
        git(self.box.git_root, "commit", "-qm", "validated history branch")
        validation = self.box.validate_intent_only(apply_request, session=session)
        self.assertTrue(validation["ok"])
        git(self.box.git_root, "switch", "-q", "-c", "alternate-history", initial_head)
        target.write_bytes(proposal_bytes)
        git(self.box.git_root, "add", repo_path)
        git(self.box.git_root, "commit", "-qm", "alternate exact proposal")
        self.assertEqual(target.read_bytes(), proposal_bytes)

        process, payload = self.box.write("apply", apply_request, session=session)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(payload["reason_code"], "CLOSEOUT_FAILED")
        closeout_log = self.box.runtime / "logs" / "closeout.jsonl"
        closeout = json.loads(closeout_log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertIn(
            closeout["intent_error"],
            {"BASE_GIT_HEAD_DIVERGED", "STALE_BASE"},
        )
        self.assertEqual(closeout["git_observed_through"], "")
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn:
            receipts = conn.execute(
                "SELECT COUNT(*) FROM memory_write_receipts WHERE intent_id=?",
                (prepared["proposal_id"],),
            ).fetchone()[0]
        self.assertEqual(receipts, 0)

    def test_hash_or_session_mismatch_cannot_write_and_cancel_is_terminal(self) -> None:
        session = "ailu-session-two"
        target_rel = "项目/CancelMe.md"
        request = self.prepare_request("cancelprobe94731", target_rel)
        self.bind_read_token(request, session=session)
        prepared_process, prepared = self.box.write("prepare", request, session=session)
        self.assertEqual(prepared_process.returncode, 0, prepared_process.stderr + prepared_process.stdout)
        apply_request = {
            "schema_version": 2,
            "proposal_id": prepared["proposal_id"],
            "fencing_token": prepared["fencing_token"],
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
            {
                "schema_version": 2,
                "proposal_id": prepared["proposal_id"],
                "fencing_token": prepared["fencing_token"],
            },
            session="another-ailu-session",
        )
        self.assertEqual(wrong_session_process.returncode, 2)
        self.assertEqual(wrong_session["reason_code"], "INTENT_SESSION_MISMATCH")

        cancelled_process, cancelled = self.box.write(
            "cancel",
            {
                "schema_version": 2,
                "proposal_id": prepared["proposal_id"],
                "fencing_token": prepared["fencing_token"],
            },
            session=session,
        )
        self.assertEqual(cancelled_process.returncode, 0, cancelled_process.stderr + cancelled_process.stdout)
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertFalse(cancelled["idempotent"])
        self.assertEqual(cancelled["receipt"]["outcome"], "cancelled")
        self.assertFalse((self.box.vault / target_rel).exists())

        apply_request["proposal_raw_sha256"] = prepared["proposal_raw_sha256"]
        after_cancel_process, after_cancel = self.box.write("apply", apply_request, session=session)
        self.assertEqual(after_cancel_process.returncode, 2)
        self.assertEqual(after_cancel["reason_code"], "CANCELLED_BY_USER")
        self.assertEqual(after_cancel["status"], "cancelled")
        self.assertEqual(after_cancel["receipt"], cancelled["receipt"])
        self.assertFalse((self.box.vault / target_rel).exists())

    def test_cancel_cannot_abandon_content_after_apply_has_started(self) -> None:
        session = "ailu-apply-recovery"
        target_rel = "项目/Recovery.md"
        request = self.prepare_request("applyrecovery94731", target_rel)
        self.bind_read_token(request, session=session)
        prepared_process, prepared = self.box.write("prepare", request, session=session)
        self.assertEqual(prepared_process.returncode, 0, prepared_process.stderr + prepared_process.stdout)
        apply_request = {
            "schema_version": 2,
            "proposal_id": prepared["proposal_id"],
            "fencing_token": prepared["fencing_token"],
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
            {
                "schema_version": 2,
                "proposal_id": prepared["proposal_id"],
                "fencing_token": prepared["fencing_token"],
            },
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
        session = "ailu-session-update"
        target_rel = "项目/Existing.md"
        target = self.box.vault / target_rel
        proposal = self.box._memory_text(
            "Existing noopprobe94731",
            "Stable noop fact noopprobe94731 plus durable update marker.",
            project=True,
        )
        request = {
            "schema_version": 2,
            "summary": "Stable noop fact noopprobe94731 updated",
            "proposal_markdown": proposal,
            "source_class": "user_direct",
            "knowledge_kind": "rule",
            "asserted_by": "user",
            "evidence_ref": "conversation:update-probe",
            "current_project": "ailu",
            "target_relative_path": target_rel,
            "app_id": "ailu",
            "project_id": "ailu",
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
            "schema_version": 2,
            "proposal_id": prepared["proposal_id"],
            "fencing_token": prepared["fencing_token"],
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
        session = "ailu-session-three"
        existing_text = (self.box.vault / "项目" / "Existing.md").read_text(encoding="utf-8")
        base_request = {
            "schema_version": 2,
            "summary": "Stable noop fact noopprobe94731",
            "proposal_markdown": existing_text,
            "target_relative_path": "项目/Existing.md",
            "source_class": "user_direct",
            "knowledge_kind": "rule",
            "asserted_by": "user",
            "evidence_ref": "conversation:noop",
            "current_project": "ailu",
            "app_id": "ailu",
            "project_id": "ailu",
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
        session = "ailu-scope-guard"
        marker = "private-scope-marker-94731"
        other_app = self.box.vault / "项目" / "OtherApp.md"
        other_app.write_text(
            self.box._memory_text("Other app", marker, project=True).replace(
                "app_id: ailu",
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
                "project_id: ailu",
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
            ({"schema_version": 2, "target_relative_path": "项目/Existing.md"}, "APP_ID_REQUIRED"),
            (
                {
                    "schema_version": 2,
                    "target_relative_path": "项目/OtherApp.md",
                    "app_id": "ailu",
                    "project_id": "ailu",
                },
                "APP_ID_MISMATCH",
            ),
            (
                {
                    "schema_version": 2,
                    "target_relative_path": "项目/CodexOnly.md",
                    "app_id": "ailu",
                    "project_id": "ailu",
                },
                "AGENT_SCOPE_MISMATCH",
            ),
            (
                {
                    "schema_version": 2,
                    "target_relative_path": "项目/OtherProject.md",
                    "app_id": "ailu",
                    "project_id": "ailu",
                },
                "PROJECT_SCOPE_MISMATCH",
            ),
            (
                {
                    "schema_version": 2,
                    "target_relative_path": "项目/SecretTarget.md",
                    "app_id": "ailu",
                    "project_id": "ailu",
                },
                "SECRET_MATERIAL",
            ),
            (
                {
                    "schema_version": 2,
                    "target_relative_path": "项目/Existing.md",
                    "app_id": "ailu",
                },
                "PROJECT_ID_REQUIRED",
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
        session = "ailu-required-read-token"
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
            "schema_version": 2,
            "target_relative_path": target_rel,
            "app_id": "ailu",
            "project_id": "ailu",
        }
        a_read_process, a_read = self.box.write(
            "read-target",
            scope,
            session="ailu-reader-a",
        )
        self.assertEqual(a_read_process.returncode, 0, a_read_process.stderr + a_read_process.stdout)

        b_request = {
            "schema_version": 2,
            "summary": "Stable noop fact noopprobe94731 updated by B",
            "proposal_markdown": self.box._memory_text(
                "Existing noopprobe94731",
                "Stable noop fact noopprobe94731 plus B durable version.",
                project=True,
            ),
            "target_relative_path": target_rel,
            "source_class": "user_direct",
            "knowledge_kind": "rule",
            "asserted_by": "user",
            "evidence_ref": "conversation:writer-b",
            "current_project": "ailu",
            "app_id": "ailu",
            "project_id": "ailu",
        }
        self.bind_read_token(b_request, session="ailu-writer-b")
        prepared_process, prepared = self.box.write(
            "prepare",
            b_request,
            session="ailu-writer-b",
        )
        self.assertEqual(prepared_process.returncode, 0, prepared_process.stderr + prepared_process.stdout)
        apply_request = {
            "schema_version": 2,
            "proposal_id": prepared["proposal_id"],
            "fencing_token": prepared["fencing_token"],
            "target_relative_path": target_rel,
            "proposal_markdown": b_request["proposal_markdown"],
            "proposal_raw_sha256": prepared["proposal_raw_sha256"],
            "proposal_canonical_sha256": prepared["proposal_canonical_sha256"],
            "confirmed_by": "user",
            "confirmation_reference": "conversation:writer-b-confirmed",
        }
        applied_process, _ = self.box.write("apply", apply_request, session="ailu-writer-b")
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
        stale_process, stale = self.box.write("prepare", a_request, session="ailu-reader-a")
        self.assertEqual(stale_process.returncode, 2)
        self.assertEqual(stale["reason_code"], "STALE_READ_TOKEN")
        self.assertEqual(target.read_text(encoding="utf-8"), b_content)

    def test_add_missing_read_token_cannot_claim_a_path_created_by_another_write(self) -> None:
        target_rel = "项目/AddRace.md"
        scope = {
            "schema_version": 2,
            "target_relative_path": target_rel,
            "app_id": "ailu",
            "project_id": "ailu",
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
                "schema_version": 2,
                "proposal_id": prepared["proposal_id"],
                "fencing_token": prepared["fencing_token"],
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
        session = "ailu-atomic-cas-race"
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
        self.assertFalse(payload["idempotent"])
        self.assertEqual(payload["receipt"]["outcome"], "failed")
        self.assertEqual(target.read_text(encoding="utf-8"), concurrent)
        self.assertIn(concurrent_marker, target.read_text(encoding="utf-8"))
        self.assertNotEqual(target.read_text(encoding="utf-8"), request["proposal_markdown"])
        self.assertEqual(list(target.parent.glob(".agent-memory-writer-*")), [])
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

    def test_atomic_cas_receipt_survives_claim_projection_failure_and_replay(self) -> None:
        session = "ailu-atomic-cas-claim-failure"
        target_rel, request, prepared = self.prepare_existing_update(
            session=session,
            marker="atomiccasclaimfailure94731",
        )
        target = self.box.vault / target_rel
        concurrent = target.read_text(encoding="utf-8") + (
            "\nCONCURRENT_CLAIM_FAILURE_FACT_94731\n"
        )

        first_process, first = self.raced_apply(
            session=session,
            target_rel=target_rel,
            request=request,
            prepared=prepared,
            concurrent_markdown=concurrent,
            fail_claim_release=True,
        )
        replay_process, replay = self.raced_apply(
            session=session,
            target_rel=target_rel,
            request=request,
            prepared=prepared,
            concurrent_markdown=concurrent,
            fail_claim_release=True,
        )

        self.assertEqual(first_process.returncode, 2, first_process.stderr + first_process.stdout)
        self.assertEqual(replay_process.returncode, 2, replay_process.stderr + replay_process.stdout)
        self.assertEqual(first["reason_code"], "TARGET_CHANGED_AFTER_CLAIM")
        self.assertEqual(replay["reason_code"], "TARGET_CHANGED_AFTER_CLAIM")
        self.assertFalse(first["idempotent"])
        self.assertTrue(replay["idempotent"])
        self.assertTrue(first["claim_release_pending"])
        self.assertTrue(replay["claim_release_pending"])
        self.assertEqual(first["claim_release_reason_code"], "CLAIM_RELEASE_FAILED")
        self.assertEqual(replay["claim_release_reason_code"], "CLAIM_RELEASE_FAILED")
        self.assertEqual(first["receipt"], replay["receipt"])
        self.assertEqual(first["receipt"]["outcome"], "failed")
        self.assertEqual(target.read_text(encoding="utf-8"), concurrent)

    def test_secondary_update_race_preserves_both_displaced_versions(self) -> None:
        session = "ailu-atomic-cas-secondary-race"
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
        for sidecar in target.parent.glob(".agent-memory-writer-*"):
            preserved_texts.append(sidecar.read_text(encoding="utf-8"))
        combined = "\n".join(preserved_texts)
        self.assertIn(first_marker, combined)
        self.assertIn(second_marker, combined)
        self.assertGreaterEqual(len(preserved_texts), 3)

    @unittest.skipIf(os.name == "nt", "POSIX process-group semantics are validated on macOS/Linux")
    def test_closeout_timeout_kills_grandchild_before_next_writer_operation(self) -> None:
        first_session = "ailu-timeout-first"
        second_session = "ailu-timeout-second"
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
        parent_marker = self.box.root / "closeout-parent-marker.log"
        overlap_marker = self.box.root / "grandchild-overlap.log"
        fake_python = self.box.root / "fake-closeout-python"
        fake_python.write_text(
            "#!/usr/bin/env python3\n"
            "import fcntl, os, signal, subprocess, sys, time\n"
            "lock_fd=os.open(os.environ['AILU_WRITE_LOCK'],os.O_CREAT|os.O_RDWR,0o600)\n"
            "fcntl.flock(lock_fd,fcntl.LOCK_EX)\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "marker = os.environ['AILU_GRANDCHILD_MARKER']\n"
            "with open(os.environ['AILU_PARENT_MARKER'],'w',encoding='utf-8') as h: h.write('started')\n"
            "code = (\"import os,signal,sqlite3,time\\n\"\n"
            "        \"signal.signal(signal.SIGTERM,signal.SIG_IGN)\\n\"\n"
            "        \"p=os.environ['AILU_GRANDCHILD_MARKER']\\n\"\n"
            "        \"db=os.environ['AILU_STATE_DB']\\n\"\n"
            "        \"proposal=os.environ['AILU_SECOND_PROPOSAL_ID']\\n\"\n"
            "        \"overlap=os.environ['AILU_OVERLAP_MARKER']\\n\"\n"
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
            "subprocess.Popen([os.environ['AILU_REAL_PYTHON'], '-c', code], env=os.environ.copy(),\n"
            "                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "time.sleep(60)\n",
            encoding="utf-8",
        )
        fake_python.chmod(0o700)
        apply_request = {
            "schema_version": 2,
            "proposal_id": first_prepared["proposal_id"],
            "fencing_token": first_prepared["fencing_token"],
            "target_relative_path": first_target,
            "proposal_markdown": first_request["proposal_markdown"],
            "proposal_raw_sha256": first_prepared["proposal_raw_sha256"],
            "proposal_canonical_sha256": first_prepared["proposal_canonical_sha256"],
            "confirmed_by": "user",
            "confirmation_reference": "conversation:timeout-confirmed",
        }
        cancel_request = {
            "schema_version": 2,
            "proposal_id": second_prepared["proposal_id"],
            "fencing_token": second_prepared["fencing_token"],
        }
        environment = {
            "AILU_FAKE_CLOSEOUT_SCRIPT": str(fake_python),
            "AILU_GRANDCHILD_MARKER": str(marker),
            "AILU_PARENT_MARKER": str(parent_marker),
            "AILU_REAL_PYTHON": sys.executable,
            "AILU_OVERLAP_MARKER": str(overlap_marker),
            "AILU_STATE_DB": str(self.box.state_db),
            "AILU_SECOND_PROPOSAL_ID": second_prepared["proposal_id"],
            "AILU_WRITE_LOCK": str(self.box.runtime / "locks" / "closeout.lock"),
            "AILU_FORCE_KILLPG_PERMISSION_ERROR": "1",
        }

        def timed_apply() -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
            direct_env = self.box.env(first_session)
            direct_env.update(environment)
            process = run(
                [sys.executable, "-c", TIMEOUT_APPLY_HELPER],
                cwd=REPO_ROOT,
                env=direct_env,
                input_text=json.dumps(apply_request, ensure_ascii=False),
                timeout=20,
            )
            try:
                payload = json.loads(process.stdout)
            except json.JSONDecodeError as exc:
                self.fail(
                    "timeout helper returned no JSON: "
                    f"rc={process.returncode} stdout={process.stdout!r} "
                    f"stderr={process.stderr!r} error={exc}"
                )
            return process, payload

        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(
                timed_apply,
            )
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            if not marker.exists():
                first_process, first_payload = first_future.result(timeout=10)
                self.fail(
                    "fake closeout grandchild never started: "
                    f"parent_started={parent_marker.exists()} "
                    f"rc={first_process.returncode} payload={first_payload!r} "
                    f"stderr={first_process.stderr!r}"
                )
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
        size_after_timeout = marker.stat().st_size
        time.sleep(0.4)
        self.assertEqual(marker.stat().st_size, size_after_timeout)

        self.assertEqual(second_process.returncode, 0, second_process.stderr + second_process.stdout)
        self.assertEqual(second_payload["status"], "cancelled")
        self.assertFalse(
            overlap_marker.exists(),
            "a second Ailu write acquired the lock while the timed-out process group was alive",
        )


if __name__ == "__main__":
    unittest.main()
