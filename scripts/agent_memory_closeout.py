#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import time
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from agent_memory_env import (
    RuntimeTransitionError,
    assert_runtime_maintenance_capability,
    assert_runtime_ready,
    env_value,
    expand_path,
    load_config,
)
from agent_memory_lock import private_lock
from agent_memory_generated_index_capability import (
    CAPABILITY_BINDING_ENV as GENERATED_INDEX_CAPABILITY_BINDING_ENV,
    CAPABILITY_PATH_ENV as GENERATED_INDEX_CAPABILITY_PATH_ENV,
    CAPABILITY_TOKEN_ENV as GENERATED_INDEX_CAPABILITY_TOKEN_ENV,
    GeneratedIndexCapabilityError,
    MAX_TTL_SECONDS as GENERATED_INDEX_MAX_TTL_SECONDS,
    REQUIRED_BINDING_FIELDS as GENERATED_INDEX_BINDING_FIELDS,
    TRANSACTION_TABLE as GENERATED_INDEX_TRANSACTION_TABLE,
    commit_generated_index_transaction,
    generated_index_backup_directory,
    git_commit_file_sha256,
    git_commit_full_vault_inputs_sha256,
    issue_generated_index_capability,
    mark_generated_index_transaction_outcome,
    normalize_transaction_binding,
    read_generated_index_transaction,
    resolve_failed_generated_index_transaction,
    validate_generated_index_recovery_evidence_path,
    verify_generated_index_commit_evidence,
)
from agent_memory_index import conditional_atomic_replace
from agent_memory_claim import (
    active_claim_rows,
    all_active_claim_rows,
    complete_claim_paths,
    finalize_closeout_batch,
    parse_deleted_observation,
    record_file_observations,
)
from agent_memory_safety import KNOWLEDGE_KINDS, SOURCE_CLASSES, assess_source, record_assessment
from agent_memory_state import POSIX_PERMISSION_MODEL, secure_append_text, secure_sqlite_connect
import agent_memory_intent as write_intent


SCRIPT_ROOT = Path(__file__).resolve().parent
TEMPLATE_REPO_ROOT = SCRIPT_ROOT.parent
DEFAULT_VAULT_ROOT = TEMPLATE_REPO_ROOT / "templates" / "vault"
VAULT_ROOT = expand_path(env_value("ROOT", str(DEFAULT_VAULT_ROOT))).resolve()
CONFIG_ROOT = expand_path(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory")).resolve()
STATE_DB = expand_path(env_value("STATE_DB", str(CONFIG_ROOT / "state.sqlite"))).resolve()
LOG_PATH = expand_path(env_value("CLOSEOUT_LOG", str(CONFIG_ROOT / "logs" / "closeout.jsonl"))).resolve()
LOCK_PATH = CONFIG_ROOT / "locks" / "closeout.lock"
RECONCILE_QUERY_MAX_CHARS = 900
RECONCILE_TITLE_MATCH_MIN_CHARS = 8
RECONCILE_CANDIDATE_COVERAGE_MIN_TOKENS = 8


def find_default_git_root() -> Path:
    for candidate in (VAULT_ROOT, *VAULT_ROOT.parents):
        if (candidate / ".git").exists():
            return candidate.resolve()
    return VAULT_ROOT.parent.resolve()


REPO_ROOT = expand_path(env_value("GIT_ROOT", str(find_default_git_root()))).resolve()

CHECK_SCRIPT = SCRIPT_ROOT / "agent_memory_check.py"
INDEX_SCRIPT = SCRIPT_ROOT / "agent_memory_index.py"
SEARCH_SCRIPT = SCRIPT_ROOT / "agent_memory_search.py"
ZVEC_SCRIPT = SCRIPT_ROOT / "agent_memory_zvec_index.py"
AGENT_EVOLUTION_SCRIPT = SCRIPT_ROOT / "agent_memory_evolution.py"
PYTHON = env_value("PYTHON", sys.executable)
ZVEC_PYTHON = env_value("ZVEC_PYTHON", PYTHON)
SEMANTIC_CONFIG = load_config().get("semantic_retrieval", {})
SEMANTIC_ENABLED = bool(SEMANTIC_CONFIG.get("enabled", False)) if isinstance(SEMANTIC_CONFIG, dict) else False

MEMORY_TOP_LEVELS = {"用户记忆", "项目", "工作流", "决策", "agent"}
TOP_LEVEL_MEMORY_FILES = {"AGENTS.md", "INDEX.md", "README.md", "STRUCTURE.md"}
RECONCILE_ACTIONS = {
    "ADD",
    "UPDATE",
    "NOOP",
    "MARK_OUTDATED",
    "MERGE_REQUIRED",
    "ASK_USER",
}
NONCURRENT_RECONCILE_STATUSES = {"archived", "outdated", "superseded", "deleted"}
NONFACT_RECONCILE_TYPES = {"directory_index", "routing", "template", "open_loop"}
AUTOMATIC_WRITER_ACTORS = frozenset(write_intent.CANONICAL_WRITER_ACTORS)
CLOSEOUT_ACTORS = AUTOMATIC_WRITER_ACTORS | {"human", "migration", "test"}


@dataclass
class GitEntry:
    status: str
    repo_path: str
    path: Path
    previous_repo_path: str = ""

    @property
    def exists(self) -> bool:
        return self.path.exists()

    @property
    def is_deleted(self) -> bool:
        return "D" in self.status

    @property
    def is_new(self) -> bool:
        return self.status == "??" or "A" in self.status or self.status.startswith("C")

    @property
    def is_memory_markdown(self) -> bool:
        if self.path.suffix.lower() != ".md":
            return False
        try:
            relative = self.path.relative_to(VAULT_ROOT)
        except ValueError:
            return False
        if len(relative.parts) == 1:
            return relative.name in TOP_LEVEL_MEMORY_FILES
        return bool(relative.parts) and relative.parts[0] in MEMORY_TOP_LEVELS


@dataclass(frozen=True)
class CommitSnapshot:
    path: Path
    repo_path: str
    raw_sha256: str
    blob_oid: str
    mode: str


@dataclass(frozen=True)
class GeneratedIndexSnapshot:
    path: Path
    raw: bytes
    mode: int
    raw_sha256: str


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def normalized_actor(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", value.strip().lower()).strip("-")
    return cleaned or "unknown"


def session_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16] if value else ""


def command_env_offline() -> dict[str, str]:
    env = os.environ.copy()
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        env.pop(key, None)
    env.setdefault("HF_HUB_OFFLINE", "1")
    env.setdefault("TRANSFORMERS_OFFLINE", "1")
    return env


def run_command(
    command: list[str],
    timeout: float = 120,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> dict[str, Any]:
    command_env = os.environ.copy() if env is None else env.copy()
    command_env.setdefault("PYTHONIOENCODING", "utf-8")
    command_env.setdefault("PYTHONUTF8", "1")
    started_at = utc_now()
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            input=input_text,
            timeout=timeout,
            env=command_env,
            check=False,
        )
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_ms": round((time.monotonic() - started) * 1000),
            "ok": completed.returncode == 0,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": f"timeout after {timeout}s",
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_ms": round((time.monotonic() - started) * 1000),
            "ok": False,
        }
    except OSError as exc:
        return {
            "command": command,
            "returncode": 127,
            "stdout": "",
            "stderr": str(exc),
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_ms": round((time.monotonic() - started) * 1000),
            "ok": False,
        }


GIT_INDEX_LOCK_RETRY_SECONDS = 5.0
GIT_INDEX_LOCK_RETRY_INTERVAL_SECONDS = 0.1
GIT_INDEX_SYNC_DEADLINE_SECONDS = 8.0
GIT_INDEX_SYNC_MANIFEST_VERSION = 1
GIT_INDEX_SYNC_RECOVERY_DIRECTORY = "agent-memory-closeout-recovery"


def _git_index_lock_path(*, deadline: float | None = None) -> Path | None:
    """Return the exact ordinary Git index lock without following it."""

    resolved = run_command(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--git-path", "index.lock"],
        timeout=(
            _deadline_timeout(deadline, 30)
            if deadline is not None
            else 30
        ),
    )
    git_dir_result = run_command(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--absolute-git-dir"],
        timeout=(
            _deadline_timeout(deadline, 30)
            if deadline is not None
            else 30
        ),
    )
    if not resolved.get("ok") or not git_dir_result.get("ok"):
        return None
    raw_lock_text = str(resolved.get("stdout", "")).strip()
    raw_git_dir_text = str(git_dir_result.get("stdout", "")).strip()
    if not raw_lock_text or not raw_git_dir_text:
        return None
    raw_lock = Path(raw_lock_text)
    raw_git_dir = Path(raw_git_dir_text)
    if not raw_lock.is_absolute():
        raw_lock = REPO_ROOT / raw_lock
    lock_path = Path(os.path.abspath(raw_lock))
    git_dir = Path(os.path.abspath(raw_git_dir))
    try:
        metadata = git_dir.lstat()
    except OSError:
        return None
    if (
        git_dir.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or lock_path.parent != git_dir
        or lock_path.name != "index.lock"
    ):
        return None
    return lock_path


@contextlib.contextmanager
def closeout_lock(timeout: float = 15.0):
    with private_lock(
        LOCK_PATH,
        timeout=timeout,
        timeout_message=f"another memory closeout is still running: {LOCK_PATH}",
    ):
        yield


def decode_status_line(line: str) -> GitEntry | None:
    if len(line) < 4:
        return None
    status = line[:2].strip() or line[:2]
    repo_path = line[3:]
    if " -> " in repo_path:
        repo_path = repo_path.split(" -> ", 1)[1]
    path = (REPO_ROOT / repo_path).resolve()
    return GitEntry(status=status, repo_path=repo_path, path=path)


def repo_path_in_vault(repo_path: str) -> bool:
    try:
        vault_repo_path = VAULT_ROOT.relative_to(REPO_ROOT).as_posix().rstrip("/")
    except ValueError:
        return False
    candidate = Path(repo_path).as_posix().lstrip("./")
    if vault_repo_path in {"", "."}:
        return True
    return candidate == vault_repo_path or candidate.startswith(f"{vault_repo_path}/")


def repo_path_is_memory_markdown(repo_path: str) -> bool:
    if not repo_path_in_vault(repo_path):
        return False
    return GitEntry(
        status="",
        repo_path=repo_path,
        path=(REPO_ROOT / repo_path).resolve(),
    ).is_memory_markdown


def git_status_entries() -> tuple[list[GitEntry], list[str]]:
    result = run_command(
        [
            "git",
            "-C",
            str(REPO_ROOT),
            "-c",
            "core.quotepath=false",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ],
        timeout=30,
    )
    if not result["ok"]:
        return [], [f"git status failed: {result['stderr'].strip()}"]
    entries: list[GitEntry] = []
    items = [item for item in str(result["stdout"]).split("\0") if item]
    index = 0
    while index < len(items):
        item = items[index]
        entry = decode_status_line(item)
        previous_repo_path = ""
        if entry and entry.status.startswith(("R", "C")) and index + 1 < len(items):
            previous_repo_path = items[index + 1]
            index += 1
        if entry:
            if repo_path_is_memory_markdown(entry.repo_path):
                entry.previous_repo_path = previous_repo_path
                entries.append(entry)
            elif entry.status.startswith("R") and repo_path_is_memory_markdown(previous_repo_path):
                old_path = (REPO_ROOT / previous_repo_path).resolve()
                entries.append(GitEntry(status="D", repo_path=previous_repo_path, path=old_path))
        index += 1
    return entries, []


def full_vault_markdown_git_status() -> tuple[list[str], list[str]]:
    """Return every dirty Markdown path beneath the Vault, without routing filters."""

    try:
        vault_repo_path = VAULT_ROOT.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return [], ["vault is outside Git root"]
    pathspec = vault_repo_path if vault_repo_path not in {"", "."} else ":(glob)**/*.md"
    result = run_command(
        [
            "git", "-C", str(REPO_ROOT), "-c", "core.quotepath=false",
            "status", "--porcelain=v1", "-z", "--untracked-files=all",
            "--", pathspec,
        ],
        timeout=30,
    )
    if not result.get("ok"):
        return [], [f"git status failed: {str(result.get('stderr', '')).strip()}"]
    items = [item for item in str(result.get("stdout", "")).split("\0") if item]
    dirty: set[str] = set()
    index = 0
    while index < len(items):
        item = items[index]
        status = item[:2] if len(item) >= 3 else ""
        paths = [item[3:]] if len(item) >= 4 else []
        if status.startswith(("R", "C")) and index + 1 < len(items):
            index += 1
            paths.append(items[index])
        for repo_path in paths:
            normalized = Path(repo_path).as_posix().lstrip("./")
            if normalized.lower().endswith(".md") and (
                vault_repo_path in {"", "."}
                or normalized == vault_repo_path
                or normalized.startswith(f"{vault_repo_path}/")
            ):
                dirty.add(normalized)
        index += 1
    return sorted(dirty), []


def generated_index_git_operation_fence(
    *,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Reject generated commits while Git is performing another operation.

    The generated INDEX commit deliberately preserves unrelated staged and
    working-tree bytes.  It must nevertheless obey the same repository-wide
    operation fence as porcelain commit: moving HEAD during a merge, rebase,
    cherry-pick, revert, sequencer, or bisect can corrupt the user's operation
    even when every Vault Markdown file is clean.
    """

    def command_timeout() -> float:
        if deadline is None:
            return 30.0
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return 0.0
        return max(0.05, min(30.0, remaining))

    timeout = command_timeout()
    if timeout <= 0:
        return {
            "ok": False,
            "reason_code": "GIT_INDEX_SYNC_DEADLINE_EXCEEDED",
            "unmerged_entries": 0,
            "operation_sentinels": [],
        }
    unmerged = run_command(
        ["git", "-C", str(REPO_ROOT), "ls-files", "--unmerged", "-z"],
        timeout=timeout,
    )
    if not unmerged.get("ok"):
        return {
            "ok": False,
            "reason_code": "GENERATED_INDEX_GIT_STATE_UNAVAILABLE",
            "unmerged_entries": 0,
            "operation_sentinels": [],
        }
    unmerged_entries = len(
        [entry for entry in str(unmerged.get("stdout", "")).split("\0") if entry]
    )
    active_sentinels: list[str] = []
    for sentinel in (
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "REBASE_HEAD",
        "rebase-merge",
        "rebase-apply",
        "sequencer",
        "BISECT_START",
    ):
        timeout = command_timeout()
        if timeout <= 0:
            return {
                "ok": False,
                "reason_code": "GIT_INDEX_SYNC_DEADLINE_EXCEEDED",
                "unmerged_entries": unmerged_entries,
                "operation_sentinels": active_sentinels,
            }
        resolved = run_command(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--git-path", sentinel],
            timeout=timeout,
        )
        if not resolved.get("ok"):
            return {
                "ok": False,
                "reason_code": "GENERATED_INDEX_GIT_STATE_UNAVAILABLE",
                "unmerged_entries": unmerged_entries,
                "operation_sentinels": active_sentinels,
            }
        raw_path = Path(str(resolved.get("stdout", "")).strip())
        if not raw_path.is_absolute():
            raw_path = REPO_ROOT / raw_path
        operation_path = Path(os.path.abspath(raw_path))
        if operation_path.exists() or operation_path.is_symlink():
            active_sentinels.append(sentinel)
    blocked = bool(unmerged_entries or active_sentinels)
    return {
        "ok": not blocked,
        "reason_code": (
            "GENERATED_INDEX_GIT_OPERATION_IN_PROGRESS" if blocked else ""
        ),
        "unmerged_entries": unmerged_entries,
        "operation_sentinels": active_sentinels,
    }


def generated_index_recovery_plan() -> dict[str, Any]:
    """Read-only check for retained generated-index transactions."""

    if not STATE_DB.exists() and not STATE_DB.is_symlink():
        return {"ok": True, "pending": 0, "recovery_required": 0}
    if STATE_DB.is_symlink() or not STATE_DB.is_file():
        return {
            "ok": False,
            "pending": 0,
            "recovery_required": 0,
            "reason_code": "GENERATED_INDEX_RECOVERY_UNAVAILABLE",
        }
    try:
        with secure_sqlite_connect(
            STATE_DB,
            create=False,
            read_only=True,
            row_factory=sqlite3.Row,
            pragmas=("PRAGMA busy_timeout=2000",),
        ) as conn:
            table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (GENERATED_INDEX_TRANSACTION_TABLE,),
            ).fetchone()
            if table is None:
                return {"ok": True, "pending": 0, "recovery_required": 0}
            rows = conn.execute(
                f"SELECT status, COUNT(*) AS count FROM {GENERATED_INDEX_TRANSACTION_TABLE} "
                "WHERE status IN ('registered','issued','claimed','generated_bound','failed') "
                "GROUP BY status"
            ).fetchall()
    except (OSError, sqlite3.Error):
        return {
            "ok": False,
            "pending": 0,
            "recovery_required": 0,
            "reason_code": "GENERATED_INDEX_RECOVERY_UNAVAILABLE",
        }
    counts = {str(row["status"]): int(row["count"]) for row in rows}
    pending = sum(
        counts.get(status, 0)
        for status in ("registered", "issued", "claimed", "generated_bound")
    )
    recovery_required = counts.get("failed", 0)
    return {
        "ok": pending == 0 and recovery_required == 0,
        "pending": pending,
        "recovery_required": recovery_required,
        "reason_code": (
            "" if pending == 0 and recovery_required == 0
            else "GENERATED_INDEX_RECOVERY_REQUIRED"
        ),
    }


def current_git_head() -> tuple[str, list[str]]:
    result = run_command(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], timeout=30)
    if not result["ok"]:
        return "", [f"git rev-parse failed: {str(result['stderr']).strip()}"]
    return str(result["stdout"]).strip(), []


def last_observed_git_head() -> str:
    if not LOG_PATH.exists():
        return ""
    try:
        lines = LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    for line in reversed(lines):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("status") != "ok":
            continue
        if "git_observed_through" in item:
            value = str(item.get("git_observed_through", ""))
            if value and value != "skipped" and re.fullmatch(r"[0-9a-fA-F]{7,64}", value):
                return value
            # New logs make this field authoritative.  An intentionally empty
            # baseline means this run deferred committed history owned by
            # another session; never promote the same row's HEAD/commit as a
            # fallback and silently skip that outstanding claim next time.
            continue
        for key in ("git_head_after", "commit"):
            value = str(item.get(key, ""))
            if value and value != "skipped" and re.fullmatch(r"[0-9a-fA-F]{7,64}", value):
                return value
    return ""


def git_history_entries(baseline: str, head: str) -> tuple[list[GitEntry], list[str]]:
    if not baseline or not head or baseline == head:
        return [], []
    ancestor = run_command(["git", "-C", str(REPO_ROOT), "merge-base", "--is-ancestor", baseline, head], timeout=30)
    if ancestor["returncode"] != 0:
        return [], [f"closeout git baseline is not an ancestor of HEAD: baseline={baseline[:12]} head={head[:12]}"]
    result = run_command(
        [
            "git", "-C", str(REPO_ROOT), "-c", "core.quotepath=false",
            "diff", "--find-renames", "--name-status", "-z", f"{baseline}..{head}",
        ],
        timeout=60,
    )
    if not result["ok"]:
        return [], [f"git history diff failed: {str(result['stderr']).strip()}"]
    items = [item for item in str(result["stdout"]).split("\0") if item]
    entries: list[GitEntry] = []
    index = 0
    while index < len(items):
        status = items[index]
        index += 1
        if index >= len(items):
            break
        if status.startswith(("R", "C")):
            if index + 1 >= len(items):
                break
            previous_repo_path = items[index]
            index += 1
            repo_path = items[index]
            index += 1
        else:
            previous_repo_path = ""
            repo_path = items[index]
            index += 1
        if repo_path_is_memory_markdown(repo_path):
            entries.append(
                GitEntry(
                    status=status,
                    repo_path=repo_path,
                    path=(REPO_ROOT / repo_path).resolve(),
                    previous_repo_path=previous_repo_path,
                )
            )
        elif status.startswith("R") and repo_path_is_memory_markdown(previous_repo_path):
            old_path = (REPO_ROOT / previous_repo_path).resolve()
            entries.append(GitEntry(status="D", repo_path=previous_repo_path, path=old_path))
    return entries, []


def explicit_entries(paths: list[str]) -> tuple[list[GitEntry], list[str]]:
    entries: list[GitEntry] = []
    warnings: list[str] = []
    for raw in paths:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        else:
            path = path.resolve()
        try:
            repo_path = path.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            warnings.append(f"changed file outside repo skipped: {path}")
            continue
        if not repo_path_is_memory_markdown(repo_path):
            warnings.append(f"changed non-memory file skipped: {path}")
            continue
        status = "??" if path.exists() else "D"
        entries.append(GitEntry(status=status, repo_path=repo_path, path=path))
    return entries, warnings


def relative_to_vault(path: Path) -> str:
    try:
        return path.relative_to(VAULT_ROOT).as_posix()
    except ValueError:
        return str(path)


def assert_governed_markdown_worktree_mode(
    raw_path: str | Path,
    *,
    allow_missing: bool = False,
) -> None:
    """Require a governed Markdown worktree path to be regular and non-executable.

    Git records only one executable bit, but the worktree may expose execute
    permission to owner, group, or other.  Any of those bits is invalid for a
    governed Markdown document.  This assertion is deliberately read-only: a
    closeout must never silently chmod user content into compliance.
    """

    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    lexical = Path(os.path.abspath(str(candidate)))
    vault_lexical = Path(os.path.abspath(str(VAULT_ROOT)))
    try:
        relative = lexical.relative_to(vault_lexical)
    except ValueError:
        return
    if lexical.suffix.casefold() != ".md" or not relative.parts:
        return
    try:
        metadata = lexical.lstat()
    except FileNotFoundError:
        if allow_missing:
            return
        raise write_intent.IntentError(
            "GOVERNED_MARKDOWN_MODE_INVALID",
            "governed Markdown target is missing at the mode checkpoint",
        )
    except OSError as exc:
        raise write_intent.IntentError(
            "GOVERNED_MARKDOWN_MODE_INVALID",
            "governed Markdown mode cannot be verified",
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or bool(metadata.st_mode & 0o111):
        raise write_intent.IntentError(
            "GOVERNED_MARKDOWN_MODE_INVALID",
            "governed Markdown must be a non-executable regular file",
        )


def read_text(path: Path, limit: int = 12000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return text[:limit]


def title_from_text(text: str, path: Path) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem


def without_frontmatter(text: str) -> str:
    if not text.startswith("---"):
        return text
    end = text.find("\n---", 3)
    if end == -1:
        return text
    return text[end + 4 :].lstrip("\r\n")


def summary_from_text(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("summary:"):
            return stripped.split(":", 1)[1].strip().strip('"')
    current_summary = text.find("## 当前有效摘要")
    if current_summary != -1:
        section = text[current_summary + len("## 当前有效摘要") :]
        next_heading = re.search(r"\n##\s+", section)
        if next_heading is not None:
            section = section[: next_heading.start()]
        lines = [line.strip() for line in section.splitlines() if line.strip()]
        return " ".join(lines)[:500]
    body = without_frontmatter(text)
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    return " ".join(lines[:8])[:700]


def frontmatter_list(path: Path, key: str) -> set[str]:
    text = read_text(path)
    if not text.startswith("---"):
        return set()
    end = text.find("\n---", 3)
    if end == -1:
        return set()
    values: list[str] = []
    current_key = ""
    for line in text[3:end].splitlines():
        if re.match(r"^\s+-\s+", line) and current_key == key:
            values.append(re.sub(r"^\s+-\s+", "", line).strip())
            continue
        if line.startswith(" ") or ":" not in line:
            continue
        current_key, raw_value = line.split(":", 1)
        current_key = current_key.strip()
        if current_key != key:
            continue
        raw_value = raw_value.strip()
        if raw_value.startswith("[") and raw_value.endswith("]"):
            values.extend(item.strip() for item in raw_value[1:-1].split(","))
        elif raw_value:
            values.append(raw_value)
    return {value.strip().strip("'\"`") for value in values if value.strip()}


def legacy_context_candidate_for_explicit_fact(
    source_fact_keys: set[str],
    row: dict[str, Any],
) -> bool:
    """Return whether a legacy context document is covered by fact migration.

    A validated temporal fact has already passed the fact-key graph gate and
    evidence requirement.  Its legacy multi-fact source is expected to remain
    searchable as context, and another explicit fact_key is a separate fact
    slot.  Postwrite semantic reconciliation must not turn either intentional
    overlap into MERGE_REQUIRED.  A same-key record remains a candidate unless
    the caller declared it in ``supersedes``; the temporal graph also rejects
    multiple unresolved heads before the file is written.
    """

    if not source_fact_keys:
        return False
    candidate_fact_key = str(row.get("fact_key") or "").strip()
    return candidate_fact_key not in source_fact_keys


def reconcile_query_for_file(path: Path) -> str:
    text = read_text(path)
    title = title_from_text(text, path)
    summary = summary_from_text(text)
    query = f"{title} {summary}".strip()
    return query[:RECONCILE_QUERY_MAX_CHARS]


def reconcile_query_for_text(text: str) -> str:
    """Build a bounded retrieval query while retaining the full text for safety checks."""
    compact = re.sub(r"\s+", " ", text).strip()
    if not compact:
        return ""
    title = ""
    for line in text.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            break
    summary = summary_from_text(text)
    query = re.sub(r"\s+", " ", f"{title} {summary}".strip()) or compact
    return query[:RECONCILE_QUERY_MAX_CHARS]


def is_current_reconcile_target(path: Path) -> bool:
    statuses = {value.lower() for value in frontmatter_list(path, "status")}
    return not bool(statuses & NONCURRENT_RECONCILE_STATUSES)


def project_scope_for_file(path: Path, explicit_project: str = "") -> str:
    if explicit_project.strip():
        return explicit_project.strip()
    tracks = {value.casefold() for value in frontmatter_list(path, "track")}
    if "project" not in tracks:
        return ""
    project_ids = sorted(frontmatter_list(path, "project_id"))
    return project_ids[0] if len(project_ids) == 1 else ""


def tokenize(text: str) -> set[str]:
    tokens: set[str] = set()
    for word in re.findall(r"[A-Za-z0-9_]{2,}", text.lower()):
        tokens.add(word)
    for seq in re.findall(r"[\u4e00-\u9fff]{2,}", text):
        if len(seq) <= 6:
            tokens.add(seq)
        for index in range(max(len(seq) - 1, 0)):
            tokens.add(seq[index : index + 2])
    return tokens


def jaccard(left: str, right: str) -> float:
    left_tokens = tokenize(left)
    right_tokens = tokenize(right)
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def coverage(left: str, right: str) -> float:
    left_tokens = tokenize(left)
    right_tokens = tokenize(right)
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens)


def compact_identity_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return "".join(character for character in normalized if character.isalnum())


RECONCILE_CHECKPOINT_LEXICAL_LANES = ("legacy_sqlite",)
RECONCILE_HYBRID_LEXICAL_LANES = ("unicode_fts", "trigram_fts")


def failed_search_status(warning: str) -> dict[str, Any]:
    return {"sqlite": {"status": "error", "results": 0, "warnings": [warning]}}


def reconcile_backend_status(
    backend_status: Any,
    *,
    ranking_version: str,
    process_ok: bool,
    rows: list[Any],
    warnings: list[str],
) -> dict[str, Any]:
    """Fold the lexical lanes that supplied candidates into one ``sqlite`` status.

    Reconcile may only recommend ADD after the SQLite lexical search behind the
    returned candidates actually answered.  Hybrid search reports one status per
    lane, so the lanes feeding the effective ranking must all be ``ok``; a
    missing lane counts as failed.  Semantic lanes stay advisory.
    """
    status = dict(backend_status) if isinstance(backend_status, dict) else {}
    sqlite_status = status.get("sqlite")
    if isinstance(sqlite_status, dict):
        if not process_ok:
            status["sqlite"] = {**sqlite_status, "status": "error"}
        return status
    known_lanes = (*RECONCILE_CHECKPOINT_LEXICAL_LANES, *RECONCILE_HYBRID_LEXICAL_LANES)
    if any(lane in status for lane in known_lanes):
        lanes = (
            RECONCILE_HYBRID_LEXICAL_LANES
            if ranking_version == "hybrid-v2"
            else RECONCILE_CHECKPOINT_LEXICAL_LANES
        )
        lane_status = {lane: str(status.get(lane, "missing")) for lane in lanes}
        healthy = process_ok and all(value == "ok" for value in lane_status.values())
        summary: dict[str, Any] = {"lanes": lane_status}
    else:
        healthy = process_ok and not any(
            warning.casefold().startswith("sqlite ") for warning in warnings
        )
        summary = {}
    status["sqlite"] = {
        "status": "ok" if healthy else "error",
        "results": len(rows),
        "warnings": list(warnings),
        **summary,
    }
    return status


def search_memory(
    query: str,
    limit: int = 8,
    no_zvec: bool = True,
    current_project: str = "",
    read_only: bool = False,
    app_id: str = "",
    agent_scope: str = "",
    project_id: str = "",
    canonical_actor: str = "",
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    if canonical_actor == "ailu":
        # Ailu's raw Search CLI is intentionally disabled.  Confirmed Writer
        # and Closeout code may use Canonical Retrieve's private in-process
        # candidate lane, bound here to the exact Ailu app/project boundary.
        import agent_memory_retrieve as memory_retrieve

        exact_project = (project_id or current_project).strip()
        try:
            exact_app, exact_project = memory_retrieve.validate_ailu_scope_request(
                app_id or memory_retrieve.AILU_APP_ID,
                exact_project,
            )
            candidate_rows, warnings, namespace = memory_retrieve._run_candidate_search(
                query,
                limit,
                actor="ailu",
                app_id=exact_app,
                project_id=exact_project,
                semantic_mode=(
                    memory_retrieve.memory_search.DEFAULT_SEMANTIC_MODE
                    if SEMANTIC_ENABLED and not no_zvec
                    else "off"
                ),
            )
        except memory_retrieve.RetrievalProtocolError as exc:
            warning = f"search failed: {exc.code}"
            return [], [warning], failed_search_status(warning)
        rows = [row.to_dict() for row in candidate_rows]
        backend_status = reconcile_backend_status(
            getattr(namespace, "_backend_status", {}),
            ranking_version=str(getattr(namespace, "_effective_ranking_version", "") or ""),
            process_ok=True,
            rows=rows,
            warnings=warnings,
        )
        return rows, warnings, backend_status

    command = [PYTHON, str(SEARCH_SCRIPT), "--query-stdin", "--limit", str(limit), "--json"]
    if no_zvec:
        command.append("--no-zvec")
    if current_project.strip():
        command.extend(["--current-project", current_project.strip()])
    if app_id.strip():
        command.extend(["--app-id", app_id.strip()])
    if agent_scope.strip():
        command.extend(["--agent-scope", agent_scope.strip()])
    if project_id.strip():
        command.extend(["--project-id", project_id.strip()])
    if read_only:
        command.append("--no-log")
    result = run_command(
        command,
        timeout=80,
        env=command_env_offline(),
        input_text=query,
    )
    try:
        payload = json.loads(str(result["stdout"]))
    except json.JSONDecodeError:
        detail = str(result["stderr"]).strip() or str(result["returncode"])
        warning = f"search failed: {detail}" if not result["ok"] else "search returned non-json output"
        return [], [warning], failed_search_status(warning)
    if not isinstance(payload, dict):
        warning = "search returned invalid payload"
        return [], [warning], failed_search_status(warning)
    rows = payload.get("results", [])
    warnings = payload.get("warnings", [])
    if not isinstance(rows, list):
        rows = []
    if not isinstance(warnings, list):
        warnings = []
    normalized_warnings = [str(item) for item in warnings]
    if not result["ok"] and not normalized_warnings:
        detail = str(payload.get("reason_code") or "").strip() or str(result["returncode"])
        normalized_warnings.append(f"search failed: {detail}")
    backend_status = reconcile_backend_status(
        payload.get("backend_status"),
        ranking_version=str(payload.get("ranking_version") or ""),
        process_ok=bool(result["ok"]) and payload.get("ok") is not False,
        rows=rows,
        warnings=normalized_warnings,
    )
    return rows, normalized_warnings, backend_status


def semantic_distance(row: dict[str, Any]) -> float | None:
    """Return raw semantic distance only; adjusted rank scores are never evidence."""
    details = row.get("source_details")
    if not isinstance(details, dict):
        return None
    try:
        return float(details.get("zvec_raw_distance"))
    except (TypeError, ValueError):
        return None


def raw_semantic_distance(row: dict[str, Any]) -> float | None:
    return semantic_distance(row)


def rank_semantic_score(row: dict[str, Any]) -> float | None:
    details = row.get("source_details")
    if not isinstance(details, dict):
        return None
    for key in ("zvec_rank_distance", "zvec_rank_score", "zvec_score"):
        try:
            value = details.get(key)
            if value is not None:
                return float(value)
        except (TypeError, ValueError):
            continue
    return None


def prewrite_recommendation(text: str, rows: list[dict[str, Any]]) -> tuple[str, dict[str, Any] | None, dict[str, Any]]:
    if not rows:
        return "ADD", None, {
            "similarity": 0.0,
            "coverage": 0.0,
            "candidate_coverage": 0.0,
            "title_match": False,
            "semantic_distance": None,
            "raw_semantic_distance": None,
        }
    candidates: list[tuple[int, int, float, float, float, float, str, dict[str, Any]]] = []
    action_priority = {"NOOP": 4, "UPDATE": 3, "MERGE_REQUIRED": 2, "ADD": 1}
    compact_input = compact_identity_text(text)
    for row in rows:
        comparison = " ".join(
            str(row.get(key, ""))
            for key in ("title", "rel_path", "summary", "hit")
        )
        similarity = jaccard(text, comparison)
        row_coverage = coverage(text, comparison)
        candidate_coverage = coverage(comparison, text)
        candidate_coverage_eligible = (
            len(tokenize(comparison)) >= RECONCILE_CANDIDATE_COVERAGE_MIN_TOKENS
        )
        title = str(row.get("title", ""))
        compact_title = compact_identity_text(title)
        title_tokens = tokenize(title)
        title_match = (
            len(compact_title) >= RECONCILE_TITLE_MATCH_MIN_CHARS
            and len(title_tokens) >= 2
            and compact_title in compact_input
        )
        distance = raw_semantic_distance(row)
        if similarity >= 0.80 or row_coverage >= 0.90:
            action = "NOOP"
        elif (
            title_match
            or similarity >= 0.45
            or row_coverage >= 0.55
            or (candidate_coverage_eligible and candidate_coverage >= 0.70)
            or (distance is not None and distance <= 0.32)
        ):
            action = "UPDATE"
        elif (
            similarity >= 0.28
            or row_coverage >= 0.35
            or (candidate_coverage_eligible and candidate_coverage >= 0.45)
            or (distance is not None and distance <= 0.55)
        ):
            action = "MERGE_REQUIRED"
        else:
            action = "ADD"
        semantic_quality = 1.0 - distance if distance is not None else -1.0
        candidates.append(
            (
                action_priority[action],
                int(title_match),
                semantic_quality,
                candidate_coverage,
                row_coverage,
                similarity,
                action,
                row,
            )
        )
    (
        _,
        best_title_match,
        _,
        best_candidate_coverage,
        best_coverage,
        best_similarity,
        action,
        best_row,
    ) = max(candidates, key=lambda item: item[:6])
    distance = semantic_distance(best_row)
    raw_distance = raw_semantic_distance(best_row)
    return action, best_row, {
        "similarity": best_similarity,
        "coverage": best_coverage,
        "candidate_coverage": best_candidate_coverage,
        "title_match": bool(best_title_match),
        "semantic_distance": distance,
        "raw_semantic_distance": raw_distance,
    }


def run_prewrite(args: argparse.Namespace) -> dict[str, Any]:
    run_id = uuid.uuid4().hex
    hashed_session = session_hash(args.session_id)
    safety = assess_source(
        args.prewrite,
        source_class=args.source_class,
        knowledge_kind=args.knowledge_kind,
        asserted_by=args.asserted_by or args.actor,
        evidence_ref=args.evidence_ref,
    )
    try:
        safety_audit_id = record_assessment(
            STATE_DB,
            safety,
            run_id=run_id,
            actor=args.actor,
            session_hash=hashed_session,
            trigger=args.trigger,
        )
        safety["audit_recorded"] = True
        safety["audit_id"] = safety_audit_id
    except (OSError, sqlite3.Error) as exc:
        safety["audit_recorded"] = False
        safety["audit_error"] = type(exc).__name__
        safety["decision"] = "BLOCK"
        safety["reason_code"] = "SAFETY_AUDIT_UNAVAILABLE"
        safety["can_reconcile"] = False
        safety["can_create_intent"] = False
    if safety["decision"] != "ALLOW":
        return {
            "time": utc_now(),
            "run_id": run_id,
            "actor": args.actor,
            "trigger": args.trigger,
            "session_hash": hashed_session,
            "mode": "prewrite",
            "input_sha256": safety["input_sha256"],
            "input_length": safety["input_length"],
            "safety": safety,
            "reconcile": {"status": "skipped", "reason_code": safety["reason_code"]},
            "recommended_action": "ASK_USER" if safety["decision"] == "ASK_USER" else "BLOCK",
            "recommended_target": None,
            "recommendation_metrics": {
                "similarity": 0.0,
                "coverage": 0.0,
                "candidate_coverage": 0.0,
                "title_match": False,
                "semantic_distance": None,
                "raw_semantic_distance": None,
            },
            "allowed_actions": sorted(RECONCILE_ACTIONS),
            "candidates": [],
            "warnings": [safety["reason_code"]],
            "status": "warning" if safety["decision"] == "ASK_USER" else "blocked",
        }
    inferred_project = ""
    if getattr(args, "proposal_file", ""):
        inferred_project = project_scope_for_file(
            Path(args.proposal_file).expanduser(),
            getattr(args, "current_project", ""),
        )
    search_query = reconcile_query_for_text(args.prewrite)
    rows, warnings, backend_status = search_memory(
        search_query,
        limit=args.limit,
        no_zvec=args.no_zvec,
        current_project=inferred_project or getattr(args, "current_project", ""),
        canonical_actor=str(getattr(args, "actor", "") or ""),
    )
    sqlite_healthy = backend_status.get("sqlite", {}).get("status") == "ok"
    action, target, metrics = prewrite_recommendation(args.prewrite, rows)
    recommendation_unavailable_reason = ""
    if not sqlite_healthy:
        action = None
        target = None
        recommendation_unavailable_reason = "RECONCILE_SEARCH_UNHEALTHY"
        if recommendation_unavailable_reason not in warnings:
            warnings.append(recommendation_unavailable_reason)
    intent_payload: dict[str, Any] | None = None
    intent_error = ""
    if getattr(args, "create_intent", False):
        if not sqlite_healthy:
            intent_error = "RECONCILE_SEARCH_UNHEALTHY"
        elif action == "NOOP":
            warnings.append("NOOP_REQUIRES_NO_WRITE_INTENT")
        elif not args.target_file or not args.proposal_file:
            intent_error = "INTENT_TARGET_AND_PROPOSAL_REQUIRED"
        elif not args.session_id:
            intent_error = "INTENT_SESSION_REQUIRED"
        else:
            try:
                intent_payload = write_intent.create_intent(
                    actor=args.actor,
                    raw_session_id=args.session_id,
                    target=args.target_file,
                    proposal_file=args.proposal_file,
                    approval_required=action in {"ASK_USER", "MERGE_REQUIRED"},
                    source_class=args.source_class,
                    knowledge_kind=args.knowledge_kind,
                    asserted_by=args.asserted_by or args.actor,
                    evidence_ref_sha256=str(safety.get("evidence_ref_sha256", "")),
                    reconcile_action=action,
                )
            except (write_intent.IntentError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
                intent_error = str(getattr(exc, "reason_code", "INTENT_CREATE_FAILED"))
                warnings.append(intent_error)
    return {
        "time": utc_now(),
        "run_id": run_id,
        "actor": args.actor,
        "trigger": args.trigger,
        "session_hash": hashed_session,
        "mode": "prewrite",
        "input_sha256": safety["input_sha256"],
        "input_length": safety["input_length"],
        "safety": safety,
        "reconcile": {
            "status": "completed" if sqlite_healthy else "blocked",
            "reason_code": recommendation_unavailable_reason,
            "recommended_action": action,
            "recommended_target": target.get("rel_path", "") if isinstance(target, dict) else "",
        },
        "write_intent": intent_payload,
        "write_intent_error": intent_error,
        "recommended_action": action,
        "recommendation_unavailable_reason": recommendation_unavailable_reason,
        "recommended_target": target,
        "recommendation_metrics": {
            "similarity": round(metrics["similarity"], 4),
            "coverage": round(metrics["coverage"], 4),
            "candidate_coverage": round(metrics["candidate_coverage"], 4),
            "title_match": metrics["title_match"],
            "semantic_distance": round(metrics["semantic_distance"], 4) if metrics["semantic_distance"] is not None else None,
            "raw_semantic_distance": round(metrics["raw_semantic_distance"], 4) if metrics["raw_semantic_distance"] is not None else None,
        },
        "allowed_actions": sorted(RECONCILE_ACTIONS),
        "candidates": rows,
        "backend_status": backend_status,
        "warnings": warnings,
        "status": (
            "blocked"
            if not sqlite_healthy or intent_error
            else ("warning" if warnings or action in {"ASK_USER", "MERGE_REQUIRED"} else "ok")
        ),
    }


def postwrite_reconcile(entries: list[GitEntry], args: argparse.Namespace) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    findings: list[dict[str, Any]] = []
    targets = [
        entry
        for entry in entries
        if entry.exists
        and entry.is_memory_markdown
        and (entry.is_new or args.reconcile_all)
        and is_current_reconcile_target(entry.path)
    ]
    for entry in targets:
        declared_relations = frontmatter_list(entry.path, "related_workflows")
        declared_supersedes = set(frontmatter_list(entry.path, "supersedes"))
        source_fact_keys = frontmatter_list(entry.path, "fact_key")
        query = reconcile_query_for_file(entry.path)
        if not query:
            continue
        rows, search_warnings, backend_status = search_memory(
            query,
            limit=max(args.limit, 8),
            no_zvec=args.no_zvec,
            current_project=project_scope_for_file(
                entry.path,
                getattr(args, "current_project", ""),
            ),
            read_only=bool(getattr(args, "dry_run", False)),
            canonical_actor=str(getattr(args, "actor", "") or ""),
        )
        warnings.extend(search_warnings)
        if backend_status.get("sqlite", {}).get("status") != "ok":
            findings.append(
                {
                    "action": "ASK_USER",
                    "file": str(entry.path),
                    "rel_path": relative_to_vault(entry.path),
                    "reason": "reconcile_search_unhealthy",
                    "candidates": [],
                }
            )
            continue
        source_text = query
        candidates: list[dict[str, Any]] = []
        for row in rows:
            if row.get("path") == str(entry.path) or row.get("rel_path") == relative_to_vault(entry.path):
                continue
            if str(row.get("rel_path") or "") in declared_relations:
                continue
            if str(row.get("rel_path") or "") in declared_supersedes:
                continue
            if legacy_context_candidate_for_explicit_fact(source_fact_keys, row):
                continue
            if str(row.get("memory_type") or "").lower() in NONFACT_RECONCILE_TYPES:
                continue
            comparison = " ".join(
                str(row.get(key, ""))
                for key in ("title", "rel_path", "summary", "hit")
            )
            similarity = jaccard(source_text, comparison)
            row_coverage = coverage(source_text, comparison)
            distance = semantic_distance(row)
            raw_distance = raw_semantic_distance(row)
            semantic_duplicate = raw_distance is not None and raw_distance <= args.semantic_merge_threshold
            if similarity >= args.merge_threshold or row_coverage >= args.merge_coverage_threshold or semantic_duplicate:
                candidates.append(
                    {
                        "rel_path": row.get("rel_path", ""),
                        "title": row.get("title", ""),
                        "similarity": round(similarity, 4),
                        "coverage": round(row_coverage, 4),
                        "semantic_distance": round(distance, 4) if distance is not None else None,
                        "raw_semantic_distance": round(raw_distance, 4) if raw_distance is not None else None,
                        "sources": row.get("sources", []),
                        "path": row.get("path", ""),
                    }
                )
        if candidates:
            findings.append(
                {
                    "action": "MERGE_REQUIRED",
                    "file": str(entry.path),
                    "rel_path": relative_to_vault(entry.path),
                    "reason": "new_or_checked_file_similar_to_existing_memory",
                    "candidates": candidates,
                }
            )
    return findings, warnings


def run_check(files: list[Path], args: argparse.Namespace) -> dict[str, Any]:
    command = [PYTHON, str(CHECK_SCRIPT), "--json"]
    for path in files:
        command.extend(["--changed-file", str(path)])
    result = run_command(command, timeout=180)
    try:
        payload = json.loads(str(result.get("stdout", "")))
    except json.JSONDecodeError:
        result["detail"] = "check_returned_non_json"
        return result
    result["check_payload"] = payload
    result["advisories"] = payload.get("advisories", []) if isinstance(payload, dict) else []
    result["detail"] = str(payload.get("status", "")) if isinstance(payload, dict) else ""
    return result


def _canonical_projection_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def full_vault_input_projection_sha256() -> str:
    """Hash every Markdown input consumed by a full index scan, excluding INDEX."""

    projection: list[tuple[str, str]] = []
    index_path = (VAULT_ROOT / "INDEX.md").resolve()
    for path in sorted(VAULT_ROOT.rglob("*.md"), key=lambda item: item.as_posix()):
        if path.is_symlink() or not path.is_file():
            raise OSError("GENERATED_INDEX_INPUT_UNSAFE")
        resolved = path.resolve()
        if resolved == index_path:
            continue
        relative = resolved.relative_to(VAULT_ROOT).as_posix()
        projection.append((relative, hashlib.sha256(path.read_bytes()).hexdigest()))
    return _canonical_projection_sha256(projection)


def assert_full_vault_input_projection(expected_sha256: str) -> str:
    """Require one stable full-Vault snapshot at a closeout commit fence."""

    expected = str(expected_sha256).strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise OSError("GENERATED_INDEX_TRANSACTION_INVALID")
    first = full_vault_input_projection_sha256()
    second = full_vault_input_projection_sha256()
    if first != second or first != expected:
        raise OSError("GENERATED_INDEX_INPUT_CHANGED")
    return first


def generated_index_transaction_binding(
    *,
    transaction_id: str,
    actor: str,
    raw_session_id: str,
    git_head: str,
    index_base_sha256: str,
    full_vault_inputs_sha256: str,
    lease_checkpoints: list[dict[str, Any]],
) -> dict[str, str]:
    """Bind INDEX publication to the validated closeout snapshot and fences."""

    fence_projection = sorted(
        (
            str(item.get("intent_id", "")),
            int(item.get("fencing_token") or 0),
            hashlib.sha256(str(item.get("path", "")).encode("utf-8")).hexdigest(),
            str(item.get("lease_state", "")),
        )
        for item in lease_checkpoints
        if str(item.get("stage", "")) == "before_checks"
    )
    return {
        "transaction_id": transaction_id,
        "actor": actor,
        "task_sha256": hashlib.sha256(raw_session_id.encode("utf-8")).hexdigest(),
        "vault_root_sha256": hashlib.sha256(str(VAULT_ROOT).encode("utf-8")).hexdigest(),
        "git_head": git_head,
        "index_base_sha256": index_base_sha256,
        "full_vault_inputs_sha256": full_vault_inputs_sha256,
        "lease_fences_sha256": _canonical_projection_sha256(fence_projection),
    }


def _register_generated_index_closeout_transaction(
    *,
    transaction_binding: dict[str, str],
    ttl_seconds: int = 30,
) -> dict[str, Any]:
    """Persist the validated closeout grant; the standalone issuer cannot do this."""

    ttl = int(ttl_seconds)
    if ttl < 1 or ttl > GENERATED_INDEX_MAX_TTL_SECONDS:
        raise GeneratedIndexCapabilityError("GENERATED_INDEX_TRANSACTION_INVALID")
    binding = normalize_transaction_binding(transaction_binding)
    now = int(time.time())
    placeholder_sha256 = hashlib.sha256(
        f"registered\0{binding['transaction_id']}".encode("utf-8")
    ).hexdigest()
    try:
        with contextlib.closing(
            secure_sqlite_connect(
                STATE_DB,
                create=False,
                row_factory=sqlite3.Row,
                pragmas=("PRAGMA busy_timeout=2000",),
            )
        ) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                f"""
                INSERT INTO {GENERATED_INDEX_TRANSACTION_TABLE}(
                  transaction_id, actor, task_sha256, vault_root_sha256,
                  git_head, index_base_sha256, full_vault_inputs_sha256,
                  lease_fences_sha256, capability_sha256, issuer_pid,
                  status, issued_at_epoch, expires_at_epoch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'registered', ?, ?)
                """,
                (
                    binding["transaction_id"],
                    binding["actor"],
                    binding["task_sha256"],
                    binding["vault_root_sha256"],
                    binding["git_head"],
                    binding["index_base_sha256"],
                    binding["full_vault_inputs_sha256"],
                    binding["lease_fences_sha256"],
                    placeholder_sha256,
                    os.getpid(),
                    now,
                    now + ttl,
                ),
            )
            conn.commit()
    except (OSError, sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
        raise GeneratedIndexCapabilityError(
            "GENERATED_INDEX_CLOSEOUT_TRANSACTION_UNAVAILABLE"
        ) from exc
    return {
        "ok": True,
        "transaction_id": binding["transaction_id"],
        "issuer_pid": os.getpid(),
        "expires_at_epoch": now + ttl,
    }


def run_index(
    args: argparse.Namespace,
    *,
    transaction_binding: dict[str, str],
    maintenance_environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    if args.dry_run:
        return {"ok": True, "skipped": True, "detail": "dry_run"}
    capability = issue_generated_index_capability(
        CONFIG_ROOT,
        state_db=STATE_DB,
        transaction_binding=transaction_binding,
    )
    command_env = command_env_offline()
    if maintenance_environment:
        allowed_keys = {
            "AGENT_MEMORY_MIGRATION_CAPABILITY",
            "AGENT_MEMORY_MIGRATION_ISSUER_PID",
        }
        if set(maintenance_environment) != allowed_keys:
            return {
                "ok": False,
                "detail": "GENERATED_INDEX_MIGRATION_AUTHORITY_INVALID",
            }
        command_env.update(maintenance_environment)
    command_env[GENERATED_INDEX_CAPABILITY_PATH_ENV] = capability["path"]
    command_env[GENERATED_INDEX_CAPABILITY_TOKEN_ENV] = capability["token"]
    command_env[GENERATED_INDEX_CAPABILITY_BINDING_ENV] = json.dumps(
        transaction_binding,
        sort_keys=True,
        separators=(",", ":"),
    )
    result = run_command(
        [
            PYTHON,
            str(INDEX_SCRIPT),
            "--init",
            "--scan",
            "--sync-generated-index",
            "--report",
        ],
        timeout=180,
        env=command_env,
    )
    stdout_generated: dict[str, Any] = {"changed": False, "path": "", "sha256": ""}
    for line in str(result.get("stdout", "")).splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            continue
        if key == "generated_index_changed":
            stdout_generated["changed"] = value.strip() == "1"
        elif key == "generated_index_path":
            stdout_generated["path"] = value.strip()
        elif key == "generated_index_sha256":
            stdout_generated["sha256"] = value.strip().lower()
    try:
        receipt = read_generated_index_transaction(STATE_DB, transaction_binding)
    except GeneratedIndexCapabilityError as exc:
        result["ok"] = False
        result["detail"] = str(exc)
        result["generated_index"] = stdout_generated
        return result
    result["generated_index_transaction"] = receipt
    digest = str(receipt.get("generated_sha256", "")).strip().lower()
    canonical_path = (VAULT_ROOT / "INDEX.md").resolve()
    try:
        current_sha256 = (
            hashlib.sha256(canonical_path.read_bytes()).hexdigest()
            if canonical_path.is_file() and not canonical_path.is_symlink()
            else ""
        )
        stdout_path = Path(str(stdout_generated.get("path", ""))).expanduser().resolve()
    except OSError:
        current_sha256 = ""
        stdout_path = Path()
    changed = digest != transaction_binding["index_base_sha256"]
    generated = {
        "changed": changed,
        "path": str(canonical_path),
        "sha256": digest,
        "current_sha256": current_sha256,
        "published": bool(digest and current_sha256 == digest),
    }
    result["generated_index"] = generated
    durable_valid = (
        receipt.get("status") == "generated_bound"
        and int(receipt.get("issuer_pid") or 0) == os.getpid()
        and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
        and current_sha256 == digest
    )
    stdout_valid = (
        stdout_path == canonical_path
        and str(stdout_generated.get("sha256", "")) == digest
        and bool(stdout_generated.get("changed")) == changed
    )
    if not durable_valid:
        result["ok"] = False
        result["detail"] = "GENERATED_INDEX_DURABLE_READBACK_INVALID"
    elif not stdout_valid:
        result["ok"] = False
        result["detail"] = "GENERATED_INDEX_SYNC_EVIDENCE_INVALID"
    return result


def capture_generated_index_snapshot() -> GeneratedIndexSnapshot:
    """Bind the pre-closeout INDEX bytes so a non-commit can restore them."""

    path = VAULT_ROOT / "INDEX.md"
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise OSError("generated index must be an existing regular file")
    raw = path.read_bytes()
    return GeneratedIndexSnapshot(
        path=path.resolve(),
        raw=raw,
        mode=stat.S_IMODE(metadata.st_mode),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
    )


def restore_generated_index_snapshot(
    snapshot: GeneratedIndexSnapshot,
    *,
    expected_current_sha256: str,
    transaction_id: str,
) -> dict[str, Any]:
    """CAS-restore INDEX after a closeout that did not commit it."""

    path = snapshot.path
    try:
        if path.is_symlink():
            raise OSError("generated index became a symlink")
        current_sha256 = (
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
        )
        if current_sha256 == snapshot.raw_sha256:
            return {"ok": True, "restored": False, "detail": "unchanged"}
        if current_sha256 != expected_current_sha256:
            return {
                "ok": False,
                "restored": False,
                "detail": "GENERATED_INDEX_ROLLBACK_CONFLICT",
            }
        evidence_root = generated_index_backup_directory(CONFIG_ROOT, transaction_id)
        temporary = evidence_root / f"restore-{uuid.uuid4().hex}.md"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, snapshot.mode or 0o600)
        try:
            view = memoryview(snapshot.raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short generated index restore write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(temporary, snapshot.mode)
        evidence_path = conditional_atomic_replace(
            path,
            temporary,
            expected_current_sha256=expected_current_sha256,
        )
        directory = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        return {
            "ok": False,
            "restored": False,
            "detail": "GENERATED_INDEX_ROLLBACK_CONFLICT",
        }
    return {
        "ok": True,
        "restored": True,
        "detail": "restored_precloseout_bytes",
        "generated_bytes_evidence": str(evidence_path),
    }


def committed_file_sha256(commit: str, path: Path) -> str:
    """Read exact committed bytes instead of trusting the working tree."""

    normalized_commit = str(commit).strip().lower()
    if re.fullmatch(r"[0-9a-f]{40,64}", normalized_commit) is None:
        raise OSError("GENERATED_INDEX_COMMIT_INVALID")
    try:
        repo_path = path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError as exc:
        raise OSError("GENERATED_INDEX_COMMIT_INVALID") from exc
    try:
        completed = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "show", f"{normalized_commit}:{repo_path}"],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OSError("GENERATED_INDEX_COMMIT_INVALID") from exc
    return hashlib.sha256(completed.stdout).hexdigest()


def exact_generated_index_commit(
    transaction_binding: dict[str, str],
    generated_sha256: str,
    current_head: str,
) -> str:
    """Return only the exact closeout commit, never an arbitrary later descendant."""

    expected_vault = str(transaction_binding.get("vault_root_sha256", ""))
    current_vault = hashlib.sha256(str(VAULT_ROOT.resolve()).encode("utf-8")).hexdigest()
    if current_vault != expected_vault:
        raise OSError("GENERATED_INDEX_VAULT_ROOT_CHANGED")
    base = str(transaction_binding.get("git_head", "")).strip().lower()
    head = str(current_head).strip().lower()
    digest = str(generated_sha256).strip().lower()
    candidates: list[str] = []
    if head == base and digest == str(transaction_binding.get("index_base_sha256", "")):
        candidates.append(base)
    elif re.fullmatch(r"[0-9a-f]{40,64}", head):
        history = run_command(
            [
                "git",
                "-C",
                str(REPO_ROOT),
                "rev-list",
                "--first-parent",
                "--reverse",
                f"{base}..{head}",
            ],
            timeout=30,
        )
        if not history.get("ok"):
            raise OSError("GENERATED_INDEX_GIT_EVIDENCE_UNAVAILABLE")
        first = next(
            (
                line.strip().lower()
                for line in str(history.get("stdout", "")).splitlines()
                if re.fullmatch(r"[0-9a-f]{40,64}", line.strip().lower())
            ),
            "",
        )
        if first:
            candidates.append(first)
    for candidate in candidates:
        try:
            verify_generated_index_commit_evidence(
                REPO_ROOT,
                VAULT_ROOT,
                transaction_binding,
                generated_sha256=digest,
                closeout_git_commit=candidate,
            )
        except GeneratedIndexCapabilityError:
            continue
        return candidate
    return ""


def rescan_after_generated_index_restore() -> dict[str, Any]:
    """Return SQLite to the restored Markdown projection before reporting rollback."""

    return run_command(
        [PYTHON, str(INDEX_SCRIPT), "--scan", "--report"],
        timeout=180,
        env=command_env_offline(),
    )


def _process_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _generated_index_recovery_evidence(
    transaction_id: str,
    expected_sha256: str,
    stored_path: str = "",
) -> Path | None:
    if stored_path:
        try:
            candidate = validate_generated_index_recovery_evidence_path(
                CONFIG_ROOT,
                transaction_id,
                stored_path,
                require_exists=True,
            )
            if hashlib.sha256(candidate.read_bytes()).hexdigest() == expected_sha256:
                return candidate
        except (GeneratedIndexCapabilityError, OSError):
            return None
        return None
    root = CONFIG_ROOT / "backups" / "generated-index" / transaction_id
    try:
        # Backward-compatible discovery for an interrupted transaction created
        # before exact evidence paths were persisted.
        validate_generated_index_recovery_evidence_path(
            CONFIG_ROOT,
            transaction_id,
            root / "__probe__",
            require_exists=False,
        )
        metadata = root.lstat()
    except (GeneratedIndexCapabilityError, OSError):
        return None
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        return None
    current_uid = os.getuid() if hasattr(os, "getuid") else metadata.st_uid
    if metadata.st_uid != current_uid:
        return None
    try:
        candidates = sorted(root.iterdir(), key=lambda path: path.name)
    except OSError:
        return None
    for candidate in candidates[:128]:
        try:
            candidate_metadata = candidate.lstat()
            if (
                candidate.is_symlink()
                or not stat.S_ISREG(candidate_metadata.st_mode)
                or candidate_metadata.st_uid != current_uid
                or candidate_metadata.st_size > 16 * 1024 * 1024
            ):
                continue
            if hashlib.sha256(candidate.read_bytes()).hexdigest() == expected_sha256:
                return validate_generated_index_recovery_evidence_path(
                    CONFIG_ROOT,
                    transaction_id,
                    candidate,
                    require_exists=True,
                )
        except OSError:
            continue
    return None


def recover_generated_index_observation() -> int:
    """Restore only INDEX completion evidence proven by a consumed transaction.

    Publishing the Git commit and consuming the capability can precede the
    parent's observation write.  A crash in that gap must not turn our own
    generated artifact into an unclaimed external edit on every future task.
    This does not finalize ordinary memory intents or authorize their content.
    """
    target = VAULT_ROOT / "INDEX.md"
    if not target.exists():
        return 0
    raw, metadata = _read_regular_file(target, maximum_bytes=16 * 1024 * 1024)
    digest = hashlib.sha256(raw).hexdigest()
    canonical = str(target.resolve())
    with contextlib.closing(secure_sqlite_connect(
        STATE_DB, create=False, read_only=True, row_factory=sqlite3.Row,
    )) as conn:
        observed = conn.execute(
            "SELECT sha256 FROM memory_file_observations WHERE path=?", (canonical,),
        ).fetchone()
        if observed is not None and str(observed["sha256"]) == digest:
            return 0
        receipts = conn.execute(
            f"SELECT * FROM {GENERATED_INDEX_TRANSACTION_TABLE} "
            "WHERE status='consumed' AND generated_sha256=? "
            "ORDER BY consumed_at_epoch DESC, transaction_id DESC", (digest,),
        ).fetchall()
    if not receipts:
        return 0
    head, warnings = current_git_head()
    if warnings or committed_file_sha256(head, target) != digest:
        raise OSError("GENERATED_INDEX_OBSERVATION_DRIFT")
    receipt = dict(receipts[0])
    binding = {key: str(receipt[key]) for key in GENERATED_INDEX_BINDING_FIELDS}
    commit = str(receipt["closeout_git_commit"])
    verify_generated_index_commit_evidence(
        REPO_ROOT, VAULT_ROOT, binding,
        generated_sha256=digest, closeout_git_commit=commit,
    )
    ancestor = run_command(
        ["git", "-C", str(REPO_ROOT), "merge-base", "--is-ancestor", commit, head],
        timeout=30,
    )
    if not ancestor.get("ok"):
        raise OSError("GENERATED_INDEX_OBSERVATION_GIT_DIVERGED")
    with contextlib.closing(secure_sqlite_connect(
        STATE_DB, create=False, row_factory=sqlite3.Row,
    )) as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute(
            f"SELECT * FROM {GENERATED_INDEX_TRANSACTION_TABLE} WHERE transaction_id=?",
            (binding["transaction_id"],),
        ).fetchone()
        readback, after = _read_regular_file(target, maximum_bytes=16 * 1024 * 1024)
        if (
            current is None or dict(current) != receipt
            or (metadata.st_dev, metadata.st_ino) != (after.st_dev, after.st_ino)
            or hashlib.sha256(readback).hexdigest() != digest
            or current_git_head()[0] != head
        ):
            raise OSError("GENERATED_INDEX_OBSERVATION_DRIFT")
        conn.execute(
            "INSERT INTO memory_file_observations "
            "(path,rel_path,sha256,actor,session_hash,observed_at,intent_id,fencing_token,git_commit) "
            "VALUES (?,'INDEX.md',?,?,?,?,'',0,?) "
            "ON CONFLICT(path) DO UPDATE SET rel_path=excluded.rel_path, "
            "sha256=excluded.sha256,actor=excluded.actor,session_hash=excluded.session_hash, "
            "observed_at=excluded.observed_at,intent_id='',fencing_token=0,git_commit=excluded.git_commit",
            (canonical, digest, binding["actor"], binding["task_sha256"],
             dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), commit),
        )
        conn.commit()
    return 1


def recover_generated_index_transactions() -> dict[str, Any]:
    """Recover parent crashes without trusting stdout or overwriting later edits."""

    index_batch_recovery = recover_closeout_index_transactions()
    summary: dict[str, Any] = {
        "ok": bool(index_batch_recovery.get("ok")),
        "recovered": 0,
        "committed": 0,
        "rolled_back": 0,
        "failed": 0,
        "blocked": int(index_batch_recovery.get("blocked") or 0),
        "index_batches_recovered": int(index_batch_recovery.get("recovered") or 0),
        "index_batch_recovery": index_batch_recovery,
    }
    if not index_batch_recovery.get("ok"):
        summary["detail"] = "GENERATED_INDEX_RECOVERY_REQUIRED"
        return summary
    try:
        with secure_sqlite_connect(
            STATE_DB,
            create=False,
            read_only=True,
            row_factory=sqlite3.Row,
            pragmas=("PRAGMA busy_timeout=2000",),
        ) as conn:
            rows = conn.execute(
                f"SELECT * FROM {GENERATED_INDEX_TRANSACTION_TABLE} "
                "WHERE status IN ('registered','issued','claimed','generated_bound','failed') "
                "ORDER BY issued_at_epoch, transaction_id"
            ).fetchall()
    except (OSError, sqlite3.Error) as exc:
        return {
            **summary,
            "ok": False,
            "blocked": 1,
            "detail": "GENERATED_INDEX_RECOVERY_UNAVAILABLE",
            "error_type": type(exc).__name__,
        }

    now = int(time.time())
    target = (VAULT_ROOT / "INDEX.md").resolve()
    for row in rows:
        receipt = dict(row)
        transaction_status = str(receipt.get("status", ""))
        issuer_pid = int(receipt.get("issuer_pid") or 0)
        consumer_pid = int(receipt.get("consumer_pid") or 0)
        expired = int(receipt.get("expires_at_epoch") or 0) < now
        if transaction_status != "failed" and not expired and _process_is_alive(issuer_pid):
            summary["blocked"] += 1
            continue
        if (
            transaction_status != "failed"
            and consumer_pid
            and consumer_pid != os.getpid()
            and _process_is_alive(consumer_pid)
        ):
            summary["blocked"] += 1
            continue
        binding = {
            key: str(receipt.get(key, ""))
            for key in GENERATED_INDEX_BINDING_FIELDS
        }
        digest = str(receipt.get("generated_sha256", "")).strip().lower()
        was_failed = transaction_status == "failed"
        try:
            if not was_failed and transaction_status != "generated_bound":
                mark_generated_index_transaction_outcome(
                    STATE_DB,
                    binding,
                    outcome="rolled_back",
                    issuer_pid=issuer_pid,
                )
                summary["rolled_back"] += 1
                summary["recovered"] += 1
                continue
            current_vault_sha256 = hashlib.sha256(
                str(VAULT_ROOT.resolve()).encode("utf-8")
            ).hexdigest()
            if current_vault_sha256 != binding["vault_root_sha256"]:
                raise OSError("GENERATED_INDEX_VAULT_ROOT_CHANGED")
            if target.is_symlink() or not target.is_file():
                raise OSError("GENERATED_INDEX_TARGET_UNSAFE")
            current_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
            current_head, _warnings = current_git_head()
            if re.fullmatch(r"[0-9a-f]{40,64}", current_head) is None:
                raise OSError("GENERATED_INDEX_GIT_EVIDENCE_UNAVAILABLE")
            exact_commit = (
                exact_generated_index_commit(binding, digest, current_head)
                if re.fullmatch(r"[0-9a-f]{64}", digest)
                else ""
            )
            if exact_commit:
                if current_head == exact_commit:
                    repair_generated_index_stage_zero(
                        transaction_binding=binding,
                        exact_commit=exact_commit,
                        generated_sha256=digest,
                        current_worktree_sha256=current_sha256,
                    )
                if was_failed:
                    resolve_failed_generated_index_transaction(
                        STATE_DB,
                        binding,
                        outcome="consumed",
                        generated_sha256=digest,
                        closeout_git_commit=exact_commit,
                        issuer_pid=issuer_pid,
                    )
                else:
                    commit_generated_index_transaction(
                        STATE_DB,
                        binding,
                        generated_sha256=digest,
                        closeout_git_commit=exact_commit,
                        issuer_pid=issuer_pid,
                    )
                summary["committed"] += 1
                summary["recovered"] += 1
                continue
            base_sha256 = binding["index_base_sha256"]
            if (
                re.fullmatch(r"[0-9a-f]{64}", digest)
                and current_sha256 == digest
                and digest != base_sha256
            ):
                evidence = _generated_index_recovery_evidence(
                    binding["transaction_id"],
                    base_sha256,
                    str(receipt.get("rollback_evidence_path", "")),
                )
                if evidence is None:
                    raise OSError("GENERATED_INDEX_RECOVERY_EVIDENCE_MISSING")
                conditional_atomic_replace(
                    target,
                    evidence,
                    expected_current_sha256=digest,
                )
            elif current_sha256 != base_sha256:
                raise OSError("GENERATED_INDEX_RECOVERY_CONFLICT")
            if target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest() != base_sha256:
                raise OSError("GENERATED_INDEX_ROLLBACK_CONFLICT")
            rescan = rescan_after_generated_index_restore()
            if not rescan.get("ok"):
                raise OSError("GENERATED_INDEX_ROLLBACK_REINDEX_FAILED")
            if was_failed:
                resolve_failed_generated_index_transaction(
                    STATE_DB,
                    binding,
                    outcome="rolled_back",
                    generated_sha256=digest,
                    issuer_pid=issuer_pid,
                )
            else:
                mark_generated_index_transaction_outcome(
                    STATE_DB,
                    binding,
                    outcome="rolled_back",
                    generated_sha256=digest,
                    issuer_pid=issuer_pid,
                )
            summary["rolled_back"] += 1
            summary["recovered"] += 1
        except (GeneratedIndexCapabilityError, OSError, subprocess.SubprocessError) as exc:
            raw_reason = str(exc).strip().upper()
            failure_reason = (
                raw_reason
                if re.fullmatch(r"[A-Z0-9_]{1,128}", raw_reason)
                else "GENERATED_INDEX_RECOVERY_FAILED"
            )
            if was_failed:
                summary["blocked"] += 1
                continue
            try:
                mark_generated_index_transaction_outcome(
                    STATE_DB,
                    binding,
                    outcome="failed",
                    generated_sha256=digest if re.fullmatch(r"[0-9a-f]{64}", digest) else "",
                    failure_reason=failure_reason,
                    issuer_pid=issuer_pid,
                )
            except GeneratedIndexCapabilityError:
                pass
            summary["failed"] += 1
    if summary["blocked"] == 0 and summary["failed"] == 0:
        try:
            observed = recover_generated_index_observation()
            summary["observations_recovered"] = observed
            summary["recovered"] += observed
        except (GeneratedIndexCapabilityError, OSError, sqlite3.Error, ValueError) as exc:
            summary["failed"] += 1
            summary["observation_reason"] = str(exc)
    summary["ok"] = summary["blocked"] == 0 and summary["failed"] == 0
    if not summary["ok"]:
        summary["detail"] = "GENERATED_INDEX_RECOVERY_REQUIRED"
    else:
        summary["detail"] = "recovered" if summary["recovered"] else "none"
    return summary


def recover_expired_governance_generated_index_transaction(
    *,
    actor: str,
    raw_session_id: str,
    intent_id: str,
    target_relative_path: str,
    fencing_token: int,
    review_sha256: str,
    base_raw_sha256: str,
    base_canonical_sha256: str,
    read_token: str,
    scope_app_id: str,
    scope_project_id: str,
    proposal_raw_sha256: str,
    proposal_canonical_sha256: str,
    proposal_size_bytes: int,
    base_git_head: str,
    validated_git_head: str,
    early_commit: bool,
    proposal_commit: str,
    lock_timeout: float = 2.0,
    publish_repair: Callable[[dict[str, str]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Consume or read back one task-bound no-change INDEX crash receipt.

    This is an internal continuation lane for one elapsed governance recovery,
    not a general Doctor bypass.  It accepts only the exact actor/session,
    intent fence, review/proposal, active claim, clean HEAD/INDEX projection,
    and the one generated transaction whose lease-fence projection names that
    intent.  A previous Runtime may already have consumed the row through the
    ordinary scoped closeout; in that case this function performs no write and
    returns the same durable evidence.
    """

    def deny(code: str) -> None:
        raise GeneratedIndexCapabilityError(code)

    if (
        actor not in {"codex", "claude"}
        or not raw_session_id
        or re.fullmatch(r"[0-9a-f]{32}", str(intent_id)) is None
        or int(fencing_token) <= 0
        or re.fullmatch(r"[0-9a-f]{64}", str(review_sha256)) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(base_raw_sha256)) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(base_canonical_sha256)) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(read_token)) is None
        or not str(scope_app_id).strip()
        or not str(scope_project_id).strip()
        or re.fullmatch(r"[0-9a-f]{64}", str(proposal_raw_sha256)) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(proposal_canonical_sha256)) is None
        or int(proposal_size_bytes) <= 0
        or re.fullmatch(r"[0-9a-f]{40,64}", str(base_git_head)) is None
        or re.fullmatch(r"[0-9a-f]{40,64}", str(validated_git_head)) is None
        or (proposal_commit and re.fullmatch(r"[0-9a-f]{40,64}", str(proposal_commit)) is None)
    ):
        deny("EXPIRED_VALIDATED_RECOVERY_INDEX_BINDING_INVALID")
    canonical = write_intent.canonical_target(target_relative_path)
    try:
        with closeout_lock(lock_timeout):
            shown = write_intent.show_intent(intent_id)
            stored = shown.get("intent") if isinstance(shown, dict) else None
            receipt = shown.get("receipt") if isinstance(shown, dict) else None
            if not isinstance(stored, dict) or receipt is not None:
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_INTENT_INVALID")
            expected_evidence = hashlib.sha256(
                f"content-migration-review:{review_sha256}".encode("utf-8")
            ).hexdigest()
            stored_reason = str(stored.get("reason_code", ""))
            if stored_reason not in {
                write_intent.EXPIRED_VALIDATED_RECOVERY_REASON,
                write_intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON,
            }:
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_INTENT_INVALID")
            expected_intent = {
                "intent_id": intent_id,
                "actor": actor,
                "session_hash": session_hash(raw_session_id),
                "target_rel_path": canonical.rel_path,
                "target_key": canonical.target_key,
                "fencing_token": int(fencing_token),
                "status": "validated",
                "base_exists": 1,
                "base_raw_sha256": base_raw_sha256,
                "base_canonical_sha256": base_canonical_sha256,
                "read_token": read_token,
                "scope_app_id": scope_app_id,
                "scope_project_id": scope_project_id,
                "proposal_raw_sha256": proposal_raw_sha256,
                "proposal_canonical_sha256": proposal_canonical_sha256,
                "proposal_size_bytes": int(proposal_size_bytes),
                "final_raw_sha256": proposal_raw_sha256,
                "final_canonical_sha256": proposal_canonical_sha256,
                "base_git_head": base_git_head,
                "validated_git_head": validated_git_head,
                "early_commit": int(bool(early_commit)),
                "proposal_commit": proposal_commit,
                "evidence_ref_sha256": expected_evidence,
                "operation": "governance_migration",
                "reconcile_action": "UPDATE",
                "target_status": "",
                "transition_reason_sha256": "",
            }
            if any(stored.get(key) != value for key, value in expected_intent.items()):
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_BINDING_CHANGED")
            expiry = write_intent.parse_time(str(stored.get("expires_at", "")))
            published = write_intent.parse_time(str(stored.get("updated_at", "")))
            now_value = dt.datetime.now(dt.timezone.utc)
            marker_ttl = (
                write_intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_TTL_SECONDS
                if stored_reason
                == write_intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON
                else write_intent.EXPIRED_VALIDATED_RECOVERY_TTL_SECONDS
            )
            if (
                expiry is None
                or published is None
                or published > expiry
                or expiry - published <= dt.timedelta(0)
                or expiry - published
                > dt.timedelta(seconds=marker_ttl)
                or str(stored.get("validation_mode", "")) != "exact"
                or not str(stored.get("validated_at", ""))
                or str(stored.get("bound_base_raw_sha256", ""))
                != base_raw_sha256
                or not str(stored.get("claim_ref_sha256", ""))
                or int(stored.get("approval_required") or 0) != 1
                or str(stored.get("source_class", "")) != "user_direct"
                or str(stored.get("knowledge_kind", "")) != "rule"
                or str(stored.get("asserted_by", "")) != "user"
                or not write_intent.has_valid_confirmation_capability_approval(stored)
            ):
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_WINDOW_INVALID")
            if (
                stored_reason == write_intent.EXPIRED_VALIDATED_RECOVERY_REASON
                and expiry > now_value
            ):
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_WINDOW_INVALID")
            if (
                stored_reason
                == write_intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON
                and expiry <= now_value
            ):
                deny("EXPIRED_VALIDATED_RECOVERY_REPAIR_WINDOW_ELAPSED")
            write_intent.assert_current_lease(
                intent_id,
                actor=actor,
                raw_session_id=raw_session_id,
                fencing_token=int(fencing_token),
                target=canonical.rel_path,
                require_unexpired=False,
            )
            expected_fences = (
                write_intent._generated_index_repair_lease_fences_sha256(
                    intent_id=intent_id,
                    fencing_token=int(fencing_token),
                    rel_path=canonical.rel_path,
                )
            )
            task_sha256 = hashlib.sha256(
                raw_session_id.encode("utf-8")
            ).hexdigest()
            with secure_sqlite_connect(
                STATE_DB,
                create=False,
                read_only=True,
                row_factory=sqlite3.Row,
                pragmas=("PRAGMA busy_timeout=2000",),
            ) as conn:
                claims = conn.execute(
                    "SELECT * FROM memory_session_claims WHERE status='active' "
                    "AND (intent_id=? OR target_key=?)",
                    (intent_id, canonical.target_key),
                ).fetchall()
                candidates = conn.execute(
                    f"SELECT * FROM {GENERATED_INDEX_TRANSACTION_TABLE} "
                    "WHERE actor=? AND task_sha256=? AND lease_fences_sha256=? "
                    "AND status IN ('generated_bound','consumed') "
                    "ORDER BY issued_at_epoch, transaction_id",
                    (actor, task_sha256, expected_fences),
                ).fetchall()
                open_rows = conn.execute(
                    f"SELECT transaction_id FROM {GENERATED_INDEX_TRANSACTION_TABLE} "
                    "WHERE status IN ('registered','issued','claimed','generated_bound','failed')"
                ).fetchall()
            expected_claim = {
                "session_hash": session_hash(raw_session_id),
                "actor": actor,
                "path": str(canonical.path),
                "rel_path": canonical.rel_path,
                "status": "active",
                "completed_at": None,
                "intent_id": intent_id,
                "target_key": canonical.target_key,
                "fencing_token": int(fencing_token),
                "claim_kind": "intent",
            }
            if len(claims) != 1 or any(
                claims[0][key] != value for key, value in expected_claim.items()
            ):
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_CLAIM_CHANGED")
            current_head, head_warnings = current_git_head()
            index_path = (VAULT_ROOT / "INDEX.md").resolve()
            dirty_markdown, status_warnings = full_vault_markdown_git_status()
            git_operation = generated_index_git_operation_fence()
            lock_path = _git_index_lock_path()
            try:
                index_layout = _git_index_layout(create_recovery=False)
                recovery_root = index_layout["recovery_root"]
                pending_index_manifests: list[Path] = []
                if recovery_root.exists() or recovery_root.is_symlink():
                    recovery_entries = list(recovery_root.iterdir())
                    if len(recovery_entries) > 768:
                        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_LIMIT_EXCEEDED")
                    for manifest in recovery_entries:
                        match = re.fullmatch(
                            r"([0-9a-f]{32})\.manifest\.json",
                            manifest.name,
                        )
                        if match is None:
                            continue
                        outcome = recovery_root / f"{match.group(1)}.outcome.json"
                        if not outcome.is_file() or outcome.is_symlink():
                            pending_index_manifests.append(manifest)
            except OSError:
                pending_index_manifests = [Path("unsafe")]
            try:
                index_before = index_path.lstat()
                current_index_sha256 = hashlib.sha256(
                    index_path.read_bytes()
                ).hexdigest()
                index_after = index_path.lstat()
            except OSError:
                current_index_sha256 = ""
                index_before = None
                index_after = None
            current_full_vault_sha256 = full_vault_input_projection_sha256()
            repeated_full_vault_sha256 = full_vault_input_projection_sha256()
            if (
                head_warnings
                or status_warnings
                or dirty_markdown
                or not git_operation.get("ok")
                or lock_path is None
                or lock_path.exists()
                or lock_path.is_symlink()
                or pending_index_manifests
                or index_path.is_symlink()
                or not index_path.is_file()
                or index_before is None
                or index_after is None
                or (
                    index_before.st_dev,
                    index_before.st_ino,
                    index_before.st_mode,
                    index_before.st_size,
                    index_before.st_mtime_ns,
                )
                != (
                    index_after.st_dev,
                    index_after.st_ino,
                    index_after.st_mode,
                    index_after.st_size,
                    index_after.st_mtime_ns,
                )
                or re.fullmatch(r"[0-9a-f]{40,64}", current_head) is None
                or re.fullmatch(r"[0-9a-f]{64}", current_index_sha256) is None
                or repeated_full_vault_sha256 != current_full_vault_sha256
            ):
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_PROJECTION_DRIFT")

            # Actor/task/fence is intentionally reusable across closeout
            # attempts. Historical consumed receipts therefore remain valid
            # evidence, but only the receipt bound to the current immutable
            # Git/INDEX/full-Vault projection can authorize this recovery.
            # Do not filter on failure/status/process fields before uniqueness:
            # two well-formed rows naming the same current projection must fail
            # ambiguous, while malformed identity or binding fields fail closed.
            current_vault_sha256 = hashlib.sha256(
                str(VAULT_ROOT).encode("utf-8")
            ).hexdigest()
            projection_candidates: list[dict[str, Any]] = []
            for row in candidates:
                projected = dict(row)
                transaction_id = str(projected.get("transaction_id", ""))
                digest = str(projected.get("generated_sha256", ""))
                base_index = str(projected.get("index_base_sha256", ""))
                transaction_head = str(projected.get("git_head", ""))
                if (
                    str(projected.get("actor", "")) != actor
                    or str(projected.get("task_sha256", "")) != task_sha256
                    or str(projected.get("vault_root_sha256", ""))
                    != current_vault_sha256
                    or str(projected.get("lease_fences_sha256", ""))
                    != expected_fences
                ):
                    deny("EXPIRED_VALIDATED_RECOVERY_INDEX_TRANSACTION_INVALID")
                if (
                    re.fullmatch(r"[0-9a-f]{32}", transaction_id) is None
                    or re.fullmatch(r"[0-9a-f]{40,64}", transaction_head) is None
                    or re.fullmatch(r"[0-9a-f]{64}", base_index) is None
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                    or re.fullmatch(
                        r"[0-9a-f]{64}",
                        str(projected.get("full_vault_inputs_sha256", "")),
                    )
                    is None
                    or digest != base_index
                ):
                    deny("EXPIRED_VALIDATED_RECOVERY_INDEX_TRANSACTION_INVALID")
                if (
                    transaction_head != current_head
                    or current_index_sha256 != digest
                    or current_full_vault_sha256
                    != str(projected.get("full_vault_inputs_sha256", ""))
                ):
                    continue
                projection_candidates.append(projected)
            if len(projection_candidates) != 1:
                if not projection_candidates and len(candidates) == 1:
                    deny("EXPIRED_VALIDATED_RECOVERY_INDEX_PROJECTION_DRIFT")
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_TRANSACTION_AMBIGUOUS")

            candidate = projection_candidates[0]
            binding = {
                key: str(candidate.get(key, ""))
                for key in GENERATED_INDEX_BINDING_FIELDS
            }
            digest = str(candidate.get("generated_sha256", ""))
            transaction_head = str(candidate.get("git_head", ""))
            try:
                exact_commit = exact_generated_index_commit(
                    binding,
                    digest,
                    current_head,
                )
            except (GeneratedIndexCapabilityError, OSError):
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_COMMIT_INVALID")
            if exact_commit != transaction_head:
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_COMMIT_INVALID")
            candidate_id = str(candidate.get("transaction_id", ""))
            if any(
                str(row["transaction_id"]) != candidate_id for row in open_rows
            ):
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_OTHER_TRANSACTION_OPEN")
            first_window = (
                stored_reason == write_intent.EXPIRED_VALIDATED_RECOVERY_REASON
            )
            if (
                (
                    first_window
                    and int(candidate.get("issued_at_epoch") or 0)
                    < int(published.timestamp())
                )
                or (
                    first_window
                    and int(candidate.get("expires_at_epoch") or 0)
                    > int(expiry.timestamp())
                )
                or (
                    first_window
                    and int(candidate.get("claimed_at_epoch") or 0)
                    > int(expiry.timestamp())
                )
                or str(candidate.get("failure_reason", ""))
                or candidate.get("failure_at_epoch") is not None
                or str(candidate.get("rollback_evidence_path", ""))
            ):
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_TRANSACTION_INVALID")
            base_index = str(candidate.get("index_base_sha256", ""))
            status = str(candidate.get("status", ""))
            if status == "generated_bound":
                issuer_pid = int(candidate.get("issuer_pid") or 0)
                consumer_pid = int(candidate.get("consumer_pid") or 0)
                if _process_is_alive(issuer_pid) or _process_is_alive(consumer_pid):
                    deny("EXPIRED_VALIDATED_RECOVERY_INDEX_PROCESS_ACTIVE")
                candidate = commit_generated_index_transaction(
                    STATE_DB,
                    binding,
                    generated_sha256=digest,
                    closeout_git_commit=exact_commit,
                    issuer_pid=issuer_pid,
                )
            elif (
                status != "consumed"
                or str(candidate.get("closeout_git_commit", ""))
                != exact_commit
            ):
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_TRANSACTION_INVALID")
            durable = read_generated_index_transaction(STATE_DB, binding)
            if (
                durable.get("status") != "consumed"
                or str(durable.get("generated_sha256", "")) != digest
                or str(durable.get("closeout_git_commit", "")) != exact_commit
            ):
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_CONSUME_FAILED")
            # Consuming the SQLite row is not write authority. Re-read every
            # live Git/INDEX fence after that CAS and return no evidence if a
            # concurrent writer moved any projection. The caller also runs
            # this same exact readback again after Doctor, immediately before
            # the repair marker can be published.
            post_head, post_head_warnings = current_git_head()
            post_dirty, post_status_warnings = full_vault_markdown_git_status()
            post_operation = generated_index_git_operation_fence()
            post_lock = _git_index_lock_path()
            try:
                post_before = index_path.lstat()
                post_index_sha256 = hashlib.sha256(
                    index_path.read_bytes()
                ).hexdigest()
                post_after = index_path.lstat()
                post_full_vault_sha256 = full_vault_input_projection_sha256()
                post_full_vault_repeat = full_vault_input_projection_sha256()
            except OSError:
                post_before = None
                post_after = None
                post_index_sha256 = ""
                post_full_vault_sha256 = ""
                post_full_vault_repeat = ""
            if (
                post_head_warnings
                or post_status_warnings
                or post_dirty
                or not post_operation.get("ok")
                or post_lock is None
                or post_lock.exists()
                or post_lock.is_symlink()
                or post_before is None
                or post_after is None
                or (
                    post_before.st_dev,
                    post_before.st_ino,
                    post_before.st_mode,
                    post_before.st_size,
                    post_before.st_mtime_ns,
                )
                != (
                    post_after.st_dev,
                    post_after.st_ino,
                    post_after.st_mode,
                    post_after.st_size,
                    post_after.st_mtime_ns,
                )
                or post_head != current_head
                or post_index_sha256 != current_index_sha256
                or post_full_vault_sha256 != current_full_vault_sha256
                or post_full_vault_repeat != post_full_vault_sha256
            ):
                deny("EXPIRED_VALIDATED_RECOVERY_INDEX_CONCURRENT_DRIFT")
            evidence = {
                "transaction_id": candidate_id,
                "status": "consumed",
                "git_head": transaction_head,
                "index_base_sha256": base_index,
                "generated_sha256": digest,
                "closeout_git_commit": exact_commit,
                "lease_fences_sha256": expected_fences,
            }
            if publish_repair is None:
                return evidence
            published = publish_repair(dict(evidence))
            if (
                not isinstance(published, dict)
                or published.get("status") != "validated"
                or published.get("reason_code")
                != write_intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON
                or str(published.get("intent_id", "")) != intent_id
                or int(published.get("fencing_token") or 0)
                != int(fencing_token)
            ):
                deny("EXPIRED_VALIDATED_RECOVERY_REPAIR_PUBLISH_INVALID")
            return {
                "evidence": evidence,
                "repair_intent": published,
            }
    except TimeoutError as exc:
        raise GeneratedIndexCapabilityError(
            "EXPIRED_VALIDATED_RECOVERY_INDEX_LOCKED"
        ) from exc


def resolve_generated_index_transaction(
    *,
    transaction_binding: dict[str, str],
    index_step: dict[str, Any],
    snapshot: GeneratedIndexSnapshot | None,
    commit_step: dict[str, Any],
    git_head_before: str,
) -> dict[str, Any]:
    """Commit or conditionally roll back the durable generated-INDEX transaction."""

    try:
        receipt = read_generated_index_transaction(STATE_DB, transaction_binding)
    except GeneratedIndexCapabilityError as exc:
        return {"ok": False, "skipped": False, "detail": str(exc)}
    status = str(receipt.get("status", ""))
    digest = str(receipt.get("generated_sha256", "")).strip().lower()
    if status != "generated_bound" or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        try:
            if status in {"registered", "issued", "claimed", "generated_bound"}:
                mark_generated_index_transaction_outcome(
                    STATE_DB,
                    transaction_binding,
                    outcome=(
                        "failed" if status == "generated_bound" else "rolled_back"
                    ),
                    generated_sha256=digest if re.fullmatch(r"[0-9a-f]{64}", digest) else "",
                    failure_reason=(
                        "GENERATED_INDEX_DURABLE_READBACK_INVALID"
                        if status == "generated_bound"
                        else ""
                    ),
                )
        except GeneratedIndexCapabilityError:
            pass
        return {
            "ok": False,
            "skipped": False,
            "detail": "GENERATED_INDEX_DURABLE_READBACK_INVALID",
            "transaction_status": status,
        }

    target = (VAULT_ROOT / "INDEX.md").resolve()
    try:
        if target.is_symlink() or not target.is_file():
            raise OSError("GENERATED_INDEX_TARGET_UNSAFE")
        current_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
    except OSError:
        current_sha256 = ""
    base_sha256 = transaction_binding["index_base_sha256"]
    changed = digest != base_sha256
    published = current_sha256 == digest
    commit = str(commit_step.get("commit", "")).strip().lower()
    transaction_failure = not bool(index_step.get("ok")) or not published
    failure_detail = ""

    if index_step.get("ok") and published:
        durable_commit = commit or (git_head_before if not changed else "")
        if durable_commit:
            try:
                verify_generated_index_commit_evidence(
                    REPO_ROOT,
                    VAULT_ROOT,
                    transaction_binding,
                    generated_sha256=digest,
                    closeout_git_commit=durable_commit,
                )
                committed_blob_matches = True
            except GeneratedIndexCapabilityError:
                committed_blob_matches = False
            if committed_blob_matches:
                if not bool(commit_step.get("ok")):
                    # ``update-ref`` can succeed before the bounded real-index
                    # synchronization fails.  The commit is durable, but the
                    # generated-index transaction must remain recoverable until
                    # the exact stage-zero repair succeeds.  Consuming it here
                    # would hide the only crash-recovery record.
                    return {
                        "ok": False,
                        "skipped": False,
                        "detail": "GENERATED_INDEX_COMMIT_RECOVERY_REQUIRED",
                        "generated_sha256": digest,
                        "closeout_git_commit": durable_commit,
                        "transaction_status": "generated_bound",
                    }
                try:
                    committed = commit_generated_index_transaction(
                        STATE_DB,
                        transaction_binding,
                        generated_sha256=digest,
                        closeout_git_commit=durable_commit,
                    )
                except GeneratedIndexCapabilityError:
                    return {
                        "ok": False,
                        "skipped": False,
                        "detail": "GENERATED_INDEX_COMMIT_BIND_FAILED",
                    }
                return {
                    "ok": True,
                    "skipped": False,
                    "detail": (
                        "committed_generated_index"
                        if changed
                        else "verified_unchanged_generated_index"
                    ),
                    "generated_sha256": digest,
                    "closeout_git_commit": str(committed.get("closeout_git_commit", "")),
                }
            transaction_failure = True
            failure_detail = "GENERATED_INDEX_COMMIT_BLOB_MISMATCH"

    # No verified commit owns the generated bytes.  Restore only if the target
    # is still either our publication or the exact pre-closeout snapshot.
    rollback_ok = False
    rollback_detail = "GENERATED_INDEX_ROLLBACK_CONFLICT"
    if snapshot is not None and current_sha256 in {digest, base_sha256}:
        restored = restore_generated_index_snapshot(
            snapshot,
            expected_current_sha256=digest,
            transaction_id=transaction_binding["transaction_id"],
        )
        rollback_ok = bool(restored.get("ok"))
        rollback_detail = str(restored.get("detail", rollback_detail))
        if rollback_ok:
            rescan = rescan_after_generated_index_restore()
            if not rescan.get("ok"):
                rollback_ok = False
                rollback_detail = "GENERATED_INDEX_ROLLBACK_REINDEX_FAILED"
    try:
        mark_generated_index_transaction_outcome(
            STATE_DB,
            transaction_binding,
            outcome="rolled_back" if rollback_ok else "failed",
            generated_sha256=digest,
            failure_reason=(
                ""
                if rollback_ok
                else (
                    failure_detail
                    or rollback_detail
                    or "GENERATED_INDEX_TRANSACTION_FINALIZE_FAILED"
                )
            ),
        )
    except GeneratedIndexCapabilityError:
        return {
            "ok": False,
            "skipped": False,
            "detail": "GENERATED_INDEX_TRANSACTION_FINALIZE_FAILED",
        }
    return {
        "ok": bool(rollback_ok and not transaction_failure),
        "skipped": False,
        "restored": rollback_ok,
        "rolled_back": rollback_ok,
        "detail": (
            failure_detail
            or (
                rollback_detail
                if index_step.get("ok") or not rollback_ok
                else "ROLLED_BACK_AFTER_INDEX_FAILURE"
            )
        ),
    }


def temporal_graph_health(args: argparse.Namespace, index_step: dict[str, Any]) -> dict[str, Any]:
    if args.dry_run:
        return {"ok": True, "skipped": True, "detail": "dry_run"}
    if not index_step.get("ok"):
        return {"ok": False, "skipped": True, "detail": "index_failed"}
    try:
        with secure_sqlite_connect(
            STATE_DB,
            create=False,
            read_only=True,
            row_factory=sqlite3.Row,
            pragmas=("PRAGMA busy_timeout=10000",),
        ) as conn:
            tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"memory_supersessions", "memory_fact_states"}.issubset(tables):
                return {"ok": False, "skipped": False, "detail": "TEMPORAL_GRAPH_SCHEMA_MISSING"}
            invalid_relations = int(
                conn.execute(
                    "SELECT COUNT(*) FROM memory_supersessions WHERE relation_status<>'effective'"
                ).fetchone()[0]
            )
            unresolved = int(
                conn.execute(
                    """
                    SELECT COUNT(*) FROM memory_fact_states
                    WHERE fact_status IN ('conflict','invalid_metadata','invalid_relation','no_current')
                    """
                ).fetchone()[0]
            )
    except (OSError, sqlite3.Error):
        return {"ok": False, "skipped": False, "detail": "TEMPORAL_GRAPH_UNAVAILABLE"}
    ok = invalid_relations == 0 and unresolved == 0
    return {
        "ok": ok,
        "skipped": False,
        "detail": "ok" if ok else "TEMPORAL_GRAPH_UNRESOLVED",
        "invalid_relations": invalid_relations,
        "unresolved_fact_states": unresolved,
    }


def run_zvec(files: list[Path], args: argparse.Namespace) -> dict[str, Any]:
    if not SEMANTIC_ENABLED:
        return {"ok": True, "skipped": True, "detail": "semantic_retrieval_disabled"}
    if args.skip_zvec:
        return {"ok": True, "skipped": True, "detail": "skip_zvec"}
    if args.dry_run:
        return {"ok": True, "skipped": True, "detail": "dry_run"}
    command = [ZVEC_PYTHON, str(ZVEC_SCRIPT), "--prune", "--json"]
    for path in files:
        command.extend(["--changed-file", str(path)])
    if len(command) == 2:
        return {"ok": True, "skipped": True, "detail": "no_changed_files"}
    return run_command(command, timeout=args.zvec_timeout, env=command_env_offline())


def run_agent_evolution(files: list[Path], args: argparse.Namespace) -> dict[str, Any]:
    touches_agent = False
    for path in files:
        try:
            relative = path.relative_to(VAULT_ROOT)
        except ValueError:
            continue
        if relative.parts and relative.parts[0] == "agent":
            touches_agent = True
            break
    if not touches_agent:
        return {"ok": True, "skipped": True, "detail": "no_agent_memory_changed"}
    if args.dry_run:
        return {"ok": True, "skipped": True, "detail": "dry_run"}
    return run_command([PYTHON, str(AGENT_EVOLUTION_SCRIPT), "--init", "--scan", "--report"], timeout=120)


def run_audit_autorun(args: argparse.Namespace) -> dict[str, Any]:
    # Content audit has one canonical scheduler: the Sunday 10:30 LaunchAgent.
    # Closeout must stay deterministic and must not shift the weekly schedule
    # merely because a user happened to finish a task on another day.
    return {
        "ok": True,
        "skipped": True,
        "detail": "weekly_launchagent_owned",
    }


def _hash_object_bytes(data: bytes) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "hash-object", "-w", "--stdin"],
            input=data,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, ""
    object_id = completed.stdout.decode("ascii", errors="ignore").strip().lower()
    return completed.returncode == 0 and bool(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id)), object_id


def bind_checked_file_hashes(files: list[Path]) -> tuple[dict[Path, str], dict[str, str]]:
    """Bind each closeout file to raw and canonical hashes from one read."""

    bound: dict[Path, str] = {}
    canonical_bound: dict[str, str] = {}
    for raw_path in files:
        candidate = raw_path.expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        assert_governed_markdown_worktree_mode(candidate)
        if candidate.is_symlink():
            raise OSError(f"symlink target rejected: {candidate}")
        path = candidate.resolve()
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError(f"not a regular file: {path}")
            if path.suffix.casefold() == ".md" and bool(metadata.st_mode & 0o111):
                raise write_intent.IntentError(
                    "GOVERNED_MARKDOWN_MODE_INVALID",
                    "governed Markdown became executable while binding content",
                )
            digest = hashlib.sha256()
            payload = bytearray()
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
                payload.extend(block)
        finally:
            os.close(descriptor)
        bound[path] = digest.hexdigest()
        canonical_bound[os.path.normcase(str(path))] = write_intent.content_hashes(
            bytes(payload)
        ).canonical_sha256
    return bound, canonical_bound


def _snapshot_commit_files(
    files: list[Path],
    expected_raw_sha256: dict[Path, str],
) -> tuple[list[CommitSnapshot], dict[str, Any] | None]:
    expected = {path.expanduser().resolve(): digest for path, digest in expected_raw_sha256.items()}
    snapshots: list[CommitSnapshot] = []
    seen: set[str] = set()
    for raw_path in files:
        candidate = raw_path.expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        try:
            assert_governed_markdown_worktree_mode(candidate, allow_missing=True)
        except write_intent.IntentError as exc:
            return [], {
                "ok": False,
                "stage": "snapshot",
                "detail": exc.reason_code,
            }
        if candidate.is_symlink():
            return [], {
                "ok": False,
                "stage": "snapshot",
                "detail": "GOVERNED_MARKDOWN_MODE_INVALID",
            }
        path = candidate.resolve()
        if not path.exists():
            continue
        try:
            repo_path = path.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            continue
        if repo_path in seen:
            continue
        seen.add(repo_path)
        try:
            data = path.read_bytes()
            metadata = path.stat()
            executable = bool(metadata.st_mode & 0o111)
        except OSError:
            return [], {"ok": False, "stage": "snapshot", "detail": "file_read_failed", "file": repo_path}
        raw_sha256 = hashlib.sha256(data).hexdigest()
        expected_digest = str(expected.get(path, "")).strip().lower()
        if expected_digest and raw_sha256 != expected_digest:
            return [], {
                "ok": False,
                "stage": "validated_snapshot_verify",
                "detail": "CONTENT_CHANGED_AFTER_CHECK",
                "file": repo_path,
            }
        object_ok, blob_oid = _hash_object_bytes(data)
        if not object_ok:
            return [], {"ok": False, "stage": "hash_object", "detail": "git_blob_write_failed", "file": repo_path}
        governed_markdown = path.suffix.casefold() == ".md"
        if governed_markdown and executable:
            return [], {
                "ok": False,
                "stage": "snapshot",
                "detail": "GOVERNED_MARKDOWN_MODE_INVALID",
                "file": repo_path,
            }
        snapshots.append(
            CommitSnapshot(
                path=path,
                repo_path=repo_path,
                raw_sha256=raw_sha256,
                blob_oid=blob_oid,
                mode="100755" if executable and not governed_markdown else "100644",
            )
        )
    return snapshots, None


def _sync_real_index(
    snapshots: list[CommitSnapshot],
    *,
    prepared: dict[str, Any] | None = None,
    expected_head: str = "",
    target_head: str = "",
    deadline: float | None = None,
) -> dict[str, Any]:
    """Atomically publish one complete owned-path projection to the real index."""

    sync_deadline = (
        deadline
        if deadline is not None
        else time.monotonic() + max(GIT_INDEX_SYNC_DEADLINE_SECONDS, 0.01)
    )
    try:
        transaction = prepared or _prepare_real_index_sync(
            snapshots,
            expected_head=expected_head,
            target_head=target_head,
            deadline=sync_deadline,
        )
        return _apply_prepared_real_index_sync(
            transaction,
            deadline=sync_deadline,
        )
    except OSError as exc:
        reason = str(exc).strip().upper()
        return {
            "ok": False,
            "stage": "index_sync",
            "detail": (
                reason
                if re.fullmatch(r"[A-Z0-9_]{1,128}", reason)
                else "GIT_INDEX_SYNC_FAILED"
            ),
        }


def _commit_snapshot_mode_error(
    snapshots: list[CommitSnapshot],
    *,
    stage: str,
) -> dict[str, Any] | None:
    for snapshot in snapshots:
        try:
            assert_governed_markdown_worktree_mode(snapshot.path)
        except write_intent.IntentError as exc:
            return {
                "ok": False,
                "stage": stage,
                "detail": exc.reason_code,
                "file": snapshot.repo_path,
            }
    return None


def _git_index_stage_zero(
    repo_path: str,
    *,
    index_file: Path | None = None,
) -> tuple[str, str]:
    environment = os.environ.copy()
    if index_file is not None:
        environment["GIT_INDEX_FILE"] = str(index_file)
    result = run_command(
        ["git", "-C", str(REPO_ROOT), "ls-files", "--stage", "-z", "--", repo_path],
        timeout=30,
        env=environment,
    )
    if not result.get("ok"):
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE")
    records = [item for item in str(result.get("stdout", "")).split("\0") if item]
    if len(records) != 1:
        raise OSError("GENERATED_INDEX_GIT_INDEX_CONFLICT")
    try:
        header, returned_path = records[0].split("\t", 1)
        mode, oid, stage = header.split()
    except ValueError as exc:
        raise OSError("GENERATED_INDEX_GIT_INDEX_CONFLICT") from exc
    if (
        returned_path != repo_path
        or stage != "0"
        or re.fullmatch(r"[0-7]{6}", mode) is None
        or re.fullmatch(r"[0-9a-f]{40,64}", oid) is None
    ):
        raise OSError("GENERATED_INDEX_GIT_INDEX_CONFLICT")
    return mode, oid


def _git_tree_entry(commit: str, repo_path: str) -> tuple[str, str]:
    tree = run_command(
        ["git", "-C", str(REPO_ROOT), "ls-tree", "-z", commit, "--", repo_path],
        timeout=30,
    )
    records = [item for item in str(tree.get("stdout", "")).split("\0") if item]
    if not tree.get("ok") or len(records) != 1:
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE")
    try:
        header, returned_path = records[0].split("\t", 1)
        mode, object_type, oid = header.split()
    except ValueError as exc:
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE") from exc
    if (
        returned_path != repo_path
        or object_type != "blob"
        or re.fullmatch(r"[0-7]{6}", mode) is None
        or re.fullmatch(r"[0-9a-f]{40,64}", oid) is None
    ):
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE")
    return mode, oid


def _git_blob_sha256(oid: str, *, deadline: float | None = None) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "cat-file", "blob", oid],
            check=True,
            capture_output=True,
            timeout=(
                _deadline_timeout(deadline, 30)
                if deadline is not None
                else 30
            ),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE") from exc
    return hashlib.sha256(completed.stdout).hexdigest()


def _deadline_timeout(deadline: float, maximum: float = 60) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OSError("GIT_INDEX_SYNC_DEADLINE_EXCEEDED")
    return max(0.05, min(float(maximum), remaining))


def _bounded_current_git_head(deadline: float) -> str:
    result = run_command(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
        timeout=_deadline_timeout(deadline, 30),
    )
    head = str(result.get("stdout", "")).strip().lower()
    if not result.get("ok") or re.fullmatch(r"[0-9a-f]{40,64}", head) is None:
        raise OSError("GIT_INDEX_HEAD_UNAVAILABLE")
    return head


def _same_regular_inode(first: Path, second: Path) -> bool:
    try:
        first_stat = first.lstat()
        second_stat = second.lstat()
    except OSError:
        return False
    return (
        not first.is_symlink()
        and not second.is_symlink()
        and stat.S_ISREG(first_stat.st_mode)
        and stat.S_ISREG(second_stat.st_mode)
        and (first_stat.st_dev, first_stat.st_ino)
        == (second_stat.st_dev, second_stat.st_ino)
    )


def _git_index_layout(
    *,
    create_recovery: bool,
    deadline: float | None = None,
) -> dict[str, Path]:
    git_dir_result = run_command(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--absolute-git-dir"],
        timeout=(_deadline_timeout(deadline, 30) if deadline is not None else 30),
    )
    index_result = run_command(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--git-path", "index"],
        timeout=(_deadline_timeout(deadline, 30) if deadline is not None else 30),
    )
    if not git_dir_result.get("ok") or not index_result.get("ok"):
        raise OSError("GIT_INDEX_LAYOUT_UNAVAILABLE")
    raw_git_dir = str(git_dir_result.get("stdout", "")).strip()
    raw_index_text = str(index_result.get("stdout", "")).strip()
    if not raw_git_dir or not raw_index_text:
        raise OSError("GIT_INDEX_LAYOUT_UNAVAILABLE")
    git_dir = Path(os.path.abspath(raw_git_dir))
    raw_index = Path(raw_index_text)
    if not raw_index.is_absolute():
        raw_index = REPO_ROOT / raw_index
    raw_index = Path(os.path.abspath(raw_index))
    lock_path = _git_index_lock_path(deadline=deadline)
    expected_lock = raw_index.with_name(f"{raw_index.name}.lock")
    try:
        git_dir_metadata = git_dir.lstat()
        index_metadata = raw_index.lstat()
    except OSError as exc:
        raise OSError("GIT_INDEX_LAYOUT_UNAVAILABLE") from exc
    current_uid = os.getuid() if hasattr(os, "getuid") else git_dir_metadata.st_uid
    if (
        git_dir.is_symlink()
        or not stat.S_ISDIR(git_dir_metadata.st_mode)
        or (POSIX_PERMISSION_MODEL and git_dir_metadata.st_uid != current_uid)
        or raw_index.parent != git_dir
        or raw_index.is_symlink()
        or not stat.S_ISREG(index_metadata.st_mode)
        or (POSIX_PERMISSION_MODEL and index_metadata.st_uid != current_uid)
        or lock_path != expected_lock
    ):
        raise OSError("GIT_INDEX_LAYOUT_UNAVAILABLE")
    recovery_root = git_dir / GIT_INDEX_SYNC_RECOVERY_DIRECTORY
    if create_recovery and not recovery_root.exists() and not recovery_root.is_symlink():
        recovery_root.mkdir(mode=0o700)
        # The journal directory itself is part of the pre-HEAD durability
        # boundary.  Fsyncing only its children cannot make a newly-created
        # directory entry durable after a power loss.
        _fsync_directory(git_dir)
    if recovery_root.exists() or recovery_root.is_symlink():
        try:
            recovery_metadata = recovery_root.lstat()
        except OSError as exc:
            raise OSError("GIT_INDEX_RECOVERY_DIRECTORY_UNSAFE") from exc
        if (
            recovery_root.is_symlink()
            or not stat.S_ISDIR(recovery_metadata.st_mode)
            or (POSIX_PERMISSION_MODEL and recovery_metadata.st_uid != current_uid)
        ):
            raise OSError("GIT_INDEX_RECOVERY_DIRECTORY_UNSAFE")
        if POSIX_PERMISSION_MODEL and stat.S_IMODE(recovery_metadata.st_mode) != 0o700:
            if not create_recovery:
                raise OSError("GIT_INDEX_RECOVERY_DIRECTORY_UNSAFE")
            recovery_root.chmod(0o700)
            if stat.S_IMODE(recovery_root.lstat().st_mode) != 0o700:
                raise OSError("GIT_INDEX_RECOVERY_DIRECTORY_UNSAFE")
    elif create_recovery:
        raise OSError("GIT_INDEX_RECOVERY_DIRECTORY_UNSAFE")
    return {
        "git_dir": git_dir,
        "index": raw_index,
        "lock": expected_lock,
        "recovery_root": recovery_root,
    }


def _read_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    require_private: bool = False,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        current_uid = os.getuid() if hasattr(os, "getuid") else metadata.st_uid
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (POSIX_PERMISSION_MODEL and metadata.st_uid != current_uid)
            or metadata.st_size < 0
            or metadata.st_size > maximum_bytes
            or (
                POSIX_PERMISSION_MODEL
                and require_private
                and stat.S_IMODE(metadata.st_mode) & 0o077
            )
        ):
            raise OSError("GIT_INDEX_RECOVERY_EVIDENCE_UNSAFE")
        chunks = bytearray()
        while True:
            block = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1))
            if not block:
                break
            chunks.extend(block)
            if len(chunks) > maximum_bytes:
                raise OSError("GIT_INDEX_RECOVERY_EVIDENCE_UNSAFE")
    finally:
        os.close(descriptor)
    try:
        readback = path.lstat()
    except OSError as exc:
        raise OSError("GIT_INDEX_RECOVERY_EVIDENCE_UNSAFE") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(readback.st_mode)
        or (metadata.st_dev, metadata.st_ino) != (readback.st_dev, readback.st_ino)
        or metadata.st_size != readback.st_size
    ):
        raise OSError("GIT_INDEX_RECOVERY_EVIDENCE_UNSAFE")
    return bytes(chunks), readback


def _write_private_file_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        if POSIX_PERMISSION_MODEL:
            os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("GIT_INDEX_RECOVERY_EVIDENCE_WRITE_FAILED")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or (
            POSIX_PERMISSION_MODEL
            and stat.S_IMODE(metadata.st_mode) != 0o600
        )
    ):
        raise OSError("GIT_INDEX_RECOVERY_EVIDENCE_UNSAFE")


def _write_private_json_exclusive(path: Path, payload: dict[str, Any]) -> None:
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    _write_private_file_exclusive(path, encoded)
    _fsync_directory(path.parent)


def _publish_private_json_exclusive(path: Path, payload: dict[str, Any]) -> bool:
    """Atomically publish complete JSON without replacing an existing outcome."""

    if path.exists() or path.is_symlink():
        return False
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.outcome-candidate"
    _write_private_file_exclusive(temporary, encoded)
    _fsync_directory(path.parent)
    published = False
    try:
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            return False
        if not _same_regular_inode(temporary, path):
            raise OSError("GIT_INDEX_RECOVERY_OUTCOME_CONFLICT")
        _fsync_directory(path.parent)
        readback, _metadata = _read_regular_file(
            path,
            maximum_bytes=256 * 1024,
            require_private=True,
        )
        if readback != encoded:
            raise OSError("GIT_INDEX_RECOVERY_OUTCOME_CONFLICT")
        published = True
        return True
    finally:
        if published:
            # Keep the complete temporary inode as small private evidence
            # without deleting a file or retaining a misleading temp name.
            evidence = path.parent / (
                f"{path.name}.{uuid.uuid4().hex}.published-outcome"
            )
            try:
                os.replace(temporary, evidence)
                _fsync_directory(path.parent)
            except OSError:
                # The terminal path is already durable and read back.  A
                # leftover private candidate is harmless and must not turn a
                # successful publish into an owned-lock leak.
                pass


def _read_private_json(path: Path) -> dict[str, Any]:
    raw, _metadata = _read_regular_file(
        path,
        maximum_bytes=256 * 1024,
        require_private=True,
    )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID") from exc
    if not isinstance(payload, dict):
        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")
    return payload


def _validated_terminal_index_outcome(
    outcome_path: Path,
    transaction_id: str,
) -> dict[str, Any]:
    payload = _read_private_json(outcome_path)
    if (
        int(payload.get("schema_version") or 0) != GIT_INDEX_SYNC_MANIFEST_VERSION
        or str(payload.get("transaction_id", "")) != transaction_id
        or str(payload.get("outcome", ""))
        not in {"completed", "aborted_before_head_publish", "aborted_head_cas"}
        or re.fullmatch(
            r"[0-9a-f]{40,64}",
            str(payload.get("target_head", "")).strip().lower(),
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}",
            str(payload.get("candidate_sha256", "")).strip().lower(),
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}",
            str(payload.get("manifest_sha256", "")).strip().lower(),
        )
        is None
    ):
        raise OSError("GIT_INDEX_RECOVERY_OUTCOME_CONFLICT")
    return payload


def _validate_terminal_outcome_manifest(
    *,
    outcome: dict[str, Any],
    manifest_path: Path,
) -> None:
    raw, _metadata = _read_regular_file(
        manifest_path,
        maximum_bytes=256 * 1024,
        require_private=True,
    )
    if hashlib.sha256(raw).hexdigest() != str(outcome["manifest_sha256"]):
        raise OSError("GIT_INDEX_RECOVERY_OUTCOME_CONFLICT")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OSError("GIT_INDEX_RECOVERY_OUTCOME_CONFLICT") from exc
    transaction_id = str(outcome["transaction_id"])
    if (
        not isinstance(manifest, dict)
        or int(manifest.get("schema_version") or 0)
        != GIT_INDEX_SYNC_MANIFEST_VERSION
        or str(manifest.get("transaction_id", "")) != transaction_id
        or str(manifest.get("target_head", "")) != str(outcome["target_head"])
        or str(manifest.get("candidate_sha256", ""))
        != str(outcome["candidate_sha256"])
        or str(manifest.get("candidate_file", ""))
        != f"{transaction_id}.index"
    ):
        raise OSError("GIT_INDEX_RECOVERY_OUTCOME_CONFLICT")


def _compact_terminal_index_candidate(
    *,
    recovery_root: Path,
    outcome: dict[str, Any],
) -> bool:
    """Replace our terminal full-index hardlink with a small immutable tombstone."""

    transaction_id = str(outcome.get("transaction_id", ""))
    paths = _index_sync_paths(transaction_id, recovery_root)
    tombstone = {
        "schema_version": GIT_INDEX_SYNC_MANIFEST_VERSION,
        "transaction_id": transaction_id,
        "outcome": str(outcome.get("outcome", "")),
        "terminal_candidate_sha256": str(outcome.get("candidate_sha256", "")),
        "manifest_sha256": str(outcome.get("manifest_sha256", "")),
        "target_head": str(outcome.get("target_head", "")),
    }
    encoded = (
        json.dumps(tombstone, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    try:
        current, metadata = _read_regular_file(
            paths["candidate"],
            maximum_bytes=128 * 1024 * 1024,
            require_private=True,
        )
    except OSError:
        return False
    try:
        if current == encoded:
            return (
                not POSIX_PERMISSION_MODEL
                or stat.S_IMODE(metadata.st_mode) == 0o600
            )
        if hashlib.sha256(current).hexdigest() != tombstone["terminal_candidate_sha256"]:
            return False
        temporary = recovery_root / (
            f"{transaction_id}.{uuid.uuid4().hex}.terminal-tombstone"
        )
        _write_private_file_exclusive(temporary, encoded)
        _fsync_directory(recovery_root)
        os.replace(temporary, paths["candidate"])
        _fsync_directory(recovery_root)
        readback, readback_metadata = _read_regular_file(
            paths["candidate"],
            maximum_bytes=4096,
            require_private=True,
        )
        return (
            readback == encoded
            and (
                not POSIX_PERMISSION_MODEL
                or stat.S_IMODE(readback_metadata.st_mode) == 0o600
            )
        )
    except OSError:
        return False


def _git_index_entries(
    index_file: Path,
    *,
    deadline: float,
) -> dict[str, tuple[tuple[str, str, str], ...]]:
    environment = os.environ.copy()
    environment["GIT_INDEX_FILE"] = str(index_file)
    result = run_command(
        ["git", "-C", str(REPO_ROOT), "ls-files", "--stage", "-z"],
        timeout=_deadline_timeout(deadline, 30),
        env=environment,
    )
    if not result.get("ok"):
        raise OSError("GIT_INDEX_PROJECTION_UNAVAILABLE")
    entries: dict[str, list[tuple[str, str, str]]] = {}
    for record in (item for item in str(result.get("stdout", "")).split("\0") if item):
        try:
            header, repo_path = record.split("\t", 1)
            mode, oid, stage = header.split()
        except ValueError as exc:
            raise OSError("GIT_INDEX_PROJECTION_UNAVAILABLE") from exc
        if (
            not repo_path
            or "\0" in repo_path
            or re.fullmatch(r"[0-7]{6}", mode) is None
            or re.fullmatch(r"[0-9a-f]{40,64}", oid) is None
            or stage not in {"0", "1", "2", "3"}
        ):
            raise OSError("GIT_INDEX_PROJECTION_UNAVAILABLE")
        entries.setdefault(repo_path, []).append((mode, oid.lower(), stage))
    return {
        repo_path: tuple(sorted(values, key=lambda item: item[2]))
        for repo_path, values in entries.items()
    }


def _index_projection_sha256(
    entries: dict[str, tuple[tuple[str, str, str], ...]],
    *,
    excluded_paths: set[str],
) -> str:
    projection = [
        (repo_path, [list(item) for item in values])
        for repo_path, values in sorted(entries.items())
        if repo_path not in excluded_paths
    ]
    return _canonical_projection_sha256(projection)


def _index_flag_projection_sha256(
    index_file: Path,
    *,
    excluded_paths: set[str],
    deadline: float,
) -> str:
    """Bind per-entry index flags such as skip-worktree/assume-unchanged."""

    environment = os.environ.copy()
    environment["GIT_INDEX_FILE"] = str(index_file)
    result = run_command(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-v", "-z"],
        timeout=_deadline_timeout(deadline, 30),
        env=environment,
    )
    if not result.get("ok"):
        raise OSError("GIT_INDEX_PROJECTION_UNAVAILABLE")
    projection: list[tuple[str, str]] = []
    for record in (item for item in str(result.get("stdout", "")).split("\0") if item):
        if len(record) < 3 or record[1] != " ":
            raise OSError("GIT_INDEX_PROJECTION_UNAVAILABLE")
        tag, repo_path = record[0], record[2:]
        _validate_owned_repo_path(repo_path)
        if repo_path not in excluded_paths:
            projection.append((repo_path, tag))
    return _canonical_projection_sha256(sorted(projection))


def _manifest_entry(value: tuple[str, str] | None) -> dict[str, str] | None:
    return {"mode": value[0], "oid": value[1]} if value is not None else None


def _manifest_entry_tuple(value: Any) -> tuple[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")
    mode = str(value.get("mode", ""))
    oid = str(value.get("oid", "")).strip().lower()
    if re.fullmatch(r"[0-7]{6}", mode) is None or re.fullmatch(r"[0-9a-f]{40,64}", oid) is None:
        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")
    return mode, oid


def _index_entry_projection(value: tuple[str, str] | None) -> tuple[tuple[str, str, str], ...]:
    return () if value is None else ((value[0], value[1], "0"),)


def _git_tree_entry_optional(
    commit: str,
    repo_path: str,
    *,
    deadline: float | None = None,
) -> tuple[str, str] | None:
    tree = run_command(
        ["git", "-C", str(REPO_ROOT), "ls-tree", "-z", commit, "--", repo_path],
        timeout=(_deadline_timeout(deadline, 30) if deadline is not None else 30),
    )
    records = [item for item in str(tree.get("stdout", "")).split("\0") if item]
    if not tree.get("ok") or len(records) > 1:
        raise OSError("GIT_INDEX_COMMIT_EVIDENCE_INVALID")
    if not records:
        return None
    try:
        header, returned_path = records[0].split("\t", 1)
        mode, object_type, oid = header.split()
    except ValueError as exc:
        raise OSError("GIT_INDEX_COMMIT_EVIDENCE_INVALID") from exc
    if (
        returned_path != repo_path
        or object_type != "blob"
        or re.fullmatch(r"[0-7]{6}", mode) is None
        or re.fullmatch(r"[0-9a-f]{40,64}", oid) is None
    ):
        raise OSError("GIT_INDEX_COMMIT_EVIDENCE_INVALID")
    return mode, oid.lower()


def _git_commit_changed_paths(base_head: str, target_head: str, *, deadline: float) -> set[str]:
    if base_head == target_head:
        return set()
    parent = run_command(
        ["git", "-C", str(REPO_ROOT), "rev-parse", f"{target_head}^"],
        timeout=_deadline_timeout(deadline, 30),
    )
    if not parent.get("ok") or str(parent.get("stdout", "")).strip().lower() != base_head:
        raise OSError("GIT_INDEX_COMMIT_EVIDENCE_INVALID")
    changed = run_command(
        [
            "git",
            "-C",
            str(REPO_ROOT),
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            "-z",
            base_head,
            target_head,
        ],
        timeout=_deadline_timeout(deadline, 30),
    )
    if not changed.get("ok"):
        raise OSError("GIT_INDEX_COMMIT_EVIDENCE_INVALID")
    return {
        item
        for item in str(changed.get("stdout", "")).split("\0")
        if item
    }


def _validate_owned_repo_path(repo_path: str) -> None:
    candidate = Path(repo_path)
    if (
        not repo_path
        or "\0" in repo_path
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or candidate.as_posix() != repo_path
    ):
        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")


def _validate_manifest_commit_projection(
    manifest: dict[str, Any],
    *,
    deadline: float,
) -> list[dict[str, Any]]:
    base_head = str(manifest.get("base_head", "")).strip().lower()
    target_head = str(manifest.get("target_head", "")).strip().lower()
    if (
        re.fullmatch(r"[0-9a-f]{40,64}", base_head) is None
        or re.fullmatch(r"[0-9a-f]{40,64}", target_head) is None
    ):
        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")
    raw_owned = manifest.get("owned_paths")
    if not isinstance(raw_owned, list) or not raw_owned or len(raw_owned) > 512:
        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")
    owned: list[dict[str, Any]] = []
    seen: set[str] = set()
    changed_expected: set[str] = set()
    for raw in raw_owned:
        if not isinstance(raw, dict):
            raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")
        repo_path = str(raw.get("path", ""))
        _validate_owned_repo_path(repo_path)
        if repo_path in seen:
            raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")
        seen.add(repo_path)
        base_entry = _manifest_entry_tuple(raw.get("base"))
        target_entry = _manifest_entry_tuple(raw.get("target"))
        raw_sha256 = str(raw.get("raw_sha256", "")).strip().lower()
        if target_entry is None or re.fullmatch(r"[0-9a-f]{64}", raw_sha256) is None:
            raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")
        if _git_tree_entry_optional(base_head, repo_path, deadline=deadline) != base_entry:
            raise OSError("GIT_INDEX_COMMIT_EVIDENCE_INVALID")
        if _git_tree_entry_optional(target_head, repo_path, deadline=deadline) != target_entry:
            raise OSError("GIT_INDEX_COMMIT_EVIDENCE_INVALID")
        if _git_blob_sha256(target_entry[1], deadline=deadline) != raw_sha256:
            raise OSError("GIT_INDEX_COMMIT_EVIDENCE_INVALID")
        if base_entry != target_entry:
            changed_expected.add(repo_path)
        owned.append(
            {
                "path": repo_path,
                "base": base_entry,
                "target": target_entry,
                "raw_sha256": raw_sha256,
            }
        )
    if _git_commit_changed_paths(base_head, target_head, deadline=deadline) != changed_expected:
        raise OSError("GIT_INDEX_COMMIT_EVIDENCE_INVALID")
    return owned


def _index_sync_paths(transaction_id: str, recovery_root: Path) -> dict[str, Path]:
    if re.fullmatch(r"[0-9a-f]{32}", transaction_id) is None:
        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")
    return {
        "manifest": recovery_root / f"{transaction_id}.manifest.json",
        "candidate": recovery_root / f"{transaction_id}.index",
        "outcome": recovery_root / f"{transaction_id}.outcome.json",
    }


def _prepare_real_index_sync(
    snapshots: list[CommitSnapshot],
    *,
    expected_head: str,
    target_head: str,
    deadline: float,
) -> dict[str, Any]:
    base_head = str(expected_head).strip().lower()
    target = str(target_head or expected_head).strip().lower()
    if (
        not snapshots
        or re.fullmatch(r"[0-9a-f]{40,64}", base_head) is None
        or re.fullmatch(r"[0-9a-f]{40,64}", target) is None
    ):
        raise OSError("GIT_INDEX_SYNC_BINDING_INVALID")
    git_operation = generated_index_git_operation_fence(deadline=deadline)
    current_head = _bounded_current_git_head(deadline)
    if (
        not git_operation.get("ok")
        or current_head != base_head
    ):
        raise OSError(
            str(git_operation.get("reason_code") or "GIT_INDEX_HEAD_CHANGED")
        )
    layout = _git_index_layout(create_recovery=True, deadline=deadline)
    raw_index, raw_metadata = _read_regular_file(
        layout["index"],
        maximum_bytes=128 * 1024 * 1024,
    )
    initial_entries = _git_index_entries(layout["index"], deadline=deadline)
    owned_paths: list[dict[str, Any]] = []
    seen: set[str] = set()
    for snapshot in sorted(snapshots, key=lambda item: item.repo_path):
        _validate_owned_repo_path(snapshot.repo_path)
        if snapshot.repo_path in seen:
            raise OSError("GIT_INDEX_SYNC_BINDING_INVALID")
        seen.add(snapshot.repo_path)
        base_entry = _git_tree_entry_optional(
            base_head,
            snapshot.repo_path,
            deadline=deadline,
        )
        target_entry = _git_tree_entry_optional(
            target,
            snapshot.repo_path,
            deadline=deadline,
        )
        expected_target = (snapshot.mode, snapshot.blob_oid)
        if (
            target_entry != expected_target
            or _git_blob_sha256(snapshot.blob_oid, deadline=deadline)
            != snapshot.raw_sha256
        ):
            raise OSError("GIT_INDEX_COMMIT_EVIDENCE_INVALID")
        current_entry = initial_entries.get(snapshot.repo_path, ())
        if current_entry not in {
            _index_entry_projection(base_entry),
            _index_entry_projection(target_entry),
        }:
            raise OSError("GIT_INDEX_OWNED_PATH_DRIFT")
        owned_paths.append(
            {
                "path": snapshot.repo_path,
                "base": _manifest_entry(base_entry),
                "target": _manifest_entry(target_entry),
                "raw_sha256": snapshot.raw_sha256,
            }
        )
    changed_paths = {
        item["path"]
        for item in owned_paths
        if item["base"] != item["target"]
    }
    if _git_commit_changed_paths(base_head, target, deadline=deadline) != changed_paths:
        raise OSError("GIT_INDEX_COMMIT_EVIDENCE_INVALID")

    transaction_id = uuid.uuid4().hex
    paths = _index_sync_paths(transaction_id, layout["recovery_root"])
    _write_private_file_exclusive(paths["candidate"], raw_index)
    environment = os.environ.copy()
    environment["GIT_INDEX_FILE"] = str(paths["candidate"])
    index_info = "".join(
        f"{snapshot.mode} {snapshot.blob_oid}\t{snapshot.repo_path}\0"
        for snapshot in sorted(snapshots, key=lambda item: item.repo_path)
    )
    update = run_command(
        ["git", "-C", str(REPO_ROOT), "update-index", "-z", "--index-info"],
        timeout=_deadline_timeout(deadline, 60),
        env=environment,
        input_text=index_info,
    )
    if not update.get("ok"):
        raise OSError("GIT_INDEX_CANDIDATE_BUILD_FAILED")
    try:
        candidate_metadata_before = paths["candidate"].lstat()
        current_uid = (
            os.getuid()
            if hasattr(os, "getuid")
            else candidate_metadata_before.st_uid
        )
        if (
            paths["candidate"].is_symlink()
            or not stat.S_ISREG(candidate_metadata_before.st_mode)
            or (
                POSIX_PERMISSION_MODEL
                and candidate_metadata_before.st_uid != current_uid
            )
        ):
            raise OSError("GIT_INDEX_RECOVERY_EVIDENCE_UNSAFE")
        if POSIX_PERMISSION_MODEL:
            paths["candidate"].chmod(0o600)
        candidate_descriptor = os.open(
            paths["candidate"],
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(candidate_descriptor)
        finally:
            os.close(candidate_descriptor)
        _fsync_directory(paths["candidate"].parent)
    except OSError as exc:
        raise OSError("GIT_INDEX_RECOVERY_EVIDENCE_UNSAFE") from exc
    candidate_raw, candidate_metadata = _read_regular_file(
        paths["candidate"],
        maximum_bytes=128 * 1024 * 1024,
        require_private=True,
    )
    if (
        POSIX_PERMISSION_MODEL
        and stat.S_IMODE(candidate_metadata.st_mode) != 0o600
    ):
        raise OSError("GIT_INDEX_RECOVERY_EVIDENCE_UNSAFE")
    candidate_entries = _git_index_entries(paths["candidate"], deadline=deadline)
    for item in owned_paths:
        target_entry = _manifest_entry_tuple(item["target"])
        if candidate_entries.get(item["path"], ()) != _index_entry_projection(target_entry):
            raise OSError("GIT_INDEX_CANDIDATE_BUILD_FAILED")
    unrelated_sha256 = _index_projection_sha256(
        initial_entries,
        excluded_paths=seen,
    )
    if _index_projection_sha256(candidate_entries, excluded_paths=seen) != unrelated_sha256:
        raise OSError("GIT_INDEX_UNRELATED_PROJECTION_CHANGED")
    unrelated_flags_sha256 = _index_flag_projection_sha256(
        layout["index"],
        excluded_paths=seen,
        deadline=deadline,
    )
    if _index_flag_projection_sha256(
        paths["candidate"],
        excluded_paths=seen,
        deadline=deadline,
    ) != unrelated_flags_sha256:
        raise OSError("GIT_INDEX_UNRELATED_PROJECTION_CHANGED")
    manifest = {
        "schema_version": GIT_INDEX_SYNC_MANIFEST_VERSION,
        "transaction_id": transaction_id,
        "repo_root_sha256": hashlib.sha256(str(REPO_ROOT.resolve()).encode("utf-8")).hexdigest(),
        "base_head": base_head,
        "target_head": target,
        "head_change": target != base_head,
        "candidate_file": paths["candidate"].name,
        "candidate_sha256": hashlib.sha256(candidate_raw).hexdigest(),
        "initial_index_sha256": hashlib.sha256(raw_index).hexdigest(),
        "unrelated_index_sha256": unrelated_sha256,
        "unrelated_index_flags_sha256": unrelated_flags_sha256,
        "owned_paths": owned_paths,
        "created_at": utc_now(),
        "source_index_inode": [raw_metadata.st_dev, raw_metadata.st_ino],
    }
    if not _publish_private_json_exclusive(paths["manifest"], manifest):
        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_CONFLICT")
    readback = _read_private_json(paths["manifest"])
    if readback != manifest:
        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")
    return {
        "manifest": manifest,
        "manifest_path": paths["manifest"],
        "candidate_path": paths["candidate"],
        "outcome_path": paths["outcome"],
    }


def _load_index_sync_transaction(
    manifest_path: Path,
    *,
    layout: dict[str, Path],
    deadline: float,
) -> dict[str, Any]:
    manifest = _read_private_json(manifest_path)
    if int(manifest.get("schema_version") or 0) != GIT_INDEX_SYNC_MANIFEST_VERSION:
        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")
    transaction_id = str(manifest.get("transaction_id", "")).strip().lower()
    paths = _index_sync_paths(transaction_id, layout["recovery_root"])
    if manifest_path != paths["manifest"] or str(manifest.get("candidate_file", "")) != paths["candidate"].name:
        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")
    if str(manifest.get("repo_root_sha256", "")) != hashlib.sha256(
        str(REPO_ROOT.resolve()).encode("utf-8")
    ).hexdigest():
        raise OSError("GIT_INDEX_RECOVERY_MANIFEST_INVALID")
    candidate_raw, candidate_metadata = _read_regular_file(
        paths["candidate"],
        maximum_bytes=128 * 1024 * 1024,
        require_private=True,
    )
    if (
        (
            POSIX_PERMISSION_MODEL
            and stat.S_IMODE(candidate_metadata.st_mode) != 0o600
        )
        or hashlib.sha256(candidate_raw).hexdigest()
        != str(manifest.get("candidate_sha256", ""))
    ):
        raise OSError("GIT_INDEX_RECOVERY_EVIDENCE_UNSAFE")
    owned = _validate_manifest_commit_projection(manifest, deadline=deadline)
    candidate_entries = _git_index_entries(paths["candidate"], deadline=deadline)
    owned_set = {item["path"] for item in owned}
    for item in owned:
        if candidate_entries.get(item["path"], ()) != _index_entry_projection(item["target"]):
            raise OSError("GIT_INDEX_RECOVERY_EVIDENCE_INVALID")
    if _index_projection_sha256(candidate_entries, excluded_paths=owned_set) != str(
        manifest.get("unrelated_index_sha256", "")
    ):
        raise OSError("GIT_INDEX_RECOVERY_EVIDENCE_INVALID")
    if _index_flag_projection_sha256(
        paths["candidate"],
        excluded_paths=owned_set,
        deadline=deadline,
    ) != str(manifest.get("unrelated_index_flags_sha256", "")):
        raise OSError("GIT_INDEX_RECOVERY_EVIDENCE_INVALID")
    return {
        "manifest": manifest,
        "manifest_path": paths["manifest"],
        "candidate_path": paths["candidate"],
        "outcome_path": paths["outcome"],
        "owned": owned,
    }


def _record_index_sync_outcome(
    transaction: dict[str, Any],
    outcome: str,
    *,
    compact_candidate: bool = True,
) -> dict[str, Any]:
    outcome_path = Path(transaction["outcome_path"])
    manifest_path = Path(transaction["manifest_path"])
    manifest = transaction["manifest"]
    manifest_raw, _manifest_metadata = _read_regular_file(
        manifest_path,
        maximum_bytes=256 * 1024,
        require_private=True,
    )
    payload = {
        "schema_version": GIT_INDEX_SYNC_MANIFEST_VERSION,
        "transaction_id": manifest["transaction_id"],
        "outcome": outcome,
        "recorded_at": utc_now(),
        "target_head": manifest["target_head"],
        "candidate_sha256": manifest["candidate_sha256"],
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
    }
    if outcome_path.exists() or outcome_path.is_symlink():
        existing = _validated_terminal_index_outcome(
            outcome_path,
            str(payload["transaction_id"]),
        )
        if (
            existing.get("outcome") != outcome
            or existing.get("target_head") != payload["target_head"]
            or existing.get("candidate_sha256") != payload["candidate_sha256"]
            or existing.get("manifest_sha256") != payload["manifest_sha256"]
        ):
            raise OSError("GIT_INDEX_RECOVERY_OUTCOME_CONFLICT")
    else:
        _publish_private_json_exclusive(outcome_path, payload)
        existing = _validated_terminal_index_outcome(
            outcome_path,
            str(payload["transaction_id"]),
        )
        if (
            existing.get("outcome") != outcome
            or existing.get("target_head") != payload["target_head"]
            or existing.get("candidate_sha256") != payload["candidate_sha256"]
            or existing.get("manifest_sha256") != payload["manifest_sha256"]
        ):
            raise OSError("GIT_INDEX_RECOVERY_OUTCOME_CONFLICT")
    if compact_candidate:
        _compact_terminal_index_candidate(
            recovery_root=outcome_path.parent,
            outcome=existing,
        )
    return existing


def _current_index_matches_transaction(
    transaction: dict[str, Any],
    *,
    index_file: Path,
    deadline: float,
) -> tuple[bool, bool, str]:
    entries = _git_index_entries(index_file, deadline=deadline)
    owned = transaction["owned"]
    owned_set = {item["path"] for item in owned}
    all_target = True
    all_base = True
    for item in owned:
        current = entries.get(item["path"], ())
        base_projection = _index_entry_projection(item["base"])
        target_projection = _index_entry_projection(item["target"])
        if current not in {base_projection, target_projection}:
            raise OSError("GIT_INDEX_OWNED_PATH_DRIFT")
        if current != target_projection:
            all_target = False
        if current != base_projection:
            all_base = False
    if _index_projection_sha256(entries, excluded_paths=owned_set) != str(
        transaction["manifest"].get("unrelated_index_sha256", "")
    ):
        raise OSError("GIT_INDEX_UNRELATED_STAGED_DRIFT")
    if _index_flag_projection_sha256(
        index_file,
        excluded_paths=owned_set,
        deadline=deadline,
    ) != str(transaction["manifest"].get("unrelated_index_flags_sha256", "")):
        raise OSError("GIT_INDEX_UNRELATED_STAGED_DRIFT")
    raw, _metadata = _read_regular_file(
        index_file,
        maximum_bytes=128 * 1024 * 1024,
    )
    return all_target, all_base, hashlib.sha256(raw).hexdigest()


def _validate_owned_worktree(transaction: dict[str, Any]) -> None:
    for item in transaction["owned"]:
        repo_path = str(item["path"])
        _validate_owned_repo_path(repo_path)
        path = REPO_ROOT.joinpath(*Path(repo_path).parts)
        try:
            path.parent.resolve().relative_to(REPO_ROOT.resolve())
            raw, _metadata = _read_regular_file(
                path,
                maximum_bytes=64 * 1024 * 1024,
            )
        except (OSError, ValueError) as exc:
            raise OSError("GIT_INDEX_OWNED_WORKTREE_DRIFT") from exc
        if hashlib.sha256(raw).hexdigest() != str(item["raw_sha256"]):
            raise OSError("GIT_INDEX_OWNED_WORKTREE_DRIFT")


def _acquire_candidate_index_lock(
    *,
    lock_path: Path,
    candidate_path: Path,
    deadline: float,
) -> dict[str, Any]:
    lock_deadline = min(
        deadline,
        time.monotonic() + max(GIT_INDEX_LOCK_RETRY_SECONDS, 0.0),
    )
    attempts = 0
    waited = 0.0
    while True:
        attempts += 1
        try:
            os.link(candidate_path, lock_path, follow_symlinks=False)
            if not _same_regular_inode(lock_path, candidate_path):
                raise OSError("GIT_INDEX_LOCK_OWNERSHIP_INVALID")
            return {
                "attempts": attempts,
                "waited_ms": round(waited * 1000),
                "status": "acquired" if attempts == 1 else "recovered",
            }
        except FileExistsError:
            if _same_regular_inode(lock_path, candidate_path):
                return {
                    "attempts": attempts,
                    "waited_ms": round(waited * 1000),
                    "status": "resumed_owned_lock",
                }
            try:
                metadata = lock_path.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise OSError("GIT_INDEX_LOCK_STATE_UNAVAILABLE") from exc
            if lock_path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise OSError("GIT_INDEX_LOCK_UNSAFE")
            remaining = lock_deadline - time.monotonic()
            if remaining <= 0:
                raise OSError("GIT_INDEX_LOCKED")
            interval = min(
                max(GIT_INDEX_LOCK_RETRY_INTERVAL_SECONDS, 0.01),
                remaining,
            )
            time.sleep(interval)
            waited += interval
        except OSError as exc:
            raise OSError("GIT_INDEX_LOCKED") from exc


def _preserve_owned_index_lock(
    *,
    layout: dict[str, Path],
    candidate_path: Path,
    transaction_id: str,
) -> Path:
    """Move only our exact lock inode into private evidence; unknown locks stay put."""

    if not _same_regular_inode(layout["lock"], candidate_path):
        raise OSError("GIT_INDEX_OWNED_LOCK_RELEASE_FAILED")
    evidence = layout["recovery_root"] / (
        f"{transaction_id}.{uuid.uuid4().hex}.released-index-lock"
    )
    if evidence.exists() or evidence.is_symlink():
        raise OSError("GIT_INDEX_OWNED_LOCK_RELEASE_FAILED")
    os.replace(layout["lock"], evidence)
    _fsync_directory(layout["git_dir"])
    if (
        layout["lock"].exists()
        or layout["lock"].is_symlink()
        or not _same_regular_inode(evidence, candidate_path)
    ):
        raise OSError("GIT_INDEX_OWNED_LOCK_RELEASE_FAILED")
    return evidence


def _hold_prepared_index_lock_before_head_cas(
    transaction: dict[str, Any],
    *,
    expected_head: str,
    deadline: float,
) -> dict[str, Any]:
    layout = _git_index_layout(create_recovery=True, deadline=deadline)
    loaded = _load_index_sync_transaction(
        Path(transaction["manifest_path"]),
        layout=layout,
        deadline=deadline,
    )
    operation = generated_index_git_operation_fence(deadline=deadline)
    if not operation.get("ok") or _bounded_current_git_head(deadline) != expected_head:
        raise OSError(
            str(operation.get("reason_code") or "GIT_INDEX_HEAD_DRIFT")
        )
    _validate_owned_worktree(loaded)
    _all_target, all_base, before_sha256 = _current_index_matches_transaction(
        loaded,
        index_file=layout["index"],
        deadline=deadline,
    )
    if all_base and before_sha256 != str(
        loaded["manifest"]["initial_index_sha256"]
    ):
        raise OSError("GIT_INDEX_CONCURRENT_DRIFT")
    candidate_path = Path(loaded["candidate_path"])
    acquired = False
    try:
        lock_evidence = _acquire_candidate_index_lock(
            lock_path=layout["lock"],
            candidate_path=candidate_path,
            deadline=deadline,
        )
        acquired = True
        operation = generated_index_git_operation_fence(deadline=deadline)
        if not operation.get("ok") or _bounded_current_git_head(deadline) != expected_head:
            raise OSError("GIT_INDEX_HEAD_DRIFT")
        _validate_owned_worktree(loaded)
        _all_target_after_lock, all_base_after_lock, after_sha256 = (
            _current_index_matches_transaction(
                loaded,
                index_file=layout["index"],
                deadline=deadline,
            )
        )
        if all_base_after_lock and after_sha256 != str(
            loaded["manifest"]["initial_index_sha256"]
        ):
            raise OSError("GIT_INDEX_CONCURRENT_DRIFT")
        if after_sha256 != before_sha256:
            raise OSError("GIT_INDEX_CONCURRENT_DRIFT")
        return {
            "layout": layout,
            "loaded": loaded,
            "lock_evidence": lock_evidence,
        }
    except BaseException:
        if acquired and _same_regular_inode(layout["lock"], candidate_path):
            _preserve_owned_index_lock(
                layout=layout,
                candidate_path=candidate_path,
                transaction_id=str(loaded["manifest"]["transaction_id"]),
            )
        raise


def _release_held_index_lock(held: dict[str, Any]) -> None:
    """Release a previously verified owned lock without running Git or a timer."""

    layout = held["layout"]
    loaded = held["loaded"]
    candidate_path = Path(loaded["candidate_path"])
    lock_path = Path(layout["lock"])
    if not lock_path.exists() and not lock_path.is_symlink():
        return
    if not _same_regular_inode(lock_path, candidate_path):
        # Never remove, rename, or overwrite a lock whose inode is not the
        # transaction-bound candidate we acquired.
        raise OSError("GIT_INDEX_OWNED_LOCK_RELEASE_FAILED")
    _preserve_owned_index_lock(
        layout=layout,
        candidate_path=candidate_path,
        transaction_id=str(loaded["manifest"]["transaction_id"]),
    )


def _record_and_release_held_index_outcome(
    transaction: dict[str, Any],
    held: dict[str, Any],
    outcome: str,
) -> None:
    """Publish terminal evidence while the exact lock is held, then release it."""

    payload = _record_index_sync_outcome(
        transaction,
        outcome,
        compact_candidate=False,
    )
    _release_held_index_lock(held)
    _compact_terminal_index_candidate(
        recovery_root=Path(transaction["outcome_path"]).parent,
        outcome=payload,
    )


def _apply_prepared_real_index_sync(
    transaction: dict[str, Any],
    *,
    deadline: float,
) -> dict[str, Any]:
    layout = _git_index_layout(create_recovery=True, deadline=deadline)
    outcome_path = Path(transaction["outcome_path"])
    manifest_hint = transaction.get("manifest")
    transaction_id = (
        str(manifest_hint.get("transaction_id", ""))
        if isinstance(manifest_hint, dict)
        else outcome_path.name.split(".", 1)[0]
    )
    if outcome_path.exists() or outcome_path.is_symlink():
        outcome = _validated_terminal_index_outcome(
            outcome_path,
            transaction_id,
        )
        _validate_terminal_outcome_manifest(
            outcome=outcome,
            manifest_path=Path(transaction["manifest_path"]),
        )
        if outcome.get("outcome") != "completed":
            raise OSError("GIT_INDEX_RECOVERY_OUTCOME_CONFLICT")
        _compact_terminal_index_candidate(
            recovery_root=layout["recovery_root"],
            outcome=outcome,
        )
        return {"ok": True, "changed": False, "detail": "index_sync_already_completed"}
    loaded = _load_index_sync_transaction(
        Path(transaction["manifest_path"]),
        layout=layout,
        deadline=deadline,
    )
    git_operation = generated_index_git_operation_fence(deadline=deadline)
    current_head = _bounded_current_git_head(deadline)
    target_head = str(loaded["manifest"]["target_head"])
    if not git_operation.get("ok"):
        raise OSError(
            str(git_operation.get("reason_code") or "GIT_INDEX_GIT_OPERATION_IN_PROGRESS")
        )
    if current_head != target_head:
        raise OSError("GIT_INDEX_HEAD_DRIFT")
    _validate_owned_worktree(loaded)
    _all_target, all_base, current_index_sha256 = _current_index_matches_transaction(
        loaded,
        index_file=layout["index"],
        deadline=deadline,
    )
    if all_base and current_index_sha256 != str(
        loaded["manifest"]["initial_index_sha256"]
    ):
        raise OSError("GIT_INDEX_CONCURRENT_DRIFT")
    lock_evidence = _acquire_candidate_index_lock(
        lock_path=layout["lock"],
        candidate_path=Path(loaded["candidate_path"]),
        deadline=deadline,
    )
    candidate_path = Path(loaded["candidate_path"])
    index_replaced = False
    try:
        git_operation = generated_index_git_operation_fence(deadline=deadline)
        current_head = _bounded_current_git_head(deadline)
        if not git_operation.get("ok") or current_head != target_head:
            raise OSError("GIT_INDEX_HEAD_DRIFT")
        _validate_owned_worktree(loaded)
        (
            _all_target_after_lock,
            all_base_after_lock,
            index_sha_after_lock,
        ) = _current_index_matches_transaction(
            loaded,
            index_file=layout["index"],
            deadline=deadline,
        )
        if all_base_after_lock and index_sha_after_lock != str(
            loaded["manifest"]["initial_index_sha256"]
        ):
            raise OSError("GIT_INDEX_CONCURRENT_DRIFT")
        if index_sha_after_lock != current_index_sha256:
            raise OSError("GIT_INDEX_CONCURRENT_DRIFT")
        if not _same_regular_inode(layout["lock"], candidate_path):
            raise OSError("GIT_INDEX_LOCK_OWNERSHIP_INVALID")
        _deadline_timeout(deadline, 0.05)
        if _same_regular_inode(layout["index"], candidate_path):
            _preserve_owned_index_lock(
                layout=layout,
                candidate_path=candidate_path,
                transaction_id=str(loaded["manifest"]["transaction_id"]),
            )
        else:
            os.replace(layout["lock"], layout["index"])
        index_replaced = True
    finally:
        if not index_replaced and (
            layout["lock"].exists() or layout["lock"].is_symlink()
        ):
            _preserve_owned_index_lock(
                layout=layout,
                candidate_path=candidate_path,
                transaction_id=str(loaded["manifest"]["transaction_id"]),
            )
    _fsync_directory(layout["git_dir"])
    repaired_raw, repaired_metadata = _read_regular_file(
        layout["index"],
        maximum_bytes=128 * 1024 * 1024,
    )
    if (
        (
            POSIX_PERMISSION_MODEL
            and stat.S_IMODE(repaired_metadata.st_mode) != 0o600
        )
        or hashlib.sha256(repaired_raw).hexdigest()
        != str(loaded["manifest"]["candidate_sha256"])
    ):
        raise OSError("GIT_INDEX_SYNC_READBACK_FAILED")
    readback_target, _readback_base, _readback_sha = _current_index_matches_transaction(
        loaded,
        index_file=layout["index"],
        deadline=deadline,
    )
    _validate_owned_worktree(loaded)
    final_head = _bounded_current_git_head(deadline)
    final_operation = generated_index_git_operation_fence(deadline=deadline)
    if (
        not readback_target
        or final_head != target_head
        or not final_operation.get("ok")
    ):
        raise OSError("GIT_INDEX_SYNC_READBACK_FAILED")
    _record_index_sync_outcome(loaded, "completed")
    return {
        "ok": True,
        "changed": True,
        "detail": "index_sync_atomic_batch_completed",
        "index_lock_retry": lock_evidence,
        "files": [item["path"] for item in loaded["owned"]],
        "index_sha256": str(loaded["manifest"]["candidate_sha256"]),
    }


def _git_commit_is_ancestor(
    ancestor: str,
    descendant: str,
    *,
    deadline: float,
) -> bool:
    result = run_command(
        [
            "git",
            "-C",
            str(REPO_ROOT),
            "merge-base",
            "--is-ancestor",
            ancestor,
            descendant,
        ],
        timeout=_deadline_timeout(deadline, 30),
    )
    returncode = int(result.get("returncode", 127))
    if returncode == 0:
        return True
    if returncode == 1:
        return False
    raise OSError("GIT_INDEX_COMMIT_EVIDENCE_INVALID")


def _descendant_owned_projection_sha256(
    transaction: dict[str, Any],
    *,
    current_head: str,
    index_file: Path,
    deadline: float,
) -> str:
    entries = _git_index_entries(index_file, deadline=deadline)
    for item in transaction["owned"]:
        target = item["target"]
        if _git_tree_entry_optional(
            current_head,
            item["path"],
            deadline=deadline,
        ) != target:
            raise OSError("GIT_INDEX_HEAD_DRIFT")
        if entries.get(item["path"], ()) != _index_entry_projection(target):
            raise OSError("GIT_INDEX_HEAD_DRIFT")
    raw, _metadata = _read_regular_file(
        index_file,
        maximum_bytes=128 * 1024 * 1024,
    )
    return hashlib.sha256(raw).hexdigest()


def _complete_safe_descendant_index_transaction(
    transaction: dict[str, Any],
    *,
    layout: dict[str, Path],
    current_head: str,
    deadline: float,
) -> None:
    """Recognize a zero-write terminal descendant; never repair under drifted HEAD."""

    target_head = str(transaction["manifest"]["target_head"])
    if not _git_commit_is_ancestor(target_head, current_head, deadline=deadline):
        raise OSError("GIT_INDEX_HEAD_DRIFT")
    before_sha256 = _descendant_owned_projection_sha256(
        transaction,
        current_head=current_head,
        index_file=layout["index"],
        deadline=deadline,
    )
    _validate_owned_worktree(transaction)
    _acquire_candidate_index_lock(
        lock_path=layout["lock"],
        candidate_path=Path(transaction["candidate_path"]),
        deadline=deadline,
    )
    held = {"layout": layout, "loaded": transaction}
    terminal_outcome: dict[str, Any] | None = None
    try:
        operation = generated_index_git_operation_fence(deadline=deadline)
        if not operation.get("ok"):
            raise OSError(
                str(
                    operation.get("reason_code")
                    or "GIT_INDEX_GIT_OPERATION_IN_PROGRESS"
                )
            )
        final_head = _bounded_current_git_head(deadline)
        if final_head != current_head or not _git_commit_is_ancestor(
            target_head,
            final_head,
            deadline=deadline,
        ):
            raise OSError("GIT_INDEX_HEAD_DRIFT")
        _validate_owned_worktree(transaction)
        after_sha256 = _descendant_owned_projection_sha256(
            transaction,
            current_head=final_head,
            index_file=layout["index"],
            deadline=deadline,
        )
        if after_sha256 != before_sha256:
            raise OSError("GIT_INDEX_CONCURRENT_DRIFT")
        terminal_outcome = _record_index_sync_outcome(
            transaction,
            "completed",
            compact_candidate=False,
        )
    finally:
        _release_held_index_lock(held)
    if terminal_outcome is None:
        raise OSError("GIT_INDEX_RECOVERY_OUTCOME_CONFLICT")
    _compact_terminal_index_candidate(
        recovery_root=layout["recovery_root"],
        outcome=terminal_outcome,
    )


def recover_closeout_index_transactions() -> dict[str, Any]:
    """Repair only an exact durable index batch; never finalize writer state."""

    summary = {
        "ok": True,
        "recovered": 0,
        "completed": 0,
        "aborted": 0,
        "blocked": 0,
        "terminal_skipped": 0,
        "terminal_compacted": 0,
        "detail": "none",
    }
    deadline = time.monotonic() + max(GIT_INDEX_SYNC_DEADLINE_SECONDS, 0.01)
    try:
        layout = _git_index_layout(create_recovery=False, deadline=deadline)
    except OSError as exc:
        return {
            **summary,
            "ok": False,
            "blocked": 1,
            "detail": str(exc) or "GIT_INDEX_RECOVERY_UNAVAILABLE",
        }
    recovery_root = layout["recovery_root"]
    if not recovery_root.exists() and not recovery_root.is_symlink():
        return summary
    try:
        manifests = sorted(
            (
                path
                for path in recovery_root.iterdir()
                if re.fullmatch(r"[0-9a-f]{32}\.manifest\.json", path.name)
            ),
            key=lambda path: path.name,
        )
    except OSError:
        return {
            **summary,
            "ok": False,
            "blocked": 1,
            "detail": "GIT_INDEX_RECOVERY_DIRECTORY_UNSAFE",
        }
    pending_manifests: list[Path] = []
    for manifest_path in manifests:
        transaction_id = manifest_path.name.split(".", 1)[0]
        outcome_path = recovery_root / f"{transaction_id}.outcome.json"
        if outcome_path.exists() or outcome_path.is_symlink():
            candidate_path = recovery_root / f"{transaction_id}.index"
            outcome: dict[str, Any] | None = None
            terminal_error: OSError | None = None
            try:
                outcome = _validated_terminal_index_outcome(
                    outcome_path,
                    transaction_id,
                )
                _validate_terminal_outcome_manifest(
                    outcome=outcome,
                    manifest_path=manifest_path,
                )
            except OSError as exc:
                terminal_error = exc
            finally:
                if _same_regular_inode(layout["lock"], candidate_path):
                    try:
                        _preserve_owned_index_lock(
                            layout=layout,
                            candidate_path=candidate_path,
                            transaction_id=transaction_id,
                        )
                    except OSError as exc:
                        terminal_error = exc
            if terminal_error is not None or outcome is None:
                return {
                    **summary,
                    "ok": False,
                    "blocked": 1,
                    "detail": (
                        str(terminal_error)
                        if terminal_error is not None
                        else "GIT_INDEX_RECOVERY_OUTCOME_CONFLICT"
                    ),
                }
            summary["terminal_skipped"] += 1
            if _compact_terminal_index_candidate(
                recovery_root=recovery_root,
                outcome=outcome,
            ):
                summary["terminal_compacted"] += 1
            continue
        pending_manifests.append(manifest_path)
    if len(pending_manifests) > 256:
        return {
            **summary,
            "ok": False,
            "blocked": 1,
            "detail": "GIT_INDEX_RECOVERY_MANIFEST_LIMIT_EXCEEDED",
        }
    for manifest_path in pending_manifests:
        transaction_id = manifest_path.name.split(".", 1)[0]
        candidate_hint = recovery_root / f"{transaction_id}.index"
        transaction: dict[str, Any] | None = None
        try:
            transaction = _load_index_sync_transaction(
                manifest_path,
                layout=layout,
                deadline=deadline,
            )
            current_head = _bounded_current_git_head(deadline)
            base_head = str(transaction["manifest"]["base_head"])
            target_head = str(transaction["manifest"]["target_head"])
            head_change = bool(transaction["manifest"].get("head_change"))
            if head_change and current_head == base_head:
                candidate_path = Path(transaction["candidate_path"])
                _validate_owned_worktree(transaction)
                _acquire_candidate_index_lock(
                    lock_path=layout["lock"],
                    candidate_path=candidate_path,
                    deadline=deadline,
                )
                held = {"layout": layout, "loaded": transaction}
                terminal_outcome: dict[str, Any] | None = None
                try:
                    operation = generated_index_git_operation_fence(
                        deadline=deadline
                    )
                    if (
                        not operation.get("ok")
                        or _bounded_current_git_head(deadline) != base_head
                    ):
                        raise OSError("GIT_INDEX_HEAD_DRIFT")
                    _validate_owned_worktree(transaction)
                    all_target, _all_base, _digest = _current_index_matches_transaction(
                        transaction,
                        index_file=layout["index"],
                        deadline=deadline,
                    )
                    if all_target:
                        raise OSError("GIT_INDEX_HEAD_DRIFT")
                    current_entries = _git_index_entries(
                        layout["index"],
                        deadline=deadline,
                    )
                    for item in transaction["owned"]:
                        if current_entries.get(
                            item["path"], ()
                        ) != _index_entry_projection(item["base"]):
                            raise OSError("GIT_INDEX_OWNED_PATH_DRIFT")
                    terminal_outcome = _record_index_sync_outcome(
                        transaction,
                        "aborted_before_head_publish",
                        compact_candidate=False,
                    )
                finally:
                    _release_held_index_lock(held)
                if terminal_outcome is None:
                    raise OSError("GIT_INDEX_RECOVERY_OUTCOME_CONFLICT")
                _compact_terminal_index_candidate(
                    recovery_root=layout["recovery_root"],
                    outcome=terminal_outcome,
                )
                summary["aborted"] += 1
                summary["recovered"] += 1
                continue
            if current_head != target_head:
                _complete_safe_descendant_index_transaction(
                    transaction,
                    layout=layout,
                    current_head=current_head,
                    deadline=deadline,
                )
            else:
                applied = _apply_prepared_real_index_sync(
                    transaction,
                    deadline=deadline,
                )
                if not applied.get("ok"):
                    raise OSError("GIT_INDEX_SYNC_FAILED")
            summary["completed"] += 1
            summary["recovered"] += 1
        except OSError as exc:
            summary["ok"] = False
            summary["blocked"] += 1
            summary["detail"] = str(exc) or "GIT_INDEX_RECOVERY_REQUIRED"
            break
        finally:
            candidate_path = (
                Path(transaction["candidate_path"])
                if transaction is not None
                else candidate_hint
            )
            exact_transaction_id = (
                str(transaction["manifest"]["transaction_id"])
                if transaction is not None
                else transaction_id
            )
            if _same_regular_inode(layout["lock"], candidate_path):
                try:
                    _preserve_owned_index_lock(
                        layout=layout,
                        candidate_path=candidate_path,
                        transaction_id=exact_transaction_id,
                    )
                except OSError as exc:
                    if summary["ok"]:
                        summary["ok"] = False
                        summary["blocked"] += 1
                    summary["detail"] = (
                        str(exc) or "GIT_INDEX_OWNED_LOCK_RELEASE_FAILED"
                    )
    if summary["ok"] and summary["recovered"]:
        summary["detail"] = "recovered"
    elif not summary["ok"] and summary["detail"] == "none":
        summary["detail"] = "GIT_INDEX_RECOVERY_REQUIRED"
    return summary


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise OSError("GENERATED_INDEX_GIT_INDEX_RECOVERY_FAILED") from exc


def repair_generated_index_stage_zero(
    *,
    transaction_binding: dict[str, str],
    exact_commit: str,
    generated_sha256: str,
    current_worktree_sha256: str,
) -> dict[str, Any]:
    """CAS-repair only our update-ref-before-index-sync crash residue."""

    git_operation = generated_index_git_operation_fence()
    if not git_operation.get("ok"):
        raise OSError(
            str(
                git_operation.get("reason_code")
                or "GENERATED_INDEX_GIT_STATE_UNAVAILABLE"
            )
        )
    current_head, warnings = current_git_head()
    if warnings or current_head != exact_commit or current_worktree_sha256 != generated_sha256:
        raise OSError("GENERATED_INDEX_GIT_INDEX_RECOVERY_CONFLICT")
    index_path = (VAULT_ROOT / "INDEX.md").resolve()
    try:
        repo_path = index_path.relative_to(REPO_ROOT).as_posix()
    except ValueError as exc:
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE") from exc
    base_mode, base_oid = _git_tree_entry(transaction_binding["git_head"], repo_path)
    target_mode, target_oid = _git_tree_entry(exact_commit, repo_path)
    if (
        _git_blob_sha256(base_oid) != transaction_binding["index_base_sha256"]
        or _git_blob_sha256(target_oid) != generated_sha256
    ):
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE")

    git_path = run_command(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--git-path", "index"],
        timeout=30,
    )
    if not git_path.get("ok"):
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE")
    raw_index = Path(str(git_path.get("stdout", "")).strip())
    if not raw_index.is_absolute():
        raw_index = REPO_ROOT / raw_index
    raw_index = Path(os.path.abspath(raw_index))
    git_dir_result = run_command(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--absolute-git-dir"],
        timeout=30,
    )
    if not git_dir_result.get("ok"):
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE")
    git_dir = Path(os.path.abspath(str(git_dir_result.get("stdout", "")).strip()))
    try:
        git_dir_metadata = git_dir.lstat()
        index_metadata = raw_index.lstat()
    except OSError as exc:
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE") from exc
    if (
        raw_index.parent != git_dir
        or git_dir.is_symlink()
        or not stat.S_ISDIR(git_dir_metadata.st_mode)
        or raw_index.is_symlink()
        or not stat.S_ISREG(index_metadata.st_mode)
    ):
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE")
    generated_index_backup_directory(CONFIG_ROOT, transaction_binding["transaction_id"])
    standard_lock = raw_index.with_name(f"{raw_index.name}.lock")
    recovery_root = raw_index.parent / "agent-memory-recovery"
    if recovery_root.is_symlink():
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE")
    recovery_root.mkdir(mode=0o700, exist_ok=True)
    recovery_metadata = recovery_root.lstat()
    if not stat.S_ISDIR(recovery_metadata.st_mode):
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE")
    os.chmod(recovery_root, 0o700)
    durable_proposal = recovery_root / f"{transaction_binding['transaction_id']}.index"

    def same_inode(first: Path, second: Path) -> bool:
        try:
            first_stat = first.lstat()
            second_stat = second.lstat()
        except OSError:
            return False
        return (
            not first.is_symlink()
            and not second.is_symlink()
            and stat.S_ISREG(first_stat.st_mode)
            and stat.S_ISREG(second_stat.st_mode)
            and (first_stat.st_dev, first_stat.st_ino)
            == (second_stat.st_dev, second_stat.st_ino)
        )

    # A previous kill after linking the complete proposal but before rename is
    # recoverable only when the standard Git lock is the very same inode as our
    # transaction-bound durable proposal. Unknown locks always belong to the
    # user or another Git process and are never touched.
    if standard_lock.exists() or standard_lock.is_symlink():
        if not same_inode(standard_lock, durable_proposal):
            raise OSError("GENERATED_INDEX_GIT_INDEX_LOCKED")
        lock_mode, lock_oid = _git_index_stage_zero(
            repo_path,
            index_file=standard_lock,
        )
        current_mode, current_oid = _git_index_stage_zero(
            repo_path,
            index_file=raw_index,
        )
        if (
            (lock_mode, lock_oid) != (target_mode, target_oid)
            or (current_mode, current_oid) != (base_mode, base_oid)
            or hashlib.sha256(index_path.read_bytes()).hexdigest() != generated_sha256
        ):
            raise OSError("GENERATED_INDEX_GIT_INDEX_RECOVERY_CONFLICT")
        os.replace(standard_lock, raw_index)
        _fsync_directory(raw_index.parent)
        return {
            "ok": True,
            "changed": True,
            "detail": "git_index_linked_lock_recovered",
            "evidence": str(durable_proposal),
            "previous_mode": current_mode,
        }

    metadata = raw_index.lstat()
    if (
        raw_index.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 0
        or metadata.st_size > 128 * 1024 * 1024
    ):
        raise OSError("GENERATED_INDEX_GIT_INDEX_UNAVAILABLE")
    before = raw_index.read_bytes()
    before_sha256 = hashlib.sha256(before).hexdigest()
    candidate = recovery_root / f"{transaction_binding['transaction_id']}-{uuid.uuid4().hex}.candidate"
    descriptor = os.open(
        candidate,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        stat.S_IMODE(metadata.st_mode),
    )
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        os.fchmod(handle.fileno(), stat.S_IMODE(metadata.st_mode))
        handle.write(before)
        handle.flush()
        os.fsync(handle.fileno())
    current_mode, current_oid = _git_index_stage_zero(repo_path, index_file=candidate)
    if (current_mode, current_oid) == (target_mode, target_oid):
        return {"ok": True, "changed": False, "detail": "git_index_already_synced"}
    if (current_mode, current_oid) != (base_mode, base_oid):
        raise OSError("GENERATED_INDEX_GIT_INDEX_RECOVERY_CONFLICT")
    environment = os.environ.copy()
    environment["GIT_INDEX_FILE"] = str(candidate)
    update = run_command(
        [
            "git", "-C", str(REPO_ROOT), "update-index", "--add", "--cacheinfo",
            target_mode, target_oid, repo_path,
        ],
        timeout=60,
        env=environment,
    )
    if not update.get("ok"):
        raise OSError("GENERATED_INDEX_GIT_INDEX_RECOVERY_FAILED")
    candidate_mode, candidate_oid = _git_index_stage_zero(repo_path, index_file=candidate)
    if (candidate_mode, candidate_oid) != (target_mode, target_oid):
        raise OSError("GENERATED_INDEX_GIT_INDEX_RECOVERY_FAILED")
    candidate_bytes = candidate.read_bytes()
    if durable_proposal.exists() or durable_proposal.is_symlink():
        if (
            durable_proposal.is_symlink()
            or not durable_proposal.is_file()
            or durable_proposal.read_bytes() != candidate_bytes
        ):
            raise OSError("GENERATED_INDEX_GIT_INDEX_RECOVERY_CONFLICT")
    else:
        try:
            os.link(candidate, durable_proposal, follow_symlinks=False)
        except OSError as exc:
            if not durable_proposal.is_file() or durable_proposal.read_bytes() != candidate_bytes:
                raise OSError("GENERATED_INDEX_GIT_INDEX_RECOVERY_CONFLICT") from exc
    _fsync_directory(recovery_root)
    if (
        hashlib.sha256(raw_index.read_bytes()).hexdigest() != before_sha256
        or hashlib.sha256(index_path.read_bytes()).hexdigest() != generated_sha256
    ):
        raise OSError("GENERATED_INDEX_GIT_INDEX_RECOVERY_CONFLICT")
    try:
        os.link(durable_proposal, standard_lock, follow_symlinks=False)
    except OSError as exc:
        raise OSError("GENERATED_INDEX_GIT_INDEX_LOCKED") from exc
    if (
        not same_inode(standard_lock, durable_proposal)
        or hashlib.sha256(raw_index.read_bytes()).hexdigest() != before_sha256
        or hashlib.sha256(index_path.read_bytes()).hexdigest() != generated_sha256
    ):
        raise OSError("GENERATED_INDEX_GIT_INDEX_RECOVERY_CONFLICT")
    standard_mode, standard_oid = _git_index_stage_zero(
        repo_path,
        index_file=standard_lock,
    )
    if (standard_mode, standard_oid) != (target_mode, target_oid):
        raise OSError("GENERATED_INDEX_GIT_INDEX_RECOVERY_CONFLICT")
    _fsync_directory(raw_index.parent)
    if (
        not same_inode(standard_lock, durable_proposal)
        or hashlib.sha256(raw_index.read_bytes()).hexdigest() != before_sha256
        or hashlib.sha256(index_path.read_bytes()).hexdigest() != generated_sha256
    ):
        raise OSError("GENERATED_INDEX_GIT_INDEX_RECOVERY_CONFLICT")
    os.replace(standard_lock, raw_index)
    _fsync_directory(raw_index.parent)
    repaired_mode, repaired_oid = _git_index_stage_zero(repo_path, index_file=raw_index)
    if (
        (repaired_mode, repaired_oid) != (target_mode, target_oid)
        or hashlib.sha256(index_path.read_bytes()).hexdigest() != generated_sha256
    ):
        raise OSError("GENERATED_INDEX_GIT_INDEX_RECOVERY_FAILED")
    return {
        "ok": True,
        "changed": True,
        "detail": "git_index_crash_residue_repaired",
        "evidence": str(durable_proposal),
        "previous_mode": current_mode,
    }


def _build_isolated_commit(
    snapshots: list[CommitSnapshot],
    *,
    expected_head: str,
    message: str,
    expected_full_vault_inputs_sha256: str = "",
) -> dict[str, Any]:
    git_operation = generated_index_git_operation_fence()
    if not git_operation.get("ok"):
        return {
            "ok": False,
            "stage": "git_operation_precommit",
            "detail": str(
                git_operation.get("reason_code")
                or "GENERATED_INDEX_GIT_STATE_UNAVAILABLE"
            ),
            "git_operation": git_operation,
        }
    transaction_dir = CONFIG_ROOT / "state"
    transaction_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if POSIX_PERMISSION_MODEL:
        try:
            transaction_dir.chmod(0o700)
        except OSError:
            return {"ok": False, "stage": "transaction_index", "detail": "transaction_directory_permission_failed"}
    index_path = transaction_dir / "closeout-transaction.index"
    env = os.environ.copy()
    env["GIT_INDEX_FILE"] = str(index_path)
    read_tree = run_command(
        ["git", "-C", str(REPO_ROOT), "read-tree", "--reset", expected_head],
        timeout=60,
        env=env,
    )
    if not read_tree["ok"]:
        return {"ok": False, "stage": "read_tree", "detail": read_tree}
    if POSIX_PERMISSION_MODEL:
        try:
            index_path.chmod(0o600)
        except OSError:
            return {"ok": False, "stage": "transaction_index", "detail": "transaction_index_permission_failed"}
    for snapshot in snapshots:
        update = run_command(
            [
                "git", "-C", str(REPO_ROOT), "update-index", "--add", "--cacheinfo",
                snapshot.mode, snapshot.blob_oid, snapshot.repo_path,
            ],
            timeout=60,
            env=env,
        )
        if not update["ok"]:
            return {"ok": False, "stage": "isolated_index", "detail": update, "file": snapshot.repo_path}
    tree_result = run_command(["git", "-C", str(REPO_ROOT), "write-tree"], timeout=60, env=env)
    if not tree_result["ok"]:
        return {"ok": False, "stage": "write_tree", "detail": tree_result}
    mode_error = _commit_snapshot_mode_error(
        snapshots,
        stage="pre_commit_mode",
    )
    if mode_error is not None:
        return mode_error
    tree_oid = str(tree_result["stdout"]).strip().lower()
    head_tree = run_command(
        ["git", "-C", str(REPO_ROOT), "rev-parse", f"{expected_head}^{{tree}}"],
        timeout=30,
    )
    if not head_tree["ok"]:
        return {"ok": False, "stage": "head_tree", "detail": head_tree}
    if tree_oid == str(head_tree["stdout"]).strip().lower():
        sync_deadline = time.monotonic() + max(GIT_INDEX_SYNC_DEADLINE_SECONDS, 0.01)
        try:
            prepared_sync = _prepare_real_index_sync(
                snapshots,
                expected_head=expected_head,
                target_head=expected_head,
                deadline=sync_deadline,
            )
        except OSError as exc:
            return {
                "ok": False,
                "stage": "index_sync_prepare",
                "detail": str(exc) or "GIT_INDEX_SYNC_PREPARE_FAILED",
            }
        sync = _sync_real_index(
            snapshots,
            prepared=prepared_sync,
            expected_head=expected_head,
            target_head=expected_head,
            deadline=sync_deadline,
        )
        return sync if not sync["ok"] else {"ok": True, "skipped": True, "detail": "nothing_staged"}

    commit_environment = os.environ.copy()
    commit_environment.setdefault("GIT_AUTHOR_NAME", "Agent Memory Vault")
    commit_environment.setdefault("GIT_AUTHOR_EMAIL", "agent-memory@localhost")
    commit_environment.setdefault("GIT_COMMITTER_NAME", "Agent Memory Vault")
    commit_environment.setdefault("GIT_COMMITTER_EMAIL", "agent-memory@localhost")
    commit_result = run_command(
        ["git", "-C", str(REPO_ROOT), "commit-tree", tree_oid, "-p", expected_head, "-m", message],
        timeout=120,
        env=commit_environment,
    )
    if not commit_result["ok"]:
        return {"ok": False, "stage": "commit_tree", "detail": commit_result}
    commit_oid = str(commit_result["stdout"]).strip().lower()
    mode_error = _commit_snapshot_mode_error(
        snapshots,
        stage="pre_publish_mode",
    )
    if mode_error is not None:
        return mode_error
    if expected_full_vault_inputs_sha256:
        try:
            assert_full_vault_input_projection(expected_full_vault_inputs_sha256)
        except OSError:
            return {
                "ok": False,
                "stage": "full_vault_pre_commit",
                "detail": "GENERATED_INDEX_INPUT_CHANGED",
            }
    sync_deadline = time.monotonic() + max(GIT_INDEX_SYNC_DEADLINE_SECONDS, 0.01)
    try:
        prepared_sync = _prepare_real_index_sync(
            snapshots,
            expected_head=expected_head,
            target_head=commit_oid,
            deadline=sync_deadline,
        )
    except OSError as exc:
        return {
            "ok": False,
            "stage": "index_sync_prepare",
            "detail": str(exc) or "GIT_INDEX_SYNC_PREPARE_FAILED",
        }
    try:
        held_sync = _hold_prepared_index_lock_before_head_cas(
            prepared_sync,
            expected_head=expected_head,
            deadline=sync_deadline,
        )
    except OSError as exc:
        return {
            "ok": False,
            "stage": "index_sync_lock",
            "detail": str(exc) or "GIT_INDEX_LOCKED",
        }
    result: dict[str, Any]
    head_published = False
    try:
        git_operation = generated_index_git_operation_fence(deadline=sync_deadline)
        if not git_operation.get("ok"):
            # The owned lock is still held, so an exact HEAD readback can
            # safely distinguish a never-published transaction from an
            # ambiguous one.  Never manufacture a terminal outcome if the
            # deadline prevents that readback.
            current_head = _bounded_current_git_head(sync_deadline)
            if current_head == expected_head:
                _record_and_release_held_index_outcome(
                    prepared_sync,
                    held_sync,
                    "aborted_before_head_publish",
                )
            result = {
                "ok": False,
                "stage": "git_operation_head_cas",
                "detail": str(
                    git_operation.get("reason_code")
                    or "GENERATED_INDEX_GIT_STATE_UNAVAILABLE"
                ),
                "git_operation": git_operation,
            }
        else:
            try:
                update_ref = run_command(
                    [
                        "git",
                        "-C",
                        str(REPO_ROOT),
                        "update-ref",
                        "-m",
                        "agent-memory closeout",
                        "HEAD",
                        commit_oid,
                        expected_head,
                    ],
                    timeout=_deadline_timeout(sync_deadline, 60),
                )
            except OSError as exc:
                update_ref = {
                    "ok": False,
                    "detail": str(exc) or "GIT_INDEX_SYNC_DEADLINE_EXCEEDED",
                }
            if not update_ref.get("ok"):
                try:
                    current_head = _bounded_current_git_head(sync_deadline)
                except OSError:
                    # update-ref can report a timeout after the ref update has
                    # reached disk.  Leave the durable journal pending when a
                    # bounded readback cannot classify the result.
                    current_head = ""
                if current_head == expected_head:
                    _record_and_release_held_index_outcome(
                        prepared_sync,
                        held_sync,
                        "aborted_head_cas",
                    )
                    result = {
                        "ok": False,
                        "stage": "head_cas",
                        "detail": "GIT_HEAD_CHANGED",
                    }
                elif current_head == commit_oid:
                    head_published = True
                    # Ambiguous command status, but exact ref readback proves
                    # publication.  Continue through the normal locked index
                    # synchronization and its full readback.
                    sync = _sync_real_index(
                        snapshots,
                        prepared=prepared_sync,
                        expected_head=expected_head,
                        target_head=commit_oid,
                        deadline=sync_deadline,
                    )
                    if not sync["ok"]:
                        sync["commit"] = commit_oid
                    result = sync
                else:
                    result = {
                        "ok": False,
                        "stage": "head_cas",
                        "detail": (
                            str(update_ref.get("detail", ""))
                            or "GIT_HEAD_UPDATE_AMBIGUOUS"
                        ),
                    }
            else:
                head_published = True
                sync = _sync_real_index(
                    snapshots,
                    prepared=prepared_sync,
                    expected_head=expected_head,
                    target_head=commit_oid,
                    deadline=sync_deadline,
                )
                if not sync["ok"]:
                    sync["commit"] = commit_oid
                result = sync
    except OSError as exc:
        result = {
            "ok": False,
            "stage": "head_cas",
            "detail": str(exc) or "GIT_INDEX_RECOVERY_REQUIRED",
        }
    finally:
        try:
            _release_held_index_lock(held_sync)
        except OSError as exc:
            result = {
                "ok": False,
                "stage": "index_sync_lock_release",
                "detail": str(exc) or "GIT_INDEX_OWNED_LOCK_RELEASE_FAILED",
                "commit": commit_oid if head_published else "",
            }
    if not result.get("ok"):
        if head_published:
            result["commit"] = commit_oid
        return result
    if expected_full_vault_inputs_sha256:
        try:
            assert_full_vault_input_projection(expected_full_vault_inputs_sha256)
        except OSError:
            return {
                "ok": False,
                "stage": "full_vault_post_commit",
                "detail": "GENERATED_INDEX_INPUT_CHANGED",
                "commit": commit_oid,
            }
    return {
        "ok": True,
        "skipped": False,
        "commit": commit_oid,
        "files": [snapshot.repo_path for snapshot in snapshots],
        "snapshot_sha256": {snapshot.repo_path: snapshot.raw_sha256 for snapshot in snapshots},
    }


def commit_files(
    files: list[Path],
    args: argparse.Namespace,
    *,
    expected_raw_sha256: dict[Path, str] | None = None,
    expected_head: str = "",
    expected_full_vault_inputs_sha256: str = "",
) -> dict[str, Any]:
    if not args.commit or args.dry_run:
        return {"ok": True, "skipped": True, "detail": "commit_not_requested"}
    snapshots, snapshot_error = _snapshot_commit_files(files, expected_raw_sha256 or {})
    if snapshot_error is not None:
        return snapshot_error
    if not snapshots:
        return {"ok": True, "skipped": True, "detail": "no_existing_files_to_commit"}
    if not expected_head:
        head_result = run_command(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], timeout=30)
        if not head_result["ok"]:
            return {"ok": False, "stage": "head", "detail": head_result}
        expected_head = str(head_result["stdout"]).strip()
    message = args.message or f"memory closeout[{args.actor}]: {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}"
    return _build_isolated_commit(
        snapshots,
        expected_head=expected_head,
        message=message,
        expected_full_vault_inputs_sha256=expected_full_vault_inputs_sha256,
    )


def append_log(payload: dict[str, Any]) -> None:
    secure_append_text(LOG_PATH, json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def privacy_safe_log_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Strip ephemeral scoped diffs before writing the durable JSONL audit log."""
    copied = json.loads(json.dumps(payload, ensure_ascii=False))
    validations = copied.get("write_intent_validations", [])
    if isinstance(validations, list):
        for validation in validations:
            if not isinstance(validation, dict):
                continue
            scoped_diff = validation.pop("scoped_diff", None)
            if isinstance(scoped_diff, str):
                validation["scoped_diff_sha256"] = hashlib.sha256(scoped_diff.encode("utf-8")).hexdigest()
                validation["scoped_diff_line_count"] = len(scoped_diff.splitlines())
                validation["scoped_diff_char_count"] = len(scoped_diff)
            mismatch = validation.get("mismatch")
            if isinstance(mismatch, dict):
                diff_text = mismatch.pop("diff", None)
                if isinstance(diff_text, str):
                    mismatch["diff_sha256"] = hashlib.sha256(diff_text.encode("utf-8")).hexdigest()
                    mismatch["diff_line_count"] = len(diff_text.splitlines())
                    mismatch["diff_char_count"] = len(diff_text)
    return copied


def unobserved_history_entries(entries: list[GitEntry]) -> list[GitEntry]:
    if not entries or not STATE_DB.exists():
        return entries
    try:
        with secure_sqlite_connect(
            STATE_DB,
            timeout=5,
            create=False,
            read_only=True,
            pragmas=("PRAGMA busy_timeout=5000",),
        ) as conn:
            rows = conn.execute("SELECT path, sha256 FROM memory_file_observations").fetchall()
            deletion_rows: list[tuple[Any, ...]] = []
            try:
                deletion_rows = conn.execute(
                    """
                    SELECT path, sentinel, actor, user_authorized,
                           deletion_commit, parent_commit, prior_sha256,
                           trash_sha256, trash_path_sha256,
                           evidence_ref_sha256, evidence_ref_length
                    FROM memory_deletion_observations
                    """
                ).fetchall()
            except sqlite3.Error:
                # Older state databases legitimately predate deletion observations.
                deletion_rows = []
    except (OSError, sqlite3.Error):
        return entries
    observed = {str(Path(str(path)).resolve()): str(digest) for path, digest in rows}
    deletion_audits: dict[tuple[str, str], tuple[str, str]] = {}
    for row in deletion_rows:
        (
            path,
            sentinel,
            actor,
            user_authorized,
            commit,
            parent_commit,
            prior_sha256,
            trash_sha256,
            trash_path_sha256,
            evidence_ref_sha256,
            evidence_ref_length,
        ) = row
        parsed = parse_deleted_observation(str(sentinel))
        try:
            authorized = int(user_authorized) == 1
            evidence_length = int(evidence_ref_length)
        except (TypeError, ValueError):
            continue
        if (
            parsed is None
            or str(actor) != "human"
            or not authorized
            or parsed != (str(commit), str(prior_sha256))
            or str(trash_sha256) != str(prior_sha256)
            or re.fullmatch(r"[0-9a-f]{40}", str(parent_commit)) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(trash_path_sha256)) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(evidence_ref_sha256)) is None
            or not 0 < evidence_length <= 4096
        ):
            continue
        deletion_audits[(str(Path(str(path)).resolve()), str(sentinel))] = parsed
    pending: list[GitEntry] = []
    for entry in entries:
        resolved_path = str(entry.path.resolve())
        try:
            digest = hashlib.sha256(entry.path.read_bytes()).hexdigest()
        except OSError:
            sentinel = observed.get(resolved_path, "")
            parsed = parse_deleted_observation(sentinel)
            audit = deletion_audits.get((resolved_path, sentinel))
            if entry.is_deleted and parsed is not None and audit == parsed:
                deletion_commit, _prior_sha256 = parsed
                latest = run_command(
                    [
                        "git",
                        "-C",
                        str(REPO_ROOT),
                        "log",
                        "-1",
                        "--format=%H",
                        "HEAD",
                        "--",
                        entry.repo_path,
                    ],
                    timeout=30,
                )
                latest_commit = str(latest.get("stdout", "")).strip().lower()
                if latest.get("ok") and latest_commit == deletion_commit:
                    continue
            pending.append(entry)
            continue
        if observed.get(resolved_path) != digest:
            pending.append(entry)
    return pending


def short_step(step: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": bool(step.get("ok")),
        "skipped": bool(step.get("skipped", False)),
        "returncode": step.get("returncode"),
        "detail": step.get("detail", ""),
        "duration_ms": step.get("duration_ms"),
        "advisory_count": len(step.get("advisories", [])) if isinstance(step.get("advisories"), list) else 0,
        "stderr": str(step.get("stderr", "")).strip()[:500],
    }


def assert_current_claim_leases(
    claim_rows: list[dict[str, Any]],
    *,
    actor: str,
    raw_session_id: str,
    stage: str,
) -> list[dict[str, Any]]:
    """Bind a closeout checkpoint to each claim's current intent fence.

    Claims remain useful ownership projections for human and migration work,
    but a supported automatic writer may proceed only with an unexpired intent
    lease.  The claim's stored fencing token is deliberately supplied back to
    the intent store rather than re-read from the intent and trusted implicitly.
    """

    checked: list[dict[str, Any]] = []
    expected_session_hash = session_hash(raw_session_id)
    for row in claim_rows:
        claim_actor = str(row.get("actor", ""))
        claim_session_hash = str(row.get("session_hash", ""))
        if claim_actor != actor or claim_session_hash != expected_session_hash:
            raise write_intent.IntentError(
                "CLAIM_SESSION_MISMATCH",
                "closeout claim belongs to a different actor or session",
            )

        raw_target = Path(str(row.get("path", ""))).expanduser()
        if not raw_target.is_absolute():
            raw_target = Path.cwd() / raw_target
        lexical_target = Path(os.path.abspath(str(raw_target)))
        intent_id = str(row.get("intent_id", "")).strip()
        claim_kind = str(row.get("claim_kind", "legacy")).strip().lower() or "legacy"
        assert_governed_markdown_worktree_mode(
            lexical_target,
            allow_missing=not intent_id and claim_kind != "intent",
        )
        target = lexical_target.resolve()
        try:
            fencing_token = int(row.get("fencing_token") or 0)
        except (TypeError, ValueError) as exc:
            raise write_intent.IntentError(
                "CLAIM_BINDING_MISMATCH",
                "claim fencing token is invalid",
            ) from exc

        if not intent_id:
            if actor in AUTOMATIC_WRITER_ACTORS:
                raise write_intent.IntentError(
                    "CLAIM_HAS_NO_LIVE_LEASE",
                    "automatic writers require an intent-bound live lease",
                )
            checked.append(
                {
                    "stage": stage,
                    "path": relative_to_vault(target),
                    "lease_state": "legacy_allowed",
                }
            )
            continue
        if claim_kind != "intent" or fencing_token <= 0:
            raise write_intent.IntentError(
                "CLAIM_BINDING_MISMATCH",
                "intent claim is missing its fencing projection",
            )

        canonical = write_intent.canonical_target(target)
        if str(row.get("target_key", "")) != canonical.target_key:
            raise write_intent.IntentError(
                "CLAIM_BINDING_MISMATCH",
                "claim target does not match its canonical lease target",
            )
        lease = write_intent.assert_current_lease(
            intent_id,
            actor=actor,
            raw_session_id=raw_session_id,
            fencing_token=fencing_token,
            target=target,
            require_unexpired=True,
        )
        if (
            int(lease.get("fencing_token") or 0) != fencing_token
            or str(lease.get("target_key", "")) != canonical.target_key
        ):
            raise write_intent.IntentError(
                "LEASE_FENCED",
                "claim no longer projects the current path fence",
            )
        checked.append(
            {
                "stage": stage,
                "path": canonical.rel_path,
                "intent_id": intent_id,
                "fencing_token": fencing_token,
                "lease_state": "live",
                "expires_at": str(lease.get("expires_at", "")),
            }
        )
    return checked


def _other_session_committed_history_is_exact_validated(
    entry: GitEntry,
    *,
    claim_rows: list[dict[str, Any]],
    current_head: str,
    dirty_repo_paths: set[str],
    allow_expired_for_maintenance: bool = False,
) -> bool:
    """Recognize one narrow, already-durable other-session crash boundary.

    A claimed-only closeout must normally stop when another session owns a
    changed Markdown path: generating INDEX from that session's uncommitted
    bytes would publish them indirectly.  An external backup can, however,
    commit the exact proposal after Write Gateway validation but before the
    receipt is finalized.  Such a path is no longer dirty and is already in
    the immutable HEAD tree.  Treat it as a deferred history entry only when
    every intent, claim, approval, content, and Git-history binding proves that
    exact state.  The caller still excludes it from this session's commit,
    observation, receipt, and claim-completion sets.
    """

    try:
        raw_repo_path = str(entry.repo_path)
        normalized_repo_path = Path(raw_repo_path).as_posix()
        if (
            not raw_repo_path
            or raw_repo_path != normalized_repo_path
            or unicodedata.normalize("NFC", raw_repo_path) != raw_repo_path
            or Path(raw_repo_path).is_absolute()
            or any(part in {"", ".", ".."} for part in Path(raw_repo_path).parts)
            or raw_repo_path in dirty_repo_paths
            or entry.is_deleted
            or bool(entry.previous_repo_path)
            or entry.status.startswith(("R", "C"))
        ):
            return False
        repo_root_lexical = Path(os.path.abspath(str(REPO_ROOT)))
        lexical_entry_path = Path(
            os.path.abspath(str(repo_root_lexical / raw_repo_path))
        )
        try:
            if lexical_entry_path.relative_to(repo_root_lexical).as_posix() != raw_repo_path:
                return False
        except ValueError:
            return False
        canonical = write_intent.canonical_target(lexical_entry_path)
        try:
            canonical_repo_path = canonical.path.relative_to(repo_root_lexical).as_posix()
        except ValueError:
            return False
        if (
            canonical_repo_path != raw_repo_path
            or canonical.rel_path != relative_to_vault(canonical.path)
            or not repo_path_is_memory_markdown(raw_repo_path)
        ):
            return False
        assert_governed_markdown_worktree_mode(lexical_entry_path)

        matching_claims: list[dict[str, Any]] = []
        for row in claim_rows:
            raw_claim_path = Path(str(row.get("path", ""))).expanduser()
            if not raw_claim_path.is_absolute():
                continue
            lexical_claim_path = Path(os.path.abspath(str(raw_claim_path)))
            try:
                claim_canonical = write_intent.canonical_target(lexical_claim_path)
            except write_intent.IntentError:
                continue
            if (
                lexical_claim_path == claim_canonical.path
                and claim_canonical.path == canonical.path
                and claim_canonical.rel_path == canonical.rel_path
                and str(row.get("rel_path", "")) == canonical.rel_path
                and str(row.get("target_key", "")) == canonical.target_key
            ):
                matching_claims.append(row)
        if len(matching_claims) != 1:
            return False
        claim = matching_claims[0]
        intent_id = str(claim.get("intent_id", "")).strip()
        claim_actor = str(claim.get("actor", "")).strip()
        claim_session_hash = str(claim.get("session_hash", "")).strip()
        claim_kind = str(claim.get("claim_kind", "")).strip().casefold()
        claim_fence = int(claim.get("fencing_token") or 0)
        if (
            str(claim.get("status", "")) != "active"
            or claim_actor not in AUTOMATIC_WRITER_ACTORS
            or not intent_id
            or not claim_session_hash
            or claim_kind != "intent"
            or claim_fence <= 0
        ):
            return False

        if (
            str(claim.get("rel_path", "")) != canonical.rel_path
            or str(claim.get("target_key", "")) != canonical.target_key
        ):
            return False

        with write_intent.connect(read_only=True) as conn:
            row = conn.execute(
                "SELECT * FROM memory_write_intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            receipt = conn.execute(
                "SELECT receipt_id FROM memory_write_receipts WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            fence = conn.execute(
                "SELECT last_fence FROM memory_path_fences WHERE target_key=?",
                (canonical.target_key,),
            ).fetchone()
        if row is None or receipt is not None:
            return False
        intent = dict(row)
        if (
            str(intent.get("status", "")) != "validated"
            or str(intent.get("actor", "")) != claim_actor
            or str(intent.get("session_hash", "")) != claim_session_hash
            or str(intent.get("target_rel_path", "")) != canonical.rel_path
            or str(intent.get("target_key", "")) != canonical.target_key
            or int(intent.get("fencing_token") or 0) != claim_fence
            or fence is None
            or int(fence[0]) != claim_fence
            or str(intent.get("validation_mode", "")) != "exact"
            or not str(intent.get("validated_at", ""))
            or not str(intent.get("approved_at", ""))
            or not str(intent.get("approved_by", ""))
            or str(intent.get("approval_proposal_raw_sha256", ""))
            != str(intent.get("proposal_raw_sha256", ""))
            or str(intent.get("approval_proposal_canonical_sha256", ""))
            != str(intent.get("proposal_canonical_sha256", ""))
            or not str(intent.get("approval_ref_sha256", ""))
            or str(intent.get("approval_binding_sha256", ""))
            != write_intent._stored_approval_binding(intent)
            or str(intent.get("final_raw_sha256", ""))
            != str(intent.get("proposal_raw_sha256", ""))
            or str(intent.get("final_canonical_sha256", ""))
            != str(intent.get("proposal_canonical_sha256", ""))
            or (
                write_intent._intent_expired(intent)
                and not allow_expired_for_maintenance
            )
        ):
            return False
        if (
            write_intent.intent_requires_confirmation_capability(intent)
            and not write_intent.has_valid_confirmation_capability_approval(intent)
        ):
            return False

        base_head = str(intent.get("base_git_head", ""))
        validated_head = str(intent.get("validated_git_head", ""))
        if (
            not validated_head
            or not write_intent._git_is_ancestor(base_head, validated_head)
            or not write_intent._git_is_ancestor(validated_head, current_head)
        ):
            return False
        base_exists, base_digest = write_intent.git_target_digest_at_commit(
            base_head,
            canonical,
        )
        if (
            bool(int(intent.get("base_exists") or 0)) != base_exists
            or base_digest.raw_sha256 != str(intent.get("base_raw_sha256", ""))
            or base_digest.canonical_sha256
            != str(intent.get("base_canonical_sha256", ""))
        ):
            return False
        if base_exists and _git_tree_entry(base_head, raw_repo_path)[0] != "100644":
            return False

        live_exists, live_digest = write_intent._read_target(canonical)
        head_exists, head_digest = write_intent.git_target_digest_at_commit(
            current_head,
            canonical,
        )
        proposal_pair = (
            str(intent.get("proposal_raw_sha256", "")),
            str(intent.get("proposal_canonical_sha256", "")),
        )
        if (
            not live_exists
            or not head_exists
            or (live_digest.raw_sha256, live_digest.canonical_sha256)
            != proposal_pair
            or (head_digest.raw_sha256, head_digest.canonical_sha256)
            != proposal_pair
        ):
            return False
        if _git_tree_entry(current_head, raw_repo_path)[0] != "100644":
            return False

        repo_clean = run_command(
            [
                "git", "-C", str(REPO_ROOT), "diff", "--quiet", "HEAD",
                "--", entry.repo_path,
            ],
            timeout=30,
        )
        index_clean = run_command(
            [
                "git", "-C", str(REPO_ROOT), "diff", "--cached", "--quiet",
                "HEAD", "--", entry.repo_path,
            ],
            timeout=30,
        )
        if repo_clean.get("returncode") != 0 or index_clean.get("returncode") != 0:
            return False

        history = write_intent.git_version_chain(base_head, current_head, canonical)
        versions = history.get("versions")
        if history.get("ok") is not True or not isinstance(versions, list) or not versions:
            return False
        if any(
            not isinstance(version, dict)
            or version.get("exists") is not True
            or (
                str(version.get("raw_sha256", "")),
                str(version.get("canonical_sha256", "")),
            )
            != proposal_pair
            for version in versions
        ):
            return False
        if any(
            _git_tree_entry(str(version.get("commit", "")), raw_repo_path)[0]
            != "100644"
            for version in versions
        ):
            return False
        if bool(int(intent.get("early_commit") or 0)):
            proposal_commit = str(intent.get("proposal_commit", ""))
            version_commits = {
                str(version.get("commit", "")) for version in versions
                if isinstance(version, dict)
            }
            if (
                not proposal_commit
                or proposal_commit not in version_commits
                or not write_intent._git_is_ancestor(base_head, proposal_commit)
                or not write_intent._git_is_ancestor(proposal_commit, current_head)
                or not (
                    write_intent._git_is_ancestor(proposal_commit, validated_head)
                    or write_intent._git_is_ancestor(validated_head, proposal_commit)
                )
            ):
                return False
            proposal_exists, proposal_digest = write_intent.git_target_digest_at_commit(
                proposal_commit,
                canonical,
            )
            if (
                not proposal_exists
                or (
                    proposal_digest.raw_sha256,
                    proposal_digest.canonical_sha256,
                )
                != proposal_pair
                or _git_tree_entry(proposal_commit, raw_repo_path)[0] != "100644"
            ):
                return False
        elif str(intent.get("proposal_commit", "")):
            return False
        return True
    except (
        OSError,
        sqlite3.Error,
        TypeError,
        ValueError,
        write_intent.IntentError,
    ):
        return False


def _validated_intent_recovery_history_error(
    intent_id: str,
    *,
    current_head: str,
) -> str:
    """Fail closed when a validated retry is no longer on its bound history."""

    try:
        with write_intent.connect(read_only=True) as conn:
            row = conn.execute(
                "SELECT * FROM memory_write_intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
        if row is None:
            return "INTENT_NOT_FOUND"
        intent = dict(row)
        if str(intent.get("status", "")) != "validated":
            return ""
        if (
            str(intent.get("validation_mode", "")) not in {"exact", "format_only"}
            or not str(intent.get("validated_at", ""))
        ):
            return "STALE_BASE"
        validated_head = str(intent.get("validated_git_head", ""))
        base_head = str(intent.get("base_git_head", ""))
        if (
            not base_head
            or not validated_head
            or not current_head
            or not write_intent._git_is_ancestor(base_head, validated_head)
            or not write_intent._git_is_ancestor(validated_head, current_head)
        ):
            return "BASE_GIT_HEAD_DIVERGED"
        raw_rel_path = str(intent.get("target_rel_path", ""))
        if (
            not raw_rel_path
            or Path(raw_rel_path).is_absolute()
            or Path(raw_rel_path).as_posix() != raw_rel_path
            or unicodedata.normalize("NFC", raw_rel_path) != raw_rel_path
            or any(part in {"", ".", ".."} for part in Path(raw_rel_path).parts)
        ):
            return "STALE_BASE"
        repo_root_lexical = Path(os.path.abspath(str(REPO_ROOT)))
        vault_root_lexical = Path(os.path.abspath(str(VAULT_ROOT)))
        lexical_target = Path(os.path.abspath(str(vault_root_lexical / raw_rel_path)))
        canonical = write_intent.canonical_target(lexical_target)
        repo_path = lexical_target.relative_to(repo_root_lexical).as_posix()
        if (
            canonical.path != lexical_target
            or canonical.rel_path != raw_rel_path
            or str(intent.get("target_key", "")) != canonical.target_key
            or not repo_path_is_memory_markdown(repo_path)
        ):
            return "STALE_BASE"
        assert_governed_markdown_worktree_mode(lexical_target)
        base_exists, base_digest = write_intent.git_target_digest_at_commit(
            base_head,
            canonical,
        )
        if (
            bool(int(intent.get("base_exists") or 0)) != base_exists
            or base_digest.raw_sha256 != str(intent.get("base_raw_sha256", ""))
            or base_digest.canonical_sha256
            != str(intent.get("base_canonical_sha256", ""))
            or (base_exists and _git_tree_entry(base_head, repo_path)[0] != "100644")
        ):
            return "STALE_BASE"
        history = write_intent.git_version_chain(
            base_head,
            current_head,
            canonical,
        )
        versions = history.get("versions")
        if history.get("ok") is not True or not isinstance(versions, list):
            return "BASE_GIT_HEAD_DIVERGED"
        final_pair = (
            str(intent.get("final_raw_sha256", "")),
            str(intent.get("final_canonical_sha256", "")),
        )
        if any(
            not isinstance(version, dict)
            or version.get("exists") is not True
            or (
                str(version.get("raw_sha256", "")),
                str(version.get("canonical_sha256", "")),
            )
            != final_pair
            for version in versions
        ):
            return "STALE_BASE"
        if any(
            _git_tree_entry(str(version.get("commit", "")), repo_path)[0]
            != "100644"
            for version in versions
        ):
            return "STALE_BASE"
        is_early_commit = bool(int(intent.get("early_commit") or 0))
        if not is_early_commit:
            if versions or str(intent.get("proposal_commit", "")):
                return "STALE_BASE"
            # Ordinary freshly validated or retried writes still need the
            # current closeout to create their Git commit.  Their immutable
            # base and empty target-changing suffix are the relevant history
            # proof; requiring HEAD to contain final bytes here would reject
            # every supported non-early write before commit.
            return ""

        current_exists, current_digest = write_intent.git_target_digest_at_commit(
            current_head,
            canonical,
        )
        if (
            not current_exists
            or (current_digest.raw_sha256, current_digest.canonical_sha256)
            != final_pair
            or _git_tree_entry(current_head, repo_path)[0] != "100644"
        ):
            return "STALE_BASE"
        if is_early_commit:
            proposal_commit = str(intent.get("proposal_commit", ""))
            version_commits = {
                str(version.get("commit", "")) for version in versions
                if isinstance(version, dict)
            }
            if (
                not proposal_commit
                or not write_intent._git_is_ancestor(base_head, proposal_commit)
                or not write_intent._git_is_ancestor(
                    proposal_commit,
                    current_head,
                )
                or not (
                    write_intent._git_is_ancestor(proposal_commit, validated_head)
                    or write_intent._git_is_ancestor(validated_head, proposal_commit)
                )
                or proposal_commit not in version_commits
            ):
                return "STALE_BASE"
            proposal_exists, proposal_digest = (
                write_intent.git_target_digest_at_commit(
                    proposal_commit,
                    canonical,
                )
            )
            if (
                not proposal_exists
                or (
                    proposal_digest.raw_sha256,
                    proposal_digest.canonical_sha256,
                )
                != final_pair
                or _git_tree_entry(proposal_commit, repo_path)[0] != "100644"
            ):
                return "STALE_BASE"
        return ""
    except (
        OSError,
        sqlite3.Error,
        TypeError,
        ValueError,
        write_intent.IntentError,
    ):
        return "BASE_GIT_HEAD_DIVERGED"


def run_closeout(args: argparse.Namespace) -> dict[str, Any]:
    closeout_transaction_id = uuid.uuid4().hex
    warnings: list[str] = []
    info: list[str] = []
    index_recovery = (
        recover_generated_index_transactions()
        if not args.dry_run
        else {"ok": True, "recovered": 0, "detail": "dry_run"}
    )
    recovered_index_transactions = int(index_recovery.get("recovered") or 0)
    recovered_index_batches = int(index_recovery.get("index_batches_recovered") or 0)
    if recovered_index_batches:
        info.append(
            f"recovered {recovered_index_batches} interrupted atomic Git-index batch(es)"
        )
    if recovered_index_transactions:
        info.append(
            f"recovered {recovered_index_transactions} interrupted generated-index transaction(s)"
        )
    recovery_error = "" if index_recovery.get("ok") else "GENERATED_INDEX_RECOVERY_REQUIRED"
    git_entries, git_warnings = git_status_entries()
    warnings.extend(git_warnings)
    git_head_before, head_warnings = current_git_head()
    warnings.extend(head_warnings)
    previous_observed_head = last_observed_git_head()
    history_entries, history_warnings = git_history_entries(previous_observed_head, git_head_before)
    warnings.extend(history_warnings)
    history_preflight_error = ""
    if previous_observed_head and history_warnings:
        history_preflight_error = (
            "BASE_GIT_HEAD_DIVERGED"
            if any("not an ancestor" in warning for warning in history_warnings)
            else "GIT_HISTORY_UNAVAILABLE"
        )
    pending_history_entries = unobserved_history_entries(history_entries)
    if pending_history_entries:
        info.append(
            f"recovered {len(pending_history_entries)} unobserved memory file changes "
            "from Git history after an external/automatic commit"
        )
    observed_history_count = len(history_entries) - len(pending_history_entries)
    if observed_history_count:
        info.append(f"ignored {observed_history_count} historical memory files with matching closeout observations")
    explicit, explicit_warnings = explicit_entries(args.changed_file)
    warnings.extend(explicit_warnings)

    preflight_active_rows = (
        all_active_claim_rows(read_only=args.dry_run)
        if args.claimed_only
        else []
    )
    preflight_active_paths = {
        Path(str(row.get("path", ""))).expanduser().resolve()
        for row in preflight_active_rows
    }
    # A stale same-content observation must not hide a newly active validated
    # crash boundary.  Keep every history entry that currently aliases an
    # active claim in the ownership set; the strict lexical proof below will
    # either defer it safely or fail closed.
    claimed_history_entries = [
        entry for entry in history_entries
        if entry.path in preflight_active_paths
    ]
    by_repo_path: dict[str, GitEntry] = {
        entry.repo_path: entry
        for entry in (*pending_history_entries, *claimed_history_entries)
    }
    for entry in git_entries:
        by_repo_path[entry.repo_path] = entry
    for entry in explicit:
        by_repo_path[entry.repo_path] = entry
    discovered_entries = list(by_repo_path.values())
    session_claim_rows = (
        active_claim_rows(
            args.session_id,
            args.actor,
            read_only=args.dry_run,
        )
        if args.session_id
        else []
    )
    claim_rows = session_claim_rows if args.claimed_only else []
    claimed_paths = {Path(row["path"]).resolve() for row in claim_rows}
    excluded_entries: list[GitEntry] = []
    truly_unclaimed_entries: list[GitEntry] = []
    other_session_entries: list[GitEntry] = []
    deferred_committed_entries: list[GitEntry] = []
    foreign_active_claim_rows: list[dict[str, Any]] = []
    ownership_error = ""
    if args.claimed_only:
        active_rows = preflight_active_rows
        expected_session_hash = session_hash(args.session_id)
        foreign_active_claim_rows = [
            row
            for row in active_rows
            if (
                str(row.get("actor", "")) != args.actor
                or str(row.get("session_hash", "")) != expected_session_hash
            )
        ]
        all_claimed_paths = {Path(row["path"]).resolve() for row in active_rows}
        dirty_repo_paths = {
            entry.repo_path
            for entry in (*git_entries, *explicit)
        }
        pending_history_repo_paths = {
            entry.repo_path
            for entry in (*pending_history_entries, *claimed_history_entries)
        }
        excluded_entries = [entry for entry in discovered_entries if entry.path not in claimed_paths]
        truly_unclaimed_entries = [
            entry for entry in excluded_entries if entry.path not in all_claimed_paths
        ]
        claimed_elsewhere_entries = [
            entry for entry in excluded_entries if entry.path in all_claimed_paths
        ]
        deferred_committed_entries = [
            entry
            for entry in claimed_elsewhere_entries
            if entry.repo_path in pending_history_repo_paths
            and _other_session_committed_history_is_exact_validated(
                entry,
                claim_rows=active_rows,
                current_head=git_head_before,
                dirty_repo_paths=dirty_repo_paths,
            )
        ]
        deferred_repo_paths = {
            entry.repo_path for entry in deferred_committed_entries
        }
        other_session_entries = [
            entry
            for entry in claimed_elsewhere_entries
            if entry.repo_path not in deferred_repo_paths
        ]
        if not args.session_id:
            ownership_error = "claimed-only closeout requires --session-id"
        elif truly_unclaimed_entries:
            ownership_error = (
                "UNCLAIMED_EXTERNAL_CHANGE:"
                f"{len(truly_unclaimed_entries)};"
                "memoryctl explain UNCLAIMED_EXTERNAL_CHANGE"
            )
        elif other_session_entries:
            # INDEX is generated from the full Vault.  Committing it while a
            # different active session owns dirty Markdown would publish that
            # session's uncommitted content indirectly through the index.
            ownership_error = "GENERATED_INDEX_OTHER_SESSION_DIRTY"
        selected = {entry.path: entry for entry in discovered_entries if entry.path in claimed_paths}
        for path in claimed_paths:
            try:
                repo_path = path.relative_to(REPO_ROOT).as_posix()
            except ValueError:
                continue
            selected.setdefault(
                path,
                GitEntry(status="M" if path.exists() else "D", repo_path=repo_path, path=path),
            )
        all_entries = list(selected.values())
        if other_session_entries:
            info.append(f"excluded {len(other_session_entries)} files owned by other active sessions")
        if deferred_committed_entries:
            info.append(
                f"deferred {len(deferred_committed_entries)} exact committed file(s) "
                "owned by other validated sessions"
            )
        if foreign_active_claim_rows:
            info.append(
                f"held Git observation baseline for {len(foreign_active_claim_rows)} "
                "other active claim(s)"
            )
        if truly_unclaimed_entries:
            info.append(f"found {len(truly_unclaimed_entries)} files with no active session claim")
    else:
        all_entries = discovered_entries

    generated_index_path = (VAULT_ROOT / "INDEX.md").resolve()
    if any(
        entry.path.resolve() == generated_index_path
        for entry in (*git_entries, *explicit)
    ):
        # INDEX is a derived artifact. A closeout may generate it from an
        # initially clean file, but it must never bless or overwrite bytes
        # that were edited directly before the transaction began.
        ownership_error = "GENERATED_FILE_READ_ONLY"

    deleted_entries = [entry for entry in all_entries if entry.is_deleted]
    for entry in deleted_entries:
        warnings.append(f"deleted memory file not staged by closeout: {entry.repo_path}")

    process_entries = [
        entry
        for entry in all_entries
        if entry.exists and entry.is_memory_markdown and not entry.is_deleted
    ]
    process_files = [entry.path for entry in process_entries]

    selected_paths = {entry.path.resolve() for entry in all_entries}
    closeout_claim_rows = [
        row
        for row in session_claim_rows
        if Path(str(row.get("path", ""))).expanduser().resolve() in selected_paths
    ]
    closeout_claim_paths = {
        Path(str(row.get("path", ""))).expanduser().resolve()
        for row in closeout_claim_rows
    }
    claim_row_by_intent = {
        str(row.get("intent_id", "")).strip(): row
        for row in closeout_claim_rows
        if str(row.get("intent_id", "")).strip()
    }
    claim_path_by_intent = {
        intent_id: Path(str(row.get("path", ""))).expanduser().resolve()
        for intent_id, row in claim_row_by_intent.items()
    }
    lease_checkpoints: list[dict[str, Any]] = []
    lease_error = ""
    if args.actor in AUTOMATIC_WRITER_ACTORS:
        unleased_process_files = [
            path for path in process_files if path.resolve() not in closeout_claim_paths
        ]
        if unleased_process_files:
            lease_error = "CLAIM_HAS_NO_LIVE_LEASE"
    if not ownership_error:
        if not lease_error:
            try:
                lease_checkpoints.extend(
                    assert_current_claim_leases(
                        closeout_claim_rows,
                        actor=args.actor,
                        raw_session_id=args.session_id,
                        stage="before_checks",
                    )
                )
            except (write_intent.IntentError, OSError, sqlite3.Error, ValueError) as exc:
                lease_error = str(getattr(exc, "reason_code", "LEASE_CHECK_FAILED"))

    claim_intent_ids = sorted(
        {
            str(row.get("intent_id", "")).strip()
            for row in closeout_claim_rows
            if str(row.get("intent_id", "")).strip()
        }
    )
    intent_gate: dict[str, Any] = {
        "ok": True,
        "mode": write_intent.ENFORCEMENT_MODE,
        "blocking": False,
        "matched": [],
        "violations": [],
    }
    intent_validations: list[dict[str, Any]] = []
    intent_error = lease_error or ownership_error
    if not intent_error:
        try:
            intent_gate = write_intent.enforce_protected_changes(
                [entry.path for entry in process_entries],
                actor=args.actor,
                raw_session_id=args.session_id,
                intent_ids=claim_intent_ids,
                read_only=args.dry_run,
            )
            protected_deletions: list[str] = []
            for entry in deleted_entries:
                try:
                    if write_intent.is_protected_target(entry.path):
                        protected_deletions.append(entry.repo_path)
                except write_intent.IntentError:
                    continue
            if protected_deletions:
                violations = intent_gate.setdefault("violations", [])
                for path in protected_deletions:
                    violations.append({"path": path, "reason_code": "PROTECTED_DELETE_FORBIDDEN"})
                intent_gate["blocking"] = write_intent.ENFORCEMENT_MODE == "enforce"
                intent_gate["ok"] = not bool(intent_gate["blocking"])
                warnings.append("protected memory deletion is never staged automatically")
            if intent_gate.get("violations") and intent_gate.get("mode") == "advisory":
                warnings.append("write-intent advisory: protected changes lack a matching bound intent")
            if not intent_gate.get("ok"):
                violations = intent_gate.get("violations", [])
                first_reason = (
                    str(violations[0].get("reason_code", ""))
                    if isinstance(violations, list) and violations and isinstance(violations[0], dict)
                    else "PROTECTED_WRITE_REJECTED"
                )
                intent_error = first_reason or "PROTECTED_WRITE_REJECTED"
        except (write_intent.IntentError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
            intent_error = str(getattr(exc, "reason_code", "INTENT_GATE_FAILED"))

    if not intent_error:
        entry_paths = {entry.path.resolve() for entry in all_entries}
        matched_intent_ids = {
            str(item.get("intent_id", ""))
            for item in intent_gate.get("matched", [])
            if isinstance(item, dict) and str(item.get("intent_id", "")).strip()
        }
        if any(intent_id not in claim_path_by_intent for intent_id in matched_intent_ids):
            intent_error = "PROTECTED_WRITE_WITHOUT_MATCHING_CLAIM"
        validation_intent_ids = sorted(
            intent_id
            for intent_id, claim_path in claim_path_by_intent.items()
            if claim_path in entry_paths
        )
        if intent_error:
            validation_intent_ids = []
        for intent_id in validation_intent_ids:
            claim_path = claim_path_by_intent.get(intent_id)
            if claim_path is None:
                continue
            try:
                validation = write_intent.validate_closeout(
                    intent_id,
                    actor=args.actor,
                    raw_session_id=args.session_id,
                    target=claim_path,
                    mutate=not args.dry_run,
                )
            except (write_intent.IntentError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
                validation = {
                    "ok": False,
                    "intent_id": intent_id,
                    "reason_code": str(getattr(exc, "reason_code", "INTENT_VALIDATE_FAILED")),
                }
            intent_validations.append(validation)
            if validation.get("ok"):
                recovery_history_error = _validated_intent_recovery_history_error(
                    intent_id,
                    current_head=git_head_before,
                )
                if recovery_history_error:
                    validation = {
                        **validation,
                        "ok": False,
                        "reason_code": recovery_history_error,
                    }
                    intent_validations[-1] = validation
            if not validation.get("ok") and not intent_error:
                intent_error = str(validation.get("reason_code") or "INTENT_VALIDATE_FAILED")

    preflight_error = (
        recovery_error
        or history_preflight_error
        or ownership_error
        or intent_error
    )
    checked_commit_hashes: dict[Path, str] = {}
    checked_canonical_hashes: dict[str, str] = {}
    if process_files and not preflight_error:
        try:
            # Bind all ordinary and protected files before validation checks;
            # the isolated snapshot below must still contain these bytes.
            checked_commit_hashes, checked_canonical_hashes = bind_checked_file_hashes(
                process_files
            )
        except write_intent.IntentError as exc:
            preflight_error = exc.reason_code
        except OSError:
            preflight_error = "CHECK_INPUT_BIND_FAILED"

    if not preflight_error:
        for validation in intent_validations:
            if not validation.get("ok") or validation.get("completed"):
                continue
            intent_id = str(validation.get("intent_id", ""))
            claim_path = claim_path_by_intent.get(intent_id)
            final_canonical = str(validation.get("final_canonical_sha256", "")).strip().lower()
            if claim_path is None or not final_canonical:
                continue
            checked_key = os.path.normcase(str(claim_path.resolve()))
            if checked_canonical_hashes.get(checked_key) != final_canonical:
                preflight_error = "VALIDATED_CONTENT_CHANGED"
                break

    generated_index_snapshot: GeneratedIndexSnapshot | None = None
    if process_files and not preflight_error and not args.dry_run:
        try:
            generated_index_snapshot = capture_generated_index_snapshot()
        except OSError:
            preflight_error = "GENERATED_INDEX_BASE_UNSAFE"

    if args.dry_run:
        info.append("dry_run: no index refresh, zvec refresh, or commit will be written")
    if git_entries:
        info.append(
            "git reports dirty Agent Memory files; if some are historical, review dry-run output before committing"
        )

    check_step = run_check(process_files, args) if process_files and not preflight_error else {
        "ok": not bool(preflight_error),
        "skipped": True,
        "detail": preflight_error or "no_changed_files",
    }
    advisories = list(check_step.get("advisories", [])) if isinstance(check_step.get("advisories"), list) else []
    reconcile_findings, reconcile_warnings = (
        postwrite_reconcile(process_entries, args)
        if args.dry_run and not preflight_error else ([], [])
    )
    warnings.extend(reconcile_warnings)
    index_binding: dict[str, str] | None = None
    if process_files and not preflight_error and not args.dry_run:
        if generated_index_snapshot is None or not re.fullmatch(r"[0-9a-f]{40,64}", git_head_before):
            preflight_error = "GENERATED_INDEX_TRANSACTION_INVALID"
        else:
            try:
                full_vault_digest = full_vault_input_projection_sha256()
                if full_vault_digest != full_vault_input_projection_sha256():
                    raise OSError("GENERATED_INDEX_INPUT_UNSTABLE")
            except OSError as exc:
                preflight_error = str(exc)
                full_vault_digest = ""
        if not preflight_error and generated_index_snapshot is not None:
            index_binding = generated_index_transaction_binding(
                transaction_id=closeout_transaction_id,
                actor=args.actor,
                raw_session_id=args.session_id,
                git_head=git_head_before,
                index_base_sha256=generated_index_snapshot.raw_sha256,
                full_vault_inputs_sha256=full_vault_digest,
                lease_checkpoints=lease_checkpoints,
            )
            try:
                _register_generated_index_closeout_transaction(
                    transaction_binding=index_binding,
                )
            except GeneratedIndexCapabilityError as exc:
                preflight_error = str(exc)
    if process_files and not preflight_error and args.dry_run:
        index_step = {"ok": True, "skipped": True, "detail": "dry_run"}
    elif process_files and not preflight_error and index_binding is not None:
        index_step = run_index(args, transaction_binding=index_binding)
    else:
        index_step = {
            "ok": not bool(preflight_error),
            "skipped": True,
            "detail": preflight_error or "no_changed_files",
        }
    generated_index_files: list[Path] = []
    generated_index = index_step.get("generated_index")
    if (
        not args.dry_run
        and index_step.get("ok")
        and isinstance(generated_index, dict)
        and generated_index.get("changed")
    ):
        generated_path = Path(str(generated_index.get("path", ""))).expanduser()
        try:
            generated_path = generated_path.resolve()
            if generated_path != (VAULT_ROOT / "INDEX.md").resolve():
                raise OSError("generated index path mismatch")
            generated_hashes, generated_canonical = bind_checked_file_hashes([generated_path])
            expected_digest = str(generated_index.get("sha256", "")).strip().lower()
            if generated_hashes.get(generated_path) != expected_digest:
                raise OSError("generated index hash mismatch")
            checked_commit_hashes.update(generated_hashes)
            checked_canonical_hashes.update(generated_canonical)
            generated_index_files.append(generated_path)
        except OSError:
            index_step["ok"] = False
            index_step["detail"] = "GENERATED_INDEX_BIND_FAILED"
    temporal_step = temporal_graph_health(args, index_step) if process_files and not preflight_error else {"ok": not bool(preflight_error), "skipped": True, "detail": preflight_error or "no_changed_files"}
    zvec_step = run_zvec(process_files, args) if process_files and not preflight_error else {"ok": not bool(preflight_error), "skipped": True, "detail": preflight_error or "no_changed_files"}
    agent_step = run_agent_evolution(process_files, args) if process_files and not preflight_error else {"ok": not bool(preflight_error), "skipped": True, "detail": preflight_error or "no_changed_files"}
    # An applied proposal necessarily precedes its derived-index refresh.
    # Reconcile after both lexical and semantic refresh, so normal writes do
    # not treat that expected intermediate state as a broken public search.
    # This also checks newly indexed peers instead of comparing stale rows.
    # Findings still block publication and use the existing INDEX rollback.
    if not args.dry_run and not preflight_error and index_step.get("ok") and zvec_step.get("ok"):
        reconcile_findings, reconcile_warnings = postwrite_reconcile(process_entries, args)
        warnings.extend(reconcile_warnings)
    audit_step = run_audit_autorun(args) if not preflight_error else {"ok": False, "skipped": True, "detail": preflight_error}
    audit_payload = audit_step.get("audit_payload") if isinstance(audit_step.get("audit_payload"), dict) else {}
    if audit_payload:
        audit_status = str(audit_payload.get("status", ""))
        findings_count = int(audit_payload.get("findings_count") or 0)
        if audit_status == "ran":
            info.append(
                f"audit ran via closeout; findings={findings_count}; report={audit_payload.get('report_path', '')}"
            )
        elif audit_status in {"dry_run_due", "dry_run_recent"}:
            due_text = "would run" if audit_payload.get("would_run") else "recent"
            info.append(f"audit dry-run check: {due_text}; report={audit_payload.get('report_path', '')}")
        else:
            info.append(f"audit check: {audit_status}; report={audit_payload.get('report_path', '')}")
    elif not audit_step.get("ok") and not audit_step.get("skipped"):
        detail = str(audit_step.get("stderr", "")).strip() or str(audit_step.get("detail", "")).strip()
        info.append(f"audit autorun failed: {detail[:300]}")

    blocking_reconcile = bool(reconcile_findings)
    reconcile_unavailable = any(
        finding.get("reason") == "reconcile_search_unhealthy"
        for finding in reconcile_findings
    )
    step_failed = bool(preflight_error) or reconcile_unavailable or not all(
        bool(step.get("ok"))
        for step in (check_step, index_step, temporal_step, zvec_step, agent_step)
    )
    status = "ok"
    if step_failed:
        status = "error"
    elif blocking_reconcile or warnings:
        status = "warning"

    commit_step: dict[str, Any]
    early_commit_paths = {
        claim_path_by_intent[str(validation.get("intent_id", ""))].resolve()
        for validation in intent_validations
        if validation.get("ok")
        and validation.get("early_commit")
        and str(validation.get("intent_id", "")) in claim_path_by_intent
    }
    commit_process_files = [
        path for path in process_files if path.resolve() not in early_commit_paths
    ]
    for generated_path in generated_index_files:
        if generated_path.resolve() not in {path.resolve() for path in commit_process_files}:
            commit_process_files.append(generated_path)
    if status == "error":
        commit_step = {"ok": False, "skipped": True, "detail": "skipped_due_to_error"}
    elif blocking_reconcile and not args.commit_warnings:
        commit_step = {"ok": True, "skipped": True, "detail": "skipped_due_to_merge_required"}
    elif status == "warning" and not args.commit_warnings:
        commit_step = {"ok": True, "skipped": True, "detail": "skipped_due_to_warning"}
    else:
        if args.commit and not args.dry_run and commit_process_files:
            try:
                lease_checkpoints.extend(
                    assert_current_claim_leases(
                        closeout_claim_rows,
                        actor=args.actor,
                        raw_session_id=args.session_id,
                        stage="before_git_commit",
                    )
                )
            except (write_intent.IntentError, OSError, sqlite3.Error, ValueError) as exc:
                intent_error = str(getattr(exc, "reason_code", "LEASE_CHECK_FAILED"))
                status = "error"
        if status == "error":
            commit_step = {
                "ok": False,
                "skipped": True,
                "detail": intent_error or "LEASE_CHECK_FAILED",
            }
        else:
            commit_step = commit_files(
                commit_process_files,
                args,
                expected_raw_sha256=checked_commit_hashes,
                expected_head=git_head_before,
                expected_full_vault_inputs_sha256=(
                    index_binding["full_vault_inputs_sha256"]
                    if index_binding is not None
                    else ""
                ),
            )
            if not commit_step.get("ok"):
                status = "error"

    generated_index_transaction: dict[str, Any] = {
        "ok": True,
        "skipped": True,
        "detail": "generated_index_unchanged",
    }
    if index_binding is not None and not args.dry_run:
        generated_index_transaction = resolve_generated_index_transaction(
            transaction_binding=index_binding,
            index_step=index_step,
            snapshot=generated_index_snapshot,
            commit_step=commit_step,
            git_head_before=git_head_before,
        )
        if generated_index_transaction.get("rolled_back"):
            if isinstance(generated_index, dict):
                generated_index["rolled_back"] = True
            generated_index_files.clear()
        if not generated_index_transaction.get("ok"):
            status = "error"
            index_step["ok"] = False
            if not str(index_step.get("detail", "")).strip():
                index_step["detail"] = "GENERATED_INDEX_TRANSACTION_FAILED"

    intent_receipts: list[dict[str, Any]] = []
    intent_step: dict[str, Any] = {
        "ok": not bool(intent_error),
        "skipped": not bool(intent_validations),
        "detail": intent_error or ("no_bound_intents" if not intent_validations else "validated"),
    }
    atomic_closeout: dict[str, Any] = {
        "items": [],
        "receipts": [],
        "observed": 0,
        "completed": 0,
        "count": 0,
        "idempotent": False,
    }
    if status == "ok" and not args.dry_run and intent_validations:
        batch_items: list[dict[str, Any]] = []
        for validation in intent_validations:
            if not validation.get("ok"):
                continue
            intent_id = str(validation.get("intent_id", "")).strip()
            claim_row = claim_row_by_intent.get(intent_id)
            claim_path = claim_path_by_intent.get(intent_id)
            if claim_row is None or claim_path is None:
                intent_error = "PROTECTED_WRITE_WITHOUT_MATCHING_CLAIM"
                intent_step = {"ok": False, "skipped": False, "detail": intent_error}
                status = "error"
                break
            durable_commit = str(
                validation.get("proposal_commit")
                if validation.get("early_commit")
                else commit_step.get("commit")
            ).strip()
            if not durable_commit:
                intent_error = "PROTECTED_WRITE_NOT_DURABLE"
                intent_step = {"ok": False, "skipped": False, "detail": intent_error}
                status = "error"
                break
            try:
                fencing_token = int(claim_row.get("fencing_token") or 0)
            except (TypeError, ValueError):
                fencing_token = 0
            file_sha256 = str(checked_commit_hashes.get(claim_path.resolve(), "")).strip().lower()
            if fencing_token <= 0 or not file_sha256:
                intent_error = "CLAIM_BINDING_MISMATCH"
                intent_step = {"ok": False, "skipped": False, "detail": intent_error}
                status = "error"
                break
            canonical = write_intent.canonical_target(claim_path)
            try:
                durable_repo_path = canonical.path.relative_to(REPO_ROOT).as_posix()
                durable_mode, _durable_oid = _git_tree_entry(
                    durable_commit,
                    durable_repo_path,
                )
            except (OSError, ValueError):
                durable_mode = ""
            if durable_mode != "100644":
                intent_error = "GOVERNED_MARKDOWN_MODE_INVALID"
                intent_step = {"ok": False, "skipped": False, "detail": intent_error}
                status = "error"
                break
            batch_items.append(
                {
                    "intent_id": intent_id,
                    "fencing_token": fencing_token,
                    "target": str(claim_path),
                    "git_commit": durable_commit,
                    "file_sha256": file_sha256,
                    "rel_path": canonical.rel_path,
                    "detail_code": (
                        "EARLY_COMMIT_RECOVERED"
                        if validation.get("early_commit")
                        else "CLOSEOUT_COMMIT"
                    ),
                }
            )
        if status == "ok" and batch_items:
            try:
                lease_checkpoints.extend(
                    assert_current_claim_leases(
                        closeout_claim_rows,
                        actor=args.actor,
                        raw_session_id=args.session_id,
                        stage="before_atomic_finalize",
                    )
                )
                atomic_closeout = finalize_closeout_batch(
                    batch_items,
                    actor=args.actor,
                    raw_session_id=args.session_id,
                )
            except (write_intent.IntentError, OSError, sqlite3.Error, subprocess.SubprocessError, ValueError) as exc:
                intent_error = str(getattr(exc, "reason_code", "INTENT_RECEIPT_FAILED"))
                intent_step = {"ok": False, "skipped": False, "detail": intent_error}
                status = "error"
            else:
                intent_receipts = list(atomic_closeout.get("receipts", []))
                incidents = atomic_closeout.get("incidents", [])
                if not atomic_closeout.get("ok", True) or incidents:
                    intent_error = "POST_FINALIZE_CONTENT_DRIFT"
                    intent_step = {
                        "ok": False,
                        "skipped": False,
                        "detail": intent_error,
                        "incident_count": len(incidents) if isinstance(incidents, list) else 1,
                    }
                    status = "error"
                elif (
                    int(atomic_closeout.get("count") or 0) != len(batch_items)
                    or any(str(receipt.get("outcome", "")) != "completed" for receipt in intent_receipts)
                ):
                    intent_error = "RECEIPT_OUTCOME_CONFLICT"
                    intent_step = {"ok": False, "skipped": False, "detail": intent_error}
                    status = "error"
        if status == "ok":
            intent_step = {
                "ok": True,
                "skipped": False,
                "detail": (
                    f"validated={len(intent_validations)} receipts={len(intent_receipts)} "
                    f"atomic_batch={int(atomic_closeout.get('count') or 0)}"
                ),
            }

    intent_process_paths = {
        claim_path_by_intent[str(validation.get("intent_id", ""))].resolve()
        for validation in intent_validations
        if validation.get("ok")
        and str(validation.get("intent_id", "")) in claim_path_by_intent
    }
    legacy_process_files = [
        path for path in process_files if path.resolve() not in intent_process_paths
    ]
    observation_files = list(legacy_process_files)
    for generated_path in generated_index_files:
        if generated_path.resolve() not in {path.resolve() for path in observation_files}:
            observation_files.append(generated_path)
    claim_step: dict[str, Any] = {"ok": True, "skipped": True, "detail": "ownership_not_enabled"}
    observation_step: dict[str, Any] = {"ok": True, "skipped": True, "detail": "not_completed"}
    if status == "ok" and not args.dry_run and commit_step.get("ok"):
        try:
            legacy_observed = record_file_observations(
                args.session_id,
                args.actor,
                observation_files,
            )
            atomic_observed = int(atomic_closeout.get("observed") or 0)
            observation_step = {
                "ok": True,
                "skipped": False,
                "detail": f"atomic={atomic_observed} legacy={legacy_observed}",
            }
        except (OSError, sqlite3.Error, ValueError) as exc:
            observation_step = {"ok": False, "skipped": False, "detail": str(exc)}
            status = "error"
    if args.claimed_only:
        claim_step = {"ok": True, "skipped": True, "detail": "claims_retained"}
        if status == "ok" and not args.dry_run and commit_step.get("ok"):
            legacy_completed = complete_claim_paths(
                args.session_id,
                args.actor,
                legacy_process_files,
            )
            atomic_completed = int(atomic_closeout.get("completed") or 0)
            claim_step = {
                "ok": True,
                "skipped": False,
                "detail": f"atomic={atomic_completed} legacy={legacy_completed}",
            }

    full_vault_step: dict[str, Any] = {
        "ok": True,
        "skipped": index_binding is None or args.dry_run,
        "detail": "no_generated_index_transaction" if index_binding is None else "stable",
    }
    if index_binding is not None and not args.dry_run:
        try:
            assert_full_vault_input_projection(index_binding["full_vault_inputs_sha256"])
        except OSError:
            full_vault_step = {
                "ok": False,
                "skipped": False,
                "detail": "GENERATED_INDEX_INPUT_CHANGED",
            }
            status = "error"
        else:
            full_vault_step = {"ok": True, "skipped": False, "detail": "stable"}

    git_head_after, after_warnings = current_git_head()
    warnings.extend(after_warnings)
    final_git_entries, final_git_warnings = git_status_entries()
    warnings.extend(final_git_warnings)
    dirty_paths = {entry.path for entry in final_git_entries}
    unclaimed_history = unobserved_history_entries(
        [entry for entry in pending_history_entries if entry.path in {item.path for item in excluded_entries}]
    )
    can_advance_baseline = (
        status == "ok" and not step_failed and intent_step.get("ok")
        and observation_step.get("ok") and not blocking_reconcile
        and not deferred_committed_entries
        and not foreign_active_claim_rows
        and not deleted_entries and not unclaimed_history and bool(git_head_before)
        and (not dirty_paths or bool(commit_step.get("commit")) or commit_step.get("detail") == "nothing_staged")
    )
    would_observe_through = (
        str(commit_step.get("commit")) if can_advance_baseline and commit_step.get("commit")
        else (git_head_before if can_advance_baseline else previous_observed_head)
    )
    git_observed_through = previous_observed_head if args.dry_run else would_observe_through
    processed_report_files: list[Path] = []
    processed_report_keys: set[Path] = set()
    for processed_path in [*process_files, *generated_index_files]:
        resolved = processed_path.resolve()
        if resolved in processed_report_keys:
            continue
        processed_report_keys.add(resolved)
        processed_report_files.append(processed_path)

    payload = {
        "time": utc_now(),
        "run_id": closeout_transaction_id,
        "actor": args.actor,
        "trigger": args.trigger,
        "session_hash": session_hash(args.session_id),
        "ownership_mode": "claimed_only" if args.claimed_only else "global",
        "ownership_error": ownership_error,
        "intent_error": intent_error,
        "write_intent_gate": intent_gate,
        "write_intent_validations": intent_validations,
        "write_intent_receipts": intent_receipts,
        "closeout_incidents": atomic_closeout.get("incidents", []),
        "lease_checkpoints": lease_checkpoints,
        "cwd": str(Path.cwd()),
        "mode": "closeout",
        "git_previous_observed_head": previous_observed_head,
        "git_head_before": git_head_before,
        "git_head_after": git_head_after,
        "git_observed_through": git_observed_through,
        "git_would_observe_through": would_observe_through,
        "changed_files": [entry.repo_path for entry in all_entries],
        "claimed_files": sorted(row["rel_path"] for row in claim_rows),
        "unclaimed_files": sorted(entry.repo_path for entry in truly_unclaimed_entries),
        "other_session_files": sorted(entry.repo_path for entry in other_session_entries),
        "processed_files": [relative_to_vault(path) for path in processed_report_files],
        "deleted_files_skipped": [entry.repo_path for entry in deleted_entries],
        "reconcile_findings": reconcile_findings,
        "info": info,
        "warnings": warnings,
        "advisories": advisories,
        "steps": {
            "generated_index_recovery": short_step(index_recovery),
            "check": short_step(check_step),
            "sqlite": short_step(index_step),
            "generated_index_transaction": short_step(generated_index_transaction),
            "full_vault_snapshot": short_step(full_vault_step),
            "temporal_facts": short_step(temporal_step),
            "zvec": short_step(zvec_step),
            "agent_evolution": short_step(agent_step),
            "audit": short_step(audit_step),
            "commit": short_step(commit_step),
            "write_intents": short_step(intent_step),
            "observations": short_step(observation_step),
            "claims": short_step(claim_step),
        },
        "commit": commit_step.get("commit", "skipped"),
        "status": status,
    }
    if not args.dry_run:
        append_log(privacy_safe_log_payload(payload))
    return payload


def run_initial_generated_index_migration(
    args: argparse.Namespace,
    *,
    maintenance_capability: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Publish the first machine-generated INDEX during a locked v4 upgrade.

    This deliberately is not a second index writer.  It uses the same private
    closeout transaction/capability, byte-bound isolated Git commit, and
    recovery protocol as an ordinary closeout.  The narrower entry point
    exists only because the runtime is not ready yet and there may be no dirty
    source Markdown to make ``run_closeout`` schedule an index refresh.

    A migration must never absorb user work.  Any dirty governed Markdown,
    including a hand-edited INDEX, closes the gate before a capability is
    registered or any bytes are changed.
    """

    capability = maintenance_capability if isinstance(maintenance_capability, dict) else {}
    token = str(capability.get("token", ""))
    try:
        issuer_pid = int(capability.get("issuer_pid") or 0)
    except (TypeError, ValueError):
        issuer_pid = 0
    try:
        transition = assert_runtime_maintenance_capability(
            "generated-index-closeout",
            token=token,
            issuer_pid=issuer_pid,
        )
    except RuntimeTransitionError:
        transition = {}
    if (
        getattr(args, "actor", "") != "migration"
        or getattr(args, "trigger", "") != "migration"
        or getattr(args, "commit", False) is not True
        or getattr(args, "dry_run", False)
        or transition.get("maintenance_capability") is not True
    ):
        return {
            "ok": False,
            "status": "error",
            "mode": "initial_generated_index_migration",
            "reason_code": "GENERATED_INDEX_MIGRATION_AUTHORITY_INVALID",
            "changed_files": [],
            "processed_files": [],
            "steps": {},
            "commit": "skipped",
            "warnings": [],
            "info": [],
        }

    recovery = recover_generated_index_transactions()
    if not recovery.get("ok"):
        return {
            "ok": False,
            "status": "error",
            "mode": "initial_generated_index_migration",
            "reason_code": "GENERATED_INDEX_RECOVERY_REQUIRED",
            "changed_files": [],
            "processed_files": [],
            "steps": {"generated_index_recovery": short_step(recovery)},
            "commit": "skipped",
            "warnings": [],
            "info": [],
        }

    git_operation = generated_index_git_operation_fence()
    if not git_operation.get("ok"):
        return {
            "ok": False,
            "status": "blocked",
            "mode": "initial_generated_index_migration",
            "reason_code": str(
                git_operation.get("reason_code")
                or "GENERATED_INDEX_GIT_STATE_UNAVAILABLE"
            ),
            "changed_files": [],
            "processed_files": [],
            "steps": {
                "generated_index_recovery": short_step(recovery),
                "git_operation": git_operation,
            },
            "commit": "skipped",
            "warnings": [],
            "info": [],
        }

    dirty_paths, status_warnings = full_vault_markdown_git_status()
    if status_warnings:
        return {
            "ok": False,
            "status": "error",
            "mode": "initial_generated_index_migration",
            "reason_code": "GENERATED_INDEX_GIT_STATUS_UNAVAILABLE",
            "changed_files": [],
            "processed_files": [],
            "steps": {"generated_index_recovery": short_step(recovery)},
            "commit": "skipped",
            "warnings": status_warnings,
            "info": [],
        }
    if dirty_paths:
        return {
            "ok": False,
            "status": "blocked",
            "mode": "initial_generated_index_migration",
            "reason_code": "GENERATED_INDEX_MIGRATION_DIRTY_MEMORY",
            "changed_files": dirty_paths,
            "processed_files": [],
            "steps": {"generated_index_recovery": short_step(recovery)},
            "commit": "skipped",
            "warnings": [],
            "info": [],
        }

    git_head_before, head_warnings = current_git_head()
    if head_warnings or re.fullmatch(r"[0-9a-f]{40,64}", git_head_before) is None:
        return {
            "ok": False,
            "status": "error",
            "mode": "initial_generated_index_migration",
            "reason_code": "GENERATED_INDEX_GIT_EVIDENCE_UNAVAILABLE",
            "changed_files": [],
            "processed_files": [],
            "steps": {"generated_index_recovery": short_step(recovery)},
            "commit": "skipped",
            "warnings": head_warnings,
            "info": [],
        }

    try:
        snapshot = capture_generated_index_snapshot()
        full_vault_digest = full_vault_input_projection_sha256()
        if full_vault_digest != full_vault_input_projection_sha256():
            raise OSError("GENERATED_INDEX_INPUT_UNSTABLE")
        committed_projection = git_commit_full_vault_inputs_sha256(
            REPO_ROOT,
            VAULT_ROOT,
            git_head_before,
        )
        index_repo_path = snapshot.path.relative_to(REPO_ROOT).as_posix()
        committed_index_sha256 = git_commit_file_sha256(
            REPO_ROOT,
            git_head_before,
            index_repo_path,
        )
        if committed_projection != full_vault_digest:
            raise OSError("GENERATED_INDEX_MIGRATION_HEAD_PROJECTION_MISMATCH")
        if committed_index_sha256 != snapshot.raw_sha256:
            raise OSError("GENERATED_INDEX_MIGRATION_HEAD_INDEX_MISMATCH")
    except (GeneratedIndexCapabilityError, OSError) as exc:
        reason = str(exc).strip().upper()
        return {
            "ok": False,
            "status": "error",
            "mode": "initial_generated_index_migration",
            "reason_code": (
                reason if re.fullmatch(r"[A-Z0-9_]{1,128}", reason)
                else "GENERATED_INDEX_BASE_UNSAFE"
            ),
            "changed_files": [],
            "processed_files": [],
            "steps": {"generated_index_recovery": short_step(recovery)},
            "commit": "skipped",
            "warnings": [],
            "info": [],
        }

    binding = generated_index_transaction_binding(
        transaction_id=uuid.uuid4().hex,
        actor=args.actor,
        raw_session_id="",
        git_head=git_head_before,
        index_base_sha256=snapshot.raw_sha256,
        full_vault_inputs_sha256=full_vault_digest,
        lease_checkpoints=[],
    )
    try:
        _register_generated_index_closeout_transaction(
            transaction_binding=binding,
        )
    except GeneratedIndexCapabilityError as exc:
        return {
            "ok": False,
            "status": "error",
            "mode": "initial_generated_index_migration",
            "reason_code": str(exc),
            "changed_files": [],
            "processed_files": [],
            "steps": {"generated_index_recovery": short_step(recovery)},
            "commit": "skipped",
            "warnings": [],
            "info": [],
        }

    index_step: dict[str, Any]
    try:
        index_step = run_index(
            args,
            transaction_binding=binding,
            maintenance_environment={
                "AGENT_MEMORY_MIGRATION_CAPABILITY": token,
                "AGENT_MEMORY_MIGRATION_ISSUER_PID": str(issuer_pid),
            },
        )
    except (OSError, subprocess.SubprocessError, GeneratedIndexCapabilityError) as exc:
        index_step = {
            "ok": False,
            "detail": str(exc) or "GENERATED_INDEX_SYNC_FAILED",
            "generated_index": {},
        }
    generated = index_step.get("generated_index")
    generated_path = (VAULT_ROOT / "INDEX.md").resolve()
    generated_digest = ""
    generated_changed = False
    if isinstance(generated, dict):
        generated_digest = str(generated.get("sha256", "")).strip().lower()
        generated_changed = bool(generated.get("changed"))
    if index_step.get("ok"):
        try:
            returned_path = Path(str(generated.get("path", ""))).expanduser().resolve()
            current_digest = hashlib.sha256(generated_path.read_bytes()).hexdigest()
            if (
                returned_path != generated_path
                or re.fullmatch(r"[0-9a-f]{64}", generated_digest) is None
                or current_digest != generated_digest
                or generated_changed != (generated_digest != snapshot.raw_sha256)
            ):
                raise OSError("GENERATED_INDEX_BIND_FAILED")
        except (AttributeError, OSError):
            index_step = {
                **index_step,
                "ok": False,
                "detail": "GENERATED_INDEX_BIND_FAILED",
            }

    if index_step.get("ok"):
        commit_step = commit_files(
            [generated_path] if generated_changed else [],
            args,
            expected_raw_sha256=(
                {generated_path: generated_digest} if generated_changed else {}
            ),
            expected_head=git_head_before,
            expected_full_vault_inputs_sha256=full_vault_digest,
        )
    else:
        commit_step = {
            "ok": False,
            "skipped": True,
            "detail": "skipped_due_to_index_failure",
        }
    transaction_step = resolve_generated_index_transaction(
        transaction_binding=binding,
        index_step=index_step,
        snapshot=snapshot,
        commit_step=commit_step,
        git_head_before=git_head_before,
    )
    ok = bool(index_step.get("ok") and commit_step.get("ok") and transaction_step.get("ok"))
    git_head_after, after_warnings = current_git_head()
    payload = {
        "ok": ok,
        "status": "ok" if ok else "error",
        "mode": "initial_generated_index_migration",
        "reason_code": "" if ok else str(
            transaction_step.get("detail")
            or commit_step.get("detail")
            or index_step.get("detail")
            or "GENERATED_INDEX_MIGRATION_FAILED"
        ),
        "actor": args.actor,
        "trigger": args.trigger,
        "git_head_before": git_head_before,
        "git_head_after": git_head_after,
        "changed_files": [],
        "processed_files": ["INDEX.md"] if generated_changed else [],
        "steps": {
            "generated_index_recovery": short_step(recovery),
            "sqlite": short_step(index_step),
            "generated_index_transaction": short_step(transaction_step),
            "commit": short_step(commit_step),
        },
        "commit": commit_step.get("commit", "skipped"),
        "warnings": after_warnings,
        "info": [
            "generated INDEX migration used the closeout capability and an exact Git commit"
        ],
    }
    append_log(privacy_safe_log_payload(payload))
    return payload


def plan_initial_generated_index_migration() -> dict[str, Any]:
    """Read-only early gate for installer plan/apply before any mutation."""

    index_path = VAULT_ROOT / "INDEX.md"
    if not VAULT_ROOT.exists():
        return {
            "ok": True,
            "status": "bootstrap_pending",
            "mode": "generated_index_migration_plan",
            "blocking": False,
            "dirty_markdown": [],
        }
    if VAULT_ROOT.is_symlink() or not VAULT_ROOT.is_dir():
        return {
            "ok": False,
            "status": "blocked",
            "mode": "generated_index_migration_plan",
            "reason_code": "GENERATED_INDEX_VAULT_UNSAFE",
            "blocking": True,
            "dirty_markdown": [],
        }
    if not index_path.exists():
        if next(VAULT_ROOT.iterdir(), None) is None:
            return {
                "ok": True,
                "status": "bootstrap_pending",
                "mode": "generated_index_migration_plan",
                "blocking": False,
                "dirty_markdown": [],
            }
        return {
            "ok": False,
            "status": "blocked",
            "mode": "generated_index_migration_plan",
            "reason_code": "GENERATED_INDEX_TARGET_MISSING",
            "blocking": True,
            "dirty_markdown": [],
        }
    git_operation = generated_index_git_operation_fence()
    if not git_operation.get("ok"):
        return {
            "ok": False,
            "status": "blocked",
            "mode": "generated_index_migration_plan",
            "reason_code": str(
                git_operation.get("reason_code")
                or "GENERATED_INDEX_GIT_STATE_UNAVAILABLE"
            ),
            "blocking": True,
            "dirty_markdown": [],
            "git_operation": git_operation,
        }
    recovery_plan = generated_index_recovery_plan()
    if not recovery_plan.get("ok"):
        return {
            "ok": False,
            "status": "blocked",
            "mode": "generated_index_migration_plan",
            "reason_code": str(
                recovery_plan.get("reason_code")
                or "GENERATED_INDEX_RECOVERY_UNAVAILABLE"
            ),
            "blocking": True,
            "dirty_markdown": [],
            "generated_index_recovery": recovery_plan,
        }
    dirty, warnings = full_vault_markdown_git_status()
    if warnings:
        return {
            "ok": False,
            "status": "error",
            "mode": "generated_index_migration_plan",
            "reason_code": "GENERATED_INDEX_GIT_STATUS_UNAVAILABLE",
            "blocking": True,
            "dirty_markdown": [],
            "warnings": warnings,
        }
    if dirty:
        return {
            "ok": False,
            "status": "blocked",
            "mode": "generated_index_migration_plan",
            "reason_code": "GENERATED_INDEX_MIGRATION_DIRTY_MEMORY",
            "blocking": True,
            "dirty_markdown": dirty,
        }
    head, head_warnings = current_git_head()
    try:
        snapshot = capture_generated_index_snapshot()
        working_projection = full_vault_input_projection_sha256()
        committed_projection = git_commit_full_vault_inputs_sha256(
            REPO_ROOT,
            VAULT_ROOT,
            head,
        )
        repo_path = snapshot.path.relative_to(REPO_ROOT).as_posix()
        committed_index = git_commit_file_sha256(REPO_ROOT, head, repo_path)
    except (GeneratedIndexCapabilityError, OSError, ValueError):
        return {
            "ok": False,
            "status": "blocked",
            "mode": "generated_index_migration_plan",
            "reason_code": "GENERATED_INDEX_MIGRATION_HEAD_MISMATCH",
            "blocking": True,
            "dirty_markdown": [],
            "warnings": head_warnings,
        }
    exact = (
        re.fullmatch(r"[0-9a-f]{40,64}", head) is not None
        and committed_projection == working_projection
        and committed_index == snapshot.raw_sha256
    )
    return {
        "ok": exact,
        "status": "ready" if exact else "blocked",
        "mode": "generated_index_migration_plan",
        "reason_code": "" if exact else "GENERATED_INDEX_MIGRATION_HEAD_MISMATCH",
        "blocking": not exact,
        "dirty_markdown": [],
        "git_head": head,
        "full_vault_inputs_sha256": working_projection,
        "index_sha256": snapshot.raw_sha256,
        "warnings": head_warnings,
    }


def print_human(payload: dict[str, Any]) -> None:
    if payload.get("mode") == "prewrite":
        print(f"mode=prewrite status={payload['status']}")
        print(f"recommended_action={payload['recommended_action']}")
        for index, row in enumerate(payload.get("candidates", [])[:5], 1):
            print(f"{index}. {row.get('rel_path', '')}")
            print(f"   title: {row.get('title', '')}")
            print(f"   sources: {','.join(row.get('sources', []))}")
            print(f"   summary: {str(row.get('summary', ''))[:220]}")
        for warning in payload.get("warnings", []):
            print(f"warning: {warning}")
        return

    print(f"mode=closeout status={payload['status']}")
    print(f"changed_files={len(payload.get('changed_files', []))}")
    print(f"processed_files={len(payload.get('processed_files', []))}")
    for item in payload.get("processed_files", []):
        print(f"processed: {item}")
    for finding in payload.get("reconcile_findings", []):
        print(f"reconcile: {finding.get('action')} {finding.get('rel_path')}")
        for candidate in finding.get("candidates", []):
            print(f"  candidate: {candidate.get('rel_path')} similarity={candidate.get('similarity')}")
    for name, step in payload.get("steps", {}).items():
        skipped = " skipped" if step.get("skipped") else ""
        print(f"{name}={'ok' if step.get('ok') else 'failed'}{skipped} {step.get('detail', '')}")
    if payload.get("commit") and payload.get("commit") != "skipped":
        print(f"commit={payload['commit']}")
    for warning in payload.get("warnings", []):
        print(f"warning: {warning}")
    for item in payload.get("info", []):
        print(f"info: {item}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Unified closeout for the local Agent Memory system."
    )
    parser.add_argument("--prewrite", help="Run reconcile before writing a new memory; does not modify files.")
    parser.add_argument("--create-intent", action="store_true", help="Create a content-bound write intent after safety and reconcile pass.")
    parser.add_argument("--target-file", default="", help="Canonical memory target for --create-intent.")
    parser.add_argument("--proposal-file", default="", help="UTF-8 proposal outside the vault for --create-intent.")
    parser.add_argument(
        "--source-class",
        choices=sorted(SOURCE_CLASSES),
        default="unknown",
        help="Origin class for the proposed memory. Unknown sources require confirmation.",
    )
    parser.add_argument(
        "--knowledge-kind",
        choices=sorted(KNOWLEDGE_KINDS),
        default="fact",
        help="Whether the proposal is a fact, preference, rule, inference, or hypothesis.",
    )
    parser.add_argument("--asserted-by", default="", help="Bounded identity label for who asserted the proposal.")
    parser.add_argument("--evidence-ref", default="", help="Evidence reference; only its hash is included in safety output.")
    parser.add_argument("--changed-file", action="append", default=[], help="Explicit changed memory file. Repeatable.")
    parser.add_argument("--limit", type=int, default=8, help="Search candidates for reconcile.")
    parser.add_argument(
        "--current-project",
        default="",
        help="Current project_id for prewrite and postwrite search boundaries.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--dry-run", action="store_true", help="Inspect only; do not refresh indexes, write logs, or commit.")
    parser.add_argument("--commit", action="store_true", help="After successful closeout, commit only processed memory files.")
    parser.add_argument("--commit-warnings", action="store_true", help="Allow commit when non-blocking warnings exist.")
    parser.add_argument("--message", default="", help="Custom scoped commit message.")
    parser.add_argument("--actor", default=os.environ.get("MEMORY_ACTOR", "codex"), help="Agent that initiated closeout.")
    parser.add_argument(
        "--trigger",
        default="manual",
        choices=("manual", "stop-hook", "session-end", "launchd", "migration", "test"),
        help="How this closeout run was triggered.",
    )
    parser.add_argument("--session-id", default="", help="Optional session id; only a one-way hash is logged.")
    parser.add_argument(
        "--claimed-only",
        action="store_true",
        help="Process only files actively claimed by this actor and session.",
    )
    parser.add_argument(
        "--skip-zvec",
        action=argparse.BooleanOptionalAction,
        default=env_value("RUN_VECTOR_INDEX_AFTER_CLOSEOUT", "false").strip().casefold()
        not in {"1", "true", "yes", "on"},
        help="Skip Zvec refresh (defaults from semantic_retrieval.run_vector_index_after_closeout).",
    )
    parser.add_argument("--no-zvec", action="store_true", help="Skip Zvec during prewrite/postwrite reconcile search.")
    parser.add_argument("--zvec-timeout", type=int, default=240, help="Seconds before Zvec refresh times out.")
    parser.add_argument("--reconcile-all", action="store_true", help="Run postwrite reconcile on all changed files, not only new files.")
    parser.add_argument("--merge-threshold", type=float, default=0.42, help="Similarity threshold for MERGE_REQUIRED.")
    parser.add_argument("--merge-coverage-threshold", type=float, default=0.35, help="Coverage threshold for MERGE_REQUIRED.")
    parser.add_argument("--semantic-merge-threshold", type=float, default=0.32, help="Semantic distance threshold for postwrite MERGE_REQUIRED.")
    parser.add_argument("--lock-timeout", type=float, default=15.0, help="Seconds to wait for another closeout process.")
    parser.add_argument("--skip-audit", action="store_true", help="Compatibility flag; weekly audit is LaunchAgent-owned.")
    parser.add_argument("--audit-interval-days", type=int, default=7, help="Compatibility option; no closeout audit is scheduled.")
    parser.add_argument("--audit-limit", type=int, default=50, help="Compatibility option; no closeout audit is scheduled.")
    parser.add_argument("--audit-stale-days", type=int, default=120, help="Compatibility option; no closeout audit is scheduled.")
    parser.add_argument("--audit-open-loop-threshold", type=int, default=4, help="Compatibility option; no closeout audit is scheduled.")
    parser.add_argument("--audit-timeout", type=int, default=180, help="Compatibility option; no closeout audit is scheduled.")
    parser.add_argument(
        "--initial-generated-index-migration",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--generated-index-migration-plan",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()
    args.actor = normalized_actor(args.actor)
    if args.actor not in CLOSEOUT_ACTORS:
        parser.error(f"unsupported closeout actor: {args.actor}")
    if args.actor == "ailu":
        if args.session_id:
            parser.error("ailu session id must be supplied through AGENT_MEMORY_SESSION_ID")
        args.session_id = os.environ.get("AGENT_MEMORY_SESSION_ID", "").strip()
        if not args.session_id:
            parser.error("ailu closeout requires AGENT_MEMORY_SESSION_ID")
    if args.initial_generated_index_migration:
        if (
            args.actor != "migration"
            or args.trigger != "migration"
            or not args.commit
            or args.dry_run
            or bool(args.prewrite)
            or args.create_intent
            or args.claimed_only
            or bool(args.changed_file)
        ):
            parser.error(
                "initial generated INDEX migration requires migration actor/trigger, "
                "--commit, and no write/prewrite/claim inputs"
            )
        args.skip_zvec = True
        args.no_zvec = True
    if args.generated_index_migration_plan:
        if (
            args.actor != "migration"
            or args.trigger != "migration"
            or args.initial_generated_index_migration
            or args.commit
            or args.dry_run
            or bool(args.prewrite)
            or args.create_intent
            or args.claimed_only
            or bool(args.changed_file)
        ):
            parser.error("generated INDEX migration plan accepts migration read-only inputs only")
    args.limit = max(args.limit, 1)
    args.audit_interval_days = max(args.audit_interval_days, 1)
    args.audit_limit = max(args.audit_limit, 1)
    args.audit_stale_days = max(args.audit_stale_days, 1)
    args.audit_open_loop_threshold = max(args.audit_open_loop_threshold, 1)
    if not SEMANTIC_ENABLED:
        args.no_zvec = True
        args.skip_zvec = True
    if args.prewrite:
        args.dry_run = True
    return args


def main() -> int:
    args = parse_args()
    if args.generated_index_migration_plan:
        payload = plan_initial_generated_index_migration()
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print_human(payload)
        return 0 if payload.get("ok") else 2
    try:
        if not args.initial_generated_index_migration:
            assert_runtime_ready("closeout")
    except RuntimeTransitionError:
        payload = {
            "time": utc_now(),
            "mode": "prewrite" if args.prewrite else "closeout",
            "status": "error",
            "reason_code": "RUNTIME_TRANSITION_INCOMPLETE",
            "warnings": [],
            "advisories": [],
            "steps": {},
        }
    else:
        if args.prewrite:
            payload = run_prewrite(args)
        else:
            try:
                with closeout_lock(args.lock_timeout):
                    payload = (
                        run_initial_generated_index_migration(
                            args,
                            maintenance_capability={
                                "token": os.environ.get(
                                    "AGENT_MEMORY_MIGRATION_CAPABILITY",
                                    "",
                                ),
                                "issuer_pid": os.environ.get(
                                    "AGENT_MEMORY_MIGRATION_ISSUER_PID",
                                    "0",
                                ),
                            },
                        )
                        if args.initial_generated_index_migration
                        else run_closeout(args)
                    )
            except TimeoutError as exc:
                payload = {
                    "time": utc_now(), "mode": "closeout", "status": "error",
                    "warnings": [], "advisories": [], "error": str(exc), "steps": {},
                }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_human(payload)
    if payload.get("status") == "error":
        return 2
    if payload.get("status") == "warning":
        return 1
    if payload.get("status") == "blocked":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
