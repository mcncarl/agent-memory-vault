#!/usr/bin/env python3
"""Write-intent and immutable receipt protocol for protected Agent Memory files.

Markdown remains the source of truth.  The private mode-0600 SQLite database
may store a bounded canonical proposal snapshot solely for scoped mismatch
diffs; public intent output and immutable receipts never return that text.
"""
from __future__ import annotations

import argparse
import datetime as dt
import difflib
import fnmatch
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from agent_memory_env import env_value, expand_path, load_config
import agent_memory_safety as memory_safety
from agent_memory_state import StateSecurityError, secure_sqlite_connect


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = expand_path(env_value("ROOT", str(RUNTIME_ROOT / "templates" / "vault")))
GIT_ROOT = expand_path(env_value("GIT_ROOT", str(VAULT_ROOT)))
STATE_DB = expand_path(env_value("STATE_DB", "$HOME/.config/agent-memory/state.sqlite"))


def _configured_write_intents() -> dict[str, Any]:
    payload = load_config().get("write_intents", {})
    return payload if isinstance(payload, dict) else {}


_WRITE_INTENT_CONFIG = _configured_write_intents()
_configured_paths = _WRITE_INTENT_CONFIG.get("protected_paths", ())
if isinstance(_configured_paths, str):
    _configured_paths = (_configured_paths,)
elif not isinstance(_configured_paths, (list, tuple)):
    _configured_paths = ()

PROTECTED_PATHS: tuple[str, ...] = tuple(str(item) for item in _configured_paths if str(item).strip())
INTENTS_ENABLED = bool(_WRITE_INTENT_CONFIG.get("enabled", False))
_configured_enforcement = str(_WRITE_INTENT_CONFIG.get("enforcement", "off")).strip().lower()
ENFORCEMENT_MODE = _configured_enforcement if INTENTS_ENABLED else "off"
MAX_PROPOSAL_BYTES = int(_WRITE_INTENT_CONFIG.get("max_proposal_bytes", 2 * 1024 * 1024))
MAX_TARGET_BYTES = int(_WRITE_INTENT_CONFIG.get("max_target_bytes", 8 * 1024 * 1024))
MAX_SNAPSHOT_BYTES = int(_WRITE_INTENT_CONFIG.get("max_snapshot_bytes", 256 * 1024))
DEFAULT_TTL_HOURS = float(_WRITE_INTENT_CONFIG.get("ttl_hours", 24))
MAX_DIFF_LINES = 120
MAX_DIFF_CHARS = 16 * 1024

ACTIVE_STATUSES = ("pending", "approved", "bound", "validated")
TERMINAL_STATUSES = ("completed", "failed", "cancelled", "expired")
VALID_ENFORCEMENT_MODES = {"off", "advisory", "enforce"}
EMPTY_RAW_SHA256 = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True)
class CanonicalTarget:
    path: Path
    rel_path: str
    target_key: str


@dataclass(frozen=True)
class ContentDigest:
    raw_sha256: str
    canonical_sha256: str
    size_bytes: int
    text: str


class IntentError(ValueError):
    """A bounded protocol failure safe to show to an operator."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def parse_time(value: str) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def session_hash(raw_session_id: str) -> str:
    value = raw_session_id.strip()
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16] if value else ""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonicalize_text(text: str) -> str:
    """Normalize representation-only differences, not Markdown structure."""
    if text.startswith("\ufeff"):
        text = text[1:]
    text = unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n"))
    # Markdown uses two trailing spaces as a hard line break.  They are content,
    # not formatting noise, so canonicalization must preserve them exactly.
    return text.rstrip("\n") + ("\n" if text else "")


def content_hashes(payload: bytes, *, max_bytes: int | None = None) -> ContentDigest:
    if max_bytes is not None and len(payload) > max_bytes:
        raise IntentError("CONTENT_TOO_LARGE", f"content exceeds the {max_bytes}-byte limit")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise IntentError("CONTENT_NOT_UTF8", "content must be valid UTF-8") from exc
    canonical = canonicalize_text(text).encode("utf-8")
    return ContentDigest(
        raw_sha256=sha256_bytes(payload),
        canonical_sha256=sha256_bytes(canonical),
        size_bytes=len(payload),
        text=text,
    )


def _absolute_lexical(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expandvars(str(path.expanduser()))))


def _reject_symlinks(path: Path, *, stop_at: Path | None = None) -> None:
    """Reject any existing symlink component between stop_at and path."""
    absolute = _absolute_lexical(path)
    if stop_at is None:
        current = Path(absolute.anchor)
        parts = absolute.parts[1:]
    else:
        stop = _absolute_lexical(stop_at)
        try:
            relative = absolute.relative_to(stop)
        except ValueError as exc:
            raise IntentError("PATH_OUTSIDE_BOUNDARY", f"path is outside boundary: {absolute}") from exc
        current = stop
        if current.is_symlink():
            raise IntentError("SYMLINK_FORBIDDEN", f"symlink path component is not allowed: {current}")
        parts = relative.parts
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise IntentError("SYMLINK_FORBIDDEN", f"symlink path component is not allowed: {current}")


def canonical_target(raw_target: str | Path) -> CanonicalTarget:
    configured_root = _absolute_lexical(VAULT_ROOT)
    if not configured_root.is_dir():
        raise IntentError("VAULT_MISSING", f"memory vault does not exist: {configured_root}")
    if configured_root.is_symlink():
        raise IntentError("SYMLINK_FORBIDDEN", f"memory vault root cannot be a symlink: {configured_root}")
    # macOS exposes /var as a system symlink to /private/var.  Resolve the
    # configured root before walking target components so temporary vaults do
    # not fail solely because of that operating-system alias.
    root_lexical = configured_root.resolve(strict=True)
    raw_path = Path(raw_target).expanduser()
    if not raw_path.is_absolute():
        candidate = _absolute_lexical(root_lexical / raw_path)
    else:
        raw_absolute = _absolute_lexical(raw_path)
        relative: Path | None = None
        for root_alias in (configured_root, root_lexical):
            try:
                relative = raw_absolute.relative_to(root_alias)
                break
            except ValueError:
                continue
        candidate = _absolute_lexical(root_lexical / relative) if relative is not None else raw_absolute
    # Walk the un-resolved path beneath the already-resolved vault root first.
    # Otherwise a child symlink can resolve outside and be misreported merely as
    # an out-of-bound path, losing the stronger symlink safety signal.
    _reject_symlinks(candidate, stop_at=root_lexical)
    try:
        lexical_relative = candidate.relative_to(root_lexical)
    except ValueError as exc:
        raise IntentError("TARGET_OUTSIDE_VAULT", f"target is outside the memory vault: {candidate}") from exc

    root_resolved = root_lexical.resolve(strict=True)
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise IntentError("TARGET_OUTSIDE_VAULT", f"target resolves outside the memory vault: {candidate}") from exc
    if candidate.suffix.casefold() != ".md":
        raise IntentError("TARGET_NOT_MARKDOWN", f"target is not Markdown: {candidate}")

    rel_path = unicodedata.normalize("NFC", lexical_relative.as_posix())
    if not rel_path or rel_path in {".", ".."}:
        raise IntentError("TARGET_INVALID", "target must name a Markdown file inside the vault")
    return CanonicalTarget(path=candidate, rel_path=rel_path, target_key=rel_path.casefold())


def read_proposal_file(raw_path: str | Path, *, max_bytes: int | None = None) -> ContentDigest:
    path = _absolute_lexical(Path(raw_path))
    if path.is_symlink():
        raise IntentError("SYMLINK_FORBIDDEN", f"proposal file cannot be a symlink: {path}")
    path = path.resolve(strict=False)
    if not path.is_file():
        raise IntentError("PROPOSAL_MISSING", f"proposal file does not exist: {path}")
    root = _absolute_lexical(VAULT_ROOT).resolve(strict=True)
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError:
        pass
    else:
        raise IntentError("PROPOSAL_INSIDE_VAULT", "proposal file must be outside the memory vault")
    limit = MAX_PROPOSAL_BYTES if max_bytes is None else max_bytes
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise IntentError("PROPOSAL_UNREADABLE", f"cannot inspect proposal file: {path}") from exc
    if size > limit:
        raise IntentError("PROPOSAL_TOO_LARGE", f"proposal exceeds the {limit}-byte limit")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise IntentError("PROPOSAL_UNREADABLE", f"cannot read proposal file: {path}") from exc
    return content_hashes(payload, max_bytes=limit)


def _read_target(target: CanonicalTarget) -> tuple[bool, ContentDigest]:
    if not target.path.exists():
        return False, content_hashes(b"")
    if not target.path.is_file():
        raise IntentError("TARGET_NOT_FILE", f"target is not a regular file: {target.path}")
    _reject_symlinks(target.path, stop_at=_absolute_lexical(VAULT_ROOT).resolve(strict=True))
    try:
        payload = target.path.read_bytes()
    except OSError as exc:
        raise IntentError("TARGET_UNREADABLE", f"cannot read target: {target.rel_path}") from exc
    return True, content_hashes(payload, max_bytes=MAX_TARGET_BYTES)


def _bounded_label(value: str, *, limit: int = 120) -> str:
    return " ".join(value.strip().split())[:limit]


def _safe_code(value: str, *, limit: int = 160, default: str = "") -> str:
    code = str(value or default).strip()
    if not code:
        return ""
    if len(code) > limit or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", code) is None:
        raise IntentError("AUDIT_CODE_INVALID", "reason and detail codes may contain only safe code characters")
    return code


def _snapshot_text(canonical_text: str) -> tuple[str, bool]:
    encoded = canonical_text.encode("utf-8")
    if len(encoded) <= MAX_SNAPSHOT_BYTES:
        return canonical_text, False
    bounded = encoded[:MAX_SNAPSHOT_BYTES]
    while bounded:
        try:
            return bounded.decode("utf-8"), True
        except UnicodeDecodeError:
            bounded = bounded[:-1]
    return "", True


def _line_count(text: str) -> int:
    return len(text.splitlines())


def _redact_private_diff(diff_text: str) -> str:
    redacted: list[str] = []
    for line in diff_text.splitlines():
        detection_text = memory_safety.normalize_for_detection(line)
        if any(pattern.search(detection_text) for pattern in memory_safety.SECRET_PATTERNS):
            prefix = line[:1] if line[:1] in {"+", "-", " "} else ""
            redacted.append(prefix + "[redacted-secret-line]")
        else:
            redacted.append(line)
    return "\n".join(redacted)


def _bounded_mismatch(
    intent: dict[str, Any],
    final: ContentDigest,
    *,
    include_private_diff: bool = False,
) -> dict[str, Any]:
    proposed = str(intent.get("proposal_canonical_snapshot", ""))
    actual = canonicalize_text(final.text)
    actual_snapshot, actual_snapshot_truncated = _snapshot_text(actual)
    raw_lines = list(
        difflib.unified_diff(
            proposed.splitlines(),
            actual_snapshot.splitlines(),
            fromfile="proposal",
            tofile="target",
            lineterm="",
            n=3,
        )
    )
    selected: list[str] = []
    char_count = 0
    diff_truncated = False
    for line in raw_lines:
        needed = len(line) + (1 if selected else 0)
        if len(selected) >= MAX_DIFF_LINES or char_count + needed > MAX_DIFF_CHARS:
            diff_truncated = True
            break
        selected.append(line)
        char_count += needed
    diff_text = "\n".join(selected)
    result = {
        "diff_sha256": sha256_bytes(diff_text.encode("utf-8")),
        "diff_line_count": len(selected),
        "proposal_canonical_sha256": str(intent["proposal_canonical_sha256"]),
        "target_canonical_sha256": final.canonical_sha256,
        "proposal_line_count": int(intent.get("proposal_line_count", 0)),
        "target_line_count": _line_count(actual),
        "proposal_snapshot_truncated": bool(intent.get("proposal_snapshot_truncated", 0)),
        "target_snapshot_truncated": actual_snapshot_truncated,
        "diff_truncated": diff_truncated
        or bool(intent.get("proposal_snapshot_truncated", 0))
        or actual_snapshot_truncated,
    }
    if include_private_diff:
        result["diff"] = _redact_private_diff(diff_text)
        result["private_diff"] = True
    return result


def connect(state_db: Path | None = None, *, read_only: bool = False) -> sqlite3.Connection:
    db_path = Path(state_db or STATE_DB).expanduser()
    try:
        conn = secure_sqlite_connect(
            db_path,
            timeout=10,
            create=not read_only,
            read_only=read_only,
            row_factory=sqlite3.Row,
            pragmas=("PRAGMA busy_timeout=10000", "PRAGMA foreign_keys=ON"),
        )
    except StateSecurityError as exc:
        raise IntentError("STATE_DB_PERMISSION_FAILED", "cannot restrict the intent state database to mode 0600") from exc
    if not read_only:
        ensure_schema(conn)
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, name: str, declaration: str) -> None:
    columns = {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}
    if name not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_write_intents (
          intent_id TEXT PRIMARY KEY,
          schema_version INTEGER NOT NULL DEFAULT 2,
          actor TEXT NOT NULL,
          session_hash TEXT NOT NULL,
          target_rel_path TEXT NOT NULL,
          target_key TEXT NOT NULL,
          base_exists INTEGER NOT NULL,
          base_raw_sha256 TEXT NOT NULL,
          base_canonical_sha256 TEXT NOT NULL,
          base_git_head TEXT NOT NULL,
          read_token TEXT NOT NULL DEFAULT '',
          scope_app_id TEXT NOT NULL DEFAULT '',
          scope_project_id TEXT NOT NULL DEFAULT '',
          proposal_raw_sha256 TEXT NOT NULL,
          proposal_canonical_sha256 TEXT NOT NULL,
          proposal_size_bytes INTEGER NOT NULL,
          proposal_path_sha256 TEXT NOT NULL,
          proposal_canonical_snapshot TEXT NOT NULL DEFAULT '',
          proposal_snapshot_truncated INTEGER NOT NULL DEFAULT 0,
          proposal_line_count INTEGER NOT NULL DEFAULT 0,
          source_class TEXT NOT NULL DEFAULT '',
          knowledge_kind TEXT NOT NULL DEFAULT '',
          asserted_by TEXT NOT NULL DEFAULT '',
          evidence_ref_sha256 TEXT NOT NULL DEFAULT '',
          safety_audit_id INTEGER NOT NULL DEFAULT 0,
          safety_run_id TEXT NOT NULL DEFAULT '',
          safety_decision TEXT NOT NULL DEFAULT '',
          safety_reason_code TEXT NOT NULL DEFAULT '',
          safety_input_sha256 TEXT NOT NULL DEFAULT '',
          safety_input_length INTEGER NOT NULL DEFAULT 0,
          reconcile_action TEXT NOT NULL DEFAULT '',
          intent_system_enabled INTEGER NOT NULL DEFAULT 0,
          effective_enforcement TEXT NOT NULL DEFAULT 'off',
          approval_required INTEGER NOT NULL DEFAULT 1,
          approved_at TEXT,
          approved_by TEXT NOT NULL DEFAULT '',
          approval_proposal_raw_sha256 TEXT NOT NULL DEFAULT '',
          approval_proposal_canonical_sha256 TEXT NOT NULL DEFAULT '',
          approval_ref_sha256 TEXT NOT NULL DEFAULT '',
          approval_binding_sha256 TEXT NOT NULL DEFAULT '',
          bound_at TEXT,
          claim_ref_sha256 TEXT NOT NULL DEFAULT '',
          bound_base_raw_sha256 TEXT NOT NULL DEFAULT '',
          validated_at TEXT,
          validation_mode TEXT NOT NULL DEFAULT '',
          final_raw_sha256 TEXT NOT NULL DEFAULT '',
          final_canonical_sha256 TEXT NOT NULL DEFAULT '',
          validated_git_head TEXT NOT NULL DEFAULT '',
          early_commit INTEGER NOT NULL DEFAULT 0,
          proposal_commit TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL,
          reason_code TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          CHECK (status IN ('pending','approved','bound','validated','completed','failed','cancelled','expired'))
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_write_receipts (
          receipt_id TEXT PRIMARY KEY,
          intent_id TEXT NOT NULL UNIQUE,
          actor TEXT NOT NULL,
          session_hash TEXT NOT NULL,
          target_rel_path TEXT NOT NULL,
          target_key TEXT NOT NULL,
          outcome TEXT NOT NULL,
          reason_code TEXT NOT NULL,
          validation_mode TEXT NOT NULL DEFAULT '',
          base_raw_sha256 TEXT NOT NULL,
          proposal_raw_sha256 TEXT NOT NULL,
          proposal_canonical_sha256 TEXT NOT NULL,
          final_raw_sha256 TEXT NOT NULL DEFAULT '',
          final_canonical_sha256 TEXT NOT NULL DEFAULT '',
          base_git_head TEXT NOT NULL,
          validated_git_head TEXT NOT NULL DEFAULT '',
          git_commit TEXT NOT NULL DEFAULT '',
          early_commit INTEGER NOT NULL DEFAULT 0,
          proposal_commit TEXT NOT NULL DEFAULT '',
          approval_binding_sha256 TEXT NOT NULL DEFAULT '',
          approval_ref_sha256 TEXT NOT NULL DEFAULT '',
          source_class TEXT NOT NULL DEFAULT '',
          knowledge_kind TEXT NOT NULL DEFAULT '',
          asserted_by_sha256 TEXT NOT NULL DEFAULT '',
          safety_decision TEXT NOT NULL DEFAULT '',
          safety_reason_code TEXT NOT NULL DEFAULT '',
          safety_input_sha256 TEXT NOT NULL DEFAULT '',
          safety_input_length INTEGER NOT NULL DEFAULT 0,
          evidence_ref_sha256 TEXT NOT NULL DEFAULT '',
          detail_code TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          FOREIGN KEY(intent_id) REFERENCES memory_write_intents(intent_id)
        )
        """
    )
    intent_migrations = {
        "proposal_canonical_snapshot": "TEXT NOT NULL DEFAULT ''",
        "proposal_snapshot_truncated": "INTEGER NOT NULL DEFAULT 0",
        "proposal_line_count": "INTEGER NOT NULL DEFAULT 0",
        "safety_audit_id": "INTEGER NOT NULL DEFAULT 0",
        "safety_run_id": "TEXT NOT NULL DEFAULT ''",
        "safety_decision": "TEXT NOT NULL DEFAULT ''",
        "safety_reason_code": "TEXT NOT NULL DEFAULT ''",
        "safety_input_sha256": "TEXT NOT NULL DEFAULT ''",
        "safety_input_length": "INTEGER NOT NULL DEFAULT 0",
        "intent_system_enabled": "INTEGER NOT NULL DEFAULT 0",
        "effective_enforcement": "TEXT NOT NULL DEFAULT 'off'",
        "approval_proposal_raw_sha256": "TEXT NOT NULL DEFAULT ''",
        "approval_proposal_canonical_sha256": "TEXT NOT NULL DEFAULT ''",
        "approval_ref_sha256": "TEXT NOT NULL DEFAULT ''",
        "read_token": "TEXT NOT NULL DEFAULT ''",
        "scope_app_id": "TEXT NOT NULL DEFAULT ''",
        "scope_project_id": "TEXT NOT NULL DEFAULT ''",
    }
    for name, declaration in intent_migrations.items():
        _ensure_column(conn, "memory_write_intents", name, declaration)
    receipt_migrations = {
        "approval_binding_sha256": "TEXT NOT NULL DEFAULT ''",
        "approval_ref_sha256": "TEXT NOT NULL DEFAULT ''",
        "source_class": "TEXT NOT NULL DEFAULT ''",
        "knowledge_kind": "TEXT NOT NULL DEFAULT ''",
        "asserted_by_sha256": "TEXT NOT NULL DEFAULT ''",
        "safety_decision": "TEXT NOT NULL DEFAULT ''",
        "safety_reason_code": "TEXT NOT NULL DEFAULT ''",
        "safety_input_sha256": "TEXT NOT NULL DEFAULT ''",
        "safety_input_length": "INTEGER NOT NULL DEFAULT 0",
        "evidence_ref_sha256": "TEXT NOT NULL DEFAULT ''",
    }
    for name, declaration in receipt_migrations.items():
        _ensure_column(conn, "memory_write_receipts", name, declaration)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_safety_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          run_id TEXT NOT NULL UNIQUE,
          actor TEXT NOT NULL,
          session_hash TEXT NOT NULL DEFAULT '',
          trigger TEXT NOT NULL,
          decision TEXT NOT NULL,
          reason_code TEXT NOT NULL,
          source_class TEXT NOT NULL,
          knowledge_kind TEXT NOT NULL,
          asserted_by TEXT NOT NULL DEFAULT '',
          input_sha256 TEXT NOT NULL,
          input_length INTEGER NOT NULL,
          evidence_ref_sha256 TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_write_intents_active_target "
        "ON memory_write_intents(target_key) "
        "WHERE status IN ('pending','approved','bound','validated')"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_memory_write_intents_session "
        "ON memory_write_intents(actor, session_hash, status)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_memory_write_receipts_target "
        "ON memory_write_receipts(target_key, created_at)"
    )
    conn.commit()


def _row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return {key: row[key] for key in row.keys()} if row is not None else None


_PRIVATE_INTENT_FIELDS = {"proposal_canonical_snapshot"}


def _public_intent(intent: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in intent.items() if key not in _PRIVATE_INTENT_FIELDS}


def _fetch_intent(conn: sqlite3.Connection, intent_id: str) -> dict[str, Any] | None:
    cursor = conn.execute("SELECT * FROM memory_write_intents WHERE intent_id=?", (intent_id,))
    row = cursor.fetchone()
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        return _row_dict(row)
    names = [str(item[0]) for item in cursor.description or ()]
    return dict(zip(names, row, strict=False))


def _record_safety_assessment(
    conn: sqlite3.Connection,
    assessment: dict[str, Any],
    *,
    run_id: str,
    actor: str,
    hashed_session: str,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO memory_safety_log (
          run_id, actor, session_hash, trigger, decision, reason_code,
          source_class, knowledge_kind, asserted_by, input_sha256,
          input_length, evidence_ref_sha256, created_at
        ) VALUES (?, ?, ?, 'write_intent_proposal', ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            actor,
            hashed_session,
            str(assessment["decision"]),
            str(assessment["reason_code"]),
            str(assessment["source_class"]),
            str(assessment["knowledge_kind"]),
            sha256_bytes(str(assessment.get("asserted_by", "")).encode("utf-8")) if assessment.get("asserted_by") else "",
            str(assessment["input_sha256"]),
            int(assessment["input_length"]),
            str(assessment.get("evidence_ref_sha256", "")),
            utc_now(),
        ),
    )
    return int(cursor.lastrowid)


def _run_git(*args: str, binary: bool = False) -> subprocess.CompletedProcess[Any]:
    command = ["git", "-C", str(_absolute_lexical(GIT_ROOT)), *args]
    if binary:
        return subprocess.run(command, capture_output=True, text=False, timeout=30, check=False)
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )


def current_git_head(*, required: bool = True) -> str:
    result = _run_git("rev-parse", "HEAD")
    head = str(result.stdout).strip() if result.returncode == 0 else ""
    if required and not head:
        raise IntentError("GIT_HEAD_UNAVAILABLE", "cannot resolve the Git baseline for the memory vault")
    return head


def _repo_rel_path(target: CanonicalTarget) -> str:
    git_root = _absolute_lexical(GIT_ROOT).resolve(strict=True)
    try:
        return target.path.resolve(strict=False).relative_to(git_root).as_posix()
    except ValueError as exc:
        raise IntentError("TARGET_OUTSIDE_GIT_ROOT", "memory target is outside the configured Git root") from exc


def _git_blob(commit: str, repo_rel_path: str) -> bytes | None:
    result = _run_git("show", f"{commit}:{repo_rel_path}", binary=True)
    if result.returncode != 0:
        return None
    return bytes(result.stdout)


def _git_path_matches_worktree(commit: str, repo_rel_path: str) -> bool:
    """Compare Git and worktree content while honoring checkout filters."""
    return _run_git("diff", "--quiet", commit, "--", repo_rel_path).returncode == 0


def _git_is_ancestor(base: str, head: str) -> bool:
    if base == head:
        return True
    return _run_git("merge-base", "--is-ancestor", base, head).returncode == 0


def git_version_chain(base_head: str, head: str, target: CanonicalTarget) -> dict[str, Any]:
    repo_rel_path = _repo_rel_path(target)
    if not base_head or not head or not _git_is_ancestor(base_head, head):
        return {"ok": False, "reason_code": "BASE_GIT_HEAD_DIVERGED", "versions": []}
    if base_head == head:
        return {"ok": True, "reason_code": "", "versions": []}
    result = _run_git("rev-list", "--reverse", f"{base_head}..{head}", "--", repo_rel_path)
    if result.returncode != 0:
        return {"ok": False, "reason_code": "GIT_HISTORY_UNAVAILABLE", "versions": []}
    versions: list[dict[str, Any]] = []
    for commit in str(result.stdout).splitlines():
        commit = commit.strip()
        if not commit:
            continue
        blob = _git_blob(commit, repo_rel_path)
        if blob is None:
            versions.append({"commit": commit, "exists": False, "raw_sha256": "", "canonical_sha256": ""})
            continue
        try:
            digest = content_hashes(blob, max_bytes=MAX_TARGET_BYTES)
        except IntentError:
            versions.append({"commit": commit, "exists": True, "raw_sha256": sha256_bytes(blob), "canonical_sha256": ""})
            continue
        versions.append(
            {
                "commit": commit,
                "exists": True,
                "raw_sha256": digest.raw_sha256,
                "canonical_sha256": digest.canonical_sha256,
            }
        )
    return {"ok": True, "reason_code": "", "versions": versions}


def _approval_binding(
    intent: dict[str, Any],
    approved_by: str,
    proposal_raw_sha256: str,
    proposal_canonical_sha256: str,
    approval_ref_sha256: str,
) -> str:
    fields = {
        "intent_id": str(intent["intent_id"]),
        "actor": str(intent["actor"]),
        "session_hash": str(intent["session_hash"]),
        "target_key": str(intent["target_key"]),
        "base_raw_sha256": str(intent["base_raw_sha256"]),
        "proposal_raw_sha256": proposal_raw_sha256,
        "proposal_canonical_sha256": proposal_canonical_sha256,
        "approved_by": _bounded_label(approved_by),
        "approval_ref_sha256": approval_ref_sha256,
    }
    encoded = json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(encoded)


def _stored_approval_binding(intent: dict[str, Any]) -> str:
    return _approval_binding(
        intent,
        str(intent.get("approved_by", "")),
        str(intent.get("approval_proposal_raw_sha256", "")),
        str(intent.get("approval_proposal_canonical_sha256", "")),
        str(intent.get("approval_ref_sha256", "")),
    )


def _authorize_intent(intent: dict[str, Any], *, actor: str, raw_session_id: str) -> None:
    hashed = session_hash(raw_session_id)
    if not hashed:
        raise IntentError("SESSION_REQUIRED", "session id is required")
    if str(intent["actor"]) != actor or str(intent["session_hash"]) != hashed:
        raise IntentError("INTENT_SESSION_MISMATCH", "intent belongs to a different actor or session")


def _expire_active_rows(
    conn: sqlite3.Connection,
    *,
    current: dt.datetime,
    target_key: str | None = None,
) -> int:
    query = "SELECT * FROM memory_write_intents WHERE status IN ('pending','approved','bound','validated')"
    params: list[Any] = []
    if target_key is not None:
        query += " AND target_key=?"
        params.append(target_key)
    rows = [_row_dict(row) for row in conn.execute(query, params).fetchall()]
    timestamp = current.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat()
    applied = 0
    for intent in rows:
        if intent is None or not _intent_expired(intent, current):
            continue
        receipt_id = hashlib.sha256(f"write-receipt:{intent['intent_id']}".encode("utf-8")).hexdigest()[:32]
        conn.execute(
            """
            INSERT OR IGNORE INTO memory_write_receipts (
              receipt_id, intent_id, actor, session_hash, target_rel_path, target_key,
              outcome, reason_code, validation_mode, base_raw_sha256,
              proposal_raw_sha256, proposal_canonical_sha256, final_raw_sha256,
              final_canonical_sha256, base_git_head, validated_git_head, git_commit,
              early_commit, proposal_commit, approval_binding_sha256,
              approval_ref_sha256, source_class, knowledge_kind,
              asserted_by_sha256, safety_decision, safety_reason_code,
              safety_input_sha256, safety_input_length, evidence_ref_sha256,
              detail_code, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                receipt_id, intent["intent_id"], intent["actor"], intent["session_hash"],
                intent["target_rel_path"], intent["target_key"], "expired", "INTENT_EXPIRED",
                intent["validation_mode"], intent["base_raw_sha256"], intent["proposal_raw_sha256"],
                intent["proposal_canonical_sha256"], intent["final_raw_sha256"],
                intent["final_canonical_sha256"], intent["base_git_head"],
                intent["validated_git_head"], "", intent["early_commit"],
                intent["proposal_commit"], intent["approval_binding_sha256"],
                intent["approval_ref_sha256"], intent["source_class"], intent["knowledge_kind"],
                sha256_bytes(str(intent["asserted_by"]).encode("utf-8")) if intent["asserted_by"] else "",
                intent["safety_decision"], intent["safety_reason_code"],
                intent["safety_input_sha256"], intent["safety_input_length"],
                intent["evidence_ref_sha256"], "TTL_ELAPSED", timestamp,
            ),
        )
        cursor = conn.execute(
            "UPDATE memory_write_intents SET status='expired', reason_code='INTENT_EXPIRED', updated_at=? "
            "WHERE intent_id=? AND status IN ('pending','approved','bound','validated')",
            (timestamp, intent["intent_id"]),
        )
        applied += int(cursor.rowcount)
    return applied


def create_intent(
    *,
    actor: str,
    raw_session_id: str,
    target: str | Path,
    proposal_file: str | Path | None = None,
    proposal_text: str | None = None,
    approval_required: bool = True,
    ttl_hours: float | None = None,
    source_class: str = "",
    knowledge_kind: str = "",
    asserted_by: str = "",
    evidence_ref_sha256: str = "",
    reconcile_action: str = "",
    strict_git_base: bool = True,
    store_proposal_snapshot: bool = True,
    read_token: str = "",
    scope_app_id: str = "",
    scope_project_id: str = "",
    expected_base_exists: bool | None = None,
    expected_base_raw_sha256: str = "",
    expected_base_canonical_sha256: str = "",
    expected_base_git_head: str = "",
) -> dict[str, Any]:
    hashed_session = session_hash(raw_session_id)
    if not hashed_session:
        raise IntentError("SESSION_REQUIRED", "session id is required")
    if actor == "yichen-content-studio":
        if not approval_required:
            raise IntentError(
                "APPROVAL_REQUIRED",
                "yichen-content-studio intents always require explicit user approval",
            )
        if str(asserted_by).strip().lower() not in {"user", "claude", "codex", "opencode"}:
            raise IntentError(
                "ASSERTED_BY_UNSUPPORTED",
                "yichen-content-studio must bind a supported factual asserter",
            )
        if store_proposal_snapshot:
            raise IntentError(
                "STUDIO_PROPOSAL_SNAPSHOT_FORBIDDEN",
                "yichen-content-studio proposal bodies must not be stored in the state database",
            )
        if (
            not re.fullmatch(r"[0-9a-f]{64}", read_token)
            or expected_base_exists is None
            or not scope_app_id.strip()
        ):
            raise IntentError(
                "STUDIO_READ_TOKEN_REQUIRED",
                "yichen-content-studio intents require a bound high-level read token",
            )
    canonical = canonical_target(target)
    now_value = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        _expire_active_rows(conn, current=now_value, target_key=canonical.target_key)
        active = conn.execute(
            "SELECT intent_id FROM memory_write_intents WHERE target_key=? "
            "AND status IN ('pending','approved','bound','validated') LIMIT 1",
            (canonical.target_key,),
        ).fetchone()
        conn.commit()
    if active is not None:
        raise IntentError("ACTIVE_TARGET_CONFLICT", "another active intent already owns this target")
    if (proposal_file is None) == (proposal_text is None):
        raise IntentError(
            "PROPOSAL_SOURCE_INVALID",
            "provide exactly one of proposal_file or proposal_text",
        )
    if proposal_text is not None:
        proposal = content_hashes(
            proposal_text.encode("utf-8"),
            max_bytes=MAX_PROPOSAL_BYTES,
        )
        proposal_source_sha256 = sha256_bytes(
            f"stdin:{proposal.raw_sha256}".encode("utf-8")
        )
    else:
        proposal_path = _absolute_lexical(Path(proposal_file or ""))
        proposal = read_proposal_file(proposal_path)
        proposal_source_sha256 = sha256_bytes(str(proposal_path).encode("utf-8"))
    intent_id = uuid.uuid4().hex
    safety_run_id = f"write-intent:{intent_id}"
    normalized_source = str(source_class).strip().lower()
    normalized_kind = str(knowledge_kind).strip().lower()
    normalized_asserted_by = memory_safety.bounded_identity_label(asserted_by)
    if not normalized_source or not normalized_kind or not normalized_asserted_by:
        raise IntentError(
            "SOURCE_METADATA_REQUIRED",
            "source_class, knowledge_kind, and asserted_by are required for a write intent",
        )
    try:
        safety = memory_safety.assess_source(
            proposal.text,
            source_class=normalized_source,
            knowledge_kind=normalized_kind,
            asserted_by=normalized_asserted_by,
            evidence_ref=evidence_ref_sha256,
        )
    except ValueError as exc:
        raise IntentError("SOURCE_METADATA_INVALID", str(exc)) from exc
    if str(safety["decision"]) != "ALLOW":
        with connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            _record_safety_assessment(
                conn,
                safety,
                run_id=safety_run_id,
                actor=actor,
                hashed_session=hashed_session,
            )
            conn.commit()
        raise IntentError(str(safety["reason_code"]), "proposal content did not pass the source-safety gate")
    canonical_proposal = canonicalize_text(proposal.text)
    if store_proposal_snapshot:
        proposal_snapshot, proposal_snapshot_truncated = _snapshot_text(canonical_proposal)
    else:
        proposal_snapshot = ""
        proposal_snapshot_truncated = bool(canonical_proposal)
    normalized_reconcile_action = _bounded_label(reconcile_action).upper()
    effective_approval_required = bool(approval_required) or normalized_reconcile_action in {
        "ASK_USER",
        "MERGE_REQUIRED",
    }
    base_exists, base = _read_target(canonical)
    base_git_head = current_git_head(required=True)

    def validate_expected_base(
        observed_exists: bool,
        observed: ContentDigest,
        observed_git_head: str,
    ) -> None:
        if expected_base_exists is None:
            return
        if (
            bool(expected_base_exists) != bool(observed_exists)
            or expected_base_raw_sha256 != observed.raw_sha256
            or expected_base_canonical_sha256 != observed.canonical_sha256
            or expected_base_git_head != observed_git_head
        ):
            raise IntentError("STALE_READ_TOKEN", "target changed after the host read its CAS token")

    validate_expected_base(base_exists, base, base_git_head)
    repo_rel_path = _repo_rel_path(canonical)
    base_blob = _git_blob(base_git_head, repo_rel_path)
    if strict_git_base:
        if base_exists != (base_blob is not None):
            raise IntentError("BASE_NOT_AT_GIT_HEAD", "target must be clean at Git HEAD before creating an intent")
        if base_blob is not None and not _git_path_matches_worktree(base_git_head, repo_rel_path):
            raise IntentError("BASE_NOT_AT_GIT_HEAD", "target has uncommitted changes before intent creation")

    hours = DEFAULT_TTL_HOURS if ttl_hours is None else float(ttl_hours)
    if hours <= 0:
        raise IntentError("TTL_INVALID", "intent ttl_hours must be positive")
    now = now_value.isoformat()
    expires_at = (now_value + dt.timedelta(hours=hours)).isoformat()
    effective_enforcement = ENFORCEMENT_MODE if INTENTS_ENABLED else "off"
    try:
        with connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            _expire_active_rows(conn, current=now_value, target_key=canonical.target_key)
            locked_exists, locked_base = _read_target(canonical)
            locked_git_head = current_git_head(required=True)
            validate_expected_base(locked_exists, locked_base, locked_git_head)
            if strict_git_base:
                locked_blob = _git_blob(locked_git_head, repo_rel_path)
                if locked_exists != (locked_blob is not None):
                    raise IntentError(
                        "BASE_NOT_AT_GIT_HEAD",
                        "target must be clean at Git HEAD before creating an intent",
                    )
                if locked_blob is not None and not _git_path_matches_worktree(locked_git_head, repo_rel_path):
                    raise IntentError(
                        "BASE_NOT_AT_GIT_HEAD",
                        "target has uncommitted changes before intent creation",
                    )
            active = conn.execute(
                "SELECT intent_id FROM memory_write_intents WHERE target_key=? "
                "AND status IN ('pending','approved','bound','validated') LIMIT 1",
                (canonical.target_key,),
            ).fetchone()
            if active is not None:
                raise IntentError("ACTIVE_TARGET_CONFLICT", "another active intent already owns this target")
            safety_audit_id = _record_safety_assessment(
                conn,
                safety,
                run_id=safety_run_id,
                actor=actor,
                hashed_session=hashed_session,
            )
            conn.execute(
                """
                INSERT INTO memory_write_intents (
                  intent_id, actor, session_hash, target_rel_path, target_key,
                  base_exists, base_raw_sha256, base_canonical_sha256, base_git_head,
                  read_token, scope_app_id, scope_project_id,
                  proposal_raw_sha256, proposal_canonical_sha256, proposal_size_bytes,
                  proposal_path_sha256, proposal_canonical_snapshot,
                  proposal_snapshot_truncated, proposal_line_count,
                  source_class, knowledge_kind, asserted_by, evidence_ref_sha256,
                  safety_audit_id, safety_run_id, safety_decision,
                  safety_reason_code, safety_input_sha256, safety_input_length,
                  reconcile_action, intent_system_enabled, effective_enforcement,
                  approval_required, status, created_at, updated_at, expires_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    intent_id,
                    actor,
                    hashed_session,
                    canonical.rel_path,
                    canonical.target_key,
                    int(base_exists),
                    base.raw_sha256,
                    base.canonical_sha256,
                    base_git_head,
                    _bounded_label(read_token, limit=128),
                    _bounded_label(scope_app_id, limit=160),
                    _bounded_label(scope_project_id, limit=160),
                    proposal.raw_sha256,
                    proposal.canonical_sha256,
                    proposal.size_bytes,
                    proposal_source_sha256,
                    proposal_snapshot,
                    int(proposal_snapshot_truncated),
                    _line_count(canonical_proposal),
                    normalized_source,
                    normalized_kind,
                    normalized_asserted_by,
                    _bounded_label(evidence_ref_sha256, limit=128),
                    safety_audit_id,
                    safety_run_id,
                    str(safety["decision"]),
                    str(safety["reason_code"]),
                    str(safety["input_sha256"]),
                    int(safety["input_length"]),
                    normalized_reconcile_action,
                    int(INTENTS_ENABLED),
                    effective_enforcement,
                    int(effective_approval_required),
                    "pending",
                    now,
                    now,
                    expires_at,
                ),
            )
            conn.commit()
    except sqlite3.IntegrityError as exc:
        raise IntentError("ACTIVE_TARGET_CONFLICT", "another active intent already owns this target") from exc
    return show_intent(intent_id)["intent"]


def show_intent(intent_id: str) -> dict[str, Any]:
    with connect() as conn:
        intent = _fetch_intent(conn, intent_id)
        receipt = _row_dict(conn.execute("SELECT * FROM memory_write_receipts WHERE intent_id=?", (intent_id,)).fetchone())
    if intent is None:
        raise IntentError("INTENT_NOT_FOUND", f"write intent not found: {intent_id}")
    return {"intent": _public_intent(intent), "receipt": receipt}


def approve_intent(
    intent_id: str,
    *,
    actor: str,
    raw_session_id: str,
    target: str | Path,
    proposal_raw_sha256: str,
    proposal_canonical_sha256: str,
    approved_by: str,
    approval_ref: str,
) -> dict[str, Any]:
    approved_by = _bounded_label(approved_by)
    if not approved_by:
        raise IntentError("APPROVER_REQUIRED", "approved_by is required")
    if not str(approval_ref).strip():
        raise IntentError("APPROVAL_REF_REQUIRED", "approval_ref is required")
    approval_ref_sha256 = sha256_bytes(str(approval_ref).strip().encode("utf-8"))
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        intent = _fetch_intent(conn, intent_id)
        if intent is None:
            raise IntentError("INTENT_NOT_FOUND", f"write intent not found: {intent_id}")
        _authorize_intent(intent, actor=actor, raw_session_id=raw_session_id)
        if str(intent["status"]) not in {"pending", "approved"}:
            raise IntentError("INTENT_NOT_APPROVABLE", f"intent status cannot be approved: {intent['status']}")
        canonical = canonical_target(target)
        if canonical.target_key != str(intent["target_key"]):
            raise IntentError("APPROVAL_TARGET_MISMATCH", "approval target does not match the intent")
        if proposal_raw_sha256 != str(intent["proposal_raw_sha256"]):
            raise IntentError("APPROVAL_PROPOSAL_MISMATCH", "approval raw proposal hash does not match the intent")
        if proposal_canonical_sha256 != str(intent["proposal_canonical_sha256"]):
            raise IntentError("APPROVAL_PROPOSAL_MISMATCH", "approval proposal hash does not match the intent")
        binding = _approval_binding(
            intent,
            approved_by,
            proposal_raw_sha256,
            proposal_canonical_sha256,
            approval_ref_sha256,
        )
        if str(intent["status"]) == "approved":
            stored_matches = (
                str(intent["approved_by"]) == approved_by
                and str(intent["approval_proposal_raw_sha256"]) == proposal_raw_sha256
                and str(intent["approval_proposal_canonical_sha256"]) == proposal_canonical_sha256
                and str(intent["approval_ref_sha256"]) == approval_ref_sha256
                and str(intent["approval_binding_sha256"]) == binding
            )
            if not stored_matches:
                raise IntentError("APPROVAL_ALREADY_BOUND", "approval is already bound to different approval data")
            conn.commit()
            payload = _public_intent(intent)
            payload["idempotent"] = True
            return payload
        now = utc_now()
        conn.execute(
            """
            UPDATE memory_write_intents
            SET status='approved', approved_at=?, approved_by=?,
                approval_proposal_raw_sha256=?,
                approval_proposal_canonical_sha256=?, approval_ref_sha256=?,
                approval_binding_sha256=?, updated_at=?
            WHERE intent_id=?
            """,
            (
                now,
                approved_by,
                proposal_raw_sha256,
                proposal_canonical_sha256,
                approval_ref_sha256,
                binding,
                now,
                intent_id,
            ),
        )
        conn.commit()
    payload = show_intent(intent_id)["intent"]
    payload["idempotent"] = False
    return payload


def _intent_expired(intent: dict[str, Any], now: dt.datetime | None = None) -> bool:
    expiry = parse_time(str(intent["expires_at"]))
    return bool(expiry and expiry <= (now or dt.datetime.now(dt.timezone.utc)))


def bind_claim(
    intent_id: str,
    *,
    actor: str,
    raw_session_id: str,
    claim_path: str | Path | None = None,
    claim_ref: str = "",
    connection: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    owns_connection = connection is None
    conn = connect() if owns_connection else connection
    if conn is None:  # Narrow the Optional type for static readers.
        raise IntentError("STATE_DB_UNAVAILABLE", "intent state connection is unavailable")
    terminal: tuple[str, str, str] | None = None
    result: dict[str, Any] | None = None
    try:
        if owns_connection:
            conn.execute("BEGIN IMMEDIATE")
        snapshot = _fetch_intent(conn, intent_id)
        if snapshot is None:
            raise IntentError("INTENT_NOT_FOUND", f"write intent not found: {intent_id}")
        _authorize_intent(snapshot, actor=actor, raw_session_id=raw_session_id)
        if str(snapshot["status"]) not in {"pending", "approved", "bound"}:
            raise IntentError("INTENT_NOT_BINDABLE", f"intent status cannot be bound: {snapshot['status']}")
        if _intent_expired(snapshot):
            terminal = ("expired", "INTENT_EXPIRED", "TTL_ELAPSED")
        if terminal is None and int(snapshot["approval_required"]):
            expected = _stored_approval_binding(snapshot)
            if not snapshot["approved_at"] or str(snapshot["approval_binding_sha256"]) != expected:
                raise IntentError("APPROVAL_REQUIRED", "a correctly bound approval is required before claim binding")
        target = canonical_target(claim_path or str(snapshot["target_rel_path"]))
        if target.target_key != str(snapshot["target_key"]):
            raise IntentError("CLAIM_TARGET_MISMATCH", "claim path does not match the write intent")
        exists, current = _read_target(target)
        stale = int(snapshot["base_exists"]) != int(exists) or current.raw_sha256 != str(snapshot["base_raw_sha256"])
        current_head = current_git_head(required=True)
        history = git_version_chain(str(snapshot["base_git_head"]), current_head, target)
        if not history["ok"] or history["versions"]:
            stale = True
        if terminal is None and stale:
            terminal = (
                "failed",
                "STALE_BASE",
                _safe_code(str(history.get("reason_code") or "BASE_CONTENT_CHANGED")),
            )
        if terminal is not None:
            if owns_connection:
                conn.rollback()
        else:
            now = utc_now()
            cursor = conn.execute(
                """
                UPDATE memory_write_intents
                SET status='bound', bound_at=?, claim_ref_sha256=?,
                    bound_base_raw_sha256=?, updated_at=?
                WHERE intent_id=? AND status IN ('pending','approved','bound')
                """,
                (
                    now,
                    sha256_bytes(claim_ref.encode("utf-8")) if claim_ref else "",
                    current.raw_sha256,
                    now,
                    intent_id,
                ),
            )
            if cursor.rowcount != 1:
                raise IntentError("INTENT_STATE_CHANGED", "write intent changed while binding the claim")
            stored = _fetch_intent(conn, intent_id)
            if stored is None:
                raise IntentError("INTENT_STATE_CHANGED", "write intent disappeared while binding the claim")
            result = _public_intent(stored)
            if owns_connection:
                conn.commit()
    except Exception:
        if owns_connection and conn.in_transaction:
            conn.rollback()
        raise
    finally:
        if owns_connection:
            conn.close()
    if terminal is not None:
        outcome, reason_code, detail_code = terminal
        # An external transaction is owned by the caller.  Do not write a
        # receipt or commit/rollback it behind the caller's back.
        if owns_connection:
            finalize_receipt(
                intent_id,
                actor=actor,
                raw_session_id=raw_session_id,
                outcome=outcome,
                reason_code=reason_code,
                detail_code=detail_code,
            )
        raise IntentError(reason_code, "write intent cannot be bound to the current target baseline")
    if result is None:
        raise IntentError("INTENT_STATE_CHANGED", "write intent did not reach the bound state")
    return result


def _write_validation_failure(
    intent_id: str,
    *,
    actor: str,
    raw_session_id: str,
    reason_code: str,
    detail_code: str = "",
    final: ContentDigest | None = None,
    validation_mode: str = "",
    git_head: str = "",
) -> dict[str, Any]:
    now = utc_now()
    with connect() as conn:
        conn.execute(
            """
            UPDATE memory_write_intents
            SET validation_mode=?, final_raw_sha256=?, final_canonical_sha256=?,
                validated_git_head=?, reason_code=?, updated_at=?
            WHERE intent_id=? AND status IN ('pending','approved','bound','validated')
            """,
            (
                validation_mode,
                final.raw_sha256 if final else "",
                final.canonical_sha256 if final else "",
                git_head,
                reason_code,
                now,
                intent_id,
            ),
        )
        conn.commit()
    return finalize_receipt(
        intent_id,
        actor=actor,
        raw_session_id=raw_session_id,
        outcome="failed",
        reason_code=reason_code,
        detail_code=detail_code,
    )


def validate_closeout(
    intent_id: str,
    *,
    actor: str,
    raw_session_id: str,
    target: str | Path | None = None,
    require_bound: bool = True,
    mutate: bool = True,
    include_private_diff: bool = False,
) -> dict[str, Any]:
    with connect(read_only=not mutate) as conn:
        snapshot = _fetch_intent(conn, intent_id)
        completed_receipt = _row_dict(
            conn.execute("SELECT * FROM memory_write_receipts WHERE intent_id=?", (intent_id,)).fetchone()
        )
    if snapshot is None:
        raise IntentError("INTENT_NOT_FOUND", f"write intent not found: {intent_id}")
    _authorize_intent(snapshot, actor=actor, raw_session_id=raw_session_id)
    canonical = canonical_target(target or str(snapshot["target_rel_path"]))
    if canonical.target_key != str(snapshot["target_key"]):
        return {"ok": False, "reason_code": "INTENT_TARGET_MISMATCH", "receipt": None, "mutated": False}
    if str(snapshot["status"]) == "completed":
        exists, final = _read_target(canonical)
        if (
            exists
            and completed_receipt is not None
            and str(completed_receipt["outcome"]) == "completed"
            and final.canonical_sha256 == str(snapshot["final_canonical_sha256"])
        ):
            return {
                "ok": True,
                "intent_id": intent_id,
                "validation_mode": str(snapshot["validation_mode"]),
                "final_raw_sha256": str(snapshot["final_raw_sha256"]),
                "final_canonical_sha256": str(snapshot["final_canonical_sha256"]),
                "early_commit": bool(snapshot["early_commit"]),
                "proposal_commit": str(snapshot["proposal_commit"]),
                "idempotent": True,
                "completed": True,
                "mutated": False,
                "version_chain": [],
            }
        raise IntentError("COMPLETED_CONTENT_CHANGED", "target no longer matches the completed write receipt")
    if str(snapshot["status"]) == "validated":
        exists, final = _read_target(canonical)
        if final.canonical_sha256 == str(snapshot["final_canonical_sha256"]):
            early_commit = bool(snapshot["early_commit"])
            proposal_commit = str(snapshot["proposal_commit"])
            version_chain: list[dict[str, Any]] = []
            if exists and not early_commit:
                current_head = current_git_head(required=True)
                history = git_version_chain(str(snapshot["validated_git_head"]), current_head, canonical)
                versions = list(history.get("versions", []))
                safe_versions = [
                    version
                    for version in versions
                    if version.get("exists")
                    and str(version.get("canonical_sha256", ""))
                    == str(snapshot["final_canonical_sha256"])
                ]
                if history.get("ok") and versions and len(safe_versions) == len(versions):
                    early_commit = True
                    proposal_commit = str(versions[-1]["commit"])
                    version_chain = versions
                    if mutate:
                        with connect() as conn:
                            conn.execute("BEGIN IMMEDIATE")
                            conn.execute(
                                "UPDATE memory_write_intents SET early_commit=1, proposal_commit=?, updated_at=? "
                                "WHERE intent_id=? AND status='validated'",
                                (proposal_commit, utc_now(), intent_id),
                            )
                            conn.commit()
            return {
                "ok": True,
                "intent_id": intent_id,
                "validation_mode": str(snapshot["validation_mode"]),
                "final_raw_sha256": str(snapshot["final_raw_sha256"]),
                "final_canonical_sha256": str(snapshot["final_canonical_sha256"]),
                "early_commit": early_commit,
                "proposal_commit": proposal_commit,
                "idempotent": True,
                "mutated": bool(mutate and version_chain),
                "version_chain": version_chain,
            }
        raise IntentError("VALIDATED_CONTENT_CHANGED", "target changed after closeout validation")
    if str(snapshot["status"]) not in {"pending", "approved", "bound"}:
        raise IntentError("INTENT_NOT_VALIDATABLE", f"intent status cannot be validated: {snapshot['status']}")
    if _intent_expired(snapshot):
        receipt = None
        if mutate:
            receipt = finalize_receipt(
                intent_id,
                actor=actor,
                raw_session_id=raw_session_id,
                outcome="expired",
                reason_code="INTENT_EXPIRED",
            )
        return {"ok": False, "reason_code": "INTENT_EXPIRED", "receipt": receipt, "mutated": mutate}
    if require_bound and str(snapshot["status"]) != "bound":
        return {"ok": False, "reason_code": "CLAIM_NOT_BOUND", "receipt": None, "mutated": False}
    if int(snapshot["approval_required"]):
        expected_binding = _stored_approval_binding(snapshot)
        if not snapshot["approved_at"] or str(snapshot["approval_binding_sha256"]) != expected_binding:
            receipt = None
            if mutate:
                receipt = _write_validation_failure(
                    intent_id,
                    actor=actor,
                    raw_session_id=raw_session_id,
                    reason_code="APPROVAL_BINDING_INVALID",
                )
            return {
                "ok": False,
                "reason_code": "APPROVAL_BINDING_INVALID",
                "receipt": receipt,
                "mutated": mutate,
            }
    try:
        exists, final = _read_target(canonical)
    except IntentError as exc:
        receipt = None
        if mutate:
            receipt = _write_validation_failure(
                intent_id,
                actor=actor,
                raw_session_id=raw_session_id,
                reason_code=exc.reason_code,
            )
        return {"ok": False, "reason_code": exc.reason_code, "receipt": receipt, "mutated": mutate}
    if not exists:
        receipt = None
        if mutate:
            receipt = _write_validation_failure(
                intent_id,
                actor=actor,
                raw_session_id=raw_session_id,
                reason_code="TARGET_MISSING",
            )
        return {"ok": False, "reason_code": "TARGET_MISSING", "receipt": receipt, "mutated": mutate}

    if final.raw_sha256 == str(snapshot["proposal_raw_sha256"]):
        validation_mode = "exact"
    elif final.canonical_sha256 == str(snapshot["proposal_canonical_sha256"]):
        validation_mode = "format_only"
    else:
        validation_mode = "content_mismatch"
        receipt = None
        if mutate:
            receipt = _write_validation_failure(
                intent_id,
                actor=actor,
                raw_session_id=raw_session_id,
                reason_code="PROPOSAL_CONTENT_MISMATCH",
                final=final,
                validation_mode=validation_mode,
                git_head=current_git_head(required=False),
            )
        return {
            "ok": False,
            "reason_code": "PROPOSAL_CONTENT_MISMATCH",
            "validation_mode": validation_mode,
            "receipt": receipt,
            "mutated": mutate,
            "mismatch": _bounded_mismatch(snapshot, final, include_private_diff=include_private_diff),
        }

    head = current_git_head(required=True)
    history = git_version_chain(str(snapshot["base_git_head"]), head, canonical)
    versions = list(history.get("versions", []))
    if not history.get("ok"):
        receipt = None
        if mutate:
            receipt = _write_validation_failure(
                intent_id,
                actor=actor,
                raw_session_id=raw_session_id,
                reason_code="STALE_BASE",
                detail_code=_safe_code(str(history.get("reason_code", ""))),
                final=final,
                validation_mode=validation_mode,
                git_head=head,
            )
        return {
            "ok": False,
            "reason_code": "STALE_BASE",
            "version_chain": versions,
            "receipt": receipt,
            "mutated": mutate,
        }

    unsafe_versions = [
        version
        for version in versions
        if not version.get("exists")
        or str(version.get("canonical_sha256", "")) != str(snapshot["proposal_canonical_sha256"])
    ]
    if unsafe_versions:
        receipt = None
        if mutate:
            receipt = _write_validation_failure(
                intent_id,
                actor=actor,
                raw_session_id=raw_session_id,
                reason_code="STALE_BASE",
                detail_code="INTERVENING_TARGET_VERSION",
                final=final,
                validation_mode=validation_mode,
                git_head=head,
            )
        return {
            "ok": False,
            "reason_code": "STALE_BASE",
            "version_chain": versions,
            "receipt": receipt,
            "mutated": mutate,
        }

    early_commit = bool(versions)
    proposal_commit = str(versions[-1]["commit"]) if versions else ""
    if mutate:
        now = utc_now()
        with connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE memory_write_intents
                SET status='validated', validated_at=?, validation_mode=?,
                    final_raw_sha256=?, final_canonical_sha256=?, validated_git_head=?,
                    early_commit=?, proposal_commit=?, reason_code='', updated_at=?
                WHERE intent_id=? AND status IN ('pending','approved','bound')
                """,
                (
                    now,
                    validation_mode,
                    final.raw_sha256,
                    final.canonical_sha256,
                    head,
                    int(early_commit),
                    proposal_commit,
                    now,
                    intent_id,
                ),
            )
            if cursor.rowcount != 1:
                raise IntentError("INTENT_STATE_CHANGED", "write intent changed during closeout validation")
            conn.commit()
    return {
        "ok": True,
        "intent_id": intent_id,
        "validation_mode": validation_mode,
        "final_raw_sha256": final.raw_sha256,
        "final_canonical_sha256": final.canonical_sha256,
        "early_commit": early_commit,
        "proposal_commit": proposal_commit,
        "idempotent": False,
        "mutated": mutate,
        "version_chain": versions,
    }


def _resolve_git_commit(candidate: str) -> str:
    reference = str(candidate).strip()
    if not reference or reference.startswith("-") or re.fullmatch(r"[A-Za-z0-9._/@{}^~:+-]+", reference) is None:
        raise IntentError("GIT_COMMIT_INVALID", "git commit reference is missing or invalid")
    result = _run_git("rev-parse", "--verify", f"{reference}^{{commit}}")
    resolved = str(result.stdout).strip().lower() if result.returncode == 0 else ""
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", resolved) is None:
        raise IntentError("GIT_COMMIT_INVALID", "git commit reference cannot be resolved to a full object id")
    return resolved


def finalize_receipt(
    intent_id: str,
    *,
    actor: str,
    raw_session_id: str,
    outcome: str = "completed",
    reason_code: str = "",
    git_commit: str = "",
    detail_code: str = "",
) -> dict[str, Any]:
    outcome = outcome.strip().lower()
    if outcome not in {"completed", "failed", "cancelled", "expired"}:
        raise IntentError("OUTCOME_INVALID", f"unsupported receipt outcome: {outcome}")
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        intent = _row_dict(
            conn.execute("SELECT * FROM memory_write_intents WHERE intent_id=?", (intent_id,)).fetchone()
        )
        if intent is None:
            raise IntentError("INTENT_NOT_FOUND", f"write intent not found: {intent_id}")
        _authorize_intent(intent, actor=actor, raw_session_id=raw_session_id)
        existing = _row_dict(
            conn.execute("SELECT * FROM memory_write_receipts WHERE intent_id=?", (intent_id,)).fetchone()
        )
        if existing is not None:
            if str(existing["outcome"]) != outcome:
                raise IntentError(
                    "RECEIPT_OUTCOME_CONFLICT",
                    "an existing terminal receipt has a different outcome",
                )
            conn.commit()
            existing["idempotent"] = True
            existing["requested_outcome_mismatch"] = False
            return existing
        if outcome == "completed" and str(intent["status"]) != "validated":
            raise IntentError("INTENT_NOT_VALIDATED", "a successful receipt requires a validated intent")
        resolved_commit = ""
        if outcome == "completed":
            commit_candidate = str(git_commit).strip()
            if not commit_candidate and int(intent["early_commit"]):
                commit_candidate = str(intent["proposal_commit"])
            if not commit_candidate:
                commit_candidate = current_git_head(required=True)
            resolved_commit = _resolve_git_commit(commit_candidate)
            target = canonical_target(str(intent["target_rel_path"]))
            blob = _git_blob(resolved_commit, _repo_rel_path(target))
            committed_digest = content_hashes(blob, max_bytes=MAX_TARGET_BYTES) if blob is not None else None
            if (
                committed_digest is None
                or committed_digest.canonical_sha256 != str(intent["final_canonical_sha256"])
            ):
                raise IntentError(
                    "COMMIT_BLOB_MISMATCH",
                    "the committed target blob does not match the validated final content",
                )
        receipt_id = hashlib.sha256(f"write-receipt:{intent_id}".encode("utf-8")).hexdigest()[:32]
        now = utc_now()
        effective_reason = _safe_code(
            reason_code,
            default="WRITE_COMPLETED" if outcome == "completed" else outcome.upper(),
        )
        effective_detail = _safe_code(detail_code)
        conn.execute(
            """
            INSERT INTO memory_write_receipts (
              receipt_id, intent_id, actor, session_hash, target_rel_path, target_key,
              outcome, reason_code, validation_mode, base_raw_sha256,
              proposal_raw_sha256, proposal_canonical_sha256, final_raw_sha256,
              final_canonical_sha256, base_git_head, validated_git_head, git_commit,
              early_commit, proposal_commit, approval_binding_sha256,
              approval_ref_sha256, source_class, knowledge_kind,
              asserted_by_sha256, safety_decision, safety_reason_code,
              safety_input_sha256, safety_input_length, evidence_ref_sha256,
              detail_code, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                receipt_id,
                intent_id,
                intent["actor"],
                intent["session_hash"],
                intent["target_rel_path"],
                intent["target_key"],
                outcome,
                effective_reason,
                intent["validation_mode"],
                intent["base_raw_sha256"],
                intent["proposal_raw_sha256"],
                intent["proposal_canonical_sha256"],
                intent["final_raw_sha256"],
                intent["final_canonical_sha256"],
                intent["base_git_head"],
                intent["validated_git_head"],
                resolved_commit,
                intent["early_commit"],
                intent["proposal_commit"],
                intent["approval_binding_sha256"],
                intent["approval_ref_sha256"],
                intent["source_class"],
                intent["knowledge_kind"],
                sha256_bytes(str(intent["asserted_by"]).encode("utf-8")) if intent["asserted_by"] else "",
                intent["safety_decision"],
                intent["safety_reason_code"],
                intent["safety_input_sha256"],
                intent["safety_input_length"],
                intent["evidence_ref_sha256"],
                effective_detail,
                now,
            ),
        )
        conn.execute(
            "UPDATE memory_write_intents SET status=?, reason_code=?, updated_at=? WHERE intent_id=?",
            (outcome, effective_reason, now, intent_id),
        )
        conn.commit()
    result = show_intent(intent_id)["receipt"] or {}
    result["idempotent"] = False
    result["requested_outcome_mismatch"] = False
    return result


def cancel_intent(intent_id: str, *, actor: str, raw_session_id: str, reason_code: str = "CANCELLED_BY_ACTOR") -> dict[str, Any]:
    intent = show_intent(intent_id)["intent"]
    _authorize_intent(intent, actor=actor, raw_session_id=raw_session_id)
    if str(intent["status"]) not in ACTIVE_STATUSES:
        raise IntentError("INTENT_NOT_CANCELLABLE", f"intent status cannot be cancelled: {intent['status']}")
    return finalize_receipt(
        intent_id,
        actor=actor,
        raw_session_id=raw_session_id,
        outcome="cancelled",
        reason_code=_bounded_label(reason_code),
    )


def expire_intents(*, now: dt.datetime | None = None, apply: bool = False) -> dict[str, Any]:
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    with connect() as conn:
        rows = conn.execute(
            "SELECT intent_id, actor, session_hash, target_rel_path, expires_at FROM memory_write_intents "
            "WHERE status IN ('pending','approved','bound','validated') ORDER BY expires_at"
        ).fetchall()
    expired = [
        {key: row[key] for key in row.keys()}
        for row in rows
        if (parse_time(str(row["expires_at"])) or dt.datetime.max.replace(tzinfo=dt.timezone.utc)) <= current
    ]
    applied = 0
    if apply:
        for row in expired:
            # The raw session id is deliberately unavailable. Expiry is a system
            # transition, so write the terminal receipt in a scoped transaction.
            with connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute(
                    "SELECT receipt_id FROM memory_write_receipts WHERE intent_id=?", (row["intent_id"],)
                ).fetchone()
                if existing is not None:
                    conn.commit()
                    continue
                intent = _row_dict(
                    conn.execute("SELECT * FROM memory_write_intents WHERE intent_id=?", (row["intent_id"],)).fetchone()
                )
                if intent is None or str(intent["status"]) not in ACTIVE_STATUSES:
                    conn.commit()
                    continue
                receipt_id = hashlib.sha256(f"write-receipt:{row['intent_id']}".encode("utf-8")).hexdigest()[:32]
                timestamp = current.replace(microsecond=0).isoformat()
                conn.execute(
                    """
                    INSERT INTO memory_write_receipts (
                      receipt_id, intent_id, actor, session_hash, target_rel_path, target_key,
                      outcome, reason_code, validation_mode, base_raw_sha256,
                      proposal_raw_sha256, proposal_canonical_sha256, final_raw_sha256,
                      final_canonical_sha256, base_git_head, validated_git_head, git_commit,
                      early_commit, proposal_commit, approval_binding_sha256,
                      approval_ref_sha256, source_class, knowledge_kind,
                      asserted_by_sha256, safety_decision, safety_reason_code,
                      safety_input_sha256, safety_input_length, evidence_ref_sha256,
                      detail_code, created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        receipt_id, intent["intent_id"], intent["actor"], intent["session_hash"],
                        intent["target_rel_path"], intent["target_key"], "expired", "INTENT_EXPIRED",
                        intent["validation_mode"], intent["base_raw_sha256"], intent["proposal_raw_sha256"],
                        intent["proposal_canonical_sha256"], intent["final_raw_sha256"],
                        intent["final_canonical_sha256"], intent["base_git_head"],
                        intent["validated_git_head"], "", intent["early_commit"],
                        intent["proposal_commit"], intent["approval_binding_sha256"],
                        intent["approval_ref_sha256"], intent["source_class"],
                        intent["knowledge_kind"],
                        sha256_bytes(str(intent["asserted_by"]).encode("utf-8")) if intent["asserted_by"] else "",
                        intent["safety_decision"], intent["safety_reason_code"],
                        intent["safety_input_sha256"], intent["safety_input_length"],
                        intent["evidence_ref_sha256"], "TTL_ELAPSED", timestamp,
                    ),
                )
                conn.execute(
                    "UPDATE memory_write_intents SET status='expired', reason_code='INTENT_EXPIRED', updated_at=? "
                    "WHERE intent_id=?",
                    (timestamp, intent["intent_id"]),
                )
                conn.commit()
                applied += 1
    return {"expired": expired, "count": len(expired), "applied": applied}


def _normalized_patterns(patterns: Sequence[str] | None = None) -> tuple[str, ...]:
    source = PROTECTED_PATHS if patterns is None else patterns
    normalized: list[str] = []
    for raw in source:
        value = unicodedata.normalize("NFC", str(raw).strip().replace("\\", "/")).lstrip("./")
        if not value or value.startswith("/") or ".." in Path(value).parts:
            continue
        normalized.append(value.casefold())
    return tuple(normalized)


def is_protected_target(target: str | Path, *, protected_paths: Sequence[str] | None = None) -> bool:
    canonical = canonical_target(target)
    for pattern in _normalized_patterns(protected_paths):
        if pattern.endswith("/") and canonical.target_key.startswith(pattern):
            return True
        if any(character in pattern for character in "*?["):
            if fnmatch.fnmatchcase(canonical.target_key, pattern):
                return True
        elif canonical.target_key == pattern:
            return True
    return False


def enforce_protected_changes(
    paths: Iterable[str | Path],
    *,
    actor: str,
    raw_session_id: str,
    intent_ids: Sequence[str] | None = None,
    protected_paths: Sequence[str] | None = None,
    enforcement_mode: str | None = None,
    read_only: bool = False,
) -> dict[str, Any]:
    requested_mode = (enforcement_mode or ENFORCEMENT_MODE).strip().lower()
    if requested_mode not in VALID_ENFORCEMENT_MODES:
        raise IntentError("ENFORCEMENT_MODE_INVALID", f"unsupported enforcement mode: {requested_mode}")
    # An explicit `intent create` remains useful as an advisory/dry-run when
    # the feature flag is off, but it must never silently turn protection on.
    mode = requested_mode if INTENTS_ENABLED else "off"
    hashed = session_hash(raw_session_id)
    allowed_ids = set(intent_ids or ())
    restrict_to_ids = intent_ids is not None
    matched: list[dict[str, str]] = []
    violations: list[dict[str, str]] = []
    with connect(read_only=read_only) as conn:
        for raw_path in paths:
            try:
                target = canonical_target(raw_path)
            except IntentError as exc:
                violations.append({"path": str(raw_path), "reason_code": exc.reason_code})
                continue
            if not is_protected_target(target.path, protected_paths=protected_paths):
                continue
            params: list[Any] = [target.target_key, actor, hashed]
            query = (
                "SELECT intent_id, status FROM memory_write_intents "
                "WHERE target_key=? AND actor=? AND session_hash=? "
                "AND status IN ('pending','approved','bound','validated')"
            )
            rows = conn.execute(query, params).fetchall()
            if restrict_to_ids:
                rows = [row for row in rows if str(row["intent_id"]) in allowed_ids]
            eligible = [row for row in rows if str(row["status"]) in {"bound", "validated"}]
            if not eligible:
                violations.append({"path": target.rel_path, "reason_code": "PROTECTED_WRITE_WITHOUT_BOUND_INTENT"})
            else:
                matched.append({"path": target.rel_path, "intent_id": str(eligible[0]["intent_id"])})
    blocking = bool(violations) and mode == "enforce"
    return {
        "ok": not blocking,
        "enabled": INTENTS_ENABLED,
        "requested_mode": requested_mode,
        "mode": mode,
        "blocking": blocking,
        "matched": matched,
        "violations": violations,
        "can_authorize_action": False,
    }


def protected_deletion_guard(
    paths: Iterable[str | Path],
    *,
    explicit_user_approval: bool = False,
    moved_to_trash: bool = False,
    protected_paths: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Return the non-bypassable reason for protected-memory deletions.

    A write intent proves proposed content; it does not authorize deletion.
    Deletion additionally requires explicit user approval and a recoverable
    move to Trash.
    """
    protected: list[dict[str, str]] = []
    for raw_path in paths:
        try:
            target = canonical_target(raw_path)
        except IntentError as exc:
            protected.append({"path": str(raw_path), "reason_code": exc.reason_code})
            continue
        if is_protected_target(target.path, protected_paths=protected_paths):
            protected.append(
                {
                    "path": target.rel_path,
                    "reason_code": "PROTECTED_DELETE_REQUIRES_EXPLICIT_APPROVAL_AND_TRASH",
                }
            )
    blocking = bool(protected) and not (explicit_user_approval and moved_to_trash)
    return {
        "ok": not blocking,
        "blocking": blocking,
        "protected": protected,
        "explicit_user_approval": bool(explicit_user_approval),
        "moved_to_trash": bool(moved_to_trash),
        "can_authorize_action": False,
    }


def _session_value(explicit: str, actor: str = "codex") -> str:
    if explicit.strip():
        return explicit.strip()
    keys = {
        "codex": ("AGENT_MEMORY_SESSION_ID", "CODEX_THREAD_ID"),
        "claude": ("AGENT_MEMORY_SESSION_ID", "CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID"),
    }.get(actor, ("AGENT_MEMORY_SESSION_ID",))
    for key in keys:
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create and verify Agent Memory write intents and receipts.")
    parser.add_argument(
        "--actor",
        choices=("codex", "claude", "human", "migration", "test", "yichen-content-studio"),
        default="codex",
    )
    parser.add_argument("--session-id", default="")
    parser.add_argument("--json", action="store_true")
    subparsers = parser.add_subparsers(dest="action", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--target", required=True)
    create.add_argument("--proposal-file", required=True)
    create.add_argument("--ttl-hours", type=float, default=None)
    create.add_argument("--no-approval-required", action="store_true")
    create.add_argument("--source-class", required=True)
    create.add_argument("--knowledge-kind", required=True)
    create.add_argument("--asserted-by", required=True)
    create.add_argument("--evidence-ref-sha256", default="")
    create.add_argument("--reconcile-action", default="")

    show = subparsers.add_parser("show")
    show.add_argument("--intent-id", required=True)

    approve = subparsers.add_parser("approve")
    approve.add_argument("--intent-id", required=True)
    approve.add_argument("--target", required=True)
    approve.add_argument("--proposal-raw-sha256", required=True)
    approve.add_argument("--proposal-canonical-sha256", required=True)
    approve.add_argument("--approved-by", required=True)
    approve.add_argument("--approval-ref", required=True)

    bind = subparsers.add_parser("bind")
    bind.add_argument("--intent-id", required=True)
    bind.add_argument("--target")
    bind.add_argument("--claim-ref", default="")

    validate = subparsers.add_parser("validate")
    validate.add_argument("--intent-id", required=True)
    validate.add_argument("--target")
    validate.add_argument("--no-mutate", action="store_true")
    validate.add_argument(
        "--show-private-diff",
        action="store_true",
        help="Show a bounded, secret-redacted mismatch diff. Default output contains hashes and counts only.",
    )

    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("--intent-id", required=True)
    finalize.add_argument("--outcome", choices=("completed", "failed", "cancelled", "expired"), default="completed")
    finalize.add_argument("--reason-code", default="")
    finalize.add_argument("--git-commit", default="")
    finalize.add_argument("--detail-code", default="")

    cancel = subparsers.add_parser("cancel")
    cancel.add_argument("--intent-id", required=True)
    cancel.add_argument("--reason-code", default="CANCELLED_BY_ACTOR")

    expire = subparsers.add_parser("expire")
    expire.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw_session_id = _session_value(args.session_id, args.actor)
    try:
        if args.actor == "yichen-content-studio" and args.action == "create":
            raise IntentError(
                "STUDIO_LOW_LEVEL_API_FORBIDDEN",
                "yichen-content-studio must use the high-level write prepare/apply protocol",
            )
        if args.action == "create":
            if args.actor == "yichen-content-studio" and args.asserted_by not in {
                "user",
                "claude",
                "codex",
                "opencode",
            }:
                raise IntentError(
                    "ASSERTED_BY_UNSUPPORTED",
                    "yichen-content-studio must identify the factual asserter as user, claude, codex, or opencode",
                )
            payload: Any = create_intent(
                actor=args.actor,
                raw_session_id=raw_session_id,
                target=args.target,
                proposal_file=args.proposal_file,
                approval_required=not args.no_approval_required,
                ttl_hours=args.ttl_hours,
                source_class=args.source_class,
                knowledge_kind=args.knowledge_kind,
                asserted_by=args.asserted_by,
                evidence_ref_sha256=args.evidence_ref_sha256,
                reconcile_action=args.reconcile_action,
            )
        elif args.action == "show":
            payload = show_intent(args.intent_id)
        elif args.action == "approve":
            payload = approve_intent(
                args.intent_id,
                actor=args.actor,
                raw_session_id=raw_session_id,
                target=args.target,
                proposal_raw_sha256=args.proposal_raw_sha256,
                proposal_canonical_sha256=args.proposal_canonical_sha256,
                approved_by=args.approved_by,
                approval_ref=args.approval_ref,
            )
        elif args.action == "bind":
            payload = bind_claim(
                args.intent_id,
                actor=args.actor,
                raw_session_id=raw_session_id,
                claim_path=args.target,
                claim_ref=args.claim_ref,
            )
        elif args.action == "validate":
            payload = validate_closeout(
                args.intent_id,
                actor=args.actor,
                raw_session_id=raw_session_id,
                target=args.target,
                mutate=not args.no_mutate,
                include_private_diff=args.show_private_diff,
            )
        elif args.action == "finalize":
            payload = finalize_receipt(
                args.intent_id,
                actor=args.actor,
                raw_session_id=raw_session_id,
                outcome=args.outcome,
                reason_code=args.reason_code,
                git_commit=args.git_commit,
                detail_code=args.detail_code,
            )
        elif args.action == "cancel":
            payload = cancel_intent(
                args.intent_id,
                actor=args.actor,
                raw_session_id=raw_session_id,
                reason_code=args.reason_code,
            )
        else:
            payload = expire_intents(apply=args.apply)
    except (IntentError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
        error = {"ok": False, "reason_code": getattr(exc, "reason_code", "INTENT_ERROR"), "error": str(exc)}
        if args.json:
            print(json.dumps(error, ensure_ascii=False, indent=2))
        else:
            print(f"error={error['reason_code']} {error['error']}")
        return 2
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        if isinstance(payload, dict) and "intent_id" in payload:
            print(f"intent_id={payload['intent_id']} status={payload.get('status', payload.get('ok', ''))}")
        else:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    if isinstance(payload, dict) and payload.get("ok") is False:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
