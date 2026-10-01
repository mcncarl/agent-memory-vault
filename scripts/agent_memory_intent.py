#!/usr/bin/env python3
"""Write-intent and immutable receipt protocol for protected Agent Memory files.

Markdown remains the source of truth.  The private mode-0600 SQLite database
may store a bounded canonical proposal snapshot solely for scoped mismatch
diffs; public intent output and immutable receipts never return that text.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import difflib
import fnmatch
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import subprocess
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from agent_memory_env import assert_runtime_ready, env_value, expand_path, load_config
import agent_memory_safety as memory_safety
from agent_memory_state import (
    STATE_SCHEMA_VERSION,
    StateSecurityError,
    ensure_observability_v2_schema,
    search_log_privacy_guard_report,
    secure_sqlite_connect,
    side_effect_free_sqlite_fingerprint,
)


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = expand_path(env_value("ROOT", str(RUNTIME_ROOT / "templates" / "vault")))
GIT_ROOT = expand_path(env_value("GIT_ROOT", str(VAULT_ROOT)))
STATE_DB = expand_path(env_value("STATE_DB", "$HOME/.config/agent-memory/state.sqlite"))
WRITER_PROTOCOL_VERSION = 2
STATE_SCHEMA_REASON_CODE = "STATE_SCHEMA_MIGRATION_REQUIRED"
CANONICAL_WRITER_ACTORS = ("codex", "claude", "ailu")
SUPPORTED_LEDGER_ACTORS = (*CANONICAL_WRITER_ACTORS, "human", "migration", "test")
HUMAN_CONFIRMATION_CAPABILITY_APPROVER = "human_confirmation_capability_v1"
SENSITIVE_CONFIRMATION_ACTIONS = {"ADOPT", "MIGRATE_LEGACY_SCOPE"}
SENSITIVE_CONFIRMATION_OPERATIONS = {"status_transition", "governance_migration"}


def _configured_write_intents() -> dict[str, Any]:
    config = load_config()
    gateway = config.get("write_gateway", {})
    if isinstance(gateway, dict) and gateway:
        legacy = config.get("write_intents", {})
        merged = dict(legacy) if isinstance(legacy, dict) else {}
        mode = str(gateway.get("mode", "enforce")).strip().lower()
        merged.update(gateway)
        merged["enabled"] = mode != "off"
        merged["enforcement"] = mode
        return merged
    payload = config.get("write_intents", {})
    return payload if isinstance(payload, dict) else {}


_WRITE_INTENT_CONFIG = _configured_write_intents()
_configured_paths = _WRITE_INTENT_CONFIG.get("protected_paths", ())
if isinstance(_configured_paths, str):
    _configured_paths = (_configured_paths,)
elif not isinstance(_configured_paths, (list, tuple)):
    _configured_paths = ()

FULL_VAULT_GATEWAY = bool(_WRITE_INTENT_CONFIG.get("full_vault", False))
PROTECTED_PATHS: tuple[str, ...] = tuple(str(item) for item in _configured_paths if str(item).strip())
INTENTS_ENABLED = bool(_WRITE_INTENT_CONFIG.get("enabled", False))
_configured_enforcement = str(_WRITE_INTENT_CONFIG.get("enforcement", "off")).strip().lower()
ENFORCEMENT_MODE = _configured_enforcement if INTENTS_ENABLED else "off"
MAX_PROPOSAL_BYTES = int(_WRITE_INTENT_CONFIG.get("max_proposal_bytes", 2 * 1024 * 1024))
MAX_TARGET_BYTES = int(_WRITE_INTENT_CONFIG.get("max_target_bytes", 8 * 1024 * 1024))
MAX_SNAPSHOT_BYTES = int(_WRITE_INTENT_CONFIG.get("max_snapshot_bytes", 256 * 1024))
DEFAULT_TTL_HOURS = float(_WRITE_INTENT_CONFIG.get("ttl_hours", 24))
EXPIRED_VALIDATED_RECOVERY_REASON = "EXPIRED_VALIDATED_RECOVERY_PENDING"
EXPIRED_VALIDATED_RECOVERY_COMPLETED_REASON = (
    "EXPIRED_VALIDATED_RECOVERY_COMPLETED"
)
EXPIRED_VALIDATED_RECOVERY_TTL_SECONDS = 10 * 60
EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON = (
    "EXPIRED_VALIDATED_RECOVERY_REPAIR_PENDING"
)
EXPIRED_VALIDATED_RECOVERY_REPAIR_TTL_SECONDS = 5 * 60
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


def assert_schema_ready(conn: sqlite3.Connection) -> None:
    """Verify the installed state schema without creating or altering it."""

    tables = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    required_tables = {
        "meta",
        "memory_write_intents",
        "memory_write_receipts",
        "memory_path_fences",
        "memory_session_claims",
        "memory_file_observations",
        "memory_safety_log",
        "memory_closeout_incidents",
        "generated_index_closeout_transactions",
    }
    intent_columns = (
        {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_write_intents)")}
        if "memory_write_intents" in tables
        else set()
    )
    receipt_columns = (
        {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_write_receipts)")}
        if "memory_write_receipts" in tables
        else set()
    )
    state_version = None
    writer_version = None
    if "meta" in tables:
        try:
            state_version = conn.execute(
                "SELECT value FROM meta WHERE key='agent_memory_state_schema_version'"
            ).fetchone()
            writer_version = conn.execute(
                "SELECT value FROM meta WHERE key='agent_memory_writer_protocol_version'"
            ).fetchone()
        except sqlite3.Error as exc:
            raise IntentError(
                STATE_SCHEMA_REASON_CODE,
                "installed state schema is malformed; run the installer migration",
            ) from exc
    # Build the expected projection in an isolated in-memory database.  This
    # keeps the contract tied to the installer DDL without ever applying that
    # DDL to the caller's state database.  Comparing column sets (rather than
    # CREATE TABLE text) remains compatible with additive migrations whose
    # physical column order differs from a fresh install.
    with contextlib.closing(sqlite3.connect(":memory:")) as expected:
        ensure_schema(expected)
        required_intent_columns = {
            str(row[1]) for row in expected.execute("PRAGMA table_info(memory_write_intents)")
        }
        required_receipt_columns = {
            str(row[1]) for row in expected.execute("PRAGMA table_info(memory_write_receipts)")
        }
        expected_auxiliary_columns = {
            table: {str(row[1]) for row in expected.execute(f"PRAGMA table_info({table})")}
            for table in required_tables - {"meta", "memory_write_intents", "memory_write_receipts"}
        }
        required_indexes = {
            str(row[0])
            for row in expected.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
            )
        }
    actual_auxiliary_columns = {
        table: (
            {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}
            if table in tables
            else set()
        )
        for table in expected_auxiliary_columns
    }
    actual_indexes = {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
        )
    }
    privacy_guards_ready = False
    try:
        privacy_guards_ready = bool(search_log_privacy_guard_report(conn).get("ready"))
    except sqlite3.Error:
        privacy_guards_ready = False
    if (
        not required_tables.issubset(tables)
        or not required_intent_columns.issubset(intent_columns)
        or not required_receipt_columns.issubset(receipt_columns)
        or any(
            not columns.issubset(actual_auxiliary_columns.get(table, set()))
            for table, columns in expected_auxiliary_columns.items()
        )
        or not required_indexes.issubset(actual_indexes)
        or not privacy_guards_ready
        or state_version is None
        or str(state_version[0]) != str(STATE_SCHEMA_VERSION)
        or writer_version is None
        or str(writer_version[0]) != str(WRITER_PROTOCOL_VERSION)
    ):
        raise IntentError(
            STATE_SCHEMA_REASON_CODE,
            "installed state schema is missing or outdated; run the installer migration",
        )


def connect(
    state_db: Path | None = None,
    *,
    read_only: bool = False,
    side_effect_free: bool = False,
) -> sqlite3.Connection:
    if not read_only:
        assert_runtime_ready("state-write")
    db_path = Path(state_db or STATE_DB).expanduser()
    if not db_path.exists():
        raise IntentError(
            STATE_SCHEMA_REASON_CODE,
            "installed state database is missing; run the installer migration",
        )
    try:
        conn = secure_sqlite_connect(
            db_path,
            timeout=10,
            create=False,
            read_only=read_only,
            side_effect_free=side_effect_free,
            row_factory=sqlite3.Row,
            pragmas=("PRAGMA busy_timeout=10000", "PRAGMA foreign_keys=ON"),
        )
    except StateSecurityError as exc:
        if not db_path.exists():
            raise IntentError(
                STATE_SCHEMA_REASON_CODE,
                "installed state database is missing; run the installer migration",
            ) from exc
        raise IntentError("STATE_DB_PERMISSION_FAILED", "cannot restrict the intent state database to mode 0600") from exc
    try:
        # Ordinary reads and writes are verify-only.  The explicit installer
        # migrator calls ensure_schema() after an online backup; no production
        # command may silently CREATE/ALTER a partially damaged v4 database.
        assert_schema_ready(conn)
    except Exception:
        conn.close()
        raise
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, name: str, declaration: str) -> None:
    columns = {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}
    if name not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone() is not None


def ensure_schema(conn: sqlite3.Connection, *, commit: bool = True) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_write_intents (
          intent_id TEXT PRIMARY KEY,
          schema_version INTEGER NOT NULL DEFAULT 4,
          writer_protocol_version INTEGER NOT NULL DEFAULT 2,
          actor TEXT NOT NULL,
          session_hash TEXT NOT NULL,
          target_rel_path TEXT NOT NULL,
          target_key TEXT NOT NULL,
          fencing_token INTEGER NOT NULL DEFAULT 0,
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
          operation TEXT NOT NULL DEFAULT 'content_update',
          target_status TEXT NOT NULL DEFAULT '',
          transition_reason_sha256 TEXT NOT NULL DEFAULT '',
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
          writer_protocol_version INTEGER NOT NULL DEFAULT 2,
          actor TEXT NOT NULL,
          session_hash TEXT NOT NULL,
          target_rel_path TEXT NOT NULL,
          target_key TEXT NOT NULL,
          fencing_token INTEGER NOT NULL DEFAULT 0,
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
          operation TEXT NOT NULL DEFAULT 'content_update',
          target_status TEXT NOT NULL DEFAULT '',
          transition_reason_sha256 TEXT NOT NULL DEFAULT '',
          detail_code TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          FOREIGN KEY(intent_id) REFERENCES memory_write_intents(intent_id)
        )
        """
    )
    intent_migrations = {
        "writer_protocol_version": "INTEGER NOT NULL DEFAULT 1",
        "fencing_token": "INTEGER NOT NULL DEFAULT 0",
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
        "operation": "TEXT NOT NULL DEFAULT 'content_update'",
        "target_status": "TEXT NOT NULL DEFAULT ''",
        "transition_reason_sha256": "TEXT NOT NULL DEFAULT ''",
    }
    for name, declaration in intent_migrations.items():
        _ensure_column(conn, "memory_write_intents", name, declaration)
    receipt_migrations = {
        "writer_protocol_version": "INTEGER NOT NULL DEFAULT 1",
        "fencing_token": "INTEGER NOT NULL DEFAULT 0",
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
        "operation": "TEXT NOT NULL DEFAULT 'content_update'",
        "target_status": "TEXT NOT NULL DEFAULT ''",
        "transition_reason_sha256": "TEXT NOT NULL DEFAULT ''",
    }
    for name, declaration in receipt_migrations.items():
        _ensure_column(conn, "memory_write_receipts", name, declaration)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_path_fences (
          target_key TEXT PRIMARY KEY,
          last_fence INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL,
          CHECK (last_fence >= 0)
        )
        """
    )
    # These projections are part of the state-v4 minimum, so a fresh install
    # can publish schema 4 before the first write or observability event.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_session_claims (
          session_hash TEXT NOT NULL,
          actor TEXT NOT NULL,
          path TEXT NOT NULL,
          rel_path TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          claimed_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          completed_at TEXT,
          intent_id TEXT NOT NULL DEFAULT '',
          target_key TEXT NOT NULL DEFAULT '',
          fencing_token INTEGER NOT NULL DEFAULT 0,
          claim_kind TEXT NOT NULL DEFAULT 'legacy',
          PRIMARY KEY (session_hash, path)
        )
        """
    )
    for name, declaration in {
        "intent_id": "TEXT NOT NULL DEFAULT ''",
        "target_key": "TEXT NOT NULL DEFAULT ''",
        "fencing_token": "INTEGER NOT NULL DEFAULT 0",
        "claim_kind": "TEXT NOT NULL DEFAULT 'legacy'",
    }.items():
        _ensure_column(conn, "memory_session_claims", name, declaration)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_file_observations (
          path TEXT PRIMARY KEY,
          rel_path TEXT NOT NULL,
          sha256 TEXT NOT NULL,
          actor TEXT NOT NULL,
          session_hash TEXT NOT NULL DEFAULT '',
          intent_id TEXT NOT NULL DEFAULT '',
          fencing_token INTEGER NOT NULL DEFAULT 0,
          git_commit TEXT NOT NULL DEFAULT '',
          observed_at TEXT NOT NULL
        )
        """
    )
    for name, declaration in {
        "intent_id": "TEXT NOT NULL DEFAULT ''",
        "fencing_token": "INTEGER NOT NULL DEFAULT 0",
        "git_commit": "TEXT NOT NULL DEFAULT ''",
    }.items():
        _ensure_column(conn, "memory_file_observations", name, declaration)
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
        """
        CREATE TABLE IF NOT EXISTS memory_closeout_incidents (
          incident_id TEXT PRIMARY KEY,
          intent_id TEXT NOT NULL,
          target_key TEXT NOT NULL,
          rel_path TEXT NOT NULL,
          expected_sha256 TEXT NOT NULL,
          observed_sha256 TEXT NOT NULL DEFAULT '',
          git_commit TEXT NOT NULL,
          reason_code TEXT NOT NULL,
          detected_at TEXT NOT NULL,
          resolved_at TEXT,
          resolution_intent_id TEXT NOT NULL DEFAULT '',
          resolution_git_commit TEXT NOT NULL DEFAULT '',
          UNIQUE(intent_id, reason_code)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS generated_index_closeout_transactions (
          transaction_id TEXT PRIMARY KEY,
          actor TEXT NOT NULL,
          task_sha256 TEXT NOT NULL,
          vault_root_sha256 TEXT NOT NULL,
          git_head TEXT NOT NULL,
          index_base_sha256 TEXT NOT NULL,
          full_vault_inputs_sha256 TEXT NOT NULL,
          lease_fences_sha256 TEXT NOT NULL,
          capability_sha256 TEXT NOT NULL UNIQUE,
          issuer_pid INTEGER NOT NULL,
          consumer_pid INTEGER,
          status TEXT NOT NULL,
          issued_at_epoch INTEGER NOT NULL,
          expires_at_epoch INTEGER NOT NULL,
          claimed_at_epoch INTEGER,
          consumed_at_epoch INTEGER,
          generated_sha256 TEXT NOT NULL DEFAULT '',
          closeout_git_commit TEXT NOT NULL DEFAULT '',
          failure_reason TEXT NOT NULL DEFAULT '',
          failure_at_epoch INTEGER,
          rollback_evidence_path TEXT NOT NULL DEFAULT '',
          CHECK (status IN ('registered','issued','claimed','generated_bound','consumed','rolled_back','failed')),
          CHECK (issuer_pid > 0),
          CHECK (expires_at_epoch >= issued_at_epoch)
        )
        """
    )
    for name, declaration in {
        "resolution_intent_id": "TEXT NOT NULL DEFAULT ''",
        "resolution_git_commit": "TEXT NOT NULL DEFAULT ''",
    }.items():
        _ensure_column(conn, "memory_closeout_incidents", name, declaration)
    for name, declaration in {
        "failure_reason": "TEXT NOT NULL DEFAULT ''",
        "failure_at_epoch": "INTEGER",
        "rollback_evidence_path": "TEXT NOT NULL DEFAULT ''",
    }.items():
        _ensure_column(conn, "generated_index_closeout_transactions", name, declaration)
    conn.execute(
        "UPDATE generated_index_closeout_transactions "
        "SET failure_reason='GENERATED_INDEX_LEGACY_FAILURE', "
        "failure_at_epoch=COALESCE(failure_at_epoch, expires_at_epoch, issued_at_epoch) "
        "WHERE status='failed' AND (failure_reason='' OR failure_at_epoch IS NULL)"
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
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_session_claims_active_intent "
        "ON memory_session_claims(intent_id) WHERE intent_id<>'' AND status='active'"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_session_claims_active_target "
        "ON memory_session_claims(target_key) WHERE target_key<>'' AND status='active'"
    )
    ensure_observability_v2_schema(conn)
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
        ("agent_memory_state_schema_version", str(STATE_SCHEMA_VERSION)),
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
        ("agent_memory_writer_protocol_version", str(WRITER_PROTOCOL_VERSION)),
    )
    if commit:
        conn.commit()


def _allocate_fencing_token(conn: sqlite3.Connection, target_key: str) -> int:
    """Allocate a monotonic token for one canonical target inside a write transaction."""

    now = utc_now()
    conn.execute(
        "INSERT OR IGNORE INTO memory_path_fences(target_key, last_fence, updated_at) VALUES (?, 0, ?)",
        (target_key, now),
    )
    conn.execute(
        "UPDATE memory_path_fences SET last_fence=last_fence+1, updated_at=? WHERE target_key=?",
        (now, target_key),
    )
    row = conn.execute(
        "SELECT last_fence FROM memory_path_fences WHERE target_key=?",
        (target_key,),
    ).fetchone()
    token = int(row[0]) if row is not None else 0
    if token <= 0:
        raise IntentError("FENCE_ALLOCATION_FAILED", "could not allocate a positive path fencing token")
    return token


def assert_current_lease(
    intent_id: str,
    *,
    actor: str,
    raw_session_id: str,
    fencing_token: int | None = None,
    target: str | Path | None = None,
    require_unexpired: bool = True,
    connection: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Return the active intent only when it still owns the latest path fence."""

    owns_connection = connection is None
    conn = connect(read_only=True) if owns_connection else connection
    if conn is None:
        raise IntentError("STATE_DB_UNAVAILABLE", "intent state connection is unavailable")
    try:
        intent = _fetch_intent(conn, intent_id)
        if intent is None:
            raise IntentError("INTENT_NOT_FOUND", f"write intent not found: {intent_id}")
        _authorize_intent(intent, actor=actor, raw_session_id=raw_session_id)
        if str(intent.get("status", "")) not in ACTIVE_STATUSES:
            raise IntentError("LEASE_NOT_ACTIVE", "write intent no longer owns an active path lease")
        stored_token = int(intent.get("fencing_token") or 0)
        if stored_token <= 0 or (fencing_token is not None and int(fencing_token) != stored_token):
            raise IntentError("LEASE_FENCED", "path lease fencing token is stale")
        canonical = canonical_target(target or str(intent["target_rel_path"]))
        if canonical.target_key != str(intent["target_key"]):
            raise IntentError("INTENT_TARGET_MISMATCH", "path lease target does not match the intent")
        latest = conn.execute(
            "SELECT last_fence FROM memory_path_fences WHERE target_key=?",
            (canonical.target_key,),
        ).fetchone()
        if latest is None or int(latest[0]) != stored_token:
            raise IntentError("LEASE_FENCED", "a newer writer owns this path fence")
        if require_unexpired and _intent_expired(intent):
            raise IntentError("INTENT_EXPIRED", "path lease has expired")
        return _public_intent(intent)
    finally:
        if owns_connection:
            conn.close()


def renew_lease(
    intent_id: str,
    *,
    actor: str,
    raw_session_id: str,
    fencing_token: int,
    ttl_hours: float | None = None,
) -> dict[str, Any]:
    """Extend an active lease without changing its monotonic fencing token."""

    hours = DEFAULT_TTL_HOURS if ttl_hours is None else float(ttl_hours)
    if hours <= 0:
        raise IntentError("TTL_INVALID", "intent ttl_hours must be positive")
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        intent = assert_current_lease(
            intent_id,
            actor=actor,
            raw_session_id=raw_session_id,
            fencing_token=fencing_token,
            connection=conn,
        )
        if str(intent.get("reason_code", "")) in {
            EXPIRED_VALIDATED_RECOVERY_REASON,
            EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON,
        }:
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_RENEW_FORBIDDEN",
                "the bounded expired-write recovery window cannot be renewed",
            )
        now_value = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        expires_at = (now_value + dt.timedelta(hours=hours)).isoformat()
        cursor = conn.execute(
            "UPDATE memory_write_intents SET expires_at=?, updated_at=? "
            "WHERE intent_id=? AND fencing_token=? AND status IN ('pending','approved','bound','validated')",
            (expires_at, now_value.isoformat(), intent_id, int(intent["fencing_token"])),
        )
        if cursor.rowcount != 1:
            raise IntentError("LEASE_FENCED", "path lease changed while it was being renewed")
        conn.commit()
    return show_intent(intent_id)["intent"]


def _generated_index_repair_lease_fences_sha256(
    *,
    intent_id: str,
    fencing_token: int,
    rel_path: str,
) -> str:
    projection = [
        (
            intent_id,
            int(fencing_token),
            hashlib.sha256(rel_path.encode("utf-8")).hexdigest(),
            "live",
        )
    ]
    return hashlib.sha256(
        json.dumps(
            projection,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _validate_generated_index_repair_receipt(
    conn: sqlite3.Connection,
    *,
    intent: dict[str, Any],
    actor: str,
    raw_session_id: str,
    canonical: CanonicalTarget,
    generated_index_recovery: dict[str, Any] | None,
    first_recovery_published_at: dt.datetime | None = None,
    first_recovery_expires_at: dt.datetime | None = None,
) -> None:
    """Bind the one repair window to an exact, already-consumed INDEX row."""

    required = {
        "transaction_id",
        "status",
        "git_head",
        "index_base_sha256",
        "generated_sha256",
        "closeout_git_commit",
        "lease_fences_sha256",
    }
    if (
        not isinstance(generated_index_recovery, dict)
        or set(generated_index_recovery) != required
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_REPAIR_EVIDENCE_INVALID",
            "repair recovery requires one exact generated-index receipt",
        )
    transaction_id = str(
        generated_index_recovery.get("transaction_id", "")
    ).strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}", transaction_id) is None:
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_REPAIR_EVIDENCE_INVALID",
            "repair recovery transaction id is invalid",
        )
    row = conn.execute(
        "SELECT * FROM generated_index_closeout_transactions "
        "WHERE transaction_id=?",
        (transaction_id,),
    ).fetchone()
    if row is None:
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_REPAIR_EVIDENCE_INVALID",
            "repair recovery transaction is missing",
        )
    receipt = _row_dict(row) or {}
    intent_id = str(intent.get("intent_id", ""))
    fencing_token = int(intent.get("fencing_token") or 0)
    expected_fences = _generated_index_repair_lease_fences_sha256(
        intent_id=intent_id,
        fencing_token=fencing_token,
        rel_path=canonical.rel_path,
    )
    expected = {
        "transaction_id": transaction_id,
        "actor": actor,
        "task_sha256": hashlib.sha256(
            raw_session_id.encode("utf-8")
        ).hexdigest(),
        "vault_root_sha256": hashlib.sha256(
            str(VAULT_ROOT.resolve()).encode("utf-8")
        ).hexdigest(),
        "git_head": str(generated_index_recovery["git_head"]),
        "index_base_sha256": str(
            generated_index_recovery["index_base_sha256"]
        ),
        "lease_fences_sha256": expected_fences,
        "status": "consumed",
        "generated_sha256": str(
            generated_index_recovery["generated_sha256"]
        ),
        "closeout_git_commit": str(
            generated_index_recovery["closeout_git_commit"]
        ),
    }
    if any(str(receipt.get(key, "")) != value for key, value in expected.items()):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_REPAIR_EVIDENCE_INVALID",
            "repair recovery transaction binding changed",
        )
    if any(
        str(generated_index_recovery[key]) != str(receipt.get(key, ""))
        for key in required - {"transaction_id"}
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_REPAIR_EVIDENCE_INVALID",
            "repair recovery response does not match durable state",
        )
    git_head = str(receipt.get("git_head", ""))
    index_base = str(receipt.get("index_base_sha256", ""))
    generated = str(receipt.get("generated_sha256", ""))
    if (
        re.fullmatch(r"[0-9a-f]{40,64}", git_head) is None
        or re.fullmatch(r"[0-9a-f]{64}", index_base) is None
        or generated != index_base
        or str(receipt.get("closeout_git_commit", "")) != git_head
        or re.fullmatch(
            r"[0-9a-f]{64}",
            str(receipt.get("full_vault_inputs_sha256", "")),
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}",
            str(receipt.get("capability_sha256", "")),
        )
        is None
        or int(receipt.get("issuer_pid") or 0) <= 0
        or int(receipt.get("consumer_pid") or 0) <= 0
        or receipt.get("claimed_at_epoch") is None
        or receipt.get("consumed_at_epoch") is None
        or str(receipt.get("failure_reason", ""))
        or receipt.get("failure_at_epoch") is not None
        or str(receipt.get("rollback_evidence_path", ""))
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_REPAIR_EVIDENCE_INVALID",
            "repair recovery is not one clean exact no-change INDEX consumption",
        )
    issued_at = int(receipt.get("issued_at_epoch") or 0)
    expires_at = int(receipt.get("expires_at_epoch") or 0)
    claimed_at = int(receipt.get("claimed_at_epoch") or 0)
    consumed_at = int(receipt.get("consumed_at_epoch") or 0)
    if (
        issued_at <= 0
        or expires_at < issued_at
        or claimed_at < issued_at
        or consumed_at < claimed_at
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_REPAIR_EVIDENCE_INVALID",
            "repair recovery transaction chronology is invalid",
        )
    if (
        first_recovery_published_at is not None
        and first_recovery_expires_at is not None
    ):
        published_epoch = int(first_recovery_published_at.timestamp())
        first_expiry_epoch = int(first_recovery_expires_at.timestamp())
        if (
            issued_at < published_epoch
            or expires_at > first_expiry_epoch
            or claimed_at > first_expiry_epoch
        ):
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_REPAIR_EVIDENCE_INVALID",
                "generated-index transaction is not bound to the first recovery window",
            )
    open_rows = conn.execute(
        "SELECT transaction_id FROM generated_index_closeout_transactions "
        "WHERE status IN ('registered','issued','claimed','generated_bound','failed')"
    ).fetchall()
    if open_rows:
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_REPAIR_EVIDENCE_INVALID",
            "another generated-index transaction remains unresolved",
        )


def _stable_regular_target_snapshot(
    canonical: CanonicalTarget,
) -> tuple[ContentDigest, tuple[int, ...]]:
    """Read one non-executable regular target without accepting a path race."""

    try:
        before = canonical.path.lstat()
    except OSError as exc:
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_TARGET_DRIFT",
            "committed recovery target is unavailable",
        ) from exc
    current_uid = os.geteuid() if hasattr(os, "geteuid") else before.st_uid
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != current_uid
        or bool(before.st_mode & 0o111)
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_WORKTREE_UNSAFE",
            "committed recovery target is not one owner-controlled regular file",
        )
    exists, digest = _read_target(canonical)
    try:
        after = canonical.path.lstat()
    except OSError as exc:
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_TARGET_DRIFT",
            "committed recovery target changed while it was read",
        ) from exc
    before_projection = (
        before.st_dev,
        before.st_ino,
        before.st_uid,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_projection = (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if not exists or before_projection != after_projection:
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_TARGET_DRIFT",
            "committed recovery target changed while it was read",
        )
    return digest, after_projection


def assert_committed_content_update_recovery_projection(
    intent: dict[str, Any],
    *,
    target: str | Path,
    expected_current_git_head: str,
) -> None:
    """Prove validated -> committed bytes for one ordinary ADD or UPDATE.

    This check is intentionally stricter than normal closeout recovery.  The
    validated Git head must still contain the exact prepared base, the target
    must then change at least once, and every target-changing descendant must
    contain the exact raw and canonical proposal as a regular 100644 blob.
    Unrelated descendant commits are permitted; path drift, changed-then-
    reverted history, staged bytes, worktree bytes, and aliases are not.
    """

    canonical = canonical_target(target)
    action = str(intent.get("reconcile_action", "")).upper()
    if (
        str(intent.get("operation", "")).casefold() != "content_update"
        or action not in {"ADD", "UPDATE"}
        or canonical.rel_path != str(intent.get("target_rel_path", ""))
        or canonical.target_key != str(intent.get("target_key", ""))
        or str(intent.get("validation_mode", "")) != "exact"
        or bool(int(intent.get("early_commit") or 0))
        or str(intent.get("proposal_commit", ""))
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_BINDING_CHANGED",
            "committed content recovery no longer matches the validated write",
        )
    proposal_pair = (
        str(intent.get("proposal_raw_sha256", "")),
        str(intent.get("proposal_canonical_sha256", "")),
    )
    if (
        proposal_pair
        != (
            str(intent.get("final_raw_sha256", "")),
            str(intent.get("final_canonical_sha256", "")),
        )
        or any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in proposal_pair)
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_BINDING_CHANGED",
            "committed content recovery proposal hashes changed",
        )
    current_head = str(expected_current_git_head).strip().casefold()
    base_head = str(intent.get("base_git_head", "")).strip().casefold()
    validated_head = str(intent.get("validated_git_head", "")).strip().casefold()
    if any(
        re.fullmatch(r"[0-9a-f]{40,64}", value) is None
        for value in (base_head, validated_head, current_head)
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_GIT_PROJECTION_UNAVAILABLE",
            "committed content recovery Git binding is invalid",
        )
    if (
        current_git_head(required=True) != current_head
        or current_head == validated_head
        or not _git_is_ancestor(base_head, validated_head)
        or not _git_is_ancestor(validated_head, current_head)
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_GIT_DIVERGED",
            "committed content recovery Git ancestry changed",
        )

    base_exists = bool(int(intent.get("base_exists") or 0))
    if base_exists != (action == "UPDATE"):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_BINDING_CHANGED",
            "committed content recovery action no longer matches its base",
        )
    base_pair = (
        str(intent.get("base_raw_sha256", "")),
        str(intent.get("base_canonical_sha256", "")),
    )
    base_at_head_exists, base_at_head = git_target_digest_at_commit(
        base_head,
        canonical,
    )
    validated_exists, validated_digest = git_target_digest_at_commit(
        validated_head,
        canonical,
    )
    base_mode_exists, base_mode = git_target_mode_at_commit(base_head, canonical)
    validated_mode_exists, validated_mode = git_target_mode_at_commit(
        validated_head,
        canonical,
    )
    base_to_validated = git_version_chain(base_head, validated_head, canonical)
    if (
        base_to_validated.get("ok") is not True
        or bool(base_to_validated.get("versions"))
        or base_at_head_exists != base_exists
        or validated_exists != base_exists
        or base_mode_exists != base_exists
        or validated_mode_exists != base_exists
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_TARGET_HISTORY_CHANGED",
            "the target changed before its validated Git head",
        )
    if base_exists:
        if (
            base_mode != "100644"
            or validated_mode != "100644"
            or (base_at_head.raw_sha256, base_at_head.canonical_sha256) != base_pair
            or (validated_digest.raw_sha256, validated_digest.canonical_sha256)
            != base_pair
        ):
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_COMMIT_CONTENT_MISMATCH",
                "the validated Git target no longer matches the prepared base",
            )
    elif base_pair != (EMPTY_RAW_SHA256, EMPTY_RAW_SHA256):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_COMMIT_CONTENT_MISMATCH",
            "the validated ADD base is not the exact absent-file digest",
        )

    head_exists, head_digest = git_target_digest_at_commit(current_head, canonical)
    head_mode_exists, head_mode = git_target_mode_at_commit(current_head, canonical)
    if (
        not head_exists
        or not head_mode_exists
        or head_mode != "100644"
        or (head_digest.raw_sha256, head_digest.canonical_sha256) != proposal_pair
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_COMMIT_CONTENT_MISMATCH",
            "the current Git target is not the exact committed proposal",
        )
    history = git_version_chain(validated_head, current_head, canonical)
    versions = history.get("versions")
    if history.get("ok") is not True or not isinstance(versions, list) or not versions:
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_TARGET_HISTORY_CHANGED",
            "committed recovery requires nonempty exact target history",
        )
    for version in versions:
        if (
            not isinstance(version, dict)
            or version.get("exists") is not True
            or (
                str(version.get("raw_sha256", "")),
                str(version.get("canonical_sha256", "")),
            )
            != proposal_pair
        ):
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_TARGET_HISTORY_CHANGED",
                "target-changing history contains bytes other than the proposal",
            )
        mode_exists, mode = git_target_mode_at_commit(
            str(version.get("commit", "")),
            canonical,
        )
        if not mode_exists or mode != "100644":
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_TARGET_HISTORY_CHANGED",
                "target-changing history contains a non-regular Git mode",
            )

    live_digest, stable_projection = _stable_regular_target_snapshot(canonical)
    repo_path = _repo_rel_path(canonical)
    if (
        (live_digest.raw_sha256, live_digest.canonical_sha256) != proposal_pair
        or not _git_path_matches_worktree(current_head, repo_path)
        or _run_git(
            "diff",
            "--cached",
            "--quiet",
            current_head,
            "--",
            repo_path,
        ).returncode
        != 0
        or current_git_head(required=True) != current_head
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_WORKTREE_DIRTY",
            "committed recovery target is not clean at the expected Git head",
        )
    try:
        final_stat = canonical.path.lstat()
    except OSError as exc:
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_TARGET_DRIFT",
            "committed recovery target changed after validation",
        ) from exc
    final_projection = (
        final_stat.st_dev,
        final_stat.st_ino,
        final_stat.st_uid,
        final_stat.st_mode,
        final_stat.st_size,
        final_stat.st_mtime_ns,
        final_stat.st_ctime_ns,
    )
    if final_projection != stable_projection:
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_TARGET_DRIFT",
            "committed recovery target changed after validation",
        )


def recover_expired_validated_lease(
    intent_id: str,
    *,
    actor: str,
    raw_session_id: str,
    target: str | Path,
    fencing_token: int,
    expected_expires_at: str,
    expected_base_raw_sha256: str,
    expected_base_canonical_sha256: str,
    expected_base_git_head: str,
    expected_read_token: str,
    expected_scope_app_id: str,
    expected_scope_project_id: str,
    expected_proposal_raw_sha256: str,
    expected_proposal_canonical_sha256: str,
    expected_proposal_size_bytes: int,
    expected_final_raw_sha256: str,
    expected_final_canonical_sha256: str,
    expected_validated_git_head: str,
    expected_early_commit: bool,
    expected_proposal_commit: str,
    expected_evidence_ref_sha256: str,
    expected_operation: str,
    expected_reconcile_action: str,
    expected_approved_by: str = "",
    expected_approval_ref_sha256: str = "",
    expected_approval_binding_sha256: str = "",
    expected_claim_ref_sha256: str = "",
    expected_current_git_head: str = "",
    ttl_seconds: int = EXPIRED_VALIDATED_RECOVERY_TTL_SECONDS,
    generated_index_recovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Narrowly reopen an expired, already-validated exact write.

    This is deliberately not a general lease renewal API.  It admits either
    the existing capability-bound governance repair or one ordinary ADD/UPDATE
    whose normal approval and exact post-validation Git commit are proven.
    Immutable review fields, current path fence, and active claim must still
    agree exactly.  The marker makes a crash after this transaction auditable
    and idempotently resumable; ordinary unexpired intents cannot enter it.
    """

    if (
        not isinstance(ttl_seconds, int)
        or isinstance(ttl_seconds, bool)
        or ttl_seconds <= 0
        or ttl_seconds > EXPIRED_VALIDATED_RECOVERY_TTL_SECONDS
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_TTL_INVALID",
            "expired validated recovery has a bounded lease window",
        )
    governance_recovery = (
        expected_operation == "governance_migration"
        and expected_reconcile_action == "UPDATE"
    )
    content_update_recovery = (
        expected_operation == "content_update"
        and expected_reconcile_action in {"ADD", "UPDATE"}
    )
    if actor not in {"codex", "claude"} or not (
        governance_recovery or content_update_recovery
    ):
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_OPERATION_INVALID",
            "expired validated recovery is limited to exact supported closeout",
        )
    if content_update_recovery and generated_index_recovery is not None:
        raise IntentError(
            "EXPIRED_VALIDATED_RECOVERY_REPAIR_NOT_ALLOWED",
            "ordinary content recovery cannot consume governance repair evidence",
        )
    canonical = canonical_target(target)
    now_value = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    now = now_value.isoformat()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        stored = _fetch_intent(conn, intent_id)
        if stored is None:
            raise IntentError("INTENT_NOT_FOUND", f"write intent not found: {intent_id}")
        _authorize_intent(stored, actor=actor, raw_session_id=raw_session_id)
        if str(stored.get("status", "")) != "validated":
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_STATE_INVALID",
                "recovery requires one still-active validated intent",
            )
        receipt = conn.execute(
            "SELECT receipt_id FROM memory_write_receipts WHERE intent_id=?",
            (intent_id,),
        ).fetchone()
        if receipt is not None:
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_RECEIPT_CONFLICT",
                "validated recovery cannot replay a terminal receipt",
            )
        stored_reason = str(stored.get("reason_code", ""))
        already_recovered = stored_reason == EXPIRED_VALIDATED_RECOVERY_REASON
        repair_recovered = (
            stored_reason == EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON
        )
        if content_update_recovery and repair_recovered:
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_STATE_INVALID",
                "ordinary content recovery cannot enter the governance repair lane",
            )
        if stored_reason not in {
            "",
            EXPIRED_VALIDATED_RECOVERY_REASON,
            EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON,
        }:
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_STATE_INVALID",
                "validated recovery marker conflicts with intent state",
            )
        stored_expiry = parse_time(str(stored.get("expires_at", "")))
        if stored_expiry is None:
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_EXPIRY_INVALID",
                "validated recovery requires one parseable lease expiry",
            )
        expired_now = stored_expiry <= now_value
        published_at: dt.datetime | None = None
        recovery_window: dt.timedelta | None = None
        if already_recovered or repair_recovered:
            published_at = parse_time(str(stored.get("updated_at", "")))
            recovery_window = (
                stored_expiry - published_at
                if published_at is not None
                else None
            )
            maximum_window = (
                EXPIRED_VALIDATED_RECOVERY_REPAIR_TTL_SECONDS
                if repair_recovered
                else EXPIRED_VALIDATED_RECOVERY_TTL_SECONDS
            )
            if (
                published_at is None
                or published_at > now_value
                or recovery_window is None
                or recovery_window <= dt.timedelta(0)
                or recovery_window
                > dt.timedelta(seconds=maximum_window)
            ):
                raise IntentError(
                    "EXPIRED_VALIDATED_RECOVERY_EXPIRY_INVALID",
                    "validated recovery marker has no bounded publication window",
                )
            if expired_now:
                if repair_recovered:
                    raise IntentError(
                        "EXPIRED_VALIDATED_RECOVERY_REPAIR_WINDOW_ELAPSED",
                        "the one repair recovery window has elapsed",
                    )
                if generated_index_recovery is None:
                    raise IntentError(
                        "EXPIRED_VALIDATED_RECOVERY_WINDOW_ELAPSED",
                        "the one bounded recovery window has elapsed",
                    )
        elif not expired_now:
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_NOT_EXPIRED",
                "ordinary unexpired writes cannot use recovery",
            )
        elif generated_index_recovery is not None:
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_REPAIR_NOT_ALLOWED",
                "generated-index repair is limited to an elapsed first recovery window",
            )
        if str(stored.get("expires_at", "")) != expected_expires_at:
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_STATE_CHANGED",
                "validated recovery lease changed after preflight",
            )
        expected = {
            "target_rel_path": canonical.rel_path,
            "target_key": canonical.target_key,
            "fencing_token": int(fencing_token),
            "base_raw_sha256": expected_base_raw_sha256,
            "base_canonical_sha256": expected_base_canonical_sha256,
            "base_git_head": expected_base_git_head,
            "read_token": expected_read_token,
            "scope_app_id": expected_scope_app_id,
            "scope_project_id": expected_scope_project_id,
            "proposal_raw_sha256": expected_proposal_raw_sha256,
            "proposal_canonical_sha256": expected_proposal_canonical_sha256,
            "proposal_size_bytes": int(expected_proposal_size_bytes),
            "final_raw_sha256": expected_final_raw_sha256,
            "final_canonical_sha256": expected_final_canonical_sha256,
            "validated_git_head": expected_validated_git_head,
            "early_commit": int(bool(expected_early_commit)),
            "proposal_commit": expected_proposal_commit,
            "evidence_ref_sha256": expected_evidence_ref_sha256,
            "operation": expected_operation,
            "reconcile_action": expected_reconcile_action,
        }
        if any(stored.get(key) != value for key, value in expected.items()):
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_BINDING_CHANGED",
                "validated recovery no longer matches the reviewed write",
            )
        common_binding_invalid = (
            str(stored.get("validation_mode", "")) != "exact"
            or not str(stored.get("validated_at", ""))
            or str(stored.get("bound_base_raw_sha256", ""))
            != expected_base_raw_sha256
            or not str(stored.get("claim_ref_sha256", ""))
            or int(stored.get("approval_required") or 0) != 1
            or str(stored.get("target_status", ""))
            or str(stored.get("transition_reason_sha256", ""))
            or str(stored.get("reason_code", ""))
            not in {
                "",
                EXPIRED_VALIDATED_RECOVERY_REASON,
                EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON,
            }
        )
        governance_binding_invalid = governance_recovery and (
            int(stored.get("base_exists") or 0) != 1
            or not has_valid_confirmation_capability_approval(stored)
            or str(stored.get("source_class", "")) != "user_direct"
            or str(stored.get("knowledge_kind", "")) != "rule"
            or str(stored.get("asserted_by", "")) != "user"
        )
        content_binding_invalid = content_update_recovery and (
            int(stored.get("base_exists") or 0)
            != int(expected_reconcile_action == "UPDATE")
            or bool(int(stored.get("early_commit") or 0))
            or bool(str(stored.get("proposal_commit", "")))
            or not has_valid_ordinary_approval(stored)
            or str(stored.get("approved_by", "")) != expected_approved_by
            or str(stored.get("approval_ref_sha256", ""))
            != expected_approval_ref_sha256
            or str(stored.get("approval_binding_sha256", ""))
            != expected_approval_binding_sha256
            or str(stored.get("claim_ref_sha256", ""))
            != expected_claim_ref_sha256
            or not str(stored.get("source_class", ""))
            or not str(stored.get("knowledge_kind", ""))
            or not str(stored.get("asserted_by", ""))
            or str(stored.get("safety_decision", "")).upper() != "ALLOW"
            or re.fullmatch(r"[0-9a-f]{64}", expected_approval_ref_sha256)
            is None
            or re.fullmatch(r"[0-9a-f]{64}", expected_approval_binding_sha256)
            is None
            or re.fullmatch(r"[0-9a-f]{64}", expected_claim_ref_sha256)
            is None
        )
        if common_binding_invalid or governance_binding_invalid or content_binding_invalid:
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_BINDING_CHANGED",
                "validated recovery lacks exact approval or validation evidence",
            )
        latest = conn.execute(
            "SELECT last_fence FROM memory_path_fences WHERE target_key=?",
            (canonical.target_key,),
        ).fetchone()
        if latest is None or int(latest[0]) != int(fencing_token):
            raise IntentError("LEASE_FENCED", "a newer writer owns this target fence")
        claims = conn.execute(
            "SELECT session_hash, actor, path, rel_path, status, completed_at, "
            "intent_id, target_key, fencing_token, claim_kind "
            "FROM memory_session_claims WHERE status='active' "
            "AND (intent_id=? OR target_key=?)",
            (intent_id, canonical.target_key),
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
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_CLAIM_CHANGED",
                "validated recovery requires the exact active claim projection",
            )
        if content_update_recovery:
            assert_committed_content_update_recovery_projection(
                stored,
                target=canonical.path,
                expected_current_git_head=expected_current_git_head,
            )
        if repair_recovered:
            _validate_generated_index_repair_receipt(
                conn,
                intent=stored,
                actor=actor,
                raw_session_id=raw_session_id,
                canonical=canonical,
                generated_index_recovery=generated_index_recovery,
            )
            # A retry inside the one repair window is idempotent.  This marker
            # is terminal with respect to lease publication: once it expires,
            # no third window can be created.
            conn.commit()
            return _public_intent(stored)
        if already_recovered and not expired_now:
            if generated_index_recovery is not None:
                raise IntentError(
                    "EXPIRED_VALIDATED_RECOVERY_REPAIR_NOT_ALLOWED",
                    "the first recovery window is still active",
                )
            # A retry inside the originally published crash window is
            # idempotent.  Do not slide or renew that window indefinitely.
            conn.commit()
            return _public_intent(stored)
        if already_recovered:
            if published_at is None:
                raise IntentError(
                    "EXPIRED_VALIDATED_RECOVERY_EXPIRY_INVALID",
                    "validated recovery marker has no publication time",
                )
            _validate_generated_index_repair_receipt(
                conn,
                intent=stored,
                actor=actor,
                raw_session_id=raw_session_id,
                canonical=canonical,
                generated_index_recovery=generated_index_recovery,
                first_recovery_published_at=published_at,
                first_recovery_expires_at=stored_expiry,
            )
            repair_expires_at = (
                now_value
                + dt.timedelta(
                    seconds=EXPIRED_VALIDATED_RECOVERY_REPAIR_TTL_SECONDS
                )
            ).isoformat()
            cursor = conn.execute(
                "UPDATE memory_write_intents SET expires_at=?, reason_code=?, "
                "updated_at=? WHERE intent_id=? AND status='validated' "
                "AND fencing_token=? AND expires_at=? AND reason_code=?",
                (
                    repair_expires_at,
                    EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON,
                    now,
                    intent_id,
                    int(fencing_token),
                    expected_expires_at,
                    EXPIRED_VALIDATED_RECOVERY_REASON,
                ),
            )
            if cursor.rowcount != 1:
                raise IntentError(
                    "EXPIRED_VALIDATED_RECOVERY_STATE_CHANGED",
                    "validated recovery changed during repair publication",
                )
            conn.commit()
            return show_intent(intent_id)["intent"]
        expires_at = (
            now_value + dt.timedelta(seconds=ttl_seconds)
        ).isoformat()
        cursor = conn.execute(
            "UPDATE memory_write_intents SET expires_at=?, reason_code=?, "
            "updated_at=? WHERE intent_id=? AND status='validated' "
            "AND fencing_token=? AND expires_at=? AND reason_code=?",
            (
                expires_at,
                EXPIRED_VALIDATED_RECOVERY_REASON,
                now,
                intent_id,
                int(fencing_token),
                expected_expires_at,
                stored_reason,
            ),
        )
        if cursor.rowcount != 1:
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_STATE_CHANGED",
                "validated recovery changed during lease publication",
            )
        conn.commit()
    return show_intent(intent_id)["intent"]


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
    # ``zip(strict=...)`` was added in Python 3.10.  The public runtime still
    # supports Python 3.9, and cursor.description is guaranteed to match a
    # successfully fetched SQLite row here.
    return dict(zip(names, row))


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


def git_target_digest_at_commit(
    commit: str,
    target: CanonicalTarget,
) -> tuple[bool, ContentDigest]:
    """Read the immutable Git baseline used for write-policy recovery checks.

    This is deliberately separate from the mutable worktree baseline stored
    for ADOPT.  A retry after proposal bytes were written can therefore still
    prove whether a content_update preserved status, without adding another
    state-schema column or trusting the already-written proposal.
    """

    normalized_commit = str(commit).strip().casefold()
    if re.fullmatch(r"[0-9a-f]{40,64}", normalized_commit) is None:
        raise IntentError("GIT_BASE_UNAVAILABLE", "stored Git baseline is invalid")
    exists = _run_git("cat-file", "-e", f"{normalized_commit}^{{commit}}").returncode == 0
    if not exists:
        raise IntentError("GIT_BASE_UNAVAILABLE", "stored Git baseline is unavailable")
    blob = _git_blob(normalized_commit, _repo_rel_path(target))
    if blob is None:
        return False, ContentDigest(
            raw_sha256=EMPTY_RAW_SHA256,
            canonical_sha256=EMPTY_RAW_SHA256,
            size_bytes=0,
            text="",
        )
    return True, content_hashes(blob, max_bytes=MAX_TARGET_BYTES)


def git_target_mode_at_commit(
    commit: str,
    target: CanonicalTarget,
) -> tuple[bool, str]:
    """Return one exact Git tree mode without following worktree aliases."""

    normalized_commit = str(commit).strip().casefold()
    if re.fullmatch(r"[0-9a-f]{40,64}", normalized_commit) is None:
        raise IntentError("GIT_BASE_UNAVAILABLE", "stored Git baseline is invalid")
    repo_rel_path = _repo_rel_path(target)
    result = _run_git(
        "ls-tree",
        "-z",
        "--full-tree",
        normalized_commit,
        "--",
        repo_rel_path,
        binary=True,
    )
    if result.returncode != 0:
        raise IntentError("GIT_HISTORY_UNAVAILABLE", "Git tree entry is unavailable")
    records = [record for record in bytes(result.stdout).split(b"\0") if record]
    if not records:
        return False, ""
    if len(records) != 1:
        raise IntentError("GIT_HISTORY_UNAVAILABLE", "Git tree entry is ambiguous")
    try:
        header, raw_path = records[0].split(b"\t", 1)
        raw_mode, object_type, raw_oid = header.split()
        returned_path = raw_path.decode("utf-8", errors="strict")
        mode = raw_mode.decode("ascii", errors="strict")
        oid = raw_oid.decode("ascii", errors="strict")
    except (UnicodeError, ValueError) as exc:
        raise IntentError("GIT_HISTORY_UNAVAILABLE", "Git tree entry is invalid") from exc
    if (
        returned_path != repo_rel_path
        or object_type != b"blob"
        or re.fullmatch(r"[0-7]{6}", mode) is None
        or re.fullmatch(r"[0-9a-f]{40,64}", oid) is None
    ):
        raise IntentError("GIT_HISTORY_UNAVAILABLE", "Git tree entry is invalid")
    return True, mode


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
    result = _run_git(
        "rev-list",
        "--reverse",
        "--topo-order",
        "--full-history",
        f"{base_head}..{head}",
        "--",
        repo_rel_path,
    )
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
        "fencing_token": int(intent.get("fencing_token") or 0),
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


def intent_requires_confirmation_capability(intent: dict[str, Any]) -> bool:
    return (
        str(intent.get("reconcile_action", "")).upper() in SENSITIVE_CONFIRMATION_ACTIONS
        or str(intent.get("operation", "content_update")).casefold()
        in SENSITIVE_CONFIRMATION_OPERATIONS
    )


def has_valid_confirmation_capability_approval(intent: dict[str, Any]) -> bool:
    """Return true only for a complete approval minted from a consumed capability."""

    return bool(
        intent_requires_confirmation_capability(intent)
        and str(intent.get("approved_by", "")) == HUMAN_CONFIRMATION_CAPABILITY_APPROVER
        and str(intent.get("approved_at", ""))
        and str(intent.get("approval_proposal_raw_sha256", ""))
        == str(intent.get("proposal_raw_sha256", ""))
        and str(intent.get("approval_proposal_canonical_sha256", ""))
        == str(intent.get("proposal_canonical_sha256", ""))
        and str(intent.get("approval_ref_sha256", ""))
        and str(intent.get("approval_binding_sha256", "")) == _stored_approval_binding(intent)
    )


def has_valid_ordinary_approval(intent: dict[str, Any]) -> bool:
    """Return true only for one complete, non-capability approval binding."""

    return bool(
        not intent_requires_confirmation_capability(intent)
        and int(intent.get("approval_required") or 0) == 1
        and str(intent.get("approved_by", ""))
        and str(intent.get("approved_by", ""))
        != HUMAN_CONFIRMATION_CAPABILITY_APPROVER
        and str(intent.get("approved_at", ""))
        and str(intent.get("approval_proposal_raw_sha256", ""))
        == str(intent.get("proposal_raw_sha256", ""))
        and str(intent.get("approval_proposal_canonical_sha256", ""))
        == str(intent.get("proposal_canonical_sha256", ""))
        and re.fullmatch(
            r"[0-9a-f]{64}",
            str(intent.get("approval_ref_sha256", "")),
        )
        is not None
        and str(intent.get("approval_binding_sha256", ""))
        == _stored_approval_binding(intent)
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
              receipt_id, intent_id, writer_protocol_version, actor, session_hash,
              target_rel_path, target_key, fencing_token,
              outcome, reason_code, validation_mode, base_raw_sha256,
              proposal_raw_sha256, proposal_canonical_sha256, final_raw_sha256,
              final_canonical_sha256, base_git_head, validated_git_head, git_commit,
              early_commit, proposal_commit, approval_binding_sha256,
              approval_ref_sha256, source_class, knowledge_kind,
              asserted_by_sha256, safety_decision, safety_reason_code,
              safety_input_sha256, safety_input_length, evidence_ref_sha256,
              operation, target_status, transition_reason_sha256,
              detail_code, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                receipt_id, intent["intent_id"], intent["writer_protocol_version"],
                intent["actor"], intent["session_hash"], intent["target_rel_path"],
                intent["target_key"], intent["fencing_token"], "expired", "INTENT_EXPIRED",
                intent["validation_mode"], intent["base_raw_sha256"], intent["proposal_raw_sha256"],
                intent["proposal_canonical_sha256"], intent["final_raw_sha256"],
                intent["final_canonical_sha256"], intent["base_git_head"],
                intent["validated_git_head"], "", intent["early_commit"],
                intent["proposal_commit"], intent["approval_binding_sha256"],
                intent["approval_ref_sha256"], intent["source_class"], intent["knowledge_kind"],
                sha256_bytes(str(intent["asserted_by"]).encode("utf-8")) if intent["asserted_by"] else "",
                intent["safety_decision"], intent["safety_reason_code"],
                intent["safety_input_sha256"], intent["safety_input_length"],
                intent["evidence_ref_sha256"], intent["operation"],
                intent["target_status"], intent["transition_reason_sha256"],
                "TTL_ELAPSED", timestamp,
            ),
        )
        cursor = conn.execute(
            "UPDATE memory_write_intents SET status='expired', reason_code='INTENT_EXPIRED', updated_at=? "
            "WHERE intent_id=? AND status IN ('pending','approved','bound','validated')",
            (timestamp, intent["intent_id"]),
        )
        if cursor.rowcount and _table_exists(conn, "memory_session_claims"):
            conn.execute(
                "UPDATE memory_session_claims SET status='expired', completed_at=?, updated_at=? "
                "WHERE status='active' AND intent_id=? AND target_key=? AND fencing_token=?",
                (
                    timestamp,
                    timestamp,
                    str(intent["intent_id"]),
                    str(intent["target_key"]),
                    int(intent["fencing_token"] or 0),
                ),
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
    operation: str = "content_update",
    target_status: str = "",
    transition_reason_sha256: str = "",
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
    if actor not in SUPPORTED_LEDGER_ACTORS:
        raise IntentError("ACTOR_UNSUPPORTED", "actor is not supported")
    if actor == "ailu":
        if not approval_required:
            raise IntentError(
                "APPROVAL_REQUIRED",
                "ailu intents always require explicit user approval",
            )
        if str(asserted_by).strip().lower() not in {"user", "claude", "codex", "opencode"}:
            raise IntentError(
                "ASSERTED_BY_UNSUPPORTED",
                "ailu must bind a supported factual asserter",
            )
        if store_proposal_snapshot:
            raise IntentError(
                "AILU_PROPOSAL_SNAPSHOT_FORBIDDEN",
                "ailu proposal bodies must not be stored in the state database",
            )
        if (
            not re.fullmatch(r"[0-9a-f]{64}", read_token)
            or expected_base_exists is None
            or not scope_app_id.strip()
        ):
            raise IntentError(
                "AILU_READ_TOKEN_REQUIRED",
                "ailu intents require a bound high-level read token",
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
    normalized_operation = _bounded_label(operation, limit=64).lower() or "content_update"
    if normalized_operation not in {
        "content_update",
        "status_transition",
        "governance_migration",
    }:
        raise IntentError("OPERATION_INVALID", "unsupported write operation")
    normalized_target_status = _bounded_label(target_status, limit=64).lower()
    normalized_transition_reason = _bounded_label(transition_reason_sha256, limit=128).lower()
    if normalized_operation == "status_transition":
        if actor == "ailu":
            raise IntentError("STATUS_TRANSITION_ACTOR_FORBIDDEN", "ailu cannot transition formal memory status")
        if normalized_target_status not in {
            "active",
            "pending_verification",
            "outdated",
            "archived",
        }:
            raise IntentError("STATUS_TRANSITION_INVALID", "target status is not supported")
        if re.fullmatch(r"[0-9a-f]{64}", normalized_transition_reason) is None:
            raise IntentError("STATUS_TRANSITION_REASON_REQUIRED", "status transition reason must be hash-bound")
    elif normalized_operation == "governance_migration":
        if actor not in {"codex", "claude", "migration"}:
            raise IntentError("OPERATION_FORBIDDEN", "governance migration is unavailable to this actor")
        if normalized_target_status or normalized_transition_reason:
            raise IntentError("OPERATION_INVALID", "governance migration has no status transition fields")
    elif normalized_target_status or normalized_transition_reason:
        raise IntentError("OPERATION_INVALID", "transition metadata requires status_transition")
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
            fencing_token = _allocate_fencing_token(conn, canonical.target_key)
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
                  intent_id, schema_version, writer_protocol_version,
                  actor, session_hash, target_rel_path, target_key,
                  fencing_token,
                  base_exists, base_raw_sha256, base_canonical_sha256, base_git_head,
                  read_token, scope_app_id, scope_project_id,
                  proposal_raw_sha256, proposal_canonical_sha256, proposal_size_bytes,
                  proposal_path_sha256, proposal_canonical_snapshot,
                  proposal_snapshot_truncated, proposal_line_count,
                  source_class, knowledge_kind, asserted_by, evidence_ref_sha256,
                  safety_audit_id, safety_run_id, safety_decision,
                  safety_reason_code, safety_input_sha256, safety_input_length,
                  reconcile_action, operation, target_status, transition_reason_sha256,
                  intent_system_enabled, effective_enforcement,
                  approval_required, status, created_at, updated_at, expires_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    intent_id,
                    STATE_SCHEMA_VERSION,
                    WRITER_PROTOCOL_VERSION,
                    actor,
                    hashed_session,
                    canonical.rel_path,
                    canonical.target_key,
                    fencing_token,
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
                    normalized_operation,
                    normalized_target_status,
                    normalized_transition_reason,
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
    with connect(read_only=True) as conn:
        intent = _fetch_intent(conn, intent_id)
        receipt = _row_dict(conn.execute("SELECT * FROM memory_write_receipts WHERE intent_id=?", (intent_id,)).fetchone())
    if intent is None:
        raise IntentError("INTENT_NOT_FOUND", f"write intent not found: {intent_id}")
    return {"intent": _public_intent(intent), "receipt": receipt}


def inspect_intent(
    intent_id: str,
    *,
    actor: str,
    raw_session_id: str,
) -> dict[str, Any]:
    """Return one session-owned intent without changing SQLite sidecars."""

    snapshot_before = side_effect_free_sqlite_fingerprint(STATE_DB)
    with connect(read_only=True, side_effect_free=True) as conn:
        intent = _fetch_intent(conn, intent_id)
        if intent is None:
            raise IntentError("INTENT_NOT_FOUND", f"write intent not found: {intent_id}")
        _authorize_intent(intent, actor=actor, raw_session_id=raw_session_id)
        receipt = _row_dict(
            conn.execute(
                "SELECT * FROM memory_write_receipts WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
        )
    if side_effect_free_sqlite_fingerprint(STATE_DB) != snapshot_before:
        raise StateSecurityError("SQLite snapshot changed during recovery query")
    return {"intent": _public_intent(intent), "receipt": receipt}


def _encode_recovery_cursor(updated_at: str, intent_id: str) -> str:
    payload = json.dumps(
        [updated_at, intent_id],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_recovery_cursor(cursor: str) -> tuple[str, str]:
    value = str(cursor).strip()
    if not value or len(value) > 512 or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise IntentError("CURSOR_INVALID", "recovery cursor is invalid")
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("ascii"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise IntentError("CURSOR_INVALID", "recovery cursor is invalid") from exc
    if (
        not isinstance(decoded, list)
        or len(decoded) != 2
        or not all(isinstance(item, str) for item in decoded)
        or parse_time(decoded[0]) is None
        or re.fullmatch(r"[0-9a-f]{32}", decoded[1]) is None
    ):
        raise IntentError("CURSOR_INVALID", "recovery cursor is invalid")
    return decoded[0], decoded[1]


def list_session_intents(
    *,
    actor: str,
    raw_session_id: str,
    statuses: Sequence[str] = (),
    limit: int = 50,
    cursor: str = "",
) -> dict[str, Any]:
    """List bounded session-owned intents through a physical read-only open."""

    hashed_session = session_hash(raw_session_id)
    if not hashed_session:
        raise IntentError("SESSION_REQUIRED", "session id is required")
    if actor not in CANONICAL_WRITER_ACTORS:
        raise IntentError("ACTOR_UNSUPPORTED", "actor is not supported")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > 100:
        raise IntentError("LIMIT_INVALID", "recovery list limit must be between 1 and 100")
    normalized_statuses = tuple(
        dict.fromkeys(str(item).strip().lower() for item in statuses)
    )
    allowed = set(ACTIVE_STATUSES) | set(TERMINAL_STATUSES)
    if any(item not in allowed for item in normalized_statuses):
        raise IntentError("STATUS_FILTER_INVALID", "recovery status filter is invalid")
    params: list[Any] = [actor, hashed_session]
    where = ["actor=?", "session_hash=?"]
    if normalized_statuses:
        placeholders = ",".join("?" for _ in normalized_statuses)
        where.append(f"status IN ({placeholders})")
        params.extend(normalized_statuses)
    if cursor:
        updated_at, cursor_intent_id = _decode_recovery_cursor(cursor)
        where.append("(updated_at<? OR (updated_at=? AND intent_id<?))")
        params.extend((updated_at, updated_at, cursor_intent_id))
    params.append(limit + 1)
    query = (
        "SELECT * FROM memory_write_intents WHERE "
        + " AND ".join(where)
        + " ORDER BY updated_at DESC, intent_id DESC LIMIT ?"
    )
    snapshot_before = side_effect_free_sqlite_fingerprint(STATE_DB)
    with connect(read_only=True, side_effect_free=True) as conn:
        rows = [_row_dict(row) for row in conn.execute(query, params).fetchall()]
        intents = [row for row in rows if row is not None]
        page = intents[:limit]
        receipts: dict[str, dict[str, Any] | None] = {}
        for intent in page:
            intent_id = str(intent["intent_id"])
            receipts[intent_id] = _row_dict(
                conn.execute(
                    "SELECT * FROM memory_write_receipts WHERE intent_id=?",
                    (intent_id,),
                ).fetchone()
            )
    if side_effect_free_sqlite_fingerprint(STATE_DB) != snapshot_before:
        raise StateSecurityError("SQLite snapshot changed during recovery query")
    next_cursor = ""
    if len(intents) > limit and page:
        last = page[-1]
        next_cursor = _encode_recovery_cursor(
            str(last.get("updated_at", "")),
            str(last.get("intent_id", "")),
        )
    return {
        "items": [
            {
                "intent": _public_intent(intent),
                "receipt": receipts.get(str(intent["intent_id"])),
            }
            for intent in page
        ],
        "next_cursor": next_cursor,
    }


def verify_terminal_receipt(
    intent: dict[str, Any],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    """Verify a terminal receipt against its intent, fence, hashes and Git blob."""

    intent_id = str(intent.get("intent_id", ""))
    expected_receipt_id = hashlib.sha256(
        f"write-receipt:{intent_id}".encode("utf-8")
    ).hexdigest()[:32]
    string_fields = (
        "intent_id",
        "actor",
        "session_hash",
        "target_rel_path",
        "target_key",
        "base_raw_sha256",
        "proposal_raw_sha256",
        "proposal_canonical_sha256",
        "final_raw_sha256",
        "final_canonical_sha256",
        "base_git_head",
        "validated_git_head",
        "validation_mode",
        "proposal_commit",
        "approval_binding_sha256",
        "approval_ref_sha256",
        "source_class",
        "knowledge_kind",
        "safety_decision",
        "safety_reason_code",
        "safety_input_sha256",
        "evidence_ref_sha256",
        "operation",
        "target_status",
        "transition_reason_sha256",
    )
    integer_fields = (
        "writer_protocol_version",
        "fencing_token",
        "early_commit",
        "safety_input_length",
    )
    try:
        integer_fields_match = all(
            int(receipt.get(field) or 0) == int(intent.get(field) or 0)
            for field in integer_fields
        )
    except (TypeError, ValueError):
        integer_fields_match = False
    valid = (
        re.fullmatch(r"[0-9a-f]{32}", intent_id) is not None
        and hmac.compare_digest(str(receipt.get("receipt_id", "")), expected_receipt_id)
        and all(
            str(receipt.get(field, "")) == str(intent.get(field, ""))
            for field in string_fields
        )
        and integer_fields_match
        and hmac.compare_digest(
            str(receipt.get("asserted_by_sha256", "")),
            sha256_bytes(str(intent.get("asserted_by", "")).encode("utf-8"))
            if intent.get("asserted_by")
            else "",
        )
        and str(receipt.get("outcome", "")) == str(intent.get("status", ""))
        and str(receipt.get("reason_code", "")) == str(intent.get("reason_code", ""))
        and parse_time(str(receipt.get("created_at", ""))) is not None
    )
    if not valid or str(intent.get("status", "")) not in TERMINAL_STATUSES:
        raise IntentError(
            "RECEIPT_INTEGRITY_INVALID",
            "terminal receipt does not match its intent",
        )
    git_commit = str(receipt.get("git_commit", ""))
    git_blob_verified = False
    if str(receipt.get("outcome", "")) == "completed":
        if not git_commit or not hmac.compare_digest(_resolve_git_commit(git_commit), git_commit):
            raise IntentError(
                "RECEIPT_GIT_COMMIT_INVALID",
                "completed receipt Git commit is invalid",
            )
        target = canonical_target(str(intent.get("target_rel_path", "")))
        blob = _git_blob(git_commit, _repo_rel_path(target))
        if blob is None:
            raise IntentError(
                "RECEIPT_GIT_BLOB_MISSING",
                "completed receipt target blob is missing",
            )
        committed = content_hashes(blob, max_bytes=MAX_TARGET_BYTES)
        if (
            not hmac.compare_digest(
                committed.raw_sha256,
                str(receipt.get("final_raw_sha256", "")),
            )
            or not hmac.compare_digest(
                committed.canonical_sha256,
                str(receipt.get("final_canonical_sha256", "")),
            )
        ):
            raise IntentError(
                "RECEIPT_GIT_BLOB_MISMATCH",
                "completed receipt Git blob does not match",
            )
        git_blob_verified = True
    return {
        "verified": True,
        "git_blob_verified": git_blob_verified,
        "receipt_id": str(receipt.get("receipt_id", "")),
        "outcome": str(receipt.get("outcome", "")),
        "reason_code": str(receipt.get("reason_code", "")),
        "git_commit": git_commit,
        "created_at": str(receipt.get("created_at", "")),
    }


def approve_intent(
    intent_id: str,
    *,
    actor: str,
    raw_session_id: str,
    raw_task_id: str = "",
    target: str | Path,
    proposal_raw_sha256: str,
    proposal_canonical_sha256: str,
    approved_by: str,
    approval_ref: str,
    confirmation_capability: object | None = None,
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
        sensitive_confirmation = intent_requires_confirmation_capability(intent)
        if sensitive_confirmation and str(intent["status"]) == "approved":
            if not has_valid_confirmation_capability_approval(intent):
                raise IntentError(
                    "CONFIRMATION_CAPABILITY_INVALID",
                    "sensitive intent has no valid capability-bound approval",
                )
            conn.commit()
            payload = _public_intent(intent)
            payload["idempotent"] = True
            return payload
        if sensitive_confirmation:
            try:
                import agent_memory_confirmation_capability as confirmation_protocol

                capability_matches = confirmation_protocol.attests_to(
                    confirmation_capability,
                    subject_actor=actor,
                    raw_task_id=raw_task_id,
                    raw_session_id=raw_session_id,
                    proposal_id=intent_id,
                    proposal_raw_sha256=proposal_raw_sha256,
                    proposal_canonical_sha256=proposal_canonical_sha256,
                    target_relative_path=str(intent.get("target_rel_path", "")),
                    target_key=str(intent.get("target_key", "")),
                    operation=str(intent.get("operation", "content_update")),
                    reconcile_action=str(intent.get("reconcile_action", "")),
                    fencing_token=int(intent.get("fencing_token") or 0),
                )
                expected_reference = (
                    confirmation_protocol.approval_reference(confirmation_capability)
                    if capability_matches
                    else ""
                )
            except (ImportError, RuntimeError, TypeError, ValueError):
                capability_matches = False
                expected_reference = ""
            if (
                not capability_matches
                or approved_by != HUMAN_CONFIRMATION_CAPABILITY_APPROVER
                or approval_ref != expected_reference
            ):
                raise IntentError(
                    "CONFIRMATION_CAPABILITY_REQUIRED",
                    "sensitive intent approval requires an exact consumed human capability",
                )
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
    fencing_token: int | None = None,
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
        assert_current_lease(
            intent_id,
            actor=actor,
            raw_session_id=raw_session_id,
            fencing_token=fencing_token,
            connection=conn,
        )
        if str(snapshot["status"]) not in {"pending", "approved", "bound"}:
            raise IntentError("INTENT_NOT_BINDABLE", f"intent status cannot be bound: {snapshot['status']}")
        if _intent_expired(snapshot):
            terminal = ("expired", "INTENT_EXPIRED", "TTL_ELAPSED")
        if (
            terminal is None
            and intent_requires_confirmation_capability(snapshot)
            and not has_valid_confirmation_capability_approval(snapshot)
        ):
            raise IntentError(
                "CONFIRMATION_CAPABILITY_REQUIRED",
                "sensitive intent requires a capability-bound human approval before claim binding",
            )
        if terminal is None and int(snapshot["approval_required"]):
            expected = _stored_approval_binding(snapshot)
            if not snapshot["approved_at"] or str(snapshot["approval_binding_sha256"]) != expected:
                raise IntentError("APPROVAL_REQUIRED", "a correctly bound approval is required before claim binding")
        target = canonical_target(claim_path or str(snapshot["target_rel_path"]))
        if target.target_key != str(snapshot["target_key"]):
            raise IntentError("CLAIM_TARGET_MISMATCH", "claim path does not match the write intent")
        exists, current = _read_target(target)
        reconcile_action = str(snapshot.get("reconcile_action", "")).upper()
        proposal_already_written = (
            exists
            and current.raw_sha256 == str(snapshot["proposal_raw_sha256"])
        )
        stale = (
            int(snapshot["base_exists"]) != int(exists)
            or current.raw_sha256 != str(snapshot["base_raw_sha256"])
        )
        current_head = current_git_head(required=True)
        history = git_version_chain(str(snapshot["base_git_head"]), current_head, target)
        if not history["ok"] or history["versions"]:
            stale = True
        if reconcile_action == "ADOPT" and proposal_already_written and not history["versions"]:
            # ADOPT deliberately binds an already-written external worktree
            # version. It may bypass only the content-vs-HEAD base check; Git
            # ancestry and every later approval/fence/hash check still apply.
            stale = not bool(history["ok"])
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


def _terminalize_validated_content_drift(
    intent_id: str,
    *,
    actor: str,
    raw_session_id: str,
    target_key: str,
    fencing_token: int,
    require_bound: bool,
) -> dict[str, Any]:
    """Fail a drifted validated intent and release its exact claim atomically.

    The already-validated hashes remain immutable audit evidence. In
    particular, this helper never overwrites them with the externally changed
    bytes. The worktree is also left untouched so a later explicit ADOPT can
    acquire the next fencing token.
    """

    now = utc_now()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = _fetch_intent(conn, intent_id)
        if current is None:
            raise IntentError("INTENT_NOT_FOUND", f"write intent not found: {intent_id}")
        if str(current.get("status", "")) != "validated":
            raise IntentError("INTENT_STATE_CHANGED", "validated intent changed during drift finalization")
        if (
            str(current.get("target_key", "")) != target_key
            or int(current.get("fencing_token") or 0) != int(fencing_token)
        ):
            raise IntentError("LEASE_FENCED", "validated intent no longer owns the expected path fence")
        assert_current_lease(
            intent_id,
            actor=actor,
            raw_session_id=raw_session_id,
            fencing_token=fencing_token,
            target=str(current["target_rel_path"]),
            require_unexpired=True,
            connection=conn,
        )
        receipt = finalize_receipt(
            intent_id,
            actor=actor,
            raw_session_id=raw_session_id,
            outcome="failed",
            reason_code="VALIDATED_CONTENT_CHANGED",
            detail_code="RAW_BYTES_DRIFTED_AFTER_VALIDATION",
            fencing_token=fencing_token,
            connection=conn,
            commit=False,
        )
        cursor = conn.execute(
            "UPDATE memory_session_claims SET status='expired', completed_at=?, updated_at=? "
            "WHERE status='active' AND intent_id=? AND target_key=? AND fencing_token=?",
            (now, now, intent_id, target_key, fencing_token),
        )
        if require_bound and cursor.rowcount != 1:
            raise IntentError(
                "CLAIM_PROJECTION_MISMATCH",
                "validated path lease has no exact active claim projection",
            )
        conn.commit()
    return receipt


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
    if str(snapshot["status"]) in ACTIVE_STATUSES:
        try:
            assert_current_lease(
                intent_id,
                actor=actor,
                raw_session_id=raw_session_id,
                fencing_token=int(snapshot.get("fencing_token") or 0),
                target=target or str(snapshot["target_rel_path"]),
                require_unexpired=False,
            )
        except IntentError as exc:
            return {"ok": False, "reason_code": exc.reason_code, "receipt": None, "mutated": False}
    canonical = canonical_target(target or str(snapshot["target_rel_path"]))
    if canonical.target_key != str(snapshot["target_key"]):
        return {"ok": False, "reason_code": "INTENT_TARGET_MISMATCH", "receipt": None, "mutated": False}
    if str(snapshot["status"]) == "completed":
        exists, final = _read_target(canonical)
        if (
            exists
            and completed_receipt is not None
            and str(completed_receipt["outcome"]) == "completed"
            and final.raw_sha256 == str(snapshot["final_raw_sha256"])
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
        if exists and final.raw_sha256 == str(snapshot["final_raw_sha256"]):
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
        receipt = None
        if mutate:
            # Preserve the externally changed bytes. Terminalize only the lease
            # and its exact claim projection so a subsequent explicit ADOPT may
            # acquire a newer fence instead of being stranded behind validated.
            receipt = _terminalize_validated_content_drift(
                intent_id,
                actor=actor,
                raw_session_id=raw_session_id,
                target_key=str(snapshot["target_key"]),
                fencing_token=int(snapshot.get("fencing_token") or 0),
                require_bound=require_bound,
            )
        return {
            "ok": False,
            "reason_code": "VALIDATED_CONTENT_CHANGED",
            "receipt": receipt,
            "mutated": mutate,
        }
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
    if (
        intent_requires_confirmation_capability(snapshot)
        and not has_valid_confirmation_capability_approval(snapshot)
    ):
        return {
            "ok": False,
            "reason_code": "CONFIRMATION_CAPABILITY_INVALID",
            "receipt": None,
            "mutated": False,
        }
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
    fencing_token: int | None = None,
    connection: sqlite3.Connection | None = None,
    commit: bool = True,
) -> dict[str, Any]:
    """Finalize one intent, optionally as part of a caller-owned transaction.

    When ``connection`` is supplied with ``commit=False``, this function never
    commits or rolls back. That lets closeout atomically persist the receipt,
    latest file observation, and claim projection in one ``BEGIN IMMEDIATE``.
    """

    outcome = outcome.strip().lower()
    if outcome not in {"completed", "failed", "cancelled", "expired"}:
        raise IntentError("OUTCOME_INVALID", f"unsupported receipt outcome: {outcome}")
    owns_connection = connection is None
    conn = connect() if owns_connection else connection
    if conn is None:
        raise IntentError("STATE_DB_UNAVAILABLE", "intent state connection is unavailable")
    result: dict[str, Any] | None = None
    try:
        if owns_connection:
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
            if fencing_token is not None and int(existing.get("fencing_token") or 0) != int(fencing_token):
                raise IntentError("LEASE_FENCED", "terminal receipt belongs to a different path fence")
            if owns_connection or commit:
                conn.commit()
            existing["idempotent"] = True
            existing["requested_outcome_mismatch"] = False
            return existing
        if str(intent["status"]) in ACTIVE_STATUSES:
            assert_current_lease(
                intent_id,
                actor=actor,
                raw_session_id=raw_session_id,
                fencing_token=(
                    int(fencing_token)
                    if fencing_token is not None
                    else int(intent.get("fencing_token") or 0)
                ),
                require_unexpired=outcome != "expired",
                connection=conn,
            )
        elif fencing_token is not None and int(intent.get("fencing_token") or 0) != int(fencing_token):
            raise IntentError("LEASE_FENCED", "terminal intent belongs to a different path fence")
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
                or committed_digest.canonical_sha256
                != str(intent["final_canonical_sha256"])
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
        recovery_pending = (
            str(intent.get("reason_code", ""))
            in {
                EXPIRED_VALIDATED_RECOVERY_REASON,
                EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON,
            }
        )
        if outcome == "completed" and recovery_pending:
            if effective_reason not in {
                "WRITE_COMPLETED",
                EXPIRED_VALIDATED_RECOVERY_COMPLETED_REASON,
            }:
                raise IntentError(
                    "EXPIRED_VALIDATED_RECOVERY_COMPLETION_INVALID",
                    "expired validated recovery must retain its terminal audit marker",
                )
            effective_reason = EXPIRED_VALIDATED_RECOVERY_COMPLETED_REASON
        elif effective_reason == EXPIRED_VALIDATED_RECOVERY_COMPLETED_REASON:
            raise IntentError(
                "EXPIRED_VALIDATED_RECOVERY_COMPLETION_INVALID",
                "the expired validated recovery terminal marker is reserved",
            )
        effective_detail = _safe_code(detail_code)
        conn.execute(
            """
            INSERT INTO memory_write_receipts (
              receipt_id, intent_id, writer_protocol_version, actor, session_hash,
              target_rel_path, target_key, fencing_token,
              outcome, reason_code, validation_mode, base_raw_sha256,
              proposal_raw_sha256, proposal_canonical_sha256, final_raw_sha256,
              final_canonical_sha256, base_git_head, validated_git_head, git_commit,
              early_commit, proposal_commit, approval_binding_sha256,
              approval_ref_sha256, source_class, knowledge_kind,
              asserted_by_sha256, safety_decision, safety_reason_code,
              safety_input_sha256, safety_input_length, evidence_ref_sha256,
              operation, target_status, transition_reason_sha256,
              detail_code, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                receipt_id,
                intent_id,
                intent["writer_protocol_version"],
                intent["actor"],
                intent["session_hash"],
                intent["target_rel_path"],
                intent["target_key"],
                intent["fencing_token"],
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
                intent["operation"],
                intent["target_status"],
                intent["transition_reason_sha256"],
                effective_detail,
                now,
            ),
        )
        conn.execute(
            "UPDATE memory_write_intents SET status=?, reason_code=?, updated_at=? WHERE intent_id=?",
            (outcome, effective_reason, now, intent_id),
        )
        result = _row_dict(
            conn.execute("SELECT * FROM memory_write_receipts WHERE intent_id=?", (intent_id,)).fetchone()
        )
        if owns_connection or commit:
            conn.commit()
    except Exception:
        if (owns_connection or commit) and conn.in_transaction:
            conn.rollback()
        raise
    finally:
        if owns_connection:
            conn.close()
    if result is None:
        raise IntentError("RECEIPT_WRITE_FAILED", "terminal receipt was not persisted")
    result["idempotent"] = False
    result["requested_outcome_mismatch"] = False
    return result


def cancel_intent(
    intent_id: str,
    *,
    actor: str,
    raw_session_id: str,
    reason_code: str = "CANCELLED_BY_ACTOR",
    fencing_token: int | None = None,
) -> dict[str, Any]:
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
        fencing_token=fencing_token,
    )


def expire_intents(*, now: dt.datetime | None = None, apply: bool = False) -> dict[str, Any]:
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    with connect(read_only=not apply) as conn:
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
                      receipt_id, intent_id, writer_protocol_version, actor, session_hash,
                      target_rel_path, target_key, fencing_token,
                      outcome, reason_code, validation_mode, base_raw_sha256,
                      proposal_raw_sha256, proposal_canonical_sha256, final_raw_sha256,
                      final_canonical_sha256, base_git_head, validated_git_head, git_commit,
                      early_commit, proposal_commit, approval_binding_sha256,
                      approval_ref_sha256, source_class, knowledge_kind,
                      asserted_by_sha256, safety_decision, safety_reason_code,
                      safety_input_sha256, safety_input_length, evidence_ref_sha256,
                      operation, target_status, transition_reason_sha256,
                      detail_code, created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        receipt_id, intent["intent_id"], intent["writer_protocol_version"],
                        intent["actor"], intent["session_hash"], intent["target_rel_path"],
                        intent["target_key"], intent["fencing_token"], "expired", "INTENT_EXPIRED",
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
                        intent["evidence_ref_sha256"], intent["operation"],
                        intent["target_status"], intent["transition_reason_sha256"],
                        "TTL_ELAPSED", timestamp,
                    ),
                )
                conn.execute(
                    "UPDATE memory_write_intents SET status='expired', reason_code='INTENT_EXPIRED', updated_at=? "
                    "WHERE intent_id=?",
                    (timestamp, intent["intent_id"]),
                )
                if _table_exists(conn, "memory_session_claims"):
                    conn.execute(
                        "UPDATE memory_session_claims SET status='expired', completed_at=?, updated_at=? "
                        "WHERE status='active' AND intent_id=? AND target_key=? AND fencing_token=?",
                        (
                            timestamp,
                            timestamp,
                            str(intent["intent_id"]),
                            str(intent["target_key"]),
                            int(intent["fencing_token"] or 0),
                        ),
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
    if protected_paths is None and FULL_VAULT_GATEWAY:
        return True
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
        choices=("codex", "claude", "human", "migration", "test", "ailu"),
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

    renew = subparsers.add_parser("renew")
    renew.add_argument("--intent-id", required=True)
    renew.add_argument("--fencing-token", type=int, required=True)
    renew.add_argument("--ttl-hours", type=float, default=None)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--intent-id", required=True)
    validate.add_argument("--target")
    validate.add_argument("--no-mutate", action="store_true")
    validate.add_argument(
        "--show-private-diff",
        action="store_true",
        help="Show a bounded, secret-redacted mismatch diff. Default output contains hashes and counts only.",
    )

    finalize = subparsers.add_parser(
        "finalize",
        help="Record a non-success terminal outcome; completed is internal to atomic closeout.",
    )
    finalize.add_argument("--intent-id", required=True)
    finalize.add_argument("--outcome", choices=("failed", "cancelled", "expired"), required=True)
    finalize.add_argument("--reason-code", default="")
    finalize.add_argument("--git-commit", default="")
    finalize.add_argument("--detail-code", default="")

    cancel = subparsers.add_parser("cancel")
    cancel.add_argument("--intent-id", required=True)
    cancel.add_argument("--fencing-token", type=int, required=True)
    cancel.add_argument("--reason-code", default="CANCELLED_BY_ACTOR")

    expire = subparsers.add_parser("expire")
    expire.add_argument("--apply", action="store_true")
    return parser.parse_args()


def enforce_low_level_cli_policy(actor: str, action: str) -> None:
    if actor in CANONICAL_WRITER_ACTORS and action != "show":
        raise IntentError(
            "LOW_LEVEL_GATEWAY_MUTATION_FORBIDDEN",
            f"{actor} must mutate memory through write read-target/prepare/apply/cancel",
        )


def main() -> int:
    args = parse_args()
    raw_session_id = _session_value(args.session_id, args.actor)
    try:
        assert_runtime_ready("intent")
        enforce_low_level_cli_policy(args.actor, args.action)
        if args.action == "create":
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
        elif args.action == "renew":
            payload = renew_lease(
                args.intent_id,
                actor=args.actor,
                raw_session_id=raw_session_id,
                fencing_token=args.fencing_token,
                ttl_hours=args.ttl_hours,
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
            if args.outcome == "completed":
                raise IntentError(
                    "COMPLETED_FINALIZE_INTERNAL_ONLY",
                    "completed receipts are emitted only by atomic closeout batch finalization",
                )
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
                fencing_token=args.fencing_token,
            )
        else:
            payload = expire_intents(apply=args.apply)
    except (IntentError, OSError, sqlite3.Error, subprocess.SubprocessError, RuntimeError) as exc:
        reason_code = getattr(exc, "reason_code", "INTENT_ERROR")
        error = {
            "ok": False,
            "reason_code": reason_code,
            "error": str(exc),
            "degraded": reason_code == STATE_SCHEMA_REASON_CODE,
        }
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
