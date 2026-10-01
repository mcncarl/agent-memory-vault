#!/usr/bin/env python3
"""Plan, apply, and verify the additive Agent Memory v2 state migration.

`plan` is read-only. `apply` is explicit, additive, transaction scoped, and
never rewrites Markdown. Apply requires a new, non-existing backup path and
takes a SQLite online backup before any schema or ledger mutation. `verify` is
read-only by default. `verify --publish-ready` is the explicit commit gate that
atomically marks an installed runtime ready after all other checks succeed.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import shlex
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from agent_memory_env import (
    RUNTIME_RELEASE_VERSION,
    WRITE_GATEWAY_CAPABILITIES,
    config_path,
    env_value,
    expand_path,
    parse_toml_fallback,
)
from agent_memory_lock import private_lock
from agent_memory_state import (
    ConditionalWriteError,
    OBSERVABILITY_ACTOR_VALUES,
    POSIX_PERMISSION_MODEL,
    PRIVATE_FILE_MODE,
    StateSecurityError,
    assert_no_symlink_beneath,
    ensure_private_directory,
    drop_search_log_privacy_guards,
    install_search_log_privacy_guards,
    relative_beneath,
    runtime_python_attestation,
    secure_atomic_write_bytes_beneath,
    secure_conditional_recovery_entries_beneath,
    secure_conditional_write_bytes_beneath,
    secure_open_regular_beneath,
    secure_read_bytes_and_stat_beneath,
    secure_read_bytes_beneath,
    secure_sha256_beneath,
    search_log_privacy_guard_report,
)
from agent_memory_state import absolute_path, secure_sqlite_connect
from agent_memory_host_automation import (
    DEFAULT_AUDIT_LAUNCHAGENT_LABEL,
    LaunchAgentSpec,
    audit_scheduler_health,
    claude_hook_specs,
    classify_hook_event,
    classify_launchagent_payload,
    codex_stop_hook_spec,
    discover_all_audit_launchagents,
    load_launchagent_payload,
)
import agent_memory_intent as intent
import agent_memory_claim as memory_claim
import agent_memory_audit as audit_schema
import agent_memory_content_migrate as content_migration
import agent_memory_index as memory_index
import agent_memory_closeout as memory_closeout


STATE_SCHEMA_VERSION = intent.STATE_SCHEMA_VERSION
WRITER_PROTOCOL_VERSION = intent.WRITER_PROTOCOL_VERSION
STATE_DB = absolute_path(expand_path(env_value("STATE_DB", "$HOME/.config/agent-memory/state.sqlite")))
AUDIT_DB = absolute_path(
    expand_path(env_value("AUDIT_DB", "$HOME/.config/agent-memory/audit_decisions.sqlite"))
)
ACTIVE = intent.ACTIVE_STATUSES
_MODULE_PATH = absolute_path(__file__)
RUNTIME_ROOT = _MODULE_PATH.parent.parent
assert_no_symlink_beneath(RUNTIME_ROOT, _MODULE_PATH, include_leaf=True)
RUNTIME_MANIFEST = RUNTIME_ROOT / "config" / "runtime-manifest.json"
RUNTIME_TRANSITION = RUNTIME_ROOT / "config" / "runtime-transition.json"
RUNTIME_ANCHOR = RUNTIME_ROOT / "config" / "runtime-anchor.json"
CONFIG_ROOT = expand_path(env_value("CONFIG_ROOT", str(RUNTIME_ROOT))).resolve()
# A managed install's synchronization identity is its physical runtime root,
# never an environment override. Source checkouts retain their configured local
# lock root because there is no managed installer racing them.
MANAGED_RUNTIME_FOOTPRINT = any(
    path.exists() or path.is_symlink()
    for path in (RUNTIME_ANCHOR, RUNTIME_MANIFEST, RUNTIME_TRANSITION)
)
LOCK_ROOT = RUNTIME_ROOT if MANAGED_RUNTIME_FOOTPRINT else CONFIG_ROOT
MIGRATION_LOCK = LOCK_ROOT / "locks" / "closeout.lock"
RUNTIME_INSTALL_LOCK = LOCK_ROOT / "locks" / "runtime-install.lock"
CAPABILITY_COMMANDS = (
    "index", "evolution", "check", "zvec", "search", "observe", "doctor",
    "generated-index-closeout",
)
CANONICAL_GATEWAY_ACTORS = list(intent.CANONICAL_WRITER_ACTORS)
SUPPORTED_LEDGER_ACTORS = frozenset(intent.SUPPORTED_LEDGER_ACTORS)
MAX_RUNTIME_CONFIG_BYTES = 8 * 1024 * 1024


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def connect(*, read_only: bool) -> sqlite3.Connection:
    return secure_sqlite_connect(
        STATE_DB,
        timeout=10,
        create=False,
        read_only=read_only,
        row_factory=sqlite3.Row,
        pragmas=("PRAGMA busy_timeout=10000", "PRAGMA foreign_keys=ON"),
    )


def initialize_state() -> dict[str, Any]:
    """Create a fresh state-v4 database without pretending a backup exists."""

    if STATE_DB.exists() or STATE_DB.is_symlink():
        raise ValueError("STATE_DB_ALREADY_EXISTS")
    ensure_private_directory(STATE_DB.parent, harden_existing=True)
    descriptor = os.open(
        STATE_DB,
        os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        PRIVATE_FILE_MODE,
    )
    os.close(descriptor)
    with contextlib.closing(connect(read_only=False)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            intent.ensure_schema(conn, commit=False)
            # Claim/list commands also require the deletion and committed
            # observation ledgers; a fresh state must pass their schema gate.
            memory_claim.ensure_schema(conn, commit=False)
            install_search_log_privacy_guards(conn)
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            # Preserve the private failed-init database for operator inspection.
            raise
        report = inspect(conn)
        integrity = str(conn.execute("PRAGMA quick_check").fetchone()[0])
    ok = (
        report["state_schema_version"] == STATE_SCHEMA_VERSION
        and not report["blockers"]
        and not report["missing_claim_columns"]
        and not report["missing_intent_columns"]
        and not report["missing_receipt_columns"]
        and not report["missing_observation_columns"]
        and not report["missing_incident_columns"]
        and not report["missing_observability_columns"]
        and not report["missing_privacy_guards"]
        and report["search_log_privacy"]["ready"]
        and integrity == "ok"
    )
    return {
        "ok": ok,
        "status": "initialized" if ok else "invalid",
        "stage": "init",
        "backup": {"status": "not_applicable", "reason": "fresh_state"},
        "quick_check": integrity,
        "report": report,
    }


def _audit_tables(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }


def _audit_columns(conn: sqlite3.Connection) -> set[str]:
    if "audit_decisions" not in _audit_tables(conn):
        return set()
    return {str(row[1]) for row in conn.execute("PRAGMA table_info(audit_decisions)")}


def inspect_audit(conn: sqlite3.Connection) -> dict[str, Any]:
    tables = _audit_tables(conn)
    columns = _audit_columns(conn)
    required_columns = {
        "finding_id",
        "decision",
        "occurrence_fingerprint",
        "note",
        "snooze_until",
        "decided_at",
    }
    version = ""
    if "meta" in tables:
        row = conn.execute(
            "SELECT value FROM meta WHERE key='agent_memory_audit_schema_version'"
        ).fetchone()
        version = str(row[0]) if row is not None else ""
    missing = sorted(required_columns - columns)
    ready = (
        {"meta", "audit_decisions", "audit_finding_occurrences"}.issubset(tables)
        and not missing
        and version == str(audit_schema.AUDIT_SCHEMA_VERSION)
    )
    return {
        "audit_db": str(AUDIT_DB),
        "exists": True,
        "audit_schema_version": int(version) if version.isdigit() else 0,
        "audit_schema_required": audit_schema.AUDIT_SCHEMA_VERSION,
        "missing_tables": sorted(
            {"meta", "audit_decisions", "audit_finding_occurrences"} - tables
        ),
        "missing_columns": missing,
        "status": "ready" if ready else "migration_required",
        "ok": ready,
    }


def audit_migration_plan() -> dict[str, Any]:
    if AUDIT_DB.is_symlink():
        raise ValueError("AUDIT_DB_SYMLINK")
    if not AUDIT_DB.exists():
        return {
            "ok": True,
            "stage": "audit-plan",
            "audit_db": str(AUDIT_DB),
            "exists": False,
            "status": "initialization_required",
            "audit_schema_required": audit_schema.AUDIT_SCHEMA_VERSION,
        }
    with contextlib.closing(
        secure_sqlite_connect(
            AUDIT_DB,
            create=False,
            read_only=True,
            row_factory=sqlite3.Row,
            pragmas=("PRAGMA busy_timeout=10000",),
        )
    ) as conn:
        report = inspect_audit(conn)
        integrity = str(conn.execute("PRAGMA quick_check").fetchone()[0])
    return {
        **report,
        "stage": "audit-plan",
        "ok": integrity == "ok",
        "quick_check": integrity,
    }


def _ensure_audit_schema(conn: sqlite3.Connection) -> None:
    """Installer-only additive audit-ledger migration."""

    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_decisions (
          finding_id TEXT PRIMARY KEY,
          decision TEXT NOT NULL,
          occurrence_fingerprint TEXT NOT NULL DEFAULT '',
          note TEXT NOT NULL DEFAULT '',
          snooze_until TEXT NOT NULL DEFAULT '',
          decided_at TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_finding_occurrences (
          finding_id TEXT PRIMARY KEY,
          base_fingerprint TEXT NOT NULL,
          occurrence_seq INTEGER NOT NULL,
          active INTEGER NOT NULL DEFAULT 1,
          last_seen_cycle TEXT NOT NULL DEFAULT '',
          updated_at TEXT NOT NULL
        )
        """
    )
    for column, declaration in (
        ("occurrence_fingerprint", "TEXT NOT NULL DEFAULT ''"),
        ("note", "TEXT NOT NULL DEFAULT ''"),
        ("snooze_until", "TEXT NOT NULL DEFAULT ''"),
        ("decided_at", "TEXT NOT NULL DEFAULT ''"),
    ):
        if column not in _audit_columns(conn):
            conn.execute(f"ALTER TABLE audit_decisions ADD COLUMN {column} {declaration}")
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
        ("agent_memory_audit_schema_version", str(audit_schema.AUDIT_SCHEMA_VERSION)),
    )


def initialize_audit() -> dict[str, Any]:
    if AUDIT_DB.exists() or AUDIT_DB.is_symlink():
        raise ValueError("AUDIT_DB_ALREADY_EXISTS")
    ensure_private_directory(AUDIT_DB.parent, harden_existing=True)
    descriptor = os.open(
        AUDIT_DB,
        os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        PRIVATE_FILE_MODE,
    )
    os.close(descriptor)
    with contextlib.closing(
        secure_sqlite_connect(
            AUDIT_DB,
            create=False,
            row_factory=sqlite3.Row,
            pragmas=("PRAGMA busy_timeout=10000",),
        )
    ) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            _ensure_audit_schema(conn)
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        report = inspect_audit(conn)
        integrity = str(conn.execute("PRAGMA quick_check").fetchone()[0])
    return {
        "ok": bool(report["ok"] and integrity == "ok"),
        "status": "initialized" if report["ok"] and integrity == "ok" else "invalid",
        "stage": "audit-init",
        "backup": {"status": "not_applicable", "reason": "fresh_audit_db"},
        "quick_check": integrity,
        "report": report,
    }


@contextlib.contextmanager
def migration_lock(timeout: float = 30.0):
    """Acquire the global runtime-then-state lock order.

    The installer uses this same order. Publication can therefore never mark a
    partially swapped runtime ready, and no opposite order exists to deadlock.
    """

    with private_lock(
        RUNTIME_INSTALL_LOCK,
        timeout=timeout,
        timeout_message="MIGRATION_LOCK_TIMEOUT",
    ):
        with private_lock(
            MIGRATION_LOCK,
            timeout=timeout,
            timeout_message="MIGRATION_LOCK_TIMEOUT",
        ):
            yield


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _target_key(raw_path: str) -> str:
    return intent.canonical_target(Path(raw_path)).target_key


def inspect(conn: sqlite3.Connection) -> dict[str, Any]:
    tables = _tables(conn)
    claim_columns = _columns(conn, "memory_session_claims") if "memory_session_claims" in tables else set()
    intent_columns = _columns(conn, "memory_write_intents") if "memory_write_intents" in tables else set()
    receipt_columns = _columns(conn, "memory_write_receipts") if "memory_write_receipts" in tables else set()
    intent_id_expression = "intent_id" if "intent_id" in claim_columns else "'' AS intent_id"
    claim_rows = (
        conn.execute(
            "SELECT session_hash, actor, path, rel_path, status, updated_at, "
            f"{intent_id_expression} FROM memory_session_claims"
        ).fetchall()
        if "memory_session_claims" in tables
        else []
    )
    canonical_rows: list[dict[str, Any]] = []
    path_errors: list[dict[str, str]] = []
    for row in claim_rows:
        try:
            target_key = _target_key(str(row["path"]))
        except (OSError, ValueError, intent.IntentError) as exc:
            path_errors.append({"rel_path": str(row["rel_path"]), "error": type(exc).__name__})
            continue
        canonical_rows.append(
            {
                "session_hash": str(row["session_hash"]),
                "actor": str(row["actor"]),
                "path": str(row["path"]),
                "rel_path": str(row["rel_path"]),
                "status": str(row["status"]),
                "updated_at": str(row["updated_at"]),
                "intent_id": str(row["intent_id"] or ""),
                "target_key": target_key,
            }
        )
    active_by_target: dict[str, list[dict[str, Any]]] = {}
    for row in canonical_rows:
        if row["status"] == "active":
            active_by_target.setdefault(row["target_key"], []).append(row)
    duplicate_active = [
        {"target_key": key, "claims": value}
        for key, value in sorted(active_by_target.items())
        if len(value) > 1
    ]
    terminal_active_claims: list[dict[str, str]] = []
    if "memory_write_intents" in tables and "intent_id" in claim_columns:
        for row in conn.execute(
            "SELECT c.session_hash, c.actor, c.path, c.rel_path, c.status AS claim_status, "
            "c.updated_at, c.intent_id, i.status AS intent_status "
            "FROM memory_session_claims c "
            "JOIN memory_write_intents i ON i.intent_id=c.intent_id "
            "WHERE c.status='active' AND c.intent_id<>'' "
            "AND i.status IN ('completed','failed','cancelled','expired')"
        ):
            terminal_active_claims.append({key: str(row[key]) for key in row.keys()})
    unsupported_active_actors = {
        row["actor"]
        for row in canonical_rows
        if row["status"] == "active" and row["actor"] not in SUPPORTED_LEDGER_ACTORS
    }
    if "memory_write_intents" in tables:
        unsupported_active_actors.update(
            str(row[0])
            for row in conn.execute(
                "SELECT actor FROM memory_write_intents "
                "WHERE status IN ('pending','approved','bound','validated')"
            )
            if str(row[0]) not in SUPPORTED_LEDGER_ACTORS
        )
    unsupported_active_actor_names = sorted(unsupported_active_actors)
    active_legacy_claims = [
        {
            "session_hash": str(row["session_hash"]),
            "actor": str(row["actor"]),
            "path": str(row["path"]),
            "rel_path": str(row["rel_path"]),
            "status": str(row["status"]),
            "updated_at": str(row["updated_at"]),
            "intent_id": str(row["intent_id"]),
        }
        for row in canonical_rows
        if row["status"] == "active" and not str(row["intent_id"])
    ]
    active_v1_intents: list[dict[str, str]] = []
    if "memory_write_intents" in tables:
        protocol_expression = "writer_protocol_version" if "writer_protocol_version" in intent_columns else "1"
        fence_expression = "fencing_token" if "fencing_token" in intent_columns else "0"
        active_v1_intents = [
            {key: str(row[key]) for key in row.keys()}
            for row in conn.execute(
                "SELECT intent_id, actor, target_rel_path, "
                f"{protocol_expression} AS writer_protocol_version, "
                f"{fence_expression} AS fencing_token FROM memory_write_intents "
                "WHERE status IN ('pending','approved','bound','validated') "
                f"AND ({protocol_expression}<>? OR {fence_expression}<=0)",
                (WRITER_PROTOCOL_VERSION,),
            )
        ]
    fence_rows = 0
    if "memory_path_fences" in tables:
        fence_rows = int(conn.execute("SELECT COUNT(*) FROM memory_path_fences").fetchone()[0])
    meta_version = ""
    if "meta" in tables:
        row = conn.execute("SELECT value FROM meta WHERE key='agent_memory_state_schema_version'").fetchone()
        meta_version = str(row[0]) if row is not None else ""
    observation_columns = (
        _columns(conn, "memory_file_observations") if "memory_file_observations" in tables else set()
    )
    incident_columns = (
        _columns(conn, "memory_closeout_incidents")
        if "memory_closeout_incidents" in tables
        else set()
    )
    required_claim = {"target_key", "fencing_token", "claim_kind"}
    required_intent = {
        "writer_protocol_version",
        "fencing_token",
        "operation",
        "target_status",
        "transition_reason_sha256",
    }
    required_receipt = {
        "writer_protocol_version",
        "fencing_token",
        "operation",
        "target_status",
        "transition_reason_sha256",
    }
    required_observation = {"intent_id", "fencing_token", "git_commit"}
    required_incident = {
        "intent_id",
        "target_key",
        "rel_path",
        "expected_sha256",
        "observed_sha256",
        "git_commit",
        "reason_code",
        "detected_at",
        "resolved_at",
        "resolution_intent_id",
        "resolution_git_commit",
    }
    observability_columns = (
        _columns(conn, "memory_use_events") if "memory_use_events" in tables else set()
    )
    search_observability_columns = (
        _columns(conn, "memory_search_log") if "memory_search_log" in tables else set()
    )
    required_observability = {
        "event_id",
        "task_id",
        "event_type",
        "memory_versions_json",
        "content_sha256",
        "requires_live_verification",
    }
    required_search_observability = {
        "ranking_mode",
        "v1_result_fingerprint",
        "v2_result_fingerprint",
        "required_case_regression_count",
        "worker_status",
        "worker_restart_count",
        "metadata_gate_mode",
        "metadata_would_block_count",
        "metadata_reason_fingerprint",
    }
    privacy_report = search_log_privacy_guard_report(conn)
    missing_privacy_guards = sorted(
        [*privacy_report["missing"], *privacy_report["drifted"]]
        + [f"memory_search_log.{name}" for name in privacy_report["missing_columns"]]
        + ([] if privacy_report["version"] == privacy_report["required_version"] else ["guard_version"])
        + ([] if privacy_report["raw_query_rows"] == 0 else ["raw_query_rows"])
        + ([] if privacy_report["path_rows"] == 0 else ["used_paths_rows"])
    )
    blockers = []
    if path_errors:
        blockers.append("CLAIM_PATH_INVALID")
    if duplicate_active:
        blockers.append("DUPLICATE_ACTIVE_TARGET")
    if unsupported_active_actor_names:
        blockers.append("UNSUPPORTED_ACTIVE_ACTOR")
    if active_legacy_claims:
        blockers.append("ACTIVE_LEGACY_CLAIM")
    if active_v1_intents:
        blockers.append("ACTIVE_V1_INTENT")
    if terminal_active_claims:
        blockers.append("TERMINAL_INTENT_ACTIVE_CLAIM")
    dispositions = [
        {
            "kind": "expire_legacy_claim",
            "session_hash": row["session_hash"],
            "path": row["path"],
            "intent_id": "",
            "expected_status": row["status"],
            "expected_updated_at": row["updated_at"],
        }
        for row in active_legacy_claims
    ] + [
        {
            "kind": "dispose_terminal_intent_claim",
            "session_hash": row["session_hash"],
            "path": row["path"],
            "intent_id": row["intent_id"],
            "expected_status": row["claim_status"],
            "expected_updated_at": row["updated_at"],
            "expected_intent_status": row["intent_status"],
        }
        for row in terminal_active_claims
    ]
    return {
        "state_schema_version": int(meta_version) if meta_version.isdigit() else 0,
        "state_schema_required": STATE_SCHEMA_VERSION,
        "writer_protocol_version": WRITER_PROTOCOL_VERSION,
        "tables": sorted(tables),
        "missing_claim_columns": sorted(required_claim - claim_columns),
        "missing_intent_columns": sorted(required_intent - intent_columns),
        "missing_receipt_columns": sorted(required_receipt - receipt_columns),
        "missing_observation_columns": sorted(required_observation - observation_columns),
        "missing_incident_columns": sorted(required_incident - incident_columns),
        "missing_observability_columns": sorted(
            (required_observability - observability_columns)
            | {
                f"memory_search_log.{column}"
                for column in required_search_observability - search_observability_columns
            }
        ),
        "missing_privacy_guards": missing_privacy_guards,
        "search_log_privacy": privacy_report,
        "memory_path_fences": fence_rows,
        "claim_count": len(canonical_rows),
        "path_errors": path_errors,
        "duplicate_active_targets": duplicate_active,
        "terminal_intent_active_claims": terminal_active_claims,
        "unsupported_active_actors": unsupported_active_actor_names,
        "active_legacy_claims": active_legacy_claims,
        "active_v1_intents": active_v1_intents,
        "disposition_template": {
            "schema_version": 1,
            "state_db": str(STATE_DB),
            "decisions": dispositions,
        },
        "blockers": blockers,
    }


def _add_column(conn: sqlite3.Connection, table: str, name: str, declaration: str) -> None:
    if name not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")


def _load_disposition_document(path: Path) -> dict[str, Any]:
    candidate = path.expanduser()
    if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size > 1024 * 1024:
        raise ValueError("DISPOSITION_FILE_UNSAFE")
    payload = _read_json_object(candidate, "DISPOSITION_FILE_INVALID")
    if payload.get("schema_version") != 1 or not isinstance(payload.get("decisions"), list):
        raise ValueError("DISPOSITION_FILE_INVALID")
    configured_state = str(payload.get("state_db", ""))
    if configured_state and Path(configured_state).expanduser().resolve() != STATE_DB.resolve():
        raise ValueError("DISPOSITION_STATE_DB_MISMATCH")
    return payload


def _decision_identity(item: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(item.get("kind", "")),
        str(item.get("session_hash", "")),
        str(item.get("path", "")),
        str(item.get("intent_id", "")),
        str(item.get("expected_status", "")),
        str(item.get("expected_updated_at", "")),
        str(item.get("expected_intent_status", "")),
    )


def _row_value(row: sqlite3.Row, key: str, default: Any = "") -> Any:
    return row[key] if key in row.keys() else default


def _validate_disposition_document(
    conn: sqlite3.Connection,
    report: dict[str, Any],
    document: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    expected = report.get("disposition_template", {}).get("decisions", [])
    if not expected:
        if document is not None and document.get("decisions"):
            raise ValueError("DISPOSITION_NOT_REQUIRED")
        return []
    if document is None:
        raise ValueError("DISPOSITION_FILE_REQUIRED")
    supplied = document.get("decisions")
    if not isinstance(supplied, list) or any(not isinstance(item, dict) for item in supplied):
        raise ValueError("DISPOSITION_FILE_INVALID")
    if sorted(_decision_identity(item) for item in supplied) != sorted(
        _decision_identity(item) for item in expected
    ):
        raise ValueError("DISPOSITION_SET_MISMATCH")
    validated: list[dict[str, Any]] = []
    for raw in supplied:
        item = {key: value for key, value in raw.items()}
        row = conn.execute(
            "SELECT * FROM memory_session_claims WHERE session_hash=? AND path=?",
            (str(item["session_hash"]), str(item["path"])),
        ).fetchone()
        if row is None or any(
            str(row[key] or "") != str(expected_value)
            for key, expected_value in (
                ("status", item["expected_status"]),
                ("updated_at", item["expected_updated_at"]),
                ("intent_id", item["intent_id"]),
            )
        ):
            raise ValueError("DISPOSITION_CAS_MISMATCH")
        if item["kind"] == "expire_legacy_claim":
            if str(row["intent_id"] or ""):
                raise ValueError("DISPOSITION_KIND_MISMATCH")
        elif item["kind"] == "dispose_terminal_intent_claim":
            bound = conn.execute(
                "SELECT * FROM memory_write_intents WHERE intent_id=?",
                (str(item["intent_id"]),),
            ).fetchone()
            receipt = conn.execute(
                "SELECT * FROM memory_write_receipts WHERE intent_id=?",
                (str(item["intent_id"]),),
            ).fetchone()
            terminal = str(item.get("expected_intent_status", ""))
            try:
                claim_target = intent.canonical_target(str(row["path"]))
                bound_target = intent.canonical_target(str(bound["target_rel_path"])) if bound is not None else None
                receipt_target = (
                    intent.canonical_target(str(_row_value(receipt, "target_rel_path")))
                    if receipt is not None and str(_row_value(receipt, "target_rel_path"))
                    else None
                )
            except (OSError, ValueError, intent.IntentError) as exc:
                raise ValueError("DISPOSITION_TARGET_BINDING_MISMATCH") from exc
            if (
                bound is None
                or receipt is None
                or terminal not in {"completed", "failed", "cancelled", "expired"}
                or str(bound["status"]) != terminal
                or str(receipt["outcome"]) != terminal
                or str(bound["actor"]) != str(row["actor"])
                or str(bound["session_hash"]) != str(row["session_hash"])
                or str(receipt["actor"]) != str(row["actor"])
                or str(receipt["session_hash"]) != str(row["session_hash"])
            ):
                raise ValueError("DISPOSITION_AUDIT_CHAIN_MISMATCH")
            if (
                bound_target is None
                or receipt_target is None
                or claim_target.path != bound_target.path
                or claim_target.rel_path != str(row["rel_path"])
                or receipt_target.path != bound_target.path
                or receipt_target.rel_path != bound_target.rel_path
                or (
                    str(_row_value(row, "target_key"))
                    and str(_row_value(row, "target_key")) != bound_target.target_key
                )
                or (
                    str(_row_value(bound, "target_key"))
                    and str(_row_value(bound, "target_key")) != bound_target.target_key
                )
                or (
                    str(_row_value(receipt, "target_key"))
                    and str(_row_value(receipt, "target_key")) != bound_target.target_key
                )
            ):
                raise ValueError("DISPOSITION_TARGET_BINDING_MISMATCH")
            bound_protocol = int(_row_value(bound, "writer_protocol_version", 1) or 1)
            receipt_protocol = int(_row_value(receipt, "writer_protocol_version", 1) or 1)
            if bound_protocol != receipt_protocol or bound_protocol not in {1, WRITER_PROTOCOL_VERSION}:
                raise ValueError("DISPOSITION_PROTOCOL_BINDING_MISMATCH")
            if bound_protocol == WRITER_PROTOCOL_VERSION:
                bound_fence = int(_row_value(bound, "fencing_token", 0) or 0)
                receipt_fence = int(_row_value(receipt, "fencing_token", 0) or 0)
                claim_fence = int(_row_value(row, "fencing_token", 0) or 0)
                if bound_fence <= 0 or claim_fence != bound_fence or receipt_fence != bound_fence:
                    raise ValueError("DISPOSITION_FENCE_BINDING_MISMATCH")
            if terminal == "completed":
                resolved_commit = intent._resolve_git_commit(str(receipt["git_commit"]))
                target = intent.canonical_target(str(bound["target_rel_path"]))
                blob = intent._git_blob(resolved_commit, intent._repo_rel_path(target))
                digest = intent.content_hashes(blob, max_bytes=intent.MAX_TARGET_BYTES) if blob is not None else None
                if (
                    digest is None
                    or digest.raw_sha256 != str(bound["final_raw_sha256"])
                    or digest.canonical_sha256 != str(bound["final_canonical_sha256"])
                    or str(receipt["final_raw_sha256"]) != str(bound["final_raw_sha256"])
                    or str(receipt["final_canonical_sha256"]) != str(bound["final_canonical_sha256"])
                ):
                    raise ValueError("DISPOSITION_COMMIT_BLOB_MISMATCH")
        else:
            raise ValueError("DISPOSITION_KIND_INVALID")
        validated.append(item)
    return validated


def _apply_dispositions(conn: sqlite3.Connection, decisions: list[dict[str, Any]]) -> int:
    now = utc_now()
    changed = 0
    for item in decisions:
        if item["kind"] == "expire_legacy_claim":
            terminal_status = "expired"
        else:
            # A claim is only a projection. A successful terminal intent projects
            # to completed; every unsuccessful terminal outcome releases the path
            # as expired while its immutable receipt preserves the exact outcome.
            terminal_status = (
                "completed"
                if str(item.get("expected_intent_status", "")) == "completed"
                else "expired"
            )
        cursor = conn.execute(
            "UPDATE memory_session_claims SET status=?, completed_at=?, updated_at=? "
            "WHERE session_hash=? AND path=? AND intent_id=? AND status=? AND updated_at=?",
            (
                terminal_status,
                now,
                now,
                str(item["session_hash"]),
                str(item["path"]),
                str(item["intent_id"]),
                str(item["expected_status"]),
                str(item["expected_updated_at"]),
            ),
        )
        if cursor.rowcount != 1:
            raise ValueError("DISPOSITION_CAS_MISMATCH")
        changed += 1
    return changed


def preview_dispositions(
    conn: sqlite3.Connection,
    document: dict[str, Any] | None,
) -> dict[str, Any]:
    """Read-only proof that a reviewed disposition can clear every ledger blocker."""

    report = inspect(conn)
    allowed = {
        "ACTIVE_LEGACY_CLAIM",
        "UNSUPPORTED_ACTIVE_ACTOR",
        "TERMINAL_INTENT_ACTIVE_CLAIM",
    }
    unhandled = sorted(set(report["blockers"]) - allowed)
    if unhandled:
        return {
            "ok": False,
            "status": "blocked",
            "stage": "disposition-verify",
            "reason_code": "UNHANDLED_MIGRATION_BLOCKERS",
            "blockers": unhandled,
            "plan": report,
        }
    decisions = _validate_disposition_document(conn, report, document)
    covered_claims = {
        (str(item["session_hash"]), str(item["path"]))
        for item in decisions
    }
    uncovered_unsupported_actor_claims = [
        {
            "session_hash": str(row["session_hash"]),
            "path": str(row["path"]),
            "actor": str(row["actor"]),
        }
        for row in conn.execute(
            "SELECT session_hash, path, actor FROM memory_session_claims WHERE status='active'",
        )
        if str(row["actor"]) not in SUPPORTED_LEDGER_ACTORS
        if (str(row["session_hash"]), str(row["path"])) not in covered_claims
    ]
    unsupported_actor_intents = [
        {"intent_id": str(row["intent_id"]), "actor": str(row["actor"])}
        for row in conn.execute(
            "SELECT intent_id, actor FROM memory_write_intents "
            "WHERE status IN ('pending','approved','bound','validated')"
        )
        if str(row["actor"]) not in SUPPORTED_LEDGER_ACTORS
    ]
    if uncovered_unsupported_actor_claims or unsupported_actor_intents:
        return {
            "ok": False,
            "status": "blocked",
            "stage": "disposition-verify",
            "reason_code": "UNHANDLED_MIGRATION_BLOCKERS",
            "blockers": ["UNSUPPORTED_ACTIVE_ACTOR"],
            "uncovered_claims": uncovered_unsupported_actor_claims,
            "unsupported_intents": unsupported_actor_intents,
            "plan": report,
        }
    return {
        "ok": True,
        "status": "verified",
        "stage": "disposition-verify",
        "decision_count": len(decisions),
        "decision_identities": [_decision_identity(item) for item in decisions],
        "plan": report,
    }


def _backup_destination(backup_path: Path) -> tuple[Path, int | None]:
    """Resolve no symlinks and pin a verified private parent directory."""

    path = absolute_path(backup_path)
    if path.exists() or path.is_symlink():
        raise ValueError("BACKUP_PATH_EXISTS")
    chain: list[Path] = []
    cursor = path.parent
    while True:
        chain.append(cursor)
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    for component in reversed(chain):
        try:
            metadata = component.lstat()
        except FileNotFoundError as exc:
            raise ValueError("BACKUP_PARENT_MISSING") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("BACKUP_PARENT_SYMLINK")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("BACKUP_PARENT_MISSING")
    ensure_private_directory(path.parent, harden_existing=False)
    parent_metadata = path.parent.lstat()
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or (
            POSIX_PERMISSION_MODEL
            and stat.S_IMODE(parent_metadata.st_mode) != 0o700
        )
    ):
        raise ValueError("BACKUP_PARENT_NOT_PRIVATE")
    if not POSIX_PERMISSION_MODEL:
        return path, None
    directory_descriptor = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    pinned = os.fstat(directory_descriptor)
    current = path.parent.lstat()
    if not stat.S_ISDIR(pinned.st_mode) or (pinned.st_dev, pinned.st_ino) != (
        current.st_dev,
        current.st_ino,
    ):
        os.close(directory_descriptor)
        raise ValueError("BACKUP_PARENT_CHANGED")
    return path, directory_descriptor


def _exclusive_backup_file(path: Path, *, parent_fd: int | None) -> int:
    flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if parent_fd is not None:
        return os.open(path.name, flags, PRIVATE_FILE_MODE, dir_fd=parent_fd)
    return os.open(path, flags, PRIVATE_FILE_MODE)


def _assert_pinned_backup(path: Path, *, parent_fd: int | None, file_stat: os.stat_result) -> None:
    current = (
        os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if parent_fd is not None
        else path.lstat()
    )
    if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (
        file_stat.st_dev,
        file_stat.st_ino,
    ):
        raise ValueError("BACKUP_PATH_CHANGED")


def _online_backup(conn: sqlite3.Connection, backup_path: Path) -> dict[str, Any]:
    path, parent_fd = _backup_destination(backup_path)
    descriptor = _exclusive_backup_file(path, parent_fd=parent_fd)
    created = os.fstat(descriptor)
    destination: sqlite3.Connection | None = None
    try:
        _assert_pinned_backup(path, parent_fd=parent_fd, file_stat=created)
        destination = sqlite3.connect(path)
        conn.backup(destination)
        result = str(destination.execute("PRAGMA quick_check").fetchone()[0])
        if result != "ok":
            raise sqlite3.DatabaseError("BACKUP_QUICK_CHECK_FAILED")
        _assert_pinned_backup(path, parent_fd=parent_fd, file_stat=created)
        if os.fstat(descriptor).st_size <= 0:
            raise ValueError("BACKUP_PATH_CHANGED")
    finally:
        if destination is not None:
            destination.close()
        os.close(descriptor)
        if parent_fd is not None:
            os.close(parent_fd)
    return {"path": str(path), "quick_check": "ok"}


def apply_audit_migration(*, backup_path: Path) -> dict[str, Any]:
    if not AUDIT_DB.exists() or AUDIT_DB.is_symlink():
        raise ValueError("AUDIT_DB_MISSING")
    with contextlib.closing(
        secure_sqlite_connect(
            AUDIT_DB,
            create=False,
            row_factory=sqlite3.Row,
            pragmas=("PRAGMA busy_timeout=10000",),
        )
    ) as conn:
        before = inspect_audit(conn)
        planned_data_version = int(conn.execute("PRAGMA data_version").fetchone()[0])
        backup = _online_backup(conn, backup_path)
        conn.execute("BEGIN IMMEDIATE")
        try:
            locked_data_version = int(conn.execute("PRAGMA data_version").fetchone()[0])
            locked_before = inspect_audit(conn)
            if locked_data_version != planned_data_version or locked_before != before:
                conn.rollback()
                return {
                    "ok": False,
                    "status": "blocked",
                    "stage": "audit-apply",
                    "reason_code": "AUDIT_STATE_CHANGED_AFTER_BACKUP",
                    "backup": backup,
                    "report": locked_before,
                }
            _ensure_audit_schema(conn)
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        after = inspect_audit(conn)
        integrity = str(conn.execute("PRAGMA quick_check").fetchone()[0])
    return {
        "ok": bool(after["ok"] and integrity == "ok"),
        "status": "unchanged" if before["ok"] else "applied",
        "stage": "audit-apply",
        "backup": backup,
        "quick_check": integrity,
        "before": before,
        "after": after,
    }


def verify_audit() -> dict[str, Any]:
    plan = audit_migration_plan()
    ready = bool(plan.get("exists") and plan.get("status") == "ready" and plan.get("quick_check") == "ok")
    return {
        **plan,
        "ok": ready,
        "status": "verified" if ready else "migration_required",
        "stage": "audit-verify",
        "reason_code": "" if ready else audit_schema.AUDIT_SCHEMA_REASON_CODE,
    }


def _redact_legacy_search_rows(conn: sqlite3.Connection) -> dict[str, int]:
    if "memory_search_log" not in _tables(conn):
        return {"query_rows_redacted": 0, "path_rows_cleared": 0}
    columns = _columns(conn, "memory_search_log")
    query_rows_redacted = 0
    if {"id", "query"}.issubset(columns):
        selected = conn.execute(
            "SELECT id, query, query_sha256 FROM memory_search_log"
            if "query_sha256" in columns
            else "SELECT id, query, '' AS query_sha256 FROM memory_search_log"
        ).fetchall()
        for row in selected:
            raw = str(row["query"] or "")
            if not raw or re.fullmatch(r"\[redacted:[0-9a-f]{12}\]", raw):
                continue
            stored_digest = str(row["query_sha256"] or "").casefold()
            digest = (
                stored_digest
                if re.fullmatch(r"[0-9a-f]{64}", stored_digest)
                else hashlib.sha256(raw.encode("utf-8")).hexdigest()
            )
            if "query_length" in columns:
                conn.execute(
                    "UPDATE memory_search_log SET query=?, query_sha256=?, query_length=? WHERE id=?",
                    (f"[redacted:{digest[:12]}]", digest, len(raw), int(row["id"])),
                )
            else:
                conn.execute(
                    "UPDATE memory_search_log SET query=?, query_sha256=? WHERE id=?",
                    (f"[redacted:{digest[:12]}]", digest, int(row["id"])),
                )
            query_rows_redacted += 1
    path_rows_cleared = 0
    if "used_paths" in columns:
        path_rows_cleared = int(
            conn.execute(
                "SELECT COUNT(*) FROM memory_search_log WHERE coalesce(used_paths, '')<>''"
            ).fetchone()[0]
        )
        conn.execute("UPDATE memory_search_log SET used_paths='' WHERE coalesce(used_paths, '')<>''")
    return {
        "query_rows_redacted": query_rows_redacted,
        "path_rows_cleared": path_rows_cleared,
    }


def observability_task_seen_backfill_plan(conn: sqlite3.Connection) -> dict[str, Any]:
    """Plan opaque task denominators from durable objective legacy evidence.

    A pre-v4 search/open/completion row proves only that the opaque
    ``(actor, task_id)`` pair existed; it does not reveal a session identifier
    or task content.  The explicit installer migration may therefore add the
    missing lifecycle denominator without inventing adoption or verification
    facts.  Ordinary commands never call this function as a mutation path.
    """

    tables = _tables(conn)
    if not {"memory_search_log", "memory_use_events"}.issubset(tables):
        return {"eligible_pairs": 0, "missing_pairs": 0, "by_actor": {}}
    required_search = {"actor", "task_id", "event_source", "created_at"}
    required_events = {"actor", "task_id", "source", "event_type", "created_at"}
    if not required_search.issubset(_columns(conn, "memory_search_log")) or not required_events.issubset(
        _columns(conn, "memory_use_events")
    ):
        raise sqlite3.OperationalError("STATE_SCHEMA_MIGRATION_REQUIRED")
    rows = conn.execute(
        """
        WITH objective_evidence(actor, task_id, created_at) AS (
          SELECT actor, task_id, created_at
          FROM memory_search_log
          WHERE event_source='tool_observed'
            AND coalesce(actor, '')<>'' AND coalesce(task_id, '')<>''
          UNION ALL
          SELECT actor, task_id, created_at
          FROM memory_use_events
          WHERE source='tool_observed'
            AND coalesce(actor, '')<>'' AND coalesce(task_id, '')<>''
        ), objective_tasks AS (
          SELECT actor, task_id, MIN(created_at) AS first_evidence_at
          FROM objective_evidence
          GROUP BY actor, task_id
        )
        SELECT objective_tasks.actor, objective_tasks.task_id,
               objective_tasks.first_evidence_at,
               CASE WHEN EXISTS (
                 SELECT 1 FROM memory_use_events AS seen
                 WHERE seen.actor=objective_tasks.actor
                   AND seen.task_id=objective_tasks.task_id
                   AND seen.event_type='task_seen'
                   AND seen.source='tool_observed'
               ) THEN 0 ELSE 1 END AS missing
        FROM objective_tasks
        ORDER BY objective_tasks.actor, objective_tasks.task_id
        """
    ).fetchall()
    missing: list[tuple[str, str, str]] = []
    by_actor: dict[str, int] = {}
    for row in rows:
        actor = str(row[0] or "")
        task_id = str(row[1] or "")
        created_at = str(row[2] or "")
        if (
            actor not in OBSERVABILITY_ACTOR_VALUES
            or re.fullmatch(r"[0-9a-f]{64}", task_id) is None
            or re.fullmatch(r"[0-9T:+.Z-]{20,40}", created_at) is None
        ):
            raise sqlite3.IntegrityError("OBSERVABILITY_BACKFILL_SOURCE_INVALID")
        if int(row[3] or 0):
            missing.append((actor, task_id, created_at))
            by_actor[actor] = by_actor.get(actor, 0) + 1
    return {
        "eligible_pairs": len(rows),
        "missing_pairs": len(missing),
        "by_actor": dict(sorted(by_actor.items())),
        "_missing": missing,
    }


def _backfill_observability_task_seen(conn: sqlite3.Connection) -> dict[str, Any]:
    plan = observability_task_seen_backfill_plan(conn)
    missing = list(plan.pop("_missing", []))
    inserted = 0
    for actor, task_id, first_evidence_at in missing:
        event_id = "task_seen_backfill_v4_" + hashlib.sha256(
            f"{actor}\0{task_id}".encode("ascii")
        ).hexdigest()
        conn.execute(
            """
            INSERT INTO memory_use_events(
              event_id, actor, task_id, runtime_version, event_type, source,
              memory_ids_json, memory_versions_json, content_sha256,
              value, reason_code, confidence, labeler_ref_sha256,
              labeler_ref_length, read_mode, result_count,
              required_live_verification_count, full_utf8_bytes,
              returned_utf8_bytes, truncated, page_count, task_class,
              requires_live_verification, created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                event_id, actor, task_id, "migration-v4", "task_seen", "tool_observed",
                "[]", "[]", "", "seen", "", "", "", 0, "", None, None,
                None, None, None, None, "", 0, first_evidence_at,
            ),
        )
        inserted += 1
    remaining = observability_task_seen_backfill_plan(conn)
    if int(remaining["missing_pairs"]) != 0:
        raise sqlite3.IntegrityError("OBSERVABILITY_TASK_SEEN_BACKFILL_INCOMPLETE")
    conn.execute(
        "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
        ("memory_observability_task_seen_backfill_version", "1"),
    )
    return {
        **plan,
        "inserted": inserted,
        "remaining_pairs": int(remaining["missing_pairs"]),
        "version": 1,
    }


def _recovery_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def load_committed_recovery_document(path: Path) -> dict[str, Any]:
    candidate = absolute_path(path)
    with secure_open_regular_beneath(candidate.parent, candidate.name) as handle:
        metadata = os.fstat(handle.fileno())
        if os.name == "posix" and (metadata.st_uid != os.getuid() or metadata.st_mode & 0o077):
            raise ValueError("COMMITTED_RECOVERY_FILE_NOT_PRIVATE")
        raw = handle.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("COMMITTED_RECOVERY_FILE_TOO_LARGE")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("COMMITTED_RECOVERY_FILE_INVALID")
    return payload


def committed_recovery_plan(conn: sqlite3.Connection) -> dict[str, Any]:
    """Read-only, content/version-bound plan for expired, durable exact writes.

    This is an installer maintenance operation, not a new session's adoption
    or validation of an old proposal. No lease is renewed and no fact is
    marked live-verified. Original approval and evidence bindings are retained.
    """
    head = intent.current_git_head(required=True)
    claims = [dict(row) for row in conn.execute(
        "SELECT * FROM memory_session_claims WHERE status='active' ORDER BY path"
    )]
    rows = [dict(row) for row in conn.execute(
        "SELECT * FROM memory_write_intents WHERE status='validated' ORDER BY intent_id"
    )]
    entries: list[dict[str, Any]] = []
    blocked: list[dict[str, str]] = []
    for row in rows:
        if not intent._intent_expired(row):
            continue
        target = intent.canonical_target(str(row["target_rel_path"]))
        repo_path = target.path.relative_to(memory_closeout.REPO_ROOT).as_posix()
        entry = memory_closeout.GitEntry(status="M", repo_path=repo_path, path=target.path)
        if row["actor"] not in {"codex", "claude"} or not (
            memory_closeout._other_session_committed_history_is_exact_validated(
                entry, claim_rows=claims, current_head=head, dirty_repo_paths=set(),
                allow_expired_for_maintenance=True,
            )
        ):
            blocked.append({"intent_id": str(row["intent_id"]),
                            "target": target.rel_path, "reason_code": "COMMITTED_RECOVERY_PROOF_FAILED"})
            continue
        claim = next(item for item in claims if item.get("intent_id") == row["intent_id"])
        observation = conn.execute(
            "SELECT * FROM memory_file_observations WHERE path=?", (str(target.path),)
        ).fetchone()
        if observation and int(observation["fencing_token"] or 0) > int(row["fencing_token"]):
            blocked.append({"intent_id": str(row["intent_id"]), "target": target.rel_path,
                            "reason_code": "COMMITTED_RECOVERY_OBSERVATION_FENCED"})
            continue
        entries.append({
            "intent_id": str(row["intent_id"]), "target": target.rel_path,
            "actor": str(row["actor"]), "fencing_token": int(row["fencing_token"]),
            "content_sha256": str(row["final_raw_sha256"]),
            "ledger_sha256": _recovery_digest({
                "intent": row, "claim": claim,
                "observation": dict(observation) if observation else None,
            }),
        })
    if intent.current_git_head(required=True) != head:
        raise ValueError("COMMITTED_RECOVERY_HEAD_CHANGED")
    plan = {
        "version": 1, "git_head": head,
        "binding_sha256": _recovery_digest({
            "vault": str(memory_closeout.VAULT_ROOT),
            "git_root": str(memory_closeout.REPO_ROOT), "state_db": str(STATE_DB),
        }),
        "entries": entries, "blocked": blocked,
    }
    return {"ok": not blocked, "plan": plan, "plan_sha256": _recovery_digest(plan)}


def preview_committed_recovery(
    conn: sqlite3.Connection, document: dict[str, Any],
) -> dict[str, Any]:
    """Revalidate reviewed evidence before the installer changes any files."""
    approval = document.get("approval", {})
    if (not isinstance(approval, dict) or approval.get("approved") is not True
            or approval.get("reason_code") != "REPAIR_COMMITTED_CLOSEOUT_LEDGER"
            or not re.fullmatch(r"[0-9a-f]{64}", str(approval.get("authorization_ref_sha256", "")))):
        raise ValueError("COMMITTED_RECOVERY_APPROVAL_REQUIRED")
    expected = document.get("plan_sha256", "")
    if expected != _recovery_digest(document.get("plan")):
        raise ValueError("COMMITTED_RECOVERY_PLAN_INVALID")
    # A successful retry cannot create another receipt or manufacture a new
    # observation. The opaque maintenance marker lives in the existing meta
    # table, so this repair does not add/alter the schema.
    marker = "committed_closeout_recovery:" + str(expected)
    previous = conn.execute("SELECT value FROM meta WHERE key=?", (marker,)).fetchone()
    approval_hash = _recovery_digest(approval)
    if previous is not None:
        if str(previous[0]) != approval_hash:
            raise ValueError("COMMITTED_RECOVERY_APPROVAL_CHANGED")
        for entry in document["plan"]["entries"]:
            receipt = conn.execute(
                "SELECT outcome,reason_code,final_raw_sha256,detail_code FROM memory_write_receipts WHERE intent_id=?",
                (entry["intent_id"],),
            ).fetchone()
            if receipt is None or tuple(receipt) != (
                "completed", "MAINTENANCE_COMMITTED_RECOVERY_COMPLETED",
                entry["content_sha256"], "REVIEWED_PLAN_" + expected,
            ):
                raise ValueError("COMMITTED_RECOVERY_RECEIPT_DRIFT")
        return {"ok": True, "recovered": 0, "idempotent": True, "plan_sha256": expected}
    current = committed_recovery_plan(conn)
    if not current["ok"] or current["plan_sha256"] != expected:
        raise ValueError("COMMITTED_RECOVERY_PLAN_CHANGED")
    entries = current["plan"]["entries"]
    if not entries or len(entries) > 100:
        raise ValueError("COMMITTED_RECOVERY_BATCH_INVALID")
    return {"ok": True, "idempotent": False, **current}


def _apply_committed_recovery(
    conn: sqlite3.Connection, document: dict[str, Any],
) -> dict[str, Any]:
    """Caller owns a backed-up BEGIN IMMEDIATE and the maintenance lock."""
    if not conn.in_transaction:
        raise ValueError("COMMITTED_RECOVERY_TRANSACTION_REQUIRED")
    current = preview_committed_recovery(conn, document)
    if current["idempotent"]:
        return current
    expected = current["plan_sha256"]
    approval = document["approval"]
    approval_hash = _recovery_digest(approval)
    marker = "committed_closeout_recovery:" + expected
    entries = current["plan"]["entries"]
    now = utc_now()
    head = current["plan"]["git_head"]
    for entry in entries:
        row = dict(conn.execute(
            "SELECT * FROM memory_write_intents WHERE intent_id=?", (entry["intent_id"],)
        ).fetchone())
        # Explicit column projection preserves the original validation and
        # approval; it cannot import unreviewed session text into the ledger.
        copied = (
            "intent_id writer_protocol_version actor session_hash target_rel_path target_key "
            "fencing_token validation_mode base_raw_sha256 proposal_raw_sha256 "
            "proposal_canonical_sha256 final_raw_sha256 final_canonical_sha256 "
            "base_git_head validated_git_head early_commit proposal_commit approval_binding_sha256 "
            "approval_ref_sha256 source_class knowledge_kind safety_decision safety_reason_code "
            "safety_input_sha256 safety_input_length evidence_ref_sha256 operation target_status "
            "transition_reason_sha256"
        ).split()
        receipt = {key: row[key] for key in copied}
        receipt.update({
            "receipt_id": hashlib.sha256(f"write-receipt:{row['intent_id']}".encode()).hexdigest()[:32],
            "outcome": "completed", "reason_code": "MAINTENANCE_COMMITTED_RECOVERY_COMPLETED",
            "git_commit": head, "created_at": now,
            "asserted_by_sha256": hashlib.sha256(str(row["asserted_by"]).encode()).hexdigest()
            if row["asserted_by"] else "",
            "detail_code": "REVIEWED_PLAN_" + str(expected),
        })
        conn.execute(
            f"INSERT INTO memory_write_receipts ({','.join(receipt)}) VALUES ({','.join('?' for _ in receipt)})",
            tuple(receipt.values()),
        )
        conn.execute(
            "UPDATE memory_write_intents SET status='completed', reason_code=?, updated_at=? WHERE intent_id=?",
            (receipt["reason_code"], now, row["intent_id"]),
        )
        target = intent.canonical_target(str(row["target_rel_path"]))
        conn.execute(
            "INSERT INTO memory_file_observations "
            "(path,rel_path,sha256,actor,session_hash,observed_at,intent_id,fencing_token,git_commit) "
            "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET "
            "rel_path=excluded.rel_path,sha256=excluded.sha256,actor=excluded.actor,"
            "session_hash=excluded.session_hash,observed_at=excluded.observed_at,"
            "intent_id=excluded.intent_id,fencing_token=excluded.fencing_token,git_commit=excluded.git_commit",
            (str(target.path), target.rel_path, row["final_raw_sha256"], row["actor"],
             row["session_hash"], now, row["intent_id"], row["fencing_token"], head),
        )
        conn.execute(
            "UPDATE memory_session_claims SET status='completed', updated_at=?, completed_at=? "
            "WHERE intent_id=? AND status='active'", (now, now, row["intent_id"]),
        )
    # Obsidian's independent backup process does not share our SQLite lock.
    # Recheck both Git and bytes before publishing any terminal receipt.
    for entry in entries:
        exists, digest = intent._read_target(intent.canonical_target(entry["target"]))
        if not exists or digest.raw_sha256 != entry["content_sha256"]:
            raise ValueError("COMMITTED_RECOVERY_CONTENT_CHANGED")
    if intent.current_git_head(required=True) != head:
        raise ValueError("COMMITTED_RECOVERY_HEAD_CHANGED")
    conn.execute("INSERT INTO meta(key,value) VALUES (?,?)", (marker, approval_hash))
    return {"recovered": len(entries), "idempotent": False, "plan_sha256": expected,
            "authorization_ref_sha256": approval["authorization_ref_sha256"]}


def apply_migration(
    conn: sqlite3.Connection,
    *,
    backup_path: Path,
    disposition_document: dict[str, Any] | None = None,
    committed_recovery_document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # Backing up through a SQLite connection that already owns a write
    # transaction can self-block. Take the online backup under the outer shared
    # maintenance lock, then prove the source did not change before acquiring
    # BEGIN IMMEDIATE and re-planning inside that transaction.
    before = inspect(conn)
    allowed_disposition_blockers = {
        "ACTIVE_LEGACY_CLAIM",
        "UNSUPPORTED_ACTIVE_ACTOR",
        "TERMINAL_INTENT_ACTIVE_CLAIM",
    }
    if set(before["blockers"]) - allowed_disposition_blockers:
        return {"ok": False, "status": "blocked", "stage": "apply", "plan": before}
    decisions = _validate_disposition_document(conn, before, disposition_document)
    planned_data_version = int(conn.execute("PRAGMA data_version").fetchone()[0])
    backup = _online_backup(conn, backup_path)
    conn.execute("BEGIN IMMEDIATE")
    try:
        locked_before = inspect(conn)
        locked_data_version = int(conn.execute("PRAGMA data_version").fetchone()[0])
        if set(locked_before["blockers"]) - allowed_disposition_blockers:
            conn.rollback()
            return {"ok": False, "status": "blocked", "stage": "apply", "plan": locked_before}
        if locked_data_version != planned_data_version or locked_before != before:
            conn.rollback()
            return {
                "ok": False,
                "status": "blocked",
                "stage": "apply",
                "reason_code": "STATE_CHANGED_AFTER_BACKUP",
                "backup": backup,
                "plan": locked_before,
            }
        locked_decisions = _validate_disposition_document(conn, locked_before, disposition_document)
        if [_decision_identity(item) for item in locked_decisions] != [
            _decision_identity(item) for item in decisions
        ]:
            raise ValueError("DISPOSITION_SET_CHANGED")
        recovered = (
            _apply_committed_recovery(conn, committed_recovery_document)
            if committed_recovery_document is not None else None
        )
        disposed = _apply_dispositions(conn, locked_decisions)
        post_disposition = inspect(conn)
        if post_disposition["blockers"]:
            raise ValueError("DISPOSITION_BLOCKERS_REMAIN")
        intent.ensure_schema(conn, commit=False)
        # A drifted or older guard must not block the installer from redacting
        # legacy rows inside the already-backed-up migration transaction.
        drop_search_log_privacy_guards(conn)
        privacy_migration = _redact_legacy_search_rows(conn)
        observability_backfill = _backfill_observability_task_seen(conn)
        install_search_log_privacy_guards(conn)
        _add_column(conn, "memory_session_claims", "target_key", "TEXT NOT NULL DEFAULT ''")
        _add_column(conn, "memory_session_claims", "fencing_token", "INTEGER NOT NULL DEFAULT 0")
        _add_column(conn, "memory_session_claims", "claim_kind", "TEXT NOT NULL DEFAULT 'legacy'")
        _add_column(conn, "memory_file_observations", "intent_id", "TEXT NOT NULL DEFAULT ''")
        _add_column(conn, "memory_file_observations", "fencing_token", "INTEGER NOT NULL DEFAULT 0")
        _add_column(conn, "memory_file_observations", "git_commit", "TEXT NOT NULL DEFAULT ''")

        # Seed the per-target fence ledger from any already-migrated rows, then
        # allocate a fresh monotonic token to every still-active v1 intent. A
        # terminal historical row keeps its original protocol/fence metadata.
        now = utc_now()
        for row in conn.execute(
            "SELECT target_key, MAX(fencing_token) AS max_fence "
            "FROM memory_write_intents WHERE fencing_token>0 GROUP BY target_key"
        ).fetchall():
            conn.execute(
                "INSERT INTO memory_path_fences(target_key, last_fence, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(target_key) DO UPDATE SET "
                "last_fence=MAX(memory_path_fences.last_fence, excluded.last_fence), "
                "updated_at=excluded.updated_at",
                (str(row["target_key"]), int(row["max_fence"]), now),
            )
        active_intents = conn.execute(
            "SELECT intent_id, target_key FROM memory_write_intents "
            "WHERE status IN ('pending','approved','bound','validated') AND fencing_token<=0 "
            "ORDER BY created_at, intent_id"
        ).fetchall()
        for row in active_intents:
            fencing_token = intent._allocate_fencing_token(conn, str(row["target_key"]))
            conn.execute(
                "UPDATE memory_write_intents SET writer_protocol_version=?, fencing_token=?, updated_at=? "
                "WHERE intent_id=? AND status IN ('pending','approved','bound','validated') "
                "AND fencing_token<=0",
                (WRITER_PROTOCOL_VERSION, fencing_token, now, str(row["intent_id"])),
            )
        claims = conn.execute(
            "SELECT session_hash, path, status, intent_id FROM memory_session_claims"
        ).fetchall()
        for row in claims:
            target_key = _target_key(str(row["path"]))
            fence = 0
            kind = "legacy"
            if str(row["intent_id"] or ""):
                bound = conn.execute(
                    "SELECT fencing_token FROM memory_write_intents WHERE intent_id=?",
                    (str(row["intent_id"]),),
                ).fetchone()
                if bound is not None and int(bound[0] or 0) > 0:
                    fence = int(bound[0])
                    kind = "intent"
            conn.execute(
                "UPDATE memory_session_claims SET target_key=?, fencing_token=?, claim_kind=? "
                "WHERE session_hash=? AND path=?",
                (target_key, fence, kind, str(row["session_hash"]), str(row["path"])),
            )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_session_claims_active_target "
            "ON memory_session_claims(target_key) WHERE target_key<>'' AND status='active'"
        )
        if "meta" in _tables(conn):
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                ("agent_memory_state_schema_version", str(STATE_SCHEMA_VERSION)),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                ("agent_memory_writer_protocol_version", str(WRITER_PROTOCOL_VERSION)),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    after = inspect(conn)
    return {
        "ok": not after["blockers"] and after["search_log_privacy"]["ready"],
        "status": "applied",
        "stage": "apply",
        "backup": backup,
        "before": before,
        "after": after,
        "disposed_claims": disposed,
        "committed_recovery": recovered,
        "privacy_migration": privacy_migration,
        "observability_task_seen_backfill": observability_backfill,
    }


def _read_json_object(path: Path, reason_code: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(reason_code) from exc
    if not isinstance(payload, dict):
        raise ValueError(reason_code)
    return payload


def _runtime_json_object(relative: Path, reason_code: str) -> dict[str, Any]:
    try:
        payload = json.loads(secure_read_bytes_beneath(RUNTIME_ROOT, relative).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateSecurityError) as exc:
        raise ValueError(reason_code) from exc
    if not isinstance(payload, dict):
        raise ValueError(reason_code)
    return payload


def _config_security_root(path: Path) -> Path:
    root = RUNTIME_ROOT if MANAGED_RUNTIME_FOOTPRINT else absolute_path(CONFIG_ROOT)
    relative_beneath(root, path)
    return root


def _secure_config_bytes(path: Path) -> tuple[bytes, os.stat_result]:
    root = _config_security_root(path)
    relative = relative_beneath(root, path)
    with secure_open_regular_beneath(root, relative) as handle:
        metadata = os.fstat(handle.fileno())
        if metadata.st_size < 0 or metadata.st_size > MAX_RUNTIME_CONFIG_BYTES:
            raise ValueError("RUNTIME_CONFIG_TOO_LARGE")
        raw = handle.read(MAX_RUNTIME_CONFIG_BYTES + 1)
        if len(raw) > MAX_RUNTIME_CONFIG_BYTES:
            raise ValueError("RUNTIME_CONFIG_TOO_LARGE")
        return raw, metadata


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _config_migration_operation_id(
    path: Path,
    *,
    before_sha256: str,
    after_sha256: str,
) -> str:
    root = _config_security_root(path)
    relative = relative_beneath(root, path).as_posix()
    return _sha256_bytes(
        (
            "agent-memory-config-migration-v1\0"
            f"{relative}\0{before_sha256}\0{after_sha256}"
        ).encode("utf-8")
    )


def _assert_no_config_migration_recovery(path: Path) -> None:
    root = _config_security_root(path)
    try:
        unresolved = secure_conditional_recovery_entries_beneath(
            root,
            relative_beneath(root, path),
            namespace="config",
        )
    except ConditionalWriteError as exc:
        raise ValueError("RUNTIME_CONFIG_UNSAFE") from exc
    if unresolved:
        raise ValueError("CONFIG_MIGRATION_RECOVERY_REQUIRED")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_transition(payload: dict[str, Any]) -> None:
    try:
        secure_atomic_write_bytes_beneath(
            RUNTIME_ROOT,
            Path("config/runtime-transition.json"),
            (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
            mode=PRIVATE_FILE_MODE,
        )
    except (OSError, StateSecurityError) as exc:
        raise ValueError("RUNTIME_TRANSITION_UNSAFE") from exc


def _runtime_manifest_health() -> dict[str, Any]:
    manifest = _runtime_json_object(Path("config/runtime-manifest.json"), "RUNTIME_MANIFEST_INVALID")
    anchor = _runtime_json_object(Path("config/runtime-anchor.json"), "RUNTIME_ANCHOR_INVALID")
    anchor_sha256 = secure_sha256_beneath(RUNTIME_ROOT, Path("config/runtime-anchor.json"))
    file_groups = {
        "files": Path("scripts"),
        "support_files": Path(),
        "template_files": Path(),
    }
    mode_groups = {
        "files": "file_modes",
        "support_files": "support_file_modes",
        "template_files": "template_file_modes",
    }
    mode_policy_present = any(key in manifest for key in mode_groups.values())
    calculated_groups: dict[str, dict[str, str]] = {}
    missing: list[str] = []
    mismatched: list[str] = []
    for group, prefix in file_groups.items():
        expected = manifest.get(group)
        expected_modes = manifest.get(mode_groups[group])
        if (
            not isinstance(expected, dict)
            or not expected
            or (
                mode_policy_present
                and (
                    not isinstance(expected_modes, dict)
                    or set(expected_modes) != set(expected)
                )
            )
        ):
            raise ValueError(f"RUNTIME_MANIFEST_{group.upper()}_INVALID")
        calculated: dict[str, str] = {}
        for raw_name, raw_digest in sorted(expected.items()):
            name = str(raw_name)
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("RUNTIME_MANIFEST_PATH_INVALID")
            runtime_relative = prefix / relative
            try:
                content, metadata = secure_read_bytes_and_stat_beneath(
                    RUNTIME_ROOT,
                    runtime_relative,
                )
                digest = hashlib.sha256(content).hexdigest()
            except (OSError, StateSecurityError):
                missing.append(f"{group}:{name}")
                continue
            calculated[name] = digest
            if digest != str(raw_digest):
                mismatched.append(f"{group}:{name}")
            if mode_policy_present:
                raw_mode = expected_modes.get(raw_name) if isinstance(expected_modes, dict) else None
                if (
                    not isinstance(raw_mode, str)
                    or not re.fullmatch(r"[0-7]{4}", raw_mode)
                    or (
                        os.name != "nt"
                        and stat.S_IMODE(metadata.st_mode) != int(raw_mode, 8)
                    )
                ):
                    mismatched.append(f"{mode_groups[group]}:{name}")
        calculated_groups[group] = calculated
    calculated_bundle = _sha256_bytes(
        json.dumps(
            {
                "files": manifest.get("files"),
                "support_files": manifest.get("support_files"),
                "template_files": manifest.get("template_files"),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    compatible = (
        anchor.get("schema_version") == 1
        and anchor.get("managed_runtime") is True
        and absolute_path(str(anchor.get("runtime_root", ""))) == absolute_path(RUNTIME_ROOT)
        and isinstance(anchor.get("install_id"), str)
        and len(str(anchor.get("install_id", ""))) == 64
        and manifest.get("install_id") == anchor.get("install_id")
        and manifest.get("runtime_anchor_sha256") == anchor_sha256
        and manifest.get("schema_version") == 2
        and manifest.get("release_version") == RUNTIME_RELEASE_VERSION
        and manifest.get("runtime_api_version") == 2
        and manifest.get("writer_protocol_version") == WRITER_PROTOCOL_VERSION
        and manifest.get("state_schema_required") == STATE_SCHEMA_VERSION
        and manifest.get("canonical_actors") == CANONICAL_GATEWAY_ACTORS
        and manifest.get("capabilities")
        == {"write_gateway": WRITE_GATEWAY_CAPABILITIES}
        and manifest.get("bundle_sha256") == calculated_bundle
        and not missing
        and not mismatched
    )
    if not compatible:
        raise ValueError("RUNTIME_MANIFEST_INTEGRITY_FAILED")
    return {
        "manifest": manifest,
        "install_id": str(anchor["install_id"]),
        "runtime_anchor_sha256": anchor_sha256,
        "bundle_sha256": calculated_bundle,
        "manifest_sha256": secure_sha256_beneath(
            RUNTIME_ROOT,
            Path("config/runtime-manifest.json"),
        ),
        "files_verified": sum(len(group) for group in calculated_groups.values()),
    }


def _load_toml_text(text: str) -> dict[str, Any]:
    try:
        import tomllib
    except ImportError:  # pragma: no cover - Python 3.10 fallback
        # The small fallback parser predates legal TOML comments following a
        # table header.  Normalize only that syntactic comment so Python 3.9
        # sees the same section structure as tomllib without touching values.
        fallback_text = re.sub(
            r"(?m)^(\s*\[[^\]\r\n]+\])\s+#.*$",
            r"\1",
            text,
        )
        payload = parse_toml_fallback(fallback_text)
    else:
        payload = tomllib.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("RUNTIME_CONFIG_INVALID")
    return payload


def _write_gateway_health(payload: dict[str, Any]) -> dict[str, Any]:
    gateway = payload.get("write_gateway")
    if not isinstance(gateway, dict):
        raise ValueError("WRITE_GATEWAY_MISSING")
    actors = gateway.get("canonical_actors")
    compatible = (
        str(gateway.get("mode", "")).strip().lower() == "enforce"
        and gateway.get("writer_protocol_version") == WRITER_PROTOCOL_VERSION
        and gateway.get("state_schema_required") == STATE_SCHEMA_VERSION
        and actors == CANONICAL_GATEWAY_ACTORS
        and gateway.get("path_fencing") is True
        and gateway.get("claims_are_projection") is True
        and gateway.get("full_vault") is True
    )
    if not compatible:
        raise ValueError("WRITE_GATEWAY_INVALID")
    return gateway


def _write_gateway_upgradeable(payload: dict[str, Any]) -> bool:
    """Return whether only the state-v3 -> state-v4 gate needs migration."""

    gateway = payload.get("write_gateway")
    if not isinstance(gateway, dict):
        return False
    return (
        str(gateway.get("mode", "")).strip().lower() == "enforce"
        and gateway.get("writer_protocol_version") == WRITER_PROTOCOL_VERSION
        and gateway.get("state_schema_required") == STATE_SCHEMA_VERSION - 1
        and gateway.get("canonical_actors") == CANONICAL_GATEWAY_ACTORS
        and gateway.get("path_fencing") is True
        and gateway.get("claims_are_projection") is True
        and gateway.get("full_vault") is True
    )


def _upgrade_write_gateway_state_schema(text: str) -> str:
    section = re.search(
        r"(?ms)^\[write_gateway\][^\r\n]*(?:\r?\n)(.*?)(?=^\[|\Z)",
        text,
    )
    if section is None:
        raise ValueError("WRITE_GATEWAY_INVALID")
    body = section.group(1)
    replaced, count = re.subn(
        r"(?m)^(\s*state_schema_required\s*=\s*)3(\s*(?:#.*)?$)",
        rf"\g<1>{STATE_SCHEMA_VERSION}\g<2>",
        body,
        count=1,
    )
    if count != 1:
        raise ValueError("WRITE_GATEWAY_INVALID")
    return text[: section.start(1)] + replaced + text[section.end(1) :]


def _ensure_toml_section_defaults(
    text: str,
    section_name: str,
    defaults: tuple[tuple[str, str], ...],
) -> tuple[str, list[str]]:
    """Add only absent managed keys, preserving all existing private values."""

    section = re.search(
        rf"(?ms)^\[{re.escape(section_name)}\][^\r\n]*(?:\r?\n)(.*?)(?=^\[|\Z)",
        text,
    )
    newline = "\r\n" if "\r\n" in text else "\n"
    if section is None:
        block = newline + f"[{section_name}]" + newline
        block += "".join(f"{key} = {value}{newline}" for key, value in defaults)
        return text.rstrip("\r\n") + newline + block, [key for key, _ in defaults]
    body = section.group(1)
    missing = [
        (key, value)
        for key, value in defaults
        if re.search(rf"(?m)^\s*{re.escape(key)}\s*=", body) is None
    ]
    if not missing:
        return text, []
    suffix = "" if not body or body.endswith(("\n", "\r")) else newline
    migrated_body = body + suffix + "".join(
        f"{key} = {value}{newline}" for key, value in missing
    )
    return text[: section.start(1)] + migrated_body + text[section.end(1) :], [
        key for key, _ in missing
    ]


def _managed_runtime_python(planned_runtime_root: Path | None = None) -> Path | None:
    runtime_root = planned_runtime_root or RUNTIME_ROOT
    if planned_runtime_root is None and not MANAGED_RUNTIME_FOOTPRINT:
        return None
    candidate = (
        runtime_root / ".venv" / "Scripts" / "python.exe"
        if os.name == "nt"
        else runtime_root / ".venv" / "bin" / "python"
    )
    if planned_runtime_root is not None:
        # Source checkout plan/config-plan is read-only and runs before the
        # target Runtime trust decision.  Derive only the fixed lexical path;
        # never execute or resolve the target venv here. install_runtime will
        # authenticate ready v2 or recoverably replace legacy/unattestable venvs.
        try:
            assert_no_symlink_beneath(
                runtime_root,
                candidate,
                include_leaf=False,
                allow_missing=True,
            )
        except (OSError, StateSecurityError) as exc:
            raise ValueError("MANAGED_RUNTIME_PYTHON_PATH_UNSAFE") from exc
    else:
        try:
            runtime_python_attestation(runtime_root, candidate)
        except (OSError, StateSecurityError, subprocess.SubprocessError) as exc:
            raise ValueError("MANAGED_RUNTIME_PYTHON_INVALID") from exc
    return Path(os.path.abspath(str(candidate)))


def _migrate_top_level_python(text: str, python: Path) -> tuple[str, bool]:
    """Replace only the top-level Python key; preserve semantic Python."""

    section = re.search(r"(?m)^\s*\[", text)
    end = section.start() if section is not None else len(text)
    prefix = text[:end]
    suffix = text[end:]
    encoded = json.dumps(str(python), ensure_ascii=False)
    pattern = re.compile(r"(?m)^(\s*python\s*=\s*)[^#\r\n]+")
    if pattern.search(prefix):
        migrated_prefix = pattern.sub(lambda match: f"{match.group(1)}{encoded} ", prefix, count=1)
    else:
        separator = "" if not prefix or prefix.endswith(("\n", "\r")) else "\n"
        migrated_prefix = prefix + separator + f"python = {encoded}\n"
    migrated = migrated_prefix + suffix
    return migrated, migrated != text


def _remove_obsolete_write_gateway_actor_key(text: str) -> tuple[str, bool]:
    """Remove only the obsolete actor key from the write_gateway table.

    Configuration migration is deliberately surgical: comments, ordering,
    line endings, and identically named keys in every other table remain
    byte-for-byte unchanged.  Fail closed if a semantically present key cannot
    be located as one single-line assignment in the expected table.
    """

    payload = _load_toml_text(text)
    gateway = payload.get("write_gateway")
    if not isinstance(gateway, dict):
        raise ValueError("WRITE_GATEWAY_MISSING")
    if "legacy_actor" not in gateway:
        return text, False

    headers = list(
        re.finditer(
            r"(?m)^[ \t]*\[write_gateway\][ \t]*(?:#[^\r\n]*)?(?:\r?\n|\Z)",
            text,
        )
    )
    if len(headers) != 1:
        raise ValueError("WRITE_GATEWAY_SECTION_INVALID")
    body_start = headers[0].end()
    next_header = re.search(r"(?m)^[ \t]*\[[^\r\n]+\]", text[body_start:])
    body_end = body_start + next_header.start() if next_header is not None else len(text)
    body = text[body_start:body_end]
    assignments = list(
        re.finditer(
            r'''(?m)^[ \t]*(?:legacy_actor|"legacy_actor"|'legacy_actor')[ \t]*=[^\r\n]*(?:\r?\n|\Z)''',
            body,
        )
    )
    if len(assignments) != 1:
        raise ValueError("WRITE_GATEWAY_LEGACY_ACTOR_KEY_UNSAFE")
    assignment = assignments[0]
    migrated = (
        text[: body_start + assignment.start()]
        + text[body_start + assignment.end() :]
    )
    reparsed = _load_toml_text(migrated)
    migrated_gateway = reparsed.get("write_gateway")
    if not isinstance(migrated_gateway, dict) or "legacy_actor" in migrated_gateway:
        raise ValueError("WRITE_GATEWAY_LEGACY_ACTOR_KEY_REMOVE_FAILED")
    return migrated, True


def _runtime_config_health() -> dict[str, Any]:
    path = config_path()
    if absolute_path(path) != absolute_path(RUNTIME_ROOT / "config" / "agent-memory.toml"):
        raise ValueError("RUNTIME_CONFIG_UNSAFE")
    try:
        raw, metadata = secure_read_bytes_and_stat_beneath(
            RUNTIME_ROOT,
            Path("config/agent-memory.toml"),
        )
    except (OSError, StateSecurityError) as exc:
        raise ValueError("RUNTIME_CONFIG_UNSAFE") from exc
    if POSIX_PERMISSION_MODEL and stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE:
        raise ValueError("RUNTIME_CONFIG_MODE_INVALID")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("RUNTIME_CONFIG_INVALID") from exc
    payload = _load_toml_text(text)
    _write_gateway_health(payload)
    required_paths: dict[str, Path] = {}
    for key in ("memory_root", "git_root", "state_db", "config_root"):
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError("RUNTIME_CONFIG_INCOMPLETE")
        required_paths[key] = expand_path(value.strip()).resolve()
    if not required_paths["memory_root"].is_dir() or not required_paths["git_root"].is_dir():
        raise ValueError("RUNTIME_ROOT_MISSING")
    if required_paths["config_root"] != RUNTIME_ROOT.resolve():
        raise ValueError("RUNTIME_CONFIG_ROOT_MISMATCH")
    if expand_path(env_value("ROOT", "")).resolve() != required_paths["memory_root"]:
        raise ValueError("RUNTIME_MEMORY_ROOT_OVERRIDE_MISMATCH")
    if expand_path(env_value("GIT_ROOT", "")).resolve() != required_paths["git_root"]:
        raise ValueError("RUNTIME_GIT_ROOT_OVERRIDE_MISMATCH")
    if expand_path(env_value("CONFIG_ROOT", "")).resolve() != required_paths["config_root"]:
        raise ValueError("RUNTIME_CONFIG_ROOT_OVERRIDE_MISMATCH")
    if required_paths["state_db"] != STATE_DB.resolve():
        raise ValueError("RUNTIME_STATE_PATH_MISMATCH")
    raw_python = payload.get("python")
    if not isinstance(raw_python, str) or not raw_python.strip():
        raise ValueError("RUNTIME_PYTHON_MISSING")
    python_path = absolute_path(expand_path(raw_python.strip()))
    try:
        python_identity = runtime_python_attestation(RUNTIME_ROOT, python_path)
    except (OSError, StateSecurityError, subprocess.SubprocessError) as exc:
        raise ValueError("RUNTIME_PYTHON_INVALID") from exc
    semantic = payload.get("semantic_retrieval")
    semantic = semantic if isinstance(semantic, dict) else {}
    semantic_mode = str(semantic.get("semantic_mode", "auto")).strip().casefold()
    if semantic_mode not in {"auto", "off", "required"}:
        raise ValueError("SEMANTIC_MODE_INVALID")
    host = payload.get("host")
    host = host if isinstance(host, dict) else {}
    return {
        "path": str(path),
        "sha256": _sha256_bytes(text.encode("utf-8")),
        "memory_root": str(required_paths["memory_root"]),
        "git_root": str(required_paths["git_root"]),
        "state_db": str(required_paths["state_db"]),
        "config_root": str(required_paths["config_root"]),
        "python": str(python_path),
        "runtime_python": python_identity,
        "semantic_enabled": semantic.get("enabled") is True,
        "semantic_mode": semantic_mode,
        "audit_launchagent_label": str(
            host.get("audit_launchagent_label", DEFAULT_AUDIT_LAUNCHAGENT_LABEL)
        ),
        "audit_launchagent": str(
            host.get(
                "audit_launchagent",
                f"~/Library/LaunchAgents/{DEFAULT_AUDIT_LAUNCHAGENT_LABEL}.plist",
            )
        ),
    }


def config_migration_plan(*, planned_runtime_root: Path | None = None) -> dict[str, Any]:
    path = config_path()
    _assert_no_config_migration_recovery(path)
    try:
        original = _secure_config_bytes(path)[0].decode("utf-8")
    except ValueError:
        raise
    except (OSError, UnicodeDecodeError, StateSecurityError) as exc:
        raise ValueError("RUNTIME_CONFIG_UNSAFE")
    payload = _load_toml_text(original)
    gateway = payload.get("write_gateway")
    if isinstance(gateway, dict):
        operations: list[str] = []
        if _write_gateway_upgradeable(payload):
            migrated = _upgrade_write_gateway_state_schema(original)
            operations.append("UPGRADE_WRITE_GATEWAY_STATE_SCHEMA_V4")
        else:
            _write_gateway_health(payload)
            migrated = original
        migrated, obsolete_actor_removed = _remove_obsolete_write_gateway_actor_key(migrated)
        if obsolete_actor_removed:
            operations.append("REMOVE_WRITE_GATEWAY_LEGACY_ACTOR")
    else:
        if gateway is not None:
            raise ValueError("WRITE_GATEWAY_INVALID")
        legacy = payload.get("write_intents")
        if legacy is not None and not isinstance(legacy, dict):
            raise ValueError("WRITE_INTENTS_INVALID")
        migrated = original
        if isinstance(legacy, dict):
            section = re.search(r"(?ms)^\[write_intents\][^\r\n]*(?:\r?\n)(.*?)(?=^\[|\Z)", migrated)
            if section is None:
                raise ValueError("WRITE_INTENTS_SECTION_INVALID")
            body = section.group(1)
            if re.search(r"(?m)^\s*enabled\s*=", body):
                body = re.sub(r"(?m)^(\s*enabled\s*=\s*)[^#\r\n]+", r"\1false ", body, count=1)
            else:
                body += "enabled = false\n"
            if re.search(r"(?m)^\s*enforcement\s*=", body):
                body = re.sub(r"(?m)^(\s*enforcement\s*=\s*)[^#\r\n]+", r'\1"off" ', body, count=1)
            else:
                body += 'enforcement = "off"\n'
            migrated = migrated[: section.start(1)] + body + migrated[section.end(1) :]
        block = (
            "\n[write_gateway]\n"
            'mode = "enforce"\n'
            "writer_protocol_version = 2\n"
            f"state_schema_required = {STATE_SCHEMA_VERSION}\n"
            'canonical_actors = ["codex", "claude", "ailu"]\n'
            "path_fencing = true\n"
            "claims_are_projection = true\n"
            "full_vault = true\n"
            "ttl_hours = 24\n"
        )
        migrated = migrated.rstrip() + "\n" + block
        _write_gateway_health(_load_toml_text(migrated))
        operations = ["ADD_WRITE_GATEWAY_V2"]
        if isinstance(legacy, dict):
            operations.append("DISABLE_LEGACY_WRITE_INTENTS")
    configured_runtime_root = payload.get("config_root")
    defaults_runtime_root = (
        planned_runtime_root
        if planned_runtime_root is not None
        else (
            expand_path(configured_runtime_root).resolve()
            if isinstance(configured_runtime_root, str) and configured_runtime_root.strip()
            else RUNTIME_ROOT.resolve()
        )
    )
    defaults_semantic_python = (
        defaults_runtime_root / ".venv" / "Scripts" / "python.exe"
        if os.name == "nt"
        else defaults_runtime_root / ".venv" / "bin" / "python"
    )
    managed_defaults = (
        (
            "host",
            (
                ("audit_launchagent_label", '"com.agent-memory-vault.audit"'),
                ("audit_launchagent", '"~/Library/LaunchAgents/com.agent-memory-vault.audit.plist"'),
            ),
        ),
        (
            "observability",
            (
                ("enabled", "true"),
                ("stale_adoption_enforcement", '"shadow"'),
                ("metadata_enforcement", '"shadow"'),
                ("shadow_min_days", "7"),
            ),
        ),
        (
            "shadow",
            (
                ("state_dir", json.dumps(str(defaults_runtime_root / "shadow"), ensure_ascii=False)),
                ("status", '"observing"'),
                ("shadow_started_at", '""'),
                ("runtime_installed_at", '""'),
                ("manifest_sha256", '""'),
                ("cutover_evidence_sha256", '""'),
                ("cutover_evidence_file", '""'),
                ("cutover_from_config_sha256", '""'),
                ("cutover_config_backup", '""'),
                ("cutover_at", '""'),
            ),
        ),
        (
            "semantic_retrieval",
            (
                ("enabled", "false"),
                ("semantic_mode", '"auto"'),
                ("ranking_version", '"hybrid-v2-shadow"'),
                ("vector_dir", json.dumps(str(defaults_runtime_root / "zvec" / "memory_chunks_embeddinggemma_768"), ensure_ascii=False)),
                ("embedding_model", '"google/embeddinggemma-300m"'),
                ("embedding_dim", "768"),
                ("embedding_device", '"cpu"'),
                ("python", json.dumps(str(defaults_semantic_python), ensure_ascii=False)),
                ("lock_path", json.dumps(str(defaults_runtime_root / "locks" / "zvec.lock"), ensure_ascii=False)),
                ("zvec_lock_timeout_seconds", "2"),
                ("zvec_max_distance", "0.72"),
                ("require_local_model", "false"),
                ("model_revision", '""'),
                ("model_manifest", json.dumps(str(defaults_runtime_root / "models" / "embeddinggemma-300m" / "model-manifest.json"), ensure_ascii=False)),
                ("dependency_lock", json.dumps(str(defaults_runtime_root / "requirements-vector.lock"), ensure_ascii=False)),
                ("candidate_pool_min", "64"),
                ("candidate_pool_factor", "16"),
                ("candidate_pool_scope_min", "128"),
                ("candidate_pool_max", "512"),
                ("embedding_worker_socket", json.dumps(str(defaults_runtime_root / "run" / "embedding.sock"), ensure_ascii=False)),
                ("embedding_worker_idle_seconds", "600"),
                ("embedding_worker_cold_timeout_seconds", "12"),
                ("embedding_worker_warm_timeout_seconds", "2"),
                ("run_vector_index_after_closeout", "false"),
            ),
        ),
    )
    for section_name, defaults in managed_defaults:
        migrated, added_keys = _ensure_toml_section_defaults(
            migrated,
            section_name,
            defaults,
        )
        if added_keys:
            operations.append(f"ADD_{section_name.upper()}_V4_DEFAULTS")
    if planned_runtime_root is not None:
        configured_root = payload.get("config_root")
        if not isinstance(configured_root, str) or (
            expand_path(configured_root).resolve() != planned_runtime_root.resolve()
        ):
            raise ValueError("PLANNED_RUNTIME_ROOT_MISMATCH")
    managed_python = _managed_runtime_python(planned_runtime_root)
    if managed_python is not None:
        migrated, python_changed = _migrate_top_level_python(migrated, managed_python)
        if python_changed:
            operations.append("PIN_MANAGED_RUNTIME_PYTHON")
    # Reparse after all surgical edits, proving that the semantic section and
    # every unrelated private key still form valid TOML.
    _write_gateway_health(_load_toml_text(migrated))
    before_sha256 = _sha256_bytes(original.encode("utf-8"))
    after_sha256 = _sha256_bytes(migrated.encode("utf-8"))
    return {
        "ok": True,
        "status": "ready" if migrated == original else "migration_required",
        "stage": "config-plan",
        "changed": migrated != original,
        "operations": operations,
        "path": str(path),
        "before_sha256": before_sha256,
        "after_sha256": after_sha256,
        "operation_id": (
            _config_migration_operation_id(
                path,
                before_sha256=before_sha256,
                after_sha256=after_sha256,
            )
            if migrated != original
            else ""
        ),
        "_migrated_text": migrated,
    }


def _exclusive_private_backup(path: Path, content: bytes) -> dict[str, Any]:
    target, parent_fd = _backup_destination(path)
    descriptor = _exclusive_backup_file(target, parent_fd=parent_fd)
    created = os.fstat(descriptor)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _assert_pinned_backup(target, parent_fd=parent_fd, file_stat=created)
        if parent_fd is not None:
            try:
                os.fsync(parent_fd)
            except OSError as exc:
                raise ValueError("BACKUP_PARENT_FSYNC_FAILED") from exc
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
    return {"path": str(target), "sha256": _sha256_bytes(content)}


def apply_config_migration(*, backup_path: Path | None) -> dict[str, Any]:
    plan = config_migration_plan()
    migrated = str(plan.pop("_migrated_text"))
    if not plan["changed"]:
        return {**plan, "status": "unchanged", "stage": "config-apply", "backup": {"status": "not_applicable"}}
    if backup_path is None:
        raise ValueError("BACKUP_PATH_REQUIRED")
    path = config_path()
    try:
        before = _secure_config_bytes(path)[0]
    except (OSError, StateSecurityError) as exc:
        raise ValueError("RUNTIME_CONFIG_UNSAFE") from exc
    if _sha256_bytes(before) != plan["before_sha256"]:
        raise ValueError("CONFIG_CHANGED_AFTER_PLAN")
    backup = _exclusive_private_backup(backup_path, before)
    try:
        current = _secure_config_bytes(path)[0]
        if _sha256_bytes(current) != plan["before_sha256"]:
            raise ValueError("CONFIG_CHANGED_BEFORE_REPLACE")
        security_root = _config_security_root(path)
        secure_conditional_write_bytes_beneath(
            security_root,
            relative_beneath(security_root, path),
            migrated.encode("utf-8"),
            expected_sha256=str(plan["before_sha256"]),
            expected_size=len(before),
            operation_id=str(plan["operation_id"]),
            namespace="config",
            max_capture_bytes=MAX_RUNTIME_CONFIG_BYTES,
            mode=PRIVATE_FILE_MODE,
        )
    except ConditionalWriteError as exc:
        if exc.reason_code == "CONDITIONAL_WRITE_TARGET_CHANGED":
            raise ValueError("CONFIG_CHANGED_BEFORE_REPLACE") from exc
        if exc.reason_code == "CONDITIONAL_WRITE_RECOVERY_REQUIRED":
            raise ValueError("CONFIG_MIGRATION_RECOVERY_REQUIRED") from exc
        raise ValueError("CONFIG_MIGRATION_REPLACE_FAILED") from exc
    except (OSError, StateSecurityError) as exc:
        raise ValueError("CONFIG_MIGRATION_REPLACE_FAILED") from exc
    verified = _runtime_config_health()
    if verified["sha256"] != plan["after_sha256"]:
        raise ValueError("CONFIG_MIGRATION_VERIFY_FAILED")
    return {**plan, "status": "applied", "stage": "config-apply", "backup": backup}


def _issue_preflight_capability(manifest_health: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    marker = _runtime_json_object(
        Path("config/runtime-transition.json"),
        "RUNTIME_TRANSITION_MARKER_INVALID",
    )
    bundle = str(manifest_health["bundle_sha256"])
    if marker.get("bundle_sha256") != bundle:
        raise ValueError("RUNTIME_TRANSITION_NOT_MIGRATABLE")
    # A ready marker may need a fresh attestation after an unrelated host
    # configuration edit changes the container file hash while the managed
    # Hook semantics remain intact.  The caller has already verified the
    # runtime manifest, config and state, and the preflight below rechecks all
    # of them under the maintenance lock before publishing ready again.  Let
    # that fail-closed path re-attest in place instead of forcing a Runtime
    # reinstall (which would also discard the managed venv packages).
    token = secrets.token_hex(32)
    expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)
    capability = {
        **marker,
        "phase": "preflight",
        "bundle_sha256": bundle,
        "capability_sha256": _sha256_bytes(token.encode("utf-8")),
        "capability_parent_pid": os.getpid(),
        "capability_expires_at": expires.replace(microsecond=0).isoformat(),
        "capability_commands": list(CAPABILITY_COMMANDS),
        "updated_at": utc_now(),
    }
    _atomic_transition(capability)
    return token, capability


def validate_doctor_process_contract(
    payload: dict[str, Any],
    returncode: int | None = None,
) -> None:
    """Bind Doctor's JSON envelope to its native process exit contract."""

    summary = payload.get("summary")
    if (
        not isinstance(summary, dict)
        or set(summary) != {"pass", "warn", "fail"}
        or any(
            not isinstance(summary.get(key), int)
            or isinstance(summary.get(key), bool)
            or int(summary[key]) < 0
            for key in ("pass", "warn", "fail")
        )
        or not isinstance(payload.get("ok"), bool)
    ):
        raise ValueError("PREFLIGHT_DOCTOR_PROCESS_CONTRACT_INVALID")
    status = payload.get("status")
    if status == "error":
        expected_ok = False
        expected_returncode = 2
    elif status in {"ok", "warning"}:
        expected_ok = True
        expected_returncode = 0
    else:
        raise ValueError("PREFLIGHT_DOCTOR_PROCESS_CONTRACT_INVALID")
    if payload["ok"] is not expected_ok or (
        returncode is not None and returncode != expected_returncode
    ):
        raise ValueError("PREFLIGHT_DOCTOR_PROCESS_CONTRACT_INVALID")


def _run_preflight_command(
    command: list[str],
    *,
    token: str,
    expect_json: bool = False,
    accepted_returncodes: tuple[int, ...] = (0,),
    doctor_process_contract: bool = False,
) -> dict[str, Any]:
    child_env = os.environ.copy()
    child_env["AGENT_MEMORY_MIGRATION_CAPABILITY"] = token
    child_env["AGENT_MEMORY_MIGRATION_ISSUER_PID"] = str(os.getpid())
    completed = subprocess.run(
        command,
        cwd=RUNTIME_ROOT,
        env=child_env,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=600,
        check=False,
    )
    target_name = next(
        (Path(item).stem for item in command if str(item).endswith(".py")),
        Path(command[0]).stem,
    )
    if completed.returncode not in accepted_returncodes:
        raise ValueError(f"PREFLIGHT_{target_name.upper()}_FAILED")
    payload: dict[str, Any] = {}
    if expect_json:
        try:
            candidate = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ValueError("PREFLIGHT_JSON_INVALID") from exc
        if not isinstance(candidate, dict):
            raise ValueError("PREFLIGHT_JSON_INVALID")
        payload = candidate
        if doctor_process_contract:
            validate_doctor_process_contract(payload, completed.returncode)
    return {"command": f"{target_name}.py", "returncode": completed.returncode, "payload": payload}


def _isolated_runtime_script(
    runtime_python: str,
    target: Path,
    *arguments: str,
    load_site_packages: bool = False,
) -> list[str]:
    runner = (
        "import runpy,sys;"
        "target=sys.argv[1];sys.path.append(str(__import__('pathlib').Path(target).parent));"
        "sys.argv=sys.argv[1:];runpy.run_path(target,run_name='__main__')"
    )
    # Pure first-party preflight scripts run without site initialization.  The
    # vector preflight is the deliberate exception: it must load the pinned
    # native/model dependencies from the managed venv.  ``-I`` still ignores
    # user-site packages and Python environment variables.
    flags = ["-I"] if load_site_packages else ["-I", "-S"]
    return [runtime_python, *flags, "-c", runner, str(target), *arguments]


def _run_generated_index_migration_locked(*, token: str) -> dict[str, Any]:
    """Run the private closeout transaction under ``migration_lock``.

    This stays in-process because the caller already owns ``closeout.lock``;
    spawning the closeout CLI would deadlock trying to reacquire that lock.
    The closeout implementation still uses its one-shot generated-index
    capability and exact Git HEAD CAS commit.
    """

    payload = memory_closeout.run_initial_generated_index_migration(
        argparse.Namespace(
            actor="migration",
            trigger="migration",
            commit=True,
            dry_run=False,
            message="agent-memory migration: generate INDEX",
        ),
        maintenance_capability={"token": token, "issuer_pid": os.getpid()},
    )
    if payload.get("ok") is not True or payload.get("status") != "ok":
        raise ValueError(
            str(payload.get("reason_code") or "PREFLIGHT_GENERATED_INDEX_MIGRATION_FAILED")
        )
    return {
        "command": "agent_memory_closeout.py",
        "returncode": 0,
        "payload": payload,
    }


def migrate_generated_index() -> dict[str, Any]:
    """Perform the initial generated INDEX closeout before Host mutation."""

    manifest = _runtime_manifest_health()
    config = _runtime_config_health()
    audit = verify_audit()
    if not audit.get("ok"):
        raise ValueError("AUDIT_SCHEMA_NOT_READY")
    with contextlib.closing(connect(read_only=True)) as conn:
        state = verify(conn, publish_ready=False)
    if not state.get("ok"):
        raise ValueError("STATE_SCHEMA_NOT_READY")
    token, capability = _issue_preflight_capability(manifest)
    result = _run_generated_index_migration_locked(token=token)
    terminal_manifest = _runtime_manifest_health()
    terminal_config = _runtime_config_health()
    if terminal_manifest.get("manifest_sha256") != manifest.get("manifest_sha256"):
        raise ValueError("RUNTIME_MANIFEST_CHANGED_DURING_INDEX_MIGRATION")
    if terminal_config.get("sha256") != config.get("sha256"):
        raise ValueError("RUNTIME_CONFIG_CHANGED_DURING_INDEX_MIGRATION")
    return {
        "ok": True,
        "status": "generated_index_migrated",
        "stage": "generated-index-migrate",
        "generated_index": result["payload"],
        "runtime_transition": {
            "phase": capability.get("phase"),
            "maintenance_capability": True,
        },
    }


CONTENT_MIGRATION_ATTESTATION_SCHEMA_VERSION = 1
CONTENT_MIGRATION_REASON_ORDER = (
    "LEGACY_SCOPE_AUTOMATIC",
    "GOVERNANCE_METADATA_V4_AUTOMATIC",
    "RISK_V4_AUTOMATIC",
)


def _validate_preflight_doctor_payload(
    payload: dict[str, Any],
    *,
    ready_content_debt: bool = False,
) -> dict[str, Any]:
    validate_doctor_process_contract(payload)
    checks = payload.get("checks")
    summary = payload.get("summary")
    if not isinstance(checks, list) or not checks or not isinstance(summary, dict):
        raise ValueError("PREFLIGHT_DOCTOR_JSON_INVALID")
    names: list[str] = []
    calculated = {"pass": 0, "warn": 0, "fail": 0}
    normalized: list[dict[str, Any]] = []
    for raw_check in checks:
        if not isinstance(raw_check, dict):
            raise ValueError("PREFLIGHT_DOCTOR_JSON_INVALID")
        name = raw_check.get("name")
        status = raw_check.get("status")
        if not isinstance(name, str) or not name or status not in calculated:
            raise ValueError("PREFLIGHT_DOCTOR_JSON_INVALID")
        names.append(name)
        calculated[str(status)] += 1
        normalized.append(raw_check)
    if len(names) != len(set(names)) or any(summary.get(key) != value for key, value in calculated.items()):
        raise ValueError("PREFLIGHT_DOCTOR_JSON_INVALID")
    expected_status = "error" if calculated["fail"] else ("warning" if calculated["warn"] else "ok")
    if payload.get("status") != expected_status:
        raise ValueError("PREFLIGHT_DOCTOR_JSON_INVALID")

    try:
        legacy_binding = content_migration.normalize_doctor_query(
            payload,
            require_all_automatable=True,
        )
    except content_migration.ContentMigrationError as exc:
        raise ValueError("PREFLIGHT_DOCTOR_SCOPE_CHECK_INVALID") from exc
    scope_matches = [
        item for item in normalized if item.get("name") == "legacy_scope_documents"
    ]
    if len(scope_matches) != 1:
        raise ValueError("PREFLIGHT_DOCTOR_SCOPE_CHECK_INVALID")
    scope_check = scope_matches[0]
    scope_detail = scope_check.get("detail")
    legacy_scope_documents = int(legacy_binding["legacy_scope_documents"])
    if not isinstance(scope_detail, dict):
        raise ValueError("PREFLIGHT_DOCTOR_SCOPE_CHECK_INVALID")
    if legacy_scope_documents == 0:
        if scope_check.get("status") != "pass":
            raise ValueError("PREFLIGHT_DOCTOR_SCOPE_CHECK_INVALID")
    elif ready_content_debt:
        if (
            scope_check.get("status") != "fail"
            or scope_detail.get("bootstrap_advisory") is not False
        ):
            raise ValueError("PREFLIGHT_DOCTOR_SCOPE_CHECK_INVALID")
    elif (
        scope_check.get("status") != "warn"
        or scope_detail.get("bootstrap_advisory") is not True
    ):
        raise ValueError("PREFLIGHT_DOCTOR_SCOPE_CHECK_INVALID")

    try:
        governance_debt = content_migration.preflight_governance_migration_debt(
            payload
        )
    except content_migration.ContentMigrationError as exc:
        raise ValueError("PREFLIGHT_DOCTOR_GOVERNANCE_DEBT_INVALID") from exc

    failures = {
        str(item["name"])
        for item in normalized
        if item.get("status") == "fail"
    }
    safe_governance_documents = int(
        governance_debt["safe_automatic_governance_documents"]
    )
    allowed_failures: set[str] = set()
    if int(governance_debt["temporal_failure_documents"]):
        allowed_failures.add("temporal_fact_coverage")
    governance_check = next(
        item for item in normalized if item.get("name") == "governance_metadata_v4"
    )
    if governance_check.get("status") == "fail" and safe_governance_documents:
        allowed_failures.add("governance_metadata_v4")
    if ready_content_debt and legacy_scope_documents:
        allowed_failures.add("legacy_scope_documents")
    if failures - allowed_failures:
        raise ValueError("PREFLIGHT_DOCTOR_FAILED")
    if failures and not (legacy_scope_documents or safe_governance_documents):
        raise ValueError("PREFLIGHT_DOCTOR_FAILED")

    reason_codes: list[str] = []
    if legacy_scope_documents:
        reason_codes.append(CONTENT_MIGRATION_REASON_ORDER[0])
    if int(governance_debt["governance_metadata_automatic_documents"]):
        reason_codes.append(CONTENT_MIGRATION_REASON_ORDER[1])
    if int(governance_debt["governance_risk_automatic_documents"]):
        reason_codes.append(CONTENT_MIGRATION_REASON_ORDER[2])
    legacy_binding_sha256 = content_migration.canonical_sha256(legacy_binding)
    content_debt = {
        "schema_version": CONTENT_MIGRATION_ATTESTATION_SCHEMA_VERSION,
        "legacy_scope_documents": legacy_scope_documents,
        "safe_automatic_governance_documents": safe_governance_documents,
        "governance_metadata_automatic_documents": int(
            governance_debt["governance_metadata_automatic_documents"]
        ),
        "governance_risk_automatic_documents": int(
            governance_debt["governance_risk_automatic_documents"]
        ),
        "governance_automatic_overlap_documents": int(
            governance_debt["governance_automatic_overlap_documents"]
        ),
        "governance_manual_review_documents": int(
            governance_debt["governance_manual_review_documents"]
        ),
        "governance_unsafe_documents": int(
            governance_debt["governance_unsafe_documents"]
        ),
        "temporal_failure_documents": int(
            governance_debt["temporal_failure_documents"]
        ),
        "legacy_binding_sha256": legacy_binding_sha256,
        "governance_binding_sha256": str(
            governance_debt["governance_binding_sha256"]
        ),
        "governance_automatic_migration_fingerprint_sha256": str(
            governance_debt["automatic_migration_fingerprint_sha256"]
        ),
        "reason_codes": reason_codes,
    }
    content_debt["automatic_migration_fingerprint_sha256"] = (
        content_migration.canonical_sha256({
            "schema_version": CONTENT_MIGRATION_ATTESTATION_SCHEMA_VERSION,
            "legacy_binding_sha256": legacy_binding_sha256,
            "governance_automatic_migration_fingerprint_sha256": content_debt[
                "governance_automatic_migration_fingerprint_sha256"
            ],
        })
    )
    required = bool(legacy_scope_documents or safe_governance_documents)
    return {
        "legacy_scope_documents": legacy_scope_documents,
        "safe_automatic_governance_documents": safe_governance_documents,
        "content_migration_required": required,
        "content_migration": content_debt,
    }


def _validate_content_migration_attestation(
    attestation: dict[str, Any],
) -> dict[str, Any]:
    """Validate the installer-facing, path-free content debt invariant."""

    content_debt = attestation.get("content_migration")
    expected_keys = {
        "schema_version",
        "legacy_scope_documents",
        "safe_automatic_governance_documents",
        "governance_metadata_automatic_documents",
        "governance_risk_automatic_documents",
        "governance_automatic_overlap_documents",
        "governance_manual_review_documents",
        "governance_unsafe_documents",
        "temporal_failure_documents",
        "legacy_binding_sha256",
        "governance_binding_sha256",
        "governance_automatic_migration_fingerprint_sha256",
        "automatic_migration_fingerprint_sha256",
        "reason_codes",
    }
    if not isinstance(content_debt, dict) or set(content_debt) != expected_keys:
        raise ValueError("CONTENT_MIGRATION_ATTESTATION_INVALID")
    if content_debt.get("schema_version") != CONTENT_MIGRATION_ATTESTATION_SCHEMA_VERSION:
        raise ValueError("CONTENT_MIGRATION_ATTESTATION_INVALID")
    count_keys = {
        "legacy_scope_documents",
        "safe_automatic_governance_documents",
        "governance_metadata_automatic_documents",
        "governance_risk_automatic_documents",
        "governance_automatic_overlap_documents",
        "governance_manual_review_documents",
        "governance_unsafe_documents",
        "temporal_failure_documents",
    }
    if any(
        not isinstance(content_debt.get(key), int)
        or isinstance(content_debt.get(key), bool)
        or int(content_debt[key]) < 0
        for key in count_keys
    ):
        raise ValueError("CONTENT_MIGRATION_ATTESTATION_INVALID")
    metadata_count = int(content_debt["governance_metadata_automatic_documents"])
    risk_count = int(content_debt["governance_risk_automatic_documents"])
    overlap_count = int(content_debt["governance_automatic_overlap_documents"])
    safe_count = int(content_debt["safe_automatic_governance_documents"])
    if (
        overlap_count > min(metadata_count, risk_count)
        or safe_count != metadata_count + risk_count - overlap_count
        or int(content_debt["temporal_failure_documents"]) > safe_count
    ):
        raise ValueError("CONTENT_MIGRATION_ATTESTATION_INVALID")
    hash_keys = {
        "legacy_binding_sha256",
        "governance_binding_sha256",
        "governance_automatic_migration_fingerprint_sha256",
        "automatic_migration_fingerprint_sha256",
    }
    if any(
        not isinstance(content_debt.get(key), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(content_debt[key])) is None
        for key in hash_keys
    ):
        raise ValueError("CONTENT_MIGRATION_ATTESTATION_INVALID")
    expected_fingerprint = content_migration.canonical_sha256({
        "schema_version": CONTENT_MIGRATION_ATTESTATION_SCHEMA_VERSION,
        "legacy_binding_sha256": content_debt["legacy_binding_sha256"],
        "governance_automatic_migration_fingerprint_sha256": content_debt[
            "governance_automatic_migration_fingerprint_sha256"
        ],
    })
    if content_debt["automatic_migration_fingerprint_sha256"] != expected_fingerprint:
        raise ValueError("CONTENT_MIGRATION_ATTESTATION_INVALID")
    expected_reasons: list[str] = []
    if int(content_debt["legacy_scope_documents"]):
        expected_reasons.append(CONTENT_MIGRATION_REASON_ORDER[0])
    if metadata_count:
        expected_reasons.append(CONTENT_MIGRATION_REASON_ORDER[1])
    if risk_count:
        expected_reasons.append(CONTENT_MIGRATION_REASON_ORDER[2])
    if content_debt.get("reason_codes") != expected_reasons:
        raise ValueError("CONTENT_MIGRATION_ATTESTATION_INVALID")
    required = bool(int(content_debt["legacy_scope_documents"]) or safe_count)
    if (
        attestation.get("content_migration_required") is not required
        or attestation.get("legacy_scope_documents")
        != content_debt["legacy_scope_documents"]
        or attestation.get("safe_automatic_governance_documents") != safe_count
    ):
        raise ValueError("CONTENT_MIGRATION_ATTESTATION_INVALID")
    return content_debt


def validate_final_doctor_content_debt(
    payload: dict[str, Any],
    attestation: dict[str, Any],
) -> dict[str, Any]:
    """Re-attest the final Doctor and reject any post-publish debt drift."""

    expected = _validate_content_migration_attestation(attestation)
    observed = _validate_preflight_doctor_payload(
        payload,
        ready_content_debt=True,
    )
    if observed["content_migration"] != expected:
        raise ValueError("PREFLIGHT_FINAL_CONTENT_DEBT_DRIFT")
    return observed


def _index_health(conn: sqlite3.Connection, vault_root: Path) -> dict[str, Any]:
    tables = _tables(conn)
    fts_tables = {"memory_fts", "memory_fts_unicode", "memory_fts_trigram"}
    if not ({"memory_docs", "meta"} | fts_tables).issubset(tables):
        raise ValueError("DERIVED_INDEX_MISSING")
    schema_row = conn.execute("SELECT value FROM meta WHERE key='memory_index_schema_version'").fetchone()
    if schema_row is None or str(schema_row[0]) != str(memory_index.INDEX_SCHEMA_VERSION):
        raise ValueError("DERIVED_INDEX_SCHEMA_INVALID")
    expected: dict[str, str] = {}
    for path in sorted(vault_root.rglob("*.md")):
        if path.is_symlink() or not path.is_file():
            raise ValueError("VAULT_MARKDOWN_UNSAFE")
        expected[str(path.resolve())] = _sha256_bytes(path.read_text(encoding="utf-8", errors="replace").encode("utf-8"))
    actual = {str(row[0]): str(row[1]) for row in conn.execute("SELECT path, sha256 FROM memory_docs")}
    fts_counts: dict[str, int] = {}
    for table in sorted(fts_tables):
        paths = {str(row[0]) for row in conn.execute(f"SELECT path FROM {table}")}
        if paths != set(expected):
            raise ValueError("DERIVED_INDEX_STALE")
        fts_counts[table] = len(paths)
    if actual != expected:
        raise ValueError("DERIVED_INDEX_STALE")
    return {"doc_count": len(expected), "fts_counts": fts_counts}


def _command_matches(
    entry: dict[str, Any],
    *,
    python: Path,
    script: Path,
    required: tuple[str, ...],
    forbidden: tuple[str, ...] = (),
    max_timeout: float | None = None,
    expected_timeout: float | None = None,
) -> bool:
    if str(entry.get("type", "")).casefold() != "command":
        return False
    timeout = entry.get("timeout")
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or timeout <= 0
        or (max_timeout is not None and timeout > max_timeout)
        or (expected_timeout is not None and timeout != expected_timeout)
    ):
        return False
    try:
        argv = shlex.split(str(entry.get("command", "")), posix=os.name != "nt")
    except ValueError:
        return False
    if len(argv) < 2:
        return False
    try:
        executable = Path(os.path.abspath(str(Path(argv[0].strip('"')).expanduser())))
    except (OSError, ValueError):
        return False
    expected_python = Path(os.path.abspath(str(python)))
    if script.name in {"agent_memory_stop_hook.py", "agent_memory_session_hook.py"}:
        actor = next(
            (required[index + 1] for index, value in enumerate(required[:-1]) if value == "--actor"),
            "",
        )
        command_name = "stop-hook" if script.name == "agent_memory_stop_hook.py" else "session-hook"
        expected_memoryctl = Path(os.path.abspath(str(RUNTIME_ROOT / "scripts" / "memoryctl")))
        try:
            memoryctl = Path(os.path.abspath(str(Path(argv[3].strip('"')).expanduser())))
        except (IndexError, OSError, ValueError):
            return False
        tail: list[str] = []
        skip_actor_value = False
        for index, value in enumerate(required):
            if skip_actor_value:
                skip_actor_value = False
                continue
            if value == "--actor" and index + 1 < len(required):
                skip_actor_value = True
                continue
            tail.append(value)
        prefix_ok = (
            len(argv) == 7 + len(tail)
            and executable == expected_python
            and argv[1:3] == ["-I", "-S"]
            and memoryctl == expected_memoryctl
            and argv[4:7] == ["--actor", actor, command_name]
            and argv[7:] == tail
        )
    else:
        try:
            target = Path(os.path.abspath(str(Path(argv[1].strip('"')).expanduser())))
        except (IndexError, OSError, ValueError):
            return False
        prefix_ok = executable == expected_python and target == Path(os.path.abspath(str(script)))
    return (
        prefix_ok
        and all(value in argv for value in required)
        and all(value not in argv for value in forbidden)
    )


def _agent_memory_managed_hook_route(entry: dict[str, Any], *, command_name: str) -> bool:
    if str(entry.get("type", "")).casefold() != "command":
        return False
    try:
        argv = shlex.split(str(entry.get("command", "")), posix=os.name != "nt")
    except ValueError:
        return False
    names = [Path(item.strip('"')).name.casefold() for item in argv]
    legacy_name = (
        "agent_memory_session_hook.py" if command_name == "session-hook" else "agent_memory_stop_hook.py"
    )
    if legacy_name in names:
        return True
    if command_name == "stop-hook" and "stop-hook.ps1" in names:
        return True
    return any(
        name == "memoryctl" and command_name in argv[index + 1 :]
        for index, name in enumerate(names)
    )


def _single_exact_managed_hook(
    entries: list[dict[str, Any]],
    *,
    command_name: str,
    matches: Any,
) -> bool:
    managed = [
        entry
        for entry in entries
        if _agent_memory_managed_hook_route(entry, command_name=command_name)
    ]
    return len(managed) == 1 and bool(matches(managed[0]))


def _event_entries(payload: dict[str, Any], event: str) -> list[dict[str, Any]]:
    hooks = payload.get("hooks")
    groups = hooks.get(event, []) if isinstance(hooks, dict) else []
    if not isinstance(groups, list):
        return []
    entries: list[dict[str, Any]] = []
    for group in groups:
        candidates = group.get("hooks", []) if isinstance(group, dict) else []
        if isinstance(candidates, list):
            entries.extend(item for item in candidates if isinstance(item, dict))
    return entries


def _canonical_required_hosts(required_hosts: tuple[str, ...]) -> tuple[str, ...]:
    """Return the stable host-policy representation written to readiness."""

    if any(host not in {"codex", "claude"} for host in required_hosts):
        raise ValueError("HOST_HOOK_POLICY_INVALID")
    return tuple(sorted(set(required_hosts)))


def _host_hook_health(*, no_host_hooks: bool, required_hosts: tuple[str, ...], runtime_python: Path) -> dict[str, Any]:
    required_hosts = _canonical_required_hosts(required_hosts)
    if no_host_hooks == bool(required_hosts):
        raise ValueError("HOST_HOOK_POLICY_REQUIRED")
    if no_host_hooks:
        return {"policy": "explicitly_disabled", "verified": True}
    result: dict[str, Any] = {"policy": "required", "verified": True, "hosts": list(required_hosts)}
    if "codex" in required_hosts:
        hooks = Path.home() / ".codex" / "hooks.json"
        if hooks.is_symlink() or not hooks.is_file():
            raise ValueError("CODEX_HOOKS_MISSING")
        codex_text = hooks.read_text(encoding="utf-8-sig")
        codex_payload = json.loads(codex_text)
        codex_health = classify_hook_event(
            codex_payload.get("hooks", {}) if isinstance(codex_payload, dict) else {},
            "Stop",
            runtime_python=runtime_python,
            runtime_root=RUNTIME_ROOT,
            spec=codex_stop_hook_spec(),
        )
        if not isinstance(codex_payload, dict) or not codex_health["healthy"]:
            raise ValueError("CODEX_HOOKS_INVALID")
        codex_config = Path.home() / ".codex" / "config.toml"
        if codex_config.is_symlink() or not codex_config.is_file():
            raise ValueError("CODEX_HOOKS_DISABLED")
        features = _load_toml_text(codex_config.read_text(encoding="utf-8")).get("features")
        if not isinstance(features, dict) or features.get("hooks") is not True:
            raise ValueError("CODEX_HOOKS_DISABLED")
        result["codex"] = {
            "hooks_sha256": _sha256_file(hooks),
            "config_sha256": _sha256_file(codex_config),
            # Only this managed setting is part of the readiness contract.
            # The full digest remains diagnostic provenance; Codex legitimately
            # rewrites unrelated model, effort, and service-tier settings.
            "config_hooks_enabled": True,
            "classification": codex_health,
        }
    if "claude" in required_hosts:
        settings = Path.home() / ".claude" / "settings.json"
        if settings.is_symlink() or not settings.is_file():
            raise ValueError("CLAUDE_HOOKS_MISSING")
        claude_text = settings.read_text(encoding="utf-8-sig")
        claude_payload = json.loads(claude_text)
        if not isinstance(claude_payload, dict):
            raise ValueError("CLAUDE_HOOKS_INVALID")
        claude_specs = claude_hook_specs()
        claude_health = {
            event: classify_hook_event(
                claude_payload.get("hooks", {}),
                event,
                runtime_python=runtime_python,
                runtime_root=RUNTIME_ROOT,
                spec=spec,
            )
            for event, spec in claude_specs.items()
        }
        if not all(item["healthy"] for item in claude_health.values()):
            raise ValueError("CLAUDE_HOOKS_INVALID")
        result["claude"] = {
            "settings_sha256": _sha256_file(settings),
            "classification": claude_health,
        }
    return result


def _publish_scheduler_health(
    config: dict[str, Any],
    *,
    require_live: bool = False,
) -> dict[str, Any]:
    if sys.platform != "darwin":
        return {"healthy": True, "skipped": True, "detail": "non_darwin"}
    home = Path(os.path.abspath(str(Path.home())))
    label = str(config.get("audit_launchagent_label", "")).strip()
    plist_raw = str(config.get("audit_launchagent", "")).strip()
    if not label or not plist_raw:
        raise ValueError("AUDIT_SCHEDULER_CONFIG_INVALID")
    # Keep the configured lexical path so the shared loader can reject a
    # symlink exactly as the installer does.
    plist_path = Path(os.path.abspath(str(expand_path(plist_raw))))
    spec = LaunchAgentSpec(
        label=label,
        plist_path=plist_path,
        runtime_root=RUNTIME_ROOT,
        runtime_python=Path(str(config["python"])),
        stdout_path=RUNTIME_ROOT / "logs" / "audit-launchd.out.log",
        stderr_path=RUNTIME_ROOT / "logs" / "audit-launchd.err.log",
        working_directory=home,
    )
    try:
        primary_classification = classify_launchagent_payload(
            load_launchagent_payload(plist_path),
            spec,
        )
    except ValueError as exc:
        raise ValueError("AUDIT_SCHEDULER_INVALID") from exc
    inventory = discover_all_audit_launchagents(spec)
    route_counts = {
        "canonical": int(inventory["canonical_count"]),
        "legacy": int(inventory["legacy_count"]),
        "ambiguous": int(inventory["ambiguous_count"]),
    }
    unique = bool(inventory["healthy"])
    structural_ok = primary_classification.kind == "canonical" and unique
    if not structural_ok:
        raise ValueError("AUDIT_SCHEDULER_INVALID")
    if not require_live:
        return {
            "healthy": True,
            "skipped": False,
            "structural_only": True,
            "classification": primary_classification.as_dict(),
            "route_counts": route_counts,
            "scheduler_inventory": inventory,
            "unique": True,
        }
    completed = subprocess.run(
        ["launchctl", "print", f"gui/{home.stat().st_uid}/{label}"],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=15,
        check=False,
    )
    health = audit_scheduler_health(
        spec,
        print_returncode=completed.returncode,
        print_stdout=completed.stdout,
        success_report_path=RUNTIME_ROOT / "reports" / "latest-audit.json",
    )
    result = {
        **health,
        "skipped": False,
        "structural_only": False,
        "route_counts": route_counts,
        "scheduler_inventory": inventory,
        "unique": True,
    }
    if not health.get("healthy"):
        raise ValueError("AUDIT_SCHEDULER_INVALID")
    return result


def _publish_runtime_ready(*, attestation: dict[str, Any]) -> dict[str, Any]:
    marker = _runtime_json_object(
        Path("config/runtime-transition.json"),
        "RUNTIME_TRANSITION_MARKER_INVALID",
    )
    bundle = str(attestation.get("bundle_sha256", ""))
    if (
        marker.get("phase") != "preflight"
        or marker.get("bundle_sha256") != bundle
        or marker.get("install_id") != attestation.get("install_id")
        or marker.get("runtime_anchor_sha256") != attestation.get("runtime_anchor_sha256")
    ):
        raise ValueError("RUNTIME_PREFLIGHT_ATTESTATION_MISSING")
    ready_payload = {
        key: value
        for key, value in marker.items()
        if not str(key).startswith("capability_")
    }
    ready_payload.update({
        "phase": "ready",
        "state_schema_version": STATE_SCHEMA_VERSION,
        "writer_protocol_version": WRITER_PROTOCOL_VERSION,
        "verified_at": utc_now(),
        "preflight_attestation": attestation,
    })
    _atomic_transition(ready_payload)
    return {
        "ok": True,
        "ready": True,
        "changed": True,
        "phase": "ready",
        "bundle_sha256": bundle,
    }


def publish_ready_preflight(*, no_host_hooks: bool, required_hosts: tuple[str, ...]) -> dict[str, Any]:
    initial_manifest = _runtime_manifest_health()
    initial_config = _runtime_config_health()
    audit = verify_audit()
    if not audit["ok"]:
        return audit
    with contextlib.closing(connect(read_only=True)) as conn:
        state = verify(conn, publish_ready=False)
    if not state["ok"]:
        return state
    token, _capability = _issue_preflight_capability(initial_manifest)
    runtime_python = str(Path(initial_config["python"]))
    commands = [
        _run_preflight_command(
            _isolated_runtime_script(runtime_python, RUNTIME_ROOT / "scripts" / "agent_memory_evolution.py", "--init", "--scan", "--report"),
            token=token,
        ),
        _run_preflight_command(
            _isolated_runtime_script(runtime_python, RUNTIME_ROOT / "scripts" / "agent_memory_index.py", "--init", "--scan", "--report"),
            token=token,
        ),
    ]
    semantic_mode = str(initial_config.get("semantic_mode", "auto"))
    if not bool(initial_config.get("semantic_enabled")) or semantic_mode == "off":
        commands.append(
            {
                "command": "agent_memory_zvec_index.py",
                "returncode": 0,
                "payload": {"ok": True, "status": "semantic_disabled"},
                "skipped": True,
                "detail": "semantic_disabled",
            }
        )
    else:
        try:
            commands.append(
                _run_preflight_command(
                    _isolated_runtime_script(
                        runtime_python,
                        RUNTIME_ROOT / "scripts" / "agent_memory_zvec_index.py",
                        "--init",
                        "--scan",
                        "--prune",
                        "--json",
                        load_site_packages=True,
                    ),
                    token=token,
                    expect_json=True,
                )
            )
        except ValueError:
            if semantic_mode == "required":
                raise
            commands.append(
                {
                    "command": "agent_memory_zvec_index.py",
                    "returncode": 1,
                    "payload": {"ok": False, "status": "semantic_degraded"},
                    "skipped": False,
                    "detail": "semantic_degraded",
                }
            )
    check_command = _run_preflight_command(
            _isolated_runtime_script(runtime_python, RUNTIME_ROOT / "scripts" / "agent_memory_check.py", "--json"),
            token=token,
            expect_json=True,
        )
    doctor_command = _run_preflight_command(
            _isolated_runtime_script(runtime_python, RUNTIME_ROOT / "scripts" / "agent_memory_doctor.py", "--json"),
            token=token,
            expect_json=True,
            accepted_returncodes=(0, 2),
            doctor_process_contract=True,
        )
    commands.extend([check_command, doctor_command])
    if check_command["payload"].get("ok") is not True:
        raise ValueError("PREFLIGHT_CHECK_FAILED")
    content_debt = _validate_preflight_doctor_payload(doctor_command["payload"])
    final_manifest = _runtime_manifest_health()
    final_config = _runtime_config_health()
    if final_manifest["manifest_sha256"] != initial_manifest["manifest_sha256"]:
        raise ValueError("RUNTIME_MANIFEST_CHANGED_DURING_PREFLIGHT")
    if final_config["sha256"] != initial_config["sha256"]:
        raise ValueError("RUNTIME_CONFIG_CHANGED_DURING_PREFLIGHT")
    hooks = _host_hook_health(
        no_host_hooks=no_host_hooks,
        required_hosts=required_hosts,
        runtime_python=Path(final_config["python"]),
    )
    scheduler = _publish_scheduler_health(final_config)
    with contextlib.closing(connect(read_only=True)) as conn:
        before_data_version = int(conn.execute("PRAGMA data_version").fetchone()[0])
        final_state = verify(conn, publish_ready=False)
        if not final_state["ok"]:
            return final_state
        index = _index_health(conn, Path(final_config["memory_root"]))
        if int(conn.execute("PRAGMA data_version").fetchone()[0]) != before_data_version:
            raise ValueError("STATE_CHANGED_DURING_PREFLIGHT")
        # Re-hash the immutable runtime and config once more immediately before
        # atomically publishing ready while this connection and maintenance lock
        # remain held.
        terminal_manifest = _runtime_manifest_health()
        terminal_config = _runtime_config_health()
        if terminal_manifest["manifest_sha256"] != final_manifest["manifest_sha256"]:
            raise ValueError("RUNTIME_MANIFEST_CHANGED_DURING_PREFLIGHT")
        if terminal_config["sha256"] != final_config["sha256"]:
            raise ValueError("RUNTIME_CONFIG_CHANGED_DURING_PREFLIGHT")
        terminal_hooks = _host_hook_health(
            no_host_hooks=no_host_hooks,
            required_hosts=required_hosts,
            runtime_python=Path(terminal_config["python"]),
        )
        if terminal_hooks != hooks:
            raise ValueError("HOST_HOOKS_CHANGED_DURING_PREFLIGHT")
        terminal_scheduler = _publish_scheduler_health(terminal_config)
        if terminal_scheduler != scheduler:
            raise ValueError("AUDIT_SCHEDULER_CHANGED_DURING_PREFLIGHT")
        # This is the terminal fact-source gate. Editors do not honor the
        # maintenance lock, so repeat the full Markdown<->SQLite/FTS hash scan,
        # quick_check, and data_version immediately before marker publication.
        terminal_index = _index_health(conn, Path(terminal_config["memory_root"]))
        if terminal_index != index:
            raise ValueError("DERIVED_INDEX_CHANGED_DURING_PREFLIGHT")
        terminal_quick_check = str(conn.execute("PRAGMA quick_check").fetchone()[0])
        terminal_data_version = int(conn.execute("PRAGMA data_version").fetchone()[0])
        if terminal_quick_check != "ok" or terminal_data_version != before_data_version:
            raise ValueError("STATE_CHANGED_DURING_PREFLIGHT")
        attestation = {
            "schema_version": 1,
            "bundle_sha256": terminal_manifest["bundle_sha256"],
            "install_id": terminal_manifest["install_id"],
            "runtime_anchor_sha256": terminal_manifest["runtime_anchor_sha256"],
            "manifest_sha256": terminal_manifest["manifest_sha256"],
            "runtime_files_verified": terminal_manifest["files_verified"],
            "config_sha256": terminal_config["sha256"],
            "memory_root": terminal_config["memory_root"],
            "git_root": terminal_config["git_root"],
            "state_db": str(STATE_DB),
            "audit_db": str(AUDIT_DB),
            "audit_schema_version": audit_schema.AUDIT_SCHEMA_VERSION,
            "config_root": terminal_config["config_root"],
            "runtime_python": terminal_config["runtime_python"],
            "state_data_version": terminal_data_version,
            "quick_check": terminal_quick_check,
            "index": terminal_index,
            "host_hooks": terminal_hooks,
            "audit_scheduler": terminal_scheduler,
            "check_status": check_command["payload"].get("status", "ok"),
            "doctor_status": doctor_command["payload"].get("status"),
            "content_migration_required": content_debt["content_migration_required"],
            "legacy_scope_documents": content_debt["legacy_scope_documents"],
            "safe_automatic_governance_documents": content_debt[
                "safe_automatic_governance_documents"
            ],
            "content_migration": content_debt["content_migration"],
            "verified_at": utc_now(),
        }
        _validate_content_migration_attestation(attestation)
        # Re-read the exact terminal inputs after attestation construction. A
        # drift here must leave the preflight marker closed rather than attest
        # a bundle/config/Python/index snapshot that is no longer current.
        publish_manifest = _runtime_manifest_health()
        publish_config = _runtime_config_health()
        publish_hooks = _host_hook_health(
            no_host_hooks=no_host_hooks,
            required_hosts=required_hosts,
            runtime_python=Path(publish_config["python"]),
        )
        publish_index = _index_health(conn, Path(publish_config["memory_root"]))
        publish_scheduler = _publish_scheduler_health(publish_config)
        publish_quick_check = str(conn.execute("PRAGMA quick_check").fetchone()[0])
        publish_data_version = int(conn.execute("PRAGMA data_version").fetchone()[0])
        if (
            publish_manifest["manifest_sha256"] != terminal_manifest["manifest_sha256"]
            or publish_config["sha256"] != terminal_config["sha256"]
            or publish_config["runtime_python"] != terminal_config["runtime_python"]
            or publish_hooks != terminal_hooks
            or publish_scheduler != terminal_scheduler
            or publish_index != terminal_index
            or publish_quick_check != terminal_quick_check
            or publish_data_version != terminal_data_version
        ):
            raise ValueError("PREFLIGHT_TERMINAL_INPUT_DRIFT")
        transition = _publish_runtime_ready(attestation=attestation)
    return {**final_state, "runtime_transition": transition, "preflight_attestation": attestation}


def verify(conn: sqlite3.Connection, *, publish_ready: bool = False) -> dict[str, Any]:
    report = inspect(conn)
    schema_ok = report["state_schema_version"] == STATE_SCHEMA_VERSION
    columns_ok = not any(
        report[key]
        for key in (
            "missing_claim_columns",
            "missing_intent_columns",
            "missing_receipt_columns",
            "missing_observation_columns",
            "missing_incident_columns",
            "missing_observability_columns",
            "missing_privacy_guards",
        )
    )
    ledger_ok = not report["blockers"] and not report["terminal_intent_active_claims"]
    integrity = str(conn.execute("PRAGMA quick_check").fetchone()[0])
    ok = schema_ok and columns_ok and ledger_ok and integrity == "ok"
    transition: dict[str, Any] = {"ok": True, "ready": False, "changed": False, "phase": "not_published"}
    if publish_ready:
        # Publishing requires the locked runtime/config/index/Doctor/Hook
        # preflight. A caller holding only a state connection cannot satisfy it.
        transition = {
            "ok": False,
            "ready": False,
            "changed": False,
            "phase": "publish_failed",
            "reason_code": "STRONG_PREFLIGHT_REQUIRED",
        }
        ok = False
    migration_required = not schema_ok or not columns_ok
    return {
        "ok": ok,
        "status": "verified" if ok else ("migration_required" if migration_required else "invalid"),
        "reason_code": "" if not migration_required else "STATE_SCHEMA_MIGRATION_REQUIRED",
        "stage": "verify",
        "state_schema_required": STATE_SCHEMA_VERSION,
        "writer_protocol_version": WRITER_PROTOCOL_VERSION,
        "quick_check": integrity,
        "runtime_transition": transition,
        "report": report,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Agent Memory v2 state migration")
    parser.add_argument(
        "action",
        choices=(
            "plan", "init", "apply", "verify", "config-plan", "config-apply",
            "disposition-verify", "audit-plan", "audit-init", "audit-apply",
            "audit-verify", "generated-index-migrate", "committed-recovery-plan", "committed-recovery-verify",
        ),
    )
    parser.add_argument("--backup-path", default="")
    parser.add_argument("--committed-recovery-file", default="")
    parser.add_argument(
        "--disposition-file",
        default="",
        help="Exact plan-generated claim disposition JSON; apply only, never accepted by ordinary claim commands.",
    )
    parser.add_argument(
        "--publish-ready",
        action="store_true",
        help="With verify only, publish the managed runtime ready marker after verification.",
    )
    hooks = parser.add_mutually_exclusive_group()
    hooks.add_argument(
        "--require-host-hooks",
        action="store_true",
        help="Require and attest both Codex and Claude lifecycle hooks.",
    )
    hooks.add_argument(
        "--require-host-hook",
        action="append",
        choices=("codex", "claude"),
        default=[],
        help="Require one host's structured lifecycle hook; repeat for both.",
    )
    hooks.add_argument(
        "--no-host-hooks",
        action="store_true",
        help="Explicitly attest that this installation intentionally has no host hooks.",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.publish_ready and args.action != "verify":
            raise ValueError("PUBLISH_READY_REQUIRES_VERIFY")
        if args.committed_recovery_file and args.action not in {"apply", "committed-recovery-verify"}:
            raise ValueError("COMMITTED_RECOVERY_REQUIRES_BACKED_UP_MIGRATION")
        if (args.no_host_hooks or args.require_host_hooks or args.require_host_hook) and not (
            args.action == "verify" and args.publish_ready
        ):
            raise ValueError("HOST_HOOK_POLICY_REQUIRES_PUBLISH_READY")
        if args.action == "committed-recovery-verify":
            if not args.committed_recovery_file:
                raise ValueError("COMMITTED_RECOVERY_FILE_REQUIRED")
            with contextlib.closing(connect(read_only=True)) as conn:
                payload = preview_committed_recovery(conn, load_committed_recovery_document(
                    Path(args.committed_recovery_file),
                ))
        elif args.action == "committed-recovery-plan":
            with contextlib.closing(connect(read_only=True)) as conn:
                payload = committed_recovery_plan(conn)
        elif args.action == "audit-plan":
            if args.backup_path:
                raise ValueError("BACKUP_NOT_APPLICABLE")
            payload = audit_migration_plan()
        elif args.action == "audit-init":
            if args.backup_path:
                raise ValueError("BACKUP_NOT_APPLICABLE")
            with migration_lock():
                payload = initialize_audit()
        elif args.action == "audit-apply":
            if not args.backup_path:
                raise ValueError("BACKUP_PATH_REQUIRED")
            with migration_lock():
                payload = apply_audit_migration(backup_path=Path(args.backup_path))
        elif args.action == "audit-verify":
            if args.backup_path:
                raise ValueError("BACKUP_NOT_APPLICABLE")
            payload = verify_audit()
        elif args.action == "init":
            if args.backup_path:
                raise ValueError("BACKUP_NOT_APPLICABLE")
            with migration_lock():
                payload = initialize_state()
        elif args.action == "apply":
            if not args.backup_path:
                raise ValueError("BACKUP_PATH_REQUIRED")
            with migration_lock():
                disposition_document = (
                    _load_disposition_document(Path(args.disposition_file))
                    if args.disposition_file
                    else None
                )
                with contextlib.closing(connect(read_only=False)) as conn:
                    payload = apply_migration(
                        conn,
                        backup_path=Path(args.backup_path),
                        disposition_document=disposition_document,
                        committed_recovery_document=(
                            load_committed_recovery_document(Path(args.committed_recovery_file))
                            if args.committed_recovery_file else None
                        ),
                    )
        elif args.action == "config-plan":
            planned_root_raw = os.environ.get("AGENT_MEMORY_MIGRATION_RUNTIME_ROOT", "").strip()
            report = config_migration_plan(
                planned_runtime_root=absolute_path(planned_root_raw) if planned_root_raw else None,
            )
            report.pop("_migrated_text", None)
            payload = report
        elif args.action == "config-apply":
            with migration_lock():
                payload = apply_config_migration(
                    backup_path=Path(args.backup_path) if args.backup_path else None,
                )
        elif args.action == "generated-index-migrate":
            if args.backup_path or args.disposition_file:
                raise ValueError("BACKUP_NOT_APPLICABLE")
            with migration_lock():
                payload = migrate_generated_index()
        elif args.action == "disposition-verify":
            disposition_document = (
                _load_disposition_document(Path(args.disposition_file))
                if args.disposition_file
                else None
            )
            with contextlib.closing(connect(read_only=True)) as conn:
                payload = preview_dispositions(conn, disposition_document)
        elif args.action == "verify" and args.publish_ready:
            # The publication function owns the entire maintenance interval,
            # including its short-lived child capability and final rechecks.
            with migration_lock():
                payload = publish_ready_preflight(
                    no_host_hooks=args.no_host_hooks,
                    required_hosts=_canonical_required_hosts(tuple(
                        ("codex", "claude")
                        if args.require_host_hooks
                        else args.require_host_hook
                    )),
                )
        else:
            with contextlib.closing(connect(read_only=True)) as conn:
                report = inspect(conn) if args.action == "plan" else verify(conn, publish_ready=False)
            payload = (
                {
                    "ok": not report["blockers"],
                    "status": "ready" if not report["blockers"] else "blocked",
                    "stage": "plan",
                    "plan": report,
                }
                if args.action == "plan"
                else report
            )
    except (OSError, sqlite3.Error, ValueError, TimeoutError, StateSecurityError, intent.IntentError) as exc:
        safe_reason = str(getattr(exc, "reason_code", "") or str(exc) or type(exc).__name__).upper()
        payload = {
            "ok": False,
            "status": "error",
            "stage": args.action,
            "reason_code": safe_reason,
        }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"migration={payload.get('status')} stage={args.action}")
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
