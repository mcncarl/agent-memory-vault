#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import sys
import unicodedata
import uuid
from pathlib import Path
from typing import Any, Iterable, Sequence

from agent_memory_env import RuntimeTransitionError, assert_runtime_ready, env_value, expand_path
from agent_memory_state import (
    OBSERVABILITY_SCHEMA_VERSION,
    OBSERVABILITY_ACTOR_VALUES,
    OBSERVABILITY_CONFIDENCE_VALUES,
    OBSERVABILITY_EVENT_SOURCES,
    OBSERVABILITY_EVENT_VALUES,
    OBSERVABILITY_MEMORY_VERSION_STATES,
    OBSERVABILITY_READ_MODE_VALUES,
    OBSERVABILITY_REASON_VALUES,
    OBSERVABILITY_TASK_CLASS_VALUES,
    SEARCH_LOG_CANONICAL_SOURCES,
    SEARCH_LOG_SOURCE_VALUES,
    SEARCH_LOG_STATUS_VALUES,
    ensure_observability_v2_schema,
    secure_sqlite_connect,
)


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
CONFIG_ROOT = expand_path(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory")).resolve()
STATE_DB = expand_path(env_value("STATE_DB", str(CONFIG_ROOT / "state.sqlite"))).resolve()
RUNTIME_MANIFEST = CONFIG_ROOT / "config" / "runtime-manifest.json"

SCHEMA_VERSION = str(OBSERVABILITY_SCHEMA_VERSION)
SOURCES = {"tool_observed", "agent_declared", "human_declared", "independent_model"}
# State owns the database-enforced enum definitions.  Export the historical
# observability names for callers while keeping application and trigger policy
# on one source of truth.
EVENT_VALUES = {key: set(values) for key, values in OBSERVABILITY_EVENT_VALUES.items()}
EVENT_SOURCES = {key: set(values) for key, values in OBSERVABILITY_EVENT_SOURCES.items()}
REASON_CODES = set(OBSERVABILITY_REASON_VALUES)
CONFIDENCE_VALUES = set(OBSERVABILITY_CONFIDENCE_VALUES)
READ_MODES = set(OBSERVABILITY_READ_MODE_VALUES)
TASK_CLASSES = set(OBSERVABILITY_TASK_CLASS_VALUES)
MEMORY_VERSION_STATES = set(OBSERVABILITY_MEMORY_VERSION_STATES)
ACTOR_VALUES = set(OBSERVABILITY_ACTOR_VALUES)
MAINTENANCE_ACTORS = frozenset({"migration", "test"})
RANKING_MODES = {"legacy_v1", "shadow", "hybrid_v2"}
WORKER_STATUSES = {"not_used", "reused", "started", "restarted", "degraded", "failed"}
SEARCH_SOURCES = set(SEARCH_LOG_SOURCE_VALUES) | {"none"}
SEARCH_STATUSES = set(SEARCH_LOG_STATUS_VALUES) - {"legacy_unknown"}
EVENT_TYPE_ALIASES = {
    "search": "search_completed",
    "opened_original": "source_opened",
    "opened_original_declared": "source_opened_declared",
    "adoption": "adoption_declared",
    "outcome": "task_completed",
}
_SYNTHETIC_BENCHMARK_CAPABILITY = object()


class ObservabilityLedgerUnavailable(RuntimeError):
    """Stable fail-closed signal for a missing or unreadable use ledger."""


def canonical_event_type(value: object) -> str:
    normalized = str(value or "")
    return EVENT_TYPE_ALIASES.get(normalized, normalized)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def observability_enabled() -> bool:
    return env_value("OBSERVABILITY_ENABLED", "false").strip().casefold() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _purpose_hash(purpose: str, value: str) -> str:
    if not value:
        return ""
    payload = f"agent-memory-{purpose}\0{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def task_ref(raw_task_id: str, actor: str) -> str:
    return _purpose_hash("task-v1", f"{actor}\0{raw_task_id.strip()}") if raw_task_id.strip() else ""


def memory_ref(rel_path: str) -> str:
    normalized = unicodedata.normalize("NFKC", rel_path.replace("\\", "/").strip())
    return _purpose_hash("memory-ref-v1", normalized) if normalized else ""


def current_raw_task_id(actor: str) -> str:
    explicit = os.environ.get("AGENT_MEMORY_TASK_ID", "").strip()
    if explicit:
        return explicit
    keys = {
        "codex": ("AGENT_MEMORY_SESSION_ID", "CODEX_THREAD_ID"),
        "claude": ("AGENT_MEMORY_SESSION_ID", "CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID"),
    }.get(actor, ("AGENT_MEMORY_SESSION_ID",))
    for key in keys:
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return ""


def current_task_ref(actor: str) -> str:
    return task_ref(current_raw_task_id(actor), actor)


def runtime_version() -> str:
    try:
        payload = json.loads(RUNTIME_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "unmanaged"
    if not isinstance(payload, dict):
        return "unmanaged"
    version = str(payload.get("source_commit") or "unmanaged")
    return f"{version}+dirty" if payload.get("source_dirty") else version


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
    columns = {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Apply an additive, idempotent observability migration."""

    base_tables = {
        str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    if not {"meta", "memory_search_log"}.issubset(base_tables):
        raise sqlite3.OperationalError("observability_requires_initialized_memory_index")
    ensure_observability_v2_schema(conn)


def assert_schema_ready(conn: sqlite3.Connection) -> None:
    """Read-only schema gate used by all ordinary observation commands."""

    tables = {
        str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    required_search_columns = {
        "search_id",
        "query_sha256",
        "returned_memory_ids_json",
        "ranking_mode",
        "worker_status",
        "worker_restart_count",
        "metadata_gate_mode",
        "metadata_would_block_count",
        "metadata_reason_fingerprint",
    }
    required_event_columns = {
        "event_id",
        "actor",
        "task_id",
        "event_type",
        "memory_versions_json",
        "content_sha256",
        "requires_live_verification",
    }
    search_columns = (
        {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_search_log)")}
        if "memory_search_log" in tables
        else set()
    )
    event_columns = (
        {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_use_events)")}
        if "memory_use_events" in tables
        else set()
    )
    version = None
    if "meta" in tables:
        version = conn.execute(
            "SELECT value FROM meta WHERE key='memory_observability_schema_version'"
        ).fetchone()
    if (
        not {"meta", "memory_search_log", "memory_use_events"}.issubset(tables)
        or not required_search_columns.issubset(search_columns)
        or not required_event_columns.issubset(event_columns)
        or version is None
        or str(version[0]) != SCHEMA_VERSION
    ):
        raise sqlite3.OperationalError("STATE_SCHEMA_MIGRATION_REQUIRED")


def connect(*, timeout: float = 0.1, read_only: bool = False) -> sqlite3.Connection:
    assert_runtime_ready("observe")
    pragmas = ("PRAGMA busy_timeout=100",) if read_only else (
        "PRAGMA journal_mode=WAL",
        "PRAGMA busy_timeout=100",
    )
    return secure_sqlite_connect(
        STATE_DB,
        timeout=timeout,
        create=False,
        read_only=read_only,
        pragmas=pragmas,
        row_factory=sqlite3.Row,
    )


def _validate_event(event_type: str, source: str, value: str, reason_code: str, confidence: str) -> None:
    if event_type not in EVENT_VALUES:
        raise ValueError(f"unsupported_event_type:{event_type}")
    if value not in EVENT_VALUES[event_type]:
        raise ValueError(f"unsupported_event_value:{event_type}:{value}")
    if source not in EVENT_SOURCES[event_type]:
        raise ValueError(f"unsupported_event_source:{event_type}:{source}")
    if reason_code not in REASON_CODES:
        raise ValueError(f"unsupported_reason_code:{reason_code}")
    if confidence not in CONFIDENCE_VALUES:
        raise ValueError(f"unsupported_confidence:{confidence}")


def _validate_actor(actor: object) -> str:
    normalized = str(actor or "").strip().casefold()
    if normalized not in ACTOR_VALUES:
        raise ValueError("unsupported_actor")
    return normalized


def _controlled_event_id(value: object) -> str:
    normalized = str(value or "")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{7,159}", normalized) is None:
        raise ValueError("event_id_invalid")
    return normalized


def _controlled_runtime_version(value: object) -> str:
    normalized = str(value or "")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,159}", normalized) is None:
        raise ValueError("runtime_version_invalid")
    return normalized


def _nonnegative_integer(value: int | None, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field}_invalid")
    return value


def _normalized_memory_ids(values: Iterable[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        item = value.strip().casefold()
        if len(item) != 64 or any(character not in "0123456789abcdef" for character in item):
            raise ValueError("memory_id_must_be_sha256")
        if item not in output:
            output.append(item)
        if len(output) > 512:
            raise ValueError("memory_id_limit_exceeded")
    return output


def _sha256_value(value: str, *, field: str, allow_empty: bool = True) -> str:
    normalized = str(value or "").strip().casefold()
    if not normalized and allow_empty:
        return ""
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise ValueError(f"{field}_must_be_sha256")
    return normalized


def _normalized_memory_versions(
    values: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw in values:
        if not isinstance(raw, dict):
            raise ValueError("memory_version_invalid")
        memory_id = _sha256_value(str(raw.get("memory_id", "")), field="memory_id", allow_empty=False)
        content_sha256 = _sha256_value(
            str(raw.get("content_sha256", "")),
            field="content_sha256",
            allow_empty=True,
        )
        policy_state = str(raw.get("policy_state", "unknown")).strip().casefold() or "unknown"
        if policy_state not in MEMORY_VERSION_STATES:
            raise ValueError(f"memory_version_state_unsupported:{policy_state}")
        requires = bool(raw.get("requires_live_verification", False))
        identity = (memory_id, content_sha256)
        if identity in seen:
            continue
        seen.add(identity)
        output.append(
            {
                "memory_id": memory_id,
                "content_sha256": content_sha256,
                "policy_state": policy_state,
                "requires_live_verification": requires,
            }
        )
        if len(output) > 512:
            raise ValueError("memory_version_limit_exceeded")
    return output


def memory_version(
    rel_path: str,
    content_sha256: str,
    *,
    memory_id: str = "",
    explicit_memory_id: str = "",
    policy_state: str = "unknown",
    requires_live_verification: bool = False,
) -> dict[str, Any]:
    """Build a version-bound event reference without exposing a local path."""

    if memory_id and explicit_memory_id and memory_id != explicit_memory_id:
        raise ValueError("memory_id_conflict")
    stable_id = memory_id or explicit_memory_id
    return _normalized_memory_versions(
        [
            {
                "memory_id": (
                    _sha256_value(
                        stable_id,
                        field="explicit_memory_id",
                        allow_empty=False,
                    )
                    if stable_id
                    else memory_ref(rel_path)
                ),
                "content_sha256": content_sha256,
                "policy_state": policy_state,
                "requires_live_verification": requires_live_verification,
            }
        ]
    )[0]


def _insert_event(
    conn: sqlite3.Connection,
    *,
    actor: str,
    task_id: str,
    event_type: str,
    source: str,
    value: str,
    memory_ids: Sequence[str] = (),
    memory_versions: Sequence[dict[str, Any]] = (),
    content_sha256: str = "",
    reason_code: str = "",
    confidence: str = "",
    labeler_ref: str = "",
    read_mode: str = "",
    result_count: int | None = None,
    required_live_verification_count: int | None = None,
    full_utf8_bytes: int | None = None,
    returned_utf8_bytes: int | None = None,
    truncated: bool | None = None,
    page_count: int | None = None,
    task_class: str = "",
    event_id: str = "",
) -> str:
    actor = _validate_actor(actor)
    event_type = str(event_type or "").strip()
    source = str(source or "").strip()
    value = str(value or "").strip()
    reason_code = str(reason_code or "").strip()
    confidence = str(confidence or "").strip()
    _validate_event(event_type, source, value, reason_code, confidence)
    task_id = _sha256_value(task_id, field="task_id", allow_empty=False)
    if read_mode not in READ_MODES:
        raise ValueError(f"unsupported_read_mode:{read_mode}")
    if task_class not in TASK_CLASSES:
        raise ValueError(f"unsupported_task_class:{task_class}")
    normalized_versions = _normalized_memory_versions(memory_versions)
    normalized_ids = _normalized_memory_ids(
        [*memory_ids, *(str(item["memory_id"]) for item in normalized_versions)]
    )
    normalized_content = _sha256_value(content_sha256, field="content_sha256")
    if not normalized_content and len(normalized_versions) == 1:
        normalized_content = str(normalized_versions[0]["content_sha256"])
    if event_type in {
        "adoption",
        "adoption_declared",
        "opened_original",
        "source_opened",
        "opened_original_declared",
    } and not normalized_ids:
        raise ValueError(f"memory_id_required:{event_type}")
    canonical_type = canonical_event_type(event_type)
    exact_version_required = canonical_type == "live_verified" or event_type == "source_opened" or (
        canonical_type == "adoption_declared" and value == "adopted"
    )
    if exact_version_required:
        if not normalized_versions or any(not str(item["content_sha256"]) for item in normalized_versions):
            raise ValueError(f"content_sha256_required:{canonical_type}")
    if normalized_content and not any(
        str(item["content_sha256"]) == normalized_content for item in normalized_versions
    ):
        raise ValueError("content_sha256_version_mismatch")
    result_count = _nonnegative_integer(result_count, field="result_count")
    required_live_verification_count = _nonnegative_integer(
        required_live_verification_count,
        field="required_live_verification_count",
    )
    full_utf8_bytes = _nonnegative_integer(full_utf8_bytes, field="full_utf8_bytes")
    returned_utf8_bytes = _nonnegative_integer(returned_utf8_bytes, field="returned_utf8_bytes")
    page_count = _nonnegative_integer(page_count, field="page_count")
    if truncated is not None and not isinstance(truncated, bool):
        raise ValueError("truncated_invalid")
    if len(labeler_ref) > 65535:
        raise ValueError("labeler_ref_too_long")
    labeler_digest = hashlib.sha256(labeler_ref.encode("utf-8")).hexdigest() if labeler_ref else ""
    identifier = _controlled_event_id(event_id or str(uuid.uuid4()))
    version = _controlled_runtime_version(runtime_version())
    conn.execute(
        """
        INSERT OR IGNORE INTO memory_use_events(
          event_id, actor, task_id, runtime_version, event_type, source,
          memory_ids_json, memory_versions_json, content_sha256,
          value, reason_code, confidence,
          labeler_ref_sha256, labeler_ref_length, read_mode, result_count,
          required_live_verification_count, full_utf8_bytes, returned_utf8_bytes,
          truncated, page_count, task_class, requires_live_verification, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            identifier,
            actor,
            task_id,
            version,
            event_type,
            source,
            json.dumps(normalized_ids, ensure_ascii=True, separators=(",", ":")),
            json.dumps(normalized_versions, ensure_ascii=True, separators=(",", ":")),
            normalized_content,
            value,
            reason_code,
            confidence,
            labeler_digest,
            len(labeler_ref),
            read_mode,
            result_count,
            required_live_verification_count,
            full_utf8_bytes,
            returned_utf8_bytes,
            None if truncated is None else int(truncated),
            page_count,
            task_class,
            int(any(bool(item["requires_live_verification"]) for item in normalized_versions)),
            utc_now(),
        ),
    )
    return identifier


def _mark_enabled(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES (?, ?)",
        ("observability_enabled_at", utc_now()),
    )


def _ensure_task_seen_event(conn: sqlite3.Connection, *, actor: str, task_id: str) -> str:
    if not actor or not task_id:
        return ""
    identifier = "task-seen-" + _purpose_hash("event-v2", f"{actor}\0{task_id}")
    return _insert_event(
        conn,
        actor=actor,
        task_id=task_id,
        event_type="task_seen",
        source="tool_observed",
        value="seen",
        event_id=identifier,
    )


def record_task_seen(raw_task_id: str, actor: str) -> str:
    """Best-effort hook telemetry; never raises into a host lifecycle hook."""

    if not observability_enabled():
        return ""
    if not STATE_DB.is_file():
        return ""
    task_id = task_ref(raw_task_id, actor)
    if not task_id:
        return ""
    try:
        with connect() as conn:
            assert_schema_ready(conn)
            _mark_enabled(conn)
            return _ensure_task_seen_event(conn, actor=actor, task_id=task_id)
    except (OSError, sqlite3.Error, RuntimeTransitionError, ValueError):
        return ""


def record_search(
    conn: sqlite3.Connection,
    *,
    query: str,
    rel_paths: Sequence[str],
    memory_ids: Sequence[str] | None = None,
    sources: Sequence[str],
    duration_ms: int,
    search_status: str,
    required_live_verification_count: int = 0,
    ranking_mode: str = "legacy_v1",
    v1_result_fingerprint: str = "",
    v2_result_fingerprint: str = "",
    required_case_regression_count: int = 0,
    worker_status: str = "not_used",
    worker_restart_count: int = 0,
    metadata_gate_mode: str = "shadow",
    metadata_would_block_count: int = 0,
    metadata_reason_fingerprint: str = "",
    _synthetic_benchmark_capability: object | None = None,
) -> str:
    """Write the existing redacted search row and, when enabled, a task event."""

    assert_schema_ready(conn)
    if not isinstance(query, str):
        raise ValueError("query_must_be_text")
    normalized_source_values = [str(value).strip().casefold() for value in sources]
    if any(value not in SEARCH_SOURCES - {"none"} for value in normalized_source_values):
        raise ValueError("search_source_unsupported")
    canonical_sources = ",".join(sorted(set(normalized_source_values))) or "none"
    if canonical_sources not in SEARCH_LOG_CANONICAL_SOURCES:
        raise ValueError("search_sources_invalid")
    synthetic_benchmark = (
        _synthetic_benchmark_capability is _SYNTHETIC_BENCHMARK_CAPABILITY
    )
    if _synthetic_benchmark_capability is not None and not synthetic_benchmark:
        raise ValueError("synthetic_benchmark_capability_invalid")
    if synthetic_benchmark and canonical_sources != "hybrid_benchmark":
        raise ValueError("synthetic_benchmark_source_invalid")
    normalized_search_status = str(search_status).strip().casefold()
    if normalized_search_status not in SEARCH_STATUSES:
        raise ValueError(f"search_status_unsupported:{normalized_search_status}")
    normalized_ranking = str(ranking_mode).strip().casefold()
    if normalized_ranking not in RANKING_MODES:
        raise ValueError(f"ranking_mode_unsupported:{normalized_ranking}")
    normalized_worker = str(worker_status).strip().casefold()
    if normalized_worker not in WORKER_STATUSES:
        raise ValueError(f"worker_status_unsupported:{normalized_worker}")
    if isinstance(worker_restart_count, bool) or not isinstance(worker_restart_count, int):
        raise ValueError("worker_restart_count_invalid")
    if worker_restart_count not in {0, 1}:
        raise ValueError("worker_restart_count_invalid")
    normalized_gate_mode = str(metadata_gate_mode).strip().casefold()
    if normalized_gate_mode not in {"shadow", "enforce"}:
        raise ValueError(f"metadata_gate_mode_unsupported:{normalized_gate_mode}")
    gate_block_count = _nonnegative_integer(
        metadata_would_block_count,
        field="metadata_would_block_count",
    )
    assert gate_block_count is not None
    gate_reason_fingerprint = str(metadata_reason_fingerprint).strip().lower()
    if gate_block_count:
        if re.fullmatch(r"[0-9a-f]{64}", gate_reason_fingerprint) is None:
            raise ValueError("metadata_reason_fingerprint_required")
    elif gate_reason_fingerprint:
        raise ValueError("metadata_reason_fingerprint_without_block")
    v1_fingerprint = _sha256_value(v1_result_fingerprint, field="v1_result_fingerprint")
    v2_fingerprint = _sha256_value(v2_result_fingerprint, field="v2_result_fingerprint")
    regressions = _nonnegative_integer(
        required_case_regression_count,
        field="required_case_regression_count",
    )
    assert regressions is not None
    duration_ms = _nonnegative_integer(duration_ms, field="duration_ms")
    required_live_verification_count = _nonnegative_integer(
        required_live_verification_count,
        field="required_live_verification_count",
    )
    assert duration_ms is not None and required_live_verification_count is not None
    digest = hashlib.sha256(query.encode("utf-8")).hexdigest()
    supplied_ids = [str(value).strip().lower() for value in (memory_ids or [])]
    if supplied_ids and (
        len(supplied_ids) != len(rel_paths)
        or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in supplied_ids)
    ):
        raise ValueError("memory_ids_invalid")
    ids = supplied_ids or [memory_ref(path) for path in rel_paths]
    if len(ids) > 512:
        raise ValueError("returned_memory_id_limit_exceeded")
    if len(set(ids)) != len(ids):
        raise ValueError("returned_memory_ids_duplicate")
    ids = _normalized_memory_ids(ids)
    search_id = str(uuid.uuid4())
    enabled = observability_enabled()
    if synthetic_benchmark:
        # Quality benchmarks contribute privacy-safe ranking/Worker counters,
        # but are not user tasks and must not create disposition obligations.
        actor = "test"
        task_id = task_ref("retrieval-benchmark:" + search_id, actor)
    else:
        actor = os.environ.get("MEMORY_ACTOR", "").strip() if enabled else ""
        if actor:
            actor = _validate_actor(actor)
        task_id = current_task_ref(actor) if enabled and actor else ""
    version = runtime_version() if enabled else ""
    conn.execute(
        """
        INSERT INTO memory_search_log(
          query, result_count, used_paths, query_sha256, query_length,
          sources, duration_ms, created_at, search_id, actor, task_id,
          runtime_version, event_source, returned_memory_ids_json, search_status,
          ranking_mode, v1_result_fingerprint, v2_result_fingerprint,
          required_case_regression_count, worker_status, worker_restart_count,
          metadata_gate_mode, metadata_would_block_count,
          metadata_reason_fingerprint
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "",
            len(rel_paths),
            "",
            digest,
            len(query),
            canonical_sources,
            duration_ms,
            utc_now(),
            search_id,
            actor or None,
            task_id or None,
            version or None,
            "tool_observed" if task_id else None,
            json.dumps(ids, ensure_ascii=True, separators=(",", ":")),
            normalized_search_status,
            normalized_ranking,
            v1_fingerprint,
            v2_fingerprint,
            regressions,
            normalized_worker,
            worker_restart_count,
            normalized_gate_mode,
            gate_block_count,
            gate_reason_fingerprint,
        ),
    )
    if enabled and task_id and not synthetic_benchmark:
        _mark_enabled(conn)
        _ensure_task_seen_event(conn, actor=actor, task_id=task_id)
        _insert_event(
            conn,
            actor=actor,
            task_id=task_id,
            event_type="search_completed",
            source="tool_observed",
            value=normalized_search_status,
            memory_ids=ids,
            result_count=len(rel_paths),
            required_live_verification_count=required_live_verification_count,
            event_id="search-" + search_id,
        )
    return search_id


def record_benchmark_search(
    conn: sqlite3.Connection,
    *,
    query: str,
    rel_paths: Sequence[str],
    memory_ids: Sequence[str],
    duration_ms: int,
    search_status: str,
    v1_result_fingerprint: str,
    v2_result_fingerprint: str,
    required_case_regression_count: int,
    worker_status: str,
    worker_restart_count: int,
) -> str:
    """Record synthetic ranking evidence without entering the task ledger."""

    return record_search(
        conn,
        query=query,
        rel_paths=rel_paths,
        memory_ids=memory_ids,
        sources=("hybrid_benchmark",),
        duration_ms=duration_ms,
        search_status=search_status,
        ranking_mode="shadow",
        v1_result_fingerprint=v1_result_fingerprint,
        v2_result_fingerprint=v2_result_fingerprint,
        required_case_regression_count=required_case_regression_count,
        worker_status=worker_status,
        worker_restart_count=worker_restart_count,
        _synthetic_benchmark_capability=_SYNTHETIC_BENCHMARK_CAPABILITY,
    )


def record_opened_original(
    *,
    actor: str,
    rel_path: str,
    read_mode: str,
    full_utf8_bytes: int,
    returned_utf8_bytes: int,
    truncated: bool,
    page_count: int = 1,
    content_sha256: str = "",
    memory_id: str = "",
    explicit_memory_id: str = "",
    policy_state: str = "unknown",
    requires_live_verification: bool = False,
) -> str:
    """Best-effort objective read event for an explicitly observed retrieve."""

    if not observability_enabled():
        return ""
    if not STATE_DB.is_file():
        return ""
    task_id = current_task_ref(actor)
    if not task_id:
        return ""
    try:
        with connect() as conn:
            assert_schema_ready(conn)
            _mark_enabled(conn)
            _ensure_task_seen_event(conn, actor=actor, task_id=task_id)
            version = memory_version(
                rel_path,
                content_sha256,
                memory_id=memory_id,
                explicit_memory_id=explicit_memory_id,
                policy_state=policy_state,
                requires_live_verification=requires_live_verification,
            )
            return _insert_event(
                conn,
                actor=actor,
                task_id=task_id,
                event_type="source_opened",
                source="tool_observed",
                value="yes",
                memory_ids=[str(version["memory_id"])],
                memory_versions=[version],
                content_sha256=content_sha256,
                read_mode=read_mode,
                full_utf8_bytes=max(0, int(full_utf8_bytes)),
                returned_utf8_bytes=max(0, int(returned_utf8_bytes)),
                truncated=bool(truncated),
                page_count=max(1, int(page_count)),
            )
    except (OSError, sqlite3.Error, RuntimeTransitionError, ValueError):
        return ""


def record_source_opened_version(
    *,
    actor: str,
    task_id: str,
    memory_version: dict[str, Any],
    read_mode: str = "full",
) -> str:
    """Record the synthetic canary's objective opened-version projection.

    Production actors must use Canonical Retrieve, which calls
    record_opened_original after reading current bytes.  This narrow helper is
    intentionally restricted to the non-production ``test`` actor so the
    seven-day canary can exercise the same version-bound ledger chain without
    pretending that an Agent declaration was a tool observation.
    """

    if actor != "test":
        raise ValueError("synthetic_source_opened_requires_test_actor")
    if not re.fullmatch(r"[0-9a-f]{64}", str(task_id or "")):
        raise ValueError("task_id_required")
    normalized = _normalized_memory_versions([memory_version])
    with connect(timeout=1.0) as conn:
        assert_schema_ready(conn)
        _mark_enabled(conn)
        _ensure_task_seen_event(conn, actor=actor, task_id=task_id)
        return _insert_event(
            conn,
            actor=actor,
            task_id=task_id,
            event_type="source_opened",
            source="tool_observed",
            value="yes",
            memory_versions=normalized,
            memory_ids=[str(normalized[0]["memory_id"])],
            content_sha256=str(normalized[0]["content_sha256"]),
            read_mode=read_mode,
            full_utf8_bytes=0,
            returned_utf8_bytes=0,
            truncated=False,
            page_count=1,
        )


def record_declared_event(
    *,
    actor: str,
    task_id: str,
    event_type: str,
    source: str,
    value: str,
    memory_ids: Sequence[str] = (),
    memory_versions: Sequence[dict[str, Any]] = (),
    reason_code: str = "",
    confidence: str = "",
    labeler_ref: str = "",
    task_class: str = "",
) -> str:
    if source == "tool_observed":
        raise ValueError("tool_observed_cannot_be_declared")
    if source == "independent_model" and not labeler_ref.strip():
        raise ValueError("independent_model_labeler_ref_required")
    if not observability_enabled():
        raise RuntimeError("observability_disabled")
    if not STATE_DB.is_file():
        raise RuntimeError("observability_not_initialized")
    with connect(timeout=1.0) as conn:
        assert_schema_ready(conn)
        _mark_enabled(conn)
        if source in {"human_declared", "independent_model"}:
            exists = conn.execute(
                "SELECT 1 FROM memory_use_events WHERE actor=? AND task_id=? LIMIT 1",
                (actor, task_id),
            ).fetchone()
            if exists is None:
                raise ValueError("labeled_task_not_observed")
        else:
            _ensure_task_seen_event(conn, actor=actor, task_id=task_id)
        canonical_type = canonical_event_type(event_type)
        if canonical_type in {"adoption_declared", "live_verified"}:
            requested_versions = _normalized_memory_versions(memory_versions)
            supplied_ids = _normalized_memory_ids(memory_ids)
            supplied_version_ids = [str(item["memory_id"]) for item in requested_versions]
            if supplied_ids and supplied_version_ids and set(supplied_ids) != set(supplied_version_ids):
                raise ValueError("declared_memory_version_identity_mismatch")
            requires_objective_version = bool(
                value == "adopted" or canonical_type == "live_verified"
            )
            if requires_objective_version:
                if not requested_versions or any(
                    not str(item["content_sha256"]) for item in requested_versions
                ):
                    raise ValueError("declared_content_version_required")
                opened = _objective_opened_versions(conn, actor=actor, task_id=task_id)
                objective_versions: list[dict[str, Any]] = []
                for item in requested_versions:
                    key = (str(item["memory_id"]), str(item["content_sha256"]))
                    objective = opened.get(key)
                    if objective is None:
                        raise ValueError("declared_version_not_source_opened")
                    objective_versions.append(dict(objective))
                # The Agent may identify the version it used, but it may not
                # downgrade the objective temporal state observed by Canonical
                # Retrieve.  Persist the tool-derived projection instead.
                memory_versions = objective_versions
                memory_ids = [str(item["memory_id"]) for item in objective_versions]
            else:
                # A rejected/reference-only candidate need not be opened, but
                # it must be one of this task's objectively returned/opened
                # opaque IDs.  This lets the Agent disposition a search-only
                # candidate without inventing a content hash.  Exact versions,
                # when supplied, retain a fail-closed policy projection.
                candidate_ids = _objective_candidate_ids(
                    conn,
                    actor=actor,
                    task_id=task_id,
                )
                declared_ids = supplied_version_ids or supplied_ids
                if not declared_ids:
                    raise ValueError("declared_candidate_identity_required")
                if not set(declared_ids).issubset(candidate_ids):
                    raise ValueError("declared_candidate_not_observed")
                memory_versions = [
                    {
                        "memory_id": str(item["memory_id"]),
                        "content_sha256": str(item["content_sha256"]),
                        "policy_state": "unknown",
                        "requires_live_verification": True,
                    }
                    for item in requested_versions
                ]
                memory_ids = declared_ids
        return _insert_event(
            conn,
            actor=actor,
            task_id=task_id,
            event_type=event_type,
            source=source,
            value=value,
            memory_ids=memory_ids,
            memory_versions=memory_versions,
            reason_code=reason_code,
            confidence=confidence,
            labeler_ref=labeler_ref,
            task_class=task_class,
        )


def _objective_opened_versions(
    conn: sqlite3.Connection,
    *,
    actor: str,
    task_id: str,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Return latest exact content versions opened by the canonical tool."""

    rows = conn.execute(
        """
        SELECT memory_versions_json
        FROM memory_use_events
        WHERE actor=? AND task_id=?
          AND event_type IN ('source_opened', 'opened_original')
          AND source='tool_observed'
        ORDER BY id
        """,
        (actor, task_id),
    ).fetchall()
    opened: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        try:
            raw = json.loads(str(row["memory_versions_json"] or "[]"))
            versions = _normalized_memory_versions(raw if isinstance(raw, list) else [])
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        for item in versions:
            content_sha = str(item["content_sha256"])
            if not content_sha:
                continue
            key = (str(item["memory_id"]), content_sha)
            opened[key] = dict(item)
    return opened


def _objective_candidate_ids(
    conn: sqlite3.Connection,
    *,
    actor: str,
    task_id: str,
) -> set[str]:
    """Return opaque IDs objectively returned or opened in this task."""

    rows = conn.execute(
        """
        SELECT memory_ids_json, memory_versions_json
        FROM memory_use_events
        WHERE actor=? AND task_id=?
          AND event_type IN (
            'search', 'search_completed',
            'source_opened', 'opened_original'
          )
          AND source='tool_observed'
        ORDER BY id
        """,
        (actor, task_id),
    ).fetchall()
    candidates: set[str] = set()
    for row in rows:
        try:
            raw_ids = json.loads(str(row["memory_ids_json"] or "[]"))
            raw_versions = json.loads(str(row["memory_versions_json"] or "[]"))
            candidates.update(
                _normalized_memory_ids(raw_ids if isinstance(raw_ids, list) else [])
            )
            candidates.update(
                str(item["memory_id"])
                for item in _normalized_memory_versions(
                    raw_versions if isinstance(raw_versions, list) else []
                )
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
    return candidates


def record_task_completed(
    raw_task_id: str,
    actor: str,
    *,
    value: str = "success",
) -> str:
    """Best-effort lifecycle completion event for Stop/SessionEnd adapters."""

    if not observability_enabled() or not STATE_DB.is_file():
        return ""
    task_id = task_ref(raw_task_id, actor)
    if not task_id:
        return ""
    try:
        with connect() as conn:
            assert_schema_ready(conn)
            _mark_enabled(conn)
            _ensure_task_seen_event(conn, actor=actor, task_id=task_id)
            high_water_row = conn.execute(
                """
                SELECT COALESCE(MAX(id), 0)
                FROM memory_use_events
                WHERE actor=? AND task_id=?
                  AND event_type NOT IN ('task_completed', 'outcome')
                """,
                (actor, task_id),
            ).fetchone()
            high_water = int(high_water_row[0] if high_water_row else 0)
            # Stop is turn-scoped even when the host task/thread identifier is
            # reused. Bind idempotency to the last non-completion event: a
            # duplicate Stop with no new activity is ignored, while a later
            # turn receives a distinct completion boundary.
            identifier = "task-completed-" + _purpose_hash(
                "event-v3",
                f"{actor}\0{task_id}\0{value}\0{high_water}",
            )
            return _insert_event(
                conn,
                actor=actor,
                task_id=task_id,
                event_type="task_completed",
                source="tool_observed",
                value=value,
                event_id=identifier,
            )
    except (OSError, sqlite3.Error, RuntimeTransitionError, ValueError):
        return ""


def _row_value(row: Any, key: str, default: Any = "") -> Any:
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if value is None else value


def reduce_versioned_events(
    rows: Iterable[Any],
) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    """Reduce ordered events into one exact state per content version.

    The identity deliberately includes actor and task as well as ``memory_id``
    and ``content_sha256``.  A verification for version A must never clear
    version B, and a later ``no`` or non-adoption declaration must replace an
    earlier ``yes``/``adopted`` value for that exact key.
    """

    states: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in rows:
        actor = str(_row_value(row, "actor"))
        task_id = str(_row_value(row, "task_id"))
        event_type = canonical_event_type(_row_value(row, "event_type"))
        source = str(_row_value(row, "source"))
        value = str(_row_value(row, "value"))
        try:
            raw_versions = json.loads(str(_row_value(row, "memory_versions_json", "[]") or "[]"))
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("memory_versions_json_invalid") from exc
        normalized = _normalized_memory_versions(
            raw_versions if isinstance(raw_versions, list) else []
        )
        version_items = [
            (
                (actor, task_id, str(item["memory_id"]), str(item["content_sha256"])),
                item,
            )
            for item in normalized
            if str(item["content_sha256"])
        ]

        def state_for(key: tuple[str, str, str, str]) -> dict[str, Any]:
            return states.setdefault(
                key,
                {
                    "opened": False,
                    # An adopted version without an objective open is treated
                    # as sensitive/fail-closed until the chain is repaired.
                    "requires_live_verification": True,
                    "policy_state": "unknown",
                    "adoption": "",
                    "adoption_source": "",
                    "adoption_by_source": {},
                    "live_verified": "",
                    "verification_source": "",
                    "verification_by_source": {},
                },
            )

        if event_type == "source_opened" and source == "tool_observed":
            for key, item in version_items:
                state = state_for(key)
                policy_state = str(item["policy_state"])
                state["opened"] = True
                state["policy_state"] = policy_state
                state["requires_live_verification"] = bool(
                    item["requires_live_verification"]
                ) or policy_state in {
                    "overdue",
                    "expired",
                    "conflict",
                    "inactive",
                    "unknown",
                }
        elif event_type == "adoption_declared":
            keys = [key for key, _item in version_items]
            for key in keys:
                state = state_for(key)
                state["adoption"] = value
                state["adoption_source"] = source
                state["adoption_by_source"][source] = value
        elif event_type == "live_verified":
            for key, _item in version_items:
                state = state_for(key)
                state["live_verified"] = value
                state["verification_source"] = source
                state["verification_by_source"][source] = value
    return states


def adopted_stale_without_verification(actor: str, raw_task_id: str) -> int:
    """Count task-local adopted stale content versions lacking live verification.

    Identity is the pair ``(memory_id, content_sha256)``.  Later adoption
    declarations replace earlier ones; ``reference_only`` and ``rejected``
    clear a prior adoption, while the latest version-bound ``live_verified``
    declaration controls verification state.
    """

    if not STATE_DB.is_file() or STATE_DB.is_symlink():
        raise ObservabilityLedgerUnavailable("OBSERVABILITY_LEDGER_UNAVAILABLE")
    task_id = task_ref(raw_task_id, actor)
    if not task_id:
        raise ObservabilityLedgerUnavailable("OBSERVABILITY_TASK_ID_UNAVAILABLE")
    with connect(timeout=1.0, read_only=True) as conn:
        assert_schema_ready(conn)
        tables = {
            str(row[0])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "memory_use_events" not in tables:
            raise ObservabilityLedgerUnavailable("OBSERVABILITY_LEDGER_UNAVAILABLE")
        rows = conn.execute(
            """
            SELECT actor, task_id, event_type, source, value,
                   memory_ids_json, memory_versions_json
            FROM memory_use_events
            WHERE actor=? AND task_id=?
              AND event_type IN (
                'source_opened', 'opened_original',
                'adoption', 'adoption_declared', 'live_verified'
              )
            ORDER BY id
            """,
            (actor, task_id),
        ).fetchall()
    states = reduce_versioned_events(rows)
    return sum(
        1
        for state in states.values()
        if state["adoption"] == "adopted"
        and bool(state["requires_live_verification"])
        and state["live_verified"] != "yes"
    )


def _parse_since(value: str, days: int) -> str:
    if value:
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            parsed_date = dt.date.fromisoformat(value)
            parsed = dt.datetime.combine(parsed_date, dt.time.min, tzinfo=dt.timezone.utc)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat()
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=max(1, days))).replace(microsecond=0).isoformat()


def build_report(conn: sqlite3.Connection, *, since: str = "", days: int = 30) -> dict[str, Any]:
    assert_schema_ready(conn)
    requested_since = _parse_since(since, days)
    started_row = conn.execute("SELECT value FROM meta WHERE key='observability_enabled_at'").fetchone()
    enabled_at = str(started_row[0]) if started_row else ""
    effective_since = max(requested_since, enabled_at) if enabled_at else requested_since
    rows = conn.execute(
        """
        SELECT id, actor, task_id, event_type, source, value, task_class,
               memory_ids_json, memory_versions_json, content_sha256,
               required_live_verification_count, requires_live_verification,
               created_at
        FROM memory_use_events
        WHERE created_at>=?
        ORDER BY id
        """,
        (effective_since,),
    ).fetchall()
    linkage_seen_tasks = {
        (str(row[0]), str(row[1]))
        for row in conn.execute(
            """
            SELECT DISTINCT actor, task_id
            FROM memory_use_events
            WHERE event_type='task_seen' AND source='tool_observed'
            """
        ).fetchall()
        if str(row[0]) not in MAINTENANCE_ACTORS
    }
    # Stop enforcement and reporting intentionally share this ordered,
    # exact-version reducer.  Report-local "latest yes" projections must not
    # disagree with the blocker for the same content version.
    version_states = reduce_versioned_events(rows)

    declared_types = {
        "source_opened_declared",
        "task_completed",
        "applicability_self",
        "applicability_independent",
    }
    latest_declared: dict[tuple[str, str, str, str, str], sqlite3.Row] = {}
    for row in rows:
        event_type = canonical_event_type(row["event_type"])
        if event_type not in declared_types:
            continue
        memory_key = ""
        if event_type == "source_opened_declared":
            try:
                version_values = json.loads(str(row["memory_versions_json"] or "[]"))
            except json.JSONDecodeError:
                version_values = []
            version_identities = sorted(
                (
                    str(item.get("memory_id", "")),
                    str(item.get("content_sha256", "")),
                )
                for item in (version_values if isinstance(version_values, list) else [])
                if isinstance(item, dict)
            )
            if version_identities:
                memory_key = json.dumps(
                    version_identities,
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
            else:
                try:
                    memory_values = json.loads(str(row["memory_ids_json"] or "[]"))
                except json.JSONDecodeError:
                    memory_values = []
                memory_key = json.dumps(
                    sorted(str(item) for item in memory_values),
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
        key = (
            str(row["actor"]),
            str(row["task_id"]),
            event_type,
            str(row["source"]),
            memory_key,
        )
        latest_declared[key] = row
    latest_rows = list(latest_declared.values())

    def value_counts(event_type: str, source: str | None = None) -> dict[str, int]:
        values = [
            str(row["value"])
            for row in latest_rows
            if canonical_event_type(row["event_type"]) == event_type
            and (source is None or str(row["source"]) == source)
        ]
        return {value: values.count(value) for value in sorted(set(values))}

    def version_value_counts(field: str, source: str) -> dict[str, int]:
        values = [
            str(per_source[source])
            for state in version_states.values()
            for per_source in [state[field]]
            if source in per_source
        ]
        return {value: values.count(value) for value in sorted(set(values))}

    period_seen_tasks = {
        (str(row["actor"]), str(row["task_id"]))
        for row in rows
        if (str(row["actor"]), str(row["task_id"])) in linkage_seen_tasks
    }
    searched_tasks = {
        (str(row["actor"]), str(row["task_id"]))
        for row in rows
        if canonical_event_type(row["event_type"]) == "search_completed"
        and str(row["source"]) == "tool_observed"
        and str(row["actor"]) not in MAINTENANCE_ACTORS
    }
    opened_tasks = {
        (str(row["actor"]), str(row["task_id"]))
        for row in rows
        if canonical_event_type(row["event_type"]) == "source_opened"
        and str(row["source"]) == "tool_observed"
        and str(row["actor"]) not in MAINTENANCE_ACTORS
    }
    independently_labeled = {
        (str(row["actor"]), str(row["task_id"]))
        for row in latest_rows
        if canonical_event_type(row["event_type"]) == "applicability_independent"
        and str(row["source"]) in {"human_declared", "independent_model"}
    }
    independent_by_task_class: dict[str, dict[str, int]] = {}
    for row in latest_rows:
        if canonical_event_type(row["event_type"]) != "applicability_independent" or str(row["source"]) not in {
            "human_declared",
            "independent_model",
        }:
            continue
        task_class = str(row["task_class"] or "unclassified")
        value = str(row["value"])
        counts = independent_by_task_class.setdefault(task_class, {})
        counts[value] = counts.get(value, 0) + 1
    self_labels = {
        (str(row["actor"]), str(row["task_id"])): str(row["value"])
        for row in latest_rows
        if canonical_event_type(row["event_type"]) == "applicability_self"
        and str(row["source"]) == "agent_declared"
    }
    agreement: dict[str, dict[str, int | float | None]] = {}
    for source in ("human_declared", "independent_model"):
        compared = 0
        agreed = 0
        for row in latest_rows:
            if canonical_event_type(row["event_type"]) != "applicability_independent" or str(row["source"]) != source:
                continue
            self_value = self_labels.get((str(row["actor"]), str(row["task_id"])))
            if self_value is None:
                continue
            compared += 1
            agreed += int(self_value == str(row["value"]))
        agreement[source] = {
            "compared": compared,
            "agreed": agreed,
            "rate": (agreed / compared) if compared else None,
        }

    independent_labels_by_source: dict[str, dict[tuple[str, str], str]] = {
        "human_declared": {},
        "independent_model": {},
    }
    for row in latest_rows:
        source = str(row["source"])
        if (
            canonical_event_type(row["event_type"]) == "applicability_independent"
            and source in independent_labels_by_source
        ):
            independent_labels_by_source[source][
                (str(row["actor"]), str(row["task_id"]))
            ] = str(row["value"])

    def applicable_yes_metric(source: str) -> dict[str, Any]:
        labels = independent_labels_by_source[source]
        denominator_tasks = {
            task
            for task, value in labels.items()
            if value == "yes" and task in linkage_seen_tasks
        }
        denominator = len(denominator_tasks)
        not_searched = denominator_tasks - searched_tasks
        not_opened = denominator_tasks - opened_tasks
        neither = denominator_tasks - searched_tasks - opened_tasks
        searched_not_opened = (denominator_tasks & searched_tasks) - opened_tasks
        direct_open_without_search = (denominator_tasks & opened_tasks) - searched_tasks
        counts = {
            "not_searched": len(not_searched),
            "not_opened": len(not_opened),
            "neither_search_nor_open": len(neither),
            "searched_not_opened": len(searched_not_opened),
            "direct_open_without_search": len(direct_open_without_search),
        }
        return {
            "denominator": denominator,
            **counts,
            "rate": {
                key: (count / denominator) if denominator else None
                for key, count in counts.items()
            },
        }

    labels_without_task_seen: dict[str, dict[str, Any]] = {}
    for source, labels in independent_labels_by_source.items():
        values = [value for task, value in labels.items() if task not in linkage_seen_tasks]
        labels_without_task_seen[source] = {
            "total": len(values),
            "by_value": {value: values.count(value) for value in sorted(set(values))},
        }

    human_labels = independent_labels_by_source["human_declared"]
    model_labels = independent_labels_by_source["independent_model"]
    jointly_labeled = set(human_labels) & set(model_labels)
    conflicting_labels = {
        task for task in jointly_labeled if human_labels[task] != model_labels[task]
    }
    source_conflicts = {
        "both_labeled": len(jointly_labeled),
        "conflicting": len(conflicting_labels),
        "with_task_seen": len(conflicting_labels & linkage_seen_tasks),
        "without_task_seen": len(conflicting_labels - linkage_seen_tasks),
    }

    time_sensitive_tasks: set[tuple[str, str]] = set()
    for row in rows:
        if canonical_event_type(row["event_type"]) != "search_completed" or str(row["source"]) != "tool_observed":
            continue
        try:
            requires_live_verification = int(row["required_live_verification_count"] or 0) > 0
        except (TypeError, ValueError):
            requires_live_verification = False
        if requires_live_verification:
            time_sensitive_tasks.add((str(row["actor"]), str(row["task_id"])))
    live_verification_by_source: dict[str, dict[str, int | float | None]] = {}
    for source in ("agent_declared", "human_declared", "independent_model"):
        yes_tasks = {
            (key[0], key[1])
            for key, state in version_states.items()
            if state["verification_by_source"].get(source) == "yes"
        }
        verified = len(time_sensitive_tasks & yes_tasks)
        denominator = len(time_sensitive_tasks)
        live_verification_by_source[source] = {
            "yes_verification": verified,
            "no_yes_event": denominator - verified,
            "yes_verification_rate": (verified / denominator) if denominator else None,
            "no_yes_event_rate": ((denominator - verified) / denominator) if denominator else None,
        }

    opened_versions = {
        key for key, state in version_states.items() if bool(state["opened"])
    }
    adopted_versions = {
        key for key, state in version_states.items() if state["adoption"] == "adopted"
    }
    adopted_sensitive_versions = {
        key
        for key, state in version_states.items()
        if state["adoption"] == "adopted"
        and bool(state["requires_live_verification"])
    }
    verified_versions = {
        key for key, state in version_states.items() if state["live_verified"] == "yes"
    }
    completed_tasks: set[tuple[str, str]] = set()
    event_tasks: set[tuple[str, str]] = set()
    for row in rows:
        event_type = canonical_event_type(row["event_type"])
        task = (str(row["actor"]), str(row["task_id"]))
        if task[0] in MAINTENANCE_ACTORS:
            continue
        event_tasks.add(task)
        if event_type == "task_completed" and str(row["source"] or "") == "tool_observed":
            completed_tasks.add(task)

    disposition_marker_row = conn.execute(
        "SELECT value FROM meta WHERE key='disposition_tracking_enabled_at'"
    ).fetchone()
    disposition_enabled_at = (
        _parse_since(str(disposition_marker_row[0]), days)
        if disposition_marker_row and str(disposition_marker_row[0] or "")
        else ""
    )
    disposition_since = (
        max(effective_since, disposition_enabled_at)
        if disposition_enabled_at
        else ""
    )
    returned_candidates: set[tuple[str, str, str]] = set()
    opened_candidates: set[tuple[str, str, str]] = set()
    latest_candidate_event: dict[tuple[str, str, str], int] = {}
    latest_dispositions: dict[tuple[str, str, str], tuple[int, str]] = {}
    latest_successful_completion: dict[tuple[str, str], int] = {}

    def row_memory_ids(row: sqlite3.Row) -> set[str]:
        values: set[str] = set()
        try:
            raw_ids = json.loads(str(row["memory_ids_json"] or "[]"))
            values.update(
                _normalized_memory_ids(raw_ids if isinstance(raw_ids, list) else [])
            )
            raw_versions = json.loads(str(row["memory_versions_json"] or "[]"))
            values.update(
                str(item["memory_id"])
                for item in _normalized_memory_versions(
                    raw_versions if isinstance(raw_versions, list) else []
                )
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            return set()
        return values

    if disposition_since:
        for row in rows:
            if str(row["created_at"] or "") < disposition_since:
                continue
            actor = str(row["actor"] or "")
            if actor not in {"codex", "claude"}:
                continue
            task_id = str(row["task_id"] or "")
            task = (actor, task_id)
            event_order = int(row["id"])
            event_type = canonical_event_type(row["event_type"])
            source = str(row["source"] or "")
            ids = row_memory_ids(row)
            if event_type == "search_completed" and source == "tool_observed":
                candidates = {(actor, task_id, item) for item in ids}
                returned_candidates.update(candidates)
                for candidate in candidates:
                    latest_candidate_event[candidate] = event_order
            elif event_type == "source_opened" and source == "tool_observed":
                candidates = {(actor, task_id, item) for item in ids}
                opened_candidates.update(candidates)
                for candidate in candidates:
                    latest_candidate_event[candidate] = event_order
            elif event_type == "adoption_declared":
                for item in ids:
                    latest_dispositions[(actor, task_id, item)] = (
                        event_order,
                        str(row["value"] or ""),
                    )
            elif (
                event_type == "task_completed"
                and source == "tool_observed"
                and str(row["value"] or "") == "success"
            ):
                latest_successful_completion[task] = event_order

    completed_returned = {
        candidate
        for candidate in returned_candidates
        if latest_successful_completion.get(candidate[:2], -1)
        > latest_candidate_event.get(candidate, -1)
    }
    completed_opened = {
        candidate
        for candidate in opened_candidates
        if latest_successful_completion.get(candidate[:2], -1)
        > latest_candidate_event.get(candidate, -1)
    }
    accepted_dispositions = {"adopted", "reference_only", "rejected"}

    def has_current_disposition(candidate: tuple[str, str, str]) -> bool:
        disposition_order, disposition = latest_dispositions.get(candidate, (-1, ""))
        return (
            disposition in accepted_dispositions
            and disposition_order >= latest_candidate_event.get(candidate, -1)
        )

    returned_without_disposition = {
        candidate
        for candidate in completed_returned
        if not has_current_disposition(candidate)
    }
    opened_without_disposition = {
        candidate
        for candidate in completed_opened
        if not has_current_disposition(candidate)
    }
    disposition_gap_tasks = {
        candidate[:2]
        for candidate in returned_without_disposition | opened_without_disposition
    }
    adopted_without_source = adopted_versions - opened_versions
    adopted_stale_without_verification = adopted_sensitive_versions - verified_versions
    legacy_unversioned_adoption_events = 0
    for row in rows:
        if (
            canonical_event_type(row["event_type"]) != "adoption_declared"
            or str(row["value"] or "") != "adopted"
        ):
            continue
        try:
            raw_versions = json.loads(str(row["memory_versions_json"] or "[]"))
        except (TypeError, json.JSONDecodeError):
            raw_versions = []
        if not any(
            isinstance(item, dict) and str(item.get("content_sha256", ""))
            for item in (raw_versions if isinstance(raw_versions, list) else [])
        ):
            legacy_unversioned_adoption_events += 1
    seven_days_since = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7)
    ).replace(microsecond=0).isoformat()
    shadow_since = max(effective_since, seven_days_since)
    shadow_rows = conn.execute(
        """
        SELECT query, used_paths, actor, task_id, sources, search_status, ranking_mode,
               v1_result_fingerprint, v2_result_fingerprint,
               required_case_regression_count, worker_status,
               worker_restart_count
        FROM memory_search_log
        WHERE created_at>=?
        """,
        (shadow_since,),
    ).fetchall()
    worker_counts: dict[str, int] = {}
    for row in shadow_rows:
        status = str(row["worker_status"] or "not_used")
        worker_counts[status] = worker_counts.get(status, 0) + 1
    invalid_source_rows = sum(
        1
        for row in shadow_rows
        if str(row["sources"] or "") not in SEARCH_LOG_CANONICAL_SOURCES
    )
    invalid_search_status_rows = sum(
        1
        for row in shadow_rows
        if str(row["search_status"] or "") not in SEARCH_LOG_STATUS_VALUES
    )
    privacy_violations = sum(
        1
        for row in shadow_rows
        if str(row["used_paths"] or "")
        or str(row["query"] or "")
        or str(row["sources"] or "") not in SEARCH_LOG_CANONICAL_SOURCES
        or str(row["search_status"] or "") not in SEARCH_LOG_STATUS_VALUES
    )
    return {
        "enabled": observability_enabled(),
        "requested_since": requested_since,
        "enabled_at": enabled_at,
        "effective_since": effective_since,
        "tool_observed": {
            "task_denominator": len(period_seen_tasks),
            "searched_tasks": len(period_seen_tasks & searched_tasks),
            "not_searched_tasks": len(period_seen_tasks - searched_tasks),
            "opened_original_tasks": len(period_seen_tasks & opened_tasks),
            "tasks_without_hook_denominator": len(searched_tasks - linkage_seen_tasks),
        },
        "applicability": {
            "independent_task_denominator": len(independently_labeled),
            "human": value_counts("applicability_independent", "human_declared"),
            "independent_model": value_counts("applicability_independent", "independent_model"),
            "agent_self": value_counts("applicability_self", "agent_declared"),
            "independent_by_task_class": independent_by_task_class,
            "self_independent_agreement": agreement,
        },
        "live_verification": {
            source: version_value_counts("verification_by_source", source)
            for source in sorted(SOURCES)
        },
        "adoption": {
            source: version_value_counts("adoption_by_source", source)
            for source in ("agent_declared", "human_declared")
        },
        "outcome": {
            source: value_counts("task_completed", source)
            for source in ("agent_declared", "human_declared", "independent_model")
        },
        "cross_metrics": {
            "applicable_yes": {
                "by_source": {
                    source: applicable_yes_metric(source)
                    for source in ("human_declared", "independent_model")
                },
                "labels_without_task_seen": labels_without_task_seen,
                "source_conflicts": source_conflicts,
            },
            "time_sensitive_live_verification": {
                "denominator": len(time_sensitive_tasks),
                "by_source": live_verification_by_source,
                "no_yes_event_meaning": "unknown_or_not_verified",
            },
            "chain_health": {
                "orphan_event_tasks": len(event_tasks - linkage_seen_tasks),
                "tasks_without_completion": len(period_seen_tasks - completed_tasks),
                "adopted_versions": len(adopted_versions),
                "adopted_without_source_opened": len(adopted_without_source),
                "adopted_stale_without_live_verification": len(adopted_stale_without_verification),
                "legacy_unversioned_adoption_events": legacy_unversioned_adoption_events,
                "disposition_tracking_enabled_at": disposition_enabled_at,
                "returned_without_disposition": len(returned_without_disposition),
                "opened_without_disposition": len(opened_without_disposition),
                "tasks_with_missing_disposition": len(disposition_gap_tasks),
            },
            "shadow_7d": {
                "since": shadow_since,
                "searches": len(shadow_rows),
                "required_regressions": sum(
                    max(0, int(row["required_case_regression_count"] or 0))
                    for row in shadow_rows
                ),
                "missing_denominator": sum(
                    1
                    for row in shadow_rows
                    if str(row["actor"] or "") not in MAINTENANCE_ACTORS
                    and not any(
                        marker in source
                        for source in str(row["sources"] or "").split(",")
                        for marker in ("benchmark", "canary", "synthetic", "test")
                    )
                    and (str(row["actor"] or ""), str(row["task_id"] or ""))
                    not in linkage_seen_tasks
                ),
                "privacy_violation": privacy_violations,
                "invalid_source_rows": invalid_source_rows,
                "invalid_search_status_rows": invalid_search_status_rows,
                "worker_status": worker_counts,
                "worker_restarts": sum(
                    max(0, int(row["worker_restart_count"] or 0))
                    for row in shadow_rows
                ),
            },
        },
        "interpretation": {
            "missing_tool_event": "unknown unless task_seen supplies the denominator",
            "headline_applicability_denominator": "human_declared or independent_model only",
            "applicable_yes_cross_metrics": "each source uses only its latest explicit yes label on task_seen tasks",
            "live_verification_no_yes_event": "unknown-or-not-verified; never an inferred no",
            "sources_combined": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Privacy-preserving Agent Memory task observability.")
    parser.add_argument("--actor", choices=("codex", "claude", "human", "migration", "test"), default=os.environ.get("MEMORY_ACTOR", "codex"))
    parser.add_argument("--json", action="store_true")
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("current")

    self_parser = subparsers.add_parser("self")
    self_parser.add_argument("--applicability", choices=("yes", "no", "uncertain"), required=True)
    self_parser.add_argument("--reason", choices=tuple(sorted(REASON_CODES - {""})), required=True)
    self_parser.add_argument("--task-class", choices=tuple(sorted(TASK_CLASSES - {""})), required=True)
    self_parser.add_argument("--memory-id", action="append", default=[])
    self_parser.add_argument("--confidence", choices=("high", "medium", "low"), default="")

    adoption_parser = subparsers.add_parser("adoption")
    adoption_parser.add_argument("--value", choices=("adopted", "rejected", "reference_only", "unknown"), required=True)
    adoption_parser.add_argument("--memory-id", action="append", default=[])
    adoption_parser.add_argument("--content-sha256", action="append", default=[])
    adoption_parser.add_argument("--policy-state", choices=tuple(sorted(MEMORY_VERSION_STATES)), default="unknown")
    adoption_parser.add_argument("--requires-live-verification", action="store_true")
    adoption_parser.add_argument("--reason", choices=tuple(sorted(REASON_CODES)), default="")
    adoption_parser.add_argument("--confidence", choices=("high", "medium", "low"), default="")

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--value", choices=("yes", "no", "not_required", "unknown"), required=True)
    verify_parser.add_argument("--memory-id", action="append", default=[])
    verify_parser.add_argument("--content-sha256", action="append", default=[])
    verify_parser.add_argument("--policy-state", choices=tuple(sorted(MEMORY_VERSION_STATES)), default="unknown")
    verify_parser.add_argument("--requires-live-verification", action="store_true")
    verify_parser.add_argument("--reason", choices=tuple(sorted(REASON_CODES)), default="")
    verify_parser.add_argument("--confidence", choices=("high", "medium", "low"), default="")

    outcome_parser = subparsers.add_parser("outcome")
    outcome_parser.add_argument("--value", choices=("success", "user_corrected", "failure", "unknown"), required=True)
    outcome_parser.add_argument("--reason", choices=tuple(sorted(REASON_CODES)), default="")
    outcome_parser.add_argument("--confidence", choices=("high", "medium", "low"), default="")

    label_parser = subparsers.add_parser("label")
    label_parser.add_argument("--task-hash", required=True)
    label_parser.add_argument("--subject-actor", choices=("codex", "claude", "test"), required=True)
    label_parser.add_argument(
        "--kind",
        choices=("applicability", "adoption", "verify", "outcome"),
        default="applicability",
    )
    label_parser.add_argument(
        "--value",
        choices=(
            "yes", "no", "uncertain", "not_required", "unknown",
            "adopted", "rejected", "reference_only",
            "success", "user_corrected", "failure",
        ),
        required=True,
    )
    label_parser.add_argument("--labeler-kind", choices=("human", "independent_model"), required=True)
    label_parser.add_argument("--memory-id", action="append", default=[])
    label_parser.add_argument("--content-sha256", action="append", default=[])
    label_parser.add_argument("--policy-state", choices=tuple(sorted(MEMORY_VERSION_STATES)), default="unknown")
    label_parser.add_argument("--requires-live-verification", action="store_true")
    label_parser.add_argument("--task-class", choices=tuple(sorted(TASK_CLASSES - {""})), required=True)
    label_parser.add_argument("--labeler-ref", default="")
    label_parser.add_argument("--reason", choices=tuple(sorted(REASON_CODES)), default="")
    label_parser.add_argument("--confidence", choices=("high", "medium", "low"), default="")

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("--since", default="")
    report_parser.add_argument("--days", type=int, default=30)
    return parser.parse_args()


def _current_payload(actor: str) -> dict[str, Any]:
    task_id = current_task_ref(actor)
    enabled_at = ""
    if STATE_DB.is_file():
        try:
            with connect(timeout=1.0, read_only=True) as conn:
                tables = {
                    str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                if "meta" in tables:
                    row = conn.execute("SELECT value FROM meta WHERE key='observability_enabled_at'").fetchone()
                    enabled_at = str(row[0]) if row else ""
        except (OSError, sqlite3.Error):
            pass
    return {
        "enabled": observability_enabled(),
        "actor": actor,
        "task_hash": task_id,
        "task_available": bool(task_id),
        "runtime_version": runtime_version(),
        "enabled_at": enabled_at,
    }


def _versions_from_cli(args: argparse.Namespace, memory_ids: Sequence[str]) -> list[dict[str, Any]]:
    hashes = list(getattr(args, "content_sha256", []) or [])
    if not memory_ids and hashes:
        raise ValueError("memory_id_required_for_content_hash")
    if hashes and len(hashes) != len(memory_ids):
        raise ValueError("memory_version_count_mismatch")
    return _normalized_memory_versions(
        [
            {
                "memory_id": memory_id,
                "content_sha256": hashes[index] if hashes else "",
                "policy_state": getattr(args, "policy_state", "unknown"),
                "requires_live_verification": bool(
                    getattr(args, "requires_live_verification", False)
                ),
            }
            for index, memory_id in enumerate(memory_ids)
        ]
    )


def main() -> int:
    args = parse_args()
    try:
        assert_runtime_ready("observe")
    except RuntimeTransitionError as exc:
        if args.json:
            print(json.dumps({"ok": False, "reason_code": "RUNTIME_TRANSITION_INCOMPLETE"}))
        else:
            print(str(exc), file=sys.stderr)
        return 2
    try:
        if args.action == "current":
            payload: dict[str, Any] = _current_payload(args.actor)
        elif args.action == "report":
            if not STATE_DB.is_file():
                raise RuntimeError("observability_not_initialized")
            with connect(timeout=1.0, read_only=True) as conn:
                payload = build_report(conn, since=args.since, days=args.days)
        else:
            if args.action == "label":
                if args.actor not in {"human", "migration"}:
                    raise ValueError("independent_label_requires_human_or_migration_actor")
                task_id = args.task_hash.strip().casefold()
                if len(task_id) != 64 or any(character not in "0123456789abcdef" for character in task_id):
                    raise ValueError("task_hash_must_be_sha256")
                source = "human_declared" if args.labeler_kind == "human" else "independent_model"
                event_type = {
                    "applicability": "applicability_independent",
                    "adoption": "adoption_declared",
                    "verify": "live_verified",
                    "outcome": "task_completed",
                }[args.kind]
                if event_type == "adoption_declared" and source != "human_declared":
                    raise ValueError("adoption_label_requires_human")
                actor = args.subject_actor
                value = args.value
                memory_ids = args.memory_id
                task_class = args.task_class
                labeler_ref = args.labeler_ref
            else:
                if args.actor not in {"codex", "claude", "test"}:
                    raise ValueError("task_self_event_requires_agent_actor")
                task_id = current_task_ref(args.actor)
                if not task_id:
                    raise ValueError("current_task_id_unavailable")
                source = "human_declared" if args.actor == "human" else "agent_declared"
                actor = args.actor
                labeler_ref = ""
                if args.action == "self":
                    if source != "agent_declared":
                        raise ValueError("self_applicability_requires_agent_actor")
                    event_type, value, memory_ids = "applicability_self", args.applicability, args.memory_id
                    task_class = args.task_class
                elif args.action == "adoption":
                    event_type, value, memory_ids = "adoption_declared", args.value, args.memory_id
                    task_class = ""
                elif args.action == "verify":
                    event_type, value, memory_ids = "live_verified", args.value, args.memory_id
                    task_class = ""
                else:
                    event_type, value, memory_ids = "task_completed", args.value, ()
                    task_class = ""
            memory_versions = _versions_from_cli(args, memory_ids)
            event_id = record_declared_event(
                actor=actor,
                task_id=task_id,
                event_type=event_type,
                source=source,
                value=value,
                memory_ids=memory_ids,
                memory_versions=memory_versions,
                reason_code=args.reason,
                confidence=args.confidence,
                labeler_ref=labeler_ref,
                task_class=task_class,
            )
            payload = {"ok": True, "event_id": event_id, "event_type": event_type, "source": source}
    except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
        reason = str(exc)
        payload = {
            "ok": False,
            "error": reason,
            **(
                {"reason_code": "STATE_SCHEMA_MIGRATION_REQUIRED", "degraded": True}
                if reason == "STATE_SCHEMA_MIGRATION_REQUIRED"
                else {}
            ),
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(payload["error"], file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for key, value in payload.items():
            print(f"{key}={json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
