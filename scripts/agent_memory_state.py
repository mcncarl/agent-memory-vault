from __future__ import annotations

import os
import re
import sqlite3
import stat
import ctypes
import errno
import hashlib
import contextlib
import itertools
import json
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator


PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
POSIX_PERMISSION_MODEL = os.name != "nt"
STATE_SCHEMA_VERSION = 4
OBSERVABILITY_SCHEMA_VERSION = 4
SEARCH_LOG_PRIVACY_GUARD_VERSION = "3"
SEARCH_LOG_PRIVACY_REASON_CODE = "SEARCH_LOG_PRIVACY_VIOLATION"
SEARCH_LOG_CONTROL_REASON_CODE = "SEARCH_LOG_CONTROL_VALUE_INVALID"
OBSERVABILITY_EVENT_CONTROL_REASON_CODE = "OBSERVABILITY_EVENT_CONTROL_VALUE_INVALID"
SEARCH_LOG_PRIVACY_TRIGGER_INSERT = "agent_memory_search_log_privacy_insert"
SEARCH_LOG_PRIVACY_TRIGGER_UPDATE = "agent_memory_search_log_privacy_update"
SEARCH_LOG_CONTROL_TRIGGER_INSERT = "agent_memory_search_log_control_insert"
SEARCH_LOG_CONTROL_TRIGGER_UPDATE = "agent_memory_search_log_control_update"
OBSERVABILITY_EVENT_CONTROL_TRIGGER_INSERT = "agent_memory_use_event_control_insert"
OBSERVABILITY_EVENT_CONTROL_TRIGGER_UPDATE = "agent_memory_use_event_control_update"

OBSERVABILITY_ACTOR_VALUES = frozenset({
    "ailu",
    "claude",
    "codex",
    "human",
    "migration",
    "test",
})
OBSERVABILITY_REASON_VALUES = frozenset({
    "",
    "cross_project_reference",
    "existing_project",
    "no_relevant_memory",
    "not_applicable",
    "one_off_task",
    "other_controlled",
    "prior_decision",
    "user_preference",
    "workflow_rule",
})
OBSERVABILITY_CONFIDENCE_VALUES = frozenset({"", "high", "medium", "low"})
OBSERVABILITY_READ_MODE_VALUES = frozenset({"", "full", "outline", "query", "section"})
OBSERVABILITY_TASK_CLASS_VALUES = frozenset({
    "",
    "coding",
    "existing_project",
    "formal_memory",
    "one_off",
    "other_controlled",
    "research",
    "troubleshooting",
    "writing",
})
OBSERVABILITY_MEMORY_VERSION_STATES = frozenset({
    "conflict",
    "current",
    "expired",
    "inactive",
    "overdue",
    "unknown",
})
OBSERVABILITY_EVENT_VALUES = {
    "adoption": frozenset({"adopted", "reference_only", "rejected", "unknown"}),
    "adoption_declared": frozenset({"adopted", "reference_only", "rejected", "unknown"}),
    "applicability_independent": frozenset({"no", "uncertain", "yes"}),
    "applicability_self": frozenset({"no", "uncertain", "yes"}),
    "live_verified": frozenset({"no", "not_required", "unknown", "yes"}),
    "opened_original": frozenset({"yes"}),
    "opened_original_declared": frozenset({"yes"}),
    "outcome": frozenset({"failure", "success", "unknown", "user_corrected"}),
    "search": frozenset({"backend_failed", "partial", "success"}),
    "search_completed": frozenset({"backend_failed", "partial", "success"}),
    "source_opened": frozenset({"yes"}),
    "task_completed": frozenset({"failure", "success", "unknown", "user_corrected"}),
    "task_seen": frozenset({"seen"}),
}
OBSERVABILITY_EVENT_SOURCES = {
    "adoption": frozenset({"agent_declared", "human_declared"}),
    "adoption_declared": frozenset({"agent_declared", "human_declared"}),
    "applicability_independent": frozenset({"human_declared", "independent_model"}),
    "applicability_self": frozenset({"agent_declared"}),
    "live_verified": frozenset({
        "agent_declared", "human_declared", "independent_model", "tool_observed"
    }),
    "opened_original": frozenset({"tool_observed"}),
    "opened_original_declared": frozenset({"agent_declared", "human_declared"}),
    "outcome": frozenset({"agent_declared", "human_declared", "independent_model"}),
    "search": frozenset({"tool_observed"}),
    "search_completed": frozenset({"tool_observed"}),
    "source_opened": frozenset({"tool_observed"}),
    "task_completed": frozenset({
        "agent_declared", "human_declared", "independent_model", "tool_observed"
    }),
    "task_seen": frozenset({"tool_observed"}),
}

SEARCH_LOG_SOURCE_VALUES = frozenset({
    "canonical_retrieve",
    "hybrid_benchmark",
    "rg",
    "sqlite",
    "trigram_fts",
    "unicode_fts",
    "zvec",
})
SEARCH_LOG_CANONICAL_SOURCES = frozenset(
    {"legacy_unknown", "none"}
    | {
        ",".join(values)
        for size in range(1, len(SEARCH_LOG_SOURCE_VALUES) + 1)
        for values in itertools.combinations(sorted(SEARCH_LOG_SOURCE_VALUES), size)
    }
)
SEARCH_LOG_STATUS_VALUES = frozenset({
    "backend_failed",
    "legacy_unknown",
    "partial",
    "success",
})


def _search_log_privacy_condition(prefix: str = "NEW") -> str:
    return f"""
      NOT (
        coalesce({prefix}.query, '') = ''
        AND coalesce({prefix}.used_paths, '') = ''
      )
    """.strip()


def _sql_string_set(values: Iterable[str]) -> str:
    return ", ".join("'" + value.replace("'", "''") + "'" for value in sorted(values))


def _sql_sha256(expression: str, *, allow_empty: bool = False) -> str:
    valid = (
        f"length({expression})=64 AND lower({expression})={expression} "
        f"AND {expression} NOT GLOB '*[^0-9a-f]*'"
    )
    return f"({expression}='' OR ({valid}))" if allow_empty else f"({valid})"


def _sql_controlled_token(
    expression: str,
    *,
    minimum: int,
    maximum: int,
    allowed_characters: str,
) -> str:
    return (
        f"length({expression}) BETWEEN {minimum} AND {maximum} "
        f"AND {expression} NOT GLOB '*[^{allowed_characters}]*'"
    )


def _search_log_control_condition(prefix: str = "NEW") -> str:
    sources = _sql_string_set(SEARCH_LOG_CANONICAL_SOURCES)
    statuses = _sql_string_set(SEARCH_LOG_STATUS_VALUES)
    actors = _sql_string_set(OBSERVABILITY_ACTOR_VALUES)
    rankings = _sql_string_set({"hybrid_v2", "legacy_v1", "shadow"})
    workers = _sql_string_set({"degraded", "failed", "not_used", "restarted", "reused", "started"})
    sha_query = _sql_sha256(f"coalesce({prefix}.query_sha256, '')", allow_empty=True)
    sha_task = _sql_sha256(f"coalesce({prefix}.task_id, '')", allow_empty=True)
    sha_v1 = _sql_sha256(f"coalesce({prefix}.v1_result_fingerprint, '')", allow_empty=True)
    sha_v2 = _sql_sha256(f"coalesce({prefix}.v2_result_fingerprint, '')", allow_empty=True)
    sha_metadata = _sql_sha256(
        f"coalesce({prefix}.metadata_reason_fingerprint, '')", allow_empty=True
    )
    search_id = _sql_controlled_token(
        f"coalesce({prefix}.search_id, '')",
        minimum=36,
        maximum=36,
        allowed_characters="0-9a-f-",
    )
    created_at = _sql_controlled_token(
        f"coalesce({prefix}.created_at, '')",
        minimum=20,
        maximum=40,
        allowed_characters="0-9T:+.Z-",
    )
    return f"""
      coalesce({prefix}.query, '')=''
      AND coalesce({prefix}.used_paths, '')=''
      AND NOT (
        coalesce({prefix}.sources, '') IN ({sources})
        AND coalesce({prefix}.search_status, '') IN ({statuses})
        AND {sha_query}
        AND {sha_task}
        AND {sha_v1}
        AND {sha_v2}
        AND {sha_metadata}
        AND (
          coalesce({prefix}.search_id, '')=''
          OR ({search_id})
        )
        AND coalesce({prefix}.actor, '') IN ('', {actors})
        AND coalesce({prefix}.event_source, '') IN ('', 'tool_observed')
        AND (
          (coalesce({prefix}.task_id, '')='' AND coalesce({prefix}.actor, '')=''
             AND coalesce({prefix}.event_source, '')='')
          OR
          (coalesce({prefix}.task_id, '')<>'' AND coalesce({prefix}.actor, '')<>''
             AND coalesce({prefix}.event_source, '')='tool_observed')
        )
        AND typeof({prefix}.result_count)='integer' AND {prefix}.result_count>=0
        AND ({prefix}.query_length IS NULL OR
             (typeof({prefix}.query_length)='integer' AND {prefix}.query_length>=0))
        AND ({prefix}.duration_ms IS NULL OR
             (typeof({prefix}.duration_ms)='integer' AND {prefix}.duration_ms>=0))
        AND ({created_at})
        AND coalesce({prefix}.ranking_mode, '') IN ({rankings})
        AND coalesce({prefix}.worker_status, '') IN ({workers})
        AND typeof({prefix}.worker_restart_count)='integer'
        AND {prefix}.worker_restart_count IN (0, 1)
        AND typeof({prefix}.required_case_regression_count)='integer'
        AND {prefix}.required_case_regression_count>=0
        AND coalesce({prefix}.metadata_gate_mode, '') IN ('shadow', 'enforce')
        AND typeof({prefix}.metadata_would_block_count)='integer'
        AND {prefix}.metadata_would_block_count>=0
        AND (
          ({prefix}.metadata_would_block_count=0
             AND coalesce({prefix}.metadata_reason_fingerprint, '')='')
          OR
          ({prefix}.metadata_would_block_count>0
             AND coalesce({prefix}.metadata_reason_fingerprint, '')<>'')
        )
        AND (
          coalesce({prefix}.returned_memory_ids_json, '')=''
          OR (
            json_valid({prefix}.returned_memory_ids_json)=1
            AND json_type({prefix}.returned_memory_ids_json)='array'
            AND json_array_length({prefix}.returned_memory_ids_json)<=512
            AND NOT EXISTS (
              SELECT 1 FROM json_each({prefix}.returned_memory_ids_json) AS memory_id
              WHERE memory_id.type<>'text'
                 OR NOT ({_sql_sha256('memory_id.value')})
            )
            AND (
              SELECT count(*) FROM json_each({prefix}.returned_memory_ids_json)
            )=(
              SELECT count(DISTINCT value) FROM json_each({prefix}.returned_memory_ids_json)
            )
          )
        )
        AND (
          coalesce({prefix}.search_id, '')=''
          OR (
            coalesce({prefix}.query_sha256, '')<>''
            AND coalesce({prefix}.returned_memory_ids_json, '')<>''
            AND coalesce({prefix}.search_status, '')<>'legacy_unknown'
          )
        )
      )
    """.strip()


def _event_control_condition(prefix: str = "NEW") -> str:
    actors = _sql_string_set(OBSERVABILITY_ACTOR_VALUES)
    reasons = _sql_string_set(OBSERVABILITY_REASON_VALUES)
    confidences = _sql_string_set(OBSERVABILITY_CONFIDENCE_VALUES)
    read_modes = _sql_string_set(OBSERVABILITY_READ_MODE_VALUES)
    task_classes = _sql_string_set(OBSERVABILITY_TASK_CLASS_VALUES)
    version_states = _sql_string_set(OBSERVABILITY_MEMORY_VERSION_STATES)
    allowed_event_triples = " OR ".join(
        "(" +
        f"{prefix}.event_type='{event_type}' " +
        f"AND {prefix}.source IN ({_sql_string_set(OBSERVABILITY_EVENT_SOURCES[event_type])}) " +
        f"AND {prefix}.value IN ({_sql_string_set(values)})" +
        ")"
        for event_type, values in sorted(OBSERVABILITY_EVENT_VALUES.items())
    )
    event_id = _sql_controlled_token(
        f"coalesce({prefix}.event_id, '')",
        minimum=8,
        maximum=160,
        allowed_characters="A-Za-z0-9._-",
    )
    runtime_version = _sql_controlled_token(
        f"coalesce({prefix}.runtime_version, '')",
        minimum=1,
        maximum=160,
        allowed_characters="A-Za-z0-9._+-",
    )
    created_at = _sql_controlled_token(
        f"coalesce({prefix}.created_at, '')",
        minimum=20,
        maximum=40,
        allowed_characters="0-9T:+.Z-",
    )
    memory_ids_json = f"coalesce({prefix}.memory_ids_json, '')"
    versions_json = f"coalesce({prefix}.memory_versions_json, '')"
    content_sha = f"coalesce({prefix}.content_sha256, '')"
    labeler_sha = f"coalesce({prefix}.labeler_ref_sha256, '')"
    return f"""
      NOT (
        ({event_id})
        AND {prefix}.actor IN ({actors})
        AND {_sql_sha256(f'{prefix}.task_id')}
        AND ({runtime_version})
        AND ({allowed_event_triples})
        AND coalesce({prefix}.reason_code, '') IN ({reasons})
        AND coalesce({prefix}.confidence, '') IN ({confidences})
        AND coalesce({prefix}.read_mode, '') IN ({read_modes})
        AND coalesce({prefix}.task_class, '') IN ({task_classes})
        AND ({created_at})
        AND {_sql_sha256(content_sha, allow_empty=True)}
        AND {_sql_sha256(labeler_sha, allow_empty=True)}
        AND typeof({prefix}.labeler_ref_length)='integer'
        AND {prefix}.labeler_ref_length>=0
        AND (({prefix}.labeler_ref_length=0 AND {labeler_sha}='')
             OR ({prefix}.labeler_ref_length>0 AND {labeler_sha}<>''))
        AND ({prefix}.result_count IS NULL OR
             (typeof({prefix}.result_count)='integer' AND {prefix}.result_count>=0))
        AND ({prefix}.required_live_verification_count IS NULL OR
             (typeof({prefix}.required_live_verification_count)='integer'
              AND {prefix}.required_live_verification_count>=0))
        AND ({prefix}.full_utf8_bytes IS NULL OR
             (typeof({prefix}.full_utf8_bytes)='integer' AND {prefix}.full_utf8_bytes>=0))
        AND ({prefix}.returned_utf8_bytes IS NULL OR
             (typeof({prefix}.returned_utf8_bytes)='integer' AND {prefix}.returned_utf8_bytes>=0))
        AND ({prefix}.truncated IS NULL OR
             (typeof({prefix}.truncated)='integer' AND {prefix}.truncated IN (0,1)))
        AND ({prefix}.page_count IS NULL OR
             (typeof({prefix}.page_count)='integer' AND {prefix}.page_count>=0))
        AND typeof({prefix}.requires_live_verification)='integer'
        AND {prefix}.requires_live_verification IN (0,1)
        AND json_valid({memory_ids_json})=1
        AND json_type({memory_ids_json})='array'
        AND json_array_length({memory_ids_json})<=512
        AND NOT EXISTS (
          SELECT 1 FROM json_each({memory_ids_json}) AS memory_id
          WHERE memory_id.type<>'text' OR NOT ({_sql_sha256('memory_id.value')})
        )
        AND (SELECT count(*) FROM json_each({memory_ids_json}))=(
          SELECT count(DISTINCT value) FROM json_each({memory_ids_json})
        )
        AND json_valid({versions_json})=1
        AND json_type({versions_json})='array'
        AND json_array_length({versions_json})<=512
        AND NOT EXISTS (
          SELECT 1 FROM json_each({versions_json}) AS version
          WHERE version.type<>'object'
             OR (SELECT count(*) FROM json_each(version.value))<>4
             OR EXISTS (
               SELECT 1 FROM json_each(version.value) AS field
               WHERE field.key NOT IN (
                 'memory_id','content_sha256','policy_state','requires_live_verification'
               )
             )
             OR json_type(version.value, '$.memory_id')<>'text'
             OR NOT ({_sql_sha256("json_extract(version.value, '$.memory_id')")})
             OR json_type(version.value, '$.content_sha256')<>'text'
             OR NOT ({_sql_sha256("json_extract(version.value, '$.content_sha256')", allow_empty=True)})
             OR json_type(version.value, '$.policy_state')<>'text'
             OR json_extract(version.value, '$.policy_state') NOT IN ({version_states})
             OR json_type(version.value, '$.requires_live_verification') NOT IN ('true','false')
             OR NOT EXISTS (
               SELECT 1 FROM json_each({memory_ids_json}) AS memory_id
               WHERE memory_id.value=json_extract(version.value, '$.memory_id')
             )
        )
        AND {prefix}.requires_live_verification=(
          CASE WHEN EXISTS (
            SELECT 1 FROM json_each({versions_json}) AS version
            WHERE json_extract(version.value, '$.requires_live_verification')=1
          ) THEN 1 ELSE 0 END
        )
        AND (
          {content_sha}=''
          OR EXISTS (
            SELECT 1 FROM json_each({versions_json}) AS version
            WHERE json_extract(version.value, '$.content_sha256')={content_sha}
          )
        )
        AND (
          NOT (
            {prefix}.event_type IN ('live_verified','source_opened')
            OR (
              {prefix}.event_type IN ('adoption','adoption_declared')
              AND {prefix}.value='adopted'
            )
          )
          OR (
            json_array_length({versions_json})>0
            AND NOT EXISTS (
              SELECT 1 FROM json_each({versions_json}) AS version
              WHERE json_extract(version.value, '$.content_sha256')=''
            )
          )
        )
      )
    """.strip()


SEARCH_LOG_PRIVACY_TRIGGER_SQL = {
    SEARCH_LOG_PRIVACY_TRIGGER_INSERT: f"""
        CREATE TRIGGER {SEARCH_LOG_PRIVACY_TRIGGER_INSERT}
        BEFORE INSERT ON memory_search_log
        WHEN {_search_log_privacy_condition()}
        BEGIN
          SELECT RAISE(ABORT, '{SEARCH_LOG_PRIVACY_REASON_CODE}');
        END
    """.strip(),
    SEARCH_LOG_PRIVACY_TRIGGER_UPDATE: f"""
        CREATE TRIGGER {SEARCH_LOG_PRIVACY_TRIGGER_UPDATE}
        BEFORE UPDATE ON memory_search_log
        WHEN {_search_log_privacy_condition()}
        BEGIN
          SELECT RAISE(ABORT, '{SEARCH_LOG_PRIVACY_REASON_CODE}');
        END
    """.strip(),
    SEARCH_LOG_CONTROL_TRIGGER_INSERT: f"""
        CREATE TRIGGER {SEARCH_LOG_CONTROL_TRIGGER_INSERT}
        BEFORE INSERT ON memory_search_log
        WHEN {_search_log_control_condition()}
        BEGIN
          SELECT RAISE(ABORT, '{SEARCH_LOG_CONTROL_REASON_CODE}');
        END
    """.strip(),
    SEARCH_LOG_CONTROL_TRIGGER_UPDATE: f"""
        CREATE TRIGGER {SEARCH_LOG_CONTROL_TRIGGER_UPDATE}
        BEFORE UPDATE ON memory_search_log
        WHEN {_search_log_control_condition()}
        BEGIN
          SELECT RAISE(ABORT, '{SEARCH_LOG_CONTROL_REASON_CODE}');
        END
    """.strip(),
    OBSERVABILITY_EVENT_CONTROL_TRIGGER_INSERT: f"""
        CREATE TRIGGER {OBSERVABILITY_EVENT_CONTROL_TRIGGER_INSERT}
        BEFORE INSERT ON memory_use_events
        WHEN {_event_control_condition()}
        BEGIN
          SELECT RAISE(ABORT, '{OBSERVABILITY_EVENT_CONTROL_REASON_CODE}');
        END
    """.strip(),
    OBSERVABILITY_EVENT_CONTROL_TRIGGER_UPDATE: f"""
        CREATE TRIGGER {OBSERVABILITY_EVENT_CONTROL_TRIGGER_UPDATE}
        BEFORE UPDATE ON memory_use_events
        WHEN {_event_control_condition()}
        BEGIN
          SELECT RAISE(ABORT, '{OBSERVABILITY_EVENT_CONTROL_REASON_CODE}');
        END
    """.strip(),
}


class StateSecurityError(OSError):
    """Raised when a private runtime path is unsafe to open."""


class ConditionalWriteError(StateSecurityError):
    """Bounded failure from a beneath-aware compare-and-swap write."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _sqlite_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _ensure_sqlite_column(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    declaration: str,
) -> None:
    if column not in _sqlite_columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def ensure_observability_v2_schema(conn: sqlite3.Connection) -> None:
    """Create the privacy-bounded state-v4 observability projection.

    This helper is deliberately located in the state module so the explicit
    state migrator and the observability writer share one schema definition.
    It stores only hashes, controlled labels, counts, and timestamps; source
    text, queries, URLs, and raw host session identifiers have no columns.
    """

    conn.execute(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_search_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          query TEXT NOT NULL,
          result_count INTEGER NOT NULL,
          used_paths TEXT,
          query_sha256 TEXT,
          query_length INTEGER,
          sources TEXT,
          duration_ms INTEGER,
          created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_use_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id TEXT NOT NULL UNIQUE,
          actor TEXT NOT NULL,
          task_id TEXT NOT NULL,
          runtime_version TEXT NOT NULL,
          event_type TEXT NOT NULL,
          source TEXT NOT NULL,
          memory_ids_json TEXT NOT NULL DEFAULT '[]',
          memory_versions_json TEXT NOT NULL DEFAULT '[]',
          content_sha256 TEXT NOT NULL DEFAULT '',
          value TEXT NOT NULL DEFAULT '',
          reason_code TEXT NOT NULL DEFAULT '',
          confidence TEXT NOT NULL DEFAULT '',
          labeler_ref_sha256 TEXT NOT NULL DEFAULT '',
          labeler_ref_length INTEGER NOT NULL DEFAULT 0,
          read_mode TEXT NOT NULL DEFAULT '',
          result_count INTEGER,
          required_live_verification_count INTEGER,
          requires_live_verification INTEGER NOT NULL DEFAULT 0,
          full_utf8_bytes INTEGER,
          returned_utf8_bytes INTEGER,
          truncated INTEGER,
          page_count INTEGER,
          task_class TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL
        )
        """
    )
    for column, declaration in (
        ("search_id", "TEXT"),
        ("actor", "TEXT"),
        ("task_id", "TEXT"),
        ("runtime_version", "TEXT"),
        ("event_source", "TEXT"),
        ("returned_memory_ids_json", "TEXT"),
        ("search_status", "TEXT"),
        ("ranking_mode", "TEXT NOT NULL DEFAULT 'legacy_v1'"),
        ("v1_result_fingerprint", "TEXT NOT NULL DEFAULT ''"),
        ("v2_result_fingerprint", "TEXT NOT NULL DEFAULT ''"),
        ("required_case_regression_count", "INTEGER NOT NULL DEFAULT 0"),
        ("worker_status", "TEXT NOT NULL DEFAULT 'not_used'"),
        ("worker_restart_count", "INTEGER NOT NULL DEFAULT 0"),
        ("metadata_gate_mode", "TEXT NOT NULL DEFAULT 'shadow'"),
        ("metadata_would_block_count", "INTEGER NOT NULL DEFAULT 0"),
        ("metadata_reason_fingerprint", "TEXT NOT NULL DEFAULT ''"),
    ):
        _ensure_sqlite_column(conn, "memory_search_log", column, declaration)
    for column, declaration in (
        ("task_class", "TEXT NOT NULL DEFAULT ''"),
        ("memory_versions_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("content_sha256", "TEXT NOT NULL DEFAULT ''"),
        ("requires_live_verification", "INTEGER NOT NULL DEFAULT 0"),
    ):
        _ensure_sqlite_column(conn, "memory_use_events", column, declaration)
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_search_id "
        "ON memory_search_log(search_id) WHERE search_id IS NOT NULL"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_memory_use_task "
        "ON memory_use_events(task_id, actor, created_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_memory_use_type "
        "ON memory_use_events(event_type, source, created_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_memory_use_content "
        "ON memory_use_events(content_sha256, event_type) WHERE content_sha256<>''"
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
        ("memory_observability_schema_version", str(OBSERVABILITY_SCHEMA_VERSION)),
    )
    # Completeness is enforced prospectively.  Existing v4 ledgers predate the
    # requirement that every returned/opened candidate receive a disposition;
    # the installer records the first instant from which Doctor and shadow may
    # treat an omitted declaration as a real chain gap.
    conn.execute(
        "INSERT OR IGNORE INTO meta(key, value) "
        "VALUES ('disposition_tracking_enabled_at', "
        "strftime('%Y-%m-%dT%H:%M:%SZ','now'))"
    )


def _normalized_sql(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().casefold()


def _is_sha256(value: object, *, allow_empty: bool = False) -> bool:
    normalized = str(value or "")
    return bool(
        (allow_empty and not normalized)
        or re.fullmatch(r"[0-9a-f]{64}", normalized)
    )


def _is_controlled_timestamp(value: object) -> bool:
    return re.fullmatch(r"[0-9T:+.Z-]{20,40}", str(value or "")) is not None


def _hash_list(value: object, *, allow_empty_storage: bool) -> list[str] | None:
    if value is None or value == "":
        return [] if allow_empty_storage else None
    try:
        decoded = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if (
        not isinstance(decoded, list)
        or len(decoded) > 512
        or any(not isinstance(item, str) or not _is_sha256(item) for item in decoded)
        or len(set(decoded)) != len(decoded)
    ):
        return None
    return decoded


def _version_list(value: object, memory_ids: set[str]) -> list[dict[str, Any]] | None:
    try:
        decoded = json.loads(str(value or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, list) or len(decoded) > 512:
        return None
    normalized: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    expected_keys = {
        "content_sha256",
        "memory_id",
        "policy_state",
        "requires_live_verification",
    }
    for item in decoded:
        if not isinstance(item, dict) or set(item) != expected_keys:
            return None
        memory_id = item.get("memory_id")
        content_sha = item.get("content_sha256")
        policy_state = item.get("policy_state")
        requires = item.get("requires_live_verification")
        if (
            not isinstance(memory_id, str)
            or not _is_sha256(memory_id)
            or memory_id not in memory_ids
            or not isinstance(content_sha, str)
            or not _is_sha256(content_sha, allow_empty=True)
            or policy_state not in OBSERVABILITY_MEMORY_VERSION_STATES
            or not isinstance(requires, bool)
        ):
            return None
        identity = (memory_id, content_sha)
        if identity in identities:
            return None
        identities.add(identity)
        normalized.append(item)
    return normalized


def _nonnegative_db_integer(value: object, *, allow_none: bool = True) -> bool:
    if value is None:
        return allow_none
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _search_control_row_valid(row: dict[str, Any]) -> bool:
    search_id = str(row.get("search_id") or "")
    actor = str(row.get("actor") or "")
    task_id = str(row.get("task_id") or "")
    event_source = str(row.get("event_source") or "")
    returned_ids = _hash_list(
        row.get("returned_memory_ids_json"),
        allow_empty_storage=not bool(search_id),
    )
    metadata_count = row.get("metadata_would_block_count")
    metadata_fingerprint = str(row.get("metadata_reason_fingerprint") or "")
    task_binding_valid = (
        not task_id and not actor and not event_source
    ) or (
        _is_sha256(task_id)
        and actor in OBSERVABILITY_ACTOR_VALUES
        and event_source == "tool_observed"
    )
    return bool(
        str(row.get("sources") or "") in SEARCH_LOG_CANONICAL_SOURCES
        and str(row.get("search_status") or "") in SEARCH_LOG_STATUS_VALUES
        and _is_sha256(row.get("query_sha256"), allow_empty=True)
        and _is_sha256(row.get("v1_result_fingerprint"), allow_empty=True)
        and _is_sha256(row.get("v2_result_fingerprint"), allow_empty=True)
        and _is_sha256(metadata_fingerprint, allow_empty=True)
        and (not search_id or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", search_id))
        and task_binding_valid
        and _nonnegative_db_integer(row.get("result_count"), allow_none=False)
        and _nonnegative_db_integer(row.get("query_length"))
        and _nonnegative_db_integer(row.get("duration_ms"))
        and _is_controlled_timestamp(row.get("created_at"))
        and str(row.get("ranking_mode") or "") in {"hybrid_v2", "legacy_v1", "shadow"}
        and str(row.get("worker_status") or "")
        in {"degraded", "failed", "not_used", "restarted", "reused", "started"}
        and row.get("worker_restart_count") in {0, 1}
        and _nonnegative_db_integer(row.get("required_case_regression_count"), allow_none=False)
        and str(row.get("metadata_gate_mode") or "") in {"shadow", "enforce"}
        and _nonnegative_db_integer(metadata_count, allow_none=False)
        and ((metadata_count == 0 and not metadata_fingerprint)
             or (isinstance(metadata_count, int) and metadata_count > 0 and bool(metadata_fingerprint)))
        and returned_ids is not None
        and (
            not search_id
            or (
                _is_sha256(row.get("query_sha256"))
                and row.get("returned_memory_ids_json") not in {None, ""}
                and str(row.get("search_status") or "") != "legacy_unknown"
            )
        )
    )


def _event_control_row_valid(row: dict[str, Any]) -> bool:
    event_type = str(row.get("event_type") or "")
    source = str(row.get("source") or "")
    value = str(row.get("value") or "")
    memory_ids_list = _hash_list(row.get("memory_ids_json"), allow_empty_storage=False)
    if memory_ids_list is None:
        return False
    versions = _version_list(row.get("memory_versions_json"), set(memory_ids_list))
    if versions is None:
        return False
    version_contents = {str(item["content_sha256"]) for item in versions}
    requires = any(bool(item["requires_live_verification"]) for item in versions)
    labeler_hash = str(row.get("labeler_ref_sha256") or "")
    labeler_length = row.get("labeler_ref_length")
    content_sha = str(row.get("content_sha256") or "")
    exact_version_required = event_type in {"live_verified", "source_opened"} or (
        event_type in {"adoption", "adoption_declared"} and value == "adopted"
    )
    return bool(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{7,159}", str(row.get("event_id") or ""))
        and str(row.get("actor") or "") in OBSERVABILITY_ACTOR_VALUES
        and _is_sha256(row.get("task_id"))
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,159}", str(row.get("runtime_version") or ""))
        and event_type in OBSERVABILITY_EVENT_VALUES
        and source in OBSERVABILITY_EVENT_SOURCES.get(event_type, ())
        and value in OBSERVABILITY_EVENT_VALUES.get(event_type, ())
        and str(row.get("reason_code") or "") in OBSERVABILITY_REASON_VALUES
        and str(row.get("confidence") or "") in OBSERVABILITY_CONFIDENCE_VALUES
        and str(row.get("read_mode") or "") in OBSERVABILITY_READ_MODE_VALUES
        and str(row.get("task_class") or "") in OBSERVABILITY_TASK_CLASS_VALUES
        and _is_controlled_timestamp(row.get("created_at"))
        and _is_sha256(content_sha, allow_empty=True)
        and (not content_sha or content_sha in version_contents)
        and _is_sha256(labeler_hash, allow_empty=True)
        and _nonnegative_db_integer(labeler_length, allow_none=False)
        and ((labeler_length == 0 and not labeler_hash)
             or (isinstance(labeler_length, int) and labeler_length > 0 and bool(labeler_hash)))
        and all(
            _nonnegative_db_integer(row.get(field))
            for field in (
                "result_count",
                "required_live_verification_count",
                "full_utf8_bytes",
                "returned_utf8_bytes",
                "page_count",
            )
        )
        and row.get("truncated") in {None, 0, 1}
        and row.get("requires_live_verification") in {0, 1}
        and bool(row.get("requires_live_verification")) == requires
        and (
            not exact_version_required
            or bool(versions) and all(bool(item["content_sha256"]) for item in versions)
        )
    )


def search_log_privacy_guard_report(conn: sqlite3.Connection) -> dict[str, Any]:
    """Inspect database-enforced search-log privacy without mutating schema.

    ``query`` and ``used_paths`` must both be empty.  Hashes and lengths retain
    the useful telemetry.  ``sources`` and ``search_status`` are also treated
    as privacy boundaries: accepting arbitrary strings there would create a
    second place where query text, paths, or URLs could be smuggled into the
    state database.
    """

    tables = {
        str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    search_columns = (
        {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_search_log)")}
        if "memory_search_log" in tables
        else set()
    )
    required_search_columns = {
        "actor", "created_at", "duration_ms", "event_source",
        "metadata_gate_mode", "metadata_reason_fingerprint",
        "metadata_would_block_count", "query", "query_length", "query_sha256",
        "ranking_mode", "required_case_regression_count", "result_count",
        "returned_memory_ids_json", "search_id", "search_status", "sources",
        "task_id", "used_paths", "v1_result_fingerprint", "v2_result_fingerprint",
        "worker_restart_count", "worker_status",
    }
    event_columns = (
        {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_use_events)")}
        if "memory_use_events" in tables
        else set()
    )
    required_event_columns = {
        "actor", "confidence", "content_sha256", "created_at", "event_id",
        "event_type", "full_utf8_bytes", "labeler_ref_length", "labeler_ref_sha256",
        "memory_ids_json", "memory_versions_json", "page_count", "read_mode",
        "reason_code", "required_live_verification_count",
        "requires_live_verification", "result_count", "returned_utf8_bytes",
        "runtime_version", "source", "task_class", "task_id", "truncated", "value",
    }
    missing_columns = sorted(required_search_columns - search_columns)
    missing_event_columns = sorted(required_event_columns - event_columns)
    trigger_rows = {
        str(row[0]): str(row[1] or "")
        for row in conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='trigger'"
        )
        if str(row[0]) in SEARCH_LOG_PRIVACY_TRIGGER_SQL
    }
    missing = sorted(set(SEARCH_LOG_PRIVACY_TRIGGER_SQL) - set(trigger_rows))
    drifted = sorted(
        name
        for name, expected in SEARCH_LOG_PRIVACY_TRIGGER_SQL.items()
        if name in trigger_rows and _normalized_sql(trigger_rows[name]) != _normalized_sql(expected)
    )
    version = ""
    if "meta" in tables:
        row = conn.execute(
            "SELECT value FROM meta WHERE key='memory_search_privacy_guard_version'"
        ).fetchone()
        version = str(row[0]) if row is not None else ""
    raw_query_rows = 0
    path_rows = 0
    invalid_source_rows = 0
    invalid_search_status_rows = 0
    invalid_search_control_rows = 0
    invalid_event_control_rows = 0
    if "memory_search_log" in tables and not missing_columns:
        raw_query_rows = int(
            conn.execute(
                "SELECT COUNT(*) FROM memory_search_log WHERE coalesce(query, '')<>''"
            ).fetchone()[0]
        )
        path_rows = int(
            conn.execute(
                "SELECT COUNT(*) FROM memory_search_log WHERE coalesce(used_paths, '')<>''"
            ).fetchone()[0]
        )
        selected = sorted(required_search_columns)
        rows = conn.execute(
            f"SELECT {', '.join(selected)} FROM memory_search_log"
        ).fetchall()
        mapped_rows = [dict(zip(selected, row)) for row in rows]
        invalid_source_rows = sum(
            1
            for row in mapped_rows
            if str(row["sources"] or "") not in SEARCH_LOG_CANONICAL_SOURCES
        )
        invalid_search_status_rows = sum(
            1
            for row in mapped_rows
            if str(row["search_status"] or "") not in SEARCH_LOG_STATUS_VALUES
        )
        invalid_search_control_rows = sum(
            1 for row in mapped_rows if not _search_control_row_valid(row)
        )
    if "memory_use_events" in tables and not missing_event_columns:
        selected = sorted(required_event_columns)
        rows = conn.execute(
            f"SELECT {', '.join(selected)} FROM memory_use_events"
        ).fetchall()
        invalid_event_control_rows = sum(
            1
            for raw in rows
            if not _event_control_row_valid(dict(zip(selected, raw)))
        )
    if invalid_source_rows:
        drifted.append("memory_search_log.sources_enum_rows")
    if invalid_search_status_rows:
        drifted.append("memory_search_log.search_status_enum_rows")
    if invalid_search_control_rows:
        drifted.append("memory_search_log.control_rows")
    if invalid_event_control_rows:
        drifted.append("memory_use_events.control_rows")
    drifted.sort()
    ready = bool(
        {"memory_search_log", "memory_use_events"}.issubset(tables)
        and not missing_columns
        and not missing_event_columns
        and not missing
        and not drifted
        and version == SEARCH_LOG_PRIVACY_GUARD_VERSION
        and raw_query_rows == 0
        and path_rows == 0
        and invalid_source_rows == 0
        and invalid_search_status_rows == 0
        and invalid_search_control_rows == 0
        and invalid_event_control_rows == 0
    )
    return {
        "ready": ready,
        "version": version,
        "required_version": SEARCH_LOG_PRIVACY_GUARD_VERSION,
        "missing": missing,
        "drifted": drifted,
        "missing_columns": missing_columns,
        "missing_event_columns": missing_event_columns,
        "raw_query_rows": raw_query_rows,
        "path_rows": path_rows,
        "invalid_source_rows": invalid_source_rows,
        "invalid_search_status_rows": invalid_search_status_rows,
        "invalid_search_control_rows": invalid_search_control_rows,
        "invalid_event_control_rows": invalid_event_control_rows,
    }


def drop_search_log_privacy_guards(conn: sqlite3.Connection) -> None:
    """Migration-only removal used inside the backed-up state transaction."""

    for name in SEARCH_LOG_PRIVACY_TRIGGER_SQL:
        conn.execute(f"DROP TRIGGER IF EXISTS {name}")


def install_search_log_privacy_guards(conn: sqlite3.Connection) -> None:
    """Install exact search-log privacy guards during explicit state migration."""

    tables = {
        str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    if not {"meta", "memory_search_log", "memory_use_events"}.issubset(tables):
        raise sqlite3.OperationalError("STATE_SCHEMA_MIGRATION_REQUIRED")
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_search_log)")}
    if not {"query", "used_paths", "query_sha256", "sources", "search_status"}.issubset(columns):
        raise sqlite3.OperationalError("STATE_SCHEMA_MIGRATION_REQUIRED")

    # The installer calls this only inside its already-backed-up migration
    # transaction.  Older releases retained a short ``[redacted:...]`` marker
    # in ``query``; v4 keeps only the existing full hash and length instead.
    # Refuse to erase an un-hashed value so a broken migration cannot silently
    # destroy the sole remaining provenance metadata.
    nonempty_queries = conn.execute(
        "SELECT query_sha256 FROM memory_search_log WHERE coalesce(query, '')<>''"
    ).fetchall()
    if any(re.fullmatch(r"[0-9a-f]{64}", str(row[0] or "")) is None for row in nonempty_queries):
        raise sqlite3.IntegrityError(SEARCH_LOG_PRIVACY_REASON_CODE)
    conn.execute("UPDATE memory_search_log SET query='' WHERE coalesce(query, '')<>''")

    # Pre-v4 rows did not have these columns.  Map only the unambiguous blank
    # legacy value; arbitrary non-empty strings remain visible as migration
    # blockers rather than being silently normalized.
    conn.execute(
        "UPDATE memory_search_log SET sources='legacy_unknown' "
        "WHERE coalesce(trim(sources), '')=''"
    )
    conn.execute(
        "UPDATE memory_search_log SET search_status='legacy_unknown' "
        "WHERE coalesce(trim(search_status), '')=''"
    )
    report = search_log_privacy_guard_report(conn)
    if report["raw_query_rows"] or report["path_rows"]:
        raise sqlite3.IntegrityError(SEARCH_LOG_PRIVACY_REASON_CODE)
    if (
        report["invalid_source_rows"]
        or report["invalid_search_status_rows"]
        or report["invalid_search_control_rows"]
        or report["invalid_event_control_rows"]
        or report["missing_columns"]
        or report["missing_event_columns"]
    ):
        raise sqlite3.IntegrityError(SEARCH_LOG_CONTROL_REASON_CODE)
    drop_search_log_privacy_guards(conn)
    for sql in SEARCH_LOG_PRIVACY_TRIGGER_SQL.values():
        conn.execute(sql)
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
        ("memory_search_privacy_guard_version", SEARCH_LOG_PRIVACY_GUARD_VERSION),
    )


def absolute_path(raw_path: str | os.PathLike[str]) -> Path:
    """Return an absolute path without resolving away the final symlink."""

    return Path(os.path.abspath(os.path.expanduser(os.fspath(raw_path))))


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def _assert_directory(path: Path) -> None:
    if path.is_symlink():
        raise StateSecurityError(f"private directory must not be a symlink: {path}")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(metadata.st_mode):
        raise StateSecurityError(f"private directory path is not a directory: {path}")


def ensure_private_directory(
    raw_path: str | os.PathLike[str],
    *,
    harden_existing: bool = False,
) -> Path:
    """Create every missing directory with mode 0700.

    Existing ancestors are left unchanged unless ``harden_existing`` is true for
    the requested leaf. The requested leaf itself may never be a symlink.
    """

    path = absolute_path(raw_path)
    missing: list[Path] = []
    cursor = path
    while True:
        if cursor.is_symlink():
            raise StateSecurityError(f"private directory must not be a symlink: {cursor}")
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            missing.append(cursor)
            parent = cursor.parent
            if parent == cursor:
                raise StateSecurityError(f"cannot locate an existing parent for: {path}")
            cursor = parent
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise StateSecurityError(f"private directory ancestor is not a directory: {cursor}")
        break

    for directory in reversed(missing):
        try:
            os.mkdir(directory, PRIVATE_DIRECTORY_MODE)
        except FileExistsError:
            _assert_directory(directory)
        if POSIX_PERMISSION_MODEL:
            os.chmod(directory, PRIVATE_DIRECTORY_MODE, follow_symlinks=False)

    _assert_directory(path)
    if harden_existing and POSIX_PERMISSION_MODEL:
        os.chmod(path, PRIVATE_DIRECTORY_MODE, follow_symlinks=False)
    return path


def relative_beneath(root: str | os.PathLike[str], path: str | os.PathLike[str]) -> Path:
    root_path = absolute_path(root)
    candidate = absolute_path(path)
    try:
        relative = candidate.relative_to(root_path)
    except ValueError as exc:
        raise StateSecurityError(f"path is outside private root: {candidate}") from exc
    if relative.is_absolute() or ".." in relative.parts:
        raise StateSecurityError(f"unsafe relative private path: {relative}")
    return relative


def assert_no_symlink_path(
    path: str | os.PathLike[str],
    *,
    include_leaf: bool = True,
    allow_missing: bool = False,
) -> Path:
    """Reject a symlink or non-directory in every lexical absolute component."""

    candidate = absolute_path(path)
    components = [*reversed(candidate.parents)]
    if include_leaf:
        components.append(candidate)
    for index, component in enumerate(components):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            if allow_missing:
                return candidate
            raise StateSecurityError(f"private path component is missing: {component}")
        if stat.S_ISLNK(metadata.st_mode):
            raise StateSecurityError(f"private path component must not be a symlink: {component}")
        is_allowed_leaf = include_leaf and index == len(components) - 1
        if not is_allowed_leaf and not stat.S_ISDIR(metadata.st_mode):
            raise StateSecurityError(f"private path ancestor is not a directory: {component}")
    return candidate


def assert_no_symlink_beneath(
    root: str | os.PathLike[str],
    path: str | os.PathLike[str],
    *,
    include_leaf: bool = True,
    allow_missing: bool = False,
) -> Path:
    """Lstat every lexical component instead of resolving symlinks away."""

    root_path = absolute_path(root)
    assert_no_symlink_path(root_path, include_leaf=True, allow_missing=allow_missing)
    relative = relative_beneath(root_path, path)
    components = relative.parts if include_leaf else relative.parts[:-1]
    try:
        root_metadata = root_path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return relative
        raise StateSecurityError(f"private path component is missing: {root_path}")
    if stat.S_ISLNK(root_metadata.st_mode):
        raise StateSecurityError(f"private path component must not be a symlink: {root_path}")
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise StateSecurityError(f"private path ancestor is not a directory: {root_path}")
    cursor = root_path
    for index, part in enumerate(components):
        cursor = cursor / part
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            if allow_missing:
                return relative
            raise StateSecurityError(f"private path component is missing: {cursor}")
        if stat.S_ISLNK(metadata.st_mode):
            raise StateSecurityError(f"private path component must not be a symlink: {cursor}")
        is_allowed_leaf = include_leaf and index == len(components) - 1
        if not is_allowed_leaf and not stat.S_ISDIR(metadata.st_mode):
            raise StateSecurityError(f"private path ancestor is not a directory: {cursor}")
    return relative


@contextlib.contextmanager
def secure_open_regular_beneath(
    root: str | os.PathLike[str],
    relative: str | os.PathLike[str],
) -> Iterator[BinaryIO]:
    """Open one regular file through pinned O_NOFOLLOW directory descriptors."""

    root_path = absolute_path(root)
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or ".." in rel.parts:
        raise StateSecurityError(f"unsafe runtime relative path: {rel}")
    target = root_path / rel
    assert_no_symlink_beneath(root_path, target, include_leaf=True)
    if not POSIX_PERMISSION_MODEL:
        with target.open("rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise StateSecurityError(f"private runtime file is not regular: {target}")
            yield handle
        return
    directory_fd = os.open(
        root_path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        for part in rel.parts[:-1]:
            child_fd = os.open(
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = child_fd
        descriptor = os.open(
            rel.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise StateSecurityError(f"private runtime file is not regular: {target}")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            yield handle
    finally:
        os.close(directory_fd)


def secure_read_bytes_beneath(root: str | os.PathLike[str], relative: str | os.PathLike[str]) -> bytes:
    with secure_open_regular_beneath(root, relative) as handle:
        return handle.read()


def secure_read_bytes_and_stat_beneath(
    root: str | os.PathLike[str],
    relative: str | os.PathLike[str],
) -> tuple[bytes, os.stat_result]:
    with secure_open_regular_beneath(root, relative) as handle:
        metadata = os.fstat(handle.fileno())
        return handle.read(), metadata


def secure_sha256_beneath(root: str | os.PathLike[str], relative: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with secure_open_regular_beneath(root, relative) as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _open_pinned_directory(root_path: Path, relative_parent: Path) -> int:
    root_path = absolute_path(root_path)
    if not root_path.is_absolute():
        raise StateSecurityError(f"private root must be absolute: {root_path}")
    anchor = Path(root_path.anchor)
    descriptor = os.open(
        anchor,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        # Walk the absolute root itself through pinned no-follow descriptors,
        # then continue to the relative parent. This closes the ancestor-swap
        # window left by opening an absolute multi-component root in one call.
        root_parts = root_path.parts[1:] if root_path.anchor else root_path.parts
        for part in (*root_parts, *relative_parent.parts):
            child = os.open(
                part,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def secure_atomic_write_bytes_beneath(
    root: str | os.PathLike[str],
    relative: str | os.PathLike[str],
    payload: bytes,
    *,
    mode: int = PRIVATE_FILE_MODE,
) -> Path:
    """Atomically publish bytes without traversing a runtime symlink.

    Failed staging files are intentionally retained under the private parent so
    an interrupted migration never needs an automatic delete operation.
    """

    root_path = absolute_path(root)
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or ".." in rel.parts:
        raise StateSecurityError(f"unsafe runtime relative path: {rel}")
    target = root_path / rel
    ensure_private_directory(root_path, harden_existing=True)
    ensure_private_directory(target.parent, harden_existing=True)
    assert_no_symlink_beneath(root_path, target, include_leaf=False)
    temporary_name = f".{rel.name}.publish-{os.getpid()}-{secrets.token_hex(12)}"

    if not POSIX_PERMISSION_MODEL:
        temporary = target.parent / temporary_name
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        assert_no_symlink_beneath(root_path, target, include_leaf=False)
        try:
            leaf = target.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(leaf.st_mode) or not stat.S_ISREG(leaf.st_mode):
                raise StateSecurityError(f"private runtime file is not regular: {target}")
        os.replace(temporary, target)
        return target

    parent_fd = _open_pinned_directory(root_path, rel.parent)
    try:
        try:
            existing = os.stat(rel.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode):
                raise StateSecurityError(f"private runtime file is not regular: {target}")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary_name, flags, mode, dir_fd=parent_fd)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            if POSIX_PERMISSION_MODEL:
                os.fchmod(handle.fileno(), mode)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # Recheck the destination after staging; os.replace then operates on
        # the already pinned directory descriptor rather than a path string.
        try:
            existing = os.stat(rel.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode):
                raise StateSecurityError(f"private runtime file is not regular: {target}")
        os.replace(
            temporary_name,
            rel.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        try:
            os.fsync(parent_fd)
        except OSError:
            # Publication already committed at replace(). Directory fsync is a
            # durability enhancement unavailable on some POSIX filesystems.
            pass
    finally:
        os.close(parent_fd)
    return target


def _conditional_sidecar_names(
    relative: Path,
    *,
    namespace: str,
    operation_id: str,
) -> tuple[str, str, str, str]:
    if (
        not namespace
        or len(namespace) > 24
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in namespace)
        or len(operation_id) != 64
        or any(character not in "0123456789abcdef" for character in operation_id)
    ):
        raise ConditionalWriteError("CONDITIONAL_WRITE_INVALID")
    target_id = hashlib.sha256(relative.as_posix().encode("utf-8")).hexdigest()[:24]
    prefix = f".agent-memory-{namespace}-cas-{target_id}-"
    operation_prefix = f"{prefix}{operation_id}"
    return (
        prefix,
        f"{operation_prefix}.proposal",
        f"{operation_prefix}.displaced",
        f"{operation_prefix}.recovery",
    )


@contextlib.contextmanager
def _windows_pinned_directory_chain(path: Path) -> Iterator[None]:
    """Prevent replacement of a Windows directory chain during path APIs.

    Windows lacks the dir_fd variants used below on POSIX. Open every lexical
    directory without FILE_SHARE_DELETE and reject reparse points so the full
    path consumed by ReplaceFileW cannot be redirected while the handles live.
    """

    if os.name != "nt":
        yield
        return
    from ctypes import wintypes

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    get_attributes = ctypes.WinDLL("kernel32", use_last_error=True).GetFileAttributesW
    get_attributes.argtypes = [wintypes.LPCWSTR]
    get_attributes.restype = wintypes.DWORD

    file_read_attributes = 0x0080
    file_share_read = 0x00000001
    file_share_write = 0x00000002
    open_existing = 3
    file_flag_backup_semantics = 0x02000000
    file_flag_open_reparse_point = 0x00200000
    file_attribute_directory = 0x00000010
    file_attribute_reparse_point = 0x00000400
    invalid_attributes = 0xFFFFFFFF
    invalid_handle = ctypes.c_void_p(-1).value

    candidate = absolute_path(path)
    chain = [*reversed(candidate.parents), candidate]
    handles: list[int] = []
    try:
        for directory in chain:
            attributes = int(get_attributes(str(directory)))
            if (
                attributes == invalid_attributes
                or not attributes & file_attribute_directory
                or attributes & file_attribute_reparse_point
            ):
                raise ConditionalWriteError("CONDITIONAL_WRITE_UNSAFE")
            handle = create_file(
                str(directory),
                file_read_attributes,
                file_share_read | file_share_write,
                None,
                open_existing,
                file_flag_backup_semantics | file_flag_open_reparse_point,
                None,
            )
            if handle == invalid_handle:
                raise ConditionalWriteError("CONDITIONAL_WRITE_UNSAFE")
            handles.append(handle)
        yield
    finally:
        for handle in reversed(handles):
            close_handle(handle)


@contextlib.contextmanager
def _conditional_parent(
    root_path: Path,
    relative: Path,
) -> Iterator[tuple[int | None, Path]]:
    target_parent = root_path / relative.parent
    assert_no_symlink_beneath(root_path, target_parent, include_leaf=True)
    if POSIX_PERMISSION_MODEL:
        descriptor = _open_pinned_directory(root_path, relative.parent)
        try:
            yield descriptor, target_parent
        finally:
            os.close(descriptor)
        return
    with _windows_pinned_directory_chain(target_parent):
        assert_no_symlink_beneath(root_path, target_parent, include_leaf=True)
        yield None, target_parent


def _conditional_directory_entries(parent_fd: int | None, parent: Path) -> set[str]:
    try:
        return set(os.listdir(parent_fd if parent_fd is not None else parent))
    except OSError as exc:
        raise ConditionalWriteError("CONDITIONAL_WRITE_UNSAFE") from exc


def _conditional_recovery_entries(
    parent_fd: int | None,
    parent: Path,
    prefix: str,
) -> tuple[str, ...]:
    return tuple(
        sorted(name for name in _conditional_directory_entries(parent_fd, parent) if name.startswith(prefix))
    )


def secure_conditional_recovery_entries_beneath(
    root: str | os.PathLike[str],
    relative: str | os.PathLike[str],
    *,
    namespace: str,
) -> tuple[str, ...]:
    """List unresolved CAS artifacts for one target without mutating them."""

    root_path = absolute_path(root)
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or ".." in rel.parts:
        raise ConditionalWriteError("CONDITIONAL_WRITE_INVALID")
    # The operation id does not affect the target-specific recovery prefix.
    prefix = _conditional_sidecar_names(
        rel,
        namespace=namespace,
        operation_id="0" * 64,
    )[0]
    with _conditional_parent(root_path, rel) as (parent_fd, parent):
        return _conditional_recovery_entries(parent_fd, parent, prefix)


def _conditional_open_read(
    parent_fd: int | None,
    parent: Path,
    name: str,
    *,
    max_bytes: int,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = (
            os.open(name, flags, dir_fd=parent_fd)
            if parent_fd is not None
            else os.open(parent / name, flags)
        )
    except OSError as exc:
        raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 0
            or metadata.st_size > max_bytes
        ):
            raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED")
        return payload, metadata
    finally:
        os.close(descriptor)


def _conditional_create(
    parent_fd: int | None,
    parent: Path,
    name: str,
    payload: bytes,
    *,
    mode: int,
) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = (
            os.open(name, flags, mode, dir_fd=parent_fd)
            if parent_fd is not None
            else os.open(parent / name, flags, mode)
        )
    except OSError as exc:
        raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED") from exc
    try:
        if POSIX_PERMISSION_MODEL:
            os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("conditional write made no progress")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED") from exc
    finally:
        os.close(descriptor)


def _conditional_unlink_exact(
    parent_fd: int | None,
    parent: Path,
    name: str,
    expected: bytes,
) -> None:
    payload, opened = _conditional_open_read(
        parent_fd,
        parent,
        name,
        max_bytes=len(expected),
    )
    try:
        current = (
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if parent_fd is not None
            else (parent / name).lstat()
        )
    except OSError as exc:
        raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED") from exc
    if (
        payload != expected
        or not stat.S_ISREG(current.st_mode)
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED")
    try:
        if parent_fd is not None:
            os.unlink(name, dir_fd=parent_fd)
        else:
            os.unlink(parent / name)
    except OSError as exc:
        raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED") from exc


def _conditional_fsync_parent(parent_fd: int | None, parent: Path) -> None:
    if parent_fd is None:
        return
    try:
        os.fsync(parent_fd)
    except OSError as exc:
        raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED") from exc


def _conditional_atomic_exchange(parent_fd: int, first: str, second: str) -> None:
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        rename_swap = getattr(libc, "renameatx_np", None)
        if rename_swap is None:
            raise ConditionalWriteError("CONDITIONAL_WRITE_UNAVAILABLE")
        rename_swap.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_swap.restype = ctypes.c_int
        result = rename_swap(
            parent_fd,
            os.fsencode(first),
            parent_fd,
            os.fsencode(second),
            0x00000002,
        )
    elif sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        rename_swap = getattr(libc, "renameat2", None)
        if rename_swap is None:
            raise ConditionalWriteError("CONDITIONAL_WRITE_UNAVAILABLE")
        rename_swap.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_swap.restype = ctypes.c_int
        result = rename_swap(
            parent_fd,
            os.fsencode(first),
            parent_fd,
            os.fsencode(second),
            0x00000002,
        )
    else:
        raise ConditionalWriteError("CONDITIONAL_WRITE_UNAVAILABLE")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {
        errno.ENOSYS,
        errno.EINVAL,
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }:
        raise ConditionalWriteError("CONDITIONAL_WRITE_UNAVAILABLE")
    raise OSError(error_number, os.strerror(error_number))


def _conditional_atomic_rename_noreplace(
    source_fd: int | None,
    source_parent: Path,
    source_name: str,
    destination_fd: int | None,
    destination_parent: Path,
    destination_name: str,
) -> None:
    """Atomically move one name without ever replacing the destination."""

    if source_fd is not None and destination_fd is not None:
        libc = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin":
            rename = getattr(libc, "renameatx_np", None)
            flag = 0x00000004  # RENAME_EXCL
        elif sys.platform.startswith("linux"):
            rename = getattr(libc, "renameat2", None)
            flag = 0x00000001  # RENAME_NOREPLACE
        else:
            rename = None
            flag = 0
        if rename is None:
            raise ConditionalWriteError("CONDITIONAL_WRITE_UNAVAILABLE")
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(
            source_fd,
            os.fsencode(source_name),
            destination_fd,
            os.fsencode(destination_name),
            flag,
        )
        if result == 0:
            return
        error_number = ctypes.get_errno()
        if error_number in {
            errno.ENOSYS,
            errno.EINVAL,
            getattr(errno, "ENOTSUP", errno.EINVAL),
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        }:
            raise ConditionalWriteError("CONDITIONAL_WRITE_UNAVAILABLE")
        raise OSError(error_number, os.strerror(error_number))
    if os.name != "nt":
        raise ConditionalWriteError("CONDITIONAL_WRITE_UNAVAILABLE")
    # Windows rename is no-replace by default. The directory-chain handles
    # held by `_conditional_parent` prevent either parent from being rebound.
    os.rename(
        source_parent / source_name,
        destination_parent / destination_name,
    )


def secure_conditional_move_bytes_beneath(
    source_root: str | os.PathLike[str],
    source_relative: str | os.PathLike[str],
    destination_root: str | os.PathLike[str],
    destination_relative: str | os.PathLike[str],
    *,
    expected_sha256: str,
    expected_size: int,
    max_capture_bytes: int,
) -> Path:
    """Move exact bytes to an unused recovery name without deleting races.

    The no-replace rename may capture a concurrently replaced source inode.
    Such an inode is inspected at the destination and atomically restored when
    the source name is still free. If restoration races too, both names are
    retained and the caller receives ``RECOVERY_REQUIRED``; user bytes are
    never overwritten or unlinked.
    """

    source_root_path = absolute_path(source_root)
    destination_root_path = absolute_path(destination_root)
    source_rel = Path(source_relative)
    destination_rel = Path(destination_relative)
    if (
        source_rel.is_absolute()
        or destination_rel.is_absolute()
        or not source_rel.parts
        or not destination_rel.parts
        or ".." in source_rel.parts
        or ".." in destination_rel.parts
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
        or expected_size < 0
        or max_capture_bytes < expected_size
    ):
        raise ConditionalWriteError("CONDITIONAL_WRITE_INVALID")
    source = source_root_path / source_rel
    destination = destination_root_path / destination_rel
    assert_no_symlink_beneath(source_root_path, source, include_leaf=True)
    assert_no_symlink_beneath(
        destination_root_path,
        destination,
        include_leaf=False,
    )
    with contextlib.ExitStack() as stack:
        source_fd, source_parent = stack.enter_context(
            _conditional_parent(source_root_path, source_rel)
        )
        destination_fd, destination_parent = stack.enter_context(
            _conditional_parent(destination_root_path, destination_rel)
        )
        try:
            current, _ = _conditional_open_read(
                source_fd,
                source_parent,
                source_rel.name,
                max_bytes=max_capture_bytes,
            )
        except ConditionalWriteError as exc:
            raise ConditionalWriteError("CONDITIONAL_WRITE_TARGET_CHANGED") from exc
        if (
            len(current) != expected_size
            or hashlib.sha256(current).hexdigest() != expected_sha256
        ):
            raise ConditionalWriteError("CONDITIONAL_WRITE_TARGET_CHANGED")
        try:
            if destination_fd is not None:
                os.stat(
                    destination_rel.name,
                    dir_fd=destination_fd,
                    follow_symlinks=False,
                )
            else:
                destination.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ConditionalWriteError("CONDITIONAL_WRITE_UNSAFE") from exc
        else:
            raise ConditionalWriteError("CONDITIONAL_WRITE_TARGET_CHANGED")

        try:
            _conditional_atomic_rename_noreplace(
                source_fd,
                source_parent,
                source_rel.name,
                destination_fd,
                destination_parent,
                destination_rel.name,
            )
        except FileExistsError as exc:
            raise ConditionalWriteError("CONDITIONAL_WRITE_TARGET_CHANGED") from exc
        except OSError as exc:
            if exc.errno in {errno.EEXIST, errno.ENOENT}:
                raise ConditionalWriteError("CONDITIONAL_WRITE_TARGET_CHANGED") from exc
            raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED") from exc
        _conditional_fsync_parent(source_fd, source_parent)
        if destination_fd != source_fd:
            _conditional_fsync_parent(destination_fd, destination_parent)

        moved, _ = _conditional_open_read(
            destination_fd,
            destination_parent,
            destination_rel.name,
            max_bytes=max_capture_bytes,
        )
        if (
            len(moved) == expected_size
            and hashlib.sha256(moved).hexdigest() == expected_sha256
        ):
            return destination

        try:
            _conditional_atomic_rename_noreplace(
                destination_fd,
                destination_parent,
                destination_rel.name,
                source_fd,
                source_parent,
                source_rel.name,
            )
            _conditional_fsync_parent(source_fd, source_parent)
            if destination_fd != source_fd:
                _conditional_fsync_parent(destination_fd, destination_parent)
            restored, _ = _conditional_open_read(
                source_fd,
                source_parent,
                source_rel.name,
                max_bytes=max_capture_bytes,
            )
            if restored != moved:
                raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED")
        except (OSError, ConditionalWriteError) as exc:
            raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED") from exc
        raise ConditionalWriteError("CONDITIONAL_WRITE_TARGET_CHANGED")


def _conditional_windows_replace(
    parent: Path,
    *,
    target: str,
    replacement: str,
    backup: str,
) -> None:
    if os.name != "nt":
        raise ConditionalWriteError("CONDITIONAL_WRITE_UNAVAILABLE")
    replace_file = ctypes.WinDLL("kernel32", use_last_error=True).ReplaceFileW
    replace_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    replace_file.restype = ctypes.c_int
    if replace_file(
        str(parent / target),
        str(parent / replacement),
        str(parent / backup),
        0x00000001,
        None,
        None,
    ):
        return
    error_number = ctypes.get_last_error()
    raise OSError(error_number, os.strerror(error_number))


def _conditional_capture(
    parent_fd: int | None,
    parent: Path,
    *,
    target: str,
    proposal: str,
    displaced: str,
) -> str:
    if parent_fd is not None:
        _conditional_atomic_exchange(parent_fd, proposal, target)
        return proposal
    _conditional_windows_replace(
        parent,
        target=target,
        replacement=proposal,
        backup=displaced,
    )
    return displaced


def _conditional_restore(
    parent_fd: int | None,
    parent: Path,
    *,
    target: str,
    captured: str,
    proposal: str,
) -> str:
    if parent_fd is not None:
        _conditional_atomic_exchange(parent_fd, captured, target)
        return captured
    _conditional_windows_replace(
        parent,
        target=target,
        replacement=captured,
        backup=proposal,
    )
    return proposal


def secure_conditional_write_bytes_beneath(
    root: str | os.PathLike[str],
    relative: str | os.PathLike[str],
    payload: bytes,
    *,
    expected_sha256: str,
    expected_size: int,
    operation_id: str,
    namespace: str,
    max_capture_bytes: int,
    mode: int = PRIVATE_FILE_MODE,
) -> Path:
    """Atomically replace exact expected bytes beneath a pinned private root.

    A raced destination is exchanged back after its bytes are captured. Any
    uncertain recovery leaves deterministic sidecars and every later plan or
    apply must fail closed until an operator resolves them.
    """

    root_path = absolute_path(root)
    rel = Path(relative)
    if (
        rel.is_absolute()
        or not rel.parts
        or ".." in rel.parts
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
        or expected_size < 0
        or max_capture_bytes < expected_size
        or len(payload) > max_capture_bytes
    ):
        raise ConditionalWriteError("CONDITIONAL_WRITE_INVALID")
    target = root_path / rel
    assert_no_symlink_beneath(root_path, target, include_leaf=True)
    prefix, proposal, displaced, recovery = _conditional_sidecar_names(
        rel,
        namespace=namespace,
        operation_id=operation_id,
    )
    with _conditional_parent(root_path, rel) as (parent_fd, parent):
        unresolved = _conditional_recovery_entries(parent_fd, parent, prefix)
        if unresolved:
            raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED")
        current, _ = _conditional_open_read(
            parent_fd,
            parent,
            rel.name,
            max_bytes=max_capture_bytes,
        )
        if len(current) != expected_size or hashlib.sha256(current).hexdigest() != expected_sha256:
            raise ConditionalWriteError("CONDITIONAL_WRITE_TARGET_CHANGED")

        proposal_created = False
        captured = False
        captured_name = ""
        try:
            _conditional_create(parent_fd, parent, proposal, payload, mode=mode)
            proposal_created = True
            _conditional_fsync_parent(parent_fd, parent)
            if _conditional_recovery_entries(parent_fd, parent, prefix) != (proposal,):
                raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED")
            captured_name = _conditional_capture(
                parent_fd,
                parent,
                target=rel.name,
                proposal=proposal,
                displaced=displaced,
            )
            captured = True
            _conditional_fsync_parent(parent_fd, parent)
            captured_payload, _ = _conditional_open_read(
                parent_fd,
                parent,
                captured_name,
                max_bytes=max_capture_bytes,
            )
            captured_matches = (
                len(captured_payload) == expected_size
                and hashlib.sha256(captured_payload).hexdigest() == expected_sha256
            )
            if captured_matches:
                _conditional_unlink_exact(
                    parent_fd,
                    parent,
                    captured_name,
                    captured_payload,
                )
                _conditional_fsync_parent(parent_fd, parent)
                return target

            _conditional_create(
                parent_fd,
                parent,
                recovery,
                captured_payload,
                mode=mode,
            )
            _conditional_fsync_parent(parent_fd, parent)
            returned_proposal = _conditional_restore(
                parent_fd,
                parent,
                target=rel.name,
                captured=captured_name,
                proposal=proposal,
            )
            _conditional_fsync_parent(parent_fd, parent)
            restored, _ = _conditional_open_read(
                parent_fd,
                parent,
                rel.name,
                max_bytes=max_capture_bytes,
            )
            returned, _ = _conditional_open_read(
                parent_fd,
                parent,
                returned_proposal,
                max_bytes=max_capture_bytes,
            )
            if restored != captured_payload or returned != payload:
                raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED")
            _conditional_unlink_exact(
                parent_fd,
                parent,
                returned_proposal,
                payload,
            )
            _conditional_unlink_exact(
                parent_fd,
                parent,
                recovery,
                captured_payload,
            )
            _conditional_fsync_parent(parent_fd, parent)
            raise ConditionalWriteError("CONDITIONAL_WRITE_TARGET_CHANGED")
        except ConditionalWriteError:
            if proposal_created and not captured:
                try:
                    _conditional_unlink_exact(parent_fd, parent, proposal, payload)
                    _conditional_fsync_parent(parent_fd, parent)
                except ConditionalWriteError:
                    raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED")
            raise
        except OSError as exc:
            if proposal_created and not captured:
                try:
                    _conditional_unlink_exact(parent_fd, parent, proposal, payload)
                    _conditional_fsync_parent(parent_fd, parent)
                except ConditionalWriteError:
                    raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED") from exc
                raise ConditionalWriteError("CONDITIONAL_WRITE_UNAVAILABLE") from exc
            raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED") from exc


def secure_conditional_create_bytes_beneath(
    root: str | os.PathLike[str],
    relative: str | os.PathLike[str],
    payload: bytes,
    *,
    operation_id: str,
    namespace: str,
    max_capture_bytes: int,
    mode: int = PRIVATE_FILE_MODE,
) -> Path:
    """Atomically create an absent target without ever replacing a raced file.

    The proposal is linked into the pinned parent with the filesystem's
    atomic no-overwrite create semantics. If another process publishes the
    target first, its bytes remain untouched and the proposal is deliberately
    retained as recovery evidence.
    """

    root_path = absolute_path(root)
    rel = Path(relative)
    if (
        rel.is_absolute()
        or not rel.parts
        or ".." in rel.parts
        or len(payload) > max_capture_bytes
    ):
        raise ConditionalWriteError("CONDITIONAL_WRITE_INVALID")
    target = root_path / rel
    assert_no_symlink_beneath(root_path, target, include_leaf=False)
    prefix, proposal, _displaced, _recovery = _conditional_sidecar_names(
        rel,
        namespace=namespace,
        operation_id=operation_id,
    )
    with _conditional_parent(root_path, rel) as (parent_fd, parent):
        if _conditional_recovery_entries(parent_fd, parent, prefix):
            raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED")
        try:
            if parent_fd is not None:
                os.stat(rel.name, dir_fd=parent_fd, follow_symlinks=False)
            else:
                (parent / rel.name).lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ConditionalWriteError("CONDITIONAL_WRITE_UNSAFE") from exc
        else:
            raise ConditionalWriteError("CONDITIONAL_WRITE_TARGET_CHANGED")

        _conditional_create(parent_fd, parent, proposal, payload, mode=mode)
        _conditional_fsync_parent(parent_fd, parent)
        if _conditional_recovery_entries(parent_fd, parent, prefix) != (proposal,):
            raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED")
        try:
            if parent_fd is not None:
                os.link(
                    proposal,
                    rel.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            else:
                os.link(
                    parent / proposal,
                    parent / rel.name,
                    follow_symlinks=False,
                )
        except FileExistsError as exc:
            raise ConditionalWriteError("CONDITIONAL_WRITE_TARGET_CHANGED") from exc
        except OSError as exc:
            raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED") from exc
        _conditional_fsync_parent(parent_fd, parent)
        try:
            created, created_stat = _conditional_open_read(
                parent_fd,
                parent,
                rel.name,
                max_bytes=max_capture_bytes,
            )
            staged, staged_stat = _conditional_open_read(
                parent_fd,
                parent,
                proposal,
                max_bytes=max_capture_bytes,
            )
            if (
                created != payload
                or staged != payload
                or (created_stat.st_dev, created_stat.st_ino)
                != (staged_stat.st_dev, staged_stat.st_ino)
            ):
                raise ConditionalWriteError("CONDITIONAL_WRITE_RECOVERY_REQUIRED")
            _conditional_unlink_exact(parent_fd, parent, proposal, payload)
            _conditional_fsync_parent(parent_fd, parent)
        except ConditionalWriteError:
            # The target was already linked. Leave both names in place rather
            # than risk deleting a raced inode; later health checks fail on the
            # deterministic sidecar prefix until recovery is explicit.
            raise
    return target


def secure_atomic_copy_beneath(
    source: str | os.PathLike[str],
    root: str | os.PathLike[str],
    relative: str | os.PathLike[str],
    *,
    mode: int | None = None,
) -> Path:
    source_path = absolute_path(source)
    try:
        source_metadata = source_path.lstat()
    except FileNotFoundError as exc:
        raise StateSecurityError(f"runtime source file is missing: {source_path}") from exc
    if stat.S_ISLNK(source_metadata.st_mode) or not stat.S_ISREG(source_metadata.st_mode):
        raise StateSecurityError(f"runtime source file must be regular and non-symlink: {source_path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source_path, flags)
    with os.fdopen(descriptor, "rb", closefd=True) as handle:
        pinned = os.fstat(handle.fileno())
        if not stat.S_ISREG(pinned.st_mode) or (pinned.st_dev, pinned.st_ino) != (
            source_metadata.st_dev,
            source_metadata.st_ino,
        ):
            raise StateSecurityError(f"runtime source changed while opening: {source_path}")
        payload = handle.read()
    target_mode = stat.S_IMODE(source_metadata.st_mode) if mode is None else mode
    return secure_atomic_write_bytes_beneath(root, relative, payload, mode=target_mode)


def _stat_identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "mode": int(stat.S_IMODE(metadata.st_mode)),
        "size": int(metadata.st_size),
        "mtime_ns": int(metadata.st_mtime_ns),
    }


def _python_launcher_identity(runtime_root: Path, launcher: Path) -> dict[str, Any]:
    expected = (
        runtime_root / ".venv" / "Scripts" / "python.exe"
        if os.name == "nt"
        else runtime_root / ".venv" / "bin" / "python"
    )
    if launcher != expected:
        raise StateSecurityError(f"runtime Python must use the managed launcher: {expected}")
    # The private runtime and .venv/bin directory chain may never be redirected.
    assert_no_symlink_beneath(runtime_root, expected, include_leaf=False)
    chain: list[dict[str, Any]] = []
    current = expected
    in_bin_root = expected.parent
    seen: set[str] = set()
    for _ in range(16):
        key = str(current)
        if key in seen:
            raise StateSecurityError("managed runtime Python symlink cycle")
        seen.add(key)
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise StateSecurityError(f"managed runtime Python is missing: {current}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            link_target = os.readlink(current)
            chain.append({
                "path": relative_beneath(runtime_root, current).as_posix(),
                "kind": "symlink",
                "link_target": link_target,
                "link_sha256": hashlib.sha256(link_target.encode("utf-8", errors="surrogateescape")).hexdigest(),
                "identity": _stat_identity(metadata),
            })
            next_path = absolute_path(Path(link_target) if os.path.isabs(link_target) else current.parent / link_target)
            try:
                next_path.relative_to(in_bin_root)
            except ValueError:
                current = current.resolve(strict=True)
                break
            current = next_path
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise StateSecurityError(f"managed runtime Python target is not regular: {current}")
        chain.append({
            "path": relative_beneath(runtime_root, current).as_posix(),
            "kind": "regular",
            "identity": _stat_identity(metadata),
        })
        break
    else:
        raise StateSecurityError("managed runtime Python symlink chain is too deep")

    resolved = current.resolve(strict=True)
    resolved_lstat = resolved.lstat()
    if stat.S_ISLNK(resolved_lstat.st_mode) or not stat.S_ISREG(resolved_lstat.st_mode):
        raise StateSecurityError(f"resolved runtime Python is not a regular file: {resolved}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(resolved, flags)
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "rb", closefd=True) as handle:
        pinned = os.fstat(handle.fileno())
        if not stat.S_ISREG(pinned.st_mode) or (pinned.st_dev, pinned.st_ino) != (
            resolved_lstat.st_dev,
            resolved_lstat.st_ino,
        ):
            raise StateSecurityError(f"resolved runtime Python changed while opening: {resolved}")
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    if POSIX_PERMISSION_MODEL and not (stat.S_IMODE(pinned.st_mode) & 0o111):
        raise StateSecurityError(f"resolved runtime Python is not executable: {resolved}")
    return {
        "launcher": str(expected),
        "launcher_chain": chain,
        "resolved_path": str(resolved),
        "resolved_sha256": digest.hexdigest(),
        "resolved_identity": _stat_identity(pinned),
    }


def runtime_python_attestation(
    runtime_root: str | os.PathLike[str],
    launcher: str | os.PathLike[str],
) -> dict[str, Any]:
    """Bind a managed venv launcher, its symlink chain, and base executable.

    Relative links inside ``.venv/bin`` are supported. A final external base
    Python (for example Homebrew) is also supported, but its resolved path,
    inode metadata, executable bytes, implementation, and version are all part
    of the day-2 readiness identity.
    """

    root_path = absolute_path(runtime_root)
    launcher_path = absolute_path(launcher)
    before = _python_launcher_identity(root_path, launcher_path)
    probe_code = (
        "import json,platform,sys; "
        "print(json.dumps({'version':[sys.version_info.major,sys.version_info.minor,sys.version_info.micro],"
        "'implementation':platform.python_implementation(),'executable':sys.executable,'base_prefix':sys.base_prefix},"
        "sort_keys=True,separators=(',',':')))"
    )
    completed = subprocess.run(
        [str(launcher_path), "-I", "-S", "-c", probe_code],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        raise StateSecurityError("managed runtime Python probe failed")
    try:
        probe = json.loads(completed.stdout)
        version = tuple(int(item) for item in probe["version"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise StateSecurityError("managed runtime Python probe was invalid") from exc
    if len(version) != 3 or version < (3, 10, 0):
        raise StateSecurityError("managed runtime Python is older than 3.10")
    after = _python_launcher_identity(root_path, launcher_path)
    if after != before:
        raise StateSecurityError("managed runtime Python changed during attestation")
    payload: dict[str, Any] = {
        "schema_version": 1,
        **after,
        "version": list(version),
        "implementation": str(probe.get("implementation", "")),
        "probe_executable": str(probe.get("executable", "")),
        "base_prefix": str(probe.get("base_prefix", "")),
    }
    payload["attestation_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return payload


_RUNTIME_PYTHON_STATIC_KEYS = (
    "launcher", "launcher_chain", "resolved_path", "resolved_sha256", "resolved_identity",
)


def _runtime_python_attestation_digest_is_valid(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    digest = value.get("attestation_sha256")
    unsigned = {key: item for key, item in value.items() if key != "attestation_sha256"}
    calculated = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return isinstance(digest, str) and len(digest) == 64 and digest == calculated


def _runtime_python_persistent_view(
    value: object,
    *,
    static_only: bool,
    platform: str | None,
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    if static_only:
        if any(key not in value for key in _RUNTIME_PYTHON_STATIC_KEYS):
            return None
        view = {key: value[key] for key in _RUNTIME_PYTHON_STATIC_KEYS}
    else:
        view = {key: item for key, item in value.items() if key != "attestation_sha256"}
    if (platform or sys.platform) != "darwin":
        return view
    chain = view.get("launcher_chain")
    resolved = view.get("resolved_identity")
    if not isinstance(chain, list) or not isinstance(resolved, dict):
        return None
    normalized_chain: list[dict[str, Any]] = []
    for raw_entry in chain:
        if not isinstance(raw_entry, dict) or not isinstance(raw_entry.get("identity"), dict):
            return None
        identity = dict(raw_entry["identity"])
        if not isinstance(identity.get("device"), int) or isinstance(identity.get("device"), bool):
            return None
        identity.pop("device")
        entry = dict(raw_entry)
        entry["identity"] = identity
        normalized_chain.append(entry)
    normalized_resolved = dict(resolved)
    if not isinstance(normalized_resolved.get("device"), int) or isinstance(
        normalized_resolved.get("device"), bool
    ):
        return None
    normalized_resolved.pop("device")
    view["launcher_chain"] = normalized_chain
    view["resolved_identity"] = normalized_resolved
    return view


def runtime_python_static_attestation_matches(
    expected: object,
    actual: object,
    *,
    platform: str | None = None,
) -> bool:
    expected_view = _runtime_python_persistent_view(
        expected, static_only=True, platform=platform
    )
    actual_view = _runtime_python_persistent_view(
        actual, static_only=True, platform=platform
    )
    return (
        _runtime_python_attestation_digest_is_valid(expected)
        and expected_view is not None
        and expected_view == actual_view
    )


def runtime_python_attestation_matches(
    expected: object,
    actual: object,
    *,
    platform: str | None = None,
) -> bool:
    expected_view = _runtime_python_persistent_view(
        expected, static_only=False, platform=platform
    )
    actual_view = _runtime_python_persistent_view(
        actual, static_only=False, platform=platform
    )
    return (
        _runtime_python_attestation_digest_is_valid(expected)
        and _runtime_python_attestation_digest_is_valid(actual)
        and expected_view is not None
        and expected_view == actual_view
    )


def sqlite_paths(raw_path: str | os.PathLike[str]) -> tuple[Path, ...]:
    path = absolute_path(raw_path)
    return (path, *(Path(f"{path}{suffix}") for suffix in SQLITE_SIDECAR_SUFFIXES))


def side_effect_free_sqlite_fingerprint(
    raw_path: str | os.PathLike[str],
) -> tuple[tuple[Any, ...], ...]:
    """Fingerprint a stable SQLite main file and its existing sidecars.

    Immutable recovery reads intentionally ignore WAL bytes. A WAL containing
    frames, or a non-empty rollback journal, therefore makes an exact snapshot
    unavailable and is rejected. Comparing fingerprints before and after the
    query catches concurrent checkpoints and sidecar transitions.
    """

    path = absolute_path(raw_path)
    assert_no_symlink_path(path.parent, include_leaf=True)
    entries: list[tuple[Any, ...]] = []
    for index, candidate in enumerate(sqlite_paths(path)):
        try:
            before = candidate.lstat()
        except FileNotFoundError:
            if index == 0:
                raise StateSecurityError(f"SQLite database is missing: {path}")
            entries.append((candidate.name, "missing"))
            continue
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise StateSecurityError(f"unsafe SQLite snapshot path: {candidate}")
        suffix = candidate.name[len(path.name) :]
        if suffix == "-wal" and before.st_size not in {0, 32}:
            raise StateSecurityError("SQLite has uncheckpointed WAL state")
        if suffix == "-journal" and before.st_size > 0:
            raise StateSecurityError("SQLite has an active rollback journal")
        digest = hashlib.sha256()
        with secure_open_regular_beneath(path.parent, candidate.name) as handle:
            opened = os.fstat(handle.fileno())
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
            after_open = os.fstat(handle.fileno())
        try:
            after = candidate.lstat()
        except FileNotFoundError as exc:
            raise StateSecurityError("SQLite snapshot changed during inspection") from exc

        def identity(item: os.stat_result) -> tuple[int, int, int, int, int, int]:
            return (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if not (
            identity(before)
            == identity(opened)
            == identity(after_open)
            == identity(after)
        ):
            raise StateSecurityError("SQLite snapshot changed during inspection")
        entries.append((candidate.name, *identity(after), digest.hexdigest()))
    return tuple(entries)


def _inspect_private_file(path: Path, *, required: bool) -> list[dict[str, Any]]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return ([{"path": str(path), "reason": "missing"}] if required else [])
    if stat.S_ISLNK(metadata.st_mode):
        return [{"path": str(path), "reason": "symlink"}]
    if not stat.S_ISREG(metadata.st_mode):
        return [{"path": str(path), "reason": "not_regular"}]
    actual_mode = stat.S_IMODE(metadata.st_mode)
    if POSIX_PERMISSION_MODEL and actual_mode != PRIVATE_FILE_MODE:
        return [
            {
                "path": str(path),
                "reason": "mode",
                "expected_mode": "0600",
                "actual_mode": f"{actual_mode:04o}",
            }
        ]
    return []


def sqlite_permission_report(
    raw_path: str | os.PathLike[str],
    *,
    require_database: bool = True,
) -> dict[str, Any]:
    paths = sqlite_paths(raw_path)
    issues: list[dict[str, Any]] = []
    for index, path in enumerate(paths):
        issues.extend(_inspect_private_file(path, required=require_database and index == 0))
    return {
        "ok": not issues,
        "database": str(paths[0]),
        "checked": [str(path) for path in paths if path.exists() or path.is_symlink()],
        "issues": issues,
    }


def harden_private_file(raw_path: str | os.PathLike[str], *, required: bool = True) -> Path:
    path = absolute_path(raw_path)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if required:
            raise StateSecurityError(f"private file is missing: {path}")
        return path
    if stat.S_ISLNK(metadata.st_mode):
        raise StateSecurityError(f"private file must not be a symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise StateSecurityError(f"private file is not regular: {path}")
    # chmod(0600) is not a no-op on an already-private file: it updates ctime
    # and invalidates the exact SQLite-generation proof on every open/close.
    # Still inspect type/symlink/mode on every call and repair actual drift.
    if POSIX_PERMISSION_MODEL and stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE:
        os.chmod(path, PRIVATE_FILE_MODE, follow_symlinks=False)
    return path


def harden_sqlite_files(raw_path: str | os.PathLike[str], *, require_database: bool = True) -> None:
    for index, path in enumerate(sqlite_paths(raw_path)):
        harden_private_file(path, required=require_database and index == 0)


def _create_private_file(path: Path) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    except FileExistsError:
        return
    try:
        if POSIX_PERMISSION_MODEL:
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
    finally:
        os.close(descriptor)


class PrivateSQLiteConnection(sqlite3.Connection):
    _agent_memory_path: Path | None = None
    _agent_memory_repair_permissions: bool = True

    def _harden(self) -> None:
        if self._agent_memory_path is not None and self._agent_memory_repair_permissions:
            harden_sqlite_files(self._agent_memory_path)

    def commit(self) -> None:
        super().commit()
        self._harden()

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        try:
            result = super().__exit__(exc_type, exc_value, traceback)
            self._harden()
            return bool(result)
        finally:
            self.close()

    def close(self) -> None:
        try:
            self._harden()
        finally:
            super().close()


def secure_sqlite_connect(
    raw_path: str | os.PathLike[str],
    *,
    timeout: float = 5.0,
    create: bool = True,
    repair_permissions: bool = True,
    read_only: bool = False,
    side_effect_free: bool = False,
    row_factory: Any | None = None,
    pragmas: Iterable[str] = (),
) -> sqlite3.Connection:
    """Open a private SQLite database without following a final symlink.

    Normal runtime callers repair existing mode drift before opening. Diagnostic
    callers may pass ``repair_permissions=False`` after recording the drift.
    """

    path = absolute_path(raw_path)
    if side_effect_free and not read_only:
        raise StateSecurityError("side-effect-free SQLite access must be read-only")
    if read_only:
        # A diagnostic/dry-run open must not create the main database or chmod
        # private state. The query-only WAL fallback below may participate in
        # normal SQLite locking/sidecar handling, but never creates the DB.
        assert_no_symlink_path(path.parent, include_leaf=True)
        if not path.parent.exists():
            raise StateSecurityError(f"SQLite parent directory is missing: {path.parent}")
    else:
        ensure_private_directory(path.parent)
    if path.is_symlink():
        raise StateSecurityError(f"SQLite database must not be a symlink: {path}")
    if read_only:
        create = False
        repair_permissions = False
    if not path.exists():
        if not create:
            raise StateSecurityError(f"SQLite database is missing: {path}")
        _create_private_file(path)
    report = sqlite_permission_report(path)
    non_mode_issues = [item for item in report["issues"] if item.get("reason") != "mode"]
    if non_mode_issues:
        raise StateSecurityError(f"unsafe SQLite path: {non_mode_issues[0]['reason']} {non_mode_issues[0]['path']}")
    if repair_permissions:
        harden_sqlite_files(path)

    def open_connection(target: str, *, uri: bool, query_only: bool) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                target,
                timeout=timeout,
                factory=PrivateSQLiteConnection,
                uri=uri,
            )
            connection._agent_memory_path = path  # type: ignore[attr-defined]
            connection._agent_memory_repair_permissions = repair_permissions  # type: ignore[attr-defined]
            if row_factory is not None:
                connection.row_factory = row_factory
            if query_only:
                connection.execute("PRAGMA query_only=ON")
            for pragma in pragmas:
                connection.execute(pragma)
                if query_only:
                    # Do not let a caller-supplied PRAGMA leave the fallback
                    # connection writable (for example, query_only=OFF).
                    connection.execute("PRAGMA query_only=ON")
            if query_only:
                # SQLite can defer opening WAL/SHM until the first schema read.
                # Probe here so a mode=ro WAL failure can use the safe fallback
                # below instead of surfacing later during the caller's query.
                connection.execute("PRAGMA schema_version").fetchone()
            if repair_permissions:
                harden_sqlite_files(path)
            return connection
        except Exception:
            if connection is not None:
                connection.close()
            raise

    if not read_only:
        return open_connection(str(path), uri=False, query_only=False)

    if side_effect_free:
        # A normal SQLite read may create or rewrite WAL/SHM even with
        # query_only enabled. Recovery queries use an immutable main-file
        # snapshot only after proving there are no uncheckpointed WAL frames.
        wal_path = Path(f"{path}-wal")
        shm_path = Path(f"{path}-shm")
        for sidecar in (wal_path, shm_path):
            if sidecar.exists() or sidecar.is_symlink():
                metadata = sidecar.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                    raise StateSecurityError(f"unsafe SQLite sidecar path: {sidecar}")
        if wal_path.exists() and wal_path.lstat().st_size not in {0, 32}:
            raise StateSecurityError("SQLite has uncheckpointed WAL state")
        immutable_target = f"{path.as_uri()}?mode=ro&immutable=1"
        return open_connection(immutable_target, uri=True, query_only=True)

    read_only_target = f"{path.as_uri()}?mode=ro"
    try:
        return open_connection(read_only_target, uri=True, query_only=True)
    except sqlite3.OperationalError as exc:
        error_code = getattr(exc, "sqlite_errorcode", None)
        cant_open = (
            isinstance(error_code, int)
            and (error_code & 0xFF) == getattr(sqlite3, "SQLITE_CANTOPEN", 14)
        ) or "unable to open database file" in str(exc).lower()
        if not cant_open:
            raise

    # Some SQLite builds cannot attach WAL/SHM through mode=ro even when the
    # database and sidecars are accessible. mode=rw still refuses to create a
    # missing database, honors WAL and locking, and query_only blocks SQL
    # writes. Never use immutable here: it can silently ignore live WAL pages.
    read_existing_target = f"{path.as_uri()}?mode=rw"
    return open_connection(read_existing_target, uri=True, query_only=True)


def secure_append_text(raw_path: str | os.PathLike[str], text: str) -> Path:
    """Append UTF-8 text to a private regular file without following symlinks."""

    path = absolute_path(raw_path)
    ensure_private_directory(path.parent)
    if path.is_symlink():
        raise StateSecurityError(f"private log must not be a symlink: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise StateSecurityError(f"private log is not a regular file: {path}")
        if POSIX_PERMISSION_MODEL:
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
        payload = text.encode("utf-8")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("private log append made no progress")
            offset += written
    finally:
        os.close(descriptor)
    return path
