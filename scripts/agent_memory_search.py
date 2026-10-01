#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import copy
import datetime as dt
import hashlib
import inspect
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_memory_env import RuntimeTransitionError, assert_runtime_ready, env_value, expand_path
from agent_memory_state import StateSecurityError, secure_read_bytes_beneath, secure_sqlite_connect


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = REPO_ROOT / "scripts"
DEFAULT_VAULT_ROOT = REPO_ROOT / "templates" / "vault"
VAULT_ROOT = expand_path(env_value("ROOT", str(DEFAULT_VAULT_ROOT))).resolve()
STATE_DB = expand_path(env_value("STATE_DB", "$HOME/.config/agent-memory/state.sqlite")).resolve()
ZVEC_SCRIPT = SCRIPT_ROOT / "agent_memory_zvec_index.py"
ZVEC_PYTHON = env_value("ZVEC_PYTHON", sys.executable)
REVIEW_OVERDUE_WARNING = "memory_review_overdue"
NON_REVIEWABLE_VERIFICATION_SOURCES = {"structural", "snapshot"}
UNVERIFIED_VERIFICATION_SOURCES = {"mtime_fallback", "needs_review"}
RANKING_VERSION = "hybrid-v2"
DEFAULT_RANKING_VERSION = env_value("RANKING_VERSION", "hybrid-v2-shadow")
DEFAULT_RETRIEVABLE_STATUSES = frozenset({"active", "pending_verification"})
INACTIVE_REFERENCE_STATUSES = frozenset({"outdated", "archived"})
RETRIEVAL_BACKENDS_UNAVAILABLE = "RETRIEVAL_BACKENDS_UNAVAILABLE"
RETRIEVAL_BACKEND_REQUIRED_UNAVAILABLE = "RETRIEVAL_BACKEND_REQUIRED_UNAVAILABLE"
SEARCH_ACTOR_SCOPE_CONFLICT = "SEARCH_ACTOR_SCOPE_CONFLICT"
AILU_SEARCH_DISABLED = "AILU_SEARCH_DISABLED"
CHECKPOINT_RANKING_VERSION = "hybrid-v1"
CHECKPOINT_COMMIT = "3d57999"
PATH_TRACK_FLOORS = {"项目": "project", "工作流": "workflow", "决策": "decision"}
PATH_MEMORY_TYPE_FLOORS = {"项目": "project", "工作流": "workflow", "决策": "decision"}
ACTION_SENSITIVE_MEMORY_TYPES = {"fact", "atomic_fact", "current_fact"}


def configured_number(name: str, default: str, *, minimum: float, maximum: float, integer: bool = False) -> float | int:
    raw = env_value(name, default)
    try:
        value = int(raw) if integer else float(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"SEMANTIC_CONFIG_INVALID:{name}") from exc
    if value < minimum or value > maximum:
        raise RuntimeError(f"SEMANTIC_CONFIG_INVALID:{name}")
    return value


SEMANTIC_ENABLED = env_value("SEMANTIC_ENABLED", "false").strip().casefold() in {"1", "true", "yes", "on"}
CONFIGURED_SEMANTIC_MODE = env_value("SEMANTIC_MODE", "auto").strip().casefold()
if CONFIGURED_SEMANTIC_MODE not in {"auto", "off", "required"}:
    raise RuntimeError("SEMANTIC_CONFIG_INVALID:SEMANTIC_MODE")
DEFAULT_SEMANTIC_MODE = (
    "off" if not SEMANTIC_ENABLED and CONFIGURED_SEMANTIC_MODE == "auto" else CONFIGURED_SEMANTIC_MODE
)
DEFAULT_ZVEC_LOCK_TIMEOUT = float(configured_number("ZVEC_LOCK_TIMEOUT_SECONDS", "2", minimum=0.05, maximum=60))
DEFAULT_ZVEC_MAX_DISTANCE = float(configured_number("ZVEC_MAX_DISTANCE", "0.72", minimum=0.01, maximum=2.0))
DEFAULT_WORKER_COLD_TIMEOUT = float(configured_number("EMBEDDING_WORKER_COLD_TIMEOUT_SECONDS", "12", minimum=0.1, maximum=60))
DEFAULT_WORKER_WARM_TIMEOUT = float(configured_number("EMBEDDING_WORKER_WARM_TIMEOUT_SECONDS", "2", minimum=0.1, maximum=30))
DEFAULT_WORKER_IDLE_SECONDS = int(configured_number("EMBEDDING_WORKER_IDLE_SECONDS", "600", minimum=1, maximum=86400, integer=True))
DEFAULT_CANDIDATE_POOL_MIN = int(configured_number("CANDIDATE_POOL_MIN", "64", minimum=1, maximum=512, integer=True))
DEFAULT_CANDIDATE_POOL_FACTOR = int(configured_number("CANDIDATE_POOL_FACTOR", "16", minimum=1, maximum=128, integer=True))
DEFAULT_CANDIDATE_POOL_SCOPE_MIN = int(configured_number("CANDIDATE_POOL_SCOPE_MIN", "128", minimum=1, maximum=512, integer=True))
DEFAULT_CANDIDATE_POOL_MAX = int(configured_number("CANDIDATE_POOL_MAX", "512", minimum=1, maximum=512, integer=True))
if DEFAULT_CANDIDATE_POOL_MAX < max(DEFAULT_CANDIDATE_POOL_MIN, DEFAULT_CANDIDATE_POOL_SCOPE_MIN):
    raise RuntimeError("SEMANTIC_CONFIG_INVALID:CANDIDATE_POOL_ORDER")
RRF_K = 20
RRF_WEIGHTS = {
    "zvec": 0.55,
    "unicode_fts": 0.25,
    "trigram_fts": 0.20,
    "rg": 0.05,
}
MAX_BACKEND_CANDIDATES = DEFAULT_CANDIDATE_POOL_MAX

if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import agent_memory_index as memory_index  # noqa: E402
import agent_memory_observability as observability  # noqa: E402
import agent_memory_shadow as shadow_gate  # noqa: E402


@dataclass
class SearchResult:
    path: str
    rel_path: str
    title: str = ""
    memory_type: str = ""
    track: str = ""
    project_id: str = ""
    status: str = ""
    risk_class: str = ""
    risk_class_source: str = ""
    verified_at: str = ""
    verified_at_source: str = ""
    fact_key: str = ""
    valid_from: str = ""
    valid_until: str = ""
    supersedes: str = ""
    temporal_policy: str = ""
    temporal_policy_source: str = ""
    review_after_days: int = 0
    review_after_source: str = ""
    user_id: str = ""
    agent_id: str = ""
    agent_scope: str = "shared"
    app_id: str = ""
    session_id: str = ""
    has_open_loop: int = 0
    summary: str = ""
    hit: str = ""
    score: float = 0.0
    legacy_score: float = 0.0
    sources: set[str] = field(default_factory=set)
    source_details: dict[str, Any] = field(default_factory=dict)
    time_status: str = "unknown"
    fact_status: str = "not_fact"
    current_fact_path: str = ""
    superseded_by: str = ""
    superseded_at: str = ""
    fact_reason_code: str = ""
    review_status: str = "unspecified"
    review_due_at: str = ""
    scope_status: str = "unspecified"
    policy_warnings: list[str] = field(default_factory=list)
    can_authorize_action: bool = False
    requires_live_verification: bool = False
    analogy_only: bool = False
    current_project_context: str = ""
    memory_id_value: str = ""
    memory_id_source_value: str = ""
    ranking_version_value: str = RANKING_VERSION
    canonical_read_required: bool = True
    legacy_authorizable: bool = False
    metadata_gate_reasons: tuple[str, ...] = ()
    metadata_gate_evaluated: bool = False
    metadata_gate_mode: str = "shadow"
    as_of_status: str = "current"
    path_policy_reason_codes: tuple[str, ...] = ()

    @property
    def memory_id(self) -> str:
        if re.fullmatch(r"[0-9a-f]{64}", self.memory_id_value):
            return self.memory_id_value
        return legacy_memory_id(self.rel_path)

    @property
    def memory_id_source(self) -> str:
        return self.memory_id_source_value or "legacy_path_hash"

    def merge(self, other: "SearchResult") -> None:
        self.sources.update(other.sources)
        self.score += other.score
        self.legacy_score += other.legacy_score
        self.source_details.update(other.source_details)
        for attr in (
            "title", "memory_type", "track", "project_id", "status", "risk_class",
            "risk_class_source", "verified_at",
            "verified_at_source", "fact_key", "valid_from", "valid_until", "supersedes",
            "temporal_policy", "temporal_policy_source", "review_after_days",
            "review_after_source", "user_id", "agent_id",
            "agent_scope", "app_id", "session_id", "summary", "hit", "memory_id_value",
            "memory_id_source_value",
        ):
            if not getattr(self, attr) and getattr(other, attr):
                setattr(self, attr, getattr(other, attr))
    def to_dict(self) -> dict[str, Any]:
        return {
            "memory_id": self.memory_id,
            "memory_id_source": self.memory_id_source,
            "memory_ref": self.memory_id,
            "rel_path": self.rel_path,
            "title": self.title,
            "memory_type": self.memory_type,
            "track": self.track,
            "project_id": self.project_id,
            "status": self.status,
            "risk_class": self.risk_class,
            "risk_class_source": self.risk_class_source,
            "verified_at": self.verified_at,
            "verified_at_source": self.verified_at_source,
            "fact_key": self.fact_key,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "supersedes": self.supersedes,
            "temporal_policy": self.temporal_policy,
            "temporal_policy_source": self.temporal_policy_source,
            "time_status": self.time_status,
            "fact_status": self.fact_status,
            "current_fact_path": self.current_fact_path,
            "superseded_by": self.superseded_by,
            "superseded_at": self.superseded_at,
            "fact_reason_code": self.fact_reason_code,
            "review_after_days": self.review_after_days,
            "review_after_source": self.review_after_source,
            "review_status": self.review_status,
            "review_due_at": self.review_due_at,
            "scope_status": self.scope_status,
            "policy_warnings": self.policy_warnings,
            "can_authorize_action": self.can_authorize_action,
            "canonical_read_required": self.canonical_read_required,
            "metadata_gate_would_block": bool(self.metadata_gate_reasons),
            "metadata_gate_reason_codes": list(self.metadata_gate_reasons),
            "metadata_gate_mode": self.metadata_gate_mode,
            "as_of_status": self.as_of_status,
            "path_policy_reason_codes": list(self.path_policy_reason_codes),
            "requires_live_verification": self.requires_live_verification,
            "analogy_only": self.analogy_only,
            "current_project_context": self.current_project_context,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "agent_scope": self.agent_scope or "shared",
            "app_id": self.app_id,
            "session_id": self.session_id,
            "summary": self.summary,
            "hit": self.hit,
            "sources": sorted(self.sources),
            "score": round(self.score, 4),
            "legacy_score": round(self.legacy_score, 4),
            "path": self.path,
            "source_details": self.source_details,
            "ranking_version": self.ranking_version_value,
        }


class SearchProtocolError(ValueError):
    """Stable fail-closed Search invocation error with no private context."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def legacy_memory_id(rel_path: str) -> str:
    canonical = unicodedata.normalize("NFC", rel_path.replace("\\", "/").strip())
    return hashlib.sha256(b"agent-memory-v1\0" + canonical.encode("utf-8")).hexdigest()


def enforce_runtime_actor_scope(args: argparse.Namespace) -> str:
    """Bind Search visibility to the host-authenticated runtime actor.

    ``memoryctl`` supplies ``MEMORY_ACTOR`` to the child process.  Treat that
    value as the authority and the CLI flag merely as a consistency assertion.
    Canonical Retrieve uses the same search engine in-process; its private
    namespace marker is the only exception that permits Ailu candidate
    discovery, while the public/raw Ailu Search surface remains disabled.
    """

    runtime_actor = unicodedata.normalize(
        "NFKC", os.environ.get("MEMORY_ACTOR", "").strip()
    ).casefold()
    canonical_actor = unicodedata.normalize(
        "NFKC", str(getattr(args, "_canonical_retrieve_actor", "") or "").strip()
    ).casefold()
    if runtime_actor in {"codex", "claude", "ailu"} and canonical_actor:
        if canonical_actor != runtime_actor:
            raise SearchProtocolError(SEARCH_ACTOR_SCOPE_CONFLICT)
    effective_actor = runtime_actor or canonical_actor
    if effective_actor == "ailu":
        if canonical_actor != "ailu":
            raise SearchProtocolError(AILU_SEARCH_DISABLED)
        # Ailu's exact app/project boundary is re-read from Markdown by
        # Canonical Retrieve.  Candidate search may see shared rows only.
        if str(getattr(args, "agent_scope", "") or "") != "shared":
            raise SearchProtocolError(SEARCH_ACTOR_SCOPE_CONFLICT)
        return effective_actor
    if effective_actor in {"codex", "claude"}:
        requested = unicodedata.normalize(
            "NFKC", str(getattr(args, "agent_scope", "") or "").strip()
        ).casefold()
        if requested and requested != effective_actor:
            raise SearchProtocolError(SEARCH_ACTOR_SCOPE_CONFLICT)
        args.agent_scope = effective_actor
    return effective_actor


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


def coverage(query: str, text: str) -> float:
    query_tokens = tokenize(query)
    text_tokens = tokenize(text)
    if not query_tokens or not text_tokens:
        return 0.0
    return len(query_tokens & text_tokens) / len(query_tokens)


def compact_match_text(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9\u3400-\u9fff]+", "", text).lower()


def connect(*, read_only: bool = False) -> sqlite3.Connection:
    assert_runtime_ready("search")
    return secure_sqlite_connect(
        STATE_DB,
        create=False,
        read_only=read_only,
        row_factory=sqlite3.Row,
        pragmas=("PRAGMA busy_timeout=10000",),
    )


def row_to_result(
    row: sqlite3.Row,
    rank: int,
    query: str,
    backend: str = "unicode_fts",
) -> SearchResult:
    weight = RRF_WEIGHTS.get(backend, 0.0)
    searchable = " ".join(str(row[key] or "") for key in ("title", "rel_path", "summary", "hit"))
    term_coverage = coverage(query, searchable)
    compact_query = compact_match_text(query)
    compact_title = compact_match_text(str(row["title"] or ""))
    exact_bonus = 4.0 if compact_query and compact_query in compact_title else 0.0
    details: dict[str, Any] = {f"{backend}_rank": rank}
    if backend == "unicode_fts":
        details["sqlite_rank"] = rank  # compatibility for older diagnostics
    return SearchResult(
        path=str(row["path"]),
        rel_path=str(row["rel_path"]),
        title=str(row["title"] or ""),
        memory_type=str(row["memory_type"] or ""),
        track=str(row["track"] or ""),
        project_id=str(row["project_id"] or ""),
        status=str(row["status"] or ""),
        risk_class=(
            str(row["risk_class"] or "")
            if "risk_class" in row.keys()
            else ""
        ),
        risk_class_source=(
            str(row["risk_class_source"] or "")
            if "risk_class_source" in row.keys()
            else ""
        ),
        verified_at=str(row["verified_at"] or ""),
        verified_at_source=str(row["verified_at_source"] or ""),
        fact_key=str(row["fact_key"] or "") if "fact_key" in row.keys() else "",
        valid_from=str(row["valid_from"] or "") if "valid_from" in row.keys() else "",
        valid_until=str(row["valid_until"] or ""),
        supersedes=str(row["supersedes"] or "") if "supersedes" in row.keys() else "",
        temporal_policy=(
            str(row["temporal_policy"] or "")
            if "temporal_policy" in row.keys()
            else ""
        ),
        temporal_policy_source=(
            str(row["temporal_policy_source"] or "")
            if "temporal_policy_source" in row.keys()
            else ""
        ),
        review_after_days=int(row["review_after_days"] or 0) if "review_after_days" in row.keys() else 0,
        review_after_source=(
            str(row["review_after_source"] or "")
            if "review_after_source" in row.keys()
            else ""
        ),
        user_id=str(row["user_id"] or ""),
        agent_id=str(row["agent_id"] or ""),
        agent_scope=str(row["agent_scope"] or "shared"),
        app_id=str(row["app_id"] or ""),
        session_id=str(row["session_id"] or ""),
        memory_id_value=(
            str(row["memory_id"] or "")
            if "memory_id" in row.keys()
            and re.fullmatch(r"[0-9a-f]{64}", str(row["memory_id"] or ""))
            else ""
        ),
        memory_id_source_value=(
            str(row["memory_id_source"] or "")
            if "memory_id_source" in row.keys()
            else ""
        ),
        has_open_loop=int(row["has_open_loop"] or 0),
        summary=str(row["summary"] or ""),
        hit=str(row["hit"] or "").replace("\n", " "),
        score=weight / (RRF_K + max(rank, 1)),
        legacy_score=(1.0 / max(rank, 1)) + (term_coverage * 3.0) + exact_bonus,
        sources={backend},
        source_details=details,
    )


def enrich_from_db(result: SearchResult, conn: sqlite3.Connection) -> SearchResult:
    doc_columns = {
        str(column[1]) for column in conn.execute("PRAGMA table_info(memory_docs)")
    }
    if "memory_id" in doc_columns:
        row = conn.execute(
            """
            SELECT *
            FROM memory_docs
            WHERE (memory_id<>'' AND memory_id=?) OR path=? OR rel_path=?
            ORDER BY CASE WHEN memory_id<>'' AND memory_id=? THEN 0 ELSE 1 END,
                     rel_path
            LIMIT 1
            """,
            (result.memory_id_value, result.path, result.rel_path, result.memory_id_value),
        ).fetchone()
    else:  # Compatibility for isolated legacy fixtures; production gates v13.
        row = conn.execute(
            "SELECT * FROM memory_docs WHERE path=? OR rel_path=? LIMIT 1",
            (result.path, result.rel_path),
        ).fetchone()
    if not row:
        return result
    result.path = str(row["path"])
    result.rel_path = str(row["rel_path"])
    result.title = result.title or str(row["title"] or "")
    result.memory_type = result.memory_type or str(row["memory_type"] or "")
    result.track = result.track or str(row["track"] or "")
    result.project_id = result.project_id or str(row["project_id"] or "")
    result.status = result.status or str(row["status"] or "")
    if "risk_class" in row.keys():
        result.risk_class = result.risk_class or str(row["risk_class"] or "")
    if "risk_class_source" in row.keys():
        result.risk_class_source = result.risk_class_source or str(
            row["risk_class_source"] or ""
        )
    result.verified_at = result.verified_at or str(row["verified_at"] or "")
    result.verified_at_source = result.verified_at_source or str(row["verified_at_source"] or "")
    if "fact_key" in row.keys():
        result.fact_key = result.fact_key or str(row["fact_key"] or "")
    if "valid_from" in row.keys():
        result.valid_from = result.valid_from or str(row["valid_from"] or "")
    result.valid_until = result.valid_until or str(row["valid_until"] or "")
    if "supersedes" in row.keys():
        result.supersedes = result.supersedes or str(row["supersedes"] or "")
    if "temporal_policy" in row.keys():
        result.temporal_policy = result.temporal_policy or str(row["temporal_policy"] or "")
    if "temporal_policy_source" in row.keys():
        result.temporal_policy_source = result.temporal_policy_source or str(
            row["temporal_policy_source"] or ""
        )
    if "review_after_days" in row.keys():
        result.review_after_days = result.review_after_days or int(row["review_after_days"] or 0)
    if "review_after_source" in row.keys():
        result.review_after_source = result.review_after_source or str(
            row["review_after_source"] or ""
        )
    result.user_id = result.user_id or str(row["user_id"] or "")
    result.agent_id = result.agent_id or str(row["agent_id"] or "")
    result.agent_scope = str(row["agent_scope"] or "shared")
    result.app_id = result.app_id or str(row["app_id"] or "")
    result.session_id = result.session_id or str(row["session_id"] or "")
    if "memory_id" in row.keys() and re.fullmatch(r"[0-9a-f]{64}", str(row["memory_id"] or "")):
        result.memory_id_value = result.memory_id_value or str(row["memory_id"])
    if "memory_id_source" in row.keys():
        result.memory_id_source_value = result.memory_id_source_value or str(
            row["memory_id_source"] or ""
        )
    result.has_open_loop = int(row["has_open_loop"] or 0)
    result.summary = result.summary or str(row["summary"] or "")
    return result


def annotate_temporal_from_db(
    result: SearchResult,
    conn: sqlite3.Connection,
    as_of: dt.date,
) -> SearchResult:
    """Resolve one explicit fact record at ``as_of`` from the derived graph."""

    if not result.fact_key:
        return result
    try:
        row = conn.execute(
            """
            SELECT rel_path, fact_key, valid_from, valid_until, status,
                   app_id, project_id, user_id, agent_scope
            FROM memory_docs WHERE rel_path=? LIMIT 1
            """,
            (result.rel_path,),
        ).fetchone()
        if row is None:
            result.fact_status = "invalid_relation"
            result.fact_reason_code = "TEMPORAL_INDEX_MISSING"
            return result
        result.fact_key = str(row["fact_key"] or "")
        result.valid_from = str(row["valid_from"] or "")
        state = conn.execute(
            "SELECT fact_status, current_rel_path, superseded_by, effective_from, reason_code "
            "FROM memory_fact_states WHERE rel_path=?",
            (result.rel_path,),
        ).fetchone()
        if state is not None and str(state["fact_status"]) == "invalid_metadata":
            result.fact_status = "invalid_metadata"
            result.fact_reason_code = str(state["reason_code"] or "FACT_METADATA_INVALID")
            return result

        valid_from = parsed_date(result.valid_from)
        if valid_from is None:
            result.fact_status = "invalid_metadata"
            result.fact_reason_code = "VALID_FROM_INVALID"
            return result
        if valid_from > as_of:
            result.fact_status = "not_yet_valid"
            result.fact_reason_code = "VALID_FROM_IN_FUTURE"
            return result

        group_rows = conn.execute(
            """
            SELECT rel_path, valid_from, valid_until, status,
                   app_id, project_id, user_id, agent_scope
            FROM memory_docs
            WHERE fact_key=?
            ORDER BY rel_path
            """,
            (result.fact_key,),
        ).fetchall()
        group = [item for item in group_rows if memory_index._fact_scope(item) == memory_index._fact_scope(row)]
        lineage_eligible = {
            str(item["rel_path"])
            for item in group
            if str(item["status"] or "").casefold()
            in memory_index.FACT_LINEAGE_SOURCE_STATUSES
            and parsed_date(str(item["valid_from"] or "")) is not None
            and parsed_date(str(item["valid_from"] or "")) <= as_of
        }
        current_candidates = {
            str(item["rel_path"])
            for item in group
            if str(item["rel_path"]) in lineage_eligible
            and str(item["status"] or "").casefold() == "active"
        }
        edge_rows = conn.execute(
            """
            SELECT source_rel_path, target_rel_path, effective_from
            FROM memory_supersessions
            WHERE relation_status='effective' AND source_fact_key=?
            """,
            (result.fact_key,),
        ).fetchall()
        lineage_edges = [
            item
            for item in edge_rows
            if str(item["source_rel_path"]) in lineage_eligible
            and str(item["target_rel_path"]) in lineage_eligible
            and parsed_date(str(item["effective_from"] or "")) is not None
            and parsed_date(str(item["effective_from"] or "")) <= as_of
        ]
        superseded = {str(item["target_rel_path"]) for item in lineage_edges}
        heads = sorted(current_candidates - superseded)
        result.current_fact_path = heads[0] if len(heads) == 1 else ""
        if len(heads) > 1:
            result.fact_status = "conflict"
            result.fact_reason_code = "MULTIPLE_CURRENT_FACTS"
            return result

        invalid = conn.execute(
            """
            SELECT reason_code FROM memory_supersessions
            WHERE relation_status<>'effective'
              AND (source_rel_path=? OR target_rel_path=?)
            ORDER BY reason_code LIMIT 1
            """,
            (result.rel_path, result.rel_path),
        ).fetchone()
        if invalid is not None:
            result.fact_status = "invalid_relation"
            result.fact_reason_code = str(invalid["reason_code"] or "RELATION_INVALID")
            return result

        incoming = next(
            (item for item in lineage_edges if str(item["target_rel_path"]) == result.rel_path),
            None,
        )
        if incoming is not None:
            result.fact_status = "superseded"
            result.superseded_by = str(incoming["source_rel_path"])
            result.superseded_at = str(incoming["effective_from"])
            result.fact_reason_code = "SUPERSEDED_BY_EXPLICIT_EDGE"
        elif result.rel_path in heads:
            valid_until = parsed_date(result.valid_until)
            if valid_until is not None and valid_until < as_of:
                result.fact_status = "expired"
                result.fact_reason_code = "CURRENT_HEAD_EXPIRED"
            else:
                result.fact_status = "current"
        else:
            result.fact_status = "historical"
            result.fact_reason_code = "NO_ACTIVE_CURRENT_FACT"
    except sqlite3.Error:
        result.fact_status = "invalid_relation"
        result.fact_reason_code = "TEMPORAL_INDEX_UNAVAILABLE"
    return result


def _sqlite_table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone() is not None


def trigram_fts_query(raw_query: str) -> str:
    terms: list[str] = []
    normalized = unicodedata.normalize("NFKC", raw_query).strip()
    for chunk in re.findall(r"[A-Za-z0-9_.+-]{3,}|[\u3400-\u9fff]{3,}", normalized):
        if re.fullmatch(r"[\u3400-\u9fff]+", chunk):
            terms.extend(chunk[index : index + 3] for index in range(len(chunk) - 2))
        else:
            terms.append(chunk.casefold())
    escaped = [term.replace('"', '""') for term in dict.fromkeys(terms) if term]
    return " OR ".join(f'"{term}"' for term in escaped[:64]) or '""'


# The legacy lane below is intentionally copied from checkpoint 3d57999.  Do
# not replace these helpers with the evolving production index helpers: during
# the seven-day shadow window, its exact single-SQLite ordering is the control
# group against which Hybrid v2 is measured.
def checkpoint_query_chunks(raw_query: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9_.+-]+|[\u3400-\u9fff]+", raw_query.strip())


def checkpoint_lexical_terms(raw_query: str, limit: int = 18) -> list[str]:
    terms: list[str] = []
    for chunk in checkpoint_query_chunks(raw_query):
        if re.fullmatch(r"[\u3400-\u9fff]+", chunk):
            if len(chunk) <= 6:
                terms.append(chunk)
            gram_size = 2 if len(chunk) <= 8 else 3
            terms.extend(
                chunk[index : index + gram_size]
                for index in range(len(chunk) - gram_size + 1)
            )
        else:
            terms.append(chunk.lower())
    return list(dict.fromkeys(term for term in terms if term))[:limit]


def checkpoint_fts_query(raw_query: str) -> str:
    terms = checkpoint_query_chunks(raw_query)
    if not terms:
        return '""'
    escaped = [term.replace('"', '""') for term in terms[:8]]
    return " OR ".join(f'"{term}"' for term in escaped)


def checkpoint_score_row(row: sqlite3.Row, terms: list[str]) -> int:
    if not terms:
        return 0
    fields = {
        "title": str(row["title"] or "").lower(),
        "rel_path": str(row["rel_path"] or "").lower(),
        "summary": str(row["summary"] or "").lower(),
        "search_text": str(row["search_text"] or "").lower(),
    }
    score = 0
    matched = 0
    for term in terms:
        needle = term.lower()
        term_matched = False
        if needle in fields["title"]:
            score += 8
            term_matched = True
        if needle in fields["rel_path"]:
            score += 5
            term_matched = True
        if needle in fields["summary"]:
            score += 4
            term_matched = True
        if needle in fields["search_text"]:
            score += 1
            term_matched = True
        if term_matched:
            matched += 1
    if matched == len(terms):
        score += 10
    score += min(matched, 5) * 2
    if str(row["memory_type"] or "") in {"routing", "directory_index", "template"}:
        score -= 4
    if int(row["has_open_loop"] or 0):
        score += 1
    return score


def checkpoint_dedupe_and_rank(
    rows: list[sqlite3.Row], query: str, limit: int
) -> list[sqlite3.Row]:
    terms = checkpoint_lexical_terms(query)
    by_path: dict[str, sqlite3.Row] = {}
    for row in rows:
        by_path.setdefault(str(row["path"]), row)
    ranked = sorted(
        by_path.values(),
        key=lambda row: (
            checkpoint_score_row(row, terms),
            float(row["mtime"] or 0),
        ),
        reverse=True,
    )
    return ranked[:limit]


def checkpoint_row_to_result(
    row: sqlite3.Row, rank: int, query: str
) -> SearchResult:
    result = row_to_result(row, rank, query, "unicode_fts")
    searchable = " ".join(
        str(row[key] or "") for key in ("title", "rel_path", "summary", "hit")
    )
    term_coverage = coverage(query, searchable)
    compact_query = compact_match_text(query)
    compact_title = compact_match_text(str(row["title"] or ""))
    exact_bonus = 4.0 if compact_query and compact_query in compact_title else 0.0
    checkpoint_score = (1.0 / max(rank, 1)) + (term_coverage * 3.0) + exact_bonus
    result.score = checkpoint_score
    result.legacy_score = checkpoint_score
    result.sources = {"sqlite"}
    result.source_details = {
        "sqlite_rank": rank,
        "term_coverage": round(term_coverage, 4),
        "exact_title_bonus": exact_bonus,
        "checkpoint_commit": CHECKPOINT_COMMIT,
    }
    return result


def readonly_checkpoint_search(
    conn: sqlite3.Connection,
    query: str,
    limit: int,
    track: str = "",
    memory_type: str = "",
    user_id: str = "",
    agent_id: str = "",
    app_id: str = "",
    session_id: str = "",
    status: str = "",
    has_open_loop: bool = False,
) -> list[sqlite3.Row]:
    """Execute checkpoint 3d57999's one-lane SQLite candidate order.

    MATCH failures deliberately propagate.  Falling through to LIKE after an
    invalid/corrupt FTS query would turn an unhealthy control lane into a
    silent, incomparable ranking algorithm.
    """

    conn.row_factory = sqlite3.Row
    if not _sqlite_table_exists(conn, "memory_fts"):
        raise sqlite3.OperationalError("fts table missing: memory_fts")
    rows = list(
        conn.execute(
            """
            SELECT d.*, memory_fts.search_text AS search_text,
                   snippet(memory_fts, 6, '[', ']', '...', 12) AS hit
            FROM memory_fts
            JOIN memory_docs d ON d.path = memory_fts.path
            WHERE memory_fts MATCH ?
            ORDER BY bm25(memory_fts)
            LIMIT ?
            """,
            (checkpoint_fts_query(query), max(limit * 12, 50)),
        )
    )
    seen = {str(row["path"]) for row in rows}
    terms = checkpoint_lexical_terms(query)
    if terms:
        like_parts: list[str] = []
        params: list[object] = []
        for term in terms[:6]:
            like = f"%{term}%"
            like_parts.append(
                "(memory_fts.title LIKE ? OR memory_fts.rel_path LIKE ? "
                "OR memory_fts.summary LIKE ? OR memory_fts.search_text LIKE ?)"
            )
            params.extend([like, like, like, like])
        fallback = list(
            conn.execute(
                f"""
                SELECT d.*, memory_fts.search_text AS search_text,
                       substr(memory_fts.summary, 1, 160) AS hit
                FROM memory_fts
                JOIN memory_docs d ON d.path = memory_fts.path
                WHERE {' OR '.join(like_parts)}
                ORDER BY d.has_open_loop DESC, d.mtime DESC
                LIMIT ?
                """,
                [*params, max(limit * 20, 80)],
            )
        )
        for row in fallback:
            if str(row["path"]) not in seen:
                rows.append(row)
                seen.add(str(row["path"]))
    rows = [
        row
        for row in rows
        if memory_index.row_matches_filters(
            row,
            track,
            memory_type,
            "",
            user_id,
            agent_id,
            app_id,
            session_id,
            status,
            has_open_loop,
        )
    ]
    return checkpoint_dedupe_and_rank(rows, query, limit)


def readonly_index_search(
    conn: sqlite3.Connection,
    query: str,
    limit: int,
    track: str = "",
    memory_type: str = "",
    user_id: str = "",
    agent_id: str = "",
    app_id: str = "",
    session_id: str = "",
    status: str = "",
    has_open_loop: bool = False,
    *,
    table: str = "memory_fts_unicode",
    backend: str = "unicode_fts",
) -> list[sqlite3.Row]:
    """Search an already initialized index without running schema setup.

    ``agent_memory_index.search`` intentionally initializes and migrates the
    database for normal interactive searches.  A closeout dry-run must be
    observably read-only, so this path performs the same SELECT/ranking work
    against the schema that is already present and never calls ``init_db``.
    """
    del backend  # labels are attached by row_to_result after this query.
    conn.row_factory = sqlite3.Row
    selected_table = table
    if not _sqlite_table_exists(conn, selected_table):
        if table == "memory_fts_unicode" and _sqlite_table_exists(conn, "memory_fts"):
            selected_table = "memory_fts"
        else:
            raise sqlite3.OperationalError(f"fts table missing: {table}")
    if selected_table not in {"memory_fts", "memory_fts_unicode", "memory_fts_trigram"}:
        raise sqlite3.OperationalError("fts table invalid")
    match_query = (
        trigram_fts_query(query)
        if selected_table == "memory_fts_trigram"
        else memory_index.fts_query(query)
    )
    rows = list(
        conn.execute(
            f"""
            SELECT d.*, {selected_table}.search_text AS search_text,
                   snippet({selected_table}, 6, '[', ']', '...', 12) AS hit
            FROM {selected_table}
            JOIN memory_docs d ON d.path = {selected_table}.path
            WHERE {selected_table} MATCH ?
            ORDER BY bm25({selected_table})
            LIMIT ?
            """,
            (match_query, limit),
        )
    )

    seen = {str(row["path"]) for row in rows}
    terms = memory_index.lexical_terms(query)
    # Unicode LIKE fallback preserves recall for punctuation/short terms.  The
    # trigram backend remains a real FTS ranker rather than a duplicate LIKE
    # pass, so RRF receives independent evidence.
    if terms and selected_table != "memory_fts_trigram":
        like_parts: list[str] = []
        params: list[object] = []
        for term in terms[:6]:
            like = f"%{term}%"
            like_parts.append(
                f"({selected_table}.title LIKE ? OR {selected_table}.rel_path LIKE ? "
                f"OR {selected_table}.summary LIKE ? OR {selected_table}.search_text LIKE ?)"
            )
            params.extend([like, like, like, like])
        fallback = list(
            conn.execute(
                f"""
                SELECT d.*, {selected_table}.search_text AS search_text,
                       substr({selected_table}.summary, 1, 160) AS hit
                FROM {selected_table}
                JOIN memory_docs d ON d.path = {selected_table}.path
                WHERE {' OR '.join(like_parts)}
                ORDER BY d.has_open_loop DESC, d.mtime DESC
                LIMIT ?
                """,
                [*params, limit],
            )
        )
        for row in fallback:
            if str(row["path"]) not in seen:
                rows.append(row)
                seen.add(str(row["path"]))

    rows = [
        row
        for row in rows
        if memory_index.row_matches_filters(
            row,
            track,
            memory_type,
            "",
            user_id,
            agent_id,
            app_id,
            session_id,
            status,
            has_open_loop,
        )
    ]
    deduped: list[sqlite3.Row] = []
    seen_paths: set[str] = set()
    for row in rows:
        path = str(row["path"])
        if path in seen_paths:
            continue
        seen_paths.add(path)
        deduped.append(row)
        if len(deduped) >= limit:
            break
    return deduped


def legacy_sqlite_search(args: argparse.Namespace) -> tuple[list[SearchResult], list[str]]:
    """Run only the frozen checkpoint SQLite lane used for v1/shadow output."""

    if not STATE_DB.exists():
        setattr(args, "_legacy_sqlite_status", "failed")
        return [], [f"sqlite index missing: {STATE_DB}"]
    try:
        as_of = parsed_date(str(getattr(args, "as_of", "") or "")) or dt.datetime.now().date()
        with connect(read_only=True) as conn:
            memory_index.assert_schema_ready(conn)
            rows = readonly_checkpoint_search(
                conn,
                args.query,
                backend_candidate_limit(args),
                args.track,
                args.memory_type,
                args.user_id,
                args.agent_id if not args.agent_scope else "",
                args.app_id,
                args.session_id,
                args.status,
                args.has_open_loop,
            )
            results = [
                checkpoint_row_to_result(row, rank, args.query)
                for rank, row in enumerate(rows, 1)
            ]
            for result in results:
                annotate_temporal_from_db(result, conn, as_of)
        # The historical merge sorted this one lane again by its old score.
        results.sort(
            key=lambda item: (item.legacy_score, item.verified_at),
            reverse=True,
        )
        setattr(args, "_legacy_sqlite_status", "ok")
        return results, []
    except (OSError, sqlite3.Error, ValueError) as exc:
        setattr(args, "_legacy_sqlite_status", "failed")
        detail = str(exc).casefold()
        reason = "FTS_TABLE_MISSING" if "table missing" in detail else "FTS_MATCH_FAILED"
        return [], [f"legacy sqlite search failed: {reason}"]


def sqlite_search(args: argparse.Namespace) -> tuple[list[SearchResult], list[str]]:
    if not STATE_DB.exists():
        setattr(args, "_unicode_fts_status", "failed")
        setattr(args, "_trigram_fts_status", "failed")
        return [], [f"sqlite index missing: {STATE_DB}"]
    try:
        as_of = parsed_date(str(getattr(args, "as_of", "") or "")) or dt.datetime.now().date()
        with connect(read_only=True) as conn:
            memory_index.assert_schema_ready(conn)
            groups: list[list[SearchResult]] = []
            warnings: list[str] = []
            for table, backend in (
                ("memory_fts_unicode", "unicode_fts"),
                ("memory_fts_trigram", "trigram_fts"),
            ):
                try:
                    rows = readonly_index_search(
                        conn,
                        args.query,
                        backend_candidate_limit(args),
                        args.track,
                        args.memory_type,
                        args.user_id,
                        args.agent_id if not args.agent_scope else "",
                        args.app_id,
                        args.session_id,
                        args.status,
                        args.has_open_loop,
                        table=table,
                        backend=backend,
                    )
                    setattr(args, f"_{backend}_status", "ok")
                except sqlite3.Error as exc:
                    rows = []
                    setattr(args, f"_{backend}_status", "failed")
                    detail = str(exc).casefold()
                    reason = (
                        "FTS_TABLE_MISSING"
                        if "table missing" in detail
                        else "FTS_MATCH_FAILED"
                    )
                    warnings.append(f"{backend} search failed: {reason}")
                results = [
                    row_to_result(row, rank, args.query, backend)
                    for rank, row in enumerate(rows, 1)
                ]
                for result in results:
                    annotate_temporal_from_db(result, conn, as_of)
                groups.append(results)
        return merge_results(groups), warnings
    except Exception as exc:  # pragma: no cover
        setattr(args, "_unicode_fts_status", "failed")
        setattr(args, "_trigram_fts_status", "failed")
        reason = (
            "STATE_SCHEMA_MIGRATION_REQUIRED"
            if "STATE_SCHEMA_MIGRATION_REQUIRED" in str(exc)
            else "SQLITE_SEARCH_FAILED"
        )
        return [], [f"sqlite search failed: {reason}"]


def command_env_offline() -> dict[str, str]:
    env = os.environ.copy()
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    env.setdefault("HF_HUB_OFFLINE", "1")
    env.setdefault("TRANSFORMERS_OFFLINE", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    return env


def zvec_search(args: argparse.Namespace) -> tuple[list[SearchResult], list[str]]:
    semantic_mode = str(getattr(args, "semantic_mode", "auto") or "auto")
    if bool(getattr(args, "no_zvec", False)) or semantic_mode == "off":
        setattr(args, "_zvec_status", "disabled")
        setattr(args, "_worker_status", "not_used")
        setattr(args, "_worker_restart_count", 0)
        return [], []
    if not ZVEC_SCRIPT.exists():
        setattr(args, "_zvec_status", "failed")
        setattr(args, "_worker_status", "failed")
        setattr(args, "_worker_restart_count", 0)
        return [], [f"zvec script missing: {ZVEC_SCRIPT}"]
    command = [
        ZVEC_PYTHON,
        str(ZVEC_SCRIPT),
        "--search-stdin",
        "--limit",
        str(backend_candidate_limit(args)),
        "--lock-timeout",
        str(float(getattr(args, "zvec_lock_timeout", DEFAULT_ZVEC_LOCK_TIMEOUT))),
        "--worker-cold-timeout",
        str(float(getattr(args, "worker_cold_timeout", DEFAULT_WORKER_COLD_TIMEOUT))),
        "--worker-warm-timeout",
        str(float(getattr(args, "worker_warm_timeout", DEFAULT_WORKER_WARM_TIMEOUT))),
        "--worker-idle-seconds",
        str(int(getattr(args, "worker_idle_seconds", DEFAULT_WORKER_IDLE_SECONDS))),
        "--json",
    ]
    try:
        completed = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=args.zvec_timeout,
            env=command_env_offline(),
            input=args.query,
            check=False,
        )
    except subprocess.TimeoutExpired:
        setattr(args, "_zvec_status", "failed")
        setattr(args, "_worker_status", "failed")
        setattr(args, "_worker_restart_count", 0)
        return [], [f"zvec search timed out after {args.zvec_timeout}s"]
    except OSError as exc:
        setattr(args, "_zvec_status", "failed")
        setattr(args, "_worker_status", "failed")
        setattr(args, "_worker_restart_count", 0)
        return [], [f"zvec search failed to start: {exc}"]
    if completed.returncode != 0 and not completed.stdout.strip():
        detail = completed.stderr.strip() or f"returncode={completed.returncode}"
        setattr(args, "_zvec_status", "failed")
        setattr(args, "_worker_status", "failed")
        setattr(args, "_worker_restart_count", 0)
        return [], [f"zvec search failed: {detail}"]
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        detail = completed.stderr.strip() or completed.stdout.strip()[:300]
        setattr(args, "_zvec_status", "failed")
        setattr(args, "_worker_status", "failed")
        setattr(args, "_worker_restart_count", 0)
        return [], [f"zvec returned non-json output: {detail}"]
    embedding_status = payload.get("embedding", {})
    if not isinstance(embedding_status, dict):
        embedding_status = {}
    setattr(args, "_embedding_status", embedding_status)
    setattr(args, "_worker_status", str(embedding_status.get("worker_status") or "failed"))
    setattr(
        args,
        "_worker_restart_count",
        min(max(int(embedding_status.get("worker_restart_count", 0) or 0), 0), 1),
    )
    setattr(
        args,
        "_semantic_identity",
        {
            key: embedding_status[key]
            for key in (
                "model",
                "model_revision",
                "embedding_dim",
                "runtime_manifest_sha256",
                "model_manifest_sha256",
                "model_binding_id",
                "worker_identity",
            )
            if key in embedding_status
        },
    )
    if payload.get("error"):
        setattr(args, "_zvec_status", "failed")
        return [], [f"zvec search failed: {payload['error']}"]
    rows = payload.get("results", [])
    if not isinstance(rows, list):
        setattr(args, "_zvec_status", "failed")
        setattr(args, "_worker_status", "failed")
        return [], ["zvec returned invalid result shape"]
    setattr(args, "_zvec_status", "ok")
    if not rows:
        return [], []
    results: list[SearchResult] = []
    as_of = parsed_date(str(getattr(args, "as_of", "") or "")) or dt.datetime.now().date()
    # Enriching vector candidates reads metadata only. Search telemetry uses
    # its own write connection later; it must not make this reader writable.
    with connect(read_only=True) as conn:
        for rank, row in enumerate(rows, 1):
            if not isinstance(row, dict):
                continue
            try:
                raw_value = row.get("raw_distance", row.get("vector_score"))
                raw_distance = float(raw_value) if raw_value is not None else None
            except (TypeError, ValueError):
                continue
            if raw_distance is None or raw_distance > args.zvec_max_distance:
                continue
            source_details: dict[str, Any] = {
                "zvec_rank": rank,
                "zvec_score": raw_distance,
                "zvec_rank_distance": raw_distance,
                "zvec_rank_score": raw_distance,
                "zvec_score_semantics": "raw_cosine_distance",
                "zvec_raw_distance": raw_distance,
            }
            result = SearchResult(
                path=str(row.get("path") or ""),
                rel_path=str(row.get("rel_path") or ""),
                title=str(row.get("title") or ""),
                memory_type=str(row.get("memory_type") or ""),
                track=str(row.get("track") or ""),
                project_id=str(row.get("project_id") or ""),
                verified_at=str(row.get("verified_at") or ""),
                memory_id_value=(
                    str(row.get("memory_id") or "").casefold()
                    if re.fullmatch(
                        r"[0-9a-fA-F]{64}", str(row.get("memory_id") or "")
                    )
                    else ""
                ),
                memory_id_source_value=(
                    "frontmatter" if row.get("memory_id") else ""
                ),
                summary=str(row.get("summary") or ""),
                hit=str(row.get("summary") or ""),
                score=RRF_WEIGHTS["zvec"] / (RRF_K + max(rank, 1)),
                legacy_score=(0.8 / max(rank, 1))
                + max(0.0, 1.0 - (raw_distance / args.zvec_max_distance)) * 2.0
                + coverage(
                    args.query,
                    " ".join(str(row.get(key) or "") for key in ("title", "rel_path", "summary")),
                ) * 2.0,
                sources={"zvec"},
                source_details=source_details,
            )
            result = enrich_from_db(result, conn)
            results.append(annotate_temporal_from_db(result, conn, as_of))
    return results, []


def rg_search(args: argparse.Namespace) -> tuple[list[SearchResult], list[str]]:
    if not args.force_rg:
        return [], []
    command = ["rg", "--line-number", "--ignore-case", "--fixed-strings", "--", args.query, str(VAULT_ROOT)]
    try:
        completed = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=args.rg_timeout,
            check=False,
        )
    except FileNotFoundError:
        return [], ["rg not found"]
    except subprocess.TimeoutExpired:
        return [], [f"rg timed out after {args.rg_timeout}s"]
    if completed.returncode not in {0, 1}:
        return [], [completed.stderr.strip() or f"rg failed: {completed.returncode}"]
    results: list[SearchResult] = []
    seen: set[str] = set()
    as_of = parsed_date(str(getattr(args, "as_of", "") or "")) or dt.datetime.now().date()
    with connect(read_only=bool(getattr(args, "no_log", False))) as conn:
        for line in completed.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) != 3:
                continue
            path = str(Path(parts[0]).resolve())
            if path in seen:
                continue
            seen.add(path)
            try:
                rel_path = Path(path).relative_to(VAULT_ROOT).as_posix()
            except ValueError:
                rel_path = path
            result = SearchResult(
                path=path,
                rel_path=rel_path,
                hit=parts[2].strip(),
                score=RRF_WEIGHTS["rg"] / (RRF_K + max(len(seen), 1)),
                legacy_score=0.35 / max(len(seen), 1),
                sources={"rg"},
                source_details={"rg_line": parts[1]},
            )
            result = enrich_from_db(result, conn)
            results.append(annotate_temporal_from_db(result, conn, as_of))
            if len(results) >= backend_candidate_limit(args):
                break
    return results, []


def merge_results(
    result_groups: list[list[SearchResult]],
    ranking_version: str = RANKING_VERSION,
) -> list[SearchResult]:
    merged: dict[str, SearchResult] = {}
    for group in result_groups:
        for item in group:
            # Hybrid v2 is intentionally the fixed three-way production merge:
            # raw Zvec distance, Unicode FTS, and trigram FTS. ``rg`` remains a
            # manual v1 troubleshooting fallback and must never perturb v2.
            if ranking_version == RANKING_VERSION and item.sources and item.sources <= {"rg"}:
                continue
            # Hybrid identity is the stable document id.  This allows a stale
            # vector left by a rename to fuse with the current lexical row;
            # Canonical Retrieve will still re-read the current Markdown and
            # validate the explicit id before returning any bytes.
            key = item.memory_id
            if not key:
                continue
            if key in merged:
                merged[key].merge(item)
            else:
                merged[key] = copy.deepcopy(item)
    rows = list(merged.values())
    # Deterministic identity order is the final tie breaker; the subsequent
    # stable score sort preserves it for exact score/date ties.
    rows.sort(key=lambda item: (item.memory_id, item.rel_path))
    if ranking_version in {"hybrid-v1", "hybrid-v2-shadow"}:
        rows.sort(key=lambda item: (item.legacy_score, item.verified_at), reverse=True)
    else:
        rows.sort(key=lambda item: (item.score, item.verified_at), reverse=True)
    return rows


def backend_candidate_limit(args: argparse.Namespace) -> int:
    # Every backend is merged before the final authorization/scope policy is
    # applied.  Lexical search can push several filters into SQLite, but Zvec
    # cannot, and agent_scope remains a post-filter for both.  Oversample for
    # every narrowing filter so a dense set of out-of-scope neighbours cannot
    # crowd the authorized candidates out of the shared pool.
    has_post_backend_filter = any(
        bool(str(getattr(args, name, "") or "").strip())
        for name in (
            "current_project",
            "project_id",
            "agent_scope",
            "track",
            "memory_type",
            "user_id",
            "agent_id",
            "app_id",
            "session_id",
            "status",
        )
    ) or bool(getattr(args, "has_open_loop", False))
    pool_min = int(getattr(args, "candidate_pool_min", DEFAULT_CANDIDATE_POOL_MIN))
    pool_factor = int(getattr(args, "candidate_pool_factor", DEFAULT_CANDIDATE_POOL_FACTOR))
    scope_min = int(getattr(args, "candidate_pool_scope_min", DEFAULT_CANDIDATE_POOL_SCOPE_MIN))
    pool_max = int(getattr(args, "candidate_pool_max", DEFAULT_CANDIDATE_POOL_MAX))
    base = max(pool_min, int(getattr(args, "limit", 0) or 0) * pool_factor)
    if has_post_backend_filter:
        base = max(base, scope_min)
    return min(base, pool_max)


def result_matches_filters(result: SearchResult, args: argparse.Namespace) -> bool:
    normalized_status = unicodedata.normalize("NFKC", str(result.status or "")).casefold()
    include_inactive_history = bool(getattr(args, "include_inactive", False)) and (
        normalized_status in INACTIVE_REFERENCE_STATUSES
    )
    if result.fact_status in {"superseded", "not_yet_valid", "historical", "no_current"}:
        # The latest pending-verification fact remains discoverable by default
        # but is never authorizing.  A pending fact that has itself been
        # superseded is still history and therefore requires the narrower
        # ``--include-superseded`` gate.  Explicitly inactive Markdown is
        # discoverable only with ``--include-inactive``.
        inactive_fact_reference = include_inactive_history and result.fact_status in {
            "superseded",
            "historical",
        }
        pending_fact_reference = (
            normalized_status == "pending_verification"
            and result.fact_status == "historical"
        )
        if not inactive_fact_reference and not pending_fact_reference and not bool(
            getattr(args, "include_superseded", False)
        ):
            return False
    if args.agent_scope and (result.agent_scope or "shared") not in {"shared", args.agent_scope}:
        return False
    for value, actual in (
        (args.track, result.track),
        (args.memory_type, result.memory_type),
        (args.user_id, result.user_id),
        (args.agent_id, result.agent_id),
        (args.app_id, result.app_id),
        (args.session_id, result.session_id),
    ):
        if value and value != actual:
            return False
    if args.project_id and not project_matches(args.project_id, result.project_id):
        return False
    current_project = str(getattr(args, "current_project", "") or "").strip()
    if current_project and project_scope(result, current_project) == "cross_project_reference":
        if not bool(getattr(args, "cross_project", False)):
            return False
    requested_status = unicodedata.normalize(
        "NFKC", str(getattr(args, "status", "") or "")
    ).casefold()
    allowed_statuses = set(DEFAULT_RETRIEVABLE_STATUSES)
    if bool(getattr(args, "include_inactive", False)):
        allowed_statuses.update(INACTIVE_REFERENCE_STATUSES)
    # Candidate/draft and legacy pseudo-inactive states are never mixed into
    # retrieval, even when a caller supplies an explicit --status filter.
    if normalized_status not in allowed_statuses:
        return False
    if requested_status and normalized_status != requested_status:
        return False
    if args.has_open_loop and result.has_open_loop != 1:
        return False
    if (
        not args.memory_type
        and not args.include_supporting
        and result.memory_type in {"routing", "template", "directory_index"}
    ):
        return False
    return bool(result.path and result.rel_path)


def project_matches(current_project: str, result_project: str) -> bool:
    current = unicodedata.normalize("NFKC", current_project.strip()).casefold()
    candidates = {
        unicodedata.normalize("NFKC", item.strip()).casefold()
        for item in result_project.split(",")
        if item.strip()
    }
    return bool(current) and current in candidates


def project_scope(result: SearchResult, current_project: str) -> str:
    project_values = {
        unicodedata.normalize("NFKC", item.strip()).casefold()
        for item in result.project_id.split(",")
        if item.strip()
    }
    if not project_values:
        return "unscoped_shared_reference"
    # A value is globally reusable only when every declared project id says so.
    # Mixed values such as ``global, project-a`` remain project-bound.
    if project_values <= {"global", "shared"}:
        return "global_shared"
    if project_matches(current_project, result.project_id):
        return "current_project"
    return "cross_project_reference"


def project_scope_policy(result: SearchResult, current_project: str) -> str:
    """Classify project scope even when the caller has no current project.

    Unknown context must not hide potentially useful project memories, but any
    project-bound hit is explicitly analogy-only and cannot authorize action.
    """

    project_values = {
        unicodedata.normalize("NFKC", item.strip()).casefold()
        for item in result.project_id.split(",")
        if item.strip()
    }
    if not project_values:
        return "unscoped_shared_reference"
    if project_values <= {"global", "shared"}:
        return "global_shared"
    if not current_project:
        return "project_context_unknown"
    return project_scope(result, current_project)


def apply_canonical_path_floor(result: SearchResult) -> tuple[str, ...]:
    """Prevent derived-index metadata from lowering the canonical path class."""

    normalized = unicodedata.normalize("NFKC", str(result.rel_path or "")).replace("\\", "/")
    relative = Path(normalized)
    if (
        len(relative.parts) < 2
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.name == "README.md"
        or relative.name.startswith("_模板")
    ):
        return ()
    floor_track = PATH_TRACK_FLOORS.get(relative.parts[0], "")
    floor_type = PATH_MEMORY_TYPE_FLOORS.get(relative.parts[0], "")
    if not floor_track:
        return ()
    declared_type = str(result.memory_type or "").strip().casefold()
    declared_track = str(result.track or "").strip().casefold()
    risk_class = str(result.risk_class or "").strip().casefold()
    reasons: list[str] = []
    if declared_track and declared_track != floor_track:
        reasons.append("PATH_TRACK_DOWNGRADE")
    allowed_raised_types = ACTION_SENSITIVE_MEMORY_TYPES | {"decision"}
    if declared_type and declared_type not in {floor_type, *allowed_raised_types}:
        reasons.append("PATH_MEMORY_TYPE_DOWNGRADE")
    result.track = floor_track
    result.memory_type = (
        declared_type if declared_type in allowed_raised_types else floor_type
    )
    if risk_class and risk_class not in {"ordinary", "action_sensitive"}:
        reasons.append("RISK_CLASS_INVALID")
    action_sensitive = bool(
        result.status.strip().casefold() == "active"
        and (
            floor_track == "decision"
            or result.memory_type in ACTION_SENSITIVE_MEMORY_TYPES
            or result.temporal_policy.strip().casefold() == "expiring"
            or bool(result.valid_until.strip())
            or bool(result.fact_key.strip())
            or bool(result.supersedes.strip())
            or "事实-" in relative.stem
        )
    )
    if action_sensitive and risk_class == "ordinary":
        reasons.append("RISK_CLASS_DOWNGRADE")
    return tuple(dict.fromkeys(reasons))


def parsed_date(value: str) -> dt.date | None:
    raw = str(value or "").strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw) is None:
        return None
    try:
        return dt.date.fromisoformat(raw)
    except ValueError:
        return None


def review_policy(
    verified_at: str,
    verified_at_source: str,
    review_after_days: object,
    as_of: dt.date,
) -> tuple[str, str, list[str]]:
    """Return review status, due date, and stable live-verification warnings.

    A review deadline is deliberately separate from ``valid_until``: an
    overdue review means the fact needs current verification, not that the
    memory has explicitly expired. Structural and historical snapshots are
    not recurring fact-review targets, and weak/missing verification evidence
    is labelled unverified instead of being assigned a fabricated due date.
    """

    source = str(verified_at_source or "").strip().casefold()
    if source in NON_REVIEWABLE_VERIFICATION_SOURCES:
        return "not_applicable", "", []
    if source in UNVERIFIED_VERIFICATION_SOURCES or not str(verified_at or "").strip():
        return "unverified", "", ["verification_needed"]

    verified = parsed_date(str(verified_at))
    if verified is None:
        return "invalid", "", ["invalid_verified_at"]
    try:
        review_days = int(review_after_days)
    except (TypeError, ValueError):
        review_days = 0
    if review_days <= 0:
        return "unspecified", "", []

    due_at = verified + dt.timedelta(days=review_days)
    if as_of > due_at:
        return "overdue", due_at.isoformat(), [REVIEW_OVERDUE_WARNING]
    if as_of == due_at:
        return "due_today", due_at.isoformat(), []
    return "current", due_at.isoformat(), []


def annotate_result_policy(result: SearchResult, args: argparse.Namespace) -> None:
    """Attach warnings without changing retrieval score or granting authority."""
    warnings: list[str] = []
    raw_as_of = str(getattr(args, "as_of", "") or "").strip()
    as_of = parsed_date(raw_as_of) or dt.datetime.now().date()
    result.as_of_status = (
        "historical"
        if raw_as_of and as_of != dt.datetime.now().date()
        else "current"
    )
    result.requires_live_verification = False
    result.analogy_only = False
    result.path_policy_reason_codes = apply_canonical_path_floor(result)
    if result.valid_until:
        boundary = parsed_date(result.valid_until)
        if boundary is None:
            result.time_status = "invalid"
            result.requires_live_verification = True
            warnings.append("invalid_valid_until")
        elif boundary < as_of:
            result.time_status = "expired"
            result.requires_live_verification = True
            warnings.append("expired_memory_reference_only")
        elif boundary == as_of:
            result.time_status = "expires_today"
            result.requires_live_verification = True
            warnings.append("memory_expires_today")
        else:
            result.time_status = "current"
    else:
        result.time_status = "unspecified"

    result.review_status, result.review_due_at, review_warnings = review_policy(
        result.verified_at,
        result.verified_at_source,
        result.review_after_days,
        as_of,
    )
    if review_warnings:
        result.requires_live_verification = True
        warnings.extend(review_warnings)

    if result.fact_status == "superseded":
        result.requires_live_verification = True
        warnings.append("superseded_memory_reference_only")
    elif result.fact_status == "not_yet_valid":
        result.requires_live_verification = True
        warnings.append("memory_not_yet_valid")
    elif result.fact_status == "conflict":
        result.requires_live_verification = True
        warnings.append("current_fact_conflict")
    elif result.fact_status in {"invalid_metadata", "invalid_relation"}:
        result.requires_live_verification = True
        warnings.append("invalid_fact_timeline")
    elif result.fact_status == "expired" and "expired_memory_reference_only" not in warnings:
        result.requires_live_verification = True
        warnings.append("expired_memory_reference_only")

    current_project = str(getattr(args, "current_project", "") or "").strip()
    result.current_project_context = current_project
    result.scope_status = project_scope_policy(result, current_project)
    if result.scope_status in {"cross_project_reference", "project_context_unknown"}:
        result.analogy_only = True
        warnings.append(
            "project_context_unknown_reference_only"
            if result.scope_status == "project_context_unknown"
            else "cross_project_reference_only"
        )

    if result.path_policy_reason_codes:
        result.analogy_only = True
        result.requires_live_verification = True
        warnings.append("path_policy_downgrade_reference_only")
    if result.as_of_status == "historical":
        result.analogy_only = True
        result.requires_live_verification = True
        warnings.append("historical_as_of_reference_only")

    if result.status and result.status != "active":
        warnings.append("inactive_or_historical_memory")
    result.policy_warnings = warnings
    result.legacy_authorizable = bool(
        result.status == "active"
        and not result.analogy_only
        and not result.requires_live_verification
        and result.fact_status in {"not_fact", "current"}
    )
    risk_path_failure = bool(
        {"RISK_CLASS_INVALID", "RISK_CLASS_DOWNGRADE"}
        & set(result.path_policy_reason_codes)
    )
    result.metadata_gate_evaluated = bool(
        result.legacy_authorizable
        or (result.status == "active" and risk_path_failure)
    )
    result.metadata_gate_reasons = (
        shadow_gate.temporal_metadata_gate_reasons(result)
        if result.metadata_gate_evaluated
        else ()
    )
    # Search is candidate discovery over potentially stale derived indexes. It
    # can describe why a hit is risky, but only Canonical Retrieve may re-read
    # current Markdown and decide whether it can authorize an action.
    result.can_authorize_action = False
    result.canonical_read_required = True


def apply_metadata_gate(rows: list[SearchResult]) -> dict[str, Any]:
    """Project the v4 metadata gate without granting index-derived authority."""

    reason_sets = [
        row.metadata_gate_reasons
        for row in rows
        if row.metadata_gate_evaluated
    ]
    projection = shadow_gate.metadata_gate_projection(reason_sets)
    effective_mode = str(projection["effective_mode"])
    for row in rows:
        row.metadata_gate_mode = effective_mode
        if row.metadata_gate_evaluated and row.metadata_gate_reasons:
            if "metadata_gate_would_block" not in row.policy_warnings:
                row.policy_warnings.append("metadata_gate_would_block")
            # Search remains non-authorizing in both shadow and enforce mode;
            # the distinction is nevertheless exposed and logged for cutover.
            if bool(projection["enforced"]):
                row.can_authorize_action = False
    return projection


def log_search(
    query: str,
    rows: list[SearchResult],
    duration_ms: int,
    search_status: str,
    *,
    ranking_mode: str = DEFAULT_RANKING_VERSION,
    v1_result_memory_ids: list[str] | None = None,
    v2_result_memory_ids: list[str] | None = None,
    worker_status: str = "not_used",
    worker_restart_count: int = 0,
    required_case_regression_count: int = 0,
    metadata_gate_mode: str = "shadow",
    metadata_would_block_count: int = 0,
    metadata_reason_fingerprint: str = "",
) -> None:
    try:
        with connect() as conn:
            memory_index.assert_schema_ready(conn)
            observability.assert_schema_ready(conn)
            sources = sorted({source for row in rows for source in row.sources})
            v1_ids = list(v1_result_memory_ids or [])
            v2_ids = list(v2_result_memory_ids or [])
            persisted_ranking_mode = {
                "hybrid-v1": "legacy_v1",
                "hybrid-v2-shadow": "shadow",
                "hybrid-v2": "hybrid_v2",
            }.get(ranking_mode, "shadow")
            optional = {
                "memory_ids": [row.memory_id for row in rows],
                "ranking_mode": persisted_ranking_mode,
                "v1_result_fingerprint": hashlib.sha256("\0".join(v1_ids).encode("utf-8")).hexdigest(),
                "v2_result_fingerprint": hashlib.sha256("\0".join(v2_ids).encode("utf-8")).hexdigest(),
                "required_case_regression_count": max(int(required_case_regression_count), 0),
                "worker_status": worker_status,
                "worker_restart_count": min(max(int(worker_restart_count), 0), 1),
                "metadata_gate_mode": metadata_gate_mode,
                "metadata_would_block_count": max(int(metadata_would_block_count), 0),
                "metadata_reason_fingerprint": metadata_reason_fingerprint,
            }
            supported = inspect.signature(observability.record_search).parameters
            observability.record_search(
                conn,
                query=query,
                rel_paths=[row.rel_path for row in rows],
                sources=sources,
                duration_ms=duration_ms,
                search_status=search_status,
                required_live_verification_count=sum(
                    1 for row in rows if row.requires_live_verification
                ),
                **{key: value for key, value in optional.items() if key in supported},
            )
    except (OSError, sqlite3.Error, ValueError):
        return


def redact_legacy_search_logs() -> dict[str, int]:
    """Irreversibly remove legacy query text while retaining useful metadata."""
    with connect() as conn:
        memory_index.assert_schema_ready(conn)
        observability.assert_schema_ready(conn)
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            """
            SELECT id, query, query_sha256, query_length
            FROM memory_search_log
            WHERE query<>'' AND query NOT LIKE '[redacted:%'
            ORDER BY id
            """
        ).fetchall()
        for row in rows:
            query = str(row["query"] or "")
            digest = str(row["query_sha256"] or "") or hashlib.sha256(query.encode("utf-8")).hexdigest()
            length = int(row["query_length"] or len(query))
            conn.execute(
                """
                UPDATE memory_search_log
                SET query=?, query_sha256=?, query_length=?
                WHERE id=?
                """,
                (f"[redacted:{digest[:12]}]", digest, length, int(row["id"])),
            )
        conn.commit()
        remaining = int(
            conn.execute(
                "SELECT COUNT(*) FROM memory_search_log "
                "WHERE query<>'' AND query NOT LIKE '[redacted:%'"
            ).fetchone()[0]
        )
    return {"redacted": len(rows), "remaining_raw": remaining}


def index_projection_health() -> dict[str, Any]:
    """Never report an incomplete saved-memory index as a healthy empty search.

    This check only reads Markdown and hashes; it neither indexes unapproved
    edits nor stores text. Canonical Retrieve still independently checks scope
    and authority. No mtime shortcut: same-size/backdated edits also count.
    """
    try:
        with contextlib.closing(connect(read_only=True)) as conn:
            indexed = {str(row[0]): str(row[1]) for row in conn.execute(
                "SELECT rel_path,sha256 FROM memory_docs"
            )}
        actual: dict[str, str] = {}
        if not VAULT_ROOT.is_dir():
            raise OSError("vault unavailable")
        for path in VAULT_ROOT.rglob("*.md"):
            if not path.is_file() and not path.is_symlink():
                continue
            relative = path.relative_to(VAULT_ROOT).as_posix()
            raw = secure_read_bytes_beneath(VAULT_ROOT, relative)
            # Match load_doc's universal-newline text hashing, not raw bytes.
            text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
            actual[relative] = memory_index.sha256_text(text)
        missing = len(actual.keys() - indexed.keys())
        deleted = len(indexed.keys() - actual.keys())
        changed = sum(actual[key] != indexed[key] for key in actual.keys() & indexed.keys())
        return {"status": "stale" if missing or deleted or changed else "ok",
                "missing_count": missing, "changed_count": changed, "deleted_count": deleted}
    except (OSError, sqlite3.Error, ValueError, StateSecurityError):
        return {"status": "unavailable"}


def run_search(args: argparse.Namespace) -> tuple[list[SearchResult], list[str], bool]:
    started = time.monotonic()
    enforce_runtime_actor_scope(args)
    requested_ranking = str(
        getattr(args, "ranking_version", DEFAULT_RANKING_VERSION) or DEFAULT_RANKING_VERSION
    )
    if requested_ranking == RANKING_VERSION and not bool(
        getattr(args, "_shadow_benchmark_bypass", False)
    ) and not shadow_gate.cutover_active():
        # Check before starting any backend/Worker so a caller-supplied flag or
        # environment override cannot even execute the production v2 path.
        raise shadow_gate.ShadowGateError("HYBRID_V2_CUTOVER_ATTESTATION_REQUIRED")
    warnings: list[str] = []
    result_by_backend: dict[str, list[SearchResult]] = {}
    task_health: dict[str, bool] = {}
    run_checkpoint = requested_ranking != RANKING_VERSION
    run_v2 = requested_ranking in {"hybrid-v2-shadow", RANKING_VERSION}
    semantic_enabled = run_v2 and not bool(getattr(args, "no_zvec", False)) and str(
            getattr(args, "semantic_mode", "auto") or "auto"
        ) != "off"
    max_workers = int(run_checkpoint) + int(run_v2) + int(semantic_enabled)
    with ThreadPoolExecutor(max_workers=max(max_workers, 1)) as executor:
        tasks: dict[Any, str] = {}
        if run_checkpoint:
            tasks[executor.submit(legacy_sqlite_search, args)] = "legacy_sqlite"
        if run_v2:
            tasks[executor.submit(sqlite_search, args)] = "sqlite_v2"
        if semantic_enabled:
            tasks[executor.submit(zvec_search, args)] = "zvec"
        for future in as_completed(tasks):
            backend = tasks[future]
            try:
                rows, task_warnings = future.result()
            except Exception as exc:  # pragma: no cover
                rows, task_warnings = [], [f"search task failed: {exc}"]
            warnings.extend(task_warnings)
            result_by_backend[backend] = rows
            task_health[backend] = bool(rows or not task_warnings)
    legacy_status = str(
        getattr(
            args,
            "_legacy_sqlite_status",
            "ok" if task_health.get("legacy_sqlite") else "failed",
        )
    ) if run_checkpoint else "disabled"
    unicode_status = str(
        getattr(
            args,
            "_unicode_fts_status",
            "ok" if task_health.get("sqlite_v2") else "failed",
        )
    ) if run_v2 else "disabled"
    trigram_status = str(
        getattr(
            args,
            "_trigram_fts_status",
            "ok" if task_health.get("sqlite_v2") else "failed",
        )
    ) if run_v2 else "disabled"
    # Fixed group order prevents thread-completion timing from deciding which
    # backend supplies canonical metadata when identities fuse.
    v2_groups = [
        result_by_backend.get("sqlite_v2", []),
        result_by_backend.get("zvec", []),
    ]
    v2_rows = merge_results(v2_groups, RANKING_VERSION) if run_v2 else []
    # Shadow output is the frozen, one-lane checkpoint.  V2 evidence is never
    # merged into the control result order and is persisted only as telemetry.
    v1_rows = list(result_by_backend.get("legacy_sqlite", []))
    v2_visible = [row for row in v2_rows if result_matches_filters(row, args)][: args.limit]
    v1_visible = [row for row in v1_rows if result_matches_filters(row, args)][: args.limit]
    setattr(args, "_shadow_result_memory_ids", [row.memory_id for row in v2_visible])
    setattr(args, "_v1_result_memory_ids", [row.memory_id for row in v1_visible])
    if requested_ranking == RANKING_VERSION:
        rows = v2_rows
        effective_ranking = RANKING_VERSION
    else:
        rows = v1_rows
        effective_ranking = CHECKPOINT_RANKING_VERSION
    setattr(args, "_effective_ranking_version", effective_ranking)
    rows = [row for row in rows if result_matches_filters(row, args)]
    for row in rows:
        row.ranking_version_value = effective_ranking
        annotate_result_policy(row, args)
    rows = rows[: args.limit]
    metadata_projection = apply_metadata_gate(rows)
    setattr(args, "_metadata_gate_projection", metadata_projection)
    backend_status = {
        "legacy_sqlite": legacy_status,
        "unicode_fts": unicode_status,
        "trigram_fts": trigram_status,
        "zvec": str(getattr(args, "_zvec_status", "disabled" if not semantic_enabled else ("ok" if task_health.get("zvec") else "failed"))),
        "rg": "disabled",
    }
    projection_health = index_projection_health()
    backend_status["index_projection"] = projection_health
    if projection_health["status"] != "ok":
        warnings.append("INDEX_PROJECTION_STALE" if projection_health["status"] == "stale"
                        else "INDEX_PROJECTION_UNAVAILABLE")
    authoritative_backend_names = (
        ["unicode_fts", "trigram_fts", "zvec"]
        if requested_ranking == RANKING_VERSION
        else ["legacy_sqlite"]
    )
    observed_backend_names = (
        ["legacy_sqlite", "unicode_fts", "trigram_fts", "zvec"]
        if requested_ranking == "hybrid-v2-shadow"
        else list(authoritative_backend_names)
    )
    authoritative_statuses = [
        str(backend_status[name])
        for name in authoritative_backend_names
        if backend_status[name] != "disabled"
    ]
    enabled_statuses = [
        str(backend_status[name])
        for name in observed_backend_names
        if backend_status[name] != "disabled"
    ]
    all_enabled_backends_failed = not any(
        status == "ok" for status in authoritative_statuses
    )
    semantic_required_failed = (
        run_v2
        and str(getattr(args, "semantic_mode", "auto") or "auto") == "required"
        and backend_status["zvec"] != "ok"
    )
    worker_status = str(getattr(args, "_worker_status", "not_used" if not semantic_enabled else "failed"))
    if backend_status["zvec"] != "ok" and worker_status != "not_used":
        worker_status = "failed" if all_enabled_backends_failed else "degraded"
    worker_restart_count = min(max(int(getattr(args, "_worker_restart_count", 0) or 0), 0), 1)
    backend_status["worker_status"] = worker_status
    backend_status["worker_restart_count"] = worker_restart_count
    semantic_identity = getattr(args, "_semantic_identity", {})
    if semantic_enabled and isinstance(semantic_identity, dict):
        backend_status["semantic_identity"] = dict(semantic_identity)
    setattr(args, "_worker_status", worker_status)
    setattr(args, "_worker_restart_count", worker_restart_count)
    setattr(args, "_backend_status", backend_status)
    setattr(
        args,
        "_degraded",
        bool(any(status == "failed" for status in enabled_statuses)
             or projection_health["status"] != "ok"),
    )
    setattr(args, "_hard_failure", semantic_required_failed)
    failure_reason_code = ""
    if semantic_required_failed:
        failure_reason_code = RETRIEVAL_BACKEND_REQUIRED_UNAVAILABLE
    elif all_enabled_backends_failed:
        failure_reason_code = RETRIEVAL_BACKENDS_UNAVAILABLE
    setattr(args, "_failure_reason_code", failure_reason_code)
    if all_enabled_backends_failed:
        search_status = "backend_failed"
    elif warnings or bool(getattr(args, "_degraded", False)):
        search_status = "partial"
    else:
        search_status = "success"
    if not bool(getattr(args, "no_log", False)):
        log_search(
            args.query,
            rows,
            round((time.monotonic() - started) * 1000),
            search_status,
            ranking_mode=requested_ranking,
            v1_result_memory_ids=list(getattr(args, "_v1_result_memory_ids", [])),
            v2_result_memory_ids=list(getattr(args, "_shadow_result_memory_ids", [])),
            worker_status=worker_status,
            worker_restart_count=worker_restart_count,
            metadata_gate_mode=str(metadata_projection["effective_mode"]),
            metadata_would_block_count=int(metadata_projection["would_block_count"]),
            metadata_reason_fingerprint=str(metadata_projection["reason_fingerprint"]),
        )
    return rows, warnings, all_enabled_backends_failed


def print_human(query: str, rows: list[SearchResult], warnings: list[str]) -> None:
    print(f"query={query}")
    print(f"results={len(rows)}")
    for warning in warnings:
        print(f"warning: {warning}")
    for index, row in enumerate(rows, 1):
        print(f"{index}. {row.rel_path}")
        print(f"   title: {row.title}")
        print(f"   type: {row.memory_type} track={row.track} project_id={row.project_id} status={row.status}")
        print(
            f"   verified_at: {row.verified_at} source={row.verified_at_source} "
            f"review_after_days={row.review_after_days or '-'} "
            f"review_status={row.review_status} review_due_at={row.review_due_at or '-'}"
        )
        print(f"   valid_until: {row.valid_until or '-'} time_status={row.time_status} scope={row.scope_status}")
        if row.fact_key:
            print(
                f"   fact_key: {row.fact_key} fact_status={row.fact_status} "
                f"valid_from={row.valid_from or '-'} superseded_by={row.superseded_by or '-'}"
            )
        for warning in row.policy_warnings:
            print(f"   policy_warning: {warning}")
        print(f"   sources: {','.join(sorted(row.sources))} score={round(row.score, 4)}")
        print(f"   memory_id: {row.memory_id}")
        if row.summary:
            print(f"   summary: {row.summary[:240]}")
        if row.hit:
            print(f"   hit: {row.hit[:240]}")
        print(f"   path: {row.path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Unified Agent Memory search: SQLite FTS plus optional Zvec semantic results.")
    parser.add_argument("query", nargs="?", help="Search query.")
    parser.add_argument("--search", dest="search", help="Search query, alternative to positional query.")
    parser.add_argument(
        "--query-stdin",
        action="store_true",
        help="Read a private UTF-8 query from stdin so it never appears in process argv.",
    )
    parser.add_argument("--limit", type=int, default=5, help="Maximum merged results.")
    parser.add_argument(
        "--ranking-version",
        choices=("hybrid-v1", "hybrid-v2-shadow", "hybrid-v2"),
        default=DEFAULT_RANKING_VERSION,
        help="Use v1, observe v2 without reordering, or activate hybrid-v2.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--no-zvec", action="store_true", help="Skip semantic Zvec search.")
    parser.add_argument(
        "--semantic-mode",
        choices=("auto", "off", "required"),
        default=DEFAULT_SEMANTIC_MODE,
        help="Semantic backend policy; --no-zvec is retained as an alias for off.",
    )
    parser.add_argument(
        "--no-log",
        action="store_true",
        help="Read-only search: do not migrate the SQLite schema or insert a search-log row.",
    )
    parser.add_argument("--force-rg", action="store_true", help="Also run rg as a manual fallback.")
    parser.add_argument("--zvec-timeout", type=float, default=14.0, help="Total seconds before semantic search degrades.")
    parser.add_argument("--zvec-lock-timeout", type=float, default=DEFAULT_ZVEC_LOCK_TIMEOUT, help="Seconds to wait for the Zvec collection lock.")
    parser.add_argument("--worker-cold-timeout", type=float, default=DEFAULT_WORKER_COLD_TIMEOUT, help=argparse.SUPPRESS)
    parser.add_argument("--worker-warm-timeout", type=float, default=DEFAULT_WORKER_WARM_TIMEOUT, help=argparse.SUPPRESS)
    parser.add_argument("--worker-idle-seconds", type=int, default=DEFAULT_WORKER_IDLE_SECONDS, help=argparse.SUPPRESS)
    parser.add_argument("--zvec-max-distance", type=float, default=DEFAULT_ZVEC_MAX_DISTANCE, help="Discard farther semantic results.")
    parser.add_argument("--candidate-pool-min", type=int, default=DEFAULT_CANDIDATE_POOL_MIN, help=argparse.SUPPRESS)
    parser.add_argument("--candidate-pool-factor", type=int, default=DEFAULT_CANDIDATE_POOL_FACTOR, help=argparse.SUPPRESS)
    parser.add_argument("--candidate-pool-scope-min", type=int, default=DEFAULT_CANDIDATE_POOL_SCOPE_MIN, help=argparse.SUPPRESS)
    parser.add_argument("--candidate-pool-max", type=int, default=DEFAULT_CANDIDATE_POOL_MAX, help=argparse.SUPPRESS)
    parser.add_argument("--rg-timeout", type=int, default=15, help="Seconds before rg fallback times out.")
    parser.add_argument("--track", default="", help="Filter all results by track.")
    parser.add_argument("--memory-type", default="", help="Filter all results by memory_type.")
    parser.add_argument("--project-id", default="", help="Filter all results by an exact normalized project_id value.")
    parser.add_argument("--current-project", default="", help="Current project id used to contain all project-scoped retrieval.")
    parser.add_argument(
        "--cross-project",
        action="store_true",
        help="Include other project-scoped memories as labeled references; never as authorization.",
    )
    parser.add_argument(
        "--as-of",
        default="",
        help="Date used for valid_until and review-due checks (YYYY-MM-DD; defaults to today).",
    )
    parser.add_argument("--user-id", default="", help="Filter all results by user_id.")
    parser.add_argument("--agent-id", default="", help="Filter all results by agent_id.")
    parser.add_argument(
        "--agent-scope",
        choices=("codex", "claude", "shared"),
        default="",
        help="Return shared memories plus memories scoped to this Agent.",
    )
    parser.add_argument("--app-id", default="", help="Filter all results by app_id.")
    parser.add_argument("--session-id", default="", help="Filter all results by session_id.")
    parser.add_argument("--status", default="", help="Filter all results by status.")
    parser.add_argument("--has-open-loop", action="store_true", help="Only return docs with open loops.")
    parser.add_argument(
        "--include-inactive",
        action="store_true",
        help="Include outdated/archived history as non-authorizing references.",
    )
    parser.add_argument(
        "--include-superseded",
        action="store_true",
        help="Include explicit historical fact records; they remain reference-only.",
    )
    parser.add_argument("--include-supporting", action="store_true", help="Include templates and directory indexes.")
    parser.add_argument(
        "--redact-legacy-logs",
        action="store_true",
        help="Irreversibly redact legacy raw search queries while retaining hashes and lengths.",
    )
    args = parser.parse_args()
    if args.query_stdin:
        if args.search or args.query:
            parser.error("--query-stdin cannot be combined with an argv query")
        payload = sys.stdin.buffer.read(64 * 1024 + 1)
        if len(payload) > 64 * 1024:
            parser.error("stdin query is too large")
        try:
            args.query = payload.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            parser.error("stdin query must be UTF-8")
    else:
        args.query = args.search or args.query
    if not args.query and not args.redact_legacy_logs:
        parser.error("query is required")
    # ``--project-id`` remains as the compatibility spelling for the caller's
    # current project. Exact application isolation is enforced by Canonical
    # Retrieve rather than by overloading document identity here.
    if args.project_id and not args.current_project:
        args.current_project = args.project_id
        args.project_id = ""
    if args.cross_project and not args.current_project:
        parser.error("--cross-project requires --current-project")
    if args.no_log and args.redact_legacy_logs:
        parser.error("--no-log cannot be combined with --redact-legacy-logs")
    if args.as_of and parsed_date(args.as_of) is None:
        parser.error("--as-of must be YYYY-MM-DD")
    args.limit = max(args.limit, 1)
    if args.no_zvec:
        args.semantic_mode = "off"
    return args


def main() -> int:
    args = parse_args()
    try:
        assert_runtime_ready("search")
        enforce_runtime_actor_scope(args)
    except RuntimeTransitionError as exc:
        if args.json:
            print(json.dumps({"ok": False, "reason_code": "RUNTIME_TRANSITION_INCOMPLETE"}))
        else:
            print(str(exc), file=sys.stderr)
        return 2
    except SearchProtocolError as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "reason_code": exc.reason_code,
                        "error": {"code": exc.reason_code},
                        "results": [],
                    },
                    ensure_ascii=True,
                )
            )
        else:
            print(exc.reason_code, file=sys.stderr)
        return 2
    if args.redact_legacy_logs:
        payload = redact_legacy_search_logs()
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"redacted={payload['redacted']} remaining_raw={payload['remaining_raw']}")
        return 0
    try:
        rows, warnings, all_enabled_backends_failed = run_search(args)
    except SearchProtocolError as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "reason_code": exc.reason_code,
                        "error": {"code": exc.reason_code},
                        "results": [],
                    },
                    ensure_ascii=True,
                )
            )
        else:
            print(exc.reason_code, file=sys.stderr)
        return 2
    except shadow_gate.ShadowGateError as exc:
        if args.json:
            print(json.dumps({
                "ok": False,
                "reason_code": str(exc),
                "ranking_mode": getattr(args, "ranking_version", DEFAULT_RANKING_VERSION),
            }, ensure_ascii=True))
        else:
            print(str(exc), file=sys.stderr)
        return 2
    except Exception:
        failure_code = (
            RETRIEVAL_BACKEND_REQUIRED_UNAVAILABLE
            if str(getattr(args, "semantic_mode", "auto") or "auto") == "required"
            else RETRIEVAL_BACKENDS_UNAVAILABLE
        )
        if args.json:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "reason_code": failure_code,
                        "error": {"code": failure_code},
                        "backend_status": getattr(args, "_backend_status", {}),
                        "degraded": True,
                        "results": [],
                        "warnings": [],
                    },
                    ensure_ascii=True,
                )
            )
        else:
            print(failure_code, file=sys.stderr)
        return 2
    failure_reason = str(getattr(args, "_failure_reason_code", "") or "")
    if not failure_reason and all_enabled_backends_failed:
        failure_reason = RETRIEVAL_BACKENDS_UNAVAILABLE
    if args.json:
        payload: dict[str, Any] = {
            "ok": not bool(failure_reason),
            "query": args.query,
            "as_of": (
                parsed_date(str(getattr(args, "as_of", "") or ""))
                or dt.datetime.now().date()
            ).isoformat(),
            "as_of_status": (
                "historical"
                if bool(str(getattr(args, "as_of", "") or "").strip())
                and parsed_date(str(getattr(args, "as_of", "") or ""))
                != dt.datetime.now().date()
                else "current"
            ),
            "ranking_version": getattr(args, "_effective_ranking_version", RANKING_VERSION),
            "ranking_mode": getattr(args, "ranking_version", DEFAULT_RANKING_VERSION),
            "shadow": (
                {
                    "ranking_version": RANKING_VERSION,
                    "result_memory_ids": getattr(args, "_shadow_result_memory_ids", []),
                    "worker_status": getattr(args, "_worker_status", "not_used"),
                    "worker_restart_count": getattr(args, "_worker_restart_count", 0),
                }
                if getattr(args, "ranking_version", DEFAULT_RANKING_VERSION) == "hybrid-v2-shadow"
                else None
            ),
            "backend_status": getattr(args, "_backend_status", {}),
            "degraded": bool(getattr(args, "_degraded", False) or failure_reason),
            "metadata_gate": getattr(args, "_metadata_gate_projection", {}),
            # A hard backend contract failure never returns candidates that a
            # caller could accidentally treat as a successful required query.
            "results": [] if failure_reason else [row.to_dict() for row in rows],
            "warnings": warnings,
        }
        if failure_reason:
            payload["error"] = {"code": failure_reason}
            payload["reason_code"] = failure_reason
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        if failure_reason:
            print(failure_reason, file=sys.stderr)
        else:
            print_human(args.query, rows, warnings)
    return 2 if failure_reason else 0


if __name__ == "__main__":
    raise SystemExit(main())
