#!/usr/bin/env python3
"""Read verified, bounded Markdown excerpts from the formal memory vault.

Search indexes are candidate finders only.  Every candidate is canonicalized,
re-read as strict UTF-8, and filtered again from its current frontmatter before
any excerpt is returned. The command never mutates Markdown; each successful
read automatically emits only a best-effort, version-bound opaque task event.
"""
from __future__ import annotations

import argparse
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
from argparse import Namespace
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from agent_memory_env import RuntimeTransitionError, assert_runtime_ready, env_value, expand_path
import agent_memory_index as memory_index
import agent_memory_intent as memory_intent
import agent_memory_observability as observability
import agent_memory_safety as memory_safety
import agent_memory_search as memory_search
import agent_memory_shadow as shadow_gate


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = expand_path(env_value("ROOT", str(RUNTIME_ROOT / "templates" / "vault")))
GIT_ROOT = expand_path(env_value("GIT_ROOT", str(VAULT_ROOT)))

WIRE_SCHEMA_VERSION = 2
_SYNTHETIC_BENCHMARK_CAPABILITY = object()
ACTORS = ("codex", "claude", "human", "migration", "test", "ailu")
FORMAL_MEMORY_TOP_LEVELS = {"用户记忆", "项目", "工作流", "决策", "agent"}
SUPPORTING_MEMORY_TYPES = {"routing", "directory_index", "template"}
DEFAULT_MAX_RESULTS = 5
DEFAULT_MAX_FILE_BYTES = 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_EXCERPT_BYTES = 12 * 1024
MAX_RESULTS_HARD_LIMIT = 100
MAX_CANDIDATES_HARD_LIMIT = 2000
MAX_REQUEST_BYTES = 64 * 1024
MAX_QUERY_CHARS = 16_384
AILU_ACTOR = "ailu"
AILU_APP_ID = "ailu"
PATH_TRACK_FLOORS = {"项目": "project", "工作流": "workflow", "决策": "decision"}
PATH_MEMORY_TYPE_FLOORS = {"项目": "project", "工作流": "workflow", "决策": "decision"}
ACTION_SENSITIVE_MEMORY_TYPES = {"fact", "atomic_fact", "current_fact"}


class RetrievalProtocolError(ValueError):
    """A root or invocation failure that prevents safe retrieval."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Candidate:
    raw_path: str
    rel_path: str
    rank: int
    memory_id: str = ""

    @property
    def reference(self) -> str:
        raw = self.rel_path or self.raw_path
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


@dataclass(frozen=True)
class Heading:
    section_id: str
    level: int
    title: str
    parent_section_id: str
    start_line: int
    end_line: int
    start_char: int
    end_char: int
    start_byte: int
    end_byte: int


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def normalized_query(raw: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", raw)).strip()


def assert_runtime_actor_identity(actor: str) -> None:
    """Prevent an argv actor from overriding memoryctl's host identity."""

    runtime_actor = unicodedata.normalize(
        "NFKC", os.environ.get("MEMORY_ACTOR", "").strip()
    ).casefold()
    requested = unicodedata.normalize("NFKC", actor.strip()).casefold()
    if runtime_actor in {"codex", "claude", "ailu"} and requested != runtime_actor:
        raise RetrievalProtocolError("ACTOR_IDENTITY_CONFLICT")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def query_sha256(query: str) -> str:
    return hashlib.sha256(normalized_query(query).encode("utf-8")).hexdigest()


def _observation_policy_state(result: dict[str, Any]) -> str:
    """Collapse retrieve policy into the controlled state-v4 event enum."""

    policy = result.get("policy") if isinstance(result.get("policy"), dict) else {}
    status = str(policy.get("status") or "").strip().casefold()
    fact_status = str(policy.get("fact_status") or result.get("fact_status") or "").strip().casefold()
    time_status = str(policy.get("time_status") or "").strip().casefold()
    review_status = str(policy.get("review_status") or "").strip().casefold()
    if status and status != "active":
        return "inactive"
    if fact_status in {"conflict", "invalid_metadata", "invalid_relation"}:
        return "conflict"
    if fact_status == "expired" or time_status == "expired":
        return "expired"
    if review_status in {"overdue", "invalid", "unverified"}:
        return "overdue"
    # The ledger has no historical enum. Unknown is the intentional
    # fail-closed representation: it can never be mistaken for a current
    # enforcement state and requires an exact live verification before use.
    as_of_status = str(
        policy.get("as_of_status") or result.get("as_of_status") or ""
    ).strip().casefold()
    if as_of_status == "historical":
        return "unknown"
    return "current"


def _record_source_opened_events(actor: str, view: str, results: list[dict[str, Any]]) -> list[str]:
    """Best-effort version-bound reads for every Canonical Retrieve result."""

    event_ids: list[str] = []
    for result in results:
        if view == "section":
            returned_bytes = int(result.get("returned_bytes", 0) or 0)
            truncated = bool(result.get("truncated", False))
        elif view == "outline":
            returned_bytes = int(result.get("outline_returned_bytes", 0) or 0)
            truncated = bool(result.get("truncated", False))
        else:
            returned_bytes = len(str(result.get("excerpt", "")).encode("utf-8"))
            truncated = bool(result.get("excerpt_truncated", False))
        event_id = observability.record_opened_original(
            actor=actor,
            rel_path=str(result.get("relative_path", "")),
            read_mode=view,
            full_utf8_bytes=int(result.get("size_bytes", 0) or 0),
            returned_utf8_bytes=returned_bytes,
            truncated=truncated,
            content_sha256=str(result.get("sha256") or result.get("source_sha256") or ""),
            memory_id=str(result.get("memory_id") or ""),
            policy_state=_observation_policy_state(result),
            requires_live_verification=bool(result.get("requires_live_verification", False)),
        )
        if event_id:
            event_ids.append(event_id)
    return event_ids


def _record_canonical_retrieve_search(
    query: str,
    results: list[dict[str, Any]],
    *,
    duration_ms: int,
    search_status: str,
    search_metadata: dict[str, Any],
    metadata_projection: dict[str, Any],
) -> str:
    """Best-effort real-traffic denominator, with no query/body persistence."""

    ranking_mode = {
        "hybrid-v1": "legacy_v1",
        "hybrid-v2-shadow": "shadow",
        "hybrid-v2": "hybrid_v2",
    }.get(str(search_metadata.get("ranking_mode", "")), "shadow")
    backend_status = search_metadata.get("backend_status")
    backend = backend_status if isinstance(backend_status, dict) else {}
    worker_status = str(backend.get("worker_status") or "not_used").casefold()
    if worker_status not in observability.WORKER_STATUSES:
        worker_status = "failed" if bool(search_metadata.get("degraded")) else "not_used"
    try:
        with memory_search.connect() as conn:
            return observability.record_search(
                conn,
                query=query,
                rel_paths=[str(item.get("relative_path", "")) for item in results],
                memory_ids=[str(item.get("memory_id", "")) for item in results],
                sources=["canonical_retrieve"],
                duration_ms=max(int(duration_ms), 0),
                search_status=search_status,
                required_live_verification_count=sum(
                    1 for item in results if bool(item.get("requires_live_verification"))
                ),
                ranking_mode=ranking_mode,
                worker_status=worker_status,
                worker_restart_count=min(
                    max(int(backend.get("worker_restart_count", 0) or 0), 0),
                    1,
                ),
                metadata_gate_mode=str(
                    metadata_projection.get("effective_mode", "shadow")
                ),
                metadata_would_block_count=max(
                    int(metadata_projection.get("would_block_count", 0) or 0),
                    0,
                ),
                metadata_reason_fingerprint=str(
                    metadata_projection.get("reason_fingerprint", "")
                ),
            )
    except (OSError, sqlite3.Error, RuntimeTransitionError, ValueError):
        return ""


def _normalized_values(raw: str) -> set[str]:
    return {
        unicodedata.normalize("NFKC", item.strip()).casefold()
        for item in raw.split(",")
        if item.strip()
    }


def _normalized_identifier(raw: str) -> str:
    return unicodedata.normalize("NFKC", raw.strip()).casefold()


def validate_ailu_scope_request(app_id: str, project_id: str) -> tuple[str, str]:
    """Return the canonical Ailu scope or fail before candidate discovery.

    The app boundary is fixed centrally and every request selects exactly one
    project. ``global`` is an explicit project scope; omitted, ``shared``, and
    comma-separated scopes fail closed instead of becoming an implicit shared
    channel.
    """

    normalized_app = _normalized_identifier(app_id)
    if not normalized_app:
        raise RetrievalProtocolError("APP_ID_REQUIRED")
    if normalized_app != AILU_APP_ID:
        raise RetrievalProtocolError("APP_ID_UNSUPPORTED")
    normalized_project = _normalized_identifier(project_id)
    if not normalized_project:
        raise RetrievalProtocolError("PROJECT_ID_REQUIRED")
    if normalized_project == "shared" or "," in normalized_project:
        raise RetrievalProtocolError("PROJECT_ID_INVALID")
    return AILU_APP_ID, normalized_project


def _field_matches(expected: str, actual: str) -> bool:
    wanted = unicodedata.normalize("NFKC", expected.strip()).casefold()
    return bool(wanted) and wanted in _normalized_values(actual)


def _bool_value(value: object) -> bool:
    return memory_index.as_text(value).strip().casefold() in {"1", "true", "yes", "on", "required"}


def _safe_warning(
    code: str,
    *,
    candidate: Candidate | None = None,
    relative_path: str = "",
    reason: str = "",
) -> dict[str, str]:
    warning = {"code": code}
    if relative_path:
        warning["relative_path"] = relative_path
    elif candidate is not None:
        warning["candidate_ref"] = candidate.reference
    if reason:
        warning["reason"] = re.sub(r"[^A-Z0-9_]+", "_", reason.upper()).strip("_")[:80]
    return warning


def _sorted_warnings(rows: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    unique: dict[tuple[tuple[str, str], ...], dict[str, str]] = {}
    for row in rows:
        key = tuple(sorted((str(name), str(value)) for name, value in row.items()))
        unique.setdefault(key, row)
    return sorted(
        unique.values(),
        key=lambda item: (
            item.get("code", ""),
            item.get("relative_path", ""),
            item.get("candidate_ref", ""),
            item.get("reason", ""),
        ),
    )


def validate_vault_root() -> Path:
    lexical = Path(os.path.abspath(os.path.expandvars(str(VAULT_ROOT.expanduser()))))
    try:
        metadata = lexical.lstat()
    except FileNotFoundError as exc:
        raise RetrievalProtocolError("VAULT_MISSING") from exc
    except OSError as exc:
        raise RetrievalProtocolError("VAULT_UNREADABLE") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise RetrievalProtocolError("VAULT_ROOT_SYMLINK")
    if not stat.S_ISDIR(metadata.st_mode):
        raise RetrievalProtocolError("VAULT_NOT_DIRECTORY")
    try:
        return lexical.resolve(strict=True)
    except OSError as exc:
        raise RetrievalProtocolError("VAULT_UNRESOLVABLE") from exc


def _search_namespace(
    query: str,
    limit: int,
    *,
    actor: str = "",
    app_id: str = "",
    project_id: str = "",
    as_of: str = "",
    semantic_mode: str = memory_search.DEFAULT_SEMANTIC_MODE,
    cross_project: bool = False,
    include_inactive: bool = False,
) -> Namespace:
    application_client = actor == AILU_ACTOR
    return Namespace(
        query=query,
        limit=limit,
        no_zvec=semantic_mode == "off",
        semantic_mode=semantic_mode,
        ranking_version=memory_search.DEFAULT_RANKING_VERSION,
        no_log=True,
        force_rg=False,
        zvec_timeout=14.0,
        zvec_lock_timeout=memory_search.DEFAULT_ZVEC_LOCK_TIMEOUT,
        worker_cold_timeout=memory_search.DEFAULT_WORKER_COLD_TIMEOUT,
        worker_warm_timeout=memory_search.DEFAULT_WORKER_WARM_TIMEOUT,
        worker_idle_seconds=memory_search.DEFAULT_WORKER_IDLE_SECONDS,
        zvec_max_distance=memory_search.DEFAULT_ZVEC_MAX_DISTANCE,
        candidate_pool_min=memory_search.DEFAULT_CANDIDATE_POOL_MIN,
        candidate_pool_factor=memory_search.DEFAULT_CANDIDATE_POOL_FACTOR,
        candidate_pool_scope_min=memory_search.DEFAULT_CANDIDATE_POOL_SCOPE_MIN,
        candidate_pool_max=memory_search.DEFAULT_CANDIDATE_POOL_MAX,
        rg_timeout=1,
        track="",
        memory_type="",
        project_id=project_id if application_client and project_id else "",
        current_project=project_id,
        cross_project=cross_project if not application_client else False,
        as_of=as_of,
        user_id="",
        agent_id="",
        agent_scope="shared" if application_client else "",
        app_id=app_id if application_client else "",
        session_id="",
        status="",
        has_open_loop=False,
        # The current Markdown, not the possibly stale index row, decides
        # status and supporting-document eligibility below.
        # Candidate discovery stays broad; current Markdown enforces the
        # caller's inactive policy below.
        include_inactive=True,
        include_supporting=True,
        # Candidate discovery must not discard a historical version before
        # canonical Markdown and the caller's as-of date resolve the graph.
        include_superseded=True,
        # Private in-process marker consumed by the Search actor boundary.
        # It is not exposed as a CLI option.
        _canonical_retrieve_actor=actor,
    )


def _run_candidate_search(
    query: str,
    limit: int,
    *,
    actor: str = "",
    app_id: str = "",
    project_id: str = "",
    as_of: str = "",
    semantic_mode: str = memory_search.DEFAULT_SEMANTIC_MODE,
    cross_project: bool = False,
    include_inactive: bool = False,
) -> tuple[list[Any], list[str], Namespace]:
    """Run the private in-process candidate lane used by Retrieve/Writer.

    In particular, Ailu must never gain access to the raw Search CLI.  Its
    canonical Retrieve and confirmed Writer can still discover candidates by
    using this namespace, whose private actor marker is constructed from the
    already-authenticated caller rather than from user-controlled argv.
    """

    namespace = _search_namespace(
        query,
        limit,
        actor=actor,
        app_id=app_id,
        project_id=project_id,
        as_of=as_of,
        semantic_mode=semantic_mode,
        cross_project=cross_project,
        include_inactive=include_inactive,
    )
    try:
        rows, backend_warnings, all_failed = memory_search.run_search(namespace)
        if bool(getattr(namespace, "_hard_failure", False)):
            raise RetrievalProtocolError(
                memory_search.RETRIEVAL_BACKEND_REQUIRED_UNAVAILABLE
            )
        if all_failed:
            raise RetrievalProtocolError(memory_search.RETRIEVAL_BACKENDS_UNAVAILABLE)
    except RetrievalProtocolError:
        raise
    except Exception as exc:
        reason = (
            memory_search.RETRIEVAL_BACKEND_REQUIRED_UNAVAILABLE
            if semantic_mode == "required"
            else memory_search.RETRIEVAL_BACKENDS_UNAVAILABLE
        )
        raise RetrievalProtocolError(reason) from exc
    return rows, [str(item) for item in backend_warnings], namespace


def search_candidates(
    query: str,
    max_results: int,
    *,
    actor: str = "",
    app_id: str = "",
    project_id: str = "",
    as_of: str = "",
    semantic_mode: str = memory_search.DEFAULT_SEMANTIC_MODE,
    cross_project: bool = False,
    include_inactive: bool = False,
) -> tuple[list[Candidate], list[dict[str, str]], dict[str, Any]]:
    scope_floor = (
        memory_search.DEFAULT_CANDIDATE_POOL_SCOPE_MIN
        if project_id or cross_project
        else memory_search.DEFAULT_CANDIDATE_POOL_MIN
    )
    candidate_limit = min(
        max(
            max_results * memory_search.DEFAULT_CANDIDATE_POOL_FACTOR,
            memory_search.DEFAULT_CANDIDATE_POOL_MIN,
            scope_floor,
        ),
        min(MAX_CANDIDATES_HARD_LIMIT, memory_search.DEFAULT_CANDIDATE_POOL_MAX),
    )
    warnings: list[dict[str, str]] = []
    rows, backend_warnings, namespace = _run_candidate_search(
        query,
        candidate_limit,
        actor=actor,
        app_id=app_id,
        project_id=project_id,
        as_of=as_of,
        semantic_mode=semantic_mode,
        cross_project=cross_project,
        include_inactive=include_inactive,
    )

    for raw_warning in backend_warnings:
        normalized = str(raw_warning).casefold()
        code = (
            "SEARCH_INDEX_MISSING"
            if "index missing" in normalized or "table missing" in normalized
            else "SEARCH_BACKEND_WARNING"
        )
        warnings.append(
            {
                "code": code,
                "warning_ref": hashlib.sha256(str(raw_warning).encode("utf-8")).hexdigest()[:16],
            }
        )
    candidates = [
        Candidate(
            raw_path=str(row.path or ""),
            rel_path=str(row.rel_path or ""),
            rank=rank,
            memory_id=str(row.memory_id or ""),
        )
        for rank, row in enumerate(rows, 1)
    ]
    return candidates, warnings, {
        "ranking_version": str(getattr(namespace, "_effective_ranking_version", memory_search.RANKING_VERSION)),
        "ranking_mode": str(getattr(namespace, "ranking_version", memory_search.DEFAULT_RANKING_VERSION)),
        "shadow_result_memory_ids": list(getattr(namespace, "_shadow_result_memory_ids", [])),
        "backend_status": dict(getattr(namespace, "_backend_status", {})),
        "degraded": bool(getattr(namespace, "_degraded", bool(backend_warnings))),
    }


def _read_regular_file(path: Path, max_bytes: int, *, oversize_code: str = "FILE_TOO_LARGE") -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RetrievalProtocolError("FILE_NOT_REGULAR")
        if metadata.st_size > max_bytes:
            raise RetrievalProtocolError(oversize_code)
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
            raise RetrievalProtocolError(oversize_code)
        return payload
    finally:
        os.close(descriptor)


def _frontmatter_text(text: str) -> str:
    normalized = text.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    if normalized.startswith("---\n"):
        remainder = normalized[4:]
        delimiter = re.search(r"(?m)^---.*$", remainder)
        if delimiter is None or delimiter.group(0) != "---":
            raise RetrievalProtocolError("FRONTMATTER_INVALID")
        seen: set[str] = set()
        for line in remainder[: delimiter.start()].splitlines():
            if not line or line.startswith((" ", "-", "#")) or ":" not in line:
                continue
            key = line.split(":", 1)[0].strip()
            if key in memory_index.PROTECTED_FRONTMATTER_KEYS and key in seen:
                raise RetrievalProtocolError("FRONTMATTER_DUPLICATE_KEY")
            seen.add(key)
    return normalized


def _body_without_frontmatter(text: str) -> str:
    if not text.startswith("---\n"):
        return text
    end = text.find("\n---", 4)
    if end == -1:
        return ""
    after = end + 4
    if after < len(text) and text[after] == "\n":
        after += 1
    return text[after:]


def _preferred_excerpt(text: str) -> str:
    body = _body_without_frontmatter(text).strip()
    lines = body.splitlines()
    start: int | None = None
    for index, line in enumerate(lines):
        if re.match(r"^##\s+当前有效摘要\s*$", line.strip()):
            start = index + 1
            break
    if start is not None:
        captured: list[str] = []
        for line in lines[start:]:
            if re.match(r"^#{1,2}\s+", line):
                break
            captured.append(line)
        preferred = "\n".join(captured).strip()
        if preferred:
            return preferred
    return body


def _bounded_utf8(text: str, max_bytes: int) -> tuple[str, bool]:
    payload = text.encode("utf-8")
    if len(payload) <= max_bytes:
        return text, False
    marker = "\n…".encode("utf-8")
    available = max(max_bytes - len(marker), 0)
    truncated = payload[:available].decode("utf-8", errors="ignore").rstrip()
    if max_bytes >= len(marker):
        truncated += marker.decode("utf-8")
    return truncated, True


def _bounded_utf8_page(text: str, max_bytes: int, offset_chars: int) -> tuple[str, bool, int | None]:
    """Return a UTF-8-safe page and its next character offset.

    Unlike the legacy query excerpt, a section page does not append a marker:
    every returned character belongs to the source and offsets can therefore
    be replayed without gaps or duplication.
    """

    if offset_chars < 0 or offset_chars > len(text):
        raise RetrievalProtocolError("OFFSET_INVALID")
    remaining = text[offset_chars:]
    if len(remaining.encode("utf-8")) <= max_bytes:
        return remaining, False, None
    encoded = remaining.encode("utf-8")[:max_bytes]
    page = encoded.decode("utf-8", errors="ignore")
    if not page:
        raise RetrievalProtocolError("BYTE_LIMIT_INVALID")
    next_offset = offset_chars + len(page)
    return page, True, next_offset


def _body_start_char(text: str) -> int:
    offset = 1 if text.startswith("\ufeff") else 0
    lines = text[offset:].splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        return 0
    cursor = offset + len(lines[0])
    for line in lines[1:]:
        cursor += len(line)
        if line.rstrip("\r\n") == "---":
            return cursor
    return 0


def _markdown_headings(text: str) -> list[Heading]:
    """Parse ATX H1-H6 headings outside frontmatter and fenced code blocks."""

    body_start = _body_start_char(text)
    line_starts: list[int] = []
    line_byte_starts: list[int] = []
    lines = text.splitlines(keepends=True)
    cursor = 0
    byte_cursor = 0
    for line in lines:
        line_starts.append(cursor)
        line_byte_starts.append(byte_cursor)
        cursor += len(line)
        byte_cursor += len(line.encode("utf-8"))
    if not lines and text == "":
        return []
    if cursor < len(text):
        # ``splitlines(keepends=True)`` normally includes the final unterminated
        # line, but retain a safe fallback for unusual Unicode separators.
        line_starts.append(cursor)
        line_byte_starts.append(byte_cursor)
        lines.append(text[cursor:])

    parsed: list[dict[str, Any]] = []
    fence_char = ""
    fence_length = 0
    heading_pattern = re.compile(r"^[ \t]{0,3}(#{1,6})(?:[ \t]+(.*?)|[ \t]*)$")
    fence_pattern = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})(.*)$")

    for index, raw_line in enumerate(lines):
        start_char = line_starts[index]
        start_byte = line_byte_starts[index]
        if start_char < body_start:
            continue
        line = raw_line.rstrip("\r\n")
        if index == 0 and line.startswith("\ufeff"):
            line = line.removeprefix("\ufeff")
            start_char += 1
            start_byte += len("\ufeff".encode("utf-8"))
        fence = fence_pattern.match(line)
        if fence_char:
            if fence:
                marker = fence.group(1)
                tail = fence.group(2)
                if marker[0] == fence_char and len(marker) >= fence_length and not tail.strip():
                    fence_char = ""
                    fence_length = 0
            continue
        if fence:
            marker = fence.group(1)
            fence_char = marker[0]
            fence_length = len(marker)
            continue
        matched = heading_pattern.match(line)
        if not matched:
            continue
        title = (matched.group(2) or "").strip()
        title = re.sub(r"[ \t]+#+[ \t]*$", "", title).rstrip()
        parsed.append(
            {
                "level": len(matched.group(1)),
                "title": title,
                "start_line": index + 1,
                "start_char": start_char,
                "start_byte": start_byte,
            }
        )

    stack: list[int] = []
    parent_ids: list[str] = []
    end_chars = [len(text)] * len(parsed)
    end_bytes = [len(text.encode("utf-8"))] * len(parsed)
    end_lines = [len(text.splitlines())] * len(parsed)
    for index, item in enumerate(parsed):
        level = int(item["level"])
        while stack and int(parsed[stack[-1]]["level"]) >= level:
            completed = stack.pop()
            end_chars[completed] = int(item["start_char"])
            end_bytes[completed] = int(item["start_byte"])
            end_lines[completed] = max(
                int(parsed[completed]["start_line"]),
                int(item["start_line"]) - 1,
            )
        parent_id = f"s{stack[-1] + 1:04d}" if stack else ""
        parent_ids.append(parent_id)
        stack.append(index)

    headings: list[Heading] = []
    for index, item in enumerate(parsed):
        level = int(item["level"])
        section_id = f"s{index + 1:04d}"
        start_char = int(item["start_char"])
        headings.append(
            Heading(
                section_id=section_id,
                level=level,
                title=str(item["title"]),
                parent_section_id=parent_ids[index],
                start_line=int(item["start_line"]),
                end_line=max(int(item["start_line"]), end_lines[index]),
                start_char=start_char,
                end_char=end_chars[index],
                start_byte=int(item["start_byte"]),
                end_byte=end_bytes[index],
            )
        )
    return headings


def _heading_payload(heading: Heading) -> dict[str, Any]:
    return {
        "section_id": heading.section_id,
        "level": heading.level,
        "title": heading.title,
        "parent_section_id": heading.parent_section_id or None,
        "start_line": heading.start_line,
        "end_line": heading.end_line,
        "start_char": heading.start_char,
        "end_char": heading.end_char,
        "start_byte": heading.start_byte,
        "end_byte": heading.end_byte,
        "size_bytes": heading.end_byte - heading.start_byte,
    }


def _outline_page(
    headings: list[Heading],
    *,
    max_bytes: int,
    offset: int,
) -> tuple[list[dict[str, Any]], bool, int | None, int]:
    """Return a JSON-byte-bounded outline page.

    The offset is a heading index rather than a source character offset. A
    single unusually long title is UTF-8-safely shortened so every successful
    page makes progress without exceeding the caller's byte budget.
    """

    if offset < 0 or offset > len(headings):
        raise RetrievalProtocolError("OUTLINE_OFFSET_INVALID")
    if max_bytes < 2:
        raise RetrievalProtocolError("OUTLINE_BYTE_LIMIT_TOO_SMALL")
    page: list[dict[str, Any]] = []
    used_bytes = 2  # JSON array brackets.

    def encoded_size(item: dict[str, Any]) -> int:
        return len(
            json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )

    for heading in headings[offset:]:
        item = _heading_payload(heading)
        item_bytes = encoded_size(item)
        separator_bytes = 1 if page else 0
        if used_bytes + separator_bytes + item_bytes > max_bytes:
            if page:
                break
            original_title = str(item["title"])
            item["title_truncated"] = True
            low, high = 0, len(original_title)
            while low < high:
                middle = (low + high + 1) // 2
                item["title"] = original_title[:middle]
                if 2 + encoded_size(item) <= max_bytes:
                    low = middle
                else:
                    high = middle - 1
            item["title"] = original_title[:low]
            item_bytes = encoded_size(item)
            if 2 + item_bytes > max_bytes:
                raise RetrievalProtocolError("OUTLINE_BYTE_LIMIT_TOO_SMALL")
        page.append(item)
        used_bytes += separator_bytes + item_bytes
    next_offset = offset + len(page)
    truncated = next_offset < len(headings)
    return page, truncated, next_offset if truncated else None, used_bytes


def _contains_secret(text: str) -> bool:
    normalized = memory_safety.normalize_for_detection(text)
    return any(pattern.search(normalized) for pattern in memory_safety.SECRET_PATTERNS)


def _canonical_path_metadata_policy(
    path: Path,
    meta: dict[str, object],
    *,
    inferred_memory_type: str,
    inferred_track: str,
    status: str,
) -> dict[str, Any]:
    """Apply the canonical path floor to live Markdown metadata.

    Missing v4 risk metadata remains part of the seven-day shadow gate. An
    affirmative downgrade, however, is never trusted: a normal document under
    项目/工作流/决策 cannot self-declare governance, routing, template, misc, or
    structural semantics to suppress fact/validity signals.
    """

    try:
        rel_path = path.resolve(strict=False).relative_to(
            VAULT_ROOT.resolve(strict=True)
        ).as_posix()
    except (OSError, ValueError):
        return {
            "memory_type": inferred_memory_type,
            "track": inferred_track,
            "risk_class": memory_index.as_text(meta.get("risk_class")).casefold(),
            "reason_codes": ["PATH_POLICY_UNRESOLVED"],
        }
    relative = Path(rel_path)
    if len(relative.parts) < 2:
        return {
            "memory_type": inferred_memory_type,
            "track": inferred_track,
            "risk_class": memory_index.as_text(meta.get("risk_class")).casefold(),
            "reason_codes": [],
        }
    top = relative.parts[0]
    floor_track = PATH_TRACK_FLOORS.get(top, "")
    floor_type = PATH_MEMORY_TYPE_FLOORS.get(top, "")
    if not floor_track or relative.name == "README.md" or relative.name.startswith("_模板"):
        return {
            "memory_type": inferred_memory_type,
            "track": inferred_track,
            "risk_class": memory_index.as_text(meta.get("risk_class")).casefold(),
            "reason_codes": [],
        }
    declared_type = memory_index.as_text(meta.get("memory_type")).casefold()
    declared_track = memory_index.as_text(meta.get("track")).casefold()
    risk_class = memory_index.as_text(meta.get("risk_class")).casefold()
    reasons: list[str] = []
    if declared_track and declared_track != floor_track:
        reasons.append("PATH_TRACK_DOWNGRADE")
    allowed_raised_types = ACTION_SENSITIVE_MEMORY_TYPES | {"decision"}
    if declared_type and declared_type not in {floor_type, *allowed_raised_types}:
        reasons.append("PATH_MEMORY_TYPE_DOWNGRADE")
    if risk_class and risk_class not in {"ordinary", "action_sensitive"}:
        reasons.append("RISK_CLASS_INVALID")
    effective_type = (
        declared_type
        if declared_type in allowed_raised_types
        else floor_type
    )
    temporal_policy = memory_index.as_text(meta.get("temporal_policy")).casefold()
    fact = memory_index.fact_metadata(meta)
    action_sensitive = bool(
        str(status or "active").casefold() == "active"
        and (
            floor_track == "decision"
            or effective_type in ACTION_SENSITIVE_MEMORY_TYPES
            or temporal_policy == "expiring"
            or memory_index.as_text(meta.get("valid_until"))
            or bool(fact.get("enabled"))
            or "事实-" in relative.stem
        )
    )
    # A missing risk_class is handled by metadata shadow enforcement. A
    # present ordinary declaration cannot lower an objectively sensitive path
    # or fact/validity signal.
    if action_sensitive and risk_class == "ordinary":
        reasons.append("RISK_CLASS_DOWNGRADE")
    return {
        "memory_type": effective_type,
        "track": floor_track,
        "risk_class": risk_class,
        "reason_codes": list(dict.fromkeys(reasons)),
    }


def _metadata_for(path: Path, text: str) -> dict[str, Any]:
    meta = memory_index.parse_frontmatter(text)
    try:
        rel_path = path.resolve(strict=False).relative_to(
            VAULT_ROOT.resolve(strict=True)
        ).as_posix()
    except (OSError, ValueError):
        rel_path = path.name
    memory_type, track, _inferred_project_id, status = memory_index.infer_from_path(path, meta)
    path_policy = _canonical_path_metadata_policy(
        path,
        meta,
        inferred_memory_type=memory_type,
        inferred_track=track,
        status=status,
    )
    memory_type = str(path_policy["memory_type"])
    track = str(path_policy["track"])
    verified_at, verified_at_source = memory_index.extract_verified_at(text, meta, memory_type, status)
    title = memory_index.title_from_markdown(text, path)
    memory_id = memory_index.as_text(meta.get("memory_id")).strip()
    if memory_id and not re.fullmatch(r"[0-9a-f]{64}", memory_id):
        raise RetrievalProtocolError("MEMORY_ID_INVALID")
    return {
        "meta": meta,
        "rel_path": rel_path,
        "memory_id": memory_id,
        "memory_type": memory_type,
        "track": track,
        "risk_class": str(path_policy["risk_class"]),
        "risk_class_source": "frontmatter" if "risk_class" in meta else "",
        "path_policy_reason_codes": list(path_policy["reason_codes"]),
        # Missing project_id is an intentionally unscoped shared reference;
        # path-derived names are indexing aids, not an authorization scope.
        "project_id": memory_index.as_text(meta.get("project_id")),
        "status": status,
        "app_id": memory_index.as_text(meta.get("app_id"), memory_index.DEFAULT_APP_ID),
        "agent_scope": memory_index.as_text(meta.get("agent_scope"), "shared").casefold(),
        "verified_at": verified_at,
        "verified_at_source": verified_at_source,
        "fact_key": memory_index.as_text(meta.get("fact_key")),
        "valid_from": memory_index.as_text(meta.get("valid_from")),
        "valid_until": memory_index.as_text(meta.get("valid_until")),
        "supersedes": memory_index.as_list(meta.get("supersedes")),
        "review_after_days": memory_index.infer_review_after_days(
            path,
            title,
            memory_type,
            status,
            meta,
        ),
        "verification_mode": memory_index.as_text(meta.get("verification_mode")).casefold(),
        "explicit_live_verification": _bool_value(meta.get("requires_live_verification")),
    }


def _scope_status(actual_project: str, requested_project: str) -> str:
    projects = _normalized_values(actual_project)
    if not projects:
        return "unscoped_shared_reference"
    if projects <= {"global", "shared"}:
        return "global_shared"
    if requested_project and _field_matches(requested_project, actual_project):
        return "current_project"
    if not requested_project:
        return "project_context_unknown"
    return "cross_project_reference"


def _metadata_rejection(
    metadata: dict[str, Any],
    actor: str,
    app_id: str,
    project_id: str,
    *,
    relative_path: str = "",
    cross_project: bool = False,
    include_inactive: bool = False,
    accepted_statuses: set[str] | None = None,
) -> str:
    normalized_status = unicodedata.normalize("NFKC", str(metadata["status"])).casefold()
    if accepted_statuses is None:
        effective_statuses = set(memory_search.DEFAULT_RETRIEVABLE_STATUSES)
        if include_inactive:
            effective_statuses.update(memory_search.INACTIVE_REFERENCE_STATUSES)
    else:
        effective_statuses = {
            unicodedata.normalize("NFKC", str(status)).casefold()
            for status in accepted_statuses
        }
    if normalized_status not in effective_statuses:
        return "STATUS_NOT_ACTIVE"
    agent_scope = str(metadata["agent_scope"])
    allowed_scopes = {"shared"}
    if actor in {"codex", "claude"}:
        allowed_scopes.add(actor)
    if agent_scope not in allowed_scopes:
        return "AGENT_SCOPE_MISMATCH"
    if actor == AILU_ACTOR:
        if _normalized_values(str(metadata["app_id"])) != {_normalized_identifier(app_id)}:
            return "APP_ID_MISMATCH"
    elif app_id and not _field_matches(app_id, str(metadata["app_id"])):
        return "APP_ID_MISMATCH"
    scope_status = _scope_status(str(metadata["project_id"]), project_id)
    if actor == AILU_ACTOR:
        # Ailu reads are always exact single-project reads. ``global`` is not a
        # synonym for shared/unscoped data and is confined to user memory.
        actual_projects = _normalized_values(str(metadata["project_id"]))
        normalized_project = _normalized_identifier(project_id)
        if actual_projects != {normalized_project}:
            return "PROJECT_SCOPE_MISMATCH"
        if normalized_project == "global" and relative_path:
            parts = Path(relative_path).parts
            if not parts or parts[0] != "用户记忆":
                return "GLOBAL_SCOPE_TARGET_INVALID"
    elif scope_status == "cross_project_reference" and not cross_project:
        return "PROJECT_SCOPE_MISMATCH"
    if str(metadata["memory_type"]) in SUPPORTING_MEMORY_TYPES:
        return "SUPPORTING_DOCUMENT_EXCLUDED"
    return ""


def _live_verification(metadata: dict[str, Any], as_of: dt.date) -> tuple[dict[str, Any], list[str], str]:
    reasons: list[str] = []
    time_status = "unspecified"
    valid_until = str(metadata["valid_until"])
    if valid_until:
        boundary = memory_search.parsed_date(valid_until)
        if boundary is None:
            time_status = "invalid"
            reasons.append("invalid_valid_until")
        else:
            if boundary < as_of:
                time_status = "expired"
                reasons.append("expired_memory_reference_only")
            elif boundary == as_of:
                time_status = "expires_today"
                reasons.append("memory_expires_today")
            else:
                time_status = "current"
    review_status, review_due_at, review_warnings = memory_search.review_policy(
        str(metadata["verified_at"]),
        str(metadata["verified_at_source"]),
        metadata["review_after_days"],
        as_of,
    )
    reasons.extend(review_warnings)
    if str(metadata["verification_mode"]) == "needs_review":
        reasons.append("verification_needed")
    if bool(metadata["explicit_live_verification"]):
        reasons.append("frontmatter_requires_live_verification")
    # Deployment/test claims can bind to the exact installed Runtime rather
    # than inheriting a misleading calendar-only 90-day review window. A
    # version change invalidates authority, never erases historical discovery.
    bound_runtime = metadata.get("meta", {}).get("runtime_manifest_sha256", "")
    if "runtime_manifest_sha256" in metadata.get("meta", {}):
        if not isinstance(bound_runtime, str) or re.fullmatch(r"[0-9a-f]{64}", bound_runtime) is None:
            reasons.append("runtime_binding_invalid")
        else:
            try:
                actual_runtime = memory_search.shadow_gate.runtime_binding()["manifest_sha256"]
            except (OSError, ValueError, memory_search.shadow_gate.ShadowGateError):
                reasons.append("runtime_binding_unavailable")
            else:
                if bound_runtime != actual_runtime:
                    reasons.append("runtime_version_changed_reference_only")
    reasons = list(dict.fromkeys(reasons))
    return (
        {
            "required": bool(reasons),
            "reasons": reasons,
            "verification_mode": str(metadata["verification_mode"]),
            "review_status": review_status,
            "review_due_at": review_due_at,
        },
        reasons,
        time_status,
    )


def _canonical_temporal_policy(
    rel_path: str,
    raw_text: str,
    metadata: dict[str, Any],
    as_of: dt.date,
) -> dict[str, str]:
    """Resolve temporal state only when the derived row matches current Markdown."""

    fact_key = str(metadata.get("fact_key", ""))
    supersedes = metadata.get("supersedes")
    current_temporal = bool(fact_key or supersedes)
    if not current_temporal:
        return {
            "fact_key": "",
            "valid_from": str(metadata.get("valid_from", "")),
            "fact_status": "not_fact",
            "current_fact_path": "",
            "superseded_by": "",
            "superseded_at": "",
            "fact_reason_code": "",
        }
    result = memory_search.SearchResult(
        path="",
        rel_path=rel_path,
        fact_key=fact_key,
        valid_from=str(metadata.get("valid_from", "")),
        valid_until=str(metadata.get("valid_until", "")),
    )
    try:
        with memory_search.connect(read_only=True) as conn:
            indexed = conn.execute(
                "SELECT sha256, fact_key FROM memory_docs WHERE rel_path=? LIMIT 1",
                (rel_path,),
            ).fetchone()
            current_sha = memory_index.sha256_text(raw_text)
            if indexed is None or str(indexed["sha256"] or "") != current_sha:
                result.fact_status = "invalid_relation"
                result.fact_reason_code = "TEMPORAL_INDEX_STALE"
            else:
                memory_search.annotate_temporal_from_db(result, conn, as_of)
    except (OSError, sqlite3.Error, ValueError):
        if not current_temporal:
            result.fact_status = "not_fact"
            result.fact_reason_code = ""
        else:
            result.fact_status = "invalid_relation"
            result.fact_reason_code = "TEMPORAL_INDEX_UNAVAILABLE"
    return {
        "fact_key": result.fact_key,
        "valid_from": result.valid_from,
        "fact_status": result.fact_status,
        "current_fact_path": result.current_fact_path,
        "superseded_by": result.superseded_by,
        "superseded_at": result.superseded_at,
        "fact_reason_code": result.fact_reason_code,
    }
def current_git_head() -> tuple[str, dict[str, str] | None]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(GIT_ROOT), "rev-parse", "--verify", "HEAD"],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        reference = hashlib.sha256(type(exc).__name__.encode("utf-8")).hexdigest()[:16]
        return "", {"code": "GIT_HEAD_UNAVAILABLE", "warning_ref": reference}
    head = completed.stdout.strip().lower()
    if completed.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40,64}", head):
        return "", {"code": "GIT_HEAD_UNAVAILABLE"}
    return head, None


def retrieve(
    *,
    actor: str,
    app_id: str,
    project_id: str,
    query: str,
    max_results: int,
    max_file_bytes: int,
    max_total_bytes: int,
    max_excerpt_bytes: int,
    as_of: str = "",
    candidates: list[Candidate] | None = None,
    view: str = "query",
    file_path: str = "",
    section_id: str = "",
    expected_sha256: str = "",
    offset_chars: int = 0,
    outline_offset: int = 0,
    current_project: str = "",
    cross_project: bool = False,
    include_inactive: bool = False,
    semantic_mode: str = memory_search.DEFAULT_SEMANTIC_MODE,
    _observation_capability: object | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    synthetic_benchmark = (
        _observation_capability is _SYNTHETIC_BENCHMARK_CAPABILITY
    )
    validate_vault_root()
    normalized = normalized_query(query)
    if view not in {"query", "outline", "section"}:
        raise RetrievalProtocolError("VIEW_INVALID")
    if view == "query" and not normalized:
        raise RetrievalProtocolError("QUERY_REQUIRED")
    if view == "query" and file_path:
        raise RetrievalProtocolError("FILE_OPTION_INVALID")
    if view in {"outline", "section"}:
        if not file_path or len(file_path) > 4096 or "\x00" in file_path:
            raise RetrievalProtocolError("FILE_REQUIRED")
        if candidates is None:
            candidates = [Candidate(raw_path=file_path, rel_path=file_path, rank=1)]
    if view == "section":
        if not re.fullmatch(r"s\d{4,}", section_id):
            raise RetrievalProtocolError("SECTION_ID_REQUIRED")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
            raise RetrievalProtocolError("EXPECTED_SHA256_REQUIRED")
    elif section_id or expected_sha256 or offset_chars:
        raise RetrievalProtocolError("SECTION_OPTIONS_INVALID")
    if offset_chars < 0:
        raise RetrievalProtocolError("OFFSET_INVALID")
    if outline_offset < 0:
        raise RetrievalProtocolError("OUTLINE_OFFSET_INVALID")
    if view != "outline" and outline_offset:
        raise RetrievalProtocolError("OUTLINE_OPTIONS_INVALID")
    if actor not in ACTORS:
        raise RetrievalProtocolError("ACTOR_UNSUPPORTED")
    if actor == AILU_ACTOR:
        app_id, project_id = validate_ailu_scope_request(app_id, project_id)
        current_project = project_id
        cross_project = False
        include_inactive = False
    else:
        current_project = normalized_query(current_project or project_id)
    if semantic_mode not in {"auto", "off", "required"}:
        raise RetrievalProtocolError("SEMANTIC_MODE_INVALID")
    if not 1 <= max_results <= MAX_RESULTS_HARD_LIMIT:
        raise RetrievalProtocolError("MAX_RESULTS_INVALID")
    if min(max_file_bytes, max_total_bytes, max_excerpt_bytes) <= 0:
        raise RetrievalProtocolError("BYTE_LIMIT_INVALID")
    if as_of:
        as_of_date = memory_search.parsed_date(as_of)
        if as_of_date is None:
            raise RetrievalProtocolError("AS_OF_INVALID")
    else:
        as_of_date = dt.datetime.now().date()
    as_of_status = (
        "historical"
        if bool(as_of) and as_of_date != dt.datetime.now().date()
        else "current"
    )

    warnings: list[dict[str, str]] = []
    search_metadata: dict[str, Any] = {
        "ranking_version": memory_search.RANKING_VERSION,
        "backend_status": {"candidate_source": "provided"},
        "degraded": False,
    }
    if candidates is None:
        try:
            candidates, search_warnings, search_metadata = search_candidates(
                normalized,
                max_results,
                actor=actor,
                app_id=app_id,
                project_id=current_project,
                as_of=as_of_date.isoformat(),
                semantic_mode=semantic_mode,
                cross_project=cross_project,
                include_inactive=include_inactive,
            )
        except RetrievalProtocolError:
            if view == "query" and not synthetic_benchmark:
                try:
                    empty_projection = shadow_gate.metadata_gate_projection([])
                except shadow_gate.ShadowGateError:
                    empty_projection = {
                        "effective_mode": "shadow",
                        "would_block_count": 0,
                        "reason_fingerprint": "",
                    }
                _record_canonical_retrieve_search(
                    normalized,
                    [],
                    duration_ms=round((time.monotonic() - started) * 1000),
                    search_status="backend_failed",
                    search_metadata={
                        "ranking_mode": memory_search.DEFAULT_RANKING_VERSION,
                        "backend_status": {"worker_status": "failed"},
                        "degraded": True,
                    },
                    metadata_projection=empty_projection,
                )
            raise
        warnings.extend(search_warnings)

    git_head, git_warning = current_git_head()
    if git_warning:
        warnings.append(git_warning)

    results: list[dict[str, Any]] = []
    seen_targets: set[str] = set()
    seen_explicit_memory_ids: set[str] = set()
    bytes_inspected = 0
    for candidate in candidates:
        if len(results) >= max_results:
            break
        raw_target = candidate.raw_path or candidate.rel_path
        try:
            target = memory_intent.canonical_target(raw_target)
        except memory_intent.IntentError as exc:
            warnings.append(_safe_warning("CANDIDATE_REJECTED", candidate=candidate, reason=exc.reason_code))
            continue
        except OSError:
            warnings.append(_safe_warning("CANDIDATE_REJECTED", candidate=candidate, reason="PATH_UNREADABLE"))
            continue
        if target.target_key in seen_targets:
            continue
        seen_targets.add(target.target_key)
        rel_path = target.rel_path
        relative = Path(rel_path)
        if not relative.parts or relative.parts[0] not in FORMAL_MEMORY_TOP_LEVELS:
            warnings.append(_safe_warning("CANDIDATE_REJECTED", relative_path=rel_path, reason="NON_FORMAL_PATH"))
            continue
        try:
            metadata = target.path.lstat()
        except FileNotFoundError:
            warnings.append(_safe_warning("CANDIDATE_REJECTED", relative_path=rel_path, reason="FILE_MISSING"))
            continue
        except OSError:
            warnings.append(_safe_warning("CANDIDATE_REJECTED", relative_path=rel_path, reason="FILE_UNREADABLE"))
            continue
        if stat.S_ISLNK(metadata.st_mode):
            warnings.append(_safe_warning("CANDIDATE_REJECTED", relative_path=rel_path, reason="SYMLINK_FORBIDDEN"))
            continue
        if not stat.S_ISREG(metadata.st_mode):
            warnings.append(_safe_warning("CANDIDATE_REJECTED", relative_path=rel_path, reason="FILE_NOT_REGULAR"))
            continue
        if metadata.st_size > max_file_bytes:
            warnings.append(_safe_warning("CANDIDATE_REJECTED", relative_path=rel_path, reason="FILE_TOO_LARGE"))
            continue
        if bytes_inspected + metadata.st_size > max_total_bytes:
            warnings.append(_safe_warning("CANDIDATE_REJECTED", relative_path=rel_path, reason="TOTAL_BYTE_BUDGET"))
            continue
        try:
            remaining_budget = max_total_bytes - bytes_inspected
            payload = _read_regular_file(
                target.path,
                min(max_file_bytes, remaining_budget),
                oversize_code="TOTAL_BYTE_BUDGET" if remaining_budget < max_file_bytes else "FILE_TOO_LARGE",
            )
        except RetrievalProtocolError as exc:
            warnings.append(_safe_warning("CANDIDATE_REJECTED", relative_path=rel_path, reason=exc.code))
            continue
        except OSError:
            warnings.append(_safe_warning("CANDIDATE_REJECTED", relative_path=rel_path, reason="FILE_UNREADABLE"))
            continue
        bytes_inspected += len(payload)
        source_sha256 = sha256_bytes(payload)
        # A section selector is valid only for the exact bytes that produced
        # its outline.  Check this before UTF-8, secret, frontmatter, status,
        # or scope policy so every source change has one deterministic
        # protocol outcome and old coordinates are never interpreted against
        # a changed document.
        if view == "section" and source_sha256.casefold() != expected_sha256.casefold():
            raise RetrievalProtocolError("STALE_OUTLINE")
        try:
            raw_text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            warnings.append(_safe_warning("CANDIDATE_REJECTED", relative_path=rel_path, reason="CONTENT_NOT_UTF8"))
            continue
        if _contains_secret(raw_text):
            warnings.append(_safe_warning("CANDIDATE_REJECTED", relative_path=rel_path, reason="SECRET_MATERIAL"))
            continue
        try:
            parsed_text = _frontmatter_text(raw_text)
            current_metadata = _metadata_for(target.path, parsed_text)
        except (RetrievalProtocolError, OSError, ValueError) as exc:
            reason = exc.code if isinstance(exc, RetrievalProtocolError) else "FRONTMATTER_INVALID"
            warnings.append(_safe_warning("CANDIDATE_REJECTED", relative_path=rel_path, reason=reason))
            continue
        explicit_memory_id = str(current_metadata.get("memory_id") or "").casefold()
        candidate_memory_id = str(candidate.memory_id or "").casefold()
        if (
            explicit_memory_id
            and candidate_memory_id
            and candidate_memory_id != explicit_memory_id
        ):
            warnings.append(
                _safe_warning(
                    "CANDIDATE_REJECTED",
                    relative_path=rel_path,
                    reason="MEMORY_ID_INDEX_STALE",
                )
            )
            continue
        if explicit_memory_id and explicit_memory_id in seen_explicit_memory_ids:
            warnings.append(
                _safe_warning(
                    "CANDIDATE_REJECTED",
                    relative_path=rel_path,
                    reason="DUPLICATE_MEMORY_ID",
                )
            )
            continue
        rejection = _metadata_rejection(
            current_metadata,
            actor,
            app_id,
            current_project,
            relative_path=rel_path,
            cross_project=cross_project,
            include_inactive=include_inactive,
        )
        if rejection:
            warnings.append(_safe_warning("CANDIDATE_REJECTED", relative_path=rel_path, reason=rejection))
            continue

        temporal_policy = _canonical_temporal_policy(
            rel_path,
            raw_text,
            current_metadata,
            as_of_date,
        )
        fact_status = temporal_policy["fact_status"]
        inactive_fact_reference = bool(
            include_inactive
            and str(current_metadata["status"]).strip().casefold()
            in memory_search.INACTIVE_REFERENCE_STATUSES
            and fact_status in {"superseded", "historical"}
        )
        pending_fact_reference = bool(
            str(current_metadata["status"]).strip().casefold()
            == "pending_verification"
            and fact_status == "historical"
        )
        if not inactive_fact_reference and not pending_fact_reference and fact_status in {
            "superseded",
            "not_yet_valid",
            "historical",
            "no_current",
            "conflict",
            "invalid_metadata",
            "invalid_relation",
        }:
            warnings.append(
                _safe_warning(
                    "CANDIDATE_REJECTED",
                    relative_path=rel_path,
                    reason=f"FACT_{fact_status.upper()}",
                )
            )
            continue

        live_verification, policy_warnings, time_status = _live_verification(
            current_metadata,
            as_of_date,
        )
        if fact_status == "conflict":
            policy_warnings.append("current_fact_conflict")
        elif fact_status in {"invalid_metadata", "invalid_relation"}:
            policy_warnings.append("invalid_fact_timeline")
        elif fact_status == "expired" and "expired_memory_reference_only" not in policy_warnings:
            policy_warnings.append("expired_memory_reference_only")
        policy_warnings = list(dict.fromkeys(policy_warnings))
        live_verification["required"] = bool(policy_warnings)
        live_verification["reasons"] = policy_warnings
        scope_status = _scope_status(str(current_metadata["project_id"]), current_project)
        path_policy_reasons = [
            str(reason)
            for reason in current_metadata.get("path_policy_reason_codes", [])
        ]
        scope_analogy = scope_status in {
            "project_context_unknown",
            "cross_project_reference",
        }
        analogy_only = bool(
            scope_analogy
            or path_policy_reasons
            or as_of_status == "historical"
        )
        if scope_analogy:
            policy_warnings.append(
                "project_context_unknown_reference_only"
                if scope_status == "project_context_unknown"
                else "cross_project_reference_only"
            )
        if path_policy_reasons:
            policy_warnings.append("path_policy_downgrade_reference_only")
        if as_of_status == "historical":
            policy_warnings.append("historical_as_of_reference_only")
        if str(current_metadata["status"]) != "active":
            policy_warnings.append("inactive_or_historical_memory")
        policy_warnings = list(dict.fromkeys(policy_warnings))
        live_verification["required"] = bool(policy_warnings)
        live_verification["reasons"] = policy_warnings
        legacy_authorizable = bool(
            str(current_metadata["status"]) == "active"
            and not analogy_only
            and not bool(live_verification["required"])
            and fact_status in {"not_fact", "current"}
        )
        risk_path_failure = bool(
            {"RISK_CLASS_INVALID", "RISK_CLASS_DOWNGRADE"}
            & set(path_policy_reasons)
        )
        atomic_fact_gate_reasons = shadow_gate.canonical_action_sensitive_gate_reasons(
            current_metadata,
            rel_path=rel_path,
            raw_sha256=source_sha256,
        )
        metadata_gate_evaluated = bool(
            legacy_authorizable
            or atomic_fact_gate_reasons
            or (
                str(current_metadata["status"]) == "active"
                and risk_path_failure
            )
        )
        metadata_gate_reasons = (
            tuple(dict.fromkeys((
                *shadow_gate.temporal_metadata_gate_reasons(current_metadata),
                *atomic_fact_gate_reasons,
            )))
            if metadata_gate_evaluated
            else ()
        )
        can_authorize_action = legacy_authorizable
        # Keep live-verification reasons separate from the metadata shadow
        # warning: shadow observation must not silently change legacy authority.
        live_verification["reasons"] = list(policy_warnings)
        policy = {
            "status": str(current_metadata["status"]),
            "risk_class": str(current_metadata["risk_class"]),
            "risk_class_source": str(current_metadata["risk_class_source"]),
            "agent_scope": str(current_metadata["agent_scope"]),
            "app_id": str(current_metadata["app_id"]),
            "project_id": str(current_metadata["project_id"]),
            "scope_status": scope_status,
            "analogy_only": analogy_only,
            "as_of_status": as_of_status,
            "path_policy_reason_codes": path_policy_reasons,
            "valid_until": str(current_metadata["valid_until"]),
            "time_status": time_status,
            **temporal_policy,
            "review_after_days": int(current_metadata["review_after_days"]),
            "review_status": str(live_verification["review_status"]),
            "review_due_at": str(live_verification["review_due_at"]),
            "warnings": list(policy_warnings),
            "requires_live_verification": bool(live_verification["required"]),
            "can_authorize_action": can_authorize_action,
        }
        result: dict[str, Any] = {
            "relative_path": rel_path,
            "sha256": source_sha256,
            "verified_at": str(current_metadata["verified_at"]),
            "verified_at_source": str(current_metadata["verified_at_source"]),
            "risk_class": str(current_metadata["risk_class"]),
            "risk_class_source": str(current_metadata["risk_class_source"]),
            **temporal_policy,
            "requires_live_verification": bool(live_verification["required"]),
            "memory_id": str(current_metadata["memory_id"]) or memory_search.legacy_memory_id(rel_path),
            "memory_id_source": "frontmatter" if current_metadata["memory_id"] else "legacy_path_hash",
            "scope_status": scope_status,
            "analogy_only": analogy_only,
            "as_of_status": as_of_status,
            "path_policy_reason_codes": path_policy_reasons,
            "can_authorize_action": can_authorize_action,
            "canonical_read_required": False,
            "ranking_version": search_metadata.get(
                "ranking_version", memory_search.RANKING_VERSION
            ),
            "_metadata_gate_evaluated": metadata_gate_evaluated,
            "_metadata_gate_reasons": list(metadata_gate_reasons),
            "git_head": git_head,
            "size_bytes": len(payload),
            "policy": policy,
            "live_verification": live_verification,
        }
        if view == "query":
            excerpt, excerpt_truncated = _bounded_utf8(_preferred_excerpt(parsed_text), max_excerpt_bytes)
            result.update(
                {
                    "excerpt": excerpt,
                    "excerpt_truncated": excerpt_truncated,
                }
            )
        else:
            headings = _markdown_headings(raw_text)
            result.update(
                {
                    "source_sha256": source_sha256,
                    "document": {
                        "size_bytes": len(payload),
                        "size_chars": len(raw_text),
                        "line_count": len(raw_text.splitlines()),
                        "heading_count": len(headings),
                    },
                }
            )
            if view == "outline":
                outline, truncated, next_offset, returned_bytes = _outline_page(
                    headings,
                    max_bytes=max_excerpt_bytes,
                    offset=outline_offset,
                )
                result.update(
                    {
                        "outline": outline,
                        "outline_offset": outline_offset,
                        "outline_returned_bytes": returned_bytes,
                        "truncated": truncated,
                        "next_outline_offset": next_offset,
                    }
                )
            else:
                selected = next(
                    (heading for heading in headings if heading.section_id == section_id),
                    None,
                )
                if selected is None:
                    raise RetrievalProtocolError("SECTION_NOT_FOUND")
                section_text = raw_text[selected.start_char : selected.end_char]
                page, truncated, next_offset = _bounded_utf8_page(
                    section_text,
                    max_excerpt_bytes,
                    offset_chars,
                )
                result.update(
                    {
                        "section": _heading_payload(selected),
                        "excerpt": page,
                        "excerpt_offset_chars": offset_chars,
                        "returned_chars": len(page),
                        "returned_bytes": len(page.encode("utf-8")),
                        "truncated": truncated,
                        "next_offset_chars": next_offset,
                    }
                )
        if explicit_memory_id:
            seen_explicit_memory_ids.add(explicit_memory_id)
        results.append(result)

    metadata_reason_sets = [
        tuple(str(reason) for reason in item.get("_metadata_gate_reasons", []))
        for item in results
        if bool(item.get("_metadata_gate_evaluated", False))
    ]
    metadata_projection = shadow_gate.metadata_gate_projection(metadata_reason_sets)
    for item in results:
        evaluated = bool(item.pop("_metadata_gate_evaluated", False))
        reasons = tuple(str(reason) for reason in item.pop("_metadata_gate_reasons", []))
        item["metadata_gate_mode"] = str(metadata_projection["effective_mode"])
        item["metadata_gate_would_block"] = bool(evaluated and reasons)
        item["metadata_gate_reason_codes"] = list(reasons) if evaluated else []
        policy = item.get("policy")
        if evaluated and reasons and isinstance(policy, dict):
            # Shadow metadata is an observation. Preserve the legacy warning
            # surface for rows that were already reference-only for an older
            # reason (expiry, review due, scope, historical as-of, etc.).
            if bool(item.get("can_authorize_action", False)):
                policy_warnings = policy.get("warnings")
                warnings_list = (
                    list(policy_warnings)
                    if isinstance(policy_warnings, list)
                    else []
                )
                if "metadata_gate_would_block" not in warnings_list:
                    warnings_list.append("metadata_gate_would_block")
                policy["warnings"] = warnings_list
            if bool(metadata_projection["enforced"]):
                item["can_authorize_action"] = False
                policy["can_authorize_action"] = False

    canonical_search_id = ""
    if view == "query" and not synthetic_benchmark:
        canonical_search_id = _record_canonical_retrieve_search(
            normalized,
            results,
            duration_ms=round((time.monotonic() - started) * 1000),
            search_status=(
                "partial"
                if warnings or bool(search_metadata.get("degraded", False))
                else "success"
            ),
            search_metadata=search_metadata,
            metadata_projection=metadata_projection,
        )

    response = {
        "schema_version": WIRE_SCHEMA_VERSION,
        "ok": True,
        "actor": actor,
        "app_id": app_id,
        "project_id": project_id,
        "current_project": current_project,
        "ranking_version": search_metadata.get("ranking_version", memory_search.RANKING_VERSION),
        "ranking_mode": search_metadata.get("ranking_mode", memory_search.DEFAULT_RANKING_VERSION),
        "shadow": (
            {
                "ranking_version": memory_search.RANKING_VERSION,
                "result_memory_ids": search_metadata.get("shadow_result_memory_ids", []),
            }
            if search_metadata.get("ranking_mode") == "hybrid-v2-shadow"
            else None
        ),
        "backend_status": search_metadata.get("backend_status", {}),
        "degraded": bool(search_metadata.get("degraded", False)),
        "metadata_gate": metadata_projection,
        "git_head": git_head,
        "retrieved_at": utc_now(),
        "as_of": as_of_date.isoformat(),
        "as_of_status": as_of_status,
        "result_count": len(results),
        "bytes_inspected": bytes_inspected,
        "limits": {
            "max_results": max_results,
            "max_file_bytes": max_file_bytes,
            "max_total_bytes": max_total_bytes,
            "max_excerpt_bytes": max_excerpt_bytes,
        },
        "results": results,
        "warnings": _sorted_warnings(warnings),
    }
    if view == "query":
        response["query_hash"] = query_sha256(normalized)
    else:
        response["view"] = view
    event_ids = (
        []
        if synthetic_benchmark
        else _record_source_opened_events(actor, view, results)
    )
    response["observation"] = {
        "automatic": not synthetic_benchmark,
        "synthetic_benchmark": synthetic_benchmark,
        "recorded": len(event_ids),
        "event_ids": event_ids,
        "canonical_search_recorded": bool(canonical_search_id),
        "canonical_search_id": canonical_search_id,
    }
    return response


def _read_json_request() -> dict[str, Any]:
    payload = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(payload) > MAX_REQUEST_BYTES:
        raise RetrievalProtocolError("REQUEST_TOO_LARGE")
    try:
        decoded = payload.decode("utf-8", errors="strict")
        request = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetrievalProtocolError("REQUEST_INVALID") from exc
    if not isinstance(request, dict) or request.get("schema_version") != WIRE_SCHEMA_VERSION:
        raise RetrievalProtocolError("REQUEST_INVALID")
    allowed = {
        "schema_version",
        "view",
        "query",
        "file",
        "section_id",
        "expected_sha256",
        "offset_chars",
        "outline_offset",
        "app_id",
        "project_id",
        "current_project",
        "cross_project",
        "include_inactive",
        "semantic_mode",
        "as_of",
        "max_results",
        "max_file_bytes",
        "max_total_bytes",
        "max_excerpt_bytes",
    }
    if set(request) - allowed:
        raise RetrievalProtocolError("REQUEST_INVALID")
    view = request.get("view", "query")
    if view not in {"query", "outline", "section"}:
        raise RetrievalProtocolError("VIEW_INVALID")
    query = request.get("query", "")
    if not isinstance(query, str):
        raise RetrievalProtocolError("REQUEST_INVALID")
    if view == "query" and (
        not query.strip()
        or len(query) > MAX_QUERY_CHARS
        or "\x00" in query
        or any(ord(character) < 32 and character not in "\t\n\r" for character in query)
    ):
        raise RetrievalProtocolError("QUERY_REQUIRED")
    if view != "query" and query:
        raise RetrievalProtocolError("REQUEST_INVALID")
    for key in (
        "app_id", "project_id", "current_project", "semantic_mode",
        "file", "section_id", "expected_sha256", "as_of",
    ):
        value = request.get(key, "")
        maximum = 4096 if key == "file" else 160
        if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
            raise RetrievalProtocolError("REQUEST_INVALID")
    for key in (
        "max_results",
        "max_file_bytes",
        "max_total_bytes",
        "max_excerpt_bytes",
        "offset_chars",
        "outline_offset",
    ):
        if key in request and (not isinstance(request[key], int) or isinstance(request[key], bool)):
            raise RetrievalProtocolError("REQUEST_INVALID")
    for key in ("cross_project", "include_inactive"):
        if key in request and not isinstance(request[key], bool):
            raise RetrievalProtocolError("REQUEST_INVALID")
    return request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read bounded excerpts from current canonical Agent Memory Markdown."
    )
    parser.add_argument("query", nargs="?", help="Non-Ailu query; Ailu queries must use stdin JSON.")
    parser.add_argument("--query", dest="query_option", help="Legacy alternative to the positional query.")
    parser.add_argument("--view", choices=("query", "outline", "section"), default="query")
    parser.add_argument("--file", dest="file_path", default="")
    parser.add_argument("--section-id", default="")
    parser.add_argument("--expected-sha256", default="")
    parser.add_argument("--offset-chars", type=int, default=0)
    parser.add_argument(
        "--outline-offset",
        type=int,
        default=0,
        help="Zero-based heading offset for paginated outline results.",
    )
    parser.add_argument("--actor", choices=ACTORS, default=os.environ.get("MEMORY_ACTOR", "codex"))
    parser.add_argument("--app-id", default="")
    parser.add_argument("--project-id", default="", help="Compatibility alias for --current-project.")
    parser.add_argument("--current-project", default="")
    parser.add_argument("--cross-project", action="store_true")
    parser.add_argument("--include-inactive", action="store_true")
    parser.add_argument(
        "--semantic-mode",
        choices=("auto", "off", "required"),
        default=None,
    )
    parser.add_argument("--no-zvec", action="store_true", help="Compatibility alias for --semantic-mode off.")
    parser.add_argument(
        "--as-of",
        default="",
        help="Date used for valid_until and review-due checks (YYYY-MM-DD; defaults to today).",
    )
    parser.add_argument("--max-results", type=int, default=DEFAULT_MAX_RESULTS)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    parser.add_argument("--max-excerpt-bytes", type=int, default=DEFAULT_MAX_EXCERPT_BYTES)
    parser.add_argument(
        "--observe",
        action="store_true",
        help="Compatibility flag; source-opened telemetry is now automatic.",
    )
    parser.add_argument("--json", action="store_true", help="Accepted for consistency; output is always JSON.")
    args = parser.parse_args()
    args.query = args.query_option or args.query or ""
    if args.actor == AILU_ACTOR:
        if (
            args.query
            or args.app_id
            or args.project_id
            or args.current_project
            or args.cross_project
            or args.include_inactive
            or args.semantic_mode is not None
            or args.no_zvec
            or args.as_of
            or args.view != "query"
            or args.file_path
            or args.section_id
            or args.expected_sha256
            or args.offset_chars
            or args.outline_offset
            or args.observe
        ):
            raise RetrievalProtocolError("QUERY_STDIN_REQUIRED")
        request = _read_json_request()
        if (
            "current_project" in request
            or bool(request.get("cross_project", False))
            or bool(request.get("include_inactive", False))
        ):
            raise RetrievalProtocolError("AILU_SCOPE_OPTIONS_FORBIDDEN")
        args.view = str(request.get("view", "query"))
        args.query = str(request.get("query", ""))
        args.file_path = str(request.get("file", ""))
        args.section_id = str(request.get("section_id", ""))
        args.expected_sha256 = str(request.get("expected_sha256", ""))
        args.offset_chars = int(request.get("offset_chars", 0))
        args.outline_offset = int(request.get("outline_offset", 0))
        args.app_id = str(request.get("app_id", ""))
        args.project_id = str(request.get("project_id", ""))
        args.current_project = str(request.get("current_project", ""))
        args.cross_project = bool(request.get("cross_project", False))
        args.include_inactive = bool(request.get("include_inactive", False))
        args.semantic_mode = str(request.get("semantic_mode", memory_search.DEFAULT_SEMANTIC_MODE))
        args.as_of = str(request.get("as_of", ""))
        for key in ("max_results", "max_file_bytes", "max_total_bytes", "max_excerpt_bytes"):
            if key in request:
                setattr(args, key, int(request[key]))
    if args.semantic_mode is None:
        args.semantic_mode = memory_search.DEFAULT_SEMANTIC_MODE
    if args.no_zvec:
        args.semantic_mode = "off"
    if args.cross_project and not (args.current_project or args.project_id):
        raise RetrievalProtocolError("CURRENT_PROJECT_REQUIRED")
    return args


def main() -> int:
    try:
        args = parse_args()
        assert_runtime_actor_identity(args.actor)
        assert_runtime_ready("retrieve")
        payload = retrieve(
            actor=args.actor,
            app_id=args.app_id,
            project_id=args.project_id,
            query=args.query,
            max_results=args.max_results,
            max_file_bytes=args.max_file_bytes,
            max_total_bytes=args.max_total_bytes,
            max_excerpt_bytes=args.max_excerpt_bytes,
            as_of=args.as_of,
            view=args.view,
            file_path=args.file_path,
            section_id=args.section_id,
            expected_sha256=args.expected_sha256,
            offset_chars=args.offset_chars,
            outline_offset=args.outline_offset,
            current_project=args.current_project,
            cross_project=args.cross_project,
            include_inactive=args.include_inactive,
            semantic_mode=args.semantic_mode,
        )
        payload.setdefault("observation", {})["compatibility_flag_requested"] = bool(args.observe)
    except RuntimeTransitionError:
        payload = {
            "schema_version": WIRE_SCHEMA_VERSION,
            "ok": False,
            "error": {"code": "RUNTIME_TRANSITION_INCOMPLETE"},
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 2
    except RetrievalProtocolError as exc:
        payload = {"schema_version": WIRE_SCHEMA_VERSION, "ok": False, "error": {"code": exc.code}}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 2
    except Exception:
        payload = {"schema_version": WIRE_SCHEMA_VERSION, "ok": False, "error": {"code": "RETRIEVAL_FAILED"}}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 2
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
