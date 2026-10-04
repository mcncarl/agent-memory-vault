#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_memory_env import RuntimeTransitionError, assert_runtime_ready, env_value, expand_path
from agent_memory_generated_index_capability import (
    GeneratedIndexCapabilityError,
    bind_expected_generated_index_sha256,
    bind_generated_index_recovery_evidence,
    consume_generated_index_capability_from_environment,
    generated_index_backup_directory,
)
import agent_memory_intent
import agent_memory_observability
from agent_memory_state import absolute_path, secure_sqlite_connect


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VAULT_ROOT = REPO_ROOT / "templates" / "vault"
VAULT_ROOT = expand_path(env_value("ROOT", str(DEFAULT_VAULT_ROOT))).resolve()
CONFIG_ROOT = expand_path(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory")).resolve()
GIT_ROOT = expand_path(env_value("GIT_ROOT", str(VAULT_ROOT))).resolve()
STATE_DB = absolute_path(expand_path(env_value("STATE_DB", "$HOME/.config/agent-memory/state.sqlite")))
DEFAULT_USER_ID = env_value("USER_ID", "demo-user")
DEFAULT_AGENT_ID = env_value("AGENT_ID", "shared")
DEFAULT_APP_ID = env_value("APP_ID", "agent-memory")
DEFAULT_LIMIT = 5
INDEX_SCHEMA_VERSION = "13"
GENERATED_INDEX_MARKER = "<!-- agent-memory-generated-index:v1 -->"
GENERATED_INDEX_ENTRY_RE = re.compile(r"^- `(?P<rel_path>[^`\r\n]+\.md)`:")
TEMPORAL_POLICIES = {"structural", "snapshot", "stable", "reviewable", "expiring"}
FORMAL_BODY_TOP_LEVELS = {"用户记忆", "项目", "工作流", "决策", "agent"}
GOVERNANCE_MIGRATION_STATUSES = {
    "active",
    "pending_verification",
    "outdated",
    "archived",
    "candidate",
}
FACT_LINEAGE_SOURCE_STATUSES = frozenset({
    "active",
    "pending_verification",
    "outdated",
    "archived",
})
PROTECTED_FRONTMATTER_KEYS = frozenset({
    "memory_id",
    "memory_type",
    "track",
    "app_id",
    "project_id",
    "user_id",
    "agent_id",
    "agent_scope",
    "session_id",
    "status",
    "sensitivity",
    "risk_class",
    "temporal_policy",
    "verified_at",
    "fact_key",
    "valid_from",
    "valid_until",
    "review_after_days",
    "supersedes",
    "verification_mode",
    "requires_live_verification",
})


def is_formal_body_document(relative: Path) -> bool:
    """Return whether a relative Markdown path is part of the governed body.

    Doctor and Write Gateway must share this exact boundary.  Navigation
    README files are governed bodies, while archive and template material are
    deliberately excluded from automatic governance migration.
    """

    return bool(
        relative.parts
        and relative.parts[0] in FORMAL_BODY_TOP_LEVELS
        and "archive" not in {part.casefold() for part in relative.parts}
        and not relative.name.startswith("_模板")
    )


@dataclass
class MemoryDoc:
    path: Path
    rel_path: str
    memory_id: str
    memory_id_source: str
    sha256: str
    title: str
    memory_type: str
    track: str
    project_id: str
    app_id: str
    user_id: str
    agent_id: str
    agent_scope: str
    session_id: str
    status: str
    sensitivity: str
    risk_class: str
    risk_class_source: str
    verified_at: str
    verified_at_source: str
    document_date: str
    temporal_policy: str
    temporal_policy_source: str
    fact_key: str
    valid_from: str
    valid_until: str
    review_after_days: int
    review_after_source: str
    supersedes: str
    mtime: float
    size_bytes: int
    line_count: int
    summary: str
    next_hint: str
    stale_info: str
    has_open_loop: int
    open_loop_count: int
    keywords: str
    headings: str
    search_text: str
    indexed_at: str


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_markdown_text(path: Path) -> str:
    """Decode Markdown the way the index parses and hashes it.

    Universal-newline decoding turns CRLF and CR into LF, so the stored
    ``memory_docs.sha256`` is a digest of this text, not of the raw bytes.
    """
    return path.read_text(encoding="utf-8", errors="replace")


def markdown_sha256(path: Path) -> str:
    """Return the ``memory_docs.sha256`` value ``load_doc`` records for ``path``."""
    return sha256_text(read_markdown_text(path))


def _canonical_projection_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def full_vault_input_projection_sha256() -> str:
    projection: list[tuple[str, str]] = []
    index_path = (VAULT_ROOT / "INDEX.md").resolve()
    for path in sorted(VAULT_ROOT.rglob("*.md"), key=lambda item: item.as_posix()):
        if path.is_symlink() or not path.is_file():
            raise GeneratedIndexCapabilityError("GENERATED_INDEX_INPUT_UNSAFE")
        resolved = path.resolve()
        if resolved == index_path:
            continue
        projection.append(
            (
                resolved.relative_to(VAULT_ROOT).as_posix(),
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        )
    return _canonical_projection_sha256(projection)


def verify_generated_index_transaction_snapshot(
    authorization: dict[str, Any],
    *,
    expected_index_sha256: str | None = None,
) -> None:
    binding = authorization.get("transaction_binding")
    if not isinstance(binding, dict):
        raise GeneratedIndexCapabilityError("GENERATED_INDEX_TRANSACTION_INVALID")
    target = VAULT_ROOT / "INDEX.md"
    vault_root_sha256 = hashlib.sha256(str(VAULT_ROOT.resolve()).encode("utf-8")).hexdigest()
    current_index_sha256 = (
        hashlib.sha256(target.read_bytes()).hexdigest()
        if target.is_file() and not target.is_symlink()
        else ""
    )
    try:
        git_head = subprocess.run(
            ["git", "-C", str(GIT_ROOT), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip().lower()
    except (OSError, subprocess.SubprocessError) as exc:
        raise GeneratedIndexCapabilityError("GENERATED_INDEX_TRANSACTION_INVALID") from exc
    if (
        str(binding.get("vault_root_sha256", "")) != vault_root_sha256
        or str(expected_index_sha256 or binding.get("index_base_sha256", ""))
        != current_index_sha256
        or str(binding.get("git_head", "")) != git_head
        or str(binding.get("full_vault_inputs_sha256", ""))
        != full_vault_input_projection_sha256()
    ):
        raise GeneratedIndexCapabilityError("GENERATED_INDEX_TRANSACTION_CHANGED")


def _atomic_exchange_paths(first: Path, second: Path) -> None:
    """Atomically exchange two existing same-filesystem paths or fail closed."""

    if os.name == "nt":  # Windows uses ReplaceFile in the conditional wrapper.
        raise OSError("ATOMIC_EXCHANGE_UNAVAILABLE")
    libc = ctypes.CDLL(None, use_errno=True)
    first_raw = os.fsencode(first)
    second_raw = os.fsencode(second)
    if sys.platform == "darwin":
        renamex_np = getattr(libc, "renamex_np", None)
        if renamex_np is None:
            raise OSError("ATOMIC_EXCHANGE_UNAVAILABLE")
        renamex_np.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        renamex_np.restype = ctypes.c_int
        result = renamex_np(first_raw, second_raw, 0x00000002)
    else:
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise OSError("ATOMIC_EXCHANGE_UNAVAILABLE")
        renameat2.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        result = renameat2(-100, first_raw, -100, second_raw, 0x00000002)
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _fsync_parent_directories(*paths: Path) -> None:
    if os.name == "nt":
        return
    for parent in {path.parent.resolve() for path in paths}:
        descriptor = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def conditional_atomic_replace(
    target: Path,
    replacement: Path,
    *,
    expected_current_sha256: str,
    evidence_path: Path | None = None,
) -> Path:
    """Replace target atomically while preserving and verifying prior bytes."""

    if target.is_symlink() or replacement.is_symlink() or not target.is_file() or not replacement.is_file():
        raise OSError("GENERATED_INDEX_TARGET_UNSAFE")
    if os.name == "nt":
        evidence = (
            evidence_path
            if evidence_path is not None
            else replacement.parent / f"previous-{os.getpid()}-{time.time_ns()}.md"
        )
        if (
            evidence.parent.resolve() != replacement.parent.resolve()
            or evidence.exists()
            or evidence.is_symlink()
        ):
            raise OSError("GENERATED_INDEX_RECOVERY_EVIDENCE_INVALID")
        replace_file = ctypes.windll.kernel32.ReplaceFileW
        replace_file.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_void_p,
        )
        replace_file.restype = ctypes.c_int
        if not replace_file(str(target), str(replacement), str(evidence), 0x00000001, None, None):
            raise OSError(ctypes.get_last_error(), "ReplaceFileW failed")
        evidence_metadata = evidence.lstat()
        observed = (
            hashlib.sha256(evidence.read_bytes()).hexdigest()
            if stat.S_ISREG(evidence_metadata.st_mode) and not evidence.is_symlink()
            else ""
        )
        if observed != expected_current_sha256:
            generated_evidence = evidence.parent / f"generated-race-{os.getpid()}-{time.time_ns()}.md"
            if not replace_file(str(target), str(evidence), str(generated_evidence), 0x00000001, None, None):
                raise OSError("GENERATED_INDEX_CAS_RESTORE_FAILED")
            raise OSError("GENERATED_INDEX_BASE_CHANGED")
        return evidence
    if evidence_path is not None and evidence_path.resolve() != replacement.resolve():
        raise OSError("GENERATED_INDEX_RECOVERY_EVIDENCE_INVALID")
    _atomic_exchange_paths(replacement, target)
    displaced_metadata = replacement.lstat()
    observed = (
        hashlib.sha256(replacement.read_bytes()).hexdigest()
        if stat.S_ISREG(displaced_metadata.st_mode) and not replacement.is_symlink()
        else ""
    )
    if observed != expected_current_sha256:
        _atomic_exchange_paths(replacement, target)
        _fsync_parent_directories(replacement, target)
        raise OSError("GENERATED_INDEX_BASE_CHANGED")
    _fsync_parent_directories(replacement, target)
    return replacement


def memory_identity(rel_path: str, meta: dict[str, object]) -> tuple[str, str]:
    explicit = as_text(meta.get("memory_id")).casefold()
    if re.fullmatch(r"[0-9a-f]{64}", explicit):
        return explicit, "frontmatter"
    normalized = unicodedata.normalize("NFC", rel_path.replace("\\", "/").strip())
    fallback = hashlib.sha256(f"agent-memory-v1\0{normalized}".encode("utf-8")).hexdigest()
    return fallback, "legacy_path_hash_invalid" if explicit else "legacy_path_hash"


def stable_memory_id(rel_path: str, meta: dict[str, object]) -> str:
    return memory_identity(rel_path, meta)[0]


def parse_frontmatter(text: str) -> dict[str, object]:
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---", 4)
    if end == -1:
        return {}
    data: dict[str, object] = {}
    protected_seen: set[str] = set()
    current_key = ""
    for line in text[4:end].splitlines():
        if not line.strip():
            continue
        if line.startswith(("  - ", "- ")) and current_key:
            item = line.split("- ", 1)[1].strip()
            data.setdefault(current_key, [])
            if isinstance(data[current_key], list):
                data[current_key].append(item)
            continue
        if line.startswith(" ") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        current_key = key.strip()
        if current_key in PROTECTED_FRONTMATTER_KEYS:
            if current_key in protected_seen:
                raise ValueError("FRONTMATTER_DUPLICATE_KEY")
            protected_seen.add(current_key)
        value = value.strip()
        data[current_key] = value if value else []
    return data


def as_text(value: object, default: str = "") -> str:
    if isinstance(value, list):
        text = ", ".join(str(item).strip() for item in value if str(item).strip())
        return text if text else default
    if value is None:
        return default
    text = str(value).strip().strip('"').strip("'")
    return text if text else default


def as_list(value: object) -> list[str]:
    """Return a bounded, stable list from the deliberately small YAML subset.

    The vault parser is intentionally dependency-free.  It supports normal
    block lists and a conservative inline ``[a, b]`` form so temporal relation
    metadata remains human-editable without making SQLite a second source of
    truth.
    """

    values: list[object]
    if isinstance(value, list):
        values = value
    elif value in (None, ""):
        values = []
    else:
        raw = str(value).strip()
        if raw.startswith("[") and raw.endswith("]"):
            raw = raw[1:-1]
        values = raw.split(",")
    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        normalized = unicodedata.normalize("NFKC", str(item).strip().strip("'\"`"))
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def normalized_relation_ref(value: str) -> tuple[str, str]:
    """Normalize a Markdown-relative supersession reference.

    Relations are declarations in Markdown.  They may never be absolute,
    escape the vault, or silently target a non-Markdown object.  Invalid
    declarations remain auditable in ``memory_supersessions`` but never affect
    current-fact retrieval.
    """

    raw = unicodedata.normalize("NFKC", value.strip()).replace("\\", "/")
    if not raw:
        return "", "REFERENCE_EMPTY"
    candidate = Path(raw)
    if candidate.is_absolute() or raw.startswith("/"):
        return raw, "REFERENCE_ABSOLUTE"
    if any(part in {"", ".", ".."} for part in candidate.parts):
        return raw, "REFERENCE_TRAVERSAL"
    normalized = candidate.as_posix()
    if not normalized.endswith(".md"):
        return normalized, "REFERENCE_NOT_MARKDOWN"
    return normalized, ""


def normalized_fact_key(value: object) -> tuple[str, str]:
    """Return a stable fact identity or a bounded validation error.

    Fact keys are deliberately explicit.  Free text, titles, and embeddings
    are never allowed to decide that two facts replace one another.
    """

    normalized = unicodedata.normalize("NFKC", str(value or "").strip()).casefold()
    if not normalized:
        return "", "FACT_KEY_REQUIRED"
    if len(normalized) > 160 or normalized in {"null", "none", "~"}:
        return normalized[:160], "FACT_KEY_INVALID"
    if any(character.isspace() or ord(character) < 32 for character in normalized):
        return normalized, "FACT_KEY_INVALID"
    if any(character in normalized for character in (",", "|", "[", "]", "{", "}", "\\")):
        return normalized, "FACT_KEY_INVALID"
    if normalized.startswith(('.', '/')) or normalized.endswith(('.', '/')) or ".." in normalized:
        return normalized, "FACT_KEY_INVALID"
    return normalized, ""


def temporal_date(value: object) -> tuple[str, str]:
    raw = str(value or "").strip()
    if not raw:
        return "", "DATE_REQUIRED"
    try:
        parsed = dt.date.fromisoformat(raw)
    except ValueError:
        return raw, "DATE_INVALID"
    if parsed.isoformat() != raw:
        return raw, "DATE_INVALID"
    return raw, ""


def fact_metadata(meta: dict[str, object]) -> dict[str, object]:
    """Validate the opt-in, one-fact-per-file temporal contract.

    ``valid_from`` by itself remains ordinary document metadata for backward
    compatibility.  A document enters fact-record mode only when ``fact_key``
    or ``supersedes`` is declared.
    """

    raw_fact_key = meta.get("fact_key")
    declared_supersedes = as_list(meta.get("supersedes"))
    enabled = bool(str(raw_fact_key or "").strip() or declared_supersedes)
    if not enabled:
        return {
            "enabled": False,
            "fact_key": "",
            "valid_from": as_text(meta.get("valid_from")),
            "valid_until": as_text(meta.get("valid_until")),
            "supersedes": [],
            "errors": [],
        }

    fact_key, fact_key_error = normalized_fact_key(raw_fact_key)
    valid_from, valid_from_error = temporal_date(meta.get("valid_from"))
    valid_until = as_text(meta.get("valid_until"))
    errors = [code for code in (fact_key_error, valid_from_error) if code]
    if valid_until:
        normalized_until, until_error = temporal_date(valid_until)
        valid_until = normalized_until
        if until_error:
            errors.append("VALID_UNTIL_INVALID")
        elif valid_from and valid_until < valid_from:
            errors.append("VALIDITY_RANGE_INVALID")
    normalized_supersedes: list[str] = []
    for declared in declared_supersedes:
        target, reason = normalized_relation_ref(declared)
        if reason:
            errors.append(reason)
        elif target not in normalized_supersedes:
            normalized_supersedes.append(target)
    return {
        "enabled": True,
        "fact_key": fact_key,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "supersedes": normalized_supersedes,
        "errors": list(dict.fromkeys(errors)),
    }


def title_from_markdown(text: str, path: Path) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem


def headings_from_markdown(text: str) -> str:
    headings: list[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            heading = line.lstrip("#").strip()
            if heading:
                headings.append(heading)
    return " | ".join(headings)


def compact_lines(lines: list[str], limit: int = 500) -> str:
    cleaned: list[str] = []
    for line in lines:
        item = line.strip()
        if not item or item.startswith("```"):
            continue
        item = re.sub(r"^[-*]\s*", "", item)
        cleaned.append(item)
    text = "；".join(cleaned)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def section_lines(text: str, heading_patterns: list[str]) -> list[str]:
    lines = text.splitlines()
    capture = False
    captured: list[str] = []
    for line in lines:
        if line.startswith("## "):
            heading = line[3:].strip()
            if any(pattern in heading for pattern in heading_patterns):
                capture = True
                continue
            if capture:
                break
        if capture:
            captured.append(line)
    return captured


def extract_summary(text: str) -> str:
    lines = section_lines(text, ["当前有效摘要"])
    if lines:
        return compact_lines(lines, 700)
    body = [line for line in text.splitlines() if line.strip() and not line.startswith("---")]
    return compact_lines(body[:12], 500)


def extract_verified_at(
    text: str,
    meta: dict[str, object],
    memory_type: str,
    status: str,
) -> tuple[str, str]:
    frontmatter_value = as_text(meta.get("verified_at"))
    if frontmatter_value:
        return frontmatter_value, "frontmatter"
    verification_mode = as_text(meta.get("verification_mode")).lower()
    if verification_mode in {"structural", "snapshot", "needs_review"}:
        return "", verification_mode
    match = re.search(r"最近验证[:：]\s*(\d{4}-\d{2}-\d{2})", text)
    if match:
        return match.group(1), "summary"
    if extract_document_date(text):
        # A date merely appearing in a summary is provenance, never proof that
        # the fact was checked on that date.
        return "", "document_date_unverified"
    if status in {"archived", "outdated", "deprecated", "stale"}:
        return "", "snapshot"
    if memory_type in {"routing", "directory_index", "template"}:
        return "", "structural"
    return "", "needs_review"


def extract_document_date(text: str) -> str:
    summary_dates = re.findall(r"\b(20\d{2}-\d{2}-\d{2})\b", extract_summary(text))
    return max(summary_dates) if summary_dates else ""


def temporal_policy_for(
    meta: dict[str, object],
    *,
    memory_type: str,
    status: str,
    fact: dict[str, object],
) -> tuple[str, str]:
    explicit = as_text(meta.get("temporal_policy")).casefold()
    if explicit in TEMPORAL_POLICIES:
        return explicit, "frontmatter"
    if status in {"archived", "outdated", "deprecated", "stale", "superseded"}:
        return "snapshot", "inferred"
    if memory_type in {"routing", "directory_index", "template", "governance"}:
        return "structural", "inferred"
    if bool(fact.get("enabled")) and str(fact.get("valid_until") or ""):
        return "expiring", "inferred"
    if bool(fact.get("enabled")):
        return "reviewable", "inferred"
    if memory_type in {"user_profile", "decision"}:
        return "stable", "inferred"
    return "reviewable", "inferred"


def is_explicitly_action_sensitive(
    *,
    status: object,
    memory_type: object,
    temporal_policy: object,
    fact_key: object,
    valid_from: object,
    valid_until: object,
    rel_path: object,
) -> bool:
    """Classify only explicit action-sensitive fact records.

    Project, workflow, and decision documents are not facts merely because of
    their container type. Audit and Doctor share this predicate so ordinary
    reviewable guidance does not create false atomic-fact coverage debt.
    """

    normalized_status = str(status or "").casefold()
    normalized_type = str(memory_type or "").casefold()
    normalized_policy = str(temporal_policy or "").casefold()
    return bool(
        normalized_status == "active"
        and normalized_type not in {"routing", "directory_index", "template", "governance"}
        and normalized_policy != "structural"
        and (
            normalized_type in {"fact", "atomic_fact", "current_fact"}
            or normalized_policy == "expiring"
            or str(valid_from or "").strip()
            or str(valid_until or "").strip()
            or str(fact_key or "").strip()
            or "事实-" in Path(str(rel_path or "")).stem
        )
    )


def infer_review_after_days(path: Path, title: str, memory_type: str, status: str, meta: dict[str, object]) -> int:
    explicit = as_text(meta.get("review_after_days"))
    if explicit:
        try:
            return max(1, min(int(explicit), 3650))
        except ValueError:
            pass
    haystack = f"{path.as_posix()} {title}"
    if status == "candidate" or memory_type in {"agent_case_candidate", "skill_candidate", "open_loop"}:
        return 30
    if "产品调研" in haystack or "竞品调研" in haystack:
        return 30
    return {
        "project": 90,
        "workflow": 180,
        "user_profile": 365,
        "decision": 365,
        "routing": 365,
        "directory_index": 365,
        "template": 365,
    }.get(memory_type, 180)


def review_after_policy(
    path: Path,
    title: str,
    memory_type: str,
    status: str,
    meta: dict[str, object],
) -> tuple[int, str]:
    explicit = as_text(meta.get("review_after_days"))
    return infer_review_after_days(path, title, memory_type, status, meta), (
        "frontmatter" if explicit and explicit.isdigit() else "inferred"
    )


def infer_from_path(path: Path, meta: dict[str, object]) -> tuple[str, str, str, str]:
    rel = path.relative_to(VAULT_ROOT)
    parts = rel.parts
    name = path.stem

    if path.name == "README.md":
        parent = Path(*parts[:-1]).as_posix() if len(parts) > 1 else name
        default_track = parts[0] if len(parts) > 1 else "routing"
        return "directory_index", as_text(meta.get("track"), default_track), as_text(meta.get("project_id"), parent), as_text(meta.get("status"), "active")
    if path.name.startswith("_模板"):
        return "template", as_text(meta.get("track"), parts[0] if parts else "template"), as_text(meta.get("project_id"), name), as_text(meta.get("status"), "active")

    memory_type = as_text(meta.get("memory_type"))
    track = as_text(meta.get("track"))
    project_id = as_text(meta.get("project_id"))
    status = as_text(meta.get("status"))

    if memory_type and track:
        return memory_type, track, project_id or name, status or "active"

    if len(parts) == 1:
        return memory_type or "routing", track or "routing", project_id or name, status or "active"

    top = parts[0]
    if top == "用户记忆":
        return "user_profile", "user", project_id or "global", status or "active"
    if top == "项目":
        return "project", "project", project_id or name, status or "active"
    if top == "工作流":
        return "workflow", "workflow", project_id or name, status or "active"
    if top == "决策":
        return "decision", "decision", project_id or name, status or "active"
    if top == "agent":
        if len(parts) > 1 and parts[1] == "case-candidates":
            return "agent_case_candidate", "agent", project_id or name, status or "candidate"
        if len(parts) > 1 and parts[1] == "cases":
            return "agent_case", "agent", project_id or name, status or "active"
        if len(parts) > 1 and parts[1] == "skill-candidates":
            return "skill_candidate", "agent", project_id or name, status or "candidate"
        if path.name == "open-loops.md":
            return "open_loop", "agent", project_id or "open-loops", status or "active"
        return "agent_note", "agent", project_id or name, status or "active"
    return memory_type or "note", track or "misc", project_id or name, status or "active"


def extract_open_loops(path: Path, title: str, rel_path: str, text: str, indexed_at: str) -> list[tuple[str, str, str, str, str, str]]:
    records: list[tuple[str, str, str, str, str, str]] = []
    sections = [
        ("next_hint", ["下次优先看"]),
        ("open_loop", ["未闭环", "待办", "TODO"]),
        ("risk", ["风险"]),
    ]
    for kind, patterns in sections:
        for raw in section_lines(text, patterns):
            item = raw.strip()
            if not item.startswith(("-", "*")):
                continue
            item = re.sub(r"^[-*]\s*", "", item).strip()
            if item and item != "暂无。":
                records.append((str(path), rel_path, title, kind, item[:500], indexed_at))
    return records


def load_doc(path: Path, indexed_at: str) -> tuple[MemoryDoc, list[tuple[str, str, str, str, str, str]]]:
    text = read_markdown_text(path)
    meta = parse_frontmatter(text)
    stat = path.stat()
    rel_path = path.relative_to(VAULT_ROOT).as_posix()
    title = title_from_markdown(text, path)
    memory_type, track, project_id, status = infer_from_path(path, meta)
    verified_at, verified_at_source = extract_verified_at(text, meta, memory_type, status)
    summary = extract_summary(text)
    next_hint = compact_lines(section_lines(text, ["下次优先看"]), 500)
    stale_info = compact_lines(section_lines(text, ["已过时信息"]), 500)
    headings = headings_from_markdown(text)
    keywords = as_text(meta.get("keywords"))
    open_loops = extract_open_loops(path, title, rel_path, text, indexed_at)
    temporal = fact_metadata(meta)
    temporal_policy, temporal_policy_source = temporal_policy_for(
        meta,
        memory_type=memory_type,
        status=status,
        fact=temporal,
    )
    review_after_days, review_after_source = review_after_policy(
        path,
        title,
        memory_type,
        status,
        meta,
    )
    memory_id, memory_id_source = memory_identity(rel_path, meta)
    return (
        MemoryDoc(
            path=path,
            rel_path=rel_path,
            memory_id=memory_id,
            memory_id_source=memory_id_source,
            sha256=sha256_text(text),
            title=title,
            memory_type=memory_type,
            track=track,
            project_id=project_id,
            app_id=as_text(meta.get("app_id"), DEFAULT_APP_ID),
            user_id=as_text(meta.get("user_id"), DEFAULT_USER_ID),
            agent_id=as_text(meta.get("agent_id"), DEFAULT_AGENT_ID),
            agent_scope=as_text(meta.get("agent_scope"), "shared")
            if as_text(meta.get("agent_scope"), "shared") in {"shared", "codex", "claude"}
            else "shared",
            session_id=as_text(meta.get("session_id")),
            status=status,
            sensitivity=as_text(meta.get("sensitivity"), "private" if track == "user" else "normal"),
            risk_class=as_text(meta.get("risk_class")).strip().casefold(),
            risk_class_source="frontmatter" if "risk_class" in meta else "",
            verified_at=verified_at,
            verified_at_source=verified_at_source,
            document_date=extract_document_date(text),
            temporal_policy=temporal_policy,
            temporal_policy_source=temporal_policy_source,
            fact_key=str(temporal["fact_key"]),
            valid_from=str(temporal["valid_from"]),
            valid_until=str(temporal["valid_until"]),
            review_after_days=review_after_days,
            review_after_source=review_after_source,
            supersedes=", ".join(str(item) for item in temporal["supersedes"]),
            mtime=stat.st_mtime,
            size_bytes=stat.st_size,
            line_count=text.count("\n") + 1,
            summary=summary,
            next_hint=next_hint,
            stale_info=stale_info,
            has_open_loop=1 if open_loops else 0,
            open_loop_count=len(open_loops),
            keywords=keywords,
            headings=headings,
            search_text=text,
            indexed_at=indexed_at,
        ),
        open_loops,
    )


def connect() -> sqlite3.Connection:
    assert_runtime_ready("index")
    return secure_sqlite_connect(
        STATE_DB,
        create=False,
        pragmas=(
            "PRAGMA journal_mode=WAL",
            "PRAGMA foreign_keys=ON",
            "PRAGMA busy_timeout=10000",
        ),
    )


def ensure_column(conn: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS memory_docs (
          path TEXT PRIMARY KEY,
          rel_path TEXT NOT NULL,
          memory_id TEXT NOT NULL DEFAULT '',
          memory_id_source TEXT NOT NULL DEFAULT 'legacy_path_hash',
          sha256 TEXT NOT NULL,
          title TEXT NOT NULL,
          memory_type TEXT NOT NULL,
          track TEXT NOT NULL,
          project_id TEXT,
          app_id TEXT DEFAULT 'codex',
          user_id TEXT DEFAULT 'demo-user',
          agent_id TEXT DEFAULT 'codex',
          agent_scope TEXT DEFAULT 'shared',
          session_id TEXT DEFAULT '',
          status TEXT DEFAULT 'active',
          sensitivity TEXT DEFAULT 'normal',
          risk_class TEXT DEFAULT '',
          risk_class_source TEXT DEFAULT '',
          verified_at TEXT,
          verified_at_source TEXT DEFAULT 'mtime_fallback',
          document_date TEXT DEFAULT '',
          temporal_policy TEXT DEFAULT '',
          temporal_policy_source TEXT DEFAULT 'inferred',
          fact_key TEXT DEFAULT '',
          valid_from TEXT DEFAULT '',
          valid_until TEXT DEFAULT '',
          review_after_days INTEGER DEFAULT 180,
          review_after_source TEXT DEFAULT 'inferred',
          supersedes TEXT DEFAULT '',
          mtime REAL NOT NULL,
          size_bytes INTEGER NOT NULL,
          line_count INTEGER NOT NULL,
          summary TEXT,
          next_hint TEXT,
          stale_info TEXT,
          has_open_loop INTEGER DEFAULT 0,
          open_loop_count INTEGER DEFAULT 0,
          indexed_at TEXT NOT NULL
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
          path UNINDEXED,
          title,
          rel_path,
          summary,
          keywords,
          headings,
          search_text,
          tokenize = 'unicode61'
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts_unicode USING fts5(
          path UNINDEXED,
          title,
          rel_path,
          summary,
          keywords,
          headings,
          search_text,
          tokenize = 'unicode61'
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts_trigram USING fts5(
          path UNINDEXED,
          title,
          rel_path,
          summary,
          keywords,
          headings,
          search_text,
          tokenize = 'trigram'
        );

        CREATE TABLE IF NOT EXISTS memory_open_loops (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          path TEXT NOT NULL,
          rel_path TEXT NOT NULL,
          title TEXT NOT NULL,
          kind TEXT NOT NULL,
          item TEXT NOT NULL,
          status TEXT DEFAULT 'open',
          indexed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS memory_supersessions (
          source_rel_path TEXT NOT NULL,
          target_rel_path TEXT NOT NULL,
          source_fact_key TEXT NOT NULL DEFAULT '',
          target_fact_key TEXT NOT NULL DEFAULT '',
          source_valid_from TEXT NOT NULL DEFAULT '',
          target_valid_from TEXT NOT NULL DEFAULT '',
          effective_from TEXT NOT NULL DEFAULT '',
          source_status TEXT NOT NULL,
          target_status TEXT NOT NULL DEFAULT '',
          relation_status TEXT NOT NULL,
          reason_code TEXT NOT NULL DEFAULT '',
          indexed_at TEXT NOT NULL,
          PRIMARY KEY (source_rel_path, target_rel_path)
        );

        CREATE TABLE IF NOT EXISTS memory_fact_states (
          rel_path TEXT PRIMARY KEY,
          fact_key TEXT NOT NULL,
          fact_status TEXT NOT NULL,
          current_rel_path TEXT NOT NULL DEFAULT '',
          superseded_by TEXT NOT NULL DEFAULT '',
          effective_from TEXT NOT NULL DEFAULT '',
          reason_code TEXT NOT NULL DEFAULT '',
          indexed_at TEXT NOT NULL
        );

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
        );

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
        );

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
          PRIMARY KEY (session_hash, path)
        );

        CREATE TABLE IF NOT EXISTS memory_file_observations (
          path TEXT PRIMARY KEY,
          rel_path TEXT NOT NULL,
          sha256 TEXT NOT NULL,
          actor TEXT NOT NULL,
          session_hash TEXT NOT NULL DEFAULT '',
          observed_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_memory_docs_track ON memory_docs(track);
        CREATE INDEX IF NOT EXISTS idx_memory_docs_type ON memory_docs(memory_type);
        CREATE INDEX IF NOT EXISTS idx_memory_docs_project ON memory_docs(project_id);
        CREATE INDEX IF NOT EXISTS idx_memory_docs_user_agent_app ON memory_docs(user_id, agent_id, app_id);
        """
    )
    ensure_column(conn, "memory_docs", "verified_at_source", "TEXT DEFAULT 'mtime_fallback'")
    ensure_column(conn, "memory_docs", "memory_id", "TEXT NOT NULL DEFAULT ''")
    ensure_column(conn, "memory_docs", "memory_id_source", "TEXT NOT NULL DEFAULT 'legacy_path_hash'")
    # init_db is a migration/fixture primitive. The managed index command
    # reaches it only with an explicit maintenance capability; ordinary
    # index/search/retrieve/benchmark paths call assert_schema_ready instead
    # and therefore cannot silently ALTER a live database.
    ensure_column(conn, "memory_docs", "risk_class", "TEXT DEFAULT ''")
    ensure_column(conn, "memory_docs", "risk_class_source", "TEXT DEFAULT ''")
    ensure_column(conn, "memory_docs", "document_date", "TEXT DEFAULT ''")
    ensure_column(conn, "memory_docs", "temporal_policy", "TEXT DEFAULT ''")
    ensure_column(conn, "memory_docs", "temporal_policy_source", "TEXT DEFAULT 'inferred'")
    ensure_column(conn, "memory_docs", "fact_key", "TEXT DEFAULT ''")
    ensure_column(conn, "memory_docs", "valid_from", "TEXT DEFAULT ''")
    ensure_column(conn, "memory_docs", "valid_until", "TEXT DEFAULT ''")
    ensure_column(conn, "memory_docs", "review_after_days", "INTEGER DEFAULT 180")
    ensure_column(conn, "memory_docs", "review_after_source", "TEXT DEFAULT 'inferred'")
    ensure_column(conn, "memory_docs", "supersedes", "TEXT DEFAULT ''")
    for column, ddl in (
        ("source_fact_key", "TEXT NOT NULL DEFAULT ''"),
        ("target_fact_key", "TEXT NOT NULL DEFAULT ''"),
        ("source_valid_from", "TEXT NOT NULL DEFAULT ''"),
        ("target_valid_from", "TEXT NOT NULL DEFAULT ''"),
        ("effective_from", "TEXT NOT NULL DEFAULT ''"),
    ):
        ensure_column(conn, "memory_supersessions", column, ddl)
    ensure_column(conn, "memory_docs", "agent_scope", "TEXT DEFAULT 'shared'")
    ensure_column(conn, "memory_docs", "session_id", "TEXT DEFAULT ''")
    ensure_column(conn, "memory_search_log", "query_sha256", "TEXT")
    ensure_column(conn, "memory_search_log", "query_length", "INTEGER")
    ensure_column(conn, "memory_search_log", "sources", "TEXT")
    ensure_column(conn, "memory_search_log", "duration_ms", "INTEGER")
    ensure_column(conn, "memory_search_log", "metadata_gate_mode", "TEXT NOT NULL DEFAULT 'shadow'")
    ensure_column(conn, "memory_search_log", "metadata_would_block_count", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "memory_search_log", "metadata_reason_fingerprint", "TEXT NOT NULL DEFAULT ''")
    ensure_column(conn, "memory_session_claims", "intent_id", "TEXT NOT NULL DEFAULT ''")
    agent_memory_intent.ensure_schema(conn)
    agent_memory_observability.ensure_schema(conn)
    # Older databases do not have these columns until the migration above runs.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_docs_agent_scope ON memory_docs(agent_scope)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_docs_session ON memory_docs(session_id)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_memory_session_claims_active "
        "ON memory_session_claims(status, actor, session_hash)"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_session_claims_active_intent "
        "ON memory_session_claims(intent_id) WHERE intent_id<>'' AND status='active'"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_docs_fact_key ON memory_docs(fact_key)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_docs_memory_id ON memory_docs(memory_id) WHERE memory_id<>''")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_fact_states_status ON memory_fact_states(fact_status)")
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("memory_index_schema_version", INDEX_SCHEMA_VERSION))
    conn.commit()


def assert_schema_ready(conn: sqlite3.Connection) -> None:
    """Verify the derived index without creating or altering SQLite objects."""

    tables = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")
    }
    required_tables = {
        "meta",
        "memory_docs",
        "memory_fts",
        "memory_fts_unicode",
        "memory_fts_trigram",
        "memory_open_loops",
        "memory_supersessions",
        "memory_fact_states",
        "memory_search_log",
    }
    required_columns = {
        "memory_docs": {
            "path", "rel_path", "memory_id", "memory_id_source", "sha256", "title",
            "memory_type", "track", "project_id", "app_id", "user_id", "agent_id",
            "agent_scope", "session_id", "status", "sensitivity", "verified_at",
            "risk_class", "risk_class_source",
            "verified_at_source", "document_date", "temporal_policy",
            "temporal_policy_source", "fact_key", "valid_from", "valid_until",
            "review_after_days", "review_after_source", "supersedes", "mtime",
            "size_bytes", "line_count", "summary", "next_hint", "stale_info",
            "has_open_loop", "open_loop_count", "indexed_at",
        },
        "memory_fts": {"path", "title", "rel_path", "summary", "keywords", "headings", "search_text"},
        "memory_fts_unicode": {"path", "title", "rel_path", "summary", "keywords", "headings", "search_text"},
        "memory_fts_trigram": {"path", "title", "rel_path", "summary", "keywords", "headings", "search_text"},
        "memory_open_loops": {"path", "rel_path", "title", "kind", "item", "status", "indexed_at"},
        "memory_supersessions": {
            "source_rel_path", "target_rel_path", "source_fact_key", "target_fact_key",
            "source_valid_from", "target_valid_from", "effective_from", "source_status",
            "target_status", "relation_status", "reason_code", "indexed_at",
        },
        "memory_fact_states": {
            "rel_path", "fact_key", "fact_status", "current_rel_path", "superseded_by",
            "effective_from", "reason_code", "indexed_at",
        },
        "memory_search_log": {
            "metadata_gate_mode", "metadata_would_block_count",
            "metadata_reason_fingerprint",
        },
    }
    columns_ready = all(
        required.issubset(
            {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}
        )
        for table, required in required_columns.items()
        if table in tables
    )
    version = None
    if "meta" in tables:
        version = conn.execute(
            "SELECT value FROM meta WHERE key='memory_index_schema_version'"
        ).fetchone()
    if (
        not required_tables.issubset(tables)
        or not columns_ready
        or version is None
        or str(version[0]) != str(INDEX_SCHEMA_VERSION)
    ):
        raise sqlite3.OperationalError("STATE_SCHEMA_MIGRATION_REQUIRED")


def iter_markdown_files() -> list[Path]:
    if not VAULT_ROOT.is_dir():
        raise SystemExit(f"AGENT_MEMORY_ROOT does not exist or is not a directory: {VAULT_ROOT}")
    return sorted(path for path in VAULT_ROOT.rglob("*.md") if path.is_file())


def upsert_doc(conn: sqlite3.Connection, doc: MemoryDoc) -> None:
    conn.execute(
        """
        INSERT INTO memory_docs (
          path, rel_path, memory_id, memory_id_source, sha256, title, memory_type, track, project_id, app_id,
          user_id, agent_id, agent_scope, session_id, status, sensitivity, risk_class, risk_class_source,
          verified_at, verified_at_source,
          document_date, temporal_policy, temporal_policy_source,
          fact_key, valid_from, valid_until, review_after_days, review_after_source,
          supersedes, mtime, size_bytes, line_count, summary, next_hint,
          stale_info, has_open_loop, open_loop_count, indexed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
          rel_path=excluded.rel_path,
          memory_id=excluded.memory_id,
          memory_id_source=excluded.memory_id_source,
          sha256=excluded.sha256,
          title=excluded.title,
          memory_type=excluded.memory_type,
          track=excluded.track,
          project_id=excluded.project_id,
          app_id=excluded.app_id,
          user_id=excluded.user_id,
          agent_id=excluded.agent_id,
          agent_scope=excluded.agent_scope,
          session_id=excluded.session_id,
          status=excluded.status,
          sensitivity=excluded.sensitivity,
          risk_class=excluded.risk_class,
          risk_class_source=excluded.risk_class_source,
          verified_at=excluded.verified_at,
          verified_at_source=excluded.verified_at_source,
          document_date=excluded.document_date,
          temporal_policy=excluded.temporal_policy,
          temporal_policy_source=excluded.temporal_policy_source,
          fact_key=excluded.fact_key,
          valid_from=excluded.valid_from,
          valid_until=excluded.valid_until,
          review_after_days=excluded.review_after_days,
          review_after_source=excluded.review_after_source,
          supersedes=excluded.supersedes,
          mtime=excluded.mtime,
          size_bytes=excluded.size_bytes,
          line_count=excluded.line_count,
          summary=excluded.summary,
          next_hint=excluded.next_hint,
          stale_info=excluded.stale_info,
          has_open_loop=excluded.has_open_loop,
          open_loop_count=excluded.open_loop_count,
          indexed_at=excluded.indexed_at
        """,
        (
            str(doc.path),
            doc.rel_path,
            doc.memory_id,
            doc.memory_id_source,
            doc.sha256,
            doc.title,
            doc.memory_type,
            doc.track,
            doc.project_id,
            doc.app_id,
            doc.user_id,
            doc.agent_id,
            doc.agent_scope,
            doc.session_id,
            doc.status,
            doc.sensitivity,
            doc.risk_class,
            doc.risk_class_source,
            doc.verified_at,
            doc.verified_at_source,
            doc.document_date,
            doc.temporal_policy,
            doc.temporal_policy_source,
            doc.fact_key,
            doc.valid_from,
            doc.valid_until,
            doc.review_after_days,
            doc.review_after_source,
            doc.supersedes,
            doc.mtime,
            doc.size_bytes,
            doc.line_count,
            doc.summary,
            doc.next_hint,
            doc.stale_info,
            doc.has_open_loop,
            doc.open_loop_count,
            doc.indexed_at,
        ),
    )


def insert_fts(conn: sqlite3.Connection, doc: MemoryDoc) -> None:
    values = (
        str(doc.path),
        doc.title,
        doc.rel_path,
        doc.summary,
        doc.keywords,
        doc.headings,
        doc.search_text,
    )
    for table in ("memory_fts", "memory_fts_unicode", "memory_fts_trigram"):
        conn.execute(
            f"""
            INSERT INTO {table}(path, title, rel_path, summary, keywords, headings, search_text)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )


def _normalized_scope_value(value: object) -> str:
    return unicodedata.normalize("NFKC", str(value or "").strip()).casefold()


def _fact_scope(row: object) -> tuple[str, str, str, str]:
    return (
        _normalized_scope_value(row["app_id"]),
        _normalized_scope_value(row["project_id"]),
        _normalized_scope_value(row["user_id"]),
        _normalized_scope_value(row["agent_scope"] or "shared"),
    )


def _edge_in_cycle(edge: tuple[str, str], adjacency: dict[str, set[str]]) -> bool:
    source, target = edge
    pending = [target]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current == source:
            return True
        if current in visited:
            continue
        visited.add(current)
        pending.extend(adjacency.get(current, set()) - visited)
    return False


def build_temporal_projection(
    rows: list[object],
    indexed_at: str,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Build deterministic supersession edges and one current-fact state.

    The input may come from SQLite or from the Write Gateway's live Markdown
    scan.  Only explicit, same-scope, same-key, forward-dated edges can hide an
    older fact.  Ambiguity is retained as a conflict and never resolved by
    semantic similarity or timestamps alone.
    """

    by_path = {
        str(row["rel_path"]): row
        for row in rows
        if str(row.get("memory_type", "") if isinstance(row, dict) else row["memory_type"] or "").casefold()
        not in {"template", "directory_index", "routing"}
    }
    record_errors: dict[str, list[str]] = {}
    for rel_path, row in by_path.items():
        errors: list[str] = []
        raw_key = str(row["fact_key"] or "")
        raw_supersedes = as_list(str(row["supersedes"] or ""))
        if not raw_key and not raw_supersedes:
            continue
        _key, key_error = normalized_fact_key(raw_key)
        _start, start_error = temporal_date(row["valid_from"])
        if key_error:
            errors.append(key_error)
        if start_error:
            errors.append("VALID_FROM_INVALID")
        valid_until = str(row["valid_until"] or "").strip()
        if valid_until:
            _until, until_error = temporal_date(valid_until)
            if until_error:
                errors.append("VALID_UNTIL_INVALID")
            elif not start_error and valid_until < str(row["valid_from"]):
                errors.append("VALIDITY_RANGE_INVALID")
        record_errors[rel_path] = list(dict.fromkeys(errors))

    relations: list[dict[str, str]] = []
    preliminary: list[int] = []
    for source, row in by_path.items():
        for declared in as_list(str(row["supersedes"] or "")):
            target, reason = normalized_relation_ref(declared)
            target_row = by_path.get(target)
            source_key, source_key_error = normalized_fact_key(row["fact_key"])
            source_from, source_from_error = temporal_date(row["valid_from"])
            target_key = ""
            target_from = ""
            target_status = ""
            if target_row is not None:
                target_key, target_key_error = normalized_fact_key(target_row["fact_key"])
                target_from, target_from_error = temporal_date(target_row["valid_from"])
                target_status = str(target_row["status"] or "").casefold()
            else:
                target_key_error = "FACT_KEY_REQUIRED"
                target_from_error = "DATE_REQUIRED"
            if not reason and target == source:
                reason = "REFERENCE_SELF"
            elif not reason and target_row is None:
                reason = "TARGET_MISSING"
            elif (
                not reason
                and str(row["status"] or "").casefold()
                not in FACT_LINEAGE_SOURCE_STATUSES
            ):
                reason = "SOURCE_NOT_CURRENT"
            elif not reason and source_key_error:
                reason = source_key_error
            elif not reason and target_key_error:
                reason = "TARGET_FACT_KEY_INVALID"
            elif not reason and source_key != target_key:
                reason = "FACT_KEY_MISMATCH"
            elif not reason and _fact_scope(row) != _fact_scope(target_row):
                reason = "FACT_SCOPE_MISMATCH"
            elif not reason and source_from_error:
                reason = "SOURCE_VALID_FROM_INVALID"
            elif not reason and target_from_error:
                reason = "TARGET_VALID_FROM_INVALID"
            elif not reason and source_from <= target_from:
                reason = "VALID_FROM_NOT_FORWARD"
            relation = {
                "source_rel_path": source,
                "target_rel_path": target,
                "source_fact_key": source_key,
                "target_fact_key": target_key,
                "source_valid_from": source_from,
                "target_valid_from": target_from,
                "effective_from": source_from if not source_from_error else "",
                "source_status": str(row["status"] or "").casefold(),
                "target_status": target_status,
                "relation_status": "invalid" if reason else "effective",
                "reason_code": reason,
                "indexed_at": indexed_at,
            }
            relations.append(relation)
            if not reason:
                preliminary.append(len(relations) - 1)

    incoming: dict[str, list[int]] = {}
    adjacency: dict[str, set[str]] = {}
    for index in preliminary:
        relation = relations[index]
        incoming.setdefault(relation["target_rel_path"], []).append(index)
        adjacency.setdefault(relation["source_rel_path"], set()).add(relation["target_rel_path"])
    for indexes in incoming.values():
        if len(indexes) > 1:
            for index in indexes:
                relations[index]["relation_status"] = "invalid"
                relations[index]["reason_code"] = "MULTIPLE_SUCCESSORS"
    for index in preliminary:
        relation = relations[index]
        if relation["relation_status"] == "effective" and _edge_in_cycle(
            (relation["source_rel_path"], relation["target_rel_path"]), adjacency
        ):
            relation["relation_status"] = "invalid"
            relation["reason_code"] = "SUPERSESSION_CYCLE"

    effective_incoming = {
        relation["target_rel_path"]: relation
        for relation in relations
        if relation["relation_status"] == "effective"
    }
    invalid_by_path: dict[str, set[str]] = {}
    for relation in relations:
        if relation["relation_status"] == "effective":
            continue
        reason = relation["reason_code"] or "RELATION_INVALID"
        invalid_by_path.setdefault(relation["source_rel_path"], set()).add(reason)
        if relation["target_rel_path"] in by_path:
            invalid_by_path.setdefault(relation["target_rel_path"], set()).add(reason)

    groups: dict[tuple[tuple[str, str, str, str], str], list[str]] = {}
    for rel_path, row in by_path.items():
        key = str(row["fact_key"] or "")
        if key:
            groups.setdefault((_fact_scope(row), key), []).append(rel_path)

    states_by_path: dict[str, dict[str, str]] = {}
    for (_scope, fact_key), paths in groups.items():
        active = [
            path
            for path in paths
            if str(by_path[path]["status"] or "").casefold() == "active"
            and not record_errors.get(path)
        ]
        heads = [path for path in active if path not in effective_incoming]
        if len(heads) > 1:
            for path in paths:
                states_by_path[path] = {
                    "rel_path": path,
                    "fact_key": fact_key,
                    "fact_status": "conflict",
                    "current_rel_path": "",
                    "superseded_by": "",
                    "effective_from": "",
                    "reason_code": "MULTIPLE_CURRENT_FACTS",
                    "indexed_at": indexed_at,
                }
            continue
        current_path = heads[0] if heads else ""
        for path in paths:
            row = by_path[path]
            incoming_relation = effective_incoming.get(path)
            if record_errors.get(path):
                fact_status = "invalid_metadata"
                reason = ",".join(record_errors[path])
            elif path in invalid_by_path:
                fact_status = "invalid_relation"
                reason = ",".join(sorted(invalid_by_path[path]))
            elif incoming_relation is not None:
                fact_status = "superseded"
                reason = "SUPERSEDED_BY_EXPLICIT_EDGE"
            elif str(row["status"] or "").casefold() != "active":
                fact_status = "historical"
                reason = "DOCUMENT_NOT_ACTIVE"
            elif current_path == path:
                fact_status = "current"
                reason = ""
            else:
                fact_status = "no_current"
                reason = "NO_ACTIVE_CURRENT_FACT"
            states_by_path[path] = {
                "rel_path": path,
                "fact_key": fact_key,
                "fact_status": fact_status,
                "current_rel_path": current_path,
                "superseded_by": incoming_relation["source_rel_path"] if incoming_relation else "",
                "effective_from": incoming_relation["effective_from"] if incoming_relation else "",
                "reason_code": reason,
                "indexed_at": indexed_at,
            }
    return relations, [states_by_path[path] for path in sorted(states_by_path)]


def _rebuild_supersessions(conn: sqlite3.Connection, indexed_at: str) -> None:
    cursor = conn.execute(
        """
        SELECT rel_path, sha256, memory_type, status, fact_key, valid_from, valid_until,
               supersedes, app_id, project_id, user_id, agent_scope
        FROM memory_docs
        ORDER BY rel_path
        """
    )
    columns = [str(item[0]) for item in cursor.description or ()]
    rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    relations, states = build_temporal_projection(rows, indexed_at)
    conn.executemany(
        """
        INSERT INTO memory_supersessions(
          source_rel_path, target_rel_path, source_fact_key, target_fact_key,
          source_valid_from, target_valid_from, effective_from, source_status,
          target_status, relation_status, reason_code, indexed_at
        ) VALUES (
          :source_rel_path, :target_rel_path, :source_fact_key, :target_fact_key,
          :source_valid_from, :target_valid_from, :effective_from, :source_status,
          :target_status, :relation_status, :reason_code, :indexed_at
        )
        """,
        relations,
    )
    conn.executemany(
        """
        INSERT INTO memory_fact_states(
          rel_path, fact_key, fact_status, current_rel_path, superseded_by,
          effective_from, reason_code, indexed_at
        ) VALUES (
          :rel_path, :fact_key, :fact_status, :current_rel_path, :superseded_by,
          :effective_from, :reason_code, :indexed_at
        )
        """,
        states,
    )


def scan(conn: sqlite3.Connection) -> None:
    # The index is derived state, but its schema is installer-owned. Ordinary
    # scans may refresh rows only; they must never repair tables or columns.
    assert_schema_ready(conn)
    indexed_at = utc_now()
    conn.execute("DELETE FROM memory_docs")
    for table in ("memory_fts", "memory_fts_unicode", "memory_fts_trigram"):
        conn.execute(f"DELETE FROM {table}")
    conn.execute("DELETE FROM memory_open_loops")
    conn.execute("DELETE FROM memory_supersessions")
    conn.execute("DELETE FROM memory_fact_states")
    files = iter_markdown_files()
    for path in files:
        doc, open_loops = load_doc(path, indexed_at)
        upsert_doc(conn, doc)
        insert_fts(conn, doc)
        conn.executemany(
            """
            INSERT INTO memory_open_loops(path, rel_path, title, kind, item, indexed_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            open_loops,
        )
    _rebuild_supersessions(conn, indexed_at)
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("memory_index_last_scan_at", indexed_at))
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("memory_index_doc_count", str(len(files))))


def query_chunks(raw_query: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9_.+-]+|[\u3400-\u9fff]+", raw_query.strip())


def lexical_terms(raw_query: str, limit: int = 18) -> list[str]:
    terms: list[str] = []
    for chunk in query_chunks(raw_query):
        if re.fullmatch(r"[\u3400-\u9fff]+", chunk):
            if len(chunk) <= 6:
                terms.append(chunk)
            gram_size = 2 if len(chunk) <= 8 else 3
            terms.extend(chunk[index : index + gram_size] for index in range(len(chunk) - gram_size + 1))
        else:
            terms.append(chunk.lower())
    return list(dict.fromkeys(term for term in terms if term))[:limit]


def fts_query(raw_query: str) -> str:
    terms = query_chunks(raw_query)
    if not terms:
        return '""'
    escaped = [term.replace('"', '""') for term in terms[:8]]
    return " OR ".join(f'"{term}"' for term in escaped)


def row_matches_filters(
    row: sqlite3.Row,
    track: str,
    memory_type: str,
    project_id: str,
    user_id: str,
    agent_id: str,
    app_id: str,
    session_id: str,
    status: str,
    has_open_loop: bool,
) -> bool:
    if track and row["track"] != track:
        return False
    if memory_type and row["memory_type"] != memory_type:
        return False
    if project_id and project_id.lower() not in str(row["project_id"]).lower():
        return False
    if user_id and row["user_id"] != user_id:
        return False
    if agent_id and row["agent_id"] != agent_id:
        return False
    if app_id and row["app_id"] != app_id:
        return False
    if session_id and row["session_id"] != session_id:
        return False
    if status and row["status"] != status:
        return False
    if has_open_loop and int(row["has_open_loop"] or 0) != 1:
        return False
    return True


def score_row(row: sqlite3.Row, terms: list[str]) -> int:
    if not terms:
        return 0
    fields = {
        "title": str(row["title"]).lower(),
        "rel_path": str(row["rel_path"]).lower(),
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
    if row["memory_type"] in {"routing", "directory_index", "template"}:
        score -= 4
    if int(row["has_open_loop"] or 0):
        score += 1
    return score


def dedupe_and_rank(rows: list[sqlite3.Row], query: str, limit: int) -> list[sqlite3.Row]:
    terms = lexical_terms(query)
    by_path: dict[str, sqlite3.Row] = {}
    for row in rows:
        by_path.setdefault(row["path"], row)
    ranked = sorted(
        by_path.values(),
        key=lambda row: (score_row(row, terms), float(row["mtime"] or 0)),
        reverse=True,
    )
    return ranked[:limit]


def search(
    conn: sqlite3.Connection,
    query: str,
    limit: int,
    track: str = "",
    memory_type: str = "",
    project_id: str = "",
    user_id: str = "",
    agent_id: str = "",
    app_id: str = "",
    session_id: str = "",
    status: str = "",
    has_open_loop: bool = False,
) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    assert_schema_ready(conn)
    rows: list[sqlite3.Row] = []
    try:
        rows = list(
            conn.execute(
                """
                SELECT d.*, memory_fts.search_text AS search_text, snippet(memory_fts, 6, '[', ']', '...', 12) AS hit
                FROM memory_fts
                JOIN memory_docs d ON d.path = memory_fts.path
                WHERE memory_fts MATCH ?
                ORDER BY bm25(memory_fts)
                LIMIT ?
                """,
                (fts_query(query), max(limit * 12, 50)),
            )
        )
    except sqlite3.Error:
        rows = []

    seen = {row["path"] for row in rows}
    terms = lexical_terms(query)
    if terms:
        like_parts: list[str] = []
        params: list[object] = []
        for term in terms[:6]:
            like = f"%{term}%"
            like_parts.append(
                "(memory_fts.title LIKE ? OR memory_fts.rel_path LIKE ? OR memory_fts.summary LIKE ? OR memory_fts.search_text LIKE ?)"
            )
            params.extend([like, like, like, like])
        fallback = list(
            conn.execute(
                f"""
                SELECT d.*, memory_fts.search_text AS search_text, substr(memory_fts.summary, 1, 160) AS hit
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
            if row["path"] not in seen:
                rows.append(row)
                seen.add(row["path"])

    rows = [
        row
        for row in rows
        if row_matches_filters(
            row,
            track,
            memory_type,
            project_id,
            user_id,
            agent_id,
            app_id,
            session_id,
            status,
            has_open_loop,
        )
    ]
    return dedupe_and_rank(rows, query, limit)


def print_search(
    conn: sqlite3.Connection,
    query: str,
    limit: int,
    include_open_loops: bool,
    track: str,
    memory_type: str,
    project_id: str,
    user_id: str,
    agent_id: str,
    app_id: str,
    session_id: str,
    status: str,
    has_open_loop: bool,
) -> None:
    started = time.monotonic()
    rows = search(
        conn,
        query,
        limit,
        track,
        memory_type,
        project_id,
        user_id,
        agent_id,
        app_id,
        session_id,
        status,
        has_open_loop,
    )
    print(f"query={query}")
    if any([track, memory_type, project_id, user_id, agent_id, app_id, session_id, status, has_open_loop]):
        print(
            "filters="
            f"track={track or '*'} "
            f"memory_type={memory_type or '*'} "
            f"project_id={project_id or '*'} "
            f"user_id={user_id or '*'} "
            f"agent_id={agent_id or '*'} "
            f"app_id={app_id or '*'} "
            f"session_id={session_id or '*'} "
            f"status={status or '*'} "
            f"has_open_loop={has_open_loop}"
        )
    print(f"results={len(rows)}")
    for index, row in enumerate(rows, 1):
        print(f"{index}. {row['rel_path']}")
        print(f"   title: {row['title']}")
        print(
            "   type: "
            f"{row['memory_type']} track={row['track']} project_id={row['project_id']} "
            f"user_id={row['user_id']} agent_id={row['agent_id']} app_id={row['app_id']} status={row['status']}"
        )
        print(f"   verified_at: {row['verified_at']} source={row['verified_at_source']}")
        print(f"   summary: {str(row['summary'] or '')[:220]}")
        hit = str(row["hit"] or "").replace("\n", " ")
        print(f"   hit: {hit[:220]}")
        if include_open_loops:
            loops = conn.execute(
                "SELECT kind, item FROM memory_open_loops WHERE path=? AND status='open' LIMIT 3",
                (row["path"],),
            ).fetchall()
            for kind, item in loops:
                print(f"   open_loop[{kind}]: {item[:180]}")
    agent_memory_observability.record_search(
        conn,
        query=query,
        rel_paths=[str(row["rel_path"]) for row in rows],
        sources=["sqlite"],
        duration_ms=round((time.monotonic() - started) * 1000),
        search_status="success",
    )


def print_report(conn: sqlite3.Connection) -> None:
    assert_schema_ready(conn)
    doc_count = conn.execute("SELECT COUNT(*) FROM memory_docs").fetchone()[0]
    unicode_fts_count = conn.execute("SELECT COUNT(DISTINCT path) FROM memory_fts_unicode").fetchone()[0]
    trigram_fts_count = conn.execute("SELECT COUNT(DISTINCT path) FROM memory_fts_trigram").fetchone()[0]
    loop_count = conn.execute("SELECT COUNT(*) FROM memory_open_loops WHERE status='open'").fetchone()[0]
    relation_count = conn.execute("SELECT COUNT(*) FROM memory_supersessions").fetchone()[0]
    invalid_relation_count = conn.execute(
        "SELECT COUNT(*) FROM memory_supersessions WHERE relation_status<>'effective'"
    ).fetchone()[0]
    fact_state_counts = {
        str(row[0]): int(row[1])
        for row in conn.execute(
            "SELECT fact_status, COUNT(*) AS item_count FROM memory_fact_states GROUP BY fact_status"
        )
    }
    last_scan = conn.execute("SELECT value FROM meta WHERE key='memory_index_last_scan_at'").fetchone()
    print(f"vault_root={VAULT_ROOT}")
    print(f"state_db={STATE_DB}")
    print(f"memory_docs={doc_count}")
    print(f"memory_fts_unicode={unicode_fts_count}")
    print(f"memory_fts_trigram={trigram_fts_count}")
    print(f"memory_open_loops={loop_count}")
    print(f"memory_supersessions={relation_count}")
    print(f"memory_supersessions_invalid={invalid_relation_count}")
    print(
        "memory_fact_states="
        + ",".join(f"{key}:{fact_state_counts[key]}" for key in sorted(fact_state_counts))
    )
    print(f"last_scan_at={last_scan[0] if last_scan else ''}")
    for track, count in conn.execute(
        "SELECT track, COUNT(*) AS item_count FROM memory_docs GROUP BY track ORDER BY item_count DESC, track"
    ):
        print(f"track[{track}]={count}")
    for memory_type, count in conn.execute(
        "SELECT memory_type, COUNT(*) AS item_count FROM memory_docs GROUP BY memory_type ORDER BY item_count DESC, memory_type"
    ):
        print(f"type[{memory_type}]={count}")


def generated_index_markdown(conn: sqlite3.Connection) -> str:
    """Generate the canonical, deterministic INDEX.md from Markdown metadata."""
    assert_schema_ready(conn)
    rows = conn.execute(
        """
        SELECT rel_path, title, memory_type, track, project_id, status, summary
        FROM memory_docs
        WHERE rel_path<>'INDEX.md'
        ORDER BY
          CASE status
            WHEN 'active' THEN 1
            WHEN 'pending_verification' THEN 2
            WHEN 'candidate' THEN 3
            WHEN 'outdated' THEN 4
            WHEN 'archived' THEN 5
            ELSE 9
          END,
          memory_type,
          rel_path
        """
    ).fetchall()
    lines = [
        GENERATED_INDEX_MARKER,
        "# Claude Code、Codex 与 Ailu 共享记忆索引",
        "",
        "本文件由 Agent Memory Runtime 根据 Markdown/frontmatter 自动生成。请修改对应记忆文件，不要直接编辑本文件。",
    ]
    current_group = ""
    for row in rows:
        rel_path, title, memory_type, track, project_id, status, summary = row
        normalized_status = status or "active"
        normalized_type = memory_type or track or "uncategorized"
        group = f"{normalized_status} / {normalized_type}"
        if group != current_group:
            current_group = group
            lines.extend(["", f"## {current_group}", ""])
        compact_summary = (summary or "").replace("\n", " ").strip()
        if len(compact_summary) > 120:
            compact_summary = compact_summary[:117] + "..."
        metadata = str(track or "")
        if project_id:
            metadata += f"; {project_id}"
        suffix = f"; {compact_summary}" if compact_summary else ""
        lines.append(f"- `{rel_path}`: {title} ({metadata}){suffix}")
    lines.append("")
    return "\n".join(lines)


def generated_index_navigation_references(text: str) -> list[str]:
    """Return only canonical navigation rows from a generated ``INDEX.md``.

    Generated summaries are free to mention Markdown paths in inline code.  A
    navigation reference therefore exists only when a list row starts with the
    generator's canonical ``- `<relative>.md`:`` prefix.  Reject non-canonical
    spellings here as well; exact-byte verification catches generated-file
    tampering, while this parser keeps parity counts content-independent.
    """

    references: list[str] = []
    for line in text.splitlines():
        match = GENERATED_INDEX_ENTRY_RE.match(line)
        if match is None:
            continue
        rel_path = match.group("rel_path")
        parts = rel_path.split("/")
        if (
            rel_path.startswith("/")
            or "\\" in rel_path
            or any(part in {"", ".", ".."} for part in parts)
            or "/".join(parts) != rel_path
        ):
            continue
        references.append(rel_path)
    return references


def generated_index_candidate(conn: sqlite3.Connection) -> str:
    """Compatibility alias for callers that previously requested a candidate."""

    return generated_index_markdown(conn)


def write_generated_index_candidate(raw_output: str, candidate: str) -> Path:
    """Create a review candidate outside the Vault without overwriting bytes."""

    output_path = Path(raw_output).expanduser().resolve(strict=False)
    vault_root = VAULT_ROOT.resolve()
    try:
        output_path.relative_to(vault_root)
    except ValueError:
        pass
    else:
        # Neither INDEX.md nor a differently named formal-memory file may be
        # used as a side door around the generated-file/write-gateway rules.
        raise GeneratedIndexCapabilityError("GENERATED_FILE_READ_ONLY")
    if output_path.exists() or output_path.is_symlink():
        raise RuntimeError("INDEX_CANDIDATE_OUTPUT_EXISTS")
    if not output_path.parent.is_dir() or output_path.parent.is_symlink():
        raise RuntimeError("INDEX_CANDIDATE_OUTPUT_PARENT_UNSAFE")
    payload = candidate.encode("utf-8")
    descriptor = os.open(
        output_path,
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        # Preserve a partial candidate for inspection; automatic code never
        # deletes or replaces user-visible evidence.
        raise
    return output_path


def sync_generated_index(
    conn: sqlite3.Connection,
    *,
    consumed_capability: dict[str, Any] | None = None,
) -> dict[str, object]:
    """Atomically publish the generated INDEX.md and report whether bytes changed."""

    authorization = consumed_capability
    if authorization is None:
        authorization = consume_generated_index_capability_from_environment(
            CONFIG_ROOT,
            state_db=STATE_DB,
        )
    if authorization.get("ok") is not True:
        raise GeneratedIndexCapabilityError("GENERATED_FILE_READ_ONLY")
    target = VAULT_ROOT / "INDEX.md"
    verify_generated_index_transaction_snapshot(authorization)
    if target.is_symlink():
        raise RuntimeError("GENERATED_INDEX_TARGET_UNSAFE")
    payload = generated_index_markdown(conn).encode("utf-8")
    current = target.read_bytes() if target.is_file() else b""
    digest = hashlib.sha256(payload).hexdigest()
    bind_expected_generated_index_sha256(
        STATE_DB,
        authorization,
        generated_sha256=digest,
    )
    if current == payload:
        verify_generated_index_transaction_snapshot(
            authorization,
            expected_index_sha256=digest,
        )
        return {"changed": False, "path": str(target), "sha256": digest}
    target.parent.mkdir(parents=True, exist_ok=True)
    transaction_id = str(authorization["transaction_binding"]["transaction_id"])
    evidence_root = generated_index_backup_directory(CONFIG_ROOT, transaction_id)
    temporary = evidence_root / f"generated-{os.getpid()}-{time.time_ns()}-{digest[:12]}.md"
    descriptor = os.open(
        temporary,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    evidence_path: Path | None = None
    published = False
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if target.exists() and not target.is_symlink():
            os.chmod(temporary, target.stat().st_mode & 0o777)
        planned_evidence = (
            evidence_root / f"previous-{os.getpid()}-{time.time_ns()}-{digest[:12]}.md"
            if os.name == "nt"
            else temporary
        )
        bind_generated_index_recovery_evidence(
            STATE_DB,
            authorization,
            config_root=CONFIG_ROOT,
            evidence_path=planned_evidence,
        )
        evidence_path = conditional_atomic_replace(
            target,
            temporary,
            expected_current_sha256=str(
                authorization["transaction_binding"]["index_base_sha256"]
            ),
            evidence_path=planned_evidence,
        )
        published = True
        verify_generated_index_transaction_snapshot(
            authorization,
            expected_index_sha256=digest,
        )
        # The INDEX document itself is part of SQLite parity.  Do the second
        # scan before the durable transaction can become consumed.
        scan(conn)
        rescanned_payload = generated_index_markdown(conn).encode("utf-8")
        rescanned_digest = hashlib.sha256(rescanned_payload).hexdigest()
        verify_generated_index_transaction_snapshot(
            authorization,
            expected_index_sha256=digest,
        )
        target_payload = (
            target.read_bytes()
            if target.is_file() and not target.is_symlink()
            else b""
        )
        target_digest = hashlib.sha256(target_payload).hexdigest()
        if (
            rescanned_payload != payload
            or rescanned_digest != digest
            or target_payload != payload
            or target_digest != digest
        ):
            raise GeneratedIndexCapabilityError("GENERATED_INDEX_POST_SCAN_DRIFT")
    except Exception as exc:
        # If publication happened but a later verification/scan failed, restore
        # only while the target still contains our generated bytes.  A user or
        # concurrent process edit wins and is preserved as an incident.
        if published and evidence_path is not None:
            try:
                conditional_atomic_replace(
                    target,
                    evidence_path,
                    expected_current_sha256=digest,
                )
                scan(conn)
            except Exception as rollback_exc:
                raise GeneratedIndexCapabilityError(
                    "GENERATED_INDEX_ROLLBACK_CONFLICT"
                ) from rollback_exc
        if isinstance(exc, GeneratedIndexCapabilityError):
            raise
        raise GeneratedIndexCapabilityError("GENERATED_INDEX_ATOMIC_CAS_FAILED") from exc
    return {
        "changed": True,
        "path": str(target),
        "sha256": digest,
        "previous_bytes_evidence": str(evidence_path),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and query the full Agent Memory SQLite index.")
    parser.add_argument("--init", action="store_true", help="Create or migrate the index schema.")
    parser.add_argument("--scan", action="store_true", help="Scan all Markdown files into SQLite.")
    parser.add_argument("--report", action="store_true", help="Print index summary.")
    parser.add_argument("--search", help="Search the local memory index.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Maximum search results.")
    parser.add_argument("--include-open-loops", action="store_true", help="Show open loop snippets for search hits.")
    parser.add_argument("--track", default="", help="Filter by track, e.g. project, workflow, user, agent.")
    parser.add_argument("--memory-type", default="", help="Filter by memory_type.")
    parser.add_argument("--project-id", default="", help="Filter by project_id substring.")
    parser.add_argument("--user-id", default="", help="Filter by user_id.")
    parser.add_argument("--agent-id", default="", help="Filter by agent_id.")
    parser.add_argument("--app-id", default="", help="Filter by app_id.")
    parser.add_argument("--session-id", default="", help="Filter by session_id.")
    parser.add_argument("--status", default="", help="Filter by status.")
    parser.add_argument("--has-open-loop", action="store_true", help="Only return docs with open loops.")
    parser.add_argument("--gen-index-candidate", action="store_true", help="Generate an INDEX.md candidate from SQLite.")
    parser.add_argument("--sync-generated-index", action="store_true", help="Atomically synchronize the generated INDEX.md.")
    parser.add_argument("--output", default="", help="Optional output path for --gen-index-candidate.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        transition = assert_runtime_ready("index")
    except RuntimeTransitionError as exc:
        print(str(exc))
        return 2
    if not (args.init or args.scan or args.report or args.search or args.gen_index_candidate or args.sync_generated_index):
        args.init = True
        args.scan = True
        args.report = True
    generated_index_capability: dict[str, Any] | None = None
    if args.sync_generated_index:
        # Consume the short-lived one-shot capability before a potentially
        # expensive full-vault scan.  The authorization remains process-local
        # and cannot expire midway through the already-authorized operation.
        try:
            generated_index_capability = consume_generated_index_capability_from_environment(
                CONFIG_ROOT,
                state_db=STATE_DB,
            )
            verify_generated_index_transaction_snapshot(generated_index_capability)
        except GeneratedIndexCapabilityError as exc:
            print(str(exc))
            return 2
    with connect() as conn:
        try:
            if args.init:
                if transition.get("maintenance_capability"):
                    init_db(conn)
                else:
                    assert_schema_ready(conn)
            if args.scan:
                scan(conn)
                if args.sync_generated_index:
                    # The capability ledger shares the state database.  Release
                    # the derived-index write transaction before the separate
                    # one-shot ledger connection binds generated bytes.
                    conn.commit()
        except sqlite3.OperationalError as exc:
            if str(exc) == "STATE_SCHEMA_MIGRATION_REQUIRED":
                print("STATE_SCHEMA_MIGRATION_REQUIRED")
                return 2
            raise
        if args.sync_generated_index:
            try:
                result = sync_generated_index(
                    conn,
                    consumed_capability=generated_index_capability,
                )
            except (GeneratedIndexCapabilityError, OSError, RuntimeError, sqlite3.Error) as exc:
                print(str(exc))
                return 2
            print(f"generated_index_changed={int(bool(result['changed']))}")
            print(f"generated_index_path={result['path']}")
            print(f"generated_index_sha256={result['sha256']}")
        if args.search:
            print_search(
                conn,
                args.search,
                max(args.limit, 1),
                args.include_open_loops,
                args.track,
                args.memory_type,
                args.project_id,
                args.user_id,
                args.agent_id,
                args.app_id,
                args.session_id,
                args.status,
                args.has_open_loop,
            )
        if args.report or args.scan:
            print_report(conn)
        if args.gen_index_candidate:
            candidate = generated_index_candidate(conn)
            if args.output:
                try:
                    output_path = write_generated_index_candidate(args.output, candidate)
                except (GeneratedIndexCapabilityError, RuntimeError, OSError) as exc:
                    print(str(exc))
                    return 2
                print(f"index_candidate={output_path}")
            else:
                print(candidate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
