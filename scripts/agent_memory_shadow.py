#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import errno
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import sys
import time
import uuid
from pathlib import Path
from typing import Any

try:  # pragma: no cover - exercised by native POSIX jobs.
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

try:  # pragma: no cover - exercised by native Windows jobs.
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None  # type: ignore[assignment]

from agent_memory_env import (
    RuntimeTransitionError,
    assert_runtime_ready,
    config_path,
    env_value,
    expand_path,
    load_config,
    reset_config_cache,
)
from agent_memory_state import (
    ConditionalWriteError,
    StateSecurityError,
    assert_no_symlink_beneath,
    search_log_privacy_guard_report,
    secure_conditional_write_bytes_beneath,
    secure_sqlite_connect,
)


CONFIG_ROOT = expand_path(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory")).resolve()
STATE_DB = expand_path(env_value("STATE_DB", str(CONFIG_ROOT / "state.sqlite"))).resolve()
MANIFEST_PATH = CONFIG_ROOT / "config" / "runtime-manifest.json"
SHADOW_ROOT = expand_path(env_value("SHADOW_STATE_DIR", str(CONFIG_ROOT / "shadow"))).resolve()
MAX_ATTESTATION_BYTES = 256 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}")
TEMPORAL_POLICIES = frozenset({"structural", "snapshot", "stable", "reviewable", "expiring"})
RISK_CLASSES = frozenset({"ordinary", "action_sensitive"})
RISK_REQUIRED_TRACKS = frozenset({"project", "workflow", "decision"})
NON_GOVERNED_MEMORY_TYPES = frozenset({"routing", "directory_index", "template", "governance"})
ACTION_SENSITIVE_MEMORY_TYPES = frozenset({"fact", "atomic_fact", "current_fact"})
RISK_PATH_REASON_MAP = {
    "RISK_CLASS_INVALID": "METADATA_RISK_CLASS_INVALID",
    "RISK_CLASS_DOWNGRADE": "METADATA_RISK_CLASS_DOWNGRADE",
}
METADATA_GATE_REASON_CODES = frozenset({
    "METADATA_MEMORY_ID_NOT_EXPLICIT",
    "METADATA_TEMPORAL_POLICY_NOT_EXPLICIT",
    "METADATA_REVIEW_POLICY_NOT_EXPLICIT",
    "METADATA_RISK_CLASS_NOT_EXPLICIT",
    "METADATA_RISK_CLASS_INVALID",
    "METADATA_RISK_CLASS_DOWNGRADE",
    "METADATA_ATOMIC_TEMPORAL_POLICY_INVALID",
    "METADATA_ATOMIC_FACT_KEY_INVALID",
    "METADATA_ATOMIC_VALID_FROM_INVALID",
    "METADATA_ATOMIC_VERIFIED_AT_INVALID",
    "METADATA_ATOMIC_VALID_UNTIL_INVALID",
    "METADATA_CURRENT_CONTENT_EVIDENCE_RECEIPT_MISSING",
})
ATOMIC_FACT_GAP_REASON_MAP = {
    "temporal_policy": "METADATA_ATOMIC_TEMPORAL_POLICY_INVALID",
    "fact_key": "METADATA_ATOMIC_FACT_KEY_INVALID",
    "valid_from": "METADATA_ATOMIC_VALID_FROM_INVALID",
    "verified_at": "METADATA_ATOMIC_VERIFIED_AT_INVALID",
    "valid_until": "METADATA_ATOMIC_VALID_UNTIL_INVALID",
    "evidence_provenance": "METADATA_CURRENT_CONTENT_EVIDENCE_RECEIPT_MISSING",
}
METADATA_GATE_REASON_NONE = ""
NON_REAL_SOURCE_MARKERS = frozenset({"benchmark", "canary", "synthetic", "test"})
MIN_PINNED_REQUIRED_CASES = 5
PRIVATE_FILE_MODE = 0o600
SHADOW_EPOCH_REASON = "METADATA_GATE_REMEDIATED"
SHADOW_EPOCH_BENCHMARK_FIELDS = (
    "dataset_sha256",
    "required_case_set_sha256",
    "case_count",
    "required_case_count",
    "mandatory_auto_archive_case_count",
)
SHADOW_RUNTIME_BINDING_FIELDS = (
    "manifest_sha256",
    "runtime_installed_at",
    "install_id_sha256",
)
SHADOW_EPOCH_WATERMARK_FIELDS = (
    "search_log_high_watermark",
    "event_log_high_watermark",
)
SHADOW_START_ATTESTATION_KEYS = frozenset({
    "schema_version",
    "kind",
    "shadow_started_at",
    "minimum_days",
    "production_config_sha256",
    *SHADOW_EPOCH_BENCHMARK_FIELDS,
    *SHADOW_RUNTIME_BINDING_FIELDS,
})
SHADOW_EPOCH_ATTESTATION_KEYS = frozenset({
    "schema_version",
    "kind",
    "created_at",
    "epoch_started_at",
    "epoch_number",
    "reason_code",
    "root_start_attestation_sha256",
    "parent_epoch_attestation_sha256",
    "production_config_sha256",
    *SHADOW_EPOCH_BENCHMARK_FIELDS,
    *SHADOW_EPOCH_WATERMARK_FIELDS,
    *SHADOW_RUNTIME_BINDING_FIELDS,
})
SHADOW_EVIDENCE_EPOCH_KEYS = frozenset({
    "epoch_attestation_sha256",
    "epoch_number",
})
SHADOW_BENCHMARK_ATTESTATION_KEYS = frozenset({
    "schema_version",
    "kind",
    "created_at",
    "shadow_started_at",
    "start_attestation_sha256",
    "dataset_sha256",
    "required_case_set_sha256",
    "full_required_case_set",
    "mandatory_auto_archive_case_count",
    "production_config_sha256",
    "runs",
    "case_count",
    "required_case_count",
    "metrics",
    "hybrid_cold_ms",
    "hybrid_warm_p95_ms",
    "degraded_count",
    "worker_cold_status",
    "worker_warm_sample_count",
    "worker_warm_reused_count",
    *SHADOW_RUNTIME_BINDING_FIELDS,
})
SHADOW_CANARY_ATTESTATION_KEYS = frozenset({
    "schema_version",
    "kind",
    "created_at",
    "shadow_started_at",
    "start_attestation_sha256",
    "identified_before_live_verification",
    "remaining_after_live_verification",
    "task_ref_sha256",
    "memory_version_fingerprint",
    *SHADOW_RUNTIME_BINDING_FIELDS,
})
SHADOW_BENCHMARK_BACKENDS = frozenset({
    "sqlite",
    "vector",
    "hybrid",
    "canonical_retrieve",
})
SHADOW_BENCHMARK_METRIC_KEYS = frozenset({"hit_at_5", "mrr"})
SHADOW_EVIDENCE_REASON_PREFIX = {
    "benchmark-success": "SHADOW_BENCHMARK",
    "stale-canary": "SHADOW_STALE_CANARY",
}


class ShadowGateError(RuntimeError):
    """A stable, content-free shadow/cutover gate failure."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def parse_timestamp(value: object) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def production_config_sha256() -> str:
    """Hash the exact production config without exposing its path or contents."""

    target = config_path()
    try:
        target.resolve().relative_to(CONFIG_ROOT.resolve())
        raw = _regular_bytes(target, max_bytes=2 * 1024 * 1024)
    except (OSError, ValueError, ShadowGateError) as exc:
        raise ShadowGateError("SHADOW_PRODUCTION_CONFIG_UNSAFE") from exc
    return sha256_bytes(raw)


def _metadata_value(metadata: object, name: str, default: object = "") -> object:
    if isinstance(metadata, dict):
        return metadata.get(name, default)
    return getattr(metadata, name, default)


def _metadata_list(metadata: object, name: str) -> tuple[str, ...]:
    value = _metadata_value(metadata, name, ())
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return ()


def risk_metadata_gate_reasons(
    metadata: object,
    *,
    frontmatter: dict[str, object] | None = None,
) -> tuple[str, ...]:
    """Evaluate the explicit read-time risk declaration used by v4 writes.

    The gate mirrors the parts of the Write Gateway temporal gate that can be
    proven from current Markdown/index metadata.  ``knowledge_kind`` is a
    request-bound write signal and is intentionally not guessed during reads.
    Canonical path classifiers may pass their fail-closed INVALID/DOWNGRADE
    reasons through ``path_policy_reason_codes``; those are normalized into
    the public metadata reason-code namespace here.
    """

    memory_type = str(_metadata_value(metadata, "memory_type", "") or "").strip().casefold()
    track = str(_metadata_value(metadata, "track", "") or "").strip().casefold()
    if memory_type in NON_GOVERNED_MEMORY_TYPES and track not in RISK_REQUIRED_TRACKS:
        return ()

    if frontmatter is not None:
        risk_class = str(frontmatter.get("risk_class") or "").strip().casefold()
        risk_source = "frontmatter" if "risk_class" in frontmatter else ""
        fact_key = str(frontmatter.get("fact_key") or "").strip()
        valid_until = str(frontmatter.get("valid_until") or "").strip()
        supersedes = frontmatter.get("supersedes")
    else:
        risk_class = str(_metadata_value(metadata, "risk_class", "") or "").strip().casefold()
        risk_source = str(_metadata_value(metadata, "risk_class_source", "") or "").strip().casefold()
        fact_key = str(_metadata_value(metadata, "fact_key", "") or "").strip()
        valid_until = str(_metadata_value(metadata, "valid_until", "") or "").strip()
        supersedes = _metadata_value(metadata, "supersedes", ())

    reasons: list[str] = []
    path_reasons = set(_metadata_list(metadata, "path_policy_reason_codes"))
    for path_reason, metadata_reason in RISK_PATH_REASON_MAP.items():
        if path_reason in path_reasons:
            reasons.append(metadata_reason)

    explicit = risk_source == "frontmatter" and bool(risk_class)
    if track in RISK_REQUIRED_TRACKS and not explicit:
        reasons.append("METADATA_RISK_CLASS_NOT_EXPLICIT")
    if risk_class and risk_class not in RISK_CLASSES:
        reasons.append("METADATA_RISK_CLASS_INVALID")

    normalized_policy = str(
        (
            frontmatter.get("temporal_policy")
            if frontmatter is not None
            else _metadata_value(metadata, "temporal_policy", "")
        )
        or ""
    ).strip().casefold()
    rel_path = str(
        _metadata_value(
            metadata,
            "rel_path",
            _metadata_value(metadata, "relative_path", ""),
        )
        or ""
    ).replace("\\", "/")
    supersedes_declared = bool(
        supersedes
        if not isinstance(supersedes, str)
        else supersedes.strip()
    )
    action_sensitive = bool(
        track in RISK_REQUIRED_TRACKS
        and (
            track == "decision"
            or memory_type in ACTION_SENSITIVE_MEMORY_TYPES
            or normalized_policy == "expiring"
            or valid_until
            or fact_key
            or supersedes_declared
            or "事实-" in Path(rel_path).stem
        )
    )
    if action_sensitive and risk_class == "ordinary":
        reasons.append("METADATA_RISK_CLASS_DOWNGRADE")
    return tuple(dict.fromkeys(reasons))


def temporal_metadata_gate_reasons(metadata: object) -> tuple[str, ...]:
    """Return content-free v4 reasons for an otherwise-authorizable row.

    Canonical Retrieve can pass its live metadata mapping (including ``meta``),
    while Search can pass a SearchResult populated from the derived index. The
    caller deliberately decides whether the row was otherwise authorizable;
    this helper only evaluates explicit v4 identity and temporal metadata.
    """

    status = str(_metadata_value(metadata, "status", "active") or "active").strip().casefold()
    if status != "active":
        return ()
    raw_meta = _metadata_value(metadata, "meta", None)
    frontmatter = raw_meta if isinstance(raw_meta, dict) else None

    memory_id = str(
        (frontmatter.get("memory_id") if frontmatter is not None else _metadata_value(metadata, "memory_id", ""))
        or ""
    ).strip().casefold()
    memory_id_source = str(_metadata_value(metadata, "memory_id_source", "") or "").strip().casefold()
    if SHA256_RE.fullmatch(memory_id) is None or (
        frontmatter is None and memory_id_source != "frontmatter"
    ):
        reasons = ["METADATA_MEMORY_ID_NOT_EXPLICIT"]
    else:
        reasons = []

    policy = str(
        (frontmatter.get("temporal_policy") if frontmatter is not None else _metadata_value(metadata, "temporal_policy", ""))
        or ""
    ).strip().casefold()
    policy_source = str(_metadata_value(metadata, "temporal_policy_source", "") or "").strip().casefold()
    if policy not in TEMPORAL_POLICIES or (
        frontmatter is None and policy_source != "frontmatter"
    ):
        reasons.append("METADATA_TEMPORAL_POLICY_NOT_EXPLICIT")

    memory_type = str(_metadata_value(metadata, "memory_type", "") or "").strip().casefold()
    if memory_type not in {"routing", "directory_index", "template", "governance"}:
        review_raw = (
            frontmatter.get("review_after_days")
            if frontmatter is not None
            else _metadata_value(metadata, "review_after_days", "")
        )
        review_source = str(_metadata_value(metadata, "review_after_source", "") or "").strip().casefold()
        review_text = str(review_raw or "").strip()
        if (
            re.fullmatch(r"[1-9][0-9]{0,3}", review_text) is None
            or int(review_text) > 3650
            or (frontmatter is None and review_source != "frontmatter")
        ):
            reasons.append("METADATA_REVIEW_POLICY_NOT_EXPLICIT")
    reasons.extend(risk_metadata_gate_reasons(metadata, frontmatter=frontmatter))
    return tuple(dict.fromkeys(reasons))


def _canonical_action_sensitive(metadata: object) -> bool:
    """Classify an active canonical row without inspecting its body text."""

    status = str(_metadata_value(metadata, "status", "active") or "active").strip().casefold()
    if status != "active":
        return False
    raw_meta = _metadata_value(metadata, "meta", None)
    frontmatter = raw_meta if isinstance(raw_meta, dict) else None

    def value(name: str, default: object = "") -> object:
        if frontmatter is not None:
            return frontmatter.get(name, default)
        return _metadata_value(metadata, name, default)

    risk_class = str(value("risk_class") or "").strip().casefold()
    memory_type = str(_metadata_value(metadata, "memory_type", "") or "").strip().casefold()
    track = str(_metadata_value(metadata, "track", "") or "").strip().casefold()
    temporal_policy = str(value("temporal_policy") or "").strip().casefold()
    valid_from = str(value("valid_from") or "").strip()
    valid_until = str(value("valid_until") or "").strip()
    fact_key = str(value("fact_key") or "").strip()
    supersedes = value("supersedes", ())
    supersedes_declared = bool(
        supersedes if not isinstance(supersedes, str) else supersedes.strip()
    )
    rel_path = str(
        _metadata_value(
            metadata,
            "rel_path",
            _metadata_value(metadata, "relative_path", ""),
        )
        or ""
    ).replace("\\", "/")
    return bool(
        risk_class == "action_sensitive"
        or track == "decision"
        or memory_type in ACTION_SENSITIVE_MEMORY_TYPES
        or temporal_policy == "expiring"
        or valid_from
        or valid_until
        or fact_key
        or supersedes_declared
        or "事实-" in Path(rel_path).stem
    )


def _durable_current_fact_evidence(
    *,
    rel_path: str,
    raw_sha256: str,
    state_conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Reuse Doctor's exact, read-only Write Gateway v2 receipt proof.

    Only the canonical path and SHA-256 of the bytes already read by Retrieve
    enter the state query. Query text and Markdown content never enter this
    helper or the control database.
    """

    unavailable = {
        "present": False,
        "source": "write_gateway_v2_receipt",
        "reason_code": "CURRENT_CONTENT_EVIDENCE_RECEIPT_MISSING",
        "current_content_bound": False,
        "checked_receipts": 0,
    }
    if not rel_path or SHA256_RE.fullmatch(str(raw_sha256).strip().casefold()) is None:
        return unavailable
    try:
        # Imported lazily so ordinary Search and non-sensitive Retrieve do not
        # pay Doctor's import cost. Doctor does not import this module.
        import agent_memory_doctor as memory_doctor
    except (ImportError, OSError):
        return unavailable

    if state_conn is not None:
        try:
            return memory_doctor._durable_fact_evidence_provenance(
                state_conn,
                rel_path=rel_path,
                raw_sha256=str(raw_sha256).strip().casefold(),
            )
        except (KeyError, OSError, sqlite3.Error, TypeError, ValueError):
            return unavailable

    try:
        conn = secure_sqlite_connect(
            STATE_DB,
            timeout=0.2,
            create=False,
            read_only=True,
            row_factory=sqlite3.Row,
            pragmas=("PRAGMA busy_timeout=200",),
        )
    except (OSError, StateSecurityError, sqlite3.Error):
        return unavailable
    try:
        return memory_doctor._durable_fact_evidence_provenance(
            conn,
            rel_path=rel_path,
            raw_sha256=str(raw_sha256).strip().casefold(),
        )
    except (KeyError, OSError, sqlite3.Error, TypeError, ValueError):
        return unavailable
    finally:
        conn.close()


def canonical_action_sensitive_gate_reasons(
    metadata: object,
    *,
    rel_path: str,
    raw_sha256: str,
    state_conn: sqlite3.Connection | None = None,
    current_date: dt.date | None = None,
) -> tuple[str, ...]:
    """Return atomic-fact and exact-receipt gaps for Canonical Retrieve.

    This is deliberately separate from ``temporal_metadata_gate_reasons``:
    Search sees a derived candidate row and cannot prove the current bytes or
    their receipt. Canonical Retrieve calls this only after reopening the
    current Markdown. Pending/inactive rows are excluded here as well as by the
    caller, preserving their existing reference-only semantics.
    """

    if not _canonical_action_sensitive(metadata):
        return ()
    raw_meta = _metadata_value(metadata, "meta", None)
    frontmatter = raw_meta if isinstance(raw_meta, dict) else None

    def value(name: str, default: object = "") -> object:
        if frontmatter is not None:
            return frontmatter.get(name, default)
        return _metadata_value(metadata, name, default)

    provenance = _durable_current_fact_evidence(
        rel_path=rel_path,
        raw_sha256=raw_sha256,
        state_conn=state_conn,
    )
    try:
        import agent_memory_doctor as memory_doctor

        gaps = memory_doctor._action_sensitive_atomic_gap_fields(
            temporal_policy=value("temporal_policy"),
            fact_key=value("fact_key"),
            valid_from=value("valid_from"),
            valid_until=value("valid_until"),
            verified_at=value("verified_at"),
            verified_at_source=(
                "frontmatter"
                if frontmatter is not None and "verified_at" in frontmatter
                else str(_metadata_value(metadata, "verified_at_source", "") or "")
            ),
            evidence_present=bool(provenance.get("present", False)),
            current_date=current_date,
        )
    except (ImportError, KeyError, OSError, TypeError, ValueError):
        # Fail closed with the complete, content-free tuple contract if the
        # shared validator is unavailable.
        gaps = list(ATOMIC_FACT_GAP_REASON_MAP)
    return tuple(
        ATOMIC_FACT_GAP_REASON_MAP[gap]
        for gap in dict.fromkeys(gaps)
        if gap in ATOMIC_FACT_GAP_REASON_MAP
    )


def metadata_gate_projection(
    reason_sets: list[tuple[str, ...]] | tuple[tuple[str, ...], ...],
    *,
    config: dict[str, Any] | None = None,
    cutover_verified: bool | None = None,
) -> dict[str, Any]:
    """Build the privacy-safe shadow/enforce projection for one result set.

    ``reason_sets`` must contain one entry per result that was authorizable
    before the new v4 metadata gate. Shadow mode records the projection but
    never changes that legacy decision. Enforce mode is effective only when
    the atomic cutover evidence still verifies.
    """

    payload = config if config is not None else load_config()
    observability = payload.get("observability") if isinstance(payload, dict) else None
    configured = str(
        observability.get("metadata_enforcement", "shadow")
        if isinstance(observability, dict)
        else "shadow"
    ).strip().casefold()
    if configured not in {"shadow", "enforce"}:
        raise ShadowGateError("METADATA_ENFORCEMENT_CONFIG_INVALID")
    verified = cutover_active() if cutover_verified is None and configured == "enforce" else bool(cutover_verified)
    effective = "enforce" if configured == "enforce" and verified else "shadow"
    normalized: list[tuple[str, ...]] = []
    for reasons in reason_sets:
        row_reasons = tuple(dict.fromkeys(str(item).strip() for item in reasons if str(item).strip()))
        if any(item not in METADATA_GATE_REASON_CODES for item in row_reasons):
            raise ShadowGateError("METADATA_GATE_REASON_INVALID")
        normalized.append(row_reasons)
    blocked = [reasons for reasons in normalized if reasons]
    counts = {
        reason: sum(1 for reasons in blocked if reason in reasons)
        for reason in sorted(METADATA_GATE_REASON_CODES)
    }
    counts = {key: value for key, value in counts.items() if value}
    fingerprint = (
        hashlib.sha256(
            json.dumps(counts, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        if counts
        else ""
    )
    return {
        "configured_mode": configured,
        "effective_mode": effective,
        "would_block_count": len(blocked),
        "reason_codes": sorted(counts),
        "reason_fingerprint": fingerprint,
        "enforced": effective == "enforce",
    }


def _regular_bytes(path: Path, *, max_bytes: int = MAX_ATTESTATION_BYTES) -> bytes:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ShadowGateError("SHADOW_EVIDENCE_UNSAFE")
    if metadata.st_size > max_bytes:
        raise ShadowGateError("SHADOW_EVIDENCE_TOO_LARGE")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb", closefd=True) as handle:
        return handle.read(max_bytes + 1)


def _json_file(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = _regular_bytes(path)
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ShadowGateError) as exc:
        raise ShadowGateError("SHADOW_EVIDENCE_INVALID") from exc
    if not isinstance(payload, dict):
        raise ShadowGateError("SHADOW_EVIDENCE_INVALID")
    return payload, raw


def runtime_binding() -> dict[str, str]:
    try:
        payload, raw = _json_file(MANIFEST_PATH)
        installed_at = parse_timestamp(payload.get("installed_at")).isoformat()
    except (OSError, ValueError, ShadowGateError) as exc:
        raise ShadowGateError("SHADOW_RUNTIME_MANIFEST_INVALID") from exc
    return {
        "manifest_sha256": sha256_bytes(raw),
        "runtime_installed_at": installed_at,
        "install_id_sha256": hashlib.sha256(
            str(payload.get("install_id", "")).encode("utf-8")
        ).hexdigest(),
    }


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ShadowGateError("SHADOW_DIRECTORY_UNSAFE")
    if os.name == "posix":
        os.chmod(path, 0o700)


def _assert_private_shadow_root() -> None:
    try:
        relative = SHADOW_ROOT.relative_to(CONFIG_ROOT)
        if not relative.parts:
            raise ValueError("root itself is not a shadow directory")
        assert_no_symlink_beneath(
            CONFIG_ROOT,
            SHADOW_ROOT,
            include_leaf=False,
            allow_missing=True,
        )
    except (OSError, StateSecurityError, ValueError) as exc:
        raise ShadowGateError("SHADOW_DIRECTORY_OUTSIDE_PRIVATE_RUNTIME") from exc


def _exclusive_json(kind: str, payload: dict[str, Any]) -> tuple[Path, str]:
    _assert_private_shadow_root()
    _ensure_private_directory(SHADOW_ROOT)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = SHADOW_ROOT / f"{kind}-{timestamp}-{uuid.uuid4().hex}.json"
    raw = (
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        if os.name == "posix":
            os.fchmod(handle.fileno(), 0o600)
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return path, sha256_bytes(raw)


@contextlib.contextmanager
def _shadow_start_transaction_lock():
    """Serialize the check-and-create portion of shadow start.

    The private lock file is intentionally persistent. Reusing one inode
    prevents a second lock domain from appearing through unlink/recreate races.
    Contention fails immediately instead of silently waiting.
    """

    _assert_private_shadow_root()
    _ensure_private_directory(SHADOW_ROOT)
    path = SHADOW_ROOT / ".shadow-start.lock"
    descriptor: int | None = None
    try:
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            current_uid = os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != current_uid
                or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE)
            ):
                raise ShadowGateError("SHADOW_START_LOCK_UNSAFE")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
        opened = os.fstat(descriptor)
        current_uid = os.geteuid() if hasattr(os, "geteuid") else opened.st_uid
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != current_uid
            or (os.name == "posix" and stat.S_IMODE(opened.st_mode) != PRIVATE_FILE_MODE)
        ):
            raise ShadowGateError("SHADOW_START_LOCK_UNSAFE")
        if opened.st_size == 0:
            os.write(descriptor, b"0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif msvcrt is not None:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:  # pragma: no cover - all supported platforms provide one.
            raise ShadowGateError("SHADOW_START_LOCK_UNAVAILABLE")
    except ShadowGateError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except (OSError, PermissionError) as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise ShadowGateError("SHADOW_START_ALREADY_IN_PROGRESS") from exc
    try:
        yield
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            elif msvcrt is not None:
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(descriptor)


@contextlib.contextmanager
def _shadow_activity_lock(*, exclusive: bool):
    """Coordinate epoch mutations with supported Runtime task activity.

    Managed ``memoryctl`` invocations hold a shared lock for the lifetime of
    their child command. Epoch boundaries and cutover hold the exclusive form,
    which drains in-flight observability writers and prevents a new writer
    from entering between gate evaluation and config CAS.
    """

    _assert_private_shadow_root()
    _ensure_private_directory(SHADOW_ROOT)
    path = SHADOW_ROOT / ".shadow-activity.lock"
    descriptor: int | None = None
    acquired = False
    try:
        timeout_seconds = min(
            30.0,
            max(
                0.0,
                float(
                    env_value("SHADOW_ACTIVITY_LOCK_TIMEOUT_SECONDS", "15")
                    or 15
                ),
            ),
        )
    except ValueError as exc:
        raise ShadowGateError("SHADOW_ACTIVITY_LOCK_UNAVAILABLE") from exc
    deadline = time.monotonic() + timeout_seconds
    try:
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            current_uid = os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != current_uid
                or (
                    os.name == "posix"
                    and stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE
                )
            ):
                raise ShadowGateError("SHADOW_ACTIVITY_LOCK_UNSAFE")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
        opened = os.fstat(descriptor)
        current_uid = os.geteuid() if hasattr(os, "geteuid") else opened.st_uid
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != current_uid
            or (
                os.name == "posix"
                and stat.S_IMODE(opened.st_mode) != PRIVATE_FILE_MODE
            )
        ):
            raise ShadowGateError("SHADOW_ACTIVITY_LOCK_UNSAFE")
        if opened.st_size == 0:
            os.write(descriptor, b"0")
            os.fsync(descriptor)
        while not acquired:
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                if fcntl is not None:
                    mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                    fcntl.flock(descriptor, mode | fcntl.LOCK_NB)
                elif msvcrt is not None:
                    mode = (
                        msvcrt.LK_NBLCK
                        if exclusive
                        else getattr(msvcrt, "LK_NBRLCK", msvcrt.LK_NBLCK)
                    )
                    msvcrt.locking(descriptor, mode, 1)
                else:  # pragma: no cover - supported platforms provide one.
                    raise ShadowGateError("SHADOW_ACTIVITY_LOCK_UNAVAILABLE")
                acquired = True
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise
                if time.monotonic() >= deadline:
                    raise ShadowGateError("SHADOW_ACTIVITY_LOCK_BUSY") from exc
                time.sleep(0.01)
    except ShadowGateError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except (OSError, PermissionError, ValueError) as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise ShadowGateError("SHADOW_ACTIVITY_LOCK_UNAVAILABLE") from exc
    try:
        yield
    finally:
        try:
            if acquired and fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            elif acquired and msvcrt is not None:
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(descriptor)


def _attestation_reason(kind: str, suffix: str) -> str:
    prefix = SHADOW_EVIDENCE_REASON_PREFIX.get(kind)
    if prefix is None:
        raise ShadowGateError("SHADOW_ATTESTATION_KIND_UNSUPPORTED")
    return f"{prefix}_{suffix}"


def _strict_private_attestation(
    path: Path,
    *,
    kind: str,
) -> tuple[dict[str, Any], bytes]:
    """Read one evidence file without following or trusting its pathname."""

    unsafe_reason = _attestation_reason(kind, "ATTESTATION_UNSAFE")
    malformed_reason = _attestation_reason(kind, "ATTESTATION_MALFORMED")
    descriptor: int | None = None
    try:
        metadata = path.lstat()
        current_uid = os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != current_uid
            or (
                os.name == "posix"
                and stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE
            )
        ):
            raise ShadowGateError(unsafe_reason)
        if metadata.st_size > MAX_ATTESTATION_BYTES:
            raise ShadowGateError(malformed_reason)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != current_uid
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or (
                os.name == "posix"
                and stat.S_IMODE(opened.st_mode) != PRIVATE_FILE_MODE
            )
            or opened.st_size > MAX_ATTESTATION_BYTES
        ):
            raise ShadowGateError(unsafe_reason)
        chunks: list[bytes] = []
        remaining = MAX_ATTESTATION_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_ATTESTATION_BYTES or len(raw) != opened.st_size:
            raise ShadowGateError(malformed_reason)
    except ShadowGateError:
        raise
    except OSError as exc:
        raise ShadowGateError(unsafe_reason) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for key, value in pairs:
            if key in payload:
                raise ValueError("duplicate JSON member")
            payload[key] = value
        return payload

    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ShadowGateError(malformed_reason) from exc
    if not isinstance(payload, dict):
        raise ShadowGateError(malformed_reason)
    return payload, raw


def _strict_evidence_timestamp(
    value: object,
    *,
    kind: str,
) -> dt.datetime:
    malformed_reason = _attestation_reason(kind, "ATTESTATION_MALFORMED")
    if type(value) is not str:
        raise ShadowGateError(malformed_reason)
    try:
        parsed = parse_timestamp(value)
    except (TypeError, ValueError) as exc:
        raise ShadowGateError(malformed_reason) from exc
    if parsed.isoformat() != value:
        raise ShadowGateError(malformed_reason)
    return parsed


def _validate_attestation_shape(
    kind: str,
    payload: dict[str, Any],
    *,
    now: dt.datetime,
) -> tuple[dt.datetime, dt.datetime, bool]:
    malformed_reason = _attestation_reason(kind, "ATTESTATION_MALFORMED")
    base_keys = (
        SHADOW_BENCHMARK_ATTESTATION_KEYS
        if kind == "benchmark-success"
        else SHADOW_CANARY_ATTESTATION_KEYS
    )
    present_epoch_keys = set(payload).intersection(SHADOW_EVIDENCE_EPOCH_KEYS)
    if present_epoch_keys not in (set(), set(SHADOW_EVIDENCE_EPOCH_KEYS)):
        raise ShadowGateError(malformed_reason)
    expected_keys = base_keys | (
        SHADOW_EVIDENCE_EPOCH_KEYS if present_epoch_keys else frozenset()
    )
    if (
        set(payload) != expected_keys
        or type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 1
        or payload.get("kind") != kind
    ):
        raise ShadowGateError(malformed_reason)
    created_at = _strict_evidence_timestamp(payload.get("created_at"), kind=kind)
    shadow_started_at = _strict_evidence_timestamp(
        payload.get("shadow_started_at"),
        kind=kind,
    )
    _strict_evidence_timestamp(payload.get("runtime_installed_at"), kind=kind)
    if created_at < shadow_started_at or created_at > now:
        raise ShadowGateError(malformed_reason)

    common_hash_fields = (
        "start_attestation_sha256",
        "manifest_sha256",
        "install_id_sha256",
    )
    if any(
        type(payload.get(key)) is not str
        or SHA256_RE.fullmatch(payload[key]) is None
        for key in common_hash_fields
    ):
        raise ShadowGateError(malformed_reason)
    has_epoch = bool(present_epoch_keys)
    if has_epoch and (
        type(payload.get("epoch_number")) is not int
        or int(payload.get("epoch_number") or 0) < 1
        or type(payload.get("epoch_attestation_sha256")) is not str
        or SHA256_RE.fullmatch(payload["epoch_attestation_sha256"]) is None
    ):
        raise ShadowGateError(malformed_reason)

    if kind == "benchmark-success":
        integer_fields = (
            "runs",
            "case_count",
            "required_case_count",
            "mandatory_auto_archive_case_count",
            "degraded_count",
            "worker_warm_sample_count",
            "worker_warm_reused_count",
        )
        hash_fields = (
            "dataset_sha256",
            "required_case_set_sha256",
            "production_config_sha256",
        )
        metrics = payload.get("metrics")
        if (
            any(type(payload.get(key)) is not int for key in integer_fields)
            or any(
                type(payload.get(key)) is not str
                or SHA256_RE.fullmatch(payload[key]) is None
                for key in hash_fields
            )
            or payload.get("runs") != 3
            or int(payload.get("case_count") or 0)
            < int(payload.get("required_case_count") or 0)
            or int(payload.get("required_case_count") or 0)
            < MIN_PINNED_REQUIRED_CASES
            or int(payload.get("mandatory_auto_archive_case_count") or 0) < 1
            or payload.get("full_required_case_set") is not True
            or payload.get("degraded_count") != 0
            or payload.get("worker_cold_status") != "started"
            or int(payload.get("worker_warm_sample_count") or 0) < 1
            or payload.get("worker_warm_reused_count")
            != payload.get("worker_warm_sample_count")
            or not isinstance(metrics, dict)
            or set(metrics) != SHADOW_BENCHMARK_BACKENDS
        ):
            raise ShadowGateError(malformed_reason)
        for backend in SHADOW_BENCHMARK_BACKENDS:
            row = metrics.get(backend)
            if not isinstance(row, dict) or set(row) != SHADOW_BENCHMARK_METRIC_KEYS:
                raise ShadowGateError(malformed_reason)
            hit_at_5 = row.get("hit_at_5")
            mrr = row.get("mrr")
            if (
                type(hit_at_5) not in {int, float}
                or type(mrr) not in {int, float}
                or not math.isfinite(float(hit_at_5))
                or not math.isfinite(float(mrr))
                or float(hit_at_5) != 1.0
                or not 0.90 <= float(mrr) <= 1.0
            ):
                raise ShadowGateError(malformed_reason)
        cold = payload.get("hybrid_cold_ms")
        warm = payload.get("hybrid_warm_p95_ms")
        if (
            type(cold) not in {int, float}
            or type(warm) not in {int, float}
            or not math.isfinite(float(cold))
            or not math.isfinite(float(warm))
            or not 0 < float(cold) <= 8000
            or not 0 < float(warm) <= 1000
        ):
            raise ShadowGateError(malformed_reason)
    else:
        integer_fields = (
            "identified_before_live_verification",
            "remaining_after_live_verification",
        )
        hash_fields = ("task_ref_sha256", "memory_version_fingerprint")
        if (
            any(type(payload.get(key)) is not int for key in integer_fields)
            or payload.get("identified_before_live_verification") != 1
            or payload.get("remaining_after_live_verification") != 0
            or any(
                type(payload.get(key)) is not str
                or SHA256_RE.fullmatch(payload[key]) is None
                for key in hash_fields
            )
        ):
            raise ShadowGateError(malformed_reason)
    return created_at, shadow_started_at, has_epoch


def _attestation_contexts(
    *,
    now: dt.datetime,
) -> dict[str, dict[str, Any]]:
    contexts: dict[str, dict[str, Any]] = {}
    for _path, start_payload, start_digest in _shadow_start_rows():
        root_binding = {
            key: str(start_payload[key]) for key in SHADOW_RUNTIME_BINDING_FIELDS
        }
        state = _shadow_epoch_state(
            binding=root_binding,
            start_payload=start_payload,
            start_attestation_sha256=start_digest,
            now=now,
        )
        epochs = {
            start_digest: {
                "number": 0,
                "started_at": str(start_payload["shadow_started_at"]),
            }
        }
        for digest, epoch_payload in state["active_epoch_payloads"].items():
            epochs[digest] = {
                "number": int(epoch_payload["epoch_number"]),
                "started_at": str(epoch_payload["epoch_started_at"]),
            }
        contexts[start_digest] = {
            "root": start_payload,
            "binding": root_binding,
            "epochs": epochs,
        }
    return contexts


def _attestations(kind: str, binding: dict[str, str]) -> list[tuple[Path, dict[str, Any], str]]:
    """Validate every same-prefix evidence file before selecting this Runtime."""

    binding_reason = _attestation_reason(kind, "ATTESTATION_BINDING_INVALID")
    duplicate_reason = _attestation_reason(kind, "DUPLICATE_ATTESTATION")
    _assert_private_shadow_root()
    if not SHADOW_ROOT.is_dir() or SHADOW_ROOT.is_symlink():
        return []
    paths = sorted(SHADOW_ROOT.glob(f"{kind}-*.json"))
    if not paths:
        return []
    if (
        set(binding) != set(SHADOW_RUNTIME_BINDING_FIELDS)
        or type(binding.get("manifest_sha256")) is not str
        or SHA256_RE.fullmatch(binding["manifest_sha256"]) is None
        or type(binding.get("install_id_sha256")) is not str
        or SHA256_RE.fullmatch(binding["install_id_sha256"]) is None
    ):
        raise ShadowGateError(binding_reason)
    try:
        _strict_evidence_timestamp(binding.get("runtime_installed_at"), kind=kind)
    except ShadowGateError as exc:
        raise ShadowGateError(binding_reason) from exc
    current = _normalized_utc()
    contexts = _attestation_contexts(now=current)
    output: list[tuple[Path, dict[str, Any], str]] = []
    seen_digests: set[str] = set()
    for path in paths:
        payload, raw = _strict_private_attestation(path, kind=kind)
        created_at, shadow_started_at, has_epoch = _validate_attestation_shape(
            kind,
            payload,
            now=current,
        )
        digest = sha256_bytes(raw)
        if digest in seen_digests:
            raise ShadowGateError(duplicate_reason)
        seen_digests.add(digest)

        start_digest = str(payload["start_attestation_sha256"])
        context = contexts.get(start_digest)
        if context is None:
            raise ShadowGateError(binding_reason)
        root = context["root"]
        root_binding = context["binding"]
        if any(
            payload.get(key) != root_binding.get(key)
            for key in SHADOW_RUNTIME_BINDING_FIELDS
        ):
            raise ShadowGateError(binding_reason)
        epoch_digest = (
            str(payload["epoch_attestation_sha256"])
            if has_epoch
            else start_digest
        )
        epoch = context["epochs"].get(epoch_digest)
        if (
            epoch is None
            or (has_epoch and payload.get("epoch_number") != epoch["number"])
            or (not has_epoch and epoch["number"] != 0)
            or payload.get("shadow_started_at") != epoch["started_at"]
            or shadow_started_at != parse_timestamp(epoch["started_at"])
            or created_at < shadow_started_at
        ):
            raise ShadowGateError(binding_reason)
        if kind == "benchmark-success" and (
            payload.get("production_config_sha256")
            != root.get("production_config_sha256")
            or any(
                payload.get(key) != root.get(key)
                for key in SHADOW_EPOCH_BENCHMARK_FIELDS
            )
        ):
            raise ShadowGateError(binding_reason)
        if all(root_binding.get(key) == binding.get(key) for key in binding):
            output.append((path, payload, digest))
    return output


def _shadow_start_rows() -> list[tuple[Path, dict[str, Any], str]]:
    """Read every immutable root attestation with strict private-file checks."""

    _assert_private_shadow_root()
    if not SHADOW_ROOT.is_dir() or SHADOW_ROOT.is_symlink():
        return []
    output: list[tuple[Path, dict[str, Any], str]] = []
    seen_digests: set[str] = set()
    for path in sorted(SHADOW_ROOT.glob("shadow-start-*.json")):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ShadowGateError("SHADOW_START_ATTESTATION_MALFORMED") from exc
        current_uid = os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != current_uid
            or (
                os.name == "posix"
                and stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE
            )
        ):
            raise ShadowGateError("SHADOW_START_ATTESTATION_UNSAFE")
        try:
            payload, raw = _json_file(path)
            parse_timestamp(payload.get("shadow_started_at"))
            parse_timestamp(payload.get("runtime_installed_at"))
        except (OSError, TypeError, ValueError, ShadowGateError) as exc:
            raise ShadowGateError("SHADOW_START_ATTESTATION_MALFORMED") from exc
        integer_fields = (
            "schema_version",
            "minimum_days",
            "case_count",
            "required_case_count",
            "mandatory_auto_archive_case_count",
        )
        hash_fields = (
            "production_config_sha256",
            "dataset_sha256",
            "required_case_set_sha256",
            "manifest_sha256",
            "install_id_sha256",
        )
        if (
            set(payload) != SHADOW_START_ATTESTATION_KEYS
            or any(type(payload.get(key)) is not int for key in integer_fields)
            or payload.get("schema_version") != 1
            or payload.get("kind") != "shadow-start"
            or int(payload.get("minimum_days") or 0) < 7
            or int(payload.get("case_count") or 0)
            < int(payload.get("required_case_count") or 0)
            or int(payload.get("required_case_count") or 0) < MIN_PINNED_REQUIRED_CASES
            or int(payload.get("mandatory_auto_archive_case_count") or 0) < 1
            or any(
                SHA256_RE.fullmatch(str(payload.get(key) or "")) is None
                for key in hash_fields
            )
        ):
            raise ShadowGateError("SHADOW_START_ATTESTATION_MALFORMED")
        digest = sha256_bytes(raw)
        if digest in seen_digests:
            raise ShadowGateError("SHADOW_START_ATTESTATION_AMBIGUOUS")
        seen_digests.add(digest)
        output.append((path, payload, digest))
    return output


def current_start(binding: dict[str, str] | None = None) -> tuple[dict[str, Any], str] | None:
    binding = binding or runtime_binding()
    rows = [
        row
        for row in _shadow_start_rows()
        if all(row[1].get(key) == value for key, value in binding.items())
    ]
    if not rows:
        return None
    if len(rows) != 1:
        raise ShadowGateError("SHADOW_START_ATTESTATION_AMBIGUOUS")
    _path, payload, digest = rows[0]
    return payload, digest


def _normalized_utc(now: dt.datetime | None = None) -> dt.datetime:
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=dt.timezone.utc)
    return current.astimezone(dt.timezone.utc)


def _evidence_created_at(epoch_started_at: dt.datetime) -> str:
    """Use epoch-precision time and fail closed if the wall clock regresses."""

    current = _normalized_utc()
    if current < epoch_started_at:
        raise ShadowGateError("SHADOW_EVIDENCE_CLOCK_REGRESSION")
    return current.isoformat()


def _shadow_epoch_state(
    *,
    binding: dict[str, str],
    start_payload: dict[str, Any],
    start_attestation_sha256: str,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Validate the immutable, linear superseding-epoch chain."""

    current = _normalized_utc(now)
    try:
        root_started_at = parse_timestamp(start_payload.get("shadow_started_at"))
    except (TypeError, ValueError) as exc:
        raise ShadowGateError("SHADOW_EPOCH_ROOT_INVALID") from exc
    if root_started_at > current:
        raise ShadowGateError("SHADOW_EPOCH_FUTURE_TIMESTAMP")
    if SHA256_RE.fullmatch(start_attestation_sha256) is None:
        raise ShadowGateError("SHADOW_EPOCH_ROOT_INVALID")
    _assert_private_shadow_root()
    if not SHADOW_ROOT.is_dir() or SHADOW_ROOT.is_symlink():
        paths: list[Path] = []
    else:
        paths = sorted(SHADOW_ROOT.glob("shadow-epoch-*.json"))
    all_rows: list[tuple[Path, dict[str, Any], str]] = []
    seen_digests: set[str] = set()
    for path in paths:
        try:
            metadata = path.lstat()
            owner = os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
            payload, raw = _json_file(path)
        except (OSError, ShadowGateError) as exc:
            raise ShadowGateError("SHADOW_EPOCH_ATTESTATION_MALFORMED") from exc
        integer_fields = (
            "schema_version",
            "epoch_number",
            "case_count",
            "required_case_count",
            "mandatory_auto_archive_case_count",
            *SHADOW_EPOCH_WATERMARK_FIELDS,
        )
        hash_fields = (
            "root_start_attestation_sha256",
            "parent_epoch_attestation_sha256",
            "production_config_sha256",
            "dataset_sha256",
            "required_case_set_sha256",
            "manifest_sha256",
            "install_id_sha256",
        )
        try:
            created_at = parse_timestamp(payload.get("created_at"))
            epoch_started_at = parse_timestamp(payload.get("epoch_started_at"))
            parse_timestamp(payload.get("runtime_installed_at"))
        except (TypeError, ValueError) as exc:
            raise ShadowGateError("SHADOW_EPOCH_ATTESTATION_MALFORMED") from exc
        if (
            set(payload) != SHADOW_EPOCH_ATTESTATION_KEYS
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner
            or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE)
            or any(type(payload.get(key)) is not int for key in integer_fields)
            or payload.get("schema_version") != 1
            or int(payload.get("epoch_number") or 0) < 1
            or int(payload.get("case_count") or 0)
            < int(payload.get("required_case_count") or 0)
            or int(payload.get("required_case_count") or 0) < MIN_PINNED_REQUIRED_CASES
            or int(payload.get("mandatory_auto_archive_case_count") or 0) < 1
            or any(
                int(payload.get(key) or 0) < 0
                for key in SHADOW_EPOCH_WATERMARK_FIELDS
            )
            or payload.get("kind") != "shadow-epoch"
            or payload.get("reason_code") != SHADOW_EPOCH_REASON
            or any(SHA256_RE.fullmatch(str(payload.get(key) or "")) is None for key in hash_fields)
            or created_at != epoch_started_at
        ):
            raise ShadowGateError("SHADOW_EPOCH_ATTESTATION_MALFORMED")
        if created_at > current or epoch_started_at > current:
            raise ShadowGateError("SHADOW_EPOCH_FUTURE_TIMESTAMP")
        digest = sha256_bytes(raw)
        if digest in seen_digests:
            raise ShadowGateError("SHADOW_EPOCH_DUPLICATE_ATTESTATION")
        seen_digests.add(digest)
        all_rows.append((path, payload, digest))

    known_roots = {
        digest: payload for _path, payload, digest in _shadow_start_rows()
    }
    recorded_current_root = known_roots.get(start_attestation_sha256)
    if recorded_current_root is not None and recorded_current_root != start_payload:
        raise ShadowGateError("SHADOW_EPOCH_ROOT_INVALID")
    # Unit-level callers may supply an authenticated current start directly;
    # production callers arrive through current_start(), which read the same
    # immutable file above.
    known_roots[start_attestation_sha256] = start_payload
    root_started_at_by_digest: dict[str, dt.datetime] = {}
    for digest, payload in known_roots.items():
        try:
            started_at = parse_timestamp(payload.get("shadow_started_at"))
        except (TypeError, ValueError) as exc:
            raise ShadowGateError("SHADOW_EPOCH_ROOT_INVALID") from exc
        if started_at > current:
            raise ShadowGateError("SHADOW_EPOCH_FUTURE_TIMESTAMP")
        root_started_at_by_digest[digest] = started_at

    groups: dict[str, dict[str, tuple[dict[str, Any], dt.datetime]]] = {
        digest: {} for digest in known_roots
    }
    epoch_root_by_digest: dict[str, str] = {}
    for _path, payload, digest in all_rows:
        root_digest = str(payload["root_start_attestation_sha256"])
        root_payload = known_roots.get(root_digest)
        if root_payload is None:
            raise ShadowGateError("SHADOW_EPOCH_CROSS_BINDING")
        expected_runtime_binding = {
            key: (
                root_payload.get(key)
                if root_payload.get(key) is not None
                else binding.get(key)
                if root_digest == start_attestation_sha256
                else None
            )
            for key in SHADOW_RUNTIME_BINDING_FIELDS
        }
        if any(
            payload.get(key) != expected_runtime_binding.get(key)
            for key in SHADOW_RUNTIME_BINDING_FIELDS
        ):
            raise ShadowGateError("SHADOW_EPOCH_CROSS_BINDING")
        if payload.get("production_config_sha256") != root_payload.get(
            "production_config_sha256"
        ) or any(
            payload.get(key) != root_payload.get(key)
            for key in SHADOW_EPOCH_BENCHMARK_FIELDS
        ):
            raise ShadowGateError("SHADOW_EPOCH_BINDING_INVALID")
        groups[root_digest][digest] = (
            payload,
            parse_timestamp(payload["epoch_started_at"]),
        )
        epoch_root_by_digest[digest] = root_digest

    known_nodes = set(known_roots) | set(epoch_root_by_digest)

    def validate_group(
        root_digest: str,
        epochs: dict[str, tuple[dict[str, Any], dt.datetime]],
    ) -> dict[str, Any]:
        """Prove one root's complete history even when it is not current."""

        epoch_digests = set(epochs)
        children: dict[str, list[str]] = {}
        for digest, (payload, _started_at) in epochs.items():
            parent = str(payload["parent_epoch_attestation_sha256"])
            if parent != root_digest and parent not in epoch_digests:
                if parent in known_nodes:
                    raise ShadowGateError("SHADOW_EPOCH_CROSS_BINDING")
                raise ShadowGateError("SHADOW_EPOCH_PARENT_INVALID")
            children.setdefault(parent, []).append(digest)
        if any(len(values) != 1 for values in children.values()):
            raise ShadowGateError("SHADOW_EPOCH_FORK_DETECTED")

        verified: dict[str, tuple[int, dt.datetime, int, int]] = {}
        visiting: set[str] = set()

        def verify(digest: str) -> tuple[int, dt.datetime, int, int]:
            if digest in verified:
                return verified[digest]
            if digest in visiting:
                raise ShadowGateError("SHADOW_EPOCH_CYCLE_DETECTED")
            visiting.add(digest)
            payload, started_at = epochs[digest]
            parent = str(payload["parent_epoch_attestation_sha256"])
            if parent == root_digest:
                parent_number = 0
                parent_started_at = root_started_at_by_digest[root_digest]
                parent_search_high_watermark = 0
                parent_event_high_watermark = 0
            else:
                (
                    parent_number,
                    parent_started_at,
                    parent_search_high_watermark,
                    parent_event_high_watermark,
                ) = verify(parent)
            epoch_number = int(payload["epoch_number"])
            search_high_watermark = int(payload["search_log_high_watermark"])
            event_high_watermark = int(payload["event_log_high_watermark"])
            if epoch_number != parent_number + 1 or started_at <= parent_started_at:
                raise ShadowGateError("SHADOW_EPOCH_SEQUENCE_INVALID")
            if (
                epoch_number > 1
                and (
                    search_high_watermark < parent_search_high_watermark
                    or event_high_watermark < parent_event_high_watermark
                )
            ):
                raise ShadowGateError("SHADOW_EPOCH_WATERMARK_REGRESSION")
            visiting.remove(digest)
            verified[digest] = (
                epoch_number,
                started_at,
                search_high_watermark,
                event_high_watermark,
            )
            return verified[digest]

        for digest in epochs:
            verify(digest)
        if not epochs:
            return {
                "children": children,
                "head_digest": root_digest,
                "head_payload": known_roots[root_digest],
                "head_started_at": root_started_at_by_digest[root_digest],
                "head_number": 0,
                "head_search_high_watermark": None,
                "head_event_high_watermark": None,
            }
        parent_digests = {
            str(payload["parent_epoch_attestation_sha256"])
            for payload, _started_at in epochs.values()
        }
        heads = sorted(epoch_digests - parent_digests)
        if len(heads) != 1:
            raise ShadowGateError("SHADOW_EPOCH_HEAD_INVALID")
        head_digest = heads[0]
        head_payload, head_started_at = epochs[head_digest]
        return {
            "children": children,
            "head_digest": head_digest,
            "head_payload": head_payload,
            "head_started_at": head_started_at,
            "head_number": int(head_payload["epoch_number"]),
            "head_search_high_watermark": int(
                head_payload["search_log_high_watermark"]
            ),
            "head_event_high_watermark": int(
                head_payload["event_log_high_watermark"]
            ),
        }

    group_states = {
        digest: validate_group(digest, epochs)
        for digest, epochs in groups.items()
    }
    active = groups[start_attestation_sha256]
    active_digests = set(active)
    active_state = group_states[start_attestation_sha256]
    children = active_state["children"]
    if not active:
        head_digest = start_attestation_sha256
        head_payload = start_payload
        head_number = 0
        head_started_at = root_started_at
        head_search_high_watermark = None
        head_event_high_watermark = None
    else:
        head_digest = str(active_state["head_digest"])
        head_payload = active_state["head_payload"]
        head_started_at = active_state["head_started_at"]
        head_number = int(active_state["head_number"])
        head_search_high_watermark = int(
            active_state["head_search_high_watermark"]
        )
        head_event_high_watermark = int(
            active_state["head_event_high_watermark"]
        )
    return {
        "root_payload": start_payload,
        "root_attestation_sha256": start_attestation_sha256,
        "root_started_at": root_started_at,
        "head_payload": head_payload,
        "head_attestation_sha256": head_digest,
        "head_started_at": head_started_at,
        "head_number": head_number,
        "head_search_log_high_watermark": head_search_high_watermark,
        "head_event_log_high_watermark": head_event_high_watermark,
        "epoch_attestation_count": len(active),
        "children": children,
        "active_digests": active_digests,
        "active_epoch_payloads": {
            digest: payload for digest, (payload, _started_at) in active.items()
        },
    }


def current_shadow_epoch(
    binding: dict[str, str] | None = None,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any] | None:
    binding = binding or runtime_binding()
    start = current_start(binding)
    if start is None:
        return None
    start_payload, start_digest = start
    return _shadow_epoch_state(
        binding=binding,
        start_payload=start_payload,
        start_attestation_sha256=start_digest,
        now=now,
    )


def private_benchmark_binding(benchmark_file: str) -> dict[str, Any]:
    """Validate and fingerprint the exact private quality gate before day one.

    The shadow start record deliberately stores no query, case id, expected
    path, or dataset path.  It does bind the complete private file and required
    subset so a later attestation cannot silently switch to an easier fixture.
    """

    if not str(benchmark_file or "").strip():
        raise ShadowGateError("SHADOW_PRIVATE_BENCHMARK_FILE_REQUIRED")
    benchmark_root = (CONFIG_ROOT / "benchmarks").resolve()
    supplied = Path(os.path.abspath(os.path.expanduser(str(benchmark_file))))
    selected = supplied.resolve()
    try:
        selected.relative_to(benchmark_root)
        # Inspect the lexical path before opening it.  Resolving first would
        # accidentally hide a symlink that still points inside benchmarks.
        assert_no_symlink_beneath(CONFIG_ROOT, supplied, include_leaf=True)
        metadata = supplied.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ShadowGateError("SHADOW_PRIVATE_BENCHMARK_UNSAFE")
        if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ShadowGateError("SHADOW_PRIVATE_BENCHMARK_PERMISSIONS_UNSAFE")
        raw = _regular_bytes(supplied, max_bytes=2 * 1024 * 1024)
    except (OSError, StateSecurityError, ValueError) as exc:
        raise ShadowGateError("SHADOW_PRIVATE_BENCHMARK_UNSAFE") from exc

    import agent_memory_retrieval_benchmark as benchmark

    try:
        dataset, cases = benchmark.load_dataset(str(supplied))
    except (OSError, RuntimeError, ValueError) as exc:
        raise ShadowGateError("SHADOW_PRIVATE_BENCHMARK_INVALID") from exc
    dataset_digest = sha256_bytes(raw)
    if (
        dataset.get("privacy") != "private_local"
        or dataset.get("sha256") != dataset_digest
    ):
        raise ShadowGateError("SHADOW_PRIVATE_BENCHMARK_CHANGED_DURING_READ")
    required = [case for case in cases if int(case.get("required_at") or 0) > 0]
    if (
        len(required) < MIN_PINNED_REQUIRED_CASES
        or any(int(case.get("required_at") or 0) > 5 for case in required)
    ):
        raise ShadowGateError("SHADOW_PRIVATE_BENCHMARK_REQUIRED_SET_TOO_SMALL")
    normalized_required_queries = [
        benchmark.normalized_query(case.get("query")) for case in required
    ]
    if len(set(normalized_required_queries)) != len(normalized_required_queries):
        raise ShadowGateError("SHADOW_PRIVATE_BENCHMARK_REQUIRED_QUERIES_NOT_UNIQUE")
    mandatory_count = sum(
        1 for case in required if benchmark.is_mandatory_auto_archive_case(case)
    )
    if mandatory_count < 1:
        raise ShadowGateError("SHADOW_PRIVATE_BENCHMARK_MANDATORY_CASE_MISSING")
    return {
        "dataset_sha256": dataset_digest,
        "required_case_set_sha256": benchmark.required_case_set_sha256(cases),
        "case_count": len(cases),
        "required_case_count": len(required),
        "mandatory_auto_archive_case_count": mandatory_count,
    }


def start_shadow(
    *,
    actor: str,
    benchmark_file: str,
    min_days: int | None = None,
) -> dict[str, Any]:
    if actor != "migration":
        raise ShadowGateError("SHADOW_MUTATION_REQUIRES_MIGRATION_ACTOR")
    with _shadow_start_transaction_lock(), _shadow_activity_lock(exclusive=True):
        return _start_shadow_locked(benchmark_file=benchmark_file, min_days=min_days)


def _start_shadow_locked(
    *,
    benchmark_file: str,
    min_days: int | None,
) -> dict[str, Any]:
    binding = runtime_binding()
    config_digest = production_config_sha256()
    benchmark_binding = private_benchmark_binding(benchmark_file)
    existing = current_start(binding)
    if existing is not None:
        payload, digest = existing
        if payload.get("production_config_sha256") != config_digest:
            raise ShadowGateError("SHADOW_CONFIG_CHANGED_SINCE_START")
        if any(payload.get(key) != value for key, value in benchmark_binding.items()):
            raise ShadowGateError("SHADOW_BENCHMARK_CHANGED_SINCE_START")
        epoch = _shadow_epoch_state(
            binding=binding,
            start_payload=payload,
            start_attestation_sha256=digest,
        )
        return {
            "ok": True,
            "status": "already_started",
            "shadow_started_at": epoch["head_started_at"].isoformat(),
            "start_attestation_sha256": digest,
            "epoch_number": int(epoch["head_number"]),
            "epoch_attestation_sha256": str(epoch["head_attestation_sha256"]),
            **binding,
        }
    configured_days = int(env_value("SHADOW_MIN_DAYS", "7") or 7)
    days = configured_days if min_days is None else int(min_days)
    if days < 7:
        raise ShadowGateError("SHADOW_MINIMUM_MUST_BE_AT_LEAST_SEVEN_DAYS")
    config = load_config()
    semantic = config.get("semantic_retrieval") if isinstance(config, dict) else None
    observability = config.get("observability") if isinstance(config, dict) else None
    if not isinstance(semantic, dict) or semantic.get("ranking_version") != "hybrid-v2-shadow":
        raise ShadowGateError("SHADOW_RANKING_MODE_REQUIRED")
    if not isinstance(observability, dict) or observability.get("stale_adoption_enforcement") != "shadow":
        raise ShadowGateError("SHADOW_STALE_MODE_REQUIRED")
    if observability.get("metadata_enforcement") != "shadow":
        raise ShadowGateError("SHADOW_METADATA_MODE_REQUIRED")
    if observability.get("enabled") is not True:
        raise ShadowGateError("SHADOW_OBSERVABILITY_MUST_BE_ENABLED")
    payload = {
        "schema_version": 1,
        "kind": "shadow-start",
        "shadow_started_at": utc_now(),
        "minimum_days": days,
        "production_config_sha256": config_digest,
        **benchmark_binding,
        **binding,
    }
    _path, digest = _exclusive_json("shadow-start", payload)
    return {
        "ok": True,
        "status": "started",
        "shadow_started_at": payload["shadow_started_at"],
        "start_attestation_sha256": digest,
        "epoch_number": 0,
        "epoch_attestation_sha256": digest,
        **binding,
    }


def _state_high_watermarks() -> dict[str, int]:
    """Capture one read-snapshot boundary for the two append-only ledgers."""

    if not STATE_DB.is_file():
        raise ShadowGateError("SHADOW_STATE_DB_MISSING")
    try:
        metadata = STATE_DB.lstat()
    except OSError as exc:
        raise ShadowGateError("SHADOW_STATE_DB_UNSAFE") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ShadowGateError("SHADOW_STATE_DB_UNSAFE")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ShadowGateError("SHADOW_STATE_DB_PERMISSIONS_UNSAFE")
    try:
        conn = secure_sqlite_connect(
            STATE_DB,
            create=False,
            read_only=True,
            row_factory=sqlite3.Row,
            pragmas=("PRAGMA busy_timeout=1000",),
        )
    except (OSError, StateSecurityError, sqlite3.Error) as exc:
        raise ShadowGateError("SHADOW_STATE_DB_UNSAFE") from exc
    try:
        conn.execute("BEGIN")
        tables = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if not {"memory_search_log", "memory_use_events"}.issubset(tables):
            raise ShadowGateError("SHADOW_OBSERVABILITY_SCHEMA_INVALID")
        for table in ("memory_search_log", "memory_use_events"):
            columns = {
                str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")
            }
            if "id" not in columns:
                raise ShadowGateError("SHADOW_OBSERVABILITY_SCHEMA_INVALID")
        search_id = int(
            conn.execute(
                "SELECT coalesce(max(id), 0) FROM memory_search_log"
            ).fetchone()[0]
            or 0
        )
        event_id = int(
            conn.execute(
                "SELECT coalesce(max(id), 0) FROM memory_use_events"
            ).fetchone()[0]
            or 0
        )
        if search_id < 0 or event_id < 0:
            raise ShadowGateError("SHADOW_OBSERVABILITY_SCHEMA_INVALID")
        return {
            "search_log_high_watermark": search_id,
            "event_log_high_watermark": event_id,
        }
    except sqlite3.Error as exc:
        raise ShadowGateError("SHADOW_OBSERVABILITY_SCHEMA_INVALID") from exc
    finally:
        conn.close()


def restart_shadow(
    *,
    actor: str,
    benchmark_file: str,
    supersede_epoch: str,
) -> dict[str, Any]:
    """Start a fresh seven-day epoch without rewriting prior evidence."""

    if actor != "migration":
        raise ShadowGateError("SHADOW_MUTATION_REQUIRES_MIGRATION_ACTOR")
    parent_digest = str(supersede_epoch or "").strip().casefold()
    if SHA256_RE.fullmatch(parent_digest) is None:
        raise ShadowGateError("SHADOW_EPOCH_PARENT_INVALID")
    with _shadow_start_transaction_lock(), _shadow_activity_lock(exclusive=True):
        binding = runtime_binding()
        start = current_start(binding)
        if start is None:
            raise ShadowGateError("SHADOW_NOT_STARTED")
        start_payload, start_digest = start
        config_digest = production_config_sha256()
        if start_payload.get("production_config_sha256") != config_digest:
            raise ShadowGateError("SHADOW_CONFIG_CHANGED_SINCE_START")
        benchmark_binding = private_benchmark_binding(benchmark_file)
        if any(
            start_payload.get(key) != value
            for key, value in benchmark_binding.items()
        ):
            raise ShadowGateError("SHADOW_BENCHMARK_CHANGED_SINCE_START")
        current = _normalized_utc()
        state = _shadow_epoch_state(
            binding=binding,
            start_payload=start_payload,
            start_attestation_sha256=start_digest,
            now=current,
        )
        head_digest = str(state["head_attestation_sha256"])
        if parent_digest != head_digest:
            child = state["children"].get(parent_digest, [])
            if len(child) == 1 and child[0] == head_digest:
                return {
                    "ok": True,
                    "status": "already_restarted",
                    "shadow_started_at": state["head_started_at"].isoformat(),
                    "start_attestation_sha256": start_digest,
                    "epoch_number": int(state["head_number"]),
                    "epoch_attestation_sha256": head_digest,
                    "superseded_epoch_attestation_sha256": parent_digest,
                    **binding,
                }
            if (
                parent_digest == start_digest
                or parent_digest in state["active_digests"]
            ):
                raise ShadowGateError("SHADOW_EPOCH_PARENT_STALE")
            raise ShadowGateError("SHADOW_EPOCH_PARENT_UNKNOWN")
        high_watermarks = _state_high_watermarks()
        # Take the duration timestamp after the durable ledger snapshot. Any
        # writer that commits after that snapshot receives a greater row ID
        # and belongs to the new epoch even if it captured an older wall time.
        current = _normalized_utc()
        parent_started_at = state["head_started_at"]
        if current <= parent_started_at:
            raise ShadowGateError("SHADOW_EPOCH_CLOCK_NOT_ADVANCED")
        payload = {
            "schema_version": 1,
            "kind": "shadow-epoch",
            "created_at": current.isoformat(),
            "epoch_started_at": current.isoformat(),
            "epoch_number": int(state["head_number"]) + 1,
            "reason_code": SHADOW_EPOCH_REASON,
            "root_start_attestation_sha256": start_digest,
            "parent_epoch_attestation_sha256": parent_digest,
            "production_config_sha256": config_digest,
            **benchmark_binding,
            **high_watermarks,
            **binding,
        }
        _path, digest = _exclusive_json("shadow-epoch", payload)
        verified = _shadow_epoch_state(
            binding=binding,
            start_payload=start_payload,
            start_attestation_sha256=start_digest,
            now=current,
        )
        if verified.get("head_attestation_sha256") != digest:
            raise ShadowGateError("SHADOW_EPOCH_POSTWRITE_VERIFICATION_FAILED")
        return {
            "ok": True,
            "status": "restarted",
            "shadow_started_at": payload["epoch_started_at"],
            "start_attestation_sha256": start_digest,
            "epoch_number": payload["epoch_number"],
            "epoch_attestation_sha256": digest,
            "superseded_epoch_attestation_sha256": parent_digest,
            **high_watermarks,
            **binding,
        }


def write_benchmark_attestation(
    output: dict[str, Any],
    *,
    dataset_sha256: str,
    production_config_digest: str,
) -> dict[str, Any]:
    """Persist a successful private quality result without query/path/URL data."""

    if os.environ.get("MEMORY_ACTOR", "").strip() != "migration":
        raise ShadowGateError("SHADOW_MUTATION_REQUIRES_MIGRATION_ACTOR")
    binding = runtime_binding()
    epoch = current_shadow_epoch(binding)
    if epoch is None:
        raise ShadowGateError("SHADOW_NOT_STARTED")
    start_payload = epoch["root_payload"]
    start_digest = str(epoch["root_attestation_sha256"])
    epoch_number = int(epoch["head_number"])
    epoch_digest = str(epoch["head_attestation_sha256"])
    epoch_started_at_value = epoch["head_started_at"]
    epoch_started_at = epoch_started_at_value.isoformat()
    if output.get("status") != "ok" or output.get("gate_failures"):
        raise ShadowGateError("BENCHMARK_GATE_NOT_PASSED")
    if int(output.get("runs") or 0) != 3:
        raise ShadowGateError("BENCHMARK_REQUIRES_EXACTLY_THREE_RUNS")
    dataset_digest = str(dataset_sha256)
    if SHA256_RE.fullmatch(dataset_digest) is None:
        raise ShadowGateError("BENCHMARK_DATASET_DIGEST_INVALID")
    current_config_digest = production_config_sha256()
    if (
        SHA256_RE.fullmatch(str(production_config_digest)) is None
        or production_config_digest != current_config_digest
        or production_config_digest != start_payload.get("production_config_sha256")
    ):
        raise ShadowGateError("BENCHMARK_PRODUCTION_CONFIG_MISMATCH")
    required_set_digest = str(output.get("required_case_set_sha256") or "")
    if (
        output.get("full_required_case_set") is not True
        or SHA256_RE.fullmatch(required_set_digest) is None
    ):
        raise ShadowGateError("BENCHMARK_FULL_REQUIRED_CASE_SET_MISSING")
    required = output.get("required")
    case_count = int(output.get("case_count") or 0)
    required_count = int(output.get("required_case_count") or 0)
    if (
        not isinstance(required, dict)
        or required_count < MIN_PINNED_REQUIRED_CASES
        or case_count < required_count
    ):
        raise ShadowGateError("BENCHMARK_REQUIRED_CASES_MISSING")
    pinned_fields = {
        "dataset_sha256": dataset_digest,
        "required_case_set_sha256": required_set_digest,
        "case_count": case_count,
        "required_case_count": required_count,
        "mandatory_auto_archive_case_count": int(
            output.get("mandatory_auto_archive_case_count") or 0
        ),
    }
    if any(start_payload.get(key) != value for key, value in pinned_fields.items()):
        raise ShadowGateError("BENCHMARK_DOES_NOT_MATCH_SHADOW_START")
    if (
        int(output.get("mandatory_auto_archive_case_count") or 0) < 1
        or output.get("mandatory_auto_archive_passed") is not True
    ):
        raise ShadowGateError("BENCHMARK_MANDATORY_AUTO_ARCHIVE_CASE_MISSING")
    backend_metrics: dict[str, dict[str, float]] = {}
    for backend in ("sqlite", "vector", "hybrid", "canonical_retrieve"):
        raw = required.get(backend)
        if not isinstance(raw, dict):
            raise ShadowGateError("BENCHMARK_BACKEND_MISSING")
        hit5 = float(raw.get("hit@5") or 0.0)
        mrr = float(raw.get("mrr") or 0.0)
        if (
            not math.isfinite(hit5)
            or not math.isfinite(mrr)
            or hit5 != 1.0
            or not 0.90 <= mrr <= 1.0
        ):
            raise ShadowGateError("BENCHMARK_QUALITY_THRESHOLD_FAILED")
        backend_metrics[backend] = {"hit_at_5": hit5, "mrr": mrr}
    latency = output.get("latency_ms")
    hybrid_latency = latency.get("hybrid") if isinstance(latency, dict) else None
    cold = float(hybrid_latency.get("cold") or 0.0) if isinstance(hybrid_latency, dict) else 0.0
    warm = float(hybrid_latency.get("warm_p95") or 0.0) if isinstance(hybrid_latency, dict) else 0.0
    if (
        not math.isfinite(cold)
        or not math.isfinite(warm)
        or cold <= 0
        or cold > 8000
        or warm <= 0
        or warm > 1000
    ):
        raise ShadowGateError("BENCHMARK_LATENCY_THRESHOLD_FAILED")
    lifecycle = output.get("worker_lifecycle")
    if not isinstance(lifecycle, dict):
        raise ShadowGateError("BENCHMARK_WORKER_LIFECYCLE_MISSING")
    warm_samples = int(lifecycle.get("warm_sample_count") or 0)
    if (
        lifecycle.get("cold_status") != "started"
        or warm_samples < 1
        or int(lifecycle.get("warm_reused_count") or 0) != warm_samples
        or int(lifecycle.get("restart_count") or 0) != 0
        or int(lifecycle.get("failed_or_degraded_count") or 0) != 0
    ):
        raise ShadowGateError("BENCHMARK_WORKER_LIFECYCLE_FAILED")
    payload = {
        "schema_version": 1,
        "kind": "benchmark-success",
        "created_at": _evidence_created_at(epoch_started_at_value),
        "shadow_started_at": epoch_started_at,
        "start_attestation_sha256": start_digest,
        "dataset_sha256": dataset_digest,
        "required_case_set_sha256": required_set_digest,
        "full_required_case_set": True,
        "mandatory_auto_archive_case_count": int(output.get("mandatory_auto_archive_case_count") or 0),
        "production_config_sha256": production_config_digest,
        "runs": 3,
        "case_count": case_count,
        "required_case_count": required_count,
        "metrics": backend_metrics,
        "hybrid_cold_ms": round(cold, 3),
        "hybrid_warm_p95_ms": round(warm, 3),
        "degraded_count": 0,
        "worker_cold_status": "started",
        "worker_warm_sample_count": warm_samples,
        "worker_warm_reused_count": warm_samples,
        **(
            {
                "epoch_attestation_sha256": epoch_digest,
                "epoch_number": epoch_number,
            }
            if epoch_number > 0
            else {}
        ),
        **binding,
    }
    _path, digest = _exclusive_json("benchmark-success", payload)
    return {
        "ok": True,
        "benchmark_attestation_sha256": digest,
        "epoch_attestation_sha256": epoch_digest,
        "epoch_number": epoch_number,
    }


def run_stale_canary(*, actor: str) -> dict[str, Any]:
    if actor != "migration":
        raise ShadowGateError("SHADOW_MUTATION_REQUIRES_MIGRATION_ACTOR")
    binding = runtime_binding()
    epoch = current_shadow_epoch(binding)
    if epoch is None:
        raise ShadowGateError("SHADOW_NOT_STARTED")
    start_digest = str(epoch["root_attestation_sha256"])
    epoch_number = int(epoch["head_number"])
    epoch_digest = str(epoch["head_attestation_sha256"])
    epoch_started_at_value = epoch["head_started_at"]
    epoch_started_at = epoch_started_at_value.isoformat()
    import agent_memory_observability as observability

    raw_task = "shadow-canary-" + uuid.uuid4().hex
    task_id = observability.task_ref(raw_task, "test")
    memory_id = hashlib.sha256((raw_task + "-memory").encode("utf-8")).hexdigest()
    content_sha = hashlib.sha256((raw_task + "-content").encode("utf-8")).hexdigest()
    version = {
        "memory_id": memory_id,
        "content_sha256": content_sha,
        "policy_state": "overdue",
        "requires_live_verification": True,
    }
    observability.record_source_opened_version(
        actor="test",
        task_id=task_id,
        memory_version=version,
    )
    observability.record_declared_event(
        actor="test",
        task_id=task_id,
        event_type="adoption_declared",
        source="agent_declared",
        value="adopted",
        memory_versions=[version],
        reason_code="workflow_rule",
    )
    identified = observability.adopted_stale_without_verification("test", raw_task)
    observability.record_declared_event(
        actor="test",
        task_id=task_id,
        event_type="live_verified",
        source="agent_declared",
        value="yes",
        memory_versions=[version],
        reason_code="workflow_rule",
    )
    cleared = observability.adopted_stale_without_verification("test", raw_task)
    if identified != 1 or cleared != 0:
        raise ShadowGateError("STALE_ADOPTION_CANARY_FAILED")
    payload = {
        "schema_version": 1,
        "kind": "stale-canary",
        "created_at": _evidence_created_at(epoch_started_at_value),
        "shadow_started_at": epoch_started_at,
        "start_attestation_sha256": start_digest,
        "identified_before_live_verification": identified,
        "remaining_after_live_verification": cleared,
        "task_ref_sha256": hashlib.sha256(task_id.encode("ascii")).hexdigest(),
        "memory_version_fingerprint": hashlib.sha256(
            f"{memory_id}:{content_sha}".encode("ascii")
        ).hexdigest(),
        **(
            {
                "epoch_attestation_sha256": epoch_digest,
                "epoch_number": epoch_number,
            }
            if epoch_number > 0
            else {}
        ),
        **binding,
    }
    _path, digest = _exclusive_json("stale-canary", payload)
    return {
        "ok": True,
        "canary_attestation_sha256": digest,
        "epoch_attestation_sha256": epoch_digest,
        "epoch_number": epoch_number,
    }


def _candidate_disposition_metrics(
    conn: sqlite3.Connection,
    *,
    started_at: str,
    event_id_after: int | None = None,
    event_id_at_most: int | None = None,
) -> dict[str, int]:
    """Measure prospective candidate disposition completeness.

    The installer creates ``disposition_tracking_enabled_at`` only after the
    v4 ledger and its privacy guards are ready.  Databases without that marker
    predate this contract and are intentionally not judged retroactively.
    """

    empty = {
        "returned_without_disposition": 0,
        "opened_without_disposition": 0,
        "tasks_with_missing_disposition": 0,
    }
    tables = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    if "meta" not in tables or "memory_use_events" not in tables:
        return empty
    marker_row = conn.execute(
        "SELECT value FROM meta WHERE key='disposition_tracking_enabled_at'"
    ).fetchone()
    if marker_row is None or not str(marker_row[0] or ""):
        return empty
    required_columns = {
        "actor", "task_id", "event_type", "source", "value",
        "memory_ids_json", "memory_versions_json", "created_at",
    }
    columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(memory_use_events)")
    }
    if not required_columns.issubset(columns):
        raise sqlite3.OperationalError("STATE_SCHEMA_MIGRATION_REQUIRED")
    clauses: list[str] = []
    parameters: list[object] = []
    if event_id_after is None:
        tracking_since = max(
            parse_timestamp(started_at),
            parse_timestamp(str(marker_row[0])),
        ).replace(microsecond=0).isoformat()
        clauses.append("created_at>=?")
        parameters.append(tracking_since)
    else:
        clauses.append("id>?")
        parameters.append(event_id_after)
    if event_id_at_most is not None:
        clauses.append("id<=?")
        parameters.append(event_id_at_most)
    rows = conn.execute(
        f"""
        SELECT id, actor, task_id, event_type, source, value,
               memory_ids_json, memory_versions_json
        FROM memory_use_events
        WHERE {' AND '.join(clauses)}
        ORDER BY id
        """,
        tuple(parameters),
    ).fetchall()

    def memory_ids(row: sqlite3.Row) -> set[str]:
        identifiers: set[str] = set()
        try:
            raw_ids = json.loads(str(row["memory_ids_json"] or "[]"))
            raw_versions = json.loads(str(row["memory_versions_json"] or "[]"))
        except (TypeError, json.JSONDecodeError):
            return set()
        if isinstance(raw_ids, list):
            identifiers.update(
                str(value)
                for value in raw_ids
                if SHA256_RE.fullmatch(str(value or ""))
            )
        if isinstance(raw_versions, list):
            identifiers.update(
                str(value.get("memory_id") or "")
                for value in raw_versions
                if isinstance(value, dict)
                and SHA256_RE.fullmatch(str(value.get("memory_id") or ""))
            )
        return identifiers

    returned: set[tuple[str, str, str]] = set()
    opened: set[tuple[str, str, str]] = set()
    latest_candidate_event: dict[tuple[str, str, str], int] = {}
    latest_successful_completion: dict[tuple[str, str], int] = {}
    dispositions: dict[tuple[str, str, str], tuple[int, str]] = {}
    for row in rows:
        actor = str(row["actor"] or "").strip().casefold()
        task_id = str(row["task_id"] or "")
        if actor not in {"codex", "claude"} or not task_id:
            continue
        event_order = int(row["id"])
        event_type = str(row["event_type"] or "")
        source = str(row["source"] or "")
        ids = memory_ids(row)
        if event_type in {"search", "search_completed"} and source == "tool_observed":
            candidates = {(actor, task_id, value) for value in ids}
            returned.update(candidates)
            for candidate in candidates:
                latest_candidate_event[candidate] = event_order
        elif event_type in {"source_opened", "opened_original"} and source == "tool_observed":
            candidates = {(actor, task_id, value) for value in ids}
            opened.update(candidates)
            for candidate in candidates:
                latest_candidate_event[candidate] = event_order
        elif event_type in {"adoption", "adoption_declared"}:
            for value in ids:
                dispositions[(actor, task_id, value)] = (
                    event_order,
                    str(row["value"] or ""),
                )
        elif (
            event_type in {"outcome", "task_completed"}
            and source == "tool_observed"
            and str(row["value"] or "") == "success"
        ):
            latest_successful_completion[(actor, task_id)] = event_order

    accepted = {"adopted", "reference_only", "rejected"}

    def has_current_disposition(candidate: tuple[str, str, str]) -> bool:
        disposition_order, disposition = dispositions.get(candidate, (-1, ""))
        return (
            disposition in accepted
            and disposition_order >= latest_candidate_event.get(candidate, -1)
        )

    missing_returned = {
        candidate
        for candidate in returned
        if latest_successful_completion.get(candidate[:2], -1)
        > latest_candidate_event.get(candidate, -1)
        and not has_current_disposition(candidate)
    }
    missing_opened = {
        candidate
        for candidate in opened
        if latest_successful_completion.get(candidate[:2], -1)
        > latest_candidate_event.get(candidate, -1)
        and not has_current_disposition(candidate)
    }
    return {
        "returned_without_disposition": len(missing_returned),
        "opened_without_disposition": len(missing_opened),
        "tasks_with_missing_disposition": len(
            {candidate[:2] for candidate in missing_returned | missing_opened}
        ),
    }


def _shadow_metrics(
    started_at: str,
    *,
    search_id_after: int | None = None,
    event_id_after: int | None = None,
    search_id_at_most: int | None = None,
    event_id_at_most: int | None = None,
) -> dict[str, int]:
    if not STATE_DB.is_file():
        raise ShadowGateError("SHADOW_STATE_DB_MISSING")
    try:
        metadata = STATE_DB.lstat()
    except OSError as exc:
        raise ShadowGateError("SHADOW_STATE_DB_UNSAFE") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ShadowGateError("SHADOW_STATE_DB_UNSAFE")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ShadowGateError("SHADOW_STATE_DB_PERMISSIONS_UNSAFE")
    try:
        conn = secure_sqlite_connect(
            STATE_DB,
            create=False,
            read_only=True,
            row_factory=sqlite3.Row,
            pragmas=("PRAGMA busy_timeout=1000",),
        )
    except (OSError, StateSecurityError, sqlite3.Error) as exc:
        raise ShadowGateError("SHADOW_STATE_DB_UNSAFE") from exc
    try:
        guard_report = search_log_privacy_guard_report(conn)
        disposition_metrics = _candidate_disposition_metrics(
            conn,
            started_at=started_at,
            event_id_after=event_id_after,
            event_id_at_most=event_id_at_most,
        )
        search_clauses: list[str] = []
        search_parameters: list[object] = []
        if search_id_after is None:
            search_clauses.append("created_at>=?")
            search_parameters.append(started_at)
        else:
            search_clauses.append("id>?")
            search_parameters.append(search_id_after)
        if search_id_at_most is not None:
            search_clauses.append("id<=?")
            search_parameters.append(search_id_at_most)
        rows = conn.execute(
            f"""
            SELECT query, used_paths, task_id, actor, sources,
                   required_case_regression_count, worker_status,
                   worker_restart_count, metadata_gate_mode,
                   metadata_would_block_count, metadata_reason_fingerprint
            FROM memory_search_log
            WHERE {' AND '.join(search_clauses)}
            ORDER BY id
            """,
            tuple(search_parameters),
        ).fetchall()
        event_clauses: list[str] = [
            "event_type IN ('source_opened','opened_original')"
        ]
        event_parameters: list[object] = []
        if event_id_after is None:
            event_clauses.append("created_at>=?")
            event_parameters.append(started_at)
        else:
            event_clauses.append("id>?")
            event_parameters.append(event_id_after)
        if event_id_at_most is not None:
            event_clauses.append("id<=?")
            event_parameters.append(event_id_at_most)
        event_rows = conn.execute(
            f"""
            SELECT task_id, actor, event_type, source
            FROM memory_use_events
            WHERE {' AND '.join(event_clauses)}
            ORDER BY id
            """,
            tuple(event_parameters),
        ).fetchall()
        # A task may first be seen before day one and then perform a real
        # search/open during the shadow window. Its denominator is durable and
        # remains valid; only the measured activity is time-windowed.
        task_seen_clause = "event_type='task_seen'"
        task_seen_parameters: tuple[object, ...] = ()
        if event_id_at_most is not None:
            task_seen_clause += " AND id<=?"
            task_seen_parameters = (event_id_at_most,)
        task_seen_rows = conn.execute(
            f"""
            SELECT task_id, actor, event_type, source
            FROM memory_use_events
            WHERE {task_seen_clause}
            ORDER BY id
            """,
            task_seen_parameters,
        ).fetchall()
    except sqlite3.Error as exc:
        raise ShadowGateError("SHADOW_OBSERVABILITY_SCHEMA_INVALID") from exc
    finally:
        conn.close()
    privacy = 0
    missing = 0
    regressions = 0
    crash_loops = 0
    crash_run = 0
    semantic_failure_streaks = 0
    semantic_failure_run = 0
    restarts = 0
    metadata_would_block = 0
    metadata_observation_invalid = 0
    real_searches = 0
    task_seen_pairs = {
        (str(row["actor"] or "").strip().casefold(), str(row["task_id"] or ""))
        for row in task_seen_rows
        if str(row["event_type"] or "") == "task_seen"
        and str(row["source"] or "") == "tool_observed"
        and str(row["actor"] or "").strip().casefold() not in {"test", "migration"}
        and str(row["task_id"] or "")
    }
    real_tasks: set[tuple[str, str]] = set()
    for row in rows:
        query = str(row["query"] or "")
        # During the v4 shadow window even a redacted legacy placeholder is
        # forbidden: the durable row may retain only the one-way query hash,
        # length, controlled enums, counts, and timestamps.
        if str(row["used_paths"] or "") or query:
            privacy += 1
        regressions += max(0, int(row["required_case_regression_count"] or 0))
        actor = str(row["actor"] or "").strip().casefold()
        sources = {
            item.strip().casefold()
            for item in str(row["sources"] or "").split(",")
            if item.strip()
        }
        synthetic = actor in {"test", "migration"} or any(
            any(marker in source for marker in NON_REAL_SOURCE_MARKERS)
            for source in sources
        )
        task_id = str(row["task_id"] or "")
        task_key = (actor, task_id)
        real = bool(not synthetic and task_key in task_seen_pairs)
        if not synthetic and task_key not in task_seen_pairs:
            missing += 1
        if real:
            real_searches += 1
            real_tasks.add(task_key)
        restarted = int(row["worker_restart_count"] or 0)
        restarts += max(0, restarted)
        status = str(row["worker_status"] or "").strip().casefold()
        if real:
            restarted_unhealthy = restarted > 0 and status in {"restarted", "degraded", "failed"}
            crash_run = crash_run + 1 if restarted_unhealthy else 0
            if crash_run == 2:
                crash_loops += 1
            semantic_unhealthy = status in {"degraded", "failed"}
            semantic_failure_run = semantic_failure_run + 1 if semantic_unhealthy else 0
            if semantic_failure_run == 2:
                semantic_failure_streaks += 1
            metadata_mode = str(row["metadata_gate_mode"] or "").strip().casefold()
            would_block = int(row["metadata_would_block_count"] or 0)
            fingerprint = str(row["metadata_reason_fingerprint"] or "")
            metadata_would_block += max(0, would_block)
            if (
                metadata_mode not in {"shadow", "enforce"}
                or would_block < 0
                or (would_block > 0 and SHA256_RE.fullmatch(fingerprint) is None)
                or (would_block == 0 and fingerprint)
            ):
                metadata_observation_invalid += 1
    for row in event_rows:
        actor = str(row["actor"] or "").strip().casefold()
        task_id = str(row["task_id"] or "")
        if (
            str(row["event_type"] or "") in {"source_opened", "opened_original"}
            and (actor, task_id) in task_seen_pairs
            and actor not in {"test", "migration"}
            and str(row["source"] or "") == "tool_observed"
        ):
            real_tasks.add((actor, task_id))
    return {
        "searches": len(rows),
        "real_searches": real_searches,
        "real_task_count": len(real_tasks),
        "required_regressions": regressions,
        "privacy_violations": privacy,
        "missing_task_denominator": missing,
        "worker_restarts": restarts,
        "worker_crash_loops": crash_loops,
        "semantic_failure_streaks": semantic_failure_streaks,
        "metadata_would_block_count": metadata_would_block,
        "metadata_observation_invalid": metadata_observation_invalid,
        "state_privacy_guard_invalid": int(not guard_report.get("ready", False)),
        **disposition_metrics,
    }


def shadow_status(*, now: dt.datetime | None = None) -> dict[str, Any]:
    binding = runtime_binding()
    try:
        start = current_start(binding)
    except ShadowGateError as exc:
        return {
            "ok": False,
            "status": "invalid",
            "gate_failures": [str(exc)],
            **binding,
        }
    if start is None:
        return {"ok": False, "status": "not_started", "gate_failures": ["SHADOW_NOT_STARTED"], **binding}
    start_payload, start_digest = start
    current = _normalized_utc(now)
    try:
        epoch = _shadow_epoch_state(
            binding=binding,
            start_payload=start_payload,
            start_attestation_sha256=start_digest,
            now=current,
        )
    except ShadowGateError as exc:
        return {
            "ok": False,
            "status": "invalid",
            "shadow_started_at": start_payload.get("shadow_started_at"),
            "start_attestation_sha256": start_digest,
            "gate_failures": [str(exc)],
            **binding,
        }
    epoch_started_at = epoch["head_started_at"]
    epoch_started_at_text = epoch_started_at.isoformat()
    epoch_digest = str(epoch["head_attestation_sha256"])
    epoch_number = int(epoch["head_number"])
    elapsed_seconds = max(0.0, (current - epoch_started_at).total_seconds())
    minimum_days = max(7, int(start_payload.get("minimum_days") or 7))
    if epoch_number > 0:
        search_high_watermark = int(epoch["head_search_log_high_watermark"])
        event_high_watermark = int(epoch["head_event_log_high_watermark"])
        metrics = _shadow_metrics(
            epoch_started_at_text,
            search_id_after=search_high_watermark,
            event_id_after=event_high_watermark,
        )
        historical_metrics = _shadow_metrics(
            str(start_payload["shadow_started_at"]),
            search_id_at_most=search_high_watermark,
            event_id_at_most=event_high_watermark,
        )
    else:
        search_high_watermark = None
        event_high_watermark = None
        metrics = _shadow_metrics(epoch_started_at_text)
        historical_metrics = {key: 0 for key in metrics}
    if epoch_number > 0:
        metrics["historical_search_count"] = int(
            historical_metrics.get("searches", 0) or 0
        )
        for field, value in historical_metrics.items():
            if field == "searches":
                continue
            metrics[f"historical_{field}"] = int(value or 0)
    else:
        metrics["historical_search_count"] = 0
        for field in historical_metrics:
            if field != "searches":
                metrics[f"historical_{field}"] = 0
    metrics["historical_epoch_count"] = epoch_number
    current_config_digest = production_config_sha256()

    def belongs_to_current_epoch(payload: dict[str, Any]) -> bool:
        if epoch_number == 0:
            return (
                payload.get("shadow_started_at") in {None, "", epoch_started_at_text}
                and payload.get("epoch_attestation_sha256") in {None, "", epoch_digest}
                and payload.get("epoch_number") in {None, 0}
            )
        return (
            payload.get("shadow_started_at") == epoch_started_at_text
            and payload.get("epoch_attestation_sha256") == epoch_digest
            and payload.get("epoch_number") == epoch_number
        )

    def benchmark_valid(payload: dict[str, Any]) -> bool:
        metrics_payload = payload.get("metrics")
        if (
            not isinstance(metrics_payload, dict)
            or payload.get("runs") != 3
            or int(payload.get("case_count") or 0) < MIN_PINNED_REQUIRED_CASES
            or int(payload.get("required_case_count") or 0) < MIN_PINNED_REQUIRED_CASES
            or SHA256_RE.fullmatch(str(payload.get("dataset_sha256") or "")) is None
            or SHA256_RE.fullmatch(str(payload.get("required_case_set_sha256") or "")) is None
            or payload.get("dataset_sha256") != start_payload.get("dataset_sha256")
            or payload.get("required_case_set_sha256") != start_payload.get("required_case_set_sha256")
            or payload.get("case_count") != start_payload.get("case_count")
            or payload.get("required_case_count") != start_payload.get("required_case_count")
            or payload.get("mandatory_auto_archive_case_count")
            != start_payload.get("mandatory_auto_archive_case_count")
            or payload.get("production_config_sha256") != start_payload.get("production_config_sha256")
            or payload.get("full_required_case_set") is not True
            or int(payload.get("mandatory_auto_archive_case_count") or 0) < 1
            or payload.get("worker_cold_status") != "started"
            or int(payload.get("worker_warm_sample_count") or 0) < 1
            or int(payload.get("worker_warm_reused_count") or 0)
            != int(payload.get("worker_warm_sample_count") or 0)
        ):
            return False
        try:
            values = [
                (
                    float(metrics_payload[backend].get("hit_at_5") or 0),
                    float(metrics_payload[backend].get("mrr") or 0),
                )
                for backend in ("sqlite", "vector", "hybrid", "canonical_retrieve")
                if isinstance(metrics_payload.get(backend), dict)
            ]
            quality_ok = len(values) == 4 and all(
                math.isfinite(hit5)
                and math.isfinite(mrr)
                and hit5 == 1.0
                and 0.90 <= mrr <= 1.0
                for hit5, mrr in values
            )
            cold = float(payload.get("hybrid_cold_ms") or 0)
            warm = float(payload.get("hybrid_warm_p95_ms") or 0)
            latency_ok = (
                math.isfinite(cold)
                and math.isfinite(warm)
                and 0 < cold <= 8000
                and 0 < warm <= 1000
            )
        except (TypeError, ValueError):
            return False
        return quality_ok and latency_ok and int(payload.get("degraded_count") or 0) == 0

    try:
        benchmark_attestations = _attestations("benchmark-success", binding)
        canary_attestations = _attestations("stale-canary", binding)
    except ShadowGateError as exc:
        return {
            "ok": False,
            "status": "invalid",
            "shadow_started_at": epoch_started_at_text,
            "start_attestation_sha256": start_digest,
            "epoch_attestation_sha256": epoch_digest,
            "epoch_number": epoch_number,
            "gate_failures": [str(exc)],
            **binding,
        }
    all_benchmark_rows = [
        row for row in benchmark_attestations
        if row[1].get("start_attestation_sha256") == start_digest
        and benchmark_valid(row[1])
    ]
    benchmark_rows = [row for row in all_benchmark_rows if belongs_to_current_epoch(row[1])]
    all_canary_rows = [
        row for row in canary_attestations
        if row[1].get("start_attestation_sha256") == start_digest
        and row[1].get("identified_before_live_verification") == 1
        and row[1].get("remaining_after_live_verification") == 0
    ]
    canary_rows = [row for row in all_canary_rows if belongs_to_current_epoch(row[1])]
    failures: list[str] = []
    if start_payload.get("production_config_sha256") != current_config_digest:
        failures.append("SHADOW_CONFIG_CHANGED_SINCE_START")
    if elapsed_seconds < minimum_days * 86400:
        failures.append("SHADOW_MINIMUM_DURATION_NOT_MET")
    if not benchmark_rows:
        failures.append("SHADOW_BENCHMARK_ATTESTATION_MISSING")
    if not canary_rows:
        failures.append("SHADOW_STALE_CANARY_ATTESTATION_MISSING")
    if metrics["real_task_count"] < 1:
        failures.append("SHADOW_REAL_RETRIEVAL_DENOMINATOR_MISSING")
    for field, reason in (
        ("required_regressions", "SHADOW_REQUIRED_CASE_REGRESSION"),
        ("privacy_violations", "SHADOW_PRIVACY_VIOLATION"),
        ("missing_task_denominator", "SHADOW_TASK_DENOMINATOR_MISSING"),
        ("worker_crash_loops", "SHADOW_WORKER_CRASH_LOOP"),
        ("semantic_failure_streaks", "SHADOW_SEMANTIC_FAILURE_STREAK"),
        ("metadata_would_block_count", "SHADOW_METADATA_GATE_WOULD_BLOCK"),
        ("metadata_observation_invalid", "SHADOW_METADATA_OBSERVATION_INVALID"),
        ("state_privacy_guard_invalid", "SHADOW_STATE_PRIVACY_GUARD_INVALID"),
        ("tasks_with_missing_disposition", "SHADOW_CANDIDATE_DISPOSITION_MISSING"),
    ):
        if int(metrics.get(field, 0) or 0):
            failures.append(reason)
    return {
        "ok": not failures,
        "status": "passed" if not failures else "observing",
        "shadow_started_at": epoch_started_at_text,
        "root_shadow_started_at": start_payload["shadow_started_at"],
        "minimum_days": minimum_days,
        "elapsed_days": round(elapsed_seconds / 86400, 3),
        "start_attestation_sha256": start_digest,
        "epoch_attestation_sha256": epoch_digest,
        "epoch_number": epoch_number,
        "search_log_high_watermark": search_high_watermark,
        "event_log_high_watermark": event_high_watermark,
        "historical_epoch_count": epoch_number,
        "production_config_sha256": str(start_payload.get("production_config_sha256") or ""),
        "benchmark_attestation_count": len(benchmark_rows),
        "historical_benchmark_attestation_count": len(all_benchmark_rows) - len(benchmark_rows),
        "canary_attestation_count": len(canary_rows),
        "historical_canary_attestation_count": len(all_canary_rows) - len(canary_rows),
        "metrics": metrics,
        "historical_metrics": historical_metrics,
        "gate_failures": failures,
        **binding,
    }


def _toml_replace(text: str, section: str, key: str, value: object) -> str:
    rendered = json.dumps(value, ensure_ascii=True) if isinstance(value, str) else str(value).lower()
    lines = text.splitlines(keepends=True)
    header = f"[{section}]"
    section_start = next((index for index, line in enumerate(lines) if line.strip() == header), None)
    if section_start is None:
        if text and not text.endswith("\n"):
            lines.append("\n")
        lines.extend([f"\n{header}\n", f"{key} = {rendered}\n"])
        return "".join(lines)
    section_end = next(
        (index for index in range(section_start + 1, len(lines)) if lines[index].lstrip().startswith("[")),
        len(lines),
    )
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")
    for index in range(section_start + 1, section_end):
        if pattern.match(lines[index]):
            newline = "\r\n" if lines[index].endswith("\r\n") else "\n"
            lines[index] = f"{key} = {rendered}{newline}"
            return "".join(lines)
    lines.insert(section_end, f"{key} = {rendered}\n")
    return "".join(lines)


def render_cutover_config(
    original: bytes,
    *,
    evidence_sha256: str,
    evidence_file: str,
    backup_file: str,
    from_config_sha256: str,
    shadow_started_at: str,
    runtime_installed_at: str,
    manifest_sha256: str,
    cutover_at: str,
) -> bytes:
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ShadowGateError("SHADOW_CONFIG_ENCODING_INVALID") from exc
    replacements = (
        ("semantic_retrieval", "ranking_version", "hybrid-v2"),
        ("observability", "stale_adoption_enforcement", "enforce"),
        ("observability", "metadata_enforcement", "enforce"),
        ("shadow", "status", "cutover"),
        ("shadow", "shadow_started_at", shadow_started_at),
        ("shadow", "runtime_installed_at", runtime_installed_at),
        ("shadow", "manifest_sha256", manifest_sha256),
        ("shadow", "cutover_evidence_sha256", evidence_sha256),
        ("shadow", "cutover_evidence_file", evidence_file),
        ("shadow", "cutover_from_config_sha256", from_config_sha256),
        ("shadow", "cutover_config_backup", backup_file),
        ("shadow", "cutover_at", cutover_at),
    )
    for section, key, value in replacements:
        text = _toml_replace(text, section, key, value)
    return text.encode("utf-8")


def _beneath_config_root(path: Path) -> bool:
    try:
        path.resolve().relative_to(CONFIG_ROOT.resolve())
        return True
    except (OSError, ValueError):
        return False


def _exclusive_copy(path: Path, raw: bytes) -> None:
    if not _beneath_config_root(path):
        raise ShadowGateError("SHADOW_BACKUP_OUTSIDE_PRIVATE_RUNTIME")
    _ensure_private_directory(path.parent)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        if os.name == "posix":
            os.fchmod(handle.fileno(), 0o600)
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _verified_private_backup(path_value: object, *, expected_sha256: str) -> bytes:
    """Read an exact private config backup without following symlinks."""

    if SHA256_RE.fullmatch(str(expected_sha256 or "")) is None:
        raise ShadowGateError("SHADOW_ROLLBACK_BASE_DIGEST_INVALID")
    lexical = Path(os.path.abspath(os.path.expanduser(str(path_value or ""))))
    try:
        lexical.resolve().relative_to(CONFIG_ROOT.resolve())
        assert_no_symlink_beneath(CONFIG_ROOT, lexical, include_leaf=True)
        metadata = lexical.lstat()
        current_uid = os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != current_uid
            or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE)
        ):
            raise ShadowGateError("SHADOW_ROLLBACK_BACKUP_UNSAFE")
        raw = _regular_bytes(lexical, max_bytes=2 * 1024 * 1024)
    except (OSError, StateSecurityError, ValueError, ShadowGateError) as exc:
        if isinstance(exc, ShadowGateError) and str(exc) == "SHADOW_ROLLBACK_BACKUP_UNSAFE":
            raise
        raise ShadowGateError("SHADOW_ROLLBACK_BACKUP_UNSAFE") from exc
    if sha256_bytes(raw) != expected_sha256:
        raise ShadowGateError("SHADOW_ROLLBACK_BACKUP_DIGEST_MISMATCH")
    return raw


def _atomic_config(raw: bytes, *, expected: bytes) -> None:
    target = config_path()
    if target.resolve() != (CONFIG_ROOT / "config" / "agent-memory.toml").resolve():
        raise ShadowGateError("SHADOW_CONFIG_PATH_UNSAFE")
    try:
        secure_conditional_write_bytes_beneath(
            CONFIG_ROOT,
            target.relative_to(CONFIG_ROOT),
            raw,
            expected_sha256=sha256_bytes(expected),
            expected_size=len(expected),
            operation_id=hashlib.sha256(expected + b"\0" + raw).hexdigest(),
            namespace="shadow-config",
            max_capture_bytes=max(len(expected), len(raw), 2 * 1024 * 1024),
            mode=0o600,
        )
    except ConditionalWriteError as exc:
        reason = {
            "CONDITIONAL_WRITE_TARGET_CHANGED": "SHADOW_CONFIG_CAS_MISMATCH",
            "CONDITIONAL_WRITE_RECOVERY_REQUIRED": "SHADOW_CONFIG_RECOVERY_REQUIRED",
        }.get(exc.reason_code, "SHADOW_CONFIG_CAS_FAILED")
        raise ShadowGateError(reason) from exc
    reset_config_cache()


def verify_cutover_config(
    raw: bytes,
    payload: dict[str, Any],
    *,
    expected_config_sha256: str,
) -> dict[str, Any]:
    """Validate the sole permitted post-install config transformation."""

    try:
        semantic = payload["semantic_retrieval"]
        observability = payload["observability"]
        shadow = payload["shadow"]
        if (
            not isinstance(semantic, dict)
            or semantic.get("ranking_version") != "hybrid-v2"
            or not isinstance(observability, dict)
            or observability.get("stale_adoption_enforcement") != "enforce"
            or observability.get("metadata_enforcement") != "enforce"
            or not isinstance(shadow, dict)
            or shadow.get("status") != "cutover"
        ):
            return {"ok": False, "reason_code": "SHADOW_CUTOVER_CONFIG_INACTIVE"}
        fields = {
            name: str(shadow.get(name, ""))
            for name in (
                "shadow_started_at", "runtime_installed_at", "manifest_sha256",
                "cutover_evidence_sha256", "cutover_evidence_file",
                "cutover_from_config_sha256", "cutover_config_backup", "cutover_at",
            )
        }
        if any(not value for value in fields.values()):
            return {"ok": False, "reason_code": "SHADOW_CUTOVER_CONFIG_INCOMPLETE"}
        if fields["cutover_from_config_sha256"] != expected_config_sha256:
            return {"ok": False, "reason_code": "SHADOW_CUTOVER_BASE_MISMATCH"}
        if not SHA256_RE.fullmatch(fields["manifest_sha256"]) or not SHA256_RE.fullmatch(fields["cutover_evidence_sha256"]):
            return {"ok": False, "reason_code": "SHADOW_CUTOVER_DIGEST_INVALID"}
        backup = Path(fields["cutover_config_backup"])
        evidence = Path(fields["cutover_evidence_file"])
        if not _beneath_config_root(backup) or not _beneath_config_root(evidence):
            return {"ok": False, "reason_code": "SHADOW_CUTOVER_PATH_UNSAFE"}
        backup_raw = _regular_bytes(backup)
        evidence_payload, evidence_raw = _json_file(evidence)
        if sha256_bytes(backup_raw) != expected_config_sha256 or sha256_bytes(evidence_raw) != fields["cutover_evidence_sha256"]:
            return {"ok": False, "reason_code": "SHADOW_CUTOVER_EVIDENCE_MISMATCH"}
        binding = runtime_binding()
        if (
            evidence_payload.get("kind") != "cutover-gate"
            or evidence_payload.get("status") != "passed"
            or evidence_payload.get("manifest_sha256") != binding["manifest_sha256"]
            or fields["manifest_sha256"] != binding["manifest_sha256"]
            or fields["runtime_installed_at"] != binding["runtime_installed_at"]
            or evidence_payload.get("production_config_sha256") != expected_config_sha256
        ):
            return {"ok": False, "reason_code": "SHADOW_CUTOVER_RUNTIME_MISMATCH"}
        expected_raw = render_cutover_config(
            backup_raw,
            evidence_sha256=fields["cutover_evidence_sha256"],
            evidence_file=fields["cutover_evidence_file"],
            backup_file=fields["cutover_config_backup"],
            from_config_sha256=fields["cutover_from_config_sha256"],
            shadow_started_at=fields["shadow_started_at"],
            runtime_installed_at=fields["runtime_installed_at"],
            manifest_sha256=fields["manifest_sha256"],
            cutover_at=fields["cutover_at"],
        )
        return {
            "ok": raw == expected_raw,
            "reason_code": "" if raw == expected_raw else "SHADOW_CUTOVER_TRANSFORM_MISMATCH",
            "evidence_sha256": fields["cutover_evidence_sha256"],
        }
    except (KeyError, OSError, ValueError, ShadowGateError):
        return {"ok": False, "reason_code": "SHADOW_CUTOVER_EVIDENCE_INVALID"}


def cutover_active() -> bool:
    try:
        raw = _regular_bytes(config_path())
        config = load_config()
        marker, _marker_raw = _json_file(CONFIG_ROOT / "config" / "runtime-transition.json")
        attestation = marker.get("preflight_attestation")
        expected = str(attestation.get("config_sha256", "")) if isinstance(attestation, dict) else ""
        return bool(expected and verify_cutover_config(raw, config, expected_config_sha256=expected).get("ok"))
    except (OSError, ShadowGateError):
        return False


def _published_config_sha256() -> str:
    marker, _raw = _json_file(CONFIG_ROOT / "config" / "runtime-transition.json")
    attestation = marker.get("preflight_attestation")
    digest = str(attestation.get("config_sha256", "")) if isinstance(attestation, dict) else ""
    if not SHA256_RE.fullmatch(digest):
        raise ShadowGateError("SHADOW_PUBLISHED_CONFIG_ATTESTATION_INVALID")
    return digest


def cutover(*, actor: str, backup_path: str) -> dict[str, Any]:
    if actor != "migration":
        raise ShadowGateError("SHADOW_MUTATION_REQUIRES_MIGRATION_ACTOR")
    with _shadow_start_transaction_lock(), _shadow_activity_lock(exclusive=True):
        return _cutover_locked(backup_path=backup_path)


def _cutover_locked(*, backup_path: str) -> dict[str, Any]:
    """Validate and publish one exact epoch while holding the epoch lock."""

    status = shadow_status()
    if not status["ok"]:
        raise ShadowGateError("SHADOW_GATE_NOT_PASSED")
    target = config_path()
    original = _regular_bytes(target)
    original_sha = sha256_bytes(original)
    if original_sha != status.get("production_config_sha256"):
        raise ShadowGateError("SHADOW_CONFIG_CHANGED_SINCE_START")
    if original_sha != _published_config_sha256():
        raise ShadowGateError("SHADOW_CONFIG_CHANGED_SINCE_RUNTIME_INSTALL")
    backup = Path(backup_path).expanduser().resolve()
    _exclusive_copy(backup, original)
    evidence_payload = {
        "schema_version": 1,
        "kind": "cutover-gate",
        "status": "passed",
        "created_at": utc_now(),
        "shadow_started_at": status["shadow_started_at"],
        "start_attestation_sha256": status["start_attestation_sha256"],
        "epoch_attestation_sha256": status["epoch_attestation_sha256"],
        "epoch_number": status["epoch_number"],
        "benchmark_attestation_count": status["benchmark_attestation_count"],
        "canary_attestation_count": status["canary_attestation_count"],
        "metrics": status["metrics"],
        "minimum_days": status["minimum_days"],
        "elapsed_days": status["elapsed_days"],
        "from_config_sha256": original_sha,
        "production_config_sha256": str(status["production_config_sha256"]),
        "manifest_sha256": status["manifest_sha256"],
        "runtime_installed_at": status["runtime_installed_at"],
    }
    evidence_path, evidence_sha = _exclusive_json("cutover-gate", evidence_payload)
    cutover_at = utc_now()
    migrated = render_cutover_config(
        original,
        evidence_sha256=evidence_sha,
        evidence_file=str(evidence_path),
        backup_file=str(backup),
        from_config_sha256=original_sha,
        shadow_started_at=str(status["shadow_started_at"]),
        runtime_installed_at=str(status["runtime_installed_at"]),
        manifest_sha256=str(status["manifest_sha256"]),
        cutover_at=cutover_at,
    )
    try:
        _atomic_config(migrated, expected=original)
        config = load_config()
        verified = verify_cutover_config(migrated, config, expected_config_sha256=original_sha)
        if not verified.get("ok"):
            raise ShadowGateError(str(verified.get("reason_code") or "SHADOW_CUTOVER_VERIFY_FAILED"))
    except Exception as exc:
        # Roll back only our exact bytes. A concurrent config edit is never
        # overwritten while handling a failed cutover.
        rolled_back = False
        try:
            current = _regular_bytes(target)
            if current == migrated:
                _atomic_config(original, expected=migrated)
                rolled_back = True
            elif current == original:
                rolled_back = True
        except (OSError, ShadowGateError):
            rolled_back = False
        failure = {
            "schema_version": 1,
            "kind": "cutover-failure",
            "created_at": utc_now(),
            "manifest_sha256": status["manifest_sha256"],
            "runtime_installed_at": status["runtime_installed_at"],
            "gate_evidence_sha256": evidence_sha,
            "rolled_back": rolled_back,
            "reason_code": hashlib.sha256(type(exc).__name__.encode("ascii")).hexdigest(),
        }
        _exclusive_json("cutover-failure", failure)
        raise ShadowGateError(
            "SHADOW_CUTOVER_ROLLED_BACK" if rolled_back else "SHADOW_CUTOVER_RECOVERY_REQUIRED"
        ) from exc
    return {
        "ok": True,
        "status": "cutover",
        "ranking_version": "hybrid-v2",
        "stale_adoption_enforcement": "enforce",
        "metadata_enforcement": "enforce",
        "cutover_evidence_sha256": evidence_sha,
        "config_sha256": sha256_bytes(migrated),
        "backup_sha256": original_sha,
    }


def rollback(*, actor: str, backup_path: str) -> dict[str, Any]:
    if actor != "migration":
        raise ShadowGateError("SHADOW_MUTATION_REQUIRES_MIGRATION_ACTOR")
    with _shadow_start_transaction_lock(), _shadow_activity_lock(exclusive=True):
        return _rollback_locked(backup_path=backup_path)


def _rollback_locked(*, backup_path: str) -> dict[str, Any]:
    if not cutover_active():
        raise ShadowGateError("SHADOW_CUTOVER_NOT_ACTIVE")
    target = config_path()
    current = _regular_bytes(target, max_bytes=2 * 1024 * 1024)
    config = load_config()
    shadow = config.get("shadow") if isinstance(config, dict) else None
    if not isinstance(shadow, dict) or shadow.get("status") != "cutover":
        raise ShadowGateError("SHADOW_CUTOVER_NOT_ACTIVE")
    original_sha = str(shadow.get("cutover_from_config_sha256", ""))
    verified = verify_cutover_config(
        current,
        config,
        expected_config_sha256=original_sha,
    )
    if not verified.get("ok"):
        raise ShadowGateError(str(verified.get("reason_code") or "SHADOW_CUTOVER_NOT_ACTIVE"))
    if original_sha != _published_config_sha256():
        raise ShadowGateError("SHADOW_ROLLBACK_BASE_NOT_PUBLISHED")
    original = _verified_private_backup(
        shadow.get("cutover_config_backup", ""),
        expected_sha256=original_sha,
    )
    rollback_backup = Path(backup_path).expanduser().resolve()
    _exclusive_copy(rollback_backup, current)
    restored = False
    try:
        _atomic_config(original, expected=current)
        restored = True
        restored_raw = _regular_bytes(target, max_bytes=2 * 1024 * 1024)
        restored_config = load_config()
        semantic = restored_config.get("semantic_retrieval") if isinstance(restored_config, dict) else None
        observability = restored_config.get("observability") if isinstance(restored_config, dict) else None
        restored_shadow = restored_config.get("shadow") if isinstance(restored_config, dict) else None
        if (
            restored_raw != original
            or sha256_bytes(restored_raw) != original_sha
            or original_sha != _published_config_sha256()
            or not isinstance(semantic, dict)
            or semantic.get("ranking_version") != "hybrid-v2-shadow"
            or not isinstance(observability, dict)
            or observability.get("stale_adoption_enforcement") != "shadow"
            or observability.get("metadata_enforcement") != "shadow"
            or observability.get("enabled") is not True
            or not isinstance(restored_shadow, dict)
            or restored_shadow.get("status") != "observing"
        ):
            raise ShadowGateError("SHADOW_ROLLBACK_RESTORED_BASELINE_INVALID")
        binding = runtime_binding()
        _path, digest = _exclusive_json("cutover-rollback", {
            "schema_version": 1,
            "kind": "cutover-rollback",
            "created_at": utc_now(),
            "cutover_config_sha256": sha256_bytes(current),
            "restored_config_sha256": original_sha,
            **binding,
        })
    except Exception as exc:
        recovered = False
        if restored:
            try:
                latest = _regular_bytes(target, max_bytes=2 * 1024 * 1024)
                if latest == original:
                    _atomic_config(current, expected=original)
                    recovered = True
                elif latest == current:
                    recovered = True
            except (OSError, ShadowGateError):
                recovered = False
        raise ShadowGateError(
            "SHADOW_ROLLBACK_REVERTED" if recovered else "SHADOW_ROLLBACK_RECOVERY_REQUIRED"
        ) from exc
    return {"ok": True, "status": "rolled_back", "rollback_attestation_sha256": digest}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seven-day Hybrid v2 and stale-adoption cutover gate.")
    parser.add_argument("--actor", choices=("codex", "claude", "human", "migration", "test"), default=os.environ.get("MEMORY_ACTOR", "codex"))
    parser.add_argument("--json", action="store_true")
    actions = parser.add_subparsers(dest="action", required=True)
    start = actions.add_parser("start")
    start.add_argument("--min-days", type=int, default=None)
    start.add_argument("--benchmark-file", required=True)
    restart = actions.add_parser("restart")
    restart.add_argument("--benchmark-file", required=True)
    restart.add_argument("--supersede-epoch", required=True)
    actions.add_parser("status")
    actions.add_parser("canary")
    cutover_parser = actions.add_parser("cutover")
    cutover_parser.add_argument("--config-backup", required=True)
    rollback_parser = actions.add_parser("rollback")
    rollback_parser.add_argument("--config-backup", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        assert_runtime_ready("shadow")
        if args.action == "start":
            payload = start_shadow(
                actor=args.actor,
                benchmark_file=args.benchmark_file,
                min_days=args.min_days,
            )
        elif args.action == "restart":
            payload = restart_shadow(
                actor=args.actor,
                benchmark_file=args.benchmark_file,
                supersede_epoch=args.supersede_epoch,
            )
        elif args.action == "status":
            payload = shadow_status()
        elif args.action == "canary":
            payload = run_stale_canary(actor=args.actor)
        elif args.action == "cutover":
            payload = cutover(actor=args.actor, backup_path=args.config_backup)
        else:
            payload = rollback(actor=args.actor, backup_path=args.config_backup)
    except (OSError, ValueError, sqlite3.Error, RuntimeTransitionError, ShadowGateError) as exc:
        reason = str(exc) if isinstance(exc, ShadowGateError) else "SHADOW_GATE_INTERNAL_ERROR"
        payload = {"ok": False, "status": "error", "reason_code": reason}
        if args.json:
            print(json.dumps(payload, ensure_ascii=True, indent=2))
        else:
            print(f"shadow=error reason_code={reason}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(payload, ensure_ascii=True, indent=2))
    else:
        print(f"shadow={payload.get('status', 'ok')}")
    return 0 if payload.get("ok") else 3


if __name__ == "__main__":
    raise SystemExit(main())
