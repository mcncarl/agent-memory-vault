#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_memory_env import RuntimeTransitionError, assert_runtime_ready, env_value, expand_path
from agent_memory_state import StateSecurityError, absolute_path, secure_sqlite_connect
import agent_memory_index as memory_index


CONFIG_ROOT = expand_path(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory")).resolve()
STATE_DB = absolute_path(expand_path(env_value("STATE_DB", str(CONFIG_ROOT / "state.sqlite"))))
AUDIT_DB = absolute_path(expand_path(env_value("AUDIT_DB", str(CONFIG_ROOT / "audit_decisions.sqlite"))))
INVARIANTS_PATH = expand_path(
    env_value("INVARIANTS", str(CONFIG_ROOT / "config" / "system-invariants.json"))
).resolve()
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = expand_path(env_value("ROOT", str(REPO_ROOT / "templates" / "vault"))).resolve()
AUDIT_SCHEMA_VERSION = 3
AUDIT_SCHEMA_REASON_CODE = "AUDIT_SCHEMA_MIGRATION_REQUIRED"
RECURRENT_FINDING_KINDS = {"memory_expired", "stale_verified_at"}
PATH_TRACK_FLOORS = {"项目": "project", "工作流": "workflow", "决策": "decision"}
PATH_MEMORY_TYPE_FLOORS = {"项目": "project", "工作流": "workflow", "决策": "decision"}
ACTION_SENSITIVE_MEMORY_TYPES = {"fact", "atomic_fact", "current_fact"}


class AuditSchemaMigrationRequired(sqlite3.OperationalError):
    """Stable fail-closed error for an audit ledger needing installer migration."""


@dataclass
class Finding:
    id: str
    kind: str
    severity: str
    rel_path: str
    title: str
    message: str
    detail: dict[str, Any]
    occurrence_token: str = ""

    @property
    def base_fingerprint(self) -> str:
        payload = json.dumps(
            {
                "kind": self.kind,
                "rel_path": self.rel_path,
                "detail": self.detail,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]

    @property
    def occurrence_fingerprint(self) -> str:
        payload = json.dumps(
            {"base_fingerprint": self.base_fingerprint, "occurrence_token": self.occurrence_token},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "severity": self.severity,
            "rel_path": self.rel_path,
            "title": self.title,
            "message": self.message,
            "detail": self.detail,
            "occurrence_fingerprint": self.occurrence_fingerprint,
        }


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def today() -> dt.date:
    return dt.datetime.now().date()


def stable_id(kind: str, *parts: object) -> str:
    raw = "|".join([kind, *[str(part) for part in parts]])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def connect_state() -> sqlite3.Connection:
    return secure_sqlite_connect(
        STATE_DB,
        create=False,
        read_only=True,
        row_factory=sqlite3.Row,
        pragmas=("PRAGMA busy_timeout=10000",),
    )


def assert_audit_schema_ready(conn: sqlite3.Connection) -> None:
    tables = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    if not {"meta", "audit_decisions", "audit_finding_occurrences"}.issubset(tables):
        raise AuditSchemaMigrationRequired(AUDIT_SCHEMA_REASON_CODE)
    columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(audit_decisions)")
    }
    required = {
        "finding_id",
        "decision",
        "occurrence_fingerprint",
        "note",
        "snooze_until",
        "decided_at",
    }
    occurrence_columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(audit_finding_occurrences)")
    }
    required_occurrence_columns = {
        "finding_id",
        "base_fingerprint",
        "occurrence_seq",
        "active",
        "last_seen_cycle",
        "updated_at",
    }
    version = conn.execute(
        "SELECT value FROM meta WHERE key='agent_memory_audit_schema_version'"
    ).fetchone()
    if (
        not required.issubset(columns)
        or not required_occurrence_columns.issubset(occurrence_columns)
        or version is None
        or str(version[0]) != str(AUDIT_SCHEMA_VERSION)
    ):
        raise AuditSchemaMigrationRequired(AUDIT_SCHEMA_REASON_CODE)


def connect_audit(*, read_only: bool = False) -> sqlite3.Connection:
    if not AUDIT_DB.is_file() or AUDIT_DB.is_symlink():
        raise AuditSchemaMigrationRequired(AUDIT_SCHEMA_REASON_CODE)
    conn = secure_sqlite_connect(
        AUDIT_DB,
        create=False,
        read_only=read_only,
        row_factory=sqlite3.Row,
        pragmas=("PRAGMA busy_timeout=10000",),
    )
    assert_audit_schema_ready(conn)
    return conn


def parse_date(value: str) -> dt.date | None:
    raw = str(value or "").strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw) is None:
        return None
    try:
        return dt.date.fromisoformat(raw)
    except ValueError:
        return None


def severity_rank(value: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(value, 0)


def load_invariants() -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "schema_version": 1,
        "system_name": "Agent Memory Vault",
        "memory_root": str(VAULT_ROOT),
        "runtime_root": str(CONFIG_ROOT),
        "canonical_script_prefix": "agent_memory_",
        "shared_tracks": ["user", "project", "workflow", "decision", "routing"],
        "scope_exceptions": [],
        "forbidden_current_summary_patterns": [
            {
                "id": "legacy_codex_script_prefix",
                "pattern": r"codex_memory_",
                "severity": "high",
                "message": "Current summary still references the retired codex_memory_ script prefix.",
            },
            {
                "id": "legacy_codex_runtime_path",
                "pattern": r"\.config/codex-memory",
                "severity": "high",
                "message": "Current summary still references the retired codex-memory runtime path.",
            },
        ],
    }
    try:
        payload = json.loads(INVARIANTS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return defaults
    if not isinstance(payload, dict):
        return defaults
    return {**defaults, **payload}


def add_current_fact_invariant_findings(conn: sqlite3.Connection, findings: list[Finding]) -> None:
    invariants = load_invariants()
    configured_roots = {
        "memory_root": str(VAULT_ROOT),
        "runtime_root": str(CONFIG_ROOT),
    }
    for key, actual in configured_roots.items():
        expected = os.path.expandvars(str(invariants.get(key, "")))
        expected = str(Path(expected).expanduser().resolve()) if expected else ""
        if expected and expected != actual:
            findings.append(
                Finding(
                    id=stable_id("invariant_config_conflict", key),
                    kind="invariant_config_conflict",
                    severity="high",
                    rel_path="",
                    title="System invariant configuration",
                    message=f"Configured {key} does not match the active runtime.",
                    detail={"key": key, "expected": expected, "actual": actual, "invariants_file": str(INVARIANTS_PATH)},
                )
            )
    rows = conn.execute(
        """
        SELECT rel_path, title, summary, track, agent_scope, status
        FROM memory_docs
        WHERE status IN ('active', 'candidate')
        ORDER BY rel_path
        """
    ).fetchall()
    shared_tracks = {str(item) for item in invariants.get("shared_tracks", [])}
    scope_exceptions = {str(item) for item in invariants.get("scope_exceptions", [])}
    for row in rows:
        rel_path = str(row["rel_path"])
        track = str(row["track"] or "")
        scope = str(row["agent_scope"] or "shared")
        if track in shared_tracks and scope != "shared" and rel_path not in scope_exceptions:
            findings.append(
                Finding(
                    id=stable_id("agent_scope_invariant", rel_path),
                    kind="agent_scope_invariant",
                    severity="high",
                    rel_path=rel_path,
                    title=str(row["title"]),
                    message=f"Track {track} should be shared but agent_scope={scope}.",
                    detail={"track": track, "agent_scope": scope, "allowed_exceptions": sorted(scope_exceptions)},
                )
            )

    patterns = invariants.get("forbidden_current_summary_patterns", [])
    for rule in patterns if isinstance(patterns, list) else []:
        if not isinstance(rule, dict) or not rule.get("id") or not rule.get("pattern"):
            continue
        try:
            compiled = re.compile(str(rule["pattern"]), re.IGNORECASE)
        except re.error:
            continue
        for row in rows:
            summary = str(row["summary"] or "")
            if compiled.search(summary):
                rule_id = str(rule["id"])
                findings.append(
                    Finding(
                        id=stable_id("current_summary_invariant", rule_id, row["rel_path"]),
                        kind="current_summary_invariant",
                        severity=str(rule.get("severity", "medium")),
                        rel_path=str(row["rel_path"]),
                        title=str(row["title"]),
                        message=str(rule.get("message") or f"Current summary violates invariant {rule_id}."),
                        detail={"rule_id": rule_id, "pattern": str(rule["pattern"]), "invariants_file": str(INVARIANTS_PATH)},
                    )
                )

    markdown_docs = int(conn.execute("SELECT COUNT(*) FROM memory_docs").fetchone()[0])
    fts_docs = int(conn.execute("SELECT COUNT(DISTINCT path) FROM memory_fts").fetchone()[0])
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    eligible_vector_docs = 0
    indexed_vector_docs = 0
    vector_chunks = 0
    if {"memory_vector_index_state", "memory_vector_chunks"}.issubset(tables):
        eligible_vector_docs = int(
            conn.execute(
                """
                SELECT COUNT(*) FROM memory_docs
                WHERE memory_type NOT IN ('routing','directory_index','template','agent_case_candidate','skill_candidate')
                  AND status NOT IN ('archived','deleted','obsolete','outdated','deprecated','stale')
                  AND sensitivity NOT IN ('secret','credential')
                  AND rel_path NOT LIKE '%/README.md'
                  AND rel_path NOT GLOB '*/_模板*'
                """
            ).fetchone()[0]
        )
        indexed_vector_docs = int(
            conn.execute("SELECT COUNT(*) FROM memory_vector_index_state WHERE status='indexed'").fetchone()[0]
        )
        vector_chunks = int(conn.execute("SELECT COUNT(*) FROM memory_vector_chunks").fetchone()[0])

    for row in rows:
        summary = str(row["summary"] or "")
        sqlite_match = re.search(r"Markdown/SQLite/FTS[^0-9]{0,20}(\d+)/(\d+)/(\d+)", summary, re.IGNORECASE)
        if sqlite_match:
            stated = tuple(int(value) for value in sqlite_match.groups())
            actual = (markdown_docs, markdown_docs, fts_docs)
            if stated != actual:
                findings.append(
                    Finding(
                        id=stable_id("current_metric_conflict", "markdown_sqlite_fts", row["rel_path"]),
                        kind="current_metric_conflict",
                        severity="medium",
                        rel_path=str(row["rel_path"]),
                        title=str(row["title"]),
                        message=f"Current summary says Markdown/SQLite/FTS={stated}, runtime reports {actual}.",
                        detail={"metric": "markdown_sqlite_fts", "stated": stated, "actual": actual},
                    )
                )
        zvec_match = re.search(
            r"Zvec[^0-9]{0,20}(\d+)/(\d+)(?:[^0-9]{0,12}(\d+)\s*(?:个)?(?:当前事实块|事实块|chunks?))?",
            summary,
            re.IGNORECASE,
        )
        if zvec_match and indexed_vector_docs:
            stated_docs = (int(zvec_match.group(1)), int(zvec_match.group(2)))
            stated_chunks = int(zvec_match.group(3)) if zvec_match.group(3) else None
            docs_actual = (indexed_vector_docs, eligible_vector_docs)
            if stated_docs != docs_actual or (stated_chunks is not None and stated_chunks != vector_chunks):
                findings.append(
                    Finding(
                        id=stable_id("current_metric_conflict", "zvec", row["rel_path"]),
                        kind="current_metric_conflict",
                        severity="medium",
                        rel_path=str(row["rel_path"]),
                        title=str(row["title"]),
                        message=f"Current summary says Zvec={stated_docs}, runtime reports {docs_actual} with {vector_chunks} chunks.",
                        detail={
                            "metric": "zvec",
                            "stated_docs": stated_docs,
                            "stated_chunks": stated_chunks,
                            "actual_docs": docs_actual,
                            "actual_chunks": vector_chunks,
                        },
                    )
                )


def add_stale_findings(conn: sqlite3.Connection, findings: list[Finding], fallback_days: int) -> None:
    rows = conn.execute(
        """
        SELECT rel_path, title, status, verified_at, verified_at_source,
               review_after_days, memory_type, track
        FROM memory_docs
        WHERE status IN ('active', 'candidate')
          AND memory_type NOT IN ('routing', 'directory_index', 'template')
        ORDER BY rel_path
        """
    ).fetchall()
    weak_rows = [
        row
        for row in rows
        if str(row["verified_at_source"] or "") in {
            "mtime_fallback",
            "needs_review",
            "document_date_unverified",
        }
    ]
    if weak_rows:
        findings.append(
            Finding(
                id=stable_id("weak_verification_coverage"),
                kind="weak_verification_coverage",
                severity="medium",
                rel_path="",
                title="Verification provenance",
                message=f"{len(weak_rows)} memories still need an explicit provenance decision or fact review.",
                detail={"count": len(weak_rows), "total": len(rows), "sample_paths": [str(row["rel_path"]) for row in weak_rows[:10]]},
            )
        )
    for row in rows:
        source = str(row["verified_at_source"] or "mtime_fallback")
        if source in {
            "mtime_fallback",
            "needs_review",
            "document_date_unverified",
            "structural",
            "snapshot",
        }:
            continue
        verified = parse_date(str(row["verified_at"] or ""))
        if verified is None:
            findings.append(
                Finding(
                    id=stable_id("missing_verified_at", row["rel_path"]),
                    kind="missing_verified_at",
                    severity="medium",
                    rel_path=row["rel_path"],
                    title=row["title"],
                    message="没有 verified_at，之后容易把旧事实当成新事实。",
                    detail={"status": row["status"], "memory_type": row["memory_type"], "track": row["track"]},
                )
            )
            continue
        review_days = int(row["review_after_days"] or fallback_days)
        cutoff = today() - dt.timedelta(days=review_days)
        if verified < cutoff:
            findings.append(
                Finding(
                    id=stable_id("stale_verified_at", row["rel_path"]),
                    kind="stale_verified_at",
                    severity="low",
                    rel_path=row["rel_path"],
                    title=row["title"],
                    message=f"Explicit review date {verified.isoformat()} exceeds the {review_days}-day policy.",
                    detail={"verified_at": verified.isoformat(), "verified_at_source": source, "review_after_days": review_days, "status": row["status"]},
                )
            )


def _audited_path_policy(row: sqlite3.Row) -> dict[str, Any]:
    """Classify one indexed row against its canonical path and live frontmatter."""

    rel_path = str(row["rel_path"] or "")
    relative = Path(rel_path)
    if (
        len(relative.parts) < 2
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.name == "README.md"
        or relative.name.startswith("_模板")
    ):
        return {"reason_codes": [], "risk_class": "", "action_sensitive": False}
    floor_track = PATH_TRACK_FLOORS.get(relative.parts[0], "")
    floor_type = PATH_MEMORY_TYPE_FLOORS.get(relative.parts[0], "")
    if not floor_track:
        return {"reason_codes": [], "risk_class": "", "action_sensitive": False}
    indexed_type = str(row["memory_type"] or "").strip().casefold()
    indexed_track = str(row["track"] or "").strip().casefold()
    reasons: list[str] = []
    if indexed_track != floor_track:
        reasons.append("PATH_TRACK_DOWNGRADE")
    allowed_raised_types = ACTION_SENSITIVE_MEMORY_TYPES | {"decision"}
    if indexed_type not in {floor_type, *allowed_raised_types}:
        reasons.append("PATH_MEMORY_TYPE_DOWNGRADE")

    meta: dict[str, object] = {}
    target = VAULT_ROOT / relative
    try:
        resolved_root = VAULT_ROOT.resolve(strict=True)
        resolved_target = target.resolve(strict=True)
        resolved_target.relative_to(resolved_root)
        metadata = target.lstat()
        if target.is_symlink() or not target.is_file() or metadata.st_size > 2 * 1024 * 1024:
            raise OSError("unsafe audit target")
        meta = memory_index.parse_frontmatter(
            target.read_text(encoding="utf-8", errors="strict")
        )
    except (OSError, UnicodeError, ValueError):
        # Index parity and Doctor report unreadable/missing sources separately.
        # Do not infer a risk declaration from absent bytes.
        meta = {}
    risk_class = memory_index.as_text(meta.get("risk_class")).casefold()
    if risk_class and risk_class not in {"ordinary", "action_sensitive"}:
        reasons.append("RISK_CLASS_INVALID")
    temporal_policy = memory_index.as_text(meta.get("temporal_policy")).casefold() or str(
        row["temporal_policy"] or ""
    ).casefold()
    fact = memory_index.fact_metadata(meta) if meta else {
        "enabled": bool(
            str(row["fact_key"] or "").strip()
            or str(row["valid_from"] or "").strip()
            or str(row["valid_until"] or "").strip()
        )
    }
    effective_type = indexed_type if indexed_type in allowed_raised_types else floor_type
    action_sensitive = bool(
        str(row["status"] or "active").casefold() == "active"
        and (
            risk_class == "action_sensitive"
            or floor_track == "decision"
            or effective_type in ACTION_SENSITIVE_MEMORY_TYPES
            or temporal_policy == "expiring"
            or str(row["valid_until"] or "").strip()
            or bool(fact.get("enabled"))
            or "事实-" in relative.stem
        )
    )
    if action_sensitive and risk_class and risk_class != "action_sensitive":
        reasons.append("RISK_CLASS_DOWNGRADE")
    return {
        "reason_codes": list(dict.fromkeys(reasons)),
        "risk_class": risk_class,
        "action_sensitive": action_sensitive,
        "floor_track": floor_track,
        "floor_type": floor_type,
    }


def _current_raw_sha256(rel_path: str) -> str:
    relative = Path(rel_path)
    if (
        relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        return ""
    target = VAULT_ROOT / relative
    try:
        root = VAULT_ROOT.resolve(strict=True)
        resolved = target.resolve(strict=True)
        resolved.relative_to(root)
        metadata = target.lstat()
        if target.is_symlink() or not target.is_file() or metadata.st_size > 2 * 1024 * 1024:
            return ""
        return hashlib.sha256(target.read_bytes()).hexdigest()
    except (OSError, ValueError):
        return ""


def _durable_fact_evidence_provenance(
    conn: sqlite3.Connection,
    *,
    rel_path: str,
    raw_sha256: str,
) -> dict[str, Any]:
    required = {
        "writer_protocol_version",
        "target_rel_path",
        "outcome",
        "final_raw_sha256",
        "git_commit",
        "source_class",
        "knowledge_kind",
        "asserted_by_sha256",
        "safety_decision",
        "evidence_ref_sha256",
        "created_at",
    }
    if re.fullmatch(r"[0-9a-f]{64}", raw_sha256) is None:
        return {
            "present": False,
            "source": "write_gateway_v2_receipt",
            "reason_code": "CURRENT_CONTENT_HASH_UNAVAILABLE",
            "current_content_bound": False,
            "checked_receipts": 0,
        }
    try:
        tables = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "memory_write_receipts" not in tables:
            raise sqlite3.OperationalError("receipt table missing")
        columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(memory_write_receipts)")
        }
        if not required.issubset(columns):
            raise sqlite3.OperationalError("receipt columns missing")
        rows = conn.execute(
            """
            SELECT writer_protocol_version, outcome, final_raw_sha256,
                   git_commit, source_class, knowledge_kind,
                   asserted_by_sha256, safety_decision, evidence_ref_sha256
            FROM memory_write_receipts
            WHERE target_rel_path=? AND final_raw_sha256=?
            ORDER BY created_at DESC
            LIMIT 32
            """,
            (rel_path, raw_sha256),
        ).fetchall()
    except sqlite3.Error:
        return {
            "present": False,
            "source": "write_gateway_v2_receipt",
            "reason_code": "EVIDENCE_RECEIPT_SCHEMA_UNAVAILABLE",
            "current_content_bound": False,
            "checked_receipts": 0,
        }
    authoritative_sources = {"user_direct", "manual_edit", "local_verified"}
    for row in rows:
        try:
            protocol = int(row["writer_protocol_version"])
        except (KeyError, TypeError, ValueError, IndexError):
            continue
        if (
            protocol == 2
            and str(row["outcome"]) == "completed"
            and str(row["final_raw_sha256"]) == raw_sha256
            and re.fullmatch(r"[0-9a-f]{40,64}", str(row["git_commit"] or ""))
            and str(row["source_class"] or "") in authoritative_sources
            and str(row["knowledge_kind"] or "") == "fact"
            and re.fullmatch(r"[0-9a-f]{64}", str(row["asserted_by_sha256"] or ""))
            and str(row["safety_decision"] or "") == "ALLOW"
            and re.fullmatch(r"[0-9a-f]{64}", str(row["evidence_ref_sha256"] or ""))
        ):
            return {
                "present": True,
                "source": "write_gateway_v2_receipt",
                "reason_code": "",
                "current_content_bound": True,
                "checked_receipts": len(rows),
            }
    return {
        "present": False,
        "source": "write_gateway_v2_receipt",
        "reason_code": "CURRENT_CONTENT_EVIDENCE_RECEIPT_MISSING",
        "current_content_bound": False,
        "checked_receipts": len(rows),
    }


def _action_sensitive_atomic_gap_fields(
    row: sqlite3.Row,
    *,
    evidence_present: bool,
    current_date: dt.date,
) -> list[str]:
    gaps: list[str] = []
    policy = str(row["temporal_policy"] or "").strip().casefold()
    if policy not in {"stable", "reviewable", "expiring"}:
        gaps.append("temporal_policy")
    _fact_key, fact_key_error = memory_index.normalized_fact_key(row["fact_key"])
    if fact_key_error:
        gaps.append("fact_key")
    valid_from = parse_date(str(row["valid_from"] or ""))
    if valid_from is None:
        gaps.append("valid_from")
    verified_at = parse_date(str(row["verified_at"] or ""))
    if (
        verified_at is None
        or str(row["verified_at_source"] or "").casefold() != "frontmatter"
        or verified_at > current_date
        or (valid_from is not None and verified_at < valid_from)
    ):
        gaps.append("verified_at")
    if policy == "expiring":
        valid_until = parse_date(str(row["valid_until"] or ""))
        if valid_until is None or (
            valid_from is not None and valid_until < valid_from
        ):
            gaps.append("valid_until")
    if not evidence_present:
        gaps.append("evidence_provenance")
    return list(dict.fromkeys(gaps))


def add_temporal_policy_findings(conn: sqlite3.Connection, findings: list[Finding]) -> None:
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_docs)")}
    required = {
        "document_date",
        "temporal_policy",
        "temporal_policy_source",
        "review_after_source",
        "track",
        "risk_class",
        "verified_at",
        "verified_at_source",
        "fact_key",
        "valid_from",
        "valid_until",
    }
    if not required.issubset(columns):
        findings.append(
            Finding(
                id=stable_id("temporal_policy_schema_missing"),
                kind="temporal_policy_schema_missing",
                severity="high",
                rel_path="",
                title="Temporal policy schema",
                message="Temporal policy columns are missing from the state-v4 index.",
                detail={"missing_columns": sorted(required - columns)},
            )
        )
        return
    rows = conn.execute(
        """
        SELECT rel_path, title, status, memory_type, track, risk_class, verified_at,
               verified_at_source, document_date, temporal_policy,
               temporal_policy_source, valid_from, valid_until,
               review_after_days, review_after_source, fact_key
        FROM memory_docs
        WHERE status NOT IN ('deleted','obsolete')
        ORDER BY rel_path
        """
    ).fetchall()
    current_date = today()
    path_assessments: dict[str, dict[str, Any]] = {}
    for row in rows:
        rel_path = str(row["rel_path"])
        status = str(row["status"] or "active").casefold()
        policy = str(row["temporal_policy"] or "").casefold()
        policy_source = str(row["temporal_policy_source"] or "inferred")
        verified_at = str(row["verified_at"] or "")
        valid_until = parse_date(str(row["valid_until"] or ""))
        path_assessment = _audited_path_policy(row)
        path_assessments[rel_path] = path_assessment
        supporting = str(row["memory_type"] or "").casefold() in {
            "routing", "directory_index", "template", "governance",
        }
        explicitly_action_sensitive = not supporting and (
            bool(
                status == "active"
                and str(row["risk_class"] or "").casefold()
                == "action_sensitive"
            )
            or memory_index.is_explicitly_action_sensitive(
                status=row["status"],
                memory_type=row["memory_type"],
                temporal_policy=row["temporal_policy"],
                fact_key=row["fact_key"],
                valid_from=row["valid_from"],
                valid_until=row["valid_until"],
                rel_path=row["rel_path"],
            )
            or bool(path_assessment.get("action_sensitive"))
        )
        if explicitly_action_sensitive:
            evidence_provenance = _durable_fact_evidence_provenance(
                conn,
                rel_path=rel_path,
                raw_sha256=_current_raw_sha256(rel_path),
            )
            atomic_gaps = _action_sensitive_atomic_gap_fields(
                row,
                evidence_present=bool(evidence_provenance["present"]),
                current_date=current_date,
            )
            if atomic_gaps:
                findings.append(
                    Finding(
                        id=stable_id("atomic_fact_coverage", rel_path),
                        kind="atomic_fact_coverage",
                        severity="high",
                        rel_path=rel_path,
                        title="Action-sensitive fact coverage",
                        message=(
                            "Active action-sensitive memory lacks a complete atomic fact tuple "
                            "or durable evidence provenance for its current content version."
                        ),
                        detail={
                            "missing_or_invalid": atomic_gaps,
                            "memory_type": str(row["memory_type"] or ""),
                            "temporal_policy": policy,
                            "fact_key_present": bool(str(row["fact_key"] or "").strip()),
                            "valid_from": str(row["valid_from"] or ""),
                            "verified_at": str(row["verified_at"] or ""),
                            "verified_at_source": str(row["verified_at_source"] or ""),
                            "evidence_provenance": evidence_provenance,
                            "document_date_is_verification": False,
                        },
                    )
                )
        path_reasons = list(path_assessment.get("reason_codes", []))
        if path_reasons:
            findings.append(
                Finding(
                    id=stable_id("path_policy_downgrade", rel_path),
                    kind="path_policy_downgrade",
                    severity="high",
                    rel_path=rel_path,
                    title=str(row["title"]),
                    message="Frontmatter lowers the type, track, or risk floor derived from the canonical path.",
                    detail={
                        "reason_codes": path_reasons,
                        "indexed_memory_type": str(row["memory_type"] or ""),
                        "indexed_track": str(row["track"] or ""),
                        "path_memory_type_floor": str(path_assessment.get("floor_type", "")),
                        "path_track_floor": str(path_assessment.get("floor_track", "")),
                    },
                )
            )
        if (
            status == "active"
            and path_assessment.get("floor_track") in {"project", "workflow", "decision"}
            and not str(path_assessment.get("risk_class", ""))
        ):
            findings.append(
                Finding(
                    id=stable_id("risk_class_missing", rel_path),
                    kind="risk_class_missing",
                    severity="medium",
                    rel_path=rel_path,
                    title=str(row["title"]),
                    message="Active governed memory has no explicit risk_class.",
                    detail={
                        "path_track_floor": str(path_assessment.get("floor_track", "")),
                        "action_sensitive": bool(path_assessment.get("action_sensitive")),
                    },
                )
            )
        if status == "active" and policy in {"stable", "reviewable", "expiring"} and not verified_at:
            findings.append(
                Finding(
                    id=stable_id("active_unverified", rel_path),
                    kind="active_unverified",
                    severity="medium",
                    rel_path=rel_path,
                    title=str(row["title"]),
                    message="Active memory has no explicit verification date.",
                    detail={
                        "temporal_policy": policy,
                        "verified_at_source": str(row["verified_at_source"] or ""),
                        "document_date": str(row["document_date"] or ""),
                    },
                )
            )
        if str(row["document_date"] or "") and str(row["verified_at_source"] or "") == "document_date_unverified":
            findings.append(
                Finding(
                    id=stable_id("document_date_unverified", rel_path),
                    kind="document_date_unverified",
                    severity="medium",
                    rel_path=rel_path,
                    title=str(row["title"]),
                    message="A summary date is recorded only as provenance and does not verify this memory.",
                    detail={"document_date": str(row["document_date"])},
                )
            )
        if status == "active" and policy_source != "frontmatter":
            findings.append(
                Finding(
                    id=stable_id("implicit_temporal_policy", rel_path),
                    kind="implicit_temporal_policy",
                    severity="low",
                    rel_path=rel_path,
                    title=str(row["title"]),
                    message="Active memory relies on an inferred temporal policy.",
                    detail={"temporal_policy": policy, "source": policy_source},
                )
            )
        if (
            status == "active"
            and policy in {"stable", "reviewable", "expiring"}
            and str(row["review_after_source"] or "inferred") != "frontmatter"
        ):
            findings.append(
                Finding(
                    id=stable_id("implicit_review_policy", rel_path),
                    kind="implicit_review_policy",
                    severity="low",
                    rel_path=rel_path,
                    title=str(row["title"]),
                    message="Active memory relies on an inferred review interval.",
                    detail={"review_after_days": int(row["review_after_days"] or 0)},
                )
            )
        if valid_until is not None:
            days_left = (valid_until - current_date).days
            if days_left < 0 and status in {"active", "pending_verification", "candidate"}:
                findings.append(
                    Finding(
                        id=stable_id("memory_expired", rel_path),
                        kind="memory_expired",
                        severity="high" if str(row["fact_key"] or "") else "medium",
                        rel_path=rel_path,
                        title=str(row["title"]),
                        message="Memory validity ended and it cannot authorize a current action.",
                        detail={"valid_until": valid_until.isoformat(), "status": status},
                    )
                )
            elif 0 <= days_left <= 30 and status == "active":
                findings.append(
                    Finding(
                        id=stable_id("memory_expiring_soon", rel_path),
                        kind="memory_expiring_soon",
                        severity="low",
                        rel_path=rel_path,
                        title=str(row["title"]),
                        message=f"Memory validity ends in {days_left} day(s).",
                        detail={"valid_until": valid_until.isoformat(), "days_left": days_left},
                    )
                )
        conflicts: list[str] = []
        if policy == "expiring" and valid_until is None:
            conflicts.append("EXPIRING_REQUIRES_VALID_UNTIL")
        if policy == "structural" and (verified_at or str(row["valid_from"] or "") or valid_until):
            conflicts.append("STRUCTURAL_HAS_FACT_DATES")
        if policy == "structural" and explicitly_action_sensitive:
            conflicts.append("ACTION_SENSITIVE_STRUCTURAL_POLICY")
        if policy == "snapshot" and status == "active":
            conflicts.append("ACTIVE_SNAPSHOT")
        if conflicts:
            findings.append(
                Finding(
                    id=stable_id("temporal_policy_conflict", rel_path),
                    kind="temporal_policy_conflict",
                    severity="medium",
                    rel_path=rel_path,
                    title=str(row["title"]),
                    message="Temporal metadata fields conflict with the selected policy.",
                    detail={"reason_codes": conflicts, "temporal_policy": policy},
                )
            )
def add_open_loop_findings(conn: sqlite3.Connection, findings: list[Finding], threshold: int, risk_threshold: int) -> None:
    rows = conn.execute(
        """
        SELECT d.rel_path, d.title, COUNT(*) AS loop_count
        FROM memory_open_loops o
        JOIN memory_docs d ON d.path = o.path
        WHERE o.status='open' AND o.kind='open_loop'
        GROUP BY d.path, d.rel_path, d.title
        HAVING loop_count >= ?
        ORDER BY loop_count DESC, d.rel_path
        """,
        (threshold,),
    ).fetchall()
    for row in rows:
        findings.append(
            Finding(
                id=stable_id("open_loop_count", row["rel_path"]),
                kind="open_loop_count",
                severity="medium",
                rel_path=row["rel_path"],
                title=row["title"],
                message=f"{row['loop_count']} true open-loop items need review.",
                detail={"count": row["loop_count"], "kind": "open_loop"},
            )
        )
    risk_rows = conn.execute(
        """
        SELECT d.rel_path, d.title, COUNT(*) AS risk_count
        FROM memory_open_loops o
        JOIN memory_docs d ON d.path = o.path
        WHERE o.status='open' AND o.kind='risk'
        GROUP BY d.path, d.rel_path, d.title
        HAVING risk_count >= ?
        ORDER BY risk_count DESC, d.rel_path
        """,
        (risk_threshold,),
    ).fetchall()
    for row in risk_rows:
        findings.append(
            Finding(
                id=stable_id("risk_count", row["rel_path"]),
                kind="risk_count",
                severity="medium",
                rel_path=row["rel_path"],
                title=row["title"],
                message=f"{row['risk_count']} risk items need validity review.",
                detail={"count": row["risk_count"], "kind": "risk"},
            )
        )


def add_duplicate_title_findings(conn: sqlite3.Connection, findings: list[Finding]) -> None:
    rows = conn.execute(
        """
        SELECT lower(title) AS normalized_title,
               COUNT(*) AS item_count,
               GROUP_CONCAT(rel_path, ' || ') AS paths,
               GROUP_CONCAT(title, ' || ') AS titles
        FROM memory_docs
        WHERE title IS NOT NULL AND trim(title) != ''
          AND memory_type NOT IN ('directory_index', 'template')
          AND rel_path NOT LIKE '%/README.md'
        GROUP BY normalized_title
        HAVING item_count > 1
        ORDER BY item_count DESC, normalized_title
        """
    ).fetchall()
    for row in rows:
        title = str(row["titles"]).split(" || ", 1)[0]
        findings.append(
            Finding(
                id=stable_id("duplicate_title", row["normalized_title"]),
                kind="duplicate_title",
                severity="low",
                rel_path="",
                title=title,
                message=f"标题重复 {row['item_count']} 次，可能只是 README/模板，也可能是重复事实。",
                detail={"paths": str(row["paths"]).split(" || ")},
            )
        )


def add_outdated_findings(conn: sqlite3.Connection, findings: list[Finding]) -> None:
    rows = conn.execute(
        """
        SELECT rel_path, title, status, verified_at
        FROM memory_docs
        WHERE status IN ('outdated', 'deprecated', 'stale')
        ORDER BY rel_path
        """
    ).fetchall()
    for row in rows:
        findings.append(
            Finding(
                id=stable_id("outdated_status", row["rel_path"], row["status"]),
                kind="outdated_status",
                severity="low",
                rel_path=row["rel_path"],
                title=row["title"],
                message=f"status={row['status']}，检索时需要避免当成当前事实。",
                detail={"verified_at": row["verified_at"]},
            )
        )


def add_temporal_fact_findings(conn: sqlite3.Connection, findings: list[Finding]) -> None:
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {"memory_supersessions", "memory_fact_states"}.issubset(tables):
        findings.append(
            Finding(
                id=stable_id("temporal_fact_schema_missing"),
                kind="temporal_fact_schema_missing",
                severity="high",
                rel_path="",
                title="Current-fact timeline",
                message="Temporal fact projection is missing; superseded facts cannot be filtered safely.",
                detail={},
            )
        )
        return
    fact_count = int(conn.execute("SELECT COUNT(*) FROM memory_fact_states").fetchone()[0])
    if fact_count == 0:
        findings.append(
            Finding(
                id=stable_id("temporal_fact_coverage_empty"),
                kind="temporal_fact_coverage",
                severity="medium",
                rel_path="",
                title="Current-fact timeline coverage",
                message="No one-fact-per-file timeline records exist; legacy documents cannot express explicit supersession yet.",
                detail={"fact_records": 0, "automatic_semantic_migration": False},
            )
        )
    for row in conn.execute(
        """
        SELECT rel_path, fact_key, fact_status, current_rel_path, reason_code
        FROM memory_fact_states
        WHERE fact_status IN ('conflict', 'invalid_metadata', 'invalid_relation', 'no_current')
        ORDER BY rel_path
        """
    ):
        status = str(row["fact_status"])
        findings.append(
            Finding(
                id=stable_id("temporal_fact_state", row["rel_path"], status, row["reason_code"]),
                kind="temporal_fact_state",
                severity="high" if status in {"conflict", "invalid_relation"} else "medium",
                rel_path=str(row["rel_path"]),
                title=str(row["fact_key"]),
                message=f"fact_status={status}; this fact cannot be treated as a resolved current fact.",
                detail={
                    "fact_key": str(row["fact_key"]),
                    "fact_status": status,
                    "current_rel_path": str(row["current_rel_path"] or ""),
                    "reason_code": str(row["reason_code"] or ""),
                },
            )
        )
    for row in conn.execute(
        """
        SELECT source_rel_path, target_rel_path, reason_code
        FROM memory_supersessions
        WHERE relation_status<>'effective'
        ORDER BY source_rel_path, target_rel_path
        """
    ):
        findings.append(
            Finding(
                id=stable_id("invalid_supersession", row["source_rel_path"], row["target_rel_path"]),
                kind="invalid_supersession",
                severity="high",
                rel_path=str(row["source_rel_path"]),
                title="Invalid fact supersession",
                message="An explicit supersession edge is invalid and has not hidden its target.",
                detail={
                    "target_rel_path": str(row["target_rel_path"]),
                    "reason_code": str(row["reason_code"] or ""),
                },
            )
        )


def add_large_file_findings(conn: sqlite3.Connection, findings: list[Finding], line_limit: int, byte_limit: int) -> None:
    rows = conn.execute(
        """
        SELECT rel_path, title, line_count, size_bytes
        FROM memory_docs
        WHERE memory_type NOT IN ('template', 'directory_index')
          AND status IN ('active', 'candidate')
          AND (line_count > ? OR size_bytes > ?)
        ORDER BY size_bytes DESC, line_count DESC
        """,
        (line_limit, byte_limit),
    ).fetchall()
    for row in rows:
        findings.append(
            Finding(
                id=stable_id("large_memory_file", row["rel_path"]),
                kind="large_memory_file",
                severity="low",
                rel_path=row["rel_path"],
                title=row["title"],
                message=f"File has {row['line_count']} lines / {row['size_bytes']} bytes; review current facts versus history.",
                detail={"line_count": row["line_count"], "size_bytes": row["size_bytes"]},
            )
        )


def add_index_parity_findings(conn: sqlite3.Connection, findings: list[Finding]) -> None:
    doc_count = int(conn.execute("SELECT COUNT(*) FROM memory_docs").fetchone()[0])
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in ("memory_fts", "memory_fts_unicode", "memory_fts_trigram"):
        if table not in tables:
            findings.append(
                Finding(
                    id=stable_id("sqlite_fts_missing", table),
                    kind="sqlite_fts_missing",
                    severity="high",
                    rel_path="",
                    title="SQLite/FTS parity",
                    message=f"Required lexical index {table} is missing.",
                    detail={"table": table},
                )
            )
            continue
        fts_count = int(conn.execute(f"SELECT COUNT(DISTINCT path) FROM {table}").fetchone()[0])
        if doc_count != fts_count:
            findings.append(
                Finding(
                    id=stable_id("sqlite_fts_parity", table),
                    kind="sqlite_fts_parity",
                    severity="high",
                    rel_path="",
                    title="SQLite/FTS parity",
                    message=f"SQLite has {doc_count} docs but {table} has {fts_count}.",
                    detail={"memory_docs": doc_count, "fts_docs": fts_count, "table": table},
                )
            )
    if "memory_vector_index_state" not in tables:
        return
    eligible_count = int(
        conn.execute(
            """
            SELECT COUNT(*) FROM memory_docs d
            LEFT JOIN memory_fact_states f ON f.rel_path=d.rel_path
            WHERE d.memory_type NOT IN ('routing','directory_index','template','agent_case_candidate','skill_candidate')
              AND d.status NOT IN ('archived','deleted','obsolete','outdated','deprecated','stale')
              AND d.sensitivity NOT IN ('secret','credential')
              AND d.rel_path NOT LIKE '%/README.md'
              AND d.rel_path NOT GLOB '*/_模板*'
              AND (f.rel_path IS NULL OR f.fact_status='current')
            """
        ).fetchone()[0]
    )
    vector_count = int(conn.execute("SELECT COUNT(*) FROM memory_vector_index_state WHERE status='indexed'").fetchone()[0])
    state_count = int(conn.execute("SELECT COUNT(*) FROM memory_vector_index_state").fetchone()[0])
    if state_count == 0:
        return
    if eligible_count != vector_count:
        findings.append(
            Finding(
                id=stable_id("zvec_parity"), kind="zvec_parity", severity="high",
                rel_path="", title="Zvec parity",
                message=f"Expected {eligible_count} semantic docs but found {vector_count} indexed docs.",
                detail={"eligible_docs": eligible_count, "indexed_docs": vector_count},
            )
        )
    hash_mismatches = [
        str(row[0])
        for row in conn.execute(
            """
            SELECT d.rel_path
            FROM memory_docs d
            JOIN memory_vector_index_state v ON v.path=d.path
            WHERE v.status='indexed' AND coalesce(v.doc_sha256, '') != d.sha256
            ORDER BY d.rel_path
            """
        ).fetchall()
    ]
    if hash_mismatches:
        findings.append(
            Finding(
                id=stable_id("zvec_hash_parity"),
                kind="zvec_hash_parity",
                severity="high",
                rel_path="",
                title="Zvec hash parity",
                message=f"{len(hash_mismatches)} semantic documents are older than their Markdown source.",
                detail={"hash_mismatch": hash_mismatches},
            )
        )


def load_decisions(conn: sqlite3.Connection) -> dict[str, sqlite3.Row]:
    rows = conn.execute("SELECT * FROM audit_decisions").fetchall()
    return {row["finding_id"]: row for row in rows}


def occurrence_cycle(value: dt.date | None = None) -> str:
    iso = (value or today()).isocalendar()
    return f"{iso.year:04d}-W{iso.week:02d}"


def reconcile_occurrences(
    conn: sqlite3.Connection,
    findings: list[Finding],
    *,
    cycle: str | None = None,
) -> None:
    """Bind a stable finding key to a recurrence-aware occurrence epoch."""

    assert_audit_schema_ready(conn)
    current_cycle = cycle or occurrence_cycle()
    current_ids = {finding.id for finding in findings}
    conn.execute("BEGIN IMMEDIATE")
    try:
        if current_ids:
            placeholders = ",".join("?" for _ in current_ids)
            conn.execute(
                f"UPDATE audit_finding_occurrences SET active=0, updated_at=? "
                f"WHERE active=1 AND finding_id NOT IN ({placeholders})",
                (utc_now(), *sorted(current_ids)),
            )
        else:
            conn.execute(
                "UPDATE audit_finding_occurrences SET active=0, updated_at=? WHERE active=1",
                (utc_now(),),
            )
        for finding in findings:
            row = conn.execute(
                "SELECT base_fingerprint, occurrence_seq, active, last_seen_cycle "
                "FROM audit_finding_occurrences WHERE finding_id=?",
                (finding.id,),
            ).fetchone()
            sequence = 1
            if row is not None:
                sequence = max(1, int(row["occurrence_seq"] or 1))
                if (
                    not bool(row["active"])
                    or str(row["base_fingerprint"] or "") != finding.base_fingerprint
                    or (
                        finding.kind in RECURRENT_FINDING_KINDS
                        and str(row["last_seen_cycle"] or "") != current_cycle
                    )
                ):
                    sequence += 1
            finding.occurrence_token = f"occurrence-{sequence}"
            conn.execute(
                """
                INSERT INTO audit_finding_occurrences(
                  finding_id, base_fingerprint, occurrence_seq, active,
                  last_seen_cycle, updated_at
                ) VALUES (?, ?, ?, 1, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                  base_fingerprint=excluded.base_fingerprint,
                  occurrence_seq=excluded.occurrence_seq,
                  active=1,
                  last_seen_cycle=excluded.last_seen_cycle,
                  updated_at=excluded.updated_at
                """,
                (
                    finding.id,
                    finding.base_fingerprint,
                    sequence,
                    current_cycle,
                    utc_now(),
                ),
            )
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


def decision_hides(row: sqlite3.Row, finding: Finding) -> bool:
    # A decision is scoped to one concrete occurrence.  A stable finding id
    # intentionally survives recurrence, while the occurrence fingerprint
    # changes when the underlying dates/content change.  Legacy decisions have
    # no fingerprint and therefore never hide a newly observed occurrence.
    if str(row["occurrence_fingerprint"] or "") != finding.occurrence_fingerprint:
        return False
    decision = str(row["decision"])
    if decision in {"ack", "ignored", "resolved"}:
        return True
    if decision == "snoozed":
        snooze_until = parse_date(str(row["snooze_until"] or ""))
        return bool(snooze_until and snooze_until >= today())
    return False


def apply_decisions(findings: list[Finding], decisions: dict[str, sqlite3.Row], include_acknowledged: bool) -> list[Finding]:
    if include_acknowledged:
        return findings
    visible: list[Finding] = []
    for finding in findings:
        decision = decisions.get(finding.id)
        if decision is not None and decision_hides(decision, finding):
            continue
        visible.append(finding)
    return visible


def collect_raw_findings(args: argparse.Namespace) -> list[Finding]:
    if not STATE_DB.exists():
        raise sqlite3.OperationalError("STATE_SCHEMA_MIGRATION_REQUIRED")
    findings: list[Finding] = []
    with connect_state() as conn:
        add_stale_findings(conn, findings, args.stale_days)
        add_temporal_policy_findings(conn, findings)
        add_open_loop_findings(conn, findings, args.open_loop_threshold, args.risk_threshold)
        add_duplicate_title_findings(conn, findings)
        add_outdated_findings(conn, findings)
        add_temporal_fact_findings(conn, findings)
        add_large_file_findings(conn, findings, args.large_file_line_limit, args.large_file_byte_limit)
        add_index_parity_findings(conn, findings)
        add_current_fact_invariant_findings(conn, findings)
    findings.sort(key=lambda item: (severity_rank(item.severity), item.kind, item.rel_path), reverse=True)
    return findings


def collect_findings(args: argparse.Namespace) -> list[Finding]:
    findings = collect_raw_findings(args)
    with connect_audit() as audit_conn:
        reconcile_occurrences(audit_conn, findings)
        decisions = load_decisions(audit_conn)
    return apply_decisions(findings, decisions, args.include_acknowledged)[: args.limit]


def record_decision(args: argparse.Namespace) -> dict[str, Any] | None:
    actions = [
        ("ack", args.ack),
        ("ignored", args.ignore),
        ("resolved", args.resolve),
        ("snoozed", args.snooze),
    ]
    selected = [(decision, finding_id) for decision, finding_id in actions if finding_id]
    if not selected:
        return None
    decision, finding_id = selected[0]
    with connect_audit() as conn:
        raw_findings = collect_raw_findings(args)
        reconcile_occurrences(conn, raw_findings)
        matching = next((finding for finding in raw_findings if finding.id == finding_id), None)
        if matching is None:
            raise ValueError("AUDIT_FINDING_NOT_CURRENT")
        conn.execute(
            """
            INSERT INTO audit_decisions(
              finding_id, decision, occurrence_fingerprint, note,
              snooze_until, decided_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
              decision=excluded.decision,
              occurrence_fingerprint=excluded.occurrence_fingerprint,
              note=excluded.note,
              snooze_until=excluded.snooze_until,
              decided_at=excluded.decided_at
            """,
            (
                finding_id,
                decision,
                matching.occurrence_fingerprint,
                args.note,
                args.until or "",
                utc_now(),
            ),
        )
    return {
        "finding_id": finding_id,
        "decision": decision,
        "occurrence_fingerprint": matching.occurrence_fingerprint,
        "note": args.note,
        "snooze_until": args.until or "",
    }


def list_decisions() -> list[dict[str, Any]]:
    with connect_audit(read_only=True) as conn:
        rows = conn.execute(
            """
            SELECT finding_id, decision, occurrence_fingerprint, note,
                   snooze_until, decided_at
            FROM audit_decisions ORDER BY decided_at DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def print_human(payload: dict[str, Any]) -> None:
    if payload.get("recorded"):
        item = payload["recorded"]
        print(f"recorded={item['finding_id']} decision={item['decision']}")
    if payload.get("decisions") is not None:
        print(f"decisions={len(payload['decisions'])}")
        for item in payload["decisions"]:
            print(f"{item['finding_id']} {item['decision']} until={item.get('snooze_until', '')} note={item.get('note', '')}")
        return
    findings = payload.get("findings", [])
    print(f"audit_findings={len(findings)}")
    print(f"audit_db={AUDIT_DB}")
    for finding in findings:
        print(f"{finding['id']} [{finding['severity']}] {finding['kind']}")
        target = finding.get("rel_path") or finding.get("title")
        print(f"  target: {target}")
        print(f"  message: {finding['message']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit Agent Memory for stale facts, noisy loops, and duplicates.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--limit", type=int, default=50, help="Maximum visible findings.")
    parser.add_argument("--stale-days", type=int, default=180, help="Fallback review period.")
    parser.add_argument("--open-loop-threshold", type=int, default=4, help="Flag docs with at least this many open-loop indexed items.")
    parser.add_argument("--risk-threshold", type=int, default=3, help="Flag docs with at least this many risk items.")
    parser.add_argument("--large-file-line-limit", type=int, default=180, help="Advisory line threshold.")
    parser.add_argument("--large-file-byte-limit", type=int, default=24576, help="Advisory byte threshold.")
    parser.add_argument("--include-acknowledged", action="store_true", help="Show findings already ignored/resolved/snoozed.")
    parser.add_argument("--list-decisions", action="store_true", help="List audit decisions.")
    parser.add_argument("--ack", default="", help="Mark a finding as acknowledged.")
    parser.add_argument("--ignore", default="", help="Hide a finding as intentionally ignored.")
    parser.add_argument("--resolve", default="", help="Hide a finding as resolved.")
    parser.add_argument("--snooze", default="", help="Hide a finding until --until.")
    parser.add_argument("--until", default="", help="YYYY-MM-DD date for --snooze.")
    parser.add_argument("--note", default="", help="Optional decision note.")
    args = parser.parse_args()
    args.limit = max(args.limit, 1)
    args.stale_days = max(args.stale_days, 1)
    args.open_loop_threshold = max(args.open_loop_threshold, 1)
    args.risk_threshold = max(args.risk_threshold, 1)
    args.large_file_line_limit = max(args.large_file_line_limit, 1)
    args.large_file_byte_limit = max(args.large_file_byte_limit, 1)
    if args.snooze and not parse_date(args.until):
        parser.error("--snooze requires --until YYYY-MM-DD")
    decision_count = sum(bool(value) for value in (args.ack, args.ignore, args.resolve, args.snooze))
    if decision_count > 1:
        parser.error("choose only one decision action")
    return args


def main() -> int:
    args = parse_args()
    try:
        assert_runtime_ready("audit")
    except RuntimeTransitionError:
        payload = {
            "time": utc_now(),
            "audit_db": str(AUDIT_DB),
            "recorded": False,
            "findings": [],
            "summary": {"total": 0},
            "ok": False,
            "reason_code": "RUNTIME_TRANSITION_INCOMPLETE",
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("audit_error=RUNTIME_TRANSITION_INCOMPLETE")
        return 2
    try:
        recorded = record_decision(args)
        payload: dict[str, Any] = {
            "time": utc_now(),
            "audit_db": str(AUDIT_DB),
            "recorded": recorded,
            "ok": True,
        }
        if args.list_decisions:
            payload["decisions"] = list_decisions()
        else:
            findings = collect_findings(args)
            payload["findings"] = [finding.to_dict() for finding in findings]
            payload["summary"] = {
                "total": len(findings),
                "by_severity": {severity: sum(1 for item in findings if item.severity == severity) for severity in ("high", "medium", "low")},
                "by_kind": {kind: sum(1 for item in findings if item.kind == kind) for kind in sorted({item.kind for item in findings})},
            }
    except AuditSchemaMigrationRequired:
        payload = {
            "time": utc_now(),
            "audit_db": str(AUDIT_DB),
            "recorded": False,
            "findings": [],
            "summary": {"total": 0},
            "ok": False,
            "degraded": True,
            "reason_code": AUDIT_SCHEMA_REASON_CODE,
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"audit_error={AUDIT_SCHEMA_REASON_CODE}")
        return 2
    except (sqlite3.Error, StateSecurityError):
        payload = {
            "time": utc_now(),
            "audit_db": str(AUDIT_DB),
            "recorded": False,
            "findings": [],
            "summary": {"total": 0},
            "ok": False,
            "degraded": True,
            "reason_code": "STATE_SCHEMA_MIGRATION_REQUIRED",
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("audit_error=STATE_SCHEMA_MIGRATION_REQUIRED")
        return 2
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_human(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
