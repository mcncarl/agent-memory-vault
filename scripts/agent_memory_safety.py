#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import re
import sqlite3
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_memory_state import STATE_SCHEMA_VERSION, secure_sqlite_connect


SOURCE_CLASSES = {
    "user_direct",
    "manual_edit",
    "local_verified",
    "external_untrusted",
    "agent_inferred",
    "unknown",
}
KNOWLEDGE_KINDS = {"fact", "preference", "rule", "inference", "hypothesis"}

SECRET_PATTERNS = (
    re.compile(r"(?i)sk-[A-Za-z0-9][A-Za-z0-9_-]{16,}"),
    re.compile(r"(?i)gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"(?i)(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    re.compile(r"(?i)(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"(?i)(?<![A-Za-z0-9])xox[baprs]-[0-9A-Za-z-]{10,}"),
    re.compile(r"(?i)(?<![A-Za-z0-9])(?:glpat-|npm_)[A-Za-z0-9_-]{16,}"),
    re.compile(r"(?i)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    re.compile(r"(?i)\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b"),
    re.compile(
        r"(?im)^\s*authorization\s*:\s*(?:bearer|basic)\s+"
        r"(?!redacted\b|example\b|placeholder\b|your[_-]|<)[A-Za-z0-9._~+/=-]{8,}"
    ),
    re.compile(r"(?im)^\s*(?:cookie|set-cookie)\s*:\s*(?!redacted\b|example\b|placeholder\b|<)\S+"),
    re.compile(
        r"(?i)(?:验证码|短信码|校验码|动态码|一次性密码)\s*[:：=]\s*"
        r"(?!已?脱敏|示例|占位|xxxx|\*{4,})[A-Za-z0-9]{4,10}(?![A-Za-z0-9])"
    ),
    re.compile(
        r"(?im)(?:^|[{,])\s*(?:(?:export|set)\s+)?[\"']?"
        r"(?:[A-Za-z][A-Za-z0-9]*[_-])*"
        r"(?:password|passwd|pwd|api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|"
        r"refresh[_-]?token|bot[_-]?token|client[_-]?secret|app[_-]?secret|secret[_-]?key|"
        r"private[_-]?key|secret|cookie|credential)[\"']?\s*[:=]\s*[\"']?"
        r"(?!redacted\b|example\b|placeholder\b|your[_-]|changeme\b|not-a-secret\b|"
        r"dummy\b|sample\b|fake\b|test\b|<|\*{4,}|/|\.{1,2}/|~/)"
        r"(?![A-Za-z_][A-Za-z0-9_.]*\()"
        r"[^\s\"'`]{4,}"
    ),
    re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|smtps?|ftps?)://"
        r"[^\s/:@]+:(?!(?:password|passwd|secret|redacted|example|placeholder)@)[^@\s/]{3,}@"
    ),
    re.compile(r"(?<!\d)\d{8,12}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"),
)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_for_detection(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(character for character in normalized if unicodedata.category(character) != "Cf")


def bounded_identity_label(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value.strip())
    return re.sub(r"[^A-Za-z0-9._:@-]+", "-", normalized).strip("-")[:80]


def assess_source(
    text: str,
    *,
    source_class: str,
    knowledge_kind: str,
    asserted_by: str = "",
    evidence_ref: str = "",
) -> dict[str, Any]:
    """Classify whether content may proceed to reconciliation.

    This gate deliberately runs before search/reconciliation. It records only
    hashes and bounded labels, never the candidate text or evidence itself.
    """
    source = source_class.strip().lower() or "unknown"
    kind = knowledge_kind.strip().lower() or "fact"
    if source not in SOURCE_CLASSES:
        raise ValueError(f"unsupported source_class: {source}")
    if kind not in KNOWLEDGE_KINDS:
        raise ValueError(f"unsupported knowledge_kind: {kind}")

    decision = "ALLOW"
    reason_code = "SOURCE_ALLOWED"
    non_authoritative = kind in {"inference", "hypothesis"}

    detection_text = normalize_for_detection(text)
    if any(pattern.search(detection_text) for pattern in SECRET_PATTERNS):
        decision = "BLOCK"
        reason_code = "SECRET_MATERIAL"
    elif source == "external_untrusted":
        if kind in {"preference", "rule"}:
            decision = "BLOCK"
            reason_code = "UNTRUSTED_INSTRUCTION_OR_PREFERENCE"
        else:
            decision = "ASK_USER"
            reason_code = "UNTRUSTED_SOURCE_REQUIRES_VERIFICATION"
    elif source == "agent_inferred" and kind in {"fact", "preference", "rule"}:
        decision = "ASK_USER"
        reason_code = "INFERENCE_CANNOT_BECOME_AUTHORITATIVE_FACT"
    elif source == "unknown":
        decision = "ASK_USER"
        reason_code = "SOURCE_UNKNOWN"
    elif source == "local_verified" and kind == "fact" and not evidence_ref.strip():
        decision = "ASK_USER"
        reason_code = "VERIFICATION_EVIDENCE_REQUIRED"

    return {
        "decision": decision,
        "reason_code": reason_code,
        "source_class": source,
        "knowledge_kind": kind,
        "asserted_by": bounded_identity_label(asserted_by),
        "input_sha256": sha256_text(text),
        "input_length": len(text),
        "evidence_ref_sha256": sha256_text(evidence_ref.strip()) if evidence_ref.strip() else "",
        "has_evidence": bool(evidence_ref.strip()),
        "non_authoritative": non_authoritative,
        "can_reconcile": decision == "ALLOW",
        "can_create_intent": decision == "ALLOW",
        "can_authorize_action": False,
    }


def record_assessment(
    state_db: Path,
    assessment: dict[str, Any],
    *,
    run_id: str,
    actor: str,
    session_hash: str,
    trigger: str,
) -> int:
    """Persist a content-free audit row. Candidate text and evidence never enter SQLite."""
    if not state_db.exists():
        raise sqlite3.OperationalError("STATE_SCHEMA_MIGRATION_REQUIRED")
    with secure_sqlite_connect(state_db, timeout=10, create=False) as conn:
        conn.execute("PRAGMA busy_timeout=10000")
        tables = {
            str(row[0])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        required_columns = {
            "id",
            "run_id",
            "actor",
            "session_hash",
            "trigger",
            "decision",
            "reason_code",
            "source_class",
            "knowledge_kind",
            "asserted_by",
            "input_sha256",
            "input_length",
            "evidence_ref_sha256",
            "created_at",
        }
        actual_columns = (
            {
                str(row[1])
                for row in conn.execute("PRAGMA table_info(memory_safety_log)")
            }
            if "memory_safety_log" in tables
            else set()
        )
        state_version = (
            conn.execute(
                "SELECT value FROM meta WHERE key='agent_memory_state_schema_version'"
            ).fetchone()
            if "meta" in tables
            else None
        )
        if (
            "memory_safety_log" not in tables
            or not required_columns.issubset(actual_columns)
            or state_version is None
            or str(state_version[0]) != str(STATE_SCHEMA_VERSION)
        ):
            raise sqlite3.OperationalError("STATE_SCHEMA_MIGRATION_REQUIRED")
        cursor = conn.execute(
            """
            INSERT INTO memory_safety_log (
              run_id, actor, session_hash, trigger, decision, reason_code,
              source_class, knowledge_kind, asserted_by, input_sha256,
              input_length, evidence_ref_sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                actor,
                session_hash,
                trigger,
                str(assessment["decision"]),
                str(assessment["reason_code"]),
                str(assessment["source_class"]),
                str(assessment["knowledge_kind"]),
                sha256_text(str(assessment.get("asserted_by", ""))) if assessment.get("asserted_by") else "",
                str(assessment["input_sha256"]),
                int(assessment["input_length"]),
                str(assessment.get("evidence_ref_sha256", "")),
                datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)
