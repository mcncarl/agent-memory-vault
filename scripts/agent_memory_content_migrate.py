#!/usr/bin/env python3
"""Reviewed batch orchestration for deterministic scope-metadata migration.

This script never edits Markdown or SQLite directly.  Doctor supplies the
bounded migration query; every target is then read, prepared, and applied only
through the installed ``memoryctl write`` gateway.  A private review document
binds the whole query and every target baseline.  Apply keeps an append-only
private progress journal so an interrupted prepared/apply hand-off can resume
with the same intent and fence.  It never fabricates a user confirmation: a
prepared item pauses until a separately issued capability is supplied through
the private capability environment hand-off.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import unicodedata
import uuid
from pathlib import Path
from typing import Any, Callable

import agent_memory_confirmation_capability as confirmation_capability
import agent_memory_closeout as memory_closeout
import agent_memory_index as memory_index
import agent_memory_intent as write_intent
import agent_memory_write as write_gateway
from agent_memory_confirmation_capability import (
    CAPABILITY_PATH_ENV as CONFIRMATION_CAPABILITY_PATH_ENV,
    CAPABILITY_TOKEN_ENV as CONFIRMATION_CAPABILITY_TOKEN_ENV,
)

try:  # pragma: no cover - exercised by native POSIX jobs.
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

try:  # pragma: no cover - exercised by native Windows jobs.
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None  # type: ignore[assignment]


SCHEMA_VERSION = 1
WIRE_SCHEMA_VERSION = 2
LEGACY_SCOPE_MODE = "legacy-scope"
GOVERNANCE_V4_MODE = "governance-v4"
RISK_V4_MODE = "risk-v4"
MIGRATION_MODES = {LEGACY_SCOPE_MODE, GOVERNANCE_V4_MODE, RISK_V4_MODE}
REVIEW_KIND = "agent-memory-content-migration-review"
PROGRESS_KIND = "agent-memory-content-migration-progress"
MAX_REVIEW_BYTES = 16 * 1024 * 1024
MAX_STDIN_BYTES = 16 * 1024
PRIVATE_FILE_MODE = 0o600
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
GIT_HEAD_RE = re.compile(r"[0-9a-f]{40,64}\Z")
IDENTIFIER_RE = re.compile(r"[0-9a-f]{32}\Z")
TARGET_RE = re.compile(r"[^\x00\r\n]{1,512}\Z")
MEMORYCTL = Path(__file__).resolve().parent / "memoryctl"
ATOMIC_FACT_GAP_FIELDS = {
    "temporal_policy",
    "fact_key",
    "valid_from",
    "valid_until",
    "verified_at",
    "evidence_provenance",
}
GOVERNANCE_OWNER_LANE_POLICY = "agent_scope_owner_v1"
GOVERNANCE_OWNER_SCOPES = {"shared", "codex", "claude"}
PREFLIGHT_GOVERNANCE_DEBT_SCHEMA_VERSION = 1


class ContentMigrationError(RuntimeError):
    def __init__(self, reason_code: str, stage: str, detail: str = "") -> None:
        super().__init__(detail or reason_code)
        self.reason_code = reason_code
        self.stage = stage
        self.target_relative_path = detail if TARGET_RE.fullmatch(detail) else ""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def strict_json_loads(payload: str | bytes) -> Any:
    def object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> Any:
        raise ValueError("non-finite JSON number")

    return json.loads(
        payload,
        object_pairs_hook=object_without_duplicates,
        parse_constant=reject_constant,
    )


def _bounded_string(value: Any, code: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise ContentMigrationError(code, "doctor-query")
    text = value.strip()
    if not text or len(text) > maximum or "\x00" in text or "\r" in text or "\n" in text:
        raise ContentMigrationError(code, "doctor-query")
    return text


def _deep_json(value: Any, code: str) -> Any:
    try:
        return strict_json_loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise ContentMigrationError(code, "doctor-query") from exc


def _normalized_agent_scope(value: Any) -> str:
    if not isinstance(value, str):
        raise ContentMigrationError("MIGRATION_SCOPE_INVALID", "doctor-query")
    normalized = unicodedata.normalize("NFKC", value.strip()).casefold()
    if (
        len(normalized) > 160
        or any(character in normalized for character in (",", "|", "[", "]", "{", "}", "\x00", "\n", "\r"))
    ):
        raise ContentMigrationError("MIGRATION_SCOPE_INVALID", "doctor-query")
    return normalized


def _governance_owner_actor(record: dict[str, Any]) -> str:
    scope = _normalized_agent_scope(record.get("requested_agent_scope"))
    if scope in {"shared", "codex"}:
        return "codex"
    if scope == "claude":
        return "claude"
    return ""


def _record_is_in_owner_lane(record: dict[str, Any], actor: str) -> bool:
    return _governance_owner_actor(record) == actor


def _unassigned_manual_review_count(binding: dict[str, Any]) -> int:
    """Count manual debt that cannot safely be assigned to either host lane."""

    return sum(
        1
        for record in binding["manual_review_queue"]
        if isinstance(record, dict) and not _governance_owner_actor(record)
    ) + len(binding["unsafe_documents"])


def _scope_check(doctor: dict[str, Any]) -> dict[str, Any]:
    checks = doctor.get("checks")
    if not isinstance(checks, list):
        raise ContentMigrationError("DOCTOR_JSON_INVALID", "doctor")
    matches = [item for item in checks if isinstance(item, dict) and item.get("name") == "legacy_scope_documents"]
    if len(matches) != 1 or not isinstance(matches[0].get("detail"), dict):
        raise ContentMigrationError("DOCTOR_SCOPE_CHECK_INVALID", "doctor")
    return matches[0]


def normalize_doctor_query(
    doctor: dict[str, Any],
    *,
    require_all_automatable: bool,
) -> dict[str, Any]:
    """Validate and canonicalize the exact Doctor migration query."""

    check = _scope_check(doctor)
    detail = check["detail"]
    if detail.get("migration_query_schema_version") != 1:
        raise ContentMigrationError("MIGRATION_QUERY_SCHEMA_UNSUPPORTED", "doctor-query")
    count_fields: dict[str, int] = {}
    for key in (
        "legacy_scope_documents",
        "automatable_documents",
        "manual_review_documents",
    ):
        value = detail.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ContentMigrationError("MIGRATION_QUERY_COUNTS_INVALID", "doctor-query")
        count_fields[key] = value
    unsafe = detail.get("unsafe_documents", [])
    query = detail.get("migration_query")
    if not isinstance(unsafe, list) or not isinstance(query, list):
        raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")

    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in query:
        if not isinstance(raw, dict):
            raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")
        target = _bounded_string(raw.get("target_relative_path"), "MIGRATION_TARGET_INVALID")
        if TARGET_RE.fullmatch(target) is None or target in seen:
            raise ContentMigrationError("MIGRATION_TARGET_DUPLICATE", "doctor-query")
        seen.add(target)
        if (
            raw.get("migrate_action") != "MIGRATE_LEGACY_SCOPE"
            or raw.get("migrate_legacy_scope") is not True
        ):
            raise ContentMigrationError("MIGRATION_ACTION_INVALID", "doctor-query")
        requested_app_id = _bounded_string(raw.get("requested_app_id"), "MIGRATION_SCOPE_INVALID", maximum=160)
        requested_project_id = _bounded_string(raw.get("requested_project_id"), "MIGRATION_SCOPE_INVALID", maximum=160)
        legacy_scope_app_id = _bounded_string(raw.get("legacy_scope_app_id"), "MIGRATION_SCOPE_INVALID", maximum=160)
        if requested_app_id.casefold() != legacy_scope_app_id.casefold():
            raise ContentMigrationError("MIGRATION_SCOPE_INVALID", "doctor-query")
        automatable = raw.get("automatable")
        manual_reasons = raw.get("manual_review_reasons")
        issues = raw.get("issues")
        if not isinstance(automatable, bool) or not isinstance(manual_reasons, list) or not isinstance(issues, dict):
            raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")
        if require_all_automatable and (not automatable or manual_reasons):
            raise ContentMigrationError("NONAUTOMATABLE_MIGRATION_PRESENT", "doctor-query")
        record = _deep_json(raw, "MIGRATION_QUERY_INVALID")
        record["target_relative_path"] = target
        record["requested_app_id"] = requested_app_id.casefold()
        record["requested_project_id"] = requested_project_id.casefold()
        record["legacy_scope_app_id"] = legacy_scope_app_id.casefold()
        normalized.append(record)
    normalized.sort(key=lambda item: str(item["target_relative_path"]))

    automatable = sum(1 for item in normalized if item.get("automatable") is True)
    manual_in_query = sum(1 for item in normalized if item.get("automatable") is not True)
    if automatable != count_fields["automatable_documents"]:
        raise ContentMigrationError("MIGRATION_QUERY_COUNTS_INVALID", "doctor-query")
    if count_fields["legacy_scope_documents"] != len(normalized) + len(unsafe):
        raise ContentMigrationError("MIGRATION_QUERY_COUNTS_INVALID", "doctor-query")
    if count_fields["manual_review_documents"] != manual_in_query + len(unsafe):
        raise ContentMigrationError("MIGRATION_QUERY_COUNTS_INVALID", "doctor-query")
    if require_all_automatable and (unsafe or count_fields["manual_review_documents"]):
        raise ContentMigrationError("NONAUTOMATABLE_MIGRATION_PRESENT", "doctor-query")

    binding = {
        "policy": str(detail.get("policy", "")),
        "migration_query_schema_version": 1,
        **count_fields,
        "unsafe_documents": _deep_json(unsafe, "MIGRATION_QUERY_INVALID"),
        "migration_query": normalized,
    }
    binding["migration_query_sha256"] = canonical_sha256(normalized)
    return binding


def _governance_check(doctor: dict[str, Any]) -> dict[str, Any]:
    checks = doctor.get("checks")
    if not isinstance(checks, list):
        raise ContentMigrationError("DOCTOR_JSON_INVALID", "doctor")
    matches = [
        item
        for item in checks
        if isinstance(item, dict) and item.get("name") == "governance_metadata_v4"
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("detail"), dict):
        raise ContentMigrationError("DOCTOR_GOVERNANCE_CHECK_INVALID", "doctor")
    return matches[0]


def _governance_atomic_contract_shape_valid(raw: dict[str, Any]) -> bool:
    basis = raw.get("verification_basis")
    gaps = raw.get("atomic_fact_gap_fields")
    evidence = raw.get("durable_evidence_provenance")
    recommendation = raw.get("risk_recommendation")
    manual_reasons = raw.get("manual_review_reasons")
    try:
        requested_agent_scope = _normalized_agent_scope(
            raw.get("requested_agent_scope")
        )
    except ContentMigrationError:
        return False
    if (
        not isinstance(basis, dict)
        or basis.get("document_date_is_verification") is not False
        or not isinstance(raw.get("action_sensitive"), bool)
        or not isinstance(raw.get("atomic_fact_gap"), bool)
        or not isinstance(gaps, list)
        or not all(
            isinstance(value, str) and value in ATOMIC_FACT_GAP_FIELDS
            for value in gaps
        )
        or len(gaps) != len(set(gaps))
        or bool(gaps) is not raw.get("atomic_fact_gap")
        or not isinstance(evidence, dict)
        or not isinstance(evidence.get("present"), bool)
        or evidence.get("source") != "write_gateway_v2_receipt"
        or not isinstance(evidence.get("reason_code"), str)
        or not isinstance(evidence.get("current_content_bound"), bool)
        or not isinstance(evidence.get("checked_receipts"), int)
        or isinstance(evidence.get("checked_receipts"), bool)
        or int(evidence.get("checked_receipts", -1)) < 0
        or (
            evidence.get("present") is True
            and (
                evidence.get("current_content_bound") is not True
                or evidence.get("reason_code") != ""
            )
        )
        or (
            raw.get("action_sensitive") is True
            and (
                (evidence.get("present") is not True)
                != ("evidence_provenance" in gaps)
            )
        )
        or not isinstance(recommendation, dict)
        or not isinstance(manual_reasons, list)
        or any(not isinstance(value, str) for value in manual_reasons)
        or raw.get("requested_agent_scope") != requested_agent_scope
        or (
            requested_agent_scope not in GOVERNANCE_OWNER_SCOPES
            and (
                raw.get("automatable") is True
                or recommendation.get("automatable_now") is True
                or "SCOPE_REVIEW_REQUIRED" not in manual_reasons
            )
        )
    ):
        return False
    reasons = recommendation.get("reason_codes")
    source_status = recommendation.get("source_status")
    expected_recommendation_keys = {
        "source_status",
        "current",
        "recommended",
        "reason_codes",
        "followup_operation",
        "target_status",
        "automatable_after_governance",
        "automatable_now",
        "manual_review_required",
        "governance_migration_may_apply",
    }
    if (
        set(recommendation) != expected_recommendation_keys
        or not isinstance(reasons, list)
        or not all(isinstance(value, str) and value for value in reasons)
        or len(reasons) != len(set(reasons))
        or not isinstance(source_status, str)
        or (
            source_status != ""
            and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", source_status) is None
        )
        or not isinstance(recommendation.get("current"), str)
        or not isinstance(recommendation.get("recommended"), str)
        or recommendation.get("followup_operation")
        not in {"none", "content_update", "status_transition"}
        or not isinstance(recommendation.get("target_status"), str)
        or any(
            not isinstance(recommendation.get(key), bool)
            for key in (
                "automatable_after_governance",
                "automatable_now",
                "manual_review_required",
                "governance_migration_may_apply",
            )
        )
        or recommendation.get("governance_migration_may_apply") is not False
        or (
            recommendation.get("followup_operation") == "status_transition"
            and recommendation.get("target_status") != "pending_verification"
        )
        or (
            recommendation.get("followup_operation") != "status_transition"
            and recommendation.get("target_status") != ""
        )
    ):
        return False
    has_atomic_reason = "ACTION_SENSITIVE_ATOMIC_GAP" in reasons
    classification_conflict = bool(
        {"METADATA_RISK_CLASS_INVALID", "METADATA_RISK_CLASS_DOWNGRADE"}
        & set(reasons)
    )
    if has_atomic_reason and not gaps:
        return False
    return bool(
        not raw.get("action_sensitive")
        or not gaps
        or has_atomic_reason
        or classification_conflict
    )


def normalize_governance_doctor_query(doctor: dict[str, Any]) -> dict[str, Any]:
    """Validate the mixed automatic/manual v4 governance query."""

    detail = _governance_check(doctor)["detail"]
    if (
        detail.get("policy") != "governance_metadata_v4"
        or detail.get("migration_query_schema_version") != 4
        or detail.get("ordinary_document_dates_never_verify") is not True
    ):
        raise ContentMigrationError("MIGRATION_QUERY_SCHEMA_UNSUPPORTED", "doctor-query")
    counts: dict[str, int] = {}
    for key in (
        "governed_documents",
        "migration_candidate_documents",
        "automatable_documents",
        "manual_review_documents",
        "risk_candidate_documents",
        "risk_automatable_documents",
        "risk_manual_review_documents",
        "clean_documents",
    ):
        value = detail.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ContentMigrationError("MIGRATION_QUERY_COUNTS_INVALID", "doctor-query")
        counts[key] = value
    query = detail.get("migration_query")
    documents = detail.get("documents")
    manual_queue = detail.get("manual_review_queue")
    risk_queue = detail.get("risk_migration_query")
    unsafe = detail.get("unsafe_documents")
    if not all(
        isinstance(value, list)
        for value in (query, documents, manual_queue, risk_queue, unsafe)
    ):
        raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")

    normalized_query: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in query:
        if not isinstance(raw, dict):
            raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")
        target = _bounded_string(
            raw.get("target_relative_path"),
            "MIGRATION_TARGET_INVALID",
        )
        if target in seen or TARGET_RE.fullmatch(target) is None:
            raise ContentMigrationError("MIGRATION_TARGET_DUPLICATE", "doctor-query")
        seen.add(target)
        if raw.get("operation") != "governance_migration":
            raise ContentMigrationError("MIGRATION_ACTION_INVALID", "doctor-query")
        agent_scope = _normalized_agent_scope(
            raw.get("requested_agent_scope")
        )
        app_id = _bounded_string(
            raw.get("requested_app_id"),
            "MIGRATION_SCOPE_INVALID",
            maximum=160,
        ).casefold()
        project_id = _bounded_string(
            raw.get("requested_project_id"),
            "MIGRATION_SCOPE_INVALID",
            maximum=160,
        ).casefold()
        candidate = raw.get("candidate_metadata")
        missing = raw.get("missing_fields")
        invalid = raw.get("invalid_fields")
        manual_reasons = raw.get("manual_review_reasons")
        current_memory_id = raw.get("current_memory_id")
        if (
            not isinstance(candidate, dict)
            or not candidate
            or set(candidate) - {"memory_id", "temporal_policy", "review_after_days"}
            or not isinstance(missing, list)
            or not isinstance(invalid, list)
            or not isinstance(manual_reasons, list)
            or not isinstance(raw.get("automatable"), bool)
            or not isinstance(raw.get("manual_review_required"), bool)
            or not isinstance(current_memory_id, str)
        ):
            raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")
        if set(candidate) != set(missing):
            raise ContentMigrationError("MIGRATION_CANDIDATE_INVALID", "doctor-query")
        if "memory_id" in candidate and HASH_RE.fullmatch(str(candidate["memory_id"])) is None:
            raise ContentMigrationError("MIGRATION_CANDIDATE_INVALID", "doctor-query")
        if current_memory_id and HASH_RE.fullmatch(current_memory_id) is None:
            raise ContentMigrationError("MIGRATION_CANDIDATE_INVALID", "doctor-query")
        if (
            ("memory_id" in candidate and current_memory_id)
            or (
                "memory_id" not in candidate
                and "memory_id" not in invalid
                and HASH_RE.fullmatch(current_memory_id) is None
            )
        ):
            raise ContentMigrationError("MIGRATION_CANDIDATE_INVALID", "doctor-query")
        if (
            "temporal_policy" in candidate
            and str(candidate["temporal_policy"]) not in memory_index.TEMPORAL_POLICIES
        ):
            raise ContentMigrationError("MIGRATION_CANDIDATE_INVALID", "doctor-query")
        review_days = candidate.get("review_after_days")
        if review_days is not None and (
            not isinstance(review_days, int)
            or isinstance(review_days, bool)
            or review_days <= 0
            or review_days > 3650
        ):
            raise ContentMigrationError("MIGRATION_CANDIDATE_INVALID", "doctor-query")
        if raw.get("automatable") is True and invalid:
            raise ContentMigrationError("MIGRATION_CANDIDATE_INVALID", "doctor-query")
        if (
            agent_scope not in GOVERNANCE_OWNER_SCOPES
            and (
                raw.get("automatable") is True
                or "SCOPE_REVIEW_REQUIRED" not in manual_reasons
            )
        ):
            raise ContentMigrationError("MIGRATION_SCOPE_INVALID", "doctor-query")
        basis = raw.get("verification_basis")
        atomic_gap_fields = raw.get("atomic_fact_gap_fields")
        evidence_provenance = raw.get("durable_evidence_provenance")
        if (
            not isinstance(basis, dict)
            or basis.get("document_date_is_verification") is not False
            or not isinstance(raw.get("document_date_unverified"), bool)
            or not isinstance(raw.get("active_unverified"), bool)
            or not isinstance(raw.get("review_overdue"), bool)
            or not isinstance(raw.get("action_sensitive"), bool)
            or not isinstance(raw.get("atomic_fact_gap"), bool)
            or not isinstance(atomic_gap_fields, list)
            or not all(
                isinstance(value, str) and value in ATOMIC_FACT_GAP_FIELDS
                for value in atomic_gap_fields
            )
            or len(atomic_gap_fields) != len(set(atomic_gap_fields))
            or bool(atomic_gap_fields) is not raw.get("atomic_fact_gap")
            or not isinstance(evidence_provenance, dict)
            or not isinstance(evidence_provenance.get("present"), bool)
            or evidence_provenance.get("source") != "write_gateway_v2_receipt"
            or not isinstance(evidence_provenance.get("reason_code"), str)
            or not isinstance(evidence_provenance.get("current_content_bound"), bool)
            or not isinstance(evidence_provenance.get("checked_receipts"), int)
            or isinstance(evidence_provenance.get("checked_receipts"), bool)
            or int(evidence_provenance.get("checked_receipts", -1)) < 0
            or (
                evidence_provenance.get("present") is True
                and (
                    evidence_provenance.get("current_content_bound") is not True
                    or evidence_provenance.get("reason_code") != ""
                )
            )
            or (
                raw.get("action_sensitive") is True
                and (
                    (evidence_provenance.get("present") is not True)
                    != ("evidence_provenance" in atomic_gap_fields)
                )
            )
            or raw.get("body_change_allowed") is not False
            or raw.get("status_change_allowed") is not False
            or raw.get("risk_change_allowed") is not False
        ):
            raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")
        record = _deep_json(raw, "MIGRATION_QUERY_INVALID")
        record["target_relative_path"] = target
        record["requested_agent_scope"] = agent_scope
        record["requested_app_id"] = app_id
        record["requested_project_id"] = project_id
        normalized_query.append(record)
    normalized_query.sort(key=lambda item: str(item["target_relative_path"]))
    if counts["migration_candidate_documents"] != len(normalized_query):
        raise ContentMigrationError("MIGRATION_QUERY_COUNTS_INVALID", "doctor-query")
    if counts["automatable_documents"] != sum(
        1 for item in normalized_query if item.get("automatable") is True
    ):
        raise ContentMigrationError("MIGRATION_QUERY_COUNTS_INVALID", "doctor-query")
    if counts["governed_documents"] != len(documents) + len(unsafe):
        raise ContentMigrationError("MIGRATION_QUERY_COUNTS_INVALID", "doctor-query")
    if counts["manual_review_documents"] != len(manual_queue) + len(unsafe):
        raise ContentMigrationError("MIGRATION_QUERY_COUNTS_INVALID", "doctor-query")
    observed_sha = str(detail.get("migration_query_sha256", ""))
    if HASH_RE.fullmatch(observed_sha) is None or observed_sha != canonical_sha256(normalized_query):
        raise ContentMigrationError("MIGRATION_QUERY_HASH_INVALID", "doctor-query")
    normalized_risk = _deep_json(risk_queue, "MIGRATION_QUERY_INVALID")
    normalized_risk.sort(key=lambda item: str(item.get("target_relative_path", "")))
    normalized_documents = _deep_json(documents, "MIGRATION_QUERY_INVALID")
    normalized_documents.sort(key=lambda item: str(item.get("target_relative_path", "")))
    if any(
        not isinstance(item, dict)
        or not _governance_atomic_contract_shape_valid(item)
        for item in normalized_documents
    ):
        raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")
    document_map = {
        str(item.get("target_relative_path", "")): item
        for item in normalized_documents
        if isinstance(item, dict)
    }
    if len(document_map) != len(normalized_documents) or any(
        document_map.get(str(item.get("target_relative_path", ""))) != item
        for item in [*normalized_query, *normalized_risk]
    ):
        raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")
    expected_metadata = [
        item for item in normalized_documents if bool(item.get("candidate_metadata"))
    ]
    if normalized_query != expected_metadata:
        raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")
    normalized_manual = _deep_json(manual_queue, "MIGRATION_QUERY_INVALID")
    normalized_manual.sort(key=lambda item: str(item.get("target_relative_path", "")))
    expected_manual = [
        item
        for item in normalized_documents
        if item.get("manual_review_required") is True
    ]
    if normalized_manual != expected_manual:
        raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")
    expected_risk = [
        item
        for item in normalized_documents
        if isinstance(item.get("risk_recommendation"), dict)
        and bool(item["risk_recommendation"].get("reason_codes"))
    ]
    if normalized_risk != expected_risk:
        raise ContentMigrationError("MIGRATION_RISK_QUERY_INVALID", "doctor-query")
    risk_sha = str(detail.get("risk_migration_query_sha256", ""))
    if (
        counts["risk_candidate_documents"] != len(normalized_risk)
        or counts["risk_automatable_documents"] != sum(
            1
            for item in normalized_risk
            if isinstance(item, dict)
            and isinstance(item.get("risk_recommendation"), dict)
            and item["risk_recommendation"].get("automatable_now") is True
        )
        or counts["risk_manual_review_documents"] != sum(
            1
            for item in normalized_risk
            if isinstance(item, dict)
            and isinstance(item.get("risk_recommendation"), dict)
            and item["risk_recommendation"].get("manual_review_required") is True
        )
        or HASH_RE.fullmatch(risk_sha) is None
        or risk_sha != canonical_sha256(normalized_risk)
    ):
        raise ContentMigrationError("MIGRATION_RISK_QUERY_INVALID", "doctor-query")
    binding = {
        "policy": "governance_metadata_v4",
        "migration_query_schema_version": 4,
        **counts,
        "unsafe_documents": _deep_json(unsafe, "MIGRATION_QUERY_INVALID"),
        "documents": normalized_documents,
        "migration_query": normalized_query,
        "manual_review_queue": normalized_manual,
        "risk_migration_query": normalized_risk,
        "migration_query_sha256": observed_sha,
        "risk_migration_query_sha256": risk_sha,
        "ordinary_document_dates_never_verify": True,
        "allowed_automatic_fields": [
            "memory_id", "temporal_policy", "review_after_days"
        ],
    }
    return binding


def _project_validated_governance_binding(
    binding: dict[str, Any],
    *,
    actor: str,
    mode: str,
) -> dict[str, Any]:
    """Project one already-validated complete Doctor binding into its owner lane."""

    if actor not in {"codex", "claude"}:
        raise ContentMigrationError("ACTOR_FORBIDDEN", "arguments")
    if mode not in {GOVERNANCE_V4_MODE, RISK_V4_MODE}:
        raise ContentMigrationError("MIGRATION_MODE_INVALID", "arguments")

    documents = [
        item
        for item in binding["documents"]
        if isinstance(item, dict) and _record_is_in_owner_lane(item, actor)
    ]
    metadata_source = (
        binding["metadata_migration_query"]
        if mode == RISK_V4_MODE
        else binding["migration_query"]
    )
    metadata_query = [
        item
        for item in metadata_source
        if isinstance(item, dict) and _record_is_in_owner_lane(item, actor)
    ]
    manual_queue = [
        item
        for item in binding["manual_review_queue"]
        if isinstance(item, dict) and _record_is_in_owner_lane(item, actor)
    ]
    risk_query = [
        item
        for item in binding["risk_migration_query"]
        if isinstance(item, dict) and _record_is_in_owner_lane(item, actor)
    ]
    risk_automatic = sum(
        1
        for item in risk_query
        if isinstance(item.get("risk_recommendation"), dict)
        and item["risk_recommendation"].get("automatable_now") is True
    )
    risk_manual = sum(
        1
        for item in risk_query
        if isinstance(item.get("risk_recommendation"), dict)
        and item["risk_recommendation"].get("manual_review_required") is True
    )
    clean_documents = sum(
        1
        for item in documents
        if (
            not item.get("candidate_metadata")
            and item.get("manual_review_required") is not True
            and isinstance(item.get("risk_recommendation"), dict)
            and not item["risk_recommendation"].get("reason_codes")
        )
    )
    unassigned_manual_review_count = _unassigned_manual_review_count(binding)

    projected = _deep_json(binding, "MIGRATION_QUERY_INVALID")
    projected.update({
        "governed_documents": len(documents),
        "migration_candidate_documents": len(metadata_query),
        "automatable_documents": (
            risk_automatic
            if mode == RISK_V4_MODE
            else sum(1 for item in metadata_query if item.get("automatable") is True)
        ),
        "manual_review_documents": (
            risk_manual if mode == RISK_V4_MODE else len(manual_queue)
        ),
        "risk_candidate_documents": len(risk_query),
        "risk_automatable_documents": risk_automatic,
        "risk_manual_review_documents": risk_manual,
        "clean_documents": clean_documents,
        # Bind path-free debt that has no trustworthy owner.  Both owner lanes
        # must surface it, but neither lane may receive its target or content.
        "unassigned_manual_review_count": unassigned_manual_review_count,
        # Unsafe/unreadable files have no trustworthy scope owner and are
        # retained only in the complete Doctor binding.  They cannot enter an
        # automatic host lane or leak their paths through its review.
        "unsafe_documents": [],
        "documents": documents,
        "manual_review_queue": manual_queue,
        "risk_migration_query": risk_query,
        "risk_migration_query_sha256": canonical_sha256(risk_query),
        "owner_lane_policy": GOVERNANCE_OWNER_LANE_POLICY,
        "owner_actor": actor,
        "complete_doctor_binding_sha256": canonical_sha256(binding),
    })
    if mode == RISK_V4_MODE:
        projected.update({
            "mode": RISK_V4_MODE,
            "metadata_migration_query": metadata_query,
            "metadata_migration_query_sha256": canonical_sha256(metadata_query),
            "migration_query": risk_query,
            "migration_query_sha256": canonical_sha256(risk_query),
        })
    else:
        projected.update({
            "migration_query": metadata_query,
            "migration_query_sha256": canonical_sha256(metadata_query),
        })
    return projected


def _risk_binding_from_governance_detail(detail: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_query_for_mode(
        {
            "checks": [{
                "name": "governance_metadata_v4",
                "status": "warn",
                "detail": detail,
            }],
        },
        mode=RISK_V4_MODE,
    )
    return normalized


def _validate_projected_governance_binding(
    binding: dict[str, Any],
    *,
    actor: str,
    mode: str,
) -> dict[str, Any]:
    """Validate a private review projection without treating it as full Doctor output."""

    if actor not in {"codex", "claude"}:
        raise ContentMigrationError("REVIEW_ACTOR_INVALID", "review")
    projection_keys = {
        "owner_lane_policy",
        "owner_actor",
        "complete_doctor_binding_sha256",
        "unassigned_manual_review_count",
    }
    unassigned_manual_review_count = binding.get(
        "unassigned_manual_review_count"
    )
    if (
        binding.get("owner_lane_policy") != GOVERNANCE_OWNER_LANE_POLICY
        or binding.get("owner_actor") != actor
        or HASH_RE.fullmatch(
            str(binding.get("complete_doctor_binding_sha256", ""))
        ) is None
        or not isinstance(unassigned_manual_review_count, int)
        or isinstance(unassigned_manual_review_count, bool)
        or unassigned_manual_review_count < 0
    ):
        raise ContentMigrationError("REVIEW_OWNER_LANE_INVALID", "review")
    base = _deep_json(binding, "REVIEW_QUERY_BINDING_INVALID")
    projection = {key: base.pop(key, None) for key in projection_keys}
    if base.get("unsafe_documents") != []:
        raise ContentMigrationError("REVIEW_OWNER_LANE_INVALID", "review")
    try:
        if mode == GOVERNANCE_V4_MODE:
            canonical = normalize_governance_doctor_query({
                "checks": [{
                    "name": "governance_metadata_v4",
                    "status": "warn",
                    "detail": base,
                }],
            })
        elif mode == RISK_V4_MODE:
            governance_detail = _deep_json(base, "REVIEW_QUERY_BINDING_INVALID")
            metadata_query = governance_detail.pop("metadata_migration_query")
            metadata_sha = governance_detail.pop("metadata_migration_query_sha256")
            governance_detail.pop("mode")
            governance_detail["migration_query"] = metadata_query
            governance_detail["migration_query_sha256"] = metadata_sha
            governance_detail["automatable_documents"] = sum(
                1
                for record in metadata_query
                if isinstance(record, dict) and record.get("automatable") is True
            )
            governance_detail["manual_review_documents"] = len(
                governance_detail.get("manual_review_queue", [])
            )
            canonical = _risk_binding_from_governance_detail(governance_detail)
        else:
            raise ContentMigrationError("REVIEW_MODE_INVALID", "review")
    except (ContentMigrationError, KeyError, TypeError) as exc:
        raise ContentMigrationError("REVIEW_QUERY_BINDING_INVALID", "review") from exc
    if base != canonical:
        raise ContentMigrationError("REVIEW_QUERY_BINDING_INVALID", "review")
    if any(
        not isinstance(record, dict)
        or not _record_is_in_owner_lane(record, actor)
        for record in canonical["documents"]
    ):
        raise ContentMigrationError("REVIEW_OWNER_LANE_INVALID", "review")
    return {**canonical, **projection}


def normalize_query_for_mode(
    doctor: dict[str, Any],
    *,
    mode: str,
    require_all_automatable: bool = False,
) -> dict[str, Any]:
    if mode in {GOVERNANCE_V4_MODE, RISK_V4_MODE}:
        normalized = normalize_governance_doctor_query(doctor)
        if mode == RISK_V4_MODE:
            unsafe_automatic = any(
                isinstance(item, dict)
                and isinstance(item.get("risk_recommendation"), dict)
                and item["risk_recommendation"].get("automatable_now") is True
                and not _risk_recommendation_is_safe_automatic(
                    item["risk_recommendation"]
                )
                for item in normalized["risk_migration_query"]
            )
            if unsafe_automatic:
                raise ContentMigrationError(
                    "RISK_AUTOMATION_CLASSIFICATION_UNSAFE",
                    "doctor-query",
                )
            normalized = dict(normalized)
            normalized["metadata_migration_query"] = list(
                normalized["migration_query"]
            )
            normalized["metadata_migration_query_sha256"] = str(
                normalized["migration_query_sha256"]
            )
            normalized["migration_query"] = list(
                normalized["risk_migration_query"]
            )
            normalized["migration_query_sha256"] = str(
                normalized["risk_migration_query_sha256"]
            )
            normalized["automatable_documents"] = int(
                normalized["risk_automatable_documents"]
            )
            normalized["manual_review_documents"] = int(
                normalized["risk_manual_review_documents"]
            )
            normalized["mode"] = RISK_V4_MODE
        return normalized
    if mode != LEGACY_SCOPE_MODE:
        raise ContentMigrationError("MIGRATION_MODE_INVALID", "arguments")
    return normalize_doctor_query(
        doctor,
        require_all_automatable=require_all_automatable,
    )


def normalize_and_project_query_for_actor(
    doctor: dict[str, Any],
    *,
    mode: str,
    actor: str,
    require_all_automatable: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate the complete Doctor binding before deriving one host lane."""

    complete = normalize_query_for_mode(
        doctor,
        mode=mode,
        require_all_automatable=require_all_automatable,
    )
    if mode in {GOVERNANCE_V4_MODE, RISK_V4_MODE}:
        projected = _project_validated_governance_binding(
            complete,
            actor=actor,
            mode=mode,
        )
    else:
        projected = complete
    return complete, projected


def _risk_recommendation_is_safe_automatic(
    recommendation: dict[str, Any],
) -> bool:
    """Permit only explicit risk-raising or quarantine automation."""

    operation = str(recommendation.get("followup_operation", ""))
    raw_reasons = recommendation.get("reason_codes")
    if not isinstance(raw_reasons, list) or not raw_reasons or not all(
        isinstance(value, str) and value for value in raw_reasons
    ):
        return False
    reasons = set(raw_reasons)
    source_status = str(recommendation.get("source_status", ""))
    current_risk = str(recommendation.get("current", ""))
    allowed_reasons = {
        "METADATA_RISK_CLASS_NOT_EXPLICIT",
        "ACTION_SENSITIVE_ATOMIC_GAP",
        "ACTION_SENSITIVE_ACTIVE_UNVERIFIED",
        "ACTION_SENSITIVE_REVIEW_OVERDUE",
        "ACTION_SENSITIVE_EXPIRED",
    }
    return bool(
        recommendation.get("automatable_now") is True
        and recommendation.get("automatable_after_governance") is True
        and recommendation.get("manual_review_required") is False
        and str(recommendation.get("recommended", "")) == "action_sensitive"
        and reasons <= allowed_reasons
        and (
            (
                operation == "status_transition"
                and source_status == "active"
                and recommendation.get("target_status") == "pending_verification"
                and current_risk in {"", "action_sensitive"}
                and bool(
                    reasons
                    & {
                        "ACTION_SENSITIVE_ATOMIC_GAP",
                        "ACTION_SENSITIVE_ACTIVE_UNVERIFIED",
                        "ACTION_SENSITIVE_REVIEW_OVERDUE",
                        "ACTION_SENSITIVE_EXPIRED",
                    }
                )
                and (
                    current_risk == "action_sensitive"
                    or "METADATA_RISK_CLASS_NOT_EXPLICIT" in reasons
                )
            )
            or (
                operation == "content_update"
                and source_status in {"active", "pending_verification"}
                and recommendation.get("target_status") == ""
                and current_risk == ""
                and reasons == {"METADATA_RISK_CLASS_NOT_EXPLICIT"}
            )
        )
    )


def _risk_recommendation_is_strict_safe_after_governance(
    recommendation: dict[str, Any],
) -> bool:
    """Validate the same safe contract with governance as the only blocker."""

    if (
        recommendation.get("automatable_now") is not False
        or recommendation.get("automatable_after_governance") is not True
        or recommendation.get("manual_review_required") is not False
    ):
        return False
    projected = dict(recommendation)
    projected["automatable_now"] = True
    return _risk_recommendation_is_safe_automatic(projected)


def _temporal_fact_coverage_is_migration_scoped(
    doctor: dict[str, Any],
    binding: dict[str, Any],
    *,
    mode: str,
) -> bool:
    """Accept only exact temporal gaps owned by a safe automatic v4 lane."""

    if mode not in {GOVERNANCE_V4_MODE, RISK_V4_MODE}:
        return False
    checks = doctor.get("checks")
    if not isinstance(checks, list):
        return False
    matches = [
        item
        for item in checks
        if isinstance(item, dict)
        and item.get("name") == "temporal_fact_coverage"
    ]
    if len(matches) != 1:
        return False
    check = matches[0]
    if (
        set(check) != {"name", "status", "message", "detail"}
        or check.get("status") != "fail"
        or not isinstance(check.get("message"), str)
        or not str(check["message"]).strip()
        or not isinstance(check.get("detail"), dict)
    ):
        return False
    detail = check["detail"]
    expected_detail_keys = {
        "action_sensitive_documents",
        "uncovered",
        "gap_details",
        "structural_and_routing_excluded",
        "coverage_is_per_document",
        "coverage_requires",
        "fact_records",
        "migration_is_explicit_only",
    }
    if set(detail) != expected_detail_keys:
        return False
    action_sensitive = detail.get("action_sensitive_documents")
    uncovered = detail.get("uncovered")
    gap_details = detail.get("gap_details")
    fact_records = detail.get("fact_records")
    expected_requirements = [
        "non_structural_temporal_policy",
        "fact_key",
        "valid_from",
        "frontmatter_verified_at",
        "current_content_write_gateway_evidence",
    ]
    if (
        not isinstance(action_sensitive, list)
        or not isinstance(uncovered, list)
        or not uncovered
        or not isinstance(gap_details, list)
        or not isinstance(fact_records, int)
        or isinstance(fact_records, bool)
        or fact_records < 0
        or detail.get("structural_and_routing_excluded") is not True
        or detail.get("coverage_is_per_document") is not True
        or detail.get("coverage_requires") != expected_requirements
        or detail.get("migration_is_explicit_only") is not True
    ):
        return False

    def valid_targets(values: list[Any]) -> bool:
        return bool(
            all(
                isinstance(value, str)
                and value == value.strip()
                and TARGET_RE.fullmatch(value) is not None
                for value in values
            )
            and len(values) == len(set(values))
            and values == sorted(values)
        )

    if (
        not valid_targets(action_sensitive)
        or not valid_targets(uncovered)
        or not set(uncovered).issubset(action_sensitive)
        or len(gap_details) != len(uncovered)
    ):
        return False
    normalized_gap_targets: list[str] = []
    for gap in gap_details:
        if not isinstance(gap, dict) or set(gap) != {
            "rel_path",
            "missing_or_invalid",
            "evidence_provenance",
        }:
            return False
        rel_path = gap.get("rel_path")
        missing = gap.get("missing_or_invalid")
        evidence = gap.get("evidence_provenance")
        if (
            not isinstance(rel_path, str)
            or rel_path not in uncovered
            or not isinstance(missing, list)
            or not missing
            or any(
                not isinstance(value, str)
                or value not in ATOMIC_FACT_GAP_FIELDS
                for value in missing
            )
            or len(missing) != len(set(missing))
            or not isinstance(evidence, dict)
            or set(evidence) != {
                "present",
                "source",
                "reason_code",
                "current_content_bound",
                "checked_receipts",
            }
        ):
            return False
        checked_receipts = evidence.get("checked_receipts")
        evidence_present = evidence.get("present")
        if (
            not isinstance(evidence_present, bool)
            or evidence.get("source") != "write_gateway_v2_receipt"
            or not isinstance(evidence.get("reason_code"), str)
            or not isinstance(evidence.get("current_content_bound"), bool)
            or not isinstance(checked_receipts, int)
            or isinstance(checked_receipts, bool)
            or checked_receipts < 0
            or (
                evidence_present
                and (
                    evidence.get("reason_code") != ""
                    or evidence.get("current_content_bound") is not True
                )
            )
            or (
                not evidence_present
                and (
                    not str(evidence.get("reason_code", ""))
                    or evidence.get("current_content_bound") is not False
                )
            )
            or (
                ("evidence_provenance" in missing)
                is not (evidence_present is False)
            )
        ):
            return False
        normalized_gap_targets.append(rel_path)
    if normalized_gap_targets != uncovered:
        return False

    unsafe_documents = binding.get("unsafe_documents")
    migration_query = binding.get("migration_query")
    risk_migration_query = binding.get("risk_migration_query")
    if (
        not isinstance(unsafe_documents, list)
        or not isinstance(migration_query, list)
        or not isinstance(risk_migration_query, list)
        or any(
            not isinstance(value, str)
            or value != value.strip()
            or TARGET_RE.fullmatch(value) is None
            for value in unsafe_documents
        )
    ):
        return False
    unsafe_targets = set(unsafe_documents)
    if set(uncovered) & unsafe_targets:
        return False
    metadata_automatic = {
        str(record.get("target_relative_path", ""))
        for record in migration_query
        if isinstance(record, dict) and record.get("automatable") is True
    }
    risk_automatic = {
        str(record.get("target_relative_path", ""))
        for record in risk_migration_query
        if isinstance(record, dict)
        and isinstance(record.get("risk_recommendation"), dict)
        and _risk_recommendation_is_safe_automatic(
            record["risk_recommendation"]
        )
    }
    eligible = (
        metadata_automatic | risk_automatic
        if mode == GOVERNANCE_V4_MODE
        else risk_automatic
    )
    return set(uncovered).issubset(eligible)


def preflight_governance_migration_debt(
    doctor: dict[str, Any],
) -> dict[str, Any]:
    """Classify only the v4 debt that a managed migration can safely clear.

    The returned object is safe to persist in a Runtime attestation: it keeps
    counts and one-way fingerprints, never paths, query text, or Markdown.
    Full Doctor records are nevertheless normalized before any count is
    trusted.  A failing governance check is accepted only when every governed
    finding is automatic; a temporal failure must match the exact, separately
    validated automatic target set.
    """

    binding = normalize_governance_doctor_query(doctor)
    governance_check = _governance_check(doctor)
    governance_status = governance_check.get("status")
    if governance_status not in {"pass", "warn", "fail"}:
        raise ContentMigrationError(
            "DOCTOR_GOVERNANCE_CHECK_INVALID",
            "doctor",
        )

    documents = binding.get("documents")
    unsafe_documents = binding.get("unsafe_documents")
    if not isinstance(documents, list) or not isinstance(unsafe_documents, list):
        raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")
    document_targets = [
        str(record.get("target_relative_path", ""))
        for record in documents
        if isinstance(record, dict)
    ]
    if (
        len(document_targets) != len(documents)
        or document_targets != sorted(document_targets)
        or len(document_targets) != len(set(document_targets))
        or any(TARGET_RE.fullmatch(target) is None for target in document_targets)
        or unsafe_documents != sorted(unsafe_documents)
        or len(unsafe_documents) != len(set(unsafe_documents))
        or any(
            not isinstance(target, str)
            or target != target.strip()
            or TARGET_RE.fullmatch(target) is None
            for target in unsafe_documents
        )
        or set(document_targets) & set(unsafe_documents)
    ):
        raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")
    if unsafe_documents:
        raise ContentMigrationError(
            "DOCTOR_GOVERNANCE_UNSAFE_DOCUMENTS",
            "doctor",
        )
    for record in documents:
        manual_reasons = record.get("manual_review_reasons")
        if (
            not isinstance(record.get("automatable"), bool)
            or not isinstance(record.get("manual_review_required"), bool)
            or not isinstance(manual_reasons, list)
            or any(not isinstance(reason, str) or not reason for reason in manual_reasons)
            or bool(manual_reasons) is not record.get("manual_review_required")
        ):
            raise ContentMigrationError("MIGRATION_QUERY_INVALID", "doctor-query")

    metadata_targets = {
        str(record["target_relative_path"])
        for record in binding["migration_query"]
        if isinstance(record, dict) and record.get("automatable") is True
    }
    risk_targets = {
        str(record["target_relative_path"])
        for record in binding["risk_migration_query"]
        if isinstance(record, dict)
        and isinstance(record.get("risk_recommendation"), dict)
        and _risk_recommendation_is_safe_automatic(
            record["risk_recommendation"]
        )
    }
    for record in binding["risk_migration_query"]:
        recommendation = record.get("risk_recommendation")
        if not isinstance(recommendation, dict) or any(
            not isinstance(recommendation.get(field), bool)
            for field in (
                "automatable_now",
                "automatable_after_governance",
                "manual_review_required",
            )
        ):
            raise ContentMigrationError(
                "RISK_AUTOMATION_CLASSIFICATION_UNSAFE",
                "doctor-query",
            )
        safe_automatic = _risk_recommendation_is_safe_automatic(
            recommendation
        )
        target = str(record.get("target_relative_path", ""))
        safe_after_governance = bool(
            target in metadata_targets
            and _risk_recommendation_is_strict_safe_after_governance(
                recommendation
            )
        )
        explicit_manual = bool(
            recommendation["manual_review_required"] is True
            and recommendation["automatable_now"] is False
            and recommendation["automatable_after_governance"] is False
        )
        if recommendation["automatable_now"] is True and not safe_automatic:
            raise ContentMigrationError(
                "RISK_AUTOMATION_CLASSIFICATION_UNSAFE",
                "doctor-query",
            )
        if sum((safe_automatic, safe_after_governance, explicit_manual)) != 1:
            raise ContentMigrationError(
                "RISK_AUTOMATION_CLASSIFICATION_UNRESOLVED",
                "doctor-query",
            )
    safe_targets = metadata_targets | risk_targets

    checks = doctor.get("checks")
    if not isinstance(checks, list):
        raise ContentMigrationError("DOCTOR_JSON_INVALID", "doctor")
    temporal_matches = [
        check
        for check in checks
        if isinstance(check, dict)
        and check.get("name") == "temporal_fact_coverage"
    ]
    if len(temporal_matches) != 1 or temporal_matches[0].get("status") not in {
        "pass",
        "fail",
    }:
        raise ContentMigrationError(
            "DOCTOR_TEMPORAL_FACT_COVERAGE_INVALID",
            "doctor",
        )
    temporal_check = temporal_matches[0]
    temporal_failure_documents = 0
    temporal_failure_fingerprint = canonical_sha256(
        {"status": "pass", "uncovered": []}
    )
    if temporal_check.get("status") == "fail":
        if not _temporal_fact_coverage_is_migration_scoped(
            doctor,
            binding,
            mode=GOVERNANCE_V4_MODE,
        ):
            raise ContentMigrationError(
                "DOCTOR_TEMPORAL_FACT_COVERAGE_NOT_AUTOMATABLE",
                "doctor",
            )
        detail = temporal_check["detail"]
        temporal_failure_documents = len(detail["uncovered"])
        temporal_failure_fingerprint = canonical_sha256(detail)

    total_debt = int(binding["migration_candidate_documents"]) + int(
        binding["risk_candidate_documents"]
    )
    total_manual = int(binding["manual_review_documents"])
    if total_debt or total_manual:
        if governance_status not in {"warn", "fail"}:
            raise ContentMigrationError(
                "DOCTOR_GOVERNANCE_CHECK_INVALID",
                "doctor",
            )
    elif governance_status != "pass":
        raise ContentMigrationError(
            "DOCTOR_GOVERNANCE_CHECK_INVALID",
            "doctor",
        )

    if governance_status == "fail":
        metadata_query_targets = {
            str(record.get("target_relative_path", ""))
            for record in binding["migration_query"]
            if isinstance(record, dict)
        }
        risk_query_targets = {
            str(record.get("target_relative_path", ""))
            for record in binding["risk_migration_query"]
            if isinstance(record, dict)
        }
        if (
            not safe_targets
            or binding["manual_review_documents"] != 0
            or unsafe_documents
            or metadata_query_targets != metadata_targets
            or risk_query_targets != risk_targets
        ):
            raise ContentMigrationError(
                "DOCTOR_GOVERNANCE_FAILURE_NOT_AUTOMATABLE",
                "doctor",
            )

    overlap = metadata_targets & risk_targets
    fingerprint_payload = {
        "schema_version": PREFLIGHT_GOVERNANCE_DEBT_SCHEMA_VERSION,
        "binding_sha256": canonical_sha256(binding),
        "metadata_targets": sorted(metadata_targets),
        "risk_targets": sorted(risk_targets),
        "temporal_failure_fingerprint_sha256": temporal_failure_fingerprint,
    }
    return {
        "schema_version": PREFLIGHT_GOVERNANCE_DEBT_SCHEMA_VERSION,
        "safe_automatic_governance_documents": len(safe_targets),
        "governance_metadata_automatic_documents": len(metadata_targets),
        "governance_risk_automatic_documents": len(risk_targets),
        "governance_automatic_overlap_documents": len(overlap),
        "governance_manual_review_documents": int(
            binding["manual_review_documents"]
        ),
        "governance_unsafe_documents": len(unsafe_documents),
        "temporal_failure_documents": temporal_failure_documents,
        "governance_binding_sha256": canonical_sha256(binding),
        "automatic_migration_fingerprint_sha256": canonical_sha256(
            fingerprint_payload
        ),
    }


def assert_doctor_migration_safe(
    doctor: dict[str, Any],
    binding: dict[str, Any],
    *,
    mode: str = LEGACY_SCOPE_MODE,
) -> None:
    """Permit the migration finding itself, but no unrelated Doctor failure."""

    checks = doctor.get("checks")
    if not isinstance(checks, list):
        raise ContentMigrationError("DOCTOR_JSON_INVALID", "doctor")
    failures = {
        str(item.get("name", ""))
        for item in checks
        if isinstance(item, dict) and item.get("status") == "fail"
    }
    allowed_failure = (
        {"governance_metadata_v4"}
        if mode in {GOVERNANCE_V4_MODE, RISK_V4_MODE}
        else {"legacy_scope_documents"}
    )
    if (
        "temporal_fact_coverage" in failures
        and _temporal_fact_coverage_is_migration_scoped(
            doctor,
            binding,
            mode=mode,
        )
    ):
        allowed_failure.add("temporal_fact_coverage")
    if failures - allowed_failure:
        raise ContentMigrationError("DOCTOR_UNRELATED_FAILURE", "doctor")
    if mode in {GOVERNANCE_V4_MODE, RISK_V4_MODE}:
        governance_status = _governance_check(doctor).get("status")
        total_debt = int(
            binding.get("migration_candidate_documents", 0) or 0
        ) + int(binding.get("risk_candidate_documents", 0) or 0)
        total_manual = len(binding.get("manual_review_queue", [])) + len(
            binding.get("unsafe_documents", [])
        )
        if (total_debt or total_manual) and governance_status not in {"warn", "fail"}:
            raise ContentMigrationError("DOCTOR_GOVERNANCE_CHECK_INVALID", "doctor")
        if not total_debt and not total_manual and governance_status != "pass":
            raise ContentMigrationError("DOCTOR_GOVERNANCE_CHECK_INVALID", "doctor")
        return
    scope_check = _scope_check(doctor)
    scope_status = scope_check.get("status")
    if binding["legacy_scope_documents"]:
        if scope_status not in {"warn", "fail"}:
            raise ContentMigrationError("DOCTOR_SCOPE_CHECK_INVALID", "doctor")
    elif scope_status != "pass":
        raise ContentMigrationError("DOCTOR_SCOPE_CHECK_INVALID", "doctor")


def _doctor_final_fail_state(doctor: dict[str, Any]) -> tuple[bool, int]:
    """Bind final readiness to actual checks, reported fail count, and status."""

    checks = doctor.get("checks")
    summary = doctor.get("summary")
    if (
        not isinstance(checks, list)
        or not isinstance(summary, dict)
        or any(
            not isinstance(item, dict)
            or item.get("status") not in {"pass", "warn", "fail"}
            for item in checks
        )
    ):
        return False, 0
    reported_fail = summary.get("fail")
    if (
        not isinstance(reported_fail, int)
        or isinstance(reported_fail, bool)
        or reported_fail < 0
    ):
        return False, 0
    actual_fail = sum(item.get("status") == "fail" for item in checks)
    status = doctor.get("status")
    status_consistent = (
        status == "error"
        if actual_fail
        else status in {"ok", "warning"}
    )
    return bool(reported_fail == actual_fail and status_consistent), actual_fail


def migration_read_request(
    record: dict[str, Any],
    *,
    mode: str = LEGACY_SCOPE_MODE,
) -> dict[str, Any]:
    request = {
        "schema_version": WIRE_SCHEMA_VERSION,
        "target_relative_path": str(record["target_relative_path"]),
        "app_id": str(record["requested_app_id"]),
        "project_id": str(record["requested_project_id"]),
    }
    if mode == GOVERNANCE_V4_MODE:
        request["operation"] = "governance_migration"
        return request
    if mode == RISK_V4_MODE:
        recommendation = record.get("risk_recommendation", {})
        if isinstance(recommendation, dict):
            operation = str(recommendation.get("followup_operation", ""))
            if operation in {"content_update", "status_transition"}:
                request["operation"] = operation
        return request
    request.update({
        "migrate_legacy_scope": True,
        "legacy_scope_app_id": str(record["legacy_scope_app_id"]),
    })
    return request


def _proposal(
    record: dict[str, Any],
    base_text: str,
    *,
    actor: str,
    mode: str = LEGACY_SCOPE_MODE,
) -> tuple[str, write_intent.ContentDigest]:
    try:
        if mode == GOVERNANCE_V4_MODE:
            text = write_gateway._governance_v4_proposal(
                rel_path=str(record["target_relative_path"]),
                base_text=base_text,
            )
            proposal_meta = memory_index.parse_frontmatter(text)
            for key, value in dict(record.get("candidate_metadata", {})).items():
                if memory_index.as_text(proposal_meta.get(key)).strip() != str(value):
                    raise ValueError("governance candidate changed")
        elif mode == RISK_V4_MODE:
            expected = dict(record.get("risk_recommendation", {}))
            expected_operation = str(expected.get("followup_operation", ""))
            base_meta = memory_index.parse_frontmatter(base_text)
            base_status = memory_index.as_text(
                base_meta.get("status"), "active"
            ).strip().casefold()
            current_risk = memory_index.as_text(
                base_meta.get("risk_class")
            ).strip().casefold()
            if (
                not _risk_recommendation_is_safe_automatic(expected)
                or expected.get("source_status") != base_status
                or expected.get("current") != current_risk
            ):
                raise ValueError("risk source binding changed")
            try:
                recommendation = write_gateway._risk_v4_recommendation(
                    rel_path=str(record["target_relative_path"]),
                    base_text=base_text,
                )
            except write_gateway.MemoryWriteError:
                if expected_operation != "status_transition":
                    raise
                recommendation = {
                    "recommended": "",
                    "operation": "unavailable",
                    "target_status": "",
                }
            if expected_operation == "status_transition":
                gap_fields = record.get("atomic_fact_gap_fields")
                reason_codes = set(expected.get("reason_codes", []))
                quarantine_reasons = {
                    "ACTION_SENSITIVE_ATOMIC_GAP",
                    "ACTION_SENSITIVE_ACTIVE_UNVERIFIED",
                    "ACTION_SENSITIVE_REVIEW_OVERDUE",
                    "ACTION_SENSITIVE_EXPIRED",
                }
                if (
                    not isinstance(gap_fields, list)
                    or not set(gap_fields).issubset(ATOMIC_FACT_GAP_FIELDS)
                    or not reason_codes.intersection(quarantine_reasons)
                    or (
                        "ACTION_SENSITIVE_ATOMIC_GAP" in reason_codes
                        and not gap_fields
                    )
                    or expected.get("recommended") != "action_sensitive"
                    or expected.get("target_status") != "pending_verification"
                    or expected.get("source_status") != "active"
                ):
                    raise ValueError("risk quarantine binding invalid")
                if (
                    base_status != "active"
                    or current_risk not in {"", "action_sensitive"}
                    or (
                        not current_risk
                        and "METADATA_RISK_CLASS_NOT_EXPLICIT" not in reason_codes
                    )
                ):
                    raise ValueError("risk quarantine target changed")
                text = write_gateway._frontmatter_scalar_replacement(
                    base_text,
                    key="status",
                    value="pending_verification",
                    allow_insert=False,
                )
                if not current_risk:
                    text = write_gateway._frontmatter_scalar_replacement(
                        text,
                        key="risk_class",
                        value="action_sensitive",
                        allow_insert=True,
                    )
                proposal_meta = memory_index.parse_frontmatter(text)
                if (
                    memory_index.as_text(proposal_meta.get("status")).casefold()
                    != "pending_verification"
                    or memory_index.as_text(
                        proposal_meta.get("risk_class")
                    ).casefold()
                    != "action_sensitive"
                ):
                    raise ValueError("risk quarantine proposal incomplete")
                # The generic writer helper can independently see metadata
                # gaps, but it cannot see the Doctor-bound durable receipt
                # proof.  When it does classify the same quarantine, its
                # recommendation and exact bytes must still agree.
                if recommendation["operation"] == "status_transition" and (
                    recommendation["recommended"]
                    != str(expected.get("recommended", ""))
                    or recommendation["target_status"]
                    != str(expected.get("target_status", ""))
                ):
                    raise ValueError("risk recommendation changed")
                if (
                    recommendation["operation"] == "status_transition"
                    and write_gateway._risk_v4_proposal(
                        rel_path=str(record["target_relative_path"]),
                        base_text=base_text,
                    )
                    != text
                ):
                    raise ValueError("risk quarantine bytes changed")
            else:
                text = write_gateway._risk_v4_proposal(
                    rel_path=str(record["target_relative_path"]),
                    base_text=base_text,
                )
                if (
                    recommendation["recommended"] != str(expected.get("recommended", ""))
                    or recommendation["operation"] != expected_operation
                    or recommendation["target_status"] != str(expected.get("target_status", ""))
                ):
                    raise ValueError("risk recommendation changed")
        else:
            text = write_gateway._legacy_scope_proposal(
                actor=actor,
                target_relative_path=str(record["target_relative_path"]),
                requested_app_id=str(record["requested_app_id"]),
                requested_project_id=str(record["requested_project_id"]),
                legacy_scope_app_id=str(record["legacy_scope_app_id"]),
                base_text=base_text,
            )
        digest = write_intent.content_hashes(text.encode("utf-8"))
    except (UnicodeError, ValueError, write_intent.IntentError, write_gateway.MemoryWriteError) as exc:
        raise ContentMigrationError(
            "PROPOSAL_GENERATION_FAILED",
            "proposal",
            str(record["target_relative_path"]),
        ) from exc
    return text, digest


def validate_read_response(
    payload: dict[str, Any],
    record: dict[str, Any],
    *,
    mode: str = LEGACY_SCOPE_MODE,
) -> dict[str, Any]:
    target = str(record["target_relative_path"])
    if (
        payload.get("ok") is not True
        or payload.get("status") != "found"
        or payload.get("exists") is not True
        or payload.get("scope_migration") is not (mode == LEGACY_SCOPE_MODE)
        or payload.get("target_relative_path") != target
        or str(payload.get("app_id", "")).casefold() != str(record["requested_app_id"]).casefold()
        or str(payload.get("project_id", "")).casefold() != str(record["requested_project_id"]).casefold()
    ):
        raise ContentMigrationError("READ_TARGET_SCOPE_MISMATCH", "read-target", target)
    content = payload.get("content")
    token = payload.get("read_token")
    raw_hash = payload.get("base_raw_sha256")
    canonical_hash = payload.get("base_canonical_sha256")
    git_head = payload.get("base_git_head")
    if (
        not isinstance(content, str)
        or not isinstance(token, str)
        or HASH_RE.fullmatch(token) is None
        or not isinstance(raw_hash, str)
        or HASH_RE.fullmatch(raw_hash) is None
        or not isinstance(canonical_hash, str)
        or HASH_RE.fullmatch(canonical_hash) is None
        or not isinstance(git_head, str)
        or GIT_HEAD_RE.fullmatch(git_head) is None
    ):
        raise ContentMigrationError("READ_TARGET_BINDING_INVALID", "read-target", target)
    try:
        digest = write_intent.content_hashes(content.encode("utf-8"))
    except (UnicodeError, write_intent.IntentError) as exc:
        raise ContentMigrationError("READ_TARGET_CONTENT_INVALID", "read-target", target) from exc
    if digest.raw_sha256 != raw_hash or digest.canonical_sha256 != canonical_hash:
        raise ContentMigrationError("READ_TARGET_CONTENT_HASH_MISMATCH", "read-target", target)
    candidate = record.get("candidate_metadata", {})
    if mode == GOVERNANCE_V4_MODE and isinstance(candidate, dict):
        expected_id = str(
            candidate.get("memory_id") or record.get("current_memory_id", "")
        )
        if payload.get("expected_memory_id") != expected_id:
            raise ContentMigrationError(
                "READ_TARGET_MEMORY_ID_MISMATCH",
                "read-target",
                target,
            )
    return {
        "content": content,
        "read_token": token,
        "base_raw_sha256": raw_hash,
        "base_canonical_sha256": canonical_hash,
        "base_git_head": git_head,
        "expected_memory_id": str(payload.get("expected_memory_id", "")),
    }


class MemoryctlClient:
    def __init__(self, *, actor: str, session_id: str, timeout: float = 900) -> None:
        if actor not in {"codex", "claude"}:
            raise ContentMigrationError("ACTOR_FORBIDDEN", "arguments")
        if not session_id.strip():
            raise ContentMigrationError("SESSION_REQUIRED", "arguments")
        self.actor = actor
        self.session_id = session_id.strip()
        self.timeout = max(float(timeout), 1)

    def _call(self, forwarded: list[str], request: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            metadata = MEMORYCTL.lstat()
        except OSError as exc:
            raise ContentMigrationError("MEMORYCTL_UNAVAILABLE", "memoryctl") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ContentMigrationError("MEMORYCTL_UNSAFE", "memoryctl")
        environment = os.environ.copy()
        # The bearer token is forwarded only in the apply JSON on stdin.  Do
        # not leak it to doctor, read-target, prepare, closeout, or descendants
        # through their ambient environment.
        environment.pop(CONFIRMATION_CAPABILITY_PATH_ENV, None)
        environment.pop(CONFIRMATION_CAPABILITY_TOKEN_ENV, None)
        environment["AGENT_MEMORY_SESSION_ID"] = self.session_id
        # Batch confirmation uses a reproducible task identity.  The outer
        # memoryctl wrapper may have minted an invocation nonce that a separate
        # stdin-only human issuer can never know; bind this reviewed migration
        # task to its explicit session instead.
        environment["AGENT_MEMORY_TASK_ID"] = self.session_id
        # The managed memoryctl contract is isolated/no-site so neither the
        # current directory nor a manifest-external module can execute before
        # Runtime authentication.
        command = [
            sys.executable,
            "-I",
            "-S",
            str(MEMORYCTL),
            "--actor",
            self.actor,
            *forwarded,
        ]
        try:
            completed = subprocess.run(
                command,
                input=(json.dumps(request, ensure_ascii=False) + "\n" if request is not None else ""),
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=self.timeout,
                check=False,
                env=environment,
            )
            payload = strict_json_loads(completed.stdout)
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
            raise ContentMigrationError("MEMORYCTL_CALL_FAILED", "memoryctl") from exc
        if not isinstance(payload, dict):
            raise ContentMigrationError("MEMORYCTL_JSON_INVALID", "memoryctl")
        payload["_returncode"] = completed.returncode
        return payload

    def doctor(self) -> dict[str, Any]:
        payload = self._call(["doctor", "--json"])
        if payload.get("_returncode") not in {0, 2} or payload.get("status") not in {"ok", "warning", "error"}:
            raise ContentMigrationError("DOCTOR_CALL_FAILED", "doctor")
        return payload

    def write(self, action: str, request: dict[str, Any]) -> dict[str, Any]:
        payload = self._call(["write", action, "--json"], request)
        if payload.get("ok") is not True or payload.get("_returncode") != 0:
            reason = str(payload.get("reason_code") or "WRITE_GATEWAY_FAILED")
            raise ContentMigrationError(reason, action, str(request.get("target_relative_path", "")))
        return payload

def build_review(
    client: MemoryctlClient,
    *,
    mode: str = LEGACY_SCOPE_MODE,
) -> dict[str, Any]:
    first_doctor = client.doctor()
    first_complete, first = normalize_and_project_query_for_actor(
        first_doctor,
        mode=mode,
        actor=client.actor,
        require_all_automatable=mode == LEGACY_SCOPE_MODE,
    )
    assert_doctor_migration_safe(first_doctor, first_complete, mode=mode)
    items: list[dict[str, Any]] = []
    plan_head = ""
    for record in first["migration_query"]:
        if mode == GOVERNANCE_V4_MODE and record.get("automatable") is not True:
            continue
        if mode == RISK_V4_MODE and not bool(
            isinstance(record.get("risk_recommendation"), dict)
            and _risk_recommendation_is_safe_automatic(
                record["risk_recommendation"]
            )
        ):
            continue
        read = validate_read_response(
            client.write("read-target", migration_read_request(record, mode=mode)),
            record,
            mode=mode,
        )
        if plan_head and read["base_git_head"] != plan_head:
            raise ContentMigrationError("GIT_HEAD_CHANGED_DURING_PLAN", "plan")
        plan_head = read["base_git_head"]
        _text, proposal_digest = _proposal(
            record,
            read["content"],
            actor=client.actor,
            mode=mode,
        )
        item = {
            "target_relative_path": record["target_relative_path"],
            "requested_app_id": record["requested_app_id"],
            "requested_project_id": record["requested_project_id"],
            "read_token": read["read_token"],
            "base_raw_sha256": read["base_raw_sha256"],
            "base_canonical_sha256": read["base_canonical_sha256"],
            "base_git_head": read["base_git_head"],
            "proposal_raw_sha256": proposal_digest.raw_sha256,
            "proposal_canonical_sha256": proposal_digest.canonical_sha256,
            "proposal_size_bytes": proposal_digest.size_bytes,
        }
        if mode in {GOVERNANCE_V4_MODE, RISK_V4_MODE}:
            item["requested_agent_scope"] = record["requested_agent_scope"]
        if mode == GOVERNANCE_V4_MODE:
            item.update({
                "candidate_metadata": _deep_json(
                    record["candidate_metadata"],
                    "MIGRATION_CANDIDATE_INVALID",
                ),
                "expected_memory_id": read["expected_memory_id"],
                "manual_review_required": bool(record["manual_review_required"]),
                "manual_review_reasons": list(record["manual_review_reasons"]),
            })
        elif mode == RISK_V4_MODE:
            recommendation = dict(record["risk_recommendation"])
            item.update({
                "migration_operation": str(recommendation["followup_operation"]),
                "recommended_risk_class": str(recommendation["recommended"]),
                "target_status": str(recommendation["target_status"]),
                "confirmation_mode": "capability",
                "manual_review_required": bool(
                    recommendation["manual_review_required"]
                ),
                "manual_review_reasons": list(recommendation["reason_codes"]),
            })
        else:
            item["legacy_scope_app_id"] = record["legacy_scope_app_id"]
        items.append(item)
    terminal_doctor = client.doctor()
    terminal_complete, terminal = normalize_and_project_query_for_actor(
        terminal_doctor,
        mode=mode,
        actor=client.actor,
        require_all_automatable=mode == LEGACY_SCOPE_MODE,
    )
    assert_doctor_migration_safe(terminal_doctor, terminal_complete, mode=mode)
    if terminal_complete != first_complete or terminal != first:
        raise ContentMigrationError("MIGRATION_QUERY_CHANGED_DURING_PLAN", "plan")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": REVIEW_KIND,
        "created_at": utc_now(),
        "actor": client.actor,
        "mode": mode,
        "initial_git_head": plan_head,
        "doctor_binding": first,
        "items": items,
        "review_status": "pending_user_confirmation",
        "automatic_item_count": len(items),
        "manual_review_count": (
            int(first.get("manual_review_documents", 0) or 0)
            + int(first.get("unassigned_manual_review_count", 0) or 0)
        ),
        "unassigned_manual_review_count": int(
            first.get("unassigned_manual_review_count", 0) or 0
        ),
    }


def _review_bytes(review: dict[str, Any]) -> bytes:
    return (json.dumps(review, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def write_private_exclusive(path: Path, payload: bytes) -> None:
    path = Path(os.path.abspath(os.path.expanduser(str(path))))
    try:
        parent = path.parent.lstat()
    except OSError as exc:
        raise ContentMigrationError("REVIEW_PARENT_INVALID", "review-write") from exc
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise ContentMigrationError("REVIEW_PARENT_INVALID", "review-write")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            if os.name == "posix":
                os.fchmod(handle.fileno(), PRIVATE_FILE_MODE)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise ContentMigrationError("REVIEW_FILE_EXISTS", "review-write") from exc
    except OSError as exc:
        raise ContentMigrationError("REVIEW_WRITE_FAILED", "review-write") from exc


def read_private_file(path: Path, *, maximum: int = MAX_REVIEW_BYTES) -> tuple[bytes, os.stat_result]:
    path = Path(os.path.abspath(os.path.expanduser(str(path))))
    try:
        before = path.lstat()
    except OSError as exc:
        raise ContentMigrationError("PRIVATE_FILE_UNREADABLE", "private-read") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ContentMigrationError("PRIVATE_FILE_UNSAFE", "private-read")
    if os.name == "posix":
        if stat.S_IMODE(before.st_mode) & 0o077 or before.st_uid != os.geteuid():
            raise ContentMigrationError("PRIVATE_FILE_PERMISSIONS", "private-read")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or (
                    os.name == "posix"
                    and (stat.S_IMODE(opened.st_mode) & 0o077 or opened.st_uid != os.geteuid())
                )
            ):
                raise ContentMigrationError("PRIVATE_FILE_CHANGED", "private-read")
            payload = handle.read(maximum + 1)
    except OSError as exc:
        raise ContentMigrationError("PRIVATE_FILE_UNREADABLE", "private-read") from exc
    if len(payload) > maximum:
        raise ContentMigrationError("PRIVATE_FILE_TOO_LARGE", "private-read")
    return payload, before


def _validate_legacy_review(review: dict[str, Any]) -> dict[str, Any]:
    if review.get("schema_version") != SCHEMA_VERSION or review.get("kind") != REVIEW_KIND:
        raise ContentMigrationError("REVIEW_SCHEMA_INVALID", "review")
    actor = review.get("actor")
    if actor not in {"codex", "claude"}:
        raise ContentMigrationError("REVIEW_ACTOR_INVALID", "review")
    if review.get("review_status") != "pending_user_confirmation":
        raise ContentMigrationError("REVIEW_STATUS_INVALID", "review")
    binding = review.get("doctor_binding")
    items = review.get("items")
    if not isinstance(binding, dict) or not isinstance(items, list):
        raise ContentMigrationError("REVIEW_INVALID", "review")
    try:
        normalized_binding = normalize_doctor_query(
            {"checks": [{"name": "legacy_scope_documents", "detail": binding}]},
            require_all_automatable=True,
        )
    except ContentMigrationError as exc:
        raise ContentMigrationError("REVIEW_QUERY_BINDING_INVALID", "review") from exc
    if binding != normalized_binding:
        raise ContentMigrationError("REVIEW_QUERY_BINDING_INVALID", "review")
    query = binding["migration_query"]
    by_target = {str(item.get("target_relative_path", "")): item for item in query if isinstance(item, dict)}
    if len(by_target) != len(query) or len(items) != len(query):
        raise ContentMigrationError("REVIEW_ITEM_SET_INVALID", "review")
    initial_git_head = review.get("initial_git_head")
    if items and (not isinstance(initial_git_head, str) or GIT_HEAD_RE.fullmatch(initial_git_head) is None):
        raise ContentMigrationError("REVIEW_GIT_HEAD_INVALID", "review")
    if not items and initial_git_head != "":
        raise ContentMigrationError("REVIEW_GIT_HEAD_INVALID", "review")
    validated_items: list[dict[str, Any]] = []
    item_targets: set[str] = set()
    item_keys = {
        "target_relative_path", "requested_app_id", "requested_project_id",
        "legacy_scope_app_id", "read_token", "base_raw_sha256",
        "base_canonical_sha256", "base_git_head", "proposal_raw_sha256",
        "proposal_canonical_sha256", "proposal_size_bytes",
    }
    for raw in items:
        if not isinstance(raw, dict) or set(raw) != item_keys:
            raise ContentMigrationError("REVIEW_ITEM_INVALID", "review")
        target = str(raw.get("target_relative_path", ""))
        record = by_target.get(target)
        if record is None or target in item_targets:
            raise ContentMigrationError("REVIEW_ITEM_SET_INVALID", "review")
        item_targets.add(target)
        for review_key, query_key in (
            ("requested_app_id", "requested_app_id"),
            ("requested_project_id", "requested_project_id"),
            ("legacy_scope_app_id", "legacy_scope_app_id"),
        ):
            if raw.get(review_key) != record.get(query_key):
                raise ContentMigrationError("REVIEW_SCOPE_BINDING_INVALID", "review")
        for key in (
            "read_token", "base_raw_sha256", "base_canonical_sha256",
            "proposal_raw_sha256", "proposal_canonical_sha256",
        ):
            if not isinstance(raw.get(key), str) or HASH_RE.fullmatch(str(raw[key])) is None:
                raise ContentMigrationError("REVIEW_HASH_INVALID", "review")
        if (
            not isinstance(raw.get("base_git_head"), str)
            or GIT_HEAD_RE.fullmatch(str(raw["base_git_head"])) is None
            or raw["base_git_head"] != initial_git_head
        ):
            raise ContentMigrationError("REVIEW_GIT_HEAD_INVALID", "review")
        if (
            not isinstance(raw.get("proposal_size_bytes"), int)
            or isinstance(raw.get("proposal_size_bytes"), bool)
            or raw["proposal_size_bytes"] <= 0
            or raw["proposal_size_bytes"] > write_intent.MAX_PROPOSAL_BYTES
        ):
            raise ContentMigrationError("REVIEW_ITEM_INVALID", "review")
        validated_items.append(_deep_json(raw, "REVIEW_ITEM_INVALID"))
    if item_targets != set(by_target):
        raise ContentMigrationError("REVIEW_ITEM_SET_INVALID", "review")
    validated_items.sort(key=lambda item: str(item["target_relative_path"]))
    result = _deep_json(review, "REVIEW_INVALID")
    result["items"] = validated_items
    return result


def _validate_governance_review(review: dict[str, Any]) -> dict[str, Any]:
    if review.get("schema_version") != SCHEMA_VERSION or review.get("kind") != REVIEW_KIND:
        raise ContentMigrationError("REVIEW_SCHEMA_INVALID", "review")
    if review.get("mode") != GOVERNANCE_V4_MODE:
        raise ContentMigrationError("REVIEW_MODE_INVALID", "review")
    actor = review.get("actor")
    if actor not in {"codex", "claude"}:
        raise ContentMigrationError("REVIEW_ACTOR_INVALID", "review")
    if review.get("review_status") != "pending_user_confirmation":
        raise ContentMigrationError("REVIEW_STATUS_INVALID", "review")
    binding = review.get("doctor_binding")
    items = review.get("items")
    if not isinstance(binding, dict) or not isinstance(items, list):
        raise ContentMigrationError("REVIEW_INVALID", "review")
    try:
        normalized_binding = _validate_projected_governance_binding(
            binding,
            actor=actor,
            mode=GOVERNANCE_V4_MODE,
        )
    except ContentMigrationError as exc:
        raise ContentMigrationError("REVIEW_QUERY_BINDING_INVALID", "review") from exc
    if binding != normalized_binding:
        raise ContentMigrationError("REVIEW_QUERY_BINDING_INVALID", "review")
    expected_unassigned = int(binding["unassigned_manual_review_count"])
    expected_manual = (
        int(binding.get("manual_review_documents", 0) or 0)
        + expected_unassigned
    )
    if (
        review.get("automatic_item_count") != len(items)
        or review.get("manual_review_count") != expected_manual
        or review.get("unassigned_manual_review_count") != expected_unassigned
    ):
        raise ContentMigrationError("REVIEW_MANUAL_COUNT_INVALID", "review")
    query = {
        str(item["target_relative_path"]): item
        for item in binding["migration_query"]
        if isinstance(item, dict) and item.get("automatable") is True
    }
    if len(items) != len(query):
        raise ContentMigrationError("REVIEW_ITEM_SET_INVALID", "review")
    initial_git_head = review.get("initial_git_head")
    if items and (
        not isinstance(initial_git_head, str)
        or GIT_HEAD_RE.fullmatch(initial_git_head) is None
    ):
        raise ContentMigrationError("REVIEW_GIT_HEAD_INVALID", "review")
    if not items and initial_git_head != "":
        raise ContentMigrationError("REVIEW_GIT_HEAD_INVALID", "review")
    expected_keys = {
        "target_relative_path", "requested_agent_scope", "requested_app_id",
        "requested_project_id",
        "read_token", "base_raw_sha256", "base_canonical_sha256",
        "base_git_head", "proposal_raw_sha256",
        "proposal_canonical_sha256", "proposal_size_bytes",
        "candidate_metadata", "expected_memory_id",
        "manual_review_required", "manual_review_reasons",
    }
    validated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in items:
        if not isinstance(raw, dict) or set(raw) != expected_keys:
            raise ContentMigrationError("REVIEW_ITEM_INVALID", "review")
        target = str(raw.get("target_relative_path", ""))
        record = query.get(target)
        if record is None or target in seen:
            raise ContentMigrationError("REVIEW_ITEM_SET_INVALID", "review")
        seen.add(target)
        for key in (
            "requested_agent_scope", "requested_app_id", "requested_project_id",
            "candidate_metadata", "manual_review_required", "manual_review_reasons",
        ):
            if raw.get(key) != record.get(key):
                raise ContentMigrationError("REVIEW_CANDIDATE_BINDING_INVALID", "review")
        expected_id = str(
            record["candidate_metadata"].get("memory_id")
            or record.get("current_memory_id", "")
        )
        if str(raw.get("expected_memory_id", "")) != expected_id:
            raise ContentMigrationError("REVIEW_CANDIDATE_BINDING_INVALID", "review")
        for key in (
            "read_token", "base_raw_sha256", "base_canonical_sha256",
            "proposal_raw_sha256", "proposal_canonical_sha256",
        ):
            if not isinstance(raw.get(key), str) or HASH_RE.fullmatch(str(raw[key])) is None:
                raise ContentMigrationError("REVIEW_HASH_INVALID", "review")
        if (
            raw.get("base_git_head") != initial_git_head
            or not isinstance(raw.get("base_git_head"), str)
            or GIT_HEAD_RE.fullmatch(str(raw["base_git_head"])) is None
        ):
            raise ContentMigrationError("REVIEW_GIT_HEAD_INVALID", "review")
        size = raw.get("proposal_size_bytes")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or size > write_intent.MAX_PROPOSAL_BYTES
        ):
            raise ContentMigrationError("REVIEW_ITEM_INVALID", "review")
        validated.append(_deep_json(raw, "REVIEW_ITEM_INVALID"))
    if seen != set(query):
        raise ContentMigrationError("REVIEW_ITEM_SET_INVALID", "review")
    result = _deep_json(review, "REVIEW_INVALID")
    result["items"] = sorted(
        validated,
        key=lambda item: str(item["target_relative_path"]),
    )
    return result


def _validate_risk_review(review: dict[str, Any]) -> dict[str, Any]:
    actor = review.get("actor")
    if (
        review.get("schema_version") != SCHEMA_VERSION
        or review.get("kind") != REVIEW_KIND
        or review.get("mode") != RISK_V4_MODE
        or actor not in {"codex", "claude"}
        or review.get("review_status") != "pending_user_confirmation"
    ):
        raise ContentMigrationError("REVIEW_SCHEMA_INVALID", "review")
    binding = review.get("doctor_binding")
    items = review.get("items")
    if not isinstance(binding, dict) or not isinstance(items, list):
        raise ContentMigrationError("REVIEW_INVALID", "review")
    try:
        canonical_binding = _validate_projected_governance_binding(
            binding,
            actor=str(actor),
            mode=RISK_V4_MODE,
        )
    except ContentMigrationError as exc:
        raise ContentMigrationError(
            "REVIEW_QUERY_BINDING_INVALID",
            "review",
        ) from exc
    if binding != canonical_binding:
        raise ContentMigrationError("REVIEW_QUERY_BINDING_INVALID", "review")
    expected_unassigned = int(binding["unassigned_manual_review_count"])
    expected_manual = (
        int(binding.get("manual_review_documents", 0) or 0)
        + expected_unassigned
    )
    if (
        review.get("automatic_item_count") != len(items)
        or review.get("manual_review_count") != expected_manual
        or review.get("unassigned_manual_review_count") != expected_unassigned
    ):
        raise ContentMigrationError("REVIEW_MANUAL_COUNT_INVALID", "review")
    query = binding.get("migration_query")
    if (
        binding.get("mode") != RISK_V4_MODE
        or not isinstance(query, list)
        or str(binding.get("migration_query_sha256", ""))
        != canonical_sha256(query)
    ):
        raise ContentMigrationError("REVIEW_QUERY_BINDING_INVALID", "review")
    automatable: dict[str, dict[str, Any]] = {}
    for raw in query:
        if not isinstance(raw, dict):
            raise ContentMigrationError("REVIEW_QUERY_BINDING_INVALID", "review")
        target = str(raw.get("target_relative_path", ""))
        recommendation = raw.get("risk_recommendation")
        if (
            TARGET_RE.fullmatch(target) is None
            or target in automatable
            or not isinstance(recommendation, dict)
        ):
            raise ContentMigrationError("REVIEW_QUERY_BINDING_INVALID", "review")
        operation = str(recommendation.get("followup_operation", ""))
        recommended = str(recommendation.get("recommended", ""))
        target_status = str(recommendation.get("target_status", ""))
        if (
            operation not in {"none", "content_update", "status_transition"}
            or recommended not in {"", "ordinary", "action_sensitive"}
            or (
                operation == "status_transition"
                and target_status != "pending_verification"
            )
            or (
                operation in {"none", "content_update"}
                and target_status
            )
        ):
            raise ContentMigrationError("REVIEW_QUERY_BINDING_INVALID", "review")
        if _risk_recommendation_is_safe_automatic(recommendation):
            automatable[target] = raw
    if len(items) != len(automatable):
        raise ContentMigrationError("REVIEW_ITEM_SET_INVALID", "review")
    initial_head = str(review.get("initial_git_head", ""))
    if items and GIT_HEAD_RE.fullmatch(initial_head) is None:
        raise ContentMigrationError("REVIEW_GIT_HEAD_INVALID", "review")
    if not items and initial_head:
        raise ContentMigrationError("REVIEW_GIT_HEAD_INVALID", "review")
    expected_keys = {
        "target_relative_path", "requested_agent_scope", "requested_app_id",
        "requested_project_id",
        "read_token", "base_raw_sha256", "base_canonical_sha256",
        "base_git_head", "proposal_raw_sha256",
        "proposal_canonical_sha256", "proposal_size_bytes",
        "migration_operation", "recommended_risk_class", "target_status",
        "confirmation_mode", "manual_review_required",
        "manual_review_reasons",
    }
    validated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in items:
        if not isinstance(raw, dict) or set(raw) != expected_keys:
            raise ContentMigrationError("REVIEW_ITEM_INVALID", "review")
        target = str(raw.get("target_relative_path", ""))
        record = automatable.get(target)
        if record is None or target in seen:
            raise ContentMigrationError("REVIEW_ITEM_SET_INVALID", "review")
        seen.add(target)
        recommendation = record["risk_recommendation"]
        expected_mode = "capability"
        expected_values = {
            "requested_agent_scope": record["requested_agent_scope"],
            "requested_app_id": record["requested_app_id"],
            "requested_project_id": record["requested_project_id"],
            "migration_operation": recommendation["followup_operation"],
            "recommended_risk_class": recommendation["recommended"],
            "target_status": recommendation["target_status"],
            "confirmation_mode": expected_mode,
            "manual_review_required": recommendation["manual_review_required"],
            "manual_review_reasons": recommendation["reason_codes"],
        }
        if any(raw.get(key) != value for key, value in expected_values.items()):
            raise ContentMigrationError("REVIEW_CANDIDATE_BINDING_INVALID", "review")
        for key in (
            "read_token", "base_raw_sha256", "base_canonical_sha256",
            "proposal_raw_sha256", "proposal_canonical_sha256",
        ):
            if HASH_RE.fullmatch(str(raw.get(key, ""))) is None:
                raise ContentMigrationError("REVIEW_HASH_INVALID", "review")
        if raw.get("base_git_head") != initial_head:
            raise ContentMigrationError("REVIEW_GIT_HEAD_INVALID", "review")
        size = raw.get("proposal_size_bytes")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or size > write_intent.MAX_PROPOSAL_BYTES
        ):
            raise ContentMigrationError("REVIEW_ITEM_INVALID", "review")
        validated.append(_deep_json(raw, "REVIEW_ITEM_INVALID"))
    if seen != set(automatable):
        raise ContentMigrationError("REVIEW_ITEM_SET_INVALID", "review")
    result = _deep_json(review, "REVIEW_INVALID")
    result["items"] = sorted(
        validated,
        key=lambda item: str(item["target_relative_path"]),
    )
    return result


def validate_review(review: dict[str, Any]) -> dict[str, Any]:
    if review.get("mode") == RISK_V4_MODE:
        return _validate_risk_review(review)
    if review.get("mode", LEGACY_SCOPE_MODE) == GOVERNANCE_V4_MODE:
        return _validate_governance_review(review)
    return _validate_legacy_review(review)


def compare_current_query(review: dict[str, Any], current: dict[str, Any]) -> set[str]:
    """Allow only the expected shrinkage caused by already-completed items."""

    review_binding = review["doctor_binding"]
    if review.get("mode") in {GOVERNANCE_V4_MODE, RISK_V4_MODE} and (
        review_binding.get("owner_lane_policy") != GOVERNANCE_OWNER_LANE_POLICY
        or current.get("owner_lane_policy") != GOVERNANCE_OWNER_LANE_POLICY
        or review_binding.get("owner_actor") != review.get("actor")
        or current.get("owner_actor") != review.get("actor")
    ):
        raise ContentMigrationError("MIGRATION_OWNER_LANE_CHANGED", "apply-preflight")
    if (
        review.get("mode") in {GOVERNANCE_V4_MODE, RISK_V4_MODE}
        and review_binding.get("unassigned_manual_review_count")
        != current.get("unassigned_manual_review_count")
    ):
        raise ContentMigrationError(
            "MIGRATION_UNASSIGNED_MANUAL_CHANGED",
            "apply-preflight",
        )
    expected_rows = review_binding["migration_query"]
    expected = {str(item["target_relative_path"]): item for item in expected_rows}
    actual_rows = current["migration_query"]
    actual = {str(item["target_relative_path"]): item for item in actual_rows}
    for target, record in actual.items():
        if target not in expected or record != expected[target]:
            raise ContentMigrationError("MIGRATION_SCOPE_CHANGED", "apply-preflight", target)
    disappeared = set(expected) - set(actual)
    if (
        review.get("mode") in {GOVERNANCE_V4_MODE, RISK_V4_MODE}
        and not disappeared
        and review_binding.get("complete_doctor_binding_sha256")
        != current.get("complete_doctor_binding_sha256")
    ):
        # Before this lane has produced an expected shrink, the complete
        # Doctor snapshot must still be the exact one that was validated before
        # projection.  Once a journaled lane item disappears, the full hash is
        # expected to change and the exact lane rows remain the CAS boundary.
        raise ContentMigrationError(
            "MIGRATION_COMPLETE_BINDING_CHANGED",
            "apply-preflight",
        )
    return disappeared


def _progress_path(review_path: Path) -> Path:
    return review_path.with_name(review_path.name + ".progress.jsonl")


def _progress_lock_path(progress_path: Path) -> Path:
    return progress_path.with_name(progress_path.name + ".lock")


@contextlib.contextmanager
def progress_transaction_lock(progress_path: Path):
    """Fail closed when another process owns this review's state machine.

    The lock intentionally covers Doctor/read/prepare/apply and every progress
    append, not just the final write.  The small persistent lock file is never
    deleted, so a symlink swap or concurrent recreation cannot create a second
    lock domain.
    """

    path = Path(os.path.abspath(os.path.expanduser(str(_progress_lock_path(progress_path)))))
    try:
        parent = path.parent.lstat()
        current_uid = os.geteuid() if hasattr(os, "geteuid") else parent.st_uid
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != current_uid
            or (os.name != "nt" and stat.S_IMODE(parent.st_mode) & 0o077)
        ):
            raise ContentMigrationError("PROGRESS_LOCK_PARENT_UNSAFE", "lock")
        if path.exists() or path.is_symlink():
            before = path.lstat()
            if (
                stat.S_ISLNK(before.st_mode)
                or not stat.S_ISREG(before.st_mode)
                or before.st_uid != current_uid
                or (os.name != "nt" and stat.S_IMODE(before.st_mode) != PRIVATE_FILE_MODE)
            ):
                raise ContentMigrationError("PROGRESS_LOCK_UNSAFE", "lock")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != current_uid
            or (os.name != "nt" and stat.S_IMODE(opened.st_mode) != PRIVATE_FILE_MODE)
        ):
            raise ContentMigrationError("PROGRESS_LOCK_UNSAFE", "lock")
        if opened.st_size == 0:
            os.write(descriptor, b"0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif msvcrt is not None:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:  # pragma: no cover - all supported platforms provide one.
            raise ContentMigrationError("PROGRESS_LOCK_UNAVAILABLE", "lock")
    except ContentMigrationError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    except (OSError, PermissionError) as exc:
        if "descriptor" in locals():
            os.close(descriptor)
        raise ContentMigrationError("MIGRATION_ALREADY_RUNNING", "lock") from exc
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


def load_progress(path: Path, *, review_sha256: str, actor: str) -> list[dict[str, Any]]:
    if not path.exists() and not path.is_symlink():
        header = {
            "schema_version": SCHEMA_VERSION,
            "kind": PROGRESS_KIND,
            "event": "header",
            "review_sha256": review_sha256,
            "actor": actor,
            "created_at": utc_now(),
        }
        write_private_exclusive(path, canonical_bytes(header) + b"\n")
        return [header]
    payload, _metadata = read_private_file(path)
    events: list[dict[str, Any]] = []
    try:
        for line in payload.splitlines():
            if line.strip():
                event = strict_json_loads(line)
                if not isinstance(event, dict):
                    raise ValueError
                events.append(event)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ContentMigrationError("PROGRESS_INVALID", "progress") from exc
    if (
        not events
        or set(events[0]) != {
            "schema_version", "kind", "event", "review_sha256", "actor", "created_at",
        }
        or events[0].get("schema_version") != SCHEMA_VERSION
        or events[0].get("event") != "header"
        or events[0].get("kind") != PROGRESS_KIND
        or events[0].get("review_sha256") != review_sha256
        or events[0].get("actor") != actor
        or not isinstance(events[0].get("created_at"), str)
        or not str(events[0]["created_at"]).strip()
    ):
        raise ContentMigrationError("PROGRESS_BINDING_INVALID", "progress")
    return events


def append_progress(path: Path, event: dict[str, Any]) -> None:
    path = Path(os.path.abspath(os.path.expanduser(str(path))))
    payload, before = read_private_file(path)
    if not payload or not payload.endswith(b"\n"):
        raise ContentMigrationError("PROGRESS_INVALID", "progress")
    try:
        for line in payload.splitlines():
            parsed = strict_json_loads(line)
            if not isinstance(parsed, dict):
                raise ValueError
    except (UnicodeError, ValueError) as exc:
        raise ContentMigrationError("PROGRESS_INVALID", "progress") from exc
    candidate_payload = payload + canonical_bytes(event) + b"\n"
    if len(candidate_payload) > MAX_REVIEW_BYTES:
        raise ContentMigrationError("PROGRESS_TOO_LARGE", "progress")
    candidate = path.with_name(
        f".{path.name}.candidate-{uuid.uuid4().hex}"
    )
    try:
        _write_progress_candidate(candidate, candidate_payload)
        staged, _staged_metadata = read_private_file(candidate)
        if staged != candidate_payload:
            raise ContentMigrationError("PROGRESS_CANDIDATE_INVALID", "progress")
        current, current_metadata = read_private_file(path)
        if (
            (current_metadata.st_dev, current_metadata.st_ino)
            != (before.st_dev, before.st_ino)
            or current != payload
        ):
            raise ContentMigrationError("PROGRESS_CHANGED", "progress")
        os.replace(candidate, path)
        _fsync_progress_directory(path.parent)
        published, published_metadata = read_private_file(path)
        if (
            published != candidate_payload
            or (published_metadata.st_dev, published_metadata.st_ino)
            != (_staged_metadata.st_dev, _staged_metadata.st_ino)
        ):
            raise ContentMigrationError("PROGRESS_PUBLISH_INVALID", "progress")
    except ContentMigrationError:
        raise
    except OSError as exc:
        raise ContentMigrationError("PROGRESS_APPEND_FAILED", "progress") from exc


def _write_progress_candidate(path: Path, payload: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        if os.name == "posix":
            os.fchmod(handle.fileno(), PRIVATE_FILE_MODE)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_progress_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def progress_state(events: list[dict[str, Any]], review: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not events or events[0].get("event") != "header":
        raise ContentMigrationError("PROGRESS_EVENT_INVALID", "progress")
    ordered = [str(item["target_relative_path"]) for item in review["items"]]
    state: dict[str, dict[str, Any]] = {}
    item_index = 0
    expected_head = str(review.get("initial_git_head", ""))
    pending_prepared: dict[str, Any] | None = None
    for event in events[1:]:
        target = str(event.get("target_relative_path", ""))
        phase = event.get("event")
        if item_index >= len(ordered) or target != ordered[item_index] or phase not in {"prepared", "completed"}:
            raise ContentMigrationError("PROGRESS_EVENT_INVALID", "progress")
        if event.get("schema_version") != SCHEMA_VERSION:
            raise ContentMigrationError("PROGRESS_EVENT_INVALID", "progress")
        if phase == "prepared":
            ordinary_keys = {
                "schema_version", "event", "time", "target_relative_path",
                "proposal_id", "fencing_token", "base_git_head",
            }
            advanced_keys = ordinary_keys | {"advanced_from_git_head"}
            event_keys = set(event)
            advanced_from = event.get("advanced_from_git_head")
            ordinary_head = (
                event_keys == ordinary_keys
                and event.get("base_git_head") == expected_head
            )
            explicit_descendant_advance = (
                event_keys == advanced_keys
                and advanced_from == expected_head
                and event.get("base_git_head") != expected_head
                and isinstance(event.get("base_git_head"), str)
                and GIT_HEAD_RE.fullmatch(str(event["base_git_head"]))
                is not None
            )
            if (
                pending_prepared is not None
                or not (ordinary_head or explicit_descendant_advance)
                or not isinstance(event.get("proposal_id"), str)
                or IDENTIFIER_RE.fullmatch(str(event["proposal_id"])) is None
                or not isinstance(event.get("fencing_token"), int)
                or isinstance(event.get("fencing_token"), bool)
                or int(event["fencing_token"]) <= 0
            ):
                raise ContentMigrationError("PROGRESS_EVENT_ORDER_INVALID", "progress")
            pending_prepared = event
            state[target] = event
            continue
        if (
            pending_prepared is None
            or set(event) != {
                "schema_version", "event", "time", "target_relative_path",
                "proposal_id", "fencing_token", "git_commit", "receipt_id",
            }
            or event.get("proposal_id") != pending_prepared.get("proposal_id")
            or event.get("fencing_token") != pending_prepared.get("fencing_token")
            or not isinstance(event.get("git_commit"), str)
            or GIT_HEAD_RE.fullmatch(str(event["git_commit"])) is None
            or not isinstance(event.get("receipt_id"), str)
            or IDENTIFIER_RE.fullmatch(str(event["receipt_id"])) is None
        ):
            raise ContentMigrationError("PROGRESS_EVENT_ORDER_INVALID", "progress")
        state[target] = event
        expected_head = str(event["git_commit"])
        pending_prepared = None
        item_index += 1
    return state


def _prepare_request(
    record: dict[str, Any],
    read: dict[str, Any],
    proposal: str,
    review_sha256: str,
    *,
    mode: str = LEGACY_SCOPE_MODE,
) -> dict[str, Any]:
    request = {
        **migration_read_request(record, mode=mode),
        "summary": (
            f"Governance v4 metadata migration for {record['target_relative_path']}"
            if mode == GOVERNANCE_V4_MODE
            else (
                f"Risk v4 governance follow-up for {record['target_relative_path']}"
                if mode == RISK_V4_MODE
                else f"Scope metadata migration for {record['target_relative_path']}"
            )
        ),
        "proposal_markdown": proposal,
        "read_token": read["read_token"],
        "source_class": "user_direct",
        "knowledge_kind": (
            "rule" if mode == GOVERNANCE_V4_MODE else "fact"
        ),
        "asserted_by": "user",
        "evidence_ref": f"content-migration-review:{review_sha256}",
    }
    if mode == GOVERNANCE_V4_MODE:
        request["operation"] = "governance_migration"
    elif mode == RISK_V4_MODE:
        recommendation = dict(record.get("risk_recommendation", {}))
        operation = str(recommendation.get("followup_operation", ""))
        if operation == "status_transition":
            request.update({
                "operation": "status_transition",
                "target_status": "pending_verification",
                "transition_reason": (
                    "Action-sensitive memory requires quarantine because it is "
                    "expired, review-overdue, unverified, or lacks a complete "
                    "atomic fact tuple with durable evidence provenance."
                ),
            })
    return request


def _apply_request(
    item: dict[str, Any],
    prepared: dict[str, Any],
    proposal: str,
    *,
    confirmation_capability_path: str = "",
    confirmation_capability_token: str = "",
    confirmed_by: str = "",
    confirmation_reference: str = "",
) -> dict[str, Any]:
    if bool(confirmation_capability_path) != bool(confirmation_capability_token):
        raise ContentMigrationError(
            "CONFIRMATION_CAPABILITY_INVALID",
            "apply",
            str(item.get("target_relative_path", "")),
        )
    request = {
        "schema_version": WIRE_SCHEMA_VERSION,
        "proposal_id": str(prepared["proposal_id"]),
        "fencing_token": int(prepared["fencing_token"]),
        "target_relative_path": str(item["target_relative_path"]),
        "proposal_markdown": proposal,
        "proposal_raw_sha256": str(item["proposal_raw_sha256"]),
        "proposal_canonical_sha256": str(item["proposal_canonical_sha256"]),
    }
    if confirmation_capability_path and confirmation_capability_token:
        request.update(
            {
                "confirmation_capability_path": confirmation_capability_path,
                "confirmation_capability_token": confirmation_capability_token,
            }
        )
    if bool(confirmed_by) != bool(confirmation_reference):
        raise ContentMigrationError(
            "CONFIRMATION_INVALID",
            "apply",
            str(item.get("target_relative_path", "")),
        )
    if confirmed_by:
        request.update({
            "confirmed_by": confirmed_by,
            "confirmation_reference": confirmation_reference,
        })
    return request


def _consume_risk_content_update_confirmation(
    client: MemoryctlClient,
    *,
    item: dict[str, Any],
    phase: dict[str, Any],
    capability_path: str,
    capability_token: str,
) -> str:
    """Consume one exact human capability before an ordinary risk update.

    The generic writer intentionally treats normal ``content_update`` as a
    host-confirmed operation.  The governed batch is stricter: it independently
    consumes a fully bound one-shot capability, then passes only the resulting
    non-secret approval reference to the writer.
    """

    target = str(item["target_relative_path"])
    try:
        canonical_target = write_gateway._formal_target(target)
        consumed = confirmation_capability.consume_confirmation_capability(
            write_gateway.CONFIG_ROOT,
            capability_path=capability_path,
            token=capability_token,
            subject_actor=client.actor,
            raw_task_id=client.session_id,
            raw_session_id=client.session_id,
            proposal_id=str(phase["proposal_id"]),
            proposal_raw_sha256=str(item["proposal_raw_sha256"]),
            proposal_canonical_sha256=str(item["proposal_canonical_sha256"]),
            target_relative_path=target,
            target_key=canonical_target.target_key,
            operation="content_update",
            reconcile_action="UPDATE",
            fencing_token=int(phase["fencing_token"]),
            # The ordinary risk update independently consumes its capability
            # before invoking Write Gateway.  Recover only the exact same
            # proposal/fence after a crash between those two durable steps.
            allow_idempotent_recovery=True,
        )
        return confirmation_capability.approval_reference(consumed)
    except (
        confirmation_capability.ConfirmationCapabilityError,
        write_gateway.MemoryWriteError,
        ValueError,
    ) as exc:
        raise ContentMigrationError(
            getattr(exc, "reason_code", "CONFIRMATION_CAPABILITY_INVALID"),
            "apply",
            target,
        ) from exc


def _validated_prepared_phase(
    payload: dict[str, Any],
    *,
    item: dict[str, Any],
    read: dict[str, Any],
    mode: str = LEGACY_SCOPE_MODE,
) -> dict[str, Any]:
    target = str(item["target_relative_path"])
    proposal_id = payload.get("proposal_id")
    fencing_token = payload.get("fencing_token")
    if (
        payload.get("status") != "prepared"
        or payload.get("recommended_action") != (
            "UPDATE"
            if mode in {GOVERNANCE_V4_MODE, RISK_V4_MODE}
            else "MIGRATE_LEGACY_SCOPE"
        )
        or payload.get("target_relative_path") != target
        or payload.get("scope_migration") is not (mode == LEGACY_SCOPE_MODE)
        or payload.get("confirmation_required") is not True
        or not isinstance(proposal_id, str)
        or IDENTIFIER_RE.fullmatch(proposal_id) is None
        or not isinstance(fencing_token, int)
        or isinstance(fencing_token, bool)
        or fencing_token <= 0
        or payload.get("base_raw_sha256") != read["base_raw_sha256"]
        or payload.get("base_canonical_sha256") != read["base_canonical_sha256"]
        or payload.get("base_git_head") != read["base_git_head"]
        or payload.get("proposal_raw_sha256") != item["proposal_raw_sha256"]
        or payload.get("proposal_canonical_sha256") != item["proposal_canonical_sha256"]
        or payload.get("proposal_size_bytes") != item["proposal_size_bytes"]
    ):
        raise ContentMigrationError("PREPARE_RESPONSE_INVALID", "prepare", target)
    return {
        "schema_version": SCHEMA_VERSION,
        "event": "prepared",
        "time": utc_now(),
        "target_relative_path": target,
        "proposal_id": proposal_id,
        "fencing_token": fencing_token,
        "base_git_head": read["base_git_head"],
    }


def _validated_apply_response(
    payload: dict[str, Any],
    *,
    item: dict[str, Any],
    phase: dict[str, Any],
    mode: str = LEGACY_SCOPE_MODE,
) -> dict[str, Any]:
    target = str(item["target_relative_path"])
    git_commit = payload.get("git_commit")
    receipt_id = payload.get("receipt_id")
    if (
        payload.get("status") != "applied"
        or payload.get("recommended_action") != (
            "UPDATE"
            if mode in {GOVERNANCE_V4_MODE, RISK_V4_MODE}
            else "MIGRATE_LEGACY_SCOPE"
        )
        or payload.get("target_relative_path") != target
        or payload.get("scope_migration") is not (mode == LEGACY_SCOPE_MODE)
        or payload.get("proposal_id") != phase["proposal_id"]
        or payload.get("fencing_token") != phase["fencing_token"]
        or payload.get("proposal_raw_sha256") != item["proposal_raw_sha256"]
        or payload.get("proposal_canonical_sha256") != item["proposal_canonical_sha256"]
        or not isinstance(git_commit, str)
        or GIT_HEAD_RE.fullmatch(git_commit) is None
        or not isinstance(receipt_id, str)
        or IDENTIFIER_RE.fullmatch(receipt_id) is None
        or not isinstance(payload.get("idempotent"), bool)
    ):
        raise ContentMigrationError("APPLY_RESPONSE_INVALID", "apply", target)
    return {
        "schema_version": SCHEMA_VERSION,
        "event": "completed",
        "time": utc_now(),
        "target_relative_path": target,
        "proposal_id": phase["proposal_id"],
        "fencing_token": phase["fencing_token"],
        "git_commit": git_commit,
        "receipt_id": receipt_id,
    }


def _completed_recovery_matches(
    recovery: dict[str, Any] | None,
    *,
    item: dict[str, Any],
    phase: dict[str, Any],
) -> bool:
    """Bind the completed-intent crash lane to one exact prepared item."""

    if not recovery:
        return False
    expected = {
        "target_relative_path": str(item.get("target_relative_path", "")),
        "proposal_id": str(phase.get("proposal_id", "")),
        "fencing_token": int(phase.get("fencing_token", 0) or 0),
        "proposal_raw_sha256": str(item.get("proposal_raw_sha256", "")),
        "proposal_canonical_sha256": str(
            item.get("proposal_canonical_sha256", "")
        ),
    }
    return set(recovery) == set(expected) and all(
        recovery.get(key) == value for key, value in expected.items()
    )


def _assert_git_target_projection(
    *,
    target: str,
    base_commit: str,
    current_head: str,
    expected_raw_sha256: str,
    expected_canonical_sha256: str,
    stage: str,
    diverged_reason: str,
    unavailable_reason: str,
    base_mismatch_reason: str,
    current_mismatch_reason: str,
    history_changed_reason: str,
) -> None:
    """Prove one target stayed byte-identical through a descendant history."""

    try:
        if not write_intent._git_is_ancestor(base_commit, current_head):
            raise ContentMigrationError(diverged_reason, stage, target)
        canonical_target = write_gateway._formal_target(target)
        base_exists, base_digest = write_intent.git_target_digest_at_commit(
            base_commit,
            canonical_target,
        )
        current_exists, current_digest = (
            (base_exists, base_digest)
            if current_head == base_commit
            else write_intent.git_target_digest_at_commit(
                current_head,
                canonical_target,
            )
        )
        version_chain = write_intent.git_version_chain(
            base_commit,
            current_head,
            canonical_target,
        )
    except ContentMigrationError:
        raise
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        write_intent.IntentError,
        write_gateway.MemoryWriteError,
    ) as exc:
        raise ContentMigrationError(unavailable_reason, stage, target) from exc
    if (
        not base_exists
        or base_digest.raw_sha256 != expected_raw_sha256
        or base_digest.canonical_sha256 != expected_canonical_sha256
    ):
        raise ContentMigrationError(base_mismatch_reason, stage, target)
    if (
        not current_exists
        or current_digest.raw_sha256 != expected_raw_sha256
        or current_digest.canonical_sha256 != expected_canonical_sha256
    ):
        raise ContentMigrationError(current_mismatch_reason, stage, target)
    versions = version_chain.get("versions")
    if version_chain.get("ok") is not True or not isinstance(versions, list):
        raise ContentMigrationError(unavailable_reason, stage, target)
    if any(
        not isinstance(version, dict)
        or version.get("exists") is not True
        or version.get("raw_sha256") != expected_raw_sha256
        or version.get("canonical_sha256") != expected_canonical_sha256
        for version in versions
    ):
        raise ContentMigrationError(history_changed_reason, stage, target)


def _assert_completed_recovery_git_projection(
    *,
    target: str,
    item: dict[str, Any],
    receipt_commit: str,
    current_head: str,
) -> None:
    """Prove an old completion remains on the current, unchanged projection."""

    _assert_git_target_projection(
        target=target,
        base_commit=receipt_commit,
        current_head=current_head,
        expected_raw_sha256=str(item.get("proposal_raw_sha256", "")),
        expected_canonical_sha256=str(
            item.get("proposal_canonical_sha256", "")
        ),
        stage="resume",
        diverged_reason="COMPLETED_RECOVERY_GIT_DIVERGED",
        unavailable_reason="COMPLETED_RECOVERY_GIT_PROJECTION_UNAVAILABLE",
        base_mismatch_reason="COMPLETED_RECOVERY_COMMIT_CONTENT_MISMATCH",
        current_mismatch_reason=(
            "COMPLETED_RECOVERY_CURRENT_COMMIT_CONTENT_MISMATCH"
        ),
        history_changed_reason="COMPLETED_RECOVERY_TARGET_HISTORY_CHANGED",
    )


def _assert_completed_progress_git_projection(
    *,
    target: str,
    item: dict[str, Any],
    receipt_commit: str,
    current_head: str,
) -> None:
    """Revalidate a normal completed journal event against current Git."""

    _assert_git_target_projection(
        target=target,
        base_commit=receipt_commit,
        current_head=current_head,
        expected_raw_sha256=str(item.get("proposal_raw_sha256", "")),
        expected_canonical_sha256=str(
            item.get("proposal_canonical_sha256", "")
        ),
        stage="resume",
        diverged_reason="COMPLETED_PROGRESS_GIT_DIVERGED",
        unavailable_reason="COMPLETED_PROGRESS_GIT_PROJECTION_UNAVAILABLE",
        base_mismatch_reason="COMPLETED_PROGRESS_COMMIT_CONTENT_MISMATCH",
        current_mismatch_reason=(
            "COMPLETED_PROGRESS_CURRENT_COMMIT_CONTENT_MISMATCH"
        ),
        history_changed_reason="COMPLETED_PROGRESS_TARGET_HISTORY_CHANGED",
    )


def _assert_completed_targets_at_head(
    *,
    completed: list[tuple[dict[str, Any], dict[str, Any]]],
    current_head: str,
    verified_completed_heads: dict[str, str] | None = None,
) -> None:
    """Revalidate every completed target at one immutable Git head."""

    if verified_completed_heads is None:
        verified_completed_heads = {}
    for completed_item, completed_phase in completed:
        completed_target = str(completed_item["target_relative_path"])
        if verified_completed_heads.get(completed_target) == current_head:
            continue
        _assert_completed_progress_git_projection(
            target=completed_target,
            item=completed_item,
            receipt_commit=str(completed_phase.get("git_commit", "")),
            current_head=current_head,
        )
        verified_completed_heads[completed_target] = current_head


def _assert_pending_target_safe_head_advance(
    *,
    target: str,
    item: dict[str, Any],
    allowed_head: str,
    current_head: str,
    completed: list[tuple[dict[str, Any], dict[str, Any]]],
    verified_completed_heads: dict[str, str] | None = None,
) -> None:
    """Allow an unrelated descendant HEAD without weakening target CAS.

    The proposed advance is safe only when every completed target has stayed at
    its reviewed proposal since its receipt and the pending target has stayed at
    its reviewed base for the entire ``allowed_head..current_head`` range.
    Worktree equality is checked by the caller using the same read-target
    response whose ``base_git_head`` supplies ``current_head``.
    """

    try:
        is_descendant = write_intent._git_is_ancestor(
            allowed_head,
            current_head,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ContentMigrationError(
            "HEAD_ADVANCE_GIT_PROJECTION_UNAVAILABLE",
            "apply-preflight",
            target,
        ) from exc
    if not is_descendant:
        raise ContentMigrationError(
            "HEAD_ADVANCE_GIT_DIVERGED",
            "apply-preflight",
            target,
        )

    _assert_completed_targets_at_head(
        completed=completed,
        current_head=current_head,
        verified_completed_heads=verified_completed_heads,
    )

    _assert_git_target_projection(
        target=target,
        base_commit=allowed_head,
        current_head=current_head,
        expected_raw_sha256=str(item.get("base_raw_sha256", "")),
        expected_canonical_sha256=str(
            item.get("base_canonical_sha256", "")
        ),
        stage="apply-preflight",
        diverged_reason="HEAD_ADVANCE_GIT_DIVERGED",
        unavailable_reason="HEAD_ADVANCE_GIT_PROJECTION_UNAVAILABLE",
        base_mismatch_reason="PENDING_BASE_COMMIT_CONTENT_MISMATCH",
        current_mismatch_reason="PENDING_CURRENT_COMMIT_CONTENT_MISMATCH",
        history_changed_reason="PENDING_TARGET_HISTORY_CHANGED",
    )


def _assert_prepared_base_git_projection(
    *,
    target: str,
    item: dict[str, Any],
    prepared_head: str,
    completed: list[tuple[dict[str, Any], dict[str, Any]]],
    verified_completed_heads: dict[str, str] | None = None,
) -> None:
    """Prove the uncommitted prepared lane still matches its Git base."""

    _assert_completed_targets_at_head(
        completed=completed,
        current_head=prepared_head,
        verified_completed_heads=verified_completed_heads,
    )
    _assert_git_target_projection(
        target=target,
        base_commit=prepared_head,
        current_head=prepared_head,
        expected_raw_sha256=str(item.get("base_raw_sha256", "")),
        expected_canonical_sha256=str(
            item.get("base_canonical_sha256", "")
        ),
        stage="resume",
        diverged_reason="PREPARED_GIT_HEAD_DRIFT",
        unavailable_reason="PREPARED_GIT_PROJECTION_UNAVAILABLE",
        base_mismatch_reason="PREPARED_BASE_COMMIT_CONTENT_MISMATCH",
        current_mismatch_reason="PREPARED_BASE_COMMIT_CONTENT_MISMATCH",
        history_changed_reason="PREPARED_TARGET_HISTORY_CHANGED",
    )


def _assert_prepared_early_commit_git_projection(
    *,
    target: str,
    item: dict[str, Any],
    prepared_head: str,
    current_head: str,
    completed: list[tuple[dict[str, Any], dict[str, Any]]],
    verified_completed_heads: dict[str, str] | None = None,
    allow_uncommitted_worktree: bool = False,
) -> None:
    """Prove a prepared proposal is in one permitted crash boundary.

    Before closeout, an exact prepared HEAD may still expose the Git base while
    the worktree already contains the proposal. After HEAD advances, the target
    may move from the reviewed base to the exact proposal once, but it may never
    disappear, enter a third state, or return to the base after the proposal.
    """

    _assert_completed_targets_at_head(
        completed=completed,
        current_head=current_head,
        verified_completed_heads=verified_completed_heads,
    )
    try:
        if not write_intent._git_is_ancestor(prepared_head, current_head):
            raise ContentMigrationError(
                "PREPARED_GIT_HEAD_DRIFT", "resume", target
            )
        canonical_target = write_gateway._formal_target(target)
        base_exists, base_digest = write_intent.git_target_digest_at_commit(
            prepared_head,
            canonical_target,
        )
        current_exists, current_digest = (
            (base_exists, base_digest)
            if current_head == prepared_head
            else write_intent.git_target_digest_at_commit(
                current_head,
                canonical_target,
            )
        )
        version_chain = write_intent.git_version_chain(
            prepared_head,
            current_head,
            canonical_target,
        )
    except ContentMigrationError:
        raise
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        write_intent.IntentError,
        write_gateway.MemoryWriteError,
    ) as exc:
        raise ContentMigrationError(
            "PREPARED_GIT_PROJECTION_UNAVAILABLE", "resume", target
        ) from exc

    base_raw = str(item.get("base_raw_sha256", ""))
    base_canonical = str(item.get("base_canonical_sha256", ""))
    proposal_raw = str(item.get("proposal_raw_sha256", ""))
    proposal_canonical = str(item.get("proposal_canonical_sha256", ""))
    if (
        not base_exists
        or base_digest.raw_sha256 != base_raw
        or base_digest.canonical_sha256 != base_canonical
    ):
        raise ContentMigrationError(
            "PREPARED_BASE_COMMIT_CONTENT_MISMATCH", "resume", target
        )
    if current_head == prepared_head and allow_uncommitted_worktree:
        # The atomic target replace may have succeeded immediately before the
        # closeout/commit phase crashed. The caller has already bound the live
        # worktree to the exact proposal; at this narrow boundary Git must still
        # expose the exact reviewed base and no intervening target versions.
        versions = version_chain.get("versions")
        if (
            version_chain.get("ok") is not True
            or not isinstance(versions, list)
            or versions
        ):
            raise ContentMigrationError(
                "PREPARED_TARGET_HISTORY_CHANGED", "resume", target
            )
        return
    if (
        not current_exists
        or current_digest.raw_sha256 != proposal_raw
        or current_digest.canonical_sha256 != proposal_canonical
    ):
        raise ContentMigrationError(
            "PREPARED_CURRENT_COMMIT_CONTENT_MISMATCH", "resume", target
        )
    versions = version_chain.get("versions")
    if version_chain.get("ok") is not True or not isinstance(versions, list):
        raise ContentMigrationError(
            "PREPARED_GIT_PROJECTION_UNAVAILABLE", "resume", target
        )
    reached_proposal = False
    for version in versions:
        if not isinstance(version, dict) or version.get("exists") is not True:
            raise ContentMigrationError(
                "PREPARED_TARGET_HISTORY_CHANGED", "resume", target
            )
        digest_pair = (
            version.get("raw_sha256"),
            version.get("canonical_sha256"),
        )
        if digest_pair == (proposal_raw, proposal_canonical):
            reached_proposal = True
        elif digest_pair == (base_raw, base_canonical) and not reached_proposal:
            continue
        else:
            raise ContentMigrationError(
                "PREPARED_TARGET_HISTORY_CHANGED", "resume", target
            )
    if not reached_proposal:
        raise ContentMigrationError(
            "PREPARED_TARGET_HISTORY_CHANGED", "resume", target
        )


def _expired_validated_recovery_requested(
    handoff: dict[str, Any],
) -> bool:
    """Select only a proven expired-validated crash or its recovery marker."""

    if (
        handoff.get("consumed_recovery") is not True
        or handoff.get("intent_status") != "validated"
    ):
        return False
    reason = str(handoff.get("intent_reason_code", ""))
    if reason in {
        write_intent.EXPIRED_VALIDATED_RECOVERY_REASON,
        write_intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON,
    }:
        return True
    if reason:
        return False
    expiry = write_intent.parse_time(str(handoff.get("intent_expires_at", "")))
    return bool(
        expiry
        and expiry <= dt.datetime.now(dt.timezone.utc)
    )


def _governance_recovery_intent_snapshot(
    client: MemoryctlClient,
    *,
    review_sha256: str,
    item: dict[str, Any],
    phase: dict[str, Any],
    handoff: dict[str, Any],
) -> dict[str, Any]:
    """Bind one expired recovery to the exact reviewed durable intent."""

    target = str(item["target_relative_path"])
    try:
        shown = write_intent.show_intent(str(phase["proposal_id"]))
        canonical = write_gateway._formal_target(target)
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        write_intent.IntentError,
        write_gateway.MemoryWriteError,
    ) as exc:
        raise ContentMigrationError(
            getattr(
                exc,
                "reason_code",
                "EXPIRED_VALIDATED_RECOVERY_STATE_UNAVAILABLE",
            ),
            "lease-recovery",
            target,
        ) from exc
    stored = shown.get("intent") if isinstance(shown, dict) else None
    receipt = shown.get("receipt") if isinstance(shown, dict) else None
    if not isinstance(stored, dict):
        raise ContentMigrationError(
            "EXPIRED_VALIDATED_RECOVERY_STATE_UNAVAILABLE",
            "lease-recovery",
            target,
        )
    if receipt is not None:
        raise ContentMigrationError(
            "EXPIRED_VALIDATED_RECOVERY_RECEIPT_CONFLICT",
            "lease-recovery",
            target,
        )
    expected = {
        "intent_id": str(phase["proposal_id"]),
        "actor": client.actor,
        "session_hash": confirmation_capability.session_hash(
            client.session_id
        ),
        "target_rel_path": target,
        "target_key": canonical.target_key,
        "fencing_token": int(phase["fencing_token"]),
        "base_exists": 1,
        "base_raw_sha256": str(item["base_raw_sha256"]),
        "base_canonical_sha256": str(item["base_canonical_sha256"]),
        "base_git_head": str(phase["base_git_head"]),
        "read_token": str(item["read_token"]),
        "scope_app_id": str(item["requested_app_id"]),
        "scope_project_id": str(item["requested_project_id"]),
        "proposal_raw_sha256": str(item["proposal_raw_sha256"]),
        "proposal_canonical_sha256": str(
            item["proposal_canonical_sha256"]
        ),
        "proposal_size_bytes": int(item["proposal_size_bytes"]),
        "source_class": "user_direct",
        "knowledge_kind": "rule",
        "asserted_by": "user",
        "evidence_ref_sha256": hashlib.sha256(
            f"content-migration-review:{review_sha256}".encode("utf-8")
        ).hexdigest(),
        "reconcile_action": "UPDATE",
        "operation": "governance_migration",
        "target_status": "",
        "transition_reason_sha256": "",
        "approval_required": 1,
        "status": "validated",
        "validation_mode": "exact",
        "final_raw_sha256": str(item["proposal_raw_sha256"]),
        "final_canonical_sha256": str(
            item["proposal_canonical_sha256"]
        ),
    }
    if any(stored.get(key) != value for key, value in expected.items()):
        raise ContentMigrationError(
            "EXPIRED_VALIDATED_RECOVERY_BINDING_CHANGED",
            "lease-recovery",
            target,
        )
    if (
        str(stored.get("expires_at", ""))
        != str(handoff.get("intent_expires_at", ""))
        or str(stored.get("reason_code", ""))
        != str(handoff.get("intent_reason_code", ""))
        or not str(stored.get("validated_at", ""))
        or GIT_HEAD_RE.fullmatch(
            str(stored.get("validated_git_head", ""))
        )
        is None
        or str(stored.get("bound_base_raw_sha256", ""))
        != str(item["base_raw_sha256"])
        or not str(stored.get("claim_ref_sha256", ""))
        or not write_intent.has_valid_confirmation_capability_approval(stored)
    ):
        raise ContentMigrationError(
            "EXPIRED_VALIDATED_RECOVERY_BINDING_CHANGED",
            "lease-recovery",
            target,
        )
    reason = str(stored.get("reason_code", ""))
    expiry = write_intent.parse_time(str(stored.get("expires_at", "")))
    if reason in {
        write_intent.EXPIRED_VALIDATED_RECOVERY_REASON,
        write_intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON,
    }:
        return stored
    if (
        reason
        or expiry is None
        or expiry > dt.datetime.now(dt.timezone.utc)
    ):
        raise ContentMigrationError(
            "EXPIRED_VALIDATED_RECOVERY_NOT_EXPIRED",
            "lease-recovery",
            target,
        )
    return stored


def _assert_governance_recovery_git_projection(
    *,
    target: str,
    item: dict[str, Any],
    phase: dict[str, Any],
    stored: dict[str, Any],
    current_head: str,
) -> None:
    """Prove base -> exact proposal with safe modes and a clean worktree."""

    try:
        canonical = write_gateway._formal_target(target)
        before = canonical.path.lstat()
        current_uid = os.geteuid() if hasattr(os, "geteuid") else before.st_uid
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != current_uid
            or bool(before.st_mode & 0o111)
        ):
            raise ContentMigrationError(
                "EXPIRED_VALIDATED_RECOVERY_WORKTREE_UNSAFE",
                "lease-recovery",
                target,
            )
        live_exists, live_digest = write_intent._read_target(canonical)
        after = canonical.path.lstat()
        stable_stat = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
        )
        proposal_pair = (
            str(item["proposal_raw_sha256"]),
            str(item["proposal_canonical_sha256"]),
        )
        if (
            not stable_stat
            or not live_exists
            or (live_digest.raw_sha256, live_digest.canonical_sha256)
            != proposal_pair
        ):
            raise ContentMigrationError(
                "EXPIRED_VALIDATED_RECOVERY_TARGET_DRIFT",
                "lease-recovery",
                target,
            )
        if write_intent.current_git_head(required=True) != current_head:
            raise ContentMigrationError(
                "EXPIRED_VALIDATED_RECOVERY_HEAD_CHANGED",
                "lease-recovery",
                target,
            )
        base_head = str(phase["base_git_head"])
        validated_head = str(stored.get("validated_git_head", ""))
        if (
            str(item.get("base_git_head", "")) != base_head
            or not write_intent._git_is_ancestor(base_head, validated_head)
            or not write_intent._git_is_ancestor(validated_head, current_head)
        ):
            raise ContentMigrationError(
                "EXPIRED_VALIDATED_RECOVERY_GIT_DIVERGED",
                "lease-recovery",
                target,
            )
        base_exists, base_digest = write_intent.git_target_digest_at_commit(
            base_head,
            canonical,
        )
        base_mode_exists, base_mode = (
            write_intent.git_target_mode_at_commit(base_head, canonical)
        )
        head_exists, head_digest = write_intent.git_target_digest_at_commit(
            current_head,
            canonical,
        )
        head_mode_exists, head_mode = (
            write_intent.git_target_mode_at_commit(current_head, canonical)
        )
        if (
            not base_exists
            or not base_mode_exists
            or base_mode != "100644"
            or (
                base_digest.raw_sha256,
                base_digest.canonical_sha256,
            )
            != (
                str(item["base_raw_sha256"]),
                str(item["base_canonical_sha256"]),
            )
            or not head_exists
            or not head_mode_exists
            or head_mode != "100644"
            or (head_digest.raw_sha256, head_digest.canonical_sha256)
            != proposal_pair
        ):
            raise ContentMigrationError(
                "EXPIRED_VALIDATED_RECOVERY_COMMIT_CONTENT_MISMATCH",
                "lease-recovery",
                target,
            )
        repo_path = write_intent._repo_rel_path(canonical)
        if (
            not write_intent._git_path_matches_worktree(
                current_head,
                repo_path,
            )
            or write_intent._run_git(
                "diff",
                "--cached",
                "--quiet",
                current_head,
                "--",
                repo_path,
            ).returncode
            != 0
        ):
            raise ContentMigrationError(
                "EXPIRED_VALIDATED_RECOVERY_WORKTREE_DIRTY",
                "lease-recovery",
                target,
            )
        history = write_intent.git_version_chain(
            base_head,
            current_head,
            canonical,
        )
        versions = history.get("versions")
        if (
            history.get("ok") is not True
            or not isinstance(versions, list)
            or not versions
        ):
            raise ContentMigrationError(
                "EXPIRED_VALIDATED_RECOVERY_TARGET_HISTORY_CHANGED",
                "lease-recovery",
                target,
            )
        version_commits: set[str] = set()
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
                raise ContentMigrationError(
                    "EXPIRED_VALIDATED_RECOVERY_TARGET_HISTORY_CHANGED",
                    "lease-recovery",
                    target,
                )
            commit = str(version.get("commit", ""))
            mode_exists, mode = write_intent.git_target_mode_at_commit(
                commit,
                canonical,
            )
            if not mode_exists or mode != "100644":
                raise ContentMigrationError(
                    "EXPIRED_VALIDATED_RECOVERY_TARGET_HISTORY_CHANGED",
                    "lease-recovery",
                    target,
                )
            version_commits.add(commit)
        early_commit = bool(int(stored.get("early_commit") or 0))
        proposal_commit = str(stored.get("proposal_commit", ""))
        if early_commit:
            if (
                proposal_commit not in version_commits
                or not write_intent._git_is_ancestor(
                    base_head,
                    proposal_commit,
                )
                or not write_intent._git_is_ancestor(
                    proposal_commit,
                    current_head,
                )
                or not (
                    write_intent._git_is_ancestor(
                        proposal_commit,
                        validated_head,
                    )
                    or write_intent._git_is_ancestor(
                        validated_head,
                        proposal_commit,
                    )
                )
            ):
                raise ContentMigrationError(
                    "EXPIRED_VALIDATED_RECOVERY_COMMIT_BINDING_CHANGED",
                    "lease-recovery",
                    target,
                )
        elif proposal_commit or validated_head != base_head:
            raise ContentMigrationError(
                "EXPIRED_VALIDATED_RECOVERY_COMMIT_BINDING_CHANGED",
                "lease-recovery",
                target,
            )
    except ContentMigrationError:
        raise
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        write_intent.IntentError,
        write_gateway.MemoryWriteError,
    ) as exc:
        raise ContentMigrationError(
            "EXPIRED_VALIDATED_RECOVERY_GIT_PROJECTION_UNAVAILABLE",
            "lease-recovery",
            target,
        ) from exc


def _expired_recovery_result_items(
    review: dict[str, Any],
    *,
    recovered_target: str,
    recovered: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        (
            recovered
            if str(item["target_relative_path"]) == recovered_target
            else {
                "target_relative_path": str(item["target_relative_path"]),
                "status": "not_attempted",
            }
        )
        for item in review["items"]
    ]


def _run_expired_validated_governance_recovery(
    client: MemoryctlClient,
    review: dict[str, Any],
    *,
    review_sha256: str,
    progress_path: Path,
    handoff: dict[str, Any],
    append: Callable[[Path, dict[str, Any]], None],
) -> dict[str, Any]:
    """Terminalize exactly one committed-but-expired governance proposal."""

    events = load_progress(
        progress_path,
        review_sha256=review_sha256,
        actor=client.actor,
    )
    state = progress_state(events, review)
    target = _handoff_target_for_events(
        client,
        review,
        state,
        handoff,
        allowed_events={"prepared"},
    )
    if (
        not target
        or list(state) != [target]
        or str(review["items"][0]["target_relative_path"]) != target
    ):
        raise ContentMigrationError(
            "EXPIRED_VALIDATED_RECOVERY_PROGRESS_INVALID",
            "lease-recovery",
            target,
        )
    phase = state[target]
    item = review["items"][0]

    def require_current_doctor_target_absent() -> None:
        current_doctor = client.doctor()
        current_complete, current = normalize_and_project_query_for_actor(
            current_doctor,
            mode=GOVERNANCE_V4_MODE,
            actor=client.actor,
            require_all_automatable=False,
        )
        assert_doctor_migration_safe(
            current_doctor,
            current_complete,
            mode=GOVERNANCE_V4_MODE,
        )
        if (
            current.get("owner_lane_policy")
            != GOVERNANCE_OWNER_LANE_POLICY
            or current.get("owner_actor") != client.actor
        ):
            raise ContentMigrationError(
                "MIGRATION_OWNER_LANE_CHANGED",
                "lease-recovery",
                target,
            )
        if any(
            str(candidate.get("target_relative_path", "")) == target
            for candidate in current.get("migration_query", [])
            if isinstance(candidate, dict)
        ):
            raise ContentMigrationError(
                "EXPIRED_VALIDATED_RECOVERY_TARGET_NOT_DISAPPEARED",
                "lease-recovery",
                target,
            )

    handoff_reason = str(handoff.get("intent_reason_code", ""))
    handoff_expiry = write_intent.parse_time(
        str(handoff.get("intent_expires_at", ""))
    )
    repair_requested = (
        handoff_reason
        == write_intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON
        or (
            handoff_reason == write_intent.EXPIRED_VALIDATED_RECOVERY_REASON
            and handoff_expiry is not None
            and handoff_expiry <= dt.datetime.now(dt.timezone.utc)
        )
    )
    if (
        handoff_reason
        == write_intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON
        and (
            handoff_expiry is None
            or handoff_expiry <= dt.datetime.now(dt.timezone.utc)
        )
    ):
        raise ContentMigrationError(
            "EXPIRED_VALIDATED_RECOVERY_REPAIR_WINDOW_ELAPSED",
            "lease-recovery",
            target,
        )
    if not repair_requested:
        # Preserve the original first-window gate: an item must disappear from
        # Doctor before even the read/Git preflight is attempted.
        require_current_doctor_target_absent()
    record = next(
        record
        for record in review["doctor_binding"]["migration_query"]
        if str(record["target_relative_path"]) == target
    )
    read = validate_read_response(
        client.write(
            "read-target",
            migration_read_request(record, mode=GOVERNANCE_V4_MODE),
        ),
        record,
        mode=GOVERNANCE_V4_MODE,
    )
    current_digest = write_intent.content_hashes(
        read["content"].encode("utf-8")
    )
    if (
        current_digest.raw_sha256 != item["proposal_raw_sha256"]
        or current_digest.canonical_sha256
        != item["proposal_canonical_sha256"]
    ):
        raise ContentMigrationError(
            "EXPIRED_VALIDATED_RECOVERY_TARGET_DRIFT",
            "lease-recovery",
            target,
        )
    stored = _governance_recovery_intent_snapshot(
        client,
        review_sha256=review_sha256,
        item=item,
        phase=phase,
        handoff=handoff,
    )
    _assert_governance_recovery_git_projection(
        target=target,
        item=item,
        phase=phase,
        stored=stored,
        current_head=str(read["base_git_head"]),
    )
    stored_reason = str(stored.get("reason_code", ""))
    stored_expiry = write_intent.parse_time(str(stored.get("expires_at", "")))
    generated_index_recovery: dict[str, Any] | None = None
    repair_stage = (
        stored_reason
        == write_intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON
        or (
            stored_reason == write_intent.EXPIRED_VALIDATED_RECOVERY_REASON
            and stored_expiry is not None
            and stored_expiry <= dt.datetime.now(dt.timezone.utc)
        )
    )
    if repair_stage != repair_requested:
        raise ContentMigrationError(
            "EXPIRED_VALIDATED_RECOVERY_BINDING_CHANGED",
            "lease-recovery",
            target,
        )
    def publish_repair_lease(
        evidence: dict[str, str] | None,
    ) -> dict[str, Any]:
        try:
            return write_intent.recover_expired_validated_lease(
                str(phase["proposal_id"]),
                actor=client.actor,
                raw_session_id=client.session_id,
                target=target,
                fencing_token=int(phase["fencing_token"]),
                expected_expires_at=str(stored["expires_at"]),
                expected_base_raw_sha256=str(item["base_raw_sha256"]),
                expected_base_canonical_sha256=str(
                    item["base_canonical_sha256"]
                ),
                expected_base_git_head=str(phase["base_git_head"]),
                expected_read_token=str(item["read_token"]),
                expected_scope_app_id=str(item["requested_app_id"]),
                expected_scope_project_id=str(
                    item["requested_project_id"]
                ),
                expected_proposal_raw_sha256=str(
                    item["proposal_raw_sha256"]
                ),
                expected_proposal_canonical_sha256=str(
                    item["proposal_canonical_sha256"]
                ),
                expected_proposal_size_bytes=int(
                    item["proposal_size_bytes"]
                ),
                expected_final_raw_sha256=str(
                    item["proposal_raw_sha256"]
                ),
                expected_final_canonical_sha256=str(
                    item["proposal_canonical_sha256"]
                ),
                expected_validated_git_head=str(
                    stored["validated_git_head"]
                ),
                expected_early_commit=bool(
                    int(stored.get("early_commit") or 0)
                ),
                expected_proposal_commit=str(
                    stored.get("proposal_commit", "")
                ),
                expected_evidence_ref_sha256=str(
                    stored["evidence_ref_sha256"]
                ),
                expected_operation="governance_migration",
                expected_reconcile_action="UPDATE",
                generated_index_recovery=evidence,
            )
        except write_intent.IntentError as exc:
            raise ContentMigrationError(
                exc.reason_code,
                "lease-recovery",
                target,
            ) from exc

    def exact_generated_index_evidence(
        *,
        publish_repair: Callable[
            [dict[str, str]], dict[str, Any]
        ]
        | None = None,
    ) -> dict[str, Any]:
        try:
            return memory_closeout.recover_expired_governance_generated_index_transaction(
                actor=client.actor,
                raw_session_id=client.session_id,
                intent_id=str(phase["proposal_id"]),
                target_relative_path=target,
                fencing_token=int(phase["fencing_token"]),
                review_sha256=review_sha256,
                base_raw_sha256=str(item["base_raw_sha256"]),
                base_canonical_sha256=str(item["base_canonical_sha256"]),
                read_token=str(item["read_token"]),
                scope_app_id=str(item["requested_app_id"]),
                scope_project_id=str(item["requested_project_id"]),
                proposal_raw_sha256=str(item["proposal_raw_sha256"]),
                proposal_canonical_sha256=str(
                    item["proposal_canonical_sha256"]
                ),
                proposal_size_bytes=int(item["proposal_size_bytes"]),
                base_git_head=str(phase["base_git_head"]),
                validated_git_head=str(stored["validated_git_head"]),
                early_commit=bool(int(stored.get("early_commit") or 0)),
                proposal_commit=str(stored.get("proposal_commit", "")),
                publish_repair=publish_repair,
            )
        except (
            memory_closeout.GeneratedIndexCapabilityError,
            OSError,
            RuntimeError,
            sqlite3.Error,
            ValueError,
            write_intent.IntentError,
        ) as exc:
            raise ContentMigrationError(
                str(
                    getattr(
                        exc,
                        "reason_code",
                        str(exc)
                        or "EXPIRED_VALIDATED_RECOVERY_INDEX_RECOVERY_FAILED",
                    )
                ),
                "generated-index-recovery",
                target,
            ) from exc
    if repair_stage:
        generated_index_recovery = exact_generated_index_evidence()
    if repair_requested:
        # The derived-state deadlock is cleared only through the exact scoped
        # lane above. Doctor is then run with its ordinary rules; no unrelated
        # failure is waived.  The post-Doctor exact projection readback and
        # repair-marker CAS share the closeout helper's exclusive fence, so no
        # Gateway closeout can move HEAD/INDEX between evidence and authority.
        require_current_doctor_target_absent()
        published = exact_generated_index_evidence(
            publish_repair=publish_repair_lease,
        )
        if (
            published.get("evidence") != generated_index_recovery
            or not isinstance(published.get("repair_intent"), dict)
        ):
            raise ContentMigrationError(
                "EXPIRED_VALIDATED_RECOVERY_INDEX_EVIDENCE_CHANGED",
                "generated-index-recovery",
                target,
            )
        recovered = published["repair_intent"]
    else:
        recovered = publish_repair_lease(None)
    expected_recovery_reason = (
        write_intent.EXPIRED_VALIDATED_RECOVERY_REPAIR_REASON
        if generated_index_recovery is not None
        else write_intent.EXPIRED_VALIDATED_RECOVERY_REASON
    )
    if (
        recovered.get("status") != "validated"
        or recovered.get("reason_code")
        != expected_recovery_reason
    ):
        raise ContentMigrationError(
            "EXPIRED_VALIDATED_RECOVERY_STATE_CHANGED",
            "lease-recovery",
            target,
        )
    applied = client.write(
        "apply",
        _apply_request(item, phase, read["content"]),
    )
    completed = _validated_apply_response(
        applied,
        item=item,
        phase=phase,
        mode=GOVERNANCE_V4_MODE,
    )
    if applied.get("idempotent") is not True:
        raise ContentMigrationError(
            "EXPIRED_VALIDATED_RECOVERY_RESPONSE_INVALID",
            "lease-recovery",
            target,
        )
    recovery_read = validate_read_response(
        client.write(
            "read-target",
            migration_read_request(record, mode=GOVERNANCE_V4_MODE),
        ),
        record,
        mode=GOVERNANCE_V4_MODE,
    )
    recovery_digest = write_intent.content_hashes(
        recovery_read["content"].encode("utf-8")
    )
    if (
        recovery_digest.raw_sha256 != item["proposal_raw_sha256"]
        or recovery_digest.canonical_sha256
        != item["proposal_canonical_sha256"]
    ):
        raise ContentMigrationError(
            "EXPIRED_VALIDATED_RECOVERY_TARGET_DRIFT",
            "lease-recovery",
            target,
        )
    _assert_completed_recovery_git_projection(
        target=target,
        item=item,
        receipt_commit=str(completed["git_commit"]),
        current_head=str(recovery_read["base_git_head"]),
    )
    append(progress_path, completed)
    recovered_result = {
        "target_relative_path": target,
        "status": "applied",
        "idempotent": True,
        "git_commit": str(completed["git_commit"]),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "ok": False,
        "status": "replan_required",
        "reason_code": "EXPIRED_VALIDATED_RECOVERY_REPLAN_REQUIRED",
        "review_sha256": review_sha256,
        "progress_file": str(progress_path),
        "items": _expired_recovery_result_items(
            review,
            recovered_target=target,
            recovered=recovered_result,
        ),
        "next_mode": GOVERNANCE_V4_MODE,
        "recovered_target_relative_path": target,
    }


def _confirmation_required_response(
    *,
    review: dict[str, Any],
    review_sha256: str,
    progress_path: Path,
    target: str,
    phase: dict[str, Any],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    reported = list(results)
    found = False
    confirmation_mode = "capability"
    for candidate in review["items"]:
        pending = str(candidate["target_relative_path"])
        if any(item.get("target_relative_path") == pending for item in reported):
            continue
        if pending == target:
            found = True
            confirmation_mode = str(
                candidate.get("confirmation_mode", "capability")
            )
            reported.append({
                "target_relative_path": pending,
                "status": (
                    "ordinary_confirmation_required"
                    if confirmation_mode == "ordinary_host"
                    else "confirmation_required"
                ),
                "proposal_id": str(phase["proposal_id"]),
                "fencing_token": int(phase["fencing_token"]),
            })
        else:
            reported.append({"target_relative_path": pending, "status": "not_attempted"})
    if not found:
        raise ContentMigrationError("PROGRESS_EVENT_ORDER_INVALID", "progress", target)
    return {
        "schema_version": SCHEMA_VERSION,
        "ok": False,
        "status": (
            "ordinary_confirmation_required"
            if confirmation_mode == "ordinary_host"
            else "confirmation_required"
        ),
        "reason_code": (
            "ORDINARY_CONFIRMATION_REQUIRED"
            if confirmation_mode == "ordinary_host"
            else "CONFIRMATION_CAPABILITY_REQUIRED"
        ),
        "review_sha256": review_sha256,
        "progress_file": str(progress_path),
        "items": reported,
        "confirmation_capability_required": confirmation_mode != "ordinary_host",
        "confirmation_mode": confirmation_mode,
        "next_target_relative_path": target,
        "proposal_id": str(phase["proposal_id"]),
        "fencing_token": int(phase["fencing_token"]),
    }


def _run_apply(
    client: MemoryctlClient,
    review: dict[str, Any],
    *,
    review_sha256: str,
    progress_path: Path,
    confirmation_capability_path: str = "",
    confirmation_capability_token: str = "",
    completed_recovery_binding: dict[str, Any] | None = None,
    allow_apply: bool = True,
    append: Callable[[Path, dict[str, Any]], None] = append_progress,
) -> dict[str, Any]:
    mode = str(review.get("mode", LEGACY_SCOPE_MODE))
    current_doctor = client.doctor()
    current_complete, current = normalize_and_project_query_for_actor(
        current_doctor,
        mode=mode,
        actor=client.actor,
        require_all_automatable=mode == LEGACY_SCOPE_MODE,
    )
    assert_doctor_migration_safe(
        current_doctor,
        current_complete,
        mode=mode,
    )
    disappeared = compare_current_query(review, current)
    events = load_progress(progress_path, review_sha256=review_sha256, actor=client.actor)
    state = progress_state(events, review)
    for target in disappeared:
        phase = state.get(target)
        if phase is None or phase.get("event") not in {"prepared", "completed"}:
            raise ContentMigrationError("UNJOURNALED_COMPLETION", "resume", target)
    for target, phase in state.items():
        if phase.get("event") == "completed" and target not in disappeared:
            raise ContentMigrationError("PROGRESS_DOCTOR_MISMATCH", "resume", target)
    results: list[dict[str, Any]] = []
    allowed_head = str(review.get("initial_git_head", ""))
    completed_items: list[tuple[dict[str, Any], dict[str, Any]]] = []
    completed_projection_heads: dict[str, str] = {}

    records = {
        str(item["target_relative_path"]): item
        for item in review["doctor_binding"]["migration_query"]
    }
    for item in review["items"]:
        target = str(item["target_relative_path"])
        record = records[target]
        phase = state.get(target)
        read = validate_read_response(
            client.write(
                "read-target",
                migration_read_request(record, mode=mode),
            ),
            record,
            mode=mode,
        )
        current_digest = write_intent.content_hashes(read["content"].encode("utf-8"))

        if phase and phase.get("event") == "completed":
            if (
                current_digest.raw_sha256 != item["proposal_raw_sha256"]
                or current_digest.canonical_sha256
                != item["proposal_canonical_sha256"]
            ):
                raise ContentMigrationError("COMPLETED_TARGET_DRIFT", "resume", target)
            live_head = str(read["base_git_head"])
            # A concurrent host may advance HEAD between completed-target
            # reads. Before accepting this newly observed head, project every
            # earlier completed target onto that exact immutable commit.
            _assert_completed_targets_at_head(
                completed=completed_items,
                current_head=live_head,
                verified_completed_heads=completed_projection_heads,
            )
            _assert_completed_progress_git_projection(
                target=target,
                item=item,
                receipt_commit=str(phase.get("git_commit", "")),
                current_head=live_head,
            )
            allowed_head = str(phase.get("git_commit", ""))
            completed_items.append((item, phase))
            completed_projection_heads[target] = live_head
            results.append({"target_relative_path": target, "status": "already_applied", "idempotent": True})
            continue

        if phase and phase.get("event") == "prepared":
            advanced_from = str(phase.get("advanced_from_git_head", ""))
            if advanced_from:
                if advanced_from != allowed_head:
                    raise ContentMigrationError(
                        "PROGRESS_EVENT_ORDER_INVALID", "progress", target
                    )
                _assert_pending_target_safe_head_advance(
                    target=target,
                    item=item,
                    allowed_head=advanced_from,
                    current_head=str(phase.get("base_git_head", "")),
                    completed=completed_items,
                    verified_completed_heads=completed_projection_heads,
                )
            elif phase.get("base_git_head") != allowed_head:
                raise ContentMigrationError(
                    "PROGRESS_EVENT_ORDER_INVALID", "progress", target
                )
            prepared_early_commit = False
            prepared_proposal_uncommitted = False
            if current_digest.raw_sha256 == item["base_raw_sha256"]:
                if read["base_git_head"] != phase["base_git_head"]:
                    raise ContentMigrationError("PREPARED_BASE_DRIFT", "resume", target)
                proposal, digest = _proposal(
                    record,
                    read["content"],
                    actor=client.actor,
                    mode=mode,
                )
            elif current_digest.raw_sha256 == item["proposal_raw_sha256"]:
                prepared_early_commit = True
                prepared_proposal_uncommitted = (
                    read["base_git_head"] == phase["base_git_head"]
                )
                proposal, digest = read["content"], current_digest
            else:
                raise ContentMigrationError("PREPARED_TARGET_DRIFT", "resume", target)
            if digest.raw_sha256 != item["proposal_raw_sha256"] or digest.canonical_sha256 != item["proposal_canonical_sha256"]:
                raise ContentMigrationError("PROPOSAL_BINDING_CHANGED", "resume", target)
            if prepared_early_commit:
                _assert_prepared_early_commit_git_projection(
                    target=target,
                    item=item,
                    prepared_head=str(phase.get("base_git_head", "")),
                    current_head=str(read["base_git_head"]),
                    completed=completed_items,
                    verified_completed_heads=completed_projection_heads,
                    allow_uncommitted_worktree=(
                        prepared_proposal_uncommitted
                    ),
                )
            else:
                _assert_prepared_base_git_projection(
                    target=target,
                    item=item,
                    prepared_head=str(phase.get("base_git_head", "")),
                    completed=completed_items,
                    verified_completed_heads=completed_projection_heads,
                )
            completed_recovery_here = _completed_recovery_matches(
                completed_recovery_binding,
                item=item,
                phase=phase,
            )
            if not allow_apply or (
                not confirmation_capability_path
                and not completed_recovery_here
            ):
                return _confirmation_required_response(
                    review=review,
                    review_sha256=review_sha256,
                    progress_path=progress_path,
                    target=target,
                    phase=phase,
                    results=results,
                )
            risk_content_update = bool(
                mode == RISK_V4_MODE
                and item.get("migration_operation") == "content_update"
            )
            approval_reference = ""
            if risk_content_update and not completed_recovery_here:
                approval_reference = _consume_risk_content_update_confirmation(
                    client,
                    item=item,
                    phase=phase,
                    capability_path=confirmation_capability_path,
                    capability_token=confirmation_capability_token,
                )
            applied = client.write(
                "apply",
                _apply_request(
                    item,
                    phase,
                    proposal,
                    confirmation_capability_path=(
                        ""
                        if risk_content_update or completed_recovery_here
                        else confirmation_capability_path
                    ),
                    confirmation_capability_token=(
                        ""
                        if risk_content_update or completed_recovery_here
                        else confirmation_capability_token
                    ),
                    confirmed_by=(
                        "user"
                        if risk_content_update and not completed_recovery_here
                        else ""
                    ),
                    confirmation_reference=approval_reference,
                ),
            )
        else:
            if confirmation_capability_path:
                # A capability is bound to an already-existing intent.  It can
                # never legitimately authorize an intent that this call has
                # not prepared yet, and must not be forwarded speculatively.
                raise ContentMigrationError(
                    "CONFIRMATION_CAPABILITY_PREMATURE", "prepare", target
                )
            if target in disappeared:
                raise ContentMigrationError("UNJOURNALED_COMPLETION", "resume", target)
            if (
                read["base_raw_sha256"] != item["base_raw_sha256"]
                or read["base_canonical_sha256"] != item["base_canonical_sha256"]
            ):
                raise ContentMigrationError("TARGET_BASE_DRIFT", "apply-preflight", target)
            advanced_from = ""
            if read["base_git_head"] != allowed_head:
                advanced_from = allowed_head
                _assert_pending_target_safe_head_advance(
                    target=target,
                    item=item,
                    allowed_head=allowed_head,
                    current_head=str(read["base_git_head"]),
                    completed=completed_items,
                    verified_completed_heads=completed_projection_heads,
                )
                allowed_head = str(read["base_git_head"])
            proposal, digest = _proposal(
                record,
                read["content"],
                actor=client.actor,
                mode=mode,
            )
            if (
                digest.raw_sha256 != item["proposal_raw_sha256"]
                or digest.canonical_sha256 != item["proposal_canonical_sha256"]
                or digest.size_bytes != item["proposal_size_bytes"]
            ):
                raise ContentMigrationError("PROPOSAL_BINDING_CHANGED", "apply-preflight", target)
            prepared = client.write(
                "prepare",
                _prepare_request(
                    record,
                    read,
                    proposal,
                    review_sha256,
                    mode=mode,
                ),
            )
            phase = _validated_prepared_phase(
                prepared,
                item=item,
                read=read,
                mode=mode,
            )
            if advanced_from:
                phase["advanced_from_git_head"] = advanced_from
            append(progress_path, phase)
            return _confirmation_required_response(
                review=review,
                review_sha256=review_sha256,
                progress_path=progress_path,
                target=target,
                phase=phase,
                results=results,
            )

        completed = _validated_apply_response(
            applied,
            item=item,
            phase=phase,
            mode=mode,
        )
        completed_recovery_replan = False
        if completed_recovery_here:
            if (
                applied.get("idempotent") is not True
                or current_digest.raw_sha256
                != item["proposal_raw_sha256"]
                or current_digest.canonical_sha256
                != item["proposal_canonical_sha256"]
            ):
                raise ContentMigrationError(
                    "COMPLETED_RECOVERY_RESPONSE_INVALID", "resume", target
                )
            recovery_read = validate_read_response(
                client.write(
                    "read-target",
                    migration_read_request(record, mode=mode),
                ),
                record,
                mode=mode,
            )
            recovery_digest = write_intent.content_hashes(
                recovery_read["content"].encode("utf-8")
            )
            if (
                recovery_digest.raw_sha256
                != item["proposal_raw_sha256"]
                or recovery_digest.canonical_sha256
                != item["proposal_canonical_sha256"]
            ):
                raise ContentMigrationError(
                    "COMPLETED_RECOVERY_TARGET_DRIFT", "resume", target
                )
            _assert_completed_recovery_git_projection(
                target=target,
                item=item,
                receipt_commit=str(completed["git_commit"]),
                current_head=str(recovery_read["base_git_head"]),
            )
            # A recovered terminal receipt always ends this stale batch. Even
            # an exact-HEAD recovery has a second-read/append boundary that a
            # fresh review must rebind before another target is considered.
            completed_recovery_replan = True
        elif current_digest.raw_sha256 == item["proposal_raw_sha256"]:
            if prepared_proposal_uncommitted:
                _assert_prepared_early_commit_git_projection(
                    target=target,
                    item=item,
                    prepared_head=str(phase.get("base_git_head", "")),
                    current_head=str(completed["git_commit"]),
                    completed=completed_items,
                    verified_completed_heads=completed_projection_heads,
                )
            elif read["base_git_head"] != completed["git_commit"]:
                raise ContentMigrationError(
                    "PREPARED_GIT_HEAD_DRIFT", "resume", target
                )
        append(progress_path, completed)
        state[target] = completed
        allowed_head = str(applied["git_commit"])
        results.append({
            "target_relative_path": target,
            "status": "applied",
            "idempotent": applied["idempotent"],
            "git_commit": allowed_head,
        })

        if completed_recovery_replan:
            return {
                "schema_version": SCHEMA_VERSION,
                "ok": False,
                "status": "replan_required",
                "reason_code": "COMPLETED_RECOVERY_REPLAN_REQUIRED",
                "review_sha256": review_sha256,
                "progress_file": str(progress_path),
                "items": results,
                "next_mode": mode,
                "recovered_target_relative_path": target,
            }

        if (
            mode == RISK_V4_MODE
            and item.get("migration_operation") == "status_transition"
        ):
            return {
                "schema_version": SCHEMA_VERSION,
                "ok": False,
                "status": "replan_required",
                "reason_code": "RISK_FOLLOWUP_REPLAN_REQUIRED",
                "review_sha256": review_sha256,
                "progress_file": str(progress_path),
                "items": results,
                "next_mode": RISK_V4_MODE,
                "transitioned_target_relative_path": target,
            }

        # Confirmation capabilities are one-shot and bind one exact proposal.
        # Never forward the same bearer to the next document in a batch.  The
        # progress journal makes this response resumable: the operator issues
        # a new capability for ``next_target_relative_path`` and invokes apply
        # again, at which point completed targets are verified and skipped.
        remaining = [
            str(candidate["target_relative_path"])
            for candidate in review["items"]
            if state.get(str(candidate["target_relative_path"]), {}).get("event")
            != "completed"
        ]
        if remaining:
            next_target = remaining[0]
            reported = list(results)
            reported.extend(
                {
                    "target_relative_path": pending,
                    "status": (
                        "next_confirmation_required"
                        if pending == next_target
                        else "not_attempted"
                    ),
                }
                for pending in remaining
            )
            return {
                "schema_version": SCHEMA_VERSION,
                "ok": False,
                "status": "next_confirmation_required",
                "reason_code": "NEXT_CONFIRMATION_REQUIRED",
                "review_sha256": review_sha256,
                "progress_file": str(progress_path),
                "items": reported,
                "next_confirmation_required": True,
                "next_target_relative_path": next_target,
            }

    final_doctor = client.doctor()
    final_complete, final = normalize_and_project_query_for_actor(
        final_doctor,
        mode=mode,
        actor=client.actor,
        require_all_automatable=False,
    )
    assert_doctor_migration_safe(
        final_doctor,
        final_complete,
        mode=mode,
    )
    final_fail_state_consistent, final_actual_fail = _doctor_final_fail_state(
        final_doctor
    )
    if mode in {GOVERNANCE_V4_MODE, RISK_V4_MODE}:
        remaining_automatic = sum(
            1
            for record in final["migration_query"]
            if (
                record.get("automatable") is True
                if mode == GOVERNANCE_V4_MODE
                else bool(
                    isinstance(record.get("risk_recommendation"), dict)
                    and record["risk_recommendation"].get("automatable_now") is True
                )
            )
        )
        final_ready = bool(
            remaining_automatic == 0
            and final_fail_state_consistent
            and final_actual_fail == 0
        )
        final_unassigned_manual = int(
            final.get("unassigned_manual_review_count", 0) or 0
        )
        final_manual = (
            int(final.get("manual_review_documents", 0) or 0)
            + final_unassigned_manual
        )
        final_status = (
            "complete_with_manual_review"
            if final_ready and final_manual
            else ("complete" if final_ready else "blocked")
        )
        final_reason = "" if final_ready else (
            "FINAL_RISK_MIGRATION_INCOMPLETE"
            if mode == RISK_V4_MODE
            else "FINAL_GOVERNANCE_MIGRATION_INCOMPLETE"
        )
    else:
        final_ready = (
            final["legacy_scope_documents"] == 0
            and final["automatable_documents"] == 0
            and final["manual_review_documents"] == 0
            and not final["migration_query"]
            and final_fail_state_consistent
            and final_actual_fail == 0
        )
        final_manual = int(final.get("manual_review_documents", 0) or 0)
        final_unassigned_manual = 0
        final_status = "complete" if final_ready else "blocked"
        final_reason = "" if final_ready else "FINAL_SCOPE_MIGRATION_INCOMPLETE"
    return {
        "schema_version": SCHEMA_VERSION,
        "ok": final_ready,
        "status": final_status,
        "reason_code": final_reason,
        "mode": mode,
        "review_sha256": review_sha256,
        "progress_file": str(progress_path),
        "items": results,
        "final_legacy_scope_documents": int(final.get("legacy_scope_documents", 0) or 0),
        "final_governance_automatable_documents": int(
            final.get("automatable_documents", 0) or 0
        ) if mode in {GOVERNANCE_V4_MODE, RISK_V4_MODE} else 0,
        "final_manual_review_documents": final_manual,
        "final_unassigned_manual_review_count": final_unassigned_manual,
        "final_doctor_status": final_doctor.get("status"),
    }


def _run_apply_with_structured_failure(
    client: MemoryctlClient,
    review: dict[str, Any],
    *,
    review_sha256: str,
    progress_path: Path,
    confirmation_capability_path: str = "",
    confirmation_capability_token: str = "",
    completed_recovery_binding: dict[str, Any] | None = None,
    allow_apply: bool = True,
    append: Callable[[Path, dict[str, Any]], None] = append_progress,
) -> dict[str, Any]:
    """Run apply and preserve a per-target result ledger on fail-closed exits."""

    try:
        return _run_apply(
            client,
            review,
            review_sha256=review_sha256,
            progress_path=progress_path,
            confirmation_capability_path=confirmation_capability_path,
            confirmation_capability_token=confirmation_capability_token,
            completed_recovery_binding=completed_recovery_binding,
            allow_apply=allow_apply,
            append=append,
        )
    except ContentMigrationError as exc:
        state: dict[str, dict[str, Any]] = {}
        if progress_path.exists() or progress_path.is_symlink():
            try:
                events = load_progress(progress_path, review_sha256=review_sha256, actor=client.actor)
                state = progress_state(events, review)
            except ContentMigrationError:
                state = {}
        item_results: list[dict[str, Any]] = []
        for item in review["items"]:
            target = str(item["target_relative_path"])
            phase = state.get(target, {}).get("event")
            status = {
                "completed": "completed_before_block",
                "prepared": "prepared_pending_apply",
            }.get(str(phase), "not_attempted")
            result: dict[str, Any] = {
                "target_relative_path": target,
                "status": status,
            }
            if target == exc.target_relative_path:
                result.update({
                    "status": "blocked",
                    "stage": exc.stage,
                    "reason_code": exc.reason_code,
                })
            item_results.append(result)
        return {
            "schema_version": SCHEMA_VERSION,
            "ok": False,
            "status": "blocked",
            "stage": exc.stage,
            "reason_code": exc.reason_code,
            "target_relative_path": exc.target_relative_path,
            "review_sha256": review_sha256,
            "progress_file": str(progress_path),
            "items": item_results,
        }


def _handoff_target_for_events(
    client: MemoryctlClient,
    review: dict[str, Any],
    state: dict[str, dict[str, Any]],
    handoff: dict[str, Any],
    *,
    allowed_events: set[str],
) -> str:
    """Return the one journal target exactly covered by an issued handoff.

    Recovery may cover a prepared item whose writer closeout was interrupted,
    or a completed item whose outer CLI exited before scrubbing the handoff.
    The stale bearer must never be mistaken for approval of another item, so
    every immutable capability field remains bound to the journaled review
    item and recorded intent fence.
    """

    if handoff.get("status") != "issued" or not str(handoff.get("token", "")):
        return ""
    mode = str(review.get("mode", LEGACY_SCOPE_MODE))
    matches: list[str] = []
    for item in review.get("items", []):
        if not isinstance(item, dict):
            return ""
        target = str(item.get("target_relative_path", ""))
        phase = state.get(target, {})
        if phase.get("event") not in allowed_events:
            continue
        if mode == LEGACY_SCOPE_MODE:
            operation = "content_update"
            reconcile_action = "MIGRATE_LEGACY_SCOPE"
        elif mode == GOVERNANCE_V4_MODE:
            operation = "governance_migration"
            reconcile_action = "UPDATE"
        elif mode == RISK_V4_MODE:
            operation = str(item.get("migration_operation", ""))
            reconcile_action = "UPDATE"
            if operation not in {"content_update", "status_transition"}:
                return ""
        else:
            return ""
        expected = {
            "subject_actor": client.actor,
            "task_hash": confirmation_capability.task_hash(
                client.session_id,
                client.actor,
            ),
            "session_hash": confirmation_capability.session_hash(
                client.session_id
            ),
            "proposal_id": str(phase.get("proposal_id", "")),
            "proposal_raw_sha256": str(item.get("proposal_raw_sha256", "")),
            "proposal_canonical_sha256": str(
                item.get("proposal_canonical_sha256", "")
            ),
            "target_relative_path": target,
            "operation": operation,
            "reconcile_action": reconcile_action,
            "fencing_token": int(phase.get("fencing_token", 0) or 0),
        }
        handoff_target_key = str(handoff.get("target_key", "")).strip().replace(
            "\\", "/"
        )
        # Match the confirmation-capability verifier exactly: current intents
        # use the canonical case-folded path, while an in-flight pre-upgrade
        # intent may still carry its opaque SHA-256 key.  All proposal, target,
        # actor/session, operation, and fence fields remain exact-bound.
        target_key_valid = bool(
            handoff_target_key == target.casefold()
            or HASH_RE.fullmatch(handoff_target_key) is not None
        )
        if target_key_valid and all(
            handoff.get(key) == value for key, value in expected.items()
        ):
            matches.append(target)
    if len(matches) > 1:
        raise ContentMigrationError(
            "CONFIRMATION_HANDOFF_BINDING_AMBIGUOUS",
            "handoff-recovery",
        )
    return matches[0] if matches else ""


def _completed_handoff_target(
    client: MemoryctlClient,
    review: dict[str, Any],
    state: dict[str, dict[str, Any]],
    handoff: dict[str, Any],
) -> str:
    return _handoff_target_for_events(
        client,
        review,
        state,
        handoff,
        allowed_events={"completed"},
    )


def _read_confirmation_handoff_for_apply(
    client: MemoryctlClient,
    *,
    handoff_path: str,
) -> dict[str, Any]:
    """Read a fresh handoff or recover one exact, already-consumed expiry."""

    try:
        return confirmation_capability.read_confirmation_handoff(
            write_gateway.CONFIG_ROOT,
            handoff_path=handoff_path,
        )
    except confirmation_capability.ConfirmationCapabilityError as exc:
        if exc.reason_code != "CONFIRMATION_HANDOFF_EXPIRED":
            raise
    return confirmation_capability.recover_consumed_confirmation_handoff(
        write_gateway.CONFIG_ROOT,
        handoff_path=handoff_path,
        subject_actor=client.actor,
        raw_task_id=client.session_id,
        raw_session_id=client.session_id,
    )


def _recover_completed_confirmation_handoff(
    client: MemoryctlClient,
    review: dict[str, Any],
    *,
    review_sha256: str,
    progress_path: Path,
    handoff: dict[str, Any],
) -> bool:
    """Scrub one exact stale bearer left after a durable completion append."""

    if not handoff or handoff.get("status") != "issued":
        return False
    events = load_progress(
        progress_path,
        review_sha256=review_sha256,
        actor=client.actor,
    )
    state = progress_state(events, review)
    if not _completed_handoff_target(client, review, state, handoff):
        return False
    try:
        confirmation_capability.mark_confirmation_handoff_consumed(
            write_gateway.CONFIG_ROOT,
            handoff_path=str(handoff.get("handoff_path", "")),
            capability_id=str(handoff.get("capability_id", "")),
        )
    except confirmation_capability.ConfirmationCapabilityError as exc:
        raise ContentMigrationError(
            exc.reason_code,
            "handoff-recovery",
        ) from exc
    # Keep the caller's in-memory view aligned so the outer CLI neither
    # forwards the stale bearer nor attempts a second final scrub.
    handoff.pop("token", None)
    handoff["status"] = "consumed"
    return True


def run_apply(
    client: MemoryctlClient,
    review: dict[str, Any],
    *,
    review_sha256: str,
    progress_path: Path,
    confirmation_capability_path: str = "",
    confirmation_capability_token: str = "",
    confirmation_handoff: dict[str, Any] | None = None,
    allow_apply: bool = True,
    append: Callable[[Path, dict[str, Any]], None] = append_progress,
) -> dict[str, Any]:
    """Serialize the complete resumable state machine for one review."""

    with progress_transaction_lock(progress_path):
        completed_recovery_binding: dict[str, Any] | None = None
        expired_terminal_recovery_target = ""
        expired_terminal_recovery_phase: dict[str, Any] | None = None
        if (
            confirmation_handoff
            and confirmation_handoff.get("consumed_recovery") is True
        ):
            recovered_intent_status = str(
                confirmation_handoff.get("intent_status", "")
            )
            if recovered_intent_status in {
                "pending", "approved", "bound", "validated",
            }:
                # Active intents cannot already have a terminal writer receipt.
                # In particular, pending is the consume-before-approve crash
                # window and must still name this exact prepared journal row.
                recovery_events_allowed = {"prepared"}
            elif recovered_intent_status == "completed":
                # Completion may precede either the progress append or only the
                # final bearer scrub, so both durable journal phases are valid.
                recovery_events_allowed = {"prepared", "completed"}
            else:
                raise ContentMigrationError(
                    "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
                    "handoff-recovery",
                )
            recovery_events = load_progress(
                progress_path,
                review_sha256=review_sha256,
                actor=client.actor,
            )
            recovery_state = progress_state(recovery_events, review)
            recovered_target = _handoff_target_for_events(
                client,
                review,
                recovery_state,
                confirmation_handoff,
                allowed_events=recovery_events_allowed,
            )
            if not recovered_target:
                raise ContentMigrationError(
                    "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
                    "handoff-recovery",
                )
            recovered_phase = recovery_state.get(recovered_target, {})
            expired_terminal_marker = (
                str(confirmation_handoff.get("intent_reason_code", ""))
                == write_intent.EXPIRED_VALIDATED_RECOVERY_COMPLETED_REASON
            )
            if expired_terminal_marker:
                if (
                    str(review.get("mode", LEGACY_SCOPE_MODE))
                    != GOVERNANCE_V4_MODE
                    or not allow_apply
                    or recovered_intent_status != "completed"
                    or recovered_phase.get("event")
                    not in {"prepared", "completed"}
                ):
                    raise ContentMigrationError(
                        "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
                        "handoff-recovery",
                    )
                if recovered_phase.get("event") == "completed":
                    expired_terminal_recovery_target = recovered_target
                    expired_terminal_recovery_phase = recovered_phase
            if (
                recovered_intent_status == "completed"
                and recovered_phase.get("event") == "prepared"
            ):
                recovered_item = next(
                    (
                        item
                        for item in review["items"]
                        if item.get("target_relative_path") == recovered_target
                    ),
                    None,
                )
                if not isinstance(recovered_item, dict):
                    raise ContentMigrationError(
                        "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
                        "handoff-recovery",
                    )
                completed_recovery_binding = {
                    "target_relative_path": recovered_target,
                    "proposal_id": str(recovered_phase["proposal_id"]),
                    "fencing_token": int(recovered_phase["fencing_token"]),
                    "proposal_raw_sha256": str(
                        recovered_item["proposal_raw_sha256"]
                    ),
                    "proposal_canonical_sha256": str(
                        recovered_item["proposal_canonical_sha256"]
                    ),
                }
            if _expired_validated_recovery_requested(
                confirmation_handoff
            ):
                if (
                    str(review.get("mode", LEGACY_SCOPE_MODE))
                    != GOVERNANCE_V4_MODE
                    or not allow_apply
                    or recovered_intent_status != "validated"
                    or recovered_phase.get("event") != "prepared"
                ):
                    raise ContentMigrationError(
                        "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
                        "handoff-recovery",
                    )
                try:
                    return _run_expired_validated_governance_recovery(
                        client,
                        review,
                        review_sha256=review_sha256,
                        progress_path=progress_path,
                        handoff=confirmation_handoff,
                        append=append,
                    )
                except ContentMigrationError as exc:
                    item_results: list[dict[str, Any]] = []
                    for candidate in review["items"]:
                        candidate_target = str(
                            candidate["target_relative_path"]
                        )
                        result: dict[str, Any] = {
                            "target_relative_path": candidate_target,
                            "status": (
                                "prepared_pending_apply"
                                if candidate_target == recovered_target
                                else "not_attempted"
                            ),
                        }
                        if candidate_target == (
                            exc.target_relative_path or recovered_target
                        ):
                            result.update({
                                "status": "blocked",
                                "stage": exc.stage,
                                "reason_code": exc.reason_code,
                            })
                        item_results.append(result)
                    return {
                        "schema_version": SCHEMA_VERSION,
                        "ok": False,
                        "status": "blocked",
                        "stage": exc.stage,
                        "reason_code": exc.reason_code,
                        "target_relative_path": (
                            exc.target_relative_path or recovered_target
                        ),
                        "review_sha256": review_sha256,
                        "progress_file": str(progress_path),
                        "items": item_results,
                    }
        handoff_scrubbed = bool(
            confirmation_handoff
            and _recover_completed_confirmation_handoff(
                client,
                review,
                review_sha256=review_sha256,
                progress_path=progress_path,
                handoff=confirmation_handoff,
            )
        )
        if handoff_scrubbed:
            confirmation_capability_path = ""
            confirmation_capability_token = ""
        if expired_terminal_recovery_target:
            if not handoff_scrubbed or expired_terminal_recovery_phase is None:
                raise ContentMigrationError(
                    "CONFIRMATION_HANDOFF_RECOVERY_INVALID",
                    "handoff-recovery",
                    expired_terminal_recovery_target,
                )
            recovered = {
                "target_relative_path": expired_terminal_recovery_target,
                "status": "already_applied",
                "idempotent": True,
                "git_commit": str(expired_terminal_recovery_phase["git_commit"]),
            }
            return {
                "schema_version": SCHEMA_VERSION,
                "ok": False,
                "status": "replan_required",
                "reason_code": "EXPIRED_VALIDATED_RECOVERY_REPLAN_REQUIRED",
                "review_sha256": review_sha256,
                "progress_file": str(progress_path),
                "items": _expired_recovery_result_items(
                    review,
                    recovered_target=expired_terminal_recovery_target,
                    recovered=recovered,
                ),
                "next_mode": GOVERNANCE_V4_MODE,
                "recovered_target_relative_path": (
                    expired_terminal_recovery_target
                ),
            }
        return _run_apply_with_structured_failure(
            client,
            review,
            review_sha256=review_sha256,
            progress_path=progress_path,
            confirmation_capability_path=confirmation_capability_path,
            confirmation_capability_token=confirmation_capability_token,
            completed_recovery_binding=completed_recovery_binding,
            allow_apply=allow_apply,
            append=append,
        )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reviewed Agent Memory content migration", allow_abbrev=False)
    parser.add_argument("--actor", choices=("codex", "claude"), default="codex")
    parser.add_argument("--session-id", default="")
    parser.add_argument("--json", action="store_true")
    subparsers = parser.add_subparsers(dest="action", required=True)
    plan = subparsers.add_parser("plan", allow_abbrev=False)
    plan.add_argument("--review-file", default="")
    plan.add_argument("--mode", choices=tuple(sorted(MIGRATION_MODES)), default=LEGACY_SCOPE_MODE)
    prepare_parser = subparsers.add_parser("prepare", allow_abbrev=False)
    prepare_parser.add_argument("--review-file", required=True)
    apply_parser = subparsers.add_parser("apply", allow_abbrev=False)
    apply_parser.add_argument("--review-file", required=True)
    return parser.parse_args(argv)


def _session_id(args: argparse.Namespace) -> str:
    explicit = str(args.session_id or "").strip()
    if explicit:
        return explicit
    keys = ("AGENT_MEMORY_SESSION_ID", "CODEX_THREAD_ID") if args.actor == "codex" else (
        "AGENT_MEMORY_SESSION_ID", "CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID",
    )
    return next((os.environ[key].strip() for key in keys if os.environ.get(key, "").strip()), "")


def _read_apply_request() -> dict[str, Any]:
    if hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
        return {}
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    raw = stream.read(MAX_STDIN_BYTES + 1)
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not raw:
        return {}
    if len(raw) > MAX_STDIN_BYTES:
        raise ContentMigrationError("APPLY_REQUEST_TOO_LARGE", "arguments")
    try:
        payload = strict_json_loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise ContentMigrationError("APPLY_REQUEST_INVALID", "arguments") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "confirmation_handoff_path"}
        or payload.get("schema_version") != 1
        or not isinstance(payload.get("confirmation_handoff_path"), str)
        or not payload["confirmation_handoff_path"].strip()
        or len(payload["confirmation_handoff_path"]) > 2048
        or any(char in payload["confirmation_handoff_path"] for char in ("\x00", "\r", "\n"))
    ):
        raise ContentMigrationError("APPLY_REQUEST_INVALID", "arguments")
    return payload


def _load_review_for_cli(path_value: str, actor: str) -> tuple[dict[str, Any], bytes, Path]:
    path = Path(path_value)
    raw, _metadata = read_private_file(path)
    try:
        review_object = strict_json_loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise ContentMigrationError("REVIEW_JSON_INVALID", "review") from exc
    if not isinstance(review_object, dict):
        raise ContentMigrationError("REVIEW_JSON_INVALID", "review")
    review = validate_review(review_object)
    if review["actor"] != actor:
        raise ContentMigrationError("REVIEW_ACTOR_MISMATCH", "review")
    return review, raw, path


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        client = MemoryctlClient(actor=args.actor, session_id=_session_id(args))
        if args.action == "plan":
            review = build_review(client, mode=args.mode)
            raw = _review_bytes(review)
            review_sha256 = hashlib.sha256(raw).hexdigest()
            if args.review_file:
                path = Path(os.path.abspath(os.path.expanduser(args.review_file)))
                write_private_exclusive(path, raw)
                payload = {
                    "schema_version": SCHEMA_VERSION,
                    "ok": True,
                    "status": "review_required",
                    "review_file": str(path),
                    "review_sha256": review_sha256,
                    "item_count": len(review["items"]),
                    "mode": args.mode,
                    "manual_review_count": int(review.get("manual_review_count", 0) or 0),
                }
            else:
                payload = {
                    "schema_version": SCHEMA_VERSION,
                    "ok": True,
                    "status": "review_required",
                    "review_sha256_if_saved_exactly": review_sha256,
                    "review_document": review,
                }
        else:
            review, raw, review_path = _load_review_for_cli(
                args.review_file,
                args.actor,
            )
            review_sha256 = hashlib.sha256(raw).hexdigest()
            capability_path = ""
            capability_token = ""
            handoff: dict[str, Any] = {}
            if args.action == "apply":
                request = _read_apply_request()
                handoff_path = str(request.get("confirmation_handoff_path", "")).strip()
                if handoff_path:
                    try:
                        handoff = _read_confirmation_handoff_for_apply(
                            client,
                            handoff_path=handoff_path,
                        )
                    except confirmation_capability.ConfirmationCapabilityError as exc:
                        raise ContentMigrationError(exc.reason_code, "arguments") from exc
                    if handoff.get("status") == "issued":
                        capability_path = str(handoff["capability_path"])
                        capability_token = str(handoff["token"])
                elif review.get("mode", LEGACY_SCOPE_MODE) == LEGACY_SCOPE_MODE:
                    # Backward-compatible private environment handoff for the
                    # old scope migrator only. governance-v4 accepts no bearer
                    # through argv, stdout, or ambient environment.
                    capability_path = os.environ.get(CONFIRMATION_CAPABILITY_PATH_ENV, "").strip()
                    capability_token = os.environ.get(CONFIRMATION_CAPABILITY_TOKEN_ENV, "").strip()
                elif (
                    review.get("mode", LEGACY_SCOPE_MODE)
                    == GOVERNANCE_V4_MODE
                    and not handoff
                ):
                    raise ContentMigrationError(
                        "CONFIRMATION_HANDOFF_REQUIRED",
                        "arguments",
                    )
                if bool(capability_path) != bool(capability_token):
                    raise ContentMigrationError("CONFIRMATION_CAPABILITY_INVALID", "arguments")
            payload = run_apply(
                client,
                review,
                review_sha256=review_sha256,
                progress_path=_progress_path(review_path),
                confirmation_capability_path=capability_path,
                confirmation_capability_token=capability_token,
                confirmation_handoff=handoff,
                allow_apply=args.action == "apply",
            )
            if handoff and handoff.get("status") == "issued" and any(
                item.get("status") in {"applied", "already_applied"}
                for item in payload.get("items", [])
                if isinstance(item, dict)
            ):
                try:
                    confirmation_capability.mark_confirmation_handoff_consumed(
                        write_gateway.CONFIG_ROOT,
                        handoff_path=str(handoff["handoff_path"]),
                        capability_id=str(handoff["capability_id"]),
                    )
                except confirmation_capability.ConfirmationCapabilityError as exc:
                    raise ContentMigrationError(exc.reason_code, "handoff-consume") from exc
    except ContentMigrationError as exc:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "ok": False,
            "status": "blocked",
            "stage": exc.stage,
            "reason_code": exc.reason_code,
        }
        if exc.target_relative_path:
            payload["target_relative_path"] = exc.target_relative_path
    except Exception:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "ok": False,
            "status": "blocked",
            "stage": "internal",
            "reason_code": "CONTENT_MIGRATION_INTERNAL_ERROR",
        }
    print(json.dumps(payload, ensure_ascii=False, indent=2) if args.json else f"content_migration={payload['status']}")
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
