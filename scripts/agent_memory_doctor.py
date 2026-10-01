#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from agent_memory_env import (
    RuntimeTransitionError,
    assert_runtime_ready,
    env_value,
    expand_path,
    load_config,
    parse_toml_fallback,
)
from agent_memory_host_automation import (
    AUDIT_LAUNCHAGENT_LABEL_PATTERN,
    DEFAULT_AUDIT_LAUNCHAGENT_LABEL,
    LaunchAgentSpec,
    audit_scheduler_health,
    classify_claude_hooks,
    classify_hook_event,
    codex_stop_hook_spec,
    discover_all_audit_launchagents,
    json_report_freshness,
)
from agent_memory_generated_index_capability import (
    GeneratedIndexCapabilityError,
    verify_generated_index_commit_evidence,
)
from install_audit_launchagent import launchagent_transaction_health
from agent_memory_state import (
    STATE_SCHEMA_VERSION,
    absolute_path,
    secure_sqlite_connect,
    sqlite_permission_report,
)
import agent_memory_observability
import agent_memory_index as memory_index
import agent_memory_migrate
import install_runtime as runtime_installer


VERSION = "2.7"
STATE_SCHEMA_REQUIRED = STATE_SCHEMA_VERSION
WRITER_PROTOCOL_REQUIRED = 2
CANONICAL_WRITER_ACTORS = ("codex", "claude", "ailu")
SUPPORTED_LEDGER_ACTORS = (*CANONICAL_WRITER_ACTORS, "human", "migration", "test")
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = expand_path(env_value("ROOT", str(REPO_ROOT / "templates" / "vault"))).resolve()
GIT_ROOT = expand_path(env_value("GIT_ROOT", str(REPO_ROOT))).resolve()
CONFIG_ROOT = expand_path(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory")).resolve()
STATE_DB = absolute_path(expand_path(env_value("STATE_DB", str(CONFIG_ROOT / "state.sqlite"))))
SCRIPT_ROOT = REPO_ROOT / "scripts"
PYTHON = expand_path(env_value("PYTHON", sys.executable))
AUDIT_LOG = expand_path(env_value("AUDIT_RUN_LOG", str(CONFIG_ROOT / "logs" / "audit_runs.jsonl"))).resolve()
AUDIT_REPORT = absolute_path(
    expand_path(
        env_value(
            "AUDIT_REPORT",
            str(CONFIG_ROOT / "reports" / "latest-audit.json"),
        )
    )
)
CLOSEOUT_LOG = expand_path(env_value("CLOSEOUT_LOG", str(CONFIG_ROOT / "logs" / "closeout.jsonl"))).resolve()
RUNTIME_MANIFEST = CONFIG_ROOT / "config" / "runtime-manifest.json"
HOST_CONFIG = load_config().get("host", {})
if not isinstance(HOST_CONFIG, dict):
    HOST_CONFIG = {}
SEMANTIC_CONFIG = load_config().get("semantic_retrieval", {})
if not isinstance(SEMANTIC_CONFIG, dict):
    SEMANTIC_CONFIG = {}
SEMANTIC_ENABLED = bool(SEMANTIC_CONFIG.get("enabled", False))
ZVEC_PYTHON = expand_path(env_value("ZVEC_PYTHON", str(CONFIG_ROOT / ".venv" / "bin" / "python")))
EMBEDDING_MODEL = expand_path(env_value("EMBEDDING_MODEL", ""))
MODEL_MANIFEST = expand_path(env_value("MODEL_MANIFEST", str(CONFIG_ROOT / "models" / "embeddinggemma-300m" / "model-manifest.json"))).resolve()
MODEL_REVISION = env_value("MODEL_REVISION", "")
DEPENDENCY_LOCK = expand_path(env_value("DEPENDENCY_LOCK", str(CONFIG_ROOT / "requirements-vector.lock"))).resolve()
REQUIRE_LOCAL_MODEL = env_value("REQUIRE_LOCAL_MODEL", "false").strip().lower() in {"1", "true", "yes", "on"}
EXCLUDED_VECTOR_TYPES = {"routing", "directory_index", "template", "agent_case_candidate", "skill_candidate"}
EXCLUDED_VECTOR_STATUS = {"archived", "deleted", "obsolete", "outdated", "deprecated", "stale"}
STALE_CLAIM_HOURS = 24
REMOTE_BACKUP_MAX_UNPUSHED_COMMITS = 10
REMOTE_BACKUP_MAX_AGE_DAYS = 3
OBSERVABILITY_TASK_CLASSES = {
    "",
    "existing_project",
    "one_off",
    "research",
    "coding",
    "writing",
    "troubleshooting",
    "formal_memory",
    "other_controlled",
}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
NON_ACTIVE_SCOPE_STATUSES = {
    "archived",
    "candidate",
    "closed",
    "deleted",
    "deprecated",
    "historical",
    "inactive",
    "obsolete",
    "outdated",
    "pending_verification",
    "resolved",
    "stale",
    "superseded",
}

REQUIRED_RUNTIME_FILES = (
    "agent_memory_index.py",
    "agent_memory_intent.py",
    "agent_memory_migrate.py",
    "agent_memory_lock.py",
    "agent_memory_observability.py",
    "agent_memory_search.py",
    "agent_memory_retrieve.py",
    "agent_memory_retrieval_benchmark.py",
    "agent_memory_embedding_worker.py",
    "agent_memory_explain.py",
    "agent_memory_shadow.py",
    "agent_memory_write.py",
    "agent_memory_safety.py",
    "agent_memory_closeout.py",
    "agent_memory_check.py",
    "agent_memory_content_migrate.py",
    "agent_memory_audit.py",
    "agent_memory_audit_autorun.py",
    "agent_memory_zvec_index.py",
    "agent_memory_policy_benchmark.py",
    "agent_memory_doctor.py",
    "agent_memory_decision_outcomes.py",
    "agent_memory_session_hook.py",
    "agent_memory_state.py",
    "agent_memory_stop_hook.py",
    "agent_memory_host_automation.py",
    "agent_memory_generated_index_capability.py",
    "agent_memory_confirmation_capability.py",
    "agent_memory_env.py",
    "install_audit_launchagent.py",
    "install-posix.py",
    "install_runtime.py",
    "install_host_hooks.py",
    "memoryctl",
)
SCOPE_REQUIRED_KEYS = ("status", "agent_scope", "app_id", "project_id")
VALID_AGENT_SCOPES = {"shared", "codex", "claude"}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def run(command: list[str], timeout: int = 300, env: dict[str, str] | None = None) -> dict[str, Any]:
    command_env = os.environ.copy() if env is None else env.copy()
    command_env.setdefault("PYTHONIOENCODING", "utf-8")
    command_env.setdefault("PYTHONUTF8", "1")
    try:
        completed = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            env=command_env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "returncode": 127, "detail": type(exc).__name__}
    return {"ok": completed.returncode == 0, "returncode": completed.returncode, "stdout": completed.stdout, "detail": (completed.stderr or completed.stdout).strip()[:500]}


def _load_install_posix_module() -> Any:
    """Load the canonical outer-install reducer without copying its rules."""

    path = SCRIPT_ROOT / "install-posix.py"
    spec = importlib.util.spec_from_file_location(
        "_agent_memory_install_posix_doctor",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("INSTALL_ORCHESTRATION_MODULE_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install_orchestration_doctor_check() -> dict[str, Any]:
    """Fail closed on an invalid or abandoned outer installation transaction."""

    transaction_id = os.environ.get("AGENT_MEMORY_INSTALL_TRANSACTION_ID", "").strip()
    input_sha256 = os.environ.get("AGENT_MEMORY_INSTALL_INPUT_SHA256", "").strip()
    binding_supplied = bool(transaction_id or input_sha256)
    binding_valid = bool(
        re.fullmatch(r"[0-9a-f]{32}", transaction_id)
        and re.fullmatch(r"[0-9a-f]{64}", input_sha256)
    )
    if binding_supplied and not binding_valid:
        return {
            "name": "install_orchestration",
            "status": "fail",
            "message": "The active installation binding is incomplete or invalid.",
            "detail": {
                "healthy": False,
                "status": "invalid",
                "reason_code": "INSTALL_ACTIVE_BINDING_INVALID",
                "transaction_id_present": bool(transaction_id),
                "input_sha256_present": bool(input_sha256),
            },
        }
    try:
        module = _load_install_posix_module()
        detail = module.install_orchestration_health(
            CONFIG_ROOT,
            active_transaction_id=transaction_id,
            active_input_sha256=input_sha256,
        )
    except Exception as exc:  # pragma: no cover - defensive import/read boundary
        detail = {
            "healthy": False,
            "status": "invalid",
            "reason_code": "INSTALL_ORCHESTRATION_CHECK_FAILED",
            "error": type(exc).__name__,
        }
    if not isinstance(detail, dict):
        detail = {
            "healthy": False,
            "status": "invalid",
            "reason_code": "INSTALL_ORCHESTRATION_CHECK_INVALID",
        }
    if binding_supplied:
        binding_matches = bool(
            detail.get("status") == "active"
            and detail.get("transaction_id") == transaction_id
            and detail.get("input_sha256") == input_sha256
        )
        detail = {
            **detail,
            "binding_matches": binding_matches,
            "healthy": detail.get("healthy") is True and binding_matches,
            "reason_code": (
                str(detail.get("reason_code", ""))
                if binding_matches
                else "INSTALL_ACTIVE_BINDING_MISMATCH"
            ),
        }
    healthy = detail.get("healthy") is True
    state = str(detail.get("status", "invalid"))
    if healthy and state == "active":
        message = "The current installation transaction is precisely bound and active."
    elif healthy:
        message = "The outer installation journal is terminal or empty."
    else:
        message = "The outer installation journal is invalid, interrupted, open, or requires recovery."
    return {
        "name": "install_orchestration",
        "status": "pass" if healthy else "fail",
        "message": message,
        "detail": detail,
    }


def add(checks: list[dict[str, Any]], name: str, status: str, message: str, detail: dict[str, Any] | None = None) -> None:
    checks.append({"name": name, "status": status, "message": message, "detail": detail or {}})


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _explicit_frontmatter(text: str) -> tuple[dict[str, str], set[str], str]:
    """Return scalar scope metadata without applying index defaults."""

    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if not normalized.startswith("---\n"):
        return {}, set(), "missing"
    closing_match = re.search(r"(?m)^---[ \t]*(?:\n|\Z)", normalized[4:])
    if closing_match is None:
        return {}, set(), "invalid"
    closing = 4 + closing_match.start()
    metadata: dict[str, str] = {}
    duplicates: set[str] = set()
    for raw_line in normalized[4:closing].splitlines():
        if not raw_line or raw_line[0].isspace() or ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        key = key.strip()
        if key in metadata:
            duplicates.add(key)
        metadata[key] = value.strip()
    return metadata, duplicates, "present"


def _inferred_scope_status(relative: Path) -> str:
    parts = relative.parts
    if not parts:
        return ""
    if parts[0] in {"用户记忆", "项目", "工作流", "决策"}:
        return "active"
    if parts[0] != "agent":
        return ""
    if len(parts) > 1 and parts[1] in {"case-candidates", "skill-candidates"}:
        return "candidate"
    return "active"


def _inferred_project_id(relative: Path) -> str:
    if relative.parts[:2] == ("agent", "README.md"):
        return "agent-memory"
    if relative.parts[:3] == ("agent", "case-candidates", "README.md"):
        return "agent-case-candidates"
    if relative.parts[:3] == ("agent", "cases", "README.md"):
        return "agent-cases"
    if relative.parts[:3] == ("agent", "skill-candidates", "README.md"):
        return "agent-skill-candidates"
    if relative.parts[:2] == ("用户记忆", "README.md"):
        return "user-memory"
    if relative.parts and relative.parts[0] == "agent" and relative.name == "open-loops.md":
        return "open-loops"
    return relative.stem.strip() or "legacy-memory"


def _is_formal_body_document(relative: Path) -> bool:
    """Compatibility wrapper around the shared governed-body boundary."""

    return memory_index.is_formal_body_document(relative)


def _normalized_scope_scalar(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value.strip()).casefold()
    if (
        not normalized
        or len(normalized) > 160
        or normalized in {"null", "none", "~"}
        or any(character in normalized for character in (",", "|", "[", "]", "{", "}", "\x00", "\n", "\r"))
    ):
        return ""
    return normalized


def _scope_status_policy(
    relative: Path,
    frontmatter: dict[str, str],
    duplicates: set[str],
    frontmatter_state: str,
) -> tuple[str, str]:
    """Classify one body without letting duplicate order hide active debt."""

    raw_status = unicodedata.normalize("NFKC", frontmatter.get("status", "").strip()).casefold()
    if "status" in duplicates:
        return "manual", raw_status
    if frontmatter_state == "present" and raw_status in NON_ACTIVE_SCOPE_STATUSES:
        return "excluded", raw_status
    if raw_status and raw_status != "active":
        return "manual", raw_status
    if not raw_status and _inferred_scope_status(relative) != "active":
        return "excluded", _inferred_scope_status(relative) or "unclassified"
    return "active", raw_status


def _scope_value_issue(key: str, value: str, relative: Path) -> str:
    if not value.strip():
        return "missing"
    normalized = _normalized_scope_scalar(value)
    if key == "agent_scope":
        return "" if normalized in VALID_AGENT_SCOPES else "invalid"
    if not normalized:
        return "invalid"
    if key == "project_id" and (
        normalized == "shared"
        or (normalized == "global" and relative.parts[0] != "用户记忆")
    ):
        return "invalid"
    return ""


def legacy_scope_documents_health() -> dict[str, Any]:
    """Find current formal bodies that cannot enter Write Gateway v2 yet.

    Only current ``active`` bodies are completion blockers. Explicit historical,
    candidate, archived, outdated, or pending-verification statuses are reported
    as excluded and are never silently promoted to active. An unknown explicit
    status is a manual review blocker. This matches the normal writer boundary:
    ordinary writes accept explicit ``status: active`` only.
    """

    default_app_id = _normalized_scope_scalar(env_value("APP_ID", "agent-memory")) or "agent-memory"
    pending: list[dict[str, Any]] = []
    excluded_by_status: dict[str, int] = {}
    scanned = 0
    active = 0
    unsafe: list[str] = []
    for path in sorted(VAULT_ROOT.rglob("*.md")):
        try:
            relative = path.relative_to(VAULT_ROOT)
        except ValueError:
            continue
        if not _is_formal_body_document(relative):
            continue
        scanned += 1
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                unsafe.append(relative.as_posix())
                continue
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError):
            unsafe.append(relative.as_posix())
            continue
        frontmatter, duplicates, frontmatter_state = _explicit_frontmatter(text)
        raw_status = unicodedata.normalize("NFKC", frontmatter.get("status", "").strip()).casefold()
        inferred_status = _inferred_scope_status(relative)
        status_policy, status_label = _scope_status_policy(
            relative, frontmatter, duplicates, frontmatter_state
        )
        if status_policy == "excluded":
            excluded_by_status[status_label] = excluded_by_status.get(status_label, 0) + 1
            continue
        issues: dict[str, str] = {}
        if frontmatter_state == "invalid":
            issues["frontmatter"] = "invalid"
        if "status" in duplicates:
            issues["status"] = "duplicate"
        if raw_status and raw_status != "active" and "status" not in issues:
            issues["status"] = "invalid"
        elif not raw_status:
            if inferred_status != "active":
                excluded_by_status[inferred_status or "unclassified"] = (
                    excluded_by_status.get(inferred_status or "unclassified", 0) + 1
                )
                continue
            issues["status"] = "missing"
        active += 1
        for key in ("agent_scope", "app_id", "project_id"):
            if key in duplicates:
                issues[key] = "duplicate"
                continue
            if key not in frontmatter:
                issues[key] = "missing"
                continue
            issue = _scope_value_issue(key, frontmatter[key], relative)
            if issue:
                issues[key] = issue
        if not issues:
            continue
        existing_app_id = frontmatter.get("app_id", "").strip()
        normalized_app_id = _normalized_scope_scalar(existing_app_id)
        requested_app_id = normalized_app_id or default_app_id
        existing_project_id = frontmatter.get("project_id", "").strip()
        normalized_project_id = _normalized_scope_scalar(existing_project_id)
        inferred_project_id = _inferred_project_id(relative)
        requested_project_id = (
            normalized_project_id if normalized_project_id else inferred_project_id
        )
        manual_reasons = sorted(key for key, value in issues.items() if value in {"invalid", "duplicate"})
        pending.append({
            "target_relative_path": relative.as_posix(),
            "issues": issues,
            "migrate_action": "MIGRATE_LEGACY_SCOPE",
            "migrate_legacy_scope": True,
            "legacy_scope_app_id": requested_app_id,
            "requested_app_id": requested_app_id,
            "requested_project_id": requested_project_id,
            "automatable": not manual_reasons,
            "manual_review_reasons": manual_reasons,
        })
    automatable = sum(1 for item in pending if item["automatable"])
    manual_review = len(pending) - automatable + len(unsafe)
    return {
        "policy": "full_vault_explicit_scope_v1",
        "migration_query_schema_version": 1,
        "required_keys": list(SCOPE_REQUIRED_KEYS),
        "writer_status_boundary": "active_only",
        "non_active_policy": "report_and_exclude_without_promotion",
        "completion_blocking": bool(pending or unsafe),
        "scanned_body_documents": scanned,
        "active_body_documents": active,
        "legacy_scope_documents": len(pending) + len(unsafe),
        "automatable_documents": automatable,
        "manual_review_documents": manual_review,
        "excluded_non_active_documents": sum(excluded_by_status.values()),
        "excluded_by_status": dict(sorted(excluded_by_status.items())),
        "unsafe_documents": unsafe,
        "migration_query": pending,
    }


def _exact_iso_date(value: object) -> dt.date | None:
    text = str(value or "").strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text) is None:
        return None
    try:
        return dt.date.fromisoformat(text)
    except ValueError:
        return None


def _durable_fact_evidence_provenance(
    conn: sqlite3.Connection | None,
    *,
    rel_path: str,
    raw_sha256: str,
) -> dict[str, Any]:
    """Prove evidence against the exact current bytes via a completed v2 receipt.

    A Markdown date or an evidence-looking body section is not durable
    provenance.  The proof must be a Git-bound Write Gateway v2 completion for
    the same path and raw content hash, with an authoritative fact source and a
    non-empty evidence reference.  Callers deliberately pass the already-open
    state connection; this helper never falls back to ambient/live state.
    """

    missing = {
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
    if conn is None or SHA256_PATTERN.fullmatch(raw_sha256) is None:
        return {
            "present": False,
            "source": "write_gateway_v2_receipt",
            "reason_code": "EVIDENCE_STATE_NOT_BOUND",
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
        if not missing.issubset(columns):
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
            and SHA256_PATTERN.fullmatch(str(row["asserted_by_sha256"] or ""))
            and str(row["safety_decision"] or "") == "ALLOW"
            and SHA256_PATTERN.fullmatch(str(row["evidence_ref_sha256"] or ""))
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
    *,
    temporal_policy: object,
    fact_key: object,
    valid_from: object,
    valid_until: object,
    verified_at: object,
    verified_at_source: object,
    evidence_present: bool,
    current_date: dt.date | None = None,
) -> list[str]:
    """Return the incomplete members of the active atomic-fact contract."""

    gaps: list[str] = []
    policy = str(temporal_policy or "").strip().casefold()
    if policy not in {"stable", "reviewable", "expiring"}:
        gaps.append("temporal_policy")

    _normalized_key, key_error = memory_index.normalized_fact_key(fact_key)
    if key_error:
        gaps.append("fact_key")

    valid_from_date = _exact_iso_date(valid_from)
    if valid_from_date is None:
        gaps.append("valid_from")

    verification_date = _exact_iso_date(verified_at)
    if (
        verification_date is None
        or str(verified_at_source or "").strip().casefold() != "frontmatter"
    ):
        gaps.append("verified_at")
    else:
        today = current_date or dt.date.today()
        if verification_date > today or (
            valid_from_date is not None and verification_date < valid_from_date
        ):
            gaps.append("verified_at")

    if policy == "expiring":
        valid_until_date = _exact_iso_date(valid_until)
        if valid_until_date is None or (
            valid_from_date is not None and valid_until_date < valid_from_date
        ):
            gaps.append("valid_until")
    if not evidence_present:
        gaps.append("evidence_provenance")
    return list(dict.fromkeys(gaps))


def governance_metadata_migration_health(
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Build the read-only, per-document v4 governance migration query.

    Only absent ``memory_id``, ``temporal_policy`` and
    ``review_after_days`` receive deterministic candidates.  This query never
    proposes a status/risk/body change and never promotes an ordinary document
    date to ``verified_at``.  Review findings are kept alongside automatable
    metadata debt so a mixed vault can migrate safe fields without hiding the
    items that still need human verification.
    """

    today = dt.date.today()
    assessments: list[dict[str, Any]] = []
    migration_query: list[dict[str, Any]] = []
    manual_queue: list[dict[str, Any]] = []
    unsafe: list[str] = []
    for path in sorted(VAULT_ROOT.rglob("*.md")):
        try:
            relative = path.relative_to(VAULT_ROOT)
        except ValueError:
            continue
        if not _is_formal_body_document(relative):
            continue
        rel_path = relative.as_posix()
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise OSError("unsafe governance target")
            raw_bytes = path.read_bytes()
            text = raw_bytes.decode("utf-8", errors="strict")
            raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        except (OSError, UnicodeError):
            unsafe.append(rel_path)
            continue

        explicit, duplicates, frontmatter_state = _explicit_frontmatter(text)
        parse_text = (
            text.replace("\r\n", "\n")
            if text.startswith("---\r\n")
            else text
        )
        parsed = memory_index.parse_frontmatter(parse_text)
        manual_reasons: list[str] = []
        invalid_fields: list[str] = []
        if frontmatter_state != "present":
            manual_reasons.append("FRONTMATTER_INVALID")
        relevant_duplicates = sorted(
            duplicates
            & {
                "memory_id", "temporal_policy", "review_after_days",
                "status", "agent_scope", "app_id", "project_id",
                "verified_at", "risk_class", "fact_key", "valid_from",
                "valid_until",
            }
        )
        if relevant_duplicates:
            manual_reasons.append("DUPLICATE_FRONTMATTER_KEYS")

        try:
            memory_type, track, inferred_project, status = memory_index.infer_from_path(
                path,
                parsed,
            )
            fact = memory_index.fact_metadata(parsed)
            inferred_policy, _policy_source = memory_index.temporal_policy_for(
                parsed,
                memory_type=memory_type,
                status=status,
                fact=fact,
            )
            title = memory_index.title_from_markdown(parse_text, path)
            inferred_review = memory_index.infer_review_after_days(
                path,
                title,
                memory_type,
                status,
                parsed,
            )
        except (OSError, ValueError):
            unsafe.append(rel_path)
            continue

        missing_fields: list[str] = []
        candidate: dict[str, Any] = {}
        raw_memory_id = explicit.get("memory_id", "").strip()
        if "memory_id" not in explicit:
            missing_fields.append("memory_id")
            candidate["memory_id"] = memory_index.memory_identity(rel_path, {})[0]
        elif SHA256_PATTERN.fullmatch(raw_memory_id) is None:
            invalid_fields.append("memory_id")

        raw_policy = explicit.get("temporal_policy", "").strip().casefold()
        if "temporal_policy" not in explicit:
            missing_fields.append("temporal_policy")
            candidate["temporal_policy"] = inferred_policy
        elif raw_policy not in memory_index.TEMPORAL_POLICIES:
            invalid_fields.append("temporal_policy")

        raw_review = explicit.get("review_after_days", "").strip()
        if "review_after_days" not in explicit:
            missing_fields.append("review_after_days")
            candidate["review_after_days"] = int(inferred_review)
        elif (
            re.fullmatch(r"[1-9][0-9]{0,3}", raw_review) is None
            or int(raw_review) > 3650
        ):
            invalid_fields.append("review_after_days")
        if invalid_fields:
            manual_reasons.append("INVALID_GOVERNANCE_METADATA")

        declared_memory_type = explicit.get("memory_type", "").strip().casefold()
        declared_track = explicit.get("track", "").strip().casefold()
        floor_track = {
            "项目": "project",
            "工作流": "workflow",
            "决策": "decision",
        }.get(relative.parts[0] if relative.parts else "", "")
        floor_type = floor_track
        allowed_raised_types = {"fact", "atomic_fact", "current_fact", "decision"}
        path_policy_conflict = bool(
            floor_track
            and (
                (declared_track and declared_track != floor_track)
                or (
                    declared_memory_type
                    and declared_memory_type not in {floor_type, *allowed_raised_types}
                )
            )
        )
        if path_policy_conflict:
            invalid_fields.append("path_policy")
            manual_reasons.append("PATH_POLICY_DOWNGRADE_FORBIDDEN")

        normalized_status = str(status or "active").strip().casefold()
        explicit_status = explicit.get("status", "").strip().casefold()
        governance_status_automatable = bool(
            explicit_status in memory_index.GOVERNANCE_MIGRATION_STATUSES
        )
        if not governance_status_automatable:
            manual_reasons.append("STATUS_REVIEW_REQUIRED")
        effective_policy = raw_policy if raw_policy in memory_index.TEMPORAL_POLICIES else inferred_policy
        effective_review = int(raw_review) if raw_review.isdigit() and 0 < int(raw_review) <= 3650 else int(inferred_review)
        verified_raw = explicit.get("verified_at", "").strip()
        verified = _exact_iso_date(verified_raw)
        # Only an explicit field-like line is verification evidence.  A phrase
        # or an ordinary date embedded in prose remains provenance.
        summary_match = re.search(
            r"(?m)^[ \t]*(?:[-*][ \t]+)?最近验证[:：][ \t]*(\d{4}-\d{2}-\d{2})[ \t]*$",
            text,
        )
        summary_verified = _exact_iso_date(summary_match.group(1)) if summary_match else None
        document_date = memory_index.extract_document_date(text)
        verification_mode = explicit.get("verification_mode", "").strip().casefold()
        if verified_raw:
            verification_source = "frontmatter" if verified is not None else "frontmatter_invalid"
            verification_date = verified.isoformat() if verified is not None else ""
        elif summary_match:
            verification_source = "summary_recently_verified" if summary_verified is not None else "summary_invalid"
            verification_date = summary_verified.isoformat() if summary_verified is not None else ""
        elif verification_mode in {"structural", "snapshot", "needs_review"}:
            verification_source = verification_mode
            verification_date = ""
        elif document_date:
            verification_source = "document_date_unverified"
            verification_date = ""
        else:
            verification_source = "needs_review"
            verification_date = ""
        verification_basis = {
            "source": verification_source,
            "verified_at": verification_date,
            "document_date": document_date,
            "document_date_is_verification": False,
        }
        verified_for_review = verified or summary_verified
        review_overdue = bool(
            normalized_status == "active"
            and effective_policy in {"stable", "reviewable", "expiring"}
            and verified_for_review is not None
            and (today - verified_for_review).days > effective_review
        )
        active_unverified = bool(
            normalized_status == "active"
            and effective_policy in {"stable", "reviewable", "expiring"}
            and (
                verified_for_review is None
                or verified_for_review > today
            )
        )
        risk_class = explicit.get("risk_class", "").strip().casefold()
        valid_from = explicit.get("valid_from", "").strip()
        valid_until = explicit.get("valid_until", "").strip()
        valid_until_date = _exact_iso_date(valid_until)
        fact_key = explicit.get("fact_key", "").strip()
        action_sensitive_signal = bool(
            risk_class == "action_sensitive"
            or memory_type in {"fact", "atomic_fact", "current_fact"}
            or effective_policy == "expiring"
            or valid_from
            or valid_until
            or fact_key
            or "事实-" in relative.stem
            or floor_track == "decision"
        )
        action_sensitive = bool(
            normalized_status == "active" and action_sensitive_signal
        )
        action_sensitive_expired = bool(
            action_sensitive
            and valid_until_date is not None
            and valid_until_date < today
        )
        evidence_provenance = _durable_fact_evidence_provenance(
            conn,
            rel_path=rel_path,
            raw_sha256=raw_sha256,
        )
        atomic_gap_fields = (
            _action_sensitive_atomic_gap_fields(
                temporal_policy=effective_policy,
                fact_key=fact_key,
                valid_from=valid_from,
                valid_until=valid_until,
                verified_at=verified_raw,
                verified_at_source="frontmatter" if verified_raw else "",
                evidence_present=bool(evidence_provenance["present"]),
                current_date=today,
            )
            if action_sensitive_signal
            else []
        )
        atomic_gap = bool(atomic_gap_fields)
        requested_agent_scope = _normalized_scope_scalar(
            explicit.get("agent_scope", "")
        )
        requested_app_id = _normalized_scope_scalar(explicit.get("app_id", ""))
        requested_project_id = _normalized_scope_scalar(explicit.get("project_id", ""))
        scope_invalid = bool(
            any(
                _scope_value_issue(key, explicit.get(key, ""), relative)
                for key in ("agent_scope", "app_id", "project_id")
            )
        )
        risk_reason_codes: list[str] = []
        risk_required = floor_track in {"project", "workflow", "decision"}
        if risk_class and risk_class not in {"ordinary", "action_sensitive"}:
            risk_reason_codes.append("METADATA_RISK_CLASS_INVALID")
        else:
            if not risk_class and (risk_required or action_sensitive_signal):
                risk_reason_codes.append("METADATA_RISK_CLASS_NOT_EXPLICIT")
            if action_sensitive_signal and risk_class == "ordinary":
                risk_reason_codes.append("METADATA_RISK_CLASS_DOWNGRADE")
            if (
                action_sensitive_signal
                and normalized_status == "active"
                and risk_class in {"", "action_sensitive"}
            ):
                if atomic_gap:
                    risk_reason_codes.append("ACTION_SENSITIVE_ATOMIC_GAP")
                if active_unverified:
                    risk_reason_codes.append("ACTION_SENSITIVE_ACTIVE_UNVERIFIED")
                if review_overdue:
                    risk_reason_codes.append("ACTION_SENSITIVE_REVIEW_OVERDUE")
                if action_sensitive_expired:
                    risk_reason_codes.append("ACTION_SENSITIVE_EXPIRED")
        # A missing risk class is an explicit review obligation.  Track names,
        # paths, and coarse document types are useful signals, but they are not
        # evidence that a document is safe to classify as ordinary.  Only the
        # action-sensitive direction is fail-closed and mechanically safe.
        recommended_risk = "action_sensitive" if action_sensitive_signal else ""
        if risk_reason_codes:
            if (
                normalized_status == "active"
                and action_sensitive_signal
                and (
                    atomic_gap
                    or active_unverified
                    or review_overdue
                    or action_sensitive_expired
                )
            ):
                risk_followup_operation = "status_transition"
                risk_target_status = "pending_verification"
            else:
                risk_followup_operation = "content_update"
                risk_target_status = ""
        else:
            risk_followup_operation = "none"
            risk_target_status = ""
        # Risk automation must stay inside the exact source states accepted by
        # Writer.  Active documents may be quarantined or receive a strict
        # risk-only raise; pending documents may only receive that risk-only
        # completion.  Historical and candidate states remain reviewable but
        # can never be advertised as automatically executable.
        risk_operation_status_allowed = bool(
            governance_status_automatable
            and (
                (
                    risk_followup_operation == "status_transition"
                    and explicit_status == "active"
                )
                or (
                    risk_followup_operation == "content_update"
                    and explicit_status in {"active", "pending_verification"}
                    and risk_class == ""
                    and risk_reason_codes
                    == ["METADATA_RISK_CLASS_NOT_EXPLICIT"]
                    and recommended_risk == "action_sensitive"
                )
            )
        )
        risk_automatable_after_governance = bool(
            risk_reason_codes
            and frontmatter_state == "present"
            and not relevant_duplicates
            and not scope_invalid
            and not invalid_fields
            and risk_class in {"", "ordinary", "action_sensitive"}
            and "METADATA_RISK_CLASS_INVALID" not in risk_reason_codes
            and "METADATA_RISK_CLASS_DOWNGRADE" not in risk_reason_codes
            and risk_operation_status_allowed
            and (
                risk_followup_operation == "status_transition"
                or (risk_followup_operation == "content_update" and bool(recommended_risk))
            )
        )
        risk_automatable = bool(
            risk_automatable_after_governance and not missing_fields
        )
        risk_manual = bool(
            risk_reason_codes
            and (
                not risk_automatable_after_governance
                or "METADATA_RISK_CLASS_INVALID" in risk_reason_codes
                or "METADATA_RISK_CLASS_DOWNGRADE" in risk_reason_codes
            )
        )
        risk_recommendation = {
            # Bind automation to the explicit source scalar. An inferred
            # default remains visible as manual debt and can never authorize
            # Writer to insert or reinterpret a missing status field.
            "source_status": explicit_status,
            "current": risk_class,
            "recommended": recommended_risk,
            "reason_codes": risk_reason_codes,
            "followup_operation": risk_followup_operation,
            "target_status": risk_target_status,
            "automatable_after_governance": risk_automatable_after_governance,
            "automatable_now": risk_automatable,
            "manual_review_required": risk_manual,
            "governance_migration_may_apply": False,
        }
        document_date_unverified = bool(
            document_date and verified is None and summary_verified is None
        )
        if document_date_unverified:
            manual_reasons.append("DOCUMENT_DATE_UNVERIFIED")
        if active_unverified:
            manual_reasons.append("ACTIVE_UNVERIFIED")
        if review_overdue:
            manual_reasons.append("REVIEW_OVERDUE")
        if action_sensitive_expired:
            manual_reasons.append("ACTION_SENSITIVE_EXPIRED")
        if action_sensitive:
            manual_reasons.append("ACTION_SENSITIVE_REVIEW")
        if atomic_gap:
            manual_reasons.append("ATOMIC_FACT_GAP")
        if risk_manual:
            manual_reasons.extend(risk_reason_codes)

        if scope_invalid:
            manual_reasons.append("SCOPE_REVIEW_REQUIRED")
        if not requested_app_id:
            requested_app_id = _normalized_scope_scalar(env_value("APP_ID", "agent-memory")) or "agent-memory"
        if not requested_project_id:
            requested_project_id = _normalized_scope_scalar(inferred_project) or _inferred_project_id(relative)

        manual_reasons = sorted(set(manual_reasons))
        automatable = bool(
            candidate
            and frontmatter_state == "present"
            and not relevant_duplicates
            and not invalid_fields
            and not scope_invalid
            and governance_status_automatable
        )
        assessment = {
            "target_relative_path": rel_path,
            "operation": "governance_migration",
            # Bind the exact normalized owner scope into every assessment.
            # The migration orchestrator validates the complete Doctor query
            # first and only then projects records into one deterministic host
            # lane; it must never infer ownership from its caller or operation.
            "requested_agent_scope": requested_agent_scope,
            "requested_app_id": requested_app_id,
            "requested_project_id": requested_project_id,
            "missing_fields": missing_fields,
            "invalid_fields": sorted(invalid_fields),
            "current_memory_id": (
                raw_memory_id if SHA256_PATTERN.fullmatch(raw_memory_id) else ""
            ),
            "candidate_metadata": candidate,
            "automatable": automatable,
            "manual_review_required": bool(manual_reasons),
            "manual_review_reasons": manual_reasons,
            "document_date_unverified": document_date_unverified,
            "verification_basis": verification_basis,
            "active_unverified": active_unverified,
            "review_overdue": review_overdue,
            "action_sensitive": action_sensitive,
            "atomic_fact_gap": atomic_gap,
            "atomic_fact_gap_fields": atomic_gap_fields,
            "durable_evidence_provenance": evidence_provenance,
            "risk_recommendation": risk_recommendation,
            "body_change_allowed": False,
            "status_change_allowed": False,
            "risk_change_allowed": False,
        }
        assessments.append(assessment)
        if candidate:
            migration_query.append(assessment)
        if manual_reasons:
            manual_queue.append(assessment)

    assessments.sort(key=lambda item: str(item["target_relative_path"]))
    migration_query.sort(key=lambda item: str(item["target_relative_path"]))
    manual_queue.sort(key=lambda item: str(item["target_relative_path"]))
    automatable = sum(1 for item in migration_query if item["automatable"])
    risk_query = [
        item for item in assessments
        if item["risk_recommendation"]["reason_codes"]
    ]
    risk_automatic = sum(
        1 for item in risk_query
        if item["risk_recommendation"]["automatable_now"]
    )
    risk_manual = sum(
        1 for item in risk_query
        if item["risk_recommendation"]["manual_review_required"]
    )
    return {
        "policy": "governance_metadata_v4",
        "migration_query_schema_version": 4,
        "governed_documents": len(assessments) + len(unsafe),
        "migration_candidate_documents": len(migration_query),
        "automatable_documents": automatable,
        "manual_review_documents": len(manual_queue) + len(unsafe),
        "risk_candidate_documents": len(risk_query),
        "risk_automatable_documents": risk_automatic,
        "risk_manual_review_documents": risk_manual,
        "clean_documents": sum(
            1 for item in assessments
            if (
                not item["candidate_metadata"]
                and not item["manual_review_required"]
                and not item["risk_recommendation"]["reason_codes"]
            )
        ),
        "unsafe_documents": sorted(unsafe),
        "documents": assessments,
        "migration_query": migration_query,
        "manual_review_queue": manual_queue,
        "risk_migration_query": risk_query,
        "risk_migration_query_sha256": hashlib.sha256(
            json.dumps(
                risk_query,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "migration_query_sha256": hashlib.sha256(
            json.dumps(
                migration_query,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "ordinary_document_dates_never_verify": True,
        "allowed_automatic_fields": [
            "memory_id", "temporal_policy", "review_after_days"
        ],
    }


def closeout_observation_health() -> tuple[bool, dict[str, Any]]:
    """Report formal-memory history that still lacks a completed closeout observation."""
    try:
        import agent_memory_closeout as closeout

        baseline = closeout.last_observed_git_head()
        head, head_warnings = closeout.current_git_head()
        entries, history_warnings = closeout.git_history_entries(baseline, head)
        pending = closeout.unobserved_history_entries(entries)
    except (AttributeError, ImportError, OSError, sqlite3.Error, subprocess.SubprocessError, ValueError) as exc:
        return False, {"error": type(exc).__name__}

    warnings = [*head_warnings, *history_warnings]
    pending_existing = sorted(closeout.relative_to_vault(entry.path) for entry in pending if not entry.is_deleted)
    pending_deleted = sorted(closeout.relative_to_vault(entry.path) for entry in pending if entry.is_deleted)
    detail = {
        "baseline": baseline,
        "head": head,
        "history_paths": len(entries),
        "pending_count": len(pending),
        "pending_existing": pending_existing,
        "pending_deleted": pending_deleted,
        "warnings": warnings,
    }
    return bool(baseline and head and not warnings and not pending), detail


def offline_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    env["HF_HUB_OFFLINE"] = "1"
    env["TRANSFORMERS_OFFLINE"] = "1"
    return env


def verify_model_manifest() -> tuple[bool, dict[str, Any]]:
    manifest = read_json_object(MODEL_MANIFEST)
    root = Path(os.path.expandvars(str(manifest.get("root", "")))).expanduser().resolve() if manifest else Path()
    files = manifest.get("files") if isinstance(manifest, dict) else None
    missing: list[str] = []
    size_mismatch: list[str] = []
    hash_mismatch: list[str] = []
    invalid_entries: list[str] = []
    symlinks: list[str] = []
    if not manifest or not root.is_dir() or not isinstance(files, dict) or not files:
        return False, {"manifest": str(MODEL_MANIFEST), "root": str(root), "error": "manifest_or_root_missing"}
    for rel_path, expected in files.items():
        path = root / str(rel_path)
        if path.is_symlink():
            symlinks.append(str(rel_path))
        if not path.is_file():
            missing.append(str(rel_path))
            continue
        expected_size = expected.get("size") if isinstance(expected, dict) else None
        expected_hash = expected.get("sha256") if isinstance(expected, dict) else None
        if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
            or not isinstance(expected_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
        ):
            invalid_entries.append(str(rel_path))
            continue
        if expected_size is not None and path.stat().st_size != int(expected_size):
            size_mismatch.append(str(rel_path))
            continue
        if file_sha256(path) != expected_hash:
            hash_mismatch.append(str(rel_path))
    revision = str(manifest.get("revision", ""))
    revision_format_ok = bool(re.fullmatch(r"[0-9a-f]{40}", MODEL_REVISION))
    revision_ok = revision_format_ok and MODEL_REVISION == revision
    ok = not missing and not size_mismatch and not hash_mismatch and not symlinks and not invalid_entries and revision_ok
    return ok, {
        "manifest": str(MODEL_MANIFEST),
        "root": str(root),
        "revision": revision,
        "expected_revision": MODEL_REVISION,
        "revision_format_ok": revision_format_ok,
        "checked_files": len(files),
        "missing": missing,
        "size_mismatch": size_mismatch,
        "hash_mismatch": hash_mismatch,
        "invalid_entries": invalid_entries,
        "symlinks": symlinks,
    }


def verify_dependency_lock() -> tuple[bool, dict[str, Any]]:
    detail = runtime_installer.semantic_dependency_state(
        ZVEC_PYTHON,
        DEPENDENCY_LOCK,
        timeout=60,
    )
    return bool(detail.get("ok")), detail


def verify_semantic_python_runtime() -> tuple[bool, dict[str, Any]]:
    if not ZVEC_PYTHON.is_file():
        return False, {"python": str(ZVEC_PYTHON), "error": "python_missing_or_broken_symlink"}
    code = """
import json
import os
import sys
base = getattr(sys, '_base_executable', '') or sys.executable
print(json.dumps({
    'executable': sys.executable,
    'base_executable': base,
    'base_exists': os.path.isfile(base),
    'version': '.'.join(str(part) for part in sys.version_info[:3]),
}))
"""
    result = run([str(ZVEC_PYTHON), "-c", code], 30, offline_env())
    try:
        detail = json.loads(str(result.get("stdout", "")))
    except json.JSONDecodeError:
        detail = {"error": result.get("detail", "invalid_python_runtime_output")}
    detail.update({"python": str(ZVEC_PYTHON), "returncode": result.get("returncode")})
    ok = bool(result["ok"] and detail.get("base_exists"))
    if result["ok"] and not detail.get("base_exists"):
        detail["error"] = "base_interpreter_missing"
    return ok, detail


def offline_semantic_probe() -> tuple[bool, dict[str, Any]]:
    # Doctor itself is allowed to diagnose a closed Runtime.  Its semantic
    # subprocess is not: while publish-ready holds ``phase=preflight`` it must
    # inherit and prove the migrator's short-lived zvec capability.  Check the
    # same authorization in this process first so a lost capability is
    # reported explicitly instead of becoming returncode=2 with an empty error.
    try:
        transition = assert_runtime_ready("zvec")
    except RuntimeTransitionError:
        return False, {
            "error": "RUNTIME_TRANSITION_INCOMPLETE",
            "reason_code": "RUNTIME_TRANSITION_INCOMPLETE",
            "returncode": 2,
            "model": str(EMBEDDING_MODEL),
            "offline": True,
        }
    command = [
        str(ZVEC_PYTHON),
        str(SCRIPT_ROOT / "agent_memory_zvec_index.py"),
        "--search",
        "Agent Memory offline healthcheck",
        "--limit",
        "1",
        "--json",
    ]
    result = run(command, 240, offline_env())
    try:
        payload = json.loads(str(result.get("stdout", "")))
    except json.JSONDecodeError:
        detail = str(result.get("detail", "") or "non_json_probe")
        return False, {
            "error": detail,
            "reason_code": detail,
            "returncode": result.get("returncode"),
            "model": str(EMBEDDING_MODEL),
            "offline": True,
        }
    rows = payload.get("results") if isinstance(payload, dict) else None
    ok = bool(result["ok"] and isinstance(rows, list) and rows)
    reason_code = ""
    if isinstance(payload, dict):
        reason_code = str(payload.get("reason_code") or payload.get("error") or "")
    if not ok and not reason_code:
        reason_code = str(result.get("detail", "") or "SEMANTIC_OFFLINE_PROBE_FAILED")
    return ok, {
        "returncode": result.get("returncode"),
        "result_count": len(rows) if isinstance(rows, list) else 0,
        "model": str(EMBEDDING_MODEL),
        "offline": True,
        "maintenance_capability": bool(transition.get("maintenance_capability")),
        "reason_code": reason_code,
        "error": reason_code,
    }


def parse_time(value: str) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def latest_jsonl(path: Path, predicate: Any = None) -> dict[str, Any] | None:
    if not path.exists():
        return None
    latest = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and (not predicate or predicate(item)):
            latest = item
    return latest


def read_json_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _hook_command_entries(hooks: dict[str, Any], event: str) -> list[dict[str, Any]]:
    groups = hooks.get(event)
    if not isinstance(groups, list):
        return []
    entries: list[dict[str, Any]] = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
            continue
        entries.extend(item for item in group["hooks"] if isinstance(item, dict))
    return entries


def _hook_argv(entry: dict[str, Any]) -> list[str] | None:
    if str(entry.get("type", "")).casefold() != "command":
        return None
    try:
        argv = shlex.split(str(entry.get("command", "")), posix=os.name != "nt")
    except ValueError:
        return None
    return argv or None


def _hook_token_name(value: str) -> str:
    return Path(value.strip('"')).name.casefold()


def _python_command_name(value: str) -> bool:
    return bool(re.fullmatch(r"python(?:\d+(?:\.\d+)*)?(?:\.exe)?", _hook_token_name(value)))


def _hook_path_matches(value: str, expected: Path, *, executable: bool = False) -> bool:
    def normalized(raw: str | Path, *, search_path: bool) -> str:
        candidate = Path(str(raw).strip('"')).expanduser()
        if not candidate.is_absolute():
            discovered = shutil.which(str(candidate)) if search_path else None
            if not discovered:
                return ""
            candidate = Path(discovered)
        return os.path.normcase(os.path.abspath(str(candidate)))

    actual_path = normalized(value, search_path=executable)
    expected_path = normalized(expected, search_path=executable)
    return bool(actual_path and expected_path and actual_path == expected_path)


def _managed_hook_route(entry: dict[str, Any], *, command_name: str) -> bool:
    """Recognize one managed route without substring matching.

    This intentionally recognizes malformed managed routes too.  The caller can
    then reject duplicates instead of letting one exact entry hide a stale or
    unsafe second Agent Memory hook.
    """

    argv = _hook_argv(entry)
    if argv is None:
        return False
    script_name = (
        "agent_memory_session_hook.py"
        if command_name == "session-hook"
        else "agent_memory_stop_hook.py"
    )
    names = [_hook_token_name(value) for value in argv]
    if script_name in names:
        return True
    return "memoryctl" in names and command_name in argv


def _exact_hook_command(
    entry: dict[str, Any],
    *,
    actor: str,
    command_name: str,
    forwarded: tuple[str, ...],
    timeout: float,
) -> bool:
    """Validate the complete canonical or legacy command and host timeout."""

    configured_timeout = entry.get("timeout")
    if (
        not isinstance(configured_timeout, (int, float))
        or isinstance(configured_timeout, bool)
        or float(configured_timeout) != float(timeout)
    ):
        return False
    argv = _hook_argv(entry)
    if argv is None:
        return False

    script_name = (
        "agent_memory_session_hook.py"
        if command_name == "session-hook"
        else "agent_memory_stop_hook.py"
    )
    canonical_prefix = ["-I", "-S"]
    canonical = bool(
        len(argv) >= 7
        and _python_command_name(argv[0])
        and _hook_path_matches(argv[0], PYTHON, executable=True)
        and argv[1:3] == canonical_prefix
        and _hook_token_name(argv[3]) == "memoryctl"
        and _hook_path_matches(argv[3], SCRIPT_ROOT / "memoryctl")
        and argv[4:7] == ["--actor", actor, command_name]
        and argv[7:] == list(forwarded)
    )
    if canonical:
        return True

    legacy_tail = ["--actor", actor, *forwarded]
    script = SCRIPT_ROOT / script_name
    if _hook_token_name(argv[0]) == script_name and _hook_path_matches(argv[0], script):
        return argv[1:] == legacy_tail
    if not _python_command_name(argv[0]) or not _hook_path_matches(
        argv[0], PYTHON, executable=True
    ):
        return False
    if (
        len(argv) >= 2
        and _hook_token_name(argv[1]) == script_name
        and _hook_path_matches(argv[1], script)
    ):
        return argv[2:] == legacy_tail
    return bool(
        len(argv) >= 4
        and argv[1:3] == canonical_prefix
        and _hook_token_name(argv[3]) == script_name
        and _hook_path_matches(argv[3], script)
        and argv[4:] == legacy_tail
    )


def _single_exact_hook(
    entries: list[dict[str, Any]],
    *,
    actor: str,
    command_name: str,
    forwarded: tuple[str, ...],
    timeout: float,
) -> tuple[bool, int]:
    managed = [
        entry for entry in entries if _managed_hook_route(entry, command_name=command_name)
    ]
    return (
        len(managed) == 1
        and _exact_hook_command(
            managed[0],
            actor=actor,
            command_name=command_name,
            forwarded=forwarded,
            timeout=timeout,
        ),
        len(managed),
    )


def codex_hook_semantics(hooks: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    detail = classify_hook_event(
        hooks,
        "Stop",
        runtime_python=PYTHON,
        runtime_root=REPO_ROOT,
        spec=codex_stop_hook_spec(),
    )
    stop_ok = bool(detail["healthy"])
    return stop_ok, {
        **detail,
        "stop_scoped_and_blocking": stop_ok,
        "managed_stop_count": int(detail["canonical_count"])
        + int(detail["legacy_count"])
        + int(detail["ambiguous_count"]),
    }


def codex_hooks_feature_enabled(config_path: Path) -> tuple[bool, dict[str, Any]]:
    try:
        if config_path.is_symlink() or not config_path.is_file():
            raise ValueError("CODEX_CONFIG_UNSAFE")
        payload = parse_toml_fallback(config_path.read_text(encoding="utf-8-sig"))
        features = payload.get("features") if isinstance(payload, dict) else None
        enabled = isinstance(features, dict) and features.get("hooks") is True
    except (OSError, UnicodeDecodeError, ValueError):
        enabled = False
    return enabled, {
        "config_path": str(config_path),
        "config_hooks_enabled": enabled,
    }


def claude_hook_semantics(hooks: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    classified = classify_claude_hooks(
        hooks,
        runtime_python=PYTHON,
        runtime_root=REPO_ROOT,
    )
    stop = classified["events"]["Stop"]
    session_end = classified["events"]["SessionEnd"]
    session_start = classified["events"]["SessionStart"]
    stop_ok = bool(stop["healthy"])
    session_end_ok = bool(session_end["healthy"])
    session_start_ok = bool(session_start["healthy"])
    return stop_ok and session_end_ok and session_start_ok, {
        "stop_scoped_and_blocking": stop_ok,
        "session_end_non_blocking": session_end_ok,
        "session_start_bridge": session_start_ok,
        "managed_stop_count": int(stop["canonical_count"]) + int(stop["legacy_count"]) + int(stop["ambiguous_count"]),
        "managed_session_end_count": int(session_end["canonical_count"]) + int(session_end["legacy_count"]) + int(session_end["ambiguous_count"]),
        "managed_session_start_count": int(session_start["canonical_count"]) + int(session_start["legacy_count"]) + int(session_start["ambiguous_count"]),
        "legacy_count": int(stop["legacy_count"]) + int(session_end["legacy_count"]) + int(session_start["legacy_count"]),
        "ambiguous_count": int(stop["ambiguous_count"]) + int(session_end["ambiguous_count"]) + int(session_start["ambiguous_count"]),
        "disabled_count": int(stop["disabled_count"]) + int(session_end["disabled_count"]) + int(session_start["disabled_count"]),
        "wrapper_paths": sorted({
            str(path)
            for detail in (stop, session_end, session_start)
            for path in detail.get("wrapper_paths", [])
        }),
        "semantic_fingerprint_sha256": classified["semantic_fingerprint_sha256"],
        "events": {
            "Stop": stop,
            "SessionEnd": session_end,
            "SessionStart": session_start,
        },
    }


def configured_path(name: str) -> Path | None:
    raw = HOST_CONFIG.get(name)
    if not isinstance(raw, str) or not raw.strip():
        return None
    # Preserve the configured lexical path.  Resolving here erases evidence
    # that a host configuration is a symlink even though every installer
    # rejects such targets and the semantic command contract is lexical.
    return Path(os.path.abspath(str(expand_path(raw))))


def configured_or_required_host_path(
    name: str,
    *,
    host: str,
    required_hosts: set[str],
    default: Path,
) -> Path | None:
    """Prefer an explicit managed path, using host defaults only as fallback."""

    configured = configured_path(name)
    if configured is not None:
        return configured
    return default if host in required_hosts else None


def attested_host_hook_policy(
    transition_path: Path | None = None,
) -> dict[str, Any]:
    """Return the ready marker's authoritative host-policy projection.

    ``[host]`` intentionally contains scheduler/persistence paths and may not
    list Codex or Claude at all.  A ready Runtime does record that choice in
    its preflight attestation, so Doctor must use it instead of silently
    skipping live Hook checks when HOST_CONFIG has no Hook paths.
    """

    path = transition_path or (CONFIG_ROOT / "config" / "runtime-transition.json")
    marker = read_json_object(path)
    attestation = marker.get("preflight_attestation") if isinstance(marker, dict) else None
    hooks = attestation.get("host_hooks") if isinstance(attestation, dict) else None
    managed_ready = bool(
        isinstance(marker, dict)
        and marker.get("phase") == "ready"
        and REPO_ROOT.resolve() == CONFIG_ROOT.resolve()
    )
    if not isinstance(hooks, dict):
        return {
            "available": managed_ready,
            "valid": False,
            "policy": "",
            "hosts": [],
            "reason_code": "HOST_HOOK_ATTESTATION_MISSING",
            "path": str(path),
        }
    policy = str(hooks.get("policy", ""))
    verified = hooks.get("verified") is True
    raw_hosts = hooks.get("hosts", [])
    hosts_payload_valid = bool(
        isinstance(raw_hosts, list)
        and all(isinstance(item, str) for item in raw_hosts)
    )
    hosts = (
        [str(item) for item in raw_hosts]
        if hosts_payload_valid
        else []
    )
    unique_hosts = sorted(set(hosts))
    required_valid = bool(
        policy == "required"
        and verified
        and hosts_payload_valid
        and hosts
        and len(hosts) == len(unique_hosts)
        and set(hosts).issubset({"codex", "claude"})
    )
    disabled_valid = bool(
        policy == "explicitly_disabled"
        and verified
        and hosts_payload_valid
        and not hosts
    )
    valid = required_valid or disabled_valid
    return {
        "available": True,
        "valid": valid,
        "policy": policy,
        "hosts": unique_hosts if valid else [],
        "reason_code": "" if valid else "HOST_HOOK_ATTESTATION_INVALID",
        "path": str(path),
    }


def legacy_hook_wrapper_references() -> list[str]:
    """Inspect configured/default host files for referenced legacy wrappers."""

    candidates: list[tuple[str, Path]] = [
        (
            "codex",
            configured_path("codex_hooks_json")
            or (Path.home() / ".codex" / "hooks.json"),
        ),
        (
            "claude",
            configured_path("claude_settings_json")
            or (Path.home() / ".claude" / "settings.json"),
        ),
    ]
    fragment = configured_path("claude_hooks_fragment")
    if fragment is not None:
        candidates.append(("claude_fragment", fragment))
    wrapper_paths: set[str] = set()
    for kind, path in candidates:
        payload = read_json_object(path)
        if kind == "claude_fragment":
            hooks = payload
        else:
            hooks = payload.get("hooks") if isinstance(payload.get("hooks"), dict) else {}
        if kind == "codex":
            details = [classify_hook_event(
                hooks,
                "Stop",
                runtime_python=PYTHON,
                runtime_root=REPO_ROOT,
                spec=codex_stop_hook_spec(),
            )]
        else:
            details = list(classify_claude_hooks(
                hooks,
                runtime_python=PYTHON,
                runtime_root=REPO_ROOT,
            )["events"].values())
        for detail in details:
            wrapper_paths.update(
                str(item) for item in detail.get("wrapper_paths", []) if str(item)
            )
    return sorted(wrapper_paths)


def audit_launchagent_doctor_check(
    *,
    allow_content_migration_bootstrap: bool = False,
    host_config: dict[str, Any] | None = None,
    runtime_root: Path | None = None,
    runtime_python: Path | None = None,
    home: Path | None = None,
) -> dict[str, Any] | None:
    """Return the exact macOS scheduler check, including missing-config drift.

    A missing ``[host]`` table must never make the scheduler disappear from
    Doctor.  Defaults let us inspect the canonical target without trusting a
    stale config, while ``configuration_complete`` keeps final acceptance
    closed until the managed settings are explicit.
    """

    if sys.platform != "darwin":
        return None
    active_host = HOST_CONFIG if host_config is None else host_config
    if not isinstance(active_host, dict):
        active_host = {}
    active_home = Path(os.path.abspath(str(home or Path.home())))
    active_runtime_root = Path(os.path.abspath(str(runtime_root or CONFIG_ROOT)))
    # A venv launcher is normally a symlink.  The installed plist deliberately
    # records the managed launcher path, not its Homebrew/base-interpreter
    # target, so resolving it creates a false command drift in Doctor.
    active_runtime_python = Path(
        os.path.abspath(str(runtime_python or PYTHON))
    )

    issues: list[str] = []
    label_value = active_host.get("audit_launchagent_label")
    configured_label = label_value.strip() if isinstance(label_value, str) else ""
    if not configured_label:
        issues.append("AUDIT_LAUNCHAGENT_LABEL_CONFIG_MISSING")
    elif not AUDIT_LAUNCHAGENT_LABEL_PATTERN.fullmatch(configured_label):
        issues.append("AUDIT_LAUNCHAGENT_LABEL_CONFIG_INVALID")
    label = (
        configured_label
        if configured_label and AUDIT_LAUNCHAGENT_LABEL_PATTERN.fullmatch(configured_label)
        else DEFAULT_AUDIT_LAUNCHAGENT_LABEL
    )

    path_value = active_host.get("audit_launchagent")
    configured_plist = path_value.strip() if isinstance(path_value, str) else ""
    if not configured_plist:
        issues.append("AUDIT_LAUNCHAGENT_PATH_CONFIG_MISSING")
        launch_path = active_home / "Library" / "LaunchAgents" / f"{label}.plist"
    else:
        launch_path = Path(os.path.abspath(str(expand_path(configured_plist))))

    launch_spec = LaunchAgentSpec(
        label=label,
        plist_path=launch_path,
        runtime_root=active_runtime_root,
        runtime_python=active_runtime_python,
        stdout_path=active_runtime_root / "logs" / "audit-launchd.out.log",
        stderr_path=active_runtime_root / "logs" / "audit-launchd.err.log",
        working_directory=active_home,
    )
    launch_result = run(
        ["launchctl", "print", f"gui/{active_home.stat().st_uid}/{label}"],
        15,
    )
    scheduler = audit_scheduler_health(
        launch_spec,
        print_returncode=int(launch_result.get("returncode", 127)),
        print_stdout=str(launch_result.get("stdout", "")),
        success_report_path=AUDIT_REPORT,
    )
    scheduler_inventory = discover_all_audit_launchagents(launch_spec)
    transaction_detail = launchagent_transaction_health(active_runtime_root)
    configuration_complete = not issues
    launch_ok = (
        configuration_complete
        and scheduler["healthy"]
        and scheduler_inventory["healthy"]
        and transaction_detail["healthy"]
    )
    failure_status = "warn" if allow_content_migration_bootstrap else "fail"
    return {
        "name": "audit_launchagent",
        "status": "pass" if launch_ok else failure_status,
        "message": (
            "Weekly Sunday 10:30 audit LaunchAgent has explicit managed configuration, an exact command, a completed run, exit 0, and a recent successful report."
            if launch_ok
            else "Weekly audit LaunchAgent configuration is missing, drifted, unloaded, or last exited non-zero."
        ),
        "detail": {
            "configuration_complete": configuration_complete,
            "configuration_issues": issues,
            "using_default_target": bool(issues),
            "label": label,
            "plist_path": str(launch_path),
            "scheduler_inventory": scheduler_inventory,
            "transaction": transaction_detail,
            **scheduler,
        },
    }


def local_endpoint_reachable(raw_url: str) -> tuple[bool, dict[str, Any]]:
    parsed = urlparse(raw_url)
    host = parsed.hostname or ""
    if host not in {"127.0.0.1", "localhost", "::1"}:
        return True, {"url_type": "remote_or_unset"}
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True, {"host": host, "port": port, "listening": True}
    except OSError:
        return False, {"host": host, "port": port, "listening": False}


def cc_switch_hooks_match(db_path: Path, expected_hooks: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    if not db_path.exists() and not db_path.is_symlink():
        return True, {"installed": False}
    if db_path.is_symlink() or not db_path.is_file():
        return False, {
            "installed": True,
            "error": "CC_SWITCH_DB_UNSAFE",
        }
    try:
        # Doctor is read-only. ``mode=ro`` also closes the check/open race in
        # which a provider manager moves the database after ``is_file()`` and a
        # default sqlite3 connection silently creates a new empty file.
        with contextlib.closing(
            sqlite3.connect(
                f"{db_path.resolve().as_uri()}?mode=ro",
                uri=True,
                timeout=5,
            )
        ) as conn:
            conn.execute("PRAGMA busy_timeout=5000")
            common = conn.execute("SELECT value FROM settings WHERE key = 'common_config_claude'").fetchone()
            backups = conn.execute("SELECT original_config FROM proxy_live_backup WHERE app_type = 'claude'").fetchall()
            providers = conn.execute(
                "SELECT settings_config FROM providers WHERE app_type = 'claude'"
            ).fetchall()
        common_payload = json.loads(str(common[0])) if common else {}
        backup_payloads = [json.loads(str(row[0])) for row in backups]
        provider_payloads = [json.loads(str(row[0])) for row in providers]
    except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError) as exc:
        return False, {"installed": True, "error": type(exc).__name__}
    expected_ok = claude_hook_semantics(expected_hooks)[0]
    common_hooks = common_payload.get("hooks") if isinstance(common_payload, dict) else None
    common_ok = isinstance(common_hooks, dict) and claude_hook_semantics(common_hooks)[0]
    backups_ok = all(
        isinstance(payload, dict)
        and isinstance(payload.get("hooks"), dict)
        and claude_hook_semantics(payload["hooks"])[0]
        for payload in backup_payloads
    )
    provider_payloads_ok = all(
        isinstance(payload, dict)
        and (
            payload.get("hooks") is None
            or isinstance(payload.get("hooks"), dict)
        )
        for payload in provider_payloads
    )
    provider_hooks = [
        payload.get("hooks")
        for payload in provider_payloads
        if isinstance(payload, dict) and isinstance(payload.get("hooks"), dict)
    ]
    provider_hooks_ok = all(claude_hook_semantics(hooks)[0] for hooks in provider_hooks)
    return expected_ok and common_ok and backups_ok and provider_payloads_ok and provider_hooks_ok, {
        "installed": True,
        "managed_fragment_ok": expected_ok,
        "common_config_ok": common_ok,
        "backup_count": len(backup_payloads),
        "backups_ok": backups_ok,
        "provider_hooks_count": len(provider_hooks),
        "provider_payloads_ok": provider_payloads_ok,
        "provider_hooks_ok": provider_hooks_ok,
    }


def git_remote_has_credential() -> bool:
    result = run(["git", "-C", str(GIT_ROOT), "config", "--get-regexp", r"^remote\..*\.url$"], 15)
    if result["returncode"] not in {0, 1}:
        return False
    for line in str(result.get("stdout", "")).splitlines():
        _, _, url = line.partition(" ")
        if re.search(r"https?://[^/@\s]+:[^/@\s]+@", url) or re.search(r"gh[pousr]_[A-Za-z0-9]{20,}", url):
            return True
    return False


def memory_git_baseline_result(
    dirty_count: int,
    git_ok: bool,
    allow_dirty_memory: bool,
) -> tuple[str, str, dict[str, Any]]:
    if dirty_count and allow_dirty_memory:
        return (
            "pass",
            f"Memory Git baseline has {dirty_count} expected pre-commit dirty files.",
            {"dirty_count": dirty_count, "allowed_precommit": True},
        )
    if dirty_count:
        return (
            "warn",
            f"Memory Git baseline has {dirty_count} dirty files.",
            {"dirty_count": dirty_count, "allowed_precommit": False},
        )
    return (
        "pass" if git_ok else "fail",
        "Memory Git baseline is clean.",
        {"dirty_count": 0, "allowed_precommit": allow_dirty_memory},
    )


def git_remote_backup_health(memory_pathspec: str, now: dt.datetime | None = None) -> tuple[bool, dict[str, Any]]:
    upstream_result = run(
        ["git", "-C", str(GIT_ROOT), "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
        15,
    )
    if not upstream_result["ok"]:
        return False, {"configured": False, "error": "upstream_missing"}
    upstream = str(upstream_result.get("stdout", "")).strip()
    divergence = run(
        ["git", "-C", str(GIT_ROOT), "rev-list", "--left-right", "--count", "@{upstream}...HEAD"],
        30,
    )
    memory_ahead_result = run(
        ["git", "-C", str(GIT_ROOT), "rev-list", "--count", "@{upstream}..HEAD", "--", memory_pathspec],
        30,
    )
    try:
        behind, ahead_total = [int(value) for value in str(divergence.get("stdout", "")).split()]
        ahead_memory = int(str(memory_ahead_result.get("stdout", "")).strip())
    except (TypeError, ValueError):
        return False, {
            "configured": True,
            "upstream": upstream,
            "error": "git_divergence_unreadable",
        }
    oldest_age_days: float | None = None
    if ahead_memory:
        oldest_result = run(
            [
                "git",
                "-C",
                str(GIT_ROOT),
                "log",
                "--reverse",
                "--format=%ct",
                "@{upstream}..HEAD",
                "--",
                memory_pathspec,
            ],
            30,
        )
        timestamps = [line for line in str(oldest_result.get("stdout", "")).splitlines() if line]
        try:
            oldest = dt.datetime.fromtimestamp(int(timestamps[0]), tz=dt.timezone.utc)
        except (IndexError, TypeError, ValueError, OSError):
            return False, {
                "configured": True,
                "upstream": upstream,
                "ahead_total": ahead_total,
                "ahead_memory": ahead_memory,
                "behind": behind,
                "error": "oldest_unpushed_commit_unreadable",
            }
        current = now or dt.datetime.now(dt.timezone.utc)
        oldest_age_days = max(0.0, (current - oldest).total_seconds() / 86400)
    overdue = (
        behind > 0
        or ahead_memory >= REMOTE_BACKUP_MAX_UNPUSHED_COMMITS
        or (oldest_age_days is not None and oldest_age_days >= REMOTE_BACKUP_MAX_AGE_DAYS)
    )
    return not overdue, {
        "configured": True,
        "upstream": upstream,
        "ahead_total": ahead_total,
        "ahead_memory": ahead_memory,
        "behind": behind,
        "oldest_unpushed_age_days": round(oldest_age_days, 2) if oldest_age_days is not None else None,
        "warning_threshold_commits": REMOTE_BACKUP_MAX_UNPUSHED_COMMITS,
        "warning_threshold_days": REMOTE_BACKUP_MAX_AGE_DAYS,
    }


def session_claim_hygiene(
    conn: sqlite3.Connection,
    now: dt.datetime | None = None,
    max_age_hours: int = STALE_CLAIM_HOURS,
) -> tuple[bool, dict[str, Any]]:
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "memory_session_claims" not in tables:
        return False, {"active": 0, "stale": [], "error": "claim_table_missing"}
    rows = conn.execute(
        "SELECT actor, rel_path, updated_at FROM memory_session_claims WHERE status='active' ORDER BY actor, rel_path"
    ).fetchall()
    current = now or dt.datetime.now(dt.timezone.utc)
    stale: list[dict[str, Any]] = []
    for row in rows:
        updated_at = parse_time(str(row["updated_at"]))
        age_hours = (current - updated_at).total_seconds() / 3600 if updated_at else None
        if updated_at is None or age_hours is not None and age_hours >= max_age_hours:
            stale.append(
                {
                    "actor": str(row["actor"]),
                    "rel_path": str(row["rel_path"]),
                    "age_hours": round(max(0.0, age_hours), 1) if age_hours is not None else None,
                    "reason": "expired" if updated_at else "invalid_timestamp",
                }
            )
    return not stale, {"active": len(rows), "stale": stale, "stale_after_hours": max_age_hours}


def writer_protocol_health(conn: sqlite3.Connection) -> tuple[bool, dict[str, Any]]:
    """Verify the current state schema separately from writer wire protocol 2."""

    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    required_columns = {
        "memory_write_intents": {"writer_protocol_version", "fencing_token", "target_key"},
        "memory_write_receipts": {"writer_protocol_version", "fencing_token", "target_key"},
        "memory_session_claims": {"intent_id", "target_key", "fencing_token", "claim_kind"},
        "memory_file_observations": {"intent_id", "fencing_token", "git_commit"},
        "memory_path_fences": {"target_key", "last_fence", "updated_at"},
        "memory_closeout_incidents": {
            "intent_id",
            "reason_code",
            "resolved_at",
            "resolution_intent_id",
            "resolution_git_commit",
        },
        "generated_index_closeout_transactions": {
            "transaction_id",
            "actor",
            "task_sha256",
            "vault_root_sha256",
            "git_head",
            "index_base_sha256",
            "full_vault_inputs_sha256",
            "lease_fences_sha256",
            "capability_sha256",
            "issuer_pid",
            "consumer_pid",
            "status",
            "issued_at_epoch",
            "expires_at_epoch",
            "claimed_at_epoch",
            "consumed_at_epoch",
            "generated_sha256",
            "closeout_git_commit",
            "failure_reason",
            "failure_at_epoch",
            "rollback_evidence_path",
        },
    }
    missing_tables = sorted(set(required_columns) - tables)
    missing_columns: dict[str, list[str]] = {}
    for table, required in required_columns.items():
        if table not in tables:
            continue
        actual = {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}
        missing = sorted(required - actual)
        if missing:
            missing_columns[table] = missing

    meta: dict[str, str] = {}
    if "meta" in tables:
        for row in conn.execute(
            "SELECT key, value FROM meta WHERE key IN "
            "('agent_memory_state_schema_version','agent_memory_writer_protocol_version')"
        ):
            meta[str(row[0])] = str(row[1])
    def safe_int(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    state_schema = safe_int(meta.get("agent_memory_state_schema_version", "0"))
    writer_protocol = safe_int(meta.get("agent_memory_writer_protocol_version", "0"))

    counts = {
        "duplicate_active_targets": 0,
        "active_intents_without_fence": 0,
        "active_intents_not_latest_fence": 0,
        "active_claim_binding_mismatch": 0,
        "terminal_intent_active_claims": 0,
        "unsupported_active_actors": 0,
        "unresolved_closeout_incidents": 0,
        "unresolved_generated_index_transactions": 0,
        "failed_generated_index_transactions": 0,
        "invalid_consumed_generated_index_transactions": 0,
        "invalid_generated_index_failure_evidence": 0,
    }
    schema_ready = not missing_tables and not missing_columns
    if schema_ready:
        counts["duplicate_active_targets"] = int(conn.execute(
            "SELECT COUNT(*) FROM (SELECT target_key FROM memory_session_claims "
            "WHERE status='active' AND target_key<>'' GROUP BY target_key HAVING COUNT(*)>1)"
        ).fetchone()[0])
        counts["active_intents_without_fence"] = int(conn.execute(
            "SELECT COUNT(*) FROM memory_write_intents "
            "WHERE status IN ('pending','approved','bound','validated') "
            "AND (fencing_token<=0 OR writer_protocol_version<>?)",
            (WRITER_PROTOCOL_REQUIRED,),
        ).fetchone()[0])
        counts["active_intents_not_latest_fence"] = int(conn.execute(
            "SELECT COUNT(*) FROM memory_write_intents i "
            "LEFT JOIN memory_path_fences f ON f.target_key=i.target_key "
            "WHERE i.status IN ('pending','approved','bound','validated') "
            "AND (f.last_fence IS NULL OR f.last_fence<>i.fencing_token)"
        ).fetchone()[0])
        counts["active_claim_binding_mismatch"] = int(conn.execute(
            "SELECT COUNT(*) FROM memory_session_claims c "
            "LEFT JOIN memory_write_intents i ON i.intent_id=c.intent_id "
            "WHERE c.status='active' AND c.claim_kind='intent' AND ("
            "i.intent_id IS NULL OR i.actor<>c.actor OR i.session_hash<>c.session_hash OR "
            "i.target_key<>c.target_key OR i.fencing_token<>c.fencing_token)"
        ).fetchone()[0])
        counts["terminal_intent_active_claims"] = int(conn.execute(
            "SELECT COUNT(*) FROM memory_session_claims c JOIN memory_write_intents i "
            "ON i.intent_id=c.intent_id WHERE c.status='active' "
            "AND i.status IN ('completed','failed','cancelled','expired')"
        ).fetchone()[0])
        actor_placeholders = ",".join("?" for _ in SUPPORTED_LEDGER_ACTORS)
        counts["unsupported_active_actors"] = int(conn.execute(
            "SELECT COUNT(*) FROM memory_session_claims "
            f"WHERE status='active' AND actor NOT IN ({actor_placeholders})",
            SUPPORTED_LEDGER_ACTORS,
        ).fetchone()[0]) + int(conn.execute(
            "SELECT COUNT(*) FROM memory_write_intents "
            "WHERE status IN ('pending','approved','bound','validated') "
            f"AND actor NOT IN ({actor_placeholders})",
            SUPPORTED_LEDGER_ACTORS,
        ).fetchone()[0])
        counts["unresolved_closeout_incidents"] = int(conn.execute(
            "SELECT COUNT(*) FROM memory_closeout_incidents WHERE resolved_at IS NULL"
        ).fetchone()[0])
        counts["unresolved_generated_index_transactions"] = int(conn.execute(
            "SELECT COUNT(*) FROM generated_index_closeout_transactions "
            "WHERE status IN ('registered','issued','claimed','generated_bound')"
        ).fetchone()[0])
        counts["failed_generated_index_transactions"] = int(conn.execute(
            "SELECT COUNT(*) FROM generated_index_closeout_transactions "
            "WHERE status='failed'"
        ).fetchone()[0])
        counts["invalid_generated_index_failure_evidence"] = int(conn.execute(
            "SELECT COUNT(*) FROM generated_index_closeout_transactions WHERE "
            "(status='failed' AND (failure_reason='' OR failure_at_epoch IS NULL OR failure_at_epoch<=0)) "
            "OR ((failure_reason='' AND failure_at_epoch IS NOT NULL) "
            "OR (failure_reason<>'' AND (failure_at_epoch IS NULL OR failure_at_epoch<=0)))"
        ).fetchone()[0])
        consumed_rows = conn.execute(
            "SELECT transaction_id, actor, task_sha256, vault_root_sha256, git_head, "
            "index_base_sha256, full_vault_inputs_sha256, lease_fences_sha256, "
            "generated_sha256, closeout_git_commit "
            "FROM generated_index_closeout_transactions WHERE status='consumed'"
        ).fetchall()
        invalid_consumed = 0
        head_result = run(
            ["git", "-C", str(GIT_ROOT), "rev-parse", "HEAD"],
            30,
        )
        current_head = str(head_result.get("stdout", "")).strip().lower() if head_result.get("ok") else ""
        for row in consumed_rows:
            binding = {
                "transaction_id": str(row[0] or ""),
                "actor": str(row[1] or ""),
                "task_sha256": str(row[2] or ""),
                "vault_root_sha256": str(row[3] or ""),
                "git_head": str(row[4] or ""),
                "index_base_sha256": str(row[5] or ""),
                "full_vault_inputs_sha256": str(row[6] or ""),
                "lease_fences_sha256": str(row[7] or ""),
            }
            generated_sha256 = str(row[8] or "").strip().lower()
            commit = str(row[9] or "").strip().lower()
            try:
                verify_generated_index_commit_evidence(
                    GIT_ROOT,
                    VAULT_ROOT,
                    binding,
                    generated_sha256=generated_sha256,
                    closeout_git_commit=commit,
                )
                ancestor = run(
                    [
                        "git",
                        "-C",
                        str(GIT_ROOT),
                        "merge-base",
                        "--is-ancestor",
                        commit,
                        current_head,
                    ],
                    30,
                )
                if not current_head or not ancestor.get("ok"):
                    raise GeneratedIndexCapabilityError(
                        "GENERATED_INDEX_COMMIT_EVIDENCE_INVALID"
                    )
            except (GeneratedIndexCapabilityError, OSError, subprocess.SubprocessError):
                invalid_consumed += 1
        counts["invalid_consumed_generated_index_transactions"] = invalid_consumed
    config = load_config().get("write_gateway", {})
    config = config if isinstance(config, dict) else {}
    config_protocol = safe_int(config.get("writer_protocol_version", 0))
    config_state = safe_int(config.get("state_schema_required", 0))
    config_actors = tuple(str(value) for value in config.get("canonical_actors", ()))
    config_ok = (
        config_protocol == WRITER_PROTOCOL_REQUIRED
        and config_state == STATE_SCHEMA_REQUIRED
        and config_actors == CANONICAL_WRITER_ACTORS
    )
    ok = (
        schema_ready
        and state_schema == STATE_SCHEMA_REQUIRED
        and writer_protocol == WRITER_PROTOCOL_REQUIRED
        and config_ok
        and not any(counts.values())
    )
    return ok, {
        "state_schema": state_schema,
        "state_schema_required": STATE_SCHEMA_REQUIRED,
        "writer_protocol": writer_protocol,
        "writer_protocol_required": WRITER_PROTOCOL_REQUIRED,
        "canonical_writer_actors": list(CANONICAL_WRITER_ACTORS),
        "missing_tables": missing_tables,
        "missing_columns": missing_columns,
        "config_protocol_ok": config_ok,
        **counts,
    }


def observability_event_hygiene(conn: sqlite3.Connection) -> dict[str, int]:
    """Count invalid opaque references without returning their raw values."""

    counts = {
        "invalid_task_refs": 0,
        "invalid_task_classes": 0,
        "invalid_memory_id_payloads": 0,
        "invalid_memory_refs": 0,
    }
    columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(memory_use_events)")
    }
    cursor = conn.execute(
        "SELECT task_id, task_class, memory_ids_json FROM memory_use_events"
    )
    for task_id, task_class, memory_ids_json in cursor:
        if not SHA256_PATTERN.fullmatch(str(task_id or "")):
            counts["invalid_task_refs"] += 1
        if str(task_class or "") not in OBSERVABILITY_TASK_CLASSES:
            counts["invalid_task_classes"] += 1
        try:
            memory_ids = json.loads(str(memory_ids_json))
        except (TypeError, ValueError, json.JSONDecodeError):
            counts["invalid_memory_id_payloads"] += 1
            continue
        if not isinstance(memory_ids, list):
            counts["invalid_memory_id_payloads"] += 1
            continue
        counts["invalid_memory_refs"] += sum(
            1
            for memory_id in memory_ids
            if not isinstance(memory_id, str) or not SHA256_PATTERN.fullmatch(memory_id)
        )
    full_columns = {
        "event_id", "actor", "task_id", "runtime_version", "event_type", "source",
        "memory_ids_json", "memory_versions_json", "content_sha256", "value",
        "reason_code", "confidence", "labeler_ref_sha256", "labeler_ref_length",
        "read_mode", "result_count", "required_live_verification_count",
        "requires_live_verification", "full_utf8_bytes", "returned_utf8_bytes",
        "truncated", "page_count", "task_class", "created_at",
    }
    if not full_columns.issubset(columns):
        return counts

    counts.update({
        "invalid_event_ids": 0,
        "invalid_actors": 0,
        "invalid_runtime_versions": 0,
        "invalid_event_enums": 0,
        "invalid_reason_or_confidence": 0,
        "invalid_memory_version_payloads": 0,
        "invalid_content_hashes": 0,
        "invalid_labeler_refs": 0,
        "invalid_count_fields": 0,
        "invalid_timestamps": 0,
    })
    select_columns = sorted(full_columns)
    cursor = conn.execute(
        f"SELECT {', '.join(select_columns)} FROM memory_use_events"
    )
    for raw_row in cursor:
        row = dict(zip(select_columns, raw_row))
        event_id = str(row["event_id"] or "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{7,159}", event_id):
            counts["invalid_event_ids"] += 1
        if str(row["actor"] or "") not in {"codex", "claude", "ailu", "human", "migration", "test"}:
            counts["invalid_actors"] += 1
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,159}", str(row["runtime_version"] or "")):
            counts["invalid_runtime_versions"] += 1

        event_type = str(row["event_type"] or "")
        source = str(row["source"] or "")
        value = str(row["value"] or "")
        if (
            event_type not in agent_memory_observability.EVENT_VALUES
            or source not in agent_memory_observability.EVENT_SOURCES.get(event_type, set())
            or value not in agent_memory_observability.EVENT_VALUES.get(event_type, set())
            or str(row["read_mode"] or "") not in agent_memory_observability.READ_MODES
        ):
            counts["invalid_event_enums"] += 1
        if (
            str(row["reason_code"] or "") not in agent_memory_observability.REASON_CODES
            or str(row["confidence"] or "") not in agent_memory_observability.CONFIDENCE_VALUES
        ):
            counts["invalid_reason_or_confidence"] += 1

        content_hash = str(row["content_sha256"] or "")
        if content_hash and not SHA256_PATTERN.fullmatch(content_hash):
            counts["invalid_content_hashes"] += 1
        labeler_hash = str(row["labeler_ref_sha256"] or "")
        if labeler_hash and not SHA256_PATTERN.fullmatch(labeler_hash):
            counts["invalid_labeler_refs"] += 1
        try:
            labeler_length = int(row["labeler_ref_length"] or 0)
        except (TypeError, ValueError):
            labeler_length = -1
        if labeler_length < 0 or (labeler_length > 0 and not labeler_hash):
            counts["invalid_labeler_refs"] += 1

        try:
            versions = json.loads(str(row["memory_versions_json"] or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            versions = None
        versions_valid = isinstance(versions, list)
        version_requires = False
        if versions_valid:
            for item in versions:
                if not isinstance(item, dict) or set(item) != {
                    "memory_id", "content_sha256", "policy_state", "requires_live_verification"
                }:
                    versions_valid = False
                    break
                version_memory_id = str(item.get("memory_id", ""))
                version_content = str(item.get("content_sha256", ""))
                version_state = str(item.get("policy_state", ""))
                version_requires_raw = item.get("requires_live_verification")
                if (
                    not SHA256_PATTERN.fullmatch(version_memory_id)
                    or (version_content and not SHA256_PATTERN.fullmatch(version_content))
                    or version_state not in agent_memory_observability.MEMORY_VERSION_STATES
                    or not isinstance(version_requires_raw, bool)
                ):
                    versions_valid = False
                    break
                version_requires = version_requires or version_requires_raw
        if not versions_valid:
            counts["invalid_memory_version_payloads"] += 1
        try:
            requires_value = int(row["requires_live_verification"])
        except (TypeError, ValueError):
            requires_value = -1
        if requires_value not in {0, 1} or (versions_valid and bool(requires_value) != version_requires):
            counts["invalid_memory_version_payloads"] += 1

        for key in (
            "result_count", "required_live_verification_count", "full_utf8_bytes",
            "returned_utf8_bytes", "page_count",
        ):
            value_raw = row[key]
            if value_raw is None:
                continue
            try:
                numeric = int(value_raw)
            except (TypeError, ValueError):
                numeric = -1
            if numeric < 0:
                counts["invalid_count_fields"] += 1
        if row["truncated"] is not None:
            try:
                truncated = int(row["truncated"])
            except (TypeError, ValueError):
                truncated = -1
            if truncated not in {0, 1}:
                counts["invalid_count_fields"] += 1
        if parse_time(str(row["created_at"] or "")) is None:
            counts["invalid_timestamps"] += 1
    return counts


def search_observability_hygiene(conn: sqlite3.Connection) -> dict[str, int]:
    """Validate privacy-bounded search rows without exposing stored values."""

    columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(memory_search_log)")
    }
    required = {
        "query", "used_paths", "query_sha256", "returned_memory_ids_json",
        "task_id", "actor", "event_source", "ranking_mode", "worker_status",
        "worker_restart_count", "v1_result_fingerprint", "v2_result_fingerprint",
    }
    counts = {
        "raw_query_rows": 0,
        "raw_path_rows": 0,
        "invalid_query_hashes": 0,
        "invalid_task_refs": 0,
        "invalid_returned_memory_ids": 0,
        "invalid_controlled_fields": 0,
    }
    if not required.issubset(columns):
        counts["missing_privacy_columns"] = len(required - columns)
        return counts
    selected = sorted(required)
    cursor = conn.execute(f"SELECT {', '.join(selected)} FROM memory_search_log")
    for raw_row in cursor:
        row = dict(zip(selected, raw_row))
        query = str(row["query"] or "")
        if query and re.fullmatch(r"\[redacted:[0-9a-f]{12}\]", query) is None:
            counts["raw_query_rows"] += 1
        if str(row["used_paths"] or "").strip():
            counts["raw_path_rows"] += 1
        query_hash = str(row["query_sha256"] or "")
        if query_hash and not SHA256_PATTERN.fullmatch(query_hash):
            counts["invalid_query_hashes"] += 1
        task_id = str(row["task_id"] or "")
        if task_id and not SHA256_PATTERN.fullmatch(task_id):
            counts["invalid_task_refs"] += 1
        try:
            memory_ids = json.loads(str(row["returned_memory_ids_json"] or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            memory_ids = None
        if not isinstance(memory_ids, list) or any(
            not isinstance(item, str) or not SHA256_PATTERN.fullmatch(item)
            for item in (memory_ids if isinstance(memory_ids, list) else [])
        ):
            counts["invalid_returned_memory_ids"] += 1
        if (
            str(row["actor"] or "") not in {"codex", "claude", "ailu", "human", "migration", "test", ""}
            or str(row["event_source"] or "") not in {"tool_observed", ""}
            or str(row["ranking_mode"] or "") not in agent_memory_observability.RANKING_MODES
            or str(row["worker_status"] or "") not in agent_memory_observability.WORKER_STATUSES
        ):
            counts["invalid_controlled_fields"] += 1
        for key in ("v1_result_fingerprint", "v2_result_fingerprint"):
            fingerprint = str(row[key] or "")
            if fingerprint and not SHA256_PATTERN.fullmatch(fingerprint):
                counts["invalid_controlled_fields"] += 1
        try:
            restarts = int(row["worker_restart_count"] or 0)
        except (TypeError, ValueError):
            restarts = -1
        if restarts < 0:
            counts["invalid_controlled_fields"] += 1
    return counts


def fts_exact_parity_health(
    conn: sqlite3.Connection,
    actual_by_path: dict[str, Path],
    db_by_path: dict[str, sqlite3.Row],
) -> tuple[bool, dict[str, Any]]:
    """Compare every lexical row to the Markdown-derived expected projection."""

    tables = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")
    }
    expected: dict[str, tuple[str, ...]] = {}
    expected_errors: list[str] = []
    for raw_path, path in actual_by_path.items():
        try:
            doc, _open_loops = memory_index.load_doc(path, "doctor-read-only")
        except (OSError, UnicodeError, ValueError):
            expected_errors.append(path.relative_to(VAULT_ROOT).as_posix())
            continue
        expected[raw_path] = (
            raw_path,
            doc.title,
            doc.rel_path,
            doc.summary,
            doc.keywords,
            doc.headings,
            doc.search_text,
        )

    def rel_path(raw_path: str) -> str:
        row = db_by_path.get(raw_path)
        return str(row["rel_path"]) if row is not None else raw_path

    coverage: dict[str, dict[str, Any]] = {}
    table_digests: dict[str, str] = {}
    for table in ("memory_fts", "memory_fts_unicode", "memory_fts_trigram"):
        if table not in tables:
            coverage[table] = {
                "missing_table": True,
                "row_count": 0,
                "missing": sorted(rel_path(path) for path in db_by_path),
                "stale": [],
                "duplicates": [],
                "content_hash_mismatch": [],
            }
            continue
        raw_rows = [
            tuple(str(value or "") for value in row)
            for row in conn.execute(
                f"SELECT path,title,rel_path,summary,keywords,headings,search_text FROM {table} ORDER BY path"
            )
        ]
        rows_by_path: dict[str, list[tuple[str, ...]]] = {}
        for row in raw_rows:
            rows_by_path.setdefault(row[0], []).append(row)
        duplicates = sorted(
            rel_path(path) for path, rows in rows_by_path.items() if len(rows) != 1
        )
        unique_rows = {
            path: rows[0] for path, rows in rows_by_path.items() if len(rows) == 1
        }
        mismatched = sorted(
            rel_path(path)
            for path in set(unique_rows) & set(expected)
            if unique_rows[path] != expected[path]
        )
        digest = hashlib.sha256(
            json.dumps(raw_rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        table_digests[table] = digest
        coverage[table] = {
            "missing_table": False,
            "row_count": len(raw_rows),
            "covered": len(set(unique_rows) & set(expected)),
            "missing": sorted(rel_path(path) for path in set(expected) - set(unique_rows)),
            "stale": sorted(rel_path(path) for path in set(unique_rows) - set(expected)),
            "duplicates": duplicates,
            "content_hash_mismatch": mismatched,
            "projection_sha256": digest,
        }
    digest_match = len(set(table_digests.values())) <= 1 and len(table_digests) == 3
    ok = (
        not expected_errors
        and digest_match
        and all(
            not detail.get("missing_table")
            and not detail.get("missing")
            and not detail.get("stale")
            and not detail.get("duplicates")
            and not detail.get("content_hash_mismatch")
            for detail in coverage.values()
        )
    )
    return ok, {
        "expected_docs": len(expected),
        "expected_projection_errors": expected_errors,
        "table_projection_digests_match": digest_match,
        "tables": coverage,
    }


def generated_index_health(
    conn: sqlite3.Connection,
    actual_rel: set[str],
) -> tuple[bool, dict[str, Any]]:
    """Require exact generated bytes and one non-self reference per document."""

    index_path = VAULT_ROOT / "INDEX.md"
    if index_path.is_symlink() or not index_path.is_file():
        return False, {
            "missing": sorted(actual_rel - {"INDEX.md"}),
            "broken": [],
            "duplicates": [],
            "self_references": 0,
            "generated_marker": False,
            "generated_exact": False,
            "index_self_excluded": True,
        }
    text = index_path.read_text(encoding="utf-8", errors="replace")
    marker = text.startswith(memory_index.GENERATED_INDEX_MARKER + "\n")
    references = (
        memory_index.generated_index_navigation_references(text)
        if marker
        else re.findall(r"`([^`\r\n]+\.md)`", text)
    )
    counts: dict[str, int] = {}
    for reference in references:
        counts[reference] = counts.get(reference, 0) + 1
    reference_set = set(references)
    governed_rel = actual_rel - {"INDEX.md"}
    missing = sorted(governed_rel - reference_set)
    broken = sorted(reference_set - governed_rel - {"INDEX.md"})
    duplicates = sorted(path for path, count in counts.items() if count != 1 and path != "INDEX.md")
    self_references = counts.get("INDEX.md", 0)
    try:
        expected = memory_index.generated_index_markdown(conn)
        generated_exact = text == expected
    except (sqlite3.Error, ValueError, TypeError):
        generated_exact = False
    ok = bool(
        marker
        and generated_exact
        and not missing
        and not broken
        and not duplicates
        and self_references == 0
    )
    return ok, {
        "listed": len(reference_set - {"INDEX.md"}),
        "governed": len(governed_rel),
        "missing": missing,
        "broken": broken,
        "duplicates": duplicates,
        "self_references": self_references,
        "generated_marker": marker,
        "generated_exact": generated_exact,
        "index_self_excluded": True,
    }


def audit_schema_doctor_check() -> dict[str, Any]:
    """Verify the audit ledger schema through the migrator's read-only gate."""

    try:
        report = agent_memory_migrate.verify_audit()
    except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
        report = {
            "ok": False,
            "status": "migration_required",
            "reason_code": getattr(
                exc,
                "reason_code",
                "AUDIT_SCHEMA_MIGRATION_REQUIRED",
            ),
            "error_type": type(exc).__name__,
        }
    ok = report.get("ok") is True and report.get("status") == "verified"
    safe_keys = {
        "audit_db", "exists", "audit_schema_version", "audit_schema_required",
        "missing_tables", "missing_columns", "status", "stage", "quick_check",
        "reason_code", "error_type",
    }
    detail = {key: value for key, value in report.items() if key in safe_keys}
    return {
        "name": "audit_schema",
        "status": "pass" if ok else "fail",
        "message": (
            "Audit decision ledger schema is current and passed quick_check."
            if ok
            else "Audit decision ledger is missing, stale, unsafe, or requires installer migration."
        ),
        "detail": detail,
    }


def state_schema_doctor_check(conn: sqlite3.Connection) -> dict[str, Any]:
    """Run the migrator's read-only schema verifier before v4-only queries."""

    try:
        verification = agent_memory_migrate.verify(conn)
        report = verification.get("report") if isinstance(verification.get("report"), dict) else {}
        migration_required = (
            verification.get("reason_code") == "STATE_SCHEMA_MIGRATION_REQUIRED"
            or int(report.get("state_schema_version", 0) or 0) != STATE_SCHEMA_REQUIRED
        )
        safe_detail = {
            "reason_code": "STATE_SCHEMA_MIGRATION_REQUIRED" if migration_required else "",
            "state_schema": int(report.get("state_schema_version", 0) or 0),
            "state_schema_required": STATE_SCHEMA_REQUIRED,
            "missing_claim_columns": list(report.get("missing_claim_columns", [])),
            "missing_intent_columns": list(report.get("missing_intent_columns", [])),
            "missing_receipt_columns": list(report.get("missing_receipt_columns", [])),
            "missing_observation_columns": list(report.get("missing_observation_columns", [])),
            "missing_incident_columns": list(report.get("missing_incident_columns", [])),
            "missing_observability_columns": list(report.get("missing_observability_columns", [])),
            "missing_privacy_guards": list(report.get("missing_privacy_guards", [])),
            "quick_check": str(verification.get("quick_check", "")),
        }
    except (OSError, sqlite3.Error, ValueError, TypeError, KeyError) as exc:
        migration_required = True
        safe_detail = {
            "reason_code": "STATE_SCHEMA_MIGRATION_REQUIRED",
            "state_schema": 0,
            "state_schema_required": STATE_SCHEMA_REQUIRED,
            "error_type": type(exc).__name__,
        }
    return {
        "name": "state_schema",
        "status": "fail" if migration_required else "pass",
        "message": (
            "State schema is current and safe for Doctor v4 queries."
            if not migration_required
            else "State schema requires an installer-managed migration before Doctor can continue."
        ),
        "detail": safe_detail,
    }


def action_sensitive_atomic_coverage(
    docs: list[sqlite3.Row] | list[dict[str, Any]],
    *,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Return full tuple/evidence coverage for active action-sensitive facts."""

    action_sensitive: list[str] = []
    uncovered: list[str] = []
    gap_details: list[dict[str, Any]] = []

    def value(row: sqlite3.Row | dict[str, Any], key: str) -> object:
        if isinstance(row, dict):
            return row.get(key, "")
        return row[key] if key in row.keys() else ""

    for row in docs:
        status = str(value(row, "status") or "").casefold()
        memory_type = str(value(row, "memory_type") or "").casefold()
        temporal_policy = str(value(row, "temporal_policy") or "").casefold()
        fact_key = str(value(row, "fact_key") or "").strip()
        valid_from = str(value(row, "valid_from") or "").strip()
        valid_until = str(value(row, "valid_until") or "").strip()
        rel_path = str(value(row, "rel_path"))
        supporting = memory_type in {
            "routing", "directory_index", "template", "governance",
        }
        explicitly_action_sensitive = not supporting and (
            bool(
                status == "active"
                and str(value(row, "risk_class") or "").casefold()
                == "action_sensitive"
            )
            or memory_index.is_explicitly_action_sensitive(
                status=status,
                memory_type=memory_type,
                temporal_policy=temporal_policy,
                fact_key=fact_key,
                valid_from=valid_from,
                valid_until=valid_until,
                rel_path=rel_path,
            )
        )
        if not explicitly_action_sensitive:
            continue
        action_sensitive.append(rel_path)
        raw_sha256 = ""
        raw_path = str(value(row, "path") or "")
        if raw_path:
            try:
                raw_sha256 = hashlib.sha256(Path(raw_path).read_bytes()).hexdigest()
            except OSError:
                raw_sha256 = ""
        evidence = _durable_fact_evidence_provenance(
            conn,
            rel_path=rel_path,
            raw_sha256=raw_sha256,
        )
        gaps = _action_sensitive_atomic_gap_fields(
            temporal_policy=temporal_policy,
            fact_key=fact_key,
            valid_from=valid_from,
            valid_until=valid_until,
            verified_at=value(row, "verified_at"),
            verified_at_source=value(row, "verified_at_source"),
            evidence_present=bool(evidence["present"]),
        )
        if gaps:
            uncovered.append(rel_path)
            gap_details.append({
                "rel_path": rel_path,
                "missing_or_invalid": gaps,
                "evidence_provenance": evidence,
            })
    return {
        "action_sensitive_documents": sorted(action_sensitive),
        "uncovered": sorted(uncovered),
        "gap_details": sorted(gap_details, key=lambda item: str(item["rel_path"])),
        "structural_and_routing_excluded": True,
        "coverage_is_per_document": True,
        "coverage_requires": [
            "non_structural_temporal_policy",
            "fact_key",
            "valid_from",
            "frontmatter_verified_at",
            "current_content_write_gateway_evidence",
        ],
    }


def eligible_vector(row: sqlite3.Row) -> bool:
    path = Path(str(row["path"]))
    return (
        path.exists()
        and path.suffix.lower() == ".md"
        and path.name != "README.md"
        and not path.name.startswith("_模板")
        and str(row["memory_type"]) not in EXCLUDED_VECTOR_TYPES
        and str(row["status"]) not in EXCLUDED_VECTOR_STATUS
        and str(row["sensitivity"] or "").lower() not in {"secret", "credential"}
    )


def shadow_lifecycle_doctor_check() -> dict[str, Any]:
    """Expose a lost version-bound rollout without disabling ordinary reads."""
    ranking = str(SEMANTIC_CONFIG.get("ranking_version", "hybrid-v1"))
    if ranking != "hybrid-v2-shadow":
        return {"name": "shadow_lifecycle", "status": "pass",
                "message": "No pending shadow rollout is configured.",
                "detail": {"ranking_version": ranking}}
    try:
        import agent_memory_shadow
        report = agent_memory_shadow.shadow_status()
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        return {"name": "shadow_lifecycle", "status": "fail",
                "message": "The configured shadow rollout could not be verified.",
                "detail": {"reason_code": "SHADOW_STATUS_UNAVAILABLE", "error_type": type(exc).__name__}}
    pending = {"SHADOW_NOT_STARTED", "SHADOW_MINIMUM_DURATION_NOT_MET",
               "SHADOW_BENCHMARK_ATTESTATION_MISSING", "SHADOW_STALE_CANARY_ATTESTATION_MISSING",
               "SHADOW_REAL_RETRIEVAL_DENOMINATOR_MISSING"}
    failures = list(report.get("gate_failures", []))
    state = str(report.get("status", "invalid"))
    severity = "pass" if report.get("ok") else "warn"
    if state == "invalid" or any(reason not in pending for reason in failures):
        severity = "fail"
    message = ("Shadow gate passed; an explicit cutover is still required."
               if report.get("ok") else "Shadow rollout is observing the current Runtime.")
    if state == "not_started":
        message = "Current Runtime has no shadow start; earlier-version evidence does not cover this installation."
    detail = {key: report[key] for key in (
        "status", "gate_failures", "manifest_sha256", "runtime_installed_at",
        "shadow_started_at", "minimum_days", "elapsed_days",
    ) if key in report}
    detail["production_acceptance_complete"] = False
    detail["next_action"] = "shadow start" if state == "not_started" else "shadow status"
    return {"name": "shadow_lifecycle", "status": severity, "message": message, "detail": detail}


def repair_derived() -> list[dict[str, Any]]:
    actions = []
    index_result = run([str(PYTHON), str(SCRIPT_ROOT / "agent_memory_index.py"), "--init", "--scan", "--report"], 180)
    actions.append({"action": "rebuild_sqlite_fts", "ok": index_result["ok"], "detail": index_result["detail"]})
    if index_result["ok"] and SEMANTIC_ENABLED:
        vector_result = run(
            [str(ZVEC_PYTHON), str(SCRIPT_ROOT / "agent_memory_zvec_index.py"), "--scan", "--prune", "--json"],
            900,
            offline_env() if REQUIRE_LOCAL_MODEL else None,
        )
        actions.append({"action": "rebuild_zvec", "ok": vector_result["ok"], "detail": vector_result["detail"]})
    return actions


def collect_checks(
    allow_dirty_memory: bool = False,
    *,
    allow_content_migration_bootstrap: bool = False,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    missing = [name for name in REQUIRED_RUNTIME_FILES if not (SCRIPT_ROOT / name).is_file()]
    add(checks, "runtime_files", "fail" if missing else "pass", "Runtime files complete." if not missing else "Runtime files missing.", {"missing": missing})
    checks.append(audit_schema_doctor_check())
    if os.name == "nt":
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        add(
            checks,
            "windows_powershell",
            "pass" if powershell else "fail",
            "PowerShell is available." if powershell else "PowerShell was not found.",
        )
        hooks_path = configured_path("codex_hooks_json") or (Path.home() / ".codex" / "hooks.json")
        hooks_unsafe = hooks_path.is_symlink() or (hooks_path.exists() and not hooks_path.is_file())
        hooks_valid = False
        hooks_root: dict[str, Any] = {}
        if hooks_path.is_file() and not hooks_path.is_symlink():
            try:
                parsed_hooks = json.loads(hooks_path.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                parsed_hooks = None
            hooks_valid = isinstance(parsed_hooks, dict)
            hooks_root = parsed_hooks if isinstance(parsed_hooks, dict) else {}
        hooks_payload = hooks_root.get("hooks") if isinstance(hooks_root.get("hooks"), dict) else {}
        hook_detail = classify_hook_event(
            hooks_payload,
            "Stop",
            runtime_python=PYTHON,
            runtime_root=REPO_ROOT,
            spec=codex_stop_hook_spec(),
        )
        managed_count = sum(
            int(hook_detail[name])
            for name in ("canonical_count", "legacy_count", "ambiguous_count")
        )
        feature_ok, feature_detail = codex_hooks_feature_enabled(
            hooks_path.parent / "config.toml"
        )
        hook_ok = bool(
            hook_detail["healthy"]
            and hooks_valid
            and not hooks_unsafe
            and feature_ok
        )
        if hook_ok:
            hook_status = "pass"
            hook_message = "Codex Stop Hook is configured."
            reason_code = ""
        elif hooks_unsafe or (hooks_path.exists() and not hooks_valid) or managed_count:
            hook_status = "warn" if allow_content_migration_bootstrap else "fail"
            hook_message = "Codex Stop Hook is present but invalid."
            reason_code = (
                "CODEX_HOOKS_UNSAFE"
                if hooks_unsafe
                else ("CODEX_HOOKS_INVALID_JSON" if not hooks_valid else "CODEX_HOOKS_INVALID")
            )
        else:
            # Host automation is optional unless publish-ready was explicitly
            # invoked with --require-host-hook codex.
            hook_status = "warn"
            hook_message = "Codex Stop Hook is not installed."
            reason_code = "CODEX_HOOKS_MISSING"
        add(
            checks,
            "codex_stop_hook",
            hook_status,
            hook_message,
            {
                "path": str(hooks_path),
                "reason_code": reason_code,
                "json_valid": hooks_valid,
                "unsafe": hooks_unsafe,
                **feature_detail,
                **hook_detail,
            },
        )
    if REPO_ROOT.resolve() == CONFIG_ROOT.resolve():
        checks.append(install_orchestration_doctor_check())
        transaction_detail = runtime_installer.runtime_transaction_health(
            CONFIG_ROOT
        )
        add(
            checks,
            "runtime_transactions",
            "pass" if transaction_detail["healthy"] else "fail",
            (
                "All Runtime installation transactions are terminal."
                if transaction_detail["healthy"]
                else "A Runtime installation transaction is pending, invalid, or requires recovery."
            ),
            transaction_detail,
        )
        manifest = read_json_object(RUNTIME_MANIFEST)
        expected = manifest.get("files") if isinstance(manifest, dict) else None
        manifest_missing: list[str] = []
        manifest_mismatch: list[str] = []
        support_missing: list[str] = []
        support_mismatch: list[str] = []
        template_missing: list[str] = []
        template_mismatch: list[str] = []
        if isinstance(expected, dict):
            for name, digest in expected.items():
                path = SCRIPT_ROOT / str(name)
                if not path.is_file():
                    manifest_missing.append(str(name))
                elif file_sha256(path) != str(digest):
                    manifest_mismatch.append(str(name))
        support_expected = manifest.get("support_files", {}) if isinstance(manifest, dict) else {}
        if isinstance(support_expected, dict):
            for name, digest in support_expected.items():
                path = CONFIG_ROOT / str(name)
                if not path.is_file():
                    support_missing.append(str(name))
                elif file_sha256(path) != str(digest):
                    support_mismatch.append(str(name))
        template_expected = manifest.get("template_files", {}) if isinstance(manifest, dict) else {}
        if isinstance(template_expected, dict):
            for name, digest in template_expected.items():
                path = CONFIG_ROOT / str(name)
                if not path.is_file():
                    template_missing.append(str(name))
                elif file_sha256(path) != str(digest):
                    template_mismatch.append(str(name))
        manifest_ok = (
            isinstance(expected, dict)
            and manifest.get("schema_version") == 2
            and manifest.get("runtime_api_version") == 2
            and manifest.get("writer_protocol_version") == WRITER_PROTOCOL_REQUIRED
            and manifest.get("state_schema_required") == STATE_SCHEMA_REQUIRED
            and manifest.get("canonical_actors") == list(CANONICAL_WRITER_ACTORS)
            and not manifest_missing
            and not manifest_mismatch
            and not support_missing
            and not support_mismatch
            and not template_missing
            and not template_mismatch
        )
        add(
            checks,
            "runtime_manifest",
            "pass" if manifest_ok else "fail",
            "Installed runtime matches its manifest." if manifest_ok else "Installed runtime drifted from its manifest.",
            {
                "source_commit": manifest.get("source_commit", "") if manifest else "",
                "source_dirty": bool(manifest.get("source_dirty")) if manifest else False,
                "missing": manifest_missing,
                "mismatched": manifest_mismatch,
                "support_missing": support_missing,
                "support_mismatched": support_mismatch,
                "template_missing": template_missing,
                "template_mismatched": template_mismatch,
            },
        )
    if not STATE_DB.exists() and not STATE_DB.is_symlink():
        add(checks, "state_db", "fail", "State database is missing.", {"path": str(STATE_DB)})
        return checks
    permission_detail = sqlite_permission_report(STATE_DB)
    add(
        checks,
        "state_db_permissions",
        "pass" if permission_detail["ok"] else "fail",
        (
            "State database and SQLite sidecars are private (0600)."
            if permission_detail["ok"]
            else "State database or SQLite sidecar permissions are unsafe."
        ),
        permission_detail,
    )
    unsafe_path_issue = any(
        item.get("reason") in {"missing", "symlink", "not_regular"}
        for item in permission_detail["issues"]
    )
    if unsafe_path_issue:
        return checks
    conn = secure_sqlite_connect(
        STATE_DB,
        create=False,
        read_only=True,
        repair_permissions=False,
        row_factory=sqlite3.Row,
        pragmas=("PRAGMA busy_timeout=10000",),
    )
    quick = str(conn.execute("PRAGMA quick_check").fetchone()[0])
    add(checks, "sqlite_integrity", "pass" if quick == "ok" else "fail", f"SQLite quick_check={quick}.")
    state_schema_check = state_schema_doctor_check(conn)
    checks.append(state_schema_check)
    if state_schema_check["status"] == "fail":
        conn.close()
        return checks
    actual = sorted(VAULT_ROOT.rglob("*.md"))
    actual_by_path = {str(path.resolve()): path for path in actual}
    actual_rel = {path.relative_to(VAULT_ROOT).as_posix() for path in actual}
    docs = conn.execute(
        "SELECT path, rel_path, sha256, memory_type, status, sensitivity, "
        "risk_class, verified_at, verified_at_source, line_count, size_bytes, "
        "fact_key, temporal_policy, valid_from, valid_until, track FROM memory_docs"
    ).fetchall()
    db_by_path = {str(row["path"]): row for row in docs}
    missing_db = sorted(path.relative_to(VAULT_ROOT).as_posix() for raw, path in actual_by_path.items() if raw not in db_by_path)
    stale_db = sorted(str(row["rel_path"]) for raw, row in db_by_path.items() if raw not in actual_by_path)
    mismatch = sorted(str(row["rel_path"]) for raw, row in db_by_path.items() if raw in actual_by_path and file_sha256(actual_by_path[raw]) != str(row["sha256"]))
    add(checks, "markdown_sqlite_parity", "pass" if not (missing_db or stale_db or mismatch) else "fail", f"Markdown={len(actual)}, SQLite={len(docs)}.", {"missing": missing_db, "stale": stale_db, "hash_mismatch": mismatch})
    fts_ok, fts_detail = fts_exact_parity_health(conn, actual_by_path, db_by_path)
    add(
        checks,
        "sqlite_fts_parity",
        "pass" if fts_ok else "fail",
        (
            f"Legacy, Unicode, and trigram FTS each cover {len(docs)} docs."
            if fts_ok
            else "Legacy, Unicode, or trigram FTS coverage is missing or stale."
        ),
        fts_detail,
    )
    index_ok, index_detail = generated_index_health(conn, actual_rel)
    add(
        checks,
        "index_navigation_parity",
        "pass" if index_ok else "fail",
        (
            f"Generated INDEX.md lists {index_detail['listed']}/{index_detail['governed']} governed docs."
            if index_ok
            else "Generated INDEX.md is stale, edited, self-referential, missing entries, or contains broken entries."
        ),
        index_detail,
    )
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    temporal_tables = {"memory_supersessions", "memory_fact_states"}
    if temporal_tables.issubset(tables):
        fact_paths = {
            str(row[0])
            for row in conn.execute(
                "SELECT rel_path FROM memory_docs WHERE trim(fact_key)<>'' "
                "AND memory_type NOT IN ('template','directory_index','routing')"
            )
        }
        state_paths = {
            str(row[0]) for row in conn.execute("SELECT rel_path FROM memory_fact_states")
        }
        missing_fact_states = sorted(fact_paths - state_paths)
        stale_fact_states = sorted(state_paths - fact_paths)
        invalid_relations = int(
            conn.execute(
                "SELECT COUNT(*) FROM memory_supersessions WHERE relation_status<>'effective'"
            ).fetchone()[0]
        )
        unresolved = [
            {
                "rel_path": str(row["rel_path"]),
                "fact_status": str(row["fact_status"]),
                "reason_code": str(row["reason_code"] or ""),
            }
            for row in conn.execute(
                """
                SELECT rel_path, fact_status, reason_code
                FROM memory_fact_states
                WHERE fact_status IN ('conflict','invalid_metadata','invalid_relation','no_current')
                ORDER BY rel_path
                """
            )
        ]
        temporal_ok = bool(
            not missing_fact_states
            and not stale_fact_states
            and invalid_relations == 0
            and not unresolved
        )
        add(
            checks,
            "temporal_fact_graph",
            "pass" if temporal_ok else "fail",
            (
                f"Temporal fact graph resolves {len(state_paths & fact_paths)}/{len(fact_paths)} fact records without ambiguity."
                if temporal_ok
                else "Temporal fact graph has missing, invalid, or ambiguous current-fact state."
            ),
            {
                "fact_docs": len(fact_paths),
                "fact_states": len(state_paths),
                "missing_fact_states": missing_fact_states,
                "stale_fact_states": stale_fact_states,
                "invalid_relations": invalid_relations,
                "unresolved": unresolved,
            },
        )
        coverage = action_sensitive_atomic_coverage(docs, conn=conn)
        uncovered_action_docs = list(coverage["uncovered"])
        add(
            checks,
            "temporal_fact_coverage",
            "pass" if not uncovered_action_docs else "fail",
            (
                "Every active action-sensitive document has a complete atomic fact tuple and durable evidence provenance."
                if not uncovered_action_docs
                else f"{len(uncovered_action_docs)} active action-sensitive document(s) lack a complete atomic fact tuple or durable evidence provenance."
            ),
            {
                **coverage,
                "fact_records": len(fact_paths),
                "migration_is_explicit_only": True,
            },
        )
    else:
        add(
            checks,
            "temporal_fact_graph",
            "fail",
            "Temporal fact projection tables are missing.",
            {"missing_tables": sorted(temporal_tables - tables)},
        )
    if {"memory_vector_chunks", "memory_vector_index_state"}.issubset(tables):
        noncurrent_fact_paths = {
            str(row[0])
            for row in conn.execute(
                "SELECT d.path FROM memory_docs d JOIN memory_fact_states f ON f.rel_path=d.rel_path "
                "WHERE f.fact_status<>'current'"
            )
        }
        eligible = {
            str(row["path"]): {"rel_path": str(row["rel_path"]), "sha256": str(row["sha256"])}
            for row in docs
            if eligible_vector(row) and str(row["path"]) not in noncurrent_fact_paths
        }
        states = conn.execute(
            "SELECT path, rel_path, doc_sha256, status, last_error FROM memory_vector_index_state"
        ).fetchall()
        if not states:
            add(checks, "zvec_parity", "warn", "Optional vector index is not initialized.")
        else:
            indexed = {str(row["path"]) for row in states if row["status"] == "indexed"}
            vector_missing = sorted(eligible[path]["rel_path"] for path in eligible.keys() - indexed)
            vector_stale = sorted(str(row["rel_path"] or row["path"]) for row in states if str(row["path"]) not in eligible)
            vector_hash_mismatch = sorted(
                eligible[str(row["path"])]["rel_path"]
                for row in states
                if str(row["path"]) in eligible
                and str(row["status"]) == "indexed"
                and str(row["doc_sha256"] or "") != eligible[str(row["path"])]["sha256"]
            )
            vector_errors = sorted(
                str(row["rel_path"] or row["path"])
                for row in states
                if str(row["status"]) == "error"
            )
            vector_ok = not (vector_missing or vector_stale or vector_hash_mismatch or vector_errors)
            add(
                checks,
                "zvec_parity",
                "pass" if vector_ok else "fail",
                f"Zvec covers {len(indexed & eligible.keys())}/{len(eligible)} docs.",
                {
                    "missing": vector_missing,
                    "stale": vector_stale,
                    "hash_mismatch": vector_hash_mismatch,
                    "errors": vector_errors,
                },
            )
    else:
        add(checks, "zvec_parity", "warn", "Optional vector index is not initialized.")
    if SEMANTIC_ENABLED:
        local_model_ok = (not REQUIRE_LOCAL_MODEL) or (EMBEDDING_MODEL.is_absolute() and EMBEDDING_MODEL.is_dir())
        add(
            checks,
            "semantic_local_model",
            "pass" if local_model_ok else "fail",
            "Semantic retrieval is pinned to a managed local model." if local_model_ok else "Semantic retrieval is not backed by the required local model directory.",
            {"model": str(EMBEDDING_MODEL), "require_local_model": REQUIRE_LOCAL_MODEL},
        )
        manifest_ok, manifest_detail = verify_model_manifest()
        add(
            checks,
            "semantic_model_integrity",
            "pass" if manifest_ok else "fail",
            "Managed model files match the pinned manifest." if manifest_ok else "Managed model files drifted from the pinned manifest.",
            manifest_detail,
        )
        python_ok, python_detail = verify_semantic_python_runtime()
        add(
            checks,
            "semantic_python_runtime",
            "pass" if python_ok else "fail",
            "Semantic Python and its base interpreter are available." if python_ok else "Semantic Python runtime is broken or lost its base interpreter.",
            python_detail,
        )
        dependency_ok, dependency_detail = verify_dependency_lock()
        add(
            checks,
            "semantic_dependency_lock",
            "pass" if dependency_ok else "fail",
            "Semantic Python environment matches the exact dependency lock." if dependency_ok else "Semantic Python environment differs from the dependency lock.",
            dependency_detail,
        )
        probe_ok, probe_detail = offline_semantic_probe()
        add(
            checks,
            "semantic_offline_probe",
            "pass" if probe_ok else "fail",
            "Offline EmbeddingGemma + Zvec query succeeded." if probe_ok else "Offline EmbeddingGemma + Zvec query failed.",
            probe_detail,
        )
    source_counts = {str(row[0]): int(row[1]) for row in conn.execute("SELECT verified_at_source, COUNT(*) FROM memory_docs GROUP BY verified_at_source")}
    weak = sum(
        source_counts.get(source, 0)
        for source in ("mtime_fallback", "needs_review", "document_date_unverified")
    )
    add(
        checks,
        "verification_provenance",
        "warn" if weak else "pass",
        f"Explicit verification/provenance classification on {len(docs) - weak}/{len(docs)} docs.",
        {"by_source": source_counts, "needs_review": weak},
    )
    large = [
        {"rel_path": str(row["rel_path"]), "lines": int(row["line_count"]), "bytes": int(row["size_bytes"])}
        for row in docs
        if str(row["status"]) in {"active", "candidate"}
        and (int(row["line_count"]) > 180 or int(row["size_bytes"]) > 24576)
    ]
    add(checks, "large_memory_files", "warn" if large else "pass", f"{len(large)} docs exceed compaction advisory thresholds.", {"files": large})
    search_hygiene = search_observability_hygiene(conn)
    search_privacy_ok = not any(search_hygiene.values())
    add(
        checks,
        "search_log_privacy",
        "pass" if search_privacy_ok else "fail",
        (
            "Search observation rows contain only hashes, controlled fields, counts, and redacted placeholders."
            if search_privacy_ok
            else "Search observation rows contain raw or invalid privacy-sensitive fields."
        ),
        search_hygiene,
    )
    observability_columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(memory_use_events)")
    }
    required_observability_columns = {
        "event_id", "actor", "task_id", "runtime_version", "event_type",
        "source", "memory_ids_json", "memory_versions_json", "content_sha256",
        "value", "reason_code", "confidence", "labeler_ref_sha256",
        "labeler_ref_length", "read_mode", "result_count",
        "required_live_verification_count", "requires_live_verification",
        "full_utf8_bytes", "returned_utf8_bytes", "truncated", "page_count",
        "task_class", "created_at",
    }
    event_hygiene = (
        observability_event_hygiene(conn)
        if required_observability_columns.issubset(observability_columns)
        else {
            "invalid_task_refs": 0,
            "invalid_task_classes": 0,
            "invalid_memory_id_payloads": 0,
            "invalid_memory_refs": 0,
            "missing_privacy_columns": len(
                required_observability_columns - observability_columns
            ),
        }
    )
    observability_report: dict[str, Any] = {}
    chain_gaps: dict[str, int] = {"report_unavailable": 1}
    if required_observability_columns.issubset(observability_columns):
        try:
            observability_report = agent_memory_observability.build_report(conn, days=7)
            tool = observability_report.get("tool_observed", {})
            cross = observability_report.get("cross_metrics", {})
            chain = cross.get("chain_health", {}) if isinstance(cross, dict) else {}
            applicability = cross.get("applicable_yes", {}) if isinstance(cross, dict) else {}
            labels = applicability.get("labels_without_task_seen", {}) if isinstance(applicability, dict) else {}
            shadow = cross.get("shadow_7d", {}) if isinstance(cross, dict) else {}
            chain_gaps = {
                "orphan_event_tasks": int(chain.get("orphan_event_tasks", 0) or 0),
                "tasks_without_hook_denominator": int(tool.get("tasks_without_hook_denominator", 0) or 0),
                "adopted_without_source_opened": int(chain.get("adopted_without_source_opened", 0) or 0),
                "adopted_stale_without_live_verification": int(chain.get("adopted_stale_without_live_verification", 0) or 0),
                "returned_without_disposition": int(chain.get("returned_without_disposition", 0) or 0),
                "opened_without_disposition": int(chain.get("opened_without_disposition", 0) or 0),
                "tasks_with_missing_disposition": int(chain.get("tasks_with_missing_disposition", 0) or 0),
                "labels_without_task_seen": sum(
                    int(item.get("total", 0) or 0)
                    for item in labels.values()
                    if isinstance(item, dict)
                ) if isinstance(labels, dict) else 0,
                "shadow_missing_denominator": int(shadow.get("missing_denominator", 0) or 0),
                "shadow_privacy_violation": int(shadow.get("privacy_violation", 0) or 0),
            }
        except (sqlite3.Error, ValueError, TypeError):
            chain_gaps = {"report_unavailable": 1}
    observability_ok = (
        required_observability_columns.issubset(observability_columns)
        and not any(event_hygiene.values())
        and not any(chain_gaps.values())
    )
    add(
        checks,
        "memory_use_observability",
        "pass" if observability_ok else "fail",
        "Task observability schema, task classes, and opaque references are valid."
        if observability_ok else "Task observability schema, task classes, or opaque references are invalid.",
        {
            "enabled": env_value("OBSERVABILITY_ENABLED", "false").strip().casefold() in {"1", "true", "yes", "on"},
            "schema_columns": len(observability_columns),
            **event_hygiene,
            "chain_gaps": chain_gaps,
            "sources_are_reported_separately": True,
        },
    )
    claims_ok, claims_detail = session_claim_hygiene(conn)
    stale_claim_count = len(claims_detail.get("stale", []))
    add(
        checks,
        "session_claim_hygiene",
        "pass" if claims_ok else "warn",
        f"Active claims={claims_detail.get('active', 0)}, stale claims={stale_claim_count}.",
        claims_detail,
    )
    writer_ok, writer_detail = writer_protocol_health(conn)
    add(
        checks,
        "writer_protocol_v2",
        "pass" if writer_ok else "fail",
        (
            f"State schema {STATE_SCHEMA_REQUIRED} and writer protocol 2 fencing invariants are healthy."
            if writer_ok
            else f"State schema {STATE_SCHEMA_REQUIRED} or writer protocol 2 fencing invariants are incomplete."
        ),
        writer_detail,
    )
    scope_detail = legacy_scope_documents_health()
    legacy_scope_documents = int(scope_detail.get("legacy_scope_documents", 0) or 0)
    scope_status = (
        "pass"
        if legacy_scope_documents == 0
        else ("warn" if allow_content_migration_bootstrap else "fail")
    )
    scope_detail["bootstrap_advisory"] = bool(
        legacy_scope_documents and allow_content_migration_bootstrap
    )
    add(
        checks,
        "legacy_scope_documents",
        scope_status,
        (
            "Every current formal body has explicit valid status/app_id/project_id/agent_scope metadata."
            if legacy_scope_documents == 0
            else (
                f"{legacy_scope_documents} current formal body document(s) require Write Gateway v2 scope migration after Runtime publication."
                if allow_content_migration_bootstrap
                else f"{legacy_scope_documents} current formal body document(s) still block installation completion."
            )
        ),
        scope_detail,
    )
    governance_detail = governance_metadata_migration_health(conn)
    governance_debt = int(
        governance_detail.get("migration_candidate_documents", 0) or 0
    ) + int(governance_detail.get("risk_candidate_documents", 0) or 0)
    governance_manual = int(
        governance_detail.get("manual_review_documents", 0) or 0
    )
    add(
        checks,
        "governance_metadata_v4",
        "warn" if governance_debt or governance_manual else "pass",
        (
            "Every governed body has explicit v4 metadata and no outstanding temporal review signal."
            if not governance_debt and not governance_manual
            else (
                f"{governance_debt} deterministic v4 metadata/risk finding(s) remain; "
                f"{governance_manual} document(s) still require human review."
            )
        ),
        governance_detail,
    )
    conn.close()
    latest_audit = latest_jsonl(AUDIT_LOG, lambda item: item.get("status") == "ran" and item.get("ok"))
    audit_time = parse_time(str(latest_audit.get("time", ""))) if latest_audit else None
    age = (dt.datetime.now(dt.timezone.utc) - audit_time).days if audit_time else None
    audit_fresh = age is not None and 0 <= age <= 7
    add(
        checks,
        "audit_freshness",
        "pass" if audit_fresh else ("warn" if allow_content_migration_bootstrap else "fail"),
        (
            f"Last successful content audit age: {age} days."
            if age is not None
            else "No successful content audit is recorded."
        ),
        {"age_days": age, "max_age_days": 7},
    )
    doctor_report_path = CONFIG_ROOT / "reports" / "latest-doctor.json"
    doctor_report = json_report_freshness(doctor_report_path)
    add(
        checks,
        "doctor_report_freshness",
        "pass" if doctor_report["fresh"] else "warn",
        (
            f"Last persisted Doctor report age: {doctor_report['age_days']} days."
            if doctor_report["age_days"] is not None
            else "No readable persisted Doctor report timestamp."
        ),
        {"path": str(doctor_report_path), **doctor_report},
    )
    closeout = latest_jsonl(CLOSEOUT_LOG)
    add(checks, "closeout_history", "pass" if closeout and closeout.get("status") in {"ok", "warning"} else "warn", f"Latest closeout status: {closeout.get('status')}." if closeout else "No closeout history.")
    observation_ok, observation_detail = closeout_observation_health()
    pending_observations = int(observation_detail.get("pending_count", 0) or 0)
    if observation_ok:
        observation_message = "Closeout observation baseline covers current formal memory history."
    elif not observation_detail.get("baseline"):
        observation_message = "No completed closeout observation baseline is recorded."
    elif observation_detail.get("warnings") or observation_detail.get("error"):
        observation_message = "Closeout observation baseline could not be verified."
    else:
        observation_message = f"{pending_observations} formal memory paths still lack closeout completion observations."
    add(
        checks,
        "closeout_observation_baseline",
        "pass" if observation_ok else "warn",
        observation_message,
        observation_detail,
    )

    remote_has_credential = git_remote_has_credential()
    add(
        checks,
        "git_remote_credentials",
        "fail" if remote_has_credential else "pass",
        "Git remote contains an embedded credential." if remote_has_credential else "Git remote has no embedded credential.",
    )
    try:
        memory_pathspec = VAULT_ROOT.relative_to(GIT_ROOT).as_posix()
    except ValueError:
        memory_pathspec = str(VAULT_ROOT)
    git_status = run(
        ["git", "-C", str(GIT_ROOT), "-c", "core.quotepath=false", "status", "--porcelain=v1", "--", memory_pathspec],
        30,
    )
    dirty_lines = [line for line in str(git_status.get("stdout", "")).splitlines() if line]
    dirty_status, dirty_message, dirty_detail = memory_git_baseline_result(
        len(dirty_lines), bool(git_status["ok"]), allow_dirty_memory
    )
    add(
        checks,
        "memory_git_baseline",
        dirty_status,
        dirty_message,
        dirty_detail,
    )
    backup_ok, backup_detail = git_remote_backup_health(memory_pathspec)
    unpushed_memory = int(backup_detail.get("ahead_memory", 0) or 0)
    add(
        checks,
        "memory_remote_backup",
        "pass" if backup_ok else "warn",
        (
            "Memory Git history is backed up to its upstream."
            if backup_ok and unpushed_memory == 0
            else (
                f"{unpushed_memory} unpushed memory commits remain within the backup grace window."
                if backup_ok
                else "Memory Git history has no healthy recent upstream backup."
            )
        ),
        backup_detail,
    )

    host_policy = attested_host_hook_policy()
    if host_policy["available"]:
        policy_status = (
            "pass"
            if host_policy["valid"]
            else ("warn" if allow_content_migration_bootstrap else "fail")
        )
        add(
            checks,
            "host_hook_policy",
            policy_status,
            (
                "Ready attestation contains a valid explicit Host Hook policy."
                if host_policy["valid"]
                else "Ready attestation has no valid Host Hook policy."
            ),
            host_policy,
        )
    required_hosts = set(host_policy["hosts"]) if host_policy["valid"] else set()
    if HOST_CONFIG or required_hosts:
        automation_failure_status = "warn" if allow_content_migration_bootstrap else "fail"
        codex_hooks_path = configured_or_required_host_path(
            "codex_hooks_json",
            host="codex",
            required_hosts=required_hosts,
            default=Path.home() / ".codex" / "hooks.json",
        )
        if codex_hooks_path and os.name != "nt":
            codex_hooks = read_json_object(codex_hooks_path)
            codex_hooks_payload = (
                codex_hooks.get("hooks") if isinstance(codex_hooks.get("hooks"), dict) else {}
            )
            codex_routes_ok, codex_detail = codex_hook_semantics(codex_hooks_payload)
            feature_ok, feature_detail = codex_hooks_feature_enabled(
                codex_hooks_path.parent / "config.toml"
            )
            codex_ok = codex_routes_ok and feature_ok
            add(
                checks,
                "codex_stop_hook",
                "pass" if codex_ok else automation_failure_status,
                (
                    "Codex Stop hook is configured."
                    if codex_ok
                    else "Codex Stop hook is missing or invalid."
                ),
                {**codex_detail, **feature_detail},
            )

        claude_settings_path = configured_or_required_host_path(
            "claude_settings_json",
            host="claude",
            required_hosts=required_hosts,
            default=Path.home() / ".claude" / "settings.json",
        )
        claude_fragment_path = configured_path("claude_hooks_fragment")
        if "claude" in required_hosts and claude_fragment_path is None:
            claude_fragment_path = CONFIG_ROOT / "config" / "claude-hooks.json"
        claude_settings = read_json_object(claude_settings_path) if claude_settings_path else {}
        expected_hooks = read_json_object(claude_fragment_path) if claude_fragment_path else {}
        if claude_settings_path or claude_fragment_path:
            live_hooks = claude_settings.get("hooks") if isinstance(claude_settings.get("hooks"), dict) else {}
            live_semantics_ok, live_semantics_detail = claude_hook_semantics(live_hooks)
            fragment_semantics_ok, fragment_semantics_detail = claude_hook_semantics(expected_hooks)
            semantics_ok = live_semantics_ok and fragment_semantics_ok
            claude_ok = bool(expected_hooks) and semantics_ok
            add(
                checks,
                "claude_stop_hook",
                "pass" if claude_ok else automation_failure_status,
                "Claude lifecycle routes are semantically canonical."
                if claude_ok
                else "Claude lifecycle routes are missing, disabled, legacy, or ambiguous.",
                {"live": live_semantics_detail, "managed_fragment": fragment_semantics_detail},
            )
            semantics_detail = {
                "live": live_semantics_detail,
                "managed_fragment": fragment_semantics_detail,
            }
            add(
                checks,
                "claude_hook_semantics",
                "pass" if semantics_ok else automation_failure_status,
                (
                    "Claude Stop is scoped and SessionEnd is non-blocking."
                    if semantics_ok
                    else "Claude managed hooks have unsafe Stop/SessionEnd lifecycle semantics."
                ),
                semantics_detail,
            )

        cc_switch_path = configured_path("cc_switch_db")
        if cc_switch_path:
            cc_ok, cc_detail = cc_switch_hooks_match(cc_switch_path, expected_hooks)
            add(checks, "claude_hook_persistence", "pass" if cc_ok else automation_failure_status, "Claude hook persistence is healthy." if cc_ok else "A provider manager may overwrite Claude hooks.", cc_detail)

        env_payload = claude_settings.get("env") if isinstance(claude_settings, dict) else {}
        base_url = str(env_payload.get("ANTHROPIC_BASE_URL", "")) if isinstance(env_payload, dict) else ""
        if claude_settings_path:
            endpoint_ok, endpoint_detail = local_endpoint_reachable(base_url)
            add(checks, "claude_runtime_endpoint", "pass" if endpoint_ok else "warn", "Claude runtime endpoint is reachable or remote." if endpoint_ok else "Claude points to a local endpoint that is not listening.", endpoint_detail)

    wrapper_paths = legacy_hook_wrapper_references()
    add(
        checks,
        "legacy_hook_wrapper_references",
        "fail" if wrapper_paths else "pass",
        "No legacy Hook wrapper remains referenced."
        if not wrapper_paths
        else "A legacy Hook wrapper is still referenced by host automation.",
        {"count": len(wrapper_paths), "paths": wrapper_paths},
    )

    launchagent_check = audit_launchagent_doctor_check(
        allow_content_migration_bootstrap=allow_content_migration_bootstrap,
    )
    if launchagent_check is not None:
        checks.append(launchagent_check)
    checks.append(shadow_lifecycle_doctor_check())
    return checks


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only health report for the complete Agent Memory pipeline.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--repair-derived", action="store_true", help="Rebuild derived indexes without editing Markdown facts.")
    parser.add_argument(
        "--allow-dirty-memory",
        action="store_true",
        help="Treat the current pre-commit memory changes as expected; intended only for closeout piggyback checks.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        transition = assert_runtime_ready("doctor-repair" if args.repair_derived else "doctor")
    except RuntimeTransitionError:
        payload = {
            "ok": False,
            "time": utc_now(),
            "version": VERSION,
            "status": "error",
            "summary": {"pass": 0, "warn": 0, "fail": 1},
            "checks": [{
                "name": "runtime_transition",
                "status": "fail",
                "message": "RUNTIME_TRANSITION_INCOMPLETE",
            }],
            "repair_actions": [],
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("agent_memory_doctor=error reason=RUNTIME_TRANSITION_INCOMPLETE")
        return 2
    repairs = repair_derived() if args.repair_derived else []
    checks = collect_checks(
        allow_dirty_memory=args.allow_dirty_memory,
        allow_content_migration_bootstrap=(
            str(transition.get("phase", "")).casefold() == "preflight"
            and transition.get("ready") is not True
            and transition.get("maintenance_capability") is True
        ),
    )
    statuses = {str(item["status"]) for item in checks}
    status = "error" if "fail" in statuses else ("warning" if "warn" in statuses else "ok")
    payload = {
        "ok": status != "error",
        "time": utc_now(),
        "version": VERSION,
        "status": status,
        "summary": {
            name: sum(1 for item in checks if item["status"] == name)
            for name in ("pass", "warn", "fail")
        },
        "checks": checks,
        "repair_actions": repairs,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"agent_memory_doctor={status} version={VERSION}")
        for item in checks:
            print(f"[{item['status']}] {item['name']}: {item['message']}")
    return 2 if status == "error" else 0


if __name__ == "__main__":
    raise SystemExit(main())
