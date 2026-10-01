#!/usr/bin/env python3
"""User-confirmed, two-phase formal Agent Memory writes for host applications.

The request body is accepted only on stdin.  Prepare performs source safety,
read-only reconciliation, target selection, and immutable intent creation; it
never changes Markdown.  Apply accepts the exact proposal again, binds the
ordinary host confirmation or (for sensitive operations) consumes a separate
one-shot human capability, revalidates the baseline, claims the target, writes
the exact bytes, and runs session-scoped closeout.

Mutating actions return only bounded metadata, hashes, relative paths, and safe
reason codes.  The explicit read-target action returns one bounded current
Markdown file to the host but never logs it.  Proposal Markdown, search
excerpts, diffs, evidence text, and confirmation text are never printed by the
mutating actions or written to persistent logs. Ailu also disables the optional
private proposal snapshot in the intent database, leaving only its hashes and
byte/line counts.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import datetime as dt
import errno
import hashlib
import hmac
import json
import os
import re
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import unicodedata
import uuid
from pathlib import Path
from typing import Any, Iterator

from agent_memory_env import RuntimeTransitionError, assert_runtime_ready, env_value, expand_path
from agent_memory_lock import private_lock
from agent_memory_state import (
    POSIX_PERMISSION_MODEL,
    PRIVATE_FILE_MODE,
    StateSecurityError,
    ensure_private_directory,
)
import agent_memory_claim as memory_claim
import agent_memory_closeout as memory_closeout
import agent_memory_confirmation_capability as confirmation_capability
import agent_memory_index as memory_index
import agent_memory_intent as write_intent
import agent_memory_observability as memory_observability
import agent_memory_retrieve as memory_retrieve
import agent_memory_safety as memory_safety


SUPPORTED_WRITER_ACTORS = ("codex", "claude", "ailu")
ACTOR = "ailu"
ASSERTED_BY_VALUES = {"user", "claude", "codex", "opencode"}
WRITABLE_ACTIONS = {"ADD", "UPDATE", "ADOPT", "MIGRATE_LEGACY_SCOPE"}
MEMORY_STATUSES = {"active", "pending_verification", "outdated", "archived"}
CONTENT_UPDATE_STATUSES = {"active", "pending_verification"}
STATUS_TRANSITIONS = {
    "active": {"pending_verification", "outdated", "archived"},
    "pending_verification": {"active", "outdated", "archived"},
    "outdated": {"active", "archived"},
    "archived": {"active"},
}
FORMAL_MEMORY_TOP_LEVELS = {"用户记忆", "项目", "工作流", "决策", "agent"}
GOVERNANCE_MEMORY_FILES = {"AGENTS.md", "INDEX.md", "README.md", "STRUCTURE.md"}
GOVERNANCE_APP_ID = "agent-memory"
GOVERNANCE_PROJECT_IDS = {"", "agent-memory-vault"}
SCHEMA_VERSION = write_intent.WRITER_PROTOCOL_VERSION
PLATFORM_NAME = os.name
WINDOWS_READ_ONLY_ACTIONS = frozenset({"read-target", "status", "list"})
MAX_SUMMARY_CHARS = 2_400
MAX_REFERENCE_CHARS = 512
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_HOST_TARGET_BYTES = 2 * 1024 * 1024
CONFIG_ROOT = expand_path(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory"))
# File CAS and closeout share one lock domain. Apply releases this lock before
# spawning closeout; the active path fence protects the hand-off interval.
WRITE_LOCK_PATH = CONFIG_ROOT / "locks" / "closeout.lock"
CLOSEOUT_SCRIPT = Path(__file__).resolve().parent / "agent_memory_closeout.py"
PYTHON = env_value("PYTHON", sys.executable)
SAFE_REFERENCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,511}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
PROPOSAL_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
READ_TOKEN_RE = re.compile(r"[0-9a-f]{64}\Z")
PATH_TRACK_FLOORS = {
    "用户记忆": "user",
    "项目": "project",
    "工作流": "workflow",
    "决策": "decision",
    "agent": "agent",
}
PATH_MEMORY_TYPE_FLOORS = {
    "用户记忆": "user_profile",
    "项目": "project",
    "工作流": "workflow",
    "决策": "decision",
    "agent": "agent_note",
}
ACTION_SENSITIVE_MEMORY_TYPES = {"fact", "atomic_fact", "current_fact"}


class MemoryWriteError(ValueError):
    """A bounded protocol error that is safe to return to the host UI."""

    def __init__(self, reason_code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.reason_code = _safe_code(reason_code, default="WRITE_PROTOCOL_ERROR")
        self.safe_message = message[:240]
        self.retryable = retryable


def utc_now() -> str:
    return memory_closeout.utc_now()


def _safe_code(value: str, *, default: str = "WRITE_PROTOCOL_ERROR") -> str:
    normalized = str(value).strip().upper()
    if re.fullmatch(r"[A-Z0-9][A-Z0-9_.:-]{0,95}", normalized):
        return normalized
    return default


def _error_message(reason_code: str) -> str:
    messages = {
        "ACTIVE_TARGET_CONFLICT": "这个记忆目标正由另一项写入占用，请稍后重新准备。",
        "ADOPT_ACTOR_FORBIDDEN": "外部修改只能由受控的 Codex 或 Claude 人工确认流程接管。",
        "ADOPT_CONTENT_MISMATCH": "接管提案必须与当前外部修改的原始字节完全一致。",
        "ADOPT_TARGET_NOT_DIRTY": "目标与 Git 基线没有外部差异，不需要执行接管。",
        "APPROVAL_ALREADY_BOUND": "这份提案已绑定另一条确认记录，请重新准备。",
        "APPROVAL_REQUIRED": "缺少对当前提案的明确用户确认。",
        "APPLY_RECOVERY_REQUIRED": "目标已进入应用阶段且内容发生变化，必须重试应用与收尾，不能取消。",
        "BASE_NOT_AT_GIT_HEAD": "目标记忆已有尚未收尾的修改，不能覆盖。",
        "CLAIM_MISSING_FOR_RECOVERY": "上次写入的会话认领已丢失，需人工核对后再处理。",
        "CLOSEOUT_FAILED": "正式记忆收尾失败，修改仍保持认领状态，需核对后重试。",
        "CLOSEOUT_TIMEOUT": "正式记忆收尾超时，修改仍保持认领状态，需核对后重试。",
        "CONFIRMATION_INVALID": "用户确认记录格式无效。",
        "CONFIRMATION_REQUIRED": "必须明确确认这一个目标和这一版内容。",
        "CONFIRMATION_CAPABILITY_ALREADY_CONSUMED": "这份人工确认凭据已经使用，不能再次授权另一项写入。",
        "CONFIRMATION_CAPABILITY_EXPIRED": "这份人工确认凭据已经过期，请由宿主或人工工具重新签发。",
        "CONFIRMATION_CAPABILITY_INVALID": "人工确认凭据与当前任务、会话、目标或提案不匹配。",
        "CONFIRMATION_CAPABILITY_REQUIRED": "这项敏感变更需要宿主或显式人工工具另行签发的一次性确认凭据。",
        "CONTENT_NOT_UTF8": "目标记忆不是有效的 UTF-8 Markdown。",
        "CONTENT_TOO_LARGE": "提案内容超过 Agent Memory 的大小限制。",
        "EXPIRED_VALIDATED_RECOVERY_BINDING_CHANGED": "过期写入与原确认、认领或内容绑定不再完全一致，已停止恢复。",
        "EXPIRED_VALIDATED_RECOVERY_CLAIM_CHANGED": "过期写入的原会话认领已变化，已停止恢复。",
        "EXPIRED_VALIDATED_RECOVERY_COMMIT_CONTENT_MISMATCH": "Git 中的目标内容不是原提案的精确版本，已停止恢复。",
        "EXPIRED_VALIDATED_RECOVERY_EXPIRY_INVALID": "过期写入的恢复时间窗口无效，已停止恢复。",
        "EXPIRED_VALIDATED_RECOVERY_GIT_DIVERGED": "过期写入之后的 Git 历史已偏离原验证基线，已停止恢复。",
        "EXPIRED_VALIDATED_RECOVERY_GIT_PROJECTION_UNAVAILABLE": "无法完整核验过期写入的 Git 投影，已停止恢复。",
        "EXPIRED_VALIDATED_RECOVERY_TARGET_DRIFT": "过期写入的目标文件在核验期间发生变化，已停止恢复。",
        "EXPIRED_VALIDATED_RECOVERY_TARGET_HISTORY_CHANGED": "目标文件的 Git 变更历史不只包含原提案，已停止恢复。",
        "EXPIRED_VALIDATED_RECOVERY_WINDOW_ELAPSED": "一次性过期写入恢复窗口已经结束，不能再次续期。",
        "EXPIRED_VALIDATED_RECOVERY_WORKTREE_DIRTY": "目标文件或 Git 暂存区与已提交提案不一致，已停止恢复。",
        "EXPIRED_VALIDATED_RECOVERY_WORKTREE_UNSAFE": "目标不是当前用户控制的普通非可执行文件，已停止恢复。",
        "FACT_EVIDENCE_REQUIRED": "事实记录必须提供可审计的 evidence_ref。",
        "ACTION_SENSITIVE_FACT_REQUIRED": "行动敏感事实必须使用一条事实一个文件，并显式提供 fact_key、valid_from、verified_at 和 evidence_ref。",
        "FRONTMATTER_DUPLICATE_KEY": "记忆前言包含重复的受保护字段，已停止解析以避免后值覆盖授权或时态策略。",
        "FACT_IDENTITY_CHANGE_FORBIDDEN": "既有事实记录的 fact_key 或 valid_from 不能原地改写；请新建版本并显式替代。",
        "FACT_RELATION_REMOVAL_FORBIDDEN": "不能移除已声明的事实替代关系，以免旧事实重新变成当前事实。",
        "FACT_VALUE_CHANGE_FORBIDDEN": "既有事实记录的正文不能原地改写；请新建版本并显式替代旧版本。",
        "GENERATED_FILE_READ_ONLY": "INDEX.md 是机器生成文件，不能通过人工提案直接编辑。",
        "GOVERNANCE_MIGRATION_TARGET_INVALID": "治理迁移只能处理正式正文，不能修改 archive、模板或根治理文件。",
        "INTENT_EXPIRED": "这份提案已过期，请重新准备并确认。",
        "INTENT_SESSION_MISMATCH": "这份提案不属于当前插件会话，请重新准备。",
        "LEGACY_SCOPE_MIGRATION_FORBIDDEN": "旧文档 scope 迁移只允许受控的 Codex 或 Claude 执行精确的 frontmatter 前向变换。",
        "MERGE_REQUIRED": "发现可能重复或冲突的记忆，需要先选择合并方式。",
        "MEMORY_ID_INVALID": "memory_id 必须是 64 位小写十六进制标识。",
        "MEMORY_ID_REQUIRED": "新建正式记忆必须使用读取阶段生成并绑定的 memory_id。",
        "MEMORY_ID_CHANGE_FORBIDDEN": "既有记忆的 memory_id 不能在更新或状态转换中重算。",
        "NOOP": "正式记忆中已经有等价内容，不需要再次写入。",
        "PATH_POLICY_DOWNGRADE_FORBIDDEN": "记忆前言不能把规范目录声明成更低风险的类型、轨道或治理文件。",
        "PROPOSAL_CONTENT_MISMATCH": "确认的内容与准备阶段不是同一版。",
        "PROPOSAL_HASH_MISMATCH": "确认的内容哈希与准备阶段不一致。",
        "RECONCILE_UNAVAILABLE": "当前无法完成正式记忆查重，未创建写入提案。",
        "READ_TOKEN_REQUIRED": "必须先读取这个目标并提交同一版读取令牌。",
        "RECEIPT_INTEGRITY_INVALID": "持久化写入回执与任务状态不一致，已停止恢复。",
        "RECEIPT_OUTCOME_CONFLICT": "持久化写入回执与终态不一致，已停止恢复。",
        "RISK_CLASS_REQUIRED": "active 项目、工作流或决策记忆必须显式声明 risk_class。",
        "SCOPE_METADATA_INVALID": "目标或提案不属于当前创作记忆范围。",
        "SESSION_REQUIRED": "插件没有独立的 Agent Memory 会话，不能写入。",
        "STATE_SNAPSHOT_BUSY": "Agent Memory 状态正在变化，请稍后重新查询。",
        "SOURCE_METADATA_INVALID": "记忆来源信息不完整或不受支持。",
        "STATUS_TRANSITION_FORBIDDEN": "请求的记忆状态转换不在允许的前向治理路径中。",
        "STATUS_TRANSITION_INVALID": "状态转换只能修改受控的时态元数据，不能同时改写正文或其他字段。",
        "STATUS_TRANSITION_REASON_REQUIRED": "状态转换必须提供明确原因。",
        "STATUS_REACTIVATION_EVIDENCE_REQUIRED": "恢复 active 必须提供新的验证日期和证据。",
        "STALE_BASE": "准备后目标记忆发生了变化，请重新准备。",
        "STALE_READ_TOKEN": "读取目标后内容或 Git 基线已变化，请重新读取再准备。",
        "TARGET_ALREADY_EXISTS": "准备新建的目标已经存在，需要重新选择或改为更新。",
        "TARGET_CHANGED_AFTER_CLAIM": "认领后目标内容发生变化，已停止写入。",
        "TARGET_MISSING": "准备更新的目标已不存在，请重新准备。",
        "TARGET_PARENT_MISSING": "目标目录不存在，请先选择现有的正式记忆目录。",
        "TARGET_REQUIRED": "新建记忆前必须先选择具体保存文件。",
        "TARGET_RECOMMENDATION_CONFLICT": "选择的目标与查重结果不一致，需要人工确认合并。",
        "TARGET_TOO_LARGE": "目标记忆超过宿主可安全读取的大小上限。",
        "TARGET_UNREADABLE": "无法读取目标记忆。",
        "TARGET_WRITE_RECOVERY_REQUIRED": "检测到未完成或再次竞态的原子写入，已保留恢复材料并停止；需人工核对后重试。",
        "TEMPORAL_METADATA_INVALID": "事实时间元数据无效；必须提供合法 fact_key、valid_from 和显式替代关系。",
        "TEMPORAL_POLICY_REQUIRED": "active 记忆必须显式声明 temporal_policy，不能依赖索引推断。",
        "REVIEW_POLICY_REQUIRED": "active 普通记忆必须显式声明正整数 review_after_days。",
        "TEMPORAL_RELATION_INVALID": "事实替代关系存在未知目标、跨范围、日期倒退、分叉或环，未创建写入提案。",
        "TEMPORAL_SCAN_UNAVAILABLE": "无法完整核验事实时间线，未创建写入提案。",
        "ATOMIC_CONDITIONAL_WRITE_UNAVAILABLE": "当前文件系统不支持安全的原子条件写入，未修改目标记忆。",
        "USER_CONFIRMATION_REQUIRED": "只有用户本人明确确认后才能写入正式记忆。",
        "WRITE_LOCK_TIMEOUT": "另一项正式记忆写入仍在进行，请稍后重试。",
        "GLOBAL_SCOPE_TARGET_INVALID": "Ailu 的 global 范围只能访问用户记忆目录。",
    }
    return messages.get(reason_code, "正式记忆写入协议已停止本次操作。")


def _raise(reason_code: str, *, retryable: bool = False) -> None:
    code = _safe_code(reason_code)
    raise MemoryWriteError(code, _error_message(code), retryable=retryable)


def _writable_agent_scopes(actor: str) -> set[str]:
    scopes = {"shared"}
    if actor in {"codex", "claude"}:
        scopes.add(actor)
    return scopes


def _reconciliation_agent_scope(actor: str) -> str:
    # Search interprets a host-specific scope as ``shared OR self``. Ailu must
    # remain on the literal shared filter so malformed/private rows never enter
    # its reconciliation candidate set.
    return actor if actor in {"codex", "claude"} else "shared"


def _raw_session_id(explicit: str = "") -> str:
    value = memory_claim.session_value(explicit, ACTOR)
    if not value:
        _raise("SESSION_REQUIRED")
    return value


@contextlib.contextmanager
def writer_lock(timeout: float) -> Iterator[None]:
    try:
        with private_lock(
            WRITE_LOCK_PATH,
            timeout=timeout,
            timeout_message="WRITE_LOCK_TIMEOUT",
        ):
            yield
    except TimeoutError:
        _raise("WRITE_LOCK_TIMEOUT", retryable=True)
    except (OSError, StateSecurityError) as exc:
        raise MemoryWriteError(
            "WRITE_LOCK_UNSAFE",
            "正式记忆写入锁不安全或不可用。",
        ) from exc


def _read_request() -> dict[str, Any]:
    max_request_bytes = max(write_intent.MAX_PROPOSAL_BYTES * 4 + 256 * 1024, 1024 * 1024)
    payload = sys.stdin.buffer.read(max_request_bytes + 1)
    if len(payload) > max_request_bytes:
        _raise("CONTENT_TOO_LARGE")
    try:
        decoded = payload.decode("utf-8", errors="strict")
        value = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MemoryWriteError("REQUEST_INVALID", "Agent Memory 写入请求格式无效。") from exc
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        _raise("REQUEST_INVALID")
    return value


def _required_string(
    payload: dict[str, Any],
    key: str,
    *,
    max_chars: int,
    preserve: bool = False,
) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        _raise("REQUEST_INVALID")
    result = value if preserve else value.strip()
    if not result or len(result) > max_chars or "\x00" in result:
        _raise("REQUEST_INVALID")
    if any(ord(character) < 32 and character not in "\t\n\r" for character in result):
        _raise("REQUEST_INVALID")
    return result


def _optional_string(payload: dict[str, Any], key: str, *, max_chars: int) -> str:
    value = payload.get(key, "")
    if value in (None, ""):
        return ""
    if not isinstance(value, str):
        _raise("REQUEST_INVALID")
    result = value.strip()
    if len(result) > max_chars or "\x00" in result:
        _raise("REQUEST_INVALID")
    if any(ord(character) < 32 for character in result):
        _raise("REQUEST_INVALID")
    return result


def _required_positive_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        _raise("REQUEST_INVALID")
    return value


def _proposal_text(payload: dict[str, Any]) -> tuple[str, write_intent.ContentDigest]:
    value = payload.get("proposal_markdown")
    if not isinstance(value, str) or not value or "\x00" in value:
        _raise("REQUEST_INVALID")
    if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
        _raise("REQUEST_INVALID")
    try:
        digest = write_intent.content_hashes(
            value.encode("utf-8"),
            max_bytes=write_intent.MAX_PROPOSAL_BYTES,
        )
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    return value, digest


def _is_governance_target(path: Path) -> bool:
    try:
        relative = path.resolve(strict=False).relative_to(write_intent.VAULT_ROOT.resolve(strict=True)).as_posix()
    except (OSError, ValueError):
        return False
    return relative in GOVERNANCE_MEMORY_FILES


def _canonical_path_policy_floor(target_relative_path: str) -> dict[str, Any]:
    """Derive a non-downgradable document class from a canonical target path.

    Frontmatter may raise risk (for example, a project-scoped atomic fact), but
    it cannot turn a normal project/workflow/decision document into a routing,
    template, misc, or governance document. Governance is a path capability:
    only the exact managed root allowlist receives that exemption.
    """

    normalized = unicodedata.normalize(
        "NFKC", str(target_relative_path or "")
    ).replace("\\", "/")
    candidate = Path(normalized)
    if (
        not normalized
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        return {}
    rel_path = candidate.as_posix()
    if rel_path in GOVERNANCE_MEMORY_FILES and len(candidate.parts) == 1:
        return {
            "kind": "governance",
            "memory_type": "governance",
            "track": "governance",
            "supporting": True,
        }
    if len(candidate.parts) < 2:
        return {}
    top = candidate.parts[0]
    expected_track = PATH_TRACK_FLOORS.get(top, "")
    expected_type = PATH_MEMORY_TYPE_FLOORS.get(top, "")
    if not expected_track or not expected_type:
        return {}
    if candidate.name == "README.md":
        return {
            "kind": "supporting",
            "memory_type": "directory_index",
            "track": expected_track,
            "supporting": True,
        }
    if candidate.name.startswith("_模板"):
        return {
            "kind": "supporting",
            "memory_type": "template",
            "track": expected_track,
            "supporting": True,
        }
    return {
        "kind": "governed",
        "memory_type": expected_type,
        "track": expected_track,
        "supporting": False,
    }


def _allow_supporting_document(
    target: write_intent.CanonicalTarget,
    *,
    operation: str,
    legacy_scope_migration: bool = False,
) -> bool:
    """Narrowly admit supporting README files to deterministic migrations.

    Supporting documents remain excluded from ordinary retrieval and writes.
    The governance exception is limited to Codex/Claude, the exact
    byte-preserving governance migration operation, Doctor's shared formal
    body boundary, and directory-index README paths.  Legacy-scope migration
    keeps its existing separately validated exception.
    """

    if legacy_scope_migration:
        return True
    if ACTOR not in {"codex", "claude"} or operation != "governance_migration":
        return False
    relative = Path(target.rel_path)
    if not memory_index.is_formal_body_document(relative):
        return False
    floor = _canonical_path_policy_floor(target.rel_path)
    return bool(
        floor.get("supporting")
        and floor.get("memory_type") == "directory_index"
    )


def _existing_statuses_for_operation(operation: str) -> set[str] | None:
    """Return the exact existing-document states one host operation may read."""

    if ACTOR not in {"codex", "claude"}:
        return None
    if operation == "governance_migration":
        return memory_index.GOVERNANCE_MIGRATION_STATUSES
    if operation == "status_transition":
        return MEMORY_STATUSES
    return None


def _validate_governance_migration_target(
    target: write_intent.CanonicalTarget,
    *,
    operation: str,
) -> None:
    if operation == "governance_migration" and not memory_index.is_formal_body_document(
        Path(target.rel_path)
    ):
        _raise("GOVERNANCE_MIGRATION_TARGET_INVALID")


def _scope_request(
    payload: dict[str, Any],
    *,
    target: write_intent.CanonicalTarget | None = None,
    legacy_scope_migration: bool = False,
    governed_operation: str = "",
) -> tuple[str, str]:
    raw_app_id = payload.get("app_id")
    if not isinstance(raw_app_id, str) or not raw_app_id.strip():
        raise MemoryWriteError("APP_ID_REQUIRED", _error_message("SCOPE_METADATA_INVALID"))
    app_id = raw_app_id.strip()
    if len(app_id) > 160 or "\x00" in app_id:
        _raise("SCOPE_METADATA_INVALID")
    project_id = _optional_string(payload, "project_id", max_chars=160)
    try:
        if legacy_scope_migration:
            if target is None:
                raise memory_retrieve.RetrievalProtocolError("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
            legacy_scope_app_id = _required_string(payload, "legacy_scope_app_id", max_chars=160)
            return _legacy_scope_identifiers(
                actor=ACTOR,
                target_relative_path=target.rel_path,
                requested_app_id=app_id,
                requested_project_id=project_id,
                legacy_scope_app_id=legacy_scope_app_id,
            )
        if target is not None and _is_governance_target(target.path):
            if ACTOR == "ailu":
                raise memory_retrieve.RetrievalProtocolError("GOVERNANCE_SCOPE_FORBIDDEN")
            normalized_app = memory_retrieve._normalized_identifier(app_id)
            normalized_project = memory_retrieve._normalized_identifier(project_id)
            if normalized_app != GOVERNANCE_APP_ID or normalized_project not in GOVERNANCE_PROJECT_IDS:
                raise memory_retrieve.RetrievalProtocolError("GOVERNANCE_SCOPE_INVALID")
            return GOVERNANCE_APP_ID, normalized_project
        if ACTOR == "ailu":
            normalized_app, normalized_project = memory_retrieve.validate_ailu_scope_request(app_id, project_id)
            if target is not None and normalized_project == "global":
                parts = Path(target.rel_path).parts
                if not parts or parts[0] != "用户记忆":
                    raise memory_retrieve.RetrievalProtocolError("GLOBAL_SCOPE_TARGET_INVALID")
            return normalized_app, normalized_project
        normalized_app = memory_retrieve._normalized_identifier(app_id)
        normalized_project = memory_retrieve._normalized_identifier(project_id)
        if not normalized_app or "," in normalized_app:
            raise memory_retrieve.RetrievalProtocolError("APP_ID_UNSUPPORTED")
        global_user_target = bool(
            normalized_project == "global"
            and target is not None
            and Path(target.rel_path).parts
            and Path(target.rel_path).parts[0] == "用户记忆"
            and governed_operation in {"governance_migration", "status_transition"}
        )
        if (
            normalized_project == "shared"
            or (normalized_project == "global" and not global_user_target)
            or "," in normalized_project
        ):
            raise memory_retrieve.RetrievalProtocolError("PROJECT_ID_INVALID")
        return normalized_app, normalized_project
    except memory_retrieve.RetrievalProtocolError as exc:
        raise MemoryWriteError(
            exc.code,
            _error_message("SCOPE_METADATA_INVALID"),
        ) from exc


def _validate_writer_markdown(
    text: str,
    *,
    path: Path,
    app_id: str,
    project_id: str,
    require_explicit_write_scope: bool,
    allow_supporting_document: bool = False,
    allowed_statuses: set[str] | None = None,
) -> dict[str, Any]:
    if memory_retrieve._contains_secret(text):
        _raise("SECRET_MATERIAL")
    if _is_governance_target(path):
        if ACTOR == "ailu":
            _raise("GOVERNANCE_SCOPE_FORBIDDEN")
        if app_id != GOVERNANCE_APP_ID or project_id not in GOVERNANCE_PROJECT_IDS:
            _raise("GOVERNANCE_SCOPE_INVALID")
        return {
            "status": "active",
            "agent_scope": "shared",
            "app_id": GOVERNANCE_APP_ID,
            "project_id": project_id,
            "memory_type": "governance",
            "meta": {},
        }
    try:
        parsed = memory_retrieve._frontmatter_text(text)
        metadata = memory_retrieve._metadata_for(path, parsed)
    except (memory_retrieve.RetrievalProtocolError, OSError, ValueError) as exc:
        reason = exc.code if isinstance(exc, memory_retrieve.RetrievalProtocolError) else "FRONTMATTER_INVALID"
        raise MemoryWriteError(reason, _error_message("SCOPE_METADATA_INVALID")) from exc
    try:
        relative_path = path.resolve(strict=False).relative_to(
            write_intent.VAULT_ROOT.resolve(strict=True)
        ).as_posix()
    except (OSError, ValueError):
        relative_path = ""
    rejection = memory_retrieve._metadata_rejection(
        metadata,
        ACTOR,
        app_id,
        project_id,
        relative_path=relative_path,
        include_inactive=bool(allowed_statuses and allowed_statuses - {"active", "pending_verification"}),
        accepted_statuses=allowed_statuses,
    )
    if rejection and not (
        allow_supporting_document and rejection == "SUPPORTING_DOCUMENT_EXCLUDED"
    ):
        raise MemoryWriteError(rejection, _error_message("SCOPE_METADATA_INVALID"))
    if require_explicit_write_scope:
        meta = metadata.get("meta")
        if not isinstance(meta, dict):
            _raise("SCOPE_METADATA_INVALID")
        for key in ("status", "agent_scope", "app_id"):
            if key not in meta:
                _raise("SCOPE_METADATA_INVALID")
        normalized_status = str(meta.get("status", "")).strip().casefold()
        accepted_statuses = allowed_statuses or {"active"}
        if normalized_status not in accepted_statuses:
            _raise("STATUS_NOT_ACTIVE")
        explicit_scope = str(meta.get("agent_scope", "")).strip().casefold()
        if explicit_scope not in _writable_agent_scopes(ACTOR):
            _raise("AGENT_SCOPE_MISMATCH")
        if memory_retrieve._normalized_values(str(meta.get("app_id", ""))) != {app_id}:
            _raise("APP_ID_MISMATCH")
        proposal_projects = memory_retrieve._normalized_values(str(meta.get("project_id", "")))
        if project_id:
            if proposal_projects != {project_id}:
                _raise("PROJECT_SCOPE_MISMATCH")
        elif proposal_projects and not proposal_projects <= {"global", "shared"}:
            _raise("PROJECT_SCOPE_MISMATCH")
    return metadata


def _memory_id_from_text(text: str) -> str:
    value = memory_index.as_text(
        _temporal_parse_frontmatter(text).get("memory_id")
    ).strip()
    if value and SHA256_RE.fullmatch(value) is None:
        _raise("MEMORY_ID_INVALID")
    return value


def _generated_memory_id(read_token: str) -> str:
    return hashlib.sha256(f"agent-memory-add-v1\0{read_token}".encode("utf-8")).hexdigest()


def _content_update_status(
    *,
    base_text: str,
    proposal_text: str,
    base_exists: bool,
    governance_target: bool = False,
) -> str:
    """Prove that content_update cannot be used as a status-transition alias."""

    if governance_target:
        return "active"
    proposal_status = memory_index.as_text(
        _temporal_parse_frontmatter(proposal_text).get("status"),
        "active",
    ).strip().casefold()
    if proposal_status not in CONTENT_UPDATE_STATUSES:
        _raise("STATUS_TRANSITION_FORBIDDEN")
    if not base_exists:
        if proposal_status != "active":
            _raise("STATUS_TRANSITION_FORBIDDEN")
        return proposal_status
    base_status = memory_index.as_text(
        _temporal_parse_frontmatter(base_text).get("status"),
        "active",
    ).strip().casefold()
    if base_status not in CONTENT_UPDATE_STATUSES or proposal_status != base_status:
        _raise("STATUS_TRANSITION_FORBIDDEN")
    return proposal_status


def _immutable_git_base(
    *,
    target: write_intent.CanonicalTarget,
    git_head: str,
) -> tuple[bool, write_intent.ContentDigest]:
    """Read one write-policy baseline from an immutable Git tree."""

    try:
        exists, digest = write_intent.git_target_digest_at_commit(git_head, target)
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    return exists, digest


def _assert_intent_immutable_base_binding(
    intent: dict[str, Any],
    *,
    exists: bool,
    digest: write_intent.ContentDigest,
) -> None:
    if (
        bool(int(intent.get("base_exists") or 0)) != bool(exists)
        or str(intent.get("base_raw_sha256", "")) != digest.raw_sha256
        or str(intent.get("base_canonical_sha256", ""))
        != digest.canonical_sha256
    ):
        _raise("INTENT_BINDING_INVALID")


def _validate_memory_identity(
    *,
    base_text: str,
    proposal_text: str,
    target_exists: bool,
    expected_new_memory_id: str,
) -> str:
    proposal_id = _memory_id_from_text(proposal_text)
    if not target_exists:
        if proposal_id != expected_new_memory_id:
            _raise("MEMORY_ID_REQUIRED")
        return proposal_id
    base_id = _memory_id_from_text(base_text)
    if base_id != proposal_id:
        _raise("MEMORY_ID_CHANGE_FORBIDDEN")
    return proposal_id


def _status_transition_request(request: dict[str, Any]) -> tuple[str, str, str]:
    operation = _optional_string(request, "operation", max_chars=64).casefold() or "content_update"
    if operation not in {"content_update", "status_transition", "governance_migration"}:
        _raise("REQUEST_INVALID")
    if operation == "governance_migration":
        if ACTOR not in {"codex", "claude"}:
            _raise("STATUS_TRANSITION_FORBIDDEN")
        if request.get("target_status") or request.get("transition_reason"):
            _raise("REQUEST_INVALID")
        return operation, "", ""
    if operation == "content_update":
        if request.get("target_status") or request.get("transition_reason"):
            _raise("REQUEST_INVALID")
        return operation, "", ""
    if ACTOR not in {"codex", "claude"}:
        _raise("STATUS_TRANSITION_FORBIDDEN")
    target_status = _required_string(request, "target_status", max_chars=64).casefold()
    if target_status not in MEMORY_STATUSES:
        _raise("STATUS_TRANSITION_FORBIDDEN")
    reason = _required_string(request, "transition_reason", max_chars=MAX_SUMMARY_CHARS)
    if not reason.strip():
        _raise("STATUS_TRANSITION_REASON_REQUIRED")
    return operation, target_status, hashlib.sha256(reason.encode("utf-8")).hexdigest()


def _validate_governance_migration(
    *,
    rel_path: str,
    base_text: str,
    proposal_text: str,
) -> str:
    if not memory_index.is_formal_body_document(Path(rel_path)):
        _raise("GOVERNANCE_MIGRATION_TARGET_INVALID")
    candidate = _governance_v4_candidate_metadata(
        rel_path=rel_path,
        base_text=base_text,
    )
    # This operation is intentionally narrower than a generic metadata update.
    # Requiring the exact byte-preserving deterministic transform prevents a
    # caller from smuggling frontmatter reformatting, comments, status/risk
    # edits, or body changes through parser-level equivalence.
    expected = _governance_v4_proposal(rel_path=rel_path, base_text=base_text)
    if proposal_text != expected:
        _raise("STATUS_TRANSITION_INVALID")
    proposal_parse_text = (
        proposal_text.replace("\r\n", "\n")
        if proposal_text.startswith("---\r\n")
        else proposal_text
    )
    proposal_meta = memory_index.parse_frontmatter(proposal_parse_text)
    for key, value in candidate.items():
        if memory_index.as_text(proposal_meta.get(key)).strip() != str(value):
            _raise(
                "MEMORY_ID_REQUIRED"
                if key == "memory_id"
                else "TEMPORAL_METADATA_INVALID"
            )
    return memory_index.as_text(proposal_meta.get("memory_id")).strip()


def _governance_v4_candidate_metadata(
    *,
    rel_path: str,
    base_text: str,
) -> dict[str, str]:
    """Return only deterministic missing v4 fields for one existing body.

    This helper deliberately cannot classify risk, change status, or infer a
    verification date.  A date in ordinary prose remains provenance only.
    Existing scalar values are immutable in this operation; invalid values
    require a separately reviewed correction instead of being overwritten.
    """

    parse_text = (
        base_text.replace("\r\n", "\n")
        if base_text.startswith("---\r\n")
        else base_text
    )
    meta = memory_index.parse_frontmatter(parse_text)
    if not meta or not base_text.startswith(("---\n", "---\r\n")):
        _raise("FRONTMATTER_INVALID")
    current_memory_id = memory_index.as_text(meta.get("memory_id")).strip()
    if current_memory_id and SHA256_RE.fullmatch(current_memory_id) is None:
        _raise("MEMORY_ID_INVALID")
    current_policy = memory_index.as_text(meta.get("temporal_policy")).strip().casefold()
    if current_policy and current_policy not in memory_index.TEMPORAL_POLICIES:
        _raise("TEMPORAL_METADATA_INVALID")
    current_review = memory_index.as_text(meta.get("review_after_days")).strip()
    if current_review and (
        re.fullmatch(r"[1-9][0-9]{0,3}", current_review) is None
        or int(current_review) > 3650
    ):
        _raise("TEMPORAL_METADATA_INVALID")

    target_path = memory_index.VAULT_ROOT / Path(rel_path)
    try:
        memory_type, _track, _project_id, status = memory_index.infer_from_path(
            target_path,
            meta,
        )
        fact = memory_index.fact_metadata(meta)
        inferred_policy, _policy_source = memory_index.temporal_policy_for(
            meta,
            memory_type=memory_type,
            status=status,
            fact=fact,
        )
        title = memory_index.title_from_markdown(parse_text, target_path)
        inferred_review = memory_index.infer_review_after_days(
            target_path,
            title,
            memory_type,
            status,
            meta,
        )
    except (OSError, ValueError) as exc:
        raise MemoryWriteError(
            "TEMPORAL_METADATA_INVALID",
            _error_message("TEMPORAL_METADATA_INVALID"),
        ) from exc

    candidate: dict[str, str] = {}
    if "memory_id" not in meta:
        candidate["memory_id"] = memory_index.memory_identity(rel_path, {})[0]
    elif not current_memory_id:
        # A present blank key cannot be safely repaired by adding a duplicate.
        _raise("MEMORY_ID_INVALID")
    if "temporal_policy" not in meta:
        candidate["temporal_policy"] = inferred_policy
    elif not current_policy:
        _raise("TEMPORAL_METADATA_INVALID")
    if "review_after_days" not in meta:
        candidate["review_after_days"] = str(inferred_review)
    elif not current_review:
        _raise("TEMPORAL_METADATA_INVALID")
    if not candidate:
        _raise("GOVERNANCE_MIGRATION_NOT_REQUIRED")
    return candidate


def _governance_v4_proposal(*, rel_path: str, base_text: str) -> str:
    """Add the deterministic candidate fields without changing other bytes."""

    candidate = _governance_v4_candidate_metadata(
        rel_path=rel_path,
        base_text=base_text,
    )
    newline = "\r\n" if base_text.startswith("---\r\n") else "\n"
    opening_size = 3 + len(newline)
    closing = base_text.find(newline + "---", opening_size)
    if closing < 0:
        _raise("FRONTMATTER_INVALID")
    insertion = "".join(
        f"{key}: {candidate[key]}{newline}"
        for key in ("memory_id", "temporal_policy", "review_after_days")
        if key in candidate
    )
    boundary = closing + len(newline)
    return base_text[:boundary] + insertion + base_text[boundary:]


def _frontmatter_scalar_replacement(
    base_text: str,
    *,
    key: str,
    value: str,
    allow_insert: bool,
) -> str:
    """Replace one simple scalar while preserving every unrelated byte."""

    if base_text.startswith("---\r\n"):
        newline = "\r\n"
    elif base_text.startswith("---\n"):
        newline = "\n"
    else:
        _raise("FRONTMATTER_INVALID")
    opening_size = 3 + len(newline)
    closing = base_text.find(newline + "---", opening_size)
    if closing < 0:
        _raise("FRONTMATTER_INVALID")
    head = base_text[opening_size:closing]
    pattern = re.compile(rf"(?m)^{re.escape(key)}:[ \t]*[^\r\n]*")
    matches = list(pattern.finditer(head))
    if len(matches) > 1:
        _raise("TEMPORAL_METADATA_INVALID")
    if not matches:
        if not allow_insert:
            _raise("TEMPORAL_METADATA_INVALID")
        boundary = closing + len(newline)
        return (
            base_text[:boundary]
            + f"{key}: {value}{newline}"
            + base_text[boundary:]
        )
    match = matches[0]
    replacement = f"{key}: {value}"
    updated_head = head[: match.start()] + replacement + head[match.end() :]
    return base_text[:opening_size] + updated_head + base_text[closing:]


def _exact_risk_class_upgrade(
    *,
    base_text: str,
    proposal_text: str,
    target_status: str = "",
) -> bool:
    """Prove one byte-preserving missing/blank risk-class upgrade.

    The only accepted risk change is an absent or blank ``risk_class`` becoming
    the canonical ``action_sensitive`` scalar.  A status transition may bind
    the same upgrade only while changing ``active`` to
    ``pending_verification``.  Reconstructing the complete expected proposal
    from the immutable base makes comments, key order, newline style, duplicate
    fields, body bytes, and every unrelated frontmatter field fail closed.
    """

    if not base_text or not proposal_text:
        return False
    try:
        base_meta = _temporal_parse_frontmatter(base_text)
        proposal_meta = _temporal_parse_frontmatter(proposal_text)
    except MemoryWriteError:
        return False
    base_risk = memory_index.as_text(base_meta.get("risk_class")).strip().casefold()
    proposal_risk = memory_index.as_text(proposal_meta.get("risk_class")).strip().casefold()
    if base_risk or proposal_risk != "action_sensitive":
        return False
    try:
        expected = base_text
        if target_status:
            if (
                target_status != "pending_verification"
                or memory_index.as_text(base_meta.get("status"), "active").strip().casefold()
                != "active"
                or memory_index.as_text(
                    proposal_meta.get("status"), "active"
                ).strip().casefold()
                != target_status
            ):
                return False
            expected = _frontmatter_scalar_replacement(
                expected,
                key="status",
                value=target_status,
                allow_insert=False,
            )
        expected = _frontmatter_scalar_replacement(
            expected,
            key="risk_class",
            value="action_sensitive",
            allow_insert="risk_class" not in base_meta,
        )
    except MemoryWriteError:
        return False
    return proposal_text == expected


def _risk_v4_recommendation(*, rel_path: str, base_text: str) -> dict[str, str]:
    """Derive the only safe risk follow-up for one governed document."""

    parse_text = (
        base_text.replace("\r\n", "\n")
        if base_text.startswith("---\r\n")
        else base_text
    )
    meta = memory_index.parse_frontmatter(parse_text)
    if not meta or not base_text.startswith(("---\n", "---\r\n")):
        _raise("FRONTMATTER_INVALID")
    current = memory_index.as_text(meta.get("risk_class")).strip().casefold()
    if current and current not in {"ordinary", "action_sensitive"}:
        _raise("TEMPORAL_METADATA_INVALID")
    target_path = memory_index.VAULT_ROOT / Path(rel_path)
    memory_type, _track, _project, status = memory_index.infer_from_path(
        target_path,
        meta,
    )
    floor = _canonical_path_policy_floor(rel_path)
    floor_track = str(floor.get("track", ""))
    fact = memory_index.fact_metadata(meta)
    fact_key_signal = memory_index.as_text(meta.get("fact_key")).strip()
    valid_from_signal = memory_index.as_text(meta.get("valid_from")).strip()
    valid_until_signal = memory_index.as_text(meta.get("valid_until")).strip()
    temporal_policy, _source = memory_index.temporal_policy_for(
        meta,
        memory_type=memory_type,
        status=status,
        fact=fact,
    )
    action_signal = bool(
        floor_track == "decision"
        or memory_type in ACTION_SENSITIVE_MEMORY_TYPES
        or temporal_policy == "expiring"
        or bool(fact_key_signal)
        or bool(valid_from_signal)
        or bool(valid_until_signal)
        or bool(fact.get("enabled"))
        or "事实-" in Path(rel_path).stem
        or current == "action_sensitive"
    )
    risk_required = floor_track in {"project", "workflow", "decision"}
    recommended = "action_sensitive" if action_signal else (
        "ordinary" if risk_required else ""
    )
    # Absence of a sensitive signal is not evidence that a document is
    # ordinary.  Likewise, an explicit ordinary classification contradicted
    # by sensitive metadata needs human adjudication.  The migration helper
    # therefore automates only risk-raising/quarantine paths.
    if (not current and not action_signal) or (
        current == "ordinary" and action_signal
    ):
        return {
            "current": current,
            "recommended": recommended if action_signal else "",
            "operation": "manual_review",
            "target_status": "",
        }
    atomic_gap = bool(action_signal and not str(fact.get("fact_key", "")).strip())
    normalized_status = str(status or "active").casefold()
    if normalized_status not in {"active", "pending_verification"}:
        return {
            "current": current,
            "recommended": recommended,
            "operation": "manual_review",
            "target_status": "",
        }
    verified_at = memory_index.as_text(meta.get("verified_at")).strip()
    verified_date, verified_error = memory_index.temporal_date(verified_at)
    review_raw = memory_index.as_text(meta.get("review_after_days")).strip()
    review_days = int(review_raw) if review_raw.isdigit() else 0
    active_unverified = bool(
        normalized_status == "active"
        and temporal_policy in {"stable", "reviewable", "expiring"}
        and (verified_error or verified_date > dt.date.today().isoformat())
    )
    review_overdue = bool(
        normalized_status == "active"
        and not verified_error
        and review_days > 0
        and (
            dt.date.today() - dt.date.fromisoformat(verified_date)
        ).days > review_days
    )
    normalized_valid_until, valid_until_error = memory_index.temporal_date(
        valid_until_signal
    )
    expired = bool(
        normalized_status == "active"
        and valid_until_signal
        and not valid_until_error
        and normalized_valid_until < dt.date.today().isoformat()
    )
    operation = (
        "status_transition"
        if (
            action_signal
            and normalized_status == "active"
            and (atomic_gap or active_unverified or review_overdue or expired)
        )
        else "content_update"
    )
    if operation != "status_transition":
        if not recommended or current == recommended:
            _raise("GOVERNANCE_MIGRATION_NOT_REQUIRED")
        if current == "action_sensitive" and recommended == "ordinary":
            _raise("PATH_POLICY_DOWNGRADE_FORBIDDEN")
    return {
        "current": current,
        "recommended": recommended,
        "operation": operation,
        "target_status": "pending_verification" if operation == "status_transition" else "",
    }


def _risk_v4_proposal(*, rel_path: str, base_text: str) -> str:
    recommendation = _risk_v4_recommendation(
        rel_path=rel_path,
        base_text=base_text,
    )
    if recommendation["operation"] == "manual_review":
        _raise("RISK_CLASS_REQUIRED")
    if recommendation["operation"] == "status_transition":
        proposal = _frontmatter_scalar_replacement(
            base_text,
            key="status",
            value="pending_verification",
            allow_insert=False,
        )
        if not recommendation["current"]:
            proposal = _frontmatter_scalar_replacement(
                proposal,
                key="risk_class",
                value="action_sensitive",
                allow_insert=True,
            )
        return proposal
    return _frontmatter_scalar_replacement(
        base_text,
        key="risk_class",
        value=recommendation["recommended"],
        allow_insert=not bool(recommendation["current"]),
    )


def _validate_status_transition(
    *,
    base_text: str,
    proposal_text: str,
    target_status: str,
    evidence_ref: str,
) -> dict[str, str]:
    base_meta = _temporal_parse_frontmatter(base_text)
    proposal_meta = _temporal_parse_frontmatter(proposal_text)
    current_status = memory_index.as_text(base_meta.get("status"), "active").strip().casefold()
    proposal_status = memory_index.as_text(proposal_meta.get("status"), "active").strip().casefold()
    if target_status not in STATUS_TRANSITIONS.get(current_status, set()) or proposal_status != target_status:
        _raise("STATUS_TRANSITION_FORBIDDEN")
    if _temporal_body_without_frontmatter(
        base_text
    ) != _temporal_body_without_frontmatter(proposal_text):
        _raise("STATUS_TRANSITION_INVALID")
    base_comparable = dict(base_meta)
    proposal_comparable = dict(proposal_meta)
    base_comparable.pop("status", None)
    proposal_comparable.pop("status", None)
    if target_status == "active":
        base_comparable.pop("verified_at", None)
        proposal_comparable.pop("verified_at", None)
    exact_atomic_risk_quarantine = _exact_risk_class_upgrade(
        base_text=base_text,
        proposal_text=proposal_text,
        target_status=target_status,
    )
    if base_comparable != proposal_comparable and not exact_atomic_risk_quarantine:
        _raise("STATUS_TRANSITION_INVALID")
    if _memory_id_from_text(base_text) != _memory_id_from_text(proposal_text):
        _raise("MEMORY_ID_CHANGE_FORBIDDEN")
    if target_status == "active":
        verified_at = memory_index.as_text(proposal_meta.get("verified_at")).strip()
        verified_at, verified_error = memory_index.temporal_date(verified_at)
        if verified_error:
            _raise("STATUS_REACTIVATION_EVIDENCE_REQUIRED")
        base_verified = memory_index.as_text(base_meta.get("verified_at")).strip()
        normalized_base, base_error = memory_index.temporal_date(base_verified)
        if (
            verified_at > dt.date.today().isoformat()
            or verified_at == base_verified
            or (not base_error and verified_at <= normalized_base)
            or not evidence_ref
        ):
            _raise("STATUS_REACTIVATION_EVIDENCE_REQUIRED")
    return {"from_status": current_status, "target_status": target_status}


def _validate_write_temporal_gate(
    *,
    proposal_text: str,
    knowledge_kind: str,
    evidence_ref: str,
    operation: str,
    governance_target: bool = False,
    target_relative_path: str = "",
) -> None:
    """Enforce explicit write-time policy without index-derived defaults."""

    try:
        parse_text = memory_retrieve._frontmatter_text(proposal_text)
    except memory_retrieve.RetrievalProtocolError as exc:
        raise MemoryWriteError(exc.code, _error_message(exc.code)) from exc
    # Legacy scope migration is an exact, body-preserving metadata repair.  It
    # must remain possible before the separate governance migration adds the
    # v4 temporal policy and stable memory identity.
    if operation == "legacy_scope_migration" or governance_target:
        return
    meta = memory_index.parse_frontmatter(parse_text)
    status = memory_index.as_text(meta.get("status"), "active").strip().casefold()
    if status != "active":
        return
    declared_memory_type = memory_index.as_text(meta.get("memory_type")).strip().casefold()
    declared_track = memory_index.as_text(meta.get("track")).strip().casefold()
    path_floor = _canonical_path_policy_floor(target_relative_path)
    if bool(path_floor.get("supporting")):
        return
    floor_type = str(path_floor.get("memory_type", ""))
    floor_track = str(path_floor.get("track", ""))
    if floor_track in {"project", "workflow", "decision"}:
        if declared_track and declared_track != floor_track:
            _raise("PATH_POLICY_DOWNGRADE_FORBIDDEN")
        allowed_raised_types = ACTION_SENSITIVE_MEMORY_TYPES | {"decision"}
        if declared_memory_type and declared_memory_type not in {
            floor_type,
            *allowed_raised_types,
        }:
            _raise("PATH_POLICY_DOWNGRADE_FORBIDDEN")
        memory_type = declared_memory_type or floor_type
        track = floor_track
    else:
        memory_type = declared_memory_type
        track = declared_track or memory_type
        # Frontmatter never mints a root-governance capability.
        if memory_type == "governance":
            _raise("PATH_POLICY_DOWNGRADE_FORBIDDEN")
        if memory_type in {"routing", "directory_index", "template"}:
            return
    temporal_policy = memory_index.as_text(meta.get("temporal_policy")).strip().casefold()
    if temporal_policy not in memory_index.TEMPORAL_POLICIES:
        _raise("TEMPORAL_POLICY_REQUIRED")
    review_after = memory_index.as_text(meta.get("review_after_days")).strip()
    if re.fullmatch(r"[1-9][0-9]{0,3}", review_after) is None or int(review_after) > 3650:
        _raise("REVIEW_POLICY_REQUIRED")

    risk_class = memory_index.as_text(meta.get("risk_class")).strip().casefold()
    if (
        operation != "governance_migration"
        and track in {"project", "workflow", "decision"}
        and not risk_class
    ):
        _raise("RISK_CLASS_REQUIRED")
    if risk_class not in {"", "ordinary", "action_sensitive"}:
        _raise("TEMPORAL_METADATA_INVALID")
    normalized_kind = str(knowledge_kind or "").strip().casefold()
    fact = memory_index.fact_metadata(meta)
    verified_at_raw = memory_index.as_text(meta.get("verified_at")).strip()
    valid_from = memory_index.as_text(meta.get("valid_from")).strip()
    valid_until = memory_index.as_text(meta.get("valid_until")).strip()
    path_fact_signal = bool(
        target_relative_path and "事实-" in Path(target_relative_path).stem
    )
    explicit_temporal_fact = memory_index.is_explicitly_action_sensitive(
        status=status,
        memory_type=memory_type,
        temporal_policy=temporal_policy,
        fact_key=meta.get("fact_key"),
        valid_from=meta.get("valid_from"),
        valid_until=meta.get("valid_until"),
        rel_path=target_relative_path,
    )
    # Fact and expiry signals apply to every non-supporting track. A user or
    # agent path cannot turn an action-sensitive atomic fact into an ordinary
    # structural note merely by moving it outside project/workflow/decision.
    explicit_fact_signal = bool(
        normalized_kind == "fact"
        or memory_type in ACTION_SENSITIVE_MEMORY_TYPES
        or temporal_policy == "expiring"
        or bool(valid_until)
        or bool(fact.get("enabled"))
        or path_fact_signal
    )
    action_sensitive = bool(
        operation != "governance_migration"
        and (
            # Explicit classification is authoritative on every governed
            # track, including user and agent memories.
            risk_class == "action_sensitive"
            or explicit_temporal_fact
            or explicit_fact_signal
            or track == "decision"
        )
    )
    temporal_conflict = bool(
        operation != "governance_migration"
        and (
            temporal_policy == "snapshot"
            or (
                temporal_policy == "structural"
                and (
                    verified_at_raw
                    or valid_from
                    or valid_until
                    or action_sensitive
                )
            )
        )
    )
    if not action_sensitive:
        if temporal_conflict:
            _raise("TEMPORAL_METADATA_INVALID")
        return
    if risk_class != "action_sensitive":
        _raise("PATH_POLICY_DOWNGRADE_FORBIDDEN")
    if temporal_conflict:
        _raise("TEMPORAL_METADATA_INVALID")
    # Durable provenance, Doctor and Audit all recognize only a canonical
    # fact receipt for content that may authorize an action. Treat the
    # caller-supplied kind as part of that contract rather than merely as a
    # risk-raising signal; otherwise a complete action-sensitive document
    # could be written with a ``rule`` receipt that can never satisfy the
    # current-content evidence gate.
    if normalized_kind != "fact":
        _raise("ACTION_SENSITIVE_FACT_REQUIRED")
    current_date = dt.date.today()
    verified_at, verified_error = memory_index.temporal_date(meta.get("verified_at"))
    normalized_valid_until = str(fact.get("valid_until", ""))
    expired_fact = bool(
        normalized_valid_until
        and not bool(fact.get("errors"))
        and normalized_valid_until < current_date.isoformat()
    )
    review_overdue_fact = bool(
        not verified_error
        and (
            current_date - dt.date.fromisoformat(verified_at)
        ).days > int(review_after)
    )
    if (
        not bool(fact.get("enabled"))
        or bool(fact.get("errors"))
        or verified_error
        or verified_at < str(fact.get("valid_from", ""))
        or verified_at > current_date.isoformat()
        or not evidence_ref
        or (temporal_policy == "expiring" and not valid_until)
        or expired_fact
        or review_overdue_fact
    ):
        _raise("ACTION_SENSITIVE_FACT_REQUIRED")


def _temporal_parse_frontmatter(text: str) -> dict[str, object]:
    try:
        parse_text = memory_retrieve._frontmatter_text(text)
    except memory_retrieve.RetrievalProtocolError as exc:
        _raise(exc.code)
    return memory_index.parse_frontmatter(parse_text)


def _temporal_body_without_frontmatter(text: str) -> str:
    """Return the exact body after strict LF/CRLF/CR frontmatter fences."""

    cursor = 1 if text.startswith("\ufeff") else 0
    opening = re.match(r"([^\r\n]*)(\r\n|\n|\r)", text[cursor:])
    if opening is None or opening.group(1) != "---":
        _raise("FRONTMATTER_INVALID")
    cursor += opening.end()
    while cursor <= len(text):
        line = re.match(r"([^\r\n]*)(\r\n|\n|\r|\Z)", text[cursor:])
        if line is None:
            break
        content = line.group(1)
        if content.startswith("---"):
            if content != "---":
                _raise("FRONTMATTER_INVALID")
            return text[cursor + line.end() :]
        ending = line.group(2)
        if not ending:
            break
        cursor += line.end()
    _raise("FRONTMATTER_INVALID")


def _temporal_row(relative_path: str, text: str) -> dict[str, str] | None:
    meta = _temporal_parse_frontmatter(text)
    temporal = memory_index.fact_metadata(meta)
    if not bool(temporal["enabled"]):
        return None
    return {
        "rel_path": relative_path,
        "sha256": memory_index.sha256_text(text),
        "memory_type": (
            "template"
            if Path(relative_path).name.startswith("_模板")
            else memory_index.as_text(meta.get("memory_type"))
        ),
        "status": memory_index.as_text(meta.get("status"), "active").casefold(),
        "fact_key": str(temporal["fact_key"]),
        "valid_from": str(temporal["valid_from"]),
        "valid_until": str(temporal["valid_until"]),
        "supersedes": ", ".join(str(item) for item in temporal["supersedes"]),
        "app_id": memory_index.as_text(meta.get("app_id"), memory_index.DEFAULT_APP_ID),
        "project_id": memory_index.as_text(meta.get("project_id")),
        "user_id": memory_index.as_text(meta.get("user_id"), memory_index.DEFAULT_USER_ID),
        "agent_scope": memory_index.as_text(meta.get("agent_scope"), "shared"),
        "metadata_errors": ",".join(str(item) for item in temporal["errors"]),
    }


def _live_temporal_rows(
    selected_target: write_intent.CanonicalTarget,
    proposal_text: str,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    try:
        vault_root = write_intent.VAULT_ROOT.resolve(strict=True)
        paths = sorted(vault_root.rglob("*.md"))
    except OSError:
        _raise("TEMPORAL_SCAN_UNAVAILABLE", retryable=True)
    for path in paths:
        try:
            relative_path = path.relative_to(vault_root).as_posix()
        except ValueError:
            _raise("TEMPORAL_SCAN_UNAVAILABLE", retryable=True)
        if relative_path == selected_target.rel_path:
            continue
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                _raise("TEMPORAL_SCAN_UNAVAILABLE", retryable=True)
            if metadata.st_size > write_intent.MAX_TARGET_BYTES:
                _raise("TEMPORAL_SCAN_UNAVAILABLE", retryable=True)
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError):
            _raise("TEMPORAL_SCAN_UNAVAILABLE", retryable=True)
        row = _temporal_row(relative_path, text)
        if row is not None:
            rows.append(row)
    proposal_row = _temporal_row(selected_target.rel_path, proposal_text)
    if proposal_row is not None:
        rows.append(proposal_row)
    return rows


_METADATA_ONLY_HISTORICAL_FACT_STATUSES = frozenset({"superseded"})
_STATUS_TRANSITION_NON_CURRENT_FACT_STATUSES = frozenset({"historical", "superseded"})


def _temporal_relation_signature(relation: dict[str, str]) -> tuple[str, ...]:
    return tuple(
        str(relation.get(key, ""))
        for key in (
            "source_rel_path",
            "target_rel_path",
            "source_fact_key",
            "target_fact_key",
            "source_valid_from",
            "target_valid_from",
            "effective_from",
            "source_status",
            "target_status",
            "relation_status",
            "reason_code",
        )
    )


def _temporal_state_signature(state: dict[str, str]) -> tuple[str, ...]:
    return tuple(
        str(state.get(key, ""))
        for key in (
            "fact_status",
            "current_rel_path",
            "superseded_by",
            "effective_from",
            "reason_code",
        )
    )


def _allows_metadata_only_historical_fact_preservation(
    *,
    selected_target: write_intent.CanonicalTarget,
    base_text: str,
    proposal_text: str,
    base_meta: dict[str, object],
    proposal_meta: dict[str, object],
    base_temporal: dict[str, object],
    proposal_temporal: dict[str, object],
    proposal_rows: list[dict[str, str]],
    proposal_relations: list[dict[str, str]],
    proposal_states: list[dict[str, str]],
) -> bool:
    """Allow only a semantics-preserving update to an already historical fact.

    This is deliberately narrower than an ordinary fact transition.  It exists
    so governance can add document metadata (for example ``memory_id`` and an
    explicit ``temporal_policy``) without pretending that an explicitly
    superseded fact became current again.  Facts, scopes, dates, status, and the
    complete local relation projection must remain identical.
    """

    if not bool(base_temporal.get("enabled")) or base_temporal.get("errors"):
        return False
    if proposal_temporal.get("errors"):
        return False
    if _temporal_body_without_frontmatter(base_text) != _temporal_body_without_frontmatter(proposal_text):
        return False
    for key in ("fact_key", "valid_from", "valid_until"):
        if str(base_temporal.get(key, "")) != str(proposal_temporal.get(key, "")):
            return False
    if tuple(sorted(str(item) for item in base_temporal.get("supersedes", []))) != tuple(
        sorted(str(item) for item in proposal_temporal.get("supersedes", []))
    ):
        return False
    base_verified_at, base_verified_error = memory_index.temporal_date(base_meta.get("verified_at"))
    proposal_verified_at, proposal_verified_error = memory_index.temporal_date(
        proposal_meta.get("verified_at")
    )
    if (
        base_verified_error
        or proposal_verified_error
        or base_verified_at != proposal_verified_at
        or base_verified_at < str(base_temporal.get("valid_from", ""))
    ):
        return False

    base_row = _temporal_row(selected_target.rel_path, base_text)
    proposal_row = next(
        (row for row in proposal_rows if row["rel_path"] == selected_target.rel_path),
        None,
    )
    if base_row is None or proposal_row is None:
        return False
    if memory_index._fact_scope(base_row) != memory_index._fact_scope(proposal_row):
        return False
    if str(base_row["status"]) != str(proposal_row["status"]):
        return False

    base_rows = _live_temporal_rows(selected_target, base_text)
    base_relations, base_states = memory_index.build_temporal_projection(base_rows, utc_now())
    base_state = next(
        (state for state in base_states if state["rel_path"] == selected_target.rel_path),
        None,
    )
    proposal_state = next(
        (state for state in proposal_states if state["rel_path"] == selected_target.rel_path),
        None,
    )
    if base_state is None or proposal_state is None:
        return False
    if (
        str(base_state["fact_status"]) not in _METADATA_ONLY_HISTORICAL_FACT_STATUSES
        or _temporal_state_signature(base_state) != _temporal_state_signature(proposal_state)
    ):
        return False

    def relevant_signatures(relations: list[dict[str, str]]) -> tuple[tuple[str, ...], ...]:
        relevant = [
            relation
            for relation in relations
            if relation["source_rel_path"] == selected_target.rel_path
            or relation["target_rel_path"] == selected_target.rel_path
        ]
        if any(relation["relation_status"] != "effective" for relation in relevant):
            return ()
        return tuple(sorted(_temporal_relation_signature(relation) for relation in relevant))

    base_relation_signatures = relevant_signatures(base_relations)
    proposal_relation_signatures = relevant_signatures(proposal_relations)
    return bool(base_relation_signatures) and base_relation_signatures == proposal_relation_signatures


def _allows_pending_fact_risk_only_update(
    *,
    selected_target: write_intent.CanonicalTarget,
    base_text: str,
    proposal_text: str,
    base_meta: dict[str, object],
    proposal_meta: dict[str, object],
    proposal_rows: list[dict[str, str]],
    proposal_relations: list[dict[str, str]],
    proposal_states: list[dict[str, str]],
) -> bool:
    """Allow exactly one risk-class upgrade on a quarantined fact.

    ``pending_verification`` facts are intentionally non-current, so an
    ordinary content update is rejected by the temporal graph.  This narrow
    exception lets the governance migration finish a missing risk
    classification without changing the fact, its scope, its evidence dates,
    or any lineage edge.  It applies both to the latest quarantined fact
    (``historical``) and to a quarantined predecessor (``superseded``).
    """

    if (
        memory_index.as_text(base_meta.get("status"), "active").strip().casefold()
        != "pending_verification"
        or memory_index.as_text(
            proposal_meta.get("status"), "active"
        ).strip().casefold()
        != "pending_verification"
        or not _exact_risk_class_upgrade(
            base_text=base_text,
            proposal_text=proposal_text,
        )
    ):
        return False
    proposal_row = next(
        (
            row
            for row in proposal_rows
            if row["rel_path"] == selected_target.rel_path
        ),
        None,
    )
    if proposal_row is None or proposal_row["status"] != "pending_verification":
        return False

    base_rows = _live_temporal_rows(selected_target, base_text)
    base_relations, base_states = memory_index.build_temporal_projection(
        base_rows,
        utc_now(),
    )
    base_state = next(
        (state for state in base_states if state["rel_path"] == selected_target.rel_path),
        None,
    )
    proposal_state = next(
        (
            state
            for state in proposal_states
            if state["rel_path"] == selected_target.rel_path
        ),
        None,
    )
    if (
        base_state is None
        or proposal_state is None
        or str(base_state["fact_status"])
        not in _STATUS_TRANSITION_NON_CURRENT_FACT_STATUSES
        or _temporal_state_signature(base_state)
        != _temporal_state_signature(proposal_state)
    ):
        return False

    def relevant_signatures(
        relations: list[dict[str, str]],
    ) -> tuple[tuple[str, ...], ...] | None:
        relevant = [
            relation
            for relation in relations
            if relation["source_rel_path"] == selected_target.rel_path
            or relation["target_rel_path"] == selected_target.rel_path
        ]
        if any(relation["relation_status"] != "effective" for relation in relevant):
            return None
        return tuple(
            sorted(_temporal_relation_signature(relation) for relation in relevant)
        )

    return relevant_signatures(base_relations) == relevant_signatures(proposal_relations)


def _validate_temporal_transition(
    *,
    selected_target: write_intent.CanonicalTarget,
    base_text: str,
    proposal_text: str,
    operation: str = "",
    validated_status_transition: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Validate an explicit one-fact-per-file transition from live Markdown."""

    proposal_meta = _temporal_parse_frontmatter(proposal_text)
    proposal_temporal = memory_index.fact_metadata(proposal_meta)
    base_meta = _temporal_parse_frontmatter(base_text) if base_text else {}
    base_temporal = memory_index.fact_metadata(base_meta) if base_text else {
        "enabled": False,
        "fact_key": "",
        "valid_from": "",
        "supersedes": [],
        "errors": [],
    }
    if not bool(proposal_temporal["enabled"]):
        if bool(base_temporal["enabled"]):
            _raise("FACT_IDENTITY_CHANGE_FORBIDDEN")
        return {"enabled": False, "fact_key": "", "supersedes": [], "fact_status": "not_fact"}
    if proposal_temporal["errors"]:
        _raise("TEMPORAL_METADATA_INVALID")
    verified_at, verified_error = memory_index.temporal_date(proposal_meta.get("verified_at"))
    if verified_error or verified_at < str(proposal_temporal["valid_from"]):
        _raise("TEMPORAL_METADATA_INVALID")
    if str(proposal_temporal["valid_from"]) > dt.datetime.now().date().isoformat():
        _raise("TEMPORAL_METADATA_INVALID")
    if bool(base_temporal["enabled"]):
        if (
            str(base_temporal["fact_key"]) != str(proposal_temporal["fact_key"])
            or str(base_temporal["valid_from"]) != str(proposal_temporal["valid_from"])
        ):
            _raise("FACT_IDENTITY_CHANGE_FORBIDDEN")
        if _temporal_body_without_frontmatter(base_text) != _temporal_body_without_frontmatter(
            proposal_text
        ):
            _raise("FACT_VALUE_CHANGE_FORBIDDEN")
        base_edges = set(str(item) for item in base_temporal["supersedes"])
        proposal_edges = set(str(item) for item in proposal_temporal["supersedes"])
        if not base_edges <= proposal_edges:
            _raise("FACT_RELATION_REMOVAL_FORBIDDEN")

    rows = _live_temporal_rows(selected_target, proposal_text)
    relations, states = memory_index.build_temporal_projection(rows, utc_now())
    relevant_relations = [
        relation
        for relation in relations
        if relation["source_rel_path"] == selected_target.rel_path
        or relation["target_rel_path"] == selected_target.rel_path
    ]
    if any(relation["relation_status"] != "effective" for relation in relevant_relations):
        _raise("TEMPORAL_RELATION_INVALID")
    proposal_state = next(
        (state for state in states if state["rel_path"] == selected_target.rel_path),
        None,
    )
    if proposal_state is None:
        _raise("TEMPORAL_METADATA_INVALID")
    proposal_row = next(row for row in rows if row["rel_path"] == selected_target.rel_path)
    relevant_paths = {
        row["rel_path"]
        for row in rows
        if row["fact_key"] == proposal_row["fact_key"]
        and memory_index._fact_scope(row) == memory_index._fact_scope(proposal_row)
    }
    same_key_states = [state for state in states if state["rel_path"] in relevant_paths]
    if any(state["fact_status"] in {"conflict", "invalid_metadata", "invalid_relation"} for state in same_key_states):
        _raise("TEMPORAL_RELATION_INVALID")
    if proposal_state["fact_status"] != "current":
        status_transition_preserves_lineage = bool(
            operation == "status_transition"
            and validated_status_transition
            == {
                "from_status": memory_index.as_text(
                    base_meta.get("status"), "active"
                ).strip().casefold(),
                "target_status": memory_index.as_text(
                    proposal_meta.get("status"), "active"
                ).strip().casefold(),
            }
            and str(validated_status_transition.get("target_status", ""))
            in memory_index.FACT_LINEAGE_SOURCE_STATUSES - {"active"}
            and str(proposal_state["fact_status"])
            in _STATUS_TRANSITION_NON_CURRENT_FACT_STATUSES
        )
        governance_preserves_history = bool(
            operation == "governance_migration"
            and _allows_metadata_only_historical_fact_preservation(
                selected_target=selected_target,
                base_text=base_text,
                proposal_text=proposal_text,
                base_meta=base_meta,
                proposal_meta=proposal_meta,
                base_temporal=base_temporal,
                proposal_temporal=proposal_temporal,
                proposal_rows=rows,
                proposal_relations=relations,
                proposal_states=states,
            )
        )
        pending_fact_risk_only_update = bool(
            operation == "content_update"
            and _allows_pending_fact_risk_only_update(
                selected_target=selected_target,
                base_text=base_text,
                proposal_text=proposal_text,
                base_meta=base_meta,
                proposal_meta=proposal_meta,
                proposal_rows=rows,
                proposal_relations=relations,
                proposal_states=states,
            )
        )
        if not (
            status_transition_preserves_lineage
            or governance_preserves_history
            or pending_fact_risk_only_update
        ):
            _raise("TEMPORAL_RELATION_INVALID")
    return {
        "enabled": True,
        "fact_key": str(proposal_temporal["fact_key"]),
        "supersedes": list(proposal_temporal["supersedes"]),
        "fact_status": str(proposal_state["fact_status"]),
    }


def _read_token(
    target: write_intent.CanonicalTarget,
    *,
    app_id: str,
    project_id: str,
    exists: bool,
    digest: write_intent.ContentDigest,
    git_head: str,
    raw_session_id: str,
) -> str:
    material = json.dumps(
        {
            "schema": "agent-memory-read-token-v2",
            "actor": ACTOR,
            "target_key": target.target_key,
            "relative_path": target.rel_path,
            "app_id": app_id,
            "project_id": project_id,
            "base_exists": bool(exists),
            "base_raw_sha256": digest.raw_sha256,
            "base_canonical_sha256": digest.canonical_sha256,
            "base_git_head": git_head,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(raw_session_id.encode("utf-8"), material, hashlib.sha256).hexdigest()


def _target_snapshot(
    target: write_intent.CanonicalTarget,
    *,
    app_id: str,
    project_id: str,
    host_read: bool,
    raw_session_id: str,
    allow_supporting_document: bool = False,
    allowed_statuses: set[str] | None = None,
) -> tuple[bool, write_intent.ContentDigest, str, str]:
    exists, digest = _read_host_target(target) if host_read else _target_digest(target)
    if exists:
        _validate_writer_markdown(
            digest.text,
            path=target.path,
            app_id=app_id,
            project_id=project_id,
            require_explicit_write_scope=False,
            allow_supporting_document=allow_supporting_document,
            allowed_statuses=allowed_statuses,
        )
    try:
        git_head = write_intent.current_git_head(required=True)
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    return exists, digest, git_head, _read_token(
        target,
        app_id=app_id,
        project_id=project_id,
        exists=exists,
        digest=digest,
        git_head=git_head,
        raw_session_id=raw_session_id,
    )


def _external_dirty_against_head(
    target: write_intent.CanonicalTarget,
    current: write_intent.ContentDigest,
    git_head: str,
) -> bool:
    """Return true only for bytes that are not the clean Git HEAD checkout.

    A missing HEAD blob represents an externally created/untracked target. For
    an existing blob, require both a raw-byte difference and Git's filter-aware
    dirty check so a clean CRLF or smudge-filter checkout is not misclassified
    as an external edit.
    """

    try:
        repo_rel_path = write_intent._repo_rel_path(target)
        head_blob = write_intent._git_blob(git_head, repo_rel_path)
    except (OSError, write_intent.IntentError) as exc:
        raise MemoryWriteError("GIT_BASE_UNAVAILABLE", _error_message("STALE_BASE")) from exc
    if head_blob is None:
        return True
    try:
        head_digest = write_intent.content_hashes(
            head_blob,
            max_bytes=write_intent.MAX_TARGET_BYTES,
        )
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    if head_digest.raw_sha256 == current.raw_sha256:
        return False
    return not write_intent._git_path_matches_worktree(git_head, repo_rel_path)


def _formal_target(raw_target: str) -> write_intent.CanonicalTarget:
    try:
        target = write_intent.canonical_target(raw_target)
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    relative = Path(target.rel_path)
    is_governance = target.rel_path in GOVERNANCE_MEMORY_FILES
    if not is_governance and not memory_index.is_formal_body_document(relative):
        raise MemoryWriteError(
            "TARGET_NOT_FORMAL_MEMORY",
            "目标必须位于正式 Agent Memory 目录。",
        )
    if not target.path.parent.is_dir():
        _raise("TARGET_PARENT_MISSING")
    return target


def _recovery_target(raw_target: str) -> write_intent.CanonicalTarget:
    """Resolve a previously validated target even if its parent disappeared."""

    try:
        target = write_intent.canonical_target(raw_target)
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    relative = Path(target.rel_path)
    is_governance = target.rel_path in GOVERNANCE_MEMORY_FILES
    if not is_governance and not memory_index.is_formal_body_document(relative):
        raise MemoryWriteError(
            "TARGET_NOT_FORMAL_MEMORY",
            "目标必须位于正式 Agent Memory 目录。",
        )
    return target


def _target_digest(target: write_intent.CanonicalTarget) -> tuple[bool, write_intent.ContentDigest]:
    try:
        exists, digest = write_intent._read_target(target)  # Shared canonical read boundary.
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    return exists, digest


def _read_host_target(
    target: write_intent.CanonicalTarget,
) -> tuple[bool, write_intent.ContentDigest]:
    """Read one formal target exactly, without touching runtime state or logs."""
    if not target.path.exists():
        return False, write_intent.content_hashes(b"")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(target.path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            _raise("TARGET_NOT_FILE")
        if metadata.st_size > MAX_HOST_TARGET_BYTES:
            _raise("TARGET_TOO_LARGE")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            payload = handle.read(MAX_HOST_TARGET_BYTES + 1)
    except MemoryWriteError:
        raise
    except OSError as exc:
        raise MemoryWriteError(
            "TARGET_UNREADABLE",
            _error_message("TARGET_UNREADABLE"),
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > MAX_HOST_TARGET_BYTES:
        _raise("TARGET_TOO_LARGE")
    try:
        return True, write_intent.content_hashes(payload, max_bytes=MAX_HOST_TARGET_BYTES)
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)


def read_target(request: dict[str, Any], *, raw_session_id: str) -> dict[str, Any]:
    raw_target = _required_string(request, "target_relative_path", max_chars=512)
    target = _formal_target(raw_target)
    migrate_legacy_scope = request.get("migrate_legacy_scope", False)
    if not isinstance(migrate_legacy_scope, bool):
        _raise("REQUEST_INVALID")
    raw_operation = request.get("operation", "")
    if not isinstance(raw_operation, str):
        _raise("REQUEST_INVALID")
    governed_operation = raw_operation.strip().casefold()
    if governed_operation not in {
        "", "content_update", "status_transition", "governance_migration",
    }:
        _raise("REQUEST_INVALID")
    if (
        governed_operation in {"status_transition", "governance_migration"}
        and ACTOR not in {"codex", "claude"}
    ):
        _raise("STATUS_TRANSITION_FORBIDDEN")
    _validate_governance_migration_target(
        target,
        operation=governed_operation,
    )
    app_id, project_id = _scope_request(
        request,
        target=target,
        legacy_scope_migration=migrate_legacy_scope,
        governed_operation=governed_operation,
    )
    exists, digest, git_head, read_token = _target_snapshot(
        target,
        app_id=app_id,
        project_id=project_id,
        host_read=True,
        raw_session_id=raw_session_id,
        allow_supporting_document=_allow_supporting_document(
            target,
            operation=governed_operation,
            legacy_scope_migration=migrate_legacy_scope,
        ),
        allowed_statuses=_existing_statuses_for_operation(governed_operation),
    )
    response = {
        "schema_version": SCHEMA_VERSION,
        "ok": True,
        "stage": "read-target",
        "status": "found" if exists else "missing",
        "target_relative_path": target.rel_path,
        "exists": exists,
        "base_exists": exists,
        "content": digest.text,
        "raw_sha256": digest.raw_sha256,
        "canonical_sha256": digest.canonical_sha256,
        "base_raw_sha256": digest.raw_sha256,
        "base_canonical_sha256": digest.canonical_sha256,
        "size_bytes": digest.size_bytes,
        "git_head": git_head,
        "base_git_head": git_head,
        "read_token": read_token,
        "app_id": app_id,
        "project_id": project_id,
        "scope_migration": migrate_legacy_scope,
    }
    if not _is_governance_target(target.path):
        if not exists:
            response["generated_memory_id"] = _generated_memory_id(read_token)
        else:
            identity_text = (
                digest.text.replace("\r\n", "\n")
                if digest.text.startswith("---\r\n")
                else digest.text
            )
            explicit_memory_id = memory_index.as_text(
                memory_index.parse_frontmatter(identity_text).get("memory_id")
            ).strip()
            if explicit_memory_id:
                response["expected_memory_id"] = explicit_memory_id
            else:
                # Existing legacy documents use a stable path identity.  The
                # governance migrator binds this expected value at read time;
                # unlike a new ADD identity, it must not depend on a session
                # read token.
                response["expected_memory_id"] = memory_index.memory_identity(
                    target.rel_path,
                    {},
                )[0]
    return response


def _safe_candidate(
    row: dict[str, Any],
    *,
    app_id: str,
    project_id: str,
    raw_session_id: str,
) -> dict[str, Any] | None:
    raw_path = str(row.get("rel_path", "")).strip()
    if not raw_path:
        return None
    try:
        target = _formal_target(raw_path)
        exists, digest, _, _ = _target_snapshot(
            target,
            app_id=app_id,
            project_id=project_id,
            host_read=False,
            raw_session_id=raw_session_id,
        )
    except MemoryWriteError:
        return None
    if not exists:
        return None
    material = f"{target.rel_path}\0{digest.raw_sha256}".encode("utf-8")
    return {
        "relative_path": target.rel_path,
        "sha256": digest.raw_sha256,
        "candidate_ref": hashlib.sha256(material).hexdigest()[:20],
    }


def _warning_codes(warnings: list[str]) -> list[str]:
    codes: set[str] = set()
    for warning in warnings:
        lowered = warning.casefold()
        if "missing" in lowered:
            codes.add("SEARCH_INDEX_MISSING")
        elif "timeout" in lowered or "timed out" in lowered:
            codes.add("SEARCH_TIMEOUT")
        elif "failed" in lowered or "non-json" in lowered:
            codes.add("SEARCH_BACKEND_FAILED")
        else:
            codes.add("SEARCH_DEGRADED")
    return sorted(codes)


def _record_prepare_safety(
    assessment: dict[str, Any],
    *,
    raw_session_id: str,
) -> None:
    try:
        memory_safety.record_assessment(
            write_intent.STATE_DB,
            assessment,
            run_id=f"writer-prepare:{uuid.uuid4().hex}",
            actor=ACTOR,
            session_hash=write_intent.session_hash(raw_session_id),
            trigger="writer_prepare",
        )
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise MemoryWriteError(
            "SAFETY_AUDIT_UNAVAILABLE",
            "无法记录来源安全审计，未创建写入提案。",
        ) from exc


def _base_response(
    *,
    status: str,
    action: str,
    digest: write_intent.ContentDigest,
    target: str = "",
    candidates: list[dict[str, Any]] | None = None,
    warning_codes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "ok": True,
        "stage": "prepare",
        "status": status,
        "recommended_action": action,
        "target_relative_path": target,
        "proposal_raw_sha256": digest.raw_sha256,
        "proposal_canonical_sha256": digest.canonical_sha256,
        "proposal_size_bytes": digest.size_bytes,
        "confirmation_required": action in WRITABLE_ACTIONS,
        "candidates": candidates or [],
        "warnings": warning_codes or [],
    }


def _structurally_unique_recommendation(
    *,
    target_relative_path: str,
    target_exists: bool,
    target_canonical_sha256: str,
    proposal_canonical_sha256: str,
    fallback_action: str,
    fallback_recommended_path: str,
) -> tuple[str, str]:
    """Resolve root governance by its unique path without weakening other targets."""

    if target_relative_path not in GOVERNANCE_MEMORY_FILES:
        return fallback_action, fallback_recommended_path
    if target_exists and target_canonical_sha256 == proposal_canonical_sha256:
        return "NOOP", target_relative_path
    return ("UPDATE" if target_exists else "ADD"), target_relative_path


def _promote_user_direct_exact_noop(
    *,
    action: str,
    recommended_target_key: str,
    selected_target_key: str,
    candidate_target_keys: set[str] | None = None,
    target_exists: bool,
    target_canonical_sha256: str,
    proposal_canonical_sha256: str,
    source_class: str,
    asserted_by: str,
) -> str:
    """Treat an exact user-directed textual change as an UPDATE.

    Semantic reconciliation can correctly decide that a redaction or naming
    cleanup preserves the same fact, or can return MERGE_REQUIRED solely because
    its generic coverage threshold is low. Neither result should discard the
    requested byte change when the only reconciled candidate is the already
    CAS-bound target. Promotion is deliberately narrow: the existing target and
    either the recommendation or the sole candidate must be the same canonical
    path, the hashes must differ, and the source metadata must bind the request
    directly to the user. Multiple or cross-target candidates remain blocking.
    """

    exact_target = recommended_target_key == selected_target_key or (
        not recommended_target_key
        and candidate_target_keys == {selected_target_key}
    )
    if (
        action in {"NOOP", "MERGE_REQUIRED"}
        and target_exists
        and target_canonical_sha256 != proposal_canonical_sha256
        and exact_target
        and source_class == "user_direct"
        and asserted_by == "user"
    ):
        return "UPDATE"
    return action


def _legacy_scope_scalar(raw: str) -> str:
    value = unicodedata.normalize("NFKC", raw.strip())
    lowered = value.casefold()
    if (
        not value
        or lowered in {"null", "none", "~"}
        or value.startswith(("[", "{"))
        or any(character in value for character in (",", "|", "\n", "\r", "\x00"))
    ):
        _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
    return lowered


def _legacy_scope_target_allowed(target_relative_path: str) -> tuple[str, ...]:
    relative = Path(target_relative_path)
    parts = relative.parts
    folded = {part.casefold() for part in parts}
    if (
        not memory_index.is_formal_body_document(relative)
        or any(part in {"case-candidates", "skill-candidates"} for part in folded)
    ):
        _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
    return parts


def _legacy_scope_identifiers(
    *,
    actor: str,
    target_relative_path: str,
    requested_app_id: str,
    requested_project_id: str,
    legacy_scope_app_id: str,
) -> tuple[str, str]:
    parts = _legacy_scope_target_allowed(target_relative_path)
    app_id = _legacy_scope_scalar(requested_app_id)
    project_id = _legacy_scope_scalar(requested_project_id)
    legacy_app_id = _legacy_scope_scalar(legacy_scope_app_id)
    if (
        actor not in {"codex", "claude"}
        or legacy_app_id != app_id
        or project_id == "shared"
        or (project_id == "global" and parts[0] != "用户记忆")
    ):
        _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
    return app_id, project_id


def _legacy_scope_proposal(
    *,
    actor: str,
    target_relative_path: str,
    requested_app_id: str,
    requested_project_id: str,
    legacy_scope_app_id: str,
    base_text: str,
) -> str:
    """Return the only allowed metadata-only upgrade for one legacy document."""

    app_id, project_id = _legacy_scope_identifiers(
        actor=actor,
        target_relative_path=target_relative_path,
        requested_app_id=requested_app_id,
        requested_project_id=requested_project_id,
        legacy_scope_app_id=legacy_scope_app_id,
    )
    parts = Path(target_relative_path).parts
    if base_text.startswith("\ufeff"):
        _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")

    normalized = base_text.replace("\r\n", "\n").replace("\r", "\n")
    if normalized.startswith("---\n"):
        try:
            memory_retrieve._frontmatter_text(base_text)
        except memory_retrieve.RetrievalProtocolError as exc:
            raise MemoryWriteError(
                "LEGACY_SCOPE_MIGRATION_FORBIDDEN",
                _error_message("LEGACY_SCOPE_MIGRATION_FORBIDDEN"),
            ) from exc
        meta = memory_index.parse_frontmatter(normalized)
        explicit_status = str(meta.get("status", "")).strip().casefold()
        if explicit_status and explicit_status != "active":
            _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
        explicit_scope = str(meta.get("agent_scope", "")).strip().casefold()
        if explicit_scope and explicit_scope != "shared":
            _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
        app_meta_empty = "app_id" in meta and (
            (isinstance(meta["app_id"], list) and not meta["app_id"])
            or (isinstance(meta["app_id"], str) and not meta["app_id"].strip())
        )
        project_meta_empty = "project_id" in meta and (
            (isinstance(meta["project_id"], list) and not meta["project_id"])
            or (isinstance(meta["project_id"], str) and not meta["project_id"].strip())
        )
        if "app_id" in meta and not app_meta_empty and _legacy_scope_scalar(str(meta["app_id"])) != app_id:
            _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
        if "project_id" in meta and not project_meta_empty and _legacy_scope_scalar(str(meta["project_id"])) != project_id:
            _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
        lines = base_text.splitlines(keepends=True)
        closing = next(
            (index for index, line in enumerate(lines[1:], start=1) if line.rstrip("\r\n") == "---"),
            -1,
        )
        if closing < 0:
            _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
        newline = "\r\n" if lines[0].endswith("\r\n") else "\n"

        # parse_frontmatter represents an empty scalar as [], so inspect the
        # exact top-level source line as well. A truly empty app/project scalar
        # is a deterministic missing value and is filled in place; structured,
        # multi-value, duplicate, or non-empty conflicting values still fail.
        scope_lines: dict[str, tuple[int, str]] = {}
        for index, line in enumerate(lines[1:closing], start=1):
            content = line.rstrip("\r\n")
            if not content or content[0].isspace() or ":" not in content:
                continue
            raw_key, raw_value = content.split(":", 1)
            key = raw_key.strip()
            if key in {"app_id", "project_id"}:
                if key in scope_lines:
                    _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
                scope_lines[key] = (index, raw_value)

        replacements: dict[int, str] = {}
        for key, canonical in (("app_id", app_id), ("project_id", project_id)):
            source = scope_lines.get(key)
            if source is None:
                continue
            index, raw_value = source
            if raw_value.strip():
                if _legacy_scope_scalar(raw_value) != canonical:
                    _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
                continue
            original = lines[index]
            ending = "\r\n" if original.endswith("\r\n") else ("\n" if original.endswith("\n") else ("\r" if original.endswith("\r") else ""))
            replacements[index] = f"{key}: {canonical}{ending}"

        additions: list[str] = []
        if "status" not in meta:
            additions.append(f"status: active{newline}")
        if "agent_scope" not in meta:
            additions.append(f"agent_scope: shared{newline}")
        if "app_id" not in scope_lines:
            additions.append(f"app_id: {app_id}{newline}")
        if "project_id" not in scope_lines:
            additions.append(f"project_id: {project_id}{newline}")
        if not additions and not replacements:
            _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
        for index, replacement in replacements.items():
            lines[index] = replacement
        return "".join(lines[:closing]) + "".join(additions) + "".join(lines[closing:])

    if normalized.startswith("---"):
        _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
    target_path = write_intent.VAULT_ROOT / Path(target_relative_path)
    try:
        memory_type, track, _inferred_project, status = memory_index.infer_from_path(target_path, {})
    except (OSError, ValueError):
        _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
    if status.casefold() != "active":
        _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")
    newline = "\r\n" if "\r\n" in base_text and "\n" in base_text else "\n"
    header = newline.join((
        "---",
        f"memory_type: {memory_type}",
        f"track: {track}",
        f"project_id: {project_id}",
        f"app_id: {app_id}",
        "agent_scope: shared",
        f"status: {status}",
        "---",
        "",
        "",
    ))
    return header + base_text


def _validate_legacy_scope_migration(**kwargs: Any) -> None:
    proposal_text = str(kwargs.pop("proposal_text"))
    expected = _legacy_scope_proposal(**kwargs)
    if proposal_text != expected:
        _raise("LEGACY_SCOPE_MIGRATION_FORBIDDEN")


def prepare(request: dict[str, Any], *, raw_session_id: str) -> dict[str, Any]:
    proposal, digest = _proposal_text(request)
    target_request = _required_string(request, "target_relative_path", max_chars=512)
    selected_target = _formal_target(target_request)
    if selected_target.rel_path == "INDEX.md":
        _raise("GENERATED_FILE_READ_ONLY")
    operation, target_status, transition_reason_sha256 = _status_transition_request(request)
    _validate_governance_migration_target(
        selected_target,
        operation=operation,
    )
    migrate_legacy_scope = request.get("migrate_legacy_scope", False)
    if not isinstance(migrate_legacy_scope, bool):
        _raise("REQUEST_INVALID")
    adopt_external = request.get("adopt_external", False)
    if not isinstance(adopt_external, bool):
        _raise("REQUEST_INVALID")
    app_id, project_id = _scope_request(
        request,
        target=selected_target,
        legacy_scope_migration=migrate_legacy_scope,
        governed_operation=operation,
    )
    legacy_scope_app_id = ""
    if migrate_legacy_scope:
        legacy_scope_app_id = _required_string(request, "legacy_scope_app_id", max_chars=160)
    if operation == "status_transition" and migrate_legacy_scope:
        _raise("STATUS_TRANSITION_INVALID")
    allow_supporting_document = _allow_supporting_document(
        selected_target,
        operation=operation,
        legacy_scope_migration=migrate_legacy_scope,
    )
    raw_read_token = request.get("read_token")
    read_token = raw_read_token.strip() if isinstance(raw_read_token, str) else ""
    if READ_TOKEN_RE.fullmatch(read_token) is None:
        _raise("READ_TOKEN_REQUIRED")
    if not migrate_legacy_scope:
        _validate_writer_markdown(
            proposal,
            path=selected_target.path,
            app_id=app_id,
            project_id=project_id,
            require_explicit_write_scope=True,
            allow_supporting_document=allow_supporting_document,
            allowed_statuses=(
                {target_status}
                if operation == "status_transition"
                else (
                    memory_index.GOVERNANCE_MIGRATION_STATUSES
                    if operation == "governance_migration"
                    else CONTENT_UPDATE_STATUSES
                )
            ),
        )
    target_exists, target_digest, target_git_head, current_read_token = _target_snapshot(
        selected_target,
        app_id=app_id,
        project_id=project_id,
        host_read=False,
        raw_session_id=raw_session_id,
        allow_supporting_document=allow_supporting_document,
        allowed_statuses=(
            None
            if migrate_legacy_scope
            else _existing_statuses_for_operation(operation)
        ),
    )
    if current_read_token != read_token:
        _raise("STALE_READ_TOKEN", retryable=True)
    policy_base_exists = target_exists
    policy_base = target_digest
    # Preserve the cheapest fail-closed boundary first.  A caller trying to
    # disguise a status transition as content_update is rejected without any
    # Git/history dependency.
    if operation == "content_update" and not migrate_legacy_scope and not adopt_external:
        _content_update_status(
            base_text=target_digest.text,
            proposal_text=proposal,
            base_exists=target_exists,
            governance_target=_is_governance_target(selected_target.path),
        )
    # Non-ADOPT proposals are proved from the exact live bytes returned by the
    # read token.  create_intent then performs the filter-aware clean-worktree
    # check and binds that live representation to Git HEAD.  This avoids
    # mistaking a clean CRLF/smudge checkout for content drift.  ADOPT is the
    # exception: its live bytes already equal the proposal, so status/risk
    # policy must be replayed from the prior tracked Git blob (or an absent blob
    # for an untracked active ADD).
    if adopt_external:
        policy_base_exists, policy_base = _immutable_git_base(
            target=selected_target,
            git_head=target_git_head,
        )
    policy_base_text = policy_base.text
    policy_proposal_text = proposal
    if adopt_external and policy_base_exists:
        canonical_base_text = write_intent.canonicalize_text(policy_base.text)
        canonical_proposal_text = write_intent.canonicalize_text(proposal)
        canonical_proposal_meta = _temporal_parse_frontmatter(
            canonical_proposal_text
        )
        canonical_proposal_fact = memory_index.fact_metadata(
            canonical_proposal_meta
        )
        if (
            bool(canonical_proposal_fact.get("enabled"))
            and _exact_risk_class_upgrade(
                base_text=canonical_base_text,
                proposal_text=canonical_proposal_text,
            )
        ):
            policy_base_text = canonical_base_text
            policy_proposal_text = canonical_proposal_text
    if operation == "content_update" and not migrate_legacy_scope:
        _content_update_status(
            base_text=policy_base_text,
            proposal_text=policy_proposal_text,
            base_exists=policy_base_exists,
            governance_target=_is_governance_target(selected_target.path),
        )
    if operation in {"status_transition", "governance_migration"} and not target_exists:
        _raise("TARGET_MISSING")
    if operation == "governance_migration":
        _validate_governance_migration(
            rel_path=selected_target.rel_path,
            base_text=target_digest.text,
            proposal_text=proposal,
        )
    elif not _is_governance_target(selected_target.path):
        _validate_memory_identity(
            base_text=target_digest.text,
            proposal_text=proposal,
            target_exists=target_exists,
            expected_new_memory_id=_generated_memory_id(current_read_token),
        )
    if migrate_legacy_scope and not target_exists:
        _raise("TARGET_MISSING")
    if migrate_legacy_scope:
        _validate_legacy_scope_migration(
            actor=ACTOR,
            target_relative_path=selected_target.rel_path,
            requested_app_id=app_id,
            requested_project_id=project_id,
            legacy_scope_app_id=legacy_scope_app_id,
            base_text=target_digest.text,
            proposal_text=proposal,
        )
        _validate_writer_markdown(
            proposal,
            path=selected_target.path,
            app_id=app_id,
            project_id=project_id,
            require_explicit_write_scope=True,
            allow_supporting_document=True,
        )
    summary = _required_string(request, "summary", max_chars=MAX_SUMMARY_CHARS)
    source_class = _required_string(request, "source_class", max_chars=80).strip().casefold()
    knowledge_kind = _required_string(request, "knowledge_kind", max_chars=80).strip().casefold()
    asserted_by = _required_string(request, "asserted_by", max_chars=80).strip().casefold()
    evidence_ref = _optional_string(request, "evidence_ref", max_chars=MAX_REFERENCE_CHARS)
    _validate_write_temporal_gate(
        proposal_text=proposal,
        knowledge_kind=knowledge_kind,
        evidence_ref=evidence_ref,
        operation="legacy_scope_migration" if migrate_legacy_scope else operation,
        governance_target=_is_governance_target(selected_target.path),
        target_relative_path=selected_target.rel_path,
    )
    transition: dict[str, str] = {}
    if operation == "status_transition":
        transition = _validate_status_transition(
            base_text=policy_base_text,
            proposal_text=policy_proposal_text,
            target_status=target_status,
            evidence_ref=evidence_ref,
        )
    temporal_transition = _validate_temporal_transition(
        selected_target=selected_target,
        base_text=(
            policy_base_text
            if operation in {"content_update", "status_transition"}
            else (target_digest.text if target_exists else "")
        ),
        proposal_text=(
            policy_proposal_text
            if operation in {"content_update", "status_transition"}
            else proposal
        ),
        operation=operation,
        validated_status_transition=transition or None,
    )
    if adopt_external:
        if operation == "status_transition":
            _raise("STATUS_TRANSITION_INVALID")
        if ACTOR not in {"codex", "claude"}:
            _raise("ADOPT_ACTOR_FORBIDDEN")
        if not target_exists:
            _raise("TARGET_MISSING")
        if digest.raw_sha256 != target_digest.raw_sha256:
            _raise("ADOPT_CONTENT_MISMATCH")
        if not _external_dirty_against_head(selected_target, target_digest, target_git_head):
            _raise("ADOPT_TARGET_NOT_DIRTY")
    if bool(temporal_transition["enabled"]) and not evidence_ref:
        _raise("FACT_EVIDENCE_REQUIRED")
    legacy_project = _optional_string(request, "current_project", max_chars=160)
    if legacy_project and legacy_project.casefold() != (project_id or ACTOR).casefold():
        _raise("PROJECT_SCOPE_MISMATCH")
    if asserted_by not in ASSERTED_BY_VALUES:
        _raise("SOURCE_METADATA_INVALID")
    try:
        assessment = memory_safety.assess_source(
            f"{summary}\n{proposal}",
            source_class=source_class,
            knowledge_kind=knowledge_kind,
            asserted_by=asserted_by,
            evidence_ref=evidence_ref,
        )
    except ValueError as exc:
        raise MemoryWriteError(
            "SOURCE_METADATA_INVALID",
            _error_message("SOURCE_METADATA_INVALID"),
        ) from exc
    _record_prepare_safety(assessment, raw_session_id=raw_session_id)
    if str(assessment.get("decision")) != "ALLOW":
        reason_code = _safe_code(str(assessment.get("reason_code", "SOURCE_REJECTED")))
        return {
            "schema_version": SCHEMA_VERSION,
            "ok": False,
            "stage": "prepare",
            "status": "blocked",
            "reason_code": reason_code,
            "message": _error_message(reason_code),
            "retryable": False,
            "proposal_raw_sha256": digest.raw_sha256,
            "proposal_canonical_sha256": digest.canonical_sha256,
        }

    rows, warnings, backend_status = memory_closeout.search_memory(
        summary,
        limit=8,
        no_zvec=not memory_closeout.SEMANTIC_ENABLED,
        current_project=project_id,
        read_only=True,
        app_id=app_id,
        agent_scope=_reconciliation_agent_scope(ACTOR),
        project_id=project_id,
        canonical_actor=ACTOR,
    )
    if backend_status.get("sqlite", {}).get("status") != "ok":
        _raise("RECONCILE_UNAVAILABLE", retryable=True)
    scoped_rows: list[dict[str, Any]] = []
    scoped_candidates: list[dict[str, Any]] = []
    for row in rows:
        candidate = _safe_candidate(
            row,
            app_id=app_id,
            project_id=project_id,
            raw_session_id=raw_session_id,
        )
        if candidate is None:
            continue
        scoped_rows.append(row)
        if len(scoped_candidates) < 5:
            scoped_candidates.append(candidate)
    rows = scoped_rows
    action, recommended_row, metrics = memory_closeout.prewrite_recommendation(summary, rows)
    if action not in {"ADD", "UPDATE", "NOOP", "MERGE_REQUIRED"}:
        action = "MERGE_REQUIRED"
    candidates = scoped_candidates
    warning_codes = _warning_codes(warnings)
    recommended_path = ""
    if isinstance(recommended_row, dict):
        candidate = _safe_candidate(
            recommended_row,
            app_id=app_id,
            project_id=project_id,
            raw_session_id=raw_session_id,
        )
        if candidate is not None:
            recommended_path = str(candidate["relative_path"])

    # An explicit, validated fact identity is stronger than approximate text
    # similarity.  It selects only the caller's CAS-bound target; the graph
    # validator above has already proved that all prior current heads are
    # explicitly superseded and that no ambiguous branch remains.
    if bool(temporal_transition["enabled"]):
        action = "UPDATE" if target_exists else "ADD"
        recommended_path = selected_target.rel_path

    recommended_target_key = ""
    if recommended_path:
        recommended_target_key = _formal_target(recommended_path).target_key
    action = _promote_user_direct_exact_noop(
        action=action,
        recommended_target_key=recommended_target_key,
        selected_target_key=selected_target.target_key,
        candidate_target_keys={
            _formal_target(str(candidate["relative_path"])).target_key
            for candidate in candidates
        },
        target_exists=target_exists,
        target_canonical_sha256=target_digest.canonical_sha256,
        proposal_canonical_sha256=digest.canonical_sha256,
        source_class=source_class,
        asserted_by=asserted_by,
    )

    # Root governance files are structurally unique. Search and reconciliation
    # above remain mandatory audit inputs, but a semantic neighbor at another
    # path cannot replace or block the explicitly selected root target.
    action, recommended_path = _structurally_unique_recommendation(
        target_relative_path=selected_target.rel_path,
        target_exists=target_exists,
        target_canonical_sha256=target_digest.canonical_sha256,
        proposal_canonical_sha256=digest.canonical_sha256,
        fallback_action=action,
        fallback_recommended_path=recommended_path,
    )

    # Legacy scope migration is also structurally bound to the exact target and
    # read token. Semantic candidates remain audit evidence, never an alternate
    # destination for this deterministic metadata-only transformation.
    if migrate_legacy_scope:
        action = "MIGRATE_LEGACY_SCOPE"
        recommended_path = selected_target.rel_path
    if operation == "status_transition":
        action = "UPDATE"
        recommended_path = selected_target.rel_path
    if operation == "governance_migration":
        action = "UPDATE"
        recommended_path = selected_target.rel_path

    if recommended_path and action in {"UPDATE", "NOOP"}:
        selected = selected_target
        recommended = _formal_target(recommended_path)
        if selected.target_key != recommended.target_key:
            response = _base_response(
                status="merge_required",
                action="MERGE_REQUIRED",
                digest=digest,
                target=recommended.rel_path,
                candidates=candidates,
                warning_codes=warning_codes,
            )
            response["reason_code"] = "TARGET_RECOMMENDATION_CONFLICT"
            return response

    # Explicit adoption still runs source safety and reconciliation. A true
    # cross-target merge remains blocking, while ADD/UPDATE/NOOP against this
    # exact already-written target becomes the auditable ADOPT action.
    if adopt_external and action != "MERGE_REQUIRED":
        action = "ADOPT"
        recommended_path = selected_target.rel_path

    if action == "NOOP":
        return _base_response(
            status="noop",
            action="NOOP",
            digest=digest,
            target=recommended_path,
            candidates=candidates,
            warning_codes=warning_codes,
        )
    if action == "MERGE_REQUIRED":
        response = _base_response(
            status="merge_required",
            action="MERGE_REQUIRED",
            digest=digest,
            target=recommended_path,
            candidates=candidates,
            warning_codes=warning_codes,
        )
        response["reason_code"] = "MERGE_REQUIRED"
        return response

    if action != "ADD":
        if not recommended_path:
            response = _base_response(
                status="merge_required",
                action="MERGE_REQUIRED",
                digest=digest,
                candidates=candidates,
                warning_codes=warning_codes,
            )
            response["reason_code"] = "MERGE_REQUIRED"
            return response
        recommended_target = _formal_target(recommended_path)
        if recommended_target.target_key != selected_target.target_key:
            response = _base_response(
                status="merge_required",
                action="MERGE_REQUIRED",
                digest=digest,
                target=recommended_target.rel_path,
                candidates=candidates,
                warning_codes=warning_codes,
            )
            response["reason_code"] = "TARGET_RECOMMENDATION_CONFLICT"
            return response
    if action == "ADD" and target_exists:
        response = _base_response(
            status="merge_required",
            action="MERGE_REQUIRED",
            digest=digest,
            target=selected_target.rel_path,
            candidates=candidates,
            warning_codes=warning_codes,
        )
        response["reason_code"] = "TARGET_ALREADY_EXISTS"
        return response
    if action == "UPDATE" and not target_exists:
        _raise("TARGET_MISSING")
    if (
        not adopt_external
        and target_exists
        and target_digest.canonical_sha256 == digest.canonical_sha256
    ):
        return _base_response(
            status="noop",
            action="NOOP",
            digest=digest,
            target=selected_target.rel_path,
            candidates=candidates,
            warning_codes=warning_codes,
        )

    ttl_raw = request.get("ttl_hours", 1)
    if not isinstance(ttl_raw, (int, float)) or isinstance(ttl_raw, bool):
        _raise("REQUEST_INVALID")
    ttl_hours = min(max(float(ttl_raw), 0.25), 24.0)
    try:
        intent = write_intent.create_intent(
            actor=ACTOR,
            raw_session_id=raw_session_id,
            target=selected_target.path,
            proposal_text=proposal,
            approval_required=True,
            ttl_hours=ttl_hours,
            source_class=source_class,
            knowledge_kind=knowledge_kind,
            asserted_by=asserted_by,
            evidence_ref_sha256=str(assessment.get("evidence_ref_sha256", "")),
            reconcile_action=action,
            strict_git_base=not adopt_external,
            store_proposal_snapshot=False,
            read_token=read_token,
            scope_app_id=app_id,
            scope_project_id=project_id,
            expected_base_exists=target_exists,
            expected_base_raw_sha256=target_digest.raw_sha256,
            expected_base_canonical_sha256=target_digest.canonical_sha256,
            expected_base_git_head=target_git_head,
            operation=operation,
            target_status=target_status,
            transition_reason_sha256=transition_reason_sha256,
        )
    except write_intent.IntentError as exc:
        _raise(exc.reason_code, retryable=exc.reason_code == "ACTIVE_TARGET_CONFLICT")

    response = _base_response(
        status="prepared",
        action=action,
        digest=digest,
        target=selected_target.rel_path,
        candidates=candidates,
        warning_codes=warning_codes,
    )
    response.update(
        {
            "proposal_id": str(intent["intent_id"]),
            "fencing_token": int(intent.get("fencing_token") or 0),
            "base_exists": bool(intent["base_exists"]),
            "base_raw_sha256": str(intent["base_raw_sha256"]),
            "base_canonical_sha256": str(intent["base_canonical_sha256"]),
            "base_git_head": str(intent["base_git_head"]),
            "expires_at": str(intent["expires_at"]),
            "adoption": adopt_external,
            "scope_migration": migrate_legacy_scope,
            "operation": operation,
            "from_status": transition.get("from_status", ""),
            "target_status": target_status,
            "temporal_fact": bool(temporal_transition["enabled"]),
            "fact_key": str(temporal_transition["fact_key"]),
            "supersedes_count": len(temporal_transition["supersedes"]),
            "recommendation_metrics": {
                "similarity": round(float(metrics.get("similarity") or 0), 4),
                "coverage": round(float(metrics.get("coverage") or 0), 4),
                "raw_semantic_distance": (
                    round(float(metrics["raw_semantic_distance"]), 4)
                    if metrics.get("raw_semantic_distance") is not None
                    else None
                ),
            },
        }
    )
    if _requires_confirmation_capability(action, operation):
        response.update(
            {
                "confirmation_capability_required": True,
                "confirmation_capability_protocol": "human_write_confirmation_v1",
                "confirmation_capability_issuer": "host_or_explicit_human_tool",
                "confirmation_capability_host_ui_integrated": False,
            }
        )
    return response


def _authorized_intent_record(
    proposal_id: str,
    *,
    raw_session_id: str,
) -> dict[str, Any]:
    try:
        shown = write_intent.show_intent(proposal_id)
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    intent = shown.get("intent")
    if not isinstance(intent, dict):
        _raise("INTENT_NOT_FOUND")
    if (
        str(intent.get("actor", "")) != ACTOR
        or str(intent.get("session_hash", "")) != write_intent.session_hash(raw_session_id)
    ):
        _raise("INTENT_SESSION_MISMATCH")
    return shown


def _authorized_intent(proposal_id: str, *, raw_session_id: str) -> dict[str, Any]:
    shown = _authorized_intent_record(
        proposal_id,
        raw_session_id=raw_session_id,
    )
    intent = shown.get("intent")
    if not isinstance(intent, dict):
        _raise("INTENT_NOT_FOUND")
    return intent


def _record_for_authorized_intent(
    proposal_id: str,
    authorized_intent: dict[str, Any],
) -> dict[str, Any]:
    """Read the receipt normally after the caller authorized this exact intent."""

    try:
        shown = write_intent.show_intent(proposal_id)
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    current = shown.get("intent")
    if not isinstance(current, dict):
        _raise("INTENT_NOT_FOUND")
    identity_fields = (
        "intent_id",
        "actor",
        "session_hash",
        "target_key",
        "fencing_token",
    )
    if any(
        str(current.get(field, "")) != str(authorized_intent.get(field, ""))
        for field in identity_fields
    ):
        _raise("INTENT_SESSION_MISMATCH")
    return shown


def _inspect_authorized_intent(
    proposal_id: str,
    *,
    raw_session_id: str,
) -> dict[str, Any]:
    try:
        return write_intent.inspect_intent(
            proposal_id,
            actor=ACTOR,
            raw_session_id=raw_session_id,
        )
    except StateSecurityError as exc:
        raise MemoryWriteError(
            "STATE_SNAPSHOT_BUSY",
            _error_message("STATE_SNAPSHOT_BUSY"),
            retryable=True,
        ) from exc
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)


def _intent_scope_binding(
    intent: dict[str, Any],
    *,
    target: write_intent.CanonicalTarget,
    raw_session_id: str,
) -> tuple[str, str]:
    app_id = str(intent.get("scope_app_id", ""))
    project_id = str(intent.get("scope_project_id", ""))
    action = str(intent.get("reconcile_action", "")).upper()
    operation = str(intent.get("operation", "content_update")).casefold()
    target_status = str(intent.get("target_status", "")).casefold()
    try:
        if action == "MIGRATE_LEGACY_SCOPE":
            app_id, project_id = _legacy_scope_identifiers(
                actor=ACTOR,
                target_relative_path=target.rel_path,
                requested_app_id=app_id,
                requested_project_id=project_id,
                legacy_scope_app_id=app_id,
            )
        elif _is_governance_target(target.path):
            if ACTOR == "ailu":
                raise memory_retrieve.RetrievalProtocolError("GOVERNANCE_SCOPE_FORBIDDEN")
            app_id = memory_retrieve._normalized_identifier(app_id)
            project_id = memory_retrieve._normalized_identifier(project_id)
            if app_id != GOVERNANCE_APP_ID or project_id not in GOVERNANCE_PROJECT_IDS:
                raise memory_retrieve.RetrievalProtocolError("GOVERNANCE_SCOPE_INVALID")
        elif ACTOR == "ailu":
            app_id, project_id = memory_retrieve.validate_ailu_scope_request(app_id, project_id)
            parts = Path(target.rel_path).parts
            if project_id == "global" and (not parts or parts[0] != "用户记忆"):
                raise memory_retrieve.RetrievalProtocolError("GLOBAL_SCOPE_TARGET_INVALID")
        else:
            app_id = memory_retrieve._normalized_identifier(app_id)
            project_id = memory_retrieve._normalized_identifier(project_id)
            parts = Path(target.rel_path).parts
            global_user_target = bool(
                project_id == "global"
                and parts
                and parts[0] == "用户记忆"
                and operation in {"governance_migration", "status_transition"}
            )
            if (
                not app_id
                or "," in app_id
                or project_id == "shared"
                or (project_id == "global" and not global_user_target)
                or "," in project_id
            ):
                raise memory_retrieve.RetrievalProtocolError("INTENT_SCOPE_INVALID")
    except memory_retrieve.RetrievalProtocolError as exc:
        raise MemoryWriteError("INTENT_SCOPE_INVALID", _error_message("SCOPE_METADATA_INVALID")) from exc
    stored_token = str(intent.get("read_token", ""))
    if READ_TOKEN_RE.fullmatch(stored_token) is None:
        _raise("READ_TOKEN_REQUIRED")
    base_digest = write_intent.ContentDigest(
        raw_sha256=str(intent.get("base_raw_sha256", "")),
        canonical_sha256=str(intent.get("base_canonical_sha256", "")),
        size_bytes=0,
        text="",
    )
    expected = _read_token(
        target,
        app_id=app_id,
        project_id=project_id,
        exists=bool(intent.get("base_exists", 0)),
        digest=base_digest,
        git_head=str(intent.get("base_git_head", "")),
        raw_session_id=raw_session_id,
    )
    token_matches = hmac.compare_digest(stored_token, expected)
    stored_target_key = str(intent.get("target_key", ""))
    if (
        not token_matches
        and str(intent.get("status", "")) == "completed"
        and str(intent.get("target_rel_path", "")) == target.rel_path
        and SHA256_RE.fullmatch(stored_target_key) is not None
    ):
        legacy_target = write_intent.CanonicalTarget(
            path=target.path,
            rel_path=target.rel_path,
            target_key=stored_target_key,
        )
        legacy_expected = _read_token(
            legacy_target,
            app_id=app_id,
            project_id=project_id,
            exists=bool(intent.get("base_exists", 0)),
            digest=base_digest,
            git_head=str(intent.get("base_git_head", "")),
            raw_session_id=raw_session_id,
        )
        token_matches = hmac.compare_digest(stored_token, legacy_expected)
    if not token_matches:
        _raise("INTENT_BINDING_INVALID")
    return app_id, project_id


def _validate_apply_request(
    request: dict[str, Any],
) -> tuple[str, int, str, write_intent.ContentDigest, str, str, str]:
    proposal_id = _required_string(request, "proposal_id", max_chars=64)
    if PROPOSAL_ID_RE.fullmatch(proposal_id) is None:
        _raise("REQUEST_INVALID")
    fencing_token = _required_positive_int(request, "fencing_token")
    target = _required_string(request, "target_relative_path", max_chars=512)
    proposal, digest = _proposal_text(request)
    raw_hash = _required_string(request, "proposal_raw_sha256", max_chars=64)
    canonical_hash = _required_string(request, "proposal_canonical_sha256", max_chars=64)
    if SHA256_RE.fullmatch(raw_hash) is None or SHA256_RE.fullmatch(canonical_hash) is None:
        _raise("REQUEST_INVALID")
    if digest.raw_sha256 != raw_hash or digest.canonical_sha256 != canonical_hash:
        _raise("PROPOSAL_HASH_MISMATCH")
    raw_confirmed_by = request.get("confirmed_by", "")
    raw_confirmation_ref = request.get("confirmation_reference", "")
    if not isinstance(raw_confirmed_by, str) or not isinstance(raw_confirmation_ref, str):
        _raise("CONFIRMATION_INVALID")
    confirmed_by = raw_confirmed_by.strip()
    confirmation_ref = raw_confirmation_ref.strip()
    if confirmed_by:
        allowed_confirmers = {"user"} if ACTOR == "ailu" else {"user", ACTOR}
        if confirmed_by not in allowed_confirmers:
            _raise("USER_CONFIRMATION_REQUIRED")
    if confirmation_ref and (
        len(confirmation_ref) > MAX_REFERENCE_CHARS
        or SAFE_REFERENCE_RE.fullmatch(confirmation_ref) is None
    ):
        _raise("CONFIRMATION_INVALID")
    if bool(confirmed_by) != bool(confirmation_ref):
        _raise("CONFIRMATION_INVALID")
    return proposal_id, fencing_token, target, digest, proposal, confirmed_by, confirmation_ref


def _approval_matches(intent: dict[str, Any], confirmation_ref: str, confirmed_by: str) -> bool:
    return (
        str(intent.get("approved_by", "")) == confirmed_by
        and str(intent.get("approval_ref_sha256", ""))
        == hashlib.sha256(confirmation_ref.encode("utf-8")).hexdigest()
        and str(intent.get("approval_proposal_raw_sha256", ""))
        == str(intent.get("proposal_raw_sha256", ""))
        and str(intent.get("approval_proposal_canonical_sha256", ""))
        == str(intent.get("proposal_canonical_sha256", ""))
    )


def _requires_user_confirmation(action: str, operation: str) -> bool:
    return action in {"ADOPT", "MIGRATE_LEGACY_SCOPE"} or operation in {
        "status_transition",
        "governance_migration",
    }


def _requires_confirmation_capability(action: str, operation: str) -> bool:
    """Sensitive mutations require a separate host/manual confirmation event."""

    return _requires_user_confirmation(action, operation)


def _confirmation_capability_input(request: dict[str, Any]) -> tuple[str, str]:
    path_value = request.get("confirmation_capability_path", "")
    token_value = request.get("confirmation_capability_token", "")
    if not isinstance(path_value, str) or not isinstance(token_value, str):
        _raise("CONFIRMATION_CAPABILITY_INVALID")
    path = path_value.strip()
    token = token_value.strip()
    if not path and not token:
        return "", ""
    if not path or not token or len(path) > 2048 or len(token) > 256:
        _raise("CONFIRMATION_CAPABILITY_INVALID")
    if any(char in path or char in token for char in ("\x00", "\r", "\n")):
        _raise("CONFIRMATION_CAPABILITY_INVALID")
    return path, token


def _confirmation_raw_task_id(raw_session_id: str) -> str:
    """Bind to the host task when present; an explicit session is the fallback."""

    normalized_session = raw_session_id.strip()
    explicit_session = os.environ.get("AGENT_MEMORY_SESSION_ID", "").strip()
    # An explicitly supplied session is also the reproducible task binding
    # used by the stdin-only issuer.  Do not let a wrapper invocation nonce
    # silently replace it between prepare, issue, and apply.
    if (
        explicit_session
        and normalized_session
        and hmac.compare_digest(explicit_session, normalized_session)
    ):
        return normalized_session
    current = memory_observability.current_raw_task_id(ACTOR).strip()
    return current or normalized_session


def _claim_matches(proposal_id: str, *, raw_session_id: str, target: Path) -> bool:
    try:
        rows = memory_claim.active_claim_rows(raw_session_id, ACTOR)
    except (OSError, ValueError):
        return False
    return any(
        str(row.get("intent_id", "")) == proposal_id
        and Path(str(row.get("path", ""))).resolve(strict=False) == target.resolve(strict=False)
        for row in rows
    )


def _conditional_sidecar_paths(
    target: write_intent.CanonicalTarget,
    proposal_id: str,
) -> tuple[Path, Path, Path]:
    if PROPOSAL_ID_RE.fullmatch(proposal_id) is None:
        _raise("REQUEST_INVALID")
    token = hashlib.sha256(
        f"writer-cas:{proposal_id}:{target.target_key}".encode("utf-8")
    ).hexdigest()[:24]
    prefix = target.path.parent / f".agent-memory-writer-{token}"
    return (
        Path(f"{prefix}.proposal"),
        Path(f"{prefix}.displaced"),
        Path(f"{prefix}.recovery"),
    )


def _path_present(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_regular_payload(path: Path, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            _raise("TARGET_WRITE_RECOVERY_REQUIRED", retryable=True)
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
            _raise("TARGET_WRITE_RECOVERY_REQUIRED", retryable=True)
        return payload
    except MemoryWriteError:
        raise
    except OSError as exc:
        raise MemoryWriteError(
            "TARGET_WRITE_RECOVERY_REQUIRED",
            _error_message("TARGET_WRITE_RECOVERY_REQUIRED"),
            retryable=True,
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _create_exact_sidecar(path: Path, payload: bytes, mode: int) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            if POSIX_PERMISSION_MODEL:
                os.fchmod(handle.fileno(), mode)
    except FileExistsError as exc:
        raise MemoryWriteError(
            "TARGET_WRITE_RECOVERY_REQUIRED",
            _error_message("TARGET_WRITE_RECOVERY_REQUIRED"),
            retryable=True,
        ) from exc
    except OSError as exc:
        raise MemoryWriteError("TARGET_WRITE_FAILED", "无法准备原子写入文件。") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _unlink_known_sidecar(path: Path, expected_sha256: str) -> None:
    if not _path_present(path):
        return
    payload = _read_regular_payload(
        path,
        max_bytes=max(
            MAX_HOST_TARGET_BYTES,
            write_intent.MAX_TARGET_BYTES,
            write_intent.MAX_PROPOSAL_BYTES,
        ),
    )
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        _raise("TARGET_WRITE_RECOVERY_REQUIRED", retryable=True)
    try:
        path.unlink()
    except OSError as exc:
        raise MemoryWriteError(
            "TARGET_WRITE_RECOVERY_REQUIRED",
            _error_message("TARGET_WRITE_RECOVERY_REQUIRED"),
            retryable=True,
        ) from exc


def _atomic_exchange(first: Path, second: Path) -> None:
    """Atomically exchange two same-filesystem paths or fail without replacing either."""

    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        rename_swap = getattr(libc, "renamex_np", None)
        if rename_swap is None:
            _raise("ATOMIC_CONDITIONAL_WRITE_UNAVAILABLE")
        rename_swap.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename_swap.restype = ctypes.c_int
        result = rename_swap(os.fsencode(first), os.fsencode(second), 0x00000002)
    elif sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        rename_swap = getattr(libc, "renameat2", None)
        if rename_swap is None:
            _raise("ATOMIC_CONDITIONAL_WRITE_UNAVAILABLE")
        rename_swap.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_swap.restype = ctypes.c_int
        result = rename_swap(-100, os.fsencode(first), -100, os.fsencode(second), 0x00000002)
    else:
        _raise("ATOMIC_CONDITIONAL_WRITE_UNAVAILABLE")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {
        errno.ENOSYS,
        errno.EINVAL,
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }:
        _raise("ATOMIC_CONDITIONAL_WRITE_UNAVAILABLE")
    raise OSError(error_number, os.strerror(error_number))


def _windows_replace_with_backup(target: Path, replacement: Path, backup: Path) -> None:
    if os.name != "nt":
        _raise("ATOMIC_CONDITIONAL_WRITE_UNAVAILABLE")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    replace_file = kernel32.ReplaceFileW
    replace_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    replace_file.restype = ctypes.c_int
    if replace_file(str(target), str(replacement), str(backup), 0x00000001, None, None):
        return
    error_number = ctypes.get_last_error()
    raise OSError(error_number, os.strerror(error_number))


def _atomic_capture_target(
    proposal_path: Path,
    target_path: Path,
    displaced_path: Path,
) -> Path:
    if os.name == "nt":
        _windows_replace_with_backup(target_path, proposal_path, displaced_path)
        return displaced_path
    _atomic_exchange(proposal_path, target_path)
    return proposal_path


def _atomic_restore_target(
    captured_path: Path,
    target_path: Path,
    proposal_path: Path,
) -> Path:
    if os.name == "nt":
        _windows_replace_with_backup(target_path, captured_path, proposal_path)
        return proposal_path
    _atomic_exchange(captured_path, target_path)
    return captured_path


def _atomic_conditional_write(
    target: write_intent.CanonicalTarget,
    proposal: str,
    *,
    proposal_id: str,
    expected_exists: bool,
    expected_raw_sha256: str,
) -> None:
    """Publish exact bytes without ever discarding a raced target version.

    ADD uses an atomic no-replace hard link.  UPDATE atomically exchanges the
    proposal with the target, then validates the displaced bytes.  A mismatch
    is exchanged back; an independent recovery copy protects the displaced
    bytes from any second race during restoration.  Uncertain recovery leaves
    the sidecars in place and fails closed.
    """

    if not target.path.parent.is_dir():
        _raise("TARGET_PARENT_MISSING")
    proposal_path, displaced_path, recovery_path = _conditional_sidecar_paths(
        target,
        proposal_id,
    )
    if any(_path_present(path) for path in (proposal_path, displaced_path, recovery_path)):
        _raise("TARGET_WRITE_RECOVERY_REQUIRED", retryable=True)

    current_mode = 0o644
    if expected_exists:
        try:
            metadata = target.path.lstat()
        except OSError as exc:
            raise MemoryWriteError(
                "TARGET_CHANGED_AFTER_CLAIM",
                _error_message("TARGET_CHANGED_AFTER_CLAIM"),
                retryable=True,
            ) from exc
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            _raise("TARGET_CHANGED_AFTER_CLAIM", retryable=True)
        current_mode = stat.S_IMODE(metadata.st_mode) or 0o644

    proposal_payload = proposal.encode("utf-8")
    proposal_sha256 = hashlib.sha256(proposal_payload).hexdigest()
    _create_exact_sidecar(proposal_path, proposal_payload, current_mode)
    _fsync_directory(target.path.parent)

    if not expected_exists:
        try:
            os.link(proposal_path, target.path)
            _fsync_directory(target.path.parent)
        except FileExistsError as exc:
            _unlink_known_sidecar(proposal_path, proposal_sha256)
            raise MemoryWriteError(
                "TARGET_CHANGED_AFTER_CLAIM",
                _error_message("TARGET_CHANGED_AFTER_CLAIM"),
                retryable=True,
            ) from exc
        except OSError as exc:
            _unlink_known_sidecar(proposal_path, proposal_sha256)
            raise MemoryWriteError(
                "ATOMIC_CONDITIONAL_WRITE_UNAVAILABLE",
                _error_message("ATOMIC_CONDITIONAL_WRITE_UNAVAILABLE"),
            ) from exc
        _unlink_known_sidecar(proposal_path, proposal_sha256)
        _fsync_directory(target.path.parent)
        return

    try:
        captured_path = _atomic_capture_target(proposal_path, target.path, displaced_path)
    except MemoryWriteError:
        if _path_present(proposal_path):
            _unlink_known_sidecar(proposal_path, proposal_sha256)
        raise
    except OSError as exc:
        if _path_present(proposal_path):
            _unlink_known_sidecar(proposal_path, proposal_sha256)
        raise MemoryWriteError(
            "TARGET_CHANGED_AFTER_CLAIM",
            _error_message("TARGET_CHANGED_AFTER_CLAIM"),
            retryable=True,
        ) from exc
    _fsync_directory(target.path.parent)

    max_capture_bytes = max(MAX_HOST_TARGET_BYTES, write_intent.MAX_TARGET_BYTES)
    try:
        captured_payload = _read_regular_payload(captured_path, max_bytes=max_capture_bytes)
    except MemoryWriteError:
        # The exchanged object itself is still preserved at captured_path.  Try
        # to put it back, but retain the returned proposal sidecar because the
        # object could not be bounded and verified.
        try:
            _atomic_restore_target(captured_path, target.path, proposal_path)
            _fsync_directory(target.path.parent)
        except (OSError, MemoryWriteError):
            pass
        _raise("TARGET_WRITE_RECOVERY_REQUIRED", retryable=True)

    captured_sha256 = hashlib.sha256(captured_payload).hexdigest()
    if captured_sha256 == expected_raw_sha256:
        _unlink_known_sidecar(captured_path, expected_raw_sha256)
        _fsync_directory(target.path.parent)
        return

    # Preserve the exact raced bytes independently before attempting the
    # rollback.  If a second writer changes the target during that rollback,
    # both the first displaced version and the newly displaced version remain
    # recoverable instead of being silently deleted.
    _create_exact_sidecar(recovery_path, captured_payload, PRIVATE_FILE_MODE)
    _fsync_directory(target.path.parent)
    try:
        returned_proposal_path = _atomic_restore_target(
            captured_path,
            target.path,
            proposal_path,
        )
        _fsync_directory(target.path.parent)
    except (OSError, MemoryWriteError) as exc:
        raise MemoryWriteError(
            "TARGET_WRITE_RECOVERY_REQUIRED",
            _error_message("TARGET_WRITE_RECOVERY_REQUIRED"),
            retryable=True,
        ) from exc

    try:
        restored_payload = _read_regular_payload(target.path, max_bytes=max_capture_bytes)
        returned_payload = _read_regular_payload(
            returned_proposal_path,
            max_bytes=max(MAX_HOST_TARGET_BYTES, write_intent.MAX_PROPOSAL_BYTES),
        )
    except MemoryWriteError:
        _raise("TARGET_WRITE_RECOVERY_REQUIRED", retryable=True)
    restored_sha256 = hashlib.sha256(restored_payload).hexdigest()
    returned_sha256 = hashlib.sha256(returned_payload).hexdigest()
    if restored_sha256 != captured_sha256 or returned_sha256 != proposal_sha256:
        _raise("TARGET_WRITE_RECOVERY_REQUIRED", retryable=True)

    _unlink_known_sidecar(returned_proposal_path, proposal_sha256)
    _unlink_known_sidecar(recovery_path, captured_sha256)
    _fsync_directory(target.path.parent)
    _raise("TARGET_CHANGED_AFTER_CLAIM", retryable=True)


def _has_conditional_recovery_sidecar(
    target: write_intent.CanonicalTarget,
    proposal_id: str,
) -> bool:
    return any(
        _path_present(path)
        for path in _conditional_sidecar_paths(target, proposal_id)
    )


def _terminalize_safe_concurrent_failure(
    proposal_id: str,
    *,
    raw_session_id: str,
    target: Path,
) -> None:
    """Close an intent only after the concurrent target bytes are back in place."""

    try:
        write_intent.finalize_receipt(
            proposal_id,
            actor=ACTOR,
            raw_session_id=raw_session_id,
            outcome="failed",
            reason_code="TARGET_CHANGED_AFTER_CLAIM",
            detail_code="ATOMIC_CAS_REJECTED",
        )
    except (OSError, sqlite3.Error, ValueError, write_intent.IntentError) as exc:
        raise MemoryWriteError(
            "APPLY_RECOVERY_REQUIRED",
            _error_message("APPLY_RECOVERY_REQUIRED"),
            retryable=True,
        ) from exc
    try:
        memory_claim.complete_claim_paths(raw_session_id, ACTOR, [target])
    except (
        MemoryWriteError,
        RuntimeTransitionError,
        StateSecurityError,
        OSError,
        sqlite3.Error,
        ValueError,
        write_intent.IntentError,
    ):
        # The failed receipt is already authoritative. Claim cleanup is a
        # retryable projection and must never replace that terminal outcome.
        pass


def _closeout_shutdown_failed(*, cause: BaseException | None = None) -> MemoryWriteError:
    error = MemoryWriteError(
        "CLOSEOUT_SHUTDOWN_FAILED",
        "正式记忆收尾进程组未能完全停止，仍保持写入锁到安全停止边界。",
        retryable=True,
    )
    if cause is not None:
        error.__cause__ = cause
    return error


def _posix_process_group_members(group_id: int) -> tuple[list[int], list[int]]:
    """Return live same-UID members and foreign live members for one PGID.

    Darwin can return EPERM for killpg when even one group member has a
    different effective UID.  Inspecting the bounded process table lets the
    shutdown path signal only the closeout user's processes and, importantly,
    distinguish a stopped process from a harmless unreaped zombie.
    """

    ps_path = "/bin/ps" if Path("/bin/ps").is_file() else "ps"
    try:
        completed = subprocess.run(
            [ps_path, "-axo", "pid=,pgid=,uid=,stat="],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _closeout_shutdown_failed(cause=exc)
    if completed.returncode != 0:
        raise _closeout_shutdown_failed()
    own_uid = os.geteuid()
    owned: list[int] = []
    foreign: list[int] = []
    for line in completed.stdout.splitlines():
        fields = line.split(None, 3)
        if len(fields) != 4:
            continue
        try:
            pid, pgid, uid = (int(fields[index]) for index in range(3))
        except ValueError:
            continue
        if pgid != group_id or fields[3].upper().startswith("Z"):
            continue
        try:
            session_id = os.getsid(pid)
        except ProcessLookupError:
            continue
        except PermissionError as exc:
            raise _closeout_shutdown_failed(cause=exc)
        if session_id != group_id:
            continue
        (owned if uid == own_uid else foreign).append(pid)
    return sorted(set(owned)), sorted(set(foreign))


def _posix_process_group_may_exist(group_id: int) -> bool:
    try:
        os.killpg(group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _signal_owned_process(pid: int, sig: int) -> None:
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        raise _closeout_shutdown_failed(cause=exc)


def _live_closeout_descendants(group_id: int, leader_pid: int) -> list[int]:
    owned, foreign = _posix_process_group_members(group_id)
    if foreign:
        raise _closeout_shutdown_failed()
    return [pid for pid in owned if pid != leader_pid]


def _stop_closeout_descendants(
    group_id: int,
    leader_pid: int,
    *,
    term_grace: float,
    kill_grace: float,
) -> None:
    descendants = _live_closeout_descendants(group_id, leader_pid)
    term_deadline = time.monotonic() + term_grace
    while descendants and time.monotonic() < term_deadline:
        for pid in descendants:
            _signal_owned_process(pid, signal.SIGTERM)
            # The group was frozen first so the lock-owning leader cannot exit.
            # Resume descendants only after TERM is pending, allowing graceful
            # cleanup without reopening the leader-release race.
            _signal_owned_process(pid, signal.SIGCONT)
        time.sleep(0.05)
        descendants = _live_closeout_descendants(group_id, leader_pid)
    for pid in descendants:
        _signal_owned_process(pid, signal.SIGKILL)
    kill_deadline = time.monotonic() + kill_grace
    while descendants and time.monotonic() < kill_deadline:
        time.sleep(0.05)
        descendants = _live_closeout_descendants(group_id, leader_pid)
    if descendants:
        raise _closeout_shutdown_failed()


def _shutdown_process_group(
    process: subprocess.Popen[str],
    group_id: int,
    *,
    term_grace: float = 1.0,
    kill_grace: float = 5.0,
) -> None:
    """Terminate, reap, and verify a transport tree before its caller unlocks."""

    if os.name == "nt":
        try:
            process.terminate()
            process.communicate(timeout=term_grace)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.communicate(timeout=kill_grace)
            except subprocess.TimeoutExpired as exc:
                raise _closeout_shutdown_failed(cause=exc)
        except (OSError, ValueError) as exc:
            if process.poll() is None:
                raise _closeout_shutdown_failed(cause=exc)
        return

    leader_frozen = False
    if process.poll() is None:
        try:
            os.killpg(group_id, signal.SIGSTOP)
            leader_frozen = True
        except PermissionError:
            # killpg on Darwin is all-or-nothing when a foreign EUID is present.
            # Freeze the known lock owner directly, then clean only verified
            # same-UID descendants instead of swallowing the error.
            _signal_owned_process(process.pid, signal.SIGSTOP)
            leader_frozen = True
        except ProcessLookupError:
            leader_frozen = False

    _stop_closeout_descendants(
        group_id,
        process.pid,
        term_grace=term_grace,
        kill_grace=kill_grace,
    )

    if process.poll() is None:
        _signal_owned_process(process.pid, signal.SIGKILL)
    try:
        process.communicate(timeout=kill_grace)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise _closeout_shutdown_failed(cause=exc)

    descendants = _live_closeout_descendants(group_id, process.pid)
    if descendants:
        raise _closeout_shutdown_failed()
    if leader_frozen and process.returncode is None:
        raise _closeout_shutdown_failed()


def _run_closeout(
    *,
    raw_session_id: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    environment = os.environ.copy()
    for key in ("CODEX_THREAD_ID", "CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID"):
        environment.pop(key, None)
    environment["AGENT_MEMORY_SESSION_ID"] = raw_session_id
    environment["MEMORY_ACTOR"] = ACTOR
    environment.setdefault("PYTHONIOENCODING", "utf-8")
    environment.setdefault("PYTHONUTF8", "1")
    command = [
        PYTHON,
        str(CLOSEOUT_SCRIPT),
        "--actor",
        ACTOR,
        "--claimed-only",
        "--commit",
        "--json",
        "--trigger",
        "manual",
        "--skip-audit",
        "--lock-timeout",
        "30",
    ]
    if ACTOR != "ailu":
        command.extend(["--session-id", raw_session_id])
    popen_options: dict[str, Any] = {}
    if os.name == "nt":
        popen_options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_options["start_new_session"] = True
    try:
        process = subprocess.Popen(
            command,
            env=environment,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **popen_options,
        )
    except OSError as exc:
        raise MemoryWriteError("CLOSEOUT_FAILED", _error_message("CLOSEOUT_FAILED")) from exc
    group_id = process.pid
    try:
        stdout, stderr = process.communicate(timeout=max(timeout_seconds, 1))
    except subprocess.TimeoutExpired as exc:
        _shutdown_process_group(process, group_id)
        raise MemoryWriteError(
            "CLOSEOUT_TIMEOUT",
            _error_message("CLOSEOUT_TIMEOUT"),
            retryable=True,
        ) from exc
    except BaseException:
        _shutdown_process_group(process, group_id)
        raise
    if (
        os.name != "nt"
        and _posix_process_group_may_exist(group_id)
        and _live_closeout_descendants(group_id, process.pid)
    ):
        _shutdown_process_group(process, group_id)
        _raise("CLOSEOUT_FAILED", retryable=True)
    if len(stdout.encode("utf-8")) > MAX_RESPONSE_BYTES:
        _raise("CLOSEOUT_FAILED")
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise MemoryWriteError("CLOSEOUT_FAILED", _error_message("CLOSEOUT_FAILED")) from exc
    if not isinstance(payload, dict):
        _raise("CLOSEOUT_FAILED")
    if payload.get("reconcile_findings"):
        _raise("MERGE_REQUIRED")
    if process.returncode != 0 or payload.get("status") != "ok":
        _raise("CLOSEOUT_FAILED", retryable=True)
    return payload


_TERMINAL_RECEIPT_FIELDS = (
    "receipt_id",
    "intent_id",
    "writer_protocol_version",
    "actor",
    "session_hash",
    "target_rel_path",
    "target_key",
    "fencing_token",
    "outcome",
    "reason_code",
    "validation_mode",
    "base_raw_sha256",
    "proposal_raw_sha256",
    "proposal_canonical_sha256",
    "final_raw_sha256",
    "final_canonical_sha256",
    "base_git_head",
    "validated_git_head",
    "git_commit",
    "early_commit",
    "proposal_commit",
    "approval_binding_sha256",
    "approval_ref_sha256",
    "source_class",
    "knowledge_kind",
    "asserted_by_sha256",
    "safety_decision",
    "safety_reason_code",
    "safety_input_sha256",
    "safety_input_length",
    "evidence_ref_sha256",
    "operation",
    "target_status",
    "transition_reason_sha256",
    "detail_code",
    "created_at",
)


def _terminal_receipt_response(receipt: dict[str, Any]) -> dict[str, Any]:
    """Return the immutable ledger row without transient helper fields."""

    return {field: receipt.get(field) for field in _TERMINAL_RECEIPT_FIELDS}


def _completed_response(
    *,
    intent: dict[str, Any],
    receipt: dict[str, Any],
    idempotent: bool,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "ok": True,
        "stage": "apply",
        "status": "applied",
        "proposal_id": str(intent.get("intent_id", "")),
        "fencing_token": int(intent.get("fencing_token") or 0),
        "recommended_action": str(intent.get("reconcile_action", "")),
        "adoption": str(intent.get("reconcile_action", "")).upper() == "ADOPT",
        "scope_migration": str(intent.get("reconcile_action", "")).upper() == "MIGRATE_LEGACY_SCOPE",
        "target_relative_path": str(intent.get("target_rel_path", "")),
        "proposal_raw_sha256": str(intent.get("proposal_raw_sha256", "")),
        "proposal_canonical_sha256": str(intent.get("proposal_canonical_sha256", "")),
        "receipt_id": str(receipt.get("receipt_id", "")),
        "receipt": _terminal_receipt_response(receipt),
        "git_commit": str(receipt.get("git_commit", "")),
        "idempotent": idempotent,
        "completed_at": str(receipt.get("created_at", "")),
    }


def _terminal_outcome_response(
    *,
    intent: dict[str, Any],
    receipt: dict[str, Any],
    idempotent: bool,
    stage: str = "apply",
    operation_ok: bool = False,
) -> dict[str, Any]:
    outcome = str(receipt.get("outcome", ""))
    reason_code = _safe_code(str(receipt.get("reason_code", "")))
    return {
        "schema_version": SCHEMA_VERSION,
        "ok": operation_ok,
        "stage": stage,
        "status": outcome,
        "reason_code": reason_code,
        "message": _error_message(reason_code),
        "retryable": False,
        "proposal_id": str(intent.get("intent_id", "")),
        "fencing_token": int(intent.get("fencing_token") or 0),
        "recommended_action": str(intent.get("reconcile_action", "")),
        "adoption": str(intent.get("reconcile_action", "")).upper() == "ADOPT",
        "scope_migration": str(intent.get("reconcile_action", "")).upper()
        == "MIGRATE_LEGACY_SCOPE",
        "target_relative_path": str(intent.get("target_rel_path", "")),
        "proposal_raw_sha256": str(intent.get("proposal_raw_sha256", "")),
        "proposal_canonical_sha256": str(intent.get("proposal_canonical_sha256", "")),
        "receipt_id": str(receipt.get("receipt_id", "")),
        "receipt": _terminal_receipt_response(receipt),
        "git_commit": str(receipt.get("git_commit", "")),
        "idempotent": idempotent,
        "terminal_at": str(receipt.get("created_at", "")),
    }


def _verified_terminal_outcome(
    intent: dict[str, Any],
    receipt: object,
    *,
    idempotent: bool,
    stage: str = "apply",
    operation_ok: bool = False,
) -> dict[str, Any]:
    status = str(intent.get("status", ""))
    if status not in {"failed", "cancelled", "expired"}:
        _raise("INTENT_NOT_APPLICABLE")
    if not isinstance(receipt, dict) or str(receipt.get("outcome", "")) != status:
        _raise("RECEIPT_OUTCOME_CONFLICT")
    try:
        write_intent.verify_terminal_receipt(intent, receipt)
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    return _terminal_outcome_response(
        intent=intent,
        receipt=receipt,
        idempotent=idempotent,
        stage=stage,
        operation_ok=operation_ok,
    )


def _terminal_response_with_claim_release(
    *,
    intent: dict[str, Any],
    receipt: object,
    raw_session_id: str,
    idempotent: bool,
    stage: str,
    operation_ok: bool,
    target: write_intent.CanonicalTarget | None = None,
) -> dict[str, Any]:
    """Preserve the terminal receipt even if its claim projection lags."""

    payload = _verified_terminal_outcome(
        intent,
        receipt,
        idempotent=idempotent,
        stage=stage,
        operation_ok=operation_ok,
    )
    try:
        selected_target = target or _recovery_target(
            str(intent.get("target_rel_path", ""))
        )
        memory_claim.complete_claim_paths(
            raw_session_id,
            ACTOR,
            [selected_target.path],
        )
    except (
        MemoryWriteError,
        RuntimeTransitionError,
        StateSecurityError,
        OSError,
        sqlite3.Error,
        ValueError,
        write_intent.IntentError,
    ):
        return {
            **payload,
            "claim_release_pending": True,
            "claim_release_reason_code": "CLAIM_RELEASE_FAILED",
            "claim_release_retryable": True,
        }
    return {
        **payload,
        "claim_release_pending": False,
        "claim_release_reason_code": "",
        "claim_release_retryable": False,
    }


def _recover_expired_committed_content_update(
    intent: dict[str, Any],
    *,
    target: write_intent.CanonicalTarget,
    raw_session_id: str,
    confirmation_ref: str,
    confirmed_by: str,
) -> dict[str, Any]:
    """Open one bounded lease for an exact externally committed proposal."""

    if ACTOR not in {"codex", "claude"}:
        _raise("INTENT_EXPIRED")
    if not _approval_matches(intent, confirmation_ref, confirmed_by):
        _raise("APPROVAL_ALREADY_BOUND")
    expires_at = str(intent.get("expires_at", ""))
    parsed_expiry = write_intent.parse_time(expires_at)
    if parsed_expiry is None:
        _raise("EXPIRED_VALIDATED_RECOVERY_EXPIRY_INVALID")
    if parsed_expiry > dt.datetime.now(dt.timezone.utc):
        return intent
    try:
        current_head = write_intent.current_git_head(required=True)
        recovered = write_intent.recover_expired_validated_lease(
            str(intent.get("intent_id", "")),
            actor=ACTOR,
            raw_session_id=raw_session_id,
            target=target.path,
            fencing_token=int(intent.get("fencing_token") or 0),
            expected_expires_at=expires_at,
            expected_base_raw_sha256=str(intent.get("base_raw_sha256", "")),
            expected_base_canonical_sha256=str(
                intent.get("base_canonical_sha256", "")
            ),
            expected_base_git_head=str(intent.get("base_git_head", "")),
            expected_read_token=str(intent.get("read_token", "")),
            expected_scope_app_id=str(intent.get("scope_app_id", "")),
            expected_scope_project_id=str(
                intent.get("scope_project_id", "")
            ),
            expected_proposal_raw_sha256=str(
                intent.get("proposal_raw_sha256", "")
            ),
            expected_proposal_canonical_sha256=str(
                intent.get("proposal_canonical_sha256", "")
            ),
            expected_proposal_size_bytes=int(
                intent.get("proposal_size_bytes") or 0
            ),
            expected_final_raw_sha256=str(
                intent.get("final_raw_sha256", "")
            ),
            expected_final_canonical_sha256=str(
                intent.get("final_canonical_sha256", "")
            ),
            expected_validated_git_head=str(
                intent.get("validated_git_head", "")
            ),
            expected_early_commit=bool(int(intent.get("early_commit") or 0)),
            expected_proposal_commit=str(intent.get("proposal_commit", "")),
            expected_evidence_ref_sha256=str(
                intent.get("evidence_ref_sha256", "")
            ),
            expected_operation="content_update",
            expected_reconcile_action=str(
                intent.get("reconcile_action", "")
            ).upper(),
            expected_approved_by=str(intent.get("approved_by", "")),
            expected_approval_ref_sha256=str(
                intent.get("approval_ref_sha256", "")
            ),
            expected_approval_binding_sha256=str(
                intent.get("approval_binding_sha256", "")
            ),
            expected_claim_ref_sha256=str(
                intent.get("claim_ref_sha256", "")
            ),
            expected_current_git_head=current_head,
        )
    except write_intent.IntentError as exc:
        _raise(exc.reason_code, retryable=False)
    return recovered


def _apply_locked(
    request: dict[str, Any],
    *,
    raw_session_id: str,
) -> dict[str, Any]:
    proposal_id, fencing_token, raw_target, digest, proposal, confirmed_by, confirmation_ref = _validate_apply_request(request)
    intent = _authorized_intent(proposal_id, raw_session_id=raw_session_id)
    status = str(intent.get("status", ""))
    if int(intent.get("fencing_token") or 0) != fencing_token:
        _raise("LEASE_FENCED")
    action = str(intent.get("reconcile_action", "")).upper()
    operation = str(intent.get("operation", "content_update")).casefold()
    if (
        operation in {"status_transition", "governance_migration"}
        and ACTOR not in {"codex", "claude"}
    ):
        _raise("STATUS_TRANSITION_FORBIDDEN")
    target_status = str(intent.get("target_status", "")).casefold()
    sensitive_confirmation = _requires_confirmation_capability(action, operation)
    capability_path, capability_token = _confirmation_capability_input(request)
    if action not in WRITABLE_ACTIONS:
        _raise("MERGE_REQUIRED" if action == "MERGE_REQUIRED" else "NOOP")
    if not sensitive_confirmation and (capability_path or capability_token):
        _raise("CONFIRMATION_CAPABILITY_INVALID")
    if (
        not sensitive_confirmation
        and not confirmed_by
        and status != "completed"
    ):
        _raise("USER_CONFIRMATION_REQUIRED")
    if sensitive_confirmation and str(intent.get("status", "")) == "pending" and (
        not capability_path or not capability_token
    ):
        _raise("CONFIRMATION_CAPABILITY_REQUIRED")
    target = (
        _recovery_target(raw_target)
        if status in write_intent.TERMINAL_STATUSES
        else _formal_target(raw_target)
    )
    stored_target_key = str(intent.get("target_key", ""))
    legacy_completed_target_key = bool(
        status == "completed"
        and str(intent.get("target_rel_path", "")) == target.rel_path
        and SHA256_RE.fullmatch(stored_target_key) is not None
    )
    if (
        target.target_key != stored_target_key
        and not legacy_completed_target_key
    ):
        _raise("APPROVAL_TARGET_MISMATCH")
    if (
        digest.raw_sha256 != str(intent.get("proposal_raw_sha256", ""))
        or digest.canonical_sha256 != str(intent.get("proposal_canonical_sha256", ""))
    ):
        _raise("PROPOSAL_CONTENT_MISMATCH")
    receipt: object = None
    if status in write_intent.TERMINAL_STATUSES:
        shown = _record_for_authorized_intent(
            proposal_id,
            intent,
        )
        terminal_intent = shown.get("intent")
        if not isinstance(terminal_intent, dict):
            _raise("INTENT_NOT_FOUND")
        intent = terminal_intent
        receipt = shown.get("receipt")
    if status == "completed":
        if sensitive_confirmation:
            if not write_intent.has_valid_confirmation_capability_approval(intent):
                _raise("CONFIRMATION_CAPABILITY_INVALID")
        if not isinstance(receipt, dict) or str(receipt.get("outcome", "")) != "completed":
            _raise("RECEIPT_OUTCOME_CONFLICT")
        try:
            write_intent.verify_terminal_receipt(intent, receipt)
        except write_intent.IntentError as exc:
            _raise(exc.reason_code)
        return {
            "closeout_required": False,
            "payload": _completed_response(intent=intent, receipt=receipt, idempotent=True),
        }
    if status in {"failed", "cancelled", "expired"}:
        return {
            "closeout_required": False,
            "payload": _terminal_response_with_claim_release(
                intent=intent,
                receipt=receipt,
                raw_session_id=raw_session_id,
                idempotent=True,
                stage="apply",
                operation_ok=False,
            ),
        }
    _validate_governance_migration_target(
        target,
        operation=operation,
    )
    app_id, project_id = _intent_scope_binding(
        intent,
        target=target,
        raw_session_id=raw_session_id,
    )
    allow_supporting_document = _allow_supporting_document(
        target,
        operation=operation,
        legacy_scope_migration=action == "MIGRATE_LEGACY_SCOPE",
    )
    _validate_writer_markdown(
        proposal,
        path=target.path,
        app_id=app_id,
        project_id=project_id,
        require_explicit_write_scope=True,
        allow_supporting_document=allow_supporting_document,
        allowed_statuses=(
            {target_status}
            if operation == "status_transition"
            else (
                memory_index.GOVERNANCE_MIGRATION_STATUSES
                if operation == "governance_migration"
                else CONTENT_UPDATE_STATUSES
            )
        ),
    )
    # Apply replays the same temporal/risk gate from immutable intent fields.
    # Nothing supplied only in the apply JSON may lower the classification
    # that was bound during prepare.
    _validate_write_temporal_gate(
        proposal_text=proposal,
        knowledge_kind=str(intent.get("knowledge_kind", "")),
        evidence_ref=str(intent.get("evidence_ref_sha256", "")),
        operation=(
            "legacy_scope_migration"
            if action == "MIGRATE_LEGACY_SCOPE"
            else operation
        ),
        governance_target=_is_governance_target(target.path),
        target_relative_path=str(intent.get("target_rel_path", target.rel_path)),
    )
    if _has_conditional_recovery_sidecar(target, proposal_id):
        _raise("TARGET_WRITE_RECOVERY_REQUIRED", retryable=True)

    immutable_policy_base_exists = False
    immutable_policy_base: write_intent.ContentDigest | None = None
    strict_pending_risk_candidate = False
    if (
        operation == "content_update"
        and action != "MIGRATE_LEGACY_SCOPE"
    ):
        immutable_policy_base_exists, immutable_policy_base = _immutable_git_base(
            target=target,
            git_head=str(intent.get("base_git_head", "")),
        )
    if operation == "content_update" and action != "MIGRATE_LEGACY_SCOPE":
        if immutable_policy_base is None:
            _raise("INTENT_BINDING_INVALID")
        proposal_policy_meta = _temporal_parse_frontmatter(proposal)
        proposal_policy_fact = memory_index.fact_metadata(proposal_policy_meta)
        strict_pending_risk_candidate = bool(
            memory_index.as_text(
                proposal_policy_meta.get("status"), "active"
            ).strip().casefold()
            == "pending_verification"
            and memory_index.as_text(
                proposal_policy_meta.get("risk_class")
            ).strip().casefold()
            == "action_sensitive"
            and bool(proposal_policy_fact.get("enabled"))
        )
        if strict_pending_risk_candidate and not immutable_policy_base_exists:
            _raise("INTENT_BINDING_INVALID")
        _content_update_status(
            base_text=immutable_policy_base.text,
            proposal_text=proposal,
            base_exists=immutable_policy_base_exists,
            governance_target=_is_governance_target(target.path),
        )

    shown = write_intent.show_intent(proposal_id)
    receipt = shown.get("receipt")
    if status == "completed":
        if not isinstance(receipt, dict) or str(receipt.get("outcome", "")) != "completed":
            _raise("RECEIPT_OUTCOME_CONFLICT")
        exists, current = _target_digest(target)
        if not exists or current.raw_sha256 != str(intent.get("final_raw_sha256", "")):
            _raise("COMPLETED_CONTENT_CHANGED")
        return {
            "closeout_required": False,
            "payload": _completed_response(intent=intent, receipt=receipt, idempotent=True),
        }
    if status in {"failed", "cancelled", "expired"}:
        _raise("INTENT_EXPIRED" if status == "expired" else "INTENT_NOT_APPLICABLE")
    if (
        status == "validated"
        and operation == "content_update"
        and action in {"ADD", "UPDATE"}
    ):
        parsed_expiry = write_intent.parse_time(str(intent.get("expires_at", "")))
        if parsed_expiry is None:
            _raise("EXPIRED_VALIDATED_RECOVERY_EXPIRY_INVALID")
        if parsed_expiry <= dt.datetime.now(dt.timezone.utc):
            intent = _recover_expired_committed_content_update(
                intent,
                target=target,
                raw_session_id=raw_session_id,
                confirmation_ref=confirmation_ref,
                confirmed_by=confirmed_by,
            )
            status = str(intent.get("status", ""))
    try:
        write_intent.assert_current_lease(
            proposal_id,
            actor=ACTOR,
            raw_session_id=raw_session_id,
            fencing_token=fencing_token,
            target=target.path,
        )
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)

    consumed_confirmation: object | None = None
    effective_approved_by = confirmed_by
    effective_approval_ref = confirmation_ref
    if sensitive_confirmation and status == "pending":
        if not capability_path or not capability_token:
            _raise("CONFIRMATION_CAPABILITY_REQUIRED")
        raw_task_id = _confirmation_raw_task_id(raw_session_id)
        try:
            consumed_confirmation = confirmation_capability.consume_confirmation_capability(
                CONFIG_ROOT,
                capability_path=capability_path,
                token=capability_token,
                subject_actor=ACTOR,
                raw_task_id=raw_task_id,
                raw_session_id=raw_session_id,
                proposal_id=proposal_id,
                proposal_raw_sha256=digest.raw_sha256,
                proposal_canonical_sha256=digest.canonical_sha256,
                target_relative_path=target.rel_path,
                target_key=target.target_key,
                operation=operation,
                reconcile_action=action,
                fencing_token=fencing_token,
                # Consumption is journaled before the intent approval.  If the
                # process dies in that narrow window, retry may recover only
                # this exact proposal/session/target/fence binding.
                allow_idempotent_recovery=True,
            )
            effective_approved_by = write_intent.HUMAN_CONFIRMATION_CAPABILITY_APPROVER
            effective_approval_ref = confirmation_capability.approval_reference(consumed_confirmation)
        except confirmation_capability.ConfirmationCapabilityError as exc:
            _raise(exc.reason_code)
    elif sensitive_confirmation and status in {"approved", "bound", "validated"}:
        if not write_intent.has_valid_confirmation_capability_approval(intent):
            _raise("CONFIRMATION_CAPABILITY_INVALID")

    if status in {"pending", "approved"} and not (
        sensitive_confirmation and status == "approved"
    ):
        try:
            write_intent.approve_intent(
                proposal_id,
                actor=ACTOR,
                raw_session_id=raw_session_id,
                raw_task_id=_confirmation_raw_task_id(raw_session_id),
                target=target.path,
                proposal_raw_sha256=digest.raw_sha256,
                proposal_canonical_sha256=digest.canonical_sha256,
                approved_by=effective_approved_by,
                approval_ref=effective_approval_ref,
                confirmation_capability=consumed_confirmation,
            )
        except write_intent.IntentError as exc:
            _raise(exc.reason_code)
        intent = _authorized_intent(proposal_id, raw_session_id=raw_session_id)
        status = str(intent.get("status", ""))
    elif status in {"approved", "bound", "validated"}:
        if sensitive_confirmation:
            if not write_intent.has_valid_confirmation_capability_approval(intent):
                _raise("CONFIRMATION_CAPABILITY_INVALID")
        elif not _approval_matches(intent, confirmation_ref, confirmed_by):
            _raise("APPROVAL_ALREADY_BOUND")

    if status in {"pending", "approved"}:
        try:
            memory_claim.claim_paths(ACTOR, raw_session_id, [str(target.path)], proposal_id)
        except write_intent.IntentError as exc:
            _raise(exc.reason_code, retryable=exc.reason_code == "ACTIVE_TARGET_CONFLICT")
        except (OSError, ValueError) as exc:
            raise MemoryWriteError("CLAIM_FAILED", "无法认领目标记忆文件。", retryable=True) from exc
        intent = _authorized_intent(proposal_id, raw_session_id=raw_session_id)
        status = str(intent.get("status", ""))

    if status not in {"bound", "validated"}:
        _raise("INTENT_NOT_APPLICABLE")
    if not _claim_matches(proposal_id, raw_session_id=raw_session_id, target=target.path):
        _raise("CLAIM_MISSING_FOR_RECOVERY")
    try:
        write_intent.assert_current_lease(
            proposal_id,
            actor=ACTOR,
            raw_session_id=raw_session_id,
            fencing_token=fencing_token,
            target=target.path,
        )
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)

    exists, current = _target_digest(target)
    if exists:
        _validate_writer_markdown(
            current.text,
            path=target.path,
            app_id=app_id,
            project_id=project_id,
            require_explicit_write_scope=False,
            allow_supporting_document=allow_supporting_document,
            allowed_statuses=(
                (
                    memory_index.GOVERNANCE_MIGRATION_STATUSES
                    if operation == "governance_migration"
                    else MEMORY_STATUSES
                )
                if operation in {"status_transition", "governance_migration"}
                else CONTENT_UPDATE_STATUSES
            ),
        )
    try:
        current_git_head = write_intent.current_git_head(required=True)
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    proposal_already_written = exists and current.raw_sha256 == digest.raw_sha256
    base_matches = (
        int(intent.get("base_exists", 0)) == int(exists)
        and current.raw_sha256 == str(intent.get("base_raw_sha256", ""))
        and current.canonical_sha256 == str(intent.get("base_canonical_sha256", ""))
        and current_git_head == str(intent.get("base_git_head", ""))
    )
    if status == "validated" and not proposal_already_written:
        _raise("TARGET_CHANGED_AFTER_CLAIM")
    apply_status_transition: dict[str, str] = {}
    status_transition_base_text = ""
    status_transition_proposal_text = proposal
    temporal_base_text = current.text if exists else ""
    temporal_proposal_text = proposal
    strict_risk_only_content_update = False
    if operation == "content_update" and (proposal_already_written or base_matches):
        adopt_risk_only_replay = bool(
            action == "ADOPT"
            and proposal_already_written
            and strict_pending_risk_candidate
            and immutable_policy_base is not None
            and immutable_policy_base_exists
        )
        if adopt_risk_only_replay:
            canonical_base_text = write_intent.canonicalize_text(
                immutable_policy_base.text
            )
            canonical_proposal_text = write_intent.canonicalize_text(proposal)
            strict_risk_only_content_update = _exact_risk_class_upgrade(
                base_text=canonical_base_text,
                proposal_text=canonical_proposal_text,
            )
            if not strict_risk_only_content_update:
                _raise("INTENT_BINDING_INVALID")
            if (
                not bool(int(intent.get("base_exists") or 0))
                or str(intent.get("base_raw_sha256", ""))
                != current.raw_sha256
                or str(intent.get("base_canonical_sha256", ""))
                != current.canonical_sha256
                or current.raw_sha256 != digest.raw_sha256
                or current.canonical_sha256 != digest.canonical_sha256
            ):
                _raise("INTENT_BINDING_INVALID")
            temporal_base_text = canonical_base_text
            temporal_proposal_text = canonical_proposal_text
        elif base_matches:
            # The intent CAS still exposes the exact original representation,
            # so prove the narrow risk-only transform directly from live bytes.
            strict_risk_only_content_update = bool(
                strict_pending_risk_candidate
                and _exact_risk_class_upgrade(
                    base_text=current.text,
                    proposal_text=proposal,
                )
            )
        elif (
            proposal_already_written
            and strict_pending_risk_candidate
            and immutable_policy_base is not None
            and immutable_policy_base_exists
        ):
            # After the proposal is already written, the original raw checkout
            # is unavailable.  Canonical fallback is limited to this exact
            # risk-only recovery so clean CRLF/filter representations remain
            # recoverable without admitting semantic or frontmatter drift.
            canonical_base_text = write_intent.canonicalize_text(
                immutable_policy_base.text
            )
            canonical_proposal_text = write_intent.canonicalize_text(proposal)
            strict_risk_only_content_update = _exact_risk_class_upgrade(
                base_text=canonical_base_text,
                proposal_text=canonical_proposal_text,
            )
            if not strict_risk_only_content_update:
                _raise("INTENT_BINDING_INVALID")
            if (
                not bool(int(intent.get("base_exists") or 0))
                or str(intent.get("base_canonical_sha256", ""))
                != immutable_policy_base.canonical_sha256
            ):
                _raise("INTENT_BINDING_INVALID")
            temporal_base_text = canonical_base_text
            temporal_proposal_text = canonical_proposal_text
    if operation == "status_transition" and (proposal_already_written or base_matches):
        if base_matches:
            # This is the exact intent base, including any clean CRLF/filter
            # representation.  It is the only safe raw comparison source.
            status_transition_base_text = current.text
        else:
            immutable_policy_base_exists, immutable_policy_base = _immutable_git_base(
                target=target,
                git_head=str(intent.get("base_git_head", "")),
            )
            if immutable_policy_base is None or not immutable_policy_base_exists:
                _raise("TARGET_MISSING")
            canonical_base_text = write_intent.canonicalize_text(
                immutable_policy_base.text
            )
            canonical_proposal_text = write_intent.canonicalize_text(proposal)
            if _exact_risk_class_upgrade(
                base_text=canonical_base_text,
                proposal_text=canonical_proposal_text,
                target_status=target_status,
            ):
                if (
                    not bool(int(intent.get("base_exists") or 0))
                    or str(intent.get("base_canonical_sha256", ""))
                    != immutable_policy_base.canonical_sha256
                ):
                    _raise("INTENT_BINDING_INVALID")
                status_transition_base_text = canonical_base_text
                status_transition_proposal_text = canonical_proposal_text
            else:
                status_transition_base_text = immutable_policy_base.text
        apply_status_transition = _validate_status_transition(
            base_text=status_transition_base_text,
            proposal_text=status_transition_proposal_text,
            target_status=target_status,
            evidence_ref=str(intent.get("evidence_ref_sha256", "")),
        )
        temporal_base_text = status_transition_base_text
        temporal_proposal_text = status_transition_proposal_text
    if proposal_already_written or base_matches:
        _validate_temporal_transition(
            selected_target=target,
            base_text=temporal_base_text,
            proposal_text=temporal_proposal_text,
            operation=operation,
            validated_status_transition=apply_status_transition or None,
        )
    if base_matches and operation == "status_transition":
        if not _is_governance_target(target.path):
            _validate_memory_identity(
                base_text=current.text,
                proposal_text=proposal,
                target_exists=True,
                expected_new_memory_id="",
            )
    if base_matches and operation == "governance_migration":
        _validate_governance_migration(
            rel_path=target.rel_path,
            base_text=current.text,
            proposal_text=proposal,
        )
    if not proposal_already_written:
        if not base_matches:
            _terminalize_safe_concurrent_failure(
                proposal_id,
                raw_session_id=raw_session_id,
                target=target.path,
            )
            _raise("TARGET_CHANGED_AFTER_CLAIM", retryable=True)
        if action == "MIGRATE_LEGACY_SCOPE":
            _validate_legacy_scope_migration(
                actor=ACTOR,
                target_relative_path=target.rel_path,
                requested_app_id=app_id,
                requested_project_id=project_id,
                legacy_scope_app_id=app_id,
                base_text=current.text,
                proposal_text=proposal,
            )
        try:
            write_intent.assert_current_lease(
                proposal_id,
                actor=ACTOR,
                raw_session_id=raw_session_id,
                fencing_token=fencing_token,
                target=target.path,
            )
        except write_intent.IntentError as exc:
            _raise(exc.reason_code)
        try:
            _atomic_conditional_write(
                target,
                proposal,
                proposal_id=proposal_id,
                expected_exists=bool(intent.get("base_exists", 0)),
                expected_raw_sha256=str(intent.get("base_raw_sha256", "")),
            )
        except MemoryWriteError as exc:
            if exc.reason_code == "TARGET_CHANGED_AFTER_CLAIM":
                _terminalize_safe_concurrent_failure(
                    proposal_id,
                    raw_session_id=raw_session_id,
                    target=target.path,
                )
            raise
        exists, current = _target_digest(target)
        if not exists or current.raw_sha256 != digest.raw_sha256:
            _terminalize_safe_concurrent_failure(
                proposal_id,
                raw_session_id=raw_session_id,
                target=target.path,
            )
            _raise("TARGET_CHANGED_AFTER_CLAIM", retryable=True)

    try:
        validation = write_intent.validate_closeout(
            proposal_id,
            actor=ACTOR,
            raw_session_id=raw_session_id,
            target=target.path,
            require_bound=True,
            mutate=True,
        )
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    if not bool(validation.get("ok")):
        _raise(str(validation.get("reason_code") or "CLOSEOUT_FAILED"))

    return {
        "closeout_required": True,
        "proposal_id": proposal_id,
        "proposal_raw_sha256": digest.raw_sha256,
        "proposal_already_written": proposal_already_written,
        "adoption": action == "ADOPT",
        "scope_migration": action == "MIGRATE_LEGACY_SCOPE",
    }


def apply(
    request: dict[str, Any],
    *,
    raw_session_id: str,
    closeout_timeout: float,
    lock_timeout: float = 15,
) -> dict[str, Any]:
    # Never hold closeout.lock while spawning closeout, which acquires the same
    # lock. The DB path lease remains authoritative during this short hand-off.
    with writer_lock(lock_timeout):
        try:
            prepared = _apply_locked(request, raw_session_id=raw_session_id)
        except MemoryWriteError as exc:
            # A CAS rejection persists its terminal receipt before returning.
            # Surface that first receipt immediately so a lost response and a
            # replay converge on the same immutable outcome.
            if exc.reason_code != "TARGET_CHANGED_AFTER_CLAIM":
                raise
            proposal_id = request.get("proposal_id")
            if isinstance(proposal_id, str) and PROPOSAL_ID_RE.fullmatch(proposal_id):
                try:
                    shown = _authorized_intent_record(
                        proposal_id,
                        raw_session_id=raw_session_id,
                    )
                    terminal_intent = shown.get("intent")
                    if (
                        isinstance(terminal_intent, dict)
                        and str(terminal_intent.get("status", ""))
                        in {"failed", "cancelled", "expired"}
                    ):
                        return _terminal_response_with_claim_release(
                            intent=terminal_intent,
                            receipt=shown.get("receipt"),
                            raw_session_id=raw_session_id,
                            idempotent=False,
                            stage="apply",
                            operation_ok=False,
                        )
                except MemoryWriteError:
                    pass
            raise
    if not bool(prepared.get("closeout_required")):
        payload = prepared.get("payload")
        if not isinstance(payload, dict):
            _raise("WRITE_INTERNAL_ERROR")
        return payload

    proposal_id = str(prepared.get("proposal_id", ""))
    _run_closeout(raw_session_id=raw_session_id, timeout_seconds=closeout_timeout)
    shown = write_intent.show_intent(proposal_id)
    completed_intent = shown.get("intent")
    completed_receipt = shown.get("receipt")
    if (
        not isinstance(completed_intent, dict)
        or not isinstance(completed_receipt, dict)
        or str(completed_intent.get("status", "")) != "completed"
        or str(completed_receipt.get("outcome", "")) != "completed"
    ):
        _raise("CLOSEOUT_FAILED")
    try:
        write_intent.verify_terminal_receipt(completed_intent, completed_receipt)
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    target = _formal_target(str(completed_intent.get("target_rel_path", "")))
    exists, current = _target_digest(target)
    if not exists or current.raw_sha256 != str(prepared.get("proposal_raw_sha256", "")):
        _raise("COMPLETED_CONTENT_CHANGED")
    return _completed_response(
        intent=completed_intent,
        receipt=completed_receipt,
        idempotent=bool(prepared.get("proposal_already_written")),
    )


def cancel(request: dict[str, Any], *, raw_session_id: str) -> dict[str, Any]:
    proposal_id = _required_string(request, "proposal_id", max_chars=64)
    if PROPOSAL_ID_RE.fullmatch(proposal_id) is None:
        _raise("REQUEST_INVALID")
    fencing_token = _required_positive_int(request, "fencing_token")
    intent = _authorized_intent(proposal_id, raw_session_id=raw_session_id)
    if int(intent.get("fencing_token") or 0) != fencing_token:
        _raise("LEASE_FENCED")
    status = str(intent.get("status", ""))
    if status == "cancelled":
        shown = _record_for_authorized_intent(proposal_id, intent)
        return _terminal_response_with_claim_release(
            intent=intent,
            receipt=shown.get("receipt"),
            raw_session_id=raw_session_id,
            idempotent=True,
            stage="cancel",
            operation_ok=True,
        )
    if status not in write_intent.ACTIVE_STATUSES:
        _raise("INTENT_NOT_CANCELLABLE")
    try:
        write_intent.assert_current_lease(
            proposal_id,
            actor=ACTOR,
            raw_session_id=raw_session_id,
            fencing_token=fencing_token,
        )
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    target = _recovery_target(str(intent.get("target_rel_path", "")))
    if status in {"bound", "validated"}:
        exists, current = _target_digest(target)
        base_unchanged = (
            int(intent.get("base_exists", 0)) == int(exists)
            and current.raw_sha256 == str(intent.get("base_raw_sha256", ""))
        )
        if not base_unchanged:
            _raise("APPLY_RECOVERY_REQUIRED", retryable=True)
    try:
        receipt = write_intent.cancel_intent(
            proposal_id,
            actor=ACTOR,
            raw_session_id=raw_session_id,
            reason_code="CANCELLED_BY_USER",
            fencing_token=fencing_token,
        )
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    cancelled_intent = {
        **intent,
        "status": "cancelled",
        "reason_code": str(receipt.get("reason_code", "")),
        "updated_at": str(receipt.get("created_at", "")),
    }
    return _terminal_response_with_claim_release(
        intent=cancelled_intent,
        receipt=receipt,
        raw_session_id=raw_session_id,
        idempotent=False,
        stage="cancel",
        operation_ok=True,
        target=target,
    )


def _recovery_receipt_payload(
    intent: dict[str, Any],
    receipt: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, bool]:
    status_value = str(intent.get("status", ""))
    if status_value in write_intent.TERMINAL_STATUSES:
        if not isinstance(receipt, dict):
            _raise("RECEIPT_INTEGRITY_INVALID")
        try:
            verified = write_intent.verify_terminal_receipt(intent, receipt)
        except write_intent.IntentError as exc:
            _raise(exc.reason_code)
        return {
            "receipt_id": str(verified.get("receipt_id", "")),
            "outcome": str(verified.get("outcome", "")),
            "reason_code": str(verified.get("reason_code", "")),
            "git_commit": str(verified.get("git_commit", "")),
            "git_blob_verified": bool(verified.get("git_blob_verified")),
            "created_at": str(verified.get("created_at", "")),
        }, True
    if receipt is not None:
        _raise("RECEIPT_INTEGRITY_INVALID")
    return None, False


def _recovery_item(
    intent: dict[str, Any],
    receipt: dict[str, Any] | None,
) -> dict[str, Any]:
    status_value = str(intent.get("status", ""))
    if status_value not in {*write_intent.ACTIVE_STATUSES, *write_intent.TERMINAL_STATUSES}:
        _raise("INTENT_NOT_APPLICABLE")
    receipt_payload, receipt_verified = _recovery_receipt_payload(intent, receipt)
    target = _recovery_target(str(intent.get("target_rel_path", "")))
    exists, current = _target_digest(target)
    current_raw = current.raw_sha256 if exists else ""
    target_state = "missing"
    if exists:
        if current_raw == str(intent.get("final_raw_sha256", "")) and current_raw:
            target_state = "final"
        elif current_raw == str(intent.get("proposal_raw_sha256", "")):
            target_state = "proposal"
        elif (
            int(intent.get("base_exists", 0)) == 1
            and current_raw == str(intent.get("base_raw_sha256", ""))
        ):
            target_state = "base"
        else:
            target_state = "other"
    elif int(intent.get("base_exists", 0)) == 0:
        target_state = "base"
    lease_expires_at = str(intent.get("expires_at", ""))
    expiry = write_intent.parse_time(lease_expires_at)
    lease_expired = bool(
        status_value in write_intent.ACTIVE_STATUSES
        and expiry is not None
        and expiry <= dt.datetime.now(dt.timezone.utc)
    )
    recovery_sidecar = _has_conditional_recovery_sidecar(
        target,
        str(intent.get("intent_id", "")),
    )
    if status_value == "completed":
        recovery_action = "mark_succeeded"
    elif status_value in write_intent.TERMINAL_STATUSES:
        recovery_action = "mark_terminal"
    elif recovery_sidecar or target_state == "other":
        recovery_action = "manual_recovery"
    elif lease_expired:
        recovery_action = "manual_reprepare"
    elif status_value == "validated" and target_state in {"proposal", "final"}:
        recovery_action = "resume_closeout"
    else:
        recovery_action = "manual_continue_or_cancel"
    return {
        "proposal_id": str(intent.get("intent_id", "")),
        "intent_status": status_value,
        "fencing_token": int(intent.get("fencing_token") or 0),
        "target_relative_path": str(intent.get("target_rel_path", "")),
        "scope_app_id": str(intent.get("scope_app_id", "")),
        "scope_project_id": str(intent.get("scope_project_id", "")),
        "recommended_action": str(intent.get("reconcile_action", "")),
        "operation": str(intent.get("operation", "content_update")),
        "target_status": str(intent.get("target_status", "")),
        "base_exists": bool(intent.get("base_exists", 0)),
        "base_raw_sha256": str(intent.get("base_raw_sha256", "")),
        "proposal_raw_sha256": str(intent.get("proposal_raw_sha256", "")),
        "proposal_canonical_sha256": str(intent.get("proposal_canonical_sha256", "")),
        "final_raw_sha256": str(intent.get("final_raw_sha256", "")),
        "final_canonical_sha256": str(intent.get("final_canonical_sha256", "")),
        "target_state": target_state,
        "lease_expires_at": lease_expires_at,
        "lease_expired": lease_expired,
        "recovery_sidecar": recovery_sidecar,
        "recovery_action": recovery_action,
        "receipt_verified": receipt_verified,
        "receipt": receipt_payload,
        "updated_at": str(intent.get("updated_at", "")),
    }


def status(request: dict[str, Any], *, raw_session_id: str) -> dict[str, Any]:
    proposal_id = _required_string(request, "proposal_id", max_chars=64)
    if PROPOSAL_ID_RE.fullmatch(proposal_id) is None:
        _raise("REQUEST_INVALID")
    shown = _inspect_authorized_intent(proposal_id, raw_session_id=raw_session_id)
    intent = shown.get("intent")
    if not isinstance(intent, dict):
        _raise("INTENT_NOT_FOUND")
    item = _recovery_item(
        intent,
        shown.get("receipt") if isinstance(shown.get("receipt"), dict) else None,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "ok": True,
        "stage": "status",
        "status": str(item["intent_status"]),
        **item,
    }


def list_recovery(request: dict[str, Any], *, raw_session_id: str) -> dict[str, Any]:
    raw_limit = request.get("limit", 50)
    if isinstance(raw_limit, bool) or not isinstance(raw_limit, int):
        _raise("REQUEST_INVALID")
    raw_cursor = request.get("cursor", "")
    if not isinstance(raw_cursor, str):
        _raise("REQUEST_INVALID")
    raw_statuses = request.get("statuses", [])
    if not isinstance(raw_statuses, list) or any(
        not isinstance(item, str) for item in raw_statuses
    ):
        _raise("REQUEST_INVALID")
    try:
        page = write_intent.list_session_intents(
            actor=ACTOR,
            raw_session_id=raw_session_id,
            statuses=raw_statuses,
            limit=raw_limit,
            cursor=raw_cursor,
        )
    except StateSecurityError as exc:
        raise MemoryWriteError(
            "STATE_SNAPSHOT_BUSY",
            _error_message("STATE_SNAPSHOT_BUSY"),
            retryable=True,
        ) from exc
    except write_intent.IntentError as exc:
        _raise(exc.reason_code)
    items: list[dict[str, Any]] = []
    for row in page.get("items", []):
        if not isinstance(row, dict) or not isinstance(row.get("intent"), dict):
            _raise("RECEIPT_INTEGRITY_INVALID")
        items.append(
            _recovery_item(
                row["intent"],
                row.get("receipt") if isinstance(row.get("receipt"), dict) else None,
            )
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "ok": True,
        "stage": "list",
        "status": "ok",
        "items": items,
        "next_cursor": str(page.get("next_cursor", "")),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Two-phase host API for formal Agent Memory writes.",
        allow_abbrev=False,
    )
    parser.add_argument("--actor", choices=SUPPORTED_WRITER_ACTORS, default="ailu")
    parser.add_argument("--session-id", default="")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--lock-timeout", type=float, default=15)
    parser.add_argument("--closeout-timeout", type=float, default=300)
    parser.add_argument(
        "action",
        choices=("read-target", "prepare", "apply", "cancel", "status", "list"),
    )
    return parser.parse_args()


def main() -> int:
    global ACTOR
    args = parse_args()
    ACTOR = args.actor
    if PLATFORM_NAME == "nt" and args.action not in WINDOWS_READ_ONLY_ACTIONS:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "ok": False,
            "stage": args.action,
            "status": "blocked",
            "reason_code": "WINDOWS_READ_ONLY",
            "message": "Agent Memory is read-only on Windows.",
            "retryable": False,
        }
        print(json.dumps(payload, separators=(",", ":")))
        return 2
    try:
        if args.action in {"status", "list"}:
            assert_runtime_ready("write", side_effect_free_state=True)
        else:
            assert_runtime_ready("write")
        raw_session_id = _raw_session_id(args.session_id)
        request = _read_request()
        if args.action == "read-target":
            payload = read_target(request, raw_session_id=raw_session_id)
        elif args.action == "status":
            payload = status(request, raw_session_id=raw_session_id)
        elif args.action == "list":
            payload = list_recovery(request, raw_session_id=raw_session_id)
        elif args.action == "apply":
            payload = apply(
                request,
                raw_session_id=raw_session_id,
                closeout_timeout=max(float(args.closeout_timeout), 1),
                lock_timeout=max(float(args.lock_timeout), 0),
            )
        else:
            with writer_lock(args.lock_timeout):
                if args.action == "prepare":
                    payload = prepare(request, raw_session_id=raw_session_id)
                else:
                    payload = cancel(request, raw_session_id=raw_session_id)
    except RuntimeTransitionError:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "ok": False,
            "stage": getattr(args, "action", "unknown"),
            "status": "blocked",
            "reason_code": "RUNTIME_TRANSITION_INCOMPLETE",
            "message": "Agent Memory runtime migration is incomplete.",
            "retryable": False,
        }
    except MemoryWriteError as exc:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "ok": False,
            "stage": getattr(args, "action", "unknown"),
            "status": "blocked",
            "reason_code": exc.reason_code,
            "message": exc.safe_message,
            "retryable": exc.retryable,
        }
    except (OSError, ValueError, write_intent.IntentError) as exc:
        reason_code = _safe_code(str(getattr(exc, "reason_code", "WRITE_INTERNAL_ERROR")))
        payload = {
            "schema_version": SCHEMA_VERSION,
            "ok": False,
            "stage": getattr(args, "action", "unknown"),
            "status": "blocked",
            "reason_code": reason_code,
            "message": _error_message(reason_code),
            "retryable": False,
        }
    except Exception:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "ok": False,
            "stage": getattr(args, "action", "unknown"),
            "status": "blocked",
            "reason_code": "WRITE_INTERNAL_ERROR",
            "message": "正式记忆写入内部异常，未继续执行。",
            "retryable": False,
        }
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
