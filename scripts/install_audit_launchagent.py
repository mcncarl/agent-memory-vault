#!/usr/bin/env python3
"""Plan, install, verify, or roll back the managed macOS audit LaunchAgent.

Plan is read-only. Apply uses a non-overwriting private backup, byte-level CAS,
and a durable journal. A failed fresh install preserves the newly created plist
inside the backup directory instead of deleting it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from agent_memory_env import load_config
from agent_memory_lock import private_lock
from agent_memory_host_automation import (
    AMBIGUOUS,
    AUDIT_LAUNCHAGENT_LABEL_PATTERN,
    CANONICAL,
    DEFAULT_AUDIT_LAUNCHAGENT_LABEL,
    LaunchAgentSpec,
    RouteClassification,
    classify_launchagent_payload,
    discover_all_audit_launchagents,
    launchagent_bytes,
    launchctl_health,
    load_launchagent_payload,
)
from agent_memory_state import (
    ConditionalWriteError,
    PRIVATE_FILE_MODE,
    ensure_private_directory,
    secure_conditional_create_bytes_beneath,
    secure_conditional_move_bytes_beneath,
    secure_conditional_write_bytes_beneath,
)


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
LAUNCHAGENT_STATE_RELATIVE = Path("config/audit-launchagent-transactions.jsonl")
LAUNCHAGENT_TERMINAL_EVENTS = {"completed", "rolled_back", "abandoned"}
LAUNCHAGENT_STATE_EVENTS = {
    "prepared", "deferred", "completed", "rolled_back", "abandoned",
    "recovery_required", "journal_tail_recovered",
}
LAUNCHAGENT_CHILD_EVENTS = {
    "prepared", "plist_applied", "deferred", "completed", "rolled_back",
    "manual_rollback_completed", "recovery_required", "journal_tail_recovered",
}


class LaunchAgentError(RuntimeError):
    def __init__(self, reason_code: str, *, stage: str = "launchagent") -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.stage = stage


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def safe_bytes(path: Path) -> tuple[bytes, bool]:
    if path.is_symlink():
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_UNSAFE", stage="plan")
    if not path.exists():
        return b"", False
    if not path.is_file():
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_UNSAFE", stage="plan")
    return path.read_bytes(), True


def _safe_runtime_target(path: Path, *, executable: bool, allow_symlink: bool) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(metadata.st_mode):
        if not allow_symlink:
            return False
        try:
            valid = path.is_file()
        except OSError:
            return False
    else:
        valid = stat.S_ISREG(metadata.st_mode)
    return valid and (not executable or os.access(path, os.X_OK))


def atomic_write(path: Path, content: bytes, *, expected_before: bytes, expected_existed: bool) -> None:
    ensure_private_directory(path.parent, harden_existing=False)
    # `/var` is a lexical alias of `/private/var` on macOS. Pin the existing
    # parent's physical path before invoking the no-symlink CAS primitive so a
    # harmless system alias is not confused with an unsafe target leaf.
    security_root = path.parent.resolve(strict=True)
    current, existed = safe_bytes(path)
    if existed != expected_existed or current != expected_before:
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_CHANGED_BEFORE_REPLACE", stage="apply")
    operation_id = hashlib.sha256(
        expected_before + b"\0" + content + b"\0" + uuid.uuid4().hex.encode("ascii")
    ).hexdigest()
    try:
        if expected_existed:
            secure_conditional_write_bytes_beneath(
                security_root,
                Path(path.name),
                content,
                expected_sha256=sha256_bytes(expected_before),
                expected_size=len(expected_before),
                operation_id=operation_id,
                namespace="audit-launchagent",
                max_capture_bytes=max(
                    len(expected_before),
                    len(content),
                    4 * 1024 * 1024,
                ),
                mode=PRIVATE_FILE_MODE,
            )
        else:
            secure_conditional_create_bytes_beneath(
                security_root,
                Path(path.name),
                content,
                operation_id=operation_id,
                namespace="audit-launchagent",
                max_capture_bytes=max(len(content), 4 * 1024 * 1024),
                mode=PRIVATE_FILE_MODE,
            )
    except ConditionalWriteError as exc:
        reason = (
            "AUDIT_LAUNCHAGENT_CHANGED_BEFORE_REPLACE"
            if exc.reason_code == "CONDITIONAL_WRITE_TARGET_CHANGED"
            else "AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED"
        )
        raise LaunchAgentError(reason, stage="apply") from exc
    fsync_directory(path.parent)


def exclusive_backup(path: Path, backup_dir: Path, before: bytes, before_existed: bool) -> Path:
    ensure_private_directory(backup_dir, harden_existing=True)
    suffix = "plist" if before_existed else "absent"
    target = backup_dir / f"{path.parent.name}-{path.name}.before-managed.{suffix}"
    descriptor = os.open(
        target,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        PRIVATE_FILE_MODE,
    )
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        handle.write(before)
        handle.flush()
        os.fsync(handle.fileno())
    fsync_directory(backup_dir)
    return target


def write_journal(path: Path, event: dict[str, Any], *, create: bool = False) -> None:
    flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    with os.fdopen(descriptor, "a+b", closefd=True) as handle:
        handle.seek(0)
        existing = handle.read()
        if existing and not existing.endswith(b"\n"):
            # Keep an interrupted final record as evidence, then bind its exact
            # bytes to a recovery marker before any later transaction event.
            _decode_journal(existing)
            discarded = existing.rsplit(b"\n", 1)[-1]
            marker = {
                "event": "journal_tail_recovered",
                "discarded_sha256": sha256_bytes(discarded),
                "discarded_bytes": len(discarded),
            }
            handle.seek(0, os.SEEK_END)
            handle.write(b"\n")
            handle.write(
                json.dumps(marker, ensure_ascii=False, sort_keys=True).encode("utf-8")
                + b"\n"
            )
        handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    fsync_directory(path.parent)


def launchagent_state_path(spec: LaunchAgentSpec) -> Path:
    return spec.runtime_root / LAUNCHAGENT_STATE_RELATIVE


def append_launchagent_state(
    spec: LaunchAgentSpec,
    *,
    transaction_id: str,
    journal_path: Path,
    event: str,
    reason_code: str = "",
) -> None:
    if not re.fullmatch(r"[0-9a-f]{32}", transaction_id):
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_STATE_INVALID",
            stage="transaction-state",
        )
    state_path = launchagent_state_path(spec)
    ensure_private_directory(state_path.parent, harden_existing=True)
    create = not state_path.exists() and not state_path.is_symlink()
    write_journal(
        state_path,
        {
            "schema_version": 1,
            "transaction_id": transaction_id,
            "event": event,
            "journal_path": str(journal_path),
            "plist_path": str(spec.plist_path),
            "label": spec.label,
            "reason_code": reason_code,
        },
        create=create,
    )


def launchagent_transaction_health(
    runtime_root: Path,
) -> dict[str, Any]:
    """Attest both the fixed pointer and its byte-bound child transaction."""

    state_path = runtime_root / LAUNCHAGENT_STATE_RELATIVE
    base = {
        "state_path": str(state_path),
        "transaction_id": "",
        "journal_path": "",
        "child_status": "missing",
        "journal_events_sha256": "",
        "recovery_required_seen": False,
    }
    if not state_path.exists() and not state_path.is_symlink():
        return {**base, "healthy": True, "status": "none", "reason_code": ""}
    if state_path.is_symlink() or not state_path.is_file():
        return {
            **base,
            "healthy": False,
            "status": "invalid",
            "reason_code": "AUDIT_LAUNCHAGENT_STATE_UNSAFE",
        }
    try:
        rows = _decode_journal(state_path.read_bytes())
    except (OSError, LaunchAgentError):
        return {
            **base,
            "healthy": False,
            "status": "invalid",
            "reason_code": "AUDIT_LAUNCHAGENT_STATE_INVALID",
        }
    prepared_indexes = [
        index for index, row in enumerate(rows) if row.get("event") == "prepared"
    ]
    if not prepared_indexes:
        return {
            **base,
            "healthy": False,
            "status": "invalid",
            "reason_code": "AUDIT_LAUNCHAGENT_STATE_INVALID",
        }
    current = rows[prepared_indexes[-1] :]
    first = current[0]
    transaction_id = str(first.get("transaction_id", ""))
    journal_path = str(first.get("journal_path", ""))
    label = str(first.get("label", ""))
    plist_path = str(first.get("plist_path", ""))
    base.update({"transaction_id": transaction_id, "journal_path": journal_path})
    meaningful = [
        row for row in current if row.get("event") != "journal_tail_recovered"
    ]
    if (
        not re.fullmatch(r"[0-9a-f]{32}", transaction_id)
        or not journal_path
        or not label
        or not plist_path
        or any(str(row.get("event", "")) not in LAUNCHAGENT_STATE_EVENTS for row in current)
        or any(
            str(row.get("transaction_id", "")) != transaction_id
            or str(row.get("journal_path", "")) != journal_path
            or str(row.get("label", "")) != label
            or str(row.get("plist_path", "")) != plist_path
            for row in meaningful
        )
    ):
        return {
            **base,
            "healthy": False,
            "status": "invalid",
            "reason_code": "AUDIT_LAUNCHAGENT_STATE_INVALID",
        }
    last_event = str(meaningful[-1].get("event", "")) if meaningful else ""
    base["recovery_required_seen"] = any(
        row.get("event") == "recovery_required" for row in meaningful
    )
    journal = Path(journal_path)
    if last_event == "abandoned" and not journal.exists() and not journal.is_symlink():
        return {**base, "healthy": True, "status": "terminal", "reason_code": ""}
    if not journal.exists() and not journal.is_symlink():
        status = "pending" if last_event == "prepared" else "invalid"
        return {
            **base,
            "healthy": False,
            "status": status,
            "reason_code": (
                "AUDIT_LAUNCHAGENT_TRANSACTION_PENDING"
                if status == "pending"
                else "AUDIT_LAUNCHAGENT_JOURNAL_MISSING"
            ),
        }
    try:
        prepared, child_rows = read_journal(journal)
        _validated_prepared_backup(
            prepared,
            journal_path=journal,
            expected_transaction_id=transaction_id,
            expected_label=label,
            expected_plist_path=plist_path,
        )
        child_status = _launchagent_child_status(child_rows)
    except (OSError, ValueError, LaunchAgentError):
        return {
            **base,
            "healthy": False,
            "status": "invalid",
            "reason_code": "AUDIT_LAUNCHAGENT_JOURNAL_INVALID",
        }
    base["child_status"] = child_status
    base["journal_events_sha256"] = hashlib.sha256(
        json.dumps(
            child_rows,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    base["recovery_required_seen"] = bool(
        base["recovery_required_seen"]
        or any(row.get("event") == "recovery_required" for row in child_rows)
    )
    if child_status == "recovery_required":
        status = "recovery_required"
        reason_code = "AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED"
    elif (
        (last_event == "completed" and child_status == "completed")
        or (last_event == "rolled_back" and child_status == "rolled_back")
    ):
        status = "terminal"
        reason_code = ""
    elif last_event == "deferred" and child_status == "deferred":
        status = "deferred"
        reason_code = "AUDIT_LAUNCHAGENT_TRANSACTION_DEFERRED"
    else:
        status = "pending"
        reason_code = "AUDIT_LAUNCHAGENT_TRANSACTION_PENDING"
    return {
        **base,
        "healthy": status == "terminal",
        "status": status,
        "reason_code": reason_code,
    }


def _assert_launchagent_state_binding(
    spec: LaunchAgentSpec,
    *,
    transaction_id: str,
    journal_path: Path,
    allowed_statuses: set[str],
) -> dict[str, Any]:
    health = launchagent_transaction_health(spec.runtime_root)
    if health.get("status") == "recovery_required":
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED",
            stage="transaction-state",
        )
    if (
        health.get("transaction_id") != transaction_id
        or health.get("journal_path") != str(journal_path)
        or health.get("status") not in allowed_statuses
    ):
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_STATE_MISMATCH",
            stage="transaction-state",
        )
    return health


def reconcile_launchagent_transaction(spec: LaunchAgentSpec) -> dict[str, Any]:
    """Close a crash window from the fixed pointer using its bound journal."""

    health = launchagent_transaction_health(spec.runtime_root)
    if health["healthy"]:
        return health
    if health["status"] == "invalid":
        raise LaunchAgentError(
            str(health["reason_code"]),
            stage="transaction-state",
        )
    transaction_id = str(health["transaction_id"])
    journal_path = Path(str(health["journal_path"]))
    if not journal_path.exists() and not journal_path.is_symlink():
        if health["status"] != "pending":
            raise LaunchAgentError(
                "AUDIT_LAUNCHAGENT_JOURNAL_MISSING",
                stage="transaction-state",
            )
        # The fixed prepared pointer is fsynced before the per-transaction
        # journal, and the journal is fsynced before any plist mutation. No
        # journal therefore proves this attempt never reached mutation.
        append_launchagent_state(
            spec,
            transaction_id=transaction_id,
            journal_path=journal_path,
            event="abandoned",
            reason_code="AUDIT_LAUNCHAGENT_JOURNAL_NOT_CREATED",
        )
        return launchagent_transaction_health(spec.runtime_root)
    prepared, rows = read_journal(journal_path)
    _prepared_backup(spec, prepared, journal_path=journal_path)
    if str(prepared.get("transaction_id", "")) != transaction_id:
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_STATE_MISMATCH",
            stage="transaction-state",
        )
    child_status = _launchagent_child_status(rows)
    if child_status == "recovery_required":
        if health["status"] != "recovery_required":
            append_launchagent_state(
                spec,
                transaction_id=transaction_id,
                journal_path=journal_path,
                event="recovery_required",
                reason_code="AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED",
            )
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED",
            stage="transaction-state",
        )
    if child_status == "rolled_back":
        append_launchagent_state(
            spec,
            transaction_id=transaction_id,
            journal_path=journal_path,
            event="rolled_back",
        )
        return launchagent_transaction_health(spec.runtime_root)
    if child_status == "completed":
        loaded = known_launchctl_health(spec)
        _verify_installed_route(spec, loaded=loaded, require_live=True)
        append_launchagent_state(
            spec,
            transaction_id=transaction_id,
            journal_path=journal_path,
            event="completed",
        )
        return launchagent_transaction_health(spec.runtime_root)
    if child_status == "deferred":
        if health["status"] != "deferred":
            append_launchagent_state(
                spec,
                transaction_id=transaction_id,
                journal_path=journal_path,
                event="deferred",
            )
        return launchagent_transaction_health(spec.runtime_root)

    # A crash after journal preparation but before deferred/completed is not a
    # valid forward commit. Compensate from the exact bound snapshot; byte CAS
    # prevents overwriting concurrent changes.
    return {
        **_explicit_rollback_unlocked(spec, journal_path),
        **launchagent_transaction_health(spec.runtime_root),
    }


def run_launchctl(arguments: list[str], timeout: float = 30) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            ["launchctl", *arguments],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"returncode": 127, "stdout": "", "reason_code": type(exc).__name__.upper()}
    return {"returncode": completed.returncode, "stdout": completed.stdout, "reason_code": ""}


def launch_target(spec: LaunchAgentSpec, uid: int | None = None) -> str:
    return f"gui/{os.getuid() if uid is None else uid}/{spec.label}"


def launch_domain(uid: int | None = None) -> str:
    return f"gui/{os.getuid() if uid is None else uid}"


def current_launchctl_health(spec: LaunchAgentSpec) -> dict[str, Any]:
    result = run_launchctl(["print", launch_target(spec)], timeout=15)
    return launchctl_health(
        print_returncode=int(result["returncode"]),
        print_stdout=str(result.get("stdout", "")),
        spec=spec,
    )


def known_launchctl_health(spec: LaunchAgentSpec) -> dict[str, Any]:
    """Return loaded/absent state, rejecting every indeterminate print."""

    status = current_launchctl_health(spec)
    if status.get("query_ok") is False or status.get("load_state") == "unknown":
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_PRINT_FAILED",
            stage="launchctl-print",
        )
    return status


def plan_install(spec: LaunchAgentSpec) -> dict[str, Any]:
    before, before_existed = safe_bytes(spec.plist_path)
    desired = launchagent_bytes(spec)
    if before_existed:
        payload = load_launchagent_payload(spec.plist_path)
        classification = classify_launchagent_payload(payload, spec)
    else:
        classification = classify_launchagent_payload({}, spec)
    loaded = known_launchctl_health(spec) if sys.platform == "darwin" else {
        "loaded": False,
        "load_state": "absent",
        "query_ok": True,
        "healthy": False,
        "runs": None,
        "last_exit_code": None,
        "arguments_exact": False,
        "program_exact": False,
        "state": "",
    }
    inventory = discover_all_audit_launchagents(spec)
    other_routes = [
        row for row in inventory["routes"]
        if Path(str(row["path"])).resolve() != spec.plist_path.resolve()
    ]
    return {
        "ok": not other_routes,
        "status": "planned",
        "label": spec.label,
        "plist_path": str(spec.plist_path),
        "schedule": {"weekday": spec.weekday, "hour": spec.hour, "minute": spec.minute},
        "classification": classification.as_dict(),
        "before_existed": before_existed,
        "before_sha256": sha256_bytes(before),
        "after_sha256": sha256_bytes(desired),
        "changed": before != desired or not before_existed,
        "loaded": loaded,
        "scheduler_inventory": inventory,
        "other_scheduler_routes": other_routes,
    }


def _bootout_if_loaded(spec: LaunchAgentSpec) -> None:
    status = known_launchctl_health(spec)
    if not status["loaded"]:
        return
    result = run_launchctl(["bootout", launch_target(spec)], timeout=30)
    if result["returncode"] != 0:
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_BOOTOUT_FAILED", stage="launchctl")


def _bootstrap(spec: LaunchAgentSpec) -> None:
    result = run_launchctl(["bootstrap", launch_domain(), str(spec.plist_path)], timeout=30)
    if result["returncode"] != 0:
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_BOOTSTRAP_FAILED", stage="launchctl")


def _kickstart_and_wait(spec: LaunchAgentSpec, timeout: float) -> dict[str, Any]:
    before = known_launchctl_health(spec)
    baseline_runs = before.get("runs") if isinstance(before.get("runs"), int) else 0
    result = run_launchctl(["kickstart", "-k", launch_target(spec)], timeout=min(timeout, 30))
    if result["returncode"] != 0:
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_KICKSTART_FAILED", stage="kickstart")
    deadline = time.monotonic() + timeout
    last = before
    while time.monotonic() < deadline:
        last = known_launchctl_health(spec)
        runs = last.get("runs") if isinstance(last.get("runs"), int) else 0
        # `runs` increments when launchd starts the process.  While it is still
        # running, `last exit code` can remain 0 from the previous invocation;
        # accepting that pair would make a later failing audit look healthy.
        completed = str(last.get("state", "")).strip().casefold() == "not running"
        if runs > baseline_runs and completed and last.get("healthy"):
            return last
        time.sleep(0.25)
    raise LaunchAgentError("AUDIT_LAUNCHAGENT_KICKSTART_TIMEOUT", stage="kickstart")


def _preserve_created_plist(path: Path, backup_dir: Path, expected: bytes) -> str:
    target = backup_dir / f"created-{path.name}.preserved-{sha256_bytes(expected)[:12]}"
    try:
        moved = secure_conditional_move_bytes_beneath(
            path.parent.resolve(strict=True),
            Path(path.name),
            backup_dir.resolve(strict=True),
            Path(target.name),
            expected_sha256=sha256_bytes(expected),
            expected_size=len(expected),
            max_capture_bytes=max(len(expected), 4 * 1024 * 1024),
        )
    except ConditionalWriteError as exc:
        reason = (
            "AUDIT_LAUNCHAGENT_ROLLBACK_CAS_MISMATCH"
            if exc.reason_code == "CONDITIONAL_WRITE_TARGET_CHANGED"
            else "AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED"
        )
        raise LaunchAgentError(reason, stage="rollback") from exc
    return str(moved)


def rollback_prepared(
    *,
    spec: LaunchAgentSpec,
    before: bytes,
    before_existed: bool,
    before_loaded: bool,
    desired: bytes,
    backup_dir: Path,
) -> dict[str, Any]:
    # Validate the byte boundary before touching launchd.  Otherwise an
    # external plist replacement can make rollback fail CAS only *after* the
    # user's currently loaded job has already been booted out.
    current, existed = safe_bytes(spec.plist_path)
    if before_existed:
        if not existed or current not in {before, desired}:
            raise LaunchAgentError(
                "AUDIT_LAUNCHAGENT_ROLLBACK_CAS_MISMATCH",
                stage="rollback",
            )
    elif existed and current != desired:
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_ROLLBACK_CAS_MISMATCH",
            stage="rollback",
        )

    _bootout_if_loaded(spec)
    # Re-read after the launchctl side effect so a concurrent file replacement
    # cannot be adopted merely because it passed the first check.
    current, existed = safe_bytes(spec.plist_path)
    preserved = ""
    if before_existed:
        if existed and current == before:
            pass
        elif existed and current == desired:
            atomic_write(
                spec.plist_path,
                before,
                expected_before=current,
                expected_existed=True,
            )
        else:
            raise LaunchAgentError("AUDIT_LAUNCHAGENT_ROLLBACK_CAS_MISMATCH", stage="rollback")
    elif existed:
        preserved = _preserve_created_plist(spec.plist_path, backup_dir, desired)
    if before_loaded:
        if not before_existed:
            raise LaunchAgentError("AUDIT_LAUNCHAGENT_ROLLBACK_STATE_INVALID", stage="rollback")
        _bootstrap(spec)
    restored_load = known_launchctl_health(spec)
    if bool(restored_load.get("loaded")) != before_loaded:
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_ROLLBACK_LOAD_STATE_MISMATCH", stage="rollback")
    return {
        "ok": True,
        "restored": True,
        "preserved_created_plist": preserved,
        "restored_loaded": bool(restored_load.get("loaded")),
    }


def _verify_installed_route(
    spec: LaunchAgentSpec,
    *,
    loaded: dict[str, Any],
    require_live: bool,
) -> tuple[RouteClassification, dict[str, Any]]:
    classification = classify_launchagent_payload(
        load_launchagent_payload(spec.plist_path),
        spec,
    )
    if classification.kind != CANONICAL:
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_VERIFY_FAILED", stage="verify")
    inventory = discover_all_audit_launchagents(spec)
    if not inventory["healthy"]:
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_DUPLICATE_SCHEDULER", stage="verify")
    if require_live and not loaded.get("healthy"):
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_VERIFY_FAILED", stage="verify")
    return classification, inventory


def _rollback_after_failure(
    *,
    spec: LaunchAgentSpec,
    before: bytes,
    before_existed: bool,
    before_loaded: bool,
    desired: bytes,
    backup_dir: Path,
    journal_path: Path,
    failure: BaseException,
) -> None:
    try:
        rollback = rollback_prepared(
            spec=spec,
            before=before,
            before_existed=before_existed,
            before_loaded=before_loaded,
            desired=desired,
            backup_dir=backup_dir,
        )
        write_journal(
            journal_path,
            {
                "event": "rolled_back",
                "reason_code": getattr(failure, "reason_code", type(failure).__name__),
                "rollback": rollback,
            },
        )
    except BaseException as rollback_error:
        try:
            write_journal(
                journal_path,
                {
                    "event": "recovery_required",
                    "reason_code": getattr(failure, "reason_code", type(failure).__name__),
                    "rollback_error": getattr(
                        rollback_error,
                        "reason_code",
                        type(rollback_error).__name__,
                    ),
                },
            )
        except BaseException:
            pass
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED", stage="rollback") from rollback_error


def _apply_install_unlocked(
    spec: LaunchAgentSpec,
    *,
    backup_dir: Path,
    defer_load: bool,
    kickstart_timeout: float,
) -> dict[str, Any]:
    if sys.platform != "darwin":
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_MACOS_ONLY", stage="preflight")
    if not _safe_runtime_target(spec.runtime_python, executable=True, allow_symlink=True):
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_PYTHON_UNSAFE", stage="preflight")
    if not _safe_runtime_target(spec.memoryctl, executable=False, allow_symlink=False):
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_MEMORYCTL_UNSAFE", stage="preflight")
    prior_transaction = reconcile_launchagent_transaction(spec)
    if not prior_transaction["healthy"]:
        raise LaunchAgentError(
            str(prior_transaction["reason_code"]),
            stage="transaction-state",
        )
    plan = plan_install(spec)
    if not plan["ok"]:
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_DUPLICATE_SCHEDULER", stage="preflight")
    before, before_existed = safe_bytes(spec.plist_path)
    if (
        before_existed != bool(plan["before_existed"])
        or sha256_bytes(before) != str(plan["before_sha256"])
    ):
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_CHANGED_AFTER_PLAN",
            stage="preflight",
        )
    before_loaded = bool(plan["loaded"].get("loaded"))
    desired = launchagent_bytes(spec)
    changed = not before_existed or before != desired
    transaction_id = uuid.uuid4().hex
    journal_path = backup_dir / "audit-launchagent-transaction.jsonl"
    append_launchagent_state(
        spec,
        transaction_id=transaction_id,
        journal_path=journal_path,
        event="prepared",
    )
    try:
        backup_path = str(exclusive_backup(spec.plist_path, backup_dir, before, before_existed))
        write_journal(
            journal_path,
            {
                "schema_version": 1,
                "event": "prepared",
                "transaction_id": transaction_id,
                "label": spec.label,
                "plist_path": str(spec.plist_path),
                "backup_path": backup_path,
                "backup_dir": str(backup_dir),
                "before_existed": before_existed,
                "before_loaded": before_loaded,
                "before_sha256": sha256_bytes(before),
                "after_sha256": sha256_bytes(desired),
                "changed": changed,
            },
            create=True,
        )
    except BaseException as exc:
        append_launchagent_state(
            spec,
            transaction_id=transaction_id,
            journal_path=journal_path,
            event="abandoned" if not journal_path.exists() else "recovery_required",
            reason_code=getattr(exc, "reason_code", type(exc).__name__.upper()),
        )
        raise
    try:
        if changed:
            atomic_write(
                spec.plist_path,
                desired,
                expected_before=before,
                expected_existed=before_existed,
            )
            write_journal(journal_path, {"event": "plist_applied"})
        if defer_load:
            loaded = known_launchctl_health(spec)
            classification, inventory = _verify_installed_route(
                spec,
                loaded=loaded,
                require_live=False,
            )
            write_journal(
                journal_path,
                {
                    "event": "deferred",
                    "classification": classification.as_dict(),
                    "scheduler_inventory": {
                        key: inventory[key]
                        for key in ("healthy", "canonical_count", "legacy_count", "ambiguous_count")
                    },
                },
            )
        else:
            _verify_installed_route(
                spec,
                loaded=known_launchctl_health(spec),
                require_live=False,
            )
            _bootout_if_loaded(spec)
            _bootstrap(spec)
            loaded = _kickstart_and_wait(spec, kickstart_timeout)
            classification, inventory = _verify_installed_route(
                spec,
                loaded=loaded,
                require_live=True,
            )
            write_journal(
                journal_path,
                {
                    "event": "completed",
                    "defer_load": False,
                    "kickstart": True,
                    "runs": loaded.get("runs"),
                    "last_exit_code": loaded.get("last_exit_code"),
                },
            )
    except BaseException as exc:
        try:
            _rollback_after_failure(
                spec=spec,
                before=before,
                before_existed=before_existed,
                before_loaded=before_loaded,
                desired=desired,
                backup_dir=backup_dir,
                journal_path=journal_path,
                failure=exc,
            )
        except BaseException:
            append_launchagent_state(
                spec,
                transaction_id=transaction_id,
                journal_path=journal_path,
                event="recovery_required",
                reason_code=getattr(exc, "reason_code", type(exc).__name__.upper()),
            )
            raise
        append_launchagent_state(
            spec,
            transaction_id=transaction_id,
            journal_path=journal_path,
            event="rolled_back",
            reason_code=getattr(exc, "reason_code", type(exc).__name__.upper()),
        )
        raise
    append_launchagent_state(
        spec,
        transaction_id=transaction_id,
        journal_path=journal_path,
        event="deferred" if defer_load else "completed",
    )
    return {
        **plan,
        "changed": changed,
        "status": "deferred" if defer_load else "applied",
        "classification": classification.as_dict(),
        "backup_path": backup_path,
        "transaction_journal": str(journal_path),
        "defer_load": defer_load,
        "loaded": loaded,
        "scheduler_inventory": inventory,
    }


def apply_install(
    spec: LaunchAgentSpec,
    *,
    backup_dir: Path,
    defer_load: bool,
    kickstart_timeout: float,
) -> dict[str, Any]:
    try:
        with private_lock(
            spec.runtime_root / "locks" / "audit-launchagent-install.lock",
            timeout=2,
            timeout_message="AUDIT_LAUNCHAGENT_INSTALL_BUSY",
        ):
            return _apply_install_unlocked(
                spec,
                backup_dir=backup_dir,
                defer_load=defer_load,
                kickstart_timeout=kickstart_timeout,
            )
    except TimeoutError as exc:
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_INSTALL_BUSY",
            stage="transaction-lock",
        ) from exc


def _decode_journal(raw: bytes) -> list[dict[str, Any]]:
    segments = raw.split(b"\n")
    complete = segments[:-1]
    rows: list[dict[str, Any]] = []
    index = 0
    while index < len(complete):
        segment = complete[index]
        if not segment.strip():
            index += 1
            continue
        try:
            row = json.loads(segment.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            if index + 1 >= len(complete):
                raise LaunchAgentError(
                    "AUDIT_LAUNCHAGENT_JOURNAL_INVALID", stage="rollback"
                ) from exc
            try:
                marker = json.loads(complete[index + 1].decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as marker_error:
                raise LaunchAgentError(
                    "AUDIT_LAUNCHAGENT_JOURNAL_INVALID", stage="rollback"
                ) from marker_error
            if not (
                isinstance(marker, dict)
                and marker.get("event") == "journal_tail_recovered"
                and marker.get("discarded_sha256") == sha256_bytes(segment)
                and marker.get("discarded_bytes") == len(segment)
            ):
                raise LaunchAgentError(
                    "AUDIT_LAUNCHAGENT_JOURNAL_INVALID", stage="rollback"
                ) from exc
            rows.append(marker)
            index += 2
            continue
        if not isinstance(row, dict):
            raise LaunchAgentError(
                "AUDIT_LAUNCHAGENT_JOURNAL_INVALID", stage="rollback"
            )
        rows.append(row)
        index += 1
    return rows


def read_journal(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if path.is_symlink() or not path.is_file():
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_JOURNAL_UNSAFE", stage="rollback")
    try:
        rows = _decode_journal(path.read_bytes())
    except OSError as exc:
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_JOURNAL_INVALID", stage="rollback") from exc
    prepared_rows = [row for row in rows if row.get("event") == "prepared"]
    if (
        len(prepared_rows) != 1
        or prepared_rows[0].get("schema_version") != 1
        or any(str(row.get("event", "")) not in LAUNCHAGENT_CHILD_EVENTS for row in rows)
    ):
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_JOURNAL_INVALID", stage="rollback")
    prepared = prepared_rows[0]
    return prepared, rows


def read_prepared_journal(path: Path) -> dict[str, Any]:
    return read_journal(path)[0]


def _launchagent_child_status(rows: list[dict[str, Any]]) -> str:
    """Reduce the append-only child journal by its last state event."""

    status = "pending"
    for row in rows:
        event = str(row.get("event", ""))
        if event == "recovery_required":
            status = "recovery_required"
        elif event in {"manual_rollback_completed", "rolled_back"}:
            status = "rolled_back"
        elif event == "completed":
            status = "completed"
        elif event == "deferred":
            status = "deferred"
    return status


def _validated_prepared_backup(
    prepared: dict[str, Any],
    *,
    journal_path: Path,
    expected_transaction_id: str,
    expected_label: str,
    expected_plist_path: str,
) -> tuple[bytes, Path, Path]:
    """Validate the immutable child boundary without trusting fixed state."""

    if (
        prepared.get("transaction_id") != expected_transaction_id
        or prepared.get("label") != expected_label
        or prepared.get("plist_path") != expected_plist_path
        or not re.fullmatch(r"[0-9a-f]{32}", expected_transaction_id)
    ):
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_JOURNAL_TARGET_MISMATCH",
            stage="rollback",
        )
    backup_path = Path(os.path.abspath(str(prepared.get("backup_path", ""))))
    backup_dir = Path(os.path.abspath(str(prepared.get("backup_dir", ""))))
    normalized_journal = Path(os.path.abspath(str(journal_path)))
    before_sha256 = prepared.get("before_sha256")
    after_sha256 = prepared.get("after_sha256")
    before_existed = prepared.get("before_existed")
    changed = prepared.get("changed")
    digest_fields = (before_sha256, after_sha256)
    if (
        backup_dir.is_symlink()
        or not backup_dir.is_dir()
        or backup_path.parent != backup_dir
        or normalized_journal != backup_dir / "audit-launchagent-transaction.jsonl"
        or not all(
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
            for value in digest_fields
        )
        or not isinstance(before_existed, bool)
        or not isinstance(prepared.get("before_loaded"), bool)
        or not isinstance(changed, bool)
        or changed != (not before_existed or before_sha256 != after_sha256)
    ):
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_JOURNAL_BOUNDARY_INVALID",
            stage="rollback",
        )
    if backup_path.is_symlink() or not backup_path.is_file():
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_BACKUP_UNSAFE", stage="rollback")
    before = backup_path.read_bytes()
    if sha256_bytes(before) != before_sha256:
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_BACKUP_HASH_MISMATCH", stage="rollback")
    return before, backup_path, backup_dir


def _prepared_backup(
    spec: LaunchAgentSpec,
    prepared: dict[str, Any],
    *,
    journal_path: Path,
) -> tuple[bytes, Path, Path]:
    return _validated_prepared_backup(
        prepared,
        journal_path=journal_path,
        expected_transaction_id=str(prepared.get("transaction_id", "")),
        expected_label=spec.label,
        expected_plist_path=str(spec.plist_path),
    )


def _finalize_install_unlocked(
    spec: LaunchAgentSpec,
    journal_path: Path,
    *,
    kickstart_timeout: float,
) -> dict[str, Any]:
    """Complete a deferred install inside its original rollback boundary."""

    if sys.platform != "darwin":
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_MACOS_ONLY", stage="preflight")
    prepared, rows = read_journal(journal_path)
    transaction_id = str(prepared.get("transaction_id", ""))
    before, backup_path, backup_dir = _prepared_backup(
        spec,
        prepared,
        journal_path=journal_path,
    )
    _assert_launchagent_state_binding(
        spec,
        transaction_id=transaction_id,
        journal_path=journal_path,
        allowed_statuses={"deferred", "terminal"},
    )
    terminal_events = {str(row.get("event", "")) for row in rows}
    if "recovery_required" in terminal_events:
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED",
            stage="finalize",
        )
    if "rolled_back" in terminal_events or "manual_rollback_completed" in terminal_events:
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_TRANSACTION_ROLLED_BACK", stage="finalize")
    current, current_existed = safe_bytes(spec.plist_path)
    desired = launchagent_bytes(spec)
    if not current_existed or sha256_bytes(current) != prepared.get("after_sha256") or current != desired:
        write_journal(
            journal_path,
            {
                "event": "recovery_required",
                "reason_code": "AUDIT_LAUNCHAGENT_FINALIZE_CAS_MISMATCH",
            },
        )
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_FINALIZE_CAS_MISMATCH", stage="finalize")
    if "completed" in terminal_events:
        loaded = known_launchctl_health(spec)
        classification, inventory = _verify_installed_route(
            spec,
            loaded=loaded,
            require_live=True,
        )
        append_launchagent_state(
            spec,
            transaction_id=transaction_id,
            journal_path=journal_path,
            event="completed",
        )
        return {
            "ok": True,
            "status": "already_completed",
            "classification": classification.as_dict(),
            "backup_path": str(backup_path),
            "transaction_journal": str(journal_path),
            "loaded": loaded,
            "scheduler_inventory": inventory,
        }
    if "deferred" not in terminal_events:
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_NOT_DEFERRED", stage="finalize")
    try:
        _bootout_if_loaded(spec)
        _bootstrap(spec)
        loaded = _kickstart_and_wait(spec, kickstart_timeout)
        classification, inventory = _verify_installed_route(
            spec,
            loaded=loaded,
            require_live=True,
        )
        write_journal(
            journal_path,
            {
                "event": "completed",
                "defer_load": True,
                "kickstart": True,
                "runs": loaded.get("runs"),
                "last_exit_code": loaded.get("last_exit_code"),
            },
        )
    except BaseException as exc:
        try:
            _rollback_after_failure(
                spec=spec,
                before=before,
                before_existed=bool(prepared.get("before_existed")),
                before_loaded=bool(prepared.get("before_loaded")),
                desired=desired,
                backup_dir=backup_dir,
                journal_path=journal_path,
                failure=exc,
            )
        except BaseException:
            append_launchagent_state(
                spec,
                transaction_id=transaction_id,
                journal_path=journal_path,
                event="recovery_required",
                reason_code=getattr(exc, "reason_code", type(exc).__name__.upper()),
            )
            raise
        append_launchagent_state(
            spec,
            transaction_id=transaction_id,
            journal_path=journal_path,
            event="rolled_back",
            reason_code=getattr(exc, "reason_code", type(exc).__name__.upper()),
        )
        raise
    append_launchagent_state(
        spec,
        transaction_id=transaction_id,
        journal_path=journal_path,
        event="completed",
    )
    return {
        "ok": True,
        "status": "applied",
        "classification": classification.as_dict(),
        "backup_path": str(backup_path),
        "transaction_journal": str(journal_path),
        "loaded": loaded,
        "scheduler_inventory": inventory,
    }


def finalize_install(
    spec: LaunchAgentSpec,
    journal_path: Path,
    *,
    kickstart_timeout: float,
) -> dict[str, Any]:
    try:
        with private_lock(
            spec.runtime_root / "locks" / "audit-launchagent-install.lock",
            timeout=2,
            timeout_message="AUDIT_LAUNCHAGENT_INSTALL_BUSY",
        ):
            return _finalize_install_unlocked(
                spec,
                journal_path,
                kickstart_timeout=kickstart_timeout,
            )
    except TimeoutError as exc:
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_INSTALL_BUSY",
            stage="transaction-lock",
        ) from exc


def _explicit_rollback_unlocked(spec: LaunchAgentSpec, journal_path: Path) -> dict[str, Any]:
    prepared, _rows = read_journal(journal_path)
    transaction_id = str(prepared.get("transaction_id", ""))
    _assert_launchagent_state_binding(
        spec,
        transaction_id=transaction_id,
        journal_path=journal_path,
        allowed_statuses={"pending", "deferred", "terminal", "recovery_required"},
    )
    try:
        before, _backup_path, backup_dir = _prepared_backup(
            spec,
            prepared,
            journal_path=journal_path,
        )
        current, current_existed = safe_bytes(spec.plist_path)
        after_sha256 = str(prepared.get("after_sha256", ""))
        before_sha256 = str(prepared.get("before_sha256", ""))
        if current_existed and sha256_bytes(current) not in {after_sha256, before_sha256}:
            raise LaunchAgentError("AUDIT_LAUNCHAGENT_ROLLBACK_CAS_MISMATCH", stage="rollback")
        desired = current if current_existed and sha256_bytes(current) == after_sha256 else launchagent_bytes(spec)
        result = rollback_prepared(
            spec=spec,
            before=before,
            before_existed=bool(prepared.get("before_existed")),
            before_loaded=bool(prepared.get("before_loaded")),
            desired=desired,
            backup_dir=backup_dir,
        )
        write_journal(journal_path, {"event": "manual_rollback_completed"})
    except BaseException as failure:
        try:
            write_journal(
                journal_path,
                {
                    "event": "recovery_required",
                    "reason_code": getattr(
                        failure,
                        "reason_code",
                        type(failure).__name__,
                    ),
                },
            )
        except BaseException:
            pass
        try:
            append_launchagent_state(
                spec,
                transaction_id=transaction_id,
                journal_path=journal_path,
                event="recovery_required",
                reason_code=getattr(
                    failure,
                    "reason_code",
                    type(failure).__name__.upper(),
                ),
            )
        except BaseException:
            pass
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED",
            stage="rollback",
        ) from failure
    append_launchagent_state(
        spec,
        transaction_id=transaction_id,
        journal_path=journal_path,
        event="rolled_back",
    )
    return {**result, "status": "rolled_back", "transaction_journal": str(journal_path)}


def explicit_rollback(spec: LaunchAgentSpec, journal_path: Path) -> dict[str, Any]:
    try:
        with private_lock(
            spec.runtime_root / "locks" / "audit-launchagent-install.lock",
            timeout=2,
            timeout_message="AUDIT_LAUNCHAGENT_INSTALL_BUSY",
        ):
            return _explicit_rollback_unlocked(spec, journal_path)
    except TimeoutError as exc:
        raise LaunchAgentError(
            "AUDIT_LAUNCHAGENT_INSTALL_BUSY",
            stage="transaction-lock",
        ) from exc


def configured_spec(args: argparse.Namespace) -> LaunchAgentSpec:
    runtime_root = Path(os.path.abspath(os.path.expanduser(args.runtime_root)))
    config = load_config()
    host = config.get("host", {}) if isinstance(config, dict) else {}
    if not isinstance(host, dict):
        host = {}
    label = (
        args.label
        or str(host.get("audit_launchagent_label", "")).strip()
        or DEFAULT_AUDIT_LAUNCHAGENT_LABEL
    )
    if not AUDIT_LAUNCHAGENT_LABEL_PATTERN.fullmatch(label):
        raise LaunchAgentError("AUDIT_LAUNCHAGENT_LABEL_INVALID", stage="preflight")
    plist_raw = args.plist or str(host.get("audit_launchagent", "")).strip()
    plist_path = Path(os.path.abspath(os.path.expanduser(plist_raw))) if plist_raw else (
        Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
    )
    runtime_python = Path(os.path.abspath(os.path.expanduser(args.python))) if args.python else (
        runtime_root / ".venv" / "bin" / "python"
    )
    stdout_path = Path(os.path.abspath(os.path.expanduser(args.stdout_path))) if args.stdout_path else (
        runtime_root / "logs" / "audit-launchd.out.log"
    )
    stderr_path = Path(os.path.abspath(os.path.expanduser(args.stderr_path))) if args.stderr_path else (
        runtime_root / "logs" / "audit-launchd.err.log"
    )
    working_directory = Path(os.path.abspath(os.path.expanduser(args.working_directory))) if args.working_directory else Path.home()
    return LaunchAgentSpec(
        label=label,
        plist_path=plist_path,
        runtime_root=runtime_root,
        runtime_python=runtime_python,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        working_directory=working_directory,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage the canonical macOS Agent Memory audit LaunchAgent")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--plan", action="store_true")
    action.add_argument("--apply", action="store_true")
    action.add_argument("--finalize", action="store_true")
    action.add_argument("--rollback", action="store_true")
    parser.add_argument("--runtime-root", default=str(RUNTIME_ROOT))
    parser.add_argument("--python", default="")
    parser.add_argument("--plist", default="")
    parser.add_argument("--label", default="")
    parser.add_argument("--stdout-path", default="")
    parser.add_argument("--stderr-path", default="")
    parser.add_argument("--working-directory", default="")
    parser.add_argument("--backup-dir", default="")
    parser.add_argument("--journal", default="")
    parser.add_argument("--defer-load", action="store_true")
    parser.add_argument("--kickstart-timeout", type=float, default=180)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        spec = configured_spec(args)
        if args.plan:
            payload = plan_install(spec)
        elif args.apply:
            if not args.backup_dir:
                raise LaunchAgentError("AUDIT_LAUNCHAGENT_BACKUP_DIR_REQUIRED", stage="preflight")
            payload = apply_install(
                spec,
                backup_dir=Path(os.path.abspath(os.path.expanduser(args.backup_dir))),
                defer_load=args.defer_load,
                kickstart_timeout=max(1.0, args.kickstart_timeout),
            )
        elif args.finalize:
            if not args.journal:
                raise LaunchAgentError("AUDIT_LAUNCHAGENT_JOURNAL_REQUIRED", stage="finalize")
            payload = finalize_install(
                spec,
                Path(os.path.abspath(os.path.expanduser(args.journal))),
                kickstart_timeout=max(1.0, args.kickstart_timeout),
            )
        else:
            if not args.journal:
                raise LaunchAgentError("AUDIT_LAUNCHAGENT_JOURNAL_REQUIRED", stage="rollback")
            payload = explicit_rollback(
                spec,
                Path(os.path.abspath(os.path.expanduser(args.journal))),
            )
    except (OSError, ValueError, LaunchAgentError, subprocess.SubprocessError) as exc:
        payload = {
            "ok": False,
            "status": "blocked",
            "stage": getattr(exc, "stage", "launchagent"),
            "reason_code": getattr(exc, "reason_code", type(exc).__name__).upper(),
        }
    print(json.dumps(payload, ensure_ascii=False, indent=2) if args.json else f"audit_launchagent={payload['status']}")
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
