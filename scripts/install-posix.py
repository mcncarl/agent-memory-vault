#!/usr/bin/env python3
"""Fail-closed POSIX orchestration for Agent Memory v2 install and upgrade.

Plan is read-only. Apply delegates every stateful operation to the canonical
runtime installer, bootstrapper, migrator, and host-hook installer; this module
contains no duplicate schema, configuration, hook, or publication logic.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Callable

import agent_memory_migrate as state_migrator
from agent_memory_lock import private_lock
from agent_memory_state import ensure_private_directory
from install_audit_launchagent import launchagent_transaction_health
import install_runtime as runtime_installer


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_SCRIPTS = REPO_ROOT / "scripts"
INSTALL_JOURNAL_NAME = "install-orchestration.jsonl"
INSTALL_JOURNAL_EVENTS = frozenset({
    "prepared",
    "resumed",
    "stage_started",
    "stage_completed",
    "interrupted",
    "superseded",
    "recovery_required",
    "completed",
})
INSTALL_TERMINAL_EVENTS = frozenset({"completed", "superseded", "recovery_required"})
MUTATING_STAGES = frozenset({
    "backup-parents",
    "config-apply",
    "config-init",
    "bootstrap",
    "state-apply",
    "state-init",
    "audit-apply",
    "audit-init",
    "host-hooks",
    "audit-launchagent-deferred",
    "audit-launchagent-kickstart",
})
BACKUP_RECEIPT_STAGES = frozenset({
    "config-apply",
    "state-apply",
    "audit-apply",
    "host-hooks",
    "audit-launchagent-deferred",
})
BACKUP_TARGET_PROJECTION_KEYS = (
    "config_backup",
    "state_backup",
    "audit_backup",
    "hook_backup_dir",
    "launchagent_backup_dir",
)
RECOVERY_SUPERSEDE_POLICY = "state-apply-receipt-tail-leak-v1"
LAUNCHAGENT_TRANSACTION_STAGES = frozenset({
    "audit-launchagent-deferred",
    "audit-launchagent-kickstart",
    "audit-launchagent-rollback",
})
RECOVERY_SUPERSEDE_SAFE_STAGES = frozenset({
    "configured-paths",
    "config-plan",
    "state-plan",
    "audit-plan",
    "generated-index-plan",
    "backup-parents",
    "runtime-install",
})
RECOVERY_SUPERSEDE_STAGE_SEQUENCES = (
    (
        ("stage_started", "configured-paths"),
        ("stage_completed", "configured-paths"),
        ("stage_started", "config-plan"),
        ("stage_completed", "config-plan"),
        ("stage_started", "state-plan"),
        ("stage_completed", "state-plan"),
        ("stage_started", "audit-plan"),
        ("stage_completed", "audit-plan"),
        ("stage_started", "generated-index-plan"),
        ("stage_completed", "generated-index-plan"),
        ("stage_started", "backup-parents"),
        ("stage_completed", "backup-parents"),
        ("stage_started", "runtime-install"),
        ("stage_completed", "runtime-install"),
        ("stage_started", "config-plan"),
        ("stage_completed", "config-plan"),
        ("stage_started", "configured-paths"),
        ("stage_completed", "configured-paths"),
    ),
)
_ACTIVE_INSTALL_TRANSACTION: dict[str, Any] | None = None


class PosixInstallError(RuntimeError):
    def __init__(
        self,
        reason_code: str,
        stage: str,
        detail: str = "",
        *,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail or reason_code)
        self.reason_code = reason_code
        self.stage = stage
        self.evidence = dict(evidence or {})


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _install_journal_path(config_root: Path) -> Path:
    return config_root / "state" / INSTALL_JOURNAL_NAME


def _fsync_install_directory(path: Path) -> None:
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


def _append_install_event(path: Path, event: dict[str, Any]) -> None:
    ensure_private_directory(path.parent, harden_existing=True)
    payload = {
        "schema_version": 1,
        "time": utc_now(),
        **event,
    }
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > 16 * 1024:
        raise PosixInstallError("INSTALL_JOURNAL_EVENT_TOO_LARGE", "orchestration")
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PosixInstallError("INSTALL_JOURNAL_UNSAFE", "orchestration")
        os.fchmod(descriptor, 0o600)
        written = os.write(descriptor, encoded)
        if written != len(encoded):
            raise PosixInstallError("INSTALL_JOURNAL_WRITE_FAILED", "orchestration")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise PosixInstallError("INSTALL_JOURNAL_UNSAFE", "orchestration") from exc
    if (
        stat.S_ISLNK(after.st_mode)
        or (after.st_dev, after.st_ino) != (metadata.st_dev, metadata.st_ino)
    ):
        raise PosixInstallError("INSTALL_JOURNAL_UNSAFE", "orchestration")
    _fsync_install_directory(path.parent)


def _read_install_journal(path: Path) -> list[dict[str, Any]]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return []
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size > 8 * 1024 * 1024
    ):
        raise PosixInstallError("INSTALL_JOURNAL_UNSAFE", "orchestration")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise PosixInstallError("INSTALL_JOURNAL_UNSAFE", "orchestration") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size > 8 * 1024 * 1024
        ):
            raise PosixInstallError("INSTALL_JOURNAL_UNSAFE", "orchestration")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise PosixInstallError("INSTALL_JOURNAL_TRUNCATED", "orchestration")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise PosixInstallError("INSTALL_JOURNAL_UNSAFE", "orchestration") from exc
    if (
        stat.S_ISLNK(after.st_mode)
        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    ):
        raise PosixInstallError("INSTALL_JOURNAL_UNSAFE", "orchestration")
    if raw and not raw.endswith(b"\n"):
        raise PosixInstallError("INSTALL_JOURNAL_TRUNCATED", "orchestration")
    events: list[dict[str, Any]] = []
    for line in raw.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PosixInstallError("INSTALL_JOURNAL_INVALID", "orchestration") from exc
        if (
            not isinstance(item, dict)
            or item.get("schema_version") != 1
            or item.get("event") not in INSTALL_JOURNAL_EVENTS
            or re.fullmatch(r"[0-9a-f]{32}", str(item.get("transaction_id", ""))) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(item.get("input_sha256", ""))) is None
        ):
            raise PosixInstallError("INSTALL_JOURNAL_INVALID", "orchestration")
        events.append(item)
    return events


def _recovery_supersede_stage_history(
    tail: list[dict[str, Any]],
) -> dict[str, Any]:
    """Validate the exact pre-state-apply lifecycle of the known tail-leak bug."""

    if (
        len(tail) < 2
        or tail[0].get("event") != "prepared"
        or tail[-1].get("event") != "recovery_required"
    ):
        raise PosixInstallError(
            "INSTALL_RECOVERY_SUPERSEDE_STAGE_HISTORY_INVALID",
            "orchestration-supersede",
        )
    lifecycle: list[tuple[str, str]] = []
    started: list[str] = []
    completed: list[str] = []
    open_stage = ""
    for item in tail[1:-1]:
        event = str(item.get("event", ""))
        stage = str(item.get("stage", ""))
        if event not in {"stage_started", "stage_completed"} or not stage:
            raise PosixInstallError(
                "INSTALL_RECOVERY_SUPERSEDE_STAGE_HISTORY_INVALID",
                "orchestration-supersede",
            )
        if stage not in RECOVERY_SUPERSEDE_SAFE_STAGES:
            raise PosixInstallError(
                "INSTALL_RECOVERY_SUPERSEDE_UNSAFE_STAGE_EVENT",
                "orchestration-supersede",
                evidence={"event": event, "stage": stage},
            )
        lifecycle.append((event, stage))
        if event == "stage_started":
            if open_stage:
                raise PosixInstallError(
                    "INSTALL_RECOVERY_SUPERSEDE_STAGE_HISTORY_INVALID",
                    "orchestration-supersede",
                )
            open_stage = stage
            started.append(stage)
            continue
        if open_stage != stage:
            raise PosixInstallError(
                "INSTALL_RECOVERY_SUPERSEDE_STAGE_HISTORY_INVALID",
                "orchestration-supersede",
            )
        open_stage = ""
        completed.append(stage)
    if open_stage or tuple(lifecycle) not in RECOVERY_SUPERSEDE_STAGE_SEQUENCES:
        raise PosixInstallError(
            "INSTALL_RECOVERY_SUPERSEDE_STAGE_HISTORY_INVALID",
            "orchestration-supersede",
        )
    backup_receipt_started = sorted(set(started) & set(BACKUP_RECEIPT_STAGES))
    backup_receipt_completed = sorted(set(completed) & set(BACKUP_RECEIPT_STAGES))
    mutating_started = sorted(set(started) & set(MUTATING_STAGES))
    mutating_completed = sorted(set(completed) & set(MUTATING_STAGES))
    disallowed_stage_events = sorted(
        {
            stage
            for _event, stage in lifecycle
            if stage in BACKUP_RECEIPT_STAGES
            or stage in (set(MUTATING_STAGES) - {"backup-parents"})
            or stage in LAUNCHAGENT_TRANSACTION_STAGES
        }
    )
    if (
        backup_receipt_started
        or backup_receipt_completed
        or set(mutating_started) - {"backup-parents"}
        or set(mutating_completed) - {"backup-parents"}
        or disallowed_stage_events
    ):
        raise PosixInstallError(
            "INSTALL_RECOVERY_SUPERSEDE_UNSAFE_STAGE_EVENT",
            "orchestration-supersede",
        )
    return {
        "stage_lifecycle": [
            {"event": event, "stage": stage} for event, stage in lifecycle
        ],
        "started_stages": started,
        "completed_stages": completed,
        "backup_receipt_stages_started": backup_receipt_started,
        "backup_receipt_stages_completed": backup_receipt_completed,
        "mutating_stages_started": mutating_started,
        "mutating_stages_completed": mutating_completed,
        "disallowed_stage_events": disallowed_stage_events,
    }


def _active_install_tail(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not events:
        return []
    prepared_indexes = [
        index for index, item in enumerate(events) if item.get("event") == "prepared"
    ]
    if not prepared_indexes or prepared_indexes[0] != 0:
        raise PosixInstallError("INSTALL_JOURNAL_INVALID", "orchestration")
    prepared_ids = [str(events[index]["transaction_id"]) for index in prepared_indexes]
    if len(set(prepared_ids)) != len(prepared_ids):
        raise PosixInstallError("INSTALL_JOURNAL_INVALID", "orchestration")
    segments: list[list[dict[str, Any]]] = []
    for offset, start in enumerate(prepared_indexes):
        end = prepared_indexes[offset + 1] if offset + 1 < len(prepared_indexes) else len(events)
        segment = events[start:end]
        prepared = segment[0]
        txid = str(prepared["transaction_id"])
        fingerprint = str(prepared["input_sha256"])
        projection = prepared.get("input_projection")
        if (
            not isinstance(projection, dict)
            or _install_input_sha256(projection) != fingerprint
            or any(
                str(item.get("transaction_id")) != txid
                or str(item.get("input_sha256")) != fingerprint
                for item in segment
            )
        ):
            raise PosixInstallError("INSTALL_JOURNAL_INVALID", "orchestration")
        terminals = [item for item in segment if item.get("event") in INSTALL_TERMINAL_EVENTS]
        recovery_supersede_shape = (
            len(terminals) == 2
            and len(segment) >= 3
            and terminals[0] is segment[-2]
            and terminals[1] is segment[-1]
            and terminals[0].get("event") == "recovery_required"
            and terminals[1].get("event") == "superseded"
        )
        if not (
            not terminals
            or (len(terminals) == 1 and terminals[-1] is segment[-1])
            or recovery_supersede_shape
        ):
            raise PosixInstallError("INSTALL_JOURNAL_INVALID", "orchestration")
        if offset + 1 < len(prepared_indexes) and not terminals:
            raise PosixInstallError("INSTALL_JOURNAL_INVALID", "orchestration")
        if terminals and terminals[-1].get("event") == "recovery_required" and offset + 1 < len(prepared_indexes):
            raise PosixInstallError("INSTALL_JOURNAL_INVALID", "orchestration")
        if terminals and terminals[-1].get("event") == "superseded":
            terminal = terminals[-1]
            evidence = terminal.get("evidence")
            supersede_basis = (
                evidence.get("supersede_basis_event", "interrupted")
                if isinstance(evidence, dict)
                else ""
            )
            expected_predecessor = (
                "recovery_required"
                if supersede_basis == "recovery_required"
                else "interrupted"
            )
            if (
                len(segment) < 2
                or segment[-2].get("event") != expected_predecessor
                or supersede_basis not in {"interrupted", "recovery_required"}
                or terminal.get("reason_code") != "INSTALL_TRANSACTION_SUPERSEDED"
                or not isinstance(evidence, dict)
                or terminal.get("evidence_sha256") != _install_input_sha256(evidence)
                or evidence.get("schema_version") != 1
                or evidence.get("old_transaction_id") != txid
                or evidence.get("old_input_sha256") != fingerprint
                or evidence.get("replacement_transaction_id")
                != terminal.get("replacement_transaction_id")
                or evidence.get("replacement_input_sha256")
                != terminal.get("replacement_input_sha256")
                or re.fullmatch(r"[0-9a-f]{32}", str(evidence.get("replacement_transaction_id", ""))) is None
                or evidence.get("replacement_transaction_id") == txid
                or re.fullmatch(r"[0-9a-f]{64}", str(evidence.get("replacement_input_sha256", ""))) is None
                or evidence.get("launchagent_no_recovery_required") is not True
            ):
                raise PosixInstallError("INSTALL_JOURNAL_INVALID", "orchestration")
            if supersede_basis == "interrupted" and len(terminals) != 1:
                raise PosixInstallError("INSTALL_JOURNAL_INVALID", "orchestration")
            if supersede_basis == "recovery_required":
                recovery = segment[-2]
                try:
                    stage_history = _recovery_supersede_stage_history(segment[:-1])
                except PosixInstallError as exc:
                    raise PosixInstallError(
                        "INSTALL_JOURNAL_INVALID",
                        "orchestration",
                    ) from exc
                started_stages = stage_history["started_stages"]
                completed_stages = stage_history["completed_stages"]
                projected_targets = [
                    {
                        "key": key,
                        "path": str(absolute(str(projection.get(key, "")).strip())),
                        "absent": True,
                    }
                    for key in BACKUP_TARGET_PROJECTION_KEYS
                    if str(projection.get(key, "")).strip() not in {"", "."}
                ]
                runtime_started = "runtime-install" in started_stages
                runtime_attestation = evidence.get("runtime_attestation")
                launchagent_attestation = evidence.get("launchagent_attestation")
                runtime_attestation_valid = (
                    isinstance(runtime_attestation, dict)
                    and (
                        (
                            runtime_started
                            and runtime_attestation.get("healthy") is True
                            and runtime_attestation.get("bundle_sha256")
                            == projection.get("runtime_bundle_sha256")
                            and runtime_attestation.get("transition_phase")
                            in {"state_migration_required", "preflight", "ready"}
                        )
                        or (not runtime_started and runtime_attestation == {})
                    )
                )
                launchagent_attestation_valid = (
                    isinstance(launchagent_attestation, dict)
                    and launchagent_attestation.get("healthy") is True
                    and launchagent_attestation.get("status") in {"none", "terminal"}
                    and launchagent_attestation.get("recovery_required_seen") is False
                )
                if (
                    not recovery_supersede_shape
                    or prepared.get("original_mode") != "upgrade"
                    or recovery.get("reason_code") != "INSTALL_BACKUP_RECEIPT_INVALID"
                    or recovery.get("stage") != "state-apply"
                    or evidence.get("recovery_supersede_policy")
                    != RECOVERY_SUPERSEDE_POLICY
                    or evidence.get("recovery_reason_code")
                    != recovery.get("reason_code")
                    or evidence.get("recovery_stage") != recovery.get("stage")
                    or evidence.get("original_mode") != "upgrade"
                    or evidence.get("stage_lifecycle")
                    != stage_history["stage_lifecycle"]
                    or evidence.get("started_stages") != started_stages
                    or evidence.get("completed_stages") != completed_stages
                    or evidence.get("backup_receipt_stages_started")
                    != stage_history["backup_receipt_stages_started"]
                    or evidence.get("backup_receipt_stages_completed")
                    != stage_history["backup_receipt_stages_completed"]
                    or evidence.get("mutating_stages_started")
                    != stage_history["mutating_stages_started"]
                    or evidence.get("mutating_stages_completed")
                    != stage_history["mutating_stages_completed"]
                    or evidence.get("disallowed_stage_events")
                    != stage_history["disallowed_stage_events"]
                    or evidence.get("specified_backup_targets") != projected_targets
                    or evidence.get("runtime_stage_started") is not runtime_started
                    or not runtime_attestation_valid
                    or evidence.get("launchagent_stage_started") is not False
                    or not launchagent_attestation_valid
                ):
                    raise PosixInstallError("INSTALL_JOURNAL_INVALID", "orchestration")
            if offset + 1 < len(prepared_indexes):
                replacement = events[prepared_indexes[offset + 1]]
                if (
                    replacement.get("transaction_id") != evidence["replacement_transaction_id"]
                    or replacement.get("input_sha256") != evidence["replacement_input_sha256"]
                ):
                    raise PosixInstallError("INSTALL_JOURNAL_INVALID", "orchestration")
        segments.append(segment)
    return segments[-1]


def install_orchestration_health(
    config_root: Path,
    *,
    active_transaction_id: str = "",
    active_input_sha256: str = "",
) -> dict[str, Any]:
    """Reduce the fixed outer journal without changing any installation state."""

    journal = _install_journal_path(config_root)
    try:
        events = _read_install_journal(journal)
        tail = _active_install_tail(events)
    except PosixInstallError as exc:
        return {
            "healthy": False,
            "status": "invalid",
            "reason_code": exc.reason_code,
            "journal": str(journal),
        }
    binding_supplied = bool(active_transaction_id or active_input_sha256)
    if not tail:
        return {
            "healthy": not binding_supplied,
            "status": "none",
            "reason_code": (
                "INSTALL_ACTIVE_BINDING_NOT_FOUND" if binding_supplied else ""
            ),
            "journal": str(journal),
        }
    last = tail[-1]
    last_event = str(last.get("event", ""))
    transaction_id = str(tail[0].get("transaction_id", ""))
    input_sha256 = str(tail[0].get("input_sha256", ""))
    last_stage = str(last.get("stage", ""))
    base = {
        "journal": str(journal),
        "transaction_id": transaction_id,
        "input_sha256": input_sha256,
        "last_event": last_event,
        "last_stage": last_stage,
        "evidence_sha256": str(last.get("evidence_sha256", "")),
    }
    if last_event in {"completed", "superseded"}:
        return {
            **base,
            "healthy": not binding_supplied,
            "status": "terminal",
            "reason_code": (
                "INSTALL_ACTIVE_BINDING_MISMATCH" if binding_supplied else ""
            ),
        }
    if last_event == "recovery_required":
        return {
            **base,
            "healthy": False,
            "status": "recovery_required",
            "reason_code": "INSTALL_RECOVERY_REQUIRED",
        }
    if last_event == "interrupted":
        return {
            **base,
            "healthy": False,
            "status": "interrupted",
            "reason_code": "INSTALL_TRANSACTION_INTERRUPTED",
        }
    active_bound = (
        bool(active_transaction_id and active_input_sha256)
        and active_transaction_id == transaction_id
        and active_input_sha256 == input_sha256
    )
    return {
        **base,
        "healthy": active_bound,
        "status": "active" if active_bound else "open",
        "reason_code": "" if active_bound else "INSTALL_TRANSACTION_OPEN",
    }


def _install_input_projection(args: argparse.Namespace, paths: dict[str, Path]) -> dict[str, Any]:
    try:
        manifest = runtime_installer.expected_manifest(paths["config_root"])
    except (OSError, runtime_installer.StateSecurityError) as exc:
        raise PosixInstallError(
            "INSTALL_SOURCE_INVALID",
            "orchestration",
            type(exc).__name__,
        ) from exc
    source_projection = {
        "bundle_sha256": manifest.get("bundle_sha256"),
        "file_modes": manifest.get("file_modes"),
        "support_source_modes": manifest.get("support_source_modes"),
        "template_file_modes": manifest.get("template_file_modes"),
    }
    source_sha256 = hashlib.sha256(
        json.dumps(
            source_projection,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "config_root": str(paths["config_root"]),
        "memory_root": str(absolute(args.memory_root)),
        "git_root": str(absolute(args.git_root or args.memory_root)),
        "state_db": str(paths["state"]),
        "config_backup": str(paths["config_backup"]),
        "state_backup": str(paths["state_backup"]),
        "audit_backup": str(paths["audit_backup"]),
        "hook_backup_dir": str(paths["hook_backup_dir"]),
        "launchagent_backup_dir": str(paths["launchagent_backup_dir"]),
        "disposition": str(paths["disposition"]),
        "committed_recovery_file": option_text(args, "committed_recovery_file"),
        "committed_recovery_sha256": (
            state_migrator._recovery_digest(state_migrator.load_committed_recovery_document(Path(args.committed_recovery_file)))
            if option_text(args, "committed_recovery_file") else ""
        ),
        "hosts": sorted(set(args.host)),
        "no_host_hooks": bool(args.no_host_hooks),
        "user_id_sha256": hashlib.sha256(str(args.user_id).encode("utf-8")).hexdigest(),
        "agent_id": str(args.agent_id),
        "app_id": str(args.app_id),
        "platform": sys.platform,
        "runtime_bundle_sha256": str(manifest.get("bundle_sha256", "")),
        "runtime_source_sha256": source_sha256,
    }


def _install_input_sha256(projection: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(projection, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _prove_interrupted_transaction_supersedable(
    *,
    tail: list[dict[str, Any]],
    config_root: Path,
) -> dict[str, Any]:
    """Attest a compensated interrupted install without reverting forward work."""

    if not tail or tail[-1].get("event") != "interrupted":
        raise PosixInstallError(
            "INSTALL_SUPERSEDE_REQUIRES_INTERRUPTED",
            "orchestration-supersede",
        )
    prepared = tail[0]
    old_projection = prepared.get("input_projection")
    old_input_sha256 = str(prepared.get("input_sha256", ""))
    if (
        not isinstance(old_projection, dict)
        or _install_input_sha256(old_projection) != old_input_sha256
        or absolute(str(old_projection.get("config_root", ""))) != config_root
        or str(old_projection.get("platform", "")) != sys.platform
    ):
        raise PosixInstallError(
            "INSTALL_SUPERSEDE_OLD_INPUT_INVALID",
            "orchestration-supersede",
        )
    old_bundle = str(old_projection.get("runtime_bundle_sha256", ""))
    if re.fullmatch(r"[0-9a-f]{64}", old_bundle) is None:
        raise PosixInstallError(
            "INSTALL_SUPERSEDE_OLD_INPUT_INVALID",
            "orchestration-supersede",
        )
    _verify_completed_backup_receipts_from_tail(tail, old_projection)

    started_stages = {
        str(item.get("stage", ""))
        for item in tail
        if item.get("event") == "stage_started"
    }
    runtime_started = "runtime-install" in started_stages
    launchagent_started = bool(
        started_stages
        & {
            "audit-launchagent-deferred",
            "audit-launchagent-kickstart",
            "audit-launchagent-rollback",
        }
    )
    runtime_health: dict[str, Any] = {}
    if runtime_started:
        runtime_health = runtime_installer.attest_installed_runtime_static(config_root)
        if runtime_health.get("healthy") is not True:
            raise PosixInstallError(
                "INSTALL_SUPERSEDE_RUNTIME_EVIDENCE_INVALID",
                "orchestration-supersede",
            )
        if (
            runtime_health.get("bundle_sha256") != old_bundle
            or runtime_health.get("transition_phase")
            not in {"state_migration_required", "preflight", "ready"}
        ):
            raise PosixInstallError(
                "INSTALL_SUPERSEDE_RUNTIME_BUNDLE_MISMATCH",
                "orchestration-supersede",
            )

    launchagent = launchagent_transaction_health(config_root)
    launchagent_backup = str(old_projection.get("launchagent_backup_dir", "")).strip()
    if sys.platform == "darwin" and launchagent_started:
        if not launchagent_backup:
            raise PosixInstallError(
                "INSTALL_SUPERSEDE_LAUNCHAGENT_EVIDENCE_INVALID",
                "orchestration-supersede",
            )
        expected_child_journal = str(
            absolute(launchagent_backup) / "audit-launchagent-transaction.jsonl"
        )
        if (
            launchagent.get("healthy") is not True
            or launchagent.get("status") != "terminal"
            or launchagent.get("child_status") != "rolled_back"
            or launchagent.get("journal_path") != expected_child_journal
            or launchagent.get("recovery_required_seen") is not False
        ):
            raise PosixInstallError(
                "INSTALL_SUPERSEDE_LAUNCHAGENT_EVIDENCE_INVALID",
                "orchestration-supersede",
            )
    elif (
        launchagent.get("healthy") is not True
        or launchagent.get("status") not in {"none", "terminal"}
        or launchagent.get("recovery_required_seen") is not False
    ):
        raise PosixInstallError(
            "INSTALL_SUPERSEDE_LAUNCHAGENT_EVIDENCE_INVALID",
            "orchestration-supersede",
        )

    evidence = {
        "schema_version": 1,
        "old_transaction_id": str(prepared.get("transaction_id", "")),
        "old_input_sha256": old_input_sha256,
        "runtime_bundle_sha256": old_bundle,
        "runtime_stage_started": runtime_started,
        "runtime_manifest_sha256": str(runtime_health.get("manifest_sha256", "")),
        "runtime_transition_sha256": str(runtime_health.get("transition_sha256", "")),
        "runtime_transition_phase": str(runtime_health.get("transition_phase", "")),
        "runtime_install_id": str(runtime_health.get("install_id", "")),
        "runtime_anchor_sha256": str(runtime_health.get("runtime_anchor_sha256", "")),
        "runtime_transactions_sha256": str(
            runtime_health.get("runtime_transactions_sha256", "")
        ),
        "launchagent_status": str(launchagent.get("status", "")),
        "launchagent_stage_started": launchagent_started,
        "launchagent_child_status": str(launchagent.get("child_status", "")),
        "launchagent_transaction_id": str(launchagent.get("transaction_id", "")),
        "launchagent_journal_events_sha256": str(
            launchagent.get("journal_events_sha256", "")
            or hashlib.sha256(b"").hexdigest()
        ),
        "launchagent_no_recovery_required": True,
    }
    return evidence


def _prove_recovery_required_transaction_supersedable(
    *,
    tail: list[dict[str, Any]],
    config_root: Path,
) -> dict[str, Any]:
    """Attest the one known pre-backup receipt-tail failure without rewriting it."""

    if not tail or tail[-1].get("event") != "recovery_required":
        raise PosixInstallError(
            "INSTALL_RECOVERY_REQUIRED",
            "orchestration",
        )
    recovery = tail[-1]
    if (
        recovery.get("reason_code") != "INSTALL_BACKUP_RECEIPT_INVALID"
        or recovery.get("stage") != "state-apply"
    ):
        raise PosixInstallError(
            "INSTALL_RECOVERY_REQUIRED",
            "orchestration",
        )

    prepared = tail[0]
    old_projection = prepared.get("input_projection")
    old_input_sha256 = str(prepared.get("input_sha256", ""))
    if (
        not isinstance(old_projection, dict)
        or _install_input_sha256(old_projection) != old_input_sha256
        or absolute(str(old_projection.get("config_root", ""))) != config_root
        or str(old_projection.get("platform", "")) != sys.platform
        or prepared.get("original_mode") != "upgrade"
    ):
        raise PosixInstallError(
            "INSTALL_SUPERSEDE_OLD_INPUT_INVALID",
            "orchestration-supersede",
        )
    old_bundle = str(old_projection.get("runtime_bundle_sha256", ""))
    if re.fullmatch(r"[0-9a-f]{64}", old_bundle) is None:
        raise PosixInstallError(
            "INSTALL_SUPERSEDE_OLD_INPUT_INVALID",
            "orchestration-supersede",
        )

    stage_history = _recovery_supersede_stage_history(tail)
    started_stages = stage_history["started_stages"]
    completed_stages = stage_history["completed_stages"]

    specified_backup_targets: list[dict[str, Any]] = []
    for key in BACKUP_TARGET_PROJECTION_KEYS:
        raw = str(old_projection.get(key, "")).strip()
        if raw in {"", "."}:
            continue
        target = absolute(raw)
        if target.exists() or target.is_symlink():
            raise PosixInstallError(
                "INSTALL_RECOVERY_SUPERSEDE_BACKUP_TARGET_EXISTS",
                "orchestration-supersede",
                evidence={"key": key, "path": str(target)},
            )
        specified_backup_targets.append({
            "key": key,
            "path": str(target),
            "absent": True,
        })

    runtime_started = "runtime-install" in started_stages
    runtime_attestation: dict[str, Any] = {}
    if runtime_started:
        runtime_health = runtime_installer.attest_installed_runtime_static(config_root)
        if runtime_health.get("healthy") is not True:
            raise PosixInstallError(
                "INSTALL_SUPERSEDE_RUNTIME_EVIDENCE_INVALID",
                "orchestration-supersede",
            )
        if (
            runtime_health.get("bundle_sha256") != old_bundle
            or runtime_health.get("transition_phase")
            not in {"state_migration_required", "preflight", "ready"}
        ):
            raise PosixInstallError(
                "INSTALL_SUPERSEDE_RUNTIME_BUNDLE_MISMATCH",
                "orchestration-supersede",
            )
        runtime_attestation = {
            key: runtime_health.get(key)
            for key in (
                "healthy",
                "bundle_sha256",
                "manifest_sha256",
                "transition_sha256",
                "transition_phase",
                "install_id",
                "runtime_anchor_sha256",
                "runtime_transactions_sha256",
            )
        }

    launchagent_started = bool(
        set(started_stages) & set(LAUNCHAGENT_TRANSACTION_STAGES)
    )
    launchagent = launchagent_transaction_health(config_root)
    if (
        launchagent_started
        or launchagent.get("healthy") is not True
        or launchagent.get("status") not in {"none", "terminal"}
        or launchagent.get("recovery_required_seen") is not False
    ):
        raise PosixInstallError(
            "INSTALL_SUPERSEDE_LAUNCHAGENT_EVIDENCE_INVALID",
            "orchestration-supersede",
        )
    launchagent_attestation = {
        key: launchagent.get(key)
        for key in (
            "healthy",
            "status",
            "reason_code",
            "child_status",
            "transaction_id",
            "journal_path",
            "journal_events_sha256",
            "recovery_required_seen",
        )
    }

    return {
        "schema_version": 1,
        "supersede_basis_event": "recovery_required",
        "recovery_supersede_policy": RECOVERY_SUPERSEDE_POLICY,
        "recovery_reason_code": "INSTALL_BACKUP_RECEIPT_INVALID",
        "recovery_stage": "state-apply",
        "original_mode": "upgrade",
        "old_transaction_id": str(prepared.get("transaction_id", "")),
        "old_input_sha256": old_input_sha256,
        "stage_lifecycle": stage_history["stage_lifecycle"],
        "started_stages": started_stages,
        "completed_stages": completed_stages,
        "backup_receipt_stages_started": stage_history[
            "backup_receipt_stages_started"
        ],
        "backup_receipt_stages_completed": stage_history[
            "backup_receipt_stages_completed"
        ],
        "mutating_stages_started": stage_history["mutating_stages_started"],
        "mutating_stages_completed": stage_history["mutating_stages_completed"],
        "disallowed_stage_events": stage_history["disallowed_stage_events"],
        "specified_backup_targets": specified_backup_targets,
        "runtime_bundle_sha256": old_bundle,
        "runtime_stage_started": runtime_started,
        "runtime_attestation": runtime_attestation,
        "launchagent_stage_started": False,
        "launchagent_attestation": launchagent_attestation,
        "launchagent_no_recovery_required": True,
    }


def _stage_result_projection(stage: str, result: dict[str, Any]) -> dict[str, Any]:
    projected: dict[str, Any] = {"ok": result.get("ok") is True}
    for key in ("status", "stage", "changed", "transaction_journal"):
        value = result.get(key)
        if isinstance(value, (str, bool, int)):
            projected[key] = value
    if stage == "publish-ready":
        attestation = result.get("preflight_attestation")
        if isinstance(attestation, dict):
            projected["preflight_attestation"] = {
                "content_migration_required": attestation.get("content_migration_required"),
                "legacy_scope_documents": attestation.get("legacy_scope_documents"),
                "safe_automatic_governance_documents": attestation.get(
                    "safe_automatic_governance_documents"
                ),
                "content_migration": attestation.get("content_migration"),
            }
    if stage in BACKUP_RECEIPT_STAGES:
        projected["backup_receipt"] = _capture_stage_backup_receipt(stage, result)
    return projected


def _sha256_regular_file(path: Path) -> tuple[str, int, int]:
    """Hash one inode-bound regular file without following a final symlink."""

    try:
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise PosixInstallError(
            "INSTALL_BACKUP_RECEIPT_INVALID",
            "backup-receipt",
            evidence={"path": str(path)},
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise PosixInstallError(
                "INSTALL_BACKUP_RECEIPT_INVALID",
                "backup-receipt",
                evidence={"path": str(path)},
            )
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise PosixInstallError(
                    "INSTALL_BACKUP_RECEIPT_INVALID",
                    "backup-receipt",
                    evidence={"path": str(path)},
                )
            digest.update(chunk)
            remaining -= len(chunk)
        return digest.hexdigest(), int(opened.st_size), stat.S_IMODE(opened.st_mode)
    finally:
        os.close(descriptor)


def _expected_backup_target(stage: str) -> tuple[Path, str]:
    context = _ACTIVE_INSTALL_TRANSACTION
    if context is None:
        raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)
    projection = context.get("input_projection", {})
    key_and_kind = {
        "config-apply": ("config_backup", "file"),
        "state-apply": ("state_backup", "file"),
        "audit-apply": ("audit_backup", "file"),
        "host-hooks": ("hook_backup_dir", "directory"),
        "audit-launchagent-deferred": ("launchagent_backup_dir", "directory"),
    }.get(stage)
    if key_and_kind is None:
        raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)
    key, kind = key_and_kind
    raw = str(projection.get(key, "")).strip()
    if not raw:
        raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)
    return absolute(raw), kind


def _receipt_file(path: Path, *, expected_root: Path, root_kind: str) -> dict[str, Any]:
    if root_kind == "file":
        if path != expected_root:
            raise PosixInstallError(
                "INSTALL_BACKUP_RECEIPT_INVALID",
                "backup-receipt",
                evidence={"path": str(path), "expected": str(expected_root)},
            )
    elif path != expected_root and expected_root not in path.parents:
        raise PosixInstallError(
            "INSTALL_BACKUP_RECEIPT_INVALID",
            "backup-receipt",
            evidence={"path": str(path), "expected_root": str(expected_root)},
        )
    sha256, size, mode = _sha256_regular_file(path)
    if os.name != "nt" and mode != 0o600:
        raise PosixInstallError(
            "INSTALL_BACKUP_RECEIPT_INVALID",
            "backup-receipt",
            evidence={"path": str(path), "mode": oct(mode)},
        )
    return {
        "path": str(path),
        "sha256": sha256,
        "size": size,
        "mode": mode,
    }


def _capture_stage_backup_receipt(stage: str, result: dict[str, Any]) -> dict[str, Any]:
    expected, kind = _expected_backup_target(stage)
    files: list[Path] = []
    if stage in {"config-apply", "state-apply", "audit-apply"}:
        backup = result.get("backup")
        raw = str(backup.get("path", "")).strip() if isinstance(backup, dict) else ""
        if raw:
            files.append(absolute(raw))
    elif stage == "host-hooks":
        backups = result.get("backups")
        if isinstance(backups, list):
            for item in backups:
                if isinstance(item, dict) and str(item.get("path", "")).strip():
                    files.append(absolute(str(item["path"])))
        journal = str(result.get("transaction_journal", "")).strip()
        if journal:
            files.append(absolute(journal))
    else:
        backup_path = str(result.get("backup_path", "")).strip()
        journal = str(result.get("transaction_journal", "")).strip()
        if backup_path:
            files.append(absolute(backup_path))
        if not journal:
            raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)

    if not files:
        return {
            "schema_version": 1,
            "status": "not_applicable",
            "target": str(expected),
            "target_kind": kind,
            "files": [],
        }
    if kind == "directory":
        try:
            metadata = expected.lstat()
        except OSError as exc:
            raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o700)
        ):
            raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)
    unique_files = sorted(set(files), key=str)
    receipt = {
        "schema_version": 1,
        "status": "captured",
        "target": str(expected),
        "target_kind": kind,
        "files": [
            _receipt_file(path, expected_root=expected, root_kind=kind)
            for path in unique_files
        ],
    }
    if stage == "audit-launchagent-deferred":
        health = launchagent_transaction_health(
            absolute(str(_ACTIVE_INSTALL_TRANSACTION["input_projection"]["config_root"]))
        )
        transaction_id = str(health.get("transaction_id", ""))
        journal_path = str(health.get("journal_path", ""))
        if (
            re.fullmatch(r"[0-9a-f]{32}", transaction_id) is None
            or journal_path != str(absolute(journal))
            or health.get("status") != "deferred"
            or health.get("child_status") != "deferred"
            or health.get("recovery_required_seen") is not False
        ):
            raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)
        receipt["lifecycle"] = {
            "transaction_id": transaction_id,
            "journal_path": journal_path,
        }
    return receipt


def _verify_stage_backup_receipt(
    stage: str,
    result: dict[str, Any],
    *,
    allow_launchagent_rolled_back: bool = False,
) -> None:
    receipt = result.get("backup_receipt")
    expected, kind = _expected_backup_target(stage)
    if not isinstance(receipt, dict) or receipt.get("schema_version") != 1:
        raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)
    if receipt.get("target") != str(expected) or receipt.get("target_kind") != kind:
        raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)
    files = receipt.get("files")
    if not isinstance(files, list):
        raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)
    if receipt.get("status") == "not_applicable":
        if files or expected.exists() or expected.is_symlink():
            raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)
        return
    if receipt.get("status") != "captured" or not files:
        raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)
    if kind == "directory":
        try:
            metadata = expected.lstat()
        except OSError as exc:
            raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o700)
        ):
            raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)
    for item in files:
        if not isinstance(item, dict):
            raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)
        path = absolute(str(item.get("path", "")))
        current = _receipt_file(path, expected_root=expected, root_kind=kind)
        if current != item:
            raise PosixInstallError(
                "INSTALL_BACKUP_RECEIPT_MISMATCH",
                stage,
                evidence={"path": str(path)},
            )
    if stage == "audit-launchagent-deferred":
        lifecycle = receipt.get("lifecycle")
        if not isinstance(lifecycle, dict):
            raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)
        health = launchagent_transaction_health(
            absolute(str(_ACTIVE_INSTALL_TRANSACTION["input_projection"]["config_root"]))
        )
        status = str(health.get("status", ""))
        child_status = str(health.get("child_status", ""))
        lifecycle_ok = (
            (status == "deferred" and child_status == "deferred")
            or (status == "terminal" and child_status == "completed")
            or (
                allow_launchagent_rolled_back
                and status == "terminal"
                and child_status == "rolled_back"
            )
        )
        if (
            health.get("transaction_id") != lifecycle.get("transaction_id")
            or health.get("journal_path") != lifecycle.get("journal_path")
            or health.get("recovery_required_seen") is not False
            or not lifecycle_ok
        ):
            raise PosixInstallError("INSTALL_BACKUP_RECEIPT_INVALID", stage)


def _verify_completed_backup_receipts_from_tail(
    tail: list[dict[str, Any]],
    input_projection: dict[str, Any],
) -> None:
    global _ACTIVE_INSTALL_TRANSACTION
    completed: dict[str, dict[str, Any]] = {}
    for item in tail:
        if item.get("event") != "stage_completed":
            continue
        stage = str(item.get("stage", ""))
        result = item.get("result")
        if stage in BACKUP_RECEIPT_STAGES and isinstance(result, dict):
            completed[stage] = dict(result)
    previous = _ACTIVE_INSTALL_TRANSACTION
    _ACTIVE_INSTALL_TRANSACTION = {
        "input_projection": input_projection,
        "completed_results": completed,
    }
    try:
        _verify_all_completed_backup_receipts(
            allow_launchagent_rolled_back=True,
        )
    finally:
        _ACTIVE_INSTALL_TRANSACTION = previous


def _verify_all_completed_backup_receipts(
    *,
    allow_launchagent_rolled_back: bool = False,
) -> None:
    context = _ACTIVE_INSTALL_TRANSACTION
    if context is None:
        return
    completed = context.get("completed_results", {})
    for stage in sorted(BACKUP_RECEIPT_STAGES & set(completed)):
        _verify_stage_backup_receipt(
            stage,
            dict(completed[stage]),
            allow_launchagent_rolled_back=allow_launchagent_rolled_back,
        )


def _transaction_stage_started(stage: str) -> dict[str, Any] | None:
    context = _ACTIVE_INSTALL_TRANSACTION
    if context is None:
        return None
    completed = context.get("completed_results", {})
    if stage in MUTATING_STAGES and stage in completed:
        result = dict(completed[stage])
        if stage in BACKUP_RECEIPT_STAGES:
            _verify_stage_backup_receipt(stage, result)
        return result
    _append_install_event(
        context["journal"],
        {
            "event": "stage_started",
            "transaction_id": context["transaction_id"],
            "input_sha256": context["input_sha256"],
            "stage": stage,
        },
    )
    context.setdefault("started_stages", set()).add(stage)
    return None


def _transaction_stage_completed(stage: str, result: dict[str, Any]) -> None:
    context = _ACTIVE_INSTALL_TRANSACTION
    if context is None:
        return
    projected = _stage_result_projection(stage, result)
    _append_install_event(
        context["journal"],
        {
            "event": "stage_completed",
            "transaction_id": context["transaction_id"],
            "input_sha256": context["input_sha256"],
            "stage": stage,
            "result": projected,
        },
    )
    context.setdefault("completed_results", {})[stage] = projected


def absolute(raw: str) -> Path:
    return Path(os.path.abspath(os.path.expandvars(os.path.expanduser(raw))))


def option_text(args: argparse.Namespace, name: str) -> str:
    value = getattr(args, name, "")
    return value if isinstance(value, str) else ""


def run_json(
    command: list[str],
    *,
    stage: str,
    environment: dict[str, str],
    require_ok: bool = True,
    allow_blocked: bool = False,
    payload_validator: Callable[[dict[str, Any]], Any] | None = None,
    doctor_process_contract: bool = False,
) -> dict[str, Any]:
    resumed = _transaction_stage_started(stage)
    if resumed is not None:
        return resumed
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=900,
        check=False,
    )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise PosixInstallError("CHILD_JSON_INVALID", stage) from exc
    if doctor_process_contract and isinstance(payload, dict):
        try:
            state_migrator.validate_doctor_process_contract(
                payload,
                completed.returncode,
            )
        except ValueError as exc:
            raise PosixInstallError(str(exc), stage) from exc
    allowed_returncodes = {0, 2} if allow_blocked else {0}
    if (
        completed.returncode not in allowed_returncodes
        or not isinstance(payload, dict)
        or (require_ok and payload.get("ok") is not True)
    ):
        reason = str(payload.get("reason_code") or payload.get("error") or "CHILD_STAGE_FAILED") if isinstance(payload, dict) else "CHILD_STAGE_FAILED"
        raise PosixInstallError(reason, stage)
    if payload_validator is not None:
        try:
            payload_validator(payload)
        except ValueError as exc:
            reason = str(exc).strip()
            if re.fullmatch(r"[A-Z][A-Z0-9_]{2,160}", reason) is None:
                reason = "CHILD_STAGE_ATTESTATION_INVALID"
            raise PosixInstallError(reason, stage) from exc
    _transaction_stage_completed(stage, payload)
    return payload


def run_plain(command: list[str], *, stage: str, environment: dict[str, str]) -> dict[str, Any]:
    resumed = _transaction_stage_started(stage)
    if resumed is not None:
        return resumed
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=900,
        check=False,
    )
    if completed.returncode != 0:
        raise PosixInstallError("CHILD_STAGE_FAILED", stage)
    result = {"ok": True, "returncode": 0}
    _transaction_stage_completed(stage, result)
    return result


def publication_outcome(published: dict[str, Any]) -> dict[str, Any]:
    attestation = published.get("preflight_attestation")
    if not isinstance(attestation, dict):
        raise PosixInstallError("PREFLIGHT_ATTESTATION_INVALID", "publish-ready")
    try:
        content_debt = state_migrator._validate_content_migration_attestation(
            attestation
        )
    except ValueError as exc:
        raise PosixInstallError("CONTENT_MIGRATION_ATTESTATION_INVALID", "publish-ready")
    required = bool(attestation["content_migration_required"])
    scope_count = int(content_debt["legacy_scope_documents"])
    governance_count = int(
        content_debt["safe_automatic_governance_documents"]
    )
    if required:
        return {
            "status": "runtime_ready_content_migration_required",
            "runtime_ready": True,
            "installation_complete": False,
            "content_migration_required": True,
            "legacy_scope_documents": scope_count,
            "safe_automatic_governance_documents": governance_count,
            "content_migration": content_debt,
            "continuation": {
                "required": True,
                "reason_code": "AUTOMATIC_CONTENT_MIGRATION_REMAINS",
                "reason_codes": content_debt["reason_codes"],
                "legacy_scope_documents": scope_count,
                "safe_automatic_governance_documents": governance_count,
                "governance_metadata_automatic_documents": content_debt[
                    "governance_metadata_automatic_documents"
                ],
                "governance_risk_automatic_documents": content_debt[
                    "governance_risk_automatic_documents"
                ],
                "next_action": "RUN_CONTENT_MIGRATE_THEN_RERUN_INSTALLER_STRONG_PUBLISH",
                "instructions": (
                    "Run the managed memoryctl content-migrate governance-v4/risk-v4 flow for the attested "
                    "automatic debt; after Doctor reports zero automatic content debt, rerun this installer "
                    "with the same roots and host policy plus new unused config/state/hook backup paths. "
                    "Installation is complete only after that strong publish attests zero automatic debt."
                ),
            },
        }
    return {
        "status": "ready",
        "runtime_ready": True,
        "installation_complete": True,
        "content_migration_required": False,
        "legacy_scope_documents": 0,
        "safe_automatic_governance_documents": 0,
        "content_migration": content_debt,
        "continuation": {"required": False},
    }


def ensure_unused(path: Path, reason_code: str) -> None:
    if path.exists() or path.is_symlink():
        raise PosixInstallError(reason_code, "preflight")


def ensure_unused_or_resuming(
    path: Path,
    reason_code: str,
    *,
    owner_stage: str,
) -> None:
    context = _ACTIVE_INSTALL_TRANSACTION
    if context is not None and context.get("resuming"):
        completed = context.get("completed_results", {})
        if owner_stage in completed:
            _verify_stage_backup_receipt(owner_stage, dict(completed[owner_stage]))
            return
        if owner_stage in context.get("started_stages", set()) and (
            path.exists() or path.is_symlink()
        ):
            raise PosixInstallError(
                "INSTALL_BACKUP_STAGE_UNPROVEN",
                owner_stage,
                evidence={
                    "path": str(path),
                    "next_action": "SUPERSEDE_WITH_NEW_UNUSED_BACKUP_PATHS",
                },
            )
    ensure_unused(path, reason_code)


def host_policy(args: argparse.Namespace) -> tuple[list[str], list[str]]:
    hosts = sorted(set(args.host))
    if args.no_host_hooks == bool(hosts):
        raise PosixInstallError("HOST_HOOK_POLICY_REQUIRED", "preflight")
    hook_args = [item for host in hosts for item in ("--host", host)]
    publish = ["--no-host-hooks"] if args.no_host_hooks else [
        item for host in hosts for item in ("--require-host-hook", host)
    ]
    return hook_args, publish


def private_paths(args: argparse.Namespace) -> dict[str, Path]:
    config_root = absolute(args.config_root)
    return {
        "config_root": config_root,
        "config": config_root / "config" / "agent-memory.toml",
        "state": absolute(args.state_db) if args.state_db else config_root / "state.sqlite",
        "audit": config_root / "audit_decisions.sqlite",
        "config_backup": absolute(args.config_backup) if args.config_backup else Path(),
        "state_backup": absolute(args.state_backup) if args.state_backup else Path(),
        "audit_backup": (
            absolute(option_text(args, "audit_backup"))
            if option_text(args, "audit_backup")
            else Path()
        ),
        "hook_backup_dir": absolute(args.hook_backup_dir) if args.hook_backup_dir else Path(),
        "launchagent_backup_dir": (
            absolute(option_text(args, "launchagent_backup_dir"))
            if option_text(args, "launchagent_backup_dir")
            else Path()
        ),
        "disposition": absolute(args.disposition_file) if args.disposition_file else Path(),
    }


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _assert_no_symlink_ancestors(path: Path) -> None:
    chain: list[Path] = []
    cursor = path
    while True:
        chain.append(cursor)
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    for component in reversed(chain):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise PosixInstallError(
                "BACKUP_PARENT_SYMLINK",
                "backup-parents",
                evidence={"path": str(component)},
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise PosixInstallError(
                "BACKUP_PARENT_NOT_DIRECTORY",
                "backup-parents",
                evidence={"path": str(component)},
            )


def _validate_backup_namespace(
    args: argparse.Namespace,
    paths: dict[str, Path],
    target: Path,
) -> None:
    config_root = paths["config_root"]
    managed_root = config_root / "backups"
    if target == config_root or config_root in target.parents:
        if target != managed_root and managed_root not in target.parents:
            raise PosixInstallError(
                "BACKUP_TARGET_OUTSIDE_MANAGED_BACKUPS",
                "backup-parents",
                evidence={"path": str(target), "managed_root": str(managed_root)},
            )
        return

    active_paths = {
        config_root,
        paths["config"],
        paths["state"],
        paths["audit"],
        absolute(args.memory_root),
        absolute(args.git_root or args.memory_root),
        absolute("~/.codex"),
        absolute("~/.claude"),
    }
    for active in active_paths:
        if _paths_overlap(target, active):
            raise PosixInstallError(
                "BACKUP_TARGET_ACTIVE_PATH_OVERLAP",
                "backup-parents",
                evidence={"path": str(target), "active_path": str(active)},
            )


def prepare_private_backup_parents(
    args: argparse.Namespace,
    paths: dict[str, Path],
) -> dict[str, Any]:
    """Create or validate only the parent directories of fresh backup targets.

    Paths below the managed Runtime backup root may be created and hardened.
    External parents are never chmodded implicitly: they must already be 0700.
    Backup targets themselves remain absent for the exclusive child writers.
    """

    requested: list[tuple[Path, str, str]] = []
    for option, key, target_kind, owner_stage in (
        ("config_backup", "config_backup", "file", "config-apply"),
        ("state_backup", "state_backup", "file", "state-apply"),
        ("audit_backup", "audit_backup", "file", "audit-apply"),
        ("hook_backup_dir", "hook_backup_dir", "directory", "host-hooks"),
        (
            "launchagent_backup_dir",
            "launchagent_backup_dir",
            "directory",
            "audit-launchagent-deferred",
        ),
    ):
        if not option_text(args, option):
            continue
        target = paths[key]
        requested.append((target, target_kind, owner_stage))

    for index, (left, _left_kind, _left_stage) in enumerate(requested):
        for right, _right_kind, _right_stage in requested[index + 1:]:
            if left == right or left in right.parents or right in left.parents:
                raise PosixInstallError(
                    "BACKUP_TARGETS_OVERLAP",
                    "backup-parents",
                    evidence={"left": str(left), "right": str(right)},
                )

    for target, _target_kind, _owner_stage in requested:
        _validate_backup_namespace(args, paths, target)

    context = _ACTIVE_INSTALL_TRANSACTION

    def validate_target(target: Path, target_kind: str, owner_stage: str) -> None:
        try:
            metadata = target.lstat()
        except FileNotFoundError:
            return
        completed = (
            context.get("completed_results", {})
            if context is not None and context.get("resuming")
            else {}
        )
        if owner_stage in completed:
            _verify_stage_backup_receipt(owner_stage, dict(completed[owner_stage]))
            return
        if (
            context is not None
            and context.get("resuming")
            and owner_stage in context.get("started_stages", set())
        ):
            raise PosixInstallError(
                "INSTALL_BACKUP_STAGE_UNPROVEN",
                owner_stage,
                evidence={
                    "path": str(target),
                    "next_action": "SUPERSEDE_WITH_NEW_UNUSED_BACKUP_PATHS",
                },
            )
        else:
            raise PosixInstallError(
                "BACKUP_TARGET_EXISTS",
                "backup-parents",
                evidence={"path": str(target)},
            )

    for target, target_kind, owner_stage in requested:
        validate_target(target, target_kind, owner_stage)

    managed_root = paths["config_root"] / "backups"
    prepared: set[str] = set()
    for target, _target_kind, _owner_stage in requested:
        parent = target.parent
        _assert_no_symlink_ancestors(parent)
        try:
            relative = parent.relative_to(managed_root)
        except ValueError:
            ensure_private_directory(parent, harden_existing=False)
            _assert_no_symlink_ancestors(parent)
            metadata = parent.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o700)
            ):
                raise PosixInstallError(
                    "BACKUP_PARENT_NOT_PRIVATE",
                    "backup-parents",
                    evidence={"path": str(parent)},
                )
            prepared.add(str(parent))
            continue

        cursor = ensure_private_directory(managed_root, harden_existing=True)
        prepared.add(str(cursor))
        for component in relative.parts:
            cursor = ensure_private_directory(
                cursor / component,
                harden_existing=True,
            )
            prepared.add(str(cursor))
        _assert_no_symlink_ancestors(parent)
    for target, target_kind, owner_stage in requested:
        validate_target(target, target_kind, owner_stage)
    return {
        "ok": True,
        "managed_root": str(managed_root),
        "private_parents": sorted(prepared),
    }


def replace_toml_section_strings(
    text: str,
    section: str,
    values: dict[str, str],
) -> str:
    """Surgically replace required string assignments in one template section."""

    lines = text.splitlines(keepends=True)
    headers = [
        index
        for index, line in enumerate(lines)
        if line.strip() == f"[{section}]"
    ]
    if len(headers) != 1:
        raise PosixInstallError("CONFIG_TEMPLATE_INVALID", "config")
    start = headers[0] + 1
    end = next(
        (
            index
            for index in range(start, len(lines))
            if re.fullmatch(r"\s*\[[^\]\r\n]+\]\s*", lines[index].rstrip("\r\n"))
        ),
        len(lines),
    )
    for key, value in values.items():
        matches = [
            index
            for index in range(start, end)
            if re.match(rf"^[ \t]*{re.escape(key)}[ \t]*=", lines[index])
        ]
        if len(matches) != 1:
            raise PosixInstallError("CONFIG_TEMPLATE_INVALID", "config")
        index = matches[0]
        newline = "\r\n" if lines[index].endswith("\r\n") else "\n"
        lines[index] = f"{key} = {json.dumps(value, ensure_ascii=False)}{newline}"
    return "".join(lines)


def fresh_config_text(args: argparse.Namespace, paths: dict[str, Path], python: Path) -> str:
    template = REPO_ROOT / "config" / "agent-memory.example.toml"
    text = template.read_text(encoding="utf-8")
    values = {
        "memory_root": str(absolute(args.memory_root)),
        "git_root": str(absolute(args.git_root or args.memory_root)),
        "config_root": str(paths["config_root"]),
        "state_db": str(paths["state"]),
        "audit_db": str(paths["config_root"] / "audit_decisions.sqlite"),
        "closeout_log": str(paths["config_root"] / "logs" / "closeout.jsonl"),
        "audit_run_log": str(paths["config_root"] / "logs" / "audit_runs.jsonl"),
        "audit_report": str(paths["config_root"] / "reports" / "latest-audit.json"),
        "invariants_file": str(paths["config_root"] / "config" / "system-invariants.json"),
        "python": str(python),
        "user_id": args.user_id,
        "agent_id": args.agent_id,
        "app_id": args.app_id,
    }
    first_section = text.find("\n[")
    if first_section < 0:
        raise PosixInstallError("CONFIG_TEMPLATE_INVALID", "config")
    prefix, suffix = text[:first_section], text[first_section:]
    for key, value in values.items():
        pattern = re.compile(rf"(?m)^{re.escape(key)}\s*=\s*[^\r\n]+")
        replacement = f"{key} = {json.dumps(value, ensure_ascii=False)}"
        if not pattern.search(prefix):
            raise PosixInstallError("CONFIG_TEMPLATE_INVALID", "config")
        prefix = pattern.sub(replacement, prefix, count=1)
    rendered = prefix + suffix
    runtime_root = paths["config_root"]
    rendered = replace_toml_section_strings(
        rendered,
        "shadow",
        {"state_dir": str(runtime_root / "shadow")},
    )
    rendered = replace_toml_section_strings(
        rendered,
        "semantic_retrieval",
        {
            "vector_dir": str(runtime_root / "zvec" / "memory_chunks_embeddinggemma_768"),
            "python": str(python),
            "lock_path": str(runtime_root / "locks" / "zvec.lock"),
            "model_manifest": str(runtime_root / "models" / "embeddinggemma-300m" / "model-manifest.json"),
            "dependency_lock": str(runtime_root / "requirements-vector.lock"),
            "embedding_worker_socket": str(runtime_root / "run" / "embedding.sock"),
        },
    )
    return rendered


def create_fresh_config(args: argparse.Namespace, paths: dict[str, Path], python: Path) -> None:
    if paths["config"].exists() or paths["config"].is_symlink():
        raise PosixInstallError("CONFIG_ALREADY_EXISTS", "config")
    if paths["config"].parent.is_symlink() or not paths["config"].parent.is_dir():
        raise PosixInstallError("CONFIG_PARENT_UNSAFE", "config")
    content = fresh_config_text(args, paths, python).encode("utf-8")
    descriptor = os.open(
        paths["config"],
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def configured_paths(python: Path, runtime_scripts: Path, environment: dict[str, str]) -> dict[str, Path]:
    code = (
        "import json,sys;sys.path.insert(0,sys.argv[1]);"
        "from agent_memory_env import env_value,expand_path;"
        "from agent_memory_state import absolute_path;"
        "print(json.dumps({k:str(absolute_path(expand_path(env_value(v,'')))) for k,v in "
        "{'memory_root':'ROOT','git_root':'GIT_ROOT','state_db':'STATE_DB','audit_db':'AUDIT_DB'}.items()}))"
    )
    payload = run_json(
        [str(python), "-c", code, str(runtime_scripts)],
        stage="configured-paths",
        environment=environment,
        require_ok=False,
    )
    try:
        return {
            key: absolute(str(payload[key]))
            for key in ("memory_root", "git_root", "state_db", "audit_db")
        }
    except KeyError as exc:
        raise PosixInstallError("RUNTIME_CONFIG_INCOMPLETE", "configured-paths") from exc


def _lexically_beneath(root: Path, candidate: Path) -> bool:
    try:
        return os.path.commonpath((str(root), str(candidate))) == str(root)
    except ValueError:
        return False


def _expand_parent_symlinks(path: Path) -> Path | None:
    """Expand one symlinked component at a time without executing a target.

    Returning ``None`` means the chain is cyclic, too deep, or unreadable and
    therefore unsafe for source-interpreter selection.
    """

    current = absolute(str(path))
    seen: set[str] = set()
    for _ in range(64):
        identity = os.path.normcase(str(current))
        if identity in seen:
            return None
        seen.add(identity)
        parts = current.parts
        cursor = Path(current.anchor) if current.anchor else Path()
        redirected = False
        for index, part in enumerate(parts[1:] if current.anchor else parts):
            cursor = cursor / part
            try:
                metadata = cursor.lstat()
            except FileNotFoundError:
                return current
            except OSError:
                return None
            if not stat.S_ISLNK(metadata.st_mode):
                continue
            try:
                link = os.readlink(cursor)
            except OSError:
                return None
            remaining_index = index + (2 if current.anchor else 1)
            remaining = parts[remaining_index:]
            destination = Path(link) if os.path.isabs(link) else cursor.parent / link
            current = absolute(str(destination.joinpath(*remaining)))
            redirected = True
            break
        if not redirected:
            return current
    return None


def _candidate_enters_target_venv(candidate: Path, config_root: Path) -> bool:
    """Reject a target-venv path or symlink chain without executing/resolving it."""

    target = _expand_parent_symlinks(absolute(str(config_root / ".venv")))
    current = _expand_parent_symlinks(absolute(str(candidate)))
    if target is None or current is None:
        return True
    return _lexically_beneath(target, current)


def select_supported_python(args: argparse.Namespace, paths: dict[str, Path]) -> Path:
    """Select, but never create, the Python used by the source migrator."""

    candidates: list[str] = []
    if args.python:
        candidates.append(args.python)
    candidates.extend([
        sys.executable,
        *(shutil.which(name) or "" for name in ("python3.13", "python3.12", "python3.11", "python3.10")),
    ])
    seen: set[str] = set()
    explicit_identity = str(absolute(args.python)) if args.python else ""
    for raw in candidates:
        if not raw:
            continue
        candidate = absolute(raw)
        identity = str(candidate)
        if _candidate_enters_target_venv(candidate, paths["config_root"]):
            if identity == explicit_identity:
                raise PosixInstallError("SOURCE_PYTHON_TARGET_VENV_FORBIDDEN", "preflight")
            continue
        if identity in seen or candidate.is_symlink() and not candidate.exists():
            continue
        seen.add(identity)
        if not candidate.is_file():
            continue
        probe = subprocess.run(
            [str(candidate), "-c", "import sys; raise SystemExit(sys.version_info < (3, 10))"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if probe.returncode == 0:
            return candidate
    raise PosixInstallError("PYTHON_3_10_REQUIRED", "preflight")


def source_environment(paths: dict[str, Path], *, config_exists: bool) -> dict[str, str]:
    """Bind source-checkout probes to one explicit private installation.

    Inherited ``AGENT_MEMORY_*`` overrides may point at an unrelated live
    vault.  A product plan must inspect the TOML selected by ``--config-root``
    and must never borrow the caller's current Agent session configuration.
    """

    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AGENT_MEMORY_")
    }
    environment["AGENT_MEMORY_CONFIG_ROOT"] = str(paths["config_root"])
    environment["AGENT_MEMORY_MIGRATION_RUNTIME_ROOT"] = str(paths["config_root"])
    if config_exists:
        environment["AGENT_MEMORY_CONFIG_FILE"] = str(paths["config"])
    return environment


def regular_file_exists(path: Path, *, reason_prefix: str) -> bool:
    if path.is_symlink():
        raise PosixInstallError(f"{reason_prefix}_SYMLINK", "preflight")
    if path.exists() and not path.is_file():
        raise PosixInstallError(f"{reason_prefix}_NOT_REGULAR", "preflight")
    return path.is_file()


def installation_mode(*, config_exists: bool, state_exists: bool) -> str:
    if config_exists != state_exists:
        raise PosixInstallError("PARTIAL_INSTALL_AMBIGUOUS", "preflight")
    return "upgrade" if config_exists else "fresh"


def validate_requested_paths(
    args: argparse.Namespace,
    configured: dict[str, Path],
) -> None:
    requested_memory = absolute(args.memory_root)
    requested_git = absolute(args.git_root or args.memory_root)
    if configured["memory_root"] != requested_memory or configured["git_root"] != requested_git:
        raise PosixInstallError("CONFIGURED_ROOT_MISMATCH", "preflight")
    if args.state_db and configured["state_db"] != absolute(args.state_db):
        raise PosixInstallError("CONFIGURED_STATE_MISMATCH", "preflight")


def validate_upgrade_vault(
    args: argparse.Namespace,
    configured: dict[str, Path],
) -> dict[str, Any]:
    """Validate an existing vault without creating or replacing Markdown."""

    validate_requested_paths(args, configured)
    for label in ("memory_root", "git_root"):
        root = configured[label]
        if root.is_symlink() or not root.is_dir():
            raise PosixInstallError(f"UPGRADE_{label.upper()}_INVALID", "preflight")
    governance: list[str] = []
    for relative in ("AGENTS.md", "INDEX.md"):
        target = configured["memory_root"] / relative
        if target.is_symlink() or not target.is_file():
            raise PosixInstallError("UPGRADE_GOVERNANCE_MISSING", "preflight")
        governance.append(str(target))
    return {
        "ok": True,
        "memory_root": str(configured["memory_root"]),
        "git_root": str(configured["git_root"]),
        "governance": governance,
        "mutation": "none",
    }


def validate_fresh_vault(args: argparse.Namespace) -> dict[str, Any]:
    """A missing config/state pair cannot silently adopt an existing vault."""

    memory_root = absolute(args.memory_root)
    if memory_root.is_symlink() or (memory_root.exists() and not memory_root.is_dir()):
        raise PosixInstallError("FRESH_MEMORY_ROOT_INVALID", "preflight")
    if memory_root.is_dir():
        try:
            non_empty = next(memory_root.iterdir(), None) is not None
        except OSError as exc:
            raise PosixInstallError("FRESH_MEMORY_ROOT_UNREADABLE", "preflight") from exc
        if non_empty:
            raise PosixInstallError("FRESH_MEMORY_ROOT_NOT_EMPTY", "preflight")
    return {"ok": True, "memory_root": str(memory_root), "mutation": "bootstrap-on-apply"}


def discover_installation(
    args: argparse.Namespace,
    paths: dict[str, Path],
    *,
    source_python: Path,
) -> dict[str, Any]:
    config_exists = regular_file_exists(paths["config"], reason_prefix="CONFIG")
    environment = source_environment(paths, config_exists=config_exists)
    configured: dict[str, Path] | None = None
    if config_exists:
        configured = configured_paths(source_python, SOURCE_SCRIPTS, environment)
        paths["state"] = configured["state_db"]
        paths["audit"] = configured["audit_db"]
    state_exists = regular_file_exists(paths["state"], reason_prefix="STATE_DB")
    mode = installation_mode(config_exists=config_exists, state_exists=state_exists)
    vault = (
        validate_upgrade_vault(args, configured)
        if mode == "upgrade" and configured is not None
        else validate_fresh_vault(args)
    )
    return {
        "mode": mode,
        "config_exists": config_exists,
        "state_exists": state_exists,
        "configured": configured,
        "environment": environment,
        "vault": vault,
    }


def discover_installation_for_apply(
    args: argparse.Namespace,
    paths: dict[str, Path],
    *,
    source_python: Path,
) -> dict[str, Any]:
    context = _ACTIVE_INSTALL_TRANSACTION
    original_mode = str(context.get("original_mode", "")) if context else ""
    try:
        discovered = discover_installation(
            args,
            paths,
            source_python=source_python,
        )
    except PosixInstallError as exc:
        if exc.reason_code != "PARTIAL_INSTALL_AMBIGUOUS" or original_mode != "fresh":
            raise
        config_exists = regular_file_exists(paths["config"], reason_prefix="CONFIG")
        if not config_exists:
            raise
        environment = source_environment(paths, config_exists=True)
        configured = configured_paths(source_python, SOURCE_SCRIPTS, environment)
        validate_requested_paths(args, configured)
        paths["state"] = configured["state_db"]
        paths["audit"] = configured["audit_db"]
        if regular_file_exists(paths["state"], reason_prefix="STATE_DB"):
            raise
        return {
            "mode": "fresh",
            "config_exists": True,
            "state_exists": False,
            "configured": configured,
            "environment": environment,
            "vault": {"ok": True, "mutation": "resume-bootstrap"},
        }
    if original_mode == "fresh" and discovered.get("mode") == "upgrade":
        configured = discovered.get("configured")
        if not isinstance(configured, dict):
            raise PosixInstallError("PARTIAL_INSTALL_AMBIGUOUS", "preflight")
        validate_requested_paths(args, configured)
        return {
            **discovered,
            "mode": "fresh",
            "vault": {"ok": True, "mutation": "resume-bootstrap"},
        }
    return discovered


def source_config_plan(source_python: Path, environment: dict[str, str]) -> dict[str, Any]:
    return run_json(
        [str(source_python), str(SOURCE_SCRIPTS / "agent_memory_migrate.py"), "config-plan", "--json"],
        stage="config-plan",
        environment=environment,
    )


def source_state_plan(source_python: Path, environment: dict[str, str]) -> dict[str, Any]:
    payload = run_json(
        [str(source_python), str(SOURCE_SCRIPTS / "agent_memory_migrate.py"), "plan", "--json"],
        stage="state-plan",
        environment=environment,
        require_ok=False,
        allow_blocked=True,
    )
    if payload.get("stage") != "plan" or not isinstance(payload.get("plan"), dict):
        raise PosixInstallError(
            str(payload.get("reason_code") or "STATE_PLAN_INVALID"),
            "state-plan",
        )
    return payload


def source_audit_plan(source_python: Path, environment: dict[str, str]) -> dict[str, Any]:
    payload = run_json(
        [
            str(source_python),
            str(SOURCE_SCRIPTS / "agent_memory_migrate.py"),
            "audit-plan",
            "--json",
        ],
        stage="audit-plan",
        environment=environment,
        require_ok=False,
        allow_blocked=True,
    )
    if payload.get("ok") is not True or payload.get("stage") != "audit-plan" or payload.get("status") not in {
        "ready",
        "migration_required",
        "initialization_required",
    }:
        raise PosixInstallError(
            str(payload.get("reason_code") or "AUDIT_PLAN_INVALID"),
            "audit-plan",
        )
    return payload


def verify_committed_recovery_file(source_python: Path, environment: dict[str, str], path: str) -> dict[str, Any]:
    return run_json([
        str(source_python), str(SOURCE_SCRIPTS / "agent_memory_migrate.py"),
        "committed-recovery-verify", "--committed-recovery-file", str(absolute(path)), "--json",
    ], stage="committed-recovery-verify", environment=environment)


def verify_reviewed_dispositions(
    source_python: Path,
    environment: dict[str, str],
    disposition: Path | None,
) -> dict[str, Any]:
    command = [
        str(source_python),
        str(SOURCE_SCRIPTS / "agent_memory_migrate.py"),
        "disposition-verify",
    ]
    if disposition is not None:
        command.extend(["--disposition-file", str(disposition)])
    command.append("--json")
    return run_json(
        command,
        stage="disposition-verify",
        environment=environment,
    )


def source_generated_index_plan(
    source_python: Path,
    environment: dict[str, str],
    args: argparse.Namespace,
) -> dict[str, Any]:
    plan_environment = dict(environment)
    plan_environment["AGENT_MEMORY_ROOT"] = str(absolute(args.memory_root))
    plan_environment["AGENT_MEMORY_GIT_ROOT"] = str(
        absolute(args.git_root or args.memory_root)
    )
    target = SOURCE_SCRIPTS / "agent_memory_closeout.py"
    runner = (
        "import runpy,sys;"
        "target=sys.argv[1];sys.path.append(str(__import__('pathlib').Path(target).parent));"
        "sys.argv=sys.argv[1:];runpy.run_path(target,run_name='__main__')"
    )
    return run_json(
        [
            str(source_python),
            "-I",
            "-S",
            "-c",
            runner,
            str(target),
            "--actor", "migration",
            "--trigger", "migration",
            "--generated-index-migration-plan",
            "--json",
        ],
        stage="generated-index-plan",
        environment=plan_environment,
        require_ok=False,
        allow_blocked=True,
    )


def plan(args: argparse.Namespace) -> dict[str, Any]:
    paths = private_paths(args)
    selected_hosts, publish_policy = host_policy(args)
    source_python = select_supported_python(args, paths)
    discovered = discover_installation(args, paths, source_python=source_python)
    config_exists = bool(discovered["config_exists"])
    state_exists = bool(discovered["state_exists"])
    installer = SOURCE_SCRIPTS / "install_runtime.py"
    environment = discovered["environment"]
    generated_index_plan = source_generated_index_plan(
        source_python,
        environment,
        args,
    )
    runtime_plan = run_json(
        [str(source_python), str(installer), "--config-root", str(paths["config_root"]), "--dry-run", "--json"],
        stage="runtime-plan",
        environment=environment,
    )
    report: dict[str, Any] = {
        "ok": generated_index_plan.get("ok") is True,
        "status": "planned" if generated_index_plan.get("ok") is True else "blocked",
        "mode": discovered["mode"],
        "config_exists": config_exists,
        "state_exists": state_exists,
        "source_python": str(source_python),
        "source_migrator": str(SOURCE_SCRIPTS / "agent_memory_migrate.py"),
        "vault": discovered["vault"],
        "runtime": runtime_plan,
        "generated_index_plan": generated_index_plan,
        "required_inputs": [],
        "host_hook_args": selected_hosts,
        "publish_policy": publish_policy,
    }
    if selected_hosts:
        report["required_inputs"].append("--hook-backup-dir NEW_PRIVATE_DIRECTORY")
    if sys.platform == "darwin":
        report["required_inputs"].append("--launchagent-backup-dir NEW_PRIVATE_DIRECTORY")
        report["audit_launchagent"] = run_json(
            [
                str(source_python),
                str(SOURCE_SCRIPTS / "install_audit_launchagent.py"),
                "--plan",
                "--runtime-root", str(paths["config_root"]),
                "--python", str(paths["config_root"] / ".venv" / "bin" / "python"),
                "--json",
            ],
            stage="audit-launchagent-plan",
            environment=environment,
            require_ok=False,
            allow_blocked=True,
        )
    if config_exists:
        report["required_inputs"].extend([
            "--config-backup NEW_PATH",
            "--state-backup NEW_PATH",
        ])
    if discovered["mode"] == "upgrade":
        configured = discovered["configured"]
        assert isinstance(configured, dict)
        report["configured_paths"] = {key: str(value) for key, value in configured.items()}
        report["config_plan"] = source_config_plan(source_python, environment)
        state_plan = source_state_plan(source_python, environment)
        report["state_plan"] = state_plan
        if option_text(args, "committed_recovery_file"):
            report["committed_recovery"] = verify_committed_recovery_file(
                source_python, environment, args.committed_recovery_file,
            )
        report["audit_plan"] = source_audit_plan(source_python, environment)
        if report["audit_plan"].get("exists"):
            report["required_inputs"].append("--audit-backup NEW_PATH")
        decisions = state_plan.get("plan", {}).get("disposition_template", {}).get("decisions", [])
        if decisions:
            report["required_inputs"].append("--disposition-file REVIEWED_PLAN_JSON")
    return report


def apply(args: argparse.Namespace) -> dict[str, Any]:
    paths = private_paths(args)
    hook_args, publish_args = host_policy(args)
    source_python = select_supported_python(args, paths)
    discovered = discover_installation_for_apply(
        args,
        paths,
        source_python=source_python,
    )
    mode = str(discovered["mode"])
    environment = discovered["environment"]
    if _ACTIVE_INSTALL_TRANSACTION is not None:
        environment["AGENT_MEMORY_INSTALL_TRANSACTION_ID"] = str(
            _ACTIVE_INSTALL_TRANSACTION["transaction_id"]
        )
        environment["AGENT_MEMORY_INSTALL_INPUT_SHA256"] = str(
            _ACTIVE_INSTALL_TRANSACTION["input_sha256"]
        )
    source_preflight: dict[str, Any] = {"vault": discovered["vault"]}
    if mode == "upgrade":
        if not args.config_backup:
            raise PosixInstallError("CONFIG_BACKUP_REQUIRED", "preflight")
        ensure_unused_or_resuming(
            paths["config_backup"], "CONFIG_BACKUP_EXISTS", owner_stage="config-apply"
        )
        if not args.state_backup:
            raise PosixInstallError("STATE_BACKUP_REQUIRED", "preflight")
        ensure_unused_or_resuming(
            paths["state_backup"], "STATE_BACKUP_EXISTS", owner_stage="state-apply"
        )
        source_preflight["config_plan"] = source_config_plan(source_python, environment)
        source_preflight["state_plan"] = source_state_plan(source_python, environment)
        if option_text(args, "committed_recovery_file"):
            source_preflight["committed_recovery"] = verify_committed_recovery_file(
                source_python, environment, args.committed_recovery_file,
            )
        blockers = source_preflight["state_plan"].get("plan", {}).get("blockers", [])
        if blockers or args.disposition_file:
            disposition = paths["disposition"] if args.disposition_file else None
            source_preflight["disposition"] = verify_reviewed_dispositions(
                source_python,
                environment,
                disposition,
            )
        source_preflight["audit_plan"] = source_audit_plan(source_python, environment)
        if source_preflight["audit_plan"].get("exists"):
            if not option_text(args, "audit_backup"):
                raise PosixInstallError("AUDIT_BACKUP_REQUIRED", "preflight")
            ensure_unused_or_resuming(
                paths["audit_backup"], "AUDIT_BACKUP_EXISTS", owner_stage="audit-apply"
            )
    if not args.no_host_hooks:
        if not args.hook_backup_dir:
            raise PosixInstallError("HOOK_BACKUP_DIR_REQUIRED", "preflight")
        ensure_unused_or_resuming(
            paths["hook_backup_dir"], "HOOK_BACKUP_DIR_EXISTS", owner_stage="host-hooks"
        )
    if sys.platform == "darwin":
        if not option_text(args, "launchagent_backup_dir"):
            raise PosixInstallError("LAUNCHAGENT_BACKUP_DIR_REQUIRED", "preflight")
        ensure_unused_or_resuming(
            paths["launchagent_backup_dir"],
            "LAUNCHAGENT_BACKUP_DIR_EXISTS",
            owner_stage="audit-launchagent-deferred",
        )
    generated_index_plan = source_generated_index_plan(
        source_python,
        environment,
        args,
    )
    source_preflight["generated_index_plan"] = generated_index_plan
    if generated_index_plan.get("ok") is not True:
        raise PosixInstallError(
            str(
                generated_index_plan.get("reason_code")
                or "GENERATED_INDEX_MIGRATION_PLAN_BLOCKED"
            ),
            "generated-index-plan",
            evidence={"generated_index_plan": generated_index_plan},
        )
    stages: list[dict[str, Any]] = []
    stages.append({"stage": "source-preflight", "result": source_preflight})
    resumed_backup_parents = _transaction_stage_started("backup-parents")
    if resumed_backup_parents is None:
        backup_parents = prepare_private_backup_parents(args, paths)
        _transaction_stage_completed("backup-parents", backup_parents)
    else:
        backup_parents = {
            **prepare_private_backup_parents(args, paths),
            "resumed_validation": True,
        }
    stages.append({"stage": "backup-parents", "result": backup_parents})
    installed = run_json(
        [str(source_python), str(SOURCE_SCRIPTS / "install_runtime.py"), "--config-root", str(paths["config_root"]), "--json"],
        stage="runtime-install",
        environment=environment,
    )
    expected_bundle = (
        _ACTIVE_INSTALL_TRANSACTION.get("input_projection", {}).get(
            "runtime_bundle_sha256", ""
        )
        if _ACTIVE_INSTALL_TRANSACTION is not None
        else ""
    )
    if expected_bundle and installed.get("bundle_sha256") != expected_bundle:
        raise PosixInstallError(
            "INSTALL_RUNTIME_SOURCE_MISMATCH",
            "runtime-install",
            evidence={
                "expected_bundle_sha256": str(expected_bundle),
                "installed_bundle_sha256": str(installed.get("bundle_sha256", "")),
                "transaction_journal": str(
                    _ACTIVE_INSTALL_TRANSACTION.get("journal", "")
                    if _ACTIVE_INSTALL_TRANSACTION is not None
                    else ""
                ),
            },
        )
    stages.append({"stage": "runtime-install", "result": installed})
    python = paths["config_root"] / ".venv" / "bin" / "python"
    runtime_scripts = paths["config_root"] / "scripts"
    runtime_memoryctl = runtime_scripts / "memoryctl"
    def managed_command(command: str, *arguments: str) -> list[str]:
        return [
            str(python),
            "-I",
            "-S",
            str(runtime_memoryctl),
            "--actor",
            "migration",
            command,
            *arguments,
        ]
    def managed_migrate(*arguments: str) -> list[str]:
        return managed_command("migrate", *arguments)
    if mode == "upgrade":
        environment["AGENT_MEMORY_CONFIG_FILE"] = str(paths["config"])
        config_plan = run_json(managed_migrate("config-plan", "--json"), stage="config-plan", environment=environment)
        stages.append({"stage": "config-plan", "result": config_plan})
        if config_plan.get("changed"):
            config_apply = run_json(
                managed_migrate("config-apply", "--backup-path", str(paths["config_backup"]), "--json"),
                stage="config-apply",
                environment=environment,
            )
            stages.append({"stage": "config-apply", "result": config_apply})
    else:
        resumed_config = _transaction_stage_started("config-init")
        if resumed_config is None:
            if paths["config"].is_file() and not paths["config"].is_symlink():
                expected_config = fresh_config_text(args, paths, python).encode("utf-8")
                if paths["config"].read_bytes() != expected_config:
                    raise PosixInstallError("CONFIG_RESUME_CONFLICT", "config-init")
                config_result = {"ok": True, "created": False, "resumed": True}
            else:
                create_fresh_config(args, paths, python)
                config_result = {"ok": True, "created": True}
            _transaction_stage_completed("config-init", config_result)
        else:
            config_result = resumed_config
        environment["AGENT_MEMORY_CONFIG_FILE"] = str(paths["config"])
        stages.append({"stage": "config-init", "result": config_result})
    configured = configured_paths(source_python, SOURCE_SCRIPTS, environment)
    validate_requested_paths(args, configured)
    paths["state"] = configured["state_db"]
    paths["audit"] = configured.get(
        "audit_db",
        paths.get("audit", paths["config_root"] / "audit_decisions.sqlite"),
    )
    if mode == "fresh":
        bootstrap = run_plain(
            managed_command(
                "bootstrap", "--memory-root", str(absolute(args.memory_root)),
                "--config-root", str(paths["config_root"]), "--state-db", str(paths["state"]),
                "--git-root", str(absolute(args.git_root or args.memory_root)), "--user-id", args.user_id,
                "--agent-id", args.agent_id, "--app-id", args.app_id, "--init-git",
            ),
            stage="bootstrap",
            environment=environment,
        )
        stages.append({"stage": "bootstrap", "result": bootstrap})
    else:
        stages.append({"stage": "vault-upgrade", "result": discovered["vault"]})
    if mode == "upgrade":
        command = managed_migrate("apply", "--backup-path", str(paths["state_backup"]))
        if args.disposition_file:
            command.extend(["--disposition-file", str(paths["disposition"])])
        if option_text(args, "committed_recovery_file"):
            command.extend(["--committed-recovery-file", str(absolute(args.committed_recovery_file))])
        command.append("--json")
        stages.append({"stage": "state-apply", "result": run_json(command, stage="state-apply", environment=environment)})
        audit_plan = source_preflight["audit_plan"]
        if audit_plan.get("exists"):
            stages.append({
                "stage": "audit-apply",
                "result": run_json(
                    managed_migrate(
                        "audit-apply",
                        "--backup-path",
                        str(paths["audit_backup"]),
                        "--json",
                    ),
                    stage="audit-apply",
                    environment=environment,
                ),
            })
        else:
            stages.append({
                "stage": "audit-init",
                "result": run_json(
                    managed_migrate("audit-init", "--json"),
                    stage="audit-init",
                    environment=environment,
                ),
            })
    else:
        stages.append({"stage": "state-init", "result": run_json(managed_migrate("init", "--json"), stage="state-init", environment=environment)})
        stages.append({
            "stage": "audit-init",
            "result": run_json(
                managed_migrate("audit-init", "--json"),
                stage="audit-init",
                environment=environment,
            ),
        })
    stages.append({
        "stage": "generated-index-migrate",
        "result": run_json(
            managed_migrate("generated-index-migrate", "--json"),
            stage="generated-index-migrate",
            environment=environment,
        ),
    })
    if not args.no_host_hooks:
        hook_command = managed_command(
            "install-host-hooks", *hook_args,
            "--auto-closeout", "--backup-dir", str(paths["hook_backup_dir"]), "--apply", "--json",
        )
        stages.append({"stage": "host-hooks", "result": run_json(hook_command, stage="host-hooks", environment=environment)})
    launchagent_journal = (
        str(paths["launchagent_backup_dir"] / "audit-launchagent-transaction.jsonl")
        if sys.platform == "darwin"
        else ""
    )
    deferred_mutation_possible = False
    try:
        if sys.platform == "darwin":
            launchagent_deferred = run_json(
                managed_command(
                    "install-audit-launchagent",
                    "--apply",
                    "--runtime-root", str(paths["config_root"]),
                    "--python", str(python),
                    "--backup-dir", str(paths["launchagent_backup_dir"]),
                    "--defer-load",
                    "--json",
                ),
                stage="audit-launchagent-deferred",
                environment=environment,
            )
            deferred_mutation_possible = True
            returned_journal = str(
                launchagent_deferred.get("transaction_journal", "")
            ).strip()
            if returned_journal != launchagent_journal:
                raise PosixInstallError(
                    "AUDIT_LAUNCHAGENT_JOURNAL_INVALID",
                    "audit-launchagent-deferred",
                )
            stages.append({
                "stage": "audit-launchagent-deferred",
                "result": launchagent_deferred,
            })
        published = run_json(
            managed_migrate("verify", "--publish-ready", *publish_args, "--json"),
            stage="publish-ready",
            environment=environment,
        )
        stages.append({"stage": "publish-ready", "result": published})
        if sys.platform == "darwin":
            stages.append({
                "stage": "audit-launchagent-kickstart",
                "result": run_json(
                    managed_command(
                        "install-audit-launchagent",
                        "--finalize",
                        "--runtime-root", str(paths["config_root"]),
                        "--python", str(python),
                        "--journal", launchagent_journal,
                        "--json",
                    ),
                    stage="audit-launchagent-kickstart",
                    environment=environment,
                ),
            })
            stages.append({
                "stage": "final-doctor",
                "result": run_json(
                    managed_command("doctor", "--json"),
                    stage="final-doctor",
                    environment=environment,
                    require_ok=False,
                    allow_blocked=True,
                    doctor_process_contract=True,
                    payload_validator=lambda payload: (
                        state_migrator.validate_final_doctor_content_debt(
                            payload,
                            published["preflight_attestation"],
                        )
                    ),
                ),
            })
        outcome = publication_outcome(published)
    except BaseException as failure:
        journal_path = Path(launchagent_journal) if launchagent_journal else Path()
        durable_journal_exists = bool(
            launchagent_journal
            and journal_path.is_file()
            and not journal_path.is_symlink()
        )
        if (
            sys.platform != "darwin"
            or not launchagent_journal
            or not (deferred_mutation_possible or durable_journal_exists)
        ):
            raise
        try:
            compensation = run_json(
                managed_command(
                    "install-audit-launchagent",
                    "--rollback",
                    "--runtime-root", str(paths["config_root"]),
                    "--python", str(python),
                    "--journal", launchagent_journal,
                    "--json",
                ),
                stage="audit-launchagent-rollback",
                environment=environment,
            )
        except BaseException as rollback_failure:
            raise PosixInstallError(
                "AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED",
                "audit-launchagent-rollback",
                evidence={
                    "transaction_journal": launchagent_journal,
                    "launchagent_compensation": {
                        "ok": False,
                        "reason_code": getattr(
                            rollback_failure,
                            "reason_code",
                            type(rollback_failure).__name__.upper(),
                        ),
                    },
                },
            ) from rollback_failure
        original_reason = getattr(
            failure,
            "reason_code",
            type(failure).__name__.upper(),
        )
        original_stage = getattr(failure, "stage", "post-deferred")
        if isinstance(failure, (KeyboardInterrupt, SystemExit)):
            raise
        raise PosixInstallError(
            str(original_reason),
            str(original_stage),
            evidence={
                "transaction_journal": launchagent_journal,
                "launchagent_compensation": compensation,
            },
        ) from failure
    return {"ok": True, "mode": mode, "stages": stages, **outcome}


def apply_with_orchestration_transaction(args: argparse.Namespace) -> dict[str, Any]:
    """Serialize the whole install and retain one fixed crash-recovery journal."""

    global _ACTIVE_INSTALL_TRANSACTION
    paths = private_paths(args)
    config_root = paths["config_root"]
    if config_root.is_symlink() or (config_root.exists() and not config_root.is_dir()):
        raise PosixInstallError("CONFIG_ROOT_UNSAFE", "orchestration")
    lock_path = config_root / "locks" / "install-orchestration.lock"
    journal = _install_journal_path(config_root)
    try:
        lock_context = private_lock(
            lock_path,
            timeout=max(float(getattr(args, "lock_timeout", 0.0)), 0.0),
            timeout_message="INSTALL_ALREADY_RUNNING",
        )
        with lock_context:
            projection = _install_input_projection(args, paths)
            fingerprint = _install_input_sha256(projection)
            events = _read_install_journal(journal)
            tail = _active_install_tail(events)
            resuming = False
            superseded_from = ""
            supersede_target = str(
                getattr(args, "supersede_interrupted", "") or ""
            ).strip()
            supersede_requested = bool(supersede_target)
            if supersede_requested and re.fullmatch(r"[0-9a-f]{32}", supersede_target) is None:
                raise PosixInstallError(
                    "INSTALL_SUPERSEDE_TARGET_INVALID",
                    "orchestration-supersede",
                )
            if tail:
                last_event = str(tail[-1]["event"])
                if last_event == "recovery_required":
                    if not supersede_requested:
                        raise PosixInstallError(
                            "INSTALL_RECOVERY_REQUIRED",
                            "orchestration",
                            evidence={"transaction_journal": str(journal)},
                        )
                    if supersede_target != str(tail[0]["transaction_id"]):
                        raise PosixInstallError(
                            "INSTALL_SUPERSEDE_TARGET_MISMATCH",
                            "orchestration-supersede",
                            evidence={"transaction_journal": str(journal)},
                        )
                    transaction_id = uuid.uuid4().hex
                    evidence = _prove_recovery_required_transaction_supersedable(
                        tail=tail,
                        config_root=config_root,
                    )
                    evidence.update({
                        "replacement_transaction_id": transaction_id,
                        "replacement_input_sha256": fingerprint,
                    })
                    _append_install_event(
                        journal,
                        {
                            "event": "superseded",
                            "transaction_id": str(tail[0]["transaction_id"]),
                            "input_sha256": str(tail[0]["input_sha256"]),
                            "reason_code": "INSTALL_TRANSACTION_SUPERSEDED",
                            "replacement_transaction_id": transaction_id,
                            "replacement_input_sha256": fingerprint,
                            "evidence": evidence,
                            "evidence_sha256": _install_input_sha256(evidence),
                        },
                    )
                    original_mode = "upgrade" if paths["config"].exists() else "fresh"
                    superseded_from = str(tail[0]["transaction_id"])
                    tail = []
                elif last_event == "superseded":
                    evidence = tail[-1]["evidence"]
                    if str(evidence["replacement_input_sha256"]) != fingerprint:
                        raise PosixInstallError(
                            "INSTALL_SUPERSEDE_REPLACEMENT_INPUT_MISMATCH",
                            "orchestration",
                            evidence={"transaction_journal": str(journal)},
                        )
                    transaction_id = str(evidence["replacement_transaction_id"])
                    original_mode = "upgrade" if paths["config"].exists() else "fresh"
                    superseded_from = str(tail[0]["transaction_id"])
                    tail = []
                elif last_event == "interrupted" and str(tail[0]["input_sha256"]) != fingerprint:
                    if not supersede_requested:
                        raise PosixInstallError(
                            "INSTALL_TRANSACTION_INPUT_MISMATCH",
                            "orchestration",
                            evidence={"transaction_journal": str(journal)},
                        )
                    if supersede_target != str(tail[0]["transaction_id"]):
                        raise PosixInstallError(
                            "INSTALL_SUPERSEDE_TARGET_MISMATCH",
                            "orchestration-supersede",
                            evidence={"transaction_journal": str(journal)},
                        )
                    transaction_id = uuid.uuid4().hex
                    try:
                        evidence = _prove_interrupted_transaction_supersedable(
                            tail=tail,
                            config_root=config_root,
                        )
                    except PosixInstallError as exc:
                        if exc.reason_code in {
                            "INSTALL_BACKUP_RECEIPT_INVALID",
                            "INSTALL_BACKUP_RECEIPT_MISMATCH",
                        }:
                            _append_install_event(
                                journal,
                                {
                                    "event": "recovery_required",
                                    "transaction_id": str(tail[0]["transaction_id"]),
                                    "input_sha256": str(tail[0]["input_sha256"]),
                                    "reason_code": exc.reason_code,
                                    "stage": exc.stage,
                                },
                            )
                        raise
                    evidence.update({
                        "replacement_transaction_id": transaction_id,
                        "replacement_input_sha256": fingerprint,
                    })
                    _append_install_event(
                        journal,
                        {
                            "event": "superseded",
                            "transaction_id": str(tail[0]["transaction_id"]),
                            "input_sha256": str(tail[0]["input_sha256"]),
                            "reason_code": "INSTALL_TRANSACTION_SUPERSEDED",
                            "replacement_transaction_id": transaction_id,
                            "replacement_input_sha256": fingerprint,
                            "evidence": evidence,
                            "evidence_sha256": _install_input_sha256(evidence),
                        },
                    )
                    original_mode = "upgrade" if paths["config"].exists() else "fresh"
                    superseded_from = str(tail[0]["transaction_id"])
                    tail = []
                elif last_event != "completed":
                    if supersede_requested:
                        raise PosixInstallError(
                            "INSTALL_SUPERSEDE_NOT_NEEDED",
                            "orchestration",
                        )
                    if str(tail[0]["input_sha256"]) != fingerprint:
                        raise PosixInstallError(
                            "INSTALL_TRANSACTION_INPUT_MISMATCH",
                            "orchestration",
                            evidence={"transaction_journal": str(journal)},
                        )
                    transaction_id = str(tail[0]["transaction_id"])
                    original_mode = str(tail[0].get("original_mode", ""))
                    resuming = True
                else:
                    if supersede_requested:
                        raise PosixInstallError(
                            "INSTALL_SUPERSEDE_REQUIRES_INTERRUPTED",
                            "orchestration",
                        )
                    transaction_id = uuid.uuid4().hex
                    original_mode = "upgrade" if paths["config"].exists() else "fresh"
                    tail = []
            else:
                if supersede_requested:
                    raise PosixInstallError(
                        "INSTALL_SUPERSEDE_REQUIRES_INTERRUPTED",
                        "orchestration",
                    )
                transaction_id = uuid.uuid4().hex
                original_mode = "upgrade" if paths["config"].exists() else "fresh"

            started_stages = {
                str(item.get("stage"))
                for item in tail
                if item.get("event") == "stage_started" and str(item.get("stage", ""))
            }
            completed_results: dict[str, dict[str, Any]] = {}
            for item in tail:
                if item.get("event") != "stage_completed":
                    continue
                stage = str(item.get("stage", ""))
                result = item.get("result")
                if stage and isinstance(result, dict):
                    completed_results[stage] = dict(result)
            if resuming:
                _append_install_event(
                    journal,
                    {
                        "event": "resumed",
                        "transaction_id": transaction_id,
                        "input_sha256": fingerprint,
                    },
                )
            else:
                _append_install_event(
                    journal,
                    {
                        "event": "prepared",
                        "transaction_id": transaction_id,
                        "input_sha256": fingerprint,
                        "original_mode": original_mode,
                        "input_projection": projection,
                        **(
                            {"supersedes_transaction_id": superseded_from}
                            if superseded_from
                            else {}
                        ),
                    },
                )
            _ACTIVE_INSTALL_TRANSACTION = {
                "journal": journal,
                "transaction_id": transaction_id,
                "input_sha256": fingerprint,
                "input_projection": projection,
                "original_mode": original_mode,
                "resuming": resuming,
                "started_stages": started_stages,
                "completed_results": completed_results,
            }
            try:
                result = apply(args)
                try:
                    terminal_projection = _install_input_projection(args, paths)
                except PosixInstallError as exc:
                    raise PosixInstallError(
                        "INSTALL_INPUT_CHANGED_DURING_APPLY",
                        "orchestration",
                        exc.reason_code,
                        evidence={"transaction_journal": str(journal)},
                    ) from exc
                if _install_input_sha256(terminal_projection) != fingerprint:
                    raise PosixInstallError(
                        "INSTALL_INPUT_CHANGED_DURING_APPLY",
                        "orchestration",
                        evidence={"transaction_journal": str(journal)},
                    )
                _verify_all_completed_backup_receipts()
            except BaseException as exc:
                reason = str(getattr(exc, "reason_code", type(exc).__name__.upper()))
                stage = str(getattr(exc, "stage", "orchestration"))
                event = (
                    "recovery_required"
                    if reason in {
                        "AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED",
                        "INSTALL_RECOVERY_REQUIRED",
                        "INSTALL_INPUT_CHANGED_DURING_APPLY",
                        "INSTALL_RUNTIME_SOURCE_MISMATCH",
                        "INSTALL_BACKUP_RECEIPT_INVALID",
                        "INSTALL_BACKUP_RECEIPT_MISMATCH",
                    }
                    else "interrupted"
                )
                _append_install_event(
                    journal,
                    {
                        "event": event,
                        "transaction_id": transaction_id,
                        "input_sha256": fingerprint,
                        "reason_code": reason,
                        "stage": stage,
                    },
                )
                raise
            else:
                _append_install_event(
                    journal,
                    {
                        "event": "completed",
                        "transaction_id": transaction_id,
                        "input_sha256": fingerprint,
                        "status": str(result.get("status", "ready")),
                    },
                )
                return {
                    **result,
                    "install_transaction": {
                        "transaction_id": transaction_id,
                        "journal": str(journal),
                        "resumed": resuming,
                        "status": "completed",
                    },
                }
            finally:
                _ACTIVE_INSTALL_TRANSACTION = None
    except TimeoutError as exc:
        raise PosixInstallError("INSTALL_ALREADY_RUNNING", "orchestration") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plan or apply a fail-closed POSIX Agent Memory v2 installation")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--plan", action="store_true")
    action.add_argument("--apply", action="store_true")
    parser.add_argument("--config-root", default="~/.config/agent-memory")
    parser.add_argument("--memory-root", required=True)
    parser.add_argument("--git-root", default="")
    parser.add_argument("--state-db", default="")
    parser.add_argument("--python", default="", help="Existing Python 3.10+ used for source planning and installation")
    parser.add_argument("--config-backup", default="")
    parser.add_argument("--state-backup", default="")
    parser.add_argument("--audit-backup", default="")
    parser.add_argument("--disposition-file", default="")
    parser.add_argument("--committed-recovery-file", default="", help="Reviewed exact committed-write recovery plan; applied inside the backed-up state migration.")
    parser.add_argument("--hook-backup-dir", default="")
    parser.add_argument("--launchagent-backup-dir", default="")
    parser.add_argument("--host", action="append", choices=("codex", "claude"), default=[])
    parser.add_argument("--no-host-hooks", action="store_true")
    parser.add_argument("--user-id", default="demo-user")
    parser.add_argument("--agent-id", default="shared")
    parser.add_argument("--app-id", default="agent-memory")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--lock-timeout", type=float, default=0.0)
    parser.add_argument(
        "--supersede-interrupted",
        metavar="TRANSACTION_ID",
        default="",
        help=(
            "Explicitly supersede this exact proven compensated interrupted transaction, "
            "or the narrowly attested state-apply receipt-tail recovery case, before applying new inputs."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if os.name != "posix":
            raise PosixInstallError("POSIX_ONLY", "preflight")
        if args.plan and args.supersede_interrupted:
            raise PosixInstallError(
                "INSTALL_SUPERSEDE_APPLY_ONLY",
                "orchestration-supersede",
            )
        payload = plan(args) if args.plan else apply_with_orchestration_transaction(args)
    except (OSError, subprocess.SubprocessError, PosixInstallError) as exc:
        payload = {
            "ok": False,
            "status": "blocked",
            "stage": getattr(exc, "stage", "orchestration"),
            "reason_code": getattr(exc, "reason_code", type(exc).__name__).upper(),
            **(
                exc.evidence
                if isinstance(exc, PosixInstallError)
                else {}
            ),
        }
    print(json.dumps(payload, ensure_ascii=False, indent=2) if args.json else f"posix_install={payload['status']}")
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
