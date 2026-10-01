#!/usr/bin/env python3
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
import time
import uuid
from pathlib import Path
from typing import Any

from agent_memory_env import (
    RUNTIME_RELEASE_VERSION,
    WRITE_GATEWAY_CAPABILITIES,
    expand_path,
    parse_toml_fallback,
)
from agent_memory_lock import private_lock, try_lock, unlock
from agent_memory_state import (
    ConditionalWriteError,
    STATE_SCHEMA_VERSION,
    POSIX_PERMISSION_MODEL,
    PRIVATE_DIRECTORY_MODE,
    PRIVATE_FILE_MODE,
    StateSecurityError,
    absolute_path,
    assert_no_symlink_beneath,
    ensure_private_directory,
    harden_private_file,
    harden_sqlite_files,
    relative_beneath,
    runtime_python_attestation,
    runtime_python_attestation_matches,
    runtime_python_static_attestation_matches,
    _python_launcher_identity,
    secure_atomic_copy_beneath,
    secure_atomic_write_bytes_beneath,
    secure_conditional_create_bytes_beneath,
    secure_conditional_move_bytes_beneath,
    secure_conditional_write_bytes_beneath,
    secure_read_bytes_and_stat_beneath,
    secure_read_bytes_beneath,
    secure_sha256_beneath,
    secure_sqlite_connect,
    sqlite_permission_report,
)


_MODULE_PATH = absolute_path(__file__)
SOURCE_ROOT = _MODULE_PATH.parent
REPO_ROOT = SOURCE_ROOT.parent
assert_no_symlink_beneath(REPO_ROOT, _MODULE_PATH, include_leaf=True)
TEMPLATE_ROOT = REPO_ROOT / "templates" / "vault"
CORE_FILES = (
    "agent_memory_audit.py",
    "agent_memory_audit_autorun.py",
    "agent_memory_claim.py",
    "agent_memory_check.py",
    "agent_memory_closeout.py",
    "agent_memory_confirmation_capability.py",
    "agent_memory_content_migrate.py",
    "agent_memory_doctor.py",
    "agent_memory_decision_outcomes.py",
    "agent_memory_embedding_worker.py",
    "agent_memory_env.py",
    "agent_memory_evolution.py",
    "agent_memory_explain.py",
    "agent_memory_generated_index_capability.py",
    "agent_memory_index.py",
    "agent_memory_host_automation.py",
    "agent_memory_intent.py",
    "agent_memory_lock.py",
    "agent_memory_migrate.py",
    "agent_memory_observability.py",
    "agent_memory_policy_benchmark.py",
    "agent_memory_retrieval_benchmark.py",
    "agent_memory_retrieve.py",
    "agent_memory_search.py",
    "agent_memory_shadow.py",
    "agent_memory_safety.py",
    "agent_memory_write.py",
    "agent_memory_session_hook.py",
    "agent_memory_state.py",
    "agent_memory_stop_hook.py",
    "agent_memory_zvec_index.py",
    "audit-task.ps1",
    "bootstrap.py",
    "install-codex-hook.ps1",
    "install_audit_launchagent.py",
    "install-posix.py",
    "install_host_hooks.py",
    "install_runtime.py",
    "install-windows.ps1",
    "memoryctl",
    "stop-hook.ps1",
)
SUPPORT_FILES = (
    "requirements-vector.lock",
    "benchmarks/public-sample.json",
    "benchmarks/public-policy-reconcile.json",
    "benchmarks/public-policy-safety.json",
)
RUNTIME_ANCHOR_RELATIVE = Path("config/runtime-anchor.json")
RUNTIME_ANCHOR_SCHEMA_VERSION = 1
RUNTIME_PYTHON_STATIC_KEYS = (
    "launcher", "launcher_chain", "resolved_path", "resolved_sha256", "resolved_identity",
)
RUNTIME_TRANSACTION_SCHEMA_VERSION = 1
RUNTIME_TRANSACTION_JOURNAL = "transaction.jsonl"
RUNTIME_VENV_MARKER = ".agent-memory-runtime-transaction"
RUNTIME_TRANSACTION_EVENTS = {
    "prepared", "target_intent", "target_applied", "venv_move_intent",
    "venv_moved", "venv_create_started", "venv_created", "venv_create_failed",
    "semantic_dependencies_install_started",
    "semantic_dependencies_install_completed",
    "semantic_dependencies_install_failed",
    "completed", "rolled_back", "recovery_required", "journal_tail_recovered",
}

SEMANTIC_DEPENDENCY_CHECK_CODE = r"""
import importlib.metadata as metadata
import json
import re
import sys

expected = {}
invalid = []
duplicates = []
with open(sys.argv[1], encoding="utf-8") as handle:
    for line_number, raw in enumerate(handle, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        matched = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)", line)
        if matched is None:
            invalid.append(line_number)
            continue
        name, version = matched.groups()
        normalized = re.sub(r"[-_.]+", "-", name).casefold()
        if normalized in expected:
            duplicates.append(name)
            continue
        expected[normalized] = {"name": name, "version": version}

missing = []
mismatched = []
for item in expected.values():
    name = item["name"]
    version = item["version"]
    try:
        actual = metadata.version(name)
    except metadata.PackageNotFoundError:
        missing.append(name)
        continue
    if actual != version:
        mismatched.append({"name": name, "expected": version, "actual": actual})

payload = {
    "expected": len(expected),
    "missing": missing,
    "mismatched": mismatched,
    "invalid_lines": invalid,
    "duplicates": duplicates,
}
print(json.dumps(payload, sort_keys=True))
raise SystemExit(
    0
    if expected and not missing and not mismatched and not invalid and not duplicates
    else 2
)
"""


@contextlib.contextmanager
def runtime_install_lock(config_root: Path, timeout: float = 30.0):
    lock_root = config_root / "locks"
    ensure_private_directory(config_root, harden_existing=True)
    ensure_private_directory(lock_root, harden_existing=True)
    lock_path = lock_root / "runtime-install.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, PRIVATE_FILE_MODE)
    with os.fdopen(descriptor, "a+", encoding="utf-8") as handle:
        if POSIX_PERMISSION_MODEL:
            os.fchmod(handle.fileno(), PRIVATE_FILE_MODE)
        deadline = time.monotonic() + max(timeout, 0.0)
        while not try_lock(handle):
            if time.monotonic() >= deadline:
                raise TimeoutError("another Agent Memory runtime installation is still active")
            time.sleep(0.1)
        try:
            yield
        finally:
            unlock(handle)


@contextlib.contextmanager
def runtime_transition_lock(config_root: Path, timeout: float = 30.0):
    """Use the same runtime-install -> closeout order as the migrator."""

    with runtime_install_lock(config_root, timeout=timeout):
        with private_lock(
            config_root / "locks" / "closeout.lock",
            timeout=timeout,
            timeout_message="runtime transition lock timeout",
        ):
            yield


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _fsync_directory(path: Path) -> None:
    if not POSIX_PERMISSION_MODEL:
        return
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


def _append_runtime_journal(
    transaction: dict[str, Any],
    event: dict[str, Any],
    *,
    create: bool = False,
) -> None:
    journal = Path(str(transaction["journal_path"]))
    payload = {
        "transaction_id": str(transaction["transaction_id"]),
        "recorded_at": utc_now(),
        **event,
    }
    flags = (
        os.O_RDWR
        | os.O_APPEND
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor = os.open(journal, flags, PRIVATE_FILE_MODE)
    with os.fdopen(descriptor, "a+b", closefd=True) as handle:
        handle.seek(0)
        existing = handle.read()
        rows = _decode_runtime_journal(existing) if existing else []
        if rows:
            transaction_ids = {
                str(row.get("transaction_id", "")) for row in rows
            }
            expected_id = str(transaction["transaction_id"])
            if transaction_ids != {expected_id}:
                raise StateSecurityError(
                    "runtime transaction journal identity is invalid"
                )
            if any(
                row.get("event") in {"completed", "rolled_back", "recovery_required"}
                for row in rows
            ):
                raise StateSecurityError(
                    "runtime transaction journal is already terminal"
                )
        if existing and not existing.endswith(b"\n"):
            # A power loss can leave only the final JSONL record incomplete.
            # Preserve those bytes in-place, terminate the damaged record, and
            # bind a machine-verifiable recovery marker to its exact hash.  A
            # malformed *completed* record remains a hard failure when read.
            discarded = existing.rsplit(b"\n", 1)[-1]
            try:
                complete_tail = json.loads(discarded.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                complete_tail = None
            if isinstance(complete_tail, dict):
                raise StateSecurityError(
                    "runtime transaction journal has an unterminated complete record"
                )
            marker = {
                "transaction_id": expected_id,
                "recorded_at": utc_now(),
                "event": "journal_tail_recovered",
                "discarded_sha256": hashlib.sha256(discarded).hexdigest(),
                "discarded_bytes": len(discarded),
            }
            handle.seek(0, os.SEEK_END)
            handle.write(b"\n")
            handle.write(
                json.dumps(marker, ensure_ascii=False, sort_keys=True).encode("utf-8")
                + b"\n"
            )
        handle.write(
            json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            + b"\n"
        )
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_directory(journal.parent)


def _decode_runtime_journal(raw: bytes) -> list[dict[str, Any]]:
    """Decode durable JSONL while tolerating only a provable crash tail.

    An unterminated final record is ignored until the next append seals it with
    ``journal_tail_recovered``.  Once sealed, its exact bytes must match that
    marker.  Any other malformed completed record is corruption and fails
    closed.
    """

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
                raise StateSecurityError(
                    "runtime transaction journal is invalid"
                ) from exc
            try:
                marker = json.loads(complete[index + 1].decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as marker_error:
                raise StateSecurityError(
                    "runtime transaction journal is invalid"
                ) from marker_error
            if not (
                isinstance(marker, dict)
                and marker.get("event") == "journal_tail_recovered"
                and marker.get("discarded_sha256")
                == hashlib.sha256(segment).hexdigest()
                and marker.get("discarded_bytes") == len(segment)
            ):
                raise StateSecurityError(
                    "runtime transaction journal is invalid"
                ) from exc
            rows.append(marker)
            index += 2
            continue
        if not isinstance(row, dict):
            raise StateSecurityError("runtime transaction journal is invalid")
        rows.append(row)
        index += 1
    return rows


def _read_runtime_journal(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise StateSecurityError("runtime transaction journal is unsafe")
    try:
        rows = _decode_runtime_journal(path.read_bytes())
    except OSError as exc:
        raise StateSecurityError("runtime transaction journal is invalid") from exc
    if not rows or not all(isinstance(row, dict) for row in rows):
        raise StateSecurityError("runtime transaction journal is invalid")
    transaction_ids = {str(row.get("transaction_id", "")) for row in rows}
    if (
        len(transaction_ids) != 1
        or not re.fullmatch(r"[0-9a-f]{32}", next(iter(transaction_ids), ""))
        or any(str(row.get("event", "")) not in RUNTIME_TRANSACTION_EVENTS for row in rows)
    ):
        raise StateSecurityError("runtime transaction journal identity is invalid")
    return rows


def _runtime_transaction_status(rows: list[dict[str, Any]]) -> str:
    """Reduce one validated journal without allowing terminal ambiguity."""

    states = [
        str(row.get("event", ""))
        for row in rows
        if row.get("event") in {"completed", "rolled_back", "recovery_required"}
    ]
    if len(states) > 1:
        raise StateSecurityError("runtime transaction terminal state is ambiguous")
    if not states:
        return "pending"
    terminal_index = next(
        index
        for index, row in enumerate(rows)
        if row.get("event") in {"completed", "rolled_back", "recovery_required"}
    )
    if terminal_index != len(rows) - 1:
        raise StateSecurityError("runtime transaction terminal state is not final")
    return "recovery_required" if states[0] == "recovery_required" else "terminal"


def _venv_transaction_marker(venv_root: Path) -> str:
    marker = venv_root / RUNTIME_VENV_MARKER
    try:
        metadata = marker.lstat()
    except FileNotFoundError:
        return ""
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return ""
    try:
        return marker.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return ""


def _write_venv_transaction_marker(venv_root: Path, transaction_id: str) -> None:
    marker = venv_root / RUNTIME_VENV_MARKER
    descriptor = os.open(
        marker,
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        PRIVATE_FILE_MODE,
    )
    with os.fdopen(descriptor, "w", encoding="ascii", closefd=True) as handle:
        handle.write(transaction_id + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_directory(venv_root)


def managed_python_path(config_root: Path) -> Path:
    return (
        config_root / ".venv" / "Scripts" / "python.exe"
        if os.name == "nt"
        else config_root / ".venv" / "bin" / "python"
    )


def _runtime_anchor_payload(config_root: Path, install_id: str) -> dict[str, Any]:
    return {
        "schema_version": RUNTIME_ANCHOR_SCHEMA_VERSION,
        "managed_runtime": True,
        "runtime_root": str(absolute_path(config_root)),
        "install_id": install_id,
    }


def _runtime_anchor_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    ).hexdigest()


def load_or_create_runtime_anchor(config_root: Path) -> tuple[dict[str, Any], bool]:
    """Return a stable managed identity without trusting executable code.

    Existing anchors are read through the contained no-symlink primitive.  A
    missing anchor is created only by the trusted source installer; it then
    survives manifest/transition loss and makes a managed root unambiguous.
    """

    target = config_root / RUNTIME_ANCHOR_RELATIVE
    assert_no_symlink_beneath(config_root, target, include_leaf=False, allow_missing=True)
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        payload = _runtime_anchor_payload(config_root, os.urandom(32).hex())
        return payload, True
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise StateSecurityError("managed runtime anchor is unsafe")
    try:
        raw = secure_read_bytes_beneath(config_root, RUNTIME_ANCHOR_RELATIVE)
    except (OSError, StateSecurityError) as exc:
        raise StateSecurityError("managed runtime anchor is unsafe") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateSecurityError("managed runtime anchor is invalid") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != RUNTIME_ANCHOR_SCHEMA_VERSION
        or payload.get("managed_runtime") is not True
        or absolute_path(str(payload.get("runtime_root", ""))) != absolute_path(config_root)
        or not isinstance(payload.get("install_id"), str)
        or len(str(payload.get("install_id"))) != 64
    ):
        raise StateSecurityError("managed runtime anchor is invalid")
    return payload, False


def _validated_attested_python(
    expected: object,
    actual_static: object,
) -> None:
    if not isinstance(expected, dict) or not isinstance(actual_static, dict):
        raise StateSecurityError("managed runtime Python attestation is missing")
    digest = expected.get("attestation_sha256")
    unsigned = {key: value for key, value in expected.items() if key != "attestation_sha256"}
    calculated = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    version = expected.get("version")
    if (
        expected.get("schema_version") != 1
        or not isinstance(digest, str)
        or len(digest) != 64
        or digest != calculated
        or not isinstance(version, list)
        or len(version) != 3
        or any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in version)
        or tuple(version) < (3, 10, 0)
        or expected.get("implementation") != "CPython"
        or not runtime_python_static_attestation_matches(expected, actual_static)
    ):
        raise StateSecurityError("managed runtime Python pre-exec identity mismatch")


def _authenticated_existing_runtime_python(config_root: Path, python: Path) -> dict[str, Any]:
    """Pure-read authenticate a completed Runtime before executing its venv.

    A source install deliberately leaves the marker closed at
    ``state_migration_required`` and publish-ready temporarily changes it to
    ``preflight``.  Both phases still carry the source installer's bound
    ``bootstrap_attestation``.  Accepting that exact launcher identity avoids
    repeatedly preserving and recreating the same new empty venv after a later
    preflight failure; an ``installing`` or otherwise unrecognized marker stays
    untrusted and is never executed.
    """

    try:
        manifest_raw = secure_read_bytes_beneath(config_root, Path("config/runtime-manifest.json"))
        marker_raw = secure_read_bytes_beneath(config_root, Path("config/runtime-transition.json"))
        manifest = json.loads(manifest_raw.decode("utf-8"))
        marker = json.loads(marker_raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateSecurityError) as exc:
        raise StateSecurityError("existing managed Python lacks an authenticated ready Runtime") from exc
    anchor_raw: bytes | None = None
    anchor: dict[str, Any] | None = None
    anchor_path = config_root / RUNTIME_ANCHOR_RELATIVE
    if anchor_path.exists() or anchor_path.is_symlink():
        try:
            anchor_raw = secure_read_bytes_beneath(config_root, RUNTIME_ANCHOR_RELATIVE)
            candidate_anchor = json.loads(anchor_raw.decode("utf-8"))
            anchor = candidate_anchor if isinstance(candidate_anchor, dict) else None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateSecurityError) as exc:
            raise StateSecurityError("existing managed Python anchor is unsafe") from exc
    anchor_bound = any(
        key in manifest or key in marker
        for key in ("install_id", "runtime_anchor_sha256")
    )
    groups = ("files", "support_files", "template_files")
    if (
        not isinstance(manifest, dict)
        or not isinstance(marker, dict)
        or manifest.get("schema_version") != 2
        or manifest.get("release_version") != RUNTIME_RELEASE_VERSION
        or manifest.get("runtime_api_version") != 2
        or manifest.get("writer_protocol_version") != 2
        or manifest.get("state_schema_required") != STATE_SCHEMA_VERSION
        or manifest.get("canonical_actors") != ["codex", "claude", "ailu"]
        or manifest.get("capabilities")
        != {"write_gateway": WRITE_GATEWAY_CAPABILITIES}
        or absolute_path(str(manifest.get("runtime_root", ""))) != absolute_path(config_root)
        or marker.get("schema_version") != 1
        or marker.get("phase") not in {"ready", "state_migration_required", "preflight"}
        or any(not isinstance(manifest.get(group), dict) or not manifest[group] for group in groups)
    ):
        raise StateSecurityError("existing managed Python Runtime identity is invalid")
    if anchor_bound:
        if (
            anchor_raw is None
            or not isinstance(anchor, dict)
            or anchor.get("schema_version") != RUNTIME_ANCHOR_SCHEMA_VERSION
            or anchor.get("managed_runtime") is not True
            or absolute_path(str(anchor.get("runtime_root", ""))) != absolute_path(config_root)
            or not isinstance(anchor.get("install_id"), str)
            or len(str(anchor.get("install_id", ""))) != 64
            or manifest.get("install_id") != anchor.get("install_id")
            or marker.get("install_id") != anchor.get("install_id")
            or manifest.get("runtime_anchor_sha256") != hashlib.sha256(anchor_raw).hexdigest()
            or marker.get("runtime_anchor_sha256") != manifest.get("runtime_anchor_sha256")
        ):
            raise StateSecurityError("existing managed Python anchor identity is invalid")
    elif anchor_raw is not None:
        # An unbound anchor is an ambiguous partial installation, never a
        # reason to execute the target launcher.
        raise StateSecurityError("existing managed Python anchor is not bound")
    calculated_bundle = hashlib.sha256(
        json.dumps(
            {group: manifest[group] for group in groups},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if calculated_bundle != manifest.get("bundle_sha256") or marker.get("bundle_sha256") != calculated_bundle:
        raise StateSecurityError("existing Runtime bundle identity is invalid")
    prefixes = {"files": Path("scripts"), "support_files": Path(), "template_files": Path()}
    mode_groups = {
        "files": "file_modes",
        "support_files": "support_file_modes",
        "template_files": "template_file_modes",
    }
    mode_policy_present = any(key in manifest for key in mode_groups.values())
    for group, prefix in prefixes.items():
        expected_modes = manifest.get(mode_groups[group])
        if mode_policy_present and (
            not isinstance(expected_modes, dict)
            or set(expected_modes) != set(manifest[group])
        ):
            raise StateSecurityError("existing Runtime mode inventory is invalid")
        for raw_name, raw_digest in manifest[group].items():
            relative = Path(str(raw_name))
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or not isinstance(raw_digest, str)
                or len(raw_digest) != 64
                or secure_sha256_beneath(config_root, prefix / relative) != raw_digest
            ):
                raise StateSecurityError("existing Runtime bundle file identity mismatch")
            if mode_policy_present and POSIX_PERMISSION_MODEL:
                raw_mode = expected_modes.get(raw_name) if isinstance(expected_modes, dict) else None
                opened = installed_file(config_root, prefix / relative)
                if (
                    not isinstance(raw_mode, str)
                    or not re.fullmatch(r"[0-7]{4}", raw_mode)
                    or opened is None
                    or stat.S_IMODE(opened[1].st_mode) != int(raw_mode, 8)
                ):
                    raise StateSecurityError("existing Runtime bundle mode mismatch")
    preflight = marker.get("preflight_attestation")
    bootstrap = marker.get("bootstrap_attestation")
    preflight_python = (
        preflight.get("runtime_python") if isinstance(preflight, dict) else None
    )
    bootstrap_python = (
        bootstrap.get("runtime_python") if isinstance(bootstrap, dict) else None
    )
    if marker.get("phase") == "ready":
        expected = preflight_python
    else:
        # Prefer the source installer's original attestation. A later ready
        # preflight may normalize an equivalent Homebrew ``opt`` base prefix
        # to its Cellar path, so full-dict equality between the two otherwise
        # valid attestations is not a sound trust boundary.
        expected = bootstrap_python or preflight_python
    actual_static = _python_launcher_identity(absolute_path(config_root), absolute_path(python))
    _validated_attested_python(expected, actual_static)
    return dict(expected)


def _attest_authenticated_runtime_python(
    config_root: Path,
    python: Path,
    expected: dict[str, Any],
) -> dict[str, Any]:
    """Probe only a launcher whose static identity still exactly matches ready v2.

    Authentication and execution are deliberately separate.  Two static
    snapshots must both equal the ready marker's attestation before the first
    target subprocess is started; a replacement or retarget between the old
    bundle check and this call therefore fails without executing the new file.
    The same identity must also survive the isolated version probe.
    """

    root = absolute_path(config_root)
    launcher = absolute_path(python)
    before = _python_launcher_identity(root, launcher)
    _validated_attested_python(expected, before)
    pre_exec = _python_launcher_identity(root, launcher)
    _validated_attested_python(expected, pre_exec)
    if pre_exec != before:
        raise StateSecurityError("managed runtime Python changed before authenticated probe")
    probe_code = (
        "import json,platform,sys; "
        "print(json.dumps({'version':[sys.version_info.major,sys.version_info.minor,sys.version_info.micro],"
        "'implementation':platform.python_implementation(),'executable':sys.executable,'base_prefix':sys.base_prefix},"
        "sort_keys=True,separators=(',',':')))"
    )
    completed = subprocess.run(
        [str(launcher), "-I", "-S", "-c", probe_code],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        raise StateSecurityError("managed runtime Python authenticated probe failed")
    try:
        probe = json.loads(completed.stdout)
        version = tuple(int(item) for item in probe["version"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise StateSecurityError("managed runtime Python authenticated probe was invalid") from exc
    if len(version) != 3 or version < (3, 10, 0):
        raise StateSecurityError("managed runtime Python is older than 3.10")
    after = _python_launcher_identity(root, launcher)
    if after != pre_exec:
        raise StateSecurityError("managed runtime Python changed during authenticated probe")
    payload: dict[str, Any] = {
        "schema_version": 1,
        **after,
        "version": list(version),
        "implementation": str(probe.get("implementation", "")),
        "probe_executable": str(probe.get("executable", "")),
        "base_prefix": str(probe.get("base_prefix", "")),
    }
    payload["attestation_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if not runtime_python_attestation_matches(expected, payload):
        # v2 runtimes installed before isolated probes recorded Homebrew's
        # stable ``opt`` symlink as ``base_prefix``. ``-S`` reports the exact
        # Cellar directory for the same interpreter. Permit this one upgrade
        # normalization only when every other attested field is identical and
        # both directory spellings resolve to the same physical directory.
        expected_without_prefix = {
            key: value
            for key, value in expected.items()
            if key not in {*RUNTIME_PYTHON_STATIC_KEYS, "base_prefix", "attestation_sha256"}
        }
        payload_without_prefix = {
            key: value
            for key, value in payload.items()
            if key not in {*RUNTIME_PYTHON_STATIC_KEYS, "base_prefix", "attestation_sha256"}
        }
        expected_prefix = Path(str(expected.get("base_prefix", "")))
        payload_prefix = Path(str(payload.get("base_prefix", "")))
        try:
            same_prefix = (
                expected_prefix.is_dir()
                and payload_prefix.is_dir()
                and expected_prefix.resolve(strict=True) == payload_prefix.resolve(strict=True)
                and expected_prefix.stat().st_dev == payload_prefix.stat().st_dev
                and expected_prefix.stat().st_ino == payload_prefix.stat().st_ino
            )
        except OSError:
            same_prefix = False
        if (
            not runtime_python_static_attestation_matches(expected, payload)
            or expected_without_prefix != payload_without_prefix
            or not same_prefix
        ):
            raise StateSecurityError("managed runtime Python authenticated identity mismatch")
    return payload


def _recoverably_move_untrusted_venv(
    config_root: Path,
    *,
    transaction: dict[str, Any] | None = None,
) -> Path:
    """Atomically retain, never delete, a legacy/unattestable target venv."""

    venv_root = config_root / ".venv"
    try:
        metadata = venv_root.lstat()
    except FileNotFoundError as exc:
        raise StateSecurityError("managed Python environment disappeared") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise StateSecurityError("existing managed Python environment is unsafe")
    assert_no_symlink_beneath(config_root, venv_root, include_leaf=True)
    backup_root = (
        Path(str(transaction["backup_root"]))
        if transaction is not None
        else config_root / "backups"
    )
    ensure_private_directory(backup_root, harden_existing=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = backup_root / f"untrusted-venv-{stamp}-{os.getpid()}-{uuid.uuid4().hex}"
    if destination.exists() or destination.is_symlink():
        raise StateSecurityError("managed Python recovery destination already exists")
    if transaction is not None:
        _append_runtime_journal(
            transaction,
            {
                "event": "venv_move_intent",
                "source": str(venv_root),
                "destination": str(destination),
            },
        )
    os.replace(venv_root, destination)
    _fsync_directory(backup_root)
    _fsync_directory(config_root)
    if transaction is not None:
        _append_runtime_journal(
            transaction,
            {
                "event": "venv_moved",
                "source": str(venv_root),
                "destination": str(destination),
            },
        )
    return destination


def ensure_managed_python(
    config_root: Path,
    *,
    transaction: dict[str, Any] | None = None,
) -> tuple[Path, dict[str, Any], Path | None]:
    """Provide one runtime-owned Python 3.10+ for scripts and host hooks."""

    if sys.version_info < (3, 10):
        raise RuntimeError("Python 3.10 or newer is required")
    python = managed_python_path(config_root)
    assert_no_symlink_beneath(
        config_root,
        python,
        include_leaf=False,
        allow_missing=True,
    )
    venv_root = config_root / ".venv"
    existed = venv_root.exists() or venv_root.is_symlink()
    recovered_venv: Path | None = None
    expected_identity: dict[str, Any] | None = None
    if existed:
        if not python.exists():
            recovered_venv = _recoverably_move_untrusted_venv(
                config_root,
                transaction=transaction,
            )
        else:
            try:
                expected_identity = _authenticated_existing_runtime_python(config_root, python)
            except (OSError, StateSecurityError):
                # A v1/legacy, interrupted, or otherwise unattestable venv is
                # never executed.  Preserve it under a unique rollback path,
                # then let the already-trusted source interpreter create the
                # fixed replacement.
                recovered_venv = _recoverably_move_untrusted_venv(
                    config_root,
                    transaction=transaction,
                )
    if not existed or recovered_venv is not None:
        ensure_private_directory(config_root / ".venv", harden_existing=True)
        if transaction is not None:
            _write_venv_transaction_marker(
                config_root / ".venv",
                str(transaction["transaction_id"]),
            )
            _append_runtime_journal(
                transaction,
                {
                    "event": "venv_create_started",
                    "path": str(config_root / ".venv"),
                },
            )
        completed = subprocess.run(
            [sys.executable, "-m", "venv", str(config_root / ".venv")],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=180,
            check=False,
        )
        if completed.returncode != 0 or not python.is_file():
            if transaction is not None:
                _append_runtime_journal(
                    transaction,
                    {
                        "event": "venv_create_failed",
                        "path": str(config_root / ".venv"),
                    },
                )
            raise RuntimeError("managed Python virtual environment creation failed")
        if transaction is not None:
            _append_runtime_journal(
                transaction,
                {
                    "event": "venv_created",
                    "path": str(config_root / ".venv"),
                },
            )
    # The attestation validates and pins the launcher chain before executing it,
    # then repeats the identity check after the version probe.
    identity = (
        _attest_authenticated_runtime_python(config_root, python, expected_identity)
        if expected_identity is not None
        else runtime_python_attestation(config_root, python)
    )
    return python, identity, recovered_venv


def semantic_dependency_state(
    python: Path,
    dependency_lock: Path,
    *,
    timeout: int = 60,
) -> dict[str, Any]:
    """Read the exact locked-distribution state from one selected interpreter."""

    if not dependency_lock.is_file() or not python.is_file():
        return {
            "ok": False,
            "python": str(python),
            "lock": str(dependency_lock),
            "returncode": 127,
            "error": "lock_or_python_missing",
            "expected": 0,
            "missing": [],
            "mismatched": [],
            "invalid_lines": [],
            "duplicates": [],
        }
    try:
        completed = subprocess.run(
            [str(python), "-I", "-c", SEMANTIC_DEPENDENCY_CHECK_CODE, str(dependency_lock)],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "python": str(python),
            "lock": str(dependency_lock),
            "returncode": 127,
            "error": type(exc).__name__,
            "expected": 0,
            "missing": [],
            "mismatched": [],
            "invalid_lines": [],
            "duplicates": [],
        }
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    expected = payload.get("expected")
    missing = payload.get("missing")
    mismatched = payload.get("mismatched")
    invalid_lines = payload.get("invalid_lines")
    duplicates = payload.get("duplicates")
    shape_ok = (
        isinstance(expected, int)
        and not isinstance(expected, bool)
        and expected > 0
        and isinstance(missing, list)
        and isinstance(mismatched, list)
        and isinstance(invalid_lines, list)
        and isinstance(duplicates, list)
    )
    return {
        **payload,
        "ok": bool(completed.returncode == 0 and shape_ok),
        "python": str(python),
        "lock": str(dependency_lock),
        "returncode": completed.returncode,
        "error": "" if shape_ok else "invalid_dependency_check_output",
    }


def semantic_runtime_policy(config_root: Path, python: Path) -> dict[str, Any]:
    """Resolve whether this private Runtime must carry semantic dependencies.

    An existing configured semantic interpreter is executable trust input.  A
    Runtime install may only bootstrap the interpreter it just authenticated;
    an older or external semantic venv remains preserved evidence, never a
    dependency source to copy from or execute.
    """

    opened = installed_file(config_root, Path("config/agent-memory.toml"))
    if opened is None:
        return {
            "required": False,
            "enabled": False,
            "semantic_mode": "off",
            "python": str(python),
            "lock": str(config_root / "requirements-vector.lock"),
            "reason": "config_missing",
        }
    try:
        payload = parse_toml_fallback(opened[0].decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise StateSecurityError("runtime config is not valid UTF-8") from exc
    semantic = payload.get("semantic_retrieval")
    semantic = semantic if isinstance(semantic, dict) else {}
    enabled = semantic.get("enabled") is True
    semantic_mode = str(semantic.get("semantic_mode", "auto")).strip().casefold()
    if semantic_mode not in {"auto", "off", "required"}:
        raise StateSecurityError("semantic mode is invalid")
    required = bool(enabled and semantic_mode != "off")
    configured_python = absolute_path(
        expand_path(str(semantic.get("python", str(python))))
    )
    dependency_lock = absolute_path(
        expand_path(
            str(
                semantic.get(
                    "dependency_lock",
                    str(config_root / "requirements-vector.lock"),
                )
            )
        )
    )
    if required and configured_python != absolute_path(python):
        raise StateSecurityError("semantic Python is not the authenticated managed Runtime Python")
    if required and dependency_lock != absolute_path(config_root / "requirements-vector.lock"):
        raise StateSecurityError("semantic dependency lock is outside the managed Runtime")
    return {
        "required": required,
        "enabled": enabled,
        "semantic_mode": semantic_mode,
        "python": str(configured_python),
        "lock": str(dependency_lock),
        "reason": "enabled" if required else "semantic_disabled",
    }


def install_semantic_dependencies(
    config_root: Path,
    python: Path,
    *,
    transaction: dict[str, Any],
) -> dict[str, Any]:
    """Bootstrap the exact semantic lock into the authenticated managed venv."""

    policy = semantic_runtime_policy(config_root, python)
    if not policy["required"]:
        return {**policy, "ok": True, "status": "disabled"}
    dependency_lock = Path(str(policy["lock"]))
    before = semantic_dependency_state(python, dependency_lock)
    if before.get("ok") is True:
        return {
            **policy,
            "ok": True,
            "status": "already_satisfied",
            "expected": int(before.get("expected", 0)),
        }
    _append_runtime_journal(
        transaction,
        {
            "event": "semantic_dependencies_install_started",
            "python": str(python),
            "lock": str(dependency_lock),
            "expected": int(before.get("expected", 0) or 0),
            "missing_count": len(before.get("missing", [])),
            "mismatched_count": len(before.get("mismatched", [])),
        },
    )
    child_env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("PIP_") and key not in {"PYTHONHOME", "PYTHONPATH"}
    }
    child_env.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PIP_REQUIRE_VIRTUALENV": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    try:
        completed = subprocess.run(
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--requirement",
                str(dependency_lock),
            ],
            cwd=config_root,
            env=child_env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=840,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _append_runtime_journal(
            transaction,
            {
                "event": "semantic_dependencies_install_failed",
                "reason_code": type(exc).__name__.upper(),
                "returncode": 127,
            },
        )
        raise RuntimeError("semantic dependency installation failed") from exc
    if completed.returncode != 0:
        _append_runtime_journal(
            transaction,
            {
                "event": "semantic_dependencies_install_failed",
                "reason_code": "PIP_INSTALL_FAILED",
                "returncode": completed.returncode,
            },
        )
        raise RuntimeError("semantic dependency installation failed")
    after = semantic_dependency_state(python, dependency_lock)
    if after.get("ok") is not True:
        _append_runtime_journal(
            transaction,
            {
                "event": "semantic_dependencies_install_failed",
                "reason_code": "DEPENDENCY_LOCK_VERIFY_FAILED",
                "returncode": int(after.get("returncode", 2) or 2),
            },
        )
        raise RuntimeError("semantic dependency lock verification failed")
    _append_runtime_journal(
        transaction,
        {
            "event": "semantic_dependencies_install_completed",
            "python": str(python),
            "lock": str(dependency_lock),
            "expected": int(after.get("expected", 0)),
        },
    )
    return {
        **policy,
        "ok": True,
        "status": "installed",
        "expected": int(after.get("expected", 0)),
    }


def template_inventory() -> tuple[dict[str, str], dict[str, str]]:
    hashes: dict[str, str] = {}
    modes: dict[str, str] = {}
    for path in sorted(TEMPLATE_ROOT.rglob("*")):
        if path.is_symlink():
            raise StateSecurityError(f"template source must not contain symlinks: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(REPO_ROOT)
        content, metadata = secure_read_bytes_and_stat_beneath(REPO_ROOT, relative)
        if POSIX_PERMISSION_MODEL and stat.S_IMODE(metadata.st_mode) & 0o022:
            raise StateSecurityError("runtime source is group/world writable")
        hashes[relative.as_posix()] = hashlib.sha256(content).hexdigest()
        modes[relative.as_posix()] = f"{stat.S_IMODE(metadata.st_mode):04o}"
    return hashes, modes


def git_value(*args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=15,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else ""


def expected_manifest(config_root: Path, anchor: dict[str, Any] | None = None) -> dict[str, Any]:
    anchor = anchor or _runtime_anchor_payload(config_root, "0" * 64)
    hashes: dict[str, str] = {}
    file_modes: dict[str, str] = {}
    for name in CORE_FILES:
        content, metadata = secure_read_bytes_and_stat_beneath(
            REPO_ROOT,
            Path("scripts") / name,
        )
        if POSIX_PERMISSION_MODEL and stat.S_IMODE(metadata.st_mode) & 0o022:
            raise StateSecurityError("runtime source is group/world writable")
        hashes[name] = hashlib.sha256(content).hexdigest()
        file_modes[name] = f"{stat.S_IMODE(metadata.st_mode):04o}"
    support_hashes: dict[str, str] = {}
    support_modes: dict[str, str] = {}
    support_source_modes: dict[str, str] = {}
    for name in SUPPORT_FILES:
        content, metadata = secure_read_bytes_and_stat_beneath(REPO_ROOT, Path(name))
        if POSIX_PERMISSION_MODEL and stat.S_IMODE(metadata.st_mode) & 0o022:
            raise StateSecurityError("runtime source is group/world writable")
        support_hashes[name] = hashlib.sha256(content).hexdigest()
        support_source_modes[name] = f"{stat.S_IMODE(metadata.st_mode):04o}"
        support_modes[name] = f"{PRIVATE_FILE_MODE:04o}"
    installed_templates, template_modes = template_inventory()
    return {
        "schema_version": 2,
        "release_version": RUNTIME_RELEASE_VERSION,
        "runtime_api_version": 2,
        "state_schema_required": STATE_SCHEMA_VERSION,
        "writer_protocol_version": 2,
        "canonical_actors": ["codex", "claude", "ailu"],
        "capabilities": {"write_gateway": WRITE_GATEWAY_CAPABILITIES},
        "installed_at": utc_now(),
        "source_repo": str(REPO_ROOT),
        "source_commit": git_value("rev-parse", "HEAD") or "archive",
        "source_dirty": bool(git_value("status", "--porcelain")),
        "runtime_root": str(config_root),
        "install_id": str(anchor["install_id"]),
        "runtime_anchor_sha256": _runtime_anchor_sha256(anchor),
        "files": hashes,
        "file_modes": file_modes,
        "support_files": support_hashes,
        "support_file_modes": support_modes,
        "support_source_modes": support_source_modes,
        "template_files": installed_templates,
        "template_file_modes": template_modes,
        "bundle_sha256": hashlib.sha256(
            json.dumps(
                {
                    "files": hashes,
                    "support_files": support_hashes,
                    "template_files": installed_templates,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }


def _runtime_transaction_publish_bytes(
    transaction: dict[str, Any],
    relative: Path,
    content: bytes,
    *,
    mode: int,
    expected_before_sha256: str | None = None,
    expected_before_existed: bool | None = None,
) -> None:
    """Publish one target with byte CAS and append-only intent evidence."""

    config_root = Path(str(transaction["config_root"]))
    if relative.is_absolute() or ".." in relative.parts:
        raise StateSecurityError("runtime transaction target is unsafe")
    target = config_root / relative
    assert_no_symlink_beneath(
        config_root,
        target,
        include_leaf=False,
        allow_missing=True,
    )
    ensure_private_directory(target.parent, harden_existing=False)
    opened = installed_file(config_root, relative)
    before = opened[0] if opened is not None else b""
    before_existed = opened is not None
    before_sha256 = hashlib.sha256(before).hexdigest()
    if expected_before_sha256 is None or expected_before_existed is None:
        last_targets = transaction.setdefault("_target_last", {})
        baselines = transaction.get("_target_baseline")
        if not isinstance(last_targets, dict) or not isinstance(baselines, dict):
            raise StateSecurityError("runtime transaction baseline is missing")
        expected = last_targets.get(relative.as_posix(), baselines.get(relative.as_posix()))
        if not isinstance(expected, dict):
            raise StateSecurityError("runtime transaction target is outside baseline")
        expected_before_existed = bool(expected.get("existed"))
        expected_before_sha256 = str(expected.get("sha256", ""))
    if (
        before_existed != expected_before_existed
        or before_sha256 != expected_before_sha256
    ):
        raise StateSecurityError(
            f"runtime target changed since backup: {relative.as_posix()}"
        )
    intent_id = uuid.uuid4().hex
    after_sha256 = hashlib.sha256(content).hexdigest()
    _append_runtime_journal(
        transaction,
        {
            "event": "target_intent",
            "intent_id": intent_id,
            "path": relative.as_posix(),
            "before_existed": before_existed,
            "before_sha256": before_sha256,
            "after_sha256": after_sha256,
            "mode": f"{mode:04o}",
        },
    )
    operation_id = hashlib.sha256(
        (
            str(transaction["transaction_id"])
            + "\0"
            + intent_id
            + "\0"
            + relative.as_posix()
        ).encode("utf-8")
    ).hexdigest()
    try:
        if before_existed:
            secure_conditional_write_bytes_beneath(
                config_root,
                relative,
                content,
                expected_sha256=before_sha256,
                expected_size=len(before),
                operation_id=operation_id,
                namespace="runtime",
                max_capture_bytes=max(len(before), len(content), 64 * 1024 * 1024),
                mode=mode,
            )
        else:
            secure_conditional_create_bytes_beneath(
                config_root,
                relative,
                content,
                operation_id=operation_id,
                namespace="runtime",
                max_capture_bytes=max(len(content), 64 * 1024 * 1024),
                mode=mode,
            )
    except ConditionalWriteError as exc:
        if exc.reason_code == "CONDITIONAL_WRITE_TARGET_CHANGED":
            raise StateSecurityError(
                f"runtime target changed before replace: {relative.as_posix()}"
            ) from exc
        raise StateSecurityError(
            f"runtime target conditional write requires recovery: {relative.as_posix()}"
        ) from exc
    _fsync_directory(target.parent)
    published = installed_file(config_root, relative)
    if (
        published is None
        or hashlib.sha256(published[0]).hexdigest() != after_sha256
        or (
            POSIX_PERMISSION_MODEL
            and stat.S_IMODE(published[1].st_mode) != mode
        )
    ):
        raise StateSecurityError(
            f"runtime target changed during replace: {relative.as_posix()}"
        )
    _append_runtime_journal(
        transaction,
        {
            "event": "target_applied",
            "intent_id": intent_id,
            "path": relative.as_posix(),
            "after_sha256": after_sha256,
        },
    )
    last_targets = transaction.setdefault("_target_last", {})
    if not isinstance(last_targets, dict):
        raise StateSecurityError("runtime transaction target state is invalid")
    last_targets[relative.as_posix()] = {
        "existed": True,
        "sha256": after_sha256,
    }


def atomic_copy(
    source: Path,
    target: Path,
    *,
    runtime_root: Path,
    transaction: dict[str, Any] | None = None,
    expected_sha256: str | None = None,
    expected_mode: int | None = None,
    target_mode: int | None = None,
) -> None:
    """Publish one runtime file through a pinned, symlink-free directory chain."""

    assert_no_symlink_beneath(REPO_ROOT, source, include_leaf=True)
    relative = relative_beneath(runtime_root, target)
    content, metadata = secure_read_bytes_and_stat_beneath(
        REPO_ROOT,
        relative_beneath(REPO_ROOT, source),
    )
    captured_sha256 = hashlib.sha256(content).hexdigest()
    captured_mode = stat.S_IMODE(metadata.st_mode)
    if (
        expected_sha256 is not None and captured_sha256 != expected_sha256
    ) or (
        expected_mode is not None and captured_mode != expected_mode
    ):
        raise StateSecurityError("runtime source changed after manifest capture")
    publish_mode = captured_mode if target_mode is None else target_mode
    if transaction is None:
        secure_atomic_write_bytes_beneath(
            runtime_root,
            relative,
            content,
            mode=publish_mode,
        )
        return
    _runtime_transaction_publish_bytes(
        transaction,
        relative,
        content,
        mode=publish_mode,
    )


def atomic_write_json(
    target: Path,
    payload: dict[str, Any],
    *,
    runtime_root: Path,
    transaction: dict[str, Any] | None = None,
) -> None:
    encoded = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    relative = relative_beneath(runtime_root, target)
    if transaction is not None:
        _runtime_transaction_publish_bytes(
            transaction,
            relative,
            encoded,
            mode=PRIVATE_FILE_MODE,
        )
        return
    secure_atomic_write_bytes_beneath(
        runtime_root,
        relative,
        encoded,
        mode=PRIVATE_FILE_MODE,
    )


def installed_file(config_root: Path, relative: Path) -> tuple[bytes, os.stat_result] | None:
    target = config_root / relative
    assert_no_symlink_beneath(
        config_root,
        target,
        include_leaf=False,
        allow_missing=True,
    )
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise StateSecurityError(f"runtime target must be a regular non-symlink file: {target}")
    return secure_read_bytes_and_stat_beneath(config_root, relative)


def installed_sha256(config_root: Path, relative: Path) -> str | None:
    opened = installed_file(config_root, relative)
    return hashlib.sha256(opened[0]).hexdigest() if opened is not None else None


def installed_mode(config_root: Path, relative: Path) -> int | None:
    opened = installed_file(config_root, relative)
    return stat.S_IMODE(opened[1].st_mode) if opened is not None else None


def validate_runtime_layout(
    config_root: Path,
    manifest: dict[str, Any],
    *,
    allow_missing: bool,
) -> None:
    paths = [
        *(Path("scripts") / str(name) for name in manifest.get("files", {})),
        *(Path(str(name)) for name in manifest.get("support_files", {})),
        *(Path(str(name)) for name in manifest.get("template_files", {})),
        Path("config/runtime-manifest.json"),
        Path("config/runtime-transition.json"),
        RUNTIME_ANCHOR_RELATIVE,
    ]
    for relative in paths:
        if relative.is_absolute() or ".." in relative.parts:
            raise StateSecurityError(f"unsafe runtime manifest path: {relative}")
        assert_no_symlink_beneath(
            config_root,
            config_root / relative,
            include_leaf=True,
            allow_missing=allow_missing,
        )
    # The private TOML may legitimately be absent while a source-only runtime
    # is first installed, but any existing lexical component must be contained.
    assert_no_symlink_beneath(
        config_root,
        config_root / "config" / "agent-memory.toml",
        include_leaf=True,
        allow_missing=True,
    )


def _manifest_mode(manifest: dict[str, Any], group: str, name: str) -> int:
    modes = manifest.get(group)
    raw = modes.get(name) if isinstance(modes, dict) else None
    if not isinstance(raw, str) or not re.fullmatch(r"[0-7]{4}", raw):
        raise StateSecurityError("runtime manifest mode inventory is invalid")
    return int(raw, 8)


def attest_installed_runtime_bundle(
    config_root: Path,
    manifest: dict[str, Any],
    *,
    transition_phase: str,
    runtime_python_identity: dict[str, Any],
) -> None:
    """Re-read every terminal byte and mode before committing the journal."""

    validate_runtime_layout(config_root, manifest, allow_missing=False)
    groups = (
        ("files", "file_modes", Path("scripts")),
        ("support_files", "support_file_modes", Path()),
        ("template_files", "template_file_modes", Path()),
    )
    for digest_group, mode_group, prefix in groups:
        digests = manifest.get(digest_group)
        modes = manifest.get(mode_group)
        if (
            not isinstance(digests, dict)
            or not digests
            or not isinstance(modes, dict)
            or set(modes) != set(digests)
        ):
            raise StateSecurityError("runtime manifest inventory is invalid")
        for raw_name, raw_digest in digests.items():
            name = str(raw_name)
            relative = prefix / Path(name)
            opened = installed_file(config_root, relative)
            expected_mode = _manifest_mode(manifest, mode_group, name)
            if (
                opened is None
                or not isinstance(raw_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", raw_digest)
                or hashlib.sha256(opened[0]).hexdigest() != raw_digest
                or (
                    POSIX_PERMISSION_MODEL
                    and stat.S_IMODE(opened[1].st_mode) != expected_mode
                )
            ):
                raise StateSecurityError(
                    f"installed Runtime bundle attestation failed: {relative.as_posix()}"
                )
    expected_manifest = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if secure_read_bytes_beneath(config_root, Path("config/runtime-manifest.json")) != expected_manifest:
        raise StateSecurityError("installed Runtime manifest attestation failed")
    if secure_sha256_beneath(config_root, RUNTIME_ANCHOR_RELATIVE) != manifest.get(
        "runtime_anchor_sha256"
    ):
        raise StateSecurityError("installed Runtime anchor attestation failed")
    try:
        marker = json.loads(
            secure_read_bytes_beneath(
                config_root,
                Path("config/runtime-transition.json"),
            ).decode("utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateSecurityError("installed Runtime transition attestation failed") from exc
    bootstrap = marker.get("bootstrap_attestation") if isinstance(marker, dict) else None
    if (
        not isinstance(marker, dict)
        or marker.get("schema_version") != 1
        or marker.get("phase") != transition_phase
        or marker.get("bundle_sha256") != manifest.get("bundle_sha256")
        or marker.get("install_id") != manifest.get("install_id")
        or marker.get("runtime_anchor_sha256") != manifest.get("runtime_anchor_sha256")
        or not isinstance(bootstrap, dict)
        or bootstrap.get("schema_version") != 1
        or bootstrap.get("runtime_python") != runtime_python_identity
    ):
        raise StateSecurityError("installed Runtime transition attestation failed")


def transition_marker(
    *,
    phase: str,
    bundle_sha256: str,
    install_id: str,
    runtime_anchor_sha256: str,
    runtime_python: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "phase": phase,
        "bundle_sha256": bundle_sha256,
        "install_id": install_id,
        "runtime_anchor_sha256": runtime_anchor_sha256,
        "updated_at": utc_now(),
    }
    if runtime_python is not None:
        payload["bootstrap_attestation"] = {
            "schema_version": 1,
            "runtime_python": runtime_python,
        }
    return payload


def configured_state_db(config_root: Path) -> Path:
    try:
        raw = secure_read_bytes_beneath(config_root, Path("config/agent-memory.toml"))
        payload = parse_toml_fallback(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, StateSecurityError):
        payload = {}
    configured = payload.get("state_db") if isinstance(payload, dict) else None
    if isinstance(configured, str) and configured.strip():
        return absolute_path(expand_path(configured.strip()))
    return config_root / "state.sqlite"


def state_schema_ready(path: Path) -> bool:
    """Verify the durable state protocol instead of trusting only a marker."""

    if not path.is_file() or path.is_symlink():
        return False
    try:
        with contextlib.closing(
            secure_sqlite_connect(
                path,
                create=False,
                read_only=True,
                repair_permissions=False,
            )
        ) as conn:
            tables = {
                str(row[0])
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if not {
                "meta",
                "memory_path_fences",
                "memory_session_claims",
                "memory_write_intents",
                "memory_write_receipts",
                "memory_file_observations",
                "memory_closeout_incidents",
            }.issubset(tables):
                return False
            incident_columns = {
                str(row[1])
                for row in conn.execute("PRAGMA table_info(memory_closeout_incidents)")
            }
            if not {
                "intent_id",
                "target_key",
                "reason_code",
                "resolved_at",
                "resolution_intent_id",
                "resolution_git_commit",
            }.issubset(incident_columns):
                return False
            meta = {
                str(row[0]): str(row[1])
                for row in conn.execute(
                    "SELECT key, value FROM meta WHERE key IN (?, ?)",
                    (
                        "agent_memory_state_schema_version",
                        "agent_memory_writer_protocol_version",
                    ),
                )
            }
            return (
                meta.get("agent_memory_state_schema_version") == str(STATE_SCHEMA_VERSION)
                and meta.get("agent_memory_writer_protocol_version") == "2"
                and str(conn.execute("PRAGMA quick_check").fetchone()[0]) == "ok"
            )
    except (OSError, sqlite3.Error, StateSecurityError):
        return False


def backup_runtime(config_root: Path, manifest: dict[str, Any]) -> Path:
    """Create a private, copy-only rollback snapshot before publishing files."""

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_parent = config_root / "backups"
    ensure_private_directory(backup_parent, harden_existing=True)
    backup_root = backup_parent / (
        f"runtime-tx-{stamp}-{str(manifest['bundle_sha256'])[:12]}-{uuid.uuid4().hex}"
    )
    # Backups are append-only rollback evidence.  A timestamp collision or a
    # pre-created path must fail closed instead of reusing and overwriting an
    # earlier snapshot.
    try:
        os.mkdir(backup_root, PRIVATE_DIRECTORY_MODE)
    except FileExistsError as exc:
        raise StateSecurityError(f"runtime backup already exists: {backup_root}") from exc
    if POSIX_PERMISSION_MODEL:
        os.chmod(backup_root, PRIVATE_DIRECTORY_MODE, follow_symlinks=False)
    captured: list[dict[str, Any]] = []
    relative_targets = [
        *(Path("scripts") / name for name in CORE_FILES),
        *(Path(name) for name in SUPPORT_FILES),
        *(Path(name) for name in manifest["template_files"]),
        Path("config/runtime-manifest.json"),
        Path("config/runtime-transition.json"),
        RUNTIME_ANCHOR_RELATIVE,
    ]
    for relative in relative_targets:
        opened = installed_file(config_root, relative)
        if opened is None:
            continue
        content, source_metadata = opened
        target = secure_atomic_write_bytes_beneath(
            backup_root,
            relative,
            content,
            mode=PRIVATE_FILE_MODE,
        )
        captured.append(
            {
                "path": relative.as_posix(),
                "sha256": secure_sha256_beneath(backup_root, relative),
                "mode": f"{stat.S_IMODE(source_metadata.st_mode):04o}",
            }
        )
    atomic_write_json(
        backup_root / "snapshot.json",
        {
            "schema_version": 1,
            "created_at": utc_now(),
            "source_runtime": str(config_root),
            "target_bundle_sha256": manifest["bundle_sha256"],
            "files": captured,
        },
        runtime_root=backup_root,
    )
    for path in backup_root.rglob("*"):
        if path.is_symlink():
            raise StateSecurityError(f"runtime backup must not contain symlinks: {path}")
        if POSIX_PERMISSION_MODEL:
            path.chmod(PRIVATE_DIRECTORY_MODE if path.is_dir() else PRIVATE_FILE_MODE)
    return backup_root


def _managed_transaction_targets(manifest: dict[str, Any]) -> list[str]:
    return sorted({
        *(f"scripts/{name}" for name in CORE_FILES),
        *(str(name) for name in SUPPORT_FILES),
        *(str(name) for name in manifest.get("template_files", {})),
        "config/runtime-manifest.json",
        "config/runtime-transition.json",
        RUNTIME_ANCHOR_RELATIVE.as_posix(),
    })


def begin_runtime_transaction(
    config_root: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Create a durable, non-overwriting snapshot before any Runtime mutation."""

    backup_root = backup_runtime(config_root, manifest)
    managed_targets = _managed_transaction_targets(manifest)
    snapshot = _snapshot_map(backup_root)
    transaction = {
        "schema_version": RUNTIME_TRANSACTION_SCHEMA_VERSION,
        "transaction_id": uuid.uuid4().hex,
        "config_root": str(config_root),
        "backup_root": str(backup_root),
        "journal_path": str(backup_root / RUNTIME_TRANSACTION_JOURNAL),
        # Private in-process CAS state.  The durable journal stores the same
        # managed inventory and the snapshot stores every original byte.
        "_target_baseline": {
            path: {
                "existed": path in snapshot,
                "sha256": (
                    str(snapshot[path]["sha256"])
                    if path in snapshot
                    else hashlib.sha256(b"").hexdigest()
                ),
            }
            for path in managed_targets
        },
        "_target_last": {},
    }
    venv_root = config_root / ".venv"
    _append_runtime_journal(
        transaction,
        {
            "schema_version": RUNTIME_TRANSACTION_SCHEMA_VERSION,
            "event": "prepared",
            "config_root": str(config_root),
            "backup_root": str(backup_root),
            "target_bundle_sha256": str(manifest["bundle_sha256"]),
            "manifest_sha256": hashlib.sha256(
                (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
            ).hexdigest(),
            "managed_targets": managed_targets,
            "venv_before_existed": bool(venv_root.exists() or venv_root.is_symlink()),
        },
        create=True,
    )
    return transaction


def _validate_runtime_transaction_paths(
    transaction: dict[str, Any],
    *,
    expected_config_root: Path | None = None,
) -> tuple[Path, Path, Path]:
    config_root = absolute_path(str(transaction.get("config_root", "")))
    backup_root = absolute_path(str(transaction.get("backup_root", "")))
    journal_path = absolute_path(str(transaction.get("journal_path", "")))
    if expected_config_root is not None and config_root != absolute_path(expected_config_root):
        raise StateSecurityError("runtime transaction belongs to another runtime root")
    backup_parent = config_root / "backups"
    if (
        backup_root.parent != backup_parent
        or not backup_root.name.startswith("runtime-")
        or journal_path != backup_root / RUNTIME_TRANSACTION_JOURNAL
    ):
        raise StateSecurityError("runtime transaction path boundary is invalid")
    assert_no_symlink_beneath(config_root, backup_root, include_leaf=True)
    assert_no_symlink_beneath(backup_root, journal_path, include_leaf=True)
    return config_root, backup_root, journal_path


def _transaction_from_journal(
    path: Path,
    *,
    expected_config_root: Path | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if expected_config_root is not None:
        expected_root = absolute_path(expected_config_root)
        relative_beneath(expected_root / "backups", path)
        assert_no_symlink_beneath(expected_root, path, include_leaf=True)
    rows = _read_runtime_journal(path)
    prepared_rows = [row for row in rows if row.get("event") == "prepared"]
    if (
        len(prepared_rows) != 1
        or prepared_rows[0].get("schema_version") != RUNTIME_TRANSACTION_SCHEMA_VERSION
    ):
        raise StateSecurityError("runtime transaction prepared record is missing")
    prepared = prepared_rows[0]
    transaction_id = prepared.get("transaction_id")
    managed_targets = prepared.get("managed_targets")
    if (
        not isinstance(transaction_id, str)
        or not re.fullmatch(r"[0-9a-f]{32}", transaction_id)
        or not isinstance(prepared.get("config_root"), str)
        or not str(prepared.get("config_root", ""))
        or not isinstance(prepared.get("backup_root"), str)
        or not str(prepared.get("backup_root", ""))
        or not isinstance(prepared.get("target_bundle_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", str(prepared.get("target_bundle_sha256", "")))
        or not isinstance(prepared.get("manifest_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", str(prepared.get("manifest_sha256", "")))
        or not isinstance(prepared.get("venv_before_existed"), bool)
        or not isinstance(managed_targets, list)
        or not managed_targets
        or any(
            not isinstance(raw, str)
            or not raw
            or Path(raw).is_absolute()
            or ".." in Path(raw).parts
            for raw in managed_targets
        )
        or len(set(managed_targets)) != len(managed_targets)
    ):
        raise StateSecurityError("runtime transaction prepared record is invalid")
    _runtime_transaction_status(rows)
    transaction = {
        "schema_version": RUNTIME_TRANSACTION_SCHEMA_VERSION,
        "transaction_id": transaction_id,
        "config_root": str(prepared.get("config_root", "")),
        "backup_root": str(prepared.get("backup_root", "")),
        "journal_path": str(path),
    }
    _validate_runtime_transaction_paths(
        transaction,
        expected_config_root=expected_config_root,
    )
    return transaction, rows


def _snapshot_map(backup_root: Path) -> dict[str, dict[str, Any]]:
    snapshot_path = backup_root / "snapshot.json"
    try:
        assert_no_symlink_beneath(
            backup_root,
            snapshot_path,
            include_leaf=True,
        )
    except StateSecurityError as exc:
        raise StateSecurityError("runtime transaction snapshot is unsafe") from exc
    try:
        payload = json.loads(
            secure_read_bytes_beneath(backup_root, Path("snapshot.json")).decode("utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateSecurityError("runtime transaction snapshot is invalid") from exc
    files = payload.get("files") if isinstance(payload, dict) else None
    expected_runtime = backup_root.parent.parent
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or absolute_path(str(payload.get("source_runtime", "")))
        != absolute_path(expected_runtime)
        or not isinstance(files, list)
    ):
        raise StateSecurityError("runtime transaction snapshot is invalid")
    result: dict[str, dict[str, Any]] = {}
    for row in files:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("path"), str)
            or not isinstance(row.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", "")))
            or not isinstance(row.get("mode"), str)
            or not re.fullmatch(r"[0-7]{4}", str(row.get("mode", "")))
        ):
            raise StateSecurityError("runtime transaction snapshot is invalid")
        relative = Path(row["path"])
        if relative.is_absolute() or ".." in relative.parts or row["path"] in result:
            raise StateSecurityError("runtime transaction snapshot path is invalid")
        if secure_sha256_beneath(backup_root, relative) != row.get("sha256"):
            raise StateSecurityError("runtime transaction snapshot hash mismatch")
        result[row["path"]] = row
    return result


def _preserve_transaction_created_target(
    transaction: dict[str, Any],
    relative: Path,
    expected_sha256: str,
) -> Path:
    config_root = Path(str(transaction["config_root"]))
    backup_root = Path(str(transaction["backup_root"]))
    destination = backup_root / "recovered-created" / relative
    ensure_private_directory(destination.parent, harden_existing=False)
    current = installed_file(config_root, relative)
    if current is None:
        raise StateSecurityError("runtime rollback CAS mismatch")
    try:
        return secure_conditional_move_bytes_beneath(
            config_root,
            relative,
            backup_root,
            destination.relative_to(backup_root),
            expected_sha256=expected_sha256,
            expected_size=len(current[0]),
            max_capture_bytes=max(len(current[0]), 64 * 1024 * 1024),
        )
    except ConditionalWriteError as exc:
        raise StateSecurityError(
            "runtime rollback CAS mismatch"
            if exc.reason_code == "CONDITIONAL_WRITE_TARGET_CHANGED"
            else "runtime rollback preservation requires recovery"
        ) from exc


def _validate_transaction_venv_rollback(
    transaction: dict[str, Any],
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    config_root = Path(str(transaction["config_root"]))
    backup_root = Path(str(transaction["backup_root"]))
    transaction_id = str(transaction["transaction_id"])
    venv_root = config_root / ".venv"
    prepared = next((row for row in rows if row.get("event") == "prepared"), None)
    if not isinstance(prepared, dict) or not isinstance(
        prepared.get("venv_before_existed"), bool
    ):
        raise StateSecurityError("runtime venv transaction state is invalid")
    before_existed = bool(prepared["venv_before_existed"])

    moves = [
        row
        for row in rows
        if row.get("event") in {"venv_moved", "venv_move_intent"}
    ]
    move_sources = {
        str(row.get("source", ""))
        for row in moves
        if isinstance(row.get("source"), str)
    }
    move_destinations = {
        str(row.get("destination", ""))
        for row in moves
        if isinstance(row.get("destination"), str)
    }
    if moves and (
        move_sources != {str(venv_root)}
        or len(move_destinations) != 1
        or not before_existed
    ):
        raise StateSecurityError("runtime venv transaction path is invalid")
    old_venv = (
        Path(os.path.abspath(next(iter(move_destinations))))
        if move_destinations
        else None
    )
    if old_venv is not None and (
        old_venv.parent != backup_root
        or not old_venv.name.startswith("untrusted-venv-")
    ):
        raise StateSecurityError("runtime venv backup path is invalid")
    old_is_moved = bool(old_venv and (old_venv.exists() or old_venv.is_symlink()))
    if old_is_moved:
        assert old_venv is not None
        if old_venv.is_symlink() or not old_venv.is_dir():
            raise StateSecurityError("runtime venv backup is unsafe")
        assert_no_symlink_beneath(backup_root, old_venv, include_leaf=True)

    current_exists = venv_root.exists() or venv_root.is_symlink()
    if current_exists:
        metadata = venv_root.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise StateSecurityError("runtime venv rollback CAS mismatch")
        assert_no_symlink_beneath(config_root, venv_root, include_leaf=True)
    created_by_transaction = (
        current_exists and _venv_transaction_marker(venv_root) == transaction_id
    )
    create_started = any(row.get("event") == "venv_create_started" for row in rows)
    if old_is_moved and current_exists and not created_by_transaction:
        raise StateSecurityError("runtime venv rollback CAS mismatch")
    if before_existed and moves and not old_is_moved and (
        not current_exists or created_by_transaction
    ):
        # The original existed, but is at neither its source nor its bound
        # recovery destination. Never declare rollback complete in that state.
        raise StateSecurityError("runtime venv backup disappeared")
    if not before_existed and create_started and current_exists and not created_by_transaction:
        raise StateSecurityError("runtime venv rollback ownership mismatch")
    return {
        "old_venv": old_venv,
        "old_is_moved": old_is_moved,
        "current_exists": current_exists,
        "created_by_transaction": created_by_transaction,
    }


def _rollback_transaction_venv(
    transaction: dict[str, Any],
    rows: list[dict[str, Any]],
) -> str:
    config_root = Path(str(transaction["config_root"]))
    backup_root = Path(str(transaction["backup_root"]))
    venv_root = config_root / ".venv"
    state = _validate_transaction_venv_rollback(transaction, rows)
    old_venv = state["old_venv"]
    old_is_moved = bool(state["old_is_moved"])
    current_exists = bool(state["current_exists"])
    created_by_transaction = bool(state["created_by_transaction"])
    preserved = ""
    if created_by_transaction:
        destination = backup_root / f"recovered-venv-{uuid.uuid4().hex}"
        if destination.exists() or destination.is_symlink():
            raise StateSecurityError("runtime venv recovery target exists")
        os.replace(venv_root, destination)
        _fsync_directory(config_root)
        _fsync_directory(backup_root)
        preserved = str(destination)
        current_exists = False
    if old_is_moved:
        if current_exists:
            raise StateSecurityError("runtime venv rollback CAS mismatch")
        if old_venv is None or old_venv.is_symlink() or not old_venv.is_dir():
            raise StateSecurityError("runtime venv backup is unsafe")
        os.replace(old_venv, venv_root)
        _fsync_directory(config_root)
        _fsync_directory(backup_root)
    elif any(row.get("event") == "venv_create_started" for row in rows) and current_exists:
        # A created venv must carry the transaction marker. Anything else is
        # concurrent drift and cannot be moved automatically.
        raise StateSecurityError("runtime venv rollback ownership mismatch")
    return preserved


def rollback_runtime_transaction(
    transaction: dict[str, Any],
    rows: list[dict[str, Any]] | None = None,
    *,
    reason_code: str,
) -> dict[str, Any]:
    config_root, backup_root, journal_path = _validate_runtime_transaction_paths(
        transaction
    )
    if rows is None:
        rows = _read_runtime_journal(journal_path)
    prepared = next((row for row in rows if row.get("event") == "prepared"), None)
    if not isinstance(prepared, dict):
        raise StateSecurityError("runtime transaction prepared record is missing")
    if absolute_path(str(prepared.get("config_root", ""))) != absolute_path(config_root):
        raise StateSecurityError("runtime transaction root mismatch")
    snapshot = _snapshot_map(backup_root)
    intents: dict[str, set[str]] = {}
    for row in rows:
        if row.get("event") != "target_intent" or not isinstance(row.get("path"), str):
            continue
        digest = str(row.get("after_sha256", ""))
        if len(digest) != 64:
            raise StateSecurityError("runtime transaction intent is invalid")
        intents.setdefault(row["path"], set()).add(digest)
    managed_targets = prepared.get("managed_targets")
    if (
        not isinstance(managed_targets, list)
        or not all(isinstance(item, str) for item in managed_targets)
        or len(managed_targets) != len(set(managed_targets))
    ):
        raise StateSecurityError("runtime transaction target inventory is invalid")
    # Validate every deterministic rollback precondition before changing even
    # one target. A late CAS mismatch must not leave an earlier target already
    # restored and turn an otherwise recoverable failure into a partial
    # rollback. Each publication still repeats its own CAS for concurrent drift.
    rollback_targets: list[dict[str, Any]] = []
    for raw_relative in managed_targets:
        relative = Path(raw_relative)
        if relative.is_absolute() or ".." in relative.parts:
            raise StateSecurityError("runtime transaction target is invalid")
        current = installed_file(config_root, relative)
        current_sha = hashlib.sha256(current[0]).hexdigest() if current is not None else ""
        original = snapshot.get(raw_relative)
        original_sha = str(original.get("sha256", "")) if original else ""
        allowed = set(intents.get(raw_relative, set()))
        if original_sha:
            allowed.add(original_sha)
        if current is None:
            if original is not None:
                raise StateSecurityError("runtime rollback target disappeared")
            continue
        if current_sha not in allowed:
            raise StateSecurityError("runtime rollback CAS mismatch")
        rollback_targets.append({
            "raw_relative": raw_relative,
            "relative": relative,
            "current": current,
            "current_sha": current_sha,
            "original": original,
            "original_sha": original_sha,
        })
    _validate_transaction_venv_rollback(transaction, rows)

    preserved_created: list[str] = []
    for target_state in rollback_targets:
        raw_relative = str(target_state["raw_relative"])
        relative = target_state["relative"]
        current = target_state["current"]
        current_sha = str(target_state["current_sha"])
        original = target_state["original"]
        original_sha = str(target_state["original_sha"])
        if current is None:
            continue
        if original is None:
            preserved_created.append(
                str(_preserve_transaction_created_target(transaction, relative, current_sha))
            )
            continue
        if current_sha != original_sha:
            original_bytes = secure_read_bytes_beneath(backup_root, relative)
            _runtime_transaction_publish_bytes(
                transaction,
                relative,
                original_bytes,
                mode=int(str(original.get("mode", "0600")), 8),
                expected_before_sha256=current_sha,
                expected_before_existed=True,
            )
        elif (
            POSIX_PERMISSION_MODEL
            and stat.S_IMODE(current[1].st_mode)
            != int(str(original.get("mode", "0600")), 8)
        ):
            _runtime_transaction_publish_bytes(
                transaction,
                relative,
                current[0],
                mode=int(str(original.get("mode", "0600")), 8),
                expected_before_sha256=current_sha,
                expected_before_existed=True,
            )
    preserved_venv = _rollback_transaction_venv(transaction, rows)
    result = {
        "event": "rolled_back",
        "reason_code": reason_code,
        "backup_root": str(backup_root),
        "preserved_created": preserved_created,
        "recovered_venv": preserved_venv,
    }
    _append_runtime_journal(transaction, result)
    return result


def _runtime_transaction_backup_roots(backup_parent: Path) -> list[Path]:
    """Return current transaction roots plus journal-bearing older roots.

    Historical pre-journal backups also used ``runtime-*``. New transactions
    use ``runtime-tx-*`` so a kill before journal creation is observable without
    retroactively declaring every legacy snapshot an incomplete transaction.
    """

    candidates: list[Path] = []
    for backup_root in sorted(backup_parent.glob("runtime-*")):
        if backup_root.is_symlink() or not backup_root.is_dir():
            candidates.append(backup_root)
            continue
        journal = backup_root / RUNTIME_TRANSACTION_JOURNAL
        if (
            backup_root.name.startswith("runtime-tx-")
            or journal.exists()
            or journal.is_symlink()
        ):
            candidates.append(backup_root)
    return candidates


def recover_incomplete_runtime_transactions(config_root: Path) -> list[dict[str, Any]]:
    backup_parent = config_root / "backups"
    if not backup_parent.exists():
        return []
    if backup_parent.is_symlink() or not backup_parent.is_dir():
        raise StateSecurityError("runtime backup directory is unsafe")
    recovered: list[dict[str, Any]] = []
    for backup_root in _runtime_transaction_backup_roots(backup_parent):
        journal = backup_root / RUNTIME_TRANSACTION_JOURNAL
        if (
            backup_root.is_symlink()
            or not backup_root.is_dir()
            or journal.is_symlink()
            or not journal.is_file()
        ):
            raise StateSecurityError(
                f"runtime transaction evidence is missing or unsafe: {journal}"
            )
        transaction, rows = _transaction_from_journal(
            journal,
            expected_config_root=config_root,
        )
        status = _runtime_transaction_status(rows)
        if status == "terminal":
            continue
        if status == "recovery_required":
            raise StateSecurityError(f"runtime transaction requires manual recovery: {journal}")
        try:
            result = rollback_runtime_transaction(
                transaction,
                rows,
                reason_code="STARTUP_RECOVERY",
            )
        except (OSError, ValueError, StateSecurityError) as exc:
            try:
                _append_runtime_journal(
                    transaction,
                    {
                        "event": "recovery_required",
                        "reason_code": type(exc).__name__.upper(),
                    },
                )
            finally:
                raise StateSecurityError(
                    f"runtime transaction requires manual recovery: {journal}"
                ) from exc
        recovered.append({"journal": str(journal), **result})
    return recovered


def runtime_transaction_health(config_root: Path) -> dict[str, Any]:
    """Inventory durable Runtime transactions without changing any state."""

    backup_parent = config_root / "backups"
    if not backup_parent.exists() and not backup_parent.is_symlink():
        return {
            "healthy": True,
            "pending": 0,
            "recovery_required": 0,
            "invalid": 0,
            "transactions": [],
        }
    if backup_parent.is_symlink() or not backup_parent.is_dir():
        return {
            "healthy": False,
            "pending": 0,
            "recovery_required": 0,
            "invalid": 1,
            "transactions": [{
                "journal": str(backup_parent),
                "status": "invalid",
                "reason_code": "RUNTIME_BACKUP_DIRECTORY_UNSAFE",
            }],
        }
    transactions: list[dict[str, str]] = []
    for backup_root in _runtime_transaction_backup_roots(backup_parent):
        journal = backup_root / RUNTIME_TRANSACTION_JOURNAL
        if (
            backup_root.is_symlink()
            or not backup_root.is_dir()
            or journal.is_symlink()
            or not journal.is_file()
        ):
            transactions.append({
                "journal": str(journal),
                "status": "invalid",
                "reason_code": "RUNTIME_TRANSACTION_JOURNAL_MISSING_OR_UNSAFE",
            })
            continue
        try:
            _transaction, rows = _transaction_from_journal(
                journal,
                expected_config_root=config_root,
            )
        except (OSError, ValueError, TypeError, KeyError, StateSecurityError):
            transactions.append({
                "journal": str(journal),
                "status": "invalid",
                "reason_code": "RUNTIME_TRANSACTION_JOURNAL_INVALID",
            })
            continue
        try:
            status = _runtime_transaction_status(rows)
        except (OSError, ValueError, TypeError, KeyError, StateSecurityError):
            transactions.append({
                "journal": str(journal),
                "status": "invalid",
                "reason_code": "RUNTIME_TRANSACTION_JOURNAL_INVALID",
            })
            continue
        if status == "recovery_required":
            reason_code = "RUNTIME_RECOVERY_REQUIRED"
        elif status == "terminal":
            reason_code = ""
        else:
            reason_code = "RUNTIME_TRANSACTION_PENDING"
        transactions.append({
            "journal": str(journal),
            "status": status,
            "reason_code": reason_code,
        })
    pending = sum(row["status"] == "pending" for row in transactions)
    recovery_required = sum(
        row["status"] == "recovery_required" for row in transactions
    )
    invalid = sum(row["status"] == "invalid" for row in transactions)
    return {
        "healthy": not (pending or recovery_required or invalid),
        "pending": pending,
        "recovery_required": recovery_required,
        "invalid": invalid,
        "transactions": transactions,
    }


def harden_runtime_permissions(config_root: Path) -> None:
    ensure_private_directory(config_root, harden_existing=True)
    for private_name in ("config", "logs", "reports", "proposals", "benchmarks"):
        private_dir = config_root / private_name
        if not (private_dir.exists() or private_dir.is_symlink()):
            continue
        ensure_private_directory(private_dir, harden_existing=True)
        for path in private_dir.rglob("*"):
            if path.is_symlink():
                raise StateSecurityError(f"runtime private path must not be a symlink: {path}")
            if path.is_dir():
                ensure_private_directory(path, harden_existing=True)
            elif path.is_file():
                harden_private_file(path)
            else:
                raise StateSecurityError(f"runtime private path is not regular: {path}")
    harden_sqlite_files(config_root / "state.sqlite", require_database=False)


def runtime_permission_report(config_root: Path) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    try:
        metadata = config_root.lstat()
    except FileNotFoundError:
        issues.append({"path": str(config_root), "reason": "missing_config_root"})
    else:
        if stat.S_ISLNK(metadata.st_mode):
            issues.append({"path": str(config_root), "reason": "symlink"})
        elif not stat.S_ISDIR(metadata.st_mode):
            issues.append({"path": str(config_root), "reason": "not_directory"})
        else:
            actual_mode = stat.S_IMODE(metadata.st_mode)
            if POSIX_PERMISSION_MODEL and actual_mode != PRIVATE_DIRECTORY_MODE:
                issues.append(
                    {
                        "path": str(config_root),
                        "reason": "mode",
                        "expected_mode": "0700",
                        "actual_mode": f"{actual_mode:04o}",
                    }
                )

    config_dir = config_root / "config"
    if config_dir.is_symlink():
        issues.append({"path": str(config_dir), "reason": "symlink"})
    elif config_dir.is_dir():
        for path in config_dir.rglob("*"):
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(metadata.st_mode):
                issues.append({"path": str(path), "reason": "symlink"})
            elif stat.S_ISREG(metadata.st_mode):
                actual_mode = stat.S_IMODE(metadata.st_mode)
                if POSIX_PERMISSION_MODEL and actual_mode != PRIVATE_FILE_MODE:
                    issues.append(
                        {
                            "path": str(path),
                            "reason": "mode",
                            "expected_mode": "0600",
                            "actual_mode": f"{actual_mode:04o}",
                        }
                    )

    sqlite_report = sqlite_permission_report(config_root / "state.sqlite", require_database=False)
    issues.extend(sqlite_report["issues"])
    return {
        "ok": not issues,
        "config_root": str(config_root),
        "issues": issues,
        "state": sqlite_report,
    }


def attest_installed_runtime_static(config_root: Path) -> dict[str, Any]:
    """Authenticate installed Runtime bytes without executing its Python.

    Recovery orchestration uses this narrower attestation while the transition
    is intentionally still ``preflight``.  It verifies the manifest, marker,
    anchor, managed byte/mode inventory, static Python launcher identity,
    permissions, and durable Runtime transaction inventory, but starts no
    subprocess and changes no state.
    """

    root = absolute_path(config_root)
    try:
        manifest_opened = installed_file(root, Path("config/runtime-manifest.json"))
        transition_opened = installed_file(root, Path("config/runtime-transition.json"))
        if manifest_opened is None or transition_opened is None:
            raise StateSecurityError("installed Runtime identity is missing")
        manifest_raw = manifest_opened[0]
        transition_raw = transition_opened[0]
        manifest = json.loads(manifest_raw.decode("utf-8"))
        transition = json.loads(transition_raw.decode("utf-8"))
        if not isinstance(manifest, dict) or not isinstance(transition, dict):
            raise StateSecurityError("installed Runtime identity is invalid")
        _authenticated_existing_runtime_python(root, managed_python_path(root))
        manifest_after = installed_file(root, Path("config/runtime-manifest.json"))
        transition_after = installed_file(root, Path("config/runtime-transition.json"))
        if (
            manifest_after is None
            or transition_after is None
            or manifest_after[0] != manifest_raw
            or transition_after[0] != transition_raw
        ):
            raise StateSecurityError("installed Runtime identity changed during attestation")
        install_id = str(manifest.get("install_id", ""))
        anchor_sha256 = str(manifest.get("runtime_anchor_sha256", ""))
        if (
            re.fullmatch(r"[0-9a-f]{64}", install_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", anchor_sha256) is None
            or transition.get("install_id") != install_id
            or transition.get("runtime_anchor_sha256") != anchor_sha256
        ):
            raise StateSecurityError("installed Runtime binding is invalid")
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        StateSecurityError,
    ) as exc:
        return {
            "healthy": False,
            "reason_code": "RUNTIME_STATIC_ATTESTATION_INVALID",
            "error_type": type(exc).__name__,
        }

    transactions = runtime_transaction_health(root)
    permissions = runtime_permission_report(root)
    transaction_projection = {
        "healthy": transactions.get("healthy") is True,
        "pending": int(transactions.get("pending", 0) or 0),
        "recovery_required": int(transactions.get("recovery_required", 0) or 0),
        "invalid": int(transactions.get("invalid", 0) or 0),
        "transactions": transactions.get("transactions", []),
    }
    transactions_sha256 = hashlib.sha256(
        json.dumps(
            transaction_projection,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    healthy = bool(transactions.get("healthy") is True and permissions.get("ok") is True)
    return {
        "healthy": healthy,
        "reason_code": "" if healthy else "RUNTIME_STATIC_ATTESTATION_UNHEALTHY",
        "bundle_sha256": str(manifest.get("bundle_sha256", "")),
        "install_id": install_id,
        "runtime_anchor_sha256": anchor_sha256,
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "transition_sha256": hashlib.sha256(transition_raw).hexdigest(),
        "transition_phase": str(transition.get("phase", "")),
        "runtime_transactions_sha256": transactions_sha256,
        "runtime_transactions": transaction_projection,
        "permissions_ok": permissions.get("ok") is True,
    }


def verify(config_root: Path) -> dict[str, Any]:
    transactions = runtime_transaction_health(config_root)
    manifest_path = config_root / "config" / "runtime-manifest.json"
    try:
        manifest = json.loads(
            secure_read_bytes_beneath(config_root, Path("config/runtime-manifest.json")).decode("utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateSecurityError):
        return {
            "ok": False,
            "manifest": str(manifest_path),
            "missing_manifest": True,
            "runtime_transactions": transactions,
        }
    expected = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(expected, dict):
        return {
            "ok": False,
            "manifest": str(manifest_path),
            "invalid_manifest": True,
            "runtime_transactions": transactions,
        }
    manifest_protocol_ok = (
        manifest.get("schema_version") == 2
        and manifest.get("release_version") == RUNTIME_RELEASE_VERSION
        and manifest.get("runtime_api_version") == 2
        and manifest.get("writer_protocol_version") == 2
        and manifest.get("state_schema_required") == STATE_SCHEMA_VERSION
        and manifest.get("canonical_actors") == ["codex", "claude", "ailu"]
        and manifest.get("capabilities")
        == {"write_gateway": WRITE_GATEWAY_CAPABILITIES}
        and isinstance(manifest.get("file_modes"), dict)
        and set(manifest.get("file_modes", {})) == set(expected)
        and isinstance(manifest.get("support_file_modes"), dict)
        and set(manifest.get("support_file_modes", {}))
        == set(manifest.get("support_files", {}))
        and isinstance(manifest.get("support_source_modes"), dict)
        and set(manifest.get("support_source_modes", {}))
        == set(manifest.get("support_files", {}))
        and isinstance(manifest.get("template_file_modes"), dict)
        and set(manifest.get("template_file_modes", {}))
        == set(manifest.get("template_files", {}))
    )
    calculated_bundle = hashlib.sha256(
        json.dumps(
            {
                "files": expected,
                "support_files": manifest.get("support_files", {}),
                "template_files": manifest.get("template_files", {}),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    bundle_ok = manifest.get("bundle_sha256") == calculated_bundle
    transition_path = config_root / "config" / "runtime-transition.json"
    try:
        transition = json.loads(
            secure_read_bytes_beneath(config_root, Path("config/runtime-transition.json")).decode("utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateSecurityError):
        transition = {}
    transition_ok = (
        isinstance(transition, dict)
        and transition.get("phase") == "ready"
        and transition.get("bundle_sha256") == manifest.get("bundle_sha256")
        and isinstance(manifest.get("install_id"), str)
        and len(str(manifest.get("install_id", ""))) == 64
        and transition.get("install_id") == manifest.get("install_id")
        and isinstance(manifest.get("runtime_anchor_sha256"), str)
        and transition.get("runtime_anchor_sha256") == manifest.get("runtime_anchor_sha256")
    )
    # The installed runtime's environment helper owns the exact live readiness
    # contract (runtime/config/hook attestation plus state v4). Import it from
    # this runtime root so --verify cannot report a weaker result than memoryctl.
    live_readiness: dict[str, Any] = {
        "ready": False,
        "reason_code": "RUNTIME_READINESS_UNCHECKED",
    }
    runtime_python = managed_python_path(config_root)
    environment = os.environ.copy()
    environment["AGENT_MEMORY_CONFIG_ROOT"] = str(config_root)
    environment["AGENT_MEMORY_CONFIG_FILE"] = str(config_root / "config" / "agent-memory.toml")
    readiness_probe = (
        "import json,sys; sys.path.append(sys.argv[1]); "
        "from agent_memory_env import runtime_transition_status; "
        "print(json.dumps(runtime_transition_status(), separators=(',',':')))"
    )
    python_identity: dict[str, Any] = {"ok": False, "reason_code": "RUNTIME_PYTHON_UNCHECKED"}
    identity: dict[str, Any] | None = None
    expected_identity: dict[str, Any] | None = None
    if manifest_protocol_ok and bundle_ok and transition_ok:
        try:
            expected_identity = _authenticated_existing_runtime_python(config_root, runtime_python)
            candidate_identity = _attest_authenticated_runtime_python(
                config_root,
                runtime_python,
                expected_identity,
            )
            identity = candidate_identity
            python_identity = {"ok": True, **identity}
        except (OSError, StateSecurityError, subprocess.SubprocessError):
            identity = None
    if identity is not None:
        try:
            completed = subprocess.run(
                [str(runtime_python), "-I", "-S", "-c", readiness_probe, str(config_root / "scripts")],
                cwd=config_root,
                env=environment,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=60,
                check=False,
            )
            candidate = json.loads(completed.stdout) if completed.returncode == 0 else {}
            if isinstance(candidate, dict):
                live_readiness = candidate
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            pass
    readiness_ok = live_readiness.get("ready") is True
    state_path = configured_state_db(config_root)
    state_ok = state_schema_ready(state_path)
    missing: list[str] = []
    mismatched: list[str] = []
    mode_mismatched: list[str] = []
    for name, digest in expected.items():
        actual = installed_sha256(config_root, Path("scripts") / str(name))
        if actual is None:
            missing.append(str(name))
        elif actual != str(digest):
            mismatched.append(str(name))
        elif POSIX_PERMISSION_MODEL and manifest_protocol_ok and installed_mode(
            config_root, Path("scripts") / str(name)
        ) != _manifest_mode(manifest, "file_modes", str(name)):
            mode_mismatched.append(f"scripts/{name}")
    support_missing: list[str] = []
    support_mismatched: list[str] = []
    support_expected = manifest.get("support_files", {}) if isinstance(manifest, dict) else {}
    if isinstance(support_expected, dict):
        for name, digest in support_expected.items():
            actual = installed_sha256(config_root, Path(str(name)))
            if actual is None:
                support_missing.append(str(name))
            elif actual != str(digest):
                support_mismatched.append(str(name))
            elif POSIX_PERMISSION_MODEL and manifest_protocol_ok and installed_mode(
                config_root, Path(str(name))
            ) != _manifest_mode(manifest, "support_file_modes", str(name)):
                mode_mismatched.append(str(name))
    template_missing: list[str] = []
    template_mismatched: list[str] = []
    template_expected = manifest.get("template_files", {}) if isinstance(manifest, dict) else {}
    if isinstance(template_expected, dict):
        for name, digest in template_expected.items():
            actual = installed_sha256(config_root, Path(str(name)))
            if actual is None:
                template_missing.append(str(name))
            elif actual != str(digest):
                template_mismatched.append(str(name))
            elif POSIX_PERMISSION_MODEL and manifest_protocol_ok and installed_mode(
                config_root, Path(str(name))
            ) != _manifest_mode(manifest, "template_file_modes", str(name)):
                mode_mismatched.append(str(name))
    permissions = runtime_permission_report(config_root)
    return {
        "ok": transactions["healthy"]
        and manifest_protocol_ok and bundle_ok and transition_ok and readiness_ok and state_ok
        and python_identity["ok"]
        and not missing and not mismatched and not support_missing and not support_mismatched
        and not template_missing and not template_mismatched
        and not mode_mismatched and permissions["ok"],
        "manifest": str(manifest_path),
        "source_commit": manifest.get("source_commit", ""),
        "source_dirty": bool(manifest.get("source_dirty")),
        "checked_files": len(expected),
        "runtime_api_version": manifest.get("runtime_api_version"),
        "writer_protocol_version": manifest.get("writer_protocol_version"),
        "manifest_protocol_ok": manifest_protocol_ok,
        "bundle_ok": bundle_ok,
        "transition_ok": transition_ok,
        "readiness_ok": readiness_ok,
        "runtime_transition": live_readiness,
        "runtime_transactions": transactions,
        "runtime_python": python_identity,
        "state_ok": state_ok,
        "state_db": str(state_path),
        "missing": missing,
        "mismatched": mismatched,
        "support_missing": support_missing,
        "support_mismatched": support_mismatched,
        "template_missing": template_missing,
        "template_mismatched": template_mismatched,
        "mode_mismatched": mode_mismatched,
        "permissions": permissions,
    }


def install(
    config_root: Path,
    dry_run: bool,
    *,
    runtime_python_identity: dict[str, Any] | None = None,
    transaction: dict[str, Any] | None = None,
    anchor_payload: dict[str, Any] | None = None,
    manifest_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    script_root = config_root / "scripts"
    config_dir = config_root / "config"
    managed_python = managed_python_path(config_root)
    semantic_policy = semantic_runtime_policy(config_root, managed_python)
    semantic_dependencies: dict[str, Any] = {
        **semantic_policy,
        "ok": True,
        "status": "planned" if semantic_policy["required"] else "disabled",
    }
    if anchor_payload is None:
        anchor, anchor_created = load_or_create_runtime_anchor(config_root)
    else:
        anchor = anchor_payload
        anchor_created = not (config_root / RUNTIME_ANCHOR_RELATIVE).exists()
    manifest = manifest_payload or expected_manifest(config_root, anchor)
    validate_runtime_layout(config_root, manifest, allow_missing=True)
    changed: list[str] = []
    unchanged: list[str] = []
    backup_root: Path | None = None
    if not dry_run:
        if not isinstance(runtime_python_identity, dict):
            raise StateSecurityError("managed runtime Python identity is required")
        ensure_private_directory(config_root, harden_existing=True)
        ensure_private_directory(config_dir, harden_existing=True)
        if transaction is None:
            transaction = begin_runtime_transaction(config_root, manifest)
        if anchor_created:
            atomic_write_json(
                config_root / RUNTIME_ANCHOR_RELATIVE,
                anchor,
                runtime_root=config_root,
                transaction=transaction,
            )
        if secure_sha256_beneath(config_root, RUNTIME_ANCHOR_RELATIVE) != manifest["runtime_anchor_sha256"]:
            raise StateSecurityError("managed runtime anchor identity mismatch")
        backup_root = Path(str(transaction["backup_root"]))
        atomic_write_json(
            config_dir / "runtime-transition.json",
            transition_marker(
                phase="installing",
                bundle_sha256=str(manifest["bundle_sha256"]),
                install_id=str(manifest["install_id"]),
                runtime_anchor_sha256=str(manifest["runtime_anchor_sha256"]),
                runtime_python=runtime_python_identity,
            ),
            runtime_root=config_root,
            transaction=transaction,
        )
    # Publish the entrypoint before its transition-aware environment helper.
    # With the old helper this entrypoint fails to import (closed); once both
    # are present it reads the `installing` marker and refuses normal work.
    ordered_front = (
        "memoryctl",
        "agent_memory_env.py",
        # Direct host hooks must stop accepting work as soon as possible. With
        # old dependencies these new entrypoints fail to import (closed); with
        # new dependencies they see the `installing` marker and fail closed.
        "agent_memory_stop_hook.py",
        "agent_memory_closeout.py",
    )
    ordered_core_files = (
        *ordered_front,
        *(name for name in CORE_FILES if name not in set(ordered_front)),
    )
    for name in ordered_core_files:
        source = SOURCE_ROOT / name
        target = script_root / name
        expected_mode = _manifest_mode(manifest, "file_modes", name)
        if (
            installed_sha256(config_root, Path("scripts") / name) == manifest["files"][name]
            and (
                not POSIX_PERMISSION_MODEL
                or installed_mode(config_root, Path("scripts") / name) == expected_mode
            )
        ):
            unchanged.append(name)
            continue
        changed.append(name)
        if not dry_run:
            atomic_copy(
                source,
                target,
                runtime_root=config_root,
                transaction=transaction,
                expected_sha256=str(manifest["files"][name]),
                expected_mode=expected_mode,
            )
    for name in SUPPORT_FILES:
        source = REPO_ROOT / name
        target = config_root / name
        expected_mode = _manifest_mode(manifest, "support_file_modes", name)
        expected_source_mode = _manifest_mode(manifest, "support_source_modes", name)
        if (
            installed_sha256(config_root, Path(name)) == manifest["support_files"][name]
            and (
                not POSIX_PERMISSION_MODEL
                or installed_mode(config_root, Path(name)) == expected_mode
            )
        ):
            unchanged.append(name)
            continue
        changed.append(name)
        if not dry_run:
            atomic_copy(
                source,
                target,
                runtime_root=config_root,
                transaction=transaction,
                expected_sha256=str(manifest["support_files"][name]),
                expected_mode=expected_source_mode,
                target_mode=expected_mode,
            )
    for name, digest in manifest["template_files"].items():
        source = REPO_ROOT / name
        target = config_root / name
        expected_mode = _manifest_mode(manifest, "template_file_modes", str(name))
        if (
            installed_sha256(config_root, Path(name)) == digest
            and (
                not POSIX_PERMISSION_MODEL
                or installed_mode(config_root, Path(name)) == expected_mode
            )
        ):
            unchanged.append(name)
            continue
        changed.append(name)
        if not dry_run:
            atomic_copy(
                source,
                target,
                runtime_root=config_root,
                transaction=transaction,
                expected_sha256=str(digest),
                expected_mode=expected_mode,
            )
    if not dry_run:
        assert transaction is not None
        semantic_dependencies = install_semantic_dependencies(
            config_root,
            managed_python,
            transaction=transaction,
        )
        manifest_path = config_dir / "runtime-manifest.json"
        # The manifest is the commit marker and is published only after every
        # payload file has reached its final path.
        atomic_write_json(
            manifest_path,
            manifest,
            runtime_root=config_root,
            transaction=transaction,
        )
        # A missing database is not a ready runtime.  Fresh installs and
        # upgrades both remain closed until the explicit state migrator has
        # initialized/verified the configured database and published `ready`.
        # Every install, including an idempotent same-bundle refresh, closes the
        # runtime. Only the locked migrator strong preflight may republish ready;
        # state/schema alone is not an attestation for config, hashes, indexes,
        # Doctor, or host-hook policy.
        final_phase = "state_migration_required"
        atomic_write_json(
            config_dir / "runtime-transition.json",
            transition_marker(
                phase=final_phase,
                bundle_sha256=str(manifest["bundle_sha256"]),
                install_id=str(manifest["install_id"]),
                runtime_anchor_sha256=str(manifest["runtime_anchor_sha256"]),
                runtime_python=runtime_python_identity,
            ),
            runtime_root=config_root,
            transaction=transaction,
        )
        harden_runtime_permissions(config_root)
        attest_installed_runtime_bundle(
            config_root,
            manifest,
            transition_phase=final_phase,
            runtime_python_identity=runtime_python_identity,
        )
        _append_runtime_journal(
            transaction,
            {
                "event": "completed",
                "bundle_sha256": str(manifest["bundle_sha256"]),
                "backup_root": str(backup_root),
            },
        )
    return {
        "ok": True,
        "dry_run": dry_run,
        "config_root": str(config_root),
        "changed": changed,
        "unchanged": unchanged,
        "source_commit": manifest["source_commit"],
        "source_dirty": manifest["source_dirty"],
        "bundle_sha256": str(manifest["bundle_sha256"]),
        "backup": str(backup_root) if backup_root is not None else "",
        "transaction_journal": (
            str(transaction["journal_path"])
            if transaction is not None
            else ""
        ),
        "install_id": str(manifest["install_id"]),
        "runtime_anchor_sha256": str(manifest["runtime_anchor_sha256"]),
        "runtime_ready": False,
        "state_migration_required": True,
        "semantic_dependencies": semantic_dependencies,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install or verify the canonical Agent Memory runtime.")
    parser.add_argument("--config-root", default="~/.config/agent-memory")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_root = absolute_path(args.config_root)
    try:
        if args.verify or args.dry_run:
            payload = verify(config_root) if args.verify else install(config_root, True)
        else:
            with runtime_transition_lock(config_root):
                startup_recovery = recover_incomplete_runtime_transactions(config_root)
                anchor, _anchor_created = load_or_create_runtime_anchor(config_root)
                manifest = expected_manifest(config_root, anchor)
                transaction = begin_runtime_transaction(config_root, manifest)
                recovered_venv: Path | None = None
                try:
                    runtime_python, runtime_python_identity, recovered_venv = ensure_managed_python(
                        config_root,
                        transaction=transaction,
                    )
                    payload = install(
                        config_root,
                        False,
                        runtime_python_identity=runtime_python_identity,
                        transaction=transaction,
                        anchor_payload=anchor,
                        manifest_payload=manifest,
                    )
                    payload["python"] = str(runtime_python)
                    payload["recovered_untrusted_venv"] = (
                        str(recovered_venv) if recovered_venv else ""
                    )
                    payload["startup_recovery"] = startup_recovery
                except (
                    OSError,
                    RuntimeError,
                    ValueError,
                    StateSecurityError,
                    TimeoutError,
                    subprocess.SubprocessError,
                ) as exc:
                    try:
                        rollback = rollback_runtime_transaction(
                            transaction,
                            reason_code=type(exc).__name__.upper(),
                        )
                    except (OSError, RuntimeError, ValueError, StateSecurityError) as rollback_error:
                        try:
                            _append_runtime_journal(
                                transaction,
                                {
                                    "event": "recovery_required",
                                    "reason_code": type(exc).__name__.upper(),
                                    "rollback_error": type(rollback_error).__name__.upper(),
                                },
                            )
                        except (OSError, StateSecurityError):
                            pass
                        payload = {
                            "ok": False,
                            "config_root": str(config_root),
                            "error": "RUNTIME_RECOVERY_REQUIRED",
                            "detail": type(exc).__name__,
                            "backup": str(transaction["backup_root"]),
                            "transaction_journal": str(transaction["journal_path"]),
                            "recovered_untrusted_venv": (
                                str(recovered_venv) if recovered_venv else ""
                            ),
                            "recovered_venv": "",
                            "rollback": {
                                "ok": False,
                                "error": type(rollback_error).__name__,
                            },
                            "startup_recovery": startup_recovery,
                        }
                    else:
                        payload = {
                            "ok": False,
                            "config_root": str(config_root),
                            "error": type(exc).__name__,
                            "detail": str(exc),
                            "backup": str(transaction["backup_root"]),
                            "transaction_journal": str(transaction["journal_path"]),
                            "recovered_untrusted_venv": (
                                str(recovered_venv) if recovered_venv else ""
                            ),
                            "recovered_venv": str(rollback.get("recovered_venv", "")),
                            "rollback": rollback,
                            "startup_recovery": startup_recovery,
                        }
    except (
        OSError,
        RuntimeError,
        ValueError,
        StateSecurityError,
        TimeoutError,
        subprocess.SubprocessError,
    ) as exc:
        # Even a pre-transaction/startup-recovery failure uses the same stable
        # evidence shape. Empty paths explicitly mean no new transaction or
        # recovered venv was created by this invocation.
        payload = {
            "ok": False,
            "config_root": str(config_root),
            "error": type(exc).__name__,
            "detail": str(exc),
            "backup": "",
            "transaction_journal": "",
            "recovered_untrusted_venv": "",
            "recovered_venv": "",
            "rollback": {},
            "startup_recovery": [],
        }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"runtime={'ok' if payload.get('ok') else 'error'} root={config_root}")
        for key in ("changed", "missing", "mismatched"):
            if payload.get(key):
                print(f"{key}={','.join(payload[key])}")
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
