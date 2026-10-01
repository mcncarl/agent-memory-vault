#!/usr/bin/env python3
"""One-shot local capability for publishing the generated Vault INDEX.

The public index command may build/read the derived SQLite projection, but it
must never mutate ``INDEX.md`` directly.  Closeout issues this short-lived,
parent-bound capability immediately before spawning the index subprocess.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from agent_memory_state import secure_sqlite_connect

try:  # pragma: no cover - platform import is exercised by its native CI job.
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

try:  # pragma: no cover - platform import is exercised by its native CI job.
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None  # type: ignore[assignment]


CAPABILITY_VERSION = 1
CAPABILITY_PURPOSE = "generated_index_sync"
CAPABILITY_DIRECTORY = "capabilities"
CAPABILITY_PATH_ENV = "AGENT_MEMORY_GENERATED_INDEX_CAPABILITY_PATH"
CAPABILITY_TOKEN_ENV = "AGENT_MEMORY_GENERATED_INDEX_CAPABILITY_TOKEN"
CAPABILITY_BINDING_ENV = "AGENT_MEMORY_GENERATED_INDEX_TRANSACTION_BINDING"
MAX_CAPABILITY_BYTES = 16 * 1024
MAX_BINDING_BYTES = 8 * 1024
MAX_TTL_SECONDS = 60
SHA256_RE = re.compile(r"[0-9a-f]{64}")
TRANSACTION_ID_RE = re.compile(r"[0-9a-f]{32}")
GIT_HEAD_RE = re.compile(r"[0-9a-f]{40,64}")
REQUIRED_BINDING_FIELDS = (
    "transaction_id",
    "actor",
    "task_sha256",
    "vault_root_sha256",
    "git_head",
    "index_base_sha256",
    "full_vault_inputs_sha256",
    "lease_fences_sha256",
)
TRANSACTION_TABLE = "generated_index_closeout_transactions"
TRANSACTION_COLUMNS = {
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
}


class GeneratedIndexCapabilityError(RuntimeError):
    """Stable denial raised when generated INDEX publication is unauthorized."""


def _deny(code: str = "GENERATED_INDEX_CAPABILITY_INVALID") -> None:
    raise GeneratedIndexCapabilityError(code)


def _capability_root(config_root: Path) -> Path:
    return config_root.resolve() / CAPABILITY_DIRECTORY


def _secure_directory(config_root: Path) -> Path:
    root = _capability_root(config_root)
    if root.exists() and root.is_symlink():
        _deny("GENERATED_INDEX_CAPABILITY_DIRECTORY_UNSAFE")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = root.lstat()
    current_uid = os.getuid() if hasattr(os, "getuid") else metadata.st_uid
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != current_uid:
        _deny("GENERATED_INDEX_CAPABILITY_DIRECTORY_UNSAFE")
    os.chmod(root, 0o700)
    return root.resolve()


def generated_index_backup_directory(config_root: Path, transaction_id: str) -> Path:
    """Create the private, non-overwriting evidence directory for one closeout."""

    normalized_id = str(transaction_id).strip().lower()
    if TRANSACTION_ID_RE.fullmatch(normalized_id) is None:
        _deny("GENERATED_INDEX_TRANSACTION_INVALID")
    resolved_config_root = config_root.expanduser().resolve()
    root = resolved_config_root / "backups" / "generated-index" / normalized_id
    current_uid = os.getuid() if hasattr(os, "getuid") else None
    current = resolved_config_root
    for component in (current, current / "backups", current / "backups" / "generated-index", root):
        if component.exists() and component.is_symlink():
            _deny("GENERATED_INDEX_BACKUP_DIRECTORY_UNSAFE")
        component.mkdir(parents=True, exist_ok=True, mode=0o700)
        metadata = component.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or (
            current_uid is not None and metadata.st_uid != current_uid
        ):
            _deny("GENERATED_INDEX_BACKUP_DIRECTORY_UNSAFE")
        os.chmod(component, 0o700)
    return root.resolve()


def validate_generated_index_recovery_evidence_path(
    config_root: Path,
    transaction_id: str,
    evidence_path: Path | str,
    *,
    require_exists: bool,
) -> Path:
    """Require one evidence path directly inside its private transaction directory."""

    normalized_id = str(transaction_id).strip().lower()
    if TRANSACTION_ID_RE.fullmatch(normalized_id) is None:
        _deny("GENERATED_INDEX_TRANSACTION_INVALID")
    resolved_config = config_root.expanduser().resolve()
    components = (
        resolved_config,
        resolved_config / "backups",
        resolved_config / "backups" / "generated-index",
        resolved_config / "backups" / "generated-index" / normalized_id,
    )
    current_uid = os.getuid() if hasattr(os, "getuid") else None
    for component in components:
        try:
            metadata = component.lstat()
        except OSError:
            _deny("GENERATED_INDEX_RECOVERY_EVIDENCE_MISSING")
        if component.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or (
            current_uid is not None and metadata.st_uid != current_uid
        ):
            _deny("GENERATED_INDEX_BACKUP_DIRECTORY_UNSAFE")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o700:
            _deny("GENERATED_INDEX_BACKUP_DIRECTORY_UNSAFE")
    root = components[-1].resolve(strict=True)
    candidate = Path(evidence_path).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=require_exists)
    except OSError:
        _deny("GENERATED_INDEX_RECOVERY_EVIDENCE_MISSING")
    if resolved.parent != root or not resolved.name:
        _deny("GENERATED_INDEX_RECOVERY_EVIDENCE_INVALID")
    if require_exists:
        try:
            metadata = candidate.lstat()
        except OSError:
            _deny("GENERATED_INDEX_RECOVERY_EVIDENCE_MISSING")
        if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode) or (
            current_uid is not None and metadata.st_uid != current_uid
        ):
            _deny("GENERATED_INDEX_RECOVERY_EVIDENCE_INVALID")
    elif candidate.exists() or candidate.is_symlink():
        try:
            metadata = candidate.lstat()
        except OSError:
            _deny("GENERATED_INDEX_RECOVERY_EVIDENCE_INVALID")
        if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode) or (
            current_uid is not None and metadata.st_uid != current_uid
        ):
            _deny("GENERATED_INDEX_RECOVERY_EVIDENCE_INVALID")
    return resolved


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def normalize_transaction_binding(raw: dict[str, Any]) -> dict[str, str]:
    """Validate the closeout transaction projection bound to INDEX publication."""

    if not isinstance(raw, dict) or set(raw) != set(REQUIRED_BINDING_FIELDS):
        _deny("GENERATED_INDEX_TRANSACTION_REQUIRED")
    binding = {key: str(raw.get(key, "")).strip().lower() for key in REQUIRED_BINDING_FIELDS}
    if TRANSACTION_ID_RE.fullmatch(binding["transaction_id"]) is None:
        _deny("GENERATED_INDEX_TRANSACTION_INVALID")
    if binding["actor"] not in {"codex", "claude", "ailu", "human", "migration", "test"}:
        _deny("GENERATED_INDEX_TRANSACTION_INVALID")
    if GIT_HEAD_RE.fullmatch(binding["git_head"]) is None:
        _deny("GENERATED_INDEX_TRANSACTION_INVALID")
    for key in (
        "task_sha256",
        "vault_root_sha256",
        "index_base_sha256",
        "full_vault_inputs_sha256",
        "lease_fences_sha256",
    ):
        if SHA256_RE.fullmatch(binding[key]) is None:
            _deny("GENERATED_INDEX_TRANSACTION_INVALID")
    return binding


def transaction_binding_sha256(binding: dict[str, Any]) -> str:
    normalized = normalize_transaction_binding(binding)
    return hashlib.sha256(_json_bytes(normalized)).hexdigest()


def _projection_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _git_bytes(git_root: Path, args: list[str], *, input_bytes: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(git_root.resolve()), *args],
            input=input_bytes,
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GeneratedIndexCapabilityError("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID") from exc
    return completed.stdout


def git_commit_parents(git_root: Path, commit: str) -> list[str]:
    normalized = str(commit).strip().lower()
    if GIT_HEAD_RE.fullmatch(normalized) is None:
        _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
    raw = _git_bytes(git_root, ["rev-list", "--parents", "-n", "1", normalized])
    try:
        fields = raw.decode("ascii").strip().lower().split()
    except UnicodeDecodeError:
        _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
    if not fields or fields[0] != normalized or any(GIT_HEAD_RE.fullmatch(value) is None for value in fields):
        _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
    return fields[1:]


def git_commit_file_sha256(git_root: Path, commit: str, repo_path: str) -> str:
    normalized = str(commit).strip().lower()
    path = str(repo_path).strip().replace("\\", "/")
    if GIT_HEAD_RE.fullmatch(normalized) is None or not path or path.startswith("/") or "\x00" in path:
        _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
    return hashlib.sha256(_git_bytes(git_root, ["show", f"{normalized}:{path}"])).hexdigest()


def git_commit_full_vault_inputs_sha256(
    git_root: Path,
    vault_root: Path,
    commit: str,
) -> str:
    """Hash the exact non-INDEX Markdown projection stored in one Git commit."""

    normalized_commit = str(commit).strip().lower()
    if GIT_HEAD_RE.fullmatch(normalized_commit) is None:
        _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
    resolved_git = git_root.resolve()
    resolved_vault = vault_root.resolve()
    try:
        vault_repo_path = resolved_vault.relative_to(resolved_git).as_posix()
    except ValueError:
        _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
    pathspec = ["--", vault_repo_path] if vault_repo_path != "." else []
    raw_tree = _git_bytes(
        resolved_git,
        ["ls-tree", "-rz", "--full-tree", normalized_commit, *pathspec],
    )
    objects: list[tuple[str, str]] = []
    seen: set[str] = set()
    prefix = f"{vault_repo_path}/" if vault_repo_path != "." else ""
    for record in raw_tree.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, object_type, oid = header.decode("ascii").split()
            repo_path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
        if prefix:
            if not repo_path.startswith(prefix):
                _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
            relative = repo_path[len(prefix):]
        else:
            relative = repo_path
        if not relative.lower().endswith(".md") or relative == "INDEX.md":
            continue
        if object_type != "blob" or mode == "120000" or not re.fullmatch(r"[0-9a-f]{40,64}", oid):
            _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
        if not relative or relative.startswith("/") or relative in seen:
            _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
        seen.add(relative)
        objects.append((relative, oid))

    if not objects:
        return _projection_sha256([])
    request = b"".join(oid.encode("ascii") + b"\n" for _relative, oid in objects)
    raw_blobs = _git_bytes(resolved_git, ["cat-file", "--batch"], input_bytes=request)
    offset = 0
    projection: list[tuple[str, str]] = []
    for relative, expected_oid in objects:
        header_end = raw_blobs.find(b"\n", offset)
        if header_end < 0:
            _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
        try:
            oid, object_type, raw_size = raw_blobs[offset:header_end].decode("ascii").split()
            size = int(raw_size)
        except (UnicodeDecodeError, ValueError):
            _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
        start = header_end + 1
        end = start + size
        if oid != expected_oid or object_type != "blob" or size < 0 or end >= len(raw_blobs):
            _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
        data = raw_blobs[start:end]
        if raw_blobs[end:end + 1] != b"\n":
            _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
        projection.append((relative, hashlib.sha256(data).hexdigest()))
        offset = end + 1
    if offset != len(raw_blobs):
        _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
    return _projection_sha256(sorted(projection))


def verify_generated_index_commit_evidence(
    git_root: Path,
    vault_root: Path,
    transaction_binding: dict[str, Any],
    *,
    generated_sha256: str,
    closeout_git_commit: str,
) -> dict[str, Any]:
    """Verify INDEX, parent/base, Vault identity, and commit-tree input bytes."""

    binding = normalize_transaction_binding(transaction_binding)
    digest = str(generated_sha256).strip().lower()
    commit = str(closeout_git_commit).strip().lower()
    if SHA256_RE.fullmatch(digest) is None or GIT_HEAD_RE.fullmatch(commit) is None:
        _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
    current_vault_sha256 = hashlib.sha256(str(vault_root.resolve()).encode("utf-8")).hexdigest()
    if current_vault_sha256 != binding["vault_root_sha256"]:
        _deny("GENERATED_INDEX_VAULT_ROOT_CHANGED")
    try:
        index_repo_path = (vault_root.resolve() / "INDEX.md").relative_to(git_root.resolve()).as_posix()
    except ValueError:
        _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
    if git_commit_file_sha256(git_root, commit, index_repo_path) != digest:
        _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")

    changed = digest != binding["index_base_sha256"]
    projection_verified = False
    if changed or commit != binding["git_head"]:
        if git_commit_parents(git_root, commit) != [binding["git_head"]]:
            _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
        projection = git_commit_full_vault_inputs_sha256(git_root, vault_root, commit)
        if projection != binding["full_vault_inputs_sha256"]:
            _deny("GENERATED_INDEX_COMMIT_EVIDENCE_INVALID")
        projection_verified = True
    return {
        "ok": True,
        "commit": commit,
        "changed": changed,
        "projection_verified": projection_verified,
    }


def _transaction_connection(state_db: Path) -> sqlite3.Connection:
    conn: sqlite3.Connection | None = None
    try:
        conn = secure_sqlite_connect(
            state_db.resolve(),
            create=False,
            row_factory=sqlite3.Row,
            pragmas=("PRAGMA busy_timeout=2000",),
        )
        columns = {
            str(row[1])
            for row in conn.execute(f"PRAGMA table_info({TRANSACTION_TABLE})")
        }
        if columns != TRANSACTION_COLUMNS:
            raise sqlite3.OperationalError("generated index transaction schema mismatch")
        return conn
    except (OSError, sqlite3.Error) as exc:
        if conn is not None:
            conn.close()
        raise GeneratedIndexCapabilityError("STATE_SCHEMA_MIGRATION_REQUIRED") from exc


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _lock_descriptor(descriptor: int) -> None:
    if fcntl is not None:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return
    if msvcrt is None:  # pragma: no cover - every supported host has one.
        _deny("GENERATED_INDEX_CAPABILITY_LOCK_UNAVAILABLE")
    os.lseek(descriptor, 0, os.SEEK_SET)
    msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)


def _unlock_descriptor(descriptor: int) -> None:
    if fcntl is not None:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return
    if msvcrt is not None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)


def issue_generated_index_capability(
    config_root: Path,
    *,
    state_db: Path,
    transaction_binding: dict[str, Any],
    issuer_pid: int | None = None,
    ttl_seconds: int = 30,
) -> dict[str, str]:
    """Mint only for a pre-registered, validated closeout transaction."""

    ttl = int(ttl_seconds)
    if ttl < 1 or ttl > MAX_TTL_SECONDS:
        raise ValueError("generated_index_capability_ttl_invalid")
    parent_pid = int(issuer_pid if issuer_pid is not None else os.getpid())
    if parent_pid < 1:
        raise ValueError("generated_index_capability_issuer_invalid")
    binding = normalize_transaction_binding(transaction_binding)
    now = int(time.time())
    with contextlib.closing(_transaction_connection(state_db)) as conn:
        row = conn.execute(
            f"SELECT * FROM {TRANSACTION_TABLE} WHERE transaction_id=?",
            (binding["transaction_id"],),
        ).fetchone()
    if row is None:
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_MISSING")
    registered = dict(row)
    if (
        registered.get("status") != "registered"
        or int(registered.get("issuer_pid") or 0) != parent_pid
        or int(registered.get("expires_at_epoch") or 0) < now
        or int(registered.get("expires_at_epoch") or 0)
        - int(registered.get("issued_at_epoch") or 0)
        != ttl
        or any(
            str(registered.get(key, "")) != binding[key]
            for key in REQUIRED_BINDING_FIELDS
        )
    ):
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
    issued_at = int(registered["issued_at_epoch"])
    expires_at = int(registered["expires_at_epoch"])
    root = _secure_directory(config_root)
    token = secrets.token_urlsafe(32)
    payload = {
        "version": CAPABILITY_VERSION,
        "purpose": CAPABILITY_PURPOSE,
        "status": "issued",
        "issuer_pid": parent_pid,
        "issued_at_epoch": issued_at,
        "expires_at_epoch": expires_at,
        "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "transaction_binding": binding,
        "transaction_binding_sha256": transaction_binding_sha256(binding),
    }
    path = root / f"generated-index-{uuid.uuid4().hex}.json"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        raw = _json_bytes(payload)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)
        _fsync_directory(root)
    except Exception:
        # Preserve a failed issuance journal for inspection. A malformed or
        # partial capability always fails closed and is never reused.
        raise
    try:
        with contextlib.closing(_transaction_connection(state_db)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            changed = conn.execute(
                f"""
                UPDATE {TRANSACTION_TABLE}
                SET status='issued', capability_sha256=?
                WHERE transaction_id=? AND status='registered' AND issuer_pid=?
                """,
                (payload["token_sha256"], binding["transaction_id"], parent_pid),
            ).rowcount
            if changed != 1:
                _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
            conn.commit()
    except sqlite3.Error as exc:
        raise GeneratedIndexCapabilityError("GENERATED_INDEX_CLOSEOUT_TRANSACTION_UNAVAILABLE") from exc
    return {"path": str(path.resolve(strict=True)), "token": token}


def consume_generated_index_capability(
    config_root: Path,
    *,
    state_db: Path,
    capability_path: str,
    token: str,
    expected_transaction_binding: dict[str, Any],
    expected_parent_pid: int | None = None,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    """Validate and consume exactly one capability under an exclusive lock."""

    if not capability_path or not token:
        _deny("GENERATED_FILE_READ_ONLY")
    expected_binding = normalize_transaction_binding(expected_transaction_binding)
    expected_binding_sha256 = transaction_binding_sha256(expected_binding)
    root = _capability_root(config_root)
    try:
        root = root.resolve(strict=True)
        supplied_path = Path(capability_path).expanduser()
        supplied_metadata = supplied_path.lstat()
        if stat.S_ISLNK(supplied_metadata.st_mode):
            _deny()
        path = supplied_path.resolve(strict=True)
    except OSError:
        _deny()
    if path.parent != root or not path.name.startswith("generated-index-") or path.suffix != ".json":
        _deny()
    try:
        before = path.lstat()
    except OSError:
        _deny()
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        _deny()
    current_uid = os.getuid() if hasattr(os, "getuid") else before.st_uid
    if before.st_uid != current_uid or (os.name != "nt" and stat.S_IMODE(before.st_mode) != 0o600):
        _deny()
    if before.st_size < 2 or before.st_size > MAX_CAPABILITY_BYTES:
        _deny()

    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _deny()
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            _deny()
        _lock_descriptor(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = os.read(descriptor, MAX_CAPABILITY_BYTES + 1)
        if len(raw) > MAX_CAPABILITY_BYTES:
            _deny()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _deny()
        if not isinstance(payload, dict):
            _deny()
        parent_pid = int(expected_parent_pid if expected_parent_pid is not None else os.getppid())
        current_time = int(now_epoch if now_epoch is not None else time.time())
        supplied_sha = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if (
            payload.get("version") != CAPABILITY_VERSION
            or payload.get("purpose") != CAPABILITY_PURPOSE
            or payload.get("status") != "issued"
            or int(payload.get("issuer_pid", 0)) != parent_pid
            or SHA256_RE.fullmatch(str(payload.get("token_sha256", ""))) is None
            or not secrets.compare_digest(str(payload.get("token_sha256")), supplied_sha)
            or payload.get("transaction_binding") != expected_binding
            or not secrets.compare_digest(
                str(payload.get("transaction_binding_sha256", "")),
                expected_binding_sha256,
            )
        ):
            _deny()
        issued_at = int(payload.get("issued_at_epoch", 0))
        expires_at = int(payload.get("expires_at_epoch", 0))
        if issued_at > current_time + 5 or expires_at < current_time or expires_at - issued_at > MAX_TTL_SECONDS:
            _deny("GENERATED_INDEX_CAPABILITY_EXPIRED")

        with contextlib.closing(_transaction_connection(state_db)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                f"SELECT * FROM {TRANSACTION_TABLE} WHERE transaction_id=?",
                (expected_binding["transaction_id"],),
            ).fetchone()
            if row is None:
                _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_MISSING")
            row_payload = dict(row)
            transaction_matches = (
                row_payload.get("status") == "issued"
                and int(row_payload.get("issuer_pid") or 0) == parent_pid
                and str(row_payload.get("capability_sha256", "")) == supplied_sha
                and int(row_payload.get("issued_at_epoch") or 0) == issued_at
                and int(row_payload.get("expires_at_epoch") or 0) == expires_at
                and all(
                    str(row_payload.get(key, "")) == expected_binding[key]
                    for key in REQUIRED_BINDING_FIELDS
                )
            )
            if not transaction_matches:
                _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
            changed = conn.execute(
                f"""
                UPDATE {TRANSACTION_TABLE}
                SET status='claimed', consumer_pid=?, claimed_at_epoch=?
                WHERE transaction_id=? AND status='issued'
                """,
                (os.getpid(), current_time, expected_binding["transaction_id"]),
            ).rowcount
            if changed != 1:
                _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
            conn.commit()

        payload["status"] = "claimed"
        payload["claimed_at_epoch"] = current_time
        payload["consumer_pid"] = os.getpid()
        consumed = _json_bytes(payload)
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        written = os.write(descriptor, consumed)
        if written != len(consumed):
            _deny()
        os.fsync(descriptor)
        return {
            "ok": True,
            "path": str(path),
            "issuer_pid": parent_pid,
            "consumed_at_epoch": current_time,
            "transaction_binding": expected_binding,
            "state_db": str(state_db.resolve()),
        }
    except (OSError, sqlite3.Error, TypeError, ValueError):
        _deny()
    finally:
        try:
            _unlock_descriptor(descriptor)
        finally:
            os.close(descriptor)


def consume_generated_index_capability_from_environment(
    config_root: Path,
    *,
    state_db: Path,
) -> dict[str, Any]:
    """Consume the closeout-only capability supplied to the index child."""

    capability_path = os.environ.get(CAPABILITY_PATH_ENV, "")
    token = os.environ.get(CAPABILITY_TOKEN_ENV, "")
    if not capability_path or not token:
        _deny("GENERATED_FILE_READ_ONLY")
    raw_binding = os.environ.get(CAPABILITY_BINDING_ENV, "")
    if not raw_binding or len(raw_binding.encode("utf-8")) > MAX_BINDING_BYTES:
        _deny("GENERATED_INDEX_TRANSACTION_REQUIRED")
    try:
        decoded = json.loads(raw_binding)
    except (TypeError, ValueError, json.JSONDecodeError):
        _deny("GENERATED_INDEX_TRANSACTION_INVALID")
    if not isinstance(decoded, dict):
        _deny("GENERATED_INDEX_TRANSACTION_INVALID")

    return consume_generated_index_capability(
        config_root,
        state_db=state_db,
        capability_path=capability_path,
        token=token,
        expected_transaction_binding=decoded,
    )


def read_generated_index_transaction(
    state_db: Path,
    transaction_binding: dict[str, Any],
) -> dict[str, Any]:
    """Read back the durable transaction and require an exact binding match."""

    binding = normalize_transaction_binding(transaction_binding)
    with contextlib.closing(_transaction_connection(state_db)) as conn:
        row = conn.execute(
            f"SELECT * FROM {TRANSACTION_TABLE} WHERE transaction_id=?",
            (binding["transaction_id"],),
        ).fetchone()
    if row is None:
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_MISSING")
    receipt = dict(row)
    if any(str(receipt.get(key, "")) != binding[key] for key in REQUIRED_BINDING_FIELDS):
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
    return receipt


def commit_generated_index_transaction(
    state_db: Path,
    transaction_binding: dict[str, Any],
    *,
    generated_sha256: str,
    closeout_git_commit: str,
    issuer_pid: int | None = None,
) -> dict[str, Any]:
    """Finish publication only after the parent verifies the committed Git blob."""

    binding = normalize_transaction_binding(transaction_binding)
    digest = str(generated_sha256).strip().lower()
    commit = str(closeout_git_commit).strip().lower()
    parent_pid = int(issuer_pid if issuer_pid is not None else os.getpid())
    if SHA256_RE.fullmatch(digest) is None or GIT_HEAD_RE.fullmatch(commit) is None or parent_pid < 1:
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
    with contextlib.closing(_transaction_connection(state_db)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            f"SELECT * FROM {TRANSACTION_TABLE} WHERE transaction_id=?",
            (binding["transaction_id"],),
        ).fetchone()
        if row is None:
            _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_MISSING")
        receipt = dict(row)
        if (
            any(str(receipt.get(key, "")) != binding[key] for key in REQUIRED_BINDING_FIELDS)
            or int(receipt.get("issuer_pid") or 0) != parent_pid
            or str(receipt.get("generated_sha256", "")) != digest
        ):
            _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
        if receipt.get("status") == "consumed":
            if str(receipt.get("closeout_git_commit", "")) != commit:
                _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
            conn.rollback()
            return receipt
        changed = conn.execute(
            f"""
            UPDATE {TRANSACTION_TABLE}
            SET status='consumed', consumed_at_epoch=?, closeout_git_commit=?
            WHERE transaction_id=? AND status='generated_bound'
              AND issuer_pid=? AND generated_sha256=?
            """,
            (int(time.time()), commit, binding["transaction_id"], parent_pid, digest),
        ).rowcount
        if changed != 1:
            _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
        conn.commit()
    return read_generated_index_transaction(state_db, binding)


def bind_generated_index_recovery_evidence(
    state_db: Path,
    authorization: dict[str, Any],
    *,
    config_root: Path,
    evidence_path: Path,
) -> str:
    """Persist the exact private rollback path before INDEX publication."""

    raw_binding = authorization.get("transaction_binding")
    if not isinstance(raw_binding, dict):
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
    binding = normalize_transaction_binding(raw_binding)
    resolved = validate_generated_index_recovery_evidence_path(
        config_root,
        binding["transaction_id"],
        evidence_path,
        require_exists=False,
    )
    with contextlib.closing(_transaction_connection(state_db)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        changed = conn.execute(
            f"""
            UPDATE {TRANSACTION_TABLE}
            SET rollback_evidence_path=?
            WHERE transaction_id=? AND status='generated_bound' AND consumer_pid=?
              AND rollback_evidence_path=''
            """,
            (str(resolved), binding["transaction_id"], os.getpid()),
        ).rowcount
        if changed != 1:
            _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
        conn.commit()
    return str(resolved)


def mark_generated_index_transaction_outcome(
    state_db: Path,
    transaction_binding: dict[str, Any],
    *,
    outcome: str,
    generated_sha256: str = "",
    failure_reason: str = "",
    issuer_pid: int | None = None,
) -> dict[str, Any]:
    """Retain a failed or rolled-back transaction without erasing evidence."""

    binding = normalize_transaction_binding(transaction_binding)
    normalized_outcome = str(outcome).strip().lower()
    parent_pid = int(issuer_pid if issuer_pid is not None else os.getpid())
    digest = str(generated_sha256).strip().lower()
    reason = str(failure_reason).strip().upper()
    if normalized_outcome not in {"rolled_back", "failed"} or parent_pid < 1:
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
    if digest and SHA256_RE.fullmatch(digest) is None:
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
    if normalized_outcome == "failed" and re.fullmatch(r"[A-Z0-9_]{1,128}", reason) is None:
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
    if normalized_outcome == "rolled_back" and reason:
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
    with contextlib.closing(_transaction_connection(state_db)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            f"SELECT * FROM {TRANSACTION_TABLE} WHERE transaction_id=?",
            (binding["transaction_id"],),
        ).fetchone()
        if row is None:
            _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_MISSING")
        receipt = dict(row)
        if (
            any(str(receipt.get(key, "")) != binding[key] for key in REQUIRED_BINDING_FIELDS)
            or int(receipt.get("issuer_pid") or 0) != parent_pid
            or (digest and str(receipt.get("generated_sha256", "")) not in {"", digest})
        ):
            _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
        if receipt.get("status") == normalized_outcome:
            conn.rollback()
            return receipt
        if normalized_outcome == "failed":
            changed = conn.execute(
                f"""
                UPDATE {TRANSACTION_TABLE}
                SET status='failed', failure_reason=?, failure_at_epoch=?
                WHERE transaction_id=? AND issuer_pid=?
                  AND status IN ('registered','issued','claimed','generated_bound')
                """,
                (reason, int(time.time()), binding["transaction_id"], parent_pid),
            ).rowcount
        else:
            changed = conn.execute(
                f"""
                UPDATE {TRANSACTION_TABLE}
                SET status='rolled_back'
                WHERE transaction_id=? AND issuer_pid=?
                  AND status IN ('registered','issued','claimed','generated_bound')
                """,
                (binding["transaction_id"], parent_pid),
            ).rowcount
        if changed != 1:
            _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
        conn.commit()
    return read_generated_index_transaction(state_db, binding)


def resolve_failed_generated_index_transaction(
    state_db: Path,
    transaction_binding: dict[str, Any],
    *,
    outcome: str,
    generated_sha256: str = "",
    closeout_git_commit: str = "",
    issuer_pid: int | None = None,
) -> dict[str, Any]:
    """CAS-resolve retained failure evidence after objective recovery succeeds."""

    binding = normalize_transaction_binding(transaction_binding)
    normalized_outcome = str(outcome).strip().lower()
    digest = str(generated_sha256).strip().lower()
    commit = str(closeout_git_commit).strip().lower()
    parent_pid = int(issuer_pid if issuer_pid is not None else os.getpid())
    if normalized_outcome not in {"rolled_back", "consumed"} or parent_pid < 1:
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
    if digest and SHA256_RE.fullmatch(digest) is None:
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
    if normalized_outcome == "consumed" and (
        SHA256_RE.fullmatch(digest) is None or GIT_HEAD_RE.fullmatch(commit) is None
    ):
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
    with contextlib.closing(_transaction_connection(state_db)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            f"SELECT * FROM {TRANSACTION_TABLE} WHERE transaction_id=?",
            (binding["transaction_id"],),
        ).fetchone()
        if row is None:
            _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_MISSING")
        receipt = dict(row)
        if (
            any(str(receipt.get(key, "")) != binding[key] for key in REQUIRED_BINDING_FIELDS)
            or int(receipt.get("issuer_pid") or 0) != parent_pid
            or not str(receipt.get("failure_reason", "")).strip()
            or int(receipt.get("failure_at_epoch") or 0) <= 0
            or (digest and str(receipt.get("generated_sha256", "")) not in {"", digest})
        ):
            _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
        if receipt.get("status") == normalized_outcome:
            if normalized_outcome == "consumed" and str(receipt.get("closeout_git_commit", "")) != commit:
                _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
            conn.rollback()
            return receipt
        if normalized_outcome == "consumed":
            changed = conn.execute(
                f"""
                UPDATE {TRANSACTION_TABLE}
                SET status='consumed', consumed_at_epoch=?, closeout_git_commit=?
                WHERE transaction_id=? AND status='failed' AND issuer_pid=?
                """,
                (int(time.time()), commit, binding["transaction_id"], parent_pid),
            ).rowcount
        else:
            changed = conn.execute(
                f"""
                UPDATE {TRANSACTION_TABLE}
                SET status='rolled_back'
                WHERE transaction_id=? AND status='failed' AND issuer_pid=?
                """,
                (binding["transaction_id"], parent_pid),
            ).rowcount
        if changed != 1:
            _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
        conn.commit()
    return read_generated_index_transaction(state_db, binding)


def bind_expected_generated_index_sha256(
    state_db: Path,
    authorization: dict[str, Any],
    *,
    generated_sha256: str,
) -> None:
    """Bind deterministic generated bytes before the INDEX target is replaced."""

    binding = authorization.get("transaction_binding")
    if not isinstance(binding, dict) or SHA256_RE.fullmatch(generated_sha256) is None:
        _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
    normalized = normalize_transaction_binding(binding)
    with contextlib.closing(_transaction_connection(state_db)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        changed = conn.execute(
            f"""
            UPDATE {TRANSACTION_TABLE}
            SET generated_sha256=?, status='generated_bound'
            WHERE transaction_id=? AND status='claimed' AND consumer_pid=?
              AND generated_sha256=''
            """,
            (generated_sha256, normalized["transaction_id"], os.getpid()),
        ).rowcount
        if changed != 1:
            _deny("GENERATED_INDEX_CLOSEOUT_TRANSACTION_INVALID")
        conn.commit()


def recover_expired_generated_index_transactions(
    state_db: Path,
    *,
    now_epoch: int | None = None,
) -> int:
    """Mark expired incomplete grants failed while retaining durable evidence."""

    current_time = int(now_epoch if now_epoch is not None else time.time())
    with contextlib.closing(_transaction_connection(state_db)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        changed = conn.execute(
            f"""
            UPDATE {TRANSACTION_TABLE}
            SET status='failed', failure_reason='GENERATED_INDEX_CAPABILITY_EXPIRED',
                failure_at_epoch=?
            WHERE status IN ('registered','issued','claimed','generated_bound')
              AND expires_at_epoch < ?
            """,
            (current_time, current_time),
        ).rowcount
        conn.commit()
    return int(changed)
