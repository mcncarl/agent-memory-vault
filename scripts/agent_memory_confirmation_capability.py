#!/usr/bin/env python3
"""Short-lived, one-shot human-confirmation capabilities for risky writes.

The canonical write gateway deliberately cannot mint these capabilities.  A
host integration, or the explicit manual issuer in this module, must issue one
*after* a write intent exists.  The bearer token is returned once and only its
SHA-256 digest is persisted.  The durable journal is bound to the complete
intent identity and is retained after consumption; a second create-once
consumption receipt prevents an accidentally restored ``issued`` journal from
rewinding the one-shot decision.  The canonical Gateway may use that exact
receipt to recover only the crash window between consumption and durable intent
approval; ordinary consumers still observe strict one-shot behavior.

There is currently no claim here that Codex, Claude, or another host UI has
provided an unforgeable human-presence credential.  Until such a host bridge
invokes the issuer, sensitive writes therefore fail closed.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import threading
import time
import unicodedata
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from agent_memory_env import RuntimeTransitionError, assert_runtime_ready, env_value, expand_path

try:  # pragma: no cover - exercised by the native POSIX test job.
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

try:  # pragma: no cover - exercised by the native Windows test job.
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None  # type: ignore[assignment]


CAPABILITY_VERSION = 1
CAPABILITY_PURPOSE = "human_write_confirmation"
CAPABILITY_PARENT_DIRECTORY = "capabilities"
CAPABILITY_DIRECTORY = "human-confirmations"
CAPABILITY_PATH_ENV = "AGENT_MEMORY_CONFIRMATION_CAPABILITY_PATH"
CAPABILITY_TOKEN_ENV = "AGENT_MEMORY_CONFIRMATION_CAPABILITY_TOKEN"
HANDOFF_DIRECTORY = "handoffs"
HANDOFF_KIND = "human_confirmation_handoff"
HANDOFF_PREFIX = "human-confirmation-handoff-"
CONSUMPTION_RECEIPT_PREFIX = "human-confirmation-consumed-"
CONSUMPTION_LEDGER_DIRECTORY = "confirmation-consumption-ledger"
DEFAULT_TTL_SECONDS = 120
MAX_TTL_SECONDS = 300
MAX_CAPABILITY_BYTES = 32 * 1024
MAX_REQUEST_BYTES = 16 * 1024
MAX_HANDOFF_BYTES = 16 * 1024
HUMAN_ISSUER_ACTOR = "human"
SUBJECT_ACTORS = {"codex", "claude"}
SENSITIVE_ACTIONS = {"ADOPT", "MIGRATE_LEGACY_SCOPE"}
SENSITIVE_OPERATIONS = {"status_transition", "governance_migration"}
OPERATIONS = {"content_update", *SENSITIVE_OPERATIONS}
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[0-9a-f]{32}\Z")


class ConfirmationCapabilityError(RuntimeError):
    """Stable denial raised by the confirmation capability protocol."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _deny(code: str = "CONFIRMATION_CAPABILITY_INVALID") -> None:
    raise ConfirmationCapabilityError(code)


def session_hash(raw_session_id: str) -> str:
    value = str(raw_session_id).strip()
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16] if value else ""


def task_hash(raw_task_id: str, actor: str) -> str:
    """Match observability.task_ref without importing the stateful module."""

    value = str(raw_task_id).strip()
    normalized_actor = str(actor).strip().casefold()
    if not value or normalized_actor not in SUBJECT_ACTORS:
        return ""
    payload = f"agent-memory-task-v1\0{normalized_actor}\0{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _sensitive(action: str, operation: str) -> bool:
    return (
        str(action).strip().upper() in SENSITIVE_ACTIONS
        or str(operation).strip().casefold() in SENSITIVE_OPERATIONS
    )


def _bounded_reference(value: str) -> str:
    reference = str(value).strip()
    if not reference or len(reference) > 512 or any(ord(char) < 0x20 for char in reference):
        raise ValueError("confirmation_reference_invalid")
    return reference


def _relative_target(value: str) -> str:
    target = str(value).strip().replace("\\", "/")
    parsed = PurePosixPath(target)
    if (
        not target
        or len(target) > 512
        or target.startswith("/")
        or parsed.is_absolute()
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or "\x00" in target
        or "\r" in target
        or "\n" in target
    ):
        raise ValueError("target_relative_path_invalid")
    return unicodedata.normalize("NFC", parsed.as_posix())


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _consumption_receipt_path(root: Path, capability_id: str) -> Path:
    if IDENTIFIER_RE.fullmatch(str(capability_id)) is None:
        _deny()
    return root / f"{CONSUMPTION_RECEIPT_PREFIX}{capability_id}.json"


def _issued_journal_bytes(payload: dict[str, Any]) -> bytes:
    """Reconstruct the exact create-once journal bytes from a consumed row."""

    issued = dict(payload)
    issued["status"] = "issued"
    for key in (
        "consumed_at_epoch",
        "consumer_pid",
        "consumption_receipt_sha256",
    ):
        issued.pop(key, None)
    return _json_bytes(issued)


def _matching_consumption_receipt(
    root: Path,
    *,
    payload: dict[str, Any],
    issued_raw: bytes,
) -> tuple[str, int] | None:
    """Read one immutable receipt and verify its complete proposal/fence binding."""

    capability_id = str(payload.get("capability_id", ""))
    path = _consumption_receipt_path(root, capability_id)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        _deny()
    current_uid = os.getuid() if hasattr(os, "getuid") else before.st_uid
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != current_uid
        or (os.name != "nt" and stat.S_IMODE(before.st_mode) != 0o600)
        or before.st_size > MAX_HANDOFF_BYTES
    ):
        _deny()
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            _deny()
        raw = os.read(descriptor, MAX_HANDOFF_BYTES + 1)
    except ConfirmationCapabilityError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    except OSError:
        if "descriptor" in locals():
            os.close(descriptor)
        _deny()
    else:
        os.close(descriptor)
    if len(raw) > MAX_HANDOFF_BYTES:
        _deny()
    try:
        receipt = _strict_json_object(raw)
        consumed_at = int(receipt.get("consumed_at_epoch", 0))
        issued_at = int(payload.get("issued_at_epoch", 0))
        expires_at = int(payload.get("expires_at_epoch", 0))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        _deny()
    expected = {
        "version": CAPABILITY_VERSION,
        "kind": "human_confirmation_consumed",
        "capability_id": capability_id,
        "issued_journal_sha256": hashlib.sha256(issued_raw).hexdigest(),
        "binding_sha256": hashlib.sha256(
            _json_bytes(_immutable_payload(payload))
        ).hexdigest(),
        "consumed_at_epoch": consumed_at,
    }
    if (
        receipt != expected
        or consumed_at < issued_at
        or consumed_at > expires_at
    ):
        _deny()
    return hashlib.sha256(raw).hexdigest(), consumed_at


def _write_consumption_receipt(
    root: Path,
    *,
    payload: dict[str, Any],
    issued_raw: bytes,
    consumed_at_epoch: int,
) -> str:
    """Create a second monotonic marker before changing the mutable journal.

    Restoring an older ``status=issued`` copy of the journal can no longer make
    an honestly consumed capability reusable.  A malicious process with full
    same-UID filesystem control can still remove both files; that trust-domain
    limitation is intentionally not described as cryptographic user presence.
    """

    capability_id = str(payload.get("capability_id", ""))
    if IDENTIFIER_RE.fullmatch(capability_id) is None:
        _deny()
    receipt = {
        "version": CAPABILITY_VERSION,
        "kind": "human_confirmation_consumed",
        "capability_id": capability_id,
        "issued_journal_sha256": hashlib.sha256(issued_raw).hexdigest(),
        "binding_sha256": hashlib.sha256(
            _json_bytes(_immutable_payload(payload))
        ).hexdigest(),
        "consumed_at_epoch": int(consumed_at_epoch),
    }
    raw = _json_bytes(receipt)
    path = _consumption_receipt_path(root, capability_id)
    flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            _deny("CONFIRMATION_CAPABILITY_ALREADY_CONSUMED")
        _deny()
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            if os.name != "nt":
                os.fchmod(handle.fileno(), 0o600)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(root)
    except OSError:
        _deny()
    return hashlib.sha256(raw).hexdigest()


def _immutable_payload(payload: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "version",
        "purpose",
        "capability_id",
        "issuer_actor",
        "subject_actor",
        "task_hash",
        "session_hash",
        "proposal_id",
        "proposal_raw_sha256",
        "proposal_canonical_sha256",
        "target_relative_path",
        "target_key",
        "operation",
        "reconcile_action",
        "fencing_token",
        "confirmation_reference_sha256",
        "issued_at_epoch",
        "expires_at_epoch",
        "token_sha256",
    )
    return {key: payload.get(key) for key in keys}


def _binding_hmac(token: str, payload: dict[str, Any]) -> str:
    return hmac.new(
        str(token).encode("utf-8"),
        _json_bytes(_immutable_payload(payload)),
        hashlib.sha256,
    ).hexdigest()


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> Any:
        raise ValueError("non_finite_json")

    payload = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=no_duplicates,
        parse_constant=reject_constant,
    )
    if not isinstance(payload, dict):
        raise ValueError("json_object_required")
    return payload


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
        _deny("CONFIRMATION_CAPABILITY_LOCK_UNAVAILABLE")
    os.lseek(descriptor, 0, os.SEEK_SET)
    msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)


def _unlock_descriptor(descriptor: int) -> None:
    if fcntl is not None:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    elif msvcrt is not None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)


def _secure_child(parent: Path, name: str) -> Path:
    child = parent / name
    if child.exists() and child.is_symlink():
        _deny("CONFIRMATION_CAPABILITY_DIRECTORY_UNSAFE")
    child.mkdir(exist_ok=True, mode=0o700)
    metadata = child.lstat()
    current_uid = os.getuid() if hasattr(os, "getuid") else metadata.st_uid
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != current_uid:
        _deny("CONFIRMATION_CAPABILITY_DIRECTORY_UNSAFE")
    if os.name != "nt":
        os.chmod(child, 0o700)
    return child.resolve(strict=True)


def _secure_directory(config_root: Path) -> Path:
    configured = Path(config_root).expanduser()
    if configured.exists() and configured.is_symlink():
        _deny("CONFIRMATION_CAPABILITY_DIRECTORY_UNSAFE")
    configured.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = configured.resolve(strict=True)
    capabilities = _secure_child(root, CAPABILITY_PARENT_DIRECTORY)
    return _secure_child(capabilities, CAPABILITY_DIRECTORY)


def _secure_consumption_directory(config_root: Path) -> Path:
    configured = Path(config_root).expanduser()
    if configured.exists() and configured.is_symlink():
        _deny("CONFIRMATION_CAPABILITY_DIRECTORY_UNSAFE")
    configured.mkdir(parents=True, exist_ok=True, mode=0o700)
    return _secure_child(configured.resolve(strict=True), CONSUMPTION_LEDGER_DIRECTORY)


def _secure_handoff_directory(config_root: Path) -> Path:
    return _secure_child(_secure_directory(config_root), HANDOFF_DIRECTORY)


_CONSUMED_PROOF = object()
_PROCESS_CONSUME_LOCK = threading.Lock()


class ConsumedConfirmation:
    """Opaque in-process evidence returned only after atomic consumption."""

    __slots__ = ("_binding", "_proof")

    def __init__(self, binding: dict[str, Any], proof: object) -> None:
        if proof is not _CONSUMED_PROOF:
            _deny()
        self._binding = dict(binding)
        self._proof = proof

    @property
    def capability_id(self) -> str:
        return str(self._binding["capability_id"])


def _expected_binding(
    *,
    subject_actor: str,
    raw_task_id: str,
    raw_session_id: str,
    proposal_id: str,
    proposal_raw_sha256: str,
    proposal_canonical_sha256: str,
    target_relative_path: str,
    target_key: str,
    operation: str,
    reconcile_action: str,
    fencing_token: int,
) -> dict[str, Any]:
    actor = str(subject_actor).strip().casefold()
    normalized_operation = str(operation).strip().casefold()
    action = str(reconcile_action).strip().upper()
    task = task_hash(raw_task_id, actor)
    session = session_hash(raw_session_id)
    target = _relative_target(target_relative_path)
    normalized_target_key = str(target_key).strip().replace("\\", "/")
    # Current write intents use the canonical case-folded relative path as the
    # target key.  Retain acceptance of the earlier opaque SHA-256 form so an
    # in-flight pre-upgrade intent can still be completed, but never accept an
    # unrelated free-form key.
    target_key_valid = bool(
        normalized_target_key == target.casefold()
        or SHA256_RE.fullmatch(normalized_target_key) is not None
    )
    if (
        actor not in SUBJECT_ACTORS
        or not task
        or not session
        or IDENTIFIER_RE.fullmatch(str(proposal_id)) is None
        or SHA256_RE.fullmatch(str(proposal_raw_sha256)) is None
        or SHA256_RE.fullmatch(str(proposal_canonical_sha256)) is None
        or not target_key_valid
        or normalized_operation not in OPERATIONS
        or not (
            _sensitive(action, normalized_operation)
            or (normalized_operation == "content_update" and action == "UPDATE")
        )
        or not isinstance(fencing_token, int)
        or isinstance(fencing_token, bool)
        or fencing_token < 1
    ):
        raise ValueError("confirmation_capability_binding_invalid")
    return {
        "subject_actor": actor,
        "task_hash": task,
        "session_hash": session,
        "proposal_id": str(proposal_id),
        "proposal_raw_sha256": str(proposal_raw_sha256),
        "proposal_canonical_sha256": str(proposal_canonical_sha256),
        "target_relative_path": target,
        "target_key": normalized_target_key,
        "operation": normalized_operation,
        "reconcile_action": action,
        "fencing_token": fencing_token,
    }


def issue_confirmation_capability(
    config_root: Path,
    *,
    issuer_actor: str,
    subject_actor: str,
    raw_task_id: str,
    raw_session_id: str,
    proposal_id: str,
    proposal_raw_sha256: str,
    proposal_canonical_sha256: str,
    target_relative_path: str,
    target_key: str,
    operation: str,
    reconcile_action: str,
    fencing_token: int,
    confirmation_reference: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> dict[str, Any]:
    """Issue a capability from the explicit human/host authorization surface."""

    if str(issuer_actor).strip().casefold() != HUMAN_ISSUER_ACTOR:
        _deny("CONFIRMATION_CAPABILITY_ISSUER_FORBIDDEN")
    binding = _expected_binding(
        subject_actor=subject_actor,
        raw_task_id=raw_task_id,
        raw_session_id=raw_session_id,
        proposal_id=proposal_id,
        proposal_raw_sha256=proposal_raw_sha256,
        proposal_canonical_sha256=proposal_canonical_sha256,
        target_relative_path=target_relative_path,
        target_key=target_key,
        operation=operation,
        reconcile_action=reconcile_action,
        fencing_token=fencing_token,
    )
    reference = _bounded_reference(confirmation_reference)
    ttl = int(ttl_seconds)
    if ttl < 1 or ttl > MAX_TTL_SECONDS:
        raise ValueError("confirmation_capability_ttl_invalid")
    root = _secure_directory(config_root)
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    capability_id = uuid.uuid4().hex
    payload = {
        "version": CAPABILITY_VERSION,
        "purpose": CAPABILITY_PURPOSE,
        "status": "issued",
        "capability_id": capability_id,
        "issuer_actor": HUMAN_ISSUER_ACTOR,
        **binding,
        "confirmation_reference_sha256": hashlib.sha256(reference.encode("utf-8")).hexdigest(),
        "issued_at_epoch": now,
        "expires_at_epoch": now + ttl,
        "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
    }
    payload["binding_hmac_sha256"] = _binding_hmac(token, payload)
    # The intent ID is the create-once issuance key.  A fresh prepare receives
    # a fresh proposal ID, while the same proposal can never accumulate
    # multiple usable bearer capabilities (including under concurrent issuers).
    path = root / f"human-confirmation-proposal-{proposal_id}.json"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            _deny("CONFIRMATION_CAPABILITY_ALREADY_ISSUED")
        _deny()
    raw = _json_bytes(payload)
    if len(raw) > MAX_CAPABILITY_BYTES:
        os.close(descriptor)
        _deny()
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    if os.name != "nt":
        os.chmod(path, 0o600)
    _fsync_directory(root)
    return {
        "capability_id": capability_id,
        "path": str(path.resolve(strict=True)),
        "token": token,
        "expires_at_epoch": now + ttl,
    }


def issue_for_intent(
    config_root: Path,
    *,
    issuer_actor: str,
    subject_actor: str,
    raw_task_id: str,
    raw_session_id: str,
    proposal_id: str,
    confirmation_reference: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> dict[str, Any]:
    """Derive every mutation binding from an already-created intent."""

    import agent_memory_intent as write_intent  # Lazy import avoids a module cycle.

    shown = write_intent.show_intent(str(proposal_id))
    intent = shown.get("intent")
    if not isinstance(intent, dict):
        _deny()
    actor = str(subject_actor).strip().casefold()
    if (
        str(intent.get("status", "")) != "pending"
        or str(intent.get("actor", "")) != actor
        or str(intent.get("session_hash", "")) != session_hash(raw_session_id)
    ):
        _deny()
    return issue_confirmation_capability(
        config_root,
        issuer_actor=issuer_actor,
        subject_actor=actor,
        raw_task_id=raw_task_id,
        raw_session_id=raw_session_id,
        proposal_id=str(intent.get("intent_id", "")),
        proposal_raw_sha256=str(intent.get("proposal_raw_sha256", "")),
        proposal_canonical_sha256=str(intent.get("proposal_canonical_sha256", "")),
        target_relative_path=str(intent.get("target_rel_path", "")),
        target_key=str(intent.get("target_key", "")),
        operation=str(intent.get("operation", "content_update")),
        reconcile_action=str(intent.get("reconcile_action", "")),
        fencing_token=int(intent.get("fencing_token") or 0),
        confirmation_reference=confirmation_reference,
        ttl_seconds=ttl_seconds,
    )


def _handoff_public_summary(payload: dict[str, Any], path: Path) -> dict[str, Any]:
    return {
        "capability_id": str(payload.get("capability_id", "")),
        "capability_path": str(payload.get("capability_path", "")),
        "handoff_path": str(path),
        "proposal_id": str(payload.get("proposal_id", "")),
        "target_relative_path": str(payload.get("target_relative_path", "")),
        "operation": str(payload.get("operation", "")),
        "reconcile_action": str(payload.get("reconcile_action", "")),
        "fencing_token": int(payload.get("fencing_token", 0) or 0),
        "expires_at_epoch": int(payload.get("expires_at_epoch", 0) or 0),
        "binding_sha256": str(payload.get("binding_sha256", "")),
        "same_uid_trust_boundary": True,
        "cryptographic_user_presence": False,
    }


def _handoff_public_binding(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: payload.get(key)
        for key in (
            "capability_id", "subject_actor", "task_hash", "session_hash",
            "proposal_id", "proposal_raw_sha256",
            "proposal_canonical_sha256", "target_relative_path",
            "target_key", "operation", "reconcile_action",
            "fencing_token", "expires_at_epoch",
        )
    }


def _issued_handoff_token(
    payload: dict[str, Any],
    *,
    require_fresh: bool,
) -> str:
    """Validate one issued handoff without silently consuming its capability."""

    token = str(payload.get("token", ""))
    if (
        payload.get("status") != "issued"
        or not token
        or not secrets.compare_digest(
            str(payload.get("binding_sha256", "")),
            hashlib.sha256(
                _json_bytes(_handoff_public_binding(payload))
            ).hexdigest(),
        )
        or not secrets.compare_digest(
            str(payload.get("token_sha256", "")),
            hashlib.sha256(token.encode("utf-8")).hexdigest(),
        )
    ):
        _deny("CONFIRMATION_HANDOFF_INVALID")
    try:
        expired = int(payload.get("expires_at_epoch", 0) or 0) < int(
            time.time()
        )
    except (TypeError, ValueError):
        _deny("CONFIRMATION_HANDOFF_INVALID")
    if require_fresh and expired:
        _deny("CONFIRMATION_HANDOFF_EXPIRED")
    if not require_fresh and not expired:
        _deny("CONFIRMATION_HANDOFF_RECOVERY_INVALID")
    return token


def issue_for_intent_handoff(
    config_root: Path,
    *,
    issuer_actor: str,
    subject_actor: str,
    raw_task_id: str,
    raw_session_id: str,
    proposal_id: str,
    confirmation_reference: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> dict[str, Any]:
    """Issue one capability and persist its bearer in a private handoff.

    The returned value is safe to print: it intentionally omits the bearer.
    The handoff itself is current-user-only and remains subject to the
    disclosed same-UID trust boundary; this is not a host-backed proof of
    physical user presence.
    """

    issued = issue_for_intent(
        config_root,
        issuer_actor=issuer_actor,
        subject_actor=subject_actor,
        raw_task_id=raw_task_id,
        raw_session_id=raw_session_id,
        proposal_id=proposal_id,
        confirmation_reference=confirmation_reference,
        ttl_seconds=ttl_seconds,
    )
    capability_path = Path(str(issued["path"]))
    try:
        capability_payload = _strict_json_object(capability_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        _deny()
    public_binding = {
        key: capability_payload.get(key)
        for key in (
            "capability_id", "subject_actor", "task_hash", "session_hash",
            "proposal_id", "proposal_raw_sha256", "proposal_canonical_sha256",
            "target_relative_path", "target_key", "operation",
            "reconcile_action", "fencing_token", "expires_at_epoch",
        )
    }
    binding_sha256 = hashlib.sha256(_json_bytes(public_binding)).hexdigest()
    handoff_payload = {
        "version": CAPABILITY_VERSION,
        "kind": HANDOFF_KIND,
        "status": "issued",
        "capability_id": str(issued["capability_id"]),
        "capability_path": str(capability_path.resolve(strict=True)),
        "token": str(issued["token"]),
        "token_sha256": hashlib.sha256(str(issued["token"]).encode("utf-8")).hexdigest(),
        **public_binding,
        "binding_sha256": binding_sha256,
        "created_at_epoch": int(time.time()),
    }
    root = _secure_handoff_directory(config_root)
    path = root / f"{HANDOFF_PREFIX}{issued['capability_id']}.json"
    flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    raw = _json_bytes(handoff_payload)
    if len(raw) > MAX_HANDOFF_BYTES:
        _deny()
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            if os.name != "nt":
                os.fchmod(handle.fileno(), 0o600)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(root)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            _deny("CONFIRMATION_HANDOFF_ALREADY_EXISTS")
        _deny()
    return _handoff_public_summary(handoff_payload, path.resolve(strict=True))


def _open_handoff(config_root: Path, handoff_path: str) -> tuple[int, Path, dict[str, Any]]:
    root = _secure_handoff_directory(config_root)
    try:
        supplied = Path(str(handoff_path)).expanduser()
        before = supplied.lstat()
        if stat.S_ISLNK(before.st_mode):
            _deny("CONFIRMATION_HANDOFF_INVALID")
        path = supplied.resolve(strict=True)
    except OSError:
        _deny("CONFIRMATION_HANDOFF_INVALID")
    current_uid = os.getuid() if hasattr(os, "getuid") else before.st_uid
    if (
        path.parent != root
        or not path.name.startswith(HANDOFF_PREFIX)
        or path.suffix != ".json"
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != current_uid
        or (os.name != "nt" and stat.S_IMODE(before.st_mode) != 0o600)
        or before.st_size > MAX_HANDOFF_BYTES
    ):
        _deny("CONFIRMATION_HANDOFF_INVALID")
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            _deny("CONFIRMATION_HANDOFF_INVALID")
        _lock_descriptor(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = os.read(descriptor, MAX_HANDOFF_BYTES + 1)
        if len(raw) > MAX_HANDOFF_BYTES:
            _deny("CONFIRMATION_HANDOFF_INVALID")
        payload = _strict_json_object(raw)
    except ConfirmationCapabilityError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        if "descriptor" in locals():
            os.close(descriptor)
        _deny("CONFIRMATION_HANDOFF_INVALID")
    if (
        payload.get("version") != CAPABILITY_VERSION
        or payload.get("kind") != HANDOFF_KIND
        or IDENTIFIER_RE.fullmatch(str(payload.get("capability_id", ""))) is None
        or SHA256_RE.fullmatch(str(payload.get("binding_sha256", ""))) is None
    ):
        _unlock_descriptor(descriptor)
        os.close(descriptor)
        _deny("CONFIRMATION_HANDOFF_INVALID")
    return descriptor, path, payload


def read_confirmation_handoff(
    config_root: Path,
    *,
    handoff_path: str,
) -> dict[str, Any]:
    """Read a private bearer handoff for one stdin-bound apply invocation."""

    descriptor, path, payload = _open_handoff(config_root, handoff_path)
    try:
        status_value = str(payload.get("status", ""))
        token = str(payload.get("token", ""))
        if status_value == "consumed":
            return {**_handoff_public_summary(payload, path), "status": "consumed"}
        token = _issued_handoff_token(payload, require_fresh=True)
        return {
            **_handoff_public_summary(payload, path),
            **_handoff_public_binding(payload),
            "status": "issued",
            "token": token,
        }
    finally:
        _unlock_descriptor(descriptor)
        os.close(descriptor)


def mark_confirmation_handoff_consumed(
    config_root: Path,
    *,
    handoff_path: str,
    capability_id: str,
) -> dict[str, Any]:
    """Scrub the bearer while retaining a non-secret consumed audit record."""

    descriptor, path, payload = _open_handoff(config_root, handoff_path)
    try:
        if not secrets.compare_digest(
            str(payload.get("capability_id", "")),
            str(capability_id),
        ):
            _deny("CONFIRMATION_HANDOFF_INVALID")
        if payload.get("status") == "consumed":
            return {**_handoff_public_summary(payload, path), "status": "consumed"}
        if payload.get("status") != "issued" or not str(payload.get("token", "")):
            _deny("CONFIRMATION_HANDOFF_INVALID")
        payload.pop("token", None)
        payload["status"] = "consumed"
        payload["consumed_at_epoch"] = int(time.time())
        payload["consumer_pid"] = os.getpid()
        raw = _json_bytes(payload)
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        if os.write(descriptor, raw) != len(raw):
            _deny("CONFIRMATION_HANDOFF_INVALID")
        os.fsync(descriptor)
        return {**_handoff_public_summary(payload, path), "status": "consumed"}
    finally:
        _unlock_descriptor(descriptor)
        os.close(descriptor)


def _consume_confirmation_capability(
    config_root: Path,
    *,
    capability_path: str,
    token: str,
    subject_actor: str,
    raw_task_id: str,
    raw_session_id: str,
    proposal_id: str,
    proposal_raw_sha256: str,
    proposal_canonical_sha256: str,
    target_relative_path: str,
    target_key: str,
    operation: str,
    reconcile_action: str,
    fencing_token: int,
    now_epoch: int | None = None,
    allow_idempotent_recovery: bool = False,
    require_preconsumed: bool = False,
) -> ConsumedConfirmation:
    """Atomically validate and consume exactly one fully-bound capability."""

    if not str(capability_path).strip() or not str(token):
        _deny("CONFIRMATION_CAPABILITY_REQUIRED")
    if (
        not isinstance(allow_idempotent_recovery, bool)
        or not isinstance(require_preconsumed, bool)
        or (require_preconsumed and not allow_idempotent_recovery)
    ):
        _deny()
    try:
        expected = _expected_binding(
            subject_actor=subject_actor,
            raw_task_id=raw_task_id,
            raw_session_id=raw_session_id,
            proposal_id=proposal_id,
            proposal_raw_sha256=proposal_raw_sha256,
            proposal_canonical_sha256=proposal_canonical_sha256,
            target_relative_path=target_relative_path,
            target_key=target_key,
            operation=operation,
            reconcile_action=reconcile_action,
            fencing_token=fencing_token,
        )
    except ValueError:
        _deny()
    configured_root = Path(config_root).expanduser()
    if configured_root.exists() and configured_root.is_symlink():
        _deny("CONFIRMATION_CAPABILITY_DIRECTORY_UNSAFE")
    root = configured_root.resolve(strict=False) / CAPABILITY_PARENT_DIRECTORY / CAPABILITY_DIRECTORY
    try:
        root = root.resolve(strict=True)
        supplied = Path(capability_path).expanduser()
        supplied_metadata = supplied.lstat()
        if stat.S_ISLNK(supplied_metadata.st_mode):
            _deny()
        path = supplied.resolve(strict=True)
    except OSError:
        _deny()
    if path.parent != root or not path.name.startswith("human-confirmation-") or path.suffix != ".json":
        _deny()
    before = path.lstat()
    current_uid = os.getuid() if hasattr(os, "getuid") else before.st_uid
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != current_uid
        or (os.name != "nt" and stat.S_IMODE(before.st_mode) != 0o600)
        or before.st_size > MAX_CAPABILITY_BYTES
    ):
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
            payload = _strict_json_object(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            _deny()
        supplied_token_sha256 = hashlib.sha256(str(token).encode("utf-8")).hexdigest()
        fixed = {
            "version": CAPABILITY_VERSION,
            "purpose": CAPABILITY_PURPOSE,
            "issuer_actor": HUMAN_ISSUER_ACTOR,
        }
        if any(payload.get(key) != value for key, value in fixed.items()):
            _deny()
        if any(payload.get(key) != value for key, value in expected.items()):
            _deny()
        if (
            IDENTIFIER_RE.fullmatch(str(payload.get("capability_id", ""))) is None
            or SHA256_RE.fullmatch(str(payload.get("confirmation_reference_sha256", ""))) is None
            or SHA256_RE.fullmatch(str(payload.get("token_sha256", ""))) is None
            or SHA256_RE.fullmatch(str(payload.get("binding_hmac_sha256", ""))) is None
            or not secrets.compare_digest(str(payload.get("token_sha256", "")), supplied_token_sha256)
            or not secrets.compare_digest(
                str(payload.get("binding_hmac_sha256", "")),
                _binding_hmac(str(token), payload),
            )
        ):
            _deny()
        status_value = payload.get("status")
        consumption_root = _secure_consumption_directory(configured_root)
        if status_value == "consumed":
            if not allow_idempotent_recovery:
                _deny("CONFIRMATION_CAPABILITY_ALREADY_CONSUMED")
            issued_raw = _issued_journal_bytes(payload)
            recovered = _matching_consumption_receipt(
                consumption_root,
                payload=payload,
                issued_raw=issued_raw,
            )
            if recovered is None or not secrets.compare_digest(
                str(payload.get("consumption_receipt_sha256", "")),
                recovered[0],
            ):
                _deny()
            return ConsumedConfirmation(payload, _CONSUMED_PROOF)
        if status_value != "issued":
            _deny()
        existing_receipt = _consumption_receipt_path(
            consumption_root,
            str(payload.get("capability_id", "")),
        )
        if existing_receipt.exists() or existing_receipt.is_symlink():
            if not allow_idempotent_recovery:
                _deny("CONFIRMATION_CAPABILITY_ALREADY_CONSUMED")
            recovered = _matching_consumption_receipt(
                consumption_root,
                payload=payload,
                issued_raw=raw,
            )
            if recovered is None:
                _deny()
            payload["status"] = "consumed"
            payload["consumed_at_epoch"] = recovered[1]
            payload["consumer_pid"] = os.getpid()
            payload["consumption_receipt_sha256"] = recovered[0]
            consumed_raw = _json_bytes(payload)
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.ftruncate(descriptor, 0)
            if os.write(descriptor, consumed_raw) != len(consumed_raw):
                _deny()
            os.fsync(descriptor)
            return ConsumedConfirmation(payload, _CONSUMED_PROOF)
        if require_preconsumed:
            # Recovery may observe either a consumed journal or the narrower
            # receipt-before-journal crash window.  It must never turn an
            # expired, still-issued capability into a new authorization.
            _deny("CONFIRMATION_CAPABILITY_NOT_CONSUMED")
        current_time = int(now_epoch if now_epoch is not None else time.time())
        issued_at = int(payload.get("issued_at_epoch", 0))
        expires_at = int(payload.get("expires_at_epoch", 0))
        if issued_at > current_time + 5 or expires_at < current_time or expires_at - issued_at > MAX_TTL_SECONDS:
            _deny("CONFIRMATION_CAPABILITY_EXPIRED")
        # Keep the monotonic receipt outside the mutable capability directory.
        # Restoring a snapshot of only ``capabilities/human-confirmations``
        # therefore cannot rewind consumption.  A rollback of the entire
        # current-user Runtime remains part of the disclosed same-UID trust
        # boundary and requires a future OS/Host-backed monotonic store.
        receipt_sha256 = _write_consumption_receipt(
            consumption_root,
            payload=payload,
            issued_raw=raw,
            consumed_at_epoch=current_time,
        )
        payload["status"] = "consumed"
        payload["consumed_at_epoch"] = current_time
        payload["consumer_pid"] = os.getpid()
        payload["consumption_receipt_sha256"] = receipt_sha256
        consumed_raw = _json_bytes(payload)
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        if os.write(descriptor, consumed_raw) != len(consumed_raw):
            _deny()
        os.fsync(descriptor)
        return ConsumedConfirmation(payload, _CONSUMED_PROOF)
    except ConfirmationCapabilityError:
        raise
    except (OSError, TypeError, ValueError):
        _deny()
    finally:
        try:
            _unlock_descriptor(descriptor)
        finally:
            os.close(descriptor)


def consume_confirmation_capability(
    config_root: Path,
    **kwargs: Any,
) -> ConsumedConfirmation:
    """Serialize same-process consumers in addition to the cross-process lock."""

    with _PROCESS_CONSUME_LOCK:
        return _consume_confirmation_capability(config_root, **kwargs)


def recover_consumed_confirmation_capability(
    config_root: Path,
    **kwargs: Any,
) -> ConsumedConfirmation:
    """Recover proof only from an already-consumed exact capability."""

    with _PROCESS_CONSUME_LOCK:
        return _consume_confirmation_capability(
            config_root,
            allow_idempotent_recovery=True,
            require_preconsumed=True,
            **kwargs,
        )


def _completed_receipt_matches_intent(
    stored: dict[str, Any],
    receipt: object,
    *,
    approval_ref_sha256: str,
) -> bool:
    """Bind a completed recovery to the complete durable receipt projection."""

    if not isinstance(receipt, dict):
        return False
    intent_id = str(stored.get("intent_id", ""))
    asserted_by = str(stored.get("asserted_by", ""))
    expected = {
        "receipt_id": hashlib.sha256(
            f"write-receipt:{intent_id}".encode("utf-8")
        ).hexdigest()[:32],
        "intent_id": intent_id,
        "writer_protocol_version": stored.get("writer_protocol_version"),
        "actor": stored.get("actor"),
        "session_hash": stored.get("session_hash"),
        "target_rel_path": stored.get("target_rel_path"),
        "target_key": stored.get("target_key"),
        "fencing_token": stored.get("fencing_token"),
        "outcome": "completed",
        "reason_code": stored.get("reason_code"),
        "validation_mode": stored.get("validation_mode"),
        "base_raw_sha256": stored.get("base_raw_sha256"),
        "proposal_raw_sha256": stored.get("proposal_raw_sha256"),
        "proposal_canonical_sha256": stored.get(
            "proposal_canonical_sha256"
        ),
        "final_raw_sha256": stored.get("final_raw_sha256"),
        "final_canonical_sha256": stored.get("final_canonical_sha256"),
        "base_git_head": stored.get("base_git_head"),
        "validated_git_head": stored.get("validated_git_head"),
        "early_commit": stored.get("early_commit"),
        "proposal_commit": stored.get("proposal_commit"),
        "approval_binding_sha256": stored.get("approval_binding_sha256"),
        "approval_ref_sha256": approval_ref_sha256,
        "source_class": stored.get("source_class"),
        "knowledge_kind": stored.get("knowledge_kind"),
        "asserted_by_sha256": (
            hashlib.sha256(asserted_by.encode("utf-8")).hexdigest()
            if asserted_by
            else ""
        ),
        "safety_decision": stored.get("safety_decision"),
        "safety_reason_code": stored.get("safety_reason_code"),
        "safety_input_sha256": stored.get("safety_input_sha256"),
        "safety_input_length": stored.get("safety_input_length"),
        "evidence_ref_sha256": stored.get("evidence_ref_sha256"),
        "operation": stored.get("operation"),
        "target_status": stored.get("target_status"),
        "transition_reason_sha256": stored.get(
            "transition_reason_sha256"
        ),
        # finalize_receipt writes both values from the same transaction time.
        "created_at": stored.get("updated_at"),
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        return False
    if (
        not str(stored.get("validated_at", ""))
        or SHA256_RE.fullmatch(str(stored.get("final_raw_sha256", ""))) is None
        or SHA256_RE.fullmatch(
            str(stored.get("final_canonical_sha256", ""))
        ) is None
        or re.fullmatch(
            r"[0-9a-f]{40}|[0-9a-f]{64}",
            str(receipt.get("git_commit", "")),
        )
        is None
        or re.fullmatch(
            r"(?:[A-Za-z0-9][A-Za-z0-9_.:-]{0,159})?",
            str(receipt.get("detail_code", "")),
        )
        is None
        or not str(receipt.get("created_at", ""))
    ):
        return False
    if bool(stored.get("early_commit")) and receipt.get(
        "git_commit"
    ) != stored.get("proposal_commit"):
        return False
    return True


def recover_consumed_confirmation_handoff(
    config_root: Path,
    *,
    handoff_path: str,
    subject_actor: str,
    raw_task_id: str,
    raw_session_id: str,
) -> dict[str, Any]:
    """Reopen an expired handoff only for an exact preconsumed intent.

    This does not mint or consume authorization.  It requires the immutable
    consumption receipt to pre-exist, then binds that proof to the same durable
    intent that the writer can resume idempotently.  A still-pending intent is
    admitted only for the consume-before-approve crash window; the migration
    layer additionally requires its exact ``prepared`` progress event.
    """

    descriptor, path, payload = _open_handoff(config_root, handoff_path)
    try:
        token = _issued_handoff_token(payload, require_fresh=False)
        try:
            expected = _expected_binding(
                subject_actor=subject_actor,
                raw_task_id=raw_task_id,
                raw_session_id=raw_session_id,
                proposal_id=str(payload.get("proposal_id", "")),
                proposal_raw_sha256=str(
                    payload.get("proposal_raw_sha256", "")
                ),
                proposal_canonical_sha256=str(
                    payload.get("proposal_canonical_sha256", "")
                ),
                target_relative_path=str(
                    payload.get("target_relative_path", "")
                ),
                target_key=str(payload.get("target_key", "")),
                operation=str(payload.get("operation", "")),
                reconcile_action=str(payload.get("reconcile_action", "")),
                fencing_token=int(payload.get("fencing_token", 0) or 0),
            )
        except (TypeError, ValueError):
            _deny("CONFIRMATION_HANDOFF_RECOVERY_INVALID")
        if any(payload.get(key) != value for key, value in expected.items()):
            _deny("CONFIRMATION_HANDOFF_RECOVERY_INVALID")
        consumed = recover_consumed_confirmation_capability(
            config_root,
            capability_path=str(payload.get("capability_path", "")),
            token=token,
            subject_actor=str(expected["subject_actor"]),
            raw_task_id=raw_task_id,
            raw_session_id=raw_session_id,
            proposal_id=str(expected["proposal_id"]),
            proposal_raw_sha256=str(expected["proposal_raw_sha256"]),
            proposal_canonical_sha256=str(
                expected["proposal_canonical_sha256"]
            ),
            target_relative_path=str(expected["target_relative_path"]),
            target_key=str(expected["target_key"]),
            operation=str(expected["operation"]),
            reconcile_action=str(expected["reconcile_action"]),
            fencing_token=int(expected["fencing_token"]),
        )
        if not secrets.compare_digest(
            consumed.capability_id,
            str(payload.get("capability_id", "")),
        ):
            _deny("CONFIRMATION_HANDOFF_RECOVERY_INVALID")

        import agent_memory_intent as write_intent  # Lazy import avoids a cycle.

        try:
            shown = write_intent.show_intent(str(expected["proposal_id"]))
        except (OSError, RuntimeError, ValueError):
            _deny("CONFIRMATION_HANDOFF_RECOVERY_INVALID")
        if not isinstance(shown, dict):
            _deny("CONFIRMATION_HANDOFF_RECOVERY_INVALID")
        stored = shown.get("intent")
        receipt = shown.get("receipt")
        allowed_statuses = {
            "pending", "approved", "bound", "validated", "completed",
        }
        if not isinstance(stored, dict) or str(stored.get("status", "")) not in allowed_statuses:
            _deny("CONFIRMATION_HANDOFF_RECOVERY_INVALID")
        intent_expected = {
            "intent_id": expected["proposal_id"],
            "actor": expected["subject_actor"],
            "session_hash": expected["session_hash"],
            "proposal_raw_sha256": expected["proposal_raw_sha256"],
            "proposal_canonical_sha256": expected[
                "proposal_canonical_sha256"
            ],
            "target_rel_path": expected["target_relative_path"],
            "target_key": expected["target_key"],
            "operation": expected["operation"],
            "reconcile_action": expected["reconcile_action"],
            "fencing_token": expected["fencing_token"],
        }
        if any(stored.get(key) != value for key, value in intent_expected.items()):
            _deny("CONFIRMATION_HANDOFF_RECOVERY_INVALID")
        status = str(stored.get("status", ""))
        reference_sha256 = hashlib.sha256(
            approval_reference(consumed).encode("utf-8")
        ).hexdigest()
        if status == "pending":
            # Approval is one SQLite transaction, so any approval material on
            # a pending row is corruption rather than a recoverable crash
            # window.  A terminal receipt is likewise impossible here.
            if receipt is not None or any(
                stored.get(key) not in {None, ""}
                for key in (
                    "approved_at", "approved_by",
                    "approval_proposal_raw_sha256",
                    "approval_proposal_canonical_sha256",
                    "approval_ref_sha256", "approval_binding_sha256",
                )
            ):
                _deny("CONFIRMATION_HANDOFF_RECOVERY_INVALID")
        else:
            try:
                stored_approval_binding = write_intent._stored_approval_binding(
                    stored
                )
            except (KeyError, RuntimeError, TypeError, ValueError):
                _deny("CONFIRMATION_HANDOFF_RECOVERY_INVALID")
            if (
                not str(stored.get("approved_at", ""))
                or stored.get("approval_proposal_raw_sha256")
                != expected["proposal_raw_sha256"]
                or stored.get("approval_proposal_canonical_sha256")
                != expected["proposal_canonical_sha256"]
                or stored.get("approval_ref_sha256") != reference_sha256
                or stored.get("approval_binding_sha256")
                != stored_approval_binding
                or (
                    _sensitive(
                        str(expected["reconcile_action"]),
                        str(expected["operation"]),
                    )
                    and not write_intent.has_valid_confirmation_capability_approval(
                        stored
                    )
                )
                or (
                    not _sensitive(
                        str(expected["reconcile_action"]),
                        str(expected["operation"]),
                    )
                    and str(stored.get("approved_by", "")) != "user"
                )
            ):
                _deny("CONFIRMATION_HANDOFF_RECOVERY_INVALID")
            if status in {"approved", "bound", "validated"}:
                if receipt is not None:
                    _deny("CONFIRMATION_HANDOFF_RECOVERY_INVALID")
            elif not _completed_receipt_matches_intent(
                stored,
                receipt,
                approval_ref_sha256=reference_sha256,
            ):
                _deny("CONFIRMATION_HANDOFF_RECOVERY_INVALID")
        return {
            **_handoff_public_summary(payload, path),
            **_handoff_public_binding(payload),
            "status": "issued",
            "token": token,
            "consumed_recovery": True,
            "intent_status": str(stored["status"]),
            # Non-secret state is forwarded so the migration orchestrator can
            # select its narrowly audited expired-validated crash lane without
            # probing or weakening ordinary unexpired writes.
            "intent_expires_at": str(stored.get("expires_at", "")),
            "intent_reason_code": str(stored.get("reason_code", "")),
        }
    finally:
        _unlock_descriptor(descriptor)
        os.close(descriptor)


def attests_to(
    confirmation: object,
    *,
    subject_actor: str,
    raw_task_id: str,
    raw_session_id: str,
    proposal_id: str,
    proposal_raw_sha256: str,
    proposal_canonical_sha256: str,
    target_relative_path: str,
    target_key: str,
    operation: str,
    reconcile_action: str,
    fencing_token: int,
) -> bool:
    """Verify that an opaque consumed object covers this exact approval."""

    if not isinstance(confirmation, ConsumedConfirmation) or confirmation._proof is not _CONSUMED_PROOF:
        return False
    try:
        expected = _expected_binding(
            subject_actor=subject_actor,
            raw_task_id=raw_task_id,
            raw_session_id=raw_session_id,
            proposal_id=proposal_id,
            proposal_raw_sha256=proposal_raw_sha256,
            proposal_canonical_sha256=proposal_canonical_sha256,
            target_relative_path=target_relative_path,
            target_key=target_key,
            operation=operation,
            reconcile_action=reconcile_action,
            fencing_token=fencing_token,
        )
    except ValueError:
        return False
    return all(confirmation._binding.get(key) == value for key, value in expected.items())


def approval_reference(confirmation: ConsumedConfirmation) -> str:
    if not isinstance(confirmation, ConsumedConfirmation) or confirmation._proof is not _CONSUMED_PROOF:
        _deny()
    reference_sha256 = str(
        confirmation._binding.get("confirmation_reference_sha256", "")
    )
    if SHA256_RE.fullmatch(reference_sha256) is None:
        _deny()
    return (
        f"human-confirmation-capability:{confirmation.capability_id}:"
        f"confirmation-reference-sha256:{reference_sha256}"
    )


def _read_stdin_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_REQUEST_BYTES:
        _deny("CONFIRMATION_CAPABILITY_REQUEST_INVALID")
    try:
        payload = _strict_json_object(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        _deny("CONFIRMATION_CAPABILITY_REQUEST_INVALID")
    return payload


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Explicit manual/host issuer for one sensitive Agent Memory intent.",
        allow_abbrev=False,
    )
    parser.add_argument("--issuer-actor", choices=(HUMAN_ISSUER_ACTOR,), required=True)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("action", choices=("issue",))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        assert_runtime_ready("confirmation-capability")
        request = _read_stdin_request()
        subject_actor = str(request.get("subject_actor", "")).strip().casefold()
        session_id = str(request.get("session_id", "")).strip() or os.environ.get(
            "AGENT_MEMORY_SESSION_ID", ""
        ).strip()
        # The human wrapper's own ephemeral invocation nonce is not the task
        # being approved.  When the request omits a distinct task ID, the
        # reviewed migration's explicit session is the reproducible binding.
        task_id = str(request.get("task_id", "")).strip() or session_id
        payload = issue_for_intent_handoff(
            expand_path(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory")),
            issuer_actor=args.issuer_actor,
            subject_actor=subject_actor,
            raw_task_id=task_id,
            raw_session_id=session_id,
            proposal_id=str(request.get("proposal_id", "")),
            confirmation_reference=str(request.get("confirmation_reference", "")),
            ttl_seconds=int(request.get("ttl_seconds", DEFAULT_TTL_SECONDS)),
        )
        result: dict[str, Any] = {
            "ok": True,
            "status": "issued",
            "host_ui_integrated": False,
            "same_uid_trust_boundary": True,
            "cryptographic_user_presence": False,
            **payload,
        }
    except (ConfirmationCapabilityError, RuntimeTransitionError, ValueError) as exc:
        result = {
            "ok": False,
            "status": "blocked",
            "reason_code": getattr(
                exc,
                "reason_code",
                "RUNTIME_TRANSITION_INCOMPLETE"
                if isinstance(exc, RuntimeTransitionError)
                else "CONFIRMATION_CAPABILITY_REQUEST_INVALID",
            ),
            "host_ui_integrated": False,
        }
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")) if args.json else f"confirmation_capability={result['status']}")
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
