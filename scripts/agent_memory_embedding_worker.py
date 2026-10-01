#!/usr/bin/env python3
"""Private, adaptive query-embedding worker for Agent Memory.

The worker owns only the sentence-transformer model.  It never opens the Zvec
collection and never persists query text or vectors.  A small versioned JSON
protocol over an owner-only Unix socket lets interactive retrieval reuse the
model without paying its process/model startup cost for every query.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from agent_memory_env import RuntimeTransitionError, assert_runtime_ready, env_value, expand_path
from agent_memory_lock import try_lock, unlock


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 64 * 1024
DEFAULT_IDLE_SECONDS = int(env_value("EMBEDDING_WORKER_IDLE_SECONDS", "600"))
DEFAULT_COLD_TIMEOUT = float(env_value("EMBEDDING_WORKER_COLD_TIMEOUT_SECONDS", "12"))
DEFAULT_WARM_TIMEOUT = float(env_value("EMBEDDING_WORKER_WARM_TIMEOUT_SECONDS", "2"))
DEFAULT_MODEL = env_value("EMBEDDING_MODEL", "google/embeddinggemma-300m")
DEFAULT_MODEL_REVISION = env_value("MODEL_REVISION", "")
DEFAULT_MODEL_MANIFEST = expand_path(
    env_value(
        "MODEL_MANIFEST",
        str(RUNTIME_ROOT / ".agent-memory" / "models" / "embeddinggemma-300m" / "model-manifest.json"),
    )
).resolve()
DEFAULT_EMBEDDING_DIM = int(env_value("EMBEDDING_DIM", "768"))
DEFAULT_DEVICE = env_value("EMBEDDING_DEVICE", "cpu")
DEFAULT_REQUIRE_LOCAL_MODEL = env_value("REQUIRE_LOCAL_MODEL", "false").strip().casefold() in {
    "1", "true", "yes", "on",
}
DEFAULT_SOCKET_BASE = expand_path(
    env_value(
        "EMBEDDING_WORKER_SOCKET",
        str(RUNTIME_ROOT / ".agent-memory" / "run" / "embedding.sock"),
    )
).resolve()


class WorkerError(RuntimeError):
    """A content-free worker failure safe to surface as degraded metadata."""

    def __init__(self, code: str, *, restart_count: int = 0) -> None:
        super().__init__(code)
        self.code = code
        self.restart_count = 1 if restart_count else 0


BUSY_WORKER_ERRORS = frozenset(
    {"WORKER_CONNECT_BUSY", "WORKER_RESPONSE_TIMEOUT", "WORKER_REQUEST_EXPIRED", "WORKER_BUSY"}
)
RESTARTABLE_WORKER_ERRORS = frozenset(
    {
        "WORKER_CONNECT_UNAVAILABLE",
        "WORKER_RESPONSE_IO_FAILED",
        "WORKER_RESPONSE_INVALID",
        "WORKER_RESPONSE_IDENTITY_MISMATCH",
        # Compatibility for callers/tests built against protocol v1.
        "WORKER_UNAVAILABLE",
    }
)


def runtime_manifest_sha256() -> str:
    path = RUNTIME_ROOT / "config" / "runtime-manifest.json"
    try:
        payload = path.read_bytes()
    except OSError:
        # Source checkouts intentionally have no managed manifest.  Binding the
        # lexical runtime root still prevents one checkout from reusing another
        # checkout's worker socket.
        payload = f"source-checkout:{RUNTIME_ROOT}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def resolve_model_binding(
    model: str,
    revision: str,
    embedding_dim: int,
    model_manifest: Path = DEFAULT_MODEL_MANIFEST,
) -> tuple[str, str]:
    """Return an immutable model revision and optional verified manifest hash.

    A bare model id is safe only when its revision is an immutable commit hash.
    A private local snapshot may instead be pinned by a well-formed manifest
    containing real key-file hashes. The manifest's own SHA is included in the
    Worker/index identity, while Doctor remains responsible for the expensive
    full-file verification.
    """

    configured_revision = str(revision or "").strip()
    manifest_revision = ""
    manifest_sha256 = ""
    path = Path(model_manifest).expanduser().resolve()
    if path.exists() or path.is_symlink():
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise WorkerError("MODEL_MANIFEST_UNREADABLE") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise WorkerError("MODEL_MANIFEST_UNSAFE")
        if metadata.st_size <= 0 or metadata.st_size > 1024 * 1024:
            raise WorkerError("MODEL_MANIFEST_INVALID")
        try:
            payload = path.read_bytes()
            decoded = json.loads(payload.decode("utf-8", errors="strict"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkerError("MODEL_MANIFEST_INVALID") from exc
        if not isinstance(decoded, dict):
            raise WorkerError("MODEL_MANIFEST_INVALID")
        manifest_revision = str(decoded.get("revision") or "").strip()
        files = decoded.get("files")
        if not manifest_revision or not isinstance(files, dict) or not files:
            raise WorkerError("MODEL_MANIFEST_INVALID")
        for entry in files.values():
            expected_hash = entry.get("sha256") if isinstance(entry, dict) else None
            if not isinstance(expected_hash, str) or re.fullmatch(
                r"[0-9a-fA-F]{64}", expected_hash
            ) is None:
                raise WorkerError("MODEL_MANIFEST_INVALID")
        manifest_dim = decoded.get("embedding_dim")
        if manifest_dim is not None:
            try:
                if int(manifest_dim) != int(embedding_dim):
                    raise WorkerError("MODEL_MANIFEST_DIMENSION_MISMATCH")
            except (TypeError, ValueError) as exc:
                raise WorkerError("MODEL_MANIFEST_INVALID") from exc
        if configured_revision and configured_revision != manifest_revision:
            raise WorkerError("MODEL_REVISION_MISMATCH")
        raw_root = str(decoded.get("root") or "").strip()
        model_path = Path(model).expanduser()
        if model_path.is_absolute() and raw_root:
            manifest_root = Path(os.path.expandvars(raw_root)).expanduser().resolve()
            if model_path.resolve() != manifest_root:
                raise WorkerError("MODEL_MANIFEST_ROOT_MISMATCH")
        manifest_sha256 = hashlib.sha256(payload).hexdigest()

    resolved_revision = configured_revision or manifest_revision
    if not resolved_revision:
        raise WorkerError("MODEL_REVISION_REQUIRED")
    if not manifest_sha256 and re.fullmatch(
        r"[0-9a-fA-F]{40,64}", resolved_revision
    ) is None:
        raise WorkerError("MODEL_REVISION_NOT_PINNED")
    return resolved_revision, manifest_sha256


def model_binding_id(
    model: str,
    revision: str,
    embedding_dim: int,
    model_manifest_sha256: str,
) -> str:
    payload = json.dumps(
        {
            "model": model,
            "revision": revision,
            "embedding_dim": int(embedding_dim),
            "model_manifest_sha256": model_manifest_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def worker_identity(
    model: str,
    revision: str,
    embedding_dim: int,
    manifest_sha256: str,
    model_manifest_sha256: str = "",
) -> str:
    payload = json.dumps(
        {
            "protocol": PROTOCOL_VERSION,
            "model": model,
            "revision": revision,
            "embedding_dim": int(embedding_dim),
            "runtime_manifest_sha256": manifest_sha256,
            "model_manifest_sha256": model_manifest_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def socket_path_for(identity: str, base: Path = DEFAULT_SOCKET_BASE) -> Path:
    suffix = identity[:12]
    return base.with_name(f"{base.stem}-{suffix}{base.suffix or '.sock'}")


def _ensure_private_socket_parent(path: Path) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise WorkerError("WORKER_SOCKET_PARENT_UNSAFE")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise WorkerError("WORKER_SOCKET_PARENT_OWNER_MISMATCH")
    os.chmod(parent, 0o700)


def _receive_request(connection: socket.socket) -> dict[str, Any]:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = connection.recv(min(8192, MAX_REQUEST_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_REQUEST_BYTES:
            raise WorkerError("WORKER_REQUEST_TOO_LARGE")
        if b"\n" in chunk:
            break
    raw = b"".join(chunks).split(b"\n", 1)[0]
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerError("WORKER_REQUEST_INVALID") from exc
    if not isinstance(payload, dict):
        raise WorkerError("WORKER_REQUEST_INVALID")
    return payload


def _send_response(connection: socket.socket, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    connection.sendall(encoded)


def _safe_send_response(connection: socket.socket, payload: dict[str, Any]) -> bool:
    """Do not let a timed-out client terminate the long-lived Worker."""

    try:
        _send_response(connection, payload)
        return True
    except (OSError, socket.timeout):
        return False


def _normalize_vector(
    raw_vector: object,
    embedding_dim: int,
    *,
    require_list: bool,
) -> list[float]:
    """Return a protocol-safe finite vector or fail with a stable reason code.

    Python's JSON codec accepts ``NaN`` and ``Infinity`` by default even though
    neither is valid JSON.  Reject them both before the Worker serializes a
    model result and after the client decodes a response, so a malformed or
    older Worker can never pass non-finite values into Zvec.
    """

    if require_list and not isinstance(raw_vector, list):
        raise WorkerError("WORKER_VECTOR_INVALID")
    if isinstance(raw_vector, (str, bytes, bytearray, dict)):
        raise WorkerError("WORKER_VECTOR_INVALID")
    try:
        if len(raw_vector) != int(embedding_dim):  # type: ignore[arg-type]
            raise WorkerError("WORKER_VECTOR_INVALID")
        normalized = [float(item) for item in raw_vector]  # type: ignore[union-attr]
    except WorkerError:
        raise
    except (TypeError, ValueError, OverflowError) as exc:
        raise WorkerError("WORKER_VECTOR_INVALID") from exc
    if any(not math.isfinite(item) for item in normalized):
        raise WorkerError("WORKER_VECTOR_NONFINITE")
    return normalized


def _rotate_stale_socket(path: Path) -> None:
    """Preserve a stale socket entry instead of deleting it.

    The user's global policy forbids deletion.  A stale Unix socket is therefore
    renamed into an owner-only diagnostic artifact before the new worker binds.
    """

    if not path.exists() and not path.is_symlink():
        return
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise WorkerError("WORKER_SOCKET_SYMLINK_FORBIDDEN")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise WorkerError("WORKER_SOCKET_OWNER_MISMATCH")
    while True:
        stale = path.with_name(
            f"{path.name}.stale-{time.time_ns()}-{os.getpid()}-{uuid.uuid4().hex}"
        )
        if not stale.exists() and not stale.is_symlink():
            break
    # A UUID plus an explicit existence check preserves every prior artifact;
    # os.rename is used here to make the non-overwrite intent visible rather
    # than treating the destination as a replaceable backup.
    os.rename(path, stale)


def _request(path: Path, request: dict[str, Any], timeout: float) -> dict[str, Any]:
    # Unix-socket peers share this host's monotonic clock. One deadline covers
    # connect, send and every response fragment; a trickle must not repeatedly
    # renew the warm-query budget. The server can also discard expired queued
    # work without spending inference time on clients which already gave up.
    deadline = time.monotonic() + max(float(timeout), 0.05)
    encoded = json.dumps({**request, "deadline_monotonic": deadline}, ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > MAX_REQUEST_BYTES:
        raise WorkerError("WORKER_REQUEST_TOO_LARGE")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def set_remaining_timeout() -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout()
        client.settimeout(remaining)

    try:
        try:
            set_remaining_timeout()
            client.connect(str(path))
        except socket.timeout as exc:
            raise WorkerError("WORKER_CONNECT_BUSY") from exc
        except OSError as exc:
            if exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK, errno.ETIMEDOUT}:
                raise WorkerError("WORKER_CONNECT_BUSY") from exc
            raise WorkerError("WORKER_CONNECT_UNAVAILABLE") from exc
        try:
            set_remaining_timeout()
            client.sendall(encoded)
            chunks: list[bytes] = []
            total = 0
            while True:
                set_remaining_timeout()
                chunk = client.recv(min(64 * 1024, MAX_REQUEST_BYTES * 16 + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_REQUEST_BYTES * 16:
                    raise WorkerError("WORKER_RESPONSE_TOO_LARGE")
                if b"\n" in chunk:
                    break
        except socket.timeout as exc:
            # A connected but slow Worker is busy, not stale. Never rotate it
            # or launch another model merely because this caller timed out.
            raise WorkerError("WORKER_RESPONSE_TIMEOUT") from exc
        except OSError as exc:
            raise WorkerError("WORKER_RESPONSE_IO_FAILED") from exc
    finally:
        client.close()
    try:
        payload = json.loads(b"".join(chunks).split(b"\n", 1)[0].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerError("WORKER_RESPONSE_INVALID") from exc
    if not isinstance(payload, dict):
        raise WorkerError("WORKER_RESPONSE_INVALID")
    if not payload.get("ok"):
        raise WorkerError(str(payload.get("error") or "WORKER_REQUEST_FAILED"))
    if (
        payload.get("protocol_version") != PROTOCOL_VERSION
        or payload.get("identity") != request.get("identity")
    ):
        raise WorkerError("WORKER_RESPONSE_IDENTITY_MISMATCH")
    return payload


def _launch_lock(path: Path, timeout: float):
    class _Lock:
        def __enter__(self) -> None:
            self.handle = path.with_suffix(path.suffix + ".launch.lock").open("a+", encoding="utf-8")
            deadline = time.monotonic() + max(float(timeout), 0.05)
            while not try_lock(self.handle, exclusive=True):
                if time.monotonic() >= deadline:
                    self.handle.close()
                    raise WorkerError("WORKER_LAUNCH_LOCK_TIMEOUT")
                time.sleep(0.05)

        def __exit__(self, *_args: object) -> None:
            unlock(self.handle)
            self.handle.close()

    return _Lock()


def _start_worker(
    path: Path,
    *,
    identity: str,
    model: str,
    revision: str,
    embedding_dim: int,
    idle_seconds: int,
    model_manifest: Path,
) -> subprocess.Popen[bytes]:
    _ensure_private_socket_parent(path)
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--serve",
        "--socket",
        str(path),
        "--identity",
        identity,
        "--model",
        model,
        "--model-revision",
        revision,
        "--model-manifest",
        str(model_manifest),
        "--embedding-dim",
        str(embedding_dim),
        "--idle-seconds",
        str(idle_seconds),
    ]
    environment = os.environ.copy()
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        environment.pop(key, None)
    environment.setdefault("HF_HUB_OFFLINE", "1")
    environment.setdefault("TRANSFORMERS_OFFLINE", "1")
    # A query Worker serves one short input at a time. Unbounded BLAS/OpenMP
    # pools compete with the host and other inference runtimes, hurting tail
    # latency. Scope the fixed two-thread budget to this child only, before
    # any numerical library is imported; model/revision and math stay intact.
    for key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "VECLIB_MAXIMUM_THREADS"):
        environment[key] = "2"
    environment["TOKENIZERS_PARALLELISM"] = "false"
    return subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        start_new_session=True,
    )


def _terminate_failed_launch(
    process: subprocess.Popen[bytes],
    path: Path,
    *,
    grace_seconds: float = 0.5,
) -> bool:
    """Stop and reap only the Worker session created by this invocation.

    ``_start_worker`` always uses ``start_new_session=True``.  Its PID is
    therefore also the new process-group ID, which lets a failed cold start
    stop model-loader descendants as well as the Python session leader.  This
    helper is never called for a successfully reused Worker because the caller
    does not own that process.

    The live socket is rotated only after the owned session leader is known to
    be stopped.  That preserves diagnostic evidence without leaving a dead
    endpoint at the canonical path or creating an opportunity for a second
    Worker while the first is still alive.
    """

    stopped = False
    try:
        raw_pid = getattr(process, "pid", 0)
        pid = int(raw_pid) if isinstance(raw_pid, int) else 0
        pgid = pid
        leader_alive = process.poll() is None
        # _start_worker creates a new session, so this invocation owns PGID
        # == PID even if the short-lived Python leader exits before cleanup
        # observes it. Model-loader descendants can remain in that group.
        group_owned = pgid > 0 and os.name != "nt"
        if leader_alive and pgid > 0 and os.name != "nt":
            try:
                group_owned = os.getpgid(pid) == pgid
            except ProcessLookupError:
                leader_alive = False
            except OSError:
                group_owned = False

        def owned_group_alive() -> bool:
            if not group_owned:
                return False
            try:
                os.killpg(pgid, 0)
                return True
            except ProcessLookupError:
                return False
            except PermissionError:
                return True
            except OSError:
                return False

        if leader_alive or owned_group_alive():
            try:
                if group_owned:
                    os.killpg(pgid, signal.SIGTERM)
                else:  # Defensive fallback for non-POSIX tests/platforms.
                    process.terminate()
            except (OSError, ProcessLookupError):
                pass
        try:
            process.wait(timeout=max(float(grace_seconds), 0.05))
        except subprocess.TimeoutExpired:
            pass
        except (OSError, ChildProcessError):
            pass

        leader_alive = process.poll() is None
        group_alive = owned_group_alive()
        if leader_alive or group_alive:
            try:
                if group_owned:
                    os.killpg(pgid, signal.SIGKILL)
                else:
                    process.kill()
            except (OSError, ProcessLookupError):
                pass
            try:
                process.wait(timeout=max(float(grace_seconds), 0.05))
            except (subprocess.TimeoutExpired, OSError, ChildProcessError):
                pass
        if group_owned:
            group_deadline = time.monotonic() + max(float(grace_seconds), 0.05)
            while owned_group_alive() and time.monotonic() < group_deadline:
                time.sleep(0.01)
        stopped = process.poll() is not None and not owned_group_alive()
    except (OSError, TypeError, ValueError):
        stopped = process.poll() is not None

    if stopped:
        try:
            _rotate_stale_socket(path)
        except (OSError, WorkerError):
            # The failed result remains fail-closed.  In particular, never
            # rotate an unsafe or foreign-owned path merely to hide cleanup
            # trouble.
            pass
    return stopped


def embed_query(
    query: str,
    *,
    model: str = DEFAULT_MODEL,
    revision: str = DEFAULT_MODEL_REVISION,
    embedding_dim: int = DEFAULT_EMBEDDING_DIM,
    cold_timeout: float = DEFAULT_COLD_TIMEOUT,
    warm_timeout: float = DEFAULT_WARM_TIMEOUT,
    idle_seconds: int = DEFAULT_IDLE_SECONDS,
    socket_base: Path = DEFAULT_SOCKET_BASE,
    model_manifest: Path = DEFAULT_MODEL_MANIFEST,
) -> tuple[list[float], dict[str, Any]]:
    revision, model_manifest_sha = resolve_model_binding(
        model,
        revision,
        embedding_dim,
        model_manifest,
    )
    manifest_sha = runtime_manifest_sha256()
    identity = worker_identity(
        model,
        revision,
        embedding_dim,
        manifest_sha,
        model_manifest_sha,
    )
    path = socket_path_for(identity, socket_base)
    _ensure_private_socket_parent(path)
    request = {
        "protocol_version": PROTOCOL_VERSION,
        "operation": "embed_query",
        "identity": identity,
        "query": query,
    }
    started = time.monotonic()
    stale_at_start = path.exists() or path.is_symlink()
    overall_deadline = started + (
        min(max(float(cold_timeout), 0.1), 3.0)
        if stale_at_start
        else max(float(cold_timeout), 0.1)
    )
    restart_count = 0
    launched_process: subprocess.Popen[bytes] | None = None
    launched_worker_accepted = False

    def remaining() -> float:
        return max(overall_deadline - time.monotonic(), 0.0)

    def bounded_timeout(requested: float) -> float:
        available = remaining()
        if available <= 0:
            raise WorkerError(
                "WORKER_RECOVERY_DEADLINE_EXCEEDED",
                restart_count=restart_count,
            )
        return min(max(float(requested), 0.05), available)

    try:
        try:
            response = _request(path, request, bounded_timeout(warm_timeout))
            worker_status = "reused"
            startup = "warm"
        except WorkerError as first_error:
            if first_error.code in BUSY_WORKER_ERRORS:
                raise WorkerError("WORKER_BUSY") from first_error
            if first_error.code not in RESTARTABLE_WORKER_ERRORS:
                raise
            with _launch_lock(path, bounded_timeout(remaining())):
                try:
                    response = _request(path, request, bounded_timeout(warm_timeout))
                    worker_status = "reused"
                    startup = "warm_after_wait"
                except WorkerError as retry_error:
                    if retry_error.code in BUSY_WORKER_ERRORS:
                        raise WorkerError("WORKER_BUSY") from retry_error
                    if retry_error.code not in RESTARTABLE_WORKER_ERRORS:
                        raise
                    replacing_stale_worker = path.exists() or path.is_symlink()
                    restart_count = 1 if replacing_stale_worker else 0
                    _rotate_stale_socket(path)
                    launched_process = _start_worker(
                        path,
                        identity=identity,
                        model=model,
                        revision=revision,
                        embedding_dim=embedding_dim,
                        idle_seconds=idle_seconds,
                        model_manifest=model_manifest,
                    )
                    # A genuine first load receives the full cold-start
                    # budget. A crashed/stale worker gets exactly one bounded
                    # restart so lexical fallback is visible in about three
                    # seconds instead of hanging for the full model timeout.
                    last_error: WorkerError | None = None
                    while remaining() > 0:
                        if launched_process.poll() is not None:
                            raise WorkerError("WORKER_START_FAILED", restart_count=restart_count)
                        try:
                            response = _request(
                                path,
                                request,
                                # The first connected inference loads the model;
                                # it receives the remaining cold-start budget,
                                # while already-connected warm calls retain the
                                # strict warm timeout above.
                                bounded_timeout(remaining()),
                            )
                            worker_status = "restarted" if restart_count else "started"
                            startup = "cold"
                            break
                        except WorkerError as exc:
                            last_error = exc
                            if (
                                exc.code not in RESTARTABLE_WORKER_ERRORS
                                and exc.code not in BUSY_WORKER_ERRORS
                            ):
                                raise
                            time.sleep(0.05)
                    else:
                        raise WorkerError("WORKER_COLD_TIMEOUT", restart_count=restart_count) from last_error
        try:
            normalized = _normalize_vector(
                response.get("vector"),
                embedding_dim,
                require_list=True,
            )
        except WorkerError as exc:
            raise WorkerError(exc.code, restart_count=restart_count) from exc
        launched_worker_accepted = True
    except WorkerError as exc:
        exc.restart_count = max(exc.restart_count, restart_count)
        raise
    finally:
        if launched_process is not None and not launched_worker_accepted:
            _terminate_failed_launch(launched_process, path)
    return normalized, {
        "worker": startup,
        "worker_status": worker_status,
        "worker_restart_count": restart_count,
        "worker_identity": identity,
        "model": model,
        "model_revision": revision,
        "embedding_dim": int(embedding_dim),
        "runtime_manifest_sha256": manifest_sha,
        "model_manifest_sha256": model_manifest_sha,
        "model_binding_id": model_binding_id(
            model,
            revision,
            embedding_dim,
            model_manifest_sha,
        ),
        "duration_ms": round((time.monotonic() - started) * 1000),
    }


def shutdown_worker(
    *,
    model: str = DEFAULT_MODEL,
    revision: str = DEFAULT_MODEL_REVISION,
    embedding_dim: int = DEFAULT_EMBEDDING_DIM,
    socket_base: Path = DEFAULT_SOCKET_BASE,
    model_manifest: Path = DEFAULT_MODEL_MANIFEST,
    timeout: float = DEFAULT_WARM_TIMEOUT,
) -> bool:
    """Ask one exactly identified Worker to exit without launching a Worker.

    Callers must provide the same socket namespace and immutable model binding
    used to launch the Worker.  This is primarily used by isolated lifecycle
    probes; it never scans for, signals, or terminates a different Worker.
    """

    resolved_revision, model_manifest_sha = resolve_model_binding(
        model,
        revision,
        embedding_dim,
        model_manifest,
    )
    identity = worker_identity(
        model,
        resolved_revision,
        embedding_dim,
        runtime_manifest_sha256(),
        model_manifest_sha,
    )
    path = socket_path_for(identity, socket_base)
    response = _request(
        path,
        {
            "protocol_version": PROTOCOL_VERSION,
            "operation": "shutdown",
            "identity": identity,
        },
        max(float(timeout), 0.05),
    )
    return bool(response.get("shutdown"))


def serve(
    path: Path,
    *,
    identity: str,
    model: str,
    revision: str,
    embedding_dim: int,
    idle_seconds: int,
    model_manifest: Path = DEFAULT_MODEL_MANIFEST,
    embedder_factory: Callable[[], Any] | None = None,
) -> int:
    revision, model_manifest_sha = resolve_model_binding(
        model,
        revision,
        embedding_dim,
        model_manifest,
    )
    expected_identity = worker_identity(
        model,
        revision,
        embedding_dim,
        runtime_manifest_sha256(),
        model_manifest_sha,
    )
    if identity != expected_identity:
        raise WorkerError("WORKER_IDENTITY_MISMATCH")
    _ensure_private_socket_parent(path)
    _rotate_stale_socket(path)
    if embedder_factory is None:
        from agent_memory_zvec_index import EmbeddingGemmaEmbedder

        embedder_factory = lambda: EmbeddingGemmaEmbedder(
            model,
            embedding_dim,
            DEFAULT_DEVICE,
            "",
            DEFAULT_REQUIRE_LOCAL_MODEL,
            revision,
        )
    embedder = embedder_factory()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
        os.chmod(path, 0o600)
        server.listen(8)
        server.settimeout(min(max(float(idle_seconds), 0.1), 1.0))
        last_request = time.monotonic()
        while time.monotonic() - last_request < max(float(idle_seconds), 0.1):
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(2.0)
                last_request = time.monotonic()
                try:
                    request = _receive_request(connection)
                    if (
                        request.get("protocol_version") != PROTOCOL_VERSION
                        or request.get("identity") != identity
                    ):
                        raise WorkerError("WORKER_REQUEST_INVALID")
                    operation = request.get("operation")
                    if operation == "shutdown":
                        _safe_send_response(
                            connection,
                            {
                                "ok": True,
                                "protocol_version": PROTOCOL_VERSION,
                                "identity": expected_identity,
                                "shutdown": True,
                            },
                        )
                        return 0
                    if operation != "embed_query" or not isinstance(
                        request.get("query"), str
                    ):
                        raise WorkerError("WORKER_REQUEST_INVALID")
                    deadline = request.get("deadline_monotonic")
                    if deadline is not None:
                        if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
                                or not math.isfinite(deadline) or deadline <= 0):
                            raise WorkerError("WORKER_REQUEST_INVALID")
                        if time.monotonic() >= deadline:
                            raise WorkerError("WORKER_REQUEST_EXPIRED")
                    vector = _normalize_vector(
                        embedder.embed_query(str(request["query"])),
                        embedding_dim,
                        require_list=False,
                    )
                    _safe_send_response(
                        connection,
                        {
                            "ok": True,
                            "protocol_version": PROTOCOL_VERSION,
                            "identity": expected_identity,
                            "vector": vector,
                        },
                    )
                except WorkerError as exc:
                    _safe_send_response(
                        connection,
                        {
                            "ok": False,
                            "protocol_version": PROTOCOL_VERSION,
                            "identity": expected_identity,
                            "error": str(exc),
                        },
                    )
                except Exception:
                    _safe_send_response(
                        connection,
                        {
                            "ok": False,
                            "protocol_version": PROTOCOL_VERSION,
                            "identity": expected_identity,
                            "error": "WORKER_EMBEDDING_FAILED",
                        },
                    )
                finally:
                    # Do not retain the last query/vector in this long-lived
                    # frame throughout the ten-minute idle interval.
                    request = None
                    vector = None
        return 0
    finally:
        server.close()
        # A clean idle exit rotates its closed socket immediately.  The next
        # query therefore receives a normal cold-start budget and is not
        # misclassified as a crashed-worker restart.  Crash leftovers remain
        # at the live socket path and take the bounded one-restart path.
        _rotate_stale_socket(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Adaptive private query-embedding worker.")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--socket", default=str(DEFAULT_SOCKET_BASE))
    parser.add_argument("--identity", default="")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--model-revision", default=DEFAULT_MODEL_REVISION)
    parser.add_argument("--model-manifest", default=str(DEFAULT_MODEL_MANIFEST))
    parser.add_argument("--embedding-dim", type=int, default=DEFAULT_EMBEDDING_DIM)
    parser.add_argument("--idle-seconds", type=int, default=DEFAULT_IDLE_SECONDS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.serve or not args.identity:
        print("WORKER_SERVE_ARGUMENTS_REQUIRED", file=sys.stderr)
        return 2
    try:
        assert_runtime_ready("zvec")
        return serve(
            Path(args.socket).expanduser().resolve(),
            identity=args.identity,
            model=args.model,
            revision=args.model_revision,
            embedding_dim=max(int(args.embedding_dim), 1),
            idle_seconds=max(int(args.idle_seconds), 1),
            model_manifest=Path(args.model_manifest).expanduser().resolve(),
        )
    except RuntimeTransitionError:
        return 2
    except WorkerError:
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
