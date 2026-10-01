from __future__ import annotations

import os
import ast
import json
import sqlite3
import hashlib
import re
import datetime as dt
import shlex
import stat
import subprocess
import sys
import threading
import time
from functools import lru_cache
from pathlib import Path
from typing import Any


_MODULE_PATH = Path(os.path.abspath(__file__))
_LEXICAL_RUNTIME_ROOT = _MODULE_PATH.parent.parent
for _bootstrap_path, _bootstrap_kind in (
    (_LEXICAL_RUNTIME_ROOT, "directory"),
    (_MODULE_PATH.parent, "directory"),
    (_MODULE_PATH, "file"),
    (_MODULE_PATH.parent / "agent_memory_state.py", "file"),
):
    try:
        _bootstrap_stat = _bootstrap_path.lstat()
    except FileNotFoundError as exc:  # pragma: no cover - import cannot normally reach this branch
        raise RuntimeError(f"RUNTIME_BOOTSTRAP_PATH_MISSING: {_bootstrap_path}") from exc
    if stat.S_ISLNK(_bootstrap_stat.st_mode):
        raise RuntimeError(f"RUNTIME_BOOTSTRAP_SYMLINK_FORBIDDEN: {_bootstrap_path}")
    if _bootstrap_kind == "directory" and not stat.S_ISDIR(_bootstrap_stat.st_mode):
        raise RuntimeError(f"RUNTIME_BOOTSTRAP_DIRECTORY_INVALID: {_bootstrap_path}")
    if _bootstrap_kind == "file" and not stat.S_ISREG(_bootstrap_stat.st_mode):
        raise RuntimeError(f"RUNTIME_BOOTSTRAP_FILE_INVALID: {_bootstrap_path}")

from agent_memory_state import (
    STATE_SCHEMA_VERSION,
    StateSecurityError,
    absolute_path,
    assert_no_symlink_beneath,
    runtime_python_attestation,
    runtime_python_attestation_matches,
    secure_sqlite_connect,
    secure_read_bytes_and_stat_beneath,
    secure_read_bytes_beneath,
    secure_sha256_beneath,
)
from agent_memory_host_automation import classify_claude_hooks

try:
    import tomllib
except ImportError:  # pragma: no cover - Python 3.10 fallback for import-time clarity
    tomllib = None  # type: ignore[assignment]


RUNTIME_ROOT = _LEXICAL_RUNTIME_ROOT
DEFAULT_HOME = Path.home()
LOCAL_PATH_DEFAULTS: dict[str, tuple[str, ...]] = {
    "CONFIG_ROOT": (),
    "STATE_DB": ("state.sqlite",),
    "AUDIT_DB": ("audit_decisions.sqlite",),
    "CLOSEOUT_LOG": ("logs", "closeout.jsonl"),
    "AUDIT_RUN_LOG": ("logs", "audit_runs.jsonl"),
    "AUDIT_REPORT": ("reports", "latest-audit.json"),
    "INVARIANTS": ("config", "system-invariants.json"),
    "VECTOR_DIR": ("zvec", "memory_chunks_embeddinggemma_768"),
    "ZVEC_LOCK": ("locks", "zvec.lock"),
    "MODEL_MANIFEST": ("models", "embeddinggemma-300m", "model-manifest.json"),
    "DEPENDENCY_LOCK": ("requirements-vector.lock",),
    "EMBEDDING_WORKER_SOCKET": ("run", "embedding.sock"),
    "SHADOW_STATE_DIR": ("shadow",),
}
CONFIG_KEYS: dict[str, tuple[str, ...]] = {
    "ROOT": ("memory_root",),
    "GIT_ROOT": ("git_root",),
    "CONFIG_ROOT": ("config_root",),
    "STATE_DB": ("state_db",),
    "AUDIT_DB": ("audit_db",),
    "CLOSEOUT_LOG": ("closeout_log",),
    "AUDIT_RUN_LOG": ("audit_run_log",),
    "AUDIT_REPORT": ("audit_report",),
    "INVARIANTS": ("invariants_file",),
    "PYTHON": ("python",),
    "USER_ID": ("user_id",),
    "AGENT_ID": ("agent_id",),
    "APP_ID": ("app_id",),
    "VECTOR_DIR": ("semantic_retrieval", "vector_dir"),
    "EMBEDDING_MODEL": ("semantic_retrieval", "embedding_model"),
    "EMBEDDING_DIM": ("semantic_retrieval", "embedding_dim"),
    "EMBEDDING_DEVICE": ("semantic_retrieval", "embedding_device"),
    "ZVEC_PYTHON": ("semantic_retrieval", "python"),
    "ZVEC_LOCK": ("semantic_retrieval", "lock_path"),
    "REQUIRE_LOCAL_MODEL": ("semantic_retrieval", "require_local_model"),
    "MODEL_MANIFEST": ("semantic_retrieval", "model_manifest"),
    "MODEL_REVISION": ("semantic_retrieval", "model_revision"),
    "DEPENDENCY_LOCK": ("semantic_retrieval", "dependency_lock"),
    "EMBEDDING_WORKER_SOCKET": ("semantic_retrieval", "embedding_worker_socket"),
    "EMBEDDING_WORKER_IDLE_SECONDS": ("semantic_retrieval", "embedding_worker_idle_seconds"),
    "EMBEDDING_WORKER_COLD_TIMEOUT_SECONDS": ("semantic_retrieval", "embedding_worker_cold_timeout_seconds"),
    "EMBEDDING_WORKER_WARM_TIMEOUT_SECONDS": ("semantic_retrieval", "embedding_worker_warm_timeout_seconds"),
    "SEMANTIC_ENABLED": ("semantic_retrieval", "enabled"),
    "SEMANTIC_MODE": ("semantic_retrieval", "semantic_mode"),
    "RANKING_VERSION": ("semantic_retrieval", "ranking_version"),
    "ZVEC_LOCK_TIMEOUT_SECONDS": ("semantic_retrieval", "zvec_lock_timeout_seconds"),
    "ZVEC_MAX_DISTANCE": ("semantic_retrieval", "zvec_max_distance"),
    "CANDIDATE_POOL_MIN": ("semantic_retrieval", "candidate_pool_min"),
    "CANDIDATE_POOL_FACTOR": ("semantic_retrieval", "candidate_pool_factor"),
    "CANDIDATE_POOL_SCOPE_MIN": ("semantic_retrieval", "candidate_pool_scope_min"),
    "CANDIDATE_POOL_MAX": ("semantic_retrieval", "candidate_pool_max"),
    "RUN_VECTOR_INDEX_AFTER_CLOSEOUT": ("semantic_retrieval", "run_vector_index_after_closeout"),
    "OBSERVABILITY_ENABLED": ("observability", "enabled"),
    "STALE_ADOPTION_ENFORCEMENT": ("observability", "stale_adoption_enforcement"),
    "SHADOW_MIN_DAYS": ("observability", "shadow_min_days"),
    "SHADOW_STATE_DIR": ("shadow", "state_dir"),
}
RUNTIME_RELEASE_VERSION = "2.1.0"
WRITE_GATEWAY_CAPABILITIES = {
    "schema_version": 2,
    "actions": ["read-target", "prepare", "apply", "cancel", "status", "list"],
    "recovery_queries": ["status", "list"],
    "receipt_first_terminal_replay": True,
    "session_scoped_recovery": True,
    "side_effect_free_recovery_queries": True,
    "windows_mode": "read_only",
}


def expand_path(value: str) -> Path:
    """Expand user and environment paths consistently on Unix and Windows."""

    if ("$HOME" in value or "${HOME}" in value) and not os.environ.get("HOME"):
        home = os.environ.get("USERPROFILE") or str(DEFAULT_HOME)
        value = value.replace("${HOME}", home).replace("$HOME", home)
    return Path(os.path.expandvars(value)).expanduser()


def config_path() -> Path:
    explicit = os.environ.get("AGENT_MEMORY_CONFIG_FILE", "").strip()
    if explicit:
        return absolute_path(expand_path(explicit))
    return RUNTIME_ROOT / "config" / "agent-memory.toml"


class RuntimeTransitionError(RuntimeError):
    """Raised when an interrupted runtime upgrade must fail closed."""


def managed_python_launcher() -> Path:
    return (
        RUNTIME_ROOT / ".venv" / "Scripts" / "python.exe"
        if os.name == "nt"
        else RUNTIME_ROOT / ".venv" / "bin" / "python"
    )


def _lexical_path(path: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _managed_read_optional(relative: Path) -> bytes | None:
    target = RUNTIME_ROOT / relative
    assert_no_symlink_beneath(
        RUNTIME_ROOT,
        target,
        include_leaf=False,
        allow_missing=True,
    )
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise StateSecurityError(f"managed runtime file is unsafe: {target}")
    return secure_read_bytes_beneath(RUNTIME_ROOT, relative)


def _managed_json(relative: Path, reason_code: str) -> dict[str, Any]:
    try:
        raw = _managed_read_optional(relative)
        payload = json.loads(raw.decode("utf-8")) if raw is not None else None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateSecurityError) as exc:
        raise RuntimeTransitionError(reason_code) from exc
    if not isinstance(payload, dict):
        raise RuntimeTransitionError(reason_code)
    return payload


def explicit_migration_capability_valid(
    command: str,
    *,
    token: str,
    issuer_pid: int,
) -> bool:
    """Validate one migration capability without mutating process environment."""

    if len(token) < 32 or issuer_pid <= 0:
        return False
    try:
        marker = _managed_json(Path("config/runtime-transition.json"), "RUNTIME_TRANSITION_MARKER_INVALID")
        manifest = _managed_json(Path("config/runtime-manifest.json"), "RUNTIME_MANIFEST_INVALID")
        expires = dt.datetime.fromisoformat(str(marker.get("capability_expires_at", "")).replace("Z", "+00:00"))
    except (RuntimeTransitionError, ValueError, TypeError):
        return False
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=dt.timezone.utc)
    allowed = marker.get("capability_commands", [])
    return (
        isinstance(marker, dict)
        and isinstance(manifest, dict)
        and marker.get("phase") == "preflight"
        and marker.get("bundle_sha256") == manifest.get("bundle_sha256")
        and marker.get("capability_sha256") == hashlib.sha256(token.encode("utf-8")).hexdigest()
        and marker.get("capability_parent_pid") == issuer_pid
        and dt.datetime.now(dt.timezone.utc) <= expires.astimezone(dt.timezone.utc)
        and isinstance(allowed, list)
        and command in {str(item) for item in allowed}
    )


def assert_runtime_maintenance_capability(
    command: str,
    *,
    token: str,
    issuer_pid: int,
) -> dict[str, Any]:
    """Return transition status only for an explicitly bound maintenance grant."""

    status = runtime_transition_status()
    if status.get("ready"):
        return status
    if explicit_migration_capability_valid(
        command,
        token=token,
        issuer_pid=issuer_pid,
    ):
        return {**status, "maintenance_capability": True}
    raise RuntimeTransitionError("RUNTIME_TRANSITION_INCOMPLETE")


def _migration_capability_valid(command: str) -> bool:
    """Accept a short-lived child capability issued by the locked migrator.

    The token itself exists only in the child environment. The transition
    marker stores its hash, issuing parent pid, expiry, bundle, and allowlist.
    This is an installation capability, not a public force flag.
    """

    token = os.environ.get("AGENT_MEMORY_MIGRATION_CAPABILITY", "")
    raw_issuer = os.environ.get("AGENT_MEMORY_MIGRATION_ISSUER_PID", "").strip()
    try:
        issuer_pid = int(raw_issuer) if raw_issuer else os.getppid()
    except ValueError:
        return False
    return explicit_migration_capability_valid(
        command,
        token=token,
        issuer_pid=issuer_pid,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def managed_runtime_integrity() -> dict[str, Any]:
    """Re-hash every manifest-bound runtime artifact for the live handshake."""

    try:
        raw_manifest = _managed_read_optional(Path("config/runtime-manifest.json"))
        manifest = json.loads(raw_manifest.decode("utf-8")) if raw_manifest is not None else None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateSecurityError):
        return {"ok": False, "reason_code": "RUNTIME_MANIFEST_UNSAFE"}
    if not isinstance(manifest, dict):
        return {"ok": False, "reason_code": "RUNTIME_MANIFEST_INVALID"}
    groups = {
        "files": Path("scripts"),
        "support_files": Path(),
        "template_files": Path(),
    }
    mode_groups = {
        "files": "file_modes",
        "support_files": "support_file_modes",
        "template_files": "template_file_modes",
    }
    mode_policy_present = any(key in manifest for key in mode_groups.values())
    mismatched: list[str] = []
    file_count = 0
    for group, prefix in groups.items():
        expected = manifest.get(group)
        expected_modes = manifest.get(mode_groups[group])
        if (
            not isinstance(expected, dict)
            or not expected
            or (
                mode_policy_present
                and (
                    not isinstance(expected_modes, dict)
                    or set(expected_modes) != set(expected)
                )
            )
        ):
            return {"ok": False, "reason_code": "RUNTIME_MANIFEST_GROUP_INVALID"}
        for raw_name, raw_digest in expected.items():
            relative = Path(str(raw_name))
            if relative.is_absolute() or ".." in relative.parts:
                return {"ok": False, "reason_code": "RUNTIME_MANIFEST_PATH_INVALID"}
            runtime_relative = prefix / relative
            metadata: os.stat_result | None = None
            try:
                content, metadata = secure_read_bytes_and_stat_beneath(
                    RUNTIME_ROOT,
                    runtime_relative,
                )
                digest = hashlib.sha256(content).hexdigest()
            except (OSError, StateSecurityError):
                digest = ""
            if digest != str(raw_digest):
                mismatched.append(f"{group}:{relative.as_posix()}")
            if mode_policy_present:
                raw_mode = expected_modes.get(raw_name) if isinstance(expected_modes, dict) else None
                if (
                    not isinstance(raw_mode, str)
                    or not re.fullmatch(r"[0-7]{4}", raw_mode)
                    or (
                        os.name != "nt"
                        and metadata is not None
                        and stat.S_IMODE(metadata.st_mode) != int(raw_mode, 8)
                    )
                    or (os.name != "nt" and metadata is None)
                ):
                    mismatched.append(f"{mode_groups[group]}:{relative.as_posix()}")
            file_count += 1
    calculated_bundle = hashlib.sha256(
        json.dumps(
            {key: manifest.get(key) for key in groups},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    manifest_sha256 = hashlib.sha256(raw_manifest or b"").hexdigest()
    ok = calculated_bundle == manifest.get("bundle_sha256") and not mismatched
    return {
        "ok": ok,
        "reason_code": "" if ok else "RUNTIME_INTEGRITY_MISMATCH",
        "bundle_sha256": calculated_bundle,
        "manifest_sha256": manifest_sha256,
        "runtime_integrity_sha256": hashlib.sha256(
            f"{manifest_sha256}:{calculated_bundle}".encode("ascii")
        ).hexdigest(),
        "file_count": file_count,
        "mismatched_count": len(mismatched),
    }


def managed_config_integrity(marker: dict[str, Any]) -> dict[str, Any]:
    attestation = marker.get("preflight_attestation")
    if not isinstance(attestation, dict):
        return {"ok": False, "reason_code": "RUNTIME_CONFIG_ATTESTATION_MISSING"}
    path = config_path()
    canonical_path = RUNTIME_ROOT / "config" / "agent-memory.toml"
    if absolute_path(path) != absolute_path(canonical_path):
        return {"ok": False, "reason_code": "RUNTIME_CONFIG_UNSAFE"}
    try:
        raw, metadata = secure_read_bytes_and_stat_beneath(
            RUNTIME_ROOT,
            Path("config/agent-memory.toml"),
        )
        mode = stat.S_IMODE(metadata.st_mode)
        digest = hashlib.sha256(raw).hexdigest()
        text = raw.decode("utf-8")
        if tomllib is not None:
            payload = tomllib.loads(text)
        else:
            payload = parse_toml_fallback(text)
        gateway = payload.get("write_gateway") if isinstance(payload, dict) else None
        def effective_path(env_key: str, config_key: str) -> Path:
            explicit = os.environ.get(f"AGENT_MEMORY_{env_key}", "").strip()
            configured = payload.get(config_key) if isinstance(payload, dict) else None
            raw_value = explicit or (configured if isinstance(configured, str) else "")
            if not raw_value:
                raise ValueError(f"missing {config_key}")
            return expand_path(raw_value).resolve()

        memory_root = effective_path("ROOT", "memory_root")
        git_root = effective_path("GIT_ROOT", "git_root")
        state_db = effective_path("STATE_DB", "state_db")
        config_root = effective_path("CONFIG_ROOT", "config_root")
        raw_python = payload.get("python") if isinstance(payload, dict) else None
        if not isinstance(raw_python, str) or not raw_python.strip():
            raise ValueError("missing python")
        python_path = absolute_path(expand_path(raw_python.strip()))
        launcher = managed_python_launcher()
        configured_launcher_ok = _lexical_path(python_path) == _lexical_path(launcher)
        current_launcher_ok = _lexical_path(sys.executable) == _lexical_path(launcher)
        expected_python = attestation.get("runtime_python")
        actual_python = runtime_python_attestation(RUNTIME_ROOT, python_path)
        python_ok = (
            configured_launcher_ok
            and current_launcher_ok
            and runtime_python_attestation_matches(expected_python, actual_python)
        )
    except (OSError, ValueError, UnicodeDecodeError, StateSecurityError, subprocess.SubprocessError):
        return {"ok": False, "reason_code": "RUNTIME_CONFIG_UNREADABLE"}
    expected = str(attestation.get("config_sha256", ""))
    gateway_ok = (
        isinstance(gateway, dict)
        and gateway.get("mode") == "enforce"
        and gateway.get("writer_protocol_version") == 2
        and gateway.get("state_schema_required") == STATE_SCHEMA_VERSION
        and gateway.get("canonical_actors") == ["codex", "claude", "ailu"]
        and gateway.get("path_fencing") is True
        and gateway.get("claims_are_projection") is True
        and gateway.get("full_vault") is True
    )
    paths_match = (
        str(memory_root) == str(attestation.get("memory_root", ""))
        and str(git_root) == str(attestation.get("git_root", ""))
        and str(state_db) == str(attestation.get("state_db", ""))
        and str(config_root) == str(attestation.get("config_root", ""))
    )
    mode_ok = os.name != "posix" or mode == 0o600
    cutover_integrity: dict[str, Any] = {"ok": False, "reason_code": "SHADOW_CUTOVER_NOT_USED"}
    digest_ok = bool(expected) and digest == expected
    if bool(expected) and not digest_ok:
        # Runtime publication binds the original shadow-mode config.  The one
        # allowed post-install mutation is the migration-only cutover whose
        # exact base backup and privacy-safe seven-day evidence are verified
        # here.  Arbitrary config edits remain fail-closed.
        try:
            from agent_memory_shadow import verify_cutover_config

            cutover_integrity = verify_cutover_config(
                raw,
                payload if isinstance(payload, dict) else {},
                expected_config_sha256=expected,
            )
            digest_ok = bool(cutover_integrity.get("ok"))
        except (ImportError, OSError, RuntimeError, ValueError):
            digest_ok = False
    ok = digest_ok and paths_match and mode_ok and gateway_ok and python_ok
    return {
        "ok": ok,
        "reason_code": "" if ok else "RUNTIME_CONFIG_ATTESTATION_MISMATCH",
        "config_sha256": digest,
        "mode": f"{mode:04o}",
        "paths_match": paths_match,
        "write_gateway_ok": gateway_ok,
        "runtime_python_ok": python_ok,
        "configured_runtime_launcher_ok": configured_launcher_ok,
        "current_runtime_launcher_ok": current_launcher_ok,
        "runtime_python_integrity_sha256": str(actual_python.get("attestation_sha256", "")),
        "shadow_cutover_integrity": cutover_integrity,
    }


def managed_host_hook_integrity(marker: dict[str, Any]) -> dict[str, Any]:
    """Verify managed Hook bytes and only the host settings they depend on.

    Codex rewrites ``config.toml`` for ordinary model, reasoning-effort, and
    service-tier changes.  Binding Runtime readiness to that whole mutable file
    disables memory even though the dedicated Hook is untouched.  The managed
    contract only depends on ``features.hooks = true``; the exact Hook command
    remains protected by the attested ``hooks.json`` digest.
    """

    attestation = marker.get("preflight_attestation")
    hooks = attestation.get("host_hooks") if isinstance(attestation, dict) else None
    if not isinstance(hooks, dict) or hooks.get("verified") is not True:
        return {"ok": False, "reason_code": "HOST_HOOK_ATTESTATION_MISSING"}
    policy = str(hooks.get("policy", ""))
    if policy == "explicitly_disabled":
        return {"ok": True, "reason_code": "", "policy": policy}
    if policy != "required" or not isinstance(hooks.get("hosts"), list):
        return {"ok": False, "reason_code": "HOST_HOOK_ATTESTATION_INVALID"}
    paths: list[tuple[Path, str]] = []
    semantic_mismatches = 0
    claude_semantic_fingerprints: list[str] = []
    for host in hooks["hosts"]:
        if host == "codex":
            expected = hooks.get("codex")
            if not isinstance(expected, dict):
                return {"ok": False, "reason_code": "HOST_HOOK_ATTESTATION_INVALID"}
            # New publications state the semantic dependency explicitly.  A
            # legacy ready marker is also safe to upgrade in place because its
            # preflight could only have been published after the same feature
            # check and it carries the former whole-file digest.
            if expected.get("config_hooks_enabled") is not True and not str(
                expected.get("config_sha256", "")
            ):
                return {"ok": False, "reason_code": "HOST_HOOK_ATTESTATION_INVALID"}
            paths.append(
                (Path.home() / ".codex" / "hooks.json", str(expected.get("hooks_sha256", "")))
            )
            config_path = Path.home() / ".codex" / "config.toml"
            try:
                if config_path.is_symlink() or not config_path.is_file():
                    semantic_mismatches += 1
                else:
                    text = config_path.read_text(encoding="utf-8-sig")
                    payload = tomllib.loads(text) if tomllib is not None else parse_toml_fallback(text)
                    features = payload.get("features") if isinstance(payload, dict) else None
                    if not isinstance(features, dict) or features.get("hooks") is not True:
                        semantic_mismatches += 1
            except (OSError, UnicodeDecodeError, ValueError):
                semantic_mismatches += 1
        elif host == "claude":
            expected = hooks.get("claude")
            if not isinstance(expected, dict):
                return {"ok": False, "reason_code": "HOST_HOOK_ATTESTATION_INVALID"}
            expected_routes = expected.get("semantic_routes", expected.get("classification"))
            if isinstance(expected_routes, dict) and isinstance(expected_routes.get("events"), dict):
                expected_events = expected_routes["events"]
            else:
                expected_events = expected_routes
            expected_semantically_healthy = bool(
                isinstance(expected_events, dict)
                and all(
                    isinstance(expected_events.get(event), dict)
                    and expected_events[event].get("healthy") is True
                    and int(expected_events[event].get("canonical_count", 0)) == 1
                    and int(expected_events[event].get("legacy_count", 0)) == 0
                    and int(expected_events[event].get("ambiguous_count", 0)) == 0
                    for event in ("SessionStart", "Stop", "SessionEnd")
                )
            )
            settings_path = Path.home() / ".claude" / "settings.json"
            try:
                if settings_path.is_symlink() or not settings_path.is_file():
                    raise ValueError("CLAUDE_SETTINGS_UNSAFE")
                settings_payload = json.loads(settings_path.read_text(encoding="utf-8-sig"))
                live_hooks = settings_payload.get("hooks") if isinstance(settings_payload, dict) else None
                live = classify_claude_hooks(
                    live_hooks,
                    runtime_python=(
                        RUNTIME_ROOT / ".venv" / "Scripts" / "python.exe"
                        if os.name == "nt"
                        else RUNTIME_ROOT / ".venv" / "bin" / "python"
                    ),
                    runtime_root=RUNTIME_ROOT,
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
                live = {"healthy": False, "semantic_fingerprint_sha256": ""}
            if not expected_semantically_healthy or live.get("healthy") is not True:
                semantic_mismatches += 1
            claude_semantic_fingerprints.append(
                str(live.get("semantic_fingerprint_sha256", ""))
            )
        else:
            return {"ok": False, "reason_code": "HOST_HOOK_ATTESTATION_INVALID"}
    mismatched: list[str] = []
    for path, expected in paths:
        try:
            if not expected or path.is_symlink() or not path.is_file() or _sha256_file(path) != expected:
                mismatched.append(str(path))
        except OSError:
            mismatched.append(str(path))
    mismatch_count = len(mismatched) + semantic_mismatches
    return {
        "ok": mismatch_count == 0,
        "reason_code": "" if mismatch_count == 0 else "HOST_HOOK_ATTESTATION_MISMATCH",
        "policy": policy,
        "mismatched_count": mismatch_count,
        "claude_semantic_fingerprints": claude_semantic_fingerprints,
    }


def runtime_transition_status(*, side_effect_free_state: bool = False) -> dict[str, Any]:
    marker = RUNTIME_ROOT / "config" / "runtime-transition.json"
    manifest_path = RUNTIME_ROOT / "config" / "runtime-manifest.json"
    try:
        anchor_raw = _managed_read_optional(Path("config/runtime-anchor.json"))
        marker_raw = _managed_read_optional(Path("config/runtime-transition.json"))
        manifest_raw = _managed_read_optional(Path("config/runtime-manifest.json"))
    except (OSError, StateSecurityError) as exc:
        return {
            "ready": False,
            "phase": "unsafe",
            "marker": str(marker),
            "managed": True,
            "reason_code": "RUNTIME_PATH_CONTAINMENT_FAILED",
            "detail": type(exc).__name__,
        }
    managed_layout = any(
        path.exists() or path.is_symlink()
        for path in (
            RUNTIME_ROOT / ".venv",
            RUNTIME_ROOT / "state.sqlite",
            RUNTIME_ROOT / "config" / "agent-memory.toml",
        )
    )
    if anchor_raw is None and marker_raw is None and manifest_raw is None and managed_layout:
        return {
            "ready": False,
            "phase": "missing",
            "marker": str(marker),
            "managed": True,
            "reason_code": "RUNTIME_MANAGED_IDENTITY_MISSING",
        }
    if anchor_raw is not None and (marker_raw is None or manifest_raw is None):
        return {
            "ready": False,
            "phase": "missing",
            "marker": str(marker),
            "managed": True,
            "reason_code": "RUNTIME_MANAGED_IDENTITY_INCOMPLETE",
        }
    if marker_raw is None:
        # A source checkout has no installed-runtime manifest, but it must still
        # prove that its configured state is already v4. Otherwise an ordinary
        # command could call ensure_schema() and silently migrate a v1 database
        # without the explicit plan/backup/apply/verify protocol.
        if manifest_raw is None:
            state = _runtime_state_status(
                require_toml=False,
                side_effect_free=side_effect_free_state,
            )
            return {
                "ready": bool(state.get("ok")),
                "phase": "source_checkout",
                "marker": str(marker),
                "managed": False,
                "reason_code": "" if state.get("ok") else str(state.get("reason_code", "RUNTIME_STATE_NOT_READY")),
                "state": state,
            }
        try:
            manifest_without_marker = json.loads(manifest_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            manifest_without_marker = {}
        if isinstance(manifest_without_marker, dict) and manifest_without_marker.get("schema_version") == 1:
            # If v2 code is present beside a managed v1 manifest, this is a
            # partial/manual copy. The old runtime does not need this module for
            # compatibility; allowing ordinary v2 commands here would silently
            # mutate v1 state through ensure_schema().
            return {
                "ready": False,
                "phase": "state_migration_required",
                "marker": str(marker),
                "managed": True,
                "reason_code": "STATE_MIGRATION_REQUIRED",
            }
        return {
            "ready": False,
            "phase": "missing",
            "marker": str(marker),
            "managed": True,
            "reason_code": "RUNTIME_TRANSITION_MARKER_MISSING",
        }
    try:
        payload = json.loads(marker_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            "ready": False,
            "phase": "invalid",
            "marker": str(marker),
            "reason_code": "RUNTIME_TRANSITION_MARKER_INVALID",
            "detail": type(exc).__name__,
        }
    if not isinstance(payload, dict):
        return {
            "ready": False,
            "phase": "invalid",
            "marker": str(marker),
            "reason_code": "RUNTIME_TRANSITION_MARKER_INVALID",
        }
    phase = str(payload.get("phase", "")).strip().lower() or "unknown"
    try:
        manifest = json.loads(manifest_raw.decode("utf-8")) if manifest_raw is not None else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        manifest = {}
    try:
        anchor = json.loads(anchor_raw.decode("utf-8")) if anchor_raw is not None else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        anchor = {}
    anchor_matches = (
        isinstance(anchor, dict)
        and anchor.get("schema_version") == 1
        and anchor.get("managed_runtime") is True
        and _lexical_path(str(anchor.get("runtime_root", ""))) == _lexical_path(RUNTIME_ROOT)
        and isinstance(anchor.get("install_id"), str)
        and len(str(anchor.get("install_id", ""))) == 64
        and isinstance(manifest, dict)
        and manifest.get("install_id") == anchor.get("install_id")
        and payload.get("install_id") == anchor.get("install_id")
        and manifest.get("runtime_anchor_sha256") == hashlib.sha256(anchor_raw or b"").hexdigest()
        and payload.get("runtime_anchor_sha256") == manifest.get("runtime_anchor_sha256")
    )
    protocol_matches = (
        anchor_matches
        and isinstance(manifest, dict)
        and manifest.get("schema_version") == 2
        and manifest.get("release_version") == RUNTIME_RELEASE_VERSION
        and manifest.get("runtime_api_version") == 2
        and manifest.get("writer_protocol_version") == 2
        and manifest.get("state_schema_required") == STATE_SCHEMA_VERSION
        and manifest.get("canonical_actors") == ["codex", "claude", "ailu"]
        and manifest.get("capabilities")
        == {"write_gateway": WRITE_GATEWAY_CAPABILITIES}
        and payload.get("bundle_sha256") == manifest.get("bundle_sha256")
    )
    integrity = managed_runtime_integrity() if phase == "ready" and protocol_matches else {
        "ok": False,
        "reason_code": "RUNTIME_INTEGRITY_NOT_CHECKED",
    }
    config_integrity = managed_config_integrity(payload) if phase == "ready" and protocol_matches else {
        "ok": False,
        "reason_code": "RUNTIME_CONFIG_NOT_CHECKED",
    }
    hook_integrity = managed_host_hook_integrity(payload) if (
        phase == "ready" and protocol_matches and integrity.get("ok") and config_integrity.get("ok")
    ) else {
        "ok": False,
        "reason_code": "HOST_HOOK_ATTESTATION_NOT_CHECKED",
    }
    state = _runtime_state_status(side_effect_free=side_effect_free_state) if (
        phase == "ready"
        and protocol_matches
        and integrity.get("ok")
        and config_integrity.get("ok")
        and hook_integrity.get("ok")
    ) else {
        "ok": False,
        "reason_code": "RUNTIME_STATE_NOT_CHECKED",
    }
    ready = (
        phase == "ready"
        and protocol_matches
        and bool(integrity.get("ok"))
        and bool(config_integrity.get("ok"))
        and bool(hook_integrity.get("ok"))
        and bool(state.get("ok"))
    )
    runtime_integrity_sha256 = ""
    if ready:
        runtime_integrity_sha256 = hashlib.sha256(
            json.dumps(
                {
                    "runtime": integrity.get("runtime_integrity_sha256"),
                    "config": config_integrity.get("config_sha256"),
                    "python": config_integrity.get("runtime_python_integrity_sha256"),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    return {
        "ready": ready,
        "phase": phase,
        "marker": str(marker),
        "managed": True,
        "reason_code": (
            ""
            if ready
            else str(
                integrity.get("reason_code")
                or config_integrity.get("reason_code")
                or hook_integrity.get("reason_code")
                or state.get("reason_code")
                or "RUNTIME_TRANSITION_INCOMPLETE"
            )
        ),
        "runtime_integrity": integrity,
        "runtime_integrity_sha256": runtime_integrity_sha256,
        "config_integrity": config_integrity,
        "host_hook_integrity": hook_integrity,
        "state": state,
    }


def assert_runtime_ready(
    command: str,
    *,
    side_effect_free_state: bool = False,
) -> dict[str, Any]:
    status = runtime_transition_status(
        side_effect_free_state=side_effect_free_state,
    )
    if status["ready"] or command in {
        "version",
        "migrate",
        "bootstrap",
        "install-host-hooks",
        "install-audit-launchagent",
        "explain",
    }:
        return status
    if _migration_capability_valid(command):
        return {**status, "maintenance_capability": True}
    # Doctor remains available as a read-only diagnostic while a transition is
    # closed.  It does not receive migration privileges unless the locked
    # migrator supplied the short-lived parent-bound capability above.
    if command == "doctor":
        return status
    raise RuntimeTransitionError(
        f"RUNTIME_TRANSITION_INCOMPLETE: runtime phase={status['phase']}; "
        "run memoryctl migrate plan/init/apply/verify or restore the previous runtime snapshot"
    )


@lru_cache(maxsize=1)
def load_dotenv() -> dict[str, str]:
    path = RUNTIME_ROOT / ".env"
    if not path.is_file():
        return {}
    payload: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            try:
                fields = shlex.split(line[7:], comments=True, posix=True)
            except ValueError:
                continue
            if len(fields) != 1:
                continue
            line = fields[0]
        key, separator, raw_value = line.partition("=")
        key = key.strip()
        if not separator or not key.isidentifier():
            continue
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            try:
                parsed = ast.literal_eval(value)
            except (SyntaxError, ValueError):
                continue
            value = str(parsed)
        payload[key] = value
    return payload


def parse_toml_fallback(text: str) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    section: tuple[str, ...] = ()
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        raw_line = lines[index]
        index += 1
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = tuple(part.strip() for part in line[1:-1].split(".") if part.strip())
            continue
        key, separator, raw_value = line.partition("=")
        if not separator:
            continue
        key = key.strip()
        raw_value = raw_value.strip()
        if raw_value.startswith("[") and not raw_value.rstrip().endswith("]"):
            # macOS still ships Python versions without tomllib.  Preserve
            # newlines so Python's literal parser also handles comments and
            # trailing commas in ordinary TOML string arrays.
            continuation = [raw_value]
            while index < len(lines):
                next_line = lines[index]
                index += 1
                continuation.append(next_line)
                if next_line.strip().endswith("]"):
                    break
            raw_value = "\n".join(continuation)
        try:
            value: object = ast.literal_eval(raw_value)
        except (SyntaxError, ValueError):
            lowered = raw_value.lower()
            if lowered in {"true", "false"}:
                value = lowered == "true"
            else:
                try:
                    value = int(raw_value)
                except ValueError:
                    value = raw_value
        target = payload
        for part in section:
            child = target.setdefault(part, {})
            if not isinstance(child, dict):
                break
            target = child
        else:
            target[key] = value
    return payload


@lru_cache(maxsize=1)
def load_config() -> dict[str, Any]:
    path = config_path()
    try:
        managed_manifest = _managed_read_optional(Path("config/runtime-manifest.json"))
        if managed_manifest is not None:
            if absolute_path(path) != absolute_path(RUNTIME_ROOT / "config" / "agent-memory.toml"):
                return {}
            raw = _managed_read_optional(Path("config/agent-memory.toml"))
            if raw is None:
                return {}
            if tomllib is not None:
                payload = tomllib.loads(raw.decode("utf-8"))
            else:
                payload = parse_toml_fallback(raw.decode("utf-8"))
        else:
            if not path.is_file() or path.is_symlink():
                return {}
            if tomllib is not None:
                with path.open("rb") as handle:
                    payload = tomllib.load(handle)
            else:
                payload = parse_toml_fallback(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, StateSecurityError):
        return {}
    return payload if isinstance(payload, dict) else {}


def reset_config_cache() -> None:
    load_config.cache_clear()
    load_dotenv.cache_clear()
    # Test fixtures and callers changing the configured state must start with
    # a fresh proof. Do not replace a lock another thread may currently hold.
    global _state_check_cache
    with _state_check_lock:
        _state_check_cache = None


_STATE_CHECK_REUSE_SECONDS = 1.0
_state_check_lock = threading.RLock()
_state_check_cache: tuple[tuple[object, ...], float] | None = None


def _reset_state_check_cache() -> None:
    # A child must neither reuse its parent's proof nor inherit a held lock.
    global _state_check_lock, _state_check_cache
    _state_check_lock = threading.RLock()
    _state_check_cache = None


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_state_check_cache)


def _state_check_fingerprint(path: Path) -> tuple[object, ...]:
    """Identify the exact on-disk SQLite generation, including pending WAL."""
    parts: list[object] = [os.getpid(), str(absolute_path(path))]
    for suffix in ("", "-wal", "-journal"):
        try:
            metadata = Path(str(path) + suffix).lstat()
        except FileNotFoundError:
            if not suffix:
                raise StateSecurityError("runtime state disappeared during verification")
            parts.append(None)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise StateSecurityError("runtime state generation is not a regular file")
        # ctime detects same-size edits even when mtime is restored. Windows'
        # ctime has different semantics, so reuse is disabled there below.
        parts.append((metadata.st_dev, metadata.st_ino, metadata.st_size,
                      metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_mode,
                      metadata.st_uid, metadata.st_gid, metadata.st_nlink))
    return tuple(parts)


def _runtime_state_quick_check(
    connection: sqlite3.Connection,
    path: Path,
    *,
    opened_generation: tuple[object, ...] | None = None,
) -> str:
    """Coalesce duplicate integrity scans, never readiness or schema checks.

    Only a successful scan of an unchanged DB/WAL/journal may be reused, for
    at most one second in this process. No content, query or durable proof is
    cached. Every caller still opens the secured database, validates schema,
    and authenticates Runtime/config/Hook bytes. A concurrent commit, replace,
    backdated edit, checkpoint or transaction invalidates reuse immediately.
    """
    global _state_check_cache
    if os.name != "posix" or connection.in_transaction or opened_generation is None:
        return str(connection.execute("PRAGMA quick_check").fetchone()[0])
    with _state_check_lock:
        before = _state_check_fingerprint(path)
        if before != opened_generation:
            # A path replaced after connect may no longer name the connection's
            # inode. Retain the original full scan, but never reuse/publish its
            # proof against the replacement or a different WAL generation.
            _state_check_cache = None
            return str(connection.execute("PRAGMA quick_check").fetchone()[0])
        now = time.monotonic()
        if _state_check_cache is not None:
            fingerprint, checked_at = _state_check_cache
            if before == fingerprint and 0 <= now - checked_at < _STATE_CHECK_REUSE_SECONDS:
                return "ok"
        _state_check_cache = None
        started = time.monotonic()
        result = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        after = _state_check_fingerprint(path)
        finished = time.monotonic()
        if result == "ok" and before == after and 0 <= finished - started < _STATE_CHECK_REUSE_SECONDS:
            # Date from the scan's beginning, not its completion: slow checks
            # must not extend the evidence lifetime.
            _state_check_cache = (after, started)
        return result


def _runtime_state_status(
    *,
    require_toml: bool = True,
    side_effect_free: bool = False,
) -> dict[str, Any]:
    """Verify the managed runtime's configured state without mutating it.

    A ready marker is only a publication record.  It must never allow a
    missing, rolled-back, or wrong-schema database to be recreated implicitly
    by the first ordinary command.
    """

    configured = config_path()
    if configured.is_symlink() or (require_toml and not configured.is_file()):
        return {
            "ok": False,
            "reason_code": "RUNTIME_CONFIG_MISSING",
            "config": str(configured),
        }
    # Source checkouts may intentionally use a private .env only. Managed
    # runtimes must have their canonical TOML. In both modes the root, Git root,
    # and state path must be explicitly configured; default fallbacks are not a
    # readiness proof.
    memory_root_value = env_value("ROOT", "").strip()
    git_root_value = env_value("GIT_ROOT", "").strip()
    state_value = env_value("STATE_DB", "").strip()
    if not memory_root_value or not git_root_value or not state_value:
        return {
            "ok": False,
            "reason_code": "RUNTIME_CONFIG_INCOMPLETE",
            "config": str(configured),
        }
    memory_root = expand_path(memory_root_value)
    git_root = expand_path(git_root_value)
    if not memory_root.is_dir() or not git_root.is_dir():
        return {
            "ok": False,
            "reason_code": "RUNTIME_ROOT_MISSING",
            "config": str(configured),
            "memory_root": str(memory_root),
            "git_root": str(git_root),
        }
    state_path = expand_path(state_value)
    if state_path.is_symlink() or not state_path.is_file():
        return {
            "ok": False,
            "reason_code": "RUNTIME_STATE_MISSING",
            "path": str(state_path),
        }
    required_tables = {
        "meta",
        "memory_files",
        "agent_case_state",
        "reminders",
        "memory_docs",
        "memory_fts",
        "memory_fts_unicode",
        "memory_fts_trigram",
        "memory_open_loops",
        "memory_supersessions",
        "memory_fact_states",
        "memory_search_log",
        "memory_use_events",
        "memory_path_fences",
        "memory_session_claims",
        "memory_write_intents",
        "memory_write_receipts",
        "memory_file_observations",
        "memory_closeout_incidents",
    }
    connection: sqlite3.Connection | None = None
    try:
        opened_generation = _state_check_fingerprint(state_path)
        connection = secure_sqlite_connect(
            state_path,
            timeout=5,
            create=False,
            read_only=True,
            repair_permissions=False,
            side_effect_free=side_effect_free,
        )
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        meta = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT key, value FROM meta WHERE key IN (?, ?)",
                (
                    "agent_memory_state_schema_version",
                    "agent_memory_writer_protocol_version",
                ),
            )
        } if "meta" in tables else {}
        integrity = _runtime_state_quick_check(
            connection, state_path, opened_generation=opened_generation,
        )
        incident_columns = (
            {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(memory_closeout_incidents)")
            }
            if "memory_closeout_incidents" in tables
            else set()
        )
        docs_columns = (
            {str(row[1]) for row in connection.execute("PRAGMA table_info(memory_docs)")}
            if "memory_docs" in tables
            else set()
        )
        search_columns = (
            {str(row[1]) for row in connection.execute("PRAGMA table_info(memory_search_log)")}
            if "memory_search_log" in tables
            else set()
        )
        use_columns = (
            {str(row[1]) for row in connection.execute("PRAGMA table_info(memory_use_events)")}
            if "memory_use_events" in tables
            else set()
        )
    except (OSError, sqlite3.Error, ValueError, StateSecurityError) as exc:
        return {
            "ok": False,
            "reason_code": "RUNTIME_STATE_UNREADABLE",
            "path": str(state_path),
            "detail": type(exc).__name__,
        }
    finally:
        if connection is not None:
            connection.close()
    missing = sorted(required_tables - tables)
    missing_incident_columns = sorted(
        {
            "intent_id",
            "target_key",
            "reason_code",
            "resolved_at",
            "resolution_intent_id",
            "resolution_git_commit",
        }
        - incident_columns
    )
    missing_docs_columns = sorted(
        {"memory_id", "temporal_policy", "verified_at_source", "status", "sha256"}
        - docs_columns
    )
    missing_search_columns = sorted(
        {
            "query_sha256", "returned_memory_ids_json", "ranking_mode",
            "v1_result_fingerprint", "v2_result_fingerprint",
            "required_case_regression_count", "worker_status", "worker_restart_count",
        }
        - search_columns
    )
    missing_use_columns = sorted(
        {
            "event_type", "memory_ids_json", "memory_versions_json",
            "content_sha256", "required_live_verification_count",
            "requires_live_verification",
        }
        - use_columns
    )
    ok = (
        not missing
        and not missing_incident_columns
        and not missing_docs_columns
        and not missing_search_columns
        and not missing_use_columns
        and meta.get("agent_memory_state_schema_version") == str(STATE_SCHEMA_VERSION)
        and meta.get("agent_memory_writer_protocol_version") == "2"
        and integrity == "ok"
    )
    return {
        "ok": ok,
        "reason_code": "" if ok else "RUNTIME_STATE_SCHEMA_MISMATCH",
        "path": str(state_path),
        "state_schema_version": meta.get("agent_memory_state_schema_version", ""),
        "writer_protocol_version": meta.get("agent_memory_writer_protocol_version", ""),
        "missing_tables": missing,
        "missing_incident_columns": missing_incident_columns,
        "missing_docs_columns": missing_docs_columns,
        "missing_search_columns": missing_search_columns,
        "missing_use_columns": missing_use_columns,
        "quick_check": integrity,
    }


def config_value(name: str) -> object | None:
    keys = CONFIG_KEYS.get(name)
    if not keys:
        return None
    value: object = load_config()
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def local_path_default(name: str) -> str | None:
    suffix = LOCAL_PATH_DEFAULTS.get(name)
    if suffix is None:
        return None
    dotenv = load_dotenv()
    configured_root = (
        os.environ.get("AGENT_MEMORY_CONFIG_ROOT", "").strip()
        or str(config_value("CONFIG_ROOT") or "").strip()
        or dotenv.get("AGENT_MEMORY_CONFIG_ROOT", "").strip()
    )
    if configured_root:
        root = expand_path(configured_root)
    elif any(
        path.exists() or path.is_symlink()
        for path in (
            RUNTIME_ROOT / "config" / "runtime-anchor.json",
            RUNTIME_ROOT / "config" / "runtime-manifest.json",
            RUNTIME_ROOT / "config" / "runtime-transition.json",
        )
    ):
        root = RUNTIME_ROOT
    else:
        root = RUNTIME_ROOT / ".agent-memory"
    return str(root.joinpath(*suffix))


def env_value(name: str, default: str = "") -> str:
    """Read environment, runtime TOML, local .env, then an isolated safe default."""
    value = os.environ.get(f"AGENT_MEMORY_{name}")
    if value not in (None, ""):
        return value
    configured = config_value(name)
    if configured not in (None, ""):
        return str(configured)
    dotenv_value = load_dotenv().get(f"AGENT_MEMORY_{name}")
    if dotenv_value not in (None, ""):
        return str(dotenv_value)
    local_default = local_path_default(name)
    if local_default is not None:
        return local_default
    return default
