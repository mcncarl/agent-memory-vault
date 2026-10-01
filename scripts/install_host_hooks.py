#!/usr/bin/env python3
"""Preview or atomically migrate Codex/Claude hooks to the managed runtime.

The default is read-only. ``--apply`` requires a private backup directory and
never overwrites a backup. Unrelated JSON keys and hook entries are preserved.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_memory_env import config_path, parse_toml_fallback
from agent_memory_host_automation import (
    HookSpec,
    any_agent_memory_hook_route,
    canonical_hook_command,
    claude_hook_specs,
    classify_hook_event,
)
from agent_memory_state import PRIVATE_FILE_MODE, ensure_private_directory


RUNTIME_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class CcSwitchUpdate:
    """One compare-and-swap update to a CC Switch JSON column."""

    table: str
    key_columns: tuple[str, ...]
    key_values: tuple[object, ...]
    value_column: str
    before_value: str | None
    after_value: str
    insert: bool = False


@dataclass(frozen=True)
class CcSwitchState:
    path: Path
    installed: bool
    common_config: tuple[str, dict[str, Any]] | None
    backups: tuple[tuple[str, dict[str, Any]], ...]
    providers: tuple[tuple[object, str, dict[str, Any]], ...]


@dataclass(frozen=True)
class CcSwitchPlan:
    path: Path
    installed: bool
    updates: tuple[CcSwitchUpdate, ...]
    common_action: str
    backup_count: int
    provider_count: int
    provider_hooks_count: int
    provider_hooks_updated: int


@dataclass(frozen=True)
class HostFileUpdate:
    path: Path
    before: bytes
    after: bytes
    operations: tuple[str, ...]
    before_existed: bool


class ApplyRolledBackError(RuntimeError):
    def __init__(
        self,
        reason_code: str,
        *,
        journal_path: Path,
        backups: list[dict[str, str]],
    ) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.journal_path = journal_path
        self.backups = backups


class RecoveryRequiredError(RuntimeError):
    def __init__(
        self,
        *,
        journal_path: Path,
        backups: list[dict[str, str]],
        unresolved: list[dict[str, str]],
    ) -> None:
        super().__init__("RECOVERY_REQUIRED")
        self.journal_path = journal_path
        self.backups = backups
        self.unresolved = unresolved


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def regular_file_bytes(path: Path, reason_code: str = "HOST_CONFIG_UNSAFE") -> bytes:
    if path.is_symlink():
        raise ValueError(reason_code)
    if not path.exists():
        return b""
    if not path.is_file():
        raise ValueError(reason_code)
    return path.read_bytes()


def load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError("HOST_CONFIG_UNSAFE")
    if not path.exists():
        return {}
    content = regular_file_bytes(path)
    try:
        payload = json.loads(content.decode("utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ValueError("HOST_CONFIG_JSON_INVALID") from exc
    if not isinstance(payload, dict):
        raise ValueError("HOST_CONFIG_JSON_INVALID")
    return payload


def runtime_config() -> dict[str, Any]:
    path = config_path()
    if path.is_symlink() or not path.is_file():
        raise ValueError("RUNTIME_CONFIG_UNSAFE")
    text = path.read_text(encoding="utf-8")
    try:
        import tomllib
    except ImportError:  # pragma: no cover
        payload = parse_toml_fallback(text)
    else:
        payload = tomllib.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("RUNTIME_CONFIG_INVALID")
    return payload


def configured_python() -> Path:
    payload = runtime_config()
    raw = str(payload.get("python", "")).strip() if isinstance(payload, dict) else ""
    resolved = shutil.which(raw) if raw and not Path(raw).expanduser().is_absolute() else raw
    python = Path(os.path.abspath(str(Path(resolved or "").expanduser())))
    expected = (
        RUNTIME_ROOT / ".venv" / "Scripts" / "python.exe"
        if os.name == "nt"
        else RUNTIME_ROOT / ".venv" / "bin" / "python"
    )
    if (
        not python.is_file()
        or os.path.normcase(str(python)) != os.path.normcase(str(expected))
        or os.path.normcase(os.path.abspath(sys.executable)) != os.path.normcase(os.path.abspath(str(expected)))
    ):
        raise ValueError("HOST_PYTHON_INVALID")
    return python


def configured_host_path(name: str, explicit: str, default: Path) -> Path:
    if explicit.strip():
        return Path(explicit).expanduser()
    host = runtime_config().get("host", {})
    if host is not None and not isinstance(host, dict):
        raise ValueError("HOST_CONFIG_INVALID")
    configured = str((host or {}).get(name, "")).strip()
    return Path(configured).expanduser() if configured else default.expanduser()


def configured_optional_host_path(name: str, explicit: str) -> Path | None:
    if explicit.strip():
        return Path(explicit).expanduser()
    host = runtime_config().get("host", {})
    if host is not None and not isinstance(host, dict):
        raise ValueError("HOST_CONFIG_INVALID")
    configured = str((host or {}).get(name, "")).strip()
    return Path(configured).expanduser() if configured else None


def json_bytes(payload: dict[str, Any], *, original: bytes = b"") -> bytes:
    """Serialize without reordering fields and roughly preserve compactness."""

    text = original.decode("utf-8-sig") if original else ""
    indent = 2 if not original or "\n" in text.strip() else None
    separators = None if indent is not None else (",", ":")
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        indent=indent,
        separators=separators,
    ).encode("utf-8")
    return encoded + b"\n"


def command(python: Path, script: str, *args: str) -> str:
    target = RUNTIME_ROOT / "scripts" / "memoryctl"
    if target.is_symlink() or not target.is_file():
        raise ValueError("HOST_HOOK_RUNTIME_FILE_MISSING")
    actor = "claude" if "--actor" in args and args[args.index("--actor") + 1] == "claude" else "codex"
    forwarded = list(args)
    if "--actor" in forwarded:
        index = forwarded.index("--actor")
        del forwarded[index:index + 2]
    command_name = "session-hook" if script == "agent_memory_session_hook.py" else "stop-hook"
    return canonical_hook_command(
        python,
        RUNTIME_ROOT,
        HookSpec(actor, command_name, tuple(forwarded), 0),
    )


def _managed_event_route(raw_command: object, *, script_name: str) -> bool:
    """Compatibility wrapper over the shared Host Automation classifier."""

    command_name = "session-hook" if script_name == "agent_memory_session_hook.py" else "stop-hook"
    return any_agent_memory_hook_route(raw_command, command_name=command_name)


def merge_event(
    hooks: dict[str, Any],
    event: str,
    *,
    script_name: str,
    entry: dict[str, Any],
) -> str:
    groups = hooks.setdefault(event, [])
    if not isinstance(groups, list):
        raise ValueError("HOST_HOOK_EVENT_INVALID")
    matches = 0
    for group in groups:
        entries = group.get("hooks", []) if isinstance(group, dict) else []
        if not isinstance(entries, list):
            continue
        group_disabled = bool(
            isinstance(group, dict)
            and (group.get("enabled") is False or group.get("disabled") is True)
        )
        group_matcher = group.get("matcher") if isinstance(group, dict) else None
        group_scoped = bool(
            isinstance(group, dict)
            and "matcher" in group
            and group_matcher is not None
            and group_matcher != ""
        )
        retained: list[Any] = []
        for existing in entries:
            if isinstance(existing, dict) and _managed_event_route(
                existing.get("command", ""),
                script_name=script_name,
            ):
                if group_disabled or group_scoped:
                    # Keep the disabled group and every unrelated entry, but
                    # move the one managed route to an enabled catch-all group.
                    # Updating it in place would leave a canonical-looking yet
                    # non-executable/scoped route and create a Doctor false green.
                    continue
                if matches:
                    # One managed hook per event is sufficient. Preserve every
                    # unrelated entry but remove stale managed duplicates so a
                    # Stop event cannot execute closeout multiple times.
                    continue
                existing.clear()
                existing.update(entry)
                matches += 1
            retained.append(existing)
        group["hooks"] = retained
    if not matches:
        groups.append({"hooks": [entry]})
        return "added"
    return "updated"


def codex_payload(path: Path, python: Path, auto_closeout: bool = True) -> tuple[bytes, list[str]]:
    payload = load_json(path)
    hooks = payload.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("HOST_HOOKS_INVALID")
    if hooks.get("enabled") is False:
        hooks["enabled"] = True
    if hooks.get("disabled") is True:
        hooks["disabled"] = False
    args = ["--actor", "codex", "--protocol", "codex", "--event", "stop-hook"]
    if auto_closeout:
        args.extend(["--auto-closeout", "--timeout", "300"])
    operation = merge_event(
        hooks,
        "Stop",
        script_name="agent_memory_stop_hook.py",
        entry={
            "type": "command",
            "command": command(python, "agent_memory_stop_hook.py", *args),
            "timeout": 320 if auto_closeout else 20,
        },
    )
    spec = HookSpec(
        "codex",
        "stop-hook",
        (
            "--protocol", "codex", "--event", "stop-hook",
            *( ("--auto-closeout", "--timeout", "300") if auto_closeout else () ),
        ),
        320 if auto_closeout else 20,
    )
    health = classify_hook_event(
        hooks,
        "Stop",
        runtime_python=python,
        runtime_root=RUNTIME_ROOT,
        spec=spec,
    )
    if not health["healthy"]:
        raise ValueError("CODEX_HOOK_CANONICALIZATION_FAILED")
    return (json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8") + b"\n", [f"codex_stop_{operation}"])


def merge_hook_sources(
    target: dict[str, Any],
    source: dict[str, Any],
) -> None:
    """Union unrelated hook groups while preserving matcher boundaries."""

    for event, source_groups in source.items():
        if event not in target:
            target[event] = copy.deepcopy(source_groups)
            continue
        target_groups = target[event]
        if target_groups == source_groups:
            continue
        if not isinstance(target_groups, list) or not isinstance(source_groups, list):
            raise ValueError("HOST_HOOK_EVENT_CONFLICT")
        for source_group in source_groups:
            if not isinstance(source_group, dict):
                if source_group not in target_groups:
                    target_groups.append(copy.deepcopy(source_group))
                continue
            source_entries = source_group.get("hooks")
            if not isinstance(source_entries, list):
                if source_group not in target_groups:
                    target_groups.append(copy.deepcopy(source_group))
                continue
            source_matcher = {
                key: value for key, value in source_group.items() if key != "hooks"
            }
            matching_group = next(
                (
                    group
                    for group in target_groups
                    if isinstance(group, dict)
                    and isinstance(group.get("hooks"), list)
                    and {
                        key: value for key, value in group.items() if key != "hooks"
                    }
                    == source_matcher
                ),
                None,
            )
            if matching_group is None:
                target_groups.append(copy.deepcopy(source_group))
                continue
            target_entries = matching_group["hooks"]
            for entry in source_entries:
                if entry not in target_entries:
                    target_entries.append(copy.deepcopy(entry))


def install_claude_managed_hooks(
    hooks: dict[str, Any],
    python: Path,
) -> list[str]:
    if hooks.get("enabled") is False:
        hooks["enabled"] = True
    if hooks.get("disabled") is True:
        hooks["disabled"] = False
    operations = [
        "claude_session_start_" + merge_event(
            hooks,
            "SessionStart",
            script_name="agent_memory_session_hook.py",
            entry={
                "type": "command",
                "command": command(python, "agent_memory_session_hook.py", "--actor", "claude"),
                "timeout": 10,
            },
        ),
        "claude_stop_" + merge_event(
            hooks,
            "Stop",
            script_name="agent_memory_stop_hook.py",
            entry={
                "type": "command",
                "command": command(
                    python,
                    "agent_memory_stop_hook.py",
                    "--actor", "claude", "--protocol", "claude", "--event", "stop-hook",
                    "--auto-closeout", "--timeout", "300",
                ),
                "timeout": 320,
            },
        ),
        "claude_session_end_" + merge_event(
            hooks,
            "SessionEnd",
            script_name="agent_memory_stop_hook.py",
            entry={
                "type": "command",
                "command": command(
                    python,
                    "agent_memory_stop_hook.py",
                    "--actor", "claude", "--protocol", "claude", "--event", "session-end",
                    "--auto-closeout", "--non-blocking", "--timeout", "45",
                ),
                "timeout": 60,
            },
        ),
    ]
    for event, spec in claude_hook_specs().items():
        health = classify_hook_event(
            hooks,
            event,
            runtime_python=python,
            runtime_root=RUNTIME_ROOT,
            spec=spec,
        )
        if not health["healthy"]:
            raise ValueError("CLAUDE_HOOK_CANONICALIZATION_FAILED")
    return operations


def claude_payload(path: Path, python: Path) -> tuple[bytes, list[str]]:
    payload = load_json(path)
    hooks = payload.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("HOST_HOOKS_INVALID")
    operations = install_claude_managed_hooks(hooks, python)
    original = regular_file_bytes(path)
    return json_bytes(payload, original=original), operations


def claude_persistence_payloads(
    settings_path: Path,
    fragment_path: Path,
    python: Path,
    *,
    additional_global_hooks: tuple[dict[str, Any], ...] = (),
) -> tuple[bytes, bytes, dict[str, Any], list[str]]:
    """Build one shared hook set for live settings and persistent managers."""

    settings = load_json(settings_path)
    settings_hooks = settings.get("hooks", {})
    if not isinstance(settings_hooks, dict):
        raise ValueError("HOST_HOOKS_INVALID")
    fragment = load_json(fragment_path)
    hooks = copy.deepcopy(settings_hooks)
    merge_hook_sources(hooks, fragment)
    for source in additional_global_hooks:
        if not isinstance(source, dict):
            raise ValueError("HOST_HOOKS_INVALID")
        merge_hook_sources(hooks, source)
    operations = install_claude_managed_hooks(hooks, python)
    settings["hooks"] = hooks
    settings_original = regular_file_bytes(settings_path)
    fragment_original = regular_file_bytes(fragment_path)
    return (
        json_bytes(settings, original=settings_original),
        json_bytes(hooks, original=fragment_original),
        hooks,
        [*operations, "claude_managed_fragment_reconciled"],
    )


def _json_object_from_text(value: object, reason_code: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise ValueError(reason_code)
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(reason_code) from exc
    if not isinstance(payload, dict):
        raise ValueError(reason_code)
    return payload


def _json_text(payload: dict[str, Any], *, original: str) -> str:
    indent = 2 if "\n" in original.strip() else None
    separators = None if indent is not None else (",", ":")
    text = json.dumps(
        payload,
        ensure_ascii=False,
        indent=indent,
        separators=separators,
    )
    return text + ("\n" if original.endswith("\n") else "")


def _cc_switch_connection(path: Path, *, read_only: bool) -> sqlite3.Connection:
    if path.is_symlink() or not path.is_file():
        raise ValueError("CC_SWITCH_DB_UNSAFE")
    if read_only:
        connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
    else:
        connection = sqlite3.connect(path, timeout=5)
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


def _cc_switch_schema_ok(connection: sqlite3.Connection) -> bool:
    required = {
        "settings": {"key", "value"},
        "proxy_live_backup": {"app_type", "original_config"},
        "providers": {"id", "app_type", "settings_config"},
    }
    for table, columns in required.items():
        actual = {
            str(row[1])
            for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
        }
        if not columns.issubset(actual):
            return False
    return True


def load_cc_switch_state(path: Path) -> CcSwitchState:
    if not path.exists() and not path.is_symlink():
        return CcSwitchState(path, False, None, (), ())
    with contextlib.closing(_cc_switch_connection(path, read_only=True)) as connection:
        if not _cc_switch_schema_ok(connection):
            raise ValueError("CC_SWITCH_SCHEMA_INVALID")
        quick_check = connection.execute("PRAGMA quick_check").fetchone()
        if not quick_check or str(quick_check[0]).casefold() != "ok":
            raise ValueError("CC_SWITCH_DB_INTEGRITY_FAILED")
        common_row = connection.execute(
            "SELECT value FROM settings WHERE key = ?",
            ("common_config_claude",),
        ).fetchone()
        common = None
        if common_row is not None:
            common_raw = common_row[0]
            common = (
                str(common_raw),
                _json_object_from_text(common_raw, "CC_SWITCH_COMMON_CONFIG_INVALID"),
            )
        backups = tuple(
            (
                str(row[0]),
                _json_object_from_text(row[0], "CC_SWITCH_BACKUP_CONFIG_INVALID"),
            )
            for row in connection.execute(
                "SELECT original_config FROM proxy_live_backup WHERE app_type = ?",
                ("claude",),
            ).fetchall()
        )
        providers = tuple(
            (
                row[0],
                str(row[1]),
                _json_object_from_text(row[1], "CC_SWITCH_PROVIDER_CONFIG_INVALID"),
            )
            for row in connection.execute(
                "SELECT id, settings_config FROM providers WHERE app_type = ? ORDER BY id",
                ("claude",),
            ).fetchall()
        )
    return CcSwitchState(path, True, common, backups, providers)


def cc_switch_global_hook_sources(state: CcSwitchState) -> tuple[dict[str, Any], ...]:
    sources: list[dict[str, Any]] = []
    payloads = (
        ([state.common_config[1]] if state.common_config else [])
        + [payload for _raw, payload in state.backups]
    )
    for payload in payloads:
        hooks = payload.get("hooks")
        if hooks is None:
            continue
        if not isinstance(hooks, dict):
            raise ValueError("CC_SWITCH_HOOKS_INVALID")
        sources.append(hooks)
    return tuple(sources)


def plan_cc_switch_updates(
    state: CcSwitchState,
    expected_hooks: dict[str, Any],
    python: Path,
) -> CcSwitchPlan:
    if not state.installed:
        return CcSwitchPlan(state.path, False, (), "not_installed", 0, 0, 0, 0)
    updates: list[CcSwitchUpdate] = []
    if state.common_config is None:
        common_payload = {"hooks": copy.deepcopy(expected_hooks)}
        common_raw = _json_text(common_payload, original="")
        updates.append(CcSwitchUpdate(
            table="settings",
            key_columns=("key",),
            key_values=("common_config_claude",),
            value_column="value",
            before_value=None,
            after_value=common_raw,
            insert=True,
        ))
        common_action = "added"
    else:
        before, common_payload = state.common_config
        migrated = copy.deepcopy(common_payload)
        migrated["hooks"] = copy.deepcopy(expected_hooks)
        after = _json_text(migrated, original=before)
        if after != before:
            updates.append(CcSwitchUpdate(
                table="settings",
                key_columns=("key",),
                key_values=("common_config_claude",),
                value_column="value",
                before_value=before,
                after_value=after,
            ))
            common_action = "updated"
        else:
            common_action = "unchanged"

    for before, backup_payload in state.backups:
        migrated = copy.deepcopy(backup_payload)
        migrated["hooks"] = copy.deepcopy(expected_hooks)
        after = _json_text(migrated, original=before)
        if after != before:
            updates.append(CcSwitchUpdate(
                table="proxy_live_backup",
                key_columns=("app_type",),
                key_values=("claude",),
                value_column="original_config",
                before_value=before,
                after_value=after,
            ))

    provider_hooks_count = 0
    provider_hooks_updated = 0
    for provider_id, before, provider_payload in state.providers:
        provider_hooks = provider_payload.get("hooks")
        if provider_hooks is None:
            continue
        if not isinstance(provider_hooks, dict):
            raise ValueError("CC_SWITCH_PROVIDER_HOOKS_INVALID")
        provider_hooks_count += 1
        migrated = copy.deepcopy(provider_payload)
        install_claude_managed_hooks(migrated["hooks"], python)
        after = _json_text(migrated, original=before)
        if after == before:
            continue
        provider_hooks_updated += 1
        updates.append(CcSwitchUpdate(
            table="providers",
            key_columns=("id", "app_type"),
            key_values=(provider_id, "claude"),
            value_column="settings_config",
            before_value=before,
            after_value=after,
        ))
    return CcSwitchPlan(
        path=state.path,
        installed=True,
        updates=tuple(updates),
        common_action=common_action,
        backup_count=len(state.backups),
        provider_count=len(state.providers),
        provider_hooks_count=provider_hooks_count,
        provider_hooks_updated=provider_hooks_updated,
    )


def cc_switch_plan_detail(plan: CcSwitchPlan) -> dict[str, Any]:
    before_material = [
        {
            "table": update.table,
            "key_sha256": sha256_bytes(
                json.dumps(update.key_values, ensure_ascii=False, default=str).encode("utf-8")
            ),
            "value_sha256": (
                sha256_bytes(update.before_value.encode("utf-8"))
                if update.before_value is not None
                else None
            ),
        }
        for update in plan.updates
    ]
    after_material = [
        {
            "table": update.table,
            "key_sha256": item["key_sha256"],
            "value_sha256": sha256_bytes(update.after_value.encode("utf-8")),
        }
        for update, item in zip(plan.updates, before_material)
    ]
    return {
        "path": str(plan.path),
        "installed": plan.installed,
        "changed": bool(plan.updates),
        "before_sha256": sha256_bytes(
            json.dumps(before_material, sort_keys=True).encode("utf-8")
        ),
        "after_sha256": sha256_bytes(
            json.dumps(after_material, sort_keys=True).encode("utf-8")
        ),
        "operations": {
            "common_config": plan.common_action,
            "backup_rows": plan.backup_count,
            "provider_rows": plan.provider_count,
            "provider_hooks_found": plan.provider_hooks_count,
            "provider_hooks_updated": plan.provider_hooks_updated,
            "row_updates": len(plan.updates),
        },
    }


def codex_toml_payload(path: Path) -> tuple[bytes, list[str]]:
    original = regular_file_bytes(path).decode("utf-8")
    lines = original.splitlines(keepends=True)
    start = next((index for index, line in enumerate(lines) if line.strip() == "[features]"), None)
    if start is None:
        separator = "" if not original or original.endswith("\n") else "\n"
        migrated = original + separator + "\n[features]\nhooks = true\n"
        operation = "codex_features_added"
    else:
        end = next(
            (index for index in range(start + 1, len(lines)) if lines[index].lstrip().startswith("[")),
            len(lines),
        )
        section = "".join(lines[start + 1 : end])
        if any(line.split("#", 1)[0].strip() == "hooks = true" for line in section.splitlines()):
            migrated = original
            operation = "codex_features_unchanged"
        elif any(line.split("=", 1)[0].strip() == "hooks" for line in section.splitlines() if "=" in line):
            replaced = False
            for index in range(start + 1, end):
                if "=" in lines[index] and lines[index].split("=", 1)[0].strip() == "hooks":
                    newline = "\n" if lines[index].endswith("\n") else ""
                    lines[index] = "hooks = true" + newline
                    replaced = True
                    break
            if not replaced:
                raise ValueError("CODEX_FEATURES_INVALID")
            migrated = "".join(lines)
            operation = "codex_features_enabled"
        else:
            lines.insert(end, "hooks = true\n")
            migrated = "".join(lines)
            operation = "codex_features_enabled"
    return migrated.encode("utf-8"), [operation]


def exclusive_backup(source: Path, backup_dir: Path) -> dict[str, str]:
    ensure_private_directory(backup_dir, harden_existing=True)
    content = regular_file_bytes(source)
    target = backup_dir / f"{source.parent.name}-{source.name}.before-v2"
    descriptor = os.open(
        target,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        PRIVATE_FILE_MODE,
    )
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    return {"path": str(target), "sha256": sha256_bytes(content)}


def exclusive_sqlite_backup(source: Path, backup_dir: Path) -> dict[str, str]:
    """Create a consistent, non-overwriting SQLite backup with owner-only mode."""

    ensure_private_directory(backup_dir, harden_existing=True)
    target = backup_dir / f"{source.parent.name}-{source.name}.before-v2.sqlite"
    descriptor = os.open(
        target,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        PRIVATE_FILE_MODE,
    )
    os.close(descriptor)
    with (
        contextlib.closing(_cc_switch_connection(source, read_only=True)) as source_db,
        contextlib.closing(sqlite3.connect(target, timeout=5)) as backup_db,
    ):
        source_db.backup(backup_db)
        quick_check = backup_db.execute("PRAGMA quick_check").fetchone()
        if not quick_check or str(quick_check[0]).casefold() != "ok":
            raise ValueError("CC_SWITCH_BACKUP_INTEGRITY_FAILED")
    if os.name == "posix":
        os.chmod(target, PRIVATE_FILE_MODE, follow_symlinks=False)
    with target.open("rb") as handle:
        os.fsync(handle.fileno())
    return {"path": str(target), "sha256": sha256_file(target)}


_CC_SWITCH_UPDATE_SHAPES = {
    ("settings", ("key",), "value"),
    ("proxy_live_backup", ("app_type",), "original_config"),
    ("providers", ("id", "app_type"), "settings_config"),
}


def _cc_switch_current_value(
    connection: sqlite3.Connection,
    update: CcSwitchUpdate,
) -> str | None:
    shape = (update.table, update.key_columns, update.value_column)
    if shape not in _CC_SWITCH_UPDATE_SHAPES:
        raise ValueError("CC_SWITCH_UPDATE_SHAPE_INVALID")
    where = " AND ".join(f'"{column}" = ?' for column in update.key_columns)
    row = connection.execute(
        f'SELECT "{update.value_column}" FROM "{update.table}" WHERE {where}',
        update.key_values,
    ).fetchone()
    if row is None:
        return None
    if not isinstance(row[0], str):
        raise ValueError("CC_SWITCH_JSON_COLUMN_INVALID")
    return row[0]


def apply_cc_switch_plan(plan: CcSwitchPlan) -> None:
    if not plan.installed or not plan.updates:
        return
    with contextlib.closing(_cc_switch_connection(plan.path, read_only=False)) as connection:
        try:
            connection.execute("BEGIN IMMEDIATE")
            if not _cc_switch_schema_ok(connection):
                raise ValueError("CC_SWITCH_SCHEMA_INVALID")
            for update in plan.updates:
                current = _cc_switch_current_value(connection, update)
                if current != update.before_value:
                    raise ValueError("CC_SWITCH_CHANGED_BEFORE_REPLACE")
            for update in plan.updates:
                if update.insert:
                    if not (
                        update.table == "settings"
                        and update.key_columns == ("key",)
                        and update.value_column == "value"
                    ):
                        raise ValueError("CC_SWITCH_INSERT_SHAPE_INVALID")
                    cursor = connection.execute(
                        'INSERT INTO "settings" ("key", "value") VALUES (?, ?)',
                        (update.key_values[0], update.after_value),
                    )
                else:
                    where = " AND ".join(
                        f'"{column}" = ?' for column in update.key_columns
                    )
                    cursor = connection.execute(
                        f'UPDATE "{update.table}" SET "{update.value_column}" = ? '
                        f'WHERE {where} AND "{update.value_column}" = ?',
                        (update.after_value, *update.key_values, update.before_value),
                    )
                if cursor.rowcount != 1:
                    raise ValueError("CC_SWITCH_CHANGED_BEFORE_REPLACE")
            quick_check = connection.execute("PRAGMA quick_check").fetchone()
            if not quick_check or str(quick_check[0]).casefold() != "ok":
                raise ValueError("CC_SWITCH_DB_INTEGRITY_FAILED")
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def rollback_cc_switch_plan(plan: CcSwitchPlan) -> tuple[bool, str]:
    """Reverse only exact after-values; never overwrite concurrent DB changes."""

    if not plan.installed or not plan.updates:
        return True, "not_changed"
    try:
        with contextlib.closing(
            _cc_switch_connection(plan.path, read_only=False)
        ) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                if not _cc_switch_schema_ok(connection):
                    raise ValueError("CC_SWITCH_SCHEMA_INVALID")
                states: list[str] = []
                for update in plan.updates:
                    current = _cc_switch_current_value(connection, update)
                    if current == update.before_value:
                        states.append("before")
                    elif current == update.after_value:
                        states.append("after")
                    else:
                        raise ValueError("CC_SWITCH_RECOVERY_CAS_MISMATCH")
                for update, state in reversed(list(zip(plan.updates, states))):
                    if state == "before":
                        continue
                    where = " AND ".join(
                        f'"{column}" = ?' for column in update.key_columns
                    )
                    if update.insert:
                        cursor = connection.execute(
                            f'DELETE FROM "{update.table}" WHERE {where} '
                            f'AND "{update.value_column}" = ?',
                            (*update.key_values, update.after_value),
                        )
                    else:
                        cursor = connection.execute(
                            f'UPDATE "{update.table}" '
                            f'SET "{update.value_column}" = ? WHERE {where} '
                            f'AND "{update.value_column}" = ?',
                            (
                                update.before_value,
                                *update.key_values,
                                update.after_value,
                            ),
                        )
                    if cursor.rowcount != 1:
                        raise ValueError("CC_SWITCH_RECOVERY_CAS_MISMATCH")
                quick_check = connection.execute("PRAGMA quick_check").fetchone()
                if not quick_check or str(quick_check[0]).casefold() != "ok":
                    raise ValueError("CC_SWITCH_DB_INTEGRITY_FAILED")
                connection.commit()
            except Exception:
                connection.rollback()
                raise
    except (OSError, ValueError, sqlite3.Error):
        return False, "db_recovery_cas_or_io_failed"
    return True, "restored"


def _safe_reason_code(error: BaseException) -> str:
    raw = str(error).strip().upper()
    if raw and all(character.isalnum() or character == "_" for character in raw):
        return raw[:128]
    return type(error).__name__.upper()


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_transaction_journal(path: Path, prepared: dict[str, Any]) -> None:
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        PRIVATE_FILE_MODE,
    )
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        handle.write(
            json.dumps(prepared, ensure_ascii=False, sort_keys=True).encode("utf-8")
            + b"\n"
        )
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_directory(path.parent)


def append_transaction_event(path: Path, event: dict[str, Any]) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("HOST_HOOK_JOURNAL_UNSAFE")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_APPEND
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    with os.fdopen(descriptor, "ab", closefd=True) as handle:
        handle.write(
            json.dumps(event, ensure_ascii=False, sort_keys=True).encode("utf-8")
            + b"\n"
        )
        handle.flush()
        os.fsync(handle.fileno())


def _transaction_prepared_payload(
    transaction_id: str,
    file_updates: list[HostFileUpdate],
    file_backups: dict[Path, dict[str, str]],
    cc_switch_plan: CcSwitchPlan,
    database_backup: dict[str, str] | None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "event": "prepared",
        "files": [
            {
                "path": str(update.path),
                "before_existed": update.before_existed,
                "before_sha256": sha256_bytes(update.before),
                "after_sha256": sha256_bytes(update.after),
                "backup_path": file_backups[update.path]["path"],
            }
            for update in file_updates
        ],
        "cc_switch": {
            **cc_switch_plan_detail(cc_switch_plan),
            "backup_path": database_backup["path"] if database_backup else "",
        },
    }


def compensate_host_hook_transaction(
    file_updates: list[HostFileUpdate],
    cc_switch_plan: CcSwitchPlan,
    journal_path: Path,
) -> list[dict[str, str]]:
    """Restore exact prior states or report every state that needs recovery."""

    unresolved: list[dict[str, str]] = []
    try:
        append_transaction_event(journal_path, {"event": "compensation_started"})
    except (OSError, ValueError):
        unresolved.append({"component": "journal", "reason": "append_failed"})

    for update in reversed(file_updates):
        before_sha = sha256_bytes(update.before)
        after_sha = sha256_bytes(update.after)
        try:
            exists = update.path.exists() or update.path.is_symlink()
            current = regular_file_bytes(update.path)
            current_sha = sha256_bytes(current)
            if update.before_existed and exists and current_sha == before_sha:
                status = "already_before"
            elif update.before_existed and exists and current_sha == after_sha:
                atomic_write(
                    update.path,
                    update.before,
                    expected_before_sha256=after_sha,
                )
                if sha256_bytes(regular_file_bytes(update.path)) != before_sha:
                    raise ValueError("HOST_CONFIG_RECOVERY_VERIFY_FAILED")
                status = "restored"
            elif not update.before_existed and not exists:
                status = "already_absent"
            else:
                unresolved.append({
                    "component": "file",
                    "path": str(update.path),
                    "reason": "recovery_cas_mismatch_or_absence_restore_required",
                })
                continue
            try:
                append_transaction_event(
                    journal_path,
                    {"event": "file_compensated", "path": str(update.path), "status": status},
                )
            except (OSError, ValueError):
                unresolved.append({
                    "component": "journal",
                    "path": str(update.path),
                    "reason": "append_failed",
                })
        except (OSError, ValueError):
            unresolved.append({
                "component": "file",
                "path": str(update.path),
                "reason": "recovery_cas_or_io_failed",
            })

    db_ok, db_status = rollback_cc_switch_plan(cc_switch_plan)
    if not db_ok:
        unresolved.append({"component": "cc_switch", "reason": db_status})
    try:
        append_transaction_event(
            journal_path,
            {"event": "database_compensated", "status": db_status},
        )
        append_transaction_event(
            journal_path,
            {
                "event": "rolled_back" if not unresolved else "recovery_required",
                "unresolved_count": len(unresolved),
            },
        )
    except (OSError, ValueError):
        unresolved.append({"component": "journal", "reason": "append_failed"})
    return unresolved


def atomic_write(path: Path, content: bytes, *, expected_before_sha256: str) -> None:
    ensure_private_directory(path.parent, harden_existing=True)
    temporary = path.with_name(f".{path.name}.hook-{os.getpid()}-{uuid.uuid4().hex}")
    descriptor = os.open(
        temporary,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        PRIVATE_FILE_MODE,
    )
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    current = regular_file_bytes(path)
    if sha256_bytes(current) != expected_before_sha256:
        raise ValueError("HOST_CONFIG_CHANGED_BEFORE_REPLACE")
    os.replace(temporary, path)
    if os.name == "posix":
        os.chmod(path, PRIVATE_FILE_MODE, follow_symlinks=False)


def apply_host_hook_transaction(
    file_updates: list[HostFileUpdate],
    cc_switch_plan: CcSwitchPlan,
    backup_dir: Path,
) -> tuple[list[dict[str, str]], Path]:
    """Apply DB plus files with durable evidence and exact compensation."""

    backups: list[dict[str, str]] = []
    file_backups: dict[Path, dict[str, str]] = {}
    for update in file_updates:
        backup = exclusive_backup(update.path, backup_dir)
        backups.append(backup)
        file_backups[update.path] = backup
    database_backup = None
    if cc_switch_plan.updates:
        database_backup = exclusive_sqlite_backup(cc_switch_plan.path, backup_dir)
        backups.append(database_backup)

    journal_path = backup_dir / "host-hook-transaction.jsonl"
    transaction_id = uuid.uuid4().hex
    create_transaction_journal(
        journal_path,
        _transaction_prepared_payload(
            transaction_id,
            file_updates,
            file_backups,
            cc_switch_plan,
            database_backup,
        ),
    )
    try:
        for update in file_updates:
            current = regular_file_bytes(update.path)
            exists = update.path.exists() and not update.path.is_symlink()
            if exists != update.before_existed or current != update.before:
                raise ValueError("HOST_CONFIG_CHANGED_BEFORE_REPLACE")
        apply_cc_switch_plan(cc_switch_plan)
        append_transaction_event(journal_path, {"event": "database_applied"})
        for index, update in enumerate(file_updates):
            atomic_write(
                update.path,
                update.after,
                expected_before_sha256=sha256_bytes(update.before),
            )
            append_transaction_event(
                journal_path,
                {
                    "event": "file_applied",
                    "index": index,
                    "path": str(update.path),
                    "after_sha256": sha256_bytes(update.after),
                },
            )
        append_transaction_event(journal_path, {"event": "completed"})
    except BaseException as error:
        reason_code = _safe_reason_code(error)
        unresolved = compensate_host_hook_transaction(
            file_updates,
            cc_switch_plan,
            journal_path,
        )
        if unresolved:
            raise RecoveryRequiredError(
                journal_path=journal_path,
                backups=backups,
                unresolved=unresolved,
            ) from error
        raise ApplyRolledBackError(
            reason_code,
            journal_path=journal_path,
            backups=backups,
        ) from error
    return backups, journal_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Migrate POSIX Agent Memory host hooks")
    parser.add_argument("--host", action="append", choices=("codex", "claude"), required=True)
    parser.add_argument("--codex-hooks", default=str(Path.home() / ".codex" / "hooks.json"))
    parser.add_argument("--codex-config", default=str(Path.home() / ".codex" / "config.toml"))
    parser.add_argument("--claude-settings", default="")
    parser.add_argument("--claude-hooks-fragment", default="")
    parser.add_argument("--cc-switch-db", default="")
    parser.add_argument("--backup-dir", default="")
    parser.add_argument(
        "--auto-closeout",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="install blocking automatic closeout (required by the v2 ready attestation)",
    )
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        python = configured_python()
        planned: list[tuple[Path, bytes, list[str]]] = []
        cc_switch_plan = CcSwitchPlan(Path(), False, (), "not_selected", 0, 0, 0, 0)
        if "codex" in args.host:
            hooks = Path(args.codex_hooks).expanduser()
            content, operations = codex_payload(hooks, python, args.auto_closeout)
            planned.append((hooks, content, operations))
            config = Path(args.codex_config).expanduser()
            content, operations = codex_toml_payload(config)
            planned.append((config, content, operations))
        if "claude" in args.host:
            settings = configured_host_path(
                "claude_settings_json",
                args.claude_settings,
                Path.home() / ".claude" / "settings.json",
            )
            fragment = configured_host_path(
                "claude_hooks_fragment",
                args.claude_hooks_fragment,
                RUNTIME_ROOT / "config" / "claude-hooks.json",
            )
            cc_switch = configured_optional_host_path(
                "cc_switch_db",
                args.cc_switch_db,
            )
            cc_state = (
                load_cc_switch_state(cc_switch)
                if cc_switch is not None
                else CcSwitchState(Path(), False, None, (), ())
            )
            settings_content, fragment_content, expected_hooks, operations = (
                claude_persistence_payloads(
                    settings,
                    fragment,
                    python,
                    additional_global_hooks=cc_switch_global_hook_sources(cc_state),
                )
            )
            planned.append((settings, settings_content, operations))
            planned.append((
                fragment,
                fragment_content,
                ["claude_managed_fragment_reconciled"],
            ))
            cc_switch_plan = plan_cc_switch_updates(cc_state, expected_hooks, python)
        changes = []
        file_updates: list[HostFileUpdate] = []
        for path, content, operations in planned:
            before = regular_file_bytes(path)
            before_existed = path.exists() and not path.is_symlink()
            changed = before != content or not before_existed
            changes.append({
                "path": str(path),
                "changed": changed,
                "before_sha256": sha256_bytes(before),
                "after_sha256": sha256_bytes(content),
                "operations": operations,
            })
            if changed:
                file_updates.append(HostFileUpdate(
                    path=path,
                    before=before,
                    after=content,
                    operations=tuple(operations),
                    before_existed=before_existed,
                ))
        backups: list[dict[str, str]] = []
        journal_path: Path | None = None
        cc_switch_detail = cc_switch_plan_detail(cc_switch_plan)
        any_changes = bool(file_updates) or bool(cc_switch_plan.updates)
        if args.apply and any_changes:
            if not args.backup_dir:
                raise ValueError("BACKUP_DIR_REQUIRED")
            backup_dir = Path(args.backup_dir).expanduser()
            backups, journal_path = apply_host_hook_transaction(
                file_updates,
                cc_switch_plan,
                backup_dir,
            )
        payload = {
            "ok": True,
            "status": "applied" if args.apply else "preview",
            "python": str(python),
            "hosts": sorted(set(args.host)),
            "changes": changes,
            "claude_persistence": {"cc_switch": cc_switch_detail},
            "backups": backups,
            "transaction_journal": str(journal_path) if journal_path else "",
        }
    except RecoveryRequiredError as exc:
        payload = {
            "ok": False,
            "status": "recovery_required",
            "reason_code": "RECOVERY_REQUIRED",
            "transaction_journal": str(exc.journal_path),
            "backups": exc.backups,
            "recovery": {
                "automatic_compensation_complete": False,
                "unresolved": exc.unresolved,
            },
        }
    except ApplyRolledBackError as exc:
        payload = {
            "ok": False,
            "status": "rolled_back",
            "reason_code": exc.reason_code,
            "transaction_journal": str(exc.journal_path),
            "backups": exc.backups,
            "recovery": {"automatic_compensation_complete": True},
        }
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as exc:
        payload = {"ok": False, "status": "error", "reason_code": str(exc).upper()}
    print(json.dumps(payload, ensure_ascii=False, indent=2) if args.json else f"host_hooks={payload['status']}")
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
