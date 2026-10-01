#!/usr/bin/env python3
"""Shared, read-only classification for Agent Memory host automation.

The installers, Doctor, and publish-ready gate must agree on what constitutes
one canonical route.  Keep this module free of installation side effects so it
can be imported by all three without creating a second source of truth.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import ntpath
import os
import plistlib
import re
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


CANONICAL = "canonical"
LEGACY = "legacy"
AMBIGUOUS = "ambiguous"
UNRELATED = "unrelated"
ROUTE_KINDS = {CANONICAL, LEGACY, AMBIGUOUS, UNRELATED}

AUDIT_WEEKDAY = 0  # launchd: Sunday
AUDIT_HOUR = 10
AUDIT_MINUTE = 30
AUDIT_ACTOR = "human"
AUDIT_REASON = "launchd"
AUDIT_FRESHNESS_DAYS = 7
REPORT_FUTURE_TOLERANCE_SECONDS = 300
HOOK_ENTRY_INPUT_MAX_BYTES = 64 * 1024
DEFAULT_AUDIT_LAUNCHAGENT_LABEL = "com.agent-memory-vault.audit"
AUDIT_LAUNCHAGENT_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{2,127}$")

_HOOK_SCRIPT_BY_COMMAND = {
    "session-hook": "agent_memory_session_hook.py",
    "stop-hook": "agent_memory_stop_hook.py",
}
_KNOWN_HOOK_NAMES = {
    "agent_memory_session_hook.py",
    "agent_memory_stop_hook.py",
    "on-stop-memory.sh",
    "stop-hook.ps1",
}


@dataclass(frozen=True)
class HookSpec:
    actor: str
    command_name: str
    forwarded: tuple[str, ...]
    timeout: float

    @property
    def script_name(self) -> str:
        return _HOOK_SCRIPT_BY_COMMAND[self.command_name]


def codex_stop_hook_spec(*, auto_closeout: bool = True) -> HookSpec:
    """Return the one managed Codex Stop contract used by every host gate."""

    forwarded = (
        "--protocol", "codex", "--event", "stop-hook",
        *(('--auto-closeout',) if auto_closeout else ()),
        "--timeout", "300",
    )
    return HookSpec("codex", "stop-hook", forwarded, 320 if auto_closeout else 20)


def claude_hook_specs() -> dict[str, HookSpec]:
    """Return the complete Claude lifecycle contract used by every gate."""

    return {
        "SessionStart": HookSpec("claude", "session-hook", (), 10),
        "Stop": HookSpec(
            "claude",
            "stop-hook",
            (
                "--protocol", "claude", "--event", "stop-hook",
                "--auto-closeout", "--timeout", "300",
            ),
            320,
        ),
        "SessionEnd": HookSpec(
            "claude",
            "stop-hook",
            (
                "--protocol", "claude", "--event", "session-end",
                "--auto-closeout", "--non-blocking", "--timeout", "45",
            ),
            60,
        ),
    }


@dataclass(frozen=True)
class RouteClassification:
    kind: str
    reason_code: str
    wrapper_path: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "reason_code": self.reason_code,
            "wrapper_path": self.wrapper_path,
        }


@dataclass(frozen=True)
class LaunchAgentSpec:
    label: str
    plist_path: Path
    runtime_root: Path
    runtime_python: Path
    stdout_path: Path
    stderr_path: Path
    working_directory: Path
    weekday: int = AUDIT_WEEKDAY
    hour: int = AUDIT_HOUR
    minute: int = AUDIT_MINUTE

    @property
    def memoryctl(self) -> Path:
        return self.runtime_root / "scripts" / "memoryctl"

    @property
    def program_arguments(self) -> tuple[str, ...]:
        return (
            str(self.runtime_python),
            "-I",
            "-S",
            str(self.memoryctl),
            "--actor",
            AUDIT_ACTOR,
            "audit-autorun",
            "--reason",
            AUDIT_REASON,
            "--notify",
            "--json",
        )


def lexical_path(value: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(os.fspath(value))))


def _bounded_symlink_target_text(
    path: Path,
    *,
    max_bytes: int,
    max_links: int = 8,
) -> str | None:
    """Read a bounded final regular target without opening through a symlink.

    A legacy Hook or scheduler can be hidden behind a generically named
    symlink. Ignoring every such path creates a duplicate-route false green,
    while opening the original symlink would introduce a target-swap race.
    Resolve only a bounded link chain, then open the final inode with
    ``O_NOFOLLOW`` when available and verify the opened inode against lstat.
    The text is used only for route classification and is never returned in a
    Doctor or installer payload.
    """

    current = path
    seen: set[str] = set()
    followed = False
    for _ in range(max_links + 1):
        try:
            metadata = current.lstat()
        except OSError:
            return None
        if not stat.S_ISLNK(metadata.st_mode):
            break
        followed = True
        identity = lexical_path(current)
        if identity in seen:
            return None
        seen.add(identity)
        try:
            target = os.readlink(current)
        except OSError:
            return None
        current = Path(target) if os.path.isabs(target) else current.parent / target
        current = Path(os.path.abspath(os.path.normpath(str(current))))
    else:
        return None

    if not followed or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(current, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > max_bytes
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
        ):
            return None
        content = os.read(descriptor, max_bytes + 1)
        if len(content) > max_bytes:
            return None
        return content.decode("utf-8", errors="replace")
    except OSError:
        return None
    finally:
        os.close(descriptor)


def split_command(raw_command: object) -> list[str] | None:
    if not isinstance(raw_command, str) or not raw_command.strip():
        return None
    try:
        argv = shlex.split(raw_command, posix=os.name != "nt")
    except ValueError:
        return None
    return argv or None


def split_windows_command(raw_command: object) -> list[str] | None:
    """Split a Windows command line deterministically on every host OS.

    `shlex(..., posix=True)` consumes backslashes in paths such as
    `C:\\Users\\...\\stop-hook.ps1`.  Host classification is also exercised by
    Linux CI, so it cannot depend on the OS running the test.
    """

    if not isinstance(raw_command, str) or not raw_command.strip():
        return None
    try:
        argv = shlex.split(raw_command, posix=False)
    except ValueError:
        return None
    normalized: list[str] = []
    for item in argv:
        if len(item) >= 2 and item[0] == item[-1] and item[0] in {'"', "'"}:
            item = item[1:-1]
        normalized.append(item)
    return normalized or None


def windows_lexical_path(value: str | os.PathLike[str]) -> str:
    """Normalize a Windows path without consulting the current host OS."""

    text = os.fspath(value).strip().strip('"').replace("/", "\\")
    return ntpath.normcase(ntpath.normpath(text))


def _forwarded_option(spec: HookSpec, option: str) -> str | None:
    values = [
        spec.forwarded[index + 1]
        for index, item in enumerate(spec.forwarded[:-1])
        if item == option
    ]
    return values[0] if len(values) == 1 else None


def _windows_wrapper_contract(spec: HookSpec) -> tuple[str, bool] | None:
    """Map a canonical memoryctl Stop contract to the PowerShell adapter."""

    if spec.command_name != "stop-hook":
        return None
    protocol = _forwarded_option(spec, "--protocol")
    event = _forwarded_option(spec, "--event")
    timeout = _forwarded_option(spec, "--timeout")
    auto_closeout = "--auto-closeout" in spec.forwarded
    allowed = {"--protocol", "--event", "--timeout", "--auto-closeout"}
    index = 0
    while index < len(spec.forwarded):
        item = spec.forwarded[index]
        if item not in allowed:
            return None
        index += 1 if item == "--auto-closeout" else 2
    if index != len(spec.forwarded):
        return None
    if not protocol or event != "stop-hook" or timeout != "300":
        return None
    if float(spec.timeout) != float(320 if auto_closeout else 20):
        return None
    return protocol, auto_closeout


def canonical_windows_hook_argv(runtime_root: Path, spec: HookSpec) -> tuple[str, ...]:
    """Return the Windows form of the same managed ``memoryctl`` contract.

    ``stop-hook.ps1`` remains shipped for backwards compatibility, but a Host
    route must not execute that adapter (or either low-level Python module).
    Deriving the interpreter from ``runtime_root`` also makes this contract
    deterministic when it is classified by POSIX CI.
    """

    return (
        str(runtime_root / ".venv" / "Scripts" / "python.exe"),
        "-I",
        "-S",
        str(runtime_root / "scripts" / "memoryctl"),
        "--actor",
        spec.actor,
        spec.command_name,
        *spec.forwarded,
    )


def canonical_windows_hook_command(runtime_root: Path, spec: HookSpec) -> str:
    return subprocess.list2cmdline(list(canonical_windows_hook_argv(runtime_root, spec)))


def _windows_wrapper_route(
    entry: dict[str, Any],
    *,
    raw_command: object,
    runtime_root: Path,
    spec: HookSpec,
) -> RouteClassification | None:
    """Classify the retained PowerShell adapter as legacy, never canonical."""

    command_text = str(raw_command or "")
    if "stop-hook.ps1" not in command_text.casefold():
        return None
    argv = split_windows_command(raw_command)
    if argv is None:
        return RouteClassification(AMBIGUOUS, "HOOK_WINDOWS_WRAPPER_UNPARSEABLE")
    wrapper_tokens = [
        item for item in argv if ntpath.basename(item.replace("/", "\\")).casefold() == "stop-hook.ps1"
    ]
    wrapper_path = wrapper_tokens[0] if len(wrapper_tokens) == 1 else ""
    contract = _windows_wrapper_contract(spec)
    if contract is None:
        return RouteClassification(
            AMBIGUOUS,
            "HOOK_WINDOWS_WRAPPER_SPEC_MISMATCH",
            wrapper_path,
        )
    protocol, auto_closeout = contract
    expected = (
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(runtime_root / "scripts" / "stop-hook.ps1"),
        "-Actor",
        spec.actor,
        "-Protocol",
        protocol,
        *(("-AutoCloseout",) if auto_closeout else ()),
    )
    exact = len(argv) == len(expected)
    if exact:
        for index, (actual, wanted) in enumerate(zip(argv, expected)):
            if index == 5:
                exact = windows_lexical_path(actual) == windows_lexical_path(wanted)
            else:
                exact = actual.casefold() == wanted.casefold()
            if not exact:
                break
    if not exact:
        return RouteClassification(
            AMBIGUOUS,
            "HOOK_WINDOWS_WRAPPER_COMMAND_MISMATCH",
            wrapper_path,
        )
    timeout = entry.get("timeout")
    if (
        entry.get("type") != "command"
        or not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
    ):
        return RouteClassification(
            AMBIGUOUS,
            "HOOK_CANONICAL_METADATA_INVALID",
            wrapper_path,
        )
    if float(timeout) != float(spec.timeout):
        return RouteClassification(AMBIGUOUS, "HOOK_TIMEOUT_MISMATCH", wrapper_path)
    return RouteClassification(LEGACY, "HOOK_WINDOWS_WRAPPER_LEGACY", wrapper_path)


def _windows_memoryctl_route(
    entry: dict[str, Any],
    *,
    raw_command: object,
    runtime_root: Path,
    spec: HookSpec,
) -> RouteClassification | None:
    """Classify a native Windows managed-Python route on every host OS."""

    argv = split_windows_command(raw_command)
    if argv is None or not argv:
        return None
    executable_name = ntpath.basename(argv[0].replace("/", "\\")).casefold()
    if executable_name != "python.exe":
        return None
    expected = canonical_windows_hook_argv(runtime_root, spec)
    exact = len(argv) == len(expected)
    if exact:
        for index, (actual, wanted) in enumerate(zip(argv, expected)):
            exact = (
                windows_lexical_path(actual) == windows_lexical_path(wanted)
                if index in {0, 3}
                else actual == wanted
            )
            if not exact:
                break
    if not exact:
        if any(
            ntpath.basename(item.replace("/", "\\")).casefold() == "memoryctl"
            for item in argv
        ):
            return RouteClassification(AMBIGUOUS, "HOOK_WINDOWS_MEMORYCTL_ROUTE_MISMATCH")
        return None
    timeout = entry.get("timeout")
    if (
        entry.get("type") != "command"
        or not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
    ):
        return RouteClassification(AMBIGUOUS, "HOOK_CANONICAL_METADATA_INVALID")
    if float(timeout) != float(spec.timeout):
        return RouteClassification(AMBIGUOUS, "HOOK_TIMEOUT_MISMATCH")
    return RouteClassification(CANONICAL, "HOOK_WINDOWS_MEMORYCTL_CANONICAL")


def canonical_hook_argv(
    runtime_python: Path,
    runtime_root: Path,
    spec: HookSpec,
) -> tuple[str, ...]:
    return (
        str(runtime_python),
        "-I",
        "-S",
        str(runtime_root / "scripts" / "memoryctl"),
        "--actor",
        spec.actor,
        spec.command_name,
        *spec.forwarded,
    )


def canonical_hook_command(
    runtime_python: Path,
    runtime_root: Path,
    spec: HookSpec,
) -> str:
    return shlex.join(list(canonical_hook_argv(runtime_python, runtime_root, spec)))


def _token_names(argv: Iterable[str]) -> tuple[str, ...]:
    return tuple(Path(item.strip('"')).name.casefold() for item in argv)


def _mentions_hook_route(argv: list[str], command_name: str | None = None) -> bool:
    names = _token_names(argv)
    if any(name in _KNOWN_HOOK_NAMES for name in names):
        return True
    # Shell adapters commonly place their real command in one `-c` argument,
    # so token basenames alone are insufficient.  Treat an embedded managed
    # filename as route evidence; this is deliberately conservative because an
    # unclassified second Stop route is more dangerous than an explicit review.
    lowered_tokens = tuple(str(item).casefold() for item in argv)
    if any(
        known_name in token
        for token in lowered_tokens
        for known_name in _KNOWN_HOOK_NAMES
    ):
        return True
    for index, name in enumerate(names):
        if name != "memoryctl":
            if "memoryctl" not in lowered_tokens[index]:
                continue
        tail = argv[index + 1 :]
        tail_text = " ".join(str(item).casefold() for item in tail)
        if command_name is None:
            return "stop-hook" in tail_text or "session-hook" in tail_text
        return command_name.casefold() in tail_text
    return False


def _wrapper_route(
    argv: list[str],
    *,
    spec: HookSpec,
    max_bytes: int = 65536,
) -> RouteClassification | None:
    """Classify bounded wrappers without executing or following symlinks.

    A wrapper may be invoked directly or through ``bash``, ``sh``, ``env``,
    ``timeout``, or a shell ``-c`` argument.  Scan only regular file arguments
    and never the canonical Runtime executables themselves.
    """

    # Include argv[0] as well as arguments.  A generic wrapper can be invoked
    # directly with its own flags (``/path/wrapper --quiet``); looking only at
    # argv[0] for single-token commands or argv[1:] for multi-token commands
    # lets that second Stop route disappear merely by adding one argument.
    raw_candidates: list[str] = list(argv)
    # One level of nested tokenization covers `sh -c '/path/wrapper ...'`
    # without evaluating shell syntax.
    for token in tuple(raw_candidates):
        if not any(character.isspace() for character in token):
            continue
        nested = split_command(token)
        if nested:
            raw_candidates.extend(nested)

    seen: set[str] = set()
    for raw_candidate in raw_candidates:
        if not raw_candidate or raw_candidate.startswith("-"):
            continue
        candidate_name = Path(raw_candidate.strip('"')).name.casefold()
        if candidate_name in {
            "memoryctl",
            "agent_memory_session_hook.py",
            "agent_memory_stop_hook.py",
        }:
            continue
        wrapper = Path(os.path.abspath(os.path.expanduser(raw_candidate.strip('"'))))
        wrapper_key = lexical_path(wrapper)
        if wrapper_key in seen:
            continue
        seen.add(wrapper_key)
        try:
            metadata = wrapper.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            target_text = _bounded_symlink_target_text(
                wrapper,
                max_bytes=max_bytes,
            )
            target_lowered = target_text.casefold() if target_text is not None else ""
            if candidate_name in _KNOWN_HOOK_NAMES or any(
                name in target_lowered for name in _KNOWN_HOOK_NAMES
            ) or (
                "memoryctl" in target_lowered
                and spec.command_name in target_lowered
            ):
                return RouteClassification(
                    AMBIGUOUS,
                    "HOOK_WRAPPER_SYMLINK",
                    str(wrapper),
                )
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            continue
        try:
            text = wrapper.read_text(encoding="utf-8", errors="replace")
        except OSError:
            if candidate_name in _KNOWN_HOOK_NAMES:
                return RouteClassification(
                    AMBIGUOUS,
                    "HOOK_WRAPPER_UNREADABLE",
                    str(wrapper),
                )
            continue
        lowered = text.casefold()
        if not any(name in lowered for name in _KNOWN_HOOK_NAMES) and not (
            "memoryctl" in lowered and spec.command_name in lowered
        ):
            continue
        actor_match = re.search(r"(?:--actor|--actor=)[ \t=]*([a-z0-9_-]+)", lowered)
        if actor_match and actor_match.group(1) != spec.actor.casefold():
            return RouteClassification(
                AMBIGUOUS,
                "HOOK_WRAPPER_ACTOR_MISMATCH",
                str(wrapper),
            )
        return RouteClassification(LEGACY, "HOOK_WRAPPER_LEGACY", str(wrapper))
    return None


def classify_hook_entry(
    entry: object,
    *,
    runtime_python: Path,
    runtime_root: Path,
    spec: HookSpec,
) -> RouteClassification:
    if not isinstance(entry, dict):
        return RouteClassification(UNRELATED, "HOOK_ENTRY_NOT_OBJECT")
    raw_command = entry.get("command")
    windows_wrapper = _windows_wrapper_route(
        entry,
        raw_command=raw_command,
        runtime_root=runtime_root,
        spec=spec,
    )
    if windows_wrapper is not None:
        return windows_wrapper
    windows_memoryctl = _windows_memoryctl_route(
        entry,
        raw_command=raw_command,
        runtime_root=runtime_root,
        spec=spec,
    )
    if windows_memoryctl is not None:
        return windows_memoryctl
    argv = split_command(raw_command)
    if argv is None:
        command_text = str(raw_command or "").casefold()
        if any(name in command_text for name in _KNOWN_HOOK_NAMES) or (
            "memoryctl" in command_text and spec.command_name in command_text
        ):
            return RouteClassification(AMBIGUOUS, "HOOK_COMMAND_UNPARSEABLE")
        return RouteClassification(UNRELATED, "HOOK_COMMAND_UNRELATED")

    expected = canonical_hook_argv(runtime_python, runtime_root, spec)
    timeout = entry.get("timeout")
    exact_argv = (
        len(argv) == len(expected)
        and lexical_path(argv[0]) == lexical_path(expected[0])
        and tuple(argv[1:3]) == expected[1:3]
        and lexical_path(argv[3]) == lexical_path(expected[3])
        and tuple(argv[4:]) == expected[4:]
    )
    if exact_argv:
        if entry.get("type") != "command" or not isinstance(timeout, (int, float)):
            return RouteClassification(AMBIGUOUS, "HOOK_CANONICAL_METADATA_INVALID")
        if float(timeout) != float(spec.timeout):
            return RouteClassification(AMBIGUOUS, "HOOK_TIMEOUT_MISMATCH")
        return RouteClassification(CANONICAL, "HOOK_CANONICAL")

    wrapper = _wrapper_route(argv, spec=spec)
    if wrapper is not None:
        return wrapper

    names = _token_names(argv)
    expected_script = spec.script_name.casefold()
    if expected_script in names:
        actor_values = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "--actor"]
        if actor_values and any(value != spec.actor for value in actor_values):
            return RouteClassification(AMBIGUOUS, "HOOK_LEGACY_ACTOR_MISMATCH")
        return RouteClassification(LEGACY, "HOOK_DIRECT_SCRIPT_LEGACY")

    if _mentions_hook_route(argv, spec.command_name):
        return RouteClassification(AMBIGUOUS, "HOOK_MEMORYCTL_ROUTE_MISMATCH")
    return RouteClassification(UNRELATED, "HOOK_COMMAND_UNRELATED")


def _hook_node_disabled(node: object) -> bool:
    return bool(
        isinstance(node, dict)
        and (node.get("enabled") is False or node.get("disabled") is True)
    )


def _event_hook_entries_with_state(
    hooks: object,
    event: str,
) -> list[tuple[dict[str, Any], bool, bool]]:
    if not isinstance(hooks, dict):
        return []
    groups = hooks.get(event, [])
    if not isinstance(groups, list):
        return []
    event_disabled = _hook_node_disabled(hooks)
    entries: list[tuple[dict[str, Any], bool, bool]] = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
            continue
        inherited_disabled = event_disabled or _hook_node_disabled(group)
        # Lifecycle closeout must be a catch-all route.  Reusing an otherwise
        # canonical command inside a matcher-scoped group can prevent normal
        # Stop/SessionEnd events from reaching it while still looking exact to
        # a command-only classifier.
        matcher = group.get("matcher")
        inherited_scoped = (
            "matcher" in group and matcher is not None and matcher != ""
        )
        entries.extend(
            (
                item,
                inherited_disabled or _hook_node_disabled(item),
                inherited_scoped,
            )
            for item in group["hooks"]
            if isinstance(item, dict)
        )
    return entries


def event_hook_entries(hooks: object, event: str) -> list[dict[str, Any]]:
    return [
        entry
        for entry, _disabled, _scoped in _event_hook_entries_with_state(hooks, event)
    ]


def classify_hook_event(
    hooks: object,
    event: str,
    *,
    runtime_python: Path,
    runtime_root: Path,
    spec: HookSpec,
) -> dict[str, Any]:
    counts = {kind: 0 for kind in ROUTE_KINDS}
    reasons: dict[str, int] = {}
    wrapper_paths: list[str] = []
    disabled_count = 0
    for entry, disabled, scoped in _event_hook_entries_with_state(hooks, event):
        result = classify_hook_entry(
            entry,
            runtime_python=runtime_python,
            runtime_root=runtime_root,
            spec=spec,
        )
        if disabled and result.kind != UNRELATED:
            disabled_count += 1
            result = RouteClassification(
                AMBIGUOUS,
                "HOOK_ROUTE_DISABLED",
                result.wrapper_path,
            )
        elif scoped and result.kind != UNRELATED:
            result = RouteClassification(
                AMBIGUOUS,
                "HOOK_ROUTE_MATCHER_SCOPED",
                result.wrapper_path,
            )
        counts[result.kind] += 1
        reasons[result.reason_code] = reasons.get(result.reason_code, 0) + 1
        if result.wrapper_path:
            wrapper_paths.append(result.wrapper_path)
    if _hook_node_disabled(hooks) and not disabled_count:
        # A globally disabled Hook container cannot be healthy even when an
        # empty/malformed event hides all of its managed entries.
        counts[AMBIGUOUS] += 1
        disabled_count += 1
        reasons["HOOK_EVENT_DISABLED"] = reasons.get("HOOK_EVENT_DISABLED", 0) + 1
    healthy = counts[CANONICAL] == 1 and counts[LEGACY] == 0 and counts[AMBIGUOUS] == 0
    return {
        "healthy": healthy,
        "canonical_count": counts[CANONICAL],
        "legacy_count": counts[LEGACY],
        "ambiguous_count": counts[AMBIGUOUS],
        "unrelated_count": counts[UNRELATED],
        "disabled_count": disabled_count,
        "wrapper_paths": sorted(set(wrapper_paths)),
        "reason_counts": reasons,
    }


def classify_claude_hooks(
    hooks: object,
    *,
    runtime_python: Path,
    runtime_root: Path,
) -> dict[str, Any]:
    """Return a stable semantic proof for Claude's three managed routes.

    Only the effective lifecycle routes enter the fingerprint. Unrelated
    settings, environment keys, permissions, models, and unrelated Hooks are
    deliberately excluded from Runtime readiness.
    """

    events = {
        event: classify_hook_event(
            hooks,
            event,
            runtime_python=runtime_python,
            runtime_root=runtime_root,
            spec=spec,
        )
        for event, spec in claude_hook_specs().items()
    }
    projection = {
        event: {
            key: detail[key]
            for key in (
                "healthy",
                "canonical_count",
                "legacy_count",
                "ambiguous_count",
                "disabled_count",
                "reason_counts",
            )
        }
        for event, detail in events.items()
    }
    fingerprint = hashlib.sha256(
        json.dumps(
            projection,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "healthy": all(bool(detail["healthy"]) for detail in events.values()),
        "events": events,
        "semantic_fingerprint_sha256": fingerprint,
    }


def any_agent_memory_hook_route(raw_command: object, *, command_name: str | None = None) -> bool:
    if "stop-hook.ps1" in str(raw_command or "").casefold():
        return command_name in {None, "stop-hook"}
    argv = split_command(raw_command)
    if argv is None:
        text = str(raw_command or "").casefold()
        return any(name in text for name in _KNOWN_HOOK_NAMES) or (
            "memoryctl" in text
            and (command_name in text if command_name else ("stop-hook" in text or "session-hook" in text))
        )
    if _mentions_hook_route(argv, command_name):
        return True
    # Reuse the same bounded wrapper discovery as the semantic classifier.
    # Actor/timeout are immaterial here: this predicate intentionally removes
    # every managed or malformed route before the installer adds one canonical
    # replacement.
    probe_name = command_name or "stop-hook"
    probe_spec = HookSpec("codex", probe_name, (), 0)
    if _wrapper_route(argv, spec=probe_spec) is not None:
        return True
    if command_name is None:
        return _wrapper_route(
            argv,
            spec=HookSpec("codex", "session-hook", (), 0),
        ) is not None
    return False


def _route_token_matches_path(raw_token: object, expected: Path) -> bool:
    token = str(raw_token or "").strip().strip('"').strip("'")
    if not token:
        return False
    return (
        lexical_path(token) == lexical_path(expected)
        or windows_lexical_path(token) == windows_lexical_path(expected)
    )


def _bounded_wrapper_rewrite_text(path: Path, *, max_bytes: int = 65536) -> str | None:
    """Read bounded wrapper evidence without following a final path swap."""

    try:
        metadata = path.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(metadata.st_mode):
        return _bounded_symlink_target_text(path, max_bytes=max_bytes)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > max_bytes
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
        ):
            return None
        content = os.read(descriptor, max_bytes + 1)
        if len(content) > max_bytes:
            return None
        return content.decode("utf-8", errors="replace")
    except OSError:
        return None
    finally:
        os.close(descriptor)


def codex_stop_route_rewrite_authorized(
    entry: object,
    *,
    runtime_root: Path,
    classification: RouteClassification,
) -> bool:
    """Return whether the Windows installer may remove this existing route.

    Classification is deliberately conservative: a third-party command can be
    ambiguous merely because its executable is named ``stop-hook.ps1`` or
    ``memoryctl``. Rewrite authority is narrower and requires an exact managed
    Runtime target or bounded wrapper contents with Agent Memory-specific Stop
    evidence. Unknown ambiguous entries must survive a failed installation.
    """

    if classification.kind == UNRELATED or not isinstance(entry, dict):
        return False
    raw_command = entry.get("command")
    argv_candidates: list[list[str]] = []
    for splitter in (split_windows_command, split_command):
        argv = splitter(raw_command)
        if argv and argv not in argv_candidates:
            argv_candidates.append(argv)
    memoryctl = runtime_root / "scripts" / "memoryctl"
    direct_script = runtime_root / "scripts" / "agent_memory_stop_hook.py"
    legacy_wrapper = runtime_root / "scripts" / "stop-hook.ps1"
    for argv in argv_candidates:
        for index, token in enumerate(argv):
            if _route_token_matches_path(token, direct_script) or _route_token_matches_path(
                token,
                legacy_wrapper,
            ):
                return True
            if _route_token_matches_path(token, memoryctl) and "stop-hook" in {
                str(item).casefold() for item in argv[index + 1 :]
            }:
                return True

    wrapper_path = str(classification.wrapper_path or "").strip()
    if not wrapper_path:
        return False
    wrapper = Path(os.path.abspath(os.path.expanduser(wrapper_path)))
    text = _bounded_wrapper_rewrite_text(wrapper)
    if text is None:
        return False
    lowered = text.casefold()
    actor_codex = re.search(r"--actor(?:\s+|=)codex(?:\b|['\"])", lowered) is not None
    exact_direct = any(
        marker in lowered
        for marker in {
            str(direct_script).casefold(),
            str(direct_script).replace("/", "\\").casefold(),
        }
    )
    exact_memoryctl = any(
        marker in lowered
        for marker in {
            str(memoryctl).casefold(),
            str(memoryctl).replace("/", "\\").casefold(),
        }
    )
    return bool(
        exact_direct
        or (exact_memoryctl and "stop-hook" in lowered)
        or (actor_codex and "agent_memory_stop_hook.py" in lowered)
        or (actor_codex and "memoryctl" in lowered and "stop-hook" in lowered)
    )


def launchagent_payload(spec: LaunchAgentSpec) -> dict[str, Any]:
    return {
        "Label": spec.label,
        "ProgramArguments": list(spec.program_arguments),
        "StartCalendarInterval": {
            "Weekday": spec.weekday,
            "Hour": spec.hour,
            "Minute": spec.minute,
        },
        "StandardOutPath": str(spec.stdout_path),
        "StandardErrorPath": str(spec.stderr_path),
        "WorkingDirectory": str(spec.working_directory),
    }


def launchagent_bytes(spec: LaunchAgentSpec) -> bytes:
    return plistlib.dumps(launchagent_payload(spec), fmt=plistlib.FMT_XML, sort_keys=False)


def load_launchagent_payload(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError("AUDIT_LAUNCHAGENT_UNSAFE")
    if not path.exists():
        return {}
    if not path.is_file():
        raise ValueError("AUDIT_LAUNCHAGENT_UNSAFE")
    try:
        payload = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise ValueError("AUDIT_LAUNCHAGENT_INVALID") from exc
    if not isinstance(payload, dict):
        raise ValueError("AUDIT_LAUNCHAGENT_INVALID")
    return payload


def classify_launchagent_payload(payload: object, spec: LaunchAgentSpec) -> RouteClassification:
    if not isinstance(payload, dict) or not payload:
        return RouteClassification(AMBIGUOUS, "AUDIT_LAUNCHAGENT_MISSING")
    arguments = payload.get("ProgramArguments")
    expected = launchagent_payload(spec)
    if payload == expected:
        return RouteClassification(CANONICAL, "AUDIT_LAUNCHAGENT_CANONICAL")
    if not isinstance(arguments, list) or not all(isinstance(item, str) for item in arguments):
        return RouteClassification(AMBIGUOUS, "AUDIT_LAUNCHAGENT_ARGUMENTS_INVALID")
    names = _token_names(arguments)
    lowered_arguments = [item.casefold() for item in arguments]
    if "agent_memory_audit_autorun.py" in names or any(
        "agent_memory_audit_autorun.py" in item for item in lowered_arguments
    ):
        return RouteClassification(LEGACY, "AUDIT_LAUNCHAGENT_DIRECT_SCRIPT_LEGACY")
    if (
        "memoryctl" in names and "audit-autorun" in arguments
    ) or any("memoryctl" in item and "audit-autorun" in item for item in lowered_arguments):
        return RouteClassification(AMBIGUOUS, "AUDIT_LAUNCHAGENT_CANONICAL_DRIFT")
    wrapper = _launchagent_wrapper_route(arguments)
    if wrapper is not None:
        return wrapper
    if payload.get("Label") == spec.label:
        return RouteClassification(AMBIGUOUS, "AUDIT_LAUNCHAGENT_LABEL_COLLISION")
    return RouteClassification(UNRELATED, "AUDIT_LAUNCHAGENT_UNRELATED")


def _launchagent_wrapper_route(
    arguments: list[str],
    *,
    max_bytes: int = 65536,
) -> RouteClassification | None:
    """Recognize a bounded shell/script wrapper without executing it.

    Old audit jobs were sometimes hidden behind a generically named wrapper.
    Treat those as legacy (or ambiguous when unsafe) so a second scheduler
    cannot evade the shared inventory merely by changing its filename.
    """

    raw_candidates = list(arguments)
    # Cover shell adapters such as ``sh -c '/path/weekly-maintenance --run'``
    # without evaluating shell syntax.  The bounded regular-file read below is
    # still the only way a generically named candidate becomes an audit route.
    for token in tuple(raw_candidates):
        if not any(character.isspace() for character in token):
            continue
        nested = split_command(token)
        if nested:
            raw_candidates.extend(nested)

    seen: set[str] = set()
    for raw_candidate in raw_candidates:
        if not raw_candidate or raw_candidate.startswith("-"):
            continue
        candidate_name = Path(raw_candidate.strip('"')).name.casefold()
        if candidate_name in {
            "memoryctl",
            "agent_memory_audit_autorun.py",
        }:
            continue
        candidate = Path(
            os.path.abspath(os.path.expanduser(raw_candidate.strip('"')))
        )
        candidate_key = lexical_path(candidate)
        if candidate_key in seen:
            continue
        seen.add(candidate_key)
        try:
            metadata = candidate.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            target_text = _bounded_symlink_target_text(
                candidate,
                max_bytes=max_bytes,
            )
            target_lowered = target_text.casefold() if target_text is not None else ""
            if _has_agent_memory_token(candidate.name) or (
                "agent_memory_audit_autorun.py" in target_lowered
                or ("memoryctl" in target_lowered and "audit-autorun" in target_lowered)
            ):
                return RouteClassification(
                    AMBIGUOUS,
                    "AUDIT_LAUNCHAGENT_WRAPPER_SYMLINK",
                    str(candidate),
                )
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace").casefold()
        except OSError:
            return RouteClassification(
                AMBIGUOUS,
                "AUDIT_LAUNCHAGENT_WRAPPER_UNREADABLE",
                str(candidate),
            )
        if "agent_memory_audit_autorun.py" in text:
            return RouteClassification(
                LEGACY,
                "AUDIT_LAUNCHAGENT_WRAPPER_LEGACY",
                str(candidate),
            )
        if "memoryctl" in text and "audit-autorun" in text:
            return RouteClassification(
                AMBIGUOUS,
                "AUDIT_LAUNCHAGENT_WRAPPER_DRIFT",
                str(candidate),
            )
    return None


def _has_agent_memory_token(value: object) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(value or "").casefold())
    return "agentmemory" in normalized


def is_audit_launchagent_candidate(
    path: Path,
    payload: object,
    spec: LaunchAgentSpec,
) -> bool:
    """Return whether a non-target plist contains Agent Memory evidence."""

    if lexical_path(path) == lexical_path(spec.plist_path):
        return True
    if _has_agent_memory_token(path.name):
        return True
    if not isinstance(payload, dict):
        return False
    if _has_agent_memory_token(payload.get("Label")):
        return True
    arguments = payload.get("ProgramArguments")
    if not isinstance(arguments, list) or not all(isinstance(item, str) for item in arguments):
        return False
    lowered = [item.casefold() for item in arguments]
    if any("agent_memory_audit_autorun.py" in item for item in lowered):
        return True
    if any("memoryctl" in item and "audit-autorun" in item for item in lowered):
        return True
    names = _token_names(arguments)
    if "memoryctl" in names and "audit-autorun" in arguments:
        return True
    return _launchagent_wrapper_route(arguments) is not None


def discover_audit_launchagents(directory: Path, spec: LaunchAgentSpec) -> dict[str, Any]:
    """Classify every user LaunchAgent that can schedule Agent Memory audit.

    Looking only at the configured label misses a second scheduler introduced
    later under another filename/label.  This bounded scan reads plist metadata
    only and returns paths plus controlled classifications, never job
    environments or command output.
    """

    routes: list[dict[str, str]] = []
    if not directory.exists() and not directory.is_symlink():
        return {
            "healthy": False,
            "canonical_count": 0,
            "legacy_count": 0,
            "ambiguous_count": 0,
            "routes": [],
        }
    if directory.is_symlink() or not directory.is_dir():
        return {
            "healthy": False,
            "canonical_count": 0,
            "legacy_count": 0,
            "ambiguous_count": 1,
            "routes": [{
                "path": str(directory),
                "kind": AMBIGUOUS,
                "reason_code": "AUDIT_LAUNCHAGENT_DIRECTORY_UNSAFE_OR_MISSING",
            }],
        }
    for path in sorted(directory.glob("*.plist")):
        target = lexical_path(path) == lexical_path(spec.plist_path)
        try:
            if path.is_symlink():
                if target or _has_agent_memory_token(path.name):
                    result = RouteClassification(AMBIGUOUS, "AUDIT_LAUNCHAGENT_SYMLINK", str(path))
                else:
                    continue
            else:
                payload = load_launchagent_payload(path)
                if not is_audit_launchagent_candidate(path, payload, spec):
                    continue
                result = classify_launchagent_payload(payload, spec)
        except ValueError as exc:
            if not target and not _has_agent_memory_token(path.name):
                continue
            result = RouteClassification(AMBIGUOUS, str(exc), str(path))
        if result.kind == UNRELATED:
            continue
        routes.append(
            {
                "path": str(path),
                "kind": result.kind,
                "reason_code": result.reason_code,
            }
        )
    counts = {
        kind: sum(1 for row in routes if row["kind"] == kind)
        for kind in (CANONICAL, LEGACY, AMBIGUOUS)
    }
    return {
        "healthy": counts[CANONICAL] == 1 and counts[LEGACY] == 0 and counts[AMBIGUOUS] == 0,
        "canonical_count": counts[CANONICAL],
        "legacy_count": counts[LEGACY],
        "ambiguous_count": counts[AMBIGUOUS],
        "routes": routes,
    }


def discover_all_audit_launchagents(spec: LaunchAgentSpec) -> dict[str, Any]:
    """Inventory both the configured directory and the user's full LaunchAgents.

    ``working_directory`` is the managed user's home in the production spec.
    Scanning both locations keeps a custom/stale configured path from hiding a
    second job in ``~/Library/LaunchAgents``. Missing non-target directories are
    simply empty; an unsafe directory remains an ambiguous route.
    """

    canonical_directory = spec.working_directory / "Library" / "LaunchAgents"
    directories: list[Path] = []
    for directory in (canonical_directory, spec.plist_path.parent):
        normalized = Path(os.path.abspath(os.path.expanduser(str(directory))))
        if normalized not in directories:
            directories.append(normalized)

    routes: list[dict[str, str]] = []
    scanned: list[str] = []
    for directory in directories:
        scanned.append(str(directory))
        if not directory.exists() and not directory.is_symlink():
            continue
        result = discover_audit_launchagents(directory, spec)
        routes.extend(result["routes"])

    # The directories can overlap through lexical aliases. De-duplicate only
    # identical path/classification records; never collapse distinct jobs.
    unique_routes: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in routes:
        identity = (
            lexical_path(row["path"]),
            str(row["kind"]),
            str(row["reason_code"]),
        )
        if identity in seen:
            continue
        seen.add(identity)
        unique_routes.append(row)
    counts = {
        kind: sum(1 for row in unique_routes if row["kind"] == kind)
        for kind in (CANONICAL, LEGACY, AMBIGUOUS)
    }
    return {
        "healthy": counts[CANONICAL] == 1 and counts[LEGACY] == 0 and counts[AMBIGUOUS] == 0,
        "canonical_count": counts[CANONICAL],
        "legacy_count": counts[LEGACY],
        "ambiguous_count": counts[AMBIGUOUS],
        "directories": scanned,
        "routes": unique_routes,
    }


def parse_launchctl_print(text: str) -> dict[str, Any]:
    """Extract bounded health fields without returning environment contents."""

    detail: dict[str, Any] = {
        "state": "",
        "program": "",
        "arguments": [],
        "runs": None,
        "last_exit_code": None,
    }
    lines = text.splitlines()
    for line in lines:
        match = re.match(r"^[ \t]*(state|program|runs|last exit code) = (.*)$", line)
        if not match:
            continue
        key, raw = match.groups()
        if key == "state" and not detail["state"]:
            detail["state"] = raw.strip()
        elif key == "program" and not detail["program"]:
            detail["program"] = raw.strip()
        elif key == "runs" and detail["runs"] is None:
            try:
                detail["runs"] = int(raw.strip())
            except ValueError:
                pass
        elif key == "last exit code" and detail["last_exit_code"] is None:
            try:
                detail["last_exit_code"] = int(raw.strip())
            except ValueError:
                pass
    for index, line in enumerate(lines):
        if not re.match(r"^[ \t]*arguments = \{$", line):
            continue
        arguments: list[str] = []
        for candidate in lines[index + 1 :]:
            if re.match(r"^[ \t]*\}$", candidate):
                break
            value = candidate.strip()
            if value:
                arguments.append(value)
        detail["arguments"] = arguments
        break
    return detail


def launchctl_health(
    *,
    print_returncode: int,
    print_stdout: str,
    spec: LaunchAgentSpec,
) -> dict[str, Any]:
    # `launchctl print` uses EX_UNAVAILABLE (113) for a service that is
    # definitively absent. Other non-zero statuses include timeouts,
    # permission/domain failures, and transport errors; those are unknown, not
    # evidence that a previously loaded job was absent.
    query_ok = print_returncode in {0, 113}
    known_absent = print_returncode == 113
    parsed = parse_launchctl_print(print_stdout) if print_returncode == 0 else {
        "state": "",
        "program": "",
        "arguments": [],
        "runs": None,
        "last_exit_code": None,
    }
    expected = list(spec.program_arguments)
    arguments = parsed.get("arguments")
    exact_arguments = arguments == expected
    return {
        "loaded": print_returncode == 0,
        "load_state": (
            "loaded"
            if print_returncode == 0
            else ("absent" if known_absent else "unknown")
        ),
        "query_ok": query_ok,
        "print_returncode": print_returncode,
        "state": str(parsed.get("state", "")),
        "program_exact": str(parsed.get("program", "")) == expected[0],
        "arguments_exact": exact_arguments,
        "runs": parsed.get("runs"),
        "last_exit_code": parsed.get("last_exit_code"),
        "healthy": bool(
            print_returncode == 0
            and str(parsed.get("program", "")) == expected[0]
            and exact_arguments
            and parsed.get("last_exit_code") == 0
        ),
    }


def parse_timestamp(value: object) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def json_report_freshness(
    path: Path,
    *,
    now: dt.datetime | None = None,
    max_age_days: int = AUDIT_FRESHNESS_DAYS,
    timestamp_keys: tuple[str, ...] = ("time", "verified_at"),
) -> dict[str, Any]:
    current = now or dt.datetime.now(dt.timezone.utc)
    try:
        import json

        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {"fresh": False, "age_days": None, "reason_code": "REPORT_UNREADABLE"}
    if not isinstance(payload, dict):
        return {"fresh": False, "age_days": None, "reason_code": "REPORT_INVALID"}
    timestamp = next(
        (parse_timestamp(payload.get(key)) for key in timestamp_keys if parse_timestamp(payload.get(key)) is not None),
        None,
    )
    if timestamp is None:
        return {"fresh": False, "age_days": None, "reason_code": "REPORT_TIMESTAMP_MISSING"}
    age_seconds = (current - timestamp).total_seconds()
    if age_seconds < -REPORT_FUTURE_TOLERANCE_SECONDS:
        return {
            "fresh": False,
            "age_days": round(age_seconds / 86400, 2),
            "reason_code": "REPORT_TIMESTAMP_FUTURE",
        }
    age_days = max(0.0, age_seconds / 86400)
    return {
        "fresh": age_days <= max_age_days,
        "age_days": round(age_days, 2),
        "reason_code": "" if age_days <= max_age_days else "REPORT_STALE",
    }


def successful_audit_report_freshness(
    path: Path,
    *,
    now: dt.datetime | None = None,
    max_age_days: int = AUDIT_FRESHNESS_DAYS,
) -> dict[str, Any]:
    """Verify recency and success without returning report content."""

    freshness = json_report_freshness(path, now=now, max_age_days=max_age_days)
    if path.is_symlink():
        return {
            "fresh": False,
            "successful": False,
            "healthy": False,
            "age_days": None,
            "reason_code": "AUDIT_REPORT_UNSAFE",
        }
    try:
        import json

        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        payload = None
    successful = bool(
        isinstance(payload, dict)
        and payload.get("ok") is True
        and payload.get("status") == "ran"
    )
    reason_code = str(freshness.get("reason_code", ""))
    if not successful:
        reason_code = "AUDIT_REPORT_NOT_SUCCESSFUL"
    return {
        **freshness,
        "successful": successful,
        "healthy": bool(freshness.get("fresh") and successful),
        "reason_code": reason_code,
    }


def audit_scheduler_health(
    spec: LaunchAgentSpec,
    *,
    print_returncode: int,
    print_stdout: str,
    success_report_path: Path,
    now: dt.datetime | None = None,
    max_report_age_days: int = AUDIT_FRESHNESS_DAYS,
) -> dict[str, Any]:
    """One shared read-only scheduler verdict for installers and ready gates."""

    try:
        payload = load_launchagent_payload(spec.plist_path)
        classification = classify_launchagent_payload(payload, spec)
    except ValueError as exc:
        classification = RouteClassification(AMBIGUOUS, str(exc))
    loaded = launchctl_health(
        print_returncode=print_returncode,
        print_stdout=print_stdout,
        spec=spec,
    )
    report = successful_audit_report_freshness(
        success_report_path,
        now=now,
        max_age_days=max_report_age_days,
    )
    runs = loaded.get("runs")
    run_observed = isinstance(runs, int) and not isinstance(runs, bool) and runs > 0
    return {
        "healthy": bool(
            classification.kind == CANONICAL
            and loaded.get("healthy")
            and run_observed
            and report.get("healthy")
        ),
        "plist_exists": spec.plist_path.is_file() and not spec.plist_path.is_symlink(),
        "classification": classification.as_dict(),
        "launchctl": loaded,
        "run_observed": run_observed,
        "success_report": report,
    }


def verify_codex_hooks_file(
    hooks_path: Path,
    *,
    runtime_root: Path,
    runtime_python: Path,
    auto_closeout: bool = True,
) -> dict[str, Any]:
    """Read and classify Codex hooks for the Windows installer acceptance gate."""

    if hooks_path.is_symlink() or not hooks_path.is_file():
        return {
            "ok": False,
            "reason_code": "CODEX_HOOKS_UNSAFE_OR_MISSING",
            "classification": {},
        }
    try:
        payload = json.loads(hooks_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {
            "ok": False,
            "reason_code": "CODEX_HOOKS_INVALID_JSON",
            "classification": {},
        }
    if not isinstance(payload, dict):
        return {
            "ok": False,
            "reason_code": "CODEX_HOOKS_INVALID_JSON",
            "classification": {},
        }
    hooks = payload.get("hooks") if isinstance(payload.get("hooks"), dict) else {}
    classification = classify_hook_event(
        hooks,
        "Stop",
        runtime_python=runtime_python,
        runtime_root=runtime_root,
        spec=codex_stop_hook_spec(auto_closeout=auto_closeout),
    )
    return {
        "ok": bool(classification["healthy"]),
        "reason_code": "" if classification["healthy"] else "CODEX_HOOKS_INVALID",
        "classification": classification,
    }


def classify_codex_hook_entry_input(
    raw_input: bytes,
    *,
    runtime_root: Path,
    runtime_python: Path,
    auto_closeout: bool = True,
) -> dict[str, str | bool]:
    """Classify one installer-supplied Hook entry without echoing its command.

    The Windows installer uses this narrow interface to remove canonical,
    legacy, and explicitly Agent-Memory-related ambiguous routes before adding
    one canonical route. Unknown ambiguous third-party entries remain outside
    its rewrite authority. Keeping the entry on stdin prevents arbitrary
    existing Hook commands from becoming process arguments or error output.
    """

    if len(raw_input) > HOOK_ENTRY_INPUT_MAX_BYTES:
        raise ValueError("HOOK_ENTRY_INPUT_TOO_LARGE")
    try:
        entry = json.loads(raw_input.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("HOOK_ENTRY_INPUT_INVALID") from exc
    result = classify_hook_entry(
        entry,
        runtime_python=runtime_python,
        runtime_root=runtime_root,
        spec=codex_stop_hook_spec(auto_closeout=auto_closeout),
    )
    agent_memory_route = codex_stop_route_rewrite_authorized(
        entry,
        runtime_root=runtime_root,
        classification=result,
    )
    return {
        "kind": result.kind,
        "reason_code": result.reason_code,
        "agent_memory_route": agent_memory_route,
    }


def _parse_cli_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only Agent Memory host automation verifier.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify-codex-hook")
    verify.add_argument("--hooks-json", required=True)
    verify.add_argument("--runtime-root", required=True)
    verify.add_argument("--runtime-python", required=True)
    verify.add_argument("--auto-closeout", action="store_true")
    verify.add_argument("--json", action="store_true")
    classify_entry = subparsers.add_parser("classify-codex-hook-entry")
    classify_entry.add_argument("--runtime-root", required=True)
    classify_entry.add_argument("--runtime-python", required=True)
    classify_entry.add_argument("--auto-closeout", action="store_true")
    classify_entry.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_cli_args(argv)
    if args.command == "classify-codex-hook-entry":
        try:
            raw_input = sys.stdin.buffer.read(HOOK_ENTRY_INPUT_MAX_BYTES + 1)
            result = classify_codex_hook_entry_input(
                raw_input,
                runtime_root=Path(args.runtime_root),
                runtime_python=Path(args.runtime_python),
                auto_closeout=bool(args.auto_closeout),
            )
        except ValueError as exc:
            reason_code = str(exc)
            if reason_code not in {
                "HOOK_ENTRY_INPUT_INVALID",
                "HOOK_ENTRY_INPUT_TOO_LARGE",
            }:
                reason_code = "HOOK_ENTRY_CLASSIFICATION_FAILED"
            result = {
                "kind": AMBIGUOUS,
                "reason_code": reason_code,
                "agent_memory_route": False,
            }
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 2
        except Exception:
            # This command consumes untrusted host configuration. Never let an
            # implementation exception echo the original command or a path
            # derived from it; the installer treats any non-zero result as a
            # hard, non-mutating failure.
            result = {
                "kind": AMBIGUOUS,
                "reason_code": "HOOK_ENTRY_CLASSIFICATION_FAILED",
                "agent_memory_route": False,
            }
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 2
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    if args.command != "verify-codex-hook":
        raise AssertionError(args.command)
    result = verify_codex_hooks_file(
        Path(args.hooks_json),
        runtime_root=Path(args.runtime_root),
        runtime_python=Path(args.runtime_python),
        auto_closeout=bool(args.auto_closeout),
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print("CODEX_HOOKS_OK" if result["ok"] else str(result["reason_code"]))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
