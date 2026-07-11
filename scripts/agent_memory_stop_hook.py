#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from agent_memory_env import env_value


REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = Path(os.path.expandvars(env_value("ROOT", str(REPO_ROOT / "templates" / "vault")))).expanduser().resolve()
CONFIG_ROOT = Path(os.path.expandvars(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory"))).expanduser().resolve()
STATE_DB = Path(os.path.expandvars(env_value("STATE_DB", str(CONFIG_ROOT / "state.sqlite")))).expanduser().resolve()
LOG_PATH = Path(os.path.expandvars(env_value("CLOSEOUT_LOG", str(CONFIG_ROOT / "logs" / "closeout.jsonl")))).expanduser().resolve()
CLOSEOUT_SCRIPT = REPO_ROOT / "scripts" / "agent_memory_closeout.py"
AUDIT_AUTORUN = REPO_ROOT / "scripts" / "agent_memory_audit_autorun.py"
STAMP_ROOT = CONFIG_ROOT / "hooks"


def default_git_root() -> Path:
    for candidate in (VAULT_ROOT, *VAULT_ROOT.parents):
        if (candidate / ".git").exists():
            return candidate.resolve()
    return VAULT_ROOT.parent.resolve()


GIT_ROOT = Path(os.path.expandvars(env_value("GIT_ROOT", str(default_git_root())))).expanduser().resolve()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stop hook for Agent Memory shared by Claude Code and Codex.")
    parser.add_argument("--actor", choices=("codex", "claude"), default="codex")
    parser.add_argument("--protocol", choices=("codex", "claude"), default="codex")
    parser.add_argument("--auto-closeout", action="store_true")
    parser.add_argument("--timeout", type=int, default=300)
    return parser.parse_args()


def read_payload() -> dict[str, object]:
    try:
        value = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        return {}
    return value if isinstance(value, dict) else {}


def clean_env() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not any(token in key.upper() for token in ("KEY", "TOKEN", "SECRET", "PASSWORD", "COOKIE", "CREDENTIAL"))
        and "PROXY" not in key.upper()
    }


def session_key(payload: dict[str, object], actor: str) -> str:
    for key in ("session_id", "sessionId", "thread_id", "threadId", "conversation_id", "conversationId"):
        value = payload.get(key)
        if value:
            return str(value)
    return f"{payload.get('cwd') or actor}|{time.strftime('%Y-%m-%d')}"


def run_git(args: list[str], timeout: int = 8) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["git", "-C", str(GIT_ROOT), "-c", "core.quotepath=false", *args],
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def vault_target() -> str:
    try:
        return str(VAULT_ROOT.relative_to(GIT_ROOT))
    except ValueError:
        return str(VAULT_ROOT)


def normalize_path(repo_path: str) -> Path | None:
    path = (GIT_ROOT / repo_path).resolve()
    try:
        path.relative_to(VAULT_ROOT)
    except ValueError:
        return None
    if not path.exists() or path.suffix.lower() != ".md":
        return None
    return path


def dirty_paths() -> list[Path]:
    result = run_git(["status", "--porcelain=v1", "-z", "--", vault_target()])
    if not result or result.returncode != 0:
        return []
    paths: list[Path] = []
    for item in (part for part in result.stdout.split("\0") if len(part) >= 4):
        repo_path = item[3:].split(" -> ", 1)[-1]
        path = normalize_path(repo_path)
        if path:
            paths.append(path)
    return list(dict.fromkeys(paths))


def last_observed_head() -> str:
    if not LOG_PATH.exists():
        return ""
    for line in reversed(LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("git_observed_through"):
            return str(payload["git_observed_through"])
    return ""


def historical_paths() -> list[Path]:
    baseline = last_observed_head()
    if not baseline:
        return []
    head_result = run_git(["rev-parse", "HEAD"])
    if not head_result or head_result.returncode != 0:
        return []
    head = head_result.stdout.strip()
    if not head or head == baseline:
        return []
    ancestor = run_git(["merge-base", "--is-ancestor", baseline, head])
    if not ancestor or ancestor.returncode != 0:
        return []
    diff = run_git(["diff", "--name-only", "-z", f"{baseline}..{head}", "--", vault_target()])
    if not diff or diff.returncode != 0:
        return []
    paths = [normalize_path(item) for item in diff.stdout.split("\0") if item]
    return list(dict.fromkeys(path for path in paths if path is not None))


def pending_paths() -> list[Path]:
    return list(dict.fromkeys([*historical_paths(), *dirty_paths()]))


def notify(message: str) -> None:
    if sys.platform != "darwin":
        return
    safe = message.replace("\\", "\\\\").replace('"', '\\"')
    subprocess.run(["osascript", "-e", f'display notification "{safe}" with title "Agent memory"'], timeout=5, check=False)


def run_closeout(payload: dict[str, object], actor: str, timeout: int) -> dict[str, Any]:
    command = [
        sys.executable,
        str(CLOSEOUT_SCRIPT),
        "--commit",
        "--json",
        "--actor",
        actor,
        "--trigger",
        "stop-hook",
        "--session-id",
        session_key(payload, actor),
        "--lock-timeout",
        "60",
    ]
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=max(timeout, 30), env=clean_env(), check=False)
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"closeout timed out after {timeout}s"}
    except OSError as exc:
        return {"status": "error", "error": str(exc)}
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"status": "error", "error": (completed.stderr.strip() or "closeout returned no JSON")[:500]}
    return result if isinstance(result, dict) else {"status": "error", "error": "invalid closeout payload"}


def failure_reason(result: dict[str, Any]) -> str:
    parts = [str(result["error"])] if result.get("error") else []
    findings = result.get("reconcile_findings")
    if isinstance(findings, list) and findings:
        parts.append(f"reconcile_findings={len(findings)}")
    warnings = result.get("warnings")
    if isinstance(warnings, list):
        parts.extend(str(item) for item in warnings[:3])
    return "; ".join(parts)[:1000] or f"closeout status={result.get('status', 'unknown')}"


def report_failure(protocol: str, result: dict[str, Any]) -> int:
    reason = failure_reason(result)
    notify(reason[:180])
    if protocol == "claude":
        print(json.dumps({"decision": "block", "reason": "Memory closeout failed: " + reason}, ensure_ascii=False))
        return 0
    print(
        "Shared memory closeout did not finish. Continue this turn, resolve the issue below, "
        "and run closeout again: " + reason,
        file=sys.stderr,
    )
    return 2


def run_due_audit() -> None:
    if not AUDIT_AUTORUN.exists():
        return
    try:
        subprocess.run(
            [sys.executable, str(AUDIT_AUTORUN), "--reason", "hook", "--min-interval-days", "7", "--notify", "--json"],
            text=True,
            capture_output=True,
            timeout=12,
            env=clean_env(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return


def main() -> int:
    args = parse_args()
    payload = read_payload()
    paths = pending_paths()
    if args.auto_closeout and paths:
        result = run_closeout(payload, args.actor, args.timeout)
        return 0 if result.get("status") == "ok" else report_failure(args.protocol, result)
    if not args.auto_closeout and paths:
        state_mtime = STATE_DB.stat().st_mtime if STATE_DB.exists() else 0
        if historical_paths() or max(path.stat().st_mtime for path in paths) > state_mtime:
            STAMP_ROOT.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha1(session_key(payload, args.actor).encode("utf-8")).hexdigest()[:16]
            stamp = STAMP_ROOT / f"stop-memory-reminded-{args.actor}-{digest}.stamp"
            if not stamp.exists():
                stamp.write_text(str(int(time.time())), encoding="utf-8")
                notify(f"{len(paths)} memory files still need closeout.")
    run_due_audit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
