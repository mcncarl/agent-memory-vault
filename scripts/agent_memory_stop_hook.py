#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from agent_memory_env import (
    RuntimeTransitionError,
    assert_runtime_ready,
    env_value,
    expand_path,
)
from agent_memory_claim import (
    active_claim_lease_rows,
    all_active_claim_lease_rows,
)
import agent_memory_observability as observability
import agent_memory_shadow as shadow_gate


REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = expand_path(env_value("ROOT", str(REPO_ROOT / "templates" / "vault"))).resolve()
CONFIG_ROOT = expand_path(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory")).resolve()
STATE_DB = expand_path(env_value("STATE_DB", str(CONFIG_ROOT / "state.sqlite"))).resolve()
LOG_PATH = expand_path(env_value("CLOSEOUT_LOG", str(CONFIG_ROOT / "logs" / "closeout.jsonl"))).resolve()
CLOSEOUT_SCRIPT = REPO_ROOT / "scripts" / "agent_memory_closeout.py"
STAMP_ROOT = CONFIG_ROOT / "hooks"


def default_git_root() -> Path:
    for candidate in (VAULT_ROOT, *VAULT_ROOT.parents):
        if (candidate / ".git").exists():
            return candidate.resolve()
    return VAULT_ROOT.parent.resolve()


GIT_ROOT = expand_path(env_value("GIT_ROOT", str(default_git_root()))).resolve()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stop hook for Agent Memory shared by Claude Code and Codex.")
    parser.add_argument("--actor", choices=("codex", "claude"), default="codex")
    parser.add_argument("--protocol", choices=("codex", "claude"), default="codex")
    parser.add_argument(
        "--event",
        choices=("stop-hook", "session-end"),
        default="stop-hook",
        help="Host lifecycle event used for closeout attribution and failure behavior.",
    )
    parser.add_argument(
        "--non-blocking",
        action="store_true",
        help="Report failures by notification only; required for lifecycle events that cannot block.",
    )
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
    env = {
        key: value
        for key, value in os.environ.items()
        if not any(token in key.upper() for token in ("KEY", "TOKEN", "SECRET", "PASSWORD", "COOKIE", "CREDENTIAL"))
        and "PROXY" not in key.upper()
    }
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    return env


def session_key(payload: dict[str, object], actor: str) -> str:
    for key in ("session_id", "sessionId", "thread_id", "threadId", "conversation_id", "conversationId"):
        value = payload.get(key)
        if value:
            return str(value)
    keys = {
        "codex": ("AGENT_MEMORY_SESSION_ID", "CODEX_THREAD_ID"),
        "claude": ("AGENT_MEMORY_SESSION_ID", "CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID"),
    }.get(actor, ("AGENT_MEMORY_SESSION_ID",))
    for key in keys:
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return ""


def run_git(args: list[str], timeout: int = 8) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["git", "-C", str(GIT_ROOT), "-c", "core.quotepath=false", *args],
            text=True,
            encoding="utf-8",
            errors="replace",
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
    if path.suffix.lower() != ".md" or (path.exists() and not path.is_file()):
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


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def unobserved_paths(paths: list[Path]) -> list[Path]:
    if not paths or not STATE_DB.exists():
        return paths
    try:
        with contextlib.closing(sqlite3.connect(STATE_DB, timeout=5)) as conn:
            conn.execute("PRAGMA busy_timeout=5000")
            rows = conn.execute("SELECT path, sha256 FROM memory_file_observations").fetchall()
    except (OSError, sqlite3.Error):
        return paths
    indexed = {str(Path(str(path)).resolve()): str(digest) for path, digest in rows}
    stale: list[Path] = []
    for path in paths:
        try:
            current = file_sha256(path)
        except OSError:
            stale.append(path)
            continue
        if indexed.get(str(path.resolve())) != current:
            stale.append(path)
    return stale


def pending_paths() -> list[Path]:
    candidates = list(dict.fromkeys([*historical_paths(), *dirty_paths()]))
    return unobserved_paths(candidates)


def unresolved_closeout_incidents(
    connection: sqlite3.Connection | None = None,
) -> list[dict[str, str]]:
    """Read unresolved post-finalize drift without creating or migrating state."""

    if connection is None and (not STATE_DB.is_file() or STATE_DB.is_symlink()):
        return []
    owns_connection = connection is None
    try:
        if connection is None:
            connection = sqlite3.connect(
                f"{STATE_DB.as_uri()}?mode=ro",
                uri=True,
                timeout=5,
            )
            connection.execute("PRAGMA query_only=ON")
        table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='memory_closeout_incidents'"
        ).fetchone()
        if table is None:
            return []
        rows = connection.execute(
            "SELECT incident_id, rel_path, reason_code FROM memory_closeout_incidents "
            "WHERE resolved_at IS NULL ORDER BY detected_at LIMIT 100"
        ).fetchall()
        return [
            {
                "incident_id": str(row[0]),
                "rel_path": str(row[1]),
                "reason_code": str(row[2]),
            }
            for row in rows
        ]
    except (OSError, sqlite3.Error):
        # An unreadable v2 incident ledger cannot be treated as healthy.
        return [{
            "incident_id": "unreadable",
            "rel_path": "",
            "reason_code": "INCIDENT_LEDGER_UNREADABLE",
        }]
    finally:
        if owns_connection and connection is not None:
            connection.close()


def notify(message: str) -> None:
    if sys.platform != "darwin":
        return
    safe = message.replace("\\", "\\\\").replace('"', '\\"')
    subprocess.run(["osascript", "-e", f'display notification "{safe}" with title "Agent memory"'], timeout=5, check=False)


def run_closeout(
    payload: dict[str, object],
    actor: str,
    timeout: int,
    trigger: str = "stop-hook",
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(CLOSEOUT_SCRIPT),
        "--commit",
        "--json",
        "--actor",
        actor,
        "--trigger",
        trigger,
        "--session-id",
        session_key(payload, actor),
        "--claimed-only",
        "--lock-timeout",
        "60",
    ]
    if trigger == "session-end":
        command.append("--skip-audit")
    try:
        completed = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=max(timeout, 30),
            env=clean_env(),
            check=False,
        )
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
    if result.get("ownership_error"):
        parts.append(str(result["ownership_error"]))
    findings = result.get("reconcile_findings")
    if isinstance(findings, list) and findings:
        parts.append(f"reconcile_findings={len(findings)}")
    warnings = result.get("warnings")
    if isinstance(warnings, list):
        parts.extend(str(item) for item in warnings[:3])
    return "; ".join(parts)[:1000] or f"closeout status={result.get('status', 'unknown')}"


def report_failure(protocol: str, result: dict[str, Any], *, non_blocking: bool = False) -> int:
    reason = failure_reason(result)
    notify(reason[:180])
    if non_blocking:
        return 0
    if protocol == "claude":
        print(json.dumps({"decision": "block", "reason": "Memory closeout failed: " + reason}, ensure_ascii=False))
        return 0
    print(
        "Shared memory closeout did not finish. Continue this turn, resolve the issue below, "
        "and run closeout again: " + reason,
        file=sys.stderr,
    )
    return 2


def stop_hook_reentry(payload: dict[str, object], event: str) -> bool:
    """Claude sets stop_hook_active after a Stop hook already requested continuation."""

    return event == "stop-hook" and payload.get("stop_hook_active") is True


def handle_failure(
    protocol: str,
    result: dict[str, Any],
    *,
    payload: dict[str, object],
    event: str,
    non_blocking: bool,
) -> int:
    return report_failure(
        protocol,
        result,
        non_blocking=non_blocking or event == "session-end" or stop_hook_reentry(payload, event),
    )


def finish_success(
    *,
    actor: str,
    raw_session_id: str,
    protocol: str,
    payload: dict[str, object],
    event: str,
    non_blocking: bool,
) -> int:
    """Apply the task-local stale-adoption gate, then close observability."""

    configured_enforcement = env_value("STALE_ADOPTION_ENFORCEMENT", "shadow").strip().lower()
    enforcement = (
        "enforce"
        if configured_enforcement == "enforce" and shadow_gate.cutover_active()
        else "shadow"
    )
    try:
        stale_count = observability.adopted_stale_without_verification(
            actor,
            raw_session_id,
        )
    except (
        OSError,
        sqlite3.Error,
        ValueError,
        RuntimeTransitionError,
        observability.ObservabilityLedgerUnavailable,
    ):
        # A broken ledger is not evidence that no stale memory was adopted.
        # Shadow mode stays non-blocking but exposes a stable degraded signal;
        # enforce mode fails closed and never records a successful task.
        observability.record_task_completed(raw_session_id, actor, value="failure")
        result = {
            "status": "degraded" if enforcement == "shadow" else "error",
            "reason_code": "OBSERVABILITY_LEDGER_UNAVAILABLE",
            "ownership_error": "OBSERVABILITY_LEDGER_UNAVAILABLE",
        }
        if enforcement == "enforce":
            return handle_failure(
                protocol,
                result,
                payload=payload,
                event=event,
                non_blocking=non_blocking,
            )
        notify("OBSERVABILITY_LEDGER_UNAVAILABLE")
        print(
            "Agent Memory observability degraded: OBSERVABILITY_LEDGER_UNAVAILABLE",
            file=sys.stderr,
        )
        return 0
    if enforcement == "enforce" and stale_count:
        return handle_failure(
            protocol,
            {
                "status": "error",
                "reason_code": "ADOPTED_MEMORY_REQUIRES_LIVE_VERIFICATION",
                "ownership_error": (
                    f"{stale_count} adopted stale or conflicting memory version(s) "
                    "lack task-local live verification"
                ),
            },
            payload=payload,
            event=event,
            non_blocking=non_blocking,
        )
    observability.record_task_completed(raw_session_id, actor, value="success")
    return 0


def run_due_audit() -> None:
    """Compatibility no-op: the canonical Sunday LaunchAgent owns audits."""

    return


def claim_path(row: dict[str, Any]) -> Path:
    return Path(str(row.get("path", ""))).expanduser().resolve()


def invalid_lease_result(rows: list[dict[str, Any]], *, context: str) -> dict[str, Any]:
    states = sorted({str(row.get("lease_state", "unknown")) for row in rows})
    paths = sorted({str(row.get("rel_path") or claim_path(row)) for row in rows})
    return {
        "status": "error",
        "ownership_error": (
            f"{context}: active memory claim(s) do not hold a live intent lease; "
            f"states={','.join(states)}"
        ),
        "lease_states": states,
        "affected_files": paths,
    }


def main() -> int:
    args = parse_args()
    payload = read_payload()
    try:
        assert_runtime_ready("stop-hook")
    except RuntimeTransitionError:
        return handle_failure(
            args.protocol,
            {
                "status": "error",
                "reason_code": "RUNTIME_TRANSITION_INCOMPLETE",
                "ownership_error": "Agent Memory runtime migration is incomplete",
            },
            payload=payload,
            event=args.event,
            non_blocking=args.non_blocking,
        )
    incidents = unresolved_closeout_incidents()
    if incidents:
        return handle_failure(
            args.protocol,
            {
                "status": "error",
                "reason_code": "POST_FINALIZE_CONTENT_DRIFT",
                "ownership_error": (
                    "Agent Memory has unresolved post-finalize content drift; "
                    "run Doctor and resolve the recorded incident before continuing"
                ),
                "incident_count": len(incidents),
                "affected_files": sorted({
                    item["rel_path"] for item in incidents if item.get("rel_path")
                }),
            },
            payload=payload,
            event=args.event,
            non_blocking=args.non_blocking,
        )
    raw_session_id = session_key(payload, args.actor)
    # This is intentionally best effort and runs before every early-return
    # branch so a missing search can be distinguished from a missing task
    # denominator. The helper never raises into the host lifecycle hook.
    observability.record_task_seen(raw_session_id, args.actor)
    paths = pending_paths()
    pending_set = {path.resolve() for path in paths}
    try:
        current_claims = (
            active_claim_lease_rows(raw_session_id, args.actor)
            if raw_session_id
            else []
        )
        all_claims = all_active_claim_lease_rows() if args.auto_closeout and paths else []
    except (OSError, sqlite3.Error, ValueError) as exc:
        if not args.auto_closeout:
            current_claims, all_claims = [], []
        else:
            return handle_failure(
                args.protocol,
                {
                    "status": "error",
                    "ownership_error": "cannot verify current memory intent leases",
                    "error": type(exc).__name__,
                },
                payload=payload,
                event=args.event,
                non_blocking=args.non_blocking,
            )
    current_live_claims = [
        row for row in current_claims if str(row.get("lease_state", "")) == "live"
    ]
    current_terminal_claims = [
        row for row in current_claims if str(row.get("lease_state", "")) == "intent_terminal"
    ]
    dirty_claims = [row for row in all_claims if claim_path(row) in pending_set]
    invalid_dirty_claims = [
        row for row in dirty_claims if str(row.get("lease_state", "")) != "live"
    ]
    if args.auto_closeout and current_terminal_claims:
        return handle_failure(
            args.protocol,
            invalid_lease_result(
                current_terminal_claims,
                context="terminal intent still has an active claim",
            ),
            payload=payload,
            event=args.event,
            non_blocking=args.non_blocking,
        )
    if args.auto_closeout and invalid_dirty_claims:
        return handle_failure(
            args.protocol,
            invalid_lease_result(
                invalid_dirty_claims,
                context="dirty memory is covered by an invalid or expired lease",
            ),
            payload=payload,
            event=args.event,
            non_blocking=args.non_blocking,
        )
    if args.auto_closeout and current_live_claims:
        result = run_closeout(payload, args.actor, args.timeout, args.event)
        if result.get("status") == "ok":
            return finish_success(
                actor=args.actor,
                raw_session_id=raw_session_id,
                protocol=args.protocol,
                payload=payload,
                event=args.event,
                non_blocking=args.non_blocking,
            )
        return handle_failure(
            args.protocol,
            result,
            payload=payload,
            event=args.event,
            non_blocking=args.non_blocking,
        )
    if args.auto_closeout and paths:
        live_claimed_paths = {
            claim_path(row)
            for row in dirty_claims
            if str(row.get("lease_state", "")) == "live"
        }
        unclaimed = [path for path in paths if path.resolve() not in live_claimed_paths]
        if not unclaimed:
            return finish_success(
                actor=args.actor,
                raw_session_id=raw_session_id,
                protocol=args.protocol,
                payload=payload,
                event=args.event,
                non_blocking=args.non_blocking,
            )
        if not raw_session_id:
            result = {
                "status": "error",
                "ownership_error": (
                    "Claude/Codex hook payload has no session id; refusing an unscoped memory closeout"
                ),
            }
            return handle_failure(
                args.protocol,
                result,
                payload=payload,
                event=args.event,
                non_blocking=args.non_blocking,
            )
        if unclaimed:
            result = {
                "status": "error",
                "ownership_error": (
                    f"{len(unclaimed)} changed memory file(s) have no live intent-backed claim; "
                    f"re-read and prepare through memoryctl --actor {args.actor} write, "
                    "or explicitly ADOPT an authorized external edit"
                ),
                "unclaimed_files": [str(path) for path in unclaimed],
            }
            return handle_failure(
                args.protocol,
                result,
                payload=payload,
                event=args.event,
                non_blocking=args.non_blocking,
            )
    if not args.auto_closeout and paths:
        state_mtime = STATE_DB.stat().st_mtime if STATE_DB.exists() else 0
        path_mtimes: list[float] = []
        for path in paths:
            try:
                path_mtimes.append(path.stat().st_mtime)
            except OSError:
                continue
        if historical_paths() or len(path_mtimes) < len(paths) or max(path_mtimes, default=0) > state_mtime:
            STAMP_ROOT.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha1(session_key(payload, args.actor).encode("utf-8")).hexdigest()[:16]
            stamp = STAMP_ROOT / f"stop-memory-reminded-{args.actor}-{digest}.stamp"
            if not stamp.exists():
                stamp.write_text(str(int(time.time())), encoding="utf-8")
                notify(f"{len(paths)} memory files still need closeout.")
    return finish_success(
        actor=args.actor,
        raw_session_id=raw_session_id,
        protocol=args.protocol,
        payload=payload,
        event=args.event,
        non_blocking=args.non_blocking,
    )


if __name__ == "__main__":
    raise SystemExit(main())
