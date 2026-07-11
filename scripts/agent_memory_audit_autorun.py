#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from agent_memory_env import env_value


SCRIPT_ROOT = Path(__file__).resolve().parent
CONFIG_ROOT = Path(
    os.path.expandvars(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory"))
).expanduser().resolve()
AUDIT_SCRIPT = SCRIPT_ROOT / "agent_memory_audit.py"
PYTHON = env_value("PYTHON", sys.executable)
RUN_LOG = Path(
    os.path.expandvars(env_value("AUDIT_RUN_LOG", str(CONFIG_ROOT / "logs" / "audit_runs.jsonl")))
).expanduser().resolve()
LATEST_REPORT = Path(
    os.path.expandvars(env_value("AUDIT_REPORT", str(CONFIG_ROOT / "reports" / "latest-audit.json")))
).expanduser().resolve()
LOCK_PATH = CONFIG_ROOT / "locks" / "audit.lock"


def utc_now_dt() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def utc_now() -> str:
    return utc_now_dt().isoformat()


@contextlib.contextmanager
def audit_lock():
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def parse_time(value: str) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def read_last_successful_run() -> dt.datetime | None:
    if not RUN_LOG.exists():
        return None
    latest: dt.datetime | None = None
    try:
        lines = RUN_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("status") != "ran" or not item.get("ok"):
            continue
        parsed = parse_time(str(item.get("time", "")))
        if parsed and (latest is None or parsed > latest):
            latest = parsed
    return latest


def run_command(command: list[str], timeout: int = 180) -> dict[str, Any]:
    started_at = utc_now()
    env = {
        key: value
        for key, value in os.environ.items()
        if not any(token in key.upper() for token in ("KEY", "TOKEN", "SECRET", "PASSWORD", "COOKIE", "CREDENTIAL"))
        and "PROXY" not in key.upper()
    }
    env.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "started_at": started_at,
            "finished_at": utc_now(),
            "ok": completed.returncode == 0,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": f"timeout after {timeout}s",
            "started_at": started_at,
            "finished_at": utc_now(),
            "ok": False,
        }
    except OSError as exc:
        return {
            "command": command,
            "returncode": 127,
            "stdout": "",
            "stderr": str(exc),
            "started_at": started_at,
            "finished_at": utc_now(),
            "ok": False,
        }


def append_run_log(payload: dict[str, Any]) -> None:
    RUN_LOG.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "time": payload.get("time"),
        "reason": payload.get("reason"),
        "status": payload.get("status"),
        "ok": payload.get("ok"),
        "findings_count": payload.get("findings_count", 0),
        "report_path": payload.get("report_path", ""),
        "detail": payload.get("detail", ""),
    }
    with RUN_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(summary, ensure_ascii=False, sort_keys=True) + "\n")


def write_report(payload: dict[str, Any]) -> None:
    LATEST_REPORT.parent.mkdir(parents=True, exist_ok=True)
    temporary = LATEST_REPORT.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, LATEST_REPORT)


def notify(title: str, message: str) -> None:
    safe_title = title.replace("\\", "\\\\").replace('"', '\\"')
    safe_message = message.replace("\\", "\\\\").replace('"', '\\"')
    subprocess.run(
        [
            "osascript",
            "-e",
            f'display notification "{safe_message}" with title "{safe_title}" sound name "default"',
        ],
        timeout=5,
        check=False,
    )


def run_audit(args: argparse.Namespace, last_run: dt.datetime | None) -> dict[str, Any]:
    command = [
        PYTHON,
        str(AUDIT_SCRIPT),
        "--json",
        "--limit",
        str(args.limit),
        "--stale-days",
        str(args.stale_days),
        "--open-loop-threshold",
        str(args.open_loop_threshold),
    ]
    result = run_command(command, timeout=args.timeout)
    payload: dict[str, Any] = {
        "time": utc_now(),
        "reason": args.reason,
        "status": "ran" if result["ok"] else "error",
        "ok": bool(result["ok"]),
        "last_successful_audit": last_run.isoformat() if last_run else "",
        "min_interval_days": args.min_interval_days,
        "report_path": str(LATEST_REPORT),
        "command": command,
        "returncode": result["returncode"],
        "stderr": str(result.get("stderr", "")).strip()[:1000],
        "findings_count": 0,
        "audit_payload": {},
    }
    if result["ok"]:
        try:
            audit_payload = json.loads(str(result["stdout"]))
        except json.JSONDecodeError:
            payload["status"] = "error"
            payload["ok"] = False
            payload["detail"] = "audit returned non-json output"
        else:
            findings = audit_payload.get("findings", [])
            if not isinstance(findings, list):
                findings = []
            payload["findings_count"] = len(findings)
            payload["audit_db"] = audit_payload.get("audit_db", "")
            payload["audit_payload"] = audit_payload
    else:
        payload["detail"] = "audit command failed"

    write_report(payload)
    append_run_log(payload)

    if args.notify and payload["ok"] and payload["findings_count"]:
        notify(
            "Agent 记忆体检",
            f"发现 {payload['findings_count']} 个待看项，报告已写入 latest-audit.json。",
        )
    elif args.notify_ok and payload["ok"]:
        notify("Agent 记忆体检", "本次 audit 已完成，未发现新的待看项。")
    elif args.notify and not payload["ok"]:
        notify("Agent 记忆体检失败", "audit 自动运行失败，请查看 audit-launchd.err.log。")
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Auto-run Agent Memory audit with interval gating and optional notification.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--reason", default="manual", help="Trigger source: closeout, launchd, hook, or manual.")
    parser.add_argument("--force", action="store_true", help="Run even when the last audit is still recent.")
    parser.add_argument("--dry-run", action="store_true", help="Only report whether audit would run; do not write report/log.")
    parser.add_argument("--notify", action="store_true", help="Show a macOS notification when findings exist or audit fails.")
    parser.add_argument("--notify-ok", action="store_true", help="Also notify when audit succeeds with zero findings.")
    parser.add_argument("--min-interval-days", type=int, default=7, help="Run only when the last successful audit is older than this.")
    parser.add_argument("--limit", type=int, default=50, help="Maximum visible findings to store in the report.")
    parser.add_argument("--stale-days", type=int, default=120, help="Forwarded stale threshold for agent_memory_audit.py.")
    parser.add_argument("--open-loop-threshold", type=int, default=4, help="Forwarded open-loop threshold for agent_memory_audit.py.")
    parser.add_argument("--timeout", type=int, default=180, help="Seconds before audit command times out.")
    args = parser.parse_args()
    args.min_interval_days = max(args.min_interval_days, 1)
    args.limit = max(args.limit, 1)
    args.stale_days = max(args.stale_days, 1)
    args.open_loop_threshold = max(args.open_loop_threshold, 1)
    return args


def main() -> int:
    args = parse_args()
    with audit_lock() as acquired:
        if not acquired:
            payload = {
                "time": utc_now(), "reason": args.reason, "status": "skipped_locked",
                "ok": True, "findings_count": 0, "report_path": str(LATEST_REPORT), "run_log": str(RUN_LOG),
            }
        else:
            last_run = read_last_successful_run()
            now = utc_now_dt()
            due = last_run is None or (now - last_run) >= dt.timedelta(days=args.min_interval_days)
            if args.dry_run:
                payload = {
                    "time": utc_now(), "reason": args.reason,
                    "status": "dry_run_due" if due or args.force else "dry_run_recent",
                    "ok": True, "would_run": bool(due or args.force),
                    "last_successful_audit": last_run.isoformat() if last_run else "",
                    "min_interval_days": args.min_interval_days,
                    "report_path": str(LATEST_REPORT), "run_log": str(RUN_LOG),
                }
            elif args.force or due:
                payload = run_audit(args, last_run)
            else:
                payload = {
                    "time": utc_now(), "reason": args.reason, "status": "skipped_recent",
                    "ok": True, "findings_count": 0,
                    "last_successful_audit": last_run.isoformat() if last_run else "",
                    "min_interval_days": args.min_interval_days,
                    "report_path": str(LATEST_REPORT), "run_log": str(RUN_LOG),
                }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"status={payload['status']} ok={payload['ok']}")
        print(f"last_successful_audit={payload.get('last_successful_audit', '')}")
        print(f"findings_count={payload.get('findings_count', 0)}")
        print(f"report_path={payload.get('report_path', '')}")
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
