#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import subprocess
from pathlib import Path
from typing import Any


VERSION = "2.0"
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = Path(os.path.expandvars(os.environ.get("CODEX_MEMORY_ROOT", str(REPO_ROOT / "templates" / "vault")))).expanduser().resolve()
CONFIG_ROOT = Path(os.path.expandvars(os.environ.get("CODEX_MEMORY_CONFIG_ROOT", "$HOME/.config/codex-memory"))).expanduser().resolve()
STATE_DB = Path(os.path.expandvars(os.environ.get("CODEX_MEMORY_STATE_DB", str(CONFIG_ROOT / "state.sqlite")))).expanduser().resolve()
SCRIPT_ROOT = REPO_ROOT / "scripts"
AUDIT_LOG = CONFIG_ROOT / "logs" / "audit_runs.jsonl"
CLOSEOUT_LOG = CONFIG_ROOT / "logs" / "closeout.jsonl"
EXCLUDED_VECTOR_TYPES = {"routing", "directory_index", "template", "agent_case_candidate", "skill_candidate"}
EXCLUDED_VECTOR_STATUS = {"archived", "deleted", "obsolete", "outdated", "deprecated", "stale"}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def run(command: list[str], timeout: int = 300) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "returncode": 127, "detail": type(exc).__name__}
    return {"ok": completed.returncode == 0, "returncode": completed.returncode, "stdout": completed.stdout, "detail": (completed.stderr or completed.stdout).strip()[:500]}


def add(checks: list[dict[str, Any]], name: str, status: str, message: str, detail: dict[str, Any] | None = None) -> None:
    checks.append({"name": name, "status": status, "message": message, "detail": detail or {}})


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_time(value: str) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def latest_jsonl(path: Path, predicate: Any = None) -> dict[str, Any] | None:
    if not path.exists():
        return None
    latest = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and (not predicate or predicate(item)):
            latest = item
    return latest


def eligible_vector(row: sqlite3.Row) -> bool:
    path = Path(str(row["path"]))
    return (
        path.exists()
        and path.suffix.lower() == ".md"
        and path.name != "README.md"
        and not path.name.startswith("_模板")
        and str(row["memory_type"]) not in EXCLUDED_VECTOR_TYPES
        and str(row["status"]) not in EXCLUDED_VECTOR_STATUS
        and str(row["sensitivity"] or "").lower() not in {"secret", "credential"}
    )


def repair_derived() -> list[dict[str, Any]]:
    actions = []
    index_result = run([str(SCRIPT_ROOT / "codex_memory_index.py"), "--init", "--scan", "--report"], 180)
    actions.append({"action": "rebuild_sqlite_fts", "ok": index_result["ok"], "detail": index_result["detail"]})
    if index_result["ok"]:
        vector_result = run([str(SCRIPT_ROOT / "codex_memory_zvec_index.py"), "--scan", "--prune", "--json"], 900)
        actions.append({"action": "rebuild_zvec", "ok": vector_result["ok"], "detail": vector_result["detail"]})
    return actions


def collect_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    required = ["codex_memory_index.py", "codex_memory_search.py", "codex_memory_closeout.py", "codex_memory_check.py", "codex_memory_audit.py", "codex_memory_audit_autorun.py", "codex_memory_zvec_index.py", "codex_memory_doctor.py", "codex_memory_stop_hook.py"]
    missing = [name for name in required if not (SCRIPT_ROOT / name).is_file()]
    add(checks, "runtime_files", "fail" if missing else "pass", "Runtime files complete." if not missing else "Runtime files missing.", {"missing": missing})
    if not STATE_DB.exists():
        add(checks, "state_db", "fail", "State database is missing.", {"path": str(STATE_DB)})
        return checks
    conn = sqlite3.connect(STATE_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    quick = str(conn.execute("PRAGMA quick_check").fetchone()[0])
    add(checks, "sqlite_integrity", "pass" if quick == "ok" else "fail", f"SQLite quick_check={quick}.")
    actual = sorted(VAULT_ROOT.rglob("*.md"))
    actual_by_path = {str(path.resolve()): path for path in actual}
    actual_rel = {path.relative_to(VAULT_ROOT).as_posix() for path in actual}
    docs = conn.execute("SELECT path, rel_path, sha256, memory_type, status, sensitivity, verified_at_source, line_count, size_bytes FROM memory_docs").fetchall()
    db_by_path = {str(row["path"]): row for row in docs}
    missing_db = sorted(path.relative_to(VAULT_ROOT).as_posix() for raw, path in actual_by_path.items() if raw not in db_by_path)
    stale_db = sorted(str(row["rel_path"]) for raw, row in db_by_path.items() if raw not in actual_by_path)
    mismatch = sorted(str(row["rel_path"]) for raw, row in db_by_path.items() if raw in actual_by_path and file_sha256(actual_by_path[raw]) != str(row["sha256"]))
    add(checks, "markdown_sqlite_parity", "pass" if not (missing_db or stale_db or mismatch) else "fail", f"Markdown={len(actual)}, SQLite={len(docs)}.", {"missing": missing_db, "stale": stale_db, "hash_mismatch": mismatch})
    fts = {str(row[0]) for row in conn.execute("SELECT DISTINCT path FROM memory_fts")}
    add(checks, "sqlite_fts_parity", "pass" if fts == set(db_by_path) else "fail", f"FTS covers {len(fts)}/{len(docs)} docs.")
    index_path = VAULT_ROOT / "INDEX.md"
    refs = set(re.findall(r"`([^`]+\.md)`", index_path.read_text(encoding="utf-8", errors="replace"))) if index_path.exists() else set()
    add(checks, "index_navigation_parity", "pass" if refs == actual_rel else "warn", f"INDEX.md lists {len(refs)}/{len(actual_rel)} docs.", {"unlisted": sorted(actual_rel - refs), "broken": sorted(refs - actual_rel)})
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if {"memory_vector_chunks", "memory_vector_index_state"}.issubset(tables):
        eligible = {str(row["path"]): str(row["rel_path"]) for row in docs if eligible_vector(row)}
        states = conn.execute("SELECT path, rel_path, status FROM memory_vector_index_state").fetchall()
        if not states:
            add(checks, "zvec_parity", "warn", "Optional vector index is not initialized.")
        else:
            indexed = {str(row["path"]) for row in states if row["status"] == "indexed"}
            vector_missing = sorted(eligible[path] for path in eligible.keys() - indexed)
            vector_stale = sorted(str(row["rel_path"] or row["path"]) for row in states if str(row["path"]) not in eligible)
            add(checks, "zvec_parity", "pass" if not (vector_missing or vector_stale) else "fail", f"Zvec covers {len(indexed & eligible.keys())}/{len(eligible)} docs.", {"missing": vector_missing, "stale": vector_stale})
    else:
        add(checks, "zvec_parity", "warn", "Optional vector index is not initialized.")
    source_counts = {str(row[0]): int(row[1]) for row in conn.execute("SELECT verified_at_source, COUNT(*) FROM memory_docs GROUP BY verified_at_source")}
    weak = source_counts.get("mtime_fallback", 0)
    add(checks, "verification_provenance", "warn" if weak else "pass", f"Explicit verification source on {len(docs) - weak}/{len(docs)} docs.", {"by_source": source_counts})
    large = [{"rel_path": str(row["rel_path"]), "lines": int(row["line_count"]), "bytes": int(row["size_bytes"])} for row in docs if int(row["line_count"]) > 180 or int(row["size_bytes"]) > 24576]
    add(checks, "large_memory_files", "warn" if large else "pass", f"{len(large)} docs exceed compaction advisory thresholds.", {"files": large})
    raw_logs = int(conn.execute("SELECT COUNT(*) FROM memory_search_log WHERE query NOT LIKE '[redacted:%'").fetchone()[0])
    add(checks, "search_log_privacy", "warn" if raw_logs else "pass", f"{raw_logs} legacy raw-query rows remain.", {"legacy_raw_rows": raw_logs})
    conn.close()
    latest_audit = latest_jsonl(AUDIT_LOG, lambda item: item.get("status") == "ran" and item.get("ok"))
    audit_time = parse_time(str(latest_audit.get("time", ""))) if latest_audit else None
    age = (dt.datetime.now(dt.timezone.utc) - audit_time).days if audit_time else None
    add(checks, "audit_freshness", "pass" if age is not None and age <= 7 else "warn", f"Last successful audit age: {age} days." if age is not None else "No successful audit recorded.")
    closeout = latest_jsonl(CLOSEOUT_LOG)
    add(checks, "closeout_history", "pass" if closeout and closeout.get("status") in {"ok", "warning"} else "warn", f"Latest closeout status: {closeout.get('status')}." if closeout else "No closeout history.")
    return checks


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only health report for the complete Codex memory pipeline.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--repair-derived", action="store_true", help="Rebuild derived indexes without editing Markdown facts.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repairs = repair_derived() if args.repair_derived else []
    checks = collect_checks()
    statuses = {str(item["status"]) for item in checks}
    status = "error" if "fail" in statuses else ("warning" if "warn" in statuses else "ok")
    payload = {"time": utc_now(), "version": VERSION, "status": status, "summary": {name: sum(1 for item in checks if item["status"] == name) for name in ("pass", "warn", "fail")}, "checks": checks, "repair_actions": repairs}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"codex_memory_doctor={status} version={VERSION}")
        for item in checks:
            print(f"[{item['status']}] {item['name']}: {item['message']}")
    return 2 if status == "error" else 0


if __name__ == "__main__":
    raise SystemExit(main())
