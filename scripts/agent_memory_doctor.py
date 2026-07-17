#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from agent_memory_env import env_value, expand_path, load_config


VERSION = "2.2"
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = expand_path(env_value("ROOT", str(REPO_ROOT / "templates" / "vault"))).resolve()
GIT_ROOT = expand_path(env_value("GIT_ROOT", str(REPO_ROOT))).resolve()
CONFIG_ROOT = expand_path(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory")).resolve()
STATE_DB = expand_path(env_value("STATE_DB", str(CONFIG_ROOT / "state.sqlite"))).resolve()
SCRIPT_ROOT = REPO_ROOT / "scripts"
AUDIT_LOG = expand_path(env_value("AUDIT_RUN_LOG", str(CONFIG_ROOT / "logs" / "audit_runs.jsonl"))).resolve()
CLOSEOUT_LOG = expand_path(env_value("CLOSEOUT_LOG", str(CONFIG_ROOT / "logs" / "closeout.jsonl"))).resolve()
RUNTIME_MANIFEST = CONFIG_ROOT / "config" / "runtime-manifest.json"
HOST_CONFIG = load_config().get("host", {})
if not isinstance(HOST_CONFIG, dict):
    HOST_CONFIG = {}
SEMANTIC_CONFIG = load_config().get("semantic_retrieval", {})
if not isinstance(SEMANTIC_CONFIG, dict):
    SEMANTIC_CONFIG = {}
SEMANTIC_ENABLED = bool(SEMANTIC_CONFIG.get("enabled", False))
ZVEC_PYTHON = expand_path(env_value("ZVEC_PYTHON", str(CONFIG_ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))))
EMBEDDING_MODEL = expand_path(env_value("EMBEDDING_MODEL", ""))
MODEL_MANIFEST = expand_path(env_value("MODEL_MANIFEST", str(CONFIG_ROOT / "models" / "embeddinggemma-300m" / "model-manifest.json"))).resolve()
MODEL_REVISION = env_value("MODEL_REVISION", "")
DEPENDENCY_LOCK = expand_path(env_value("DEPENDENCY_LOCK", str(CONFIG_ROOT / "requirements-vector.lock"))).resolve()
REQUIRE_LOCAL_MODEL = env_value("REQUIRE_LOCAL_MODEL", "false").strip().lower() in {"1", "true", "yes", "on"}
EXCLUDED_VECTOR_TYPES = {"routing", "directory_index", "template", "agent_case_candidate", "skill_candidate"}
EXCLUDED_VECTOR_STATUS = {"archived", "deleted", "obsolete", "outdated", "deprecated", "stale"}
STALE_CLAIM_HOURS = 24
REMOTE_BACKUP_MAX_UNPUSHED_COMMITS = 10
REMOTE_BACKUP_MAX_AGE_DAYS = 3


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def run(command: list[str], timeout: int = 300, env: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command, text=True, encoding="utf-8", errors="replace", capture_output=True,
            timeout=timeout, env=env, check=False,
        )
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


def markdown_sha256(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def offline_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    env["HF_HUB_OFFLINE"] = "1"
    env["TRANSFORMERS_OFFLINE"] = "1"
    return env


def verify_model_manifest() -> tuple[bool, dict[str, Any]]:
    manifest = read_json_object(MODEL_MANIFEST)
    root = expand_path(str(manifest.get("root", ""))).resolve() if manifest else Path()
    files = manifest.get("files") if isinstance(manifest, dict) else None
    missing: list[str] = []
    size_mismatch: list[str] = []
    hash_mismatch: list[str] = []
    symlinks: list[str] = []
    if not manifest or not root.is_dir() or not isinstance(files, dict):
        return False, {"manifest": str(MODEL_MANIFEST), "root": str(root), "error": "manifest_or_root_missing"}
    for rel_path, expected in files.items():
        path = root / str(rel_path)
        if path.is_symlink():
            symlinks.append(str(rel_path))
        if not path.is_file():
            missing.append(str(rel_path))
            continue
        expected_size = expected.get("size") if isinstance(expected, dict) else None
        expected_hash = expected.get("sha256") if isinstance(expected, dict) else None
        if expected_size is not None and path.stat().st_size != int(expected_size):
            size_mismatch.append(str(rel_path))
            continue
        if expected_hash and file_sha256(path) != str(expected_hash):
            hash_mismatch.append(str(rel_path))
    revision = str(manifest.get("revision", ""))
    revision_ok = not MODEL_REVISION or MODEL_REVISION == revision
    ok = not missing and not size_mismatch and not hash_mismatch and not symlinks and revision_ok
    return ok, {
        "manifest": str(MODEL_MANIFEST),
        "root": str(root),
        "revision": revision,
        "expected_revision": MODEL_REVISION,
        "checked_files": len(files),
        "missing": missing,
        "size_mismatch": size_mismatch,
        "hash_mismatch": hash_mismatch,
        "symlinks": symlinks,
    }


def verify_dependency_lock() -> tuple[bool, dict[str, Any]]:
    if not DEPENDENCY_LOCK.is_file() or not ZVEC_PYTHON.is_file():
        return False, {"lock": str(DEPENDENCY_LOCK), "python": str(ZVEC_PYTHON), "error": "lock_or_python_missing"}
    code = """
import importlib.metadata as metadata
import json
import re
import sys
expected = {}
for raw in open(sys.argv[1], encoding='utf-8'):
    line = raw.strip()
    if not line or line.startswith('#') or '==' not in line:
        continue
    name, version = line.split('==', 1)
    expected[name] = version
missing = []
mismatched = []
for name, version in expected.items():
    try:
        actual = metadata.version(name)
    except metadata.PackageNotFoundError:
        missing.append(name)
        continue
    if actual != version:
        mismatched.append({'name': name, 'expected': version, 'actual': actual})
print(json.dumps({'expected': len(expected), 'missing': missing, 'mismatched': mismatched}))
raise SystemExit(0 if not missing and not mismatched else 2)
"""
    result = run([str(ZVEC_PYTHON), "-c", code, str(DEPENDENCY_LOCK)], 60, offline_env())
    try:
        detail = json.loads(str(result.get("stdout", "")))
    except json.JSONDecodeError:
        detail = {"error": result.get("detail", "invalid_dependency_check_output")}
    detail.update({"lock": str(DEPENDENCY_LOCK), "python": str(ZVEC_PYTHON)})
    return bool(result["ok"]), detail


def verify_semantic_python_runtime() -> tuple[bool, dict[str, Any]]:
    if not ZVEC_PYTHON.is_file():
        return False, {"python": str(ZVEC_PYTHON), "error": "python_missing_or_broken_symlink"}
    code = """
import json
import os
import sys
base = getattr(sys, '_base_executable', '') or sys.executable
print(json.dumps({
    'executable': sys.executable,
    'base_executable': base,
    'base_exists': os.path.isfile(base),
    'version': '.'.join(str(part) for part in sys.version_info[:3]),
}))
"""
    result = run([str(ZVEC_PYTHON), "-c", code], 30, offline_env())
    try:
        detail = json.loads(str(result.get("stdout", "")))
    except json.JSONDecodeError:
        detail = {"error": result.get("detail", "invalid_python_runtime_output")}
    detail.update({"python": str(ZVEC_PYTHON), "returncode": result.get("returncode")})
    ok = bool(result["ok"] and detail.get("base_exists"))
    if result["ok"] and not detail.get("base_exists"):
        detail["error"] = "base_interpreter_missing"
    return ok, detail


def offline_semantic_probe() -> tuple[bool, dict[str, Any]]:
    command = [
        str(ZVEC_PYTHON),
        str(SCRIPT_ROOT / "agent_memory_zvec_index.py"),
        "--search",
        "Agent Memory offline healthcheck",
        "--limit",
        "1",
        "--json",
    ]
    result = run(command, 240, offline_env())
    try:
        payload = json.loads(str(result.get("stdout", "")))
    except json.JSONDecodeError:
        return False, {"error": result.get("detail", "non_json_probe"), "returncode": result.get("returncode")}
    rows = payload.get("results") if isinstance(payload, dict) else None
    ok = bool(result["ok"] and isinstance(rows, list) and rows)
    return ok, {
        "returncode": result.get("returncode"),
        "result_count": len(rows) if isinstance(rows, list) else 0,
        "model": str(EMBEDDING_MODEL),
        "offline": True,
        "error": payload.get("error", "") if isinstance(payload, dict) else "",
    }


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


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def configured_path(name: str) -> Path | None:
    raw = HOST_CONFIG.get(name)
    if not isinstance(raw, str) or not raw.strip():
        return None
    return expand_path(raw).resolve()


def local_endpoint_reachable(raw_url: str) -> tuple[bool, dict[str, Any]]:
    parsed = urlparse(raw_url)
    host = parsed.hostname or ""
    if host not in {"127.0.0.1", "localhost", "::1"}:
        return True, {"url_type": "remote_or_unset"}
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True, {"host": host, "port": port, "listening": True}
    except OSError:
        return False, {"host": host, "port": port, "listening": False}


def cc_switch_hooks_match(db_path: Path, expected_hooks: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    if not db_path.exists():
        return True, {"installed": False}
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        conn.execute("PRAGMA busy_timeout=5000")
        common = conn.execute("SELECT value FROM settings WHERE key = 'common_config_claude'").fetchone()
        backups = conn.execute("SELECT original_config FROM proxy_live_backup WHERE app_type = 'claude'").fetchall()
        conn.close()
        common_payload = json.loads(str(common[0])) if common else {}
        backup_payloads = [json.loads(str(row[0])) for row in backups]
    except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError) as exc:
        return False, {"installed": True, "error": type(exc).__name__}
    common_ok = isinstance(common_payload, dict) and common_payload.get("hooks") == expected_hooks
    backups_ok = all(isinstance(payload, dict) and payload.get("hooks") == expected_hooks for payload in backup_payloads)
    return common_ok and backups_ok, {
        "installed": True,
        "common_config_ok": common_ok,
        "backup_count": len(backup_payloads),
        "backups_ok": backups_ok,
    }


def git_remote_has_credential() -> bool:
    result = run(["git", "-C", str(GIT_ROOT), "config", "--get-regexp", r"^remote\..*\.url$"], 15)
    if result["returncode"] not in {0, 1}:
        return False
    for line in str(result.get("stdout", "")).splitlines():
        _, _, url = line.partition(" ")
        if re.search(r"https?://[^/@\s]+:[^/@\s]+@", url) or re.search(r"gh[pousr]_[A-Za-z0-9]{20,}", url):
            return True
    return False


def memory_git_baseline_result(
    dirty_count: int,
    git_ok: bool,
    allow_dirty_memory: bool,
) -> tuple[str, str, dict[str, Any]]:
    if dirty_count and allow_dirty_memory:
        return (
            "pass",
            f"Memory Git baseline has {dirty_count} expected pre-commit dirty files.",
            {"dirty_count": dirty_count, "allowed_precommit": True},
        )
    if dirty_count:
        return (
            "warn",
            f"Memory Git baseline has {dirty_count} dirty files.",
            {"dirty_count": dirty_count, "allowed_precommit": False},
        )
    return (
        "pass" if git_ok else "fail",
        "Memory Git baseline is clean.",
        {"dirty_count": 0, "allowed_precommit": allow_dirty_memory},
    )


def git_remote_backup_health(memory_pathspec: str, now: dt.datetime | None = None) -> tuple[bool, dict[str, Any]]:
    upstream_result = run(
        ["git", "-C", str(GIT_ROOT), "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
        15,
    )
    if not upstream_result["ok"]:
        return False, {"configured": False, "error": "upstream_missing"}
    upstream = str(upstream_result.get("stdout", "")).strip()
    divergence = run(
        ["git", "-C", str(GIT_ROOT), "rev-list", "--left-right", "--count", "@{upstream}...HEAD"],
        30,
    )
    memory_ahead_result = run(
        ["git", "-C", str(GIT_ROOT), "rev-list", "--count", "@{upstream}..HEAD", "--", memory_pathspec],
        30,
    )
    try:
        behind, ahead_total = [int(value) for value in str(divergence.get("stdout", "")).split()]
        ahead_memory = int(str(memory_ahead_result.get("stdout", "")).strip())
    except (TypeError, ValueError):
        return False, {
            "configured": True,
            "upstream": upstream,
            "error": "git_divergence_unreadable",
        }
    oldest_age_days: float | None = None
    if ahead_memory:
        oldest_result = run(
            [
                "git",
                "-C",
                str(GIT_ROOT),
                "log",
                "--reverse",
                "--format=%ct",
                "@{upstream}..HEAD",
                "--",
                memory_pathspec,
            ],
            30,
        )
        timestamps = [line for line in str(oldest_result.get("stdout", "")).splitlines() if line]
        try:
            oldest = dt.datetime.fromtimestamp(int(timestamps[0]), tz=dt.timezone.utc)
        except (IndexError, TypeError, ValueError, OSError):
            return False, {
                "configured": True,
                "upstream": upstream,
                "ahead_total": ahead_total,
                "ahead_memory": ahead_memory,
                "behind": behind,
                "error": "oldest_unpushed_commit_unreadable",
            }
        current = now or dt.datetime.now(dt.timezone.utc)
        oldest_age_days = max(0.0, (current - oldest).total_seconds() / 86400)
    overdue = (
        behind > 0
        or ahead_memory >= REMOTE_BACKUP_MAX_UNPUSHED_COMMITS
        or (oldest_age_days is not None and oldest_age_days >= REMOTE_BACKUP_MAX_AGE_DAYS)
    )
    return not overdue, {
        "configured": True,
        "upstream": upstream,
        "ahead_total": ahead_total,
        "ahead_memory": ahead_memory,
        "behind": behind,
        "oldest_unpushed_age_days": round(oldest_age_days, 2) if oldest_age_days is not None else None,
        "warning_threshold_commits": REMOTE_BACKUP_MAX_UNPUSHED_COMMITS,
        "warning_threshold_days": REMOTE_BACKUP_MAX_AGE_DAYS,
    }


def session_claim_hygiene(
    conn: sqlite3.Connection,
    now: dt.datetime | None = None,
    max_age_hours: int = STALE_CLAIM_HOURS,
) -> tuple[bool, dict[str, Any]]:
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "memory_session_claims" not in tables:
        return False, {"active": 0, "stale": [], "error": "claim_table_missing"}
    rows = conn.execute(
        "SELECT actor, rel_path, updated_at FROM memory_session_claims WHERE status='active' ORDER BY actor, rel_path"
    ).fetchall()
    current = now or dt.datetime.now(dt.timezone.utc)
    stale: list[dict[str, Any]] = []
    for row in rows:
        updated_at = parse_time(str(row["updated_at"]))
        age_hours = (current - updated_at).total_seconds() / 3600 if updated_at else None
        if updated_at is None or age_hours is not None and age_hours >= max_age_hours:
            stale.append(
                {
                    "actor": str(row["actor"]),
                    "rel_path": str(row["rel_path"]),
                    "age_hours": round(max(0.0, age_hours), 1) if age_hours is not None else None,
                    "reason": "expired" if updated_at else "invalid_timestamp",
                }
            )
    return not stale, {"active": len(rows), "stale": stale, "stale_after_hours": max_age_hours}


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
    index_result = run([str(SCRIPT_ROOT / "agent_memory_index.py"), "--init", "--scan", "--report"], 180)
    actions.append({"action": "rebuild_sqlite_fts", "ok": index_result["ok"], "detail": index_result["detail"]})
    if index_result["ok"] and SEMANTIC_ENABLED:
        vector_result = run(
            [str(ZVEC_PYTHON), str(SCRIPT_ROOT / "agent_memory_zvec_index.py"), "--scan", "--prune", "--json"],
            900,
            offline_env() if REQUIRE_LOCAL_MODEL else None,
        )
        actions.append({"action": "rebuild_zvec", "ok": vector_result["ok"], "detail": vector_result["detail"]})
    return actions


def collect_checks(allow_dirty_memory: bool = False) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    required = [
        "agent_memory_index.py",
        "agent_memory_lock.py",
        "agent_memory_search.py",
        "agent_memory_closeout.py",
        "agent_memory_check.py",
        "agent_memory_audit.py",
        "agent_memory_audit_autorun.py",
        "agent_memory_zvec_index.py",
        "agent_memory_doctor.py",
        "agent_memory_session_hook.py",
        "agent_memory_stop_hook.py",
        "agent_memory_env.py",
        "install_runtime.py",
        "memoryctl",
    ]
    missing = [name for name in required if not (SCRIPT_ROOT / name).is_file()]
    add(checks, "runtime_files", "fail" if missing else "pass", "Runtime files complete." if not missing else "Runtime files missing.", {"missing": missing})
    version_ok = sys.version_info >= (3, 10)
    add(checks, "python_runtime", "pass" if version_ok else "fail", f"Python {sys.version.split()[0]} is active.")
    git_ok = bool(shutil.which("git"))
    add(checks, "git_runtime", "pass" if git_ok else "fail", "Git is available." if git_ok else "Git was not found in PATH.")
    if os.name == "nt":
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        add(checks, "windows_powershell", "pass" if powershell else "fail", "PowerShell is available." if powershell else "PowerShell was not found.")
        hooks_path = Path.home() / ".codex" / "hooks.json"
        hooks_text = hooks_path.read_text(encoding="utf-8-sig", errors="replace") if hooks_path.is_file() else ""
        hook_ok = "stop-hook.ps1" in hooks_text or "agent_memory_stop_hook.py" in hooks_text
        add(checks, "codex_stop_hook", "pass" if hook_ok else "warn", "Codex Stop Hook is configured." if hook_ok else "Codex Stop Hook is not installed.", {"path": str(hooks_path)})
        task_name = str(HOST_CONFIG.get("audit_task_name", "AgentMemoryVaultAudit"))
        task_result = run(
            [powershell, "-NoProfile", "-Command", f"Get-ScheduledTask -TaskName '{task_name}' -ErrorAction Stop | Out-Null"],
            15,
        ) if powershell else {"ok": False}
        add(checks, "audit_scheduled_task", "pass" if task_result.get("ok") else "warn", "Windows audit task is installed." if task_result.get("ok") else "Windows audit task is not installed.", {"task_name": task_name})
    if REPO_ROOT.resolve() == CONFIG_ROOT.resolve():
        manifest = read_json_object(RUNTIME_MANIFEST)
        expected = manifest.get("files") if isinstance(manifest, dict) else None
        manifest_missing: list[str] = []
        manifest_mismatch: list[str] = []
        support_missing: list[str] = []
        support_mismatch: list[str] = []
        if isinstance(expected, dict):
            for name, digest in expected.items():
                path = SCRIPT_ROOT / str(name)
                if not path.is_file():
                    manifest_missing.append(str(name))
                elif file_sha256(path) != str(digest):
                    manifest_mismatch.append(str(name))
        support_expected = manifest.get("support_files", {}) if isinstance(manifest, dict) else {}
        if isinstance(support_expected, dict):
            for name, digest in support_expected.items():
                path = CONFIG_ROOT / str(name)
                if not path.is_file():
                    support_missing.append(str(name))
                elif file_sha256(path) != str(digest):
                    support_mismatch.append(str(name))
        manifest_ok = (
            isinstance(expected, dict)
            and not manifest_missing
            and not manifest_mismatch
            and not support_missing
            and not support_mismatch
        )
        add(
            checks,
            "runtime_manifest",
            "pass" if manifest_ok else "fail",
            "Installed runtime matches its manifest." if manifest_ok else "Installed runtime drifted from its manifest.",
            {
                "source_commit": manifest.get("source_commit", "") if manifest else "",
                "source_dirty": bool(manifest.get("source_dirty")) if manifest else False,
                "missing": manifest_missing,
                "mismatched": manifest_mismatch,
                "support_missing": support_missing,
                "support_mismatched": support_mismatch,
            },
        )
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
    mismatch = sorted(str(row["rel_path"]) for raw, row in db_by_path.items() if raw in actual_by_path and markdown_sha256(actual_by_path[raw]) != str(row["sha256"]))
    add(checks, "markdown_sqlite_parity", "pass" if not (missing_db or stale_db or mismatch) else "fail", f"Markdown={len(actual)}, SQLite={len(docs)}.", {"missing": missing_db, "stale": stale_db, "hash_mismatch": mismatch})
    fts = {str(row[0]) for row in conn.execute("SELECT DISTINCT path FROM memory_fts")}
    add(checks, "sqlite_fts_parity", "pass" if fts == set(db_by_path) else "fail", f"FTS covers {len(fts)}/{len(docs)} docs.")
    index_path = VAULT_ROOT / "INDEX.md"
    refs = set(re.findall(r"`([^`]+\.md)`", index_path.read_text(encoding="utf-8", errors="replace"))) if index_path.exists() else set()
    add(checks, "index_navigation_parity", "pass" if refs == actual_rel else "warn", f"INDEX.md lists {len(refs)}/{len(actual_rel)} docs.", {"unlisted": sorted(actual_rel - refs), "broken": sorted(refs - actual_rel)})
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if {"memory_vector_chunks", "memory_vector_index_state"}.issubset(tables):
        eligible = {
            str(row["path"]): {"rel_path": str(row["rel_path"]), "sha256": str(row["sha256"])}
            for row in docs
            if eligible_vector(row)
        }
        states = conn.execute(
            "SELECT path, rel_path, doc_sha256, status, last_error FROM memory_vector_index_state"
        ).fetchall()
        if not states:
            add(checks, "zvec_parity", "warn", "Optional vector index is not initialized.")
        else:
            indexed = {str(row["path"]) for row in states if row["status"] == "indexed"}
            vector_missing = sorted(eligible[path]["rel_path"] for path in eligible.keys() - indexed)
            vector_stale = sorted(str(row["rel_path"] or row["path"]) for row in states if str(row["path"]) not in eligible)
            vector_hash_mismatch = sorted(
                eligible[str(row["path"])]["rel_path"]
                for row in states
                if str(row["path"]) in eligible
                and str(row["status"]) == "indexed"
                and str(row["doc_sha256"] or "") != eligible[str(row["path"])]["sha256"]
            )
            vector_errors = sorted(
                str(row["rel_path"] or row["path"])
                for row in states
                if str(row["status"]) == "error"
            )
            vector_ok = not (vector_missing or vector_stale or vector_hash_mismatch or vector_errors)
            add(
                checks,
                "zvec_parity",
                "pass" if vector_ok else "fail",
                f"Zvec covers {len(indexed & eligible.keys())}/{len(eligible)} docs.",
                {
                    "missing": vector_missing,
                    "stale": vector_stale,
                    "hash_mismatch": vector_hash_mismatch,
                    "errors": vector_errors,
                },
            )
    else:
        add(checks, "zvec_parity", "warn", "Optional vector index is not initialized.")
    if SEMANTIC_ENABLED:
        local_model_ok = (not REQUIRE_LOCAL_MODEL) or (EMBEDDING_MODEL.is_absolute() and EMBEDDING_MODEL.is_dir())
        add(
            checks,
            "semantic_local_model",
            "pass" if local_model_ok else "fail",
            "Semantic retrieval is pinned to a managed local model." if local_model_ok else "Semantic retrieval is not backed by the required local model directory.",
            {"model": str(EMBEDDING_MODEL), "require_local_model": REQUIRE_LOCAL_MODEL},
        )
        manifest_ok, manifest_detail = verify_model_manifest()
        add(
            checks,
            "semantic_model_integrity",
            "pass" if manifest_ok else "fail",
            "Managed model files match the pinned manifest." if manifest_ok else "Managed model files drifted from the pinned manifest.",
            manifest_detail,
        )
        python_ok, python_detail = verify_semantic_python_runtime()
        add(
            checks,
            "semantic_python_runtime",
            "pass" if python_ok else "fail",
            "Semantic Python and its base interpreter are available." if python_ok else "Semantic Python runtime is broken or lost its base interpreter.",
            python_detail,
        )
        dependency_ok, dependency_detail = verify_dependency_lock()
        add(
            checks,
            "semantic_dependency_lock",
            "pass" if dependency_ok else "fail",
            "Semantic Python environment matches the exact dependency lock." if dependency_ok else "Semantic Python environment differs from the dependency lock.",
            dependency_detail,
        )
        probe_ok, probe_detail = offline_semantic_probe()
        add(
            checks,
            "semantic_offline_probe",
            "pass" if probe_ok else "fail",
            "Offline EmbeddingGemma + Zvec query succeeded." if probe_ok else "Offline EmbeddingGemma + Zvec query failed.",
            probe_detail,
        )
    source_counts = {str(row[0]): int(row[1]) for row in conn.execute("SELECT verified_at_source, COUNT(*) FROM memory_docs GROUP BY verified_at_source")}
    weak = source_counts.get("mtime_fallback", 0) + source_counts.get("needs_review", 0)
    add(
        checks,
        "verification_provenance",
        "warn" if weak else "pass",
        f"Explicit verification/provenance classification on {len(docs) - weak}/{len(docs)} docs.",
        {"by_source": source_counts, "needs_review": weak},
    )
    large = [
        {"rel_path": str(row["rel_path"]), "lines": int(row["line_count"]), "bytes": int(row["size_bytes"])}
        for row in docs
        if str(row["status"]) in {"active", "candidate"}
        and (int(row["line_count"]) > 180 or int(row["size_bytes"]) > 24576)
    ]
    add(checks, "large_memory_files", "warn" if large else "pass", f"{len(large)} docs exceed compaction advisory thresholds.", {"files": large})
    raw_logs = int(conn.execute("SELECT COUNT(*) FROM memory_search_log WHERE query NOT LIKE '[redacted:%'").fetchone()[0])
    add(checks, "search_log_privacy", "warn" if raw_logs else "pass", f"{raw_logs} legacy raw-query rows remain.", {"legacy_raw_rows": raw_logs})
    claims_ok, claims_detail = session_claim_hygiene(conn)
    stale_claim_count = len(claims_detail.get("stale", []))
    add(
        checks,
        "session_claim_hygiene",
        "pass" if claims_ok else "warn",
        f"Active claims={claims_detail.get('active', 0)}, stale claims={stale_claim_count}.",
        claims_detail,
    )
    conn.close()
    latest_audit = latest_jsonl(AUDIT_LOG, lambda item: item.get("status") == "ran" and item.get("ok"))
    audit_time = parse_time(str(latest_audit.get("time", ""))) if latest_audit else None
    age = (dt.datetime.now(dt.timezone.utc) - audit_time).days if audit_time else None
    add(checks, "audit_freshness", "pass" if age is not None and age <= 7 else "warn", f"Last successful audit age: {age} days." if age is not None else "No successful audit recorded.")
    closeout = latest_jsonl(CLOSEOUT_LOG)
    add(checks, "closeout_history", "pass" if closeout and closeout.get("status") in {"ok", "warning"} else "warn", f"Latest closeout status: {closeout.get('status')}." if closeout else "No closeout history.")

    remote_has_credential = git_remote_has_credential()
    add(
        checks,
        "git_remote_credentials",
        "fail" if remote_has_credential else "pass",
        "Git remote contains an embedded credential." if remote_has_credential else "Git remote has no embedded credential.",
    )
    try:
        memory_pathspec = VAULT_ROOT.relative_to(GIT_ROOT).as_posix()
    except ValueError:
        memory_pathspec = str(VAULT_ROOT)
    git_status = run(
        ["git", "-C", str(GIT_ROOT), "-c", "core.quotepath=false", "status", "--porcelain=v1", "--", memory_pathspec],
        30,
    )
    dirty_lines = [line for line in str(git_status.get("stdout", "")).splitlines() if line]
    dirty_status, dirty_message, dirty_detail = memory_git_baseline_result(
        len(dirty_lines), bool(git_status["ok"]), allow_dirty_memory
    )
    add(
        checks,
        "memory_git_baseline",
        dirty_status,
        dirty_message,
        dirty_detail,
    )
    backup_ok, backup_detail = git_remote_backup_health(memory_pathspec)
    unpushed_memory = int(backup_detail.get("ahead_memory", 0) or 0)
    add(
        checks,
        "memory_remote_backup",
        "pass" if backup_ok else "warn",
        (
            "Memory Git history is backed up to its upstream."
            if backup_ok and unpushed_memory == 0
            else (
                f"{unpushed_memory} unpushed memory commits remain within the backup grace window."
                if backup_ok
                else "Memory Git history has no healthy recent upstream backup."
            )
        ),
        backup_detail,
    )

    if HOST_CONFIG:
        codex_hooks_path = configured_path("codex_hooks_json")
        if codex_hooks_path:
            codex_hooks = read_json_object(codex_hooks_path)
            codex_ok = "on-stop-memory.sh" in json.dumps(codex_hooks, ensure_ascii=False)
            add(checks, "codex_stop_hook", "pass" if codex_ok else "warn", "Codex Stop hook is configured." if codex_ok else "Codex Stop hook is missing or invalid.")

        claude_settings_path = configured_path("claude_settings_json")
        claude_fragment_path = configured_path("claude_hooks_fragment")
        claude_settings = read_json_object(claude_settings_path) if claude_settings_path else {}
        expected_hooks = read_json_object(claude_fragment_path) if claude_fragment_path else {}
        if claude_settings_path or claude_fragment_path:
            claude_ok = bool(expected_hooks) and claude_settings.get("hooks") == expected_hooks
            add(checks, "claude_stop_hook", "pass" if claude_ok else "warn", "Claude Stop/SessionEnd hooks are configured." if claude_ok else "Claude hooks differ from the managed fragment.")

        cc_switch_path = configured_path("cc_switch_db")
        if cc_switch_path:
            cc_ok, cc_detail = cc_switch_hooks_match(cc_switch_path, expected_hooks)
            add(checks, "claude_hook_persistence", "pass" if cc_ok else "warn", "Claude hook persistence is healthy." if cc_ok else "A provider manager may overwrite Claude hooks.", cc_detail)

        env_payload = claude_settings.get("env") if isinstance(claude_settings, dict) else {}
        base_url = str(env_payload.get("ANTHROPIC_BASE_URL", "")) if isinstance(env_payload, dict) else ""
        if claude_settings_path:
            endpoint_ok, endpoint_detail = local_endpoint_reachable(base_url)
            add(checks, "claude_runtime_endpoint", "pass" if endpoint_ok else "warn", "Claude runtime endpoint is reachable or remote." if endpoint_ok else "Claude points to a local endpoint that is not listening.", endpoint_detail)

        launch_path = configured_path("audit_launchagent")
        launch_label = HOST_CONFIG.get("audit_launchagent_label")
        if launch_path and isinstance(launch_label, str) and launch_label:
            launch_loaded = run(["launchctl", "print", f"gui/{Path.home().stat().st_uid}/{launch_label}"], 15)["ok"]
            launch_ok = launch_path.exists() and launch_loaded
            add(checks, "audit_launchagent", "pass" if launch_ok else "warn", "Weekly audit LaunchAgent is loaded." if launch_ok else "Weekly audit LaunchAgent is missing or unloaded.", {"plist_exists": launch_path.exists(), "loaded": launch_loaded})
    return checks


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only health report for the complete Agent Memory pipeline.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--repair-derived", action="store_true", help="Rebuild derived indexes without editing Markdown facts.")
    parser.add_argument(
        "--allow-dirty-memory",
        action="store_true",
        help="Treat the current pre-commit memory changes as expected; intended only for closeout piggyback checks.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repairs = repair_derived() if args.repair_derived else []
    checks = collect_checks(allow_dirty_memory=args.allow_dirty_memory)
    statuses = {str(item["status"]) for item in checks}
    status = "error" if "fail" in statuses else ("warning" if "warn" in statuses else "ok")
    payload = {"time": utc_now(), "version": VERSION, "status": status, "summary": {name: sum(1 for item in checks if item["status"] == name) for name in ("pass", "warn", "fail")}, "checks": checks, "repair_actions": repairs}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"agent_memory_doctor={status} version={VERSION}")
        for item in checks:
            print(f"[{item['status']}] {item['name']}: {item['message']}")
    return 2 if status == "error" else 0


if __name__ == "__main__":
    raise SystemExit(main())
