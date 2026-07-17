#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


SOURCE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = SOURCE_ROOT.parent
CORE_FILES = (
    "agent_memory_audit.py",
    "agent_memory_audit_autorun.py",
    "agent_memory_claim.py",
    "agent_memory_check.py",
    "agent_memory_closeout.py",
    "agent_memory_doctor.py",
    "agent_memory_env.py",
    "agent_memory_evolution.py",
    "agent_memory_index.py",
    "agent_memory_lock.py",
    "agent_memory_retrieval_benchmark.py",
    "agent_memory_search.py",
    "agent_memory_session_hook.py",
    "agent_memory_stop_hook.py",
    "agent_memory_zvec_index.py",
    "audit-task.ps1",
    "bootstrap.py",
    "install_runtime.py",
    "stop-hook.ps1",
    "memoryctl",
)
SUPPORT_FILES = ("requirements-vector.lock",)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_value(*args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else ""


def expected_manifest(config_root: Path) -> dict[str, Any]:
    hashes = {name: sha256(SOURCE_ROOT / name) for name in CORE_FILES}
    support_hashes = {name: sha256(REPO_ROOT / name) for name in SUPPORT_FILES}
    return {
        "schema_version": 1,
        "installed_at": utc_now(),
        "source_repo": str(REPO_ROOT),
        "source_commit": git_value("rev-parse", "HEAD") or "archive",
        "source_dirty": bool(git_value("status", "--porcelain")),
        "runtime_root": str(config_root),
        "files": hashes,
        "support_files": support_hashes,
    }


def verify(config_root: Path) -> dict[str, Any]:
    manifest_path = config_root / "config" / "runtime-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"ok": False, "manifest": str(manifest_path), "missing_manifest": True}
    expected = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(expected, dict):
        return {"ok": False, "manifest": str(manifest_path), "invalid_manifest": True}
    missing: list[str] = []
    mismatched: list[str] = []
    for name, digest in expected.items():
        path = config_root / "scripts" / str(name)
        if not path.is_file():
            missing.append(str(name))
        elif sha256(path) != str(digest):
            mismatched.append(str(name))
    support_missing: list[str] = []
    support_mismatched: list[str] = []
    support_expected = manifest.get("support_files", {}) if isinstance(manifest, dict) else {}
    if isinstance(support_expected, dict):
        for name, digest in support_expected.items():
            path = config_root / str(name)
            if not path.is_file():
                support_missing.append(str(name))
            elif sha256(path) != str(digest):
                support_mismatched.append(str(name))
    return {
        "ok": not missing and not mismatched and not support_missing and not support_mismatched,
        "manifest": str(manifest_path),
        "source_commit": manifest.get("source_commit", ""),
        "source_dirty": bool(manifest.get("source_dirty")),
        "checked_files": len(expected),
        "missing": missing,
        "mismatched": mismatched,
        "support_missing": support_missing,
        "support_mismatched": support_mismatched,
    }


def install(config_root: Path, dry_run: bool) -> dict[str, Any]:
    script_root = config_root / "scripts"
    config_dir = config_root / "config"
    manifest = expected_manifest(config_root)
    changed: list[str] = []
    unchanged: list[str] = []
    for name in CORE_FILES:
        source = SOURCE_ROOT / name
        target = script_root / name
        if target.is_file() and sha256(target) == manifest["files"][name]:
            unchanged.append(name)
            if not dry_run:
                target.chmod(source.stat().st_mode & 0o777)
            continue
        changed.append(name)
        if not dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            target.chmod(source.stat().st_mode & 0o777)
    for name in SUPPORT_FILES:
        source = REPO_ROOT / name
        target = config_root / name
        if target.is_file() and sha256(target) == manifest["support_files"][name]:
            unchanged.append(name)
            continue
        changed.append(name)
        if not dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    if not dry_run:
        config_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = config_dir / "runtime-manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        "ok": True,
        "dry_run": dry_run,
        "config_root": str(config_root),
        "changed": changed,
        "unchanged": unchanged,
        "source_commit": manifest["source_commit"],
        "source_dirty": manifest["source_dirty"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install or verify the canonical Agent Memory runtime.")
    parser.add_argument("--config-root", default="~/.config/agent-memory")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_root = Path(args.config_root).expanduser().resolve()
    payload = verify(config_root) if args.verify else install(config_root, args.dry_run)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"runtime={'ok' if payload.get('ok') else 'error'} root={config_root}")
        for key in ("changed", "missing", "mismatched"):
            if payload.get(key):
                print(f"{key}={','.join(payload[key])}")
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
