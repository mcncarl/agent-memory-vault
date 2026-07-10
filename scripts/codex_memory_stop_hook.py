#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = Path(os.path.expandvars(os.environ.get("CODEX_MEMORY_ROOT", str(REPO_ROOT / "templates" / "vault")))).expanduser().resolve()
CONFIG_ROOT = Path(os.path.expandvars(os.environ.get("CODEX_MEMORY_CONFIG_ROOT", "$HOME/.config/codex-memory"))).expanduser().resolve()
STATE_DB = Path(os.path.expandvars(os.environ.get("CODEX_MEMORY_STATE_DB", str(CONFIG_ROOT / "state.sqlite")))).expanduser().resolve()


def default_git_root() -> Path:
    for candidate in (VAULT_ROOT, *VAULT_ROOT.parents):
        if (candidate / ".git").exists():
            return candidate.resolve()
    return VAULT_ROOT.parent.resolve()


GIT_ROOT = Path(os.path.expandvars(os.environ.get("CODEX_MEMORY_GIT_ROOT", str(default_git_root())))).expanduser().resolve()
AUDIT_AUTORUN = REPO_ROOT / "scripts" / "codex_memory_audit_autorun.py"
STAMP_ROOT = CONFIG_ROOT / "hooks"


def payload() -> dict[str, object]:
    try:
        value = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        return {}
    return value if isinstance(value, dict) else {}


def session_key(data: dict[str, object]) -> str:
    for key in ("session_id", "sessionId", "thread_id", "threadId", "conversation_id", "conversationId"):
        if data.get(key):
            return str(data[key])
    return f"{data.get('cwd') or 'codex'}|{time.strftime('%Y-%m-%d')}"


def dirty_paths() -> list[Path]:
    try:
        target = str(VAULT_ROOT.relative_to(GIT_ROOT))
    except ValueError:
        target = str(VAULT_ROOT)
    try:
        result = subprocess.run(["git", "-C", str(GIT_ROOT), "-c", "core.quotepath=false", "status", "--porcelain=v1", "-z", "--", target], text=True, capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    paths = []
    for item in (part for part in result.stdout.split("\0") if len(part) >= 4):
        path = GIT_ROOT / item[3:]
        if path.exists() and path.suffix.lower() == ".md":
            paths.append(path)
    return list(dict.fromkeys(paths))


def notify(message: str) -> None:
    if sys.platform != "darwin":
        return
    safe = message.replace("\\", "\\\\").replace('"', '\\"')
    subprocess.run(["osascript", "-e", f'display notification "{safe}" with title "Codex memory"'], timeout=5, check=False)


def main() -> int:
    data = payload()
    paths = dirty_paths()
    state_mtime = STATE_DB.stat().st_mtime if STATE_DB.exists() else 0
    if paths and max(path.stat().st_mtime for path in paths) > state_mtime:
        STAMP_ROOT.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha1(session_key(data).encode("utf-8")).hexdigest()[:16]
        stamp = STAMP_ROOT / f"stop-memory-reminded-{digest}.stamp"
        if not stamp.exists():
            stamp.write_text(str(int(time.time())), encoding="utf-8")
            notify(f"{len(paths)} memory files still need closeout.")
    if AUDIT_AUTORUN.exists():
        subprocess.run([sys.executable, str(AUDIT_AUTORUN), "--reason", "hook", "--min-interval-days", "7", "--notify", "--json"], text=True, capture_output=True, timeout=12, check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
