#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bridge host session IDs into Agent Memory commands.")
    parser.add_argument("--actor", choices=("claude",), default="claude")
    return parser.parse_args()


def read_payload() -> dict[str, object]:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        return {}
    return payload if isinstance(payload, dict) else {}


def main() -> int:
    args = parse_args()
    payload = read_payload()
    session_id = str(payload.get("session_id") or "").strip()
    raw_env_file = os.environ.get("CLAUDE_ENV_FILE", "").strip()
    if args.actor != "claude" or not session_id or not raw_env_file:
        print("agent memory session bridge requires session_id and CLAUDE_ENV_FILE", file=sys.stderr)
        return 1
    env_file = Path(raw_env_file).expanduser()
    try:
        with env_file.open("a", encoding="utf-8") as handle:
            handle.write(f"export AGENT_MEMORY_SESSION_ID={shlex.quote(session_id)}\n")
            handle.write(f"export CLAUDE_SESSION_ID={shlex.quote(session_id)}\n")
            handle.write("unset CODEX_THREAD_ID\n")
    except OSError as exc:
        print(f"agent memory session bridge failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
