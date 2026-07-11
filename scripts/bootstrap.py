#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = REPO_ROOT / "templates" / "vault"


def expand_path(raw: str) -> Path:
    return Path(os.path.expandvars(raw)).expanduser().resolve()


def replacements(args: argparse.Namespace) -> dict[str, str]:
    return {
        "{{USER_ID}}": args.user_id,
        "{{AGENT_ID}}": args.agent_id,
        "{{APP_ID}}": args.app_id,
        "{{STATE_DB}}": str(expand_path(args.state_db)),
    }


def render_text(text: str, mapping: dict[str, str]) -> str:
    for key, value in mapping.items():
        text = text.replace(key, value)
    return text


def copy_template(target_root: Path, mapping: dict[str, str], overwrite: bool) -> tuple[int, int]:
    created = 0
    skipped = 0
    for source in sorted(TEMPLATE_ROOT.rglob("*")):
        relative = source.relative_to(TEMPLATE_ROOT)
        target = target_root / relative
        if source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not overwrite:
            skipped += 1
            continue
        if source.suffix.lower() in {".md", ".txt"}:
            text = source.read_text(encoding="utf-8")
            target.write_text(render_text(text, mapping), encoding="utf-8")
        else:
            shutil.copy2(source, target)
        created += 1
    return created, skipped


def write_env(args: argparse.Namespace, memory_root: Path) -> None:
    env_path = REPO_ROOT / ".env"
    if env_path.exists() and not args.overwrite_env:
        print(f"SKIP env_exists {env_path}")
        return
    config_root = expand_path(args.config_root)
    git_root = expand_path(args.git_root) if args.git_root else memory_root
    content = "\n".join(
        [
            f"AGENT_MEMORY_ROOT={memory_root}",
            f"AGENT_MEMORY_GIT_ROOT={git_root}",
            f"AGENT_MEMORY_CONFIG_ROOT={config_root}",
            f"AGENT_MEMORY_STATE_DB={expand_path(args.state_db)}",
            f"AGENT_MEMORY_USER_ID={args.user_id}",
            f"AGENT_MEMORY_AGENT_ID={args.agent_id}",
            f"AGENT_MEMORY_APP_ID={args.app_id}",
            f"AGENT_MEMORY_AUDIT_DB={config_root / 'audit_decisions.sqlite'}",
            f"AGENT_MEMORY_CLOSEOUT_LOG={config_root / 'logs' / 'closeout.jsonl'}",
            f"AGENT_MEMORY_AUDIT_RUN_LOG={config_root / 'logs' / 'audit_runs.jsonl'}",
            f"AGENT_MEMORY_AUDIT_REPORT={config_root / 'reports' / 'latest-audit.json'}",
            "",
        ]
    )
    env_path.write_text(content, encoding="utf-8")
    print(f"OK wrote_env {env_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a local Agent Memory Vault from the public template.")
    parser.add_argument("--memory-root", required=True, help="Target local memory vault path.")
    parser.add_argument(
        "--state-db",
        default="$HOME/.config/agent-memory/state.sqlite",
        help="SQLite state database path.",
    )
    parser.add_argument(
        "--config-root",
        default="$HOME/.config/agent-memory",
        help="Local config/state directory for logs, audit decisions, and derived indexes.",
    )
    parser.add_argument(
        "--git-root",
        default="",
        help="Git root that contains the memory vault. Defaults to --memory-root.",
    )
    parser.add_argument("--user-id", default="demo-user", help="Non-secret user identifier.")
    parser.add_argument("--agent-id", default="shared", help="Default memory scope: shared, codex, or claude.")
    parser.add_argument("--app-id", default="agent-memory", help="Application/workspace identifier.")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing template files in the target vault. No files are deleted.",
    )
    parser.add_argument("--write-env", action="store_true", help="Write a local .env file in this repo.")
    parser.add_argument("--overwrite-env", action="store_true", help="Overwrite an existing local .env file.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not TEMPLATE_ROOT.is_dir():
        raise SystemExit(f"Template root not found: {TEMPLATE_ROOT}")

    memory_root = expand_path(args.memory_root)
    memory_root.mkdir(parents=True, exist_ok=True)
    created, skipped = copy_template(memory_root, replacements(args), args.overwrite)
    print(f"memory_root={memory_root}")
    print(f"created_or_updated_files={created}")
    print(f"skipped_existing_files={skipped}")

    if args.write_env:
        write_env(args, memory_root)

    print("next_commands:")
    print("  source .env")
    print("  git -C \"$AGENT_MEMORY_GIT_ROOT\" init  # optional, if the vault is not already in a git repo")
    print("  python3 scripts/agent_memory_evolution.py --init --scan --report")
    print("  python3 scripts/agent_memory_index.py --init --scan --report")
    print("  python3 scripts/agent_memory_closeout.py --dry-run")
    print("  python3 scripts/agent_memory_check.py")
    print("  python3 scripts/agent_memory_doctor.py")
    print("optional_semantic_retrieval:")
    print("  python3 -m pip install -r requirements-vector.txt")
    print("  python3 scripts/agent_memory_zvec_index.py --init --scan --prune")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
