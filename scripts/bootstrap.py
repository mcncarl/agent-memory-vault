#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from agent_memory_env import expand_path


REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = REPO_ROOT / "templates" / "vault"


def replacements(args: argparse.Namespace) -> dict[str, str]:
    return {
        "{{USER_ID}}": args.user_id,
        "{{AGENT_ID}}": args.agent_id,
        "{{APP_ID}}": args.app_id,
        "{{STATE_DB}}": str(expand_path(args.state_db).resolve()),
    }


def render_text(text: str, mapping: dict[str, str]) -> str:
    for key, value in mapping.items():
        text = text.replace(key, value)
    return text


def shell_export(name: str, value: object) -> str:
    if not name.isidentifier():
        raise ValueError(f"invalid environment variable name: {name}")
    text = str(value)
    if any(character in text for character in ("\0", "\r", "\n")):
        raise ValueError(f"environment variable {name} contains an unsupported control character")
    return f"export {name}={shlex.quote(text)}"


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
    config_root = expand_path(args.config_root).resolve()
    git_root = expand_path(args.git_root).resolve() if args.git_root else memory_root
    content = "\n".join(
        [
            shell_export("AGENT_MEMORY_ROOT", memory_root),
            shell_export("AGENT_MEMORY_GIT_ROOT", git_root),
            shell_export("AGENT_MEMORY_CONFIG_ROOT", config_root),
            shell_export("AGENT_MEMORY_STATE_DB", expand_path(args.state_db).resolve()),
            shell_export("AGENT_MEMORY_USER_ID", args.user_id),
            shell_export("AGENT_MEMORY_AGENT_ID", args.agent_id),
            shell_export("AGENT_MEMORY_APP_ID", args.app_id),
            shell_export("AGENT_MEMORY_AUDIT_DB", config_root / "audit_decisions.sqlite"),
            shell_export("AGENT_MEMORY_CLOSEOUT_LOG", config_root / "logs" / "closeout.jsonl"),
            shell_export("AGENT_MEMORY_AUDIT_RUN_LOG", config_root / "logs" / "audit_runs.jsonl"),
            shell_export("AGENT_MEMORY_AUDIT_REPORT", config_root / "reports" / "latest-audit.json"),
            "",
        ]
    )
    env_path.write_text(content, encoding="utf-8")
    print(f"OK wrote_env {env_path}")


def run_git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=60,
        check=False,
    )


def initialize_git_baseline(memory_root: Path, git_root: Path) -> dict[str, str]:
    """Create a clean first Git baseline without staging unrelated parent files."""

    if git_root != memory_root:
        return {"status": "skipped", "detail": "external_git_root"}
    if shutil.which("git") is None:
        return {"status": "error", "detail": "git_not_found"}
    if not (git_root / ".git").exists():
        initialized = run_git(git_root, "init", "-q")
        if initialized.returncode != 0:
            return {"status": "error", "detail": initialized.stderr.strip() or "git_init_failed"}
    head = run_git(git_root, "rev-parse", "--verify", "HEAD")
    if head.returncode == 0:
        return {"status": "existing", "detail": head.stdout.strip()}

    template_paths = [
        source.relative_to(TEMPLATE_ROOT).as_posix()
        for source in sorted(TEMPLATE_ROOT.rglob("*"))
        if source.is_file() and (memory_root / source.relative_to(TEMPLATE_ROOT)).is_file()
    ]
    staged = run_git(git_root, "add", "--", *template_paths)
    if staged.returncode != 0:
        return {"status": "error", "detail": staged.stderr.strip() or "git_add_failed"}
    commit = run_git(
        git_root,
        "-c",
        "user.name=Agent Memory Vault",
        "-c",
        "user.email=agent-memory@localhost",
        "commit",
        "-qm",
        "Initialize Agent Memory Vault",
    )
    if commit.returncode != 0:
        return {"status": "error", "detail": commit.stderr.strip() or "git_commit_failed"}
    return {"status": "created", "detail": run_git(git_root, "rev-parse", "HEAD").stdout.strip()}


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
    git_group = parser.add_mutually_exclusive_group()
    git_group.add_argument("--init-git", dest="init_git", action="store_true", help="Create an initial Git baseline (default).")
    git_group.add_argument("--no-init-git", dest="init_git", action="store_false", help="Do not initialize Git.")
    parser.set_defaults(init_git=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not TEMPLATE_ROOT.is_dir():
        raise SystemExit(f"Template root not found: {TEMPLATE_ROOT}")

    memory_root = expand_path(args.memory_root).resolve()
    memory_root.mkdir(parents=True, exist_ok=True)
    created, skipped = copy_template(memory_root, replacements(args), args.overwrite)
    print(f"memory_root={memory_root}")
    print(f"created_or_updated_files={created}")
    print(f"skipped_existing_files={skipped}")

    if args.write_env:
        write_env(args, memory_root)

    git_root = expand_path(args.git_root).resolve() if args.git_root else memory_root
    git_baseline = initialize_git_baseline(memory_root, git_root) if args.init_git else {"status": "skipped", "detail": "disabled"}
    print(f"git_baseline={git_baseline['status']} {git_baseline['detail']}")
    if git_baseline["status"] == "error":
        return 2

    print("next_commands:")
    if os.name == "nt":
        print("  # Runtime TOML/.env is loaded by Python; no PowerShell import is required")
    else:
        print("  source .env")
    print("  memoryctl --actor migration migrate config-plan --json")
    print(
        "  memoryctl --actor migration migrate config-apply "
        "--backup-path /new/private/agent-memory-before-v2.toml --json  # only when plan says required"
    )
    state_path = expand_path(args.state_db).resolve()
    if state_path.exists():
        print("  memoryctl --actor migration migrate plan --json")
        print(
            "  memoryctl --actor migration migrate apply "
            "--backup-path /new/private/state-before-v2.sqlite --json"
        )
    else:
        print("  memoryctl --actor migration migrate init --json")
    print("  memoryctl --actor migration migrate audit-plan --json")
    print(
        "  memoryctl --actor migration migrate audit-init "
        "--json  # only when audit-plan says initialization_required"
    )
    print(
        "  memoryctl --actor migration migrate audit-apply "
        "--backup-path /new/private/audit-before-v4.sqlite --json  # only when audit-plan says migration_required"
    )
    print("  memoryctl --actor migration migrate generated-index-migrate --json")
    print("  memoryctl --actor migration migrate verify --json")
    print("  # Install the selected host hook now, or explicitly attest no host hooks")
    print(
        "  memoryctl --actor migration migrate verify "
        "--publish-ready --require-host-hooks --json  # both Codex and Claude"
    )
    print("  # Or repeat --require-host-hook codex|claude; without hooks use --no-host-hooks")
    print("optional_semantic_retrieval:")
    print(f"  {sys.executable} -m pip install -r requirements-vector.lock")
    print("  memoryctl --actor migration zvec --init --scan --prune --json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
