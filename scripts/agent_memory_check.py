#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

from agent_memory_env import env_value


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = REPO_ROOT / "scripts"
DEFAULT_VAULT_ROOT = REPO_ROOT / "templates" / "vault"
VAULT_ROOT = Path(os.path.expandvars(env_value("ROOT", str(DEFAULT_VAULT_ROOT)))).expanduser().resolve()
STATE_DB = Path(
    os.path.expandvars(env_value("STATE_DB", "$HOME/.config/agent-memory/state.sqlite"))
).expanduser().resolve()


REQUIRED_DIRS = [
    VAULT_ROOT / "用户记忆",
    VAULT_ROOT / "项目",
    VAULT_ROOT / "工作流",
    VAULT_ROOT / "决策",
    VAULT_ROOT / "agent" / "case-candidates",
    VAULT_ROOT / "agent" / "cases",
    VAULT_ROOT / "agent" / "skill-candidates",
]


REQUIRED_FILES = [
    VAULT_ROOT / "AGENTS.md",
    VAULT_ROOT / "INDEX.md",
    VAULT_ROOT / "用户记忆" / "README.md",
    VAULT_ROOT / "用户记忆" / "偏好与边界.md",
    VAULT_ROOT / "用户记忆" / "长期画像.md",
    VAULT_ROOT / "工作流" / "Agent记忆字段规范.md",
    VAULT_ROOT / "工作流" / "Agent记忆收尾决策规则.md",
    VAULT_ROOT / "工作流" / "Agent记忆SQLite全库索引设计.md",
    VAULT_ROOT / "工作流" / "Agent记忆语义检索设计.md",
    VAULT_ROOT / "agent" / "README.md",
    VAULT_ROOT / "agent" / "case-candidates" / "README.md",
    VAULT_ROOT / "agent" / "case-candidates" / "_模板-AgentCase候选.md",
    VAULT_ROOT / "agent" / "cases" / "README.md",
    VAULT_ROOT / "agent" / "cases" / "_模板-AgentCase正式记忆.md",
    VAULT_ROOT / "agent" / "skill-candidates" / "README.md",
    VAULT_ROOT / "agent" / "skill-candidates" / "_模板-Skill候选.md",
]

REQUIRED_LOCAL_FILES = [
    SCRIPT_ROOT / "bootstrap.py",
    SCRIPT_ROOT / "agent_memory_check.py",
    SCRIPT_ROOT / "agent_memory_evolution.py",
    SCRIPT_ROOT / "agent_memory_index.py",
    SCRIPT_ROOT / "agent_memory_search.py",
    SCRIPT_ROOT / "agent_memory_closeout.py",
    SCRIPT_ROOT / "agent_memory_audit.py",
    SCRIPT_ROOT / "agent_memory_audit_autorun.py",
    SCRIPT_ROOT / "agent_memory_zvec_index.py",
    SCRIPT_ROOT / "agent_memory_retrieval_benchmark.py",
    SCRIPT_ROOT / "agent_memory_doctor.py",
    SCRIPT_ROOT / "agent_memory_stop_hook.py",
]

REQUIRED_STATE_TABLES = {
    "meta",
    "memory_files",
    "agent_case_state",
    "reminders",
    "memory_docs",
    "memory_fts",
    "memory_open_loops",
}

OPTIONAL_STATE_TABLES = {
    "memory_vector_chunks",
    "memory_vector_index_state",
}

COMPACTION_DIR_NAMES = {"用户记忆", "项目", "工作流", "决策", "agent"}
DEFAULT_COMPACTION_LINE_LIMIT = 140
DEFAULT_COMPACTION_BYTE_LIMIT = 14 * 1024


SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9][A-Za-z0-9_-]{16,}"),
    re.compile(r"ghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)DEEPSEEK_API_KEY\s*=\s*sk-"),
    re.compile(r"(?i)OPENAI_API_KEY\s*=\s*sk-"),
    re.compile(r"/Users/[A-Za-z0-9._-]+/"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}"),
    re.compile(r"(?<!\d)\d{8,12}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9])(?:sk|rk)_live_[A-Za-z0-9]{16,}"),
]

SECRET_ENV_NAMES = [
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
]


def exact_secret_values() -> list[str]:
    values: list[str] = []
    for name in SECRET_ENV_NAMES:
        value = os.environ.get(name, "").strip()
        if len(value) >= 16:
            values.append(value)
    return values


def iter_text_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    ignored_dirs = {".git", "__pycache__", "node_modules", ".pytest_cache"}
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in ignored_dirs for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() in {".md", ".txt", ".py", ".toml", ".example", ".gitignore", ""} or path.name in {
            "README.md",
            ".env.example",
        }:
            files.append(path)
    return files


def scan_for_secrets(roots: list[Path]) -> list[Path]:
    leaked: list[Path] = []
    exact_values = exact_secret_values()
    seen: set[Path] = set()
    for root in roots:
        for path in iter_text_files(root):
            if path in seen:
                continue
            seen.add(path)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if any(value and value in text for value in exact_values):
                leaked.append(path)
                continue
            if any(pattern.search(text) for pattern in SECRET_PATTERNS):
                leaked.append(path)
    return leaked


def file_has_frontmatter(path: Path) -> bool:
    text = path.read_text(encoding="utf-8", errors="replace")
    return text.startswith("---\n") and "memory_type:" in text and "status:" in text


def check_state_db() -> tuple[bool, str]:
    if not STATE_DB.exists():
        return False, "missing"
    try:
        with sqlite3.connect(STATE_DB) as conn:
            conn.execute("PRAGMA busy_timeout=10000")
            rows = conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'virtual table')").fetchall()
    except sqlite3.Error as exc:
        return False, str(exc)
    tables = {row[0] for row in rows}
    missing = sorted(REQUIRED_STATE_TABLES - tables)
    if missing:
        return False, f"missing_tables={','.join(missing)}"
    optional_missing = sorted(OPTIONAL_STATE_TABLES - tables)
    optional_detail = "vector_tables=present" if not optional_missing else f"optional_missing={','.join(optional_missing)}"
    return True, f"schema_ok {optional_detail}"


def normalize_path(raw_path: str) -> Path:
    path = Path(os.path.expandvars(raw_path)).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()


def is_vault_markdown(path: Path) -> bool:
    if path.suffix.lower() != ".md":
        return False
    try:
        relative = path.relative_to(VAULT_ROOT)
    except ValueError:
        return False
    if path.name == "README.md" or path.name.startswith("_模板"):
        return False
    return bool(relative.parts) and relative.parts[0] in COMPACTION_DIR_NAMES


def changed_file_compaction_warnings(
    raw_paths: list[str],
    line_limit: int,
    byte_limit: int,
) -> tuple[list[str], list[str]]:
    warnings: list[str] = []
    infos: list[str] = []
    seen: set[Path] = set()
    for raw_path in raw_paths:
        path = normalize_path(raw_path)
        if path in seen:
            continue
        seen.add(path)

        if not path.exists():
            infos.append(f"SKIP compaction_missing_changed_file {path}")
            continue
        if not is_vault_markdown(path):
            infos.append(f"SKIP compaction_not_memory_doc {path}")
            continue

        byte_count = path.stat().st_size
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            line_count = sum(1 for _ in handle)

        detail = f"{path} lines={line_count} bytes={byte_count}"
        if line_count > line_limit or byte_count > byte_limit:
            warnings.append(
                f"NEEDS_COMPACTION {detail} "
                f"line_limit={line_limit} byte_limit={byte_limit}"
            )
        else:
            infos.append(f"OK compaction {detail}")
    return warnings, infos


def git_remote_has_embedded_credential() -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "config", "--get-regexp", r"^remote\..*\.url$"],
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"git_remote_check_failed={type(exc).__name__}"
    if completed.returncode not in {0, 1}:
        return False, f"git_remote_check_failed=returncode_{completed.returncode}"
    for line in completed.stdout.splitlines():
        _, _, url = line.partition(" ")
        if re.search(r"https?://[^/@\s]+:[^/@\s]+@", url) or re.search(r"gh[pousr]_[A-Za-z0-9]{20,}", url):
            return True, "embedded_credential_detected"
    return False, "clean"


def check_public_repo_files() -> list[str]:
    failures: list[str] = []
    forbidden_names = {".env"}
    forbidden_suffixes = {".sqlite", ".db", ".key", ".pem"}
    for path in REPO_ROOT.rglob("*"):
        if ".git" in path.parts:
            continue
        if path.is_file() and path.name in forbidden_names:
            failures.append(f"FORBIDDEN public_file {path}")
        if path.is_file() and path.suffix.lower() in forbidden_suffixes:
            failures.append(f"FORBIDDEN public_file {path}")
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check the local Agent Memory system.")
    parser.add_argument(
        "--changed-file",
        action="append",
        default=[],
        help="Only check this changed memory file for compaction hints. Repeatable.",
    )
    parser.add_argument(
        "--compaction-line-limit",
        type=int,
        default=DEFAULT_COMPACTION_LINE_LIMIT,
        help="Line count above which a changed memory file should be reviewed for compaction.",
    )
    parser.add_argument(
        "--compaction-byte-limit",
        type=int,
        default=DEFAULT_COMPACTION_BYTE_LIMIT,
        help="Byte size above which a changed memory file should be reviewed for compaction.",
    )
    parser.add_argument(
        "--skip-state-db",
        action="store_true",
        help="Skip SQLite schema checks. Useful before the first index build.",
    )
    parser.add_argument("--json", action="store_true", help="Print structured JSON output.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    failures: list[str] = []
    warnings: list[str] = []
    checks: list[str] = [f"vault_root={VAULT_ROOT}", f"state_db={STATE_DB}"]

    for path in REQUIRED_DIRS:
        if path.is_dir():
            checks.append(f"OK dir {path}")
        else:
            failures.append(f"MISSING dir {path}")

    for path in REQUIRED_FILES:
        if path.is_file():
            checks.append(f"OK file {path}")
        else:
            failures.append(f"MISSING file {path}")

    for path in REQUIRED_LOCAL_FILES:
        if path.is_file():
            checks.append(f"OK local_file {path}")
        else:
            failures.append(f"MISSING local_file {path}")

    frontmatter_targets = [
        path
        for path in REQUIRED_FILES
        if path.suffix.lower() == ".md" and path.name not in {"README.md", "AGENTS.md"} and not path.name.startswith("_模板")
    ]
    frontmatter_targets.extend(path for path in REQUIRED_FILES if path.name.startswith("_模板"))
    for path in frontmatter_targets:
        if path.exists() and file_has_frontmatter(path):
            checks.append(f"OK frontmatter {path}")
        elif path.exists():
            failures.append(f"BAD frontmatter {path}")

    leaked = scan_for_secrets([REPO_ROOT, VAULT_ROOT])
    if leaked:
        for path in leaked:
            failures.append(f"SECRET_OR_PRIVATE_PATH leak {path}")
    else:
        checks.append("OK no_secret_or_private_path_leak")

    remote_leak, remote_detail = git_remote_has_embedded_credential()
    if remote_leak:
        failures.append("SECRET git_remote_embedded_credential")
    elif remote_detail == "clean":
        checks.append("OK git_remote_no_embedded_credential")
    else:
        warnings.append(remote_detail)

    failures.extend(check_public_repo_files())

    if not args.skip_state_db:
        state_ok, state_detail = check_state_db()
        if state_ok:
            checks.append(f"OK state_db {STATE_DB} {state_detail}")
        else:
            failures.append(f"BAD state_db {STATE_DB} {state_detail}")

    if args.changed_file:
        compaction_warnings, compaction_infos = changed_file_compaction_warnings(
            args.changed_file, args.compaction_line_limit, args.compaction_byte_limit,
        )
        warnings.extend(compaction_warnings)
        checks.extend(compaction_infos)

    payload = {
        "ok": not failures,
        "failures": failures,
        "advisories": warnings,
        "checks": checks,
        "status": "error" if failures else ("advisory" if warnings else "ok"),
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for item in checks:
            print(item)
        for item in warnings:
            print(item)
        if failures:
            for item in failures:
                print(item, file=sys.stderr)
        else:
            print("agent_memory_check=ok")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
