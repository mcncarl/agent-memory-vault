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

from agent_memory_env import RuntimeTransitionError, assert_runtime_ready, env_value, expand_path
from agent_memory_safety import SECRET_PATTERNS, normalize_for_detection
from agent_memory_state import secure_sqlite_connect


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = REPO_ROOT / "scripts"
DEFAULT_VAULT_ROOT = REPO_ROOT / "templates" / "vault"
VAULT_ROOT = expand_path(env_value("ROOT", str(DEFAULT_VAULT_ROOT))).resolve()
GIT_ROOT = expand_path(env_value("GIT_ROOT", str(REPO_ROOT))).resolve()
STATE_DB = expand_path(env_value("STATE_DB", "$HOME/.config/agent-memory/state.sqlite")).resolve()
PUBLIC_TEMPLATE_MODE = DEFAULT_VAULT_ROOT.is_dir() and VAULT_ROOT == DEFAULT_VAULT_ROOT.resolve()


COMMON_REQUIRED_DIRS = [
    VAULT_ROOT / "用户记忆",
    VAULT_ROOT / "agent" / "case-candidates",
    VAULT_ROOT / "agent" / "cases",
    VAULT_ROOT / "agent" / "skill-candidates",
]

PUBLIC_REQUIRED_DIRS = [
    VAULT_ROOT / "项目",
    VAULT_ROOT / "工作流",
    VAULT_ROOT / "决策",
]


COMMON_REQUIRED_FILES = [
    VAULT_ROOT / "AGENTS.md",
    VAULT_ROOT / "INDEX.md",
    VAULT_ROOT / "用户记忆" / "README.md",
    VAULT_ROOT / "用户记忆" / "偏好与边界.md",
    VAULT_ROOT / "用户记忆" / "长期画像.md",
    VAULT_ROOT / "工作流" / "Agent记忆字段规范.md",
    VAULT_ROOT / "agent" / "case-candidates" / "README.md",
    VAULT_ROOT / "agent" / "case-candidates" / "_模板-AgentCase候选.md",
    VAULT_ROOT / "agent" / "cases" / "README.md",
    VAULT_ROOT / "agent" / "cases" / "_模板-AgentCase正式记忆.md",
    VAULT_ROOT / "agent" / "skill-candidates" / "README.md",
    VAULT_ROOT / "agent" / "skill-candidates" / "_模板-Skill候选.md",
]

PUBLIC_REQUIRED_FILES = [
    VAULT_ROOT / "工作流" / "Agent记忆收尾决策规则.md",
    VAULT_ROOT / "工作流" / "Agent记忆SQLite全库索引设计.md",
    VAULT_ROOT / "工作流" / "Agent记忆语义检索设计.md",
    VAULT_ROOT / "agent" / "README.md",
]

REQUIRED_LOCAL_FILES = [
    SCRIPT_ROOT / "bootstrap.py",
    SCRIPT_ROOT / "agent_memory_check.py",
    SCRIPT_ROOT / "agent_memory_evolution.py",
    SCRIPT_ROOT / "agent_memory_explain.py",
    SCRIPT_ROOT / "agent_memory_index.py",
    SCRIPT_ROOT / "agent_memory_host_automation.py",
    SCRIPT_ROOT / "agent_memory_intent.py",
    SCRIPT_ROOT / "agent_memory_observability.py",
    SCRIPT_ROOT / "agent_memory_search.py",
    SCRIPT_ROOT / "agent_memory_shadow.py",
    SCRIPT_ROOT / "agent_memory_safety.py",
    SCRIPT_ROOT / "agent_memory_closeout.py",
    SCRIPT_ROOT / "agent_memory_audit.py",
    SCRIPT_ROOT / "agent_memory_audit_autorun.py",
    SCRIPT_ROOT / "agent_memory_zvec_index.py",
    SCRIPT_ROOT / "agent_memory_policy_benchmark.py",
    SCRIPT_ROOT / "agent_memory_retrieval_benchmark.py",
    SCRIPT_ROOT / "agent_memory_retrieve.py",
    SCRIPT_ROOT / "agent_memory_write.py",
    SCRIPT_ROOT / "agent_memory_doctor.py",
    SCRIPT_ROOT / "agent_memory_decision_outcomes.py",
    SCRIPT_ROOT / "agent_memory_embedding_worker.py",
    SCRIPT_ROOT / "agent_memory_session_hook.py",
    SCRIPT_ROOT / "agent_memory_state.py",
    SCRIPT_ROOT / "agent_memory_stop_hook.py",
    SCRIPT_ROOT / "agent_memory_env.py",
    SCRIPT_ROOT / "install_runtime.py",
    SCRIPT_ROOT / "install_audit_launchagent.py",
    SCRIPT_ROOT / "install_host_hooks.py",
    SCRIPT_ROOT / "memoryctl",
]

PUBLIC_REQUIRED_LOCAL_FILES = [SCRIPT_ROOT / "run_tests_isolated.py"]

REQUIRED_STATE_TABLES = {
    "meta",
    "memory_files",
    "agent_case_state",
    "reminders",
    "memory_docs",
    "memory_fts",
    "memory_open_loops",
    "memory_safety_log",
    "memory_write_intents",
    "memory_write_receipts",
    "memory_session_claims",
    "memory_use_events",
    "memory_file_observations",
}

OPTIONAL_STATE_TABLES = {
    "memory_vector_chunks",
    "memory_vector_index_state",
}

COMPACTION_DIR_NAMES = {"用户记忆", "项目", "工作流", "决策", "agent"}
DEFAULT_COMPACTION_LINE_LIMIT = 140
DEFAULT_COMPACTION_BYTE_LIMIT = 14 * 1024
FORBIDDEN_HOST_AUTOMATION_TARGETS = (
    "agent_memory_stop_hook.py",
    "agent_memory_session_hook.py",
    "agent_memory_audit_autorun.py",
)
HOST_AUTOMATION_ADAPTERS = (
    Path("scripts/audit-task.ps1"),
    Path("scripts/stop-hook.ps1"),
    Path("scripts/install-codex-hook.ps1"),
    Path("scripts/agent_memory_session_hook.py"),
    Path("scripts/agent_memory_stop_hook.py"),
    Path("scripts/agent_memory_closeout.py"),
)


PRIVATE_PATH_PATTERN = re.compile(r"/Users/[A-Za-z0-9._-]+/")

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


def publishable_repo_files() -> list[Path]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        completed = None
    if completed is not None and completed.returncode == 0:
        return [
            REPO_ROOT / raw.decode("utf-8", errors="surrogateescape")
            for raw in completed.stdout.split(b"\0")
            if raw
        ]
    ignored_dirs = {".git", ".agent-memory", "__pycache__", "node_modules", ".pytest_cache"}
    return [path for path in REPO_ROOT.rglob("*") if not any(part in ignored_dirs for part in path.parts)]


def iter_text_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    ignored_dirs = {".git", "__pycache__", "node_modules", ".pytest_cache"}
    files: list[Path] = []
    candidates = publishable_repo_files() if PUBLIC_TEMPLATE_MODE and root.resolve() == REPO_ROOT.resolve() else root.rglob("*")
    for path in candidates:
        if any(part in ignored_dirs for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() in {".json", ".md", ".txt", ".py", ".toml", ".example", ".gitignore", ""} or path.name in {
            "README.md",
            ".env.example",
        }:
            files.append(path)
    return files


def scan_for_secrets(roots: list[Path], include_private_paths: bool) -> list[tuple[Path, str]]:
    leaked: list[tuple[Path, str]] = []
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
                leaked.append((path, "configured_exact_secret"))
                continue
            detection_text = normalize_for_detection(text)
            if any(pattern.search(detection_text) for pattern in SECRET_PATTERNS):
                leaked.append((path, "credential_pattern"))
                continue
            if include_private_paths and PRIVATE_PATH_PATTERN.search(text):
                leaked.append((path, "private_absolute_path"))
    return leaked


def file_has_frontmatter(path: Path) -> bool:
    text = path.read_text(encoding="utf-8", errors="replace")
    return text.startswith("---\n") and "memory_type:" in text and "status:" in text


def check_state_db() -> tuple[bool, str]:
    if not STATE_DB.exists():
        return False, "missing"
    try:
        with secure_sqlite_connect(
            STATE_DB,
            create=False,
            read_only=True,
            pragmas=("PRAGMA busy_timeout=10000",),
        ) as conn:
            rows = conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'virtual table')").fetchall()
    except (OSError, sqlite3.Error) as exc:
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
            ["git", "-C", str(GIT_ROOT), "config", "--get-regexp", r"^remote\..*\.url$"],
            text=True,
            encoding="utf-8",
            errors="replace",
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
    for path in publishable_repo_files():
        if path.is_file() and path.name in forbidden_names:
            failures.append(f"FORBIDDEN public_file {path}")
        if path.is_file() and path.suffix.lower() in forbidden_suffixes:
            failures.append(f"FORBIDDEN public_file {path}")
    return failures


def _markdown_fenced_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    fence = ""
    for line in text.splitlines():
        stripped = line.lstrip()
        marker = "```" if stripped.startswith("```") else ("~~~" if stripped.startswith("~~~") else "")
        if marker and not fence:
            fence = marker
            current = []
            continue
        if marker == fence:
            blocks.append("\n".join(current))
            current = []
            fence = ""
            continue
        if fence:
            current.append(line)
    if fence and current:
        blocks.append("\n".join(current))
    return blocks


def check_host_automation_examples(repo_root: Path = REPO_ROOT) -> list[str]:
    """Reject production examples/adapters that bypass managed memoryctl.

    Runtime implementation and classifier code may name legacy scripts to
    preserve or diagnose them.  The stricter boundary applies to copyable
    documentation blocks and the actual Host Automation adapters.
    """

    failures: list[str] = []
    markdown_paths: list[Path] = [
        path
        for path in (repo_root / "README.md", repo_root / "README.zh-CN.md")
        if path.is_file()
    ]
    for root in (repo_root / "docs", repo_root / "templates"):
        if root.is_dir():
            markdown_paths.extend(root.rglob("*.md"))
    inline_command = re.compile(
        r"(?:python(?:3)?|exec|command\s*[:=]|<string>|-Argument)[^\n]{0,500}"
        r"agent_memory_(?:stop_hook|session_hook|audit_autorun)\.py",
        re.IGNORECASE,
    )
    automation_direct = re.compile(
        r"(?:python(?:3)?|command\s*[:=]|<runtime>/.+python)[^\n]{0,500}"
        r"(?:agent_memory_[a-z0-9_]+|install_(?:host_hooks|audit_launchagent))\.py",
        re.IGNORECASE,
    )
    obsolete_claim_guidance = re.compile(
        r"(?:--actor(?:=|\s+)(?:codex|claude)\s+claim\b|\bclaim\s+--file(?:=|\s))",
        re.IGNORECASE,
    )
    for path in sorted(set(markdown_paths)):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for target in FORBIDDEN_HOST_AUTOMATION_TARGETS:
            if any(
                target in block and inline_command.search(block)
                for block in _markdown_fenced_blocks(text)
            ):
                failures.append(
                    f"HOST_AUTOMATION_BYPASS example={path.relative_to(repo_root)} target={target}"
                )
        for line_number, line in enumerate(text.splitlines(), 1):
            if inline_command.search(line) or (
                path == repo_root / "docs" / "automation.md"
                and automation_direct.search(line)
            ):
                failures.append(
                    "HOST_AUTOMATION_BYPASS "
                    f"example={path.relative_to(repo_root)}:{line_number}"
                )
            if obsolete_claim_guidance.search(line):
                failures.append(
                    "OBSOLETE_CLAIM_GUIDANCE "
                    f"example={path.relative_to(repo_root)}:{line_number}"
                )

    for relative in HOST_AUTOMATION_ADAPTERS:
        path = repo_root / relative
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for target in FORBIDDEN_HOST_AUTOMATION_TARGETS:
            if target in text:
                failures.append(f"HOST_AUTOMATION_BYPASS adapter={relative} target={target}")
    return sorted(set(failures))


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
    try:
        assert_runtime_ready("check")
    except RuntimeTransitionError as exc:
        payload = {
            "ok": False,
            "failures": ["RUNTIME_TRANSITION_INCOMPLETE"],
            "advisories": [],
            "checks": [],
            "status": "error",
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(str(exc), file=sys.stderr)
        return 2
    failures: list[str] = []
    warnings: list[str] = []
    mode = "public_template" if PUBLIC_TEMPLATE_MODE else "private_runtime"
    checks: list[str] = [f"mode={mode}", f"vault_root={VAULT_ROOT}", f"state_db={STATE_DB}"]

    required_dirs = COMMON_REQUIRED_DIRS + (PUBLIC_REQUIRED_DIRS if PUBLIC_TEMPLATE_MODE else [])
    required_files = COMMON_REQUIRED_FILES + (PUBLIC_REQUIRED_FILES if PUBLIC_TEMPLATE_MODE else [])

    for path in required_dirs:
        if path.is_dir():
            checks.append(f"OK dir {path}")
        else:
            failures.append(f"MISSING dir {path}")

    for path in required_files:
        if path.is_file():
            checks.append(f"OK file {path}")
        else:
            failures.append(f"MISSING file {path}")

    required_local_files = REQUIRED_LOCAL_FILES + (
        PUBLIC_REQUIRED_LOCAL_FILES if PUBLIC_TEMPLATE_MODE else []
    )
    for path in required_local_files:
        if path.is_file():
            checks.append(f"OK local_file {path}")
        else:
            failures.append(f"MISSING local_file {path}")

    frontmatter_targets = [
        path
        for path in required_files
        if path.name.startswith("_模板") or path.name in {"偏好与边界.md", "长期画像.md"}
    ]
    if PUBLIC_TEMPLATE_MODE:
        frontmatter_targets.extend(
            path
            for path in required_files
            if path.suffix.lower() == ".md"
            and path.name not in {"README.md", "AGENTS.md", "INDEX.md"}
            and not path.name.startswith("_模板")
            and path not in frontmatter_targets
        )
    for path in frontmatter_targets:
        if path.exists() and file_has_frontmatter(path):
            checks.append(f"OK frontmatter {path}")
        elif path.exists():
            failures.append(f"BAD frontmatter {path}")

    scan_roots = [REPO_ROOT] if PUBLIC_TEMPLATE_MODE else [VAULT_ROOT]
    leaked = scan_for_secrets(scan_roots, include_private_paths=PUBLIC_TEMPLATE_MODE)
    if leaked:
        for path, reason in leaked:
            failures.append(f"SECRET_OR_PRIVATE_PATH leak reason={reason} path={path}")
    else:
        checks.append("OK no_secret_or_private_path_leak")

    remote_leak, remote_detail = git_remote_has_embedded_credential()
    if remote_leak:
        failures.append("SECRET git_remote_embedded_credential")
    elif remote_detail == "clean":
        checks.append("OK git_remote_no_embedded_credential")
    else:
        warnings.append(remote_detail)

    if PUBLIC_TEMPLATE_MODE:
        failures.extend(check_public_repo_files())
        automation_failures = check_host_automation_examples()
        failures.extend(automation_failures)
        if not automation_failures:
            checks.append("OK host_automation_examples_use_managed_memoryctl")

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
