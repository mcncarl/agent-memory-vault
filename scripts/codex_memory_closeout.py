#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_ROOT = Path(__file__).resolve().parent
TEMPLATE_REPO_ROOT = SCRIPT_ROOT.parent
DEFAULT_VAULT_ROOT = TEMPLATE_REPO_ROOT / "templates" / "vault"
VAULT_ROOT = Path(
    os.path.expandvars(os.environ.get("CODEX_MEMORY_ROOT", str(DEFAULT_VAULT_ROOT)))
).expanduser().resolve()
CONFIG_ROOT = Path(
    os.path.expandvars(os.environ.get("CODEX_MEMORY_CONFIG_ROOT", "$HOME/.config/codex-memory"))
).expanduser().resolve()
STATE_DB = Path(
    os.path.expandvars(os.environ.get("CODEX_MEMORY_STATE_DB", str(CONFIG_ROOT / "state.sqlite")))
).expanduser().resolve()
LOG_PATH = Path(
    os.path.expandvars(os.environ.get("CODEX_MEMORY_CLOSEOUT_LOG", str(CONFIG_ROOT / "logs" / "closeout.jsonl")))
).expanduser().resolve()


def find_default_git_root() -> Path:
    for candidate in (VAULT_ROOT, *VAULT_ROOT.parents):
        if (candidate / ".git").exists():
            return candidate.resolve()
    return VAULT_ROOT.parent.resolve()


REPO_ROOT = Path(
    os.path.expandvars(os.environ.get("CODEX_MEMORY_GIT_ROOT", str(find_default_git_root())))
).expanduser().resolve()

CHECK_SCRIPT = SCRIPT_ROOT / "codex_memory_check.py"
INDEX_SCRIPT = SCRIPT_ROOT / "codex_memory_index.py"
SEARCH_SCRIPT = SCRIPT_ROOT / "codex_memory_search.py"
ZVEC_SCRIPT = SCRIPT_ROOT / "codex_memory_zvec_index.py"
AGENT_EVOLUTION_SCRIPT = SCRIPT_ROOT / "codex_agent_evolution.py"
AUDIT_AUTORUN_SCRIPT = SCRIPT_ROOT / "codex_memory_audit_autorun.py"
PYTHON = os.environ.get("CODEX_MEMORY_PYTHON", sys.executable)
ZVEC_PYTHON = os.environ.get("CODEX_MEMORY_ZVEC_PYTHON", PYTHON)

MEMORY_TOP_LEVELS = {"用户记忆", "项目", "工作流", "决策", "agent"}
TOP_LEVEL_MEMORY_FILES = {"AGENTS.md", "INDEX.md", "README.md", "STRUCTURE.md"}
RECONCILE_ACTIONS = {
    "ADD",
    "UPDATE",
    "NOOP",
    "MARK_OUTDATED",
    "MERGE_REQUIRED",
    "ASK_USER",
}
ASK_USER_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password|cookie|credential)"),
    re.compile(r"(?i)sk-[A-Za-z0-9][A-Za-z0-9_-]{16,}"),
    re.compile(r"(操控|操作|打开|登录|读取|导出|发送|回复|群发).{0,12}微信|微信.{0,12}(操控|操作|打开|登录|读取|导出|发送|回复|群发)"),
    re.compile(r"(删除|删掉|移到废纸篓|移入废纸篓|永久删除|清空).{0,12}(文件|目录|记忆|仓库|vault)|rm\s+-rf|unlink"),
]


@dataclass
class GitEntry:
    status: str
    repo_path: str
    path: Path

    @property
    def exists(self) -> bool:
        return self.path.exists()

    @property
    def is_deleted(self) -> bool:
        return "D" in self.status

    @property
    def is_new(self) -> bool:
        return self.status == "??" or "A" in self.status

    @property
    def is_memory_markdown(self) -> bool:
        if self.path.suffix.lower() != ".md":
            return False
        try:
            relative = self.path.relative_to(VAULT_ROOT)
        except ValueError:
            return False
        if len(relative.parts) == 1:
            return relative.name in TOP_LEVEL_MEMORY_FILES
        return bool(relative.parts) and relative.parts[0] in MEMORY_TOP_LEVELS


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def command_env_offline() -> dict[str, str]:
    env = os.environ.copy()
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        env.pop(key, None)
    env.setdefault("HF_HUB_OFFLINE", "1")
    env.setdefault("TRANSFORMERS_OFFLINE", "1")
    return env


def run_command(
    command: list[str],
    timeout: int = 120,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    started_at = utc_now()
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


def decode_status_line(line: str) -> GitEntry | None:
    if len(line) < 4:
        return None
    status = line[:2].strip() or line[:2]
    repo_path = line[3:]
    if " -> " in repo_path:
        repo_path = repo_path.split(" -> ", 1)[1]
    path = (REPO_ROOT / repo_path).resolve()
    return GitEntry(status=status, repo_path=repo_path, path=path)


def git_status_entries() -> tuple[list[GitEntry], list[str]]:
    try:
        target = str(VAULT_ROOT.relative_to(REPO_ROOT))
    except ValueError:
        target = str(VAULT_ROOT)
    result = run_command(
        [
            "git",
            "-C",
            str(REPO_ROOT),
            "-c",
            "core.quotepath=false",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            target,
        ],
        timeout=30,
    )
    if not result["ok"]:
        return [], [f"git status failed: {result['stderr'].strip()}"]
    entries: list[GitEntry] = []
    items = [item for item in str(result["stdout"]).split("\0") if item]
    index = 0
    while index < len(items):
        item = items[index]
        entry = decode_status_line(item)
        if entry:
            entries.append(entry)
            if entry.status.startswith(("R", "C")):
                index += 1
        index += 1
    return entries, []


def explicit_entries(paths: list[str]) -> tuple[list[GitEntry], list[str]]:
    entries: list[GitEntry] = []
    warnings: list[str] = []
    for raw in paths:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        else:
            path = path.resolve()
        try:
            repo_path = str(path.relative_to(REPO_ROOT))
        except ValueError:
            warnings.append(f"changed file outside repo skipped: {path}")
            continue
        status = "??" if path.exists() else "D"
        entries.append(GitEntry(status=status, repo_path=repo_path, path=path))
    return entries, warnings


def relative_to_vault(path: Path) -> str:
    try:
        return str(path.relative_to(VAULT_ROOT))
    except ValueError:
        return str(path)


def read_text(path: Path, limit: int = 12000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return text[:limit]


def title_from_text(text: str, path: Path) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem


def summary_from_text(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("summary:"):
            return stripped.split(":", 1)[1].strip().strip('"')
    current_summary = text.find("## 当前有效摘要")
    if current_summary != -1:
        return text[current_summary : current_summary + 500].replace("\n", " ")
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("---")]
    return " ".join(lines[:8])[:700]


def reconcile_query_for_file(path: Path) -> str:
    text = read_text(path)
    title = title_from_text(text, path)
    summary = summary_from_text(text)
    query = f"{title} {summary}".strip()
    return query[:900]


def tokenize(text: str) -> set[str]:
    tokens: set[str] = set()
    for word in re.findall(r"[A-Za-z0-9_]{2,}", text.lower()):
        tokens.add(word)
    for seq in re.findall(r"[\u4e00-\u9fff]{2,}", text):
        if len(seq) <= 6:
            tokens.add(seq)
        for index in range(max(len(seq) - 1, 0)):
            tokens.add(seq[index : index + 2])
    return tokens


def jaccard(left: str, right: str) -> float:
    left_tokens = tokenize(left)
    right_tokens = tokenize(right)
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def coverage(left: str, right: str) -> float:
    left_tokens = tokenize(left)
    right_tokens = tokenize(right)
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens)


def search_memory(query: str, limit: int = 8, no_zvec: bool = True) -> tuple[list[dict[str, Any]], list[str]]:
    command = [PYTHON, str(SEARCH_SCRIPT), query, "--limit", str(limit), "--json"]
    if no_zvec:
        command.append("--no-zvec")
    result = run_command(command, timeout=80, env=command_env_offline())
    if not result["ok"]:
        return [], [f"search failed: {str(result['stderr']).strip() or result['returncode']}"]
    try:
        payload = json.loads(str(result["stdout"]))
    except json.JSONDecodeError:
        return [], ["search returned non-json output"]
    rows = payload.get("results", [])
    warnings = payload.get("warnings", [])
    if not isinstance(rows, list):
        rows = []
    if not isinstance(warnings, list):
        warnings = []
    return rows, [str(item) for item in warnings]


def prewrite_recommendation(text: str, rows: list[dict[str, Any]]) -> tuple[str, dict[str, Any] | None, dict[str, float]]:
    if any(pattern.search(text) for pattern in ASK_USER_PATTERNS):
        return "ASK_USER", None, {"similarity": 0.0, "coverage": 0.0}
    if not rows:
        return "ADD", None, {"similarity": 0.0, "coverage": 0.0}
    best_similarity = 0.0
    best_coverage = 0.0
    best_row: dict[str, Any] | None = None
    for row in rows:
        comparison = " ".join(
            str(row.get(key, ""))
            for key in ("title", "rel_path", "summary", "hit")
        )
        similarity = jaccard(text, comparison)
        row_coverage = coverage(text, comparison)
        if (row_coverage, similarity) > (best_coverage, best_similarity):
            best_similarity = similarity
            best_coverage = row_coverage
            best_row = row
    if best_similarity >= 0.45 or best_coverage >= 0.55:
        return "UPDATE", best_row, {"similarity": best_similarity, "coverage": best_coverage}
    if best_similarity >= 0.28 or best_coverage >= 0.35:
        return "MERGE_REQUIRED", best_row, {"similarity": best_similarity, "coverage": best_coverage}
    return "ADD", best_row, {"similarity": best_similarity, "coverage": best_coverage}


def run_prewrite(args: argparse.Namespace) -> dict[str, Any]:
    rows, warnings = search_memory(args.prewrite, limit=args.limit, no_zvec=args.no_zvec)
    action, target, metrics = prewrite_recommendation(args.prewrite, rows)
    return {
        "time": utc_now(),
        "mode": "prewrite",
        "input_preview": args.prewrite[:500],
        "recommended_action": action,
        "recommended_target": target,
        "recommendation_metrics": {
            "similarity": round(metrics["similarity"], 4),
            "coverage": round(metrics["coverage"], 4),
        },
        "allowed_actions": sorted(RECONCILE_ACTIONS),
        "candidates": rows,
        "warnings": warnings,
        "status": "warning" if action in {"ASK_USER", "MERGE_REQUIRED"} else "ok",
    }


def postwrite_reconcile(entries: list[GitEntry], args: argparse.Namespace) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    findings: list[dict[str, Any]] = []
    targets = [entry for entry in entries if entry.exists and entry.is_memory_markdown and (entry.is_new or args.reconcile_all)]
    for entry in targets:
        query = reconcile_query_for_file(entry.path)
        if not query:
            continue
        rows, search_warnings = search_memory(query, limit=max(args.limit, 8), no_zvec=args.no_zvec)
        warnings.extend(search_warnings)
        source_text = query
        candidates: list[dict[str, Any]] = []
        for row in rows:
            if row.get("path") == str(entry.path) or row.get("rel_path") == relative_to_vault(entry.path):
                continue
            comparison = " ".join(
                str(row.get(key, ""))
                for key in ("title", "rel_path", "summary", "hit")
            )
            similarity = jaccard(source_text, comparison)
            if similarity >= args.merge_threshold:
                candidates.append(
                    {
                        "rel_path": row.get("rel_path", ""),
                        "title": row.get("title", ""),
                        "similarity": round(similarity, 4),
                        "sources": row.get("sources", []),
                        "path": row.get("path", ""),
                    }
                )
        if candidates:
            findings.append(
                {
                    "action": "MERGE_REQUIRED",
                    "file": str(entry.path),
                    "rel_path": relative_to_vault(entry.path),
                    "reason": "new_or_checked_file_similar_to_existing_memory",
                    "candidates": candidates,
                }
            )
    return findings, warnings


def run_check(files: list[Path], args: argparse.Namespace) -> dict[str, Any]:
    command = [PYTHON, str(CHECK_SCRIPT)]
    for path in files:
        command.extend(["--changed-file", str(path)])
    if args.dry_run:
        return {"ok": True, "skipped": False, "detail": "dry_run_check_still_executed", **run_command(command, timeout=180)}
    return run_command(command, timeout=180)


def run_index(args: argparse.Namespace) -> dict[str, Any]:
    if args.dry_run:
        return {"ok": True, "skipped": True, "detail": "dry_run"}
    return run_command([PYTHON, str(INDEX_SCRIPT), "--init", "--scan", "--report"], timeout=180)


def run_zvec(files: list[Path], args: argparse.Namespace) -> dict[str, Any]:
    if args.skip_zvec:
        return {"ok": True, "skipped": True, "detail": "skip_zvec"}
    if args.dry_run:
        return {"ok": True, "skipped": True, "detail": "dry_run"}
    command = [ZVEC_PYTHON, str(ZVEC_SCRIPT), "--json"]
    for path in files:
        command.extend(["--changed-file", str(path)])
    if len(command) == 2:
        return {"ok": True, "skipped": True, "detail": "no_changed_files"}
    return run_command(command, timeout=args.zvec_timeout, env=command_env_offline())


def run_agent_evolution(files: list[Path], args: argparse.Namespace) -> dict[str, Any]:
    touches_agent = False
    for path in files:
        try:
            relative = path.relative_to(VAULT_ROOT)
        except ValueError:
            continue
        if relative.parts and relative.parts[0] == "agent":
            touches_agent = True
            break
    if not touches_agent:
        return {"ok": True, "skipped": True, "detail": "no_agent_memory_changed"}
    if args.dry_run:
        return {"ok": True, "skipped": True, "detail": "dry_run"}
    return run_command([PYTHON, str(AGENT_EVOLUTION_SCRIPT), "--init", "--scan", "--report"], timeout=120)


def run_audit_autorun(args: argparse.Namespace) -> dict[str, Any]:
    if args.skip_audit:
        return {"ok": True, "skipped": True, "detail": "skip_audit"}
    command = [
        PYTHON,
        str(AUDIT_AUTORUN_SCRIPT),
        "--reason",
        "closeout",
        "--min-interval-days",
        str(args.audit_interval_days),
        "--limit",
        str(args.audit_limit),
        "--stale-days",
        str(args.audit_stale_days),
        "--open-loop-threshold",
        str(args.audit_open_loop_threshold),
        "--json",
    ]
    if args.dry_run:
        command.append("--dry-run")
    result = run_command(command, timeout=args.audit_timeout)
    result["skipped"] = False
    result["detail"] = ""
    if result["ok"]:
        try:
            audit_payload = json.loads(str(result["stdout"]))
        except json.JSONDecodeError:
            result["ok"] = False
            result["detail"] = "audit_autorun_returned_non_json"
        else:
            status = str(audit_payload.get("status", ""))
            result["audit_payload"] = audit_payload
            result["detail"] = status
            result["skipped"] = status in {"skipped_recent", "dry_run_recent"}
    return result


def commit_files(files: list[Path], args: argparse.Namespace) -> dict[str, Any]:
    if not args.commit or args.dry_run:
        return {"ok": True, "skipped": True, "detail": "commit_not_requested"}
    repo_paths: list[str] = []
    for path in files:
        if not path.exists():
            continue
        try:
            repo_paths.append(str(path.relative_to(REPO_ROOT)))
        except ValueError:
            continue
    if not repo_paths:
        return {"ok": True, "skipped": True, "detail": "no_existing_files_to_commit"}

    add_result = run_command(["git", "-C", str(REPO_ROOT), "add", "--", *repo_paths], timeout=60)
    if not add_result["ok"]:
        return {"ok": False, "stage": "add", "detail": add_result}

    diff_result = run_command(["git", "-C", str(REPO_ROOT), "diff", "--cached", "--quiet", "--", *repo_paths], timeout=60)
    if diff_result["returncode"] == 0:
        return {"ok": True, "skipped": True, "detail": "nothing_staged"}

    message = args.message or f"codex memory closeout: {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}"
    commit_result = run_command(["git", "-C", str(REPO_ROOT), "commit", "-m", message, "--", *repo_paths], timeout=120)
    if not commit_result["ok"]:
        return {"ok": False, "stage": "commit", "detail": commit_result}

    rev_result = run_command(["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"], timeout=30)
    return {
        "ok": True,
        "skipped": False,
        "commit": str(rev_result["stdout"]).strip(),
        "files": repo_paths,
    }


def append_log(payload: dict[str, Any]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def short_step(step: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": bool(step.get("ok")),
        "skipped": bool(step.get("skipped", False)),
        "returncode": step.get("returncode"),
        "detail": step.get("detail", ""),
        "stderr": str(step.get("stderr", "")).strip()[:500],
    }


def run_closeout(args: argparse.Namespace) -> dict[str, Any]:
    warnings: list[str] = []
    info: list[str] = []
    git_entries, git_warnings = git_status_entries()
    warnings.extend(git_warnings)
    explicit, explicit_warnings = explicit_entries(args.changed_file)
    warnings.extend(explicit_warnings)

    by_path: dict[Path, GitEntry] = {entry.path: entry for entry in git_entries}
    for entry in explicit:
        by_path[entry.path] = entry
    all_entries = list(by_path.values())

    deleted_entries = [entry for entry in all_entries if entry.is_deleted]
    for entry in deleted_entries:
        warnings.append(f"deleted memory file not staged by closeout: {entry.repo_path}")

    process_entries = [
        entry
        for entry in all_entries
        if entry.exists and entry.is_memory_markdown and not entry.is_deleted
    ]
    process_files = [entry.path for entry in process_entries]

    if args.dry_run:
        warnings.append("dry_run: no index refresh, zvec refresh, or commit will be written")
    if all_entries:
        info.append(
            "git reports dirty Codex memory files; if some are historical, review dry-run output before committing"
        )

    check_step = run_check(process_files, args) if process_files else {"ok": True, "skipped": True, "detail": "no_changed_files"}
    reconcile_findings, reconcile_warnings = postwrite_reconcile(process_entries, args)
    warnings.extend(reconcile_warnings)
    index_step = run_index(args) if process_files else {"ok": True, "skipped": True, "detail": "no_changed_files"}
    zvec_step = run_zvec(process_files, args) if process_files else {"ok": True, "skipped": True, "detail": "no_changed_files"}
    agent_step = run_agent_evolution(process_files, args) if process_files else {"ok": True, "skipped": True, "detail": "no_changed_files"}
    audit_step = run_audit_autorun(args)
    audit_payload = audit_step.get("audit_payload") if isinstance(audit_step.get("audit_payload"), dict) else {}
    if audit_payload:
        audit_status = str(audit_payload.get("status", ""))
        findings_count = int(audit_payload.get("findings_count") or 0)
        if audit_status == "ran":
            info.append(
                f"audit ran via closeout; findings={findings_count}; report={audit_payload.get('report_path', '')}"
            )
        elif audit_status in {"dry_run_due", "dry_run_recent"}:
            due_text = "would run" if audit_payload.get("would_run") else "recent"
            info.append(f"audit dry-run check: {due_text}; report={audit_payload.get('report_path', '')}")
        else:
            info.append(f"audit check: {audit_status}; report={audit_payload.get('report_path', '')}")
    elif not audit_step.get("ok"):
        info.append(f"audit autorun failed: {str(audit_step.get('stderr', '')).strip()[:300]}")

    blocking_reconcile = bool(reconcile_findings)
    step_failed = not all(
        bool(step.get("ok"))
        for step in (check_step, index_step, zvec_step, agent_step)
    )
    status = "ok"
    if step_failed:
        status = "error"
    elif blocking_reconcile or warnings:
        status = "warning"

    commit_step: dict[str, Any]
    if status == "error":
        commit_step = {"ok": False, "skipped": True, "detail": "skipped_due_to_error"}
    elif blocking_reconcile and not args.commit_warnings:
        commit_step = {"ok": True, "skipped": True, "detail": "skipped_due_to_merge_required"}
    elif status == "warning" and not args.commit_warnings:
        commit_step = {"ok": True, "skipped": True, "detail": "skipped_due_to_warning"}
    else:
        commit_step = commit_files(process_files, args)
        if not commit_step.get("ok"):
            status = "error"

    payload = {
        "time": utc_now(),
        "cwd": str(Path.cwd()),
        "mode": "closeout",
        "changed_files": [entry.repo_path for entry in all_entries],
        "processed_files": [relative_to_vault(path) for path in process_files],
        "deleted_files_skipped": [entry.repo_path for entry in deleted_entries],
        "reconcile_findings": reconcile_findings,
        "info": info,
        "warnings": warnings,
        "steps": {
            "check": short_step(check_step),
            "sqlite": short_step(index_step),
            "zvec": short_step(zvec_step),
            "agent_evolution": short_step(agent_step),
            "audit": short_step(audit_step),
            "commit": short_step(commit_step),
        },
        "commit": commit_step.get("commit", "skipped"),
        "status": status,
    }
    if not args.dry_run:
        append_log(payload)
    return payload


def print_human(payload: dict[str, Any]) -> None:
    if payload.get("mode") == "prewrite":
        print(f"mode=prewrite status={payload['status']}")
        print(f"recommended_action={payload['recommended_action']}")
        for index, row in enumerate(payload.get("candidates", [])[:5], 1):
            print(f"{index}. {row.get('rel_path', '')}")
            print(f"   title: {row.get('title', '')}")
            print(f"   sources: {','.join(row.get('sources', []))}")
            print(f"   summary: {str(row.get('summary', ''))[:220]}")
        for warning in payload.get("warnings", []):
            print(f"warning: {warning}")
        return

    print(f"mode=closeout status={payload['status']}")
    print(f"changed_files={len(payload.get('changed_files', []))}")
    print(f"processed_files={len(payload.get('processed_files', []))}")
    for item in payload.get("processed_files", []):
        print(f"processed: {item}")
    for finding in payload.get("reconcile_findings", []):
        print(f"reconcile: {finding.get('action')} {finding.get('rel_path')}")
        for candidate in finding.get("candidates", []):
            print(f"  candidate: {candidate.get('rel_path')} similarity={candidate.get('similarity')}")
    for name, step in payload.get("steps", {}).items():
        skipped = " skipped" if step.get("skipped") else ""
        print(f"{name}={'ok' if step.get('ok') else 'failed'}{skipped} {step.get('detail', '')}")
    if payload.get("commit") and payload.get("commit") != "skipped":
        print(f"commit={payload['commit']}")
    for warning in payload.get("warnings", []):
        print(f"warning: {warning}")
    for item in payload.get("info", []):
        print(f"info: {item}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Unified closeout for the local Codex memory system."
    )
    parser.add_argument("--prewrite", help="Run reconcile before writing a new memory; does not modify files.")
    parser.add_argument("--changed-file", action="append", default=[], help="Explicit changed memory file. Repeatable.")
    parser.add_argument("--limit", type=int, default=8, help="Search candidates for reconcile.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--dry-run", action="store_true", help="Inspect only; do not refresh indexes, write logs, or commit.")
    parser.add_argument("--commit", action="store_true", help="After successful closeout, commit only processed memory files.")
    parser.add_argument("--commit-warnings", action="store_true", help="Allow commit when non-blocking warnings exist.")
    parser.add_argument("--message", default="", help="Custom scoped commit message.")
    parser.add_argument("--skip-zvec", action="store_true", help="Skip Zvec refresh.")
    parser.add_argument("--no-zvec", action="store_true", help="Skip Zvec during prewrite/postwrite reconcile search.")
    parser.add_argument("--zvec-timeout", type=int, default=240, help="Seconds before Zvec refresh times out.")
    parser.add_argument("--reconcile-all", action="store_true", help="Run postwrite reconcile on all changed files, not only new files.")
    parser.add_argument("--merge-threshold", type=float, default=0.42, help="Similarity threshold for MERGE_REQUIRED.")
    parser.add_argument("--skip-audit", action="store_true", help="Skip the weekly audit piggyback check.")
    parser.add_argument("--audit-interval-days", type=int, default=7, help="Run audit from closeout when the last successful audit is older than this.")
    parser.add_argument("--audit-limit", type=int, default=50, help="Maximum audit findings stored by closeout piggyback.")
    parser.add_argument("--audit-stale-days", type=int, default=120, help="Forwarded stale threshold for closeout piggyback audit.")
    parser.add_argument("--audit-open-loop-threshold", type=int, default=4, help="Forwarded open-loop threshold for closeout piggyback audit.")
    parser.add_argument("--audit-timeout", type=int, default=180, help="Seconds before closeout piggyback audit times out.")
    args = parser.parse_args()
    args.limit = max(args.limit, 1)
    args.audit_interval_days = max(args.audit_interval_days, 1)
    args.audit_limit = max(args.audit_limit, 1)
    args.audit_stale_days = max(args.audit_stale_days, 1)
    args.audit_open_loop_threshold = max(args.audit_open_loop_threshold, 1)
    if args.prewrite:
        args.dry_run = True
    return args


def main() -> int:
    args = parse_args()
    payload = run_prewrite(args) if args.prewrite else run_closeout(args)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_human(payload)
    if payload.get("status") == "error":
        return 2
    if payload.get("status") == "warning":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
